# frozen_string_literal: true

require "mail_on_rails/smtp/server"
require "mail_on_rails/smtp/session_helpers"
require "mail_on_rails/smtp/sender_auth"

module MailOnRails
  # SMTP server (RFC 5321 subset), run on a thread by Smtp::Daemon -
  # standalone in this repo's container via bin/server, or embedded in a
  # host process in development. Listens on several ports with
  # production-style roles:
  #
  #   :mx          - inbound receiving (like port 25). No auth required, but
  #                  accepts only for existing local recipients. Offers AUTH
  #                  and STARTTLS opportunistically; unauthenticated mail is
  #                  stored untrusted (authenticated_as = nil).
  #   :submission  - outgoing submission (like ports 587/465). AUTH required
  #                  before MAIL FROM, over TLS only, and MAIL FROM must match
  #                  the authenticated account. Stored trusted.
  #
  # Accepted messages are persisted through the store's SMTP interface
  # (docs/store_contract.md in the main mail_on_rails app repo) -
  # Store::Http against the host app in production, Store::Memory in tests.
  class SmtpServer < Smtp::Server
    MAX_MESSAGE_BYTES = 25 * 1024 * 1024
    MAX_LINE = 4096
    MAX_RECIPIENTS = 100
    MAX_MESSAGES_PER_SESSION = 100
    MAX_AUTH_ATTEMPTS = 3
    MAX_CONNECTIONS = Integer(ENV.fetch("MAIL_ON_RAILS_SMTP_MAX_CONN", 100))

    private

    def protocol_name = "SMTP"

    def busy_line = "421 Too many connections, try later"

    def listener_label(spec) = "#{spec[:port]}/#{spec[:tls]}/#{spec[:role]}"

    def session_class = Session

    class Session
      include Smtp::SessionHelpers

      def initialize(socket, store, spec, tls_ctx)
        @socket = socket
        @store = store
        @spec = spec
        @tls_ctx = tls_ctx
        @tls = spec[:tls] == :implicit
        @authenticated_as = nil
        @auth_attempts = 0
        @message_count = 0
        reset
      end

      def run
        set_timeout(300)
        reply 220, "#{server_name} ESMTP mail_on_rails service ready"
        while (line = read_line)
          break if handle_command(line) == :quit
        end
      rescue IOError, SystemCallError, IO::TimeoutError, OpenSSL::SSL::SSLError
        # client went away
      rescue StandardError => e
        @store.log(:error, "SMTP session error: #{e.class}: #{e.message}")
      ensure
        close_socket
      end

      private

      def reset
        @mail_from = nil
        @rcpt_to = []
      end

      # -- transport ---------------------------------------------------------

      def read_line
        line = @socket.gets("\r\n", MAX_LINE)
        return nil if line.nil?
        # A line longer than MAX_LINE comes back without its terminator.
        return "" unless line.end_with?("\r\n")

        line.chomp
      end

      def close_socket
        @socket.close
      rescue StandardError
        nil
      end

      # -- command dispatch --------------------------------------------------

      def handle_command(line)
        verb, arg = line.split(" ", 2)
        case verb&.upcase
        when "HELO" then @helo_name = arg.to_s.strip; reply 250, "#{server_name} greets #{arg}"
        when "EHLO" then @helo_name = arg.to_s.strip; ehlo(arg)
        when "STARTTLS" then starttls
        when "AUTH" then auth(arg)
        when "MAIL" then mail_from(arg)
        when "RCPT" then rcpt_to(arg)
        when "DATA" then data
        when "RSET" then reset; reply 250, "OK"
        when "NOOP" then reply 250, "OK"
        when "VRFY" then reply 252, "Cannot verify, but will accept and try"
        when "QUIT" then reply 221, "Bye"; return :quit
        else reply 502, "Command not implemented"
        end
        nil
      end

      def server_name
        @spec[:hostname] || "mail_on_rails"
      end

      def ehlo(arg)
        extensions = [ "#{server_name} greets #{arg}", "SIZE #{MAX_MESSAGE_BYTES}", "8BITMIME", "PIPELINING" ]
        extensions << "STARTTLS" if @tls_ctx && !@tls
        extensions << "AUTH PLAIN LOGIN" if auth_offered?
        multi 250, extensions
      end

      # AUTH is only offered over an encrypted channel - never send
      # credentials in the clear.
      def auth_offered?
        @tls
      end

      def starttls
        return reply 454, "TLS not available" unless @tls_ctx
        return reply 503, "TLS already active" if @tls

        reply 220, "Ready to start TLS"
        @socket = Smtp::TLS.accept(io_for(@socket), @tls_ctx)
        @tls = true
        set_timeout(300)
        reset # RFC 3207: discard all state learned before STARTTLS
      rescue OpenSSL::SSL::SSLError => e
        @store.log(:error, "SMTP STARTTLS failed: #{e.message}")
        raise IOError, "TLS handshake failed"
      end

      # -- authentication ----------------------------------------------------

      def auth(arg)
        return reply 538, "Encryption required for authentication" unless @tls
        return reply 503, "Already authenticated" if @authenticated_as

        mechanism, initial = arg.to_s.split(" ", 2)
        case mechanism&.upcase
        when "PLAIN"
          initial ||= challenge("")
          return reply 501, "Cancelled" if initial == "*"

          _authzid, user, pass = (decode_sasl_plain(initial) rescue [])
          verify_credentials(user, pass)
        when "LOGIN"
          user = decode64(initial || challenge("VXNlcm5hbWU6"))
          pass = decode64(challenge("UGFzc3dvcmQ6"))
          verify_credentials(user, pass)
        else
          reply 504, "Unrecognized authentication type"
        end
      end

      def challenge(prompt)
        @socket.write("334 #{prompt}\r\n")
        read_line.to_s
      end

      def decode64(str)
        str.to_s.unpack1("m0").to_s
      rescue ArgumentError
        ""
      end

      def verify_credentials(user, pass)
        result = @store.authenticate(user.to_s, pass.to_s)
        if result[:account_id]
          @authenticated_as = result[:email]
          @store.log(:info, "SMTP auth success for #{@authenticated_as} (#{peer_ip})")
          reply 235, "Authentication successful"
        else
          @auth_attempts += 1
          @store.log(:warn, "SMTP auth failed for #{user.to_s.empty? ? "(empty)" : user} (#{peer_ip}, attempt #{@auth_attempts}/#{MAX_AUTH_ATTEMPTS})")
          if @auth_attempts >= MAX_AUTH_ATTEMPTS
            reply 421, "Too many failed authentication attempts"
            raise IOError, "auth abuse"
          end
          reply 535, "Authentication credentials invalid"
        end
      end

      # -- envelope ----------------------------------------------------------

      def mail_from(arg)
        if @spec[:role] == :submission && !@authenticated_as
          return reply 530, "Authentication required"
        end

        unless arg =~ /\AFROM:\s*<([^>]*)>/i
          return reply 501, "Syntax: MAIL FROM:<address>"
        end

        from = Regexp.last_match(1)
        if @authenticated_as && !from.strip.casecmp?(@authenticated_as)
          return reply 550, "Sender address must match authenticated account"
        end

        @mail_from = from
        @rcpt_to = []
        reply 250, "OK"
      end

      def rcpt_to(arg)
        return reply 503, "Need MAIL command first" unless @mail_from
        return reply 452, "Too many recipients" if @rcpt_to.size >= MAX_RECIPIENTS

        unless arg =~ /\ATO:\s*<([^>]+)>/i
          return reply 501, "Syntax: RCPT TO:<address>"
        end

        recipient = Regexp.last_match(1)
        # Local recipients are accepted everywhere. Remote recipients are
        # accepted only from authenticated submission (queued for outbound
        # delivery) - the MX port stays local-only, so we never open relay.
        unless local_recipient?(recipient) || relay_allowed?(recipient)
          @store.log(:info, "SMTP rejected recipient <#{recipient}> from <#{@mail_from}> (#{@spec[:role]}, #{peer_ip})")
          return reply 550, "No such user here"
        end

        @rcpt_to << recipient
        reply 250, "OK"
      end

      def local_recipient?(address)
        result = @store.local_rcpts([ address ])
        Array(result[:local]).any?
      end

      def relay_allowed?(address)
        @spec[:role] == :submission && @authenticated_as &&
          address.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
      end

      # -- data --------------------------------------------------------------

      def data
        return reply 503, "Need RCPT command first" if @rcpt_to.empty?
        if @message_count >= MAX_MESSAGES_PER_SESSION
          return reply 421, "Too many messages this session"
        end

        reply 354, "End data with <CR><LF>.<CR><LF>"
        body = read_data_body
        return reply 552, "Message exceeds maximum size" unless body

        auth_results = nil
        if @spec[:role] == :mx && !@authenticated_as
          verdict = verify_sender(body)
          auth_results = verdict&.summary
          if verdict&.dmarc_reject?
            if Smtp::SenderAuth.enforce_dmarc?
              @store.log(:info, "SMTP rejected message from <#{@mail_from}>: DMARC policy (#{auth_results}, #{peer_ip})")
              reply 550, "5.7.1 Rejected per DMARC policy of #{verdict.from_domain}"
              reset
              return
            end
            @store.log(:info, "SMTP would reject message from <#{@mail_from}> under DMARC enforcement (#{auth_results}, #{peer_ip})")
          end
        end

        result = @store.smtp_store(@mail_from, @rcpt_to, body, @authenticated_as, auth_results: auth_results)
        if result[:code] == :insufficient_storage
          @store.log(:warn, "SMTP message from <#{@mail_from}> refused: insufficient storage (#{peer_ip})")
          reply 452, "Insufficient system storage, try later"
        elsif result[:code] == :relay_denied
          @store.log(:warn, "SMTP message from <#{@mail_from}> refused: relay denied (#{peer_ip})")
          reply 550, "Relaying denied"
        elsif result[:error]
          reply 451, "Requested action aborted: local error"
        else
          @message_count += 1
          auth_note = @authenticated_as ? ", auth #{@authenticated_as}" : ""
          @store.log(:info, "SMTP accepted message #{result[:id]} from <#{@mail_from}> to #{recipient_summary} " \
                            "(#{body.bytesize} bytes, #{@spec[:role]}#{auth_note}, #{peer_ip})")
          reply 250, "OK: queued as #{result[:id]}"
        end
        reset
      end

      # SPF/DKIM/DMARC for unauthenticated MX mail. DNS-heavy but bounded
      # (per-query timeouts, SPF lookup limits, capped DKIM signatures);
      # runs on this session's thread. Never lets a verifier bug take the
      # session down - verification failure just means no verdict.
      def verify_sender(body)
        Smtp::SenderAuth.verify(ip: peer_ip, helo: @helo_name, mail_from: @mail_from, data: body)
      rescue StandardError => e
        @store.log(:error, "SMTP sender verification error: #{e.class}: #{e.message}")
        nil
      end

      def recipient_summary
        shown = @rcpt_to.first(3).map { |r| "<#{r}>" }.join(" ")
        @rcpt_to.size > 3 ? "#{shown} +#{@rcpt_to.size - 3} more" : shown
      end

      def read_data_body
        body = +"".b
        overflow = false
        while (line = @socket.gets("\r\n"))
          break if line == ".\r\n"

          line = line[1..] if line.start_with?(".") # undo dot-stuffing
          overflow ||= body.bytesize + line.bytesize > MAX_MESSAGE_BYTES
          body << line unless overflow
        end
        overflow ? nil : body
      end

      # -- replies -----------------------------------------------------------

      def reply(code, text)
        @socket.write("#{code} #{text}\r\n")
      end

      def multi(code, lines)
        lines.each_with_index do |text, i|
          separator = i == lines.length - 1 ? " " : "-"
          @socket.write("#{code}#{separator}#{text}\r\n")
        end
      end
    end
  end
end
