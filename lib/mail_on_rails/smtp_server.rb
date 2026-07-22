# frozen_string_literal: true

require "mail_on_rails/smtp/config"
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
    MAX_RECEIVED_HOPS = 4
    MAX_RECIPIENTS = 100
    MAX_MESSAGES_PER_SESSION = 100
    MAX_AUTH_ATTEMPTS = 3
    MAX_CONNECTIONS = Smtp::Config.int("MAIL_ON_RAILS_SMTP_MAX_CONN", 100, min: 1)
    # Per-IP anti-abuse, enforced on the accept side (ConnLimiter /
    # AuthThrottle): concurrent-connection cap per peer IP, and a lockout
    # after repeated failed AUTHs (which otherwise cost the host app an HTTP
    # credential check each, MAX_AUTH_ATTEMPTS per connection, fresh on
    # every reconnect). 0 disables either.
    MAX_CONNECTIONS_PER_IP = Smtp::Config.int("MAIL_ON_RAILS_SMTP_MAX_CONN_PER_IP", 10)
    AUTH_LOCKOUT_FAILURES = Smtp::Config.int("MAIL_ON_RAILS_SMTP_AUTH_LOCKOUT_FAILURES", 10)
    AUTH_LOCKOUT_SECONDS = Smtp::Config.int("MAIL_ON_RAILS_SMTP_AUTH_LOCKOUT_SECONDS", 900, min: 1)
    # Protocol tracing default; per-listener spec[:trace] overrides. Read at
    # load time because worker Ractors cannot access ENV.
    TRACE_DEFAULT = ENV["MAIL_ON_RAILS_SMTP_TRACE"] == "1"
    LOG_REDACTION = "[redacted]"

    private

    def protocol_name = "SMTP"

    def busy_line = "421 Too many connections, try later"

    def locked_line = "421 Too many failed authentication attempts, try later"

    def listener_label(spec) = "#{spec[:port]}/#{spec[:tls]}/#{spec[:role]}"

    def session_class = Session

    class Session
      include Smtp::SessionHelpers

      # Set by Worker when per-IP auth throttling is active: a no-arg
      # callable invoked once per failed authentication attempt.
      attr_writer :on_auth_failure

      def initialize(socket, store, spec, tls_ctx)
        @socket = socket
        @store = store
        @spec = spec
        @tls_ctx = tls_ctx
        @tls = spec[:tls] == :implicit
        @trace = spec.fetch(:trace, TRACE_DEFAULT)
        @authenticated_as = nil
        @auth_attempts = 0
        @on_auth_failure = nil
        @message_count = 0
        @continuation = nil
        reset
      end

      def run
        set_timeout(300)
        reply 220, "#{server_name} ESMTP mail_on_rails service ready"
        while (chunk = @socket.gets("\r\n", MAX_LINE))
          break if handle_chunk(chunk) == :quit
        end
        # EOF with a continuation active means the peer vanished mid-DATA
        # or mid-AUTH; nothing has been stored, so ending here aborts it.
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

      def close_socket
        @socket.close
      rescue StandardError
        nil
      end

      # -- input handling ----------------------------------------------------
      #
      # The run loop above is the only read site. Each chunk is one
      # MAX_LINE-capped gets("\r\n") result: normally a full CRLF line, but
      # an overlong line arrives split with no terminator. Multi-line states
      # (DATA payload, AUTH challenge/response) install @continuation, which
      # then receives the raw chunks instead of the command dispatch and
      # clears itself when its exchange completes - Postal's @proc pattern.

      def handle_chunk(chunk)
        return @continuation.call(chunk) if @continuation

        line = line_from(chunk)
        trace "<= #{redact_for_trace(line)}"
        handle_command(line)
      end

      # A chunk without its CRLF is an overlong command line; normalize to
      # "" so dispatch rejects it rather than acting on a truncated command.
      def line_from(chunk)
        chunk.end_with?("\r\n") ? chunk.delete_suffix("\r\n") : ""
      end

      # -- protocol tracing --------------------------------------------------
      #
      # Debug-level log of the command/reply exchange, for diagnosing broken
      # peers. Credentials never reach the log: AUTH arguments are redacted
      # here, AUTH challenge responses are logged as a placeholder at the
      # challenge chokepoint, and DATA payloads bypass tracing entirely
      # (continuation chunks are never traced).

      def trace(message)
        @store.log(:debug, "SMTP #{message} (#{peer_ip})") if @trace
      end

      # An AUTH argument is an initial response - PLAIN's carries the
      # password, LOGIN's the username - so drop everything after the
      # mechanism (Postal's sanitize_input_for_log).
      def redact_for_trace(line)
        line.sub(/\A(AUTH[ \t]+\S+)[ \t].*/i) { "#{Regexp.last_match(1)} #{LOG_REDACTION}" }
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

      # Overridable via spec so tests can exercise size handling without
      # shoveling 25 MB through a loopback socket.
      def max_message_bytes
        @spec[:max_message_bytes] || MAX_MESSAGE_BYTES
      end

      def ehlo(arg)
        extensions = [ "#{server_name} greets #{arg}", "SIZE #{max_message_bytes}", "8BITMIME", "PIPELINING" ]
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
          initial ? auth_plain(initial) : challenge("") { |response| auth_plain(response) }
        when "LOGIN"
          if initial
            challenge("UGFzc3dvcmQ6") { |pass| verify_credentials(decode64(initial), decode64(pass)) }
          else
            challenge("VXNlcm5hbWU6") do |user|
              challenge("UGFzc3dvcmQ6") { |pass| verify_credentials(decode64(user), decode64(pass)) }
            end
          end
        else
          reply 504, "Unrecognized authentication type"
        end
      end

      def auth_plain(response)
        _authzid, user, pass = (decode_sasl_plain(response) rescue [])
        verify_credentials(user, pass)
      end

      # RFC 4954 challenge: send 334 and hand the client's next line to the
      # block. A lone "*" cancels the exchange (uniformly, for every prompt).
      # The response is a credential, so the trace gets a placeholder.
      def challenge(prompt, &handler)
        reply 334, prompt
        @continuation = proc do |chunk|
          @continuation = nil
          line = line_from(chunk)
          trace "<= #{line == "*" ? line : LOG_REDACTION}"
          line == "*" ? reply(501, "Cancelled") : handler.call(line)
        end
        nil
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
          @on_auth_failure&.call # recorded before the reply so the throttle can't lag the client
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
        @continuation = data_continuation
      end

      # Consumes the DATA payload one chunk at a time through the
      # terminating <CRLF>.<CRLF>. Chunks are MAX_LINE-capped, so a peer
      # that never sends CRLF cannot grow a single read without bound, and
      # line boundaries are tracked across chunk splits so the terminator
      # and dot-unstuffing apply only at true line starts - a bare-LF "."
      # line never ends DATA (SMTP smuggling).
      #
      # Over max_message_bytes the payload is discarded but still consumed
      # to stay in sync, then answered 552 at the terminator; past twice
      # the limit we stop reading mid-message, so the connection must drop
      # (:quit). A disconnect mid-payload just ends the run loop with the
      # continuation still installed - the partial body is never stored.
      def data_continuation
        body = +"".b
        consumed = 0
        line_start = true    # next chunk begins a fresh line
        dangling_cr = false  # previous chunk was cut just after a "\r"
        proc do |chunk|
          if dangling_cr && chunk.start_with?("\n")
            # A CRLF split across the chunk cap: this LF completes the line.
            consumed += 1
            body << "\n" if consumed <= max_message_bytes
            chunk = chunk[1..]
            line_start = true
            dangling_cr = false
            next if chunk.empty?
          end
          if line_start
            if chunk == ".\r\n"
              @continuation = nil
              next finish_data(consumed > max_message_bytes ? :overflow : body)
            end
            chunk = chunk[1..] if chunk.start_with?(".") # undo dot-stuffing
          end
          line_start = chunk.end_with?("\r\n")
          dangling_cr = !line_start && chunk.end_with?("\r")
          consumed += chunk.bytesize
          if consumed > max_message_bytes * 2
            @store.log(:warn, "SMTP message from <#{@mail_from}> refused: exceeds #{max_message_bytes} bytes (#{peer_ip})")
            reply 552, "Message exceeds maximum size"
            next :quit # peer kept flooding past the size limit
          end
          body << chunk if consumed <= max_message_bytes
          nil
        end
      end

      def finish_data(body)
        unless body.is_a?(String) # :overflow
          @store.log(:warn, "SMTP message from <#{@mail_from}> refused: exceeds #{max_message_bytes} bytes (#{peer_ip})")
          reply 552, "Message exceeds maximum size"
          reset
          return
        end

        if received_loop?(body)
          @store.log(:warn, "SMTP rejected message from <#{@mail_from}>: mail loop detected (#{peer_ip})")
          reply 550, "Loop detected"
          reset
          return
        end

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

      # Postal-style mail loop detection: a message whose headers show it
      # already passed through this host more than MAX_RECEIVED_HOPS times
      # is looping between forwarders.
      def received_loop?(body)
        header_section = body.split("\r\n\r\n", 2).first.to_s
        hostname = server_name.downcase
        hops = header_section.split(/\r\n(?![ \t])/).count do |header|
          header.match?(/\AReceived:/i) && header.downcase.include?(hostname)
        end
        hops > MAX_RECEIVED_HOPS
      end

      # -- replies -----------------------------------------------------------
      #
      # Reply text can echo client input (EHLO/HELO arguments); embedded
      # CR/LF or control bytes there would inject raw line breaks into our
      # replies, so everything unprintable is flattened before the wire.

      def reply(code, text)
        text = sanitize_reply(text)
        trace "=> #{code} #{text}"
        @socket.write("#{code} #{text}\r\n")
      end

      def multi(code, lines)
        lines.each_with_index do |text, i|
          text = sanitize_reply(text)
          separator = i == lines.length - 1 ? " " : "-"
          trace "=> #{code}#{separator}#{text}"
          @socket.write("#{code}#{separator}#{text}\r\n")
        end
      end

      def sanitize_reply(text)
        text.to_s.gsub(/[^[:print:]]/, " ")
      end
    end
  end
end
