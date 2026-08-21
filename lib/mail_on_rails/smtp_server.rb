# frozen_string_literal: true

require "time"
require "securerandom"
require "mail_on_rails/settings"
require "mail_on_rails/netserv/config"
require "mail_on_rails/netserv/server"
require "mail_on_rails/smtp/session_helpers"
require "mail_on_rails/sender_auth"
require "mail_on_rails/smtp/dnsbl"
require "mail_on_rails/smtp/fcrdns"
require "mail_on_rails/clamav_client"
require "mail_on_rails/send_quota"
require "mail_on_rails/scram"
require "mail_on_rails/rspamd_analyzer"

module MailOnRails
  # SMTP server (RFC 5321 subset), run on a thread by Smtp::Daemon -
  # standalone in this repo's container via bin/server, or embedded in a
  # host process in development. Listens on several ports with
  # production-style roles:
  #
  #   :mx          - inbound receiving (like port 25). Offers STARTTLS
  #                  opportunistically but never AUTH (auth is submission-
  #                  only); accepts only for existing local recipients, and
  #                  mail is stored untrusted (authenticated_as = nil).
  #   :submission  - outgoing submission (like ports 587/465). AUTH required
  #                  before MAIL FROM, over TLS only, and MAIL FROM must match
  #                  the authenticated account. Stored trusted.
  #
  # Accepted messages are persisted through the store's SMTP interface -
  # the ActiveRecord-backed Store::SmtpBackend in the app, Store::Memory in
  # tests.
  class SmtpServer < Netserv::Server
    # 1 MB under clamd's 25 MB StreamMaxLength: the app-side rescan streams
    # the message with our added headers, and a max-size message must not
    # blow the scanner's cap (which fails closed as a 451, forever).
    MAX_MESSAGE_BYTES = 24 * 1024 * 1024
    MAX_LINE = 4096
    MAX_RECEIVED_HOPS = 4
    MAX_RECIPIENTS = 100
    MAX_MESSAGES_PER_SESSION = 100
    MAX_AUTH_ATTEMPTS = 3
    # Per-session budget for 5xx syntax/state errors: a legitimate client
    # never accumulates these, a fuzzer or spam cannon does.
    MAX_PROTOCOL_ERRORS = 8
    # Absolute per-connection lifetime (Netserv::Server's reaper). The 300s
    # read timeout is per-read, so a slowloris peer trickling a byte at a
    # time holds its thread and ConnLimiter slot forever without it. An
    # hour is far beyond any legitimate session (100 messages of 24 MB
    # needs ~55 kB/s to fit - dial-up speed); 0 disables. Boot-only: the
    # lifetime is frozen into the listener specs and sizes the reaper's
    # sweep interval.
    SESSION_LIFETIME = Settings.static(:smtp_session_seconds)
    LOG_REDACTION = "[redacted]"

    # Accept-side anti-abuse limits (see Netserv::Server): process-wide and
    # per-IP concurrent caps, a lockout after repeated failed AUTHs (which
    # otherwise cost the host app an HTTP credential check each,
    # MAX_AUTH_ATTEMPTS per connection, fresh on every reconnect), and a
    # sliding-window connection rate answered with an escalating pre-banner
    # tarpit. 0 disables any of them. The per-ACCOUNT budget for
    # authenticated senders lives session-side instead (SendQuota,
    # consumed at RCPT) - the abuse it bounds, one stolen credential worked
    # from many IPs, is invisible to everything keyed by peer address.
    #
    # Read through the settings schema per check, so an admin's change
    # applies to the next connection without a restart. A constant defined
    # on a subclass still wins (the bespoke-test-server seam).
    def max_connections = tunable(:MAX_CONNECTIONS, SmtpServer) { Settings[:smtp_max_conn] }
    def max_connections_per_ip = tunable(:MAX_CONNECTIONS_PER_IP, SmtpServer) { Settings[:smtp_max_conn_per_ip] }
    def auth_lockout_failures = tunable(:AUTH_LOCKOUT_FAILURES, SmtpServer) { Settings[:smtp_auth_lockout_failures] }
    def auth_lockout_seconds = tunable(:AUTH_LOCKOUT_SECONDS, SmtpServer) { Settings[:smtp_auth_lockout_seconds] }
    def conn_rate_limit = tunable(:CONN_RATE_LIMIT, SmtpServer) { Settings[:smtp_conn_rate] }
    def conn_rate_window = tunable(:CONN_RATE_WINDOW, SmtpServer) { Settings[:smtp_conn_rate_window] }

    private

    def protocol_name = "SMTP"

    def busy_line = "421 4.7.0 Error: too many connections"

    def locked_line = "421 4.7.0 Error: too many failed login attempts"

    def listener_label(spec) = "#{spec[:port]}/#{spec[:tls]}/#{spec[:role]}"

    def session_class = Session


    class Session
      include Smtp::SessionHelpers
      include Netserv::HoneypotSession

      # Set by Server when per-IP auth throttling is active: a no-arg
      # callable invoked once per failed authentication attempt, and one
      # answering whether this peer's IP is currently locked out.
      attr_writer :on_auth_failure, :auth_locked

      def initialize(socket, store, spec, tls_ctx)
        @socket = socket
        @store = store
        @spec = spec
        @tls_ctx = tls_ctx
        @tls = spec[:tls] == :implicit
        @trace = spec.fetch(:trace) { Settings[:smtp_trace] }
        @trace_capture = spec.fetch(:trace_capture) { Settings[:smtp_trace_capture] }
        @close_reason = nil
        @helo_name = nil
        @authenticated_as = nil
        @auth_attempts = 0
        @protocol_errors = 0
        @on_auth_failure = nil
        @auth_locked = nil
        @message_count = 0
        @continuation = nil
        @lost_reply = nil
        @honeypot = false
        @honeypot_fired = false
        @honeypot_event_id = nil
        reset
      end

      # Honeypot hooks (Netserv::HoneypotSession).
      def honeypot_protocol = "smtp"
      def honeypot_username = @authenticated_as
      def honeypot_helo = @helo_name

      # Live-state snapshot for the ops UI (Server#connections). Read from
      # the web thread while the session thread runs, so plain values
      # only; a stale read costs nothing worse than a momentarily
      # out-of-date dashboard row.
      def live_info
        { user: @authenticated_as, helo: @helo_name,
          messages: @message_count, tls: @tls }
      end

      def run
        set_timeout(read_timeout)
        reply 220, honeypot_banner || "#{server_name} ESMTP service ready"
        quit = false
        while (chunk = @socket.gets("\r\n", MAX_LINE))
          if handle_chunk(chunk) == :quit
            quit = true
            break
          end
        end
        # EOF with a continuation active means the peer vanished mid-DATA
        # or mid-AUTH; nothing has been stored, so ending here aborts it.
        @close_reason = (@continuation ? "eof_mid_command" : "eof") unless quit
      rescue IO::TimeoutError
        @close_reason = "timeout"
        # An idle peer is told why before the close (best effort - it may
        # already be gone).
        @store.log(:info, "SMTP command timeout (#{@message_count} accepted this session, #{peer_ip})")
        begin
          reply 421, "4.4.2 SMTP command timeout - closing connection"
        rescue StandardError
          nil
        end
      rescue IOError, SystemCallError, OpenSSL::SSL::SSLError => e
        # error_reply pre-sets "protocol_abuse" before raising; anything
        # else here is the peer (or its network) going away.
        @close_reason ||= "connection_lost"
        log_connection_lost(e)
      rescue StandardError => e
        @close_reason = "session_error"
        @store.log(:error, "SMTP session error: #{e.class}: #{e.message}")
      ensure
        close_socket
      end

      # The transcript to persist for this session, or nil. Captures are
      # opt-in (smtp_trace_capture) and deliberately selective: only
      # sessions that ended abnormally - the ones worth diagnosing - and
      # never honeypot sessions, whose transcript already lands in their
      # HoneypotEvent. The buffer itself is redacted at the tap (AUTH
      # arguments, challenge responses) and never holds DATA payloads.
      # Called by Server#report_closed on the dying connection thread.
      def transcript_capture
        return nil unless @trace_capture && !honeypot_fired?
        return nil unless (reason = capture_reason)

        text = honeypot_transcript.to_s
        { transcript: text, close_reason: reason } unless text.empty?
      end

      private

      def reset
        @mail_from = nil
        @rcpt_to = []
        @rcpt_dsn = []
        @mail_requiretls = false
        @mail_smtputf8 = false
        @dsn_ret = nil
        @dsn_envid = nil
        @bdat = nil
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
        redacted = redact_for_trace(line)
        trace "<= #{redacted}"
        honeypot_transcript.inbound(redacted)
        # Exploit-probe payloads are recognised and refused, never dispatched -
        # the ban lands on the first hit. DATA/AUTH continuations bypass this
        # method, so a mail body full of ${...} shell noise can't false-positive.
        if (signature = Netserv::ProbeSignatures.match(line))
          trigger_honeypot("exploit_probe", signature: signature)
          # A VRFY probe gets the same reply an innocuous VRFY would -
          # answering "VRFY root" differently from "VRFY bob" would
          # fingerprint the honeypot. The event and ban have already landed.
          return signature == "vrfy_privileged" ? vrfy : error_reply(502, "5.5.1 Command not implemented")
        end
        handle_command(line)
      end

      # A chunk without its CRLF is an overlong command line; normalize to
      # "" so dispatch rejects it rather than acting on a truncated command.
      def line_from(chunk)
        chunk.end_with?("\r\n") ? chunk.delete_suffix("\r\n") : ""
      end

      # -- protocol tracing --------------------------------------------------
      #
      # Log of the command/reply exchange, for diagnosing broken peers.
      # Credentials never reach the log: AUTH arguments are redacted here,
      # AUTH challenge responses are logged as a placeholder at the
      # challenge chokepoint, and DATA payloads bypass tracing entirely
      # (continuation chunks are never traced). Logged at :info - the
      # smtp_trace setting is the opt-in, and production's default log
      # level (info) used to swallow the old :debug lines, making the
      # toggle a silent no-op exactly when it was needed.

      def trace(message)
        @store.log(:info, "SMTP #{message} (#{peer_ip})") if @trace
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
        when "HELO", "EHLO" then helo(verb, arg)
        when "STARTTLS" then starttls(arg)
        when "AUTH" then auth(arg)
        when "MAIL" then mail_from(arg)
        when "RCPT" then rcpt_to(arg)
        when "DATA" then data
        when "BDAT" then return bdat(arg)
        when "RSET" then reset; reply 250, "2.0.0 Ok"
        when "NOOP" then reply 250, "2.0.0 Ok"
        when "VRFY" then vrfy
        when "HELP" then help
        when "QUIT" then reply 221, "2.0.0 Bye"; return :quit
        else error_reply 502, "5.5.1 Command not implemented"
        end
        nil
      end

      # RFC 5321 4.1.1.8: HELP is a SHOULD; one line naming the verbs is
      # all a debugging human needs.
      def help
        reply 214, "2.0.0 See RFC 5321"
      end

      # RFC 5321 3.5.3 sanctions both stances on VRFY: the noncommittal
      # 252 and an outright 502 refusal. Which to present is a disclosure
      # policy, so the operator chooses (smtp_vrfy_response).
      def vrfy
        if Settings[:smtp_vrfy_response] == "502"
          error_reply 502, "5.5.1 Command not implemented"
        else
          reply 252, "2.0.0 Cannot VRFY user, but will accept message and attempt delivery"
        end
      end

      # RFC 5321 wants a domain or address literal as the argument;
      # validating it also keeps raw junk bytes out of the echoed
      # greeting. A repeated HELO/EHLO is legal and aborts any transaction
      # in progress (RFC 5321 4.1.4).
      def helo(verb, arg)
        name = arg.to_s.strip
        unless name.match?(/\A[A-Za-z0-9\[\].:_-]+\z/)
          return error_reply 501, "5.5.2 Syntactically invalid #{verb.upcase} argument"
        end

        @helo_name = name
        reset
        verb.casecmp?("HELO") ? reply(250, server_name) : ehlo(name)
      end

      # Counts toward the session's error budget; past it the peer gets one
      # final reply and the connection drops (the run loop's rescue).
      def error_reply(code, message)
        @protocol_errors += 1
        if @protocol_errors >= MAX_PROTOCOL_ERRORS
          reply code, "Too many syntax or protocol errors"
          @close_reason = "protocol_abuse"
          raise IOError, "protocol error abuse"
        end
        reply code, message
      end

      # Why this session's transcript is worth keeping, or nil for a
      # session with nothing to diagnose. A close reason always wins;
      # otherwise a cleanly closed session still qualifies when the peer
      # tripped protocol errors or failed every authentication attempt.
      # A bare EOF without QUIT stays nil deliberately: sloppy-but-working
      # clients and port scanners produce those constantly, and neither is
      # worth a stored transcript of real users' envelope metadata.
      def capture_reason
        return @close_reason if @close_reason && @close_reason != "eof"
        return "protocol_errors" if @protocol_errors.positive?
        return "auth_failed" if @auth_attempts.positive? && @authenticated_as.nil?

        nil
      end

      # spec[:hostname] may be a callable (the Rails host passes one so a
      # Settings-page change reaches new connections without a restart);
      # resolved once per session, before the banner.
      def server_name
        return @server_name if defined?(@server_name)

        name = @spec[:hostname]
        name = name.call if name.respond_to?(:call)
        @server_name = name || "localhost"
      end

      # Overridable via spec so tests can exercise size handling without
      # shoveling 25 MB through a loopback socket.
      def max_message_bytes
        @spec[:max_message_bytes] || MAX_MESSAGE_BYTES
      end

      # Same seam for the per-session message cap.
      def max_messages_per_session
        @spec[:max_messages] || MAX_MESSAGES_PER_SESSION
      end

      # And for the command-read timeout.
      def read_timeout
        @spec[:timeout] || 300
      end

      def ehlo(_arg)
        extensions = [ server_name, "SIZE #{max_message_bytes}", "8BITMIME", "PIPELINING",
                       "ENHANCEDSTATUSCODES", "CHUNKING",
                       # RFC 9422: the caps a client otherwise only learns
                       # by hitting 452s.
                       "LIMITS RCPTMAX=#{MAX_RECIPIENTS} MAILMAX=#{max_messages_per_session}" ]
        # RFC 6531: internationalized envelopes, both directions.
        extensions << "SMTPUTF8" if smtputf8_offered?
        extensions << "STARTTLS" if @tls_ctx && !@tls
        # RFC 8689: only a TLS session may carry the REQUIRETLS promise.
        extensions << "REQUIRETLS" if @tls
        # DSN (RFC 3461) is submission-only: the requesters are our own
        # authenticated senders, whose notifications the outbound queue
        # honors. On MX it would be a backscatter/probe oracle - inbound
        # mail is verified at RCPT time, so a remote MTA loses nothing.
        extensions << "DSN" if @spec[:role] == :submission
        if auth_offered?
          # -PLUS only when this connection can actually prove a channel
          # binding (a real TLS socket, not a wire-test loopback).
          # LOGIN is deliberately NOT advertised (obsolete, and a scanner
          # fingerprint); the handler still answers it for legacy clients
          # configured to use it regardless.
          mechanisms = Scram.channel_binding?(@socket) ? "SCRAM-SHA-256-PLUS " : ""
          extensions << "AUTH #{mechanisms}SCRAM-SHA-256 PLAIN"
        end
        multi 250, extensions
      end

      # SMTPUTF8 (RFC 6531) is a posture choice, read per session so an
      # admin's change applies to new transactions without a restart.
      # spec[:smtputf8] is the test seam.
      def smtputf8_offered?
        @spec.fetch(:smtputf8) { Settings[:smtp_smtputf8] }
      end

      # AUTH is only offered on submission listeners, over an encrypted
      # channel - never send credentials in the clear, and never accept
      # them on MX at all: an authenticated session on port 25 would skip
      # every gate unauthenticated MX mail must pass (SPF/DKIM/DMARC,
      # DNSBL), so a stolen credential could launder spam through the
      # inbound port. RFC 4954 puts AUTH on the submission service.
      def auth_offered?
        @tls && @spec[:role] == :submission
      end

      def starttls(arg)
        # RFC 3207: STARTTLS takes no parameter.
        return error_reply 501, "5.5.4 Syntax error (no parameters allowed)" if arg
        return error_reply 503, "5.5.1 TLS already active" if @tls
        return reply 454, "4.7.0 TLS not available due to local problem" unless @tls_ctx

        reply 220, "2.0.0 Ready to start TLS"
        @socket = Netserv::Tls.accept(io_for(@socket), @tls_ctx)
        @tls = true
        set_timeout(read_timeout)
        # RFC 3207: discard all state learned before STARTTLS, the
        # pre-handshake HELO included.
        @helo_name = nil
        reset
      rescue OpenSSL::SSL::SSLError => e
        @store.log(:error, "SMTP STARTTLS failed: #{e.message}")
        raise IOError, "TLS handshake failed"
      end

      # -- authentication ----------------------------------------------------

      def auth(arg)
        unless @spec[:role] == :submission
          return error_reply 503, "5.5.1 AUTH not available on this listener"
        end
        return reply 538, "5.7.11 Encryption required for requested authentication mechanism" unless @tls
        return error_reply 503, "5.5.1 Already authenticated" if @authenticated_as
        # RFC 4954: AUTH is illegal once a mail transaction is open.
        return error_reply 503, "5.5.1 AUTH not permitted in mail transaction" if @mail_from

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
        when "SCRAM-SHA-256"
          initial ? auth_scram(initial) : challenge("") { |first| auth_scram(first) }
        when "SCRAM-SHA-256-PLUS"
          if Scram.channel_binding?(@socket)
            initial ? auth_scram(initial, plus: true) : challenge("") { |first| auth_scram(first, plus: true) }
          else
            error_reply 504, "5.5.4 Unrecognized authentication type"
          end
        else
          error_reply 504, "5.5.4 Unrecognized authentication type"
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
          placeholder = line == "*" ? line : LOG_REDACTION
          trace "<= #{placeholder}"
          honeypot_transcript.inbound(placeholder)
          line == "*" ? cancel_auth : handler.call(line)
        end
        nil
      end

      # A "*" cancellation still costs a per-connection attempt. Otherwise
      # a client could loop AUTH/cancel without bound - and for SCRAM each
      # loop first drives a store credential lookup that the throttle
      # never sees (it only trips on *recorded* failures). Same accounting
      # as the IMAP session's cancel path.
      def cancel_auth
        @auth_attempts += 1
        if @auth_attempts >= MAX_AUTH_ATTEMPTS
          reply 421, "4.7.0 Error: too many failed login attempts"
          raise IOError, "auth abuse"
        end
        reply 501, "5.7.0 Authentication cancelled"
      end

      def decode64(str)
        str.to_s.unpack1("m0").to_s
      rescue ArgumentError
        ""
      end

      def verify_credentials(user, pass)
        # The accept-side lockout check only guards new connections, so
        # without this re-check every already-open session from the locked
        # IP (up to MAX_CONNECTIONS_PER_IP of them) keeps its full attempt
        # budget - each guess costing the host app a credential check.
        # Same semantics as the store-throttled branch below: temporary
        # failure, credentials never adjudicated, lockout not extended.
        if @auth_locked&.call
          @store.log(:warn, "SMTP auth refused for #{user.to_s.empty? ? "(empty)" : user}: IP locked out (#{peer_ip})")
          return reply 454, "4.7.0 Temporary authentication failure, try again later"
        end

        result = @store.authenticate(user.to_s, pass.to_s, ip: peer_ip)
        if result[:account_id]
          @authenticated_as = result[:email]
          @store.log(:info, "SMTP auth success for #{@authenticated_as} (#{peer_ip})")
          # A login against a canary can only be an attacker: record it, ban the
          # source, and keep the session so we observe the relay attempt (which
          # finish_data blackholes). The 235 is genuine - they are "in".
          honeypot_login! if result[:honeypot]
          reply 235, "2.7.0 Authentication successful"
        elsif result[:throttled]
          # The store refused to adjudicate (brute-force throttle): RFC
          # 4954's 454, so a legitimate client with a stale password backs
          # off and retries instead of treating its password as wrong. Not
          # counted as a failure anywhere - the throttle already has this
          # peer blocked.
          @store.log(:warn, "SMTP auth throttled for #{user.to_s.empty? ? "(empty)" : user} (#{peer_ip})")
          reply 454, "4.7.0 Temporary authentication failure, try again later"
        else
          auth_failure(user)
        end
      end

      # Shared failed-attempt accounting for the store-adjudicated
      # (PLAIN/LOGIN) and daemon-adjudicated (SCRAM) paths.
      def auth_failure(user)
        @auth_attempts += 1
        @on_auth_failure&.call # recorded before the reply so the throttle can't lag the client
        @store.log(:warn, "SMTP auth failed for #{user.to_s.empty? ? "(empty)" : user} (#{peer_ip}, attempt #{@auth_attempts}/#{MAX_AUTH_ATTEMPTS})")
        if @auth_attempts >= MAX_AUTH_ATTEMPTS
          reply 421, "4.7.0 Error: too many failed login attempts"
          raise IOError, "auth abuse"
        end
        reply 535, "5.7.8 Authentication credentials invalid"
      end

      # Server side of SCRAM-SHA-256 (RFC 5802/7677) and, over real TLS,
      # SCRAM-SHA-256-PLUS with channel binding (RFC 9266 / 5929) - over
      # the RFC 4954 challenge flow, same exchange as the IMAP session,
      # built on the shared Scram primitives. The store supplies
      # only verifier material (StoredKey/ServerKey); the password never
      # travels here.
      def auth_scram(client_first_b64, plus: false)
        gs2, bare, cb_type, cb_declined = Scram.split_gs2(decode64(client_first_b64))
        return error_reply 501, "5.5.2 Malformed SCRAM message" if gs2.nil?

        cb_data = nil
        if plus
          # -PLUS is only ever dispatched with channel binding available;
          # the gs2 header must then name a type this connection can prove.
          return error_reply 501, "5.5.2 Channel binding required for SCRAM-SHA-256-PLUS" unless cb_type

          cb_data = Scram.channel_binding_data(@socket, cb_type)
          return error_reply 504, "5.5.4 Unsupported channel binding type #{cb_type}" unless cb_data
        elsif cb_type
          return error_reply 501, "5.5.2 Channel binding not supported" unless Scram.channel_binding?(@socket)

          return error_reply 501, "5.5.2 Channel binding requires SCRAM-SHA-256-PLUS"
        elsif cb_declined && Scram.channel_binding?(@socket)
          # RFC 5802 §6: "y" claims the server never advertised -PLUS.
          # This one does, so the claim can only mean the advertisement
          # was stripped - fail rather than complete a downgraded exchange.
          return error_reply 535, "5.7.8 Channel binding downgrade detected"
        end

        attrs = scram_attrs(bare)
        user = attrs["n"].to_s.gsub("=2C", ",").gsub("=3D", "=")
        cnonce = attrs["r"].to_s
        return error_reply 501, "5.5.2 Malformed SCRAM message" if user.empty? || cnonce.empty?

        # Same lockout re-check as verify_credentials: accept-side only
        # guards new connections, and the credential lookup below hands
        # out salt/iterations - grind material - before any proof.
        if @auth_locked&.call
          @store.log(:warn, "SMTP auth refused for #{user}: IP locked out (#{peer_ip})")
          return reply 454, "4.7.0 Temporary authentication failure, try again later"
        end

        creds = @store.scram_credentials(user, ip: peer_ip)
        if creds[:throttled]
          @store.log(:warn, "SMTP auth throttled for #{user} (#{peer_ip})")
          return reply 454, "4.7.0 Temporary authentication failure, try again later"
        end
        if creds[:error]
          # :notfound is a real credential miss; anything else is the
          # store being unreachable.
          return reply 454, "4.7.0 Temporary authentication failure, try again later" unless creds[:code] == :notfound

          return scram_failure(user)
        end

        nonce = cnonce + SecureRandom.alphanumeric(24)
        server_first = "r=#{nonce},s=#{creds[:salt_base64]},i=#{creds[:iterations]}"
        challenge([ server_first ].pack("m0")) do |reply_b64|
          client_final = decode64(reply_b64)
          final_attrs = scram_attrs(client_final)
          proof = decode64(final_attrs["p"])
          without_proof = client_final[/\A(.*),p=[^,]*\z/m, 1].to_s
          auth_message = "#{bare},#{server_first},#{without_proof}"

          # c= carries gs2-header + raw cb data (RFC 5802 §5.1), so a
          # bound exchange only verifies against this TLS connection's
          # own binding - a MITM relaying the exchange has a different one.
          stored_key = creds[:stored_key_base64].unpack1("m0")
          unless final_attrs["r"] == nonce &&
                 final_attrs["c"] == [ gs2.b + cb_data.to_s.b ].pack("m0") &&
                 Scram.valid_proof?(stored_key, auth_message, proof)
            next scram_failure(user)
          end

          server_key = creds[:server_key_base64].unpack1("m0")
          verifier = "v=#{[ Scram.server_signature(server_key, auth_message) ].pack("m0")}"
          challenge([ verifier ].pack("m0")) do |empty|
            next error_reply 501, "5.5.2 Unexpected final client response" unless empty.empty?

            @authenticated_as = creds[:email]
            @store.log(:info, "SMTP auth success for #{@authenticated_as} (#{peer_ip}, SCRAM#{"-PLUS" if plus})")
            honeypot_login! if creds[:honeypot]
            reply 235, "2.7.0 Authentication successful"
          end
        end
      end

      def scram_attrs(message)
        message.split(",").filter_map { |part| [ part[0], part[2..] ] if part[1] == "=" }.to_h
      end

      # A SCRAM attempt this daemon rejected on its own: the proof is
      # checked here against verifier material, so the store never saw a
      # failure and has to be told - otherwise SCRAM would be an
      # unthrottled way around the store's brute-force budget.
      def scram_failure(user)
        @store.record_auth_failure(user.to_s, ip: peer_ip)
        auth_failure(user)
      end

      # -- envelope ----------------------------------------------------------

      def mail_from(arg)
        # RFC 5321 §3.3: a session starts with EHLO/HELO. Requiring it
        # here (STARTTLS resets @helo_name, so post-upgrade sessions must
        # re-greet, which conformant clients do) costs legitimate senders
        # nothing and strips a degree of freedom from scanners and spam
        # bots that jump straight to MAIL FROM.
        return error_reply 503, "5.5.1 Send EHLO/HELO first" unless @helo_name
        return error_reply 503, "5.5.1 Sender already given" if @mail_from
        if @spec[:role] == :submission && !@authenticated_as
          return reply 530, "5.7.0 Authentication required"
        end

        # A command line is read only up to its CRLF, but a bare CR/LF/NUL
        # embedded earlier survives into arg (and into the [^>]* capture
        # below). Left unchecked it would be stored verbatim as the envelope
        # sender and forge lines in the ~dozen single-line log sinks that
        # print it. Valid MAIL arguments are printable ASCII, so reject any
        # control byte outright.
        return error_reply 501, "5.5.4 Syntax: MAIL FROM:<address>" if arg.to_s.match?(/[[:cntrl:]]/)

        unless arg =~ /\AFROM:\s*<([^>]*)>\s*(.*)\z/im
          return error_reply 501, "5.5.4 Syntax: MAIL FROM:<address>"
        end

        from = Regexp.last_match(1)
        params = Regexp.last_match(2)
        # Parameters first: the SMTPUTF8 declaration (RFC 6531) rides the
        # same MAIL command as the address it legalizes.
        return unless accept_mail_parameters(params)

        unless from.ascii_only?
          # RFC 6531: a non-ASCII address is only legal in a transaction
          # that declared SMTPUTF8 against our advertisement, and only as
          # well-formed UTF-8.
          return reply 553, "5.6.7 Non-ASCII address requires the SMTPUTF8 extension" unless @mail_smtputf8
          return error_reply 501, "5.6.7 Address is not valid UTF-8" unless (from = as_utf8(from))
        end

        if (zone = rbl_listing)
          @store.log(:info, "SMTP rejected MAIL FROM:<#{from}> from #{peer_ip}: listed by DNSBL #{zone}")
          return reply 554, "5.7.1 Service unavailable; client host [#{peer_ip}] blocked using #{zone}"
        end

        # RFC 6409: the envelope sender must be an identity the login
        # owns - the account itself or one of its aliases.
        if @authenticated_as && permitted_senders.none? { |address| from.strip.casecmp?(address) }
          return reply 550, "5.7.1 Sender address must match authenticated account"
        end

        @mail_from = from
        @rcpt_to = []
        @rcpt_dsn = []
        reply 250, "2.1.0 Ok"
      end

      # ESMTP MAIL parameters (RFC 5321 4.1.1.2). We advertise SIZE and
      # 8BITMIME, so honor them: an oversize SIZE declaration is refused
      # before the client wastes the transfer (RFC 1870), BODY must be a
      # value we advertised, and AUTH= (RFC 4954) is accepted and ignored -
      # the session's own AUTH is the only identity we trust. REQUIRETLS
      # (RFC 8689) is a promise recorded for the relay path and only legal
      # on a TLS session; RET/ENVID (RFC 3461) ride with DSN, which is
      # submission-only. Anything else was never advertised, so it earns
      # RFC 5321's 555. Replies and returns false on rejection.
      #
      # xtext (RFC 3461 4): printable US-ASCII minus "+" and "=", with
      # +XX hex escapes.
      XTEXT = /\A(?:[\x21-\x2A\x2C-\x3C\x3E-\x7E]|\+[0-9A-F]{2})*\z/
      MAX_ENVID = 100
      MAX_ORCPT = 500

      def accept_mail_parameters(params)
        params.to_s.split(/\s+/).each do |param|
          key, value = param.split("=", 2)
          case key.upcase
          when "SIZE"
            unless value.to_s.match?(/\A\d+\z/)
              error_reply 501, "5.5.4 Invalid SIZE value"
              return false
            end
            if value.to_i > max_message_bytes
              reply 552, "5.3.4 Message size exceeds maximum permitted"
              return false
            end
          when "BODY"
            unless value.to_s.match?(/\A(7BIT|8BITMIME)\z/i)
              error_reply 501, "5.5.4 Invalid BODY value"
              return false
            end
          when "AUTH" # accepted, ignored
          when "REQUIRETLS"
            # RFC 8689 4.2: only advertised - and only acceptable - on a
            # TLS session; the promise must hold on the hop it rides in on.
            unless @tls
              error_reply 530, "5.7.4 REQUIRETLS requires a TLS session"
              return false
            end
            unless value.nil?
              error_reply 501, "5.5.4 REQUIRETLS takes no value"
              return false
            end
            @mail_requiretls = true
          when "RET", "ENVID"
            unless dsn_offered?
              error_reply 555, "5.5.4 MAIL parameter not recognized"
              return false
            end
            if key.casecmp?("RET")
              unless value.to_s.match?(/\A(FULL|HDRS)\z/i)
                error_reply 501, "5.5.4 Invalid RET value"
                return false
              end
              @dsn_ret = value.upcase
            else
              unless value.to_s.length <= MAX_ENVID && value.to_s.match?(XTEXT)
                error_reply 501, "5.5.4 Invalid ENVID value"
                return false
              end
              @dsn_envid = value
            end
          when "SMTPUTF8"
            # RFC 6531: legal only when advertised (a named refusal rather
            # than the generic 555 when it is not); takes no value.
            unless smtputf8_offered?
              error_reply 555, "5.6.7 SMTPUTF8 not supported"
              return false
            end
            unless value.nil?
              error_reply 501, "5.5.4 SMTPUTF8 takes no value"
              return false
            end
            @mail_smtputf8 = true
          else
            error_reply 555, "5.5.4 MAIL parameter not recognized"
            return false
          end
        end
        true
      end

      # DSN is advertised on submission listeners only (see ehlo).
      def dsn_offered?
        @spec[:role] == :submission
      end

      # The validated UTF-8 form of an SMTPUTF8 address (RFC 6531), or nil
      # for byte sequences that are not UTF-8. Tagging the encoding here
      # keeps later interpolation into log lines and store fields from
      # raising Encoding::CompatibilityError on raw high bytes.
      def as_utf8(address)
        utf8 = address.dup.force_encoding(Encoding::UTF_8)
        utf8.valid_encoding? ? utf8 : nil
      end

      def rcpt_to(arg)
        return error_reply 503, "5.5.1 Need MAIL command first" unless @mail_from
        # RFC 5321 4.5.5: a null reverse-path (a bounce) goes to exactly
        # one recipient. Accepting more would let a forged bounce fan out
        # across every hosted mailbox - a backscatter amplifier.
        if @mail_from.empty? && @rcpt_to.any?
          return error_reply 501, "5.5.4 Error: too many recipients for null sender"
        end
        return reply 452, "4.5.3 Error: too many recipients" if @rcpt_to.size >= MAX_RECIPIENTS

        # Same control-byte guard as mail_from: a bare CR/LF/NUL in the
        # recipient is log-injection material (the reject path logs
        # <#{recipient}> before refusing) and has no place in a real address.
        return error_reply 501, "5.5.4 Syntax: RCPT TO:<address>" if arg.to_s.match?(/[[:cntrl:]]/)

        unless arg =~ /\ATO:\s*<([^>]+)>\s*(.*)\z/im
          return error_reply 501, "5.5.4 Syntax: RCPT TO:<address>"
        end

        recipient = Regexp.last_match(1)
        params = Regexp.last_match(2)
        unless recipient.ascii_only?
          # RFC 6531 3.7: non-ASCII recipients only inside an SMTPUTF8
          # transaction, and only as well-formed UTF-8.
          return reply 553, "5.6.7 Non-ASCII address requires the SMTPUTF8 extension" unless @mail_smtputf8
          return error_reply 501, "5.6.7 Address is not valid UTF-8" unless (recipient = as_utf8(recipient))
        end

        # RFC 5321 s4.5.1: a bare <postmaster> (no domain, any case) MUST
        # be accepted - it addresses the postmaster of this server, so it
        # resolves against our own hostname, an address every hosted
        # domain's mail-host aliases answer (Domain#ensure_postmaster_account!).
        # Only postmaster gets this carve-out: any other unqualified
        # recipient falls through to the usual rejection.
        recipient = "postmaster@#{server_name}" if recipient.match?(/\Apostmaster\z/i)

        dsn = accept_rcpt_parameters(params)
        return unless dsn
        # Local recipients (accounts and aliases) are accepted everywhere.
        # Remote recipients are accepted only from authenticated submission
        # (queued for outbound delivery) - the MX port stays local-only, so
        # we never open relay. A miss splits two ways: an unknown user in
        # a domain we host is a 5.1.1, anything else is refused as
        # relaying.
        lookup = @store.local_rcpts([ recipient ])
        unless Array(lookup[:local]).any? || relay_allowed?(recipient)
          @store.log(:info, "SMTP rejected recipient <#{recipient}> from <#{@mail_from}> (#{@spec[:role]}, #{peer_ip})")
          if Array(lookup[:unknown_in_local_domain]).any?
            return reply 550, "5.1.1 No such user here"
          end

          return reply 550, "5.7.1 Relaying denied"
        end

        # The per-account send quota, consumed per accepted recipient. The
        # per-IP limits upstream never see one stolen credential worked
        # from many botnet IPs; this does. Tempfail (not 5xx) so a
        # legitimate client that merely burst retries later.
        if @authenticated_as && !consume_send_quota
          @store.log(:warn, "SMTP recipient refused for #{@authenticated_as}: send quota exhausted (#{peer_ip})")
          return reply 452, "4.7.1 Error: sending quota exceeded"
        end

        @rcpt_to << recipient
        @rcpt_dsn << (dsn.empty? ? nil : dsn)
        reply 250, "2.1.5 Ok"
      end

      # RCPT parameters (RFC 3461): NOTIFY and ORCPT, both DSN-only and so
      # submission-only. Returns the parsed hash ({} when none), or nil
      # after replying on rejection.
      def accept_rcpt_parameters(params)
        dsn = {}
        params.to_s.split(/\s+/).each do |param|
          key, value = param.split("=", 2)
          unless dsn_offered? && %w[NOTIFY ORCPT].include?(key.upcase)
            error_reply 555, "5.5.4 RCPT parameter not recognized"
            return nil
          end

          if key.casecmp?("NOTIFY")
            values = value.to_s.upcase.split(",")
            unless values.any? && (values == [ "NEVER" ] || (values - %w[SUCCESS FAILURE DELAY]).empty?)
              error_reply 501, "5.5.4 Invalid NOTIFY value"
              return nil
            end
            dsn[:notify] = values.uniq.join(",")
          else
            addr_type, addr = value.to_s.split(";", 2)
            unless value.to_s.length <= MAX_ORCPT && !addr.to_s.empty? &&
                   addr_type.to_s.match?(/\A[A-Za-z0-9-]+\z/) && addr.match?(XTEXT)
              error_reply 501, "5.5.4 Invalid ORCPT value"
              return nil
            end
            dsn[:orcpt] = value
          end
        end
        dsn
      end

      def relay_allowed?(address)
        @spec[:role] == :submission && @authenticated_as &&
          address.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
      end

      # -- data --------------------------------------------------------------

      def data
        return error_reply 503, "5.5.1 Need RCPT command first" if @rcpt_to.empty?
        # RFC 3030 4.2: DATA and BDAT cannot mix within one transaction.
        return error_reply 503, "5.5.1 BDAT transaction in progress" if @bdat
        if @message_count >= max_messages_per_session
          return reply 421, "4.7.0 Error: too many messages"
        end

        reply 354, "End data with <CR><LF>.<CR><LF>"
        @continuation = data_continuation
      end

      # -- BDAT (RFC 3030 CHUNKING) ------------------------------------------
      #
      # Each BDAT declares an exact byte count, which is read raw off the
      # socket - no dot-stuffing, no terminator scanning, so none of DATA's
      # smuggling surface. Chunks accumulate until one is flagged LAST,
      # which runs the same acceptance pipeline as DATA's terminator.
      #
      # A malformed or mis-sequenced BDAT must still consume its declared
      # payload before the error reply - the byte count is the only framing
      # there is, and skipping it would desynchronize the command stream.
      # The exception is a declaration beyond twice the message cap: that
      # peer is flooding, so the reply goes out and the connection drops
      # (mirroring the DATA path's mid-payload cutoff).
      def bdat(arg)
        match = arg.to_s.match(/\A(\d{1,15})(?:[ \t]+(LAST))?[ \t]*\z/i)
        return error_reply 501, "5.5.4 Syntax: BDAT <octet-count> [LAST]" unless match

        size = match[1].to_i
        last = !match[2].nil?
        consumed_so_far = @bdat ? @bdat[:consumed] : 0

        if consumed_so_far + size > max_message_bytes * 2
          @store.log(:warn, "SMTP BDAT from <#{@mail_from}> refused: exceeds #{max_message_bytes} bytes (#{peer_ip})")
          reply 552, "5.3.4 Message exceeds maximum size"
          return :quit
        end

        if @rcpt_to.empty? || (@message_count >= max_messages_per_session && !@bdat)
          discard_exactly(size)
          if @rcpt_to.empty?
            error_reply 503, "5.5.1 Need RCPT command first"
          else
            reply 421, "4.7.0 Error: too many messages"
          end
          return nil
        end

        @bdat ||= { body: +"".b, consumed: 0 }
        read_bdat_chunk(size)

        if @bdat[:consumed] > max_message_bytes
          # Consumed for framing but never stored; the verdict lands on
          # LAST so a conformant client sees one clear 552.
          @bdat[:body].clear
          @bdat[:oversize] = true
        end

        if last
          oversize = @bdat[:oversize]
          body = @bdat[:body]
          @bdat = nil
          finish_data(oversize ? :overflow : body)
        else
          reply 250, "2.0.0 Ok: #{size} bytes"
        end
        nil
      end

      # Reads exactly +size+ payload bytes into the transaction buffer.
      # gets and read share the IO's buffer, so mixing them is safe.
      def read_bdat_chunk(size)
        remaining = size
        while remaining.positive?
          chunk = @socket.read([ remaining, 65_536 ].min)
          raise IOError, "connection lost mid-BDAT" if chunk.nil? || chunk.empty?

          @bdat[:consumed] += chunk.bytesize
          @bdat[:body] << chunk unless @bdat[:oversize]
          remaining -= chunk.bytesize
        end
      end

      # Consumes and drops a payload that arrived attached to a refused
      # BDAT, keeping the command stream in sync.
      def discard_exactly(size)
        remaining = size
        while remaining.positive?
          chunk = @socket.read([ remaining, 65_536 ].min)
          raise IOError, "connection lost mid-BDAT" if chunk.nil? || chunk.empty?

          remaining -= chunk.bytesize
        end
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
            reply 552, "5.3.4 Message exceeds maximum size"
            next :quit # peer kept flooding past the size limit
          end
          body << chunk if consumed <= max_message_bytes
          nil
        end
      end

      def finish_data(body)
        unless body.is_a?(String) # :overflow
          @store.log(:warn, "SMTP message from <#{@mail_from}> refused: exceeds #{max_message_bytes} bytes (#{peer_ip})")
          reply 552, "5.3.4 Message exceeds maximum size"
          reset
          return
        end

        # A canary session's mail is blackholed: capture the envelope and a
        # sample of the body for intel, answer a convincing fake queue id, and
        # store/relay nothing. Bypasses the whole scan/store cascade below, so
        # no SmtpOutboundMessage (no relay) and no InboundEmail are ever made.
        if @honeypot
          capture_relay_attempt(body)
          @message_count += 1
          @store.log(:info, "SMTP honeypot blackholed message from <#{@mail_from}> to #{recipient_summary} (#{peer_ip})")
          reply 250, "2.0.0 Ok: queued as #{SecureRandom.hex(8).upcase}"
          reset
          return
        end

        if received_loop?(body)
          @store.log(:warn, "SMTP rejected message from <#{@mail_from}>: mail loop detected (#{peer_ip})")
          reply 550, "5.4.6 Loop detected"
          reset
          return
        end

        # RFC 6409 MSA authorization: an authenticated submission's visible
        # From: (and Sender:, if present) must be an identity the login
        # owns - the account or one of its aliases. The envelope was
        # already held to that at MAIL FROM; without this check the header
        # every human actually reads could still claim anyone.
        if @authenticated_as && Settings[:smtp_from_alignment] && (problem = from_alignment_problem(body))
          @store.log(:warn, "SMTP refused submission from #{@authenticated_as}: #{problem} (#{peer_ip})")
          reply 550, "5.7.1 #{problem}"
          reset
          return
        end

        auth_results = nil
        if @spec[:role] == :mx && !@authenticated_as && sender_auth?
          verdict = verify_sender(body)
          if verdict == :error
            # A verifier bug is not a verdict: under enforcement a missing
            # verdict must not become an accept (the spoofed mail it was
            # meant to reject would sail through), so defer to the sender's
            # retry instead.
            if SenderAuth.enforce_dmarc?
              @store.log(:warn, "SMTP tempfail for message from <#{@mail_from}>: sender verification error under DMARC enforcement (#{peer_ip})")
              reply 451, "4.7.0 Sender verification unavailable, try again later"
              reset
              return
            end
            verdict = nil
          end
          auth_results = verdict&.summary
          if verdict&.dmarc_reject? && verdict.arc_trusted_pass?
            # Forwarding legitimately breaks SPF/DKIM; an intact ARC chain
            # from an operator-trusted sealer (mailing lists, forwarders)
            # is the sanctioned local-policy override (RFC 7489 6.7).
            @store.log(:info, "SMTP accepting DMARC reject from <#{@mail_from}>: ARC chain from " \
                              "trusted sealer #{verdict.arc_sealer} (#{auth_results}, #{peer_ip})")
            record_dmarc_event(verdict, disposition: "none",
                               reason: "arc=pass from trusted sealer #{verdict.arc_sealer}")
          elsif verdict&.dmarc_reject?
            if SenderAuth.enforce_dmarc?
              @store.log(:info, "SMTP rejected message from <#{@mail_from}>: DMARC policy (#{auth_results}, #{peer_ip})")
              record_dmarc_event(verdict, disposition: "reject")
              reply 550, "5.7.1 Rejected by DMARC policy for #{verdict.from_domain}"
              reset
              return
            end
            @store.log(:info, "SMTP would reject message from <#{@mail_from}> under DMARC enforcement (#{auth_results}, #{peer_ip})")
            record_dmarc_event(verdict, disposition: "none", reason: "p=reject not enforced (local policy)")
          elsif verdict&.temperror? && SenderAuth.enforce_dmarc? && SenderAuth.fail_closed?
            @store.log(:info, "SMTP tempfail for message from <#{@mail_from}>: DMARC temperror under enforcement (#{auth_results}, #{peer_ip})")
            reply 451, "4.7.0 Sender verification temporarily unavailable, try again later"
            reset
            return
          elsif verdict
            # Accepted with a verdict: pass, or a failure under p=none /
            # p=quarantine (the edge never quarantines - the mailroom's
            # junk-filing is the quarantine disposition).
            disposition = verdict.dmarc[:result] == :fail && verdict.dmarc[:policy] == :quarantine ? "quarantine" : "none"
            record_dmarc_event(verdict, disposition: disposition)
          end
        end

        # Our own trace header, prepended after the loop check (so we count
        # only prior hops) and before storage - RFC 5321 wants every
        # receiving host to stamp one, and it's what makes the loop guard
        # meaningful for the next hop.
        body = received_header + body

        # Virus scan after the cheap rejects (loop/DMARC) so refused mail
        # never costs a clamd round-trip. Policy: infected -> hard 550 plus a
        # stamped review copy quarantined app-side; scanner unreachable ->
        # 451 so the sending MTA retries (nothing skips scanning), also
        # quarantining an "unscanned" copy for review (deduped app-side by
        # Message-ID across those retries). The quarantine store result never
        # changes the reply - the verdict alone decided it.
        scan = scan_message(body)
        if scan&.infected?
          @store.log(:warn, "SMTP rejected message from <#{@mail_from}>: virus #{scan.virus} (#{peer_ip})")
          @store.quarantine(@mail_from, @rcpt_to, body, @authenticated_as,
                            client_ip: peer_ip, helo: @helo_name,
                            auth_results: auth_results, scan_status: "infected", virus: scan.virus)
          # The signature name stays server-side (log + quarantine row): echoing
          # it in the reply hands a hostile sender an oracle for tuning payload
          # packing until the scanner goes quiet.
          reply 550, "5.7.1 Message rejected: virus detected"
          reset
          return
        elsif scan&.unavailable?
          @store.log(:error, "SMTP tempfail for message from <#{@mail_from}>: virus scanner unavailable (#{peer_ip})")
          @store.quarantine(@mail_from, @rcpt_to, body, @authenticated_as,
                            client_ip: peer_ip, helo: @helo_name,
                            auth_results: auth_results, scan_status: "unscanned")
          reply 451, "4.7.1 Virus scanner unavailable, try again later"
          reset
          return
        end

        # Outbound spam gate for authenticated senders - the only content
        # check that path gets (the mailroom's rspamd pass deliberately
        # skips authenticated mail as trusted), and the tripwire for a
        # compromised account pumping phishing text that clamav has no
        # signature for. Only rspamd's own refusal actions refuse here;
        # milder verdicts pass. An unreachable rspamd DEFERS submission by
        # default (smtp_rspamd_fail_closed defaults on, like clamav's 451)
        # - a compromised account must not spam unscored through an
        # outage; SMTP_RSPAMD_FAIL_CLOSED=0 is the fail-open opt-out for
        # deployments that would rather keep users sending than wait out
        # a scorer outage.
        spam = @authenticated_as ? submission_spam_verdict(body) : nil
        if spam&.reject? || spam&.soft_reject?
          @store.log(:warn, "SMTP refused submission from #{@authenticated_as}: rspamd action=#{spam.action} " \
                            "score=#{spam.score}/#{spam.required_score} (#{peer_ip})")
          if spam.reject?
            reply 550, "5.7.1 Message rejected as spam"
          else
            reply 451, "4.7.1 Message deferred by content filter, try again later"
          end
          reset
          return
        elsif spam&.greylist? && Settings[:smtp_rspamd_greylist]
          # rspamd asked for greylisting: a 451 a real MTA retries after
          # its window, and a spam cannon usually never does.
          @store.log(:info, "SMTP greylisted submission from #{@authenticated_as}: rspamd action=greylist " \
                            "score=#{spam.score}/#{spam.required_score} (#{peer_ip})")
          reply 451, "4.7.1 Greylisted, try again later"
          reset
          return
        elsif spam&.unavailable? && Settings[:smtp_rspamd_fail_closed]
          @store.log(:warn, "SMTP deferred submission from #{@authenticated_as}: rspamd unavailable, " \
                            "fail-closed (#{peer_ip})")
          reply 451, "4.7.1 Content filter unavailable, try again later"
          reset
          return
        end

        result = @store.smtp_store(@mail_from, @rcpt_to, body, @authenticated_as,
                                   client_ip: peer_ip, helo: @helo_name,
                                   auth_results: auth_results, scan_status: scan && "clean",
                                   requiretls: @mail_requiretls, smtputf8: @mail_smtputf8,
                                   dsn: dsn_envelope)
        if result[:code] == :insufficient_storage
          @store.log(:warn, "SMTP message from <#{@mail_from}> refused: insufficient storage (#{peer_ip})")
          reply 452, "4.3.1 Insufficient system storage, try later"
        elsif result[:code] == :relay_denied
          @store.log(:warn, "SMTP message from <#{@mail_from}> refused: relay denied (#{peer_ip})")
          reply 550, "5.7.1 Relaying denied"
        elsif result[:error]
          reply 451, "4.3.0 Requested action aborted: local error in processing"
        else
          @message_count += 1
          auth_note = @authenticated_as ? ", auth #{@authenticated_as}" : ""
          @store.log(:info, "SMTP accepted message #{result[:id]} from <#{@mail_from}> to #{recipient_summary} " \
                            "(#{body.bytesize} bytes, #{@spec[:role]}#{auth_note}, #{peer_ip})")
          reply 250, "2.0.0 Ok: queued as #{result[:id]}"
        end
        reset
      end

      # The transaction's DSN request (RFC 3461) as one value for the
      # store, or nil when the client asked for nothing - the common case,
      # which keeps the store contract's default signature unchanged.
      def dsn_envelope
        recipients = {}
        @rcpt_to.each_with_index do |recipient, i|
          recipients[recipient] = @rcpt_dsn[i] if @rcpt_dsn[i]
        end
        return nil unless @dsn_ret || @dsn_envid || recipients.any?

        { ret: @dsn_ret, envid: @dsn_envid, recipients: recipients }
      end

      # Appends a blackholed canary submission to the transcript: the envelope
      # and a bounded sample of the body (the ring buffer caps the rest), so a
      # spam relay attempt is captured without the whole payload bloating it.
      def capture_relay_attempt(body)
        honeypot_transcript.inbound("DATA MAIL FROM:<#{@mail_from}> RCPT TO: #{@rcpt_to.join(", ")}")
        honeypot_transcript.inbound(body.byteslice(0, Netserv::HoneypotSession::HONEYPOT_BODY_SAMPLE).to_s)
      end

      # The addresses the authenticated login may claim: its account plus
      # that account's aliases, from the store (older stores without the
      # contract method, or a store outage, fall back to the account alone
      # - the pre-alias behavior, never an open gate). Memoized: the set
      # cannot change in a way this session must honor mid-connection.
      def permitted_senders
        @permitted_senders ||= begin
          addresses = @store.respond_to?(:sender_addresses) ? @store.sender_addresses(@authenticated_as) : nil
          addresses = addresses.is_a?(Array) ? addresses.map { |a| a.to_s.strip.downcase }.reject(&:empty?) : []
          addresses.empty? ? [ @authenticated_as.to_s.downcase ] : addresses
        end
      end

      # Why an authenticated submission's headers fail MSA authorization
      # (RFC 6409), or nil when they pass. Unparseable headers read as
      # unauthorizable, never as a pass.
      def from_alignment_problem(body)
        froms = SenderAuth::FromHeader.addresses(body)
        return "message has no From header" if froms.nil?
        if froms.empty? || froms.any? { |a| a.nil? || !permitted_senders.include?(a) }
          return "From address must be the authenticated account or one of its aliases"
        end

        senders = SenderAuth::FromHeader.addresses(body, field: "sender")
        if senders&.any? { |a| a.nil? || !permitted_senders.include?(a) }
          return "Sender address must be the authenticated account or one of its aliases"
        end

        nil
      end

      # SPF/DKIM/DMARC switch: per-listener spec[:sender_auth] wins (the
      # test seam - worker Ractors cannot read ENV at runtime), else the
      # load-time SMTP_SENDER_AUTH default.
      def sender_auth?
        @spec.fetch(:sender_auth) { SenderAuth.enabled? }
      end

      # SPF/DKIM/DMARC for unauthenticated MX mail. DNS-heavy but bounded
      # (per-query timeouts, SPF lookup limits, capped DKIM signatures);
      # runs on this session's thread. Never lets a verifier bug take the
      # session down - a raise becomes :error, which the DATA handler
      # tempfails under enforcement rather than treating as a pass.
      def verify_sender(body)
        SenderAuth.verify(ip: peer_ip, helo: @helo_name, mail_from: @mail_from, data: body)
      rescue StandardError => e
        @store.log(:error, "SMTP sender verification error: #{e.class}: #{e.message}")
        :error
      end

      # One row of RFC 7489 aggregate-report evidence, recorded through the
      # store for every evaluated message whose From domain publishes a
      # DMARC record (SendDmarcReportsJob rolls them up into the daily
      # reports its rua= asked for). Best-effort telemetry riding the
      # acceptance path: never changes the reply, and skipped entirely for
      # stores predating the contract method.
      def record_dmarc_event(verdict, disposition:, reason: nil)
        return unless Settings[:smtp_dmarc_reports]
        return unless @store.respond_to?(:dmarc_event)

        dmarc = verdict.dmarc
        # No published record means no rua to report to; temperror and
        # permerror carry no evaluation worth aggregating.
        return unless dmarc[:domain] && %i[pass fail].include?(dmarc[:result])

        published = dmarc[:published] || {}
        spf = verdict.spf || {}
        dkim = Array(verdict.dkim).first(5).map { |s| "#{s[:domain]}=#{s[:result]}" }.join(",")
        @store.dmarc_event(
          policy_domain: dmarc[:domain], from_domain: dmarc[:from_domain],
          source_ip: peer_ip, envelope_from: @mail_from,
          disposition: disposition, override_reason: reason,
          dkim_aligned: dmarc[:dkim_aligned] || false, spf_aligned: dmarc[:spf_aligned] || false,
          spf_result: spf[:result]&.to_s, spf_domain: spf[:domain],
          dkim_results: dkim,
          policy_p: published[:p], policy_sp: published[:sp],
          policy_adkim: published[:adkim], policy_aspf: published[:aspf],
          policy_pct: published[:pct]
        )
      rescue StandardError => e
        @store.log(:error, "SMTP DMARC event not recorded: #{e.class}: #{e.message}")
      end

      # FCrDNS facts for this peer (PTR name, forward confirmation, HELO
      # match), resolved once per session for unauthenticated MX traffic.
      # Advisory only: the confirmed name decorates the Received header and
      # a mismatch earns a log line - strong spam-filter signals, but never
      # a rejection by themselves (plenty of legitimate small senders fail
      # one or the other). spec[:fcrdns] is the test seam; a checker bug
      # just means no facts.
      def client_dns
        return @client_dns if defined?(@client_dns)

        @client_dns = nil
        return nil unless @spec[:role] == :mx && !@authenticated_as

        checker = @spec.fetch(:fcrdns) { Settings[:smtp_fcrdns] ? Smtp::FcrDns.shared : nil }
        return nil unless checker

        result = checker.check(peer_ip, helo: @helo_name)
        if result && (!result.fcrdns || result.helo_matches == false)
          @store.log(:info, "SMTP FCrDNS for #{peer_ip}: ptr=#{result.ptr_name || "unconfirmed"} " \
                            "helo=#{@helo_name} helo_matches=#{result.helo_matches.nil? ? "n/a" : result.helo_matches}")
        end
        @client_dns = result
      rescue StandardError => e
        @store.log(:error, "SMTP FCrDNS check error: #{e.class}: #{e.message}")
        @client_dns = nil
      end

      # DNSBL verdict for this peer: the configured zone that lists it, or
      # nil. Checked only for unauthenticated MX traffic - authenticated
      # clients vouch for themselves - and at MAIL FROM rather than at
      # connect, so a legitimate sender stuck on a listed IP can still
      # STARTTLS + AUTH its way in. spec[:dnsbl] is the test seam (worker
      # Ractors cannot read ENV at runtime; the default checker's zones are
      # parsed at load, its verdict cache shared per worker thread). Never
      # lets a checker bug refuse mail - failure just means no verdict.
      def rbl_listing
        return nil unless @spec[:role] == :mx && !@authenticated_as

        checker = @spec.fetch(:dnsbl) { Smtp::Dnsbl.shared }
        checker&.listed(peer_ip)
      rescue StandardError => e
        @store.log(:error, "SMTP DNSBL check error: #{e.class}: #{e.message}")
        nil
      end

      # ClamAV verdict for the message body, nil when scanning is disabled
      # (no clamd address configured). Per-listener spec keys override the
      # env-derived defaults, mirroring max_message_bytes - and doubling as
      # the test seam, since worker Ractors cannot read ENV at runtime.
      def scan_message(body)
        addr = @spec.fetch(:clamav_addr) { Settings[:smtp_clamav_addr] }.to_s
        return nil if addr.empty?

        timeout = @spec[:clamav_timeout] || Settings[:smtp_clamav_timeout]
        ClamavClient.new(addr: addr, timeout: timeout).scan(body)
      end

      # One recipient slot from the authenticated account's send quota;
      # true when consumed (or no quota is active). spec[:send_quota] is
      # the test seam - an instance overrides, nil disables - else the
      # process-wide default built from load-time env.
      def consume_send_quota
        quota = @spec.fetch(:send_quota) { SendQuota.shared }
        return true unless quota

        quota.consume(@authenticated_as)
      end

      # rspamd's verdict for an authenticated submission, nil when rspamd
      # is not configured. Per-listener spec keys override the env-derived
      # defaults, mirroring clamav_addr - and doubling as the test seam.
      # The authenticated user is forwarded so rspamd applies its
      # authenticated-sender policy; transport failure comes back as an
      # :unavailable Result (never raises), which the caller passes.
      def submission_spam_verdict(body)
        addr = @spec.fetch(:rspamd_addr) { RspamdAnalyzer.addr }.to_s
        return nil if addr.empty?

        timeout = @spec[:rspamd_timeout] || RspamdAnalyzer.timeout
        verdict = RspamdAnalyzer.analyze(body, addr: addr, timeout: timeout,
                                         ip: peer_ip, helo: @helo_name, mail_from: @mail_from,
                                         rcpt: @rcpt_to.first, authenticated_as: @authenticated_as)
        if verdict.unavailable?
          @store.log(:warn, "SMTP submission from #{@authenticated_as} accepted unscored: rspamd unavailable (#{peer_ip})")
        else
          @store.log(:info, "SMTP rspamd action=#{verdict.action} score=#{verdict.score} " \
                            "for submission from #{@authenticated_as} (#{peer_ip})")
        end
        verdict
      end

      def recipient_summary
        shown = @rcpt_to.first(3).map { |r| "<#{r}>" }.join(" ")
        @rcpt_to.size > 3 ? "#{shown} +#{@rcpt_to.size - 3} more" : shown
      end

      # Our RFC 5321 §4.4 trace header. The WITH protocol keyword follows
      # RFC 3848: ESMTP, +S when the channel is TLS, +A when the client
      # authenticated. On MX traffic the TCP-info comment carries the
      # forward-confirmed PTR name (or "unknown") next to the address, the
      # classic sendmail/postfix form downstream filters read.
      def received_header
        with = +"ESMTP"
        with << "S" if @tls
        with << "A" if @authenticated_as
        helo = @helo_name.to_s.empty? ? "unknown" : sanitize_reply(@helo_name)
        source = if (dns = client_dns)
          "#{sanitize_reply(dns.ptr_name || "unknown")} [#{peer_ip}]"
        else
          "[#{peer_ip}]"
        end
        "Received: from #{helo} (#{source})\r\n" \
        "\tby #{server_name} with #{with}; #{Time.now.rfc2822}\r\n"
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
        honeypot_transcript.outbound("#{code} #{text}")
        write_reply("#{code} #{text}\r\n", code)
      end

      def multi(code, lines)
        lines.each_with_index do |text, i|
          text = sanitize_reply(text)
          separator = i == lines.length - 1 ? " " : "-"
          trace "=> #{code}#{separator}#{text}"
          honeypot_transcript.outbound("#{code}#{separator}#{text}")
          write_reply("#{code}#{separator}#{text}\r\n", code)
        end
      end

      # Every reply leaves through here so a transport failure can name the
      # reply that was lost. A reply that dies in flight is not just a
      # hung-up client: the sender treats the transaction as failed and
      # redelivers, so the disconnect log line must say which reply never
      # made it.
      def write_reply(bytes, code)
        @socket.write(bytes)
      rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
        @lost_reply ||= code
        raise
      end

      # The peer vanished mid-session (reset, TLS teardown, EPIPE). Never
      # swallowed silently: a loss that races the final reply of a
      # transaction means the sender redelivers an already-stored message,
      # and this line is the only server-side witness. Plain pre-transaction
      # drops (scanners, probes) stay at :info.
      def log_connection_lost(error)
        detail = "#{error.class}: #{error.message}"
        if @lost_reply
          @store.log(:warn, "SMTP connection lost while sending #{@lost_reply} reply: #{detail} " \
                            "(#{@message_count} accepted this session, #{peer_ip})")
        elsif @message_count.positive?
          @store.log(:warn, "SMTP connection lost after #{@message_count} accepted: #{detail} (#{peer_ip})")
        else
          @store.log(:info, "SMTP connection lost: #{detail} (#{peer_ip})")
        end
      end

      def sanitize_reply(text)
        text.to_s.gsub(/[^[:print:]]/, " ")
      end
    end
  end
end
