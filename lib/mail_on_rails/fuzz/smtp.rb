# frozen_string_literal: true

require "socket"
require "stringio"
require "logger"
require "timeout"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

module MailOnRails
  module Fuzz
    # Stateful SMTP fuzz harness: grammar-shaped sessions with per-step
    # mutations plus pure-garbage rounds. Runs against the in-memory store on
    # loopback (no Rails, no database).
    class Smtp < Runner
      EMAIL = "fuzz-user@example.test"
      PASSWORD = "pw-fuzz-123456"
      FOREIGN = "victim@foreign.test"
      PROFILES = %i[garbage mx_relay_attempt submission_no_auth auth_garbage
                    stateful_delivery data_smuggle pipelined].freeze
      # Profiles whose grammar is adversarial by construction: a dropped
      # connection is always a legitimate server response for these.
      GARBAGE_PROFILES = %i[garbage auth_garbage pipelined data_smuggle].freeze

      def initialize(**kwargs)
        super
        @logs = StringIO.new
      end

      def run
        disable_sender_verification
        super
      ensure
        restore_sender_verification
      end

      def run_round(index)
        @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(@logs = StringIO.new))
        @store.add_account(email: EMAIL, password: PASSWORD)
        inbound_before = @store.inbound_messages.size
        outbound_before = @store.outbound_messages.size
        @state = fresh_state
        @profile = pick(PROFILES)
        mutator.reset!

        run_profile(@profile)
        check_oracles(index, inbound_before, outbound_before)
      rescue StandardError => e
        if tolerable_io_error?(e)
          check_oracles(index, inbound_before, outbound_before)
        else
          fail(index, @profile || :unknown, "uncaught client error: #{e.class}: #{e.message}")
        end
      end

      # Structured profiles tolerate IO errors only when a mutation actually
      # fired this round: a line mutated into e.g. "QUIT <junk>" makes the
      # server close the connection legitimately, and the harness's next
      # write then hits EPIPE. Clean rounds keep the strict check, and the
      # oracles run either way.
      def tolerable_io_error?(error)
        return false unless GARBAGE_PROFILES.include?(@profile) || mutator.mutated?

        error.is_a?(IOError) || error.is_a?(SystemCallError) || error.is_a?(Timeout::Error)
      end

      private

      def fresh_state
        {
          role: :mx, tls: :starttls, authenticated: false, mail_from: nil,
          foreign_rcpt: false, completed_data: false, relay_attempted: false
        }
      end

      def disable_sender_verification
        singleton = MailOnRails::SenderAuth.singleton_class
        @sender_auth_original = MailOnRails::SenderAuth.method(:verify)
        singleton.define_method(:verify) { |**| nil }
      end

      def restore_sender_verification
        return unless @sender_auth_original

        MailOnRails::SenderAuth.singleton_class.define_method(:verify, @sender_auth_original)
        @sender_auth_original = nil
      end

      def run_profile(profile)
        case profile
        when :garbage then run_garbage
        when :mx_relay_attempt then run_mx_relay
        when :submission_no_auth then run_submission_no_auth
        when :auth_garbage then run_auth_garbage
        when :stateful_delivery then run_stateful_delivery
        when :data_smuggle then run_data_smuggle
        when :pipelined then run_pipelined
        end
      end

      def wire_spec
        { role: @state[:role], tls: @state[:tls] }
      end

      def with_client(&block)
        server = TCPServer.new("127.0.0.1", 0)
        client = TCPSocket.new("127.0.0.1", server.addr[1])
        client.timeout = config.timeout
        accepted = server.accept
        spec = {
          host: "127.0.0.1", port: server.addr[1], tls: @state[:tls], role: @state[:role],
          hostname: "fuzz.test", sender_auth: false, clamav_addr: "", rspamd_addr: ""
        }
        thread = Thread.new do
          MailOnRails::SmtpServer::Session.new(accepted, @store, spec, nil).run
        end
        block.call(client)
      ensure
        close_client(client)
        accepted&.close rescue nil
        thread&.join(config.timeout)
        thread&.kill if thread&.alive?
        server&.close
      end

      def close_client(client)
        return unless client

        client.shutdown(Socket::SHUT_RDWR) rescue nil
        client.close rescue nil
      end

      def read_reply(client)
        lines = []
        Timeout.timeout(config.timeout) do
          while (line = client.gets("\r\n"))
            lines << line
            break if line.bytesize >= 4 && line[3] == " "
          end
        end
        lines.join
      rescue Timeout::Error
        raise IOError, "timed out waiting for SMTP reply"
      end

      def write_line(client, line) = client.write("#{line}\r\n")

      def command(client, line)
        write_line(client, line)
        read_reply(client)
      end

      def safe_data(client)
        reply = command(client, "DATA") rescue nil
        return unless reply&.start_with?("354")

        body = mutator.malicious_body
        client.write(body) rescue nil
        client.write(".\r\n") unless body.end_with?(".\r\n")
        read_reply(client) rescue nil
      end

      def drain_replies(client, max: 8)
        max.times { read_reply(client) }
      rescue IOError, SystemCallError, Timeout::Error
        nil
      end

      def run_garbage
        @state[:role] = pick([ :mx, :submission ])
        @state[:tls] = pick([ :starttls, :implicit ])
        with_client do |client|
          read_reply(client)
          @rng.rand(1..6).times do
            write_line(client, mutator.garbage_line)
            read_reply(client) rescue nil
          end
          write_line(client, pick([ "QUIT", "RSET", mutator.garbage_line ]))
          read_reply(client) rescue nil
        end
      end

      def run_mx_relay
        @state[:relay_attempted] = true
        @state[:foreign_rcpt] = true
        with_client do |client|
          read_reply(client)
          command(client, mutator.maybe("EHLO fuzz-client.test"))
          command(client, "MAIL FROM:<#{mutator.email(local: 'attacker', domain: 'evil.test')}>")
          reply = command(client, "RCPT TO:<#{FOREIGN}>")
          if reply.start_with?("250")
            @state[:completed_data] = true
            safe_data(client)
          end
          command(client, "QUIT") rescue nil
        end
      end

      def run_submission_no_auth
        @state[:role] = :submission
        @state[:tls] = :implicit
        @state[:foreign_rcpt] = true
        with_client do |client|
          read_reply(client)
          command(client, "EHLO fuzz-client.test")
          command(client, "MAIL FROM:<#{EMAIL}>")
          command(client, "RCPT TO:<#{FOREIGN}>")
          command(client, "DATA") rescue nil
          command(client, "QUIT") rescue nil
        end
      end

      def run_auth_garbage
        @state[:role] = :submission
        @state[:tls] = :implicit
        with_client do |client|
          read_reply(client)
          command(client, "EHLO fuzz-client.test")
          @rng.rand(1..4).times do
            write_line(client, "AUTH PLAIN #{mutator.garbage_line}")
            reply = read_reply(client) rescue nil
            break if reply&.start_with?("421")
          end
          command(client, "QUIT") rescue nil
        end
      end

      def run_stateful_delivery
        if @rng.rand < 0.5
          run_mx_local_delivery
        else
          run_submission_authenticated
        end
      end

      def run_mx_local_delivery
        @state[:mail_from] = "sender@remote.test"
        with_client do |client|
          read_reply(client)
          command(client, "EHLO fuzz-client.test")
          command(client, "MAIL FROM:<sender@remote.test>")
          command(client, "RCPT TO:<#{EMAIL}>")
          safe_data(client)
          @state[:completed_data] = true
          command(client, "QUIT") rescue nil
        end
      end

      def run_submission_authenticated
        @state[:role] = :submission
        @state[:tls] = :implicit
        token = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
        with_client do |client|
          read_reply(client)
          command(client, "EHLO fuzz-client.test")
          auth_reply = command(client, "AUTH PLAIN #{token}")
          return unless auth_reply.start_with?("235")

          @state[:authenticated] = true
          from = @rng.rand < 0.3 ? mutator.email(local: "spoof", domain: "evil.test") : EMAIL
          @state[:mail_from] = from
          mail_reply = command(client, "MAIL FROM:<#{from}>")
          return unless mail_reply.start_with?("250")

          @state[:foreign_rcpt] = true
          @state[:relay_attempted] = true
          command(client, "RCPT TO:<#{FOREIGN}>")
          safe_data(client)
          @state[:completed_data] = true
          command(client, "QUIT") rescue nil
        end
      end

      def run_data_smuggle
        @state[:mail_from] = "sender@remote.test"
        with_client do |client|
          read_reply(client)
          command(client, "EHLO fuzz-client.test")
          command(client, "MAIL FROM:<sender@remote.test>")
          command(client, "RCPT TO:<#{EMAIL}>")
          safe_data(client)
          write_line(client, mutator.maybe("RCPT TO:<#{FOREIGN}>"))
          drain_replies(client)
        end
      end

      def run_pipelined
        @state[:role] = pick([ :mx, :submission ])
        @state[:tls] = :implicit
        with_client do |client|
          read_reply(client)
          command(client, "EHLO fuzz-client.test")
          burst = @rng.rand(5..15)
          burst.times { write_line(client, pick([ "NOOP", "RSET", mutator.garbage_line ])) }
          burst.times do
            read_reply(client)
          rescue IOError, SystemCallError, Timeout::Error
            break
          end
          command(client, "QUIT") rescue nil
        end
      end

      def check_oracles(round, inbound_before, outbound_before)
        log = @logs.string
        if log.include?("SMTP session error")
          fail(round, @profile, "session crashed", log[/SMTP session error.*/]&.strip)
        end

        inbound_delta = @store.inbound_messages.size - inbound_before
        outbound_delta = @store.outbound_messages.size - outbound_before

        if @profile == :garbage
          fail(round, @profile, "garbage stored inbound mail") if inbound_delta.positive?
          fail(round, @profile, "garbage stored outbound mail") if outbound_delta.positive?
        end

        if @state[:relay_attempted] && !@state[:authenticated]
          fail(round, @profile, "unauthenticated relay stored outbound mail") if outbound_delta.positive?
        end

        if @state[:role] == :submission && !@state[:authenticated]
          fail(round, @profile, "unauthenticated submission stored outbound mail") if outbound_delta.positive?
        end

        if @state[:authenticated] && @state[:mail_from] && !@state[:mail_from].casecmp?(EMAIL)
          fail(round, @profile, "envelope spoof stored outbound mail") if outbound_delta.positive?
        end

        if @profile == :data_smuggle && inbound_delta.positive?
          last = @store.inbound_messages.last
          if last[:data].include?("RCPT TO:")
            fail(round, @profile, "DATA smuggling injected RCPT into body", last[:data][0, 120])
          end
        end

        outbound_delta.times do |offset|
          row = @store.outbound_messages[outbound_before + offset]
          next unless row[:mail_from]

          unless row[:mail_from].casecmp?(EMAIL)
            fail(round, @profile, "outbound mail_from does not match authenticated identity", row.inspect)
          end
        end
      end
    end
  end
end
