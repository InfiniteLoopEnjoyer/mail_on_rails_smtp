# frozen_string_literal: true

require "socket"
require "timeout"
require_relative "config"

module MailOnRails
  module Smtp
    # Streams a raw RFC822 message to a clamd daemon over its INSTREAM
    # protocol and reports a three-way verdict: :clean, :infected (with the
    # signature name), or :unavailable (clamd unreachable, timed out, or
    # answered something unparseable - including its own size-limit error).
    # The session decides policy; this client never raises.
    #
    # clamd decodes MIME itself, so the whole message is streamed as one
    # chunk - no attachment splitting (same approach as Postal).
    class ClamavClient
      Result = Struct.new(:status, :virus) do
        def clean? = status == :clean
        def infected? = status == :infected
        def unavailable? = status == :unavailable
      end

      DEFAULT_PORT = 3310

      # Read at load time because sessions run inside worker Ractors, which
      # cannot access ENV; per-listener spec[:clamav_addr]/[:clamav_timeout]
      # override these (the test seam). Unset/empty addr disables scanning.
      ADDR = ENV["SMTP_CLAMAV_ADDR"].to_s.strip.freeze
      TIMEOUT = Smtp::Config.int("SMTP_CLAMAV_TIMEOUT", 10, min: 1)

      def self.enabled? = !ADDR.empty?

      def initialize(addr: ADDR, timeout: TIMEOUT)
        host, port = addr.to_s.split(":", 2)
        @host = host
        @port = (port || DEFAULT_PORT).to_i
        @timeout = timeout
      end

      def scan(raw)
        reply = nil
        Timeout.timeout(@timeout) do
          socket = TCPSocket.new(@host, @port)
          begin
            socket.write("zINSTREAM\0")
            socket.write([ raw.bytesize ].pack("N"))
            socket.write(raw)
            socket.write([ 0 ].pack("N"))
            socket.close_write
            reply = socket.read
          ensure
            begin
              socket.close
            rescue IOError
              nil
            end
          end
        end
        parse(reply)
      rescue Timeout::Error, SystemCallError, IOError, SocketError
        Result.new(:unavailable, nil)
      end

      private

      # clamd answers "stream: OK" or "stream: <Signature> FOUND" (NUL/LF
      # terminated); anything else (error line, truncated reply) counts as
      # unavailable rather than clean.
      def parse(reply)
        case reply.to_s
        when /\Astream: OK[\s\0]*\z/i then Result.new(:clean, nil)
        when /\Astream: (.+?) FOUND[\s\0]*\z/i then Result.new(:infected, Regexp.last_match(1).strip)
        else Result.new(:unavailable, nil)
        end
      end
    end
  end
end
