# frozen_string_literal: true

require "socket"

# Scripted clamd stand-in for the INSTREAM protocol: reads whatever the
# client streams (the client half-closes when done), then answers per mode.
# The automated suites use only this fake - real-engine verification is the
# manual EICAR smoke against a clamav/clamav container (see README).
#
#   FakeClamd.serving(:infected) { |addr| ... }   # "127.0.0.1:<port>"
#
# Modes: :clean, :infected, :garbage (unparseable reply), :hang (consume the
# stream, never answer - exercises the client timeout).
class FakeClamd
  REPLIES = {
    clean: "stream: OK\0",
    infected: "stream: Eicar-Test-Signature FOUND\0",
    garbage: "INSTREAM size limit exceeded. ERROR\0"
  }.freeze

  def self.serving(mode)
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      loop do
        conn = server.accept
        conn.read # everything up to the client's close_write
        if mode == :hang
          sleep
        else
          conn.write(REPLIES.fetch(mode))
        end
        conn.close
      end
    rescue IOError, Errno::EBADF
      nil # server closed - test is done
    end
    yield "127.0.0.1:#{server.addr[1]}"
  ensure
    thread&.kill
    server&.close
  end
end
