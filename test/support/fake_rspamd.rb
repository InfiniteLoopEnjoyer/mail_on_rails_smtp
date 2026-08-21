# frozen_string_literal: true

require "socket"
require "json"

# Scripted rspamd stand-in for the /checkv2 HTTP endpoint: reads one POST
# per connection, answers with the given action, and keeps the request
# headers so tests can assert what the client forwarded (and whether it
# called at all). Modeled on FakeClamd.
#
#   FakeRspamd.serving("reject") { |addr, fake| ... }   # "127.0.0.1:<port>"
class FakeRspamd
  attr_reader :requests # one {headers:, body:} per handled request

  def initialize(action, score: 15.0, required_score: 15.0)
    @action = action
    @score = score
    @required_score = required_score
    @requests = []
  end

  def self.serving(action, **options)
    fake = new(action, **options)
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      loop do
        conn = server.accept
        fake.handle(conn)
        conn.close
      end
    rescue IOError, Errno::EBADF
      nil # server closed - test is done
    end
    yield "127.0.0.1:#{server.addr[1]}", fake
  ensure
    thread&.kill
    server&.close
  end

  def handle(conn)
    request_line = conn.gets("\r\n")
    headers = {}
    while (line = conn.gets("\r\n")) && line != "\r\n"
      key, value = line.chomp.split(":", 2)
      headers[key.downcase] = value.to_s.strip
    end
    body = conn.read(headers["content-length"].to_i)
    @requests << { line: request_line, headers: headers, body: body }

    payload = JSON.generate({ "action" => @action, "score" => @score,
                              "required_score" => @required_score, "symbols" => {} })
    conn.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" \
               "Content-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}")
  end
end
