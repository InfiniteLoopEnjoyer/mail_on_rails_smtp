# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp/internal_api"
require "mail_on_rails/smtp/ingress_client"

# The HTTP clients must reuse keep-alive connections across requests (one
# TCP connect per burst, not per call) while keeping the no-retry policy: a
# failed request discards its connection and surfaces the error, and the
# next request dials fresh.
class HttpPoolTest < Minitest::Test
  # Serves keep-alive HTTP on a loopback socket, counting accepted TCP
  # connections. hang_first: the first connection reads its request and
  # never answers, exercising the read-timeout -> discard path.
  def with_keepalive_server(body: '{"local":[]}', hang_first: false)
    server = TCPServer.new("127.0.0.1", 0)
    counter = { connections: 0 }
    workers = []
    acceptor = Thread.new do
      loop do
        conn = server.accept
        counter[:connections] += 1
        hang = hang_first && counter[:connections] == 1
        workers << Thread.new do
          while read_request(conn)
            sleep 30 if hang # hold the connection open, never answering

            conn.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" \
                       "Content-Length: #{body.bytesize}\r\n\r\n#{body}")
          end
          conn.close
        rescue IOError
          nil
        end
      end
    rescue IOError
      nil
    end
    yield "http://127.0.0.1:#{server.addr[1]}", counter
  ensure
    acceptor&.kill
    workers&.each(&:kill)
    server&.close
  end

  # Consumes one request (head + Content-Length body); false once the peer
  # has closed the connection.
  def read_request(conn)
    line = conn.gets or return false
    length = 0
    while line && line != "\r\n"
      length = line[/\AContent-Length:\s*(\d+)/i, 1].to_i if line.match?(/\AContent-Length/i)
      line = conn.gets
    end
    conn.read(length) if line && length.positive?
    !line.nil?
  end

  test "internal api reuses one connection across sequential requests" do
    with_keepalive_server do |url, counter|
      api = MailOnRails::Smtp::InternalApi.new(url: "#{url}/internal", password: "pw")
      3.times { assert_equal [], api.local_rcpts([ "a@b.test" ]) }

      assert_equal 1, counter[:connections],
                   "sequential API calls must share one keep-alive connection"
    end
  end

  test "a timed-out request discards its connection and the next call redials" do
    with_keepalive_server(hang_first: true) do |url, counter|
      api = MailOnRails::Smtp::InternalApi.new(url: "#{url}/internal", password: "pw",
                                               open_timeout: 1, read_timeout: 0.3)

      assert_raises(Net::ReadTimeout) { api.local_rcpts([ "a@b.test" ]) }
      assert_equal [], api.local_rcpts([ "a@b.test" ]), "a fresh connection must recover"
      assert_equal 2, counter[:connections],
                   "the timed-out connection must be discarded, not reused"
    end
  end

  test "ingress client reuses one connection across deliveries" do
    with_keepalive_server(body: "{}") do |url, counter|
      ingress = MailOnRails::Smtp::IngressClient.new(url: "#{url}/relay", password: "pw",
                                                     logger: Logger.new(IO::NULL))
      2.times { assert ingress.deliver("From: a@b.test\r\n\r\nbody\r\n") }

      assert_equal 1, counter[:connections],
                   "sequential deliveries must share one keep-alive connection"
    end
  end
end
