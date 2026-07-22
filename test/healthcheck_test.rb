# frozen_string_literal: true

require "test_helper"
require "English"
require "socket"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# bin/healthcheck (todo item 17), run as the real subprocess the Docker
# HEALTHCHECK would launch, against a live loopback server.
class HealthcheckTest < Minitest::Test
  SCRIPT = File.expand_path("../bin/healthcheck", __dir__)

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each(&:call)
  end

  def start_server
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close rescue nil }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", tcp_server: listener }
    thread = Thread.new { MailOnRails::SmtpServer.run(MailOnRails::Smtp::Store::Memory.new, [ spec ], nil, workers: 1) }
    @cleanup << -> { thread.kill }
    # The accept loop needs to be up before the probe runs.
    50.times do
      TCPSocket.new("127.0.0.1", spec[:port]).close
      break
    rescue SystemCallError
      sleep 0.05
    end
    spec[:port]
  end

  def healthcheck(port)
    system({ "SMTP_PORT" => port.to_s }, RbConfig.ruby, SCRIPT,
           out: IO::NULL, err: IO::NULL)
    $CHILD_STATUS
  end

  def test_exits_zero_against_a_serving_listener
    status = healthcheck(start_server)

    assert_predicate status, :success?, "a serving listener must probe healthy"
  end

  def test_exits_nonzero_when_nothing_listens
    closed = TCPServer.new("127.0.0.1", 0)
    port = closed.addr[1]
    closed.close

    status = healthcheck(port)

    refute_predicate status, :success?, "a dead listener must probe unhealthy"
  end

  def test_exits_nonzero_against_a_non_smtp_service
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close rescue nil }
    thread = Thread.new do
      loop do
        conn = listener.accept
        conn.write("HTTP/1.1 200 OK\r\n\r\n")
        conn.close
      end
    rescue IOError
      nil
    end
    @cleanup << -> { thread.kill }

    status = healthcheck(listener.addr[1])

    refute_predicate status, :success?, "a non-SMTP banner must probe unhealthy"
  end
end
