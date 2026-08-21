# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# Readiness and graceful shutdown: the host process (Puma) must be able to
# wait for bound listeners before reporting healthy, and to stop the
# server without stranding threads - polite sessions get a drain window,
# stragglers are force-closed and unwind through their ensure paths.
class LifecycleTest < Minitest::Test
  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def build_server
    store = MailOnRails::Smtp::Store::Memory.new
    listener = TCPServer.new("127.0.0.1", 0)
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", tcp_server: listener }
    server = MailOnRails::SmtpServer.new(store, [ spec ], nil)
    thread = Thread.new { server.run }
    @cleanup << -> { thread.kill }
    [ server, spec ]
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  def test_wait_ready_then_serve_then_shutdown_refuses_new_connections
    server, spec = build_server

    assert server.wait_ready(5), "listeners must bind promptly"
    assert_predicate server, :ready?
    assert_match(/\A220 /, connect(spec).gets("\r\n"))

    server.shutdown(drain: 1)

    refute_predicate server, :ready?
    assert_raises(Errno::ECONNREFUSED) { TCPSocket.new("127.0.0.1", spec[:port]) }
  end

  def test_shutdown_returns_as_soon_as_sessions_finish
    server, spec = build_server
    server.wait_ready(5)

    client = connect(spec)

    assert_match(/\A220 /, client.gets("\r\n"))

    finisher = Thread.new do
      sleep 0.2
      client.write("QUIT\r\n")
    end
    @cleanup << -> { finisher.kill }

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    server.shutdown(drain: 10)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert_operator elapsed, :<, 5, "shutdown must not wait out the full drain once sessions are gone"
    finisher.join(2)
  end

  def test_shutdown_force_closes_idle_stragglers
    server, spec = build_server
    server.wait_ready(5)

    idler = connect(spec)

    assert_match(/\A220 /, idler.gets("\r\n"))

    server.shutdown(drain: 0.3)

    assert_nil idler.gets("\r\n"), "an idle session must be closed once the drain window lapses"
  end
end
