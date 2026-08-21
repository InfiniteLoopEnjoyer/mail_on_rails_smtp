# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The absolute session lifetime (Netserv::Server's reaper). The 300s read
# timeout is per-read, so a slowloris peer that keeps trickling bytes -
# or keeps NOOPing - is never idle and would hold its thread and
# ConnLimiter slot forever; the reaper closes it on age alone.
class SessionLifetimeTest < Minitest::Test
  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def start_server(session_lifetime:)
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", tcp_server: listener, session_lifetime: session_lifetime }
    thread = Thread.new { MailOnRails::SmtpServer.run(@store, [ spec ], nil) }
    @cleanup << -> { thread.kill }
    spec
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    assert_match(/\A220 /, client.gets("\r\n"))
    client
  end

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  test "an active session is closed once it outlives the cap" do
    spec = start_server(session_lifetime: 0.5)
    client = connect(spec)

    # Steady NOOP traffic: the session is never idle, so only the
    # absolute lifetime can end it.
    started = monotonic
    closed = false
    while monotonic - started < 5
      begin
        client.write("NOOP\r\n")
        break closed = true unless client.gets("\r\n")
      rescue IOError, SystemCallError
        break closed = true
      end
      sleep 0.05
    end

    assert closed, "the reaper must close a session past its lifetime"
    assert_operator monotonic - started, :>=, 0.3, "must not close a fresh session"
  end

  test "a zero lifetime disables the reaper" do
    spec = start_server(session_lifetime: 0)
    client = connect(spec)

    deadline = monotonic + 1.2
    while monotonic < deadline
      client.write("NOOP\r\n")
      assert_match(/\A250/, client.gets("\r\n").to_s, "session must outlive any default cap")
      sleep 0.05
    end
  end
end
