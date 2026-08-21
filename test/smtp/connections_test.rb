# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The live-connections registry behind the Rails UI's SMTP page:
# Server#connections snapshots each connection as plain values (no socket
# or thread escapes), including the session's HELO name and listener
# role, and Server#kick force-closes a banned address's live sessions.
class SmtpConnectionsTest < Minitest::Test
  # A memory store that also keeps connection history, standing in for
  # the Rails backend's optional record_closed_connection. The plain
  # Memory store used everywhere else lacks the method, which doubles as
  # the pin on the server's respond_to? guard.
  class RecordingStore < MailOnRails::Smtp::Store::Memory
    attr_reader :closed

    def initialize(*)
      super
      @closed = []
    end

    def record_closed_connection(info)
      @closed << info
      {}
    end
  end

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def build_server(store: MailOnRails::Smtp::Store::Memory.new)
    listener = TCPServer.new("127.0.0.1", 0)
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", tcp_server: listener }
    server = MailOnRails::SmtpServer.new(store, [ spec ], nil)
    thread = Thread.new { server.run }
    @cleanup << -> { thread.kill }
    server.wait_ready(5)
    [ server, spec ]
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  def read_reply(client)
    lines = []
    while (line = client.gets("\r\n"))
      lines << line
      break if line[3] == " "
    end
    lines.join
  end

  def eventually(timeout = 5, message = "condition not met")
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      flunk "#{message} within #{timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.02
    end
  end

  def test_connections_snapshots_registry_and_session_state
    server, spec = build_server

    assert_empty server.connections

    client = connect(spec)

    assert_match(/\A220 /, read_reply(client))
    eventually(5, "connection not registered") { server.connections.size == 1 }

    client.write("EHLO client.test\r\n")

    assert_match(/\A250/, read_reply(client))
    eventually(5, "HELO not visible") { server.connections.first[:helo] == "client.test" }

    conn = server.connections.first

    assert_equal "SMTP", conn[:protocol]
    assert_equal "127.0.0.1", conn[:peer_ip]
    assert_equal spec[:port], conn[:port]
    assert_equal :mx, conn[:role]
    assert_kind_of Time, conn[:connected_at]
    assert_nil conn[:user]
    assert_equal 0, conn[:messages]
    refute conn[:tls]

    client.write("QUIT\r\n")
    read_reply(client)
    eventually(5, "connection not deregistered") { server.connections.empty? }
  end

  def test_kick_closes_only_matching_connections
    server, spec = build_server
    client = connect(spec)

    assert_match(/\A220 /, read_reply(client))
    eventually(5, "connection not registered") { server.connections.size == 1 }

    assert_equal 0, server.kick { |ip| ip == "198.51.100.1" }
    assert_equal 1, server.kick { |ip| ip == "127.0.0.1" }

    assert_nil client.gets("\r\n"), "kicked client must see EOF"
    eventually(5, "kicked connection not deregistered") { server.connections.empty? }
  end

  def test_close_reports_history_to_a_store_that_keeps_it
    store = RecordingStore.new
    _server, spec = build_server(store: store)
    client = connect(spec)

    assert_match(/\A220 /, read_reply(client))
    client.write("EHLO client.test\r\n")
    read_reply(client)
    client.write("QUIT\r\n")
    read_reply(client)

    eventually(5, "close not reported") { store.closed.size == 1 }
    info = store.closed.first

    assert_equal "smtp", info[:protocol]
    assert_equal "127.0.0.1", info[:ip]
    assert_equal spec[:port], info[:port]
    assert_equal :mx, info[:role]
    assert_equal "client.test", info[:helo]
    assert_equal 0, info[:messages]
    assert_nil info[:user]
    assert_kind_of Time, info[:connected_at]
    assert_kind_of Time, info[:closed_at]
    assert_operator info[:duration_seconds], :>=, 0
  end
end
