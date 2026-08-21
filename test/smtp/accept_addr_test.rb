# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The accept-time peer address, SMTP side (the netserv accept path is
# shared, but the session seeding is per protocol). See the IMAP twin
# for the full story: production listeners are plain Sockets so
# accept(2)'s Addrinfo names even a peer that reset before getpeername
# could run.
class SmtpAcceptAddrTest < Minitest::Test
  # A memory store that also keeps connection history, standing in for
  # the Rails backend's optional record_closed_connection.
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

  def eventually(timeout = 5, message = "condition not met")
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      flunk "#{message} within #{timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.02
    end
  end

  # A scanner that connects and RSTs (SO_LINGER 0) before the server
  # accepts must still be recorded with its address, via accept(2)'s
  # Addrinfo - getpeername on its socket raises ENOTCONN.
  def test_history_names_the_peer_that_reset_before_accept
    store = RecordingStore.new
    listener = Socket.new(:INET, :STREAM)
    listener.setsockopt(:SOCKET, :REUSEADDR, true)
    listener.bind(Addrinfo.tcp("127.0.0.1", 0))
    listener.listen(5)
    @cleanup << -> { listener.close rescue nil }

    scanner = TCPSocket.new("127.0.0.1", listener.local_address.ip_port)
    scanner.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack("ii"))
    scanner.close # linger 0: close sends RST instead of FIN
    sleep 0.2     # let the RST land while the connection is still queued

    spec = { host: "127.0.0.1", port: listener.local_address.ip_port, tls: :starttls,
             role: :mx, hostname: "mx.test", tcp_server: listener }
    server = MailOnRails::SmtpServer.new(store, [ spec ], nil)
    thread = Thread.new { server.run }
    @cleanup << -> { thread.kill }
    server.wait_ready(5)

    eventually(5, "reset connection not reported") { store.closed.size == 1 }

    assert_equal "127.0.0.1", store.closed.first[:ip]
  end

  # Server-seeded address wins over the session's own getpeername; the
  # "?" fallback survives for sessions built directly (tests).
  def test_session_prefers_seeded_address_over_getpeername
    store = MailOnRails::Smtp::Store::Memory.new
    sock, other = UNIXSocket.pair
    @cleanup << -> { sock.close rescue nil }
    @cleanup << -> { other.close rescue nil }
    spec = { tls: :starttls, role: :mx, hostname: "mx.test" }

    unseeded = MailOnRails::SmtpServer::Session.new(sock, store, spec, nil)

    assert_equal "?", unseeded.send(:peer_ip)

    seeded = MailOnRails::SmtpServer::Session.new(sock, store, spec, nil)
    seeded.peer_ip = "203.0.113.9"

    assert_equal "203.0.113.9", seeded.send(:peer_ip)
  end
end
