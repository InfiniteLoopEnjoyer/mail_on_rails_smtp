# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# End-to-end runs of the full server stack - accept threads, worker
# dispatch, fiber-scheduled sessions - over real loopback sockets.
#
# Thread mode (injected Store::Memory) covers the mail flow, STARTTLS
# under the scheduler, fiber concurrency on a single worker, and the
# connection cap. Ractor mode covers the fd handoff, per-Ractor store
# construction, and the release pipe that frees ConnLimiter slots.
class WorkerPoolTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  # A store worker Ractors can rebuild (Store::Memory can't cross the
  # boundary, and per-Ractor spools would be invisible to assertions
  # anyway, so Ractor-mode tests assert protocol behavior only).
  class RactorSafeStore
    def self.from_config(_config = {}) = new
    def worker_config = { store_class: self.class }
    def log(_level, _message) = nil
    def authenticate(_email, _password) = { account_id: nil, email: nil }
    def local_rcpts(_addresses) = { local: [] }
    def smtp_store(*, **) = { error: "unavailable", code: :internal }
  end

  # A one-connection server subclass, to exercise cap + release paths.
  class TinyServer < MailOnRails::SmtpServer
    MAX_CONNECTIONS = 1
  end

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each(&:call)
  end

  # Boots a server on ephemeral loopback ports (pre-bound listeners via the
  # spec[:tcp_server] seam) and returns the specs with ports filled in.
  def start_server(store, roles:, tls_material: nil, workers: 2, server_class: MailOnRails::SmtpServer)
    specs = roles.map do |role, tls|
      listener = TCPServer.new("127.0.0.1", 0)
      @cleanup << -> { listener.close rescue nil }
      { host: "127.0.0.1", port: listener.addr[1], tls: tls, role: role,
        hostname: "mx.test", tcp_server: listener }
    end
    thread = Thread.new { server_class.run(store, specs, tls_material, workers: workers) }
    @cleanup << -> { thread.kill }
    specs
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  # One SMTP reply, possibly multi-line ("250-..." continuations).
  def read_reply(client)
    lines = []
    while (line = client.gets("\r\n"))
      lines << line
      break if line[3] == " "
    end
    lines.join
  end

  def command(client, line)
    client.write("#{line}\r\n")
    read_reply(client)
  end

  def without_sender_verification
    singleton = MailOnRails::Smtp::SenderAuth.singleton_class
    original = MailOnRails::Smtp::SenderAuth.method(:verify)
    singleton.define_method(:verify) { |**| nil }
    yield
  ensure
    singleton.define_method(:verify, original)
  end

  def memory_store
    store = MailOnRails::Smtp::Store::Memory.new
    store.add_account(email: EMAIL, password: PASSWORD)
    store
  end

  def tls_material
    @@tls_material ||= MailOnRails::Smtp::TLS.generate_self_signed
  end

  # -- thread mode ---------------------------------------------------------

  def test_thread_mode_accepts_mail_end_to_end
    store = memory_store
    spec = start_server(store, roles: [ [ :mx, :starttls ] ]).first

    without_sender_verification do
      client = connect(spec)

      assert_match(/\A220 mx\.test /, read_reply(client))
      assert_match(/\A250[- ]/, command(client, "EHLO client.test"))
      assert_equal "250 OK\r\n", command(client, "MAIL FROM:<sender@remote.test>")
      assert_equal "250 OK\r\n", command(client, "RCPT TO:<#{EMAIL}>")
      assert_match(/\A354 /, command(client, "DATA"))
      client.write(RAW + ".\r\n")

      assert_match(/\A250 OK: queued/, read_reply(client))
      assert_match(/\A221 /, command(client, "QUIT"))
    end

    assert_equal 1, store.inbound_messages.size
    assert_equal [ EMAIL ], store.inbound_messages.first[:rcpt_to]
  end

  def test_thread_mode_starttls_and_authenticated_submission
    store = memory_store
    spec = start_server(store, roles: [ [ :submission, :starttls ] ], tls_material: tls_material).first

    client = connect(spec)

    assert_match(/\A220 /, read_reply(client))
    assert_match(/STARTTLS/, command(client, "EHLO client.test"))
    assert_match(/\A220 /, command(client, "STARTTLS"))

    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    tls = OpenSSL::SSL::SSLSocket.new(client, ctx)
    tls.sync_close = true
    tls.connect
    @cleanup << -> { tls.close rescue nil }

    assert_match(/AUTH PLAIN LOGIN/, command(tls, "EHLO client.test"))
    token = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")

    assert_match(/\A235 /, command(tls, "AUTH PLAIN #{token}"))
    assert_equal "250 OK\r\n", command(tls, "MAIL FROM:<#{EMAIL}>")
    assert_equal "250 OK\r\n", command(tls, "RCPT TO:<#{EMAIL}>")
    assert_match(/\A354 /, command(tls, "DATA"))
    tls.write(RAW + ".\r\n")

    assert_match(/\A250 OK: queued/, read_reply(tls))

    assert_equal EMAIL, store.inbound_messages.first[:authenticated_as]
  end

  def test_thread_mode_single_worker_serves_sessions_concurrently
    store = memory_store
    spec = start_server(store, roles: [ [ :mx, :starttls ] ], workers: 1).first

    first = connect(spec)
    second = connect(spec)

    assert_match(/\A220 /, read_reply(first))
    assert_match(/\A220 /, read_reply(second))
    # Interleave: only completes if one worker thread multiplexes both.
    assert_match(/\A250[- ]/, command(first, "EHLO one.test"))
    assert_match(/\A250[- ]/, command(second, "EHLO two.test"))
    assert_equal "250 OK\r\n", command(first, "NOOP")
    assert_equal "250 OK\r\n", command(second, "NOOP")
  end

  def test_thread_mode_connection_cap_and_release
    spec = start_server(memory_store, roles: [ [ :mx, :starttls ] ], server_class: TinyServer).first

    holder = connect(spec)

    assert_match(/\A220 /, read_reply(holder))

    refused = connect(spec)

    assert_match(/\A421 /, read_reply(refused))

    assert_match(/\A221 /, command(holder, "QUIT"))
    assert wait_for_free_slot(spec), "slot was not released after QUIT"
  end

  def test_accepted_sockets_get_keepalive_tuning
    server = MailOnRails::SmtpServer.new(memory_store, [], nil)
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close rescue nil }
    client = TCPSocket.new("127.0.0.1", listener.addr[1])
    @cleanup << -> { client.close rescue nil }
    accepted = listener.accept
    @cleanup << -> { accepted.close rescue nil }

    server.send(:tune_keepalive, accepted)

    assert_predicate accepted.getsockopt(:SOCKET, :KEEPALIVE), :bool
    skip "no TCP_KEEP* constants on this platform" unless Socket.const_defined?(:TCP_KEEPIDLE)

    assert_equal MailOnRails::Smtp::Server::KEEPALIVE_IDLE, accepted.getsockopt(:TCP, :KEEPIDLE).int
    assert_equal MailOnRails::Smtp::Server::KEEPALIVE_INTERVAL, accepted.getsockopt(:TCP, :KEEPINTVL).int
    assert_equal MailOnRails::Smtp::Server::KEEPALIVE_PROBES, accepted.getsockopt(:TCP, :KEEPCNT).int
  end

  # -- Ractor mode ---------------------------------------------------------

  def test_ractor_mode_serves_protocol_from_worker_ractors
    spec = start_server(RactorSafeStore.new, roles: [ [ :mx, :starttls ] ]).first

    2.times do |i| # round-robin across both worker Ractors
      client = connect(spec)

      assert_match(/\A220 mx\.test /, read_reply(client))
      assert_match(/\A250[- ]/, command(client, "EHLO r#{i}.test"))
      assert_match(/\A503 /, command(client, "RCPT TO:<a@b.test>"))
      assert_equal "250 OK\r\n", command(client, "MAIL FROM:<sender@remote.test>")
      assert_match(/\A550 /, command(client, "RCPT TO:<nobody@example.test>"))
      assert_match(/\A221 /, command(client, "QUIT"))
    end
  end

  def test_ractor_mode_release_pipe_frees_slots
    spec = start_server(RactorSafeStore.new, roles: [ [ :mx, :starttls ] ], server_class: TinyServer).first

    holder = connect(spec)

    assert_match(/\A220 /, read_reply(holder))

    refused = connect(spec)

    assert_match(/\A421 /, read_reply(refused))

    assert_match(/\A221 /, command(holder, "QUIT"))
    assert wait_for_free_slot(spec), "release pipe did not free the slot"
  end

  private

  # QUIT's release is asynchronous to the client seeing "221"; poll briefly.
  def wait_for_free_slot(spec)
    20.times do
      client = connect(spec)
      reply = read_reply(client)
      client.close
      return true if reply.start_with?("220")

      sleep 0.05
    end
    false
  end
end
