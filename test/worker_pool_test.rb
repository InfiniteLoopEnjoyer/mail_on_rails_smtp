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

  # Roomy global cap but one connection per IP: a 421 here proves the
  # per-IP limiter refused, not the global one.
  class OnePerIpServer < MailOnRails::SmtpServer
    MAX_CONNECTIONS = 10
    MAX_CONNECTIONS_PER_IP = 1
  end

  # Locks an IP out after two failed AUTHs, for long enough to outlast a test.
  class LockoutServer < MailOnRails::SmtpServer
    AUTH_LOCKOUT_FAILURES = 2
    AUTH_LOCKOUT_SECONDS = 60
  end

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each(&:call)
  end

  # Boots a server on ephemeral loopback ports (pre-bound listeners via the
  # spec[:tcp_server] seam) and returns the specs with ports filled in.
  def start_server(store, roles:, tls_material: nil, workers: 2, server_class: MailOnRails::SmtpServer, spec_extra: {})
    specs = roles.map do |role, tls|
      listener = TCPServer.new("127.0.0.1", 0)
      @cleanup << -> { listener.close rescue nil }
      { host: "127.0.0.1", port: listener.addr[1], tls: tls, role: role,
        hostname: "mx.test", tcp_server: listener }.merge(spec_extra)
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
    tls = tls_wrap(client)

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

  def test_per_ip_connection_cap_and_release
    spec = start_server(memory_store, roles: [ [ :mx, :starttls ] ], server_class: OnePerIpServer).first

    holder = connect(spec)

    assert_match(/\A220 /, read_reply(holder))

    refused = connect(spec)

    assert_match(/\A421 /, read_reply(refused), "second connection from the same IP must be refused")

    assert_match(/\A221 /, command(holder, "QUIT"))
    assert wait_for_free_slot(spec), "per-IP slot was not released after QUIT"
  end

  # Wrong-password AUTHs across ONE connection must lock the IP for the NEXT
  # connection - the throttle spans connections, unlike MAX_AUTH_ATTEMPTS.
  def test_auth_lockout_refuses_subsequent_connections
    spec = start_server(memory_store, roles: [ [ :submission, :starttls ] ],
                        tls_material: tls_material, server_class: LockoutServer).first

    client = connect(spec)
    read_reply(client)
    command(client, "EHLO client.test")
    command(client, "STARTTLS")
    tls = tls_wrap(client)
    command(tls, "EHLO client.test")
    bad = [ "\0#{EMAIL}\0wrong-password" ].pack("m0")

    assert_match(/\A535 /, command(tls, "AUTH PLAIN #{bad}"))
    assert_match(/\A535 /, command(tls, "AUTH PLAIN #{bad}"))
    command(tls, "QUIT")

    # Thread mode records failures synchronously, so the lock is already set.
    locked = connect(spec)

    assert_match(/\A421 /, read_reply(locked), "the IP must be locked out on its next connection")
  end

  # A peer that connects to the implicit-TLS port and never speaks must not
  # hold its connection slot past the handshake timeout (TCP keepalive only
  # reaps dead peers; this one stays alive and silent).
  def test_implicit_tls_handshake_timeout_frees_the_slot
    spec = start_server(memory_store, roles: [ [ :submission, :implicit ] ],
                        tls_material: tls_material, server_class: TinyServer,
                        spec_extra: { handshake_timeout: 0.3 }).first

    silent = connect(spec) # occupies the only slot, never starts TLS

    # The server must close the stalled connection (EOF or reset)...
    begin
      assert_nil silent.gets("\r\n"), "server should close a stalled handshake"
    rescue SystemCallError
      # a reset also proves the close
    end

    # ...and release its slot so a well-behaved TLS client gets through.
    assert wait_for_free_tls_slot(spec), "stalled handshake did not release its slot"
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

  # Same as the thread-mode test, but here the peer IP must cross to the
  # worker on the control pipe and come back on the release pipe.
  def test_ractor_mode_per_ip_cap_and_release_via_pipes
    spec = start_server(RactorSafeStore.new, roles: [ [ :mx, :starttls ] ], server_class: OnePerIpServer).first

    holder = connect(spec)

    assert_match(/\A220 /, read_reply(holder))

    refused = connect(spec)

    assert_match(/\A421 /, read_reply(refused), "second connection from the same IP must be refused")

    assert_match(/\A221 /, command(holder, "QUIT"))
    assert wait_for_free_slot(spec), "per-IP slot was not released via the release pipe"
  end

  # Auth failures must cross the worker Ractor boundary (auth pipe) to reach
  # the accept side's throttle. RactorSafeStore fails every authentication.
  def test_ractor_mode_auth_lockout_via_pipe
    spec = start_server(RactorSafeStore.new, roles: [ [ :submission, :starttls ] ],
                        tls_material: tls_material, server_class: LockoutServer).first

    client = connect(spec)
    read_reply(client)
    command(client, "EHLO client.test")
    command(client, "STARTTLS")
    tls = tls_wrap(client)
    command(tls, "EHLO client.test")
    bad = [ "\0nobody@example.test\0nope" ].pack("m0")

    assert_match(/\A535 /, command(tls, "AUTH PLAIN #{bad}"))
    assert_match(/\A535 /, command(tls, "AUTH PLAIN #{bad}"))
    command(tls, "QUIT")

    # The failure reports travel over a pipe; poll for the lockout to land.
    assert wait_for_lockout(spec), "auth failures did not reach the accept-side throttle"
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

  # Client-side TLS over an established socket (after a 220 STARTTLS go-ahead).
  def tls_wrap(client)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    tls = OpenSSL::SSL::SSLSocket.new(client, ctx)
    tls.sync_close = true
    tls.connect
    @cleanup << -> { tls.close rescue nil }
    tls
  end

  # Polls until a fresh connection is refused with 421 (lockout engaged).
  def wait_for_lockout(spec)
    40.times do
      client = connect(spec)
      reply = read_reply(client)
      client.close
      return true if reply.start_with?("421")

      sleep 0.05
    end
    false
  end

  # Polls until a full TLS handshake + 220 banner succeeds. While the slot
  # is still held, the 421 busy line arrives as plaintext and fails the
  # client-side handshake with an SSLError.
  def wait_for_free_tls_slot(spec)
    40.times do
      begin
        client = connect(spec)
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
        tls = OpenSSL::SSL::SSLSocket.new(client, ctx)
        tls.sync_close = true
        tls.connect
        reply = read_reply(tls)
        tls.close
        return true if reply.start_with?("220")
      rescue OpenSSL::SSL::SSLError, SystemCallError, IO::TimeoutError
        nil
      end
      sleep 0.05
    end
    false
  end

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
