# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The per-IP lockout re-checked inside the session (auth_locked): the
# accept-side locked_line only refuses NEW connections, so a session
# opened before the lockout tripped must lose its remaining attempt
# budget too - otherwise up to MAX_CONNECTIONS_PER_IP already-open
# sessions each keep MAX_AUTH_ATTEMPTS guesses, and every guess costs
# the host app a credential check.
class LockoutRecheckTest < Minitest::Test
  ALICE = "alice@example.test"
  PASSWORD = "pw-123456"

  # Lockout after two failures; every other cap off so the lockout is the
  # only protection in play. No session lifetime - the reaper must not
  # race these slow, deliberate dialogues.
  class LockoutServer < MailOnRails::SmtpServer
    MAX_CONNECTIONS = 8
    MAX_CONNECTIONS_PER_IP = 0
    AUTH_LOCKOUT_FAILURES = 2
    AUTH_LOCKOUT_SECONDS = 900
    CONN_RATE_LIMIT = 0
    SESSION_LIFETIME = 0
  end

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: ALICE, password: PASSWORD)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  # Generating a keypair is slow enough to share across the suite.
  def self.tls_material
    @tls_material ||= MailOnRails::Netserv::Tls.generate_self_signed
  end

  # AUTH is only offered over an encrypted channel, so the wire tests run
  # against an implicit-TLS submission listener.
  def start_server
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :implicit, role: :submission,
             hostname: "mx.test", tcp_server: listener }
    thread = Thread.new { LockoutServer.run(@store, [ spec ], self.class.tls_material) }
    @cleanup << -> { thread.kill }
    spec
  end

  def connect_tls(spec)
    raw = TCPSocket.new("127.0.0.1", spec[:port])
    raw.timeout = 5
    @cleanup << -> { raw.close rescue nil }
    ssl = OpenSSL::SSL::SSLSocket.new(raw)
    ssl.sync_close = true
    ssl.connect
    ssl
  end

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

  def auth_plain_token(user, pass)
    [ "\0#{user}\0#{pass}" ].pack("m0")
  end

  test "a session opened before the lockout is refused once the IP locks" do
    spec = start_server
    survivor = connect_tls(spec)
    read_reply(survivor)
    command(survivor, "EHLO client.test")

    # A second connection from the same IP trips the lockout.
    abuser = connect_tls(spec)
    read_reply(abuser)
    command(abuser, "EHLO client.test")
    2.times { assert_match(/\A535/, command(abuser, "AUTH PLAIN #{auth_plain_token(ALICE, "wrong")}")) }

    # The pre-lockout session now gets the throttle's temporary failure
    # even with the RIGHT password - proof the store was never consulted
    # (correct credentials would have answered 235).
    assert_match(/\A454/, command(survivor, "AUTH PLAIN #{auth_plain_token(ALICE, PASSWORD)}"))

    # And a fresh connection still gets the accept-side 421 - written to
    # the raw socket before any TLS handshake, so read it in plaintext.
    late = TCPSocket.new("127.0.0.1", spec[:port])
    late.timeout = 5
    @cleanup << -> { late.close rescue nil }
    assert_match(/\A421/, late.gets("\r\n").to_s)
  end

  test "the session-side refusal spends the session's own attempts and then hangs up" do
    spec = start_server
    survivor = connect_tls(spec)
    read_reply(survivor)
    command(survivor, "EHLO client.test")

    abuser = connect_tls(spec)
    read_reply(abuser)
    command(abuser, "EHLO client.test")
    2.times { command(abuser, "AUTH PLAIN #{auth_plain_token(ALICE, "wrong")}") }

    # Refused 454s are not failures - if each one re-recorded against the
    # throttle the lockout would extend forever (auth_budget_test.rb pins
    # that nothing is reported) - but each spends one of the connection's
    # MAX_AUTH_ATTEMPTS: a locked-out peer is hung up on, not left free to
    # pipeline AUTH for the session lifetime (2026-11-17 audit, M3).
    (MailOnRails::SmtpServer::MAX_AUTH_ATTEMPTS - 1).times do
      assert_match(/\A454/, command(survivor, "AUTH PLAIN #{auth_plain_token(ALICE, PASSWORD)}"))
    end
    assert_match(/\A250/, command(survivor, "NOOP"), "session must survive the refusals within its budget")
    assert_match(/\A421 4\.7\.0/, command(survivor, "AUTH PLAIN #{auth_plain_token(ALICE, PASSWORD)}"))
    assert_nil survivor.gets("\r\n"), "the connection closes after the 421"
  end
end
