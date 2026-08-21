# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The per-account send quota at the RCPT hot path, over a loopback session.
# Policy under test: each accepted recipient on an authenticated session
# consumes one slot; an exhausted account gets 452 (tempfail - a legitimate
# burst retries later); the budget follows the account across sessions and
# ignores unauthenticated MX traffic entirely.
class SubmissionQuotaTest < Minitest::Test
  EMAIL = "user@example.test"
  OTHER = "other@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD)
    @store.add_account(email: OTHER, password: PASSWORD)
  end

  def with_session(role:, quota:)
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    # tls: :implicit marks the channel as already encrypted, so AUTH is
    # offered without a real TLS handshake (this suite runs plaintext).
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :implicit, role: role,
             hostname: "mx.test", send_quota: quota }
    thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, nil).run }
    yield client
  ensure
    client&.close
    thread&.join(5)
    server&.close
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

  def authenticate(client, email = EMAIL)
    read_reply(client)
    command(client, "EHLO client.test")
    token = [ "\0#{email}\0#{PASSWORD}" ].pack("m0")
    assert_match(/\A235/, command(client, "AUTH PLAIN #{token}"))
    assert_match(/\A250/, command(client, "MAIL FROM:<#{email}>"))
  end

  def test_recipients_over_the_quota_get_452
    quota = MailOnRails::SendQuota.new(limit: 2, window: 3600)
    with_session(role: :submission, quota: quota) do |client|
      authenticate(client)
      assert_match(/\A250/, command(client, "RCPT TO:<one@remote.test>"))
      assert_match(/\A250/, command(client, "RCPT TO:<two@remote.test>"))
      assert_match(/\A452 4\.7\.1 /, command(client, "RCPT TO:<three@remote.test>"))
      assert_match(/\A250/, command(client, "NOOP"), "session must stay usable after a quota refusal")
      command(client, "QUIT")
    end
  end

  def test_quota_follows_the_account_across_sessions
    quota = MailOnRails::SendQuota.new(limit: 1, window: 3600)
    with_session(role: :submission, quota: quota) do |client|
      authenticate(client)
      assert_match(/\A250/, command(client, "RCPT TO:<one@remote.test>"))
      command(client, "QUIT")
    end
    with_session(role: :submission, quota: quota) do |client|
      authenticate(client)
      assert_match(/\A452/, command(client, "RCPT TO:<two@remote.test>"),
                   "a reconnect must not refill the account's budget")
      command(client, "QUIT")
    end
    with_session(role: :submission, quota: quota) do |client|
      authenticate(client, OTHER)
      assert_match(/\A250/, command(client, "RCPT TO:<three@remote.test>"),
                   "another account's budget must be untouched")
      command(client, "QUIT")
    end
  end

  def test_unauthenticated_mx_traffic_never_touches_the_quota
    quota = MailOnRails::SendQuota.new(limit: 1, window: 3600)
    with_session(role: :mx, quota: quota) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A250/, command(client, "MAIL FROM:<sender@remote.test>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{OTHER}>"),
                   "unauthenticated recipients must not be quota-limited")
      command(client, "QUIT")
    end
    assert quota.consume(EMAIL), "the quota must be untouched by unauthenticated traffic"
  end

  def test_nil_quota_in_spec_disables
    with_session(role: :submission, quota: nil) do |client|
      authenticate(client)
      5.times do |i|
        assert_match(/\A250/, command(client, "RCPT TO:<r#{i}@remote.test>"))
      end
      command(client, "QUIT")
    end
  end
end
