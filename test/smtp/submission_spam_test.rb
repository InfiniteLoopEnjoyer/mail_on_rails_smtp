# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"
require "fake_rspamd"

# The outbound spam gate at the DATA hot path: authenticated submissions
# are scored by rspamd and refused on its "reject" (550) and "soft reject"
# (451) actions; milder verdicts pass, an unreachable rspamd fails open
# (spam scoring is advisory - contrast the virus scanner's fail-closed
# 451), and unauthenticated MX traffic is never scored at the edge (the
# mailroom's own rspamd pass covers it app-side).
class SubmissionSpamTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: user@example.test\r\nSubject: hello\r\n\r\nbody line\r\n"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def with_session(role: :submission, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    # tls: :implicit marks the channel as already encrypted, so AUTH is
    # offered without a real TLS handshake (this suite runs plaintext).
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :implicit, role: role,
             hostname: "mx.test" }.merge(spec_extra)
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

  def submit(spec_extra)
    with_session(spec_extra: spec_extra) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      token = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
      assert_match(/\A235/, command(client, "AUTH PLAIN #{token}"))
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}>"))
      assert_match(/\A250/, command(client, "RCPT TO:<someone@remote.test>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write(RAW)
      @data_reply = command(client, ".")
      assert_match(/\A250/, command(client, "NOOP"), "session must stay usable after DATA")
      command(client, "QUIT")
    end
    @data_reply
  end

  def test_reject_action_gets_550_and_nothing_is_stored
    FakeRspamd.serving("reject") do |addr, fake|
      reply = submit({ rspamd_addr: addr, rspamd_timeout: 2 })

      assert_match(/\A550 5\.7\.1 .*spam/i, reply)
      request = fake.requests.last
      refute_nil request, "the submission must have been scored"
      assert_equal EMAIL, request[:headers]["user"],
                   "the authenticated user must be forwarded so rspamd applies its authenticated-sender policy"
    end

    assert_empty @store.outbound_messages, "a rejected submission must never reach the outbound queue"
  end

  def test_soft_reject_action_gets_451
    FakeRspamd.serving("soft reject") do |addr, _fake|
      reply = submit({ rspamd_addr: addr, rspamd_timeout: 2 })

      assert_match(/\A451 4\.7\.1 /, reply)
    end

    assert_empty @store.outbound_messages
  end

  def test_greylist_action_gets_451_by_default
    FakeRspamd.serving("greylist") do |addr, _fake|
      reply = submit({ rspamd_addr: addr, rspamd_timeout: 2 })

      assert_match(/\A451 4\.7\.1 Greylisted/, reply)
    end

    assert_empty @store.outbound_messages, "a greylisted submission must not be queued"
  end

  def test_greylist_action_passes_when_opted_out
    MailOnRails::Settings.overrides = { smtp_rspamd_greylist: false }
    FakeRspamd.serving("greylist") do |addr, _fake|
      reply = submit({ rspamd_addr: addr, rspamd_timeout: 2 })

      assert_match(/\A250 2\.0\.0 Ok: queued/, reply)
    end

    refute_empty @store.outbound_messages
  ensure
    MailOnRails::Settings.reset!
  end

  def test_milder_actions_pass
    FakeRspamd.serving("add header", score: 4.0) do |addr, _fake|
      reply = submit({ rspamd_addr: addr, rspamd_timeout: 2 })

      assert_match(/\A250 2\.0\.0 Ok: queued/, reply)
    end

    refute_empty @store.outbound_messages
  end

  def test_unreachable_rspamd_fails_closed_by_default
    closed = TCPServer.new("127.0.0.1", 0)
    port = closed.addr[1]
    closed.close

    reply = submit({ rspamd_addr: "127.0.0.1:#{port}", rspamd_timeout: 1 })

    assert_match(/\A451 4\.7\.1 .*unavailable/i, reply)
    assert_empty @store.outbound_messages, "the default must defer submission on an rspamd outage"
  end

  def test_unreachable_rspamd_fails_open_when_opted_out
    MailOnRails::Settings.overrides = { smtp_rspamd_fail_closed: false }
    closed = TCPServer.new("127.0.0.1", 0)
    port = closed.addr[1]
    closed.close

    reply = submit({ rspamd_addr: "127.0.0.1:#{port}", rspamd_timeout: 1 })

    assert_match(/\A250 2\.0\.0 Ok: queued/, reply)
    refute_empty @store.outbound_messages, "the opt-out must not block outbound mail on an outage"
  ensure
    MailOnRails::Settings.reset!
  end

  def test_unauthenticated_mx_traffic_is_not_scored_at_the_edge
    FakeRspamd.serving("reject") do |addr, fake|
      with_session(role: :mx, spec_extra: { rspamd_addr: addr, sender_auth: false }) do |client|
        read_reply(client)
        command(client, "EHLO client.test")
        assert_match(/\A250/, command(client, "MAIL FROM:<sender@remote.test>"))
        assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
        assert_match(/\A354/, command(client, "DATA"))
        client.write(RAW)
        assert_match(/\A250/, command(client, "."))
        command(client, "QUIT")
      end
      assert_empty fake.requests, "unauthenticated mail is scored by the mailroom, never at the edge"
    end
  end
end
