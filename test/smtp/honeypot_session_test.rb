require "test_helper"
require "logger"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# Honeypot behavior on the SMTP session: a canary login is observed and its
# submission blackholed, exploit-probe payloads are recorded and refused, and
# a deceptive banner can replace the greeting. Driven directly over a loopback
# socket against the reference store - no Rails, no database.
class SmtpHoneypotSessionTest < Minitest::Test
  CANARY = "admin@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: CANARY, password: PASSWORD, honeypot: true)
    @store.add_account(email: "real@example.test", password: PASSWORD)
  end

  # Runs the session in a thread, keeps a reference so the test can call the
  # teardown hook (finalize_honeypot) the real Server would call, and yields
  # the client socket.
  def with_session(role: :submission, spec_extra: { tls: :implicit })
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: role, hostname: "mx.test" }.merge(spec_extra)
    @session = MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, nil)
    thread = Thread.new { @session.run }
    yield client
  ensure
    client&.close
    thread&.join(5)
    @session&.finalize_honeypot # the Server calls this at teardown
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

  def authenticate(client, email, password)
    command(client, "EHLO client.test")
    command(client, "AUTH PLAIN #{[ "\0#{email}\0#{password}" ].pack("m0")}")
  end

  def test_canary_login_is_recorded_banned_ready_and_session_continues
    with_session do |client|
      read_reply(client)
      assert_match(/\A235/, authenticate(client, CANARY, PASSWORD))
      command(client, "QUIT")
    end

    assert_equal 1, @store.honeypot_events.size
    event = @store.honeypot_events.first
    assert_equal "canary_auth", event[:trigger]
    assert_equal "smtp", event[:protocol]
    assert_equal CANARY, event[:username]
    assert_equal "127.0.0.1", event[:ip]
  end

  def test_canary_submission_is_blackholed
    with_session do |client|
      read_reply(client)
      authenticate(client, CANARY, PASSWORD)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{CANARY}>"))
      assert_match(/\A250/, command(client, "RCPT TO:<victim@remote.test>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write("Subject: spam\r\n\r\nbuy pills\r\n.\r\n")
      assert_match(/\A250 2\.0\.0 Ok: queued as/, read_reply(client))
      command(client, "QUIT")
    end

    assert_empty @store.outbound_messages, "canary submission must not relay"
    assert_empty @store.inbound_messages, "canary submission must not be stored"
    # The full transcript (flushed at teardown) captures the relay attempt.
    transcript = @store.honeypot_events.first[:transcript]
    assert_includes transcript, "RCPT TO: victim@remote.test"
    assert_includes transcript, "buy pills"
  end

  def test_transcript_redacts_the_password
    with_session do |client|
      read_reply(client)
      authenticate(client, CANARY, PASSWORD)
      command(client, "QUIT")
    end

    transcript = @store.honeypot_events.first[:transcript]
    assert_includes transcript, "AUTH PLAIN [redacted]"
    refute_includes transcript, PASSWORD
  end

  def test_a_normal_account_login_records_nothing
    with_session do |client|
      read_reply(client)
      authenticate(client, "real@example.test", PASSWORD)
      command(client, "QUIT")
    end

    assert_empty @store.honeypot_events
  end

  def test_exploit_probe_is_recorded_and_refused_without_dispatch
    with_session(role: :mx, spec_extra: {}) do |client|
      read_reply(client)
      reply = command(client, "MAIL FROM:<${run{/bin/sh -c id}}@evil.test>")
      assert_match(/\A502/, reply, "probe must be refused, not dispatched as MAIL")
      command(client, "QUIT")
    end

    assert_equal 1, @store.honeypot_events.size
    event = @store.honeypot_events.first
    assert_equal "exploit_probe", event[:trigger]
    assert_equal "exim_run", event[:signature]
  end

  def test_vrfy_root_reconnaissance_is_flagged
    with_session(role: :mx, spec_extra: {}) do |client|
      read_reply(client)
      reply = command(client, "VRFY root")
      # Same reply an innocuous VRFY gets, so recon targets can't
      # fingerprint the honeypot by comparing answers.
      assert_match(/\A252 /, reply)
      command(client, "QUIT")
    end

    assert_equal "vrfy_privileged", @store.honeypot_events.first[:signature]
  end

  def test_vrfy_probe_reply_follows_the_configured_vrfy_response
    MailOnRails::Settings.overrides = { smtp_vrfy_response: "502" }
    with_session(role: :mx, spec_extra: {}) do |client|
      read_reply(client)
      assert_match(/\A502 /, command(client, "VRFY root"))
      command(client, "QUIT")
    end

    assert_equal "vrfy_privileged", @store.honeypot_events.first[:signature]
  ensure
    MailOnRails::Settings.reset!
  end

  def test_deceptive_banner_replaces_the_greeting
    with_session(role: :mx, spec_extra: { honeypot_banner: "Exim 4.80" }) do |client|
      assert_match(/\A220 Exim 4\.80/, read_reply(client))
      command(client, "QUIT")
    end
  end
end
