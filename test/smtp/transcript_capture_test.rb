require "test_helper"
require "logger"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# Session-level rules for smtp_trace_capture (Session#transcript_capture):
# only abnormally ended sessions hand a transcript to the teardown path,
# the capture is opt-in, honeypot sessions are excluded (their transcript
# lands in the HoneypotEvent instead), and credentials never appear in the
# captured dialogue. Driven directly over a loopback socket against the
# reference store - no Rails, no database.
class SmtpTranscriptCaptureTest < Minitest::Test
  USER = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: USER, password: PASSWORD)
  end

  def with_session(spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :implicit, role: :submission,
             hostname: "mx.test", trace_capture: true }.merge(spec_extra)
    @session = MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, nil)
    thread = Thread.new { @session.run }
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

  def test_clean_quit_session_captures_nothing
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "QUIT")
    end
    assert_nil @session.transcript_capture
  end

  def test_bare_eof_without_quit_captures_nothing
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
    end
    assert_nil @session.transcript_capture
  end

  def test_protocol_errors_capture_the_dialogue_even_after_clean_quit
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "BOGUS COMMAND")
      command(client, "QUIT")
    end
    capture = @session.transcript_capture
    refute_nil capture
    assert_equal "protocol_errors", capture[:close_reason]
    assert_includes capture[:transcript], "<= BOGUS COMMAND"
    assert_includes capture[:transcript], "=> 502"
  end

  def test_failed_auth_captures_with_redacted_credentials
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "AUTH PLAIN #{[ "\0#{USER}\0wrong-password" ].pack("m0")}")
      command(client, "QUIT")
    end
    capture = @session.transcript_capture
    refute_nil capture
    assert_equal "auth_failed", capture[:close_reason]
    assert_includes capture[:transcript], "<= AUTH PLAIN"
    refute_includes capture[:transcript], [ "\0#{USER}\0wrong-password" ].pack("m0")
    refute_includes capture[:transcript], "wrong-password"
  end

  def test_successful_auth_then_quit_captures_nothing
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "AUTH PLAIN #{[ "\0#{USER}\0#{PASSWORD}" ].pack("m0")}")
      command(client, "QUIT")
    end
    assert_nil @session.transcript_capture
  end

  def test_command_timeout_captures_with_timeout_reason
    with_session(spec_extra: { timeout: 0.2 }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A421/, read_reply(client)) # the timeout notice
    end
    capture = @session.transcript_capture
    refute_nil capture
    assert_equal "timeout", capture[:close_reason]
  end

  def test_eof_mid_data_captures_as_eof_mid_command
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "AUTH PLAIN #{[ "\0#{USER}\0#{PASSWORD}" ].pack("m0")}")
      command(client, "MAIL FROM:<#{USER}>")
      command(client, "RCPT TO:<other@example.test>")
      command(client, "DATA")
      client.write("Subject: half a message\r\n")
      # ...and vanish mid-DATA.
    end
    capture = @session.transcript_capture
    refute_nil capture
    assert_equal "eof_mid_command", capture[:close_reason]
    # The DATA payload itself must never enter the capture.
    refute_includes capture[:transcript], "half a message"
  end

  def test_capture_disabled_yields_nothing_even_on_errors
    with_session(spec_extra: { trace_capture: false }) do |client|
      read_reply(client)
      command(client, "BOGUS COMMAND")
      command(client, "QUIT")
    end
    assert_nil @session.transcript_capture
  end

  def test_honeypot_sessions_are_excluded
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "VRFY root") # exploit-probe signature; fires the honeypot
      command(client, "QUIT")
    end
    assert @session.honeypot_fired?, "probe must have fired the honeypot"
    assert_nil @session.transcript_capture
  end
end
