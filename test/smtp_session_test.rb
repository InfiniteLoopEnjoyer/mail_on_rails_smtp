require "test_helper"
require "logger"
require "stringio"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# End-to-end SMTP session over a real loopback socket, backed by the
# contract's reference store - no Rails, no database, no DNS (sender
# verification is stubbed out; this gem has dedicated suites for it).
class SmtpSessionTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  # Test double for the spec[:dnsbl] seam: a fixed verdict, no DNS.
  class FakeDnsbl
    def initialize(zone) = @zone = zone
    def listed(_ip) = @zone
  end

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def with_session(role: :mx, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: role, hostname: "mx.test" }.merge(spec_extra)
    thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, nil).run }
    yield client
  ensure
    client&.close
    thread&.join(5)
    server&.close
  end

  # One SMTP reply, which may span multiple lines ("250-..." continuations).
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

  # SPF/DKIM/DMARC would do live DNS; return "no verdict" instead
  # (verification has its own suites in this gem).
  def without_sender_verification
    recording_sender_verification { yield }
  end

  # Replaces SenderAuth.verify with a recorder that returns "no verdict",
  # so tests can assert whether verification ran without live DNS.
  def recording_sender_verification
    calls = []
    singleton = MailOnRails::Smtp::SenderAuth.singleton_class
    original = MailOnRails::Smtp::SenderAuth.method(:verify)
    singleton.define_method(:verify) { |**kwargs| calls << kwargs; nil }
    yield calls
  ensure
    singleton.define_method(:verify, original)
  end

  # Full EHLO -> DATA exchange for one message; returns the final reply.
  def deliver_message(client)
    read_reply(client)
    command(client, "EHLO client.test")
    command(client, "MAIL FROM:<sender@remote.test>")
    command(client, "RCPT TO:<#{EMAIL}>")
    command(client, "DATA")
    client.write(RAW)
    command(client, ".")
  end

  def test_mx_session_refuses_mail_from_a_dnsbl_listed_ip
    with_session(spec_extra: { dnsbl: FakeDnsbl.new("bl.test") }) do |client|
      read_reply(client)
      assert_match(/\A250/, command(client, "EHLO client.test"))
      reply = command(client, "MAIL FROM:<sender@remote.test>")
      assert_match(/\A554 5\.7\.1 /, reply)
      assert_match(/bl\.test/, reply, "the reply should name the listing zone")
      assert_match(/\A503/, command(client, "RCPT TO:<#{EMAIL}>"), "the envelope must not have started")
      assert_match(/\A221/, command(client, "QUIT"))
    end
  end

  def test_mx_session_accepts_mail_from_an_unlisted_ip
    with_session(spec_extra: { dnsbl: FakeDnsbl.new(nil) }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A250/, command(client, "MAIL FROM:<sender@remote.test>"))
    end
  end

  def test_mx_session_verifies_sender_when_sender_auth_is_enabled
    recording_sender_verification do |calls|
      with_session(spec_extra: { sender_auth: true }) do |client|
        assert_match(/\A250 OK: queued/, deliver_message(client))
      end

      assert_equal 1, calls.size, "SenderAuth.verify must run for unauthenticated MX mail"
    end
  end

  def test_mx_session_skips_sender_verification_when_disabled
    recording_sender_verification do |calls|
      with_session(spec_extra: { sender_auth: false }) do |client|
        assert_match(/\A250 OK: queued/, deliver_message(client))
      end

      assert_empty calls, "SenderAuth.verify must not run when sender auth is off"
    end

    message = @store.inbound_messages.last
    assert_nil message[:auth_results], "a skipped verification must not stamp a verdict"
  end

  def test_mx_session_accepts_local_mail_end_to_end
    without_sender_verification do
      with_session do |client|
        assert_match(/\A220 mx\.test /, read_reply(client))
        assert_match(/\A250/, command(client, "EHLO client.test"))
        assert_match(/\A250/, command(client, "MAIL FROM:<sender@remote.test>"))
        assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
        assert_match(/\A354/, command(client, "DATA"))
        client.write(RAW)
        assert_match(/\A250 OK: queued/, command(client, "."))
        assert_match(/\A221/, command(client, "QUIT"))
      end
    end

    message = @store.inbound_messages.last
    refute_nil message
    assert_equal [ EMAIL ], message[:rcpt_to]
    assert_equal RAW, message[:data]
    assert_nil message[:authenticated_as], "unauthenticated mail must be stored untrusted"
  end

  def test_mx_session_rejects_unknown_recipient_and_relay
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      assert_match(/\A550/, command(client, "RCPT TO:<stranger@elsewhere.test>"))
      assert_match(/\A503/, command(client, "DATA"))
      command(client, "QUIT")
    end

    assert_empty @store.inbound_messages
    assert_empty @store.outbound_messages
  end

  # Drives a session up to the 354 prompt, ready for a DATA payload.
  def start_data(client)
    read_reply(client)
    command(client, "EHLO client.test")
    command(client, "MAIL FROM:<sender@remote.test>")
    command(client, "RCPT TO:<#{EMAIL}>")
    assert_match(/\A354/, command(client, "DATA"))
  end

  def test_bare_lf_dot_does_not_terminate_data
    without_sender_verification do
      with_session do |client|
        start_data(client)
        client.write("line one\r\n.\nline two\r\n.\r\n")
        assert_match(/\A250 OK: queued/, read_reply(client))
        command(client, "QUIT")
      end
    end

    # The ".\n" must be treated as content (its stuffing dot removed), not
    # as a terminator that would leave "line two" as a smuggled command.
    assert_equal "line one\r\n\nline two\r\n", @store.inbound_messages.last[:data]
  end

  def test_data_terminator_recognized_when_crlf_splits_at_chunk_cap
    max_line = MailOnRails::SmtpServer::MAX_LINE
    long_line = "a" * (max_line - 1) # + CRLF: the "\r" lands exactly at the chunk cap
    without_sender_verification do
      with_session do |client|
        start_data(client)
        client.write("#{long_line}\r\n.\r\n")
        assert_match(/\A250 OK: queued/, read_reply(client))
        command(client, "QUIT")
      end
    end

    assert_equal "#{long_line}\r\n", @store.inbound_messages.last[:data]
  end

  def test_oversized_message_gets_552_and_session_survives
    with_session(spec_extra: { max_message_bytes: 200 }) do |client|
      start_data(client)
      client.write(("x" * 48 + "\r\n") * 6) # 300 bytes: over the cap, under 2x
      assert_match(/\A552/, command(client, "."))
      assert_match(/\A250/, command(client, "NOOP"), "session must stay usable after 552")
      assert_match(/\A221/, command(client, "QUIT"))
    end

    assert_empty @store.inbound_messages
  end

  def test_flooding_past_twice_the_cap_drops_the_connection
    with_session(spec_extra: { max_message_bytes: 200 }) do |client|
      start_data(client)
      client.write(("y" * 48 + "\r\n") * 12) # 600 bytes, no terminator
      replies = []
      begin
        while (line = client.gets("\r\n"))
          replies << line
        end
      rescue SystemCallError
        # server may reset the connection with unread bytes in flight
      end
      assert(replies.empty? || replies.first.start_with?("552"),
             "expected 552 or a dropped connection, got #{replies.inspect}")
    end

    assert_empty @store.inbound_messages
  end

  def test_disconnect_mid_data_stores_nothing
    without_sender_verification do
      with_session do |client|
        start_data(client)
        client.write("partial line\r\n")
        client.close
      end
    end

    assert_empty @store.inbound_messages
  end

  def test_received_header_loop_is_rejected
    looping = (1..5).map { |i| "Received: from hop#{i}.test by mx.test with ESMTP; Mon, 20 Jul 2026 0#{i}:00:00 +0000\r\n" }.join +
              "From: sender@remote.test\r\n\r\nbody\r\n"
    without_sender_verification do
      with_session do |client|
        start_data(client)
        client.write(looping)
        assert_match(/\A550 Loop detected/, command(client, "."))

        # Under the threshold (and hops through other hosts) still passes.
        command(client, "MAIL FROM:<sender@remote.test>")
        command(client, "RCPT TO:<#{EMAIL}>")
        assert_match(/\A354/, command(client, "DATA"))
        client.write("Received: from a.test by mx.test; Mon, 20 Jul 2026 01:00:00 +0000\r\n#{RAW}")
        assert_match(/\A250 OK: queued/, command(client, "."))
        command(client, "QUIT")
      end
    end

    assert_equal 1, @store.inbound_messages.size
  end

  def test_auth_is_refused_on_an_unencrypted_channel
    with_session(role: :submission) do |client|
      read_reply(client)
      ehlo = command(client, "EHLO client.test")
      refute_match(/AUTH/, ehlo, "AUTH must not be advertised in the clear")
      assert_match(/\A538/, command(client, "AUTH PLAIN AHgAeQ=="))
      command(client, "QUIT")
    end
  end

  # tls: :implicit marks the channel as already encrypted, so AUTH is
  # offered without a real TLS handshake (this suite runs plaintext).
  def test_auth_login_challenge_sequence
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A334 VXNlcm5hbWU6/, command(client, "AUTH LOGIN"))
      assert_match(/\A334 UGFzc3dvcmQ6/, command(client, [ EMAIL ].pack("m0")))
      assert_match(/\A235/, command(client, [ PASSWORD ].pack("m0")))
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}>"))
      command(client, "QUIT")
    end
  end

  def test_auth_challenge_cancelled_with_star
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A334/, command(client, "AUTH LOGIN"))
      assert_match(/\A501/, command(client, "*"))
      assert_match(/\A250/, command(client, "NOOP"), "session must stay usable after a cancelled AUTH")
      assert_match(/\A530/, command(client, "MAIL FROM:<#{EMAIL}>"),
                   "cancelled AUTH must not leave the session authenticated")
      command(client, "QUIT")
    end
  end

  # -- protocol tracing ------------------------------------------------------

  # Swaps in a store whose log output can be inspected after the session.
  def capture_store_logs
    logs = StringIO.new
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(logs))
    @store.add_account(email: EMAIL, password: PASSWORD)
    logs
  end

  def test_trace_redacts_credentials
    logs = capture_store_logs
    user64 = [ EMAIL ].pack("m0")
    pass64 = [ PASSWORD ].pack("m0")
    plain64 = [ "\0#{EMAIL}\0wrong-password" ].pack("m0")
    with_session(role: :submission, spec_extra: { tls: :implicit, trace: true }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A535/, command(client, "AUTH PLAIN #{plain64}"))
      assert_match(/\A334/, command(client, "AUTH LOGIN"))
      assert_match(/\A334/, command(client, user64))
      assert_match(/\A235/, command(client, pass64))
      command(client, "QUIT")
    end

    trace = logs.string
    assert_includes trace, "<= EHLO client.test", "commands must be traced"
    assert_includes trace, "=> 235 Authentication successful", "replies must be traced"
    assert_includes trace, "<= AUTH PLAIN [redacted]"
    assert_includes trace, "<= [redacted]"
    [ plain64, user64, pass64, PASSWORD, "wrong-password" ].each do |secret|
      refute_includes trace, secret, "credential material leaked into the trace"
    end
  end

  def test_trace_excludes_data_payload
    logs = capture_store_logs
    without_sender_verification do
      with_session(spec_extra: { trace: true }) do |client|
        start_data(client)
        client.write("Subject: secret-subject\r\n\r\nsecret-body-line\r\n.\r\n")
        assert_match(/\A250 OK: queued/, read_reply(client))
        command(client, "QUIT")
      end
    end

    trace = logs.string
    assert_includes trace, "<= DATA"
    refute_includes trace, "secret-subject"
    refute_includes trace, "secret-body-line"
  end

  def test_trace_is_off_by_default
    logs = capture_store_logs
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "QUIT")
    end

    refute_includes logs.string, "<= EHLO", "tracing must be opt-in"
  end
end
