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
    singleton = MailOnRails::SenderAuth.singleton_class
    original = MailOnRails::SenderAuth.method(:verify)
    singleton.define_method(:verify) { |**kwargs| calls << kwargs; nil }
    yield calls
  ensure
    singleton.define_method(:verify, original)
  end

  # Pins SenderAuth.verify to a fixed verdict (no live DNS), so a test can
  # drive the DATA-time DMARC branch on a real MX wire session.
  def stubbing_sender_verification(result)
    singleton = MailOnRails::SenderAuth.singleton_class
    original = MailOnRails::SenderAuth.method(:verify)
    singleton.define_method(:verify) { |**| result }
    yield
  ensure
    singleton.define_method(:verify, original)
  end

  # A verdict whose From: domain published p=reject and nothing aligned.
  def dmarc_reject_result(from_domain: "remote.test")
    MailOnRails::SenderAuth::Result.new(
      spf: { result: :fail, domain: from_domain },
      dkim: [],
      dmarc: { result: :fail, policy: :reject, from_domain: from_domain }
    )
  end

  # A verdict where transient DNS failure left DMARC unevaluated.
  def dmarc_temperror_result(from_domain: "remote.test")
    MailOnRails::SenderAuth::Result.new(
      spf: { result: :temperror, domain: from_domain },
      dkim: [],
      dmarc: { result: :temperror, policy: :none, from_domain: from_domain }
    )
  end

  # Makes SenderAuth.verify raise, as a verifier bug would; the session's
  # rescue must not let the message through under enforcement.
  def breaking_sender_verification
    singleton = MailOnRails::SenderAuth.singleton_class
    original = MailOnRails::SenderAuth.method(:verify)
    singleton.define_method(:verify) { |**| raise "verifier bug" }
    yield
  ensure
    singleton.define_method(:verify, original)
  end

  def with_dmarc_enforcement(value)
    previous = ENV["SMTP_DMARC_ENFORCE"]
    value ? ENV["SMTP_DMARC_ENFORCE"] = value : ENV.delete("SMTP_DMARC_ENFORCE")
    yield
  ensure
    previous ? ENV["SMTP_DMARC_ENFORCE"] = previous : ENV.delete("SMTP_DMARC_ENFORCE")
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
        assert_match(/\A250 2\.0\.0 Ok: queued/, deliver_message(client))
      end

      assert_equal 1, calls.size, "SenderAuth.verify must run for unauthenticated MX mail"
    end
  end

  def test_mx_session_skips_sender_verification_when_disabled
    recording_sender_verification do |calls|
      with_session(spec_extra: { sender_auth: false }) do |client|
        assert_match(/\A250 2\.0\.0 Ok: queued/, deliver_message(client))
      end

      assert_empty calls, "SenderAuth.verify must not run when sender auth is off"
    end

    message = @store.inbound_messages.last
    assert_nil message[:auth_results], "a skipped verification must not stamp a verdict"
  end

  # SMTP_DMARC_ENFORCE=1 turns a p=reject DMARC failure into a hard 550 at
  # DATA time, and nothing is spooled. Only the verdict layer was tested
  # before; this drives the actual wire reply.
  def test_mx_session_rejects_spoofed_sender_under_dmarc_enforcement
    with_dmarc_enforcement("1") do
      stubbing_sender_verification(dmarc_reject_result(from_domain: "remote.test")) do
        with_session(spec_extra: { sender_auth: true }) do |client|
          read_reply(client)
          command(client, "EHLO client.test")
          command(client, "MAIL FROM:<sender@remote.test>")
          command(client, "RCPT TO:<#{EMAIL}>")
          command(client, "DATA")
          client.write(RAW)
          reply = command(client, ".")
          assert_match(/\A550 5\.7\.1 /, reply)
          assert_match(/DMARC/i, reply)
          assert_match(/remote\.test/, reply, "the reply should name the failing domain")
          command(client, "QUIT")
        end
      end
    end

    assert_empty @store.inbound_messages, "a DMARC-rejected message must not be spooled"
  end

  # The default (enforcement off): the same failing verdict is recorded on
  # the stored message, not rejected - the documented fail-open that lets
  # operators watch verdicts before flipping the switch.
  def test_mx_session_records_but_does_not_reject_dmarc_failure_when_enforcement_is_off
    with_dmarc_enforcement("0") do
      stubbing_sender_verification(dmarc_reject_result(from_domain: "remote.test")) do
        with_session(spec_extra: { sender_auth: true }) do |client|
          read_reply(client)
          command(client, "EHLO client.test")
          command(client, "MAIL FROM:<sender@remote.test>")
          command(client, "RCPT TO:<#{EMAIL}>")
          command(client, "DATA")
          client.write(RAW)
          assert_match(/\A250 2\.0\.0 Ok: queued/, command(client, "."))
          command(client, "QUIT")
        end
      end
    end

    message = @store.inbound_messages.last
    assert message, "the message must be spooled when enforcement is off"
    assert_match(/dmarc=fail/, message[:auth_results].to_s,
                 "the failing verdict must still be stamped for review")
  end

  # A verifier exception under enforcement must not fail open: no verdict
  # is not a pass, so the session defers (451) and spools nothing.
  def test_mx_session_tempfails_on_verifier_error_under_dmarc_enforcement
    with_dmarc_enforcement("1") do
      breaking_sender_verification do
        with_session(spec_extra: { sender_auth: true }) do |client|
          reply = deliver_message(client)
          assert_match(/\A451 4\.7\.0 /, reply)
          command(client, "QUIT")
        end
      end
    end

    assert_empty @store.inbound_messages, "a deferred message must not be spooled"
  end

  # With enforcement off, a verifier exception keeps today's forgiving
  # path: accept, no Authentication-Results stamp.
  def test_mx_session_accepts_unstamped_on_verifier_error_when_enforcement_is_off
    with_dmarc_enforcement("0") do
      breaking_sender_verification do
        with_session(spec_extra: { sender_auth: true }) do |client|
          assert_match(/\A250 2\.0\.0 Ok: queued/, deliver_message(client))
          command(client, "QUIT")
        end
      end
    end

    message = @store.inbound_messages.last
    assert message, "the message must be spooled when enforcement is off"
    assert_nil message[:auth_results], "a failed verification must not stamp a verdict"
  end

  # DMARC temperror under enforcement defers by default (fail-closed): a
  # DNS outage must not become a spoofing window.
  def test_mx_session_tempfails_on_dmarc_temperror_under_enforcement_by_default
    with_dmarc_enforcement("1") do
      stubbing_sender_verification(dmarc_temperror_result) do
        with_session(spec_extra: { sender_auth: true }) do |client|
          reply = deliver_message(client)
          assert_match(/\A451 4\.7\.0 /, reply)
          command(client, "QUIT")
        end
      end
    end

    assert_empty @store.inbound_messages, "a deferred message must not be spooled"
  end

  # SMTP_SENDER_AUTH_FAIL_CLOSED=0 is the explicit opt-out: temperror is
  # accepted and stamped for review, as before 2026-08-17.
  def test_mx_session_accepts_and_stamps_dmarc_temperror_when_fail_closed_is_off
    MailOnRails::Settings.overrides = { smtp_sender_auth_fail_closed: false }
    with_dmarc_enforcement("1") do
      stubbing_sender_verification(dmarc_temperror_result) do
        with_session(spec_extra: { sender_auth: true }) do |client|
          assert_match(/\A250 2\.0\.0 Ok: queued/, deliver_message(client))
          command(client, "QUIT")
        end
      end
    end

    message = @store.inbound_messages.last
    assert message, "the opted-out session must spool the message"
    assert_match(/dmarc=temperror/, message[:auth_results].to_s,
                 "the temperror verdict must be stamped for review")
  ensure
    MailOnRails::Settings.reset!
  end

  # spec[:hostname] as a callable: the unified app passes a proc that
  # reads the Settings-page value, so each connection announces the
  # current name without a server restart.
  def test_callable_hostname_is_resolved_per_session
    with_session(spec_extra: { hostname: -> { "renamed.test" } }) do |client|
      assert_match(/\A220 renamed\.test ESMTP /, read_reply(client))
      reply = command(client, "EHLO client.test")
      assert_match(/\A250-renamed\.test\r\n/, reply)
      assert_match(/\A221/, command(client, "QUIT"))
    end
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
        assert_match(/\A250 2\.0\.0 Ok: queued/, command(client, "."))
        assert_match(/\A221/, command(client, "QUIT"))
      end
    end

    message = @store.inbound_messages.last
    refute_nil message
    assert_equal [ EMAIL ], message[:rcpt_to]
    assert_equal RAW, strip_received(message[:data])
    assert_nil message[:authenticated_as], "unauthenticated mail must be stored untrusted"
  end

  # Every stored message now leads with our own Received: trace header
  # (two lines, host and timestamp vary); assert it is there and hand back
  # the payload that followed it.
  def strip_received(data)
    assert_match(/\AReceived: from [^\r]*\r\n\t[^\r]*\r\n/, data)
    data.sub(/\AReceived: from [^\r]*\r\n\t[^\r]*\r\n/, "")
  end

  def test_mx_session_rejects_unknown_recipient_and_relay
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      assert_match(/\A550 5\.7\.1 Relaying denied/, command(client, "RCPT TO:<stranger@elsewhere.test>"))
      assert_match(/\A503/, command(client, "DATA"))
      command(client, "QUIT")
    end

    assert_empty @store.inbound_messages
    assert_empty @store.outbound_messages
  end

  # RFC 5321 s4.5.1: a bare <postmaster> (no domain, any case) addresses
  # this server's postmaster and must be accepted; it delivers to
  # postmaster@<our hostname>. No other unqualified recipient gets the
  # carve-out.
  def test_bare_postmaster_is_accepted_and_resolves_to_the_server_hostname
    @store.add_account(email: "postmaster@mx.test", password: PASSWORD)
    without_sender_verification do
      with_session do |client|
        read_reply(client)
        command(client, "EHLO client.test")
        command(client, "MAIL FROM:<sender@remote.test>")
        assert_match(/\A550/, command(client, "RCPT TO:<abuse>"))
        assert_match(/\A250/, command(client, "RCPT TO:<PostMaster>"))
        assert_match(/\A354/, command(client, "DATA"))
        client.write("#{RAW}.\r\n")
        assert_match(/\A250 2\.0\.0 Ok: queued/, read_reply(client))
        command(client, "QUIT")
      end
    end

    assert_equal [ "postmaster@mx.test" ], @store.inbound_messages.last[:rcpt_to]
  end

  # An unknown user in a domain we host is a 5.1.1 "no such user", not
  # the relaying refusal a foreign domain gets.
  def test_mx_session_distinguishes_unknown_local_user_from_relay
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      assert_match(/\A550 5\.1\.1 No such user here/, command(client, "RCPT TO:<stranger@example.test>"))
      command(client, "QUIT")
    end

    assert_empty @store.inbound_messages
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
        assert_match(/\A250 2\.0\.0 Ok: queued/, read_reply(client))
        command(client, "QUIT")
      end
    end

    # The ".\n" must be treated as content (its stuffing dot removed), not
    # as a terminator that would leave "line two" as a smuggled command.
    assert_equal "line one\r\n\nline two\r\n", strip_received(@store.inbound_messages.last[:data])
  end

  def test_data_terminator_recognized_when_crlf_splits_at_chunk_cap
    max_line = MailOnRails::SmtpServer::MAX_LINE
    long_line = "a" * (max_line - 1) # + CRLF: the "\r" lands exactly at the chunk cap
    without_sender_verification do
      with_session do |client|
        start_data(client)
        client.write("#{long_line}\r\n.\r\n")
        assert_match(/\A250 2\.0\.0 Ok: queued/, read_reply(client))
        command(client, "QUIT")
      end
    end

    assert_equal "#{long_line}\r\n", strip_received(@store.inbound_messages.last[:data])
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
        assert_match(/\A550 5\.4\.6 Loop detected/, command(client, "."))

        # Under the threshold (and hops through other hosts) still passes.
        command(client, "MAIL FROM:<sender@remote.test>")
        command(client, "RCPT TO:<#{EMAIL}>")
        assert_match(/\A354/, command(client, "DATA"))
        client.write("Received: from a.test by mx.test; Mon, 20 Jul 2026 01:00:00 +0000\r\n#{RAW}")
        assert_match(/\A250 2\.0\.0 Ok: queued/, command(client, "."))
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

  # Spaces and specials must survive the SASL PLAIN base64 encoding end
  # to end - a password is arbitrary bytes, not a command token.
  def test_auth_plain_password_with_spaces_and_specials_round_trips
    special = "p@ss word+with=specials/&?"
    @store.add_account(email: "specials@example.test", password: special)
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      token = [ "\0specials@example.test\0#{special}" ].pack("m0")
      assert_match(/\A235/, command(client, "AUTH PLAIN #{token}"))
      assert_match(/\A250/, command(client, "MAIL FROM:<specials@example.test>"))
      command(client, "QUIT")
    end
  end

  # The server ties the envelope sender to the login on submission
  # (smtp_server.rb): a compromised or careless client cannot send as
  # someone else once authenticated. Only the matching-sender happy path
  # was tested before; this pins the 550.
  def test_submission_rejects_mail_from_that_does_not_match_the_authenticated_account
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      token = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
      assert_match(/\A235/, command(client, "AUTH PLAIN #{token}"))

      reply = command(client, "MAIL FROM:<someone-else@example.test>")
      assert_match(/\A550 /, reply)
      assert_match(/must match authenticated account/i, reply)

      # The rejection is per-command, not fatal: the matching sender still works.
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}>"),
                   "a mismatched sender must not poison the session")
      command(client, "QUIT")
    end
  end

  # An authorized authzid the account owns still has to match: casing
  # differences are folded, but a different local part is refused.
  def test_submission_sender_match_is_case_insensitive
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      token = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
      assert_match(/\A235/, command(client, "AUTH PLAIN #{token}"))
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL.upcase}>"),
                   "sender match folds case")
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
    # INFO level, like production's default: traces must survive it - the
    # old :debug trace lines were silently dropped exactly where the
    # toggle mattered.
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(logs, level: Logger::INFO))
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
    assert_includes trace, "=> 235 2.7.0 Authentication successful", "replies must be traced"
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
        assert_match(/\A250 2\.0\.0 Ok: queued/, read_reply(client))
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
