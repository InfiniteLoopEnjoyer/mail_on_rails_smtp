# frozen_string_literal: true

require "test_helper"
require "logger"
require "stringio"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# Wire dialogues for the envelope extensions added on top of the RFC 5321
# core: the SMTPUTF8 refusal posture (RFC 6531 - not offered, so non-ASCII
# envelopes are refused explicitly), REQUIRETLS (RFC 8689 - recorded on a
# TLS session, refused off one), and the DSN request parameters (RFC 3461
# - submission-only, validated, and recorded onto the outbound queue rows
# the deliverer reads them back from).
class SmtpExtensionsTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(StringIO.new))
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  # tls: :implicit marks the channel as already encrypted, so AUTH (and
  # REQUIRETLS) are offered without a real handshake; tls: :starttls left
  # un-upgraded exercises the plaintext refusals.
  def with_session(role: :submission, tls: :implicit, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: tls, role: role,
             hostname: "mx.test", sender_auth: false, clamav_addr: "" }.merge(spec_extra)
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

  def authenticate(client)
    read_reply(client)
    command(client, "EHLO client.test")
    token = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
    assert_match(/\A235/, command(client, "AUTH PLAIN #{token}"))
  end

  def deliver_body(client)
    assert_match(/\A354/, command(client, "DATA"))
    # From must be the authenticated identity (MSA alignment).
    client.write("From: #{EMAIL}\r\nSubject: t\r\n\r\nbody\r\n.\r\n")
    assert_match(/\A250/, read_reply(client))
  end

  # -- SMTPUTF8 posture (RFC 6531) -------------------------------------------

  def test_non_ascii_mail_from_is_refused_with_5_6_7
    with_session(role: :mx) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A553 5\.6\.7 /, command(client, "MAIL FROM:<pål@example.org>"))
      assert_match(/\A250/, command(client, "MAIL FROM:<pal@example.org>"),
                   "the session must stay usable for ASCII envelopes")
      command(client, "QUIT")
    end
  end

  def test_non_ascii_rcpt_to_is_refused_with_5_6_7
    with_session(role: :mx) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A553 5\.6\.7 /, command(client, "RCPT TO:<üser@example.test>"))
      command(client, "QUIT")
    end
  end

  def test_smtputf8_parameter_gets_a_named_refusal_when_disabled
    with_session(role: :mx, spec_extra: { smtputf8: false }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A555 5\.6\.7 SMTPUTF8 not supported/, command(client, "MAIL FROM:<a@b.test> SMTPUTF8"))
      command(client, "QUIT")
    end
  end

  # -- REQUIRETLS (RFC 8689) ---------------------------------------------------

  def test_requiretls_is_recorded_on_the_outbound_row
    with_session do |client|
      authenticate(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}> REQUIRETLS"))
      assert_match(/\A250/, command(client, "RCPT TO:<friend@elsewhere.test>"))
      deliver_body(client)
      command(client, "QUIT")
    end

    assert_equal true, @store.outbound_messages.last[:requiretls]
  end

  def test_requiretls_takes_no_value
    with_session do |client|
      authenticate(client)
      assert_match(/\A501 5\.5\.4 REQUIRETLS takes no value/,
                   command(client, "MAIL FROM:<#{EMAIL}> REQUIRETLS=YES"))
      command(client, "QUIT")
    end
  end

  def test_requiretls_is_refused_off_a_tls_session
    with_session(role: :mx, tls: :starttls) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A530 5\.7\.4 REQUIRETLS requires a TLS session/,
                   command(client, "MAIL FROM:<a@b.test> REQUIRETLS"))
      command(client, "QUIT")
    end
  end

  def test_requiretls_defaults_off
    with_session do |client|
      authenticate(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}>"))
      assert_match(/\A250/, command(client, "RCPT TO:<friend@elsewhere.test>"))
      deliver_body(client)
      command(client, "QUIT")
    end

    assert_equal false, @store.outbound_messages.last[:requiretls]
  end

  # -- DSN requests (RFC 3461) -------------------------------------------------

  def test_dsn_requests_are_recorded_on_the_outbound_row
    with_session do |client|
      authenticate(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}> RET=HDRS ENVID=QQ314159"))
      assert_match(/\A250/, command(client, "RCPT TO:<friend@elsewhere.test> NOTIFY=SUCCESS,FAILURE " \
                                            "ORCPT=rfc822;friend@elsewhere.test"))
      deliver_body(client)
      command(client, "QUIT")
    end

    row = @store.outbound_messages.last
    assert_equal "HDRS", row[:dsn_ret]
    assert_equal "QQ314159", row[:dsn_envid]
    assert_equal "SUCCESS,FAILURE", row[:dsn_notify]
    assert_equal "rfc822;friend@elsewhere.test", row[:dsn_orcpt]
  end

  def test_dsn_parameters_are_validated
    with_session do |client|
      authenticate(client)
      assert_match(/\A501 5\.5\.4 Invalid RET value/, command(client, "MAIL FROM:<#{EMAIL}> RET=SOME"))
      assert_match(/\A501 5\.5\.4 Invalid ENVID value/, command(client, "MAIL FROM:<#{EMAIL}> ENVID=a=b"))
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}>"))
      assert_match(/\A501 5\.5\.4 Invalid NOTIFY value/,
                   command(client, "RCPT TO:<f@elsewhere.test> NOTIFY=NEVER,FAILURE"),
                   "NEVER must be exclusive")
      assert_match(/\A501 5\.5\.4 Invalid NOTIFY value/,
                   command(client, "RCPT TO:<f@elsewhere.test> NOTIFY=SOMETIMES"))
      assert_match(/\A501 5\.5\.4 Invalid ORCPT value/,
                   command(client, "RCPT TO:<f@elsewhere.test> ORCPT=nosemicolon"))
      assert_match(/\A250/, command(client, "RCPT TO:<f@elsewhere.test> NOTIFY=NEVER"))
      command(client, "QUIT")
    end
  end

  def test_dsn_parameters_are_refused_on_mx
    with_session(role: :mx) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A555 5\.5\.4 MAIL parameter not recognized/,
                   command(client, "MAIL FROM:<a@b.test> RET=FULL"))
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A555 5\.5\.4 RCPT parameter not recognized/,
                   command(client, "RCPT TO:<#{EMAIL}> NOTIFY=SUCCESS"))
      command(client, "QUIT")
    end
  end

  def test_dsn_requests_reset_between_transactions
    with_session do |client|
      authenticate(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}> RET=FULL ENVID=first"))
      assert_match(/\A250/, command(client, "RCPT TO:<one@elsewhere.test> NOTIFY=SUCCESS"))
      deliver_body(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}>"))
      assert_match(/\A250/, command(client, "RCPT TO:<two@elsewhere.test>"))
      deliver_body(client)
      command(client, "QUIT")
    end

    stale = @store.outbound_messages.last
    assert_nil stale[:dsn_ret], "a new transaction must not inherit the previous DSN request"
    assert_nil stale[:dsn_envid]
    assert_nil stale[:dsn_notify]
  end
end
