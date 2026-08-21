# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# SMTPUTF8 (RFC 6531) on the wire: advertised by default, the MAIL
# parameter legalizes UTF-8 envelope addresses for the transaction, the
# declaration lands on the stored/queued message, and everything outside
# a declared transaction keeps the old ASCII-only refusals.
class Smtputf8Test < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: user@example.test\r\nSubject: hi\r\n\r\nbody\r\n"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def with_session(role: :submission, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :implicit, role: role,
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

  def test_utf8_recipient_without_the_parameter_is_refused
    with_session do |client|
      authenticate(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}>"))
      assert_match(/\A553 5\.6\.7 /, command(client, "RCPT TO:<üser@elsewhere.test>"))
      command(client, "QUIT")
    end
  end

  def test_utf8_recipient_with_the_parameter_is_accepted_and_flagged
    with_session do |client|
      authenticate(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}> SMTPUTF8"))
      assert_match(/\A250/, command(client, "RCPT TO:<pelé@example.みんな>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write(RAW)
      assert_match(/\A250 2\.0\.0 Ok: queued/, command(client, "."))
      command(client, "QUIT")
    end

    message = @store.outbound_messages.last
    assert message, "the internationalized recipient must be queued"
    assert_equal true, message[:smtputf8]
    assert_equal "pelé@example.みんな", message[:recipient].dup.force_encoding(Encoding::UTF_8)
  end

  def test_ascii_transaction_records_the_declaration
    with_session do |client|
      authenticate(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}> SMTPUTF8"))
      assert_match(/\A250/, command(client, "RCPT TO:<friend@elsewhere.test>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write(RAW)
      assert_match(/\A250/, command(client, "."))
      command(client, "QUIT")
    end

    assert_equal true, @store.outbound_messages.last[:smtputf8]
  end

  def test_invalid_utf8_bytes_are_refused_even_with_the_parameter
    with_session do |client|
      authenticate(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}> SMTPUTF8"))
      client.write("RCPT TO:<bad\xC3@elsewhere.test>\r\n".b)
      assert_match(/\A501 5\.6\.7 /, read_reply(client))
      command(client, "QUIT")
    end
  end

  def test_parameter_takes_no_value
    with_session do |client|
      authenticate(client)
      assert_match(/\A501/, command(client, "MAIL FROM:<#{EMAIL}> SMTPUTF8=YES"))
      command(client, "QUIT")
    end
  end

  def test_utf8_mail_from_is_accepted_on_mx_with_the_parameter
    with_session(role: :mx) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A250/, command(client, "MAIL FROM:<sänder@remote.test> SMTPUTF8"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write(RAW)
      assert_match(/\A250/, command(client, "."))
      command(client, "QUIT")
    end

    message = @store.inbound_messages.last
    assert message
    assert_equal "sänder@remote.test", message[:mail_from].dup.force_encoding(Encoding::UTF_8)
  end

  def test_disabled_setting_restores_the_old_refusals
    with_session(role: :mx, spec_extra: { smtputf8: false }) do |client|
      read_reply(client)
      reply = command(client, "EHLO client.test")
      refute_includes reply, "SMTPUTF8"
      assert_match(/\A553 5\.6\.7 /, command(client, "MAIL FROM:<sänder@remote.test>"))
      command(client, "QUIT")
    end
  end
end
