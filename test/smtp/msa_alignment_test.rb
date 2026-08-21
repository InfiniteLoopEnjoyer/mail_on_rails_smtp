# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# RFC 6409 MSA authorization on the wire: an authenticated submission's
# envelope sender AND visible From:/Sender: headers must be identities
# the login owns - the account or one of its aliases. Everything else is
# refused 550 before any scanner or store sees the message.
class MsaAlignmentTest < Minitest::Test
  EMAIL = "user@example.test"
  ALIAS = "boss@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD, aliases: [ ALIAS ])
  end

  def with_session(spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :implicit, role: :submission,
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

  # AUTH + MAIL/RCPT + DATA with the given header block; returns the
  # final DATA reply.
  def submit(headers, mail_from: EMAIL)
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      token = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
      assert_match(/\A235/, command(client, "AUTH PLAIN #{token}"))
      reply = command(client, "MAIL FROM:<#{mail_from}>")
      return reply unless reply.start_with?("250")

      assert_match(/\A250/, command(client, "RCPT TO:<friend@elsewhere.test>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write("#{headers}\r\n\r\nbody\r\n")
      reply = command(client, ".")
      command(client, "QUIT")
      reply
    end
  end

  def test_from_matching_the_account_is_accepted
    assert_match(/\A250 2\.0\.0 Ok: queued/, submit("From: #{EMAIL}\r\nSubject: hi"))
  end

  def test_alias_works_for_envelope_and_from_and_rides_the_queue_row
    reply = submit("From: Boss <#{ALIAS}>\r\nSubject: hi", mail_from: ALIAS)
    assert_match(/\A250 2\.0\.0 Ok: queued/, reply)
    assert_equal ALIAS, @store.outbound_messages.last[:mail_from],
                 "the alias Return-Path the sender chose must reach the queue row"
  end

  def test_foreign_envelope_sender_is_refused
    assert_match(/\A550 5\.7\.1 Sender address must match/, submit("From: #{EMAIL}", mail_from: "ceo@bank.test"))
  end

  def test_foreign_from_header_is_refused
    assert_match(/\A550 5\.7\.1 From address/, submit("From: CEO <ceo@bank.test>\r\nSubject: urgent wire"))
    assert_empty @store.outbound_messages
  end

  def test_missing_from_header_is_refused
    assert_match(/\A550 5\.7\.1 message has no From header/, submit("Subject: hi"))
  end

  def test_multiple_froms_must_all_be_owned
    assert_match(/\A550 5\.7\.1 From address/, submit("From: #{EMAIL}, ceo@bank.test\r\nSubject: hi"))
    assert_match(/\A250/, submit("From: #{EMAIL}, Boss <#{ALIAS}>\r\nSubject: hi"))
  end

  def test_foreign_sender_header_is_refused
    assert_match(/\A550 5\.7\.1 Sender address/, submit("From: #{EMAIL}\r\nSender: ceo@bank.test\r\nSubject: hi"))
    assert_match(/\A250/, submit("From: #{ALIAS}\r\nSender: #{EMAIL}\r\nSubject: hi"))
  end

  def test_unparseable_from_is_refused_never_passed
    assert_match(/\A550 5\.7\.1 From address/, submit("From: \"unterminated <#{EMAIL}>\r\nSubject: hi"))
  end

  def test_opt_out_restores_the_old_behavior
    MailOnRails::Settings.overrides = { smtp_from_alignment: false }
    assert_match(/\A250/, submit("From: CEO <ceo@bank.test>\r\nSubject: hi"))
  ensure
    MailOnRails::Settings.reset!
  end

  def test_unauthenticated_mx_mail_is_never_from_checked
    with_session(spec_extra: { role: :mx, tls: :starttls }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A250/, command(client, "MAIL FROM:<sender@remote.test>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write("From: anyone@anywhere.test\r\nSubject: hi\r\n\r\nbody\r\n")
      assert_match(/\A250/, command(client, "."), "MX mail is judged by SPF/DKIM/DMARC, not MSA alignment")
      command(client, "QUIT")
    end
  end
end
