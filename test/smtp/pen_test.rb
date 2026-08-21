# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# Penetration-test scenarios for SMTP: attacker-shaped wire sessions that
# exercise common abuse paths (relay, envelope spoofing, auth bypass, smuggling).
# Fuzzing lives in smtp_parser_abuse_test.rb; RFC dialogues in
# smtp_conformance_test.rb.
#
# Run via bin/rails test:smtp_server (or bin/rails test with this path).
class SmtpPenTest < Minitest::Test
  ALICE = "alice@example.test"
  BOB = "bob@example.test"
  PASSWORD = "pw-123456"
  REMOTE = "victim@foreign.test"
  RAW = "From: sender@remote.test\r\nSubject: pen\r\n\r\nbody\r\n"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: ALICE, password: PASSWORD)
    @store.add_account(email: BOB, password: PASSWORD)
  end

  def with_session(role: :mx, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: role,
             hostname: "mx.test", sender_auth: false }.merge(spec_extra)
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

  def auth_plain_token(user = ALICE, pass = PASSWORD)
    [ "\0#{user}\0#{pass}" ].pack("m0")
  end

  def authenticate_submission(client, user: ALICE, pass: PASSWORD)
    read_reply(client)
    command(client, "EHLO client.test")
    assert_match(/\A235/, command(client, "AUTH PLAIN #{auth_plain_token(user, pass)}"))
  end

  def without_sender_verification
    singleton = MailOnRails::SenderAuth.singleton_class
    original = MailOnRails::SenderAuth.method(:verify)
    singleton.define_method(:verify) { |**| nil }
    yield
  ensure
    singleton.define_method(:verify, original)
  end

  # -- relay and role separation ---------------------------------------------

  def test_mx_refuses_to_relay_to_a_foreign_domain
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      assert_match(/\A550 5\.7\.1 Relaying denied/, command(client, "RCPT TO:<#{REMOTE}>"))
      command(client, "QUIT")
    end

    assert_empty @store.inbound_messages
    assert_empty @store.outbound_messages
  end

  def test_mx_refuses_auth_and_remote_recipients_even_on_an_encrypted_channel
    with_session(spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      # AUTH is submission-only: a credentialed MX session would skip the
      # sender-auth gates (SPF/DKIM/DMARC, DNSBL) unauthenticated MX mail
      # must pass, so even a valid credential is refused here.
      assert_match(/\A503 5\.5\.1 AUTH not available/, command(client, "AUTH PLAIN #{auth_plain_token}"))
      assert_match(/\A250/, command(client, "MAIL FROM:<#{ALICE}>"))
      assert_match(/\A550 5\.7\.1 Relaying denied/, command(client, "RCPT TO:<#{REMOTE}>"))
      command(client, "QUIT")
    end

    assert_empty @store.outbound_messages
  end

  def test_submission_rejects_a_mail_transaction_before_authentication
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A530/, command(client, "MAIL FROM:<#{ALICE}>"))
      assert_match(/\A503/, command(client, "RCPT TO:<#{REMOTE}>"))
      assert_match(/\A503/, command(client, "DATA"))
      command(client, "QUIT")
    end
  end

  def test_submission_rejects_remote_rcpt_without_authentication
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A530/, command(client, "MAIL FROM:<#{ALICE}>"))
      assert_match(/\A503/, command(client, "RCPT TO:<#{REMOTE}>"))
      command(client, "QUIT")
    end
  end

  # -- envelope identity -----------------------------------------------------

  def test_submission_rejects_mail_from_that_does_not_match_the_authenticated_identity
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      authenticate_submission(client)
      assert_match(/\A550 5\.7\.1 Sender address must match authenticated account/,
                   command(client, "MAIL FROM:<#{BOB}>"))
      assert_match(/\A503/, command(client, "RCPT TO:<#{REMOTE}>"))
      command(client, "QUIT")
    end

    assert_empty @store.outbound_messages
  end

  def test_mail_from_match_is_case_insensitive
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      authenticate_submission(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<#{ALICE.upcase}>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{REMOTE}>"))
      command(client, "QUIT")
    end
  end

  def test_sasl_plain_authzid_cannot_impersonate_the_envelope_sender
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      token = [ "#{ALICE}\0#{BOB}\0#{PASSWORD}" ].pack("m0")
      assert_match(/\A235/, command(client, "AUTH PLAIN #{token}"))
      assert_match(/\A550 5\.7\.1 Sender address must match authenticated account/,
                   command(client, "MAIL FROM:<#{ALICE}>"))
      assert_match(/\A250/, command(client, "MAIL FROM:<#{BOB}>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{REMOTE}>"))
      assert_match(/\A354/, command(client, "DATA"))
      # From must be the authenticated identity too (MSA alignment).
      client.write("From: #{BOB}\r\nSubject: pen\r\n\r\nbody\r\n.\r\n")
      assert_match(/\A250/, read_reply(client))
      command(client, "QUIT")
    end

    refute_empty @store.outbound_messages
    assert_equal BOB, @store.outbound_messages.last[:mail_from]
  end

  # -- transport hardening ---------------------------------------------------

  def test_mx_rejects_auth_on_an_unencrypted_channel
    with_session(role: :mx) do |client|
      read_reply(client)
      ehlo = command(client, "EHLO client.test")
      refute_match(/AUTH/, ehlo)
      assert_match(/\A503 5\.5\.1 AUTH not available/, command(client, "AUTH PLAIN #{auth_plain_token}"))
      command(client, "QUIT")
    end
  end

  def test_pipelined_mail_commands_on_submission_before_auth_are_all_refused
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      client.write("MAIL FROM:<#{ALICE}>\r\nRCPT TO:<#{REMOTE}>\r\nDATA\r\n")
      assert_match(/\A530/, read_reply(client))
      assert_match(/\A503/, read_reply(client))
      assert_match(/\A503/, read_reply(client))
      command(client, "QUIT")
    end
  end

  # -- smuggling --------------------------------------------------------------
  # Malformed end-of-data sequences: smtp_smuggling_test.rb (hannob/smtpsmug
  # + The-Login/SMTP-Smuggling-Tools).

  def test_data_terminator_resynchronizes_the_command_parser
    without_sender_verification do
      with_session do |client|
        read_reply(client)
        command(client, "EHLO client.test")
        command(client, "MAIL FROM:<sender@remote.test>")
        command(client, "RCPT TO:<#{ALICE}>")
        assert_match(/\A354/, command(client, "DATA"))
        client.write("Subject: inject\r\n\r\npayload\r\n.\r\n")
        assert_match(/\A250/, read_reply(client))
        assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
        assert_match(/\A501/, command(client, "RCPT TO:<#{REMOTE}"))
        command(client, "QUIT")
      end
    end

    assert_equal 1, @store.inbound_messages.size
  end

  def test_smtp_command_injection_in_ehlo_argument_does_not_produce_extra_reply_lines
    with_session do |client|
      read_reply(client)
      reply = command(client, "EHLO evil.test\r\nMAIL FROM:<a@b.test>")
      reply.split("\r\n").each { |line| assert_match(/\A\d{3}[ -]/, line) }
      refute_match(/MAIL FROM/, reply)
      command(client, "QUIT")
    end
  end
end
