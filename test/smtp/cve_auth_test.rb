# frozen_string_literal: true

require "test_helper"
require "logger"
require "stringio"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# Regression tests against known SMTP CVE classes: authentication bypass
# (state-machine confusion - CVE-2019-19521, CVE-2013-6796, CVE-2008-6984),
# open relay (forged envelope/parameters/headers - CVE-2018-0203,
# CVE-2006-0977), and user enumeration (VRFY/EXPN and auth-response oracles -
# CVE-2008-1275, CVE-1999-0531 class). Each test drives a real wire session,
# like smtp_conformance_test.rb; scenarios already covered there or in
# pen_test.rb (AUTH on MX, AUTH mid-transaction, second AUTH, pre-auth
# MAIL/RCPT/DATA on submission, plain relay refusal) are not repeated.
class SmtpCveAuthTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  REMOTE = "victim@foreign.test"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(StringIO.new))
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def with_session(role: :mx, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: role,
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

  def auth_plain_token(user = EMAIL, pass = PASSWORD)
    [ "\0#{user}\0#{pass}" ].pack("m0")
  end

  # -- class: authentication bypass ------------------------------------------

  # CVE-2019-19521 class: a crafted credential or command ordering must
  # never leave the session authenticated. AUTH before EHLO is tolerated
  # (RFC 4954 does not forbid it), but it must not unlock the rest of the
  # state machine - MAIL still requires a greeting, and after the greeting
  # the authenticated-sender tie still holds.
  def test_auth_before_ehlo_does_not_unlock_the_mail_state_machine
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client) # banner only - no EHLO sent
      assert_match(/\A235/, command(client, "AUTH PLAIN #{auth_plain_token}"),
                   "pins current behavior: AUTH is processed pre-EHLO")
      assert_match(/\A503 5\.5\.1 Send EHLO\/HELO first/, command(client, "MAIL FROM:<#{EMAIL}>"),
                   "pre-EHLO AUTH must not bypass the greeting requirement")
      assert_match(/\A250/, command(client, "EHLO client.test"))
      assert_match(/\A550 /, command(client, "MAIL FROM:<someone-else@example.test>"),
                   "the sender/account tie must survive the odd ordering")
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}>"))
      command(client, "QUIT")
    end
  end

  # CVE-2013-6796 class (DeepOfix: empty password triggered an LDAP
  # anonymous bind and authenticated everyone): an empty password must be
  # an authentication failure, never a pass-through.
  def test_auth_with_an_empty_password_is_refused
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A535/, command(client, "AUTH PLAIN #{auth_plain_token(EMAIL, "")}"))
      assert_match(/\A530/, command(client, "MAIL FROM:<#{EMAIL}>"),
                   "an empty-password AUTH must not leave the session authenticated")
      command(client, "QUIT")
    end
  end

  def test_auth_with_empty_username_and_password_is_refused
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A535/, command(client, "AUTH PLAIN #{auth_plain_token("", "")}"))
      assert_match(/\A530/, command(client, "MAIL FROM:<#{EMAIL}>"))
      command(client, "QUIT")
    end
  end

  # CVE-2008-6984 class (Plesk: crafted base64 confused the credential
  # parser into a match): undecodable or structurally short SASL PLAIN
  # tokens must fail closed as bad credentials.
  def test_auth_with_malformed_sasl_plain_tokens_is_refused
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A535/, command(client, "AUTH PLAIN !!!not-base64!!!"))
      # Valid base64, but no NUL separators at all.
      assert_match(/\A535/, command(client, "AUTH PLAIN #{[ EMAIL ].pack("m0")}"))
      assert_match(/\A530/, command(client, "MAIL FROM:<#{EMAIL}>"),
                   "no malformed token may leave the session authenticated")
      command(client, "QUIT")
    end
  end

  # -- class: open relay -----------------------------------------------------

  # RFC 4954's MAIL AUTH= parameter is a *claim* of prior authentication.
  # CVE-2018-0203 class: trusting client-supplied envelope trust markers
  # turns the MX into a relay. The parameter must be ignored, never
  # believed.
  def test_forged_auth_mail_parameter_does_not_authorize_relay_on_mx
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A250/, command(client, "MAIL FROM:<sender@remote.test> AUTH=#{EMAIL}"),
                   "AUTH= is accepted and ignored per RFC 4954")
      assert_match(/\A550 5\.7\.1 Relaying denied/, command(client, "RCPT TO:<#{REMOTE}>"),
                   "a forged AUTH= claim must not unlock relaying")
      command(client, "QUIT")
    end

    assert_empty @store.outbound_messages
  end

  def test_forged_auth_mail_parameter_does_not_bypass_submission_auth
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A530/, command(client, "MAIL FROM:<#{EMAIL}> AUTH=#{EMAIL}"),
                   "AUTH= must not substitute for a real AUTH on submission")
      command(client, "QUIT")
    end

    assert_empty @store.outbound_messages
  end

  # Routing must follow the envelope, never message headers: forged
  # To/Cc/Bcc headers naming foreign addresses on unauthenticated MX mail
  # must not generate outbound deliveries (the forged-Bcc relay shape).
  def test_forged_bcc_and_to_headers_do_not_route_mail_outbound
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write("From: sender@remote.test\r\n" \
                   "To: #{REMOTE}\r\n" \
                   "Cc: other@foreign.test\r\n" \
                   "Bcc: hidden@foreign.test\r\n" \
                   "\r\nbody\r\n")
      assert_match(/\A250 2\.0\.0 Ok: queued/, command(client, "."))
      command(client, "QUIT")
    end

    assert_empty @store.outbound_messages, "header recipients must never drive outbound routing"
    message = @store.inbound_messages.last
    refute_nil message
    assert_equal [ EMAIL ], message[:rcpt_to], "delivery must follow the envelope alone"
  end

  # -- class: user enumeration -----------------------------------------------

  # CVE-1999-0531 / CVE-2008-1275 class: VRFY must answer identically for
  # a provisioned account and a stranger, in both configured stances.
  def test_vrfy_reply_is_identical_for_existing_and_unknown_users
    with_session do |client|
      read_reply(client)
      known = command(client, "VRFY #{EMAIL}")
      unknown = command(client, "VRFY stranger-nobody@example.test")
      assert_match(/\A252 /, known)
      assert_equal known, unknown, "VRFY must not distinguish valid from invalid users"
      command(client, "QUIT")
    end
  end

  def test_vrfy_502_stance_is_identical_for_existing_and_unknown_users
    MailOnRails::Settings.overrides = { smtp_vrfy_response: "502" }
    with_session do |client|
      read_reply(client)
      known = command(client, "VRFY #{EMAIL}")
      unknown = command(client, "VRFY stranger-nobody@example.test")
      assert_match(/\A502 /, known)
      assert_equal known, unknown
      command(client, "QUIT")
    end
  ensure
    MailOnRails::Settings.reset!
  end

  def test_expn_is_refused
    with_session do |client|
      read_reply(client)
      assert_match(/\A502 /, command(client, "EXPN staff-list"))
      command(client, "QUIT")
    end
  end

  # The AUTH failure reply must not disclose whether the username exists:
  # unknown-user and wrong-password failures must be byte-identical.
  def test_auth_failure_reply_is_identical_for_unknown_user_and_wrong_password
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      unknown_user = command(client, "AUTH PLAIN #{auth_plain_token("nobody@example.test", PASSWORD)}")
      wrong_password = command(client, "AUTH PLAIN #{auth_plain_token(EMAIL, "wrong-password")}")
      assert_match(/\A535 /, unknown_user)
      assert_equal unknown_user, wrong_password,
                   "the 535 must not reveal whether the account exists"
      refute_match(/no such|unknown|not found/i, unknown_user)
      command(client, "QUIT")
    end
  end

  # SCRAM's server-first challenge hands out salt and iteration count
  # before any proof. Real accounts have a stable salt, so decoy material
  # for unknown users must be deterministic too - a salt that changed per
  # connection would be a username oracle. (scram_smtp_test.rb already
  # covers that a decoy challenge is issued at all; this pins stability.)
  def test_scram_decoy_challenge_is_stable_across_sessions_for_the_same_unknown_user
    first = scram_server_first("nobody@example.test")
    second = scram_server_first("nobody@example.test")
    assert_equal first["s"], second["s"], "decoy salt must not vary across connections"
    assert_equal first["i"], second["i"], "decoy iteration count must not vary"

    known = scram_server_first(EMAIL)
    assert_equal known["i"], first["i"],
                 "decoy iteration count must match real accounts' - a differing i= is an oracle"
  end

  # Opens a session, starts a SCRAM exchange for +user+, and returns the
  # parsed server-first attributes (r=, s=, i=); the exchange is then
  # cancelled with "*".
  def scram_server_first(user)
    attrs = nil
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      client_first = [ "n,,n=#{user},r=clientnonce0000" ].pack("m0")
      reply = command(client, "AUTH SCRAM-SHA-256 #{client_first}")
      assert_match(/\A334 /, reply, "expected a server-first challenge for #{user}")
      server_first = reply[4..].chomp("\r\n").unpack1("m0")
      attrs = server_first.split(",").to_h { |part| [ part[0], part[2..] ] }
      command(client, "*")
      command(client, "QUIT")
    end
    attrs
  end
end
