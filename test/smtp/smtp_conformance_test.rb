# frozen_string_literal: true

require "test_helper"
require "logger"
require "stringio"
require "openssl"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# SMTP conformance dialogues at the wire: the syntax, state-machine, and
# abuse-handling behavior RFCs 5321, 1870, 4954, and 3207 require of a
# production receiver. Each test replays one dialogue; the reply codes
# and session outcomes are what it asserts.
class SmtpConformanceTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(StringIO.new))
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  # scan/sender-auth off via their spec seams: these tests exercise the
  # command layer, not the verdict pipeline.
  def with_session(role: :mx, spec_extra: {}, store: @store)
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: role,
             hostname: "mx.test", sender_auth: false, clamav_addr: "" }.merge(spec_extra)
    thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, store, spec, nil).run }
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

  def start_session(client, helo: "client.test")
    read_reply(client)
    command(client, "EHLO #{helo}")
  end

  # -- command syntax (RFC 5321 4.1.1) ---------------------------------------

  def test_mail_and_rcpt_without_an_address_operand_get_501
    with_session do |client|
      start_session(client)
      assert_match(/\A501/, command(client, "MAIL FROM:"))
      assert_match(/\A501/, command(client, "MAIL"))
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A501/, command(client, "RCPT TO:"))
      assert_match(/\A221/, command(client, "QUIT"))
    end
  end

  def test_unclosed_angle_bracket_is_a_syntax_error
    with_session do |client|
      start_session(client)
      assert_match(/\A501/, command(client, "MAIL FROM:<a@b.test"))
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A501/, command(client, "RCPT TO:<#{EMAIL}"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"),
                   "the session must resynchronize after the syntax error")
      command(client, "QUIT")
    end
  end

  def test_junk_or_missing_helo_argument_gets_501
    with_session do |client|
      read_reply(client)
      assert_match(/\A501/, command(client, "HELO !@\#$%^&*("))
      assert_match(/\A501/, command(client, "EHLO"))
      assert_match(/\A250/, command(client, "HELO client.test"),
                   "a well-formed HELO must still succeed afterwards")
      command(client, "QUIT")
    end
  end

  # -- state machine (RFC 5321 4.1.4) ----------------------------------------

  def test_rcpt_before_mail_and_data_before_rcpt_get_503
    with_session do |client|
      start_session(client)
      assert_match(/\A503/, command(client, "RCPT TO:<#{EMAIL}>"))
      assert_match(/\A503/, command(client, "DATA"))
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A503/, command(client, "DATA"), "DATA with zero accepted RCPTs is 503")
      command(client, "QUIT")
    end
  end

  def test_mail_before_ehlo_gets_503
    with_session do |client|
      read_reply(client) # banner only, no greeting sent
      assert_match(/\A503 5\.5\.1 Send EHLO\/HELO first/, command(client, "MAIL FROM:<a@b.test>"))
      # A greeting repairs the session rather than poisoning it.
      assert_match(/\A250/, command(client, "EHLO client.test"))
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      command(client, "QUIT")
    end
  end

  def test_second_mail_in_an_open_transaction_gets_503
    with_session do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A503/, command(client, "MAIL FROM:<other@b.test>"))
      command(client, "QUIT")
    end
  end

  def test_ehlo_aborts_a_pending_transaction
    with_session do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A250/, command(client, "EHLO client.test"), "a repeated EHLO is legal")
      assert_match(/\A503/, command(client, "RCPT TO:<#{EMAIL}>"),
                   "EHLO must have discarded the pending MAIL")
      command(client, "QUIT")
    end
  end

  def test_rset_discards_the_transaction
    with_session do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      assert_match(/\A250/, command(client, "RSET"))
      assert_match(/\A503/, command(client, "DATA"), "RSET must drop sender and recipients")
      assert_match(/\A250/, command(client, "MAIL FROM:<b@c.test>"))
      command(client, "QUIT")
    end
  end

  def test_quit_answers_221_and_closes_the_connection
    with_session do |client|
      start_session(client)
      assert_match(/\A221/, command(client, "QUIT"))
      assert_nil client.gets("\r\n"), "the server must close after QUIT"
    end
  end

  # -- null sender and odd-but-legal addresses (RFC 5321 4.1.2, 4.5.5) -------

  def test_null_sender_is_accepted_end_to_end
    with_session do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write("Subject: bounce\r\n\r\nbody\r\n")
      assert_match(/\A250/, command(client, "."))
      command(client, "QUIT")
    end
    assert_equal "", @store.inbound_messages.last[:mail_from]
  end

  # RFC 5321 4.5.5: a null reverse-path goes to exactly one recipient -
  # more would let a forged bounce fan out across every hosted mailbox.
  def test_null_sender_permits_exactly_one_recipient
    second = "other@example.test"
    @store.add_account(email: second, password: PASSWORD)
    with_session do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      assert_match(/\A501 5\.5\.4 /, command(client, "RCPT TO:<#{second}>"))
      assert_match(/\A354/, command(client, "DATA"), "the first recipient's transaction must survive")
      client.write("Subject: bounce\r\n\r\nbody\r\n")
      assert_match(/\A250/, command(client, "."))
      command(client, "QUIT")
    end
    assert_equal [ EMAIL ], @store.inbound_messages.last[:rcpt_to]
  end

  def test_quoted_local_part_with_spaces_is_a_legal_recipient
    quoted = '"name with spaces"@example.test'
    @store.add_account(email: quoted, password: PASSWORD)
    with_session do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{quoted}>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write("Subject: x\r\n\r\nbody\r\n")
      assert_match(/\A250/, command(client, "."))
      command(client, "QUIT")
    end
  end

  # -- ESMTP MAIL/RCPT parameters (RFC 5321 4.1.1.11, RFC 1870, RFC 6152) ----

  def test_size_parameter_is_enforced_against_the_advertised_limit
    with_session(spec_extra: { max_message_bytes: 5_000 }) do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test> SIZE=1000"))
      command(client, "RSET")
      assert_match(/\A552/, command(client, "MAIL FROM:<a@b.test> SIZE=50000"))
      assert_match(/\A552/, command(client, "MAIL FROM:<a@b.test> SIZE=50000000000000000000000"),
                   "an absurd SIZE must be refused, not overflow")
      assert_match(/\A501/, command(client, "MAIL FROM:<a@b.test> SIZE=abc"))
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test> SIZE=10"),
                   "a within-limit declaration must still be accepted")
      command(client, "QUIT")
    end
  end

  def test_body_and_auth_parameters_in_any_order
    with_session do |client|
      start_session(client)
      [ "BODY=7BIT", "BODY=8BITMIME", "SIZE=1000 BODY=7BIT",
        "BODY=7BIT AUTH=x@y.test SIZE=1000" ].each do |params|
        assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test> #{params}"),
                     "MAIL with '#{params}' must be accepted")
        command(client, "RSET")
      end
      assert_match(/\A501/, command(client, "MAIL FROM:<a@b.test> BODY=wrong"))
      assert_match(/\A555/, command(client, "MAIL FROM:<a@b.test> FOO=BAR"),
                   "an unadvertised MAIL parameter earns RFC 5321's 555")
      command(client, "QUIT")
    end
  end

  def test_rcpt_parameters_are_refused_because_none_are_advertised
    with_session do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A555/, command(client, "RCPT TO:<#{EMAIL}> NOTIFY=NEVER"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      command(client, "QUIT")
    end
  end

  # -- error budget ----------------------------------------------------------

  def test_too_many_syntax_errors_drop_the_connection
    limit = MailOnRails::SmtpServer::MAX_PROTOCOL_ERRORS
    with_session do |client|
      read_reply(client)
      (limit - 1).times do |i|
        assert_match(/\A50[02]/, command(client, "GIBBERISH#{i}"))
      end
      assert_match(/Too many syntax or protocol errors/, command(client, "GIBBERISH-final"))
      assert_nil client.gets("\r\n"), "past the error budget the connection must drop"
    end
  end

  def test_accepted_commands_do_not_count_against_the_error_budget
    with_session do |client|
      start_session(client)
      (MailOnRails::SmtpServer::MAX_PROTOCOL_ERRORS + 2).times do
        assert_match(/\A250/, command(client, "NOOP"))
      end
      assert_match(/\A221/, command(client, "QUIT"))
    end
  end

  # -- recipient and message caps (RFC 5321 4.5.3.1) -------------------------

  def test_recipient_flood_is_bounded_with_452
    with_session do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      MailOnRails::SmtpServer::MAX_RECIPIENTS.times do
        assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      end
      assert_match(/\A452/, command(client, "RCPT TO:<#{EMAIL}>"))
      command(client, "QUIT")
    end
  end

  def test_message_cap_per_session_answers_421
    with_session(spec_extra: { max_messages: 2 }) do |client|
      start_session(client)
      2.times do
        assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
        assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
        assert_match(/\A354/, command(client, "DATA"))
        client.write("Subject: x\r\n\r\nbody\r\n")
        assert_match(/\A250/, command(client, "."))
      end
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      assert_match(/\A421/, command(client, "DATA"))
      command(client, "QUIT")
    end
  end

  # -- DATA dot-stuffing (RFC 5321 4.5.2) ------------------------------------

  def test_dot_unstuffing_including_a_lone_double_dot_line
    with_session do |client|
      start_session(client)
      command(client, "MAIL FROM:<a@b.test>")
      command(client, "RCPT TO:<#{EMAIL}>")
      assert_match(/\A354/, command(client, "DATA"))
      client.write("..: this is legal\r\nFrom: me\r\n\r\n..\r\n..that line started with a dot\r\n")
      assert_match(/\A250/, command(client, "."))
      command(client, "QUIT")
    end

    data = @store.inbound_messages.last[:data]
    assert_includes data, ".: this is legal\r\n", "leading .. must unstuff to ."
    assert_includes data, "\r\n\r\n.\r\n.that", "a lone .. line unstuffs to . without ending DATA"
    assert_includes data, "\r\n.that line started with a dot\r\n"
  end

  def test_data_termination_resynchronizes_the_command_parser
    with_session do |client|
      start_session(client)
      command(client, "MAIL FROM:<a@b.test>")
      command(client, "RCPT TO:<#{EMAIL}>")
      command(client, "DATA")
      client.write("Subject: x\r\n\r\nbody\r\n")
      assert_match(/\A250/, command(client, "."))
      assert_match(/\A250/, command(client, "MAIL FROM:<b@c.test>"),
                   "the dot must end the transaction and return to command dispatch")
      assert_match(/\A501/, command(client, "RCPT TO:<#{EMAIL}"),
                   "after the dot, lines are commands again - and syntax-checked")
      command(client, "QUIT")
    end
  end

  # -- AUTH (RFC 4954) -------------------------------------------------------

  def auth_plain_token(user = EMAIL, pass = PASSWORD)
    [ "\0#{user}\0#{pass}" ].pack("m0")
  end

  def test_auth_plain_challenge_form
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      start_session(client)
      assert_match(/\A334/, command(client, "AUTH PLAIN"))
      assert_match(/\A235/, command(client, auth_plain_token))
      command(client, "QUIT")
    end
  end

  def test_auth_when_already_authenticated_gets_503
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      start_session(client)
      assert_match(/\A235/, command(client, "AUTH PLAIN #{auth_plain_token}"))
      assert_match(/\A503/, command(client, "AUTH PLAIN #{auth_plain_token}"))
      command(client, "QUIT")
    end
  end

  def test_auth_inside_an_open_transaction_gets_503
    with_session(spec_extra: { tls: :implicit }) do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A503/, command(client, "AUTH PLAIN #{auth_plain_token}"))
      command(client, "QUIT")
    end
  end

  def test_unknown_auth_mechanism_gets_504
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      start_session(client)
      assert_match(/\A504/, command(client, "AUTH RHUBARB"))
      command(client, "QUIT")
    end
  end

  def test_rejected_auth_leaves_no_challenge_pending
    with_session(spec_extra: { tls: :implicit }) do |client|
      start_session(client)
      command(client, "MAIL FROM:<a@b.test>")
      assert_match(/\A503/, command(client, "AUTH PLAIN"))
      assert_match(/\A50[02]/, command(client, auth_plain_token),
                   "the orphan credential line must be parsed as a command, not consumed")
      command(client, "QUIT")
    end
  end

  def test_failed_auth_does_not_poison_a_later_success
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      start_session(client)
      assert_match(/\A535/, command(client, "AUTH PLAIN #{auth_plain_token(EMAIL, "wrong")}"))
      assert_match(/\A235/, command(client, "AUTH PLAIN #{auth_plain_token}"),
                   "one failure must not lock the session out")
      command(client, "QUIT")
    end
  end

  # A store that always answers "throttled" - the shape the ActiveRecord
  # backend returns when AuthThrottle has the peer blocked.
  class ThrottlingStore < MailOnRails::Smtp::Store::Memory
    def authenticate(_email, _password, ip: nil, source: nil)
      { account_id: nil, email: nil, throttled: true, retry_after: 300 }
    end
  end

  def test_throttled_auth_is_a_temporary_failure_not_bad_credentials
    store = ThrottlingStore.new(logger: Logger.new(StringIO.new))
    with_session(role: :submission, spec_extra: { tls: :implicit }, store: store) do |client|
      start_session(client)
      assert_match(/\A454/, command(client, "AUTH PLAIN #{auth_plain_token}"),
                   "a throttle must read as 4xx-retry-later, not 535-wrong-password")
      assert_match(/\A250/, command(client, "NOOP"), "the session must survive it")
      command(client, "QUIT")
    end
  end

  # -- pipelining (RFC 2920) -------------------------------------------------

  def test_batched_commands_are_answered_in_order_even_before_the_banner
    with_session do |client|
      client.write("EHLO client.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<#{EMAIL}>\r\nDATA\r\n")
      assert_match(/\A220 /, read_reply(client))
      assert_match(/\A250[- ]/, read_reply(client))
      assert_match(/\A250 /, read_reply(client))
      assert_match(/\A250 /, read_reply(client))
      assert_match(/\A354/, read_reply(client))
      client.write("Subject: x\r\n\r\nbody\r\n")
      assert_match(/\A250/, command(client, "."))
      command(client, "QUIT")
    end
    assert_equal 1, @store.inbound_messages.size
  end

  # -- CHUNKING (RFC 3030) -----------------------------------------------------

  def test_bdat_chunking_assembles_a_message_across_chunks
    with_session do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))

      first = "Subject: chunked\r\n\r\npart one\r\n"
      second = "part two\r\n"
      client.write("BDAT #{first.bytesize}\r\n#{first}")
      assert_match(/\A250 /, read_reply(client))
      client.write("BDAT #{second.bytesize} LAST\r\n#{second}")
      assert_match(/\A250 2\.0\.0 Ok: queued/, read_reply(client))
      command(client, "QUIT")
    end
    assert_equal 1, @store.inbound_messages.size
    # The stamped Received: header precedes the payload; the payload
    # itself must be byte-exact - raw counting, no dot-unstuffing.
    assert @store.inbound_messages.last[:data].end_with?("Subject: chunked\r\n\r\npart one\r\npart two\r\n")
  end

  def test_bdat_and_data_do_not_mix_in_one_transaction
    with_session do |client|
      start_session(client)
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      client.write("BDAT 2\r\nhi")
      assert_match(/\A250 /, read_reply(client))
      assert_match(/\A503/, command(client, "DATA"), "DATA after BDAT is a sequence error (RFC 3030 4.2)")
      assert_match(/\A250/, command(client, "RSET"), "RSET must abandon the chunked transaction")
      assert_match(/\A503/, command(client, "DATA"), "the buffered chunk must be gone after RSET")
      command(client, "QUIT")
    end
    assert_empty @store.inbound_messages
  end

  def test_smtputf8_parameter_is_refused_when_unadvertised
    with_session(spec_extra: { smtputf8: false }) do |client|
      start_session(client)
      assert_match(/\A555/, command(client, "MAIL FROM:<a@b.test> SMTPUTF8"))
      command(client, "QUIT")
    end
  end

  # -- address-literal HELO arguments (RFC 5321 4.1.3) -----------------------

  def test_address_literal_helo_arguments_are_accepted
    with_session do |client|
      read_reply(client)
      assert_match(/\A250/, command(client, "EHLO [127.0.0.1]"))
      assert_match(/\A250/, command(client, "EHLO [IPv6:2001:db8::1]"))
      assert_match(/\A250/, command(client, "HELO [127.0.0.1]"))
      command(client, "QUIT")
    end
  end

  # -- STARTTLS protocol handling (RFC 3207) ---------------------------------

  def test_starttls_with_an_argument_is_a_syntax_error
    with_session do |client|
      start_session(client)
      assert_match(/\A501/, command(client, "STARTTLS now"))
      assert_match(/\A250/, command(client, "NOOP"), "the session must continue in clear")
      command(client, "QUIT")
    end
  end

  def test_starttls_when_unavailable_answers_454_and_the_session_continues
    with_session do |client| # harness passes no TLS context
      start_session(client)
      assert_match(/\A454/, command(client, "STARTTLS"))
      assert_match(/\A250/, command(client, "NOOP"))
      command(client, "QUIT")
    end
  end

  def test_starttls_on_an_already_encrypted_channel_gets_503
    with_session(spec_extra: { tls: :implicit }) do |client|
      start_session(client)
      assert_match(/\A503/, command(client, "STARTTLS"))
      command(client, "QUIT")
    end
  end

  def test_starttls_discards_pre_handshake_state
    listener = TCPServer.new("127.0.0.1", 0)
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", tcp_server: listener, sender_auth: false, clamav_addr: "" }
    thread = Thread.new { MailOnRails::SmtpServer.run(@store, [ spec ], self.class.tls_material) }
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5

    assert_match(/\A220 /, read_reply(client))
    command(client, "EHLO before.test")
    assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
    assert_match(/\A220 /, command(client, "STARTTLS"))
    tls = OpenSSL::SSL::SSLSocket.new(client, OpenSSL::SSL::SSLContext.new)
    tls.sync_close = true
    tls.connect

    assert_match(/\A503/, command(tls, "RCPT TO:<#{EMAIL}>"),
                 "the pre-handshake MAIL must have been discarded (RFC 3207)")
    assert_match(/\A250/, command(tls, "EHLO after.test"))
    assert_match(/\A221/, command(tls, "QUIT"))
  ensure
    tls&.close
    client&.close rescue nil
    thread&.kill
    listener&.close rescue nil
  end

  def self.tls_material
    @tls_material ||= MailOnRails::Netserv::Tls.generate_self_signed
  end

  # -- command timeout (RFC 5321 4.3.3) --------------------------------------

  def test_idle_command_timeout_answers_421_and_closes
    with_session(spec_extra: { timeout: 1 }) do |client|
      read_reply(client)
      assert_match(/\A421/, read_reply(client), "an idle peer must be told why before the close")
      assert_nil client.gets("\r\n")
    end
  end
end
