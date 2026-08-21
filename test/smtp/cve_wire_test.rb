# frozen_string_literal: true

require "test_helper"
require "logger"
require "stringio"
require "openssl"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# CVE-class regression coverage for the SMTP receiver, driven through the
# real session/socket layer (never by stubbing internals). Each test maps to
# a known family of SMTP-server bugs:
#
#   * STARTTLS plaintext command injection (CVE-2011-0411 and the ~15 issues
#     that share its shape: nginx CVE-2014-3556, Dovecot CVE-2021-33515,
#     Postfix, qmail, INN, Kerio, ...). Cleartext bytes pipelined before the
#     TLS handshake must be discarded, never executed inside the TLS session.
#   * BDAT / CHUNKING (CVE-2017-16943/44, CVE-2002-0055): the verb is neither
#     advertised nor implemented, so it can never open a chunked data phase a
#     dot-terminator confusion could smuggle through.
#   * NUL bytes in commands (CVE-2006-3277 MailEnable HELO NUL, CVE-2003-0743
#     Exim, CVE-2020-35680 OpenSMTPD): a NUL anywhere in a command line must
#     be refused cleanly, never crash the parser or corrupt envelope state.
#   * SMTP response splitting (CVE-2025-7962 Jakarta Mail, CVE-2025-57733):
#     attacker bytes echoed into a reply must not inject new reply lines.
#
# Smuggling end-of-data sequences already have dedicated coverage in
# smtp_smuggling_test.rb; this file covers the sibling classes.
class CveWireTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @logs = StringIO.new
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(@logs))
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def teardown
    refute_includes @logs.string, "SMTP session error",
                    "a hostile command must never crash the parser (Session#run catch-all)"
  end

  # Direct-session harness (matches smtp_conformance_test.rb): no TLS context,
  # so STARTTLS is unavailable but every plaintext command path is exercised.
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

  # -- STARTTLS plaintext command injection (CVE-2011-0411 family) ------------
  #
  # The whole family is buffering: a MITM (or a client fuzz) pipelines
  # cleartext SMTP commands in the same segment as STARTTLS, and a vulnerable
  # server keeps them buffered across the plaintext->TLS boundary and executes
  # them as if they arrived inside the encrypted, trusted session. The defense
  # is that the pre-handshake read buffer is dropped: this server swaps @socket
  # for a fresh SSLSocket over the raw fd, orphaning any cleartext still in the
  # old TCPSocket's read buffer. These tests need a real TLS context, so they
  # drive the full listener via SmtpServer.run with the tcp_server seam.

  def self.tls_material
    @tls_material ||= MailOnRails::Netserv::Tls.generate_self_signed
  end

  def run_listener(role: :mx)
    listener = TCPServer.new("127.0.0.1", 0)
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: role,
             hostname: "mx.test", tcp_server: listener, sender_auth: false, clamav_addr: "" }
    thread = Thread.new { MailOnRails::SmtpServer.run(@store, [ spec ], self.class.tls_material) }
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    yield client
  ensure
    client&.close
    thread&.kill
    listener&.close
  end

  def test_cleartext_command_pipelined_with_starttls_is_not_executed_after_tls
    run_listener do |client|
      assert_match(/\A220 /, read_reply(client))
      command(client, "EHLO before.test")

      # Attacker injects an EHLO in the same write as STARTTLS. A vulnerable
      # server buffers it and runs it inside the TLS session (setting
      # @helo_name), so the post-TLS MAIL FROM would be accepted.
      client.write("STARTTLS\r\nEHLO injected.attacker.test\r\n")
      assert_match(/\A220 /, read_reply(client), "STARTTLS must be answered before the handshake")

      tls = OpenSSL::SSL::SSLSocket.new(client, OpenSSL::SSL::SSLContext.new)
      tls.sync_close = true
      tls.connect

      # If the injected EHLO had survived the boundary, HELO state would be
      # set and this MAIL FROM would earn a 250. A 503 proves the cleartext
      # bytes were discarded, exactly as RFC 3207 / CVE-2011-0411 require.
      assert_match(/\A503 5\.5\.1 Send EHLO\/HELO first/, command(tls, "MAIL FROM:<a@b.test>"),
                   "cleartext pipelined past STARTTLS must not run inside the TLS session")
      assert_match(/\A250/, command(tls, "EHLO after.test"),
                   "a fresh in-TLS greeting must still work")
      command(tls, "QUIT")
      tls.close
    end
  end

  def test_cleartext_pipelined_past_starttls_leaves_no_stored_message
    run_listener do |client|
      assert_match(/\A220 /, read_reply(client))
      command(client, "EHLO before.test")

      # A full injected transaction (MAIL/RCPT/DATA/body) pipelined with
      # STARTTLS must vanish, not smuggle a message into the encrypted phase.
      client.write("STARTTLS\r\n" \
                   "MAIL FROM:<spoof@evil.test>\r\nRCPT TO:<#{EMAIL}>\r\nDATA\r\n" \
                   "Subject: injected\r\n\r\nsmuggled body\r\n.\r\n")
      assert_match(/\A220 /, read_reply(client))

      tls = OpenSSL::SSL::SSLSocket.new(client, OpenSSL::SSL::SSLContext.new)
      tls.sync_close = true
      tls.connect
      # The very next in-TLS command must be answered as a command (503,
      # needs greeting) rather than swallowed as buffered DATA payload.
      assert_match(/\A503/, command(tls, "RCPT TO:<#{EMAIL}>"))
      command(tls, "QUIT")
      tls.close
    end

    assert_empty @store.inbound_messages,
                 "no message may be assembled from cleartext buffered across STARTTLS"
  end

  # -- BDAT / CHUNKING (CVE-2017-16943/44, CVE-2002-0055) ---------------------
  #
  # CHUNKING is implemented by exact octet counting: chunk bytes are read
  # raw off the socket, never scanned for terminators and never parsed as
  # commands. The confusions those Exim CVEs turned on - bare-dot
  # terminators inside chunks, length-counting desync between the chunk
  # and the command stream - therefore have no surface: a "." line inside
  # a chunk is payload, and a refused BDAT still consumes its declared
  # octets so the command stream stays aligned.

  def test_bdat_dot_lines_are_payload_never_terminators
    with_session do |client|
      read_reply(client)
      assert_match(/CHUNKING/, command(client, "EHLO client.test"))
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))

      # A chunk full of DATA-phase terminators and pipelined command text.
      # Exact counting must keep every byte as payload; the NOOP after the
      # declared length is the first real command again.
      payload = "Subject: s\r\n\r\n.\r\nMAIL FROM:<evil@x.test>\r\n.\r\n"
      client.write("BDAT #{payload.bytesize} LAST\r\n#{payload}NOOP\r\n")
      assert_match(/\A250 2\.0\.0 Ok: queued/, read_reply(client))
      assert_match(/\A250 2\.0\.0 Ok/, read_reply(client), "the byte after the chunk is command stream again")
      command(client, "QUIT")
    end

    assert_equal 1, @store.inbound_messages.size
    assert @store.inbound_messages.last[:data].include?("\r\n.\r\nMAIL FROM:<evil@x.test>\r\n.\r\n"),
           "every declared octet must land in the payload verbatim"
  end

  def test_bdat_without_a_transaction_consumes_its_chunk_and_resynchronizes
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      # No MAIL/RCPT: the BDAT is refused, but its declared octets - which
      # spell out SMTP commands - must be swallowed, not executed.
      chunk = "MAIL FROM:<evil@x.test>\r\nNOOP\r\n"
      client.write("BDAT #{chunk.bytesize}\r\n#{chunk}")
      assert_match(/\A503/, read_reply(client))
      # The session stays in command mode and remains fully usable.
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      command(client, "QUIT")
    end

    assert_empty @store.inbound_messages, "a refused BDAT must not assemble a stored message"
  end

  # -- NUL bytes in commands (CVE-2006-3277, CVE-2003-0743, CVE-2020-35680) ---
  #
  # A NUL embedded anywhere in a command line must be refused cleanly and must
  # never crash the parser (teardown forbids "SMTP session error") nor leave
  # envelope state behind. Command lines are read up to CRLF, so a NUL earlier
  # in the line survives into the argument - exactly the MailEnable/Exim HELO
  # crash vector.

  def test_nul_byte_in_helo_argument_is_refused_and_session_survives
    with_session do |client|
      read_reply(client)
      assert_match(/\A501/, command(client, "EHLO host\x00injected.test"),
                   "a NUL in the HELO argument must be a syntax error, not a crash")
      # No HELO state was set, and the session is still usable.
      assert_match(/\A503/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A250/, command(client, "EHLO clean.test"))
      command(client, "QUIT")
    end
  end

  def test_leading_and_embedded_nul_bytes_do_not_corrupt_envelope_state
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      # Lone NUL line, NUL-prefixed verb, and NUL inside the address - each
      # rejected, none setting @mail_from.
      assert_match(/\A50[0-9]/, command(client, "\x00"))
      assert_match(/\A50[0-9]/, command(client, "\x00MAIL FROM:<a@b.test>"))
      assert_match(/\A501/, command(client, "MAIL FROM:<a@b\x00.test>"))
      # A clean MAIL FROM now must start a fresh transaction (proving none of
      # the above set envelope state).
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
      assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
      command(client, "QUIT")
    end

    assert_empty @store.inbound_messages
  end

  # -- SMTP response splitting (CVE-2025-7962, CVE-2025-57733) ----------------
  #
  # Every reply flows through Session#sanitize_reply, which flattens
  # non-printable bytes to spaces, so attacker input echoed into a reply
  # (the EHLO/HELO greeting is the only echo path) can never inject a second
  # reply line. The parser also rejects CR/LF-bearing greetings outright.

  def test_crlf_in_helo_argument_cannot_inject_a_second_reply_line
    with_session do |client|
      read_reply(client)
      # The bare LF cannot become a new "250 ..." line the client would read
      # as a separate, forged reply.
      reply = command(client, "EHLO a.test\nMAIL FROM:<spoof@evil.test>")
      reply.split("\r\n").each do |line|
        assert_match(/\A\d{3}[ -]/, line, "every physical reply line must be well-formed: #{reply.inspect}")
      end
      refute_match(/MAIL FROM/, reply, "echoed input must not surface as its own reply line")
      assert_match(/\A250/, command(client, "NOOP"), "the session must remain usable")
      command(client, "QUIT")
    end
  end

  def test_control_bytes_reaching_a_reply_echo_are_flattened
    with_session do |client|
      read_reply(client)
      # A HELO name that reaches the echoed greeting must not carry raw
      # control bytes onto the wire; the argument validator rejects it (501),
      # and whatever reply comes back is a single well-formed line.
      reply = command(client, "HELO good\x07\rname")
      reply.split("\r\n").each { |line| assert_match(/\A\d{3}[ -]/, line) }
      refute_match(/[\x00-\x08\x0b\x0c\x0e-\x1f]/, reply,
                   "no raw control byte may be echoed back into a reply")
      command(client, "QUIT")
    end
  end
end
