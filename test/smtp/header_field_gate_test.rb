# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The end-of-DATA header gates (2026-11-17 audit, H1/M1/M7).
#
# A header field whose name carries a control byte is refused outright:
# parsers disagree about where such a name ends (the Mail gem's rstrip
# drops VT/FF, a [ \t]* scan does not), and every one of those
# disagreements was a forged trusted header or a hidden second From.
# Refusing at the edge means no stored message contains the shape at all,
# whatever reads it later. And the header block as a whole is capped -
# every header parser downstream is linear at best in its size.
class HeaderFieldGateTest < Minitest::Test
  EMAIL = "user@example.test"
  ALIAS = "boss@example.test"
  PASSWORD = "pw-123456"
  SENDER = "sender@remote.test"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD, aliases: [ ALIAS ])
  end

  def with_session(role: :mx, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: (role == :mx ? :starttls : :implicit), role: role,
             hostname: "mx.test", sender_auth: false, clamav_addr: "", rspamd_addr: "" }.merge(spec_extra)
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

  # One inbound (MX) message; returns the final DATA reply.
  def deliver(message, spec_extra: {}, via: :data)
    with_session(spec_extra: spec_extra) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<#{SENDER}>")
      command(client, "RCPT TO:<#{EMAIL}>")
      if via == :bdat
        client.write("BDAT #{message.bytesize} LAST\r\n".b + message.b)
      else
        assert_match(/\A354/, command(client, "DATA"))
        client.write(message.b + ".\r\n".b)
      end
      reply = read_reply(client)
      assert_match(/\A250/, command(client, "NOOP"), "the session must survive the verdict")
      return reply
    end
  end

  # One authenticated submission; returns the final DATA reply.
  def submit(message)
    with_session(role: :submission) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A235/, command(client, "AUTH PLAIN #{[ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")}"))
      command(client, "MAIL FROM:<#{EMAIL}>")
      command(client, "RCPT TO:<friend@elsewhere.test>")
      assert_match(/\A354/, command(client, "DATA"))
      client.write(message.b + ".\r\n".b)
      return read_reply(client)
    end
  end

  CONTROLS = [ "\v", "\f", "\x01", "\x08", "\x0e", "\x1b", "\x1f", "\x7f" ].freeze

  test "MX: a trusted header name with a control byte before the colon is refused, nothing stored" do
    CONTROLS.each do |byte|
      %w[X-Original-To Return-Path X-MailOnRails-Authenticated].each do |name|
        reply = deliver("From: #{SENDER}\r\n#{name}#{byte}: victim@example.test\r\nSubject: hi\r\n\r\nbody\r\n")
        assert_match(/\A554 5\.6\.0 /, reply, "#{name} + #{byte.inspect}")
      end
    end
    assert_empty @store.inbound_messages
  end

  test "MX: any field name with a control byte is refused - in front, inside, or after" do
    [ "From\v: ceo@bank.test", "\vFrom: ceo@bank.test", "Fr\fom: ceo@bank.test", "Subject \v : x", "X-Any\x7f: x" ].each do |line|
      reply = deliver("From: #{SENDER}\r\n#{line}\r\nSubject: hi\r\n\r\nbody\r\n")
      assert_match(/\A554 5\.6\.0 /, reply, line.inspect)
    end
    assert_empty @store.inbound_messages
  end

  test "MX: the same gate holds for BDAT" do
    reply = deliver("From: #{SENDER}\r\nX-Original-To\v: victim@example.test\r\n\r\nbody\r\n", via: :bdat)
    assert_match(/\A554 5\.6\.0 /, reply)
    assert_empty @store.inbound_messages
  end

  # NUL is deleted and a lone CR becomes a line break before the gate runs
  # (OutboundData.canonicalize), so neither is a control byte in a name by
  # the time anything reads the message.
  test "MX: NUL before the colon is canonicalized away, not refused" do
    reply = deliver("From: #{SENDER}\r\nSubject\x00: hi\r\n\r\nbody\r\n")
    assert_match(/\A250/, reply)
    assert_includes @store.inbound_messages.last[:data], "Subject: hi\r\n"
  end

  test "MX: obs-syntax WSP before the colon, and control bytes elsewhere, are accepted as before" do
    accepted = [
      "From : #{SENDER}\r\nSubject\t: hi\r\n\r\nbody\r\n",                       # RFC 5322 obs-syntax
      "From: #{SENDER}\r\nSubject\r\n : folded before the colon\r\n\r\nbody\r\n",  # a fold is WSP
      "From: #{SENDER}\r\nSubject: \e$B raw iso-2022-jp \e(B \v \f\r\n\r\nbody\r\n", # controls in a value
      "From: #{SENDER}\r\nSubject: hi\r\n\r\nX-Original-To\v: only in the body\r\n\fpage two\r\n",
      "From: #{SENDER}\r\nthis line has no colon but a \v control\r\nSubject: hi\r\n\r\nbody\r\n",
      "From: #{SENDER}\r\nCaf\xC3\xA9: an 8-bit name is not a control byte\r\n\r\nbody\r\n",
      "From sender Mon Jan  1 00:00:00 2024\r\nFrom: #{SENDER}\r\n\r\nbody\r\n"   # mbox From_ line
    ]
    accepted.each do |message|
      assert_match(/\A250/, deliver(message), message.inspect)
    end
    assert_equal accepted.size, @store.inbound_messages.size
  end

  # M1 on the submission side: FromHeader now sees the second From too
  # (550 from the alignment check); with alignment off the name gate is
  # what stands between a stolen password and a DKIM-signed message that
  # carries a second, forged From.
  test "submission: a second From behind a control byte never leaves, alignment on or off" do
    message = "From: #{EMAIL}\r\nFrom\v: ceo@bank.test\r\nSubject: hi\r\n\r\nbody\r\n"

    assert_match(/\A554 5\.6\.0 /, submit(message))
    MailOnRails::Settings.overrides = { smtp_from_alignment: false }
    assert_match(/\A554 5\.6\.0 /, submit(message))
    assert_empty @store.outbound_messages
  ensure
    MailOnRails::Settings.reset!
  end

  # -- total header size ------------------------------------------------------

  def message_with_header_bytes(bytes)
    head = "From: #{SENDER}\r\nSubject: hi\r\n"
    line = "X-Pad: #{"a" * 990}\r\n"
    head += line * ((bytes - head.bytesize) / line.bytesize)
    head += "X-Fill: #{"b" * (bytes - head.bytesize - 10)}\r\n"
    raise "bad fixture: #{head.bytesize}" unless head.bytesize == bytes

    "#{head}\r\nbody\r\n"
  end

  test "a header block at the cap is accepted, one line more is refused" do
    cap = MailOnRails::SmtpServer::MAX_HEADER_BYTES
    assert_equal 1024 * 1024, cap

    # The cap is on the header block as the peer sent it: field lines with
    # their CRLFs, without the blank line.
    assert_match(/\A250/, deliver(message_with_header_bytes(cap)))
    reply = deliver(message_with_header_bytes(cap).sub("Subject: hi\r\n", "Subject: hi\r\nX-One-More: x\r\n"))
    assert_match(/\A552 5\.3\.4 Message header exceeds maximum size/, reply)
    assert_equal 1, @store.inbound_messages.size
  end

  test "a body of any size under the message cap is not a header" do
    message = "From: #{SENDER}\r\nSubject: hi\r\n\r\n" + ("x" * 998 + "\r\n") * 2000 # ~2 MB of body
    assert_match(/\A250/, deliver(message))
  end

  test "a message with no blank line is all header and is held to the header cap" do
    message = ("X-Pad: #{"a" * 990}\r\n" * 1100) # ~1.1 MB, no separator
    assert_match(/\A552 5\.3\.4 Message header exceeds maximum size/, deliver(message))
    assert_empty @store.inbound_messages
  end

  test "the cap is a spec seam like the message cap" do
    reply = deliver("From: #{SENDER}\r\nSubject: #{"s" * 200}\r\n\r\nbody\r\n", spec_extra: { max_header_bytes: 128 })
    assert_match(/\A552 5\.3\.4 Message header exceeds maximum size/, reply)
  end
end
