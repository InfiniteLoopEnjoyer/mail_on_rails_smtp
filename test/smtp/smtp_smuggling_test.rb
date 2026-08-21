# frozen_string_literal: true

require "test_helper"
require "net/smtp"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"
require "mail_on_rails/outbound_data"

# SMTP smuggling (CVE-2023-51764 Postfix, CVE-2023-51765 Sendmail,
# CVE-2023-51766 Exim). Sequences and attack shape come from:
#
#   https://github.com/hannob/smtpsmug
#   https://github.com/The-Login/SMTP-Smuggling-Tools
#
# A receiving server is vulnerable when a malformed end-of-data sequence
# ends DATA and the following SMTP commands start a second transaction
# (spoofed MAIL FROM). RFC 5321 4.1.1.4: only <CRLF>.<CRLF> terminates
# DATA. A sending server is vulnerable when it forwards those sequences
# unfiltered so a lenient next hop can be smuggled into.
class SmtpSmugglingTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  SENDER = "sender@remote.test"
  SMUGGLED = "smuggled@evil.test"
  REMOTE = "friend@elsewhere.test"
  MARK_START = "SMUGGLINGSTART"
  MARK_END = "SMUGGLINGEND"

  # hannob/smtpsmug --list-tests, plus the extra outbound probes from
  # The-Login/SMTP-Smuggling-Tools. Names match smtpsmug where they overlap.
  EOD_SEQUENCES = {
    "lflf" => "\n.\n".b,                 # both tools; Exchange Online outbound
    "crcr" => "\r.\r".b,                 # smtpsmug
    "crlf" => "\r.\n".b,                 # both
    "lfcr" => "\n.\r".b,                 # both
    "lfcrlf" => "\n.\r\n".b,             # both; Postfix inbound (CVE-2023-51764)
    "crlflf" => "\r\n.\n".b,             # smtpsmug
    "crcrlf" => "\r.\r\n".b,             # both
    "crlfcr" => "\r\n.\r".b,             # smtpsmug
    "nullbefore" => "\r\n\x00.\r\n".b,   # both
    "nullafter" => "\r\n.\x00\r\n".b,    # smtpsmug
    "crlfcrcrlf" => "\r\n.\r\r\n".b,     # The-Login outbound
    "crcrlfcrcrlf" => "\r\r\n.\r\r\n".b  # The-Login outbound
  }.freeze

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
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

  def start_data(client)
    read_reply(client)
    command(client, "EHLO client.test")
    command(client, "MAIL FROM:<#{SENDER}>")
    command(client, "RCPT TO:<#{EMAIL}>")
    assert_match(/\A354/, command(client, "DATA"))
  end

  # The-Login inbound scanner: fake EOD, then a second MAIL/RCPT/DATA as
  # if the session had returned to command mode (verbs lowercased like the
  # scanner), then a real terminator so a strict server can finish.
  def smuggle_payload(eod)
    ("From: #{SENDER}\r\nTo: #{EMAIL}\r\nSubject: probe\r\n\r\n" \
     "body-before\r\n").b + eod +
      ("mail FROM:<#{SMUGGLED}>\r\n" \
       "rcpt TO:<#{EMAIL}>\r\n" \
       "data\r\n" \
       "From: #{SMUGGLED}\r\nSubject: SMUGGLED\r\n\r\n" \
       "smuggled-body\r\n.\r\n").b
  end

  def assert_one_original_message(name, eod)
    assert_equal 1, @store.inbound_messages.size,
                 "#{name} (#{eod.inspect}) must not start a second transaction"
    assert_empty @store.outbound_messages, "#{name}: MX must not relay"
    msg = @store.inbound_messages.last
    assert_equal SENDER, msg[:mail_from],
                 "#{name}: envelope MAIL FROM must stay the original sender"
    assert_equal [ EMAIL ], msg[:rcpt_to]
    assert_includes msg[:data], "smuggled-body",
                    "#{name}: the smuggled payload must remain in the stored body"
    refute_includes msg[:mail_from], "smuggled"
  end

  # -- inbound: malformed EOD must not end DATA --------------------------------

  def test_rfc5321_crlf_dot_crlf_still_terminates_data
    with_session do |client|
      start_data(client)
      client.write("Subject: ok\r\n\r\nhello\r\n.\r\n")
      assert_match(/\A250 /, read_reply(client))
      assert_match(/\A250 /, command(client, "NOOP"))
      command(client, "QUIT")
    end

    assert_equal 1, @store.inbound_messages.size
    assert_includes @store.inbound_messages.last[:data], "hello"
  end

  def test_malformed_eod_sequences_do_not_smuggle_a_second_message
    EOD_SEQUENCES.each do |name, eod|
      @store.inbound_messages.clear
      @store.outbound_messages.clear
      with_session do |client|
        start_data(client)
        client.write(smuggle_payload(eod))
        assert_match(/\A250 /, read_reply(client),
                     "#{name} (#{eod.inspect}): expected one 250 after the real terminator")
        assert_match(/\A250 /, command(client, "NOOP"),
                     "#{name}: session must be in command mode after the real terminator")
        command(client, "QUIT")
      end
      assert_one_original_message(name, eod)
    end
  end

  # hannob/smtpsmug test_badend: send the malformed ending and see whether
  # the server answers 250 without a real <CRLF>.<CRLF>.
  def test_famous_malformed_eod_sequences_do_not_produce_250_alone
    %w[lflf lfcrlf].each do |name|
      eod = EOD_SEQUENCES.fetch(name)
      with_session do |client|
        start_data(client)
        client.write("Subject: probe\r\n\r\nbody-before\r\n".b + eod)
        client.timeout = 0.3
        reply = begin
          read_reply(client)
        rescue IO::TimeoutError, SystemCallError
          nil
        end
        refute reply&.start_with?("250"),
               "#{name} (#{eod.inspect}) must not be accepted as end of DATA, got #{reply.inspect}"

        client.timeout = 5
        client.write("after-fake-eod\r\n.\r\n")
        assert_match(/\A250 /, read_reply(client), "#{name}: the real terminator must still work")
        command(client, "QUIT")
      end
    end
  end

  # -- inbound: pipelined second envelope (smtpsmug pipelining test) -----------

  # RFC 2920 makes DATA a synchronization point, but we advertise
  # PIPELINING and currently answer a second transaction that arrives in
  # the same write as a *legitimate* terminator. That is not smuggling.
  # The same burst after a *malformed* terminator must not create mail.
  def test_pipelined_second_envelope_after_a_fake_eod_is_not_a_second_message
    eod = EOD_SEQUENCES.fetch("lfcrlf")
    with_session do |client|
      start_data(client)
      client.write("Subject: one\r\n\r\nfirst\r\n".b + eod)
      client.write("MAIL FROM:<#{SMUGGLED}>\r\nRCPT TO:<#{EMAIL}>\r\nDATA\r\n")
      client.write("Subject: two\r\n\r\nsecond\r\n.\r\n")
      assert_match(/\A250 /, read_reply(client))
      command(client, "QUIT")
    end

    assert_equal 1, @store.inbound_messages.size
    assert_equal SENDER, @store.inbound_messages.last[:mail_from]
    assert_includes @store.inbound_messages.last[:data], "second"
  end

  # -- outbound: stored mail must not leak unfiltered EOD on the wire ----------

  def test_canonicalize_strips_nuls_and_bare_newlines
    out = MailOnRails::OutboundData.canonicalize("a\n.\n\x00.\rb")
    refute_includes out, "\0"
    refute_match(/(?<!\r)\n/, out)
    refute_match(/\r(?!\n)/, out)
    assert_equal "a\r\n.\r\n.\r\nb", out
  end

  # OutboundDeliverer canonicalizes, then hands the payload to
  # Net::SMTP#send_message. A capturing sink records the DATA bytes the
  # next hop would see; none of the probe sequences may appear unquoted
  # between the analysis markers (The-Login SMTP Analysis Server).
  def test_outbound_delivery_does_not_forward_unfiltered_eod_sequences
    EOD_SEQUENCES.each do |name, eod|
      @store.outbound_messages.clear
      with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
        read_reply(client)
        command(client, "EHLO client.test")
        token = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
        assert_match(/\A235/, command(client, "AUTH PLAIN #{token}"))
        command(client, "MAIL FROM:<#{EMAIL}>")
        command(client, "RCPT TO:<#{REMOTE}>")
        assert_match(/\A354/, command(client, "DATA"))
        client.write("From: #{EMAIL}\r\nTo: #{REMOTE}\r\nSubject: #{name}\r\n\r\n".b)
        client.write("#{MARK_START}\r\n".b + eod + "#{MARK_END}\r\n.\r\n".b)
        assert_match(/\A250 /, read_reply(client), "#{name}: submission must accept the probe body")
        command(client, "QUIT")
      end

      stored = @store.outbound_messages.last
      assert stored, "#{name}: submission must queue outbound mail"
      payload = MailOnRails::OutboundData.canonicalize(stored[:data])
      wire = deliver_via_net_smtp(payload, stored[:mail_from], stored[:recipient])
      region = smuggling_region(wire)
      assert region, "#{name}: next hop must receive both analysis markers (early DATA end?)"
      refute_includes region, eod,
                      "#{name} (#{eod.inspect}) leaked unfiltered to the next hop: #{region.inspect}"
    end
  end

  def deliver_via_net_smtp(data, mail_from, recipient)
    sink = CapturingSink.new
    sink.accept_one
    smtp = Net::SMTP.new("127.0.0.1", sink.port)
    smtp.open_timeout = 2
    smtp.read_timeout = 2
    smtp.start(helo: "outbound.test") { |session| session.send_message(data, mail_from, recipient) }
    sink.finish
    sink.raw_data
  ensure
    sink&.close
  end

  def smuggling_region(wire)
    start = wire.index(MARK_START)
    finish = wire.index(MARK_END)
    return nil unless start && finish && finish > start

    wire[start + MARK_START.bytesize...finish]
  end

  # Minimal SMTP peer that records the raw DATA payload (everything before
  # the RFC terminator). Mirrors The-Login's analysis server: inspect bytes
  # as transferred, not as a MUA would display them.
  class CapturingSink
    attr_reader :raw_data

    def initialize
      @server = TCPServer.new("127.0.0.1", 0)
      @raw_data = +"".b
    end

    def port = @server.addr[1]

    def accept_one
      @thread = Thread.new do
        sock = @server.accept
        sock.timeout = 5
        sock.write("220 sink ESMTP\r\n")
        loop do
          line = sock.gets("\r\n")
          break unless line

          verb = line.split.first.to_s.upcase
          case verb
          when "EHLO", "HELO" then sock.write("250 sink\r\n")
          when "MAIL", "RCPT" then sock.write("250 OK\r\n")
          when "DATA"
            sock.write("354 End data with <CR><LF>.<CR><LF>\r\n")
            buf = +"".b
            loop do
              chunk = sock.readpartial(4096)
              buf << chunk
              break if buf.include?("\r\n.\r\n")
            end
            idx = buf.rindex("\r\n.\r\n")
            @raw_data = idx ? buf[0...idx] : buf
            sock.write("250 OK\r\n")
          when "QUIT"
            sock.write("221 bye\r\n")
            break
          else
            sock.write("502 Command not implemented\r\n")
          end
        end
      ensure
        sock&.close
      end
    end

    def finish
      @thread&.join(5)
    end

    def close
      @server&.close
    end
  end
end
