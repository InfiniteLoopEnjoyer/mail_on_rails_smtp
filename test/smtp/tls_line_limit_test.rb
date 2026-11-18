# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "timeout"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The line cap on TLS sockets (2026-11-17 audit, H2).
#
# The session reads with gets("\r\n", MAX_LINE). A TCPSocket honours the
# limit; OpenSSL::Buffering#gets reads until it has seen the terminator
# and applies the limit afterwards, re-scanning its whole buffer after
# every record. So on 465, or after STARTTLS, a peer that streamed bytes
# and never sent CRLF grew the buffer without bound at quadratic CPU,
# inside a single gets the overlong-line path, the error budget and the
# DATA size cap never got to see. The session now reads through
# Netserv::BoundedReader, whose limit holds on TLS.
class TlsLineLimitTest < Minitest::Test
  EMAIL = "user@example.test"
  SENDER = "sender@remote.test"
  Reader = MailOnRails::Netserv::BoundedReader
  MAX_LINE = MailOnRails::SmtpServer::MAX_LINE

  def self.tls_context
    @tls_context ||= MailOnRails::Netserv::Tls.context(MailOnRails::Netserv::Tls.generate_self_signed)
  end

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: "pw-123456")
    @cleanup = []
    @session = nil
  end

  def teardown
    @cleanup.reverse_each { |c| c.call rescue nil }
  end

  def client_tls(socket)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    tls = OpenSSL::SSL::SSLSocket.new(socket, ctx)
    tls.sync_close = true
    tls.connect
    tls
  end

  # A session on a real TLS socket: implicit (the listener's own handshake,
  # as Netserv::Server does for 465) or a plaintext one the test upgrades
  # with STARTTLS. Yields the client socket; @session is the live Session.
  def session(tls:, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    raw = TCPSocket.new("127.0.0.1", server.addr[1])
    raw.timeout = 10
    accepted = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: tls, role: :mx, hostname: "mx.test",
             sender_auth: false, clamav_addr: "" }.merge(spec_extra)
    ready = Queue.new
    @thread = Thread.new do
      socket = tls == :implicit ? MailOnRails::Netserv::Tls.accept(accepted, self.class.tls_context) : accepted
      @session = MailOnRails::SmtpServer::Session.new(socket, @store, spec, self.class.tls_context)
      ready << true
      @session.run
    end
    @cleanup << -> { server.close }
    @cleanup << -> { @thread.join(5) || @thread.kill }
    @cleanup << -> { raw.close }
    client = tls == :implicit ? client_tls(raw) : raw
    ready.pop
    client
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

  # Streams +bytes+ of filler with no CRLF from a second thread (the
  # server may hang up mid-stream; that is the point) and returns what
  # the client managed to read until the connection closed. Closing on a
  # peer that is still sending resets the connection, which can destroy
  # replies in flight - so what the server SAID is asserted from its own
  # transcript (replies), never from this.
  def flood(client, bytes)
    block = "A" * 65_536
    writer = Thread.new do
      (bytes / block.bytesize).times { client.write(block) }
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
      nil
    end
    @cleanup << -> { writer.kill }
    said = +""
    Timeout.timeout(15) do
      while (line = client.gets("\r\n"))
        said << line
      end
    end
    said
  rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
    said
  end

  # While a block runs, the most bytes the session ever held unread: its
  # own reader's buffer plus the SSLSocket's (which must stay unused).
  def peak_buffered
    peak = 0
    done = false
    sampler = Thread.new do
      until done
        reader = @session&.instance_variable_get(:@reader)
        socket = @session&.instance_variable_get(:@socket)
        held = reader&.instance_variable_get(:@buffer)&.bytesize.to_i +
               socket&.instance_variable_get(:@rbuffer)&.bytesize.to_i
        peak = held if held > peak
        sleep 0.001
      end
    end
    yield
    done = true
    sampler.join
    peak
  end

  # The server's side of the dialogue, from the session's own transcript.
  def replies
    @session.send(:honeypot_transcript).to_s.lines(chomp: true).grep(/\A=> /).map { |line| line.delete_prefix("=> ") }
  end

  def assert_cut_off_by_error_budget(said, replies_before)
    assert @thread.join(5), "the session thread must have ended"
    assert_match(/\A(502 |\z)/, said) # "" when the reset ate the replies in flight
    assert_equal "protocol_abuse", @session.instance_variable_get(:@close_reason)
    flood_replies = replies.drop(replies_before)
    assert_equal MailOnRails::SmtpServer::MAX_PROTOCOL_ERRORS, flood_replies.size,
                 "one reply per MAX_LINE chunk until the budget is spent"
    assert_match(/Too many syntax or protocol errors/, flood_replies.last)
  end

  test "implicit TLS: megabytes with no CRLF are cut off by the overlong-line budget, buffer bounded" do
    client = session(tls: :implicit)
    assert_match(/\A220 /, read_reply(client))

    said = nil
    peak = peak_buffered { said = flood(client, 8 * 1024 * 1024) }

    assert_cut_off_by_error_budget(said, 1)
    assert_operator peak, :<=, MAX_LINE + Reader::BLOCK, "the session buffered #{peak} unread bytes"
  end

  test "after STARTTLS the new socket is read through a new bounded reader" do
    client = session(tls: :starttls)
    assert_match(/\A220 /, read_reply(client))
    command(client, "EHLO client.test")
    assert_match(/\A220 /, command(client, "STARTTLS"))
    tls = client_tls(client)
    assert_match(/\A250/, command(tls, "EHLO client.test"), "the upgraded session must still answer")

    before = replies.size
    said = nil
    peak = peak_buffered { said = flood(tls, 8 * 1024 * 1024) }

    assert_cut_off_by_error_budget(said, before)
    assert_operator peak, :<=, MAX_LINE + Reader::BLOCK, "the session buffered #{peak} unread bytes"
  end

  test "implicit TLS: an unterminated DATA stream is stopped at twice the size cap" do
    cap = 64 * 1024
    client = session(tls: :implicit, spec_extra: { max_message_bytes: cap })
    read_reply(client)
    command(client, "EHLO client.test")
    command(client, "MAIL FROM:<#{SENDER}>")
    command(client, "RCPT TO:<#{EMAIL}>")
    assert_match(/\A354/, command(client, "DATA"))

    said = nil
    peak = peak_buffered { said = flood(client, 8 * 1024 * 1024) }

    assert @thread.join(5), "the session must have dropped the flooding peer"
    assert_equal "552 5.3.4 Message exceeds maximum size", replies.last
    assert_includes [ "", "552 5.3.4 Message exceeds maximum size\r\n" ], said # "" when the reset ate it
    assert_operator peak, :<=, MAX_LINE + Reader::BLOCK, "the session buffered #{peak} unread bytes"
    assert_empty @store.inbound_messages
  end

  # The reader also carries BDAT's exact-count reads; a pipelined command
  # behind the payload must still be found in the same buffer.
  test "implicit TLS: BDAT payloads and the commands pipelined behind them are read intact" do
    client = session(tls: :implicit)
    read_reply(client)
    command(client, "EHLO client.test")
    command(client, "MAIL FROM:<#{SENDER}>")
    command(client, "RCPT TO:<#{EMAIL}>")
    head = "From: #{SENDER}\r\nSubject: chunked\r\n\r\n"
    body = ("line of body text\r\n" * 12_000) # ~228 kB: many TLS records, several reader blocks
    client.write("BDAT #{head.bytesize}\r\n#{head}BDAT #{body.bytesize} LAST\r\n#{body}NOOP\r\n")

    assert_match(/\A250 2\.0\.0 Ok: #{head.bytesize} bytes/, read_reply(client))
    assert_match(/\A250 2\.0\.0 Ok: queued/, read_reply(client))
    assert_match(/\A250 2\.0\.0 Ok\r\n/, read_reply(client), "the pipelined NOOP must not be eaten")
    assert @store.inbound_messages.last[:data].end_with?(head + body)
  end

  test "implicit TLS: a refused BDAT's payload is discarded exactly and the stream stays in sync" do
    client = session(tls: :implicit)
    read_reply(client)
    command(client, "EHLO client.test")
    payload = "x" * 100_000
    client.write("BDAT #{payload.bytesize} LAST\r\n#{payload}NOOP\r\n") # no MAIL/RCPT: refused

    assert_match(/\A503 /, read_reply(client))
    assert_match(/\A250 2\.0\.0 Ok\r\n/, read_reply(client))
  end
end
