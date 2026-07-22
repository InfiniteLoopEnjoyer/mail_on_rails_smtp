# frozen_string_literal: true

require "test_helper"
require "logger"
require "stringio"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# Hostile-input coverage for the SMTP command dispatch (todo item 7):
# deterministic seeded garbage plus hand-picked edge cases. The invariants,
# for every abusive session: each reply line is well-formed
# ("NNN<space|dash>..."), the session either stays usable or drops cleanly,
# nothing lands in the store, and the parser never crashes - a crash
# surfaces as Session#run's catch-all logging "SMTP session error", which
# this suite forbids.
class SmtpParserAbuseTest < Minitest::Test
  EMAIL = "user@example.test"
  SEED = 0xBEEF
  ROUNDS = 15

  def setup
    @logs = StringIO.new
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(@logs))
    @store.add_account(email: EMAIL, password: "pw-123456")
  end

  def teardown
    refute_includes @logs.string, "SMTP session error",
                    "the parser crashed on hostile input (see catch-all rescue in Session#run)"
    assert_empty @store.inbound_messages, "garbage must never assemble into a stored message"
  end

  def with_session(spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 2
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test" }.merge(spec_extra)
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

  # Writes abuse lines, then drains every reply the server produces until
  # it quits or drops - each one must be well-formed. Disconnects are an
  # acceptable outcome for abuse; hangs and malformed replies are not.
  def abuse_session(lines, spec_extra: {})
    with_session(spec_extra: spec_extra) do |client|
      read_reply(client) # banner
      lines.each { |line| client.write("#{line}\r\n") }
      client.write("QUIT\r\n")
      while (raw = client.gets("\r\n"))
        assert_match(/\A\d{3}[ -]/, raw, "malformed reply #{raw.inspect} to #{lines.inspect}")
      end
    rescue SystemCallError, IO::TimeoutError
      # A dropped/stalled connection is fine for abuse; the teardown
      # invariants still apply.
      nil
    end
  end

  # -- seeded garbage --------------------------------------------------------

  def garbage_line(rng)
    case rng.rand(6)
    when 0 then rng.bytes(rng.rand(1..80)).delete("\r\n")                     # raw binary
    when 1 then (1..31).map(&:chr).shuffle(random: rng).take(10).join.delete("\r\n") # control bytes
    when 2 then "\xC3\x28\xA0\xFF\xFE garbage utf8".b                         # invalid UTF-8
    when 3 then "#{%w[MAIL RCPT DATA AUTH EHLO HELO VRFY STARTTLS RSET].sample(random: rng)} " +
                rng.bytes(20).delete("\r\n")                                  # verb + junk arg
    when 4 then "A" * rng.rand(3000..9000)                                    # around/over MAX_LINE
    when 5 then "MAIL FROM:<#{rng.bytes(12).delete("\r\n")}>"                 # junk address
    end
  end

  def test_seeded_garbage_sessions
    rng = Random.new(SEED)
    ROUNDS.times do
      abuse_session(Array.new(rng.rand(1..5)) { garbage_line(rng) })
    end
  end

  # -- deterministic edge cases ----------------------------------------------

  def test_null_and_control_bytes_in_a_command_leave_the_session_usable
    with_session do |client|
      read_reply(client)

      assert_match(/\A50[12]/, command(client, "MA\x00IL FROM:<a@b.test>"))
      assert_match(/\A250/, command(client, "NOOP"), "session must survive control bytes")
    end
  end

  def test_overlong_line_is_rejected_without_acting_on_fragments
    with_session do |client|
      read_reply(client)
      # 3x MAX_LINE of "MAIL FROM:..." prefix - if the parser acted on a
      # truncated chunk it would reply 250 and set envelope state.
      client.write("MAIL FROM:<a@b.test>#{"x" * (MailOnRails::SmtpServer::MAX_LINE * 3)}\r\n")
      client.write("NOOP\r\n") # sentinel: everything before its 250 is fragment fallout
      replies = []
      replies << read_reply(client) until replies.last&.start_with?("250")

      assert(replies[0..-2].all? { |r| r.start_with?("501", "502") },
             "overlong fragments must be rejected, got #{replies.inspect}")
      assert_match(/\A503/, command(client, "RCPT TO:<#{EMAIL}>"),
                   "no envelope state may survive from a truncated MAIL command")
    end
  end

  def test_pipelining_blast_answers_every_command
    with_session do |client|
      read_reply(client)
      count = 200
      client.write("NOOP\r\n" * count)
      count.times { assert_match(/\A250/, read_reply(client)) }

      assert_match(/\A221/, command(client, "QUIT"))
    end
  end

  def test_bare_lf_inside_a_command_cannot_inject_reply_lines
    with_session do |client|
      read_reply(client)
      reply = command(client, "EHLO a.test\nINJECTED-LINE")

      refute_match(/\n(?!\z)[^\d]/, reply, "echoed input must not inject raw lines into a reply")
      reply.split("\r\n").each { |line| assert_match(/\A\d{3}[ -]/, line) }
    end
  end

  def test_garbage_base64_auth_fails_cleanly_and_abuse_disconnects
    with_session(spec_extra: { tls: :implicit, role: :submission }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")

      assert_match(/\A535/, command(client, "AUTH PLAIN !!!not-base64!!!"))
      assert_match(/\A535/, command(client, "AUTH PLAIN AA"))
      assert_match(/\A421/, command(client, "AUTH PLAIN ####"),
                   "the third failure must trip the per-session auth limit")
      assert_nil client.gets("\r\n"), "auth abuse must drop the connection"
    end
  end

  def test_auth_challenge_fed_garbage_recovers
    with_session(spec_extra: { tls: :implicit, role: :submission }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")

      assert_match(/\A334/, command(client, "AUTH LOGIN"))
      assert_match(/\A334/, command(client, "\x01\x02 not base64"))
      assert_match(/\A535/, command(client, "still not base64"))
      assert_match(/\A250/, command(client, "NOOP"), "session must be usable after garbage AUTH")
    end
  end
end
