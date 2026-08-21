# frozen_string_literal: true

require "test_helper"
require "logger"
require "stringio"
require "socket"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# Regression tests against known SMTP CVE classes (2026-08-14 audit):
#
#   - input length limits (the Ruby analogue of the Exim/MailCarrier
#     buffer-overflow family, CVE-2023-42115 / CVE-2019-11395 / ...):
#     overlong EHLO, MAIL parameter floods - each must earn a bounded 5xx,
#     never unbounded buffering or a crash. The line cap (MAX_LINE),
#     message cap, recipient cap and error budget already have suites
#     (smtp_parser_abuse_test.rb, smtp_session_test.rb,
#     smtp_conformance_test.rb); this file covers the untested edges.
#
#   - malformed base64 in AUTH (Exim CVE-2018-6789 class): garbage,
#     misplaced NULs and oversized SASL blobs must fail cleanly through
#     the strict decoder, and abuse must hit the attempt cap.
#
#   - ReDoS: every regex the session applies to attacker-controlled input,
#     driven with crafted worst-case strings at the line cap under a wall
#     clock budget - catastrophic backtracking would blow it by orders of
#     magnitude.
#
#   - resource-exhaustion DoS: the accept-side caps have unit suites
#     (conn_limiter_test.rb, rate_limiter_test.rb, auth_throttle_test.rb)
#     and the reaper/idle timeouts have wire suites; this file adds the
#     missing SMTP wire-level proof that a full house answers 421.
class CveLimitsTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  MAX_LINE = MailOnRails::SmtpServer::MAX_LINE

  # Wall-clock budget for a single command reply. Linear parsing of a
  # MAX_LINE input is microseconds; catastrophic backtracking is minutes.
  REPLY_BUDGET = 2.0

  def setup
    @logs = StringIO.new
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(@logs))
    @store.add_account(email: EMAIL, password: PASSWORD)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
    refute_includes @logs.string, "SMTP session error",
                    "hostile input crashed the session (see catch-all rescue in Session#run)"
    assert_empty @store.inbound_messages, "hostile input must never assemble into a stored message"
  end

  def with_session(spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 10
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

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  # Sends a command and asserts the reply lands inside REPLY_BUDGET -
  # the ReDoS oracle (a catastrophic regex hangs the session thread, so
  # the reply never comes).
  def timed_command(client, line)
    started = monotonic
    reply = command(client, line)
    elapsed = monotonic - started
    assert_operator elapsed, :<, REPLY_BUDGET,
                    "reply to #{line[0, 48].inspect}... took #{elapsed.round(2)}s - possible catastrophic backtracking"
    refute_empty reply, "session must answer #{line[0, 48].inspect}..., not hang or drop"
    reply
  end

  def b64(str) = [ str ].pack("m0")

  # -- input length limits (buffer_len_limits class) --------------------------

  # An EHLO far past MAX_LINE arrives as unterminated fragments; each must
  # be refused, and no greeting state may survive (a truncated fragment
  # acted on as a real EHLO would leave the session half-greeted).
  def test_overlong_ehlo_is_rejected_in_fragments_and_leaves_no_greeting_state
    with_session do |client|
      read_reply(client) # banner
      client.write("EHLO #{"a" * (MAX_LINE * 2)}\r\n")
      client.write("NOOP\r\n") # sentinel: everything before its 250 is fragment fallout
      replies = []
      replies << read_reply(client) until replies.last&.start_with?("250")

      assert(replies[0..-2].all? { |r| r.start_with?("501", "502") },
             "overlong EHLO fragments must be rejected, got #{replies.inspect}")
      assert_match(/\A503/, command(client, "MAIL FROM:<a@b.test>"),
                   "no greeting state may survive a rejected overlong EHLO")
    end
  end

  # The largest EHLO that still fits one line must be handled promptly and
  # echoed sanitized - bounded memory, no pathological handling near the cap.
  def test_maximum_length_valid_ehlo_is_answered_promptly
    with_session do |client|
      read_reply(client)
      name = "a" * (MAX_LINE - 100)
      reply = timed_command(client, "EHLO #{name}")

      assert_match(/\A250/, reply)
      reply.split("\r\n").each { |line| assert_match(/\A\d{3}[ -]/, line, "reply line must stay well-formed") }
    end
  end

  # A MAIL parameter blob near the line cap: unadvertised parameters earn
  # RFC 5321's 555, the session survives, and a clean transaction still opens.
  def test_mail_parameter_flood_is_rejected_with_555_and_session_survives
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")

      assert_match(/\A555/, timed_command(client, "MAIL FROM:<a@b.test> #{"X" * 3000}"))
      assert_match(/\A555/, timed_command(client, "MAIL FROM:<a@b.test> #{"AUTH=x " * 20}JUNKPARAM=#{"y" * 2000}"))
      assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"),
                   "a rejected parameter list must not poison the next transaction")
    end
  end

  # -- malformed base64 in AUTH (CVE-2018-6789 class) -------------------------

  # Valid base64 whose decoded SASL PLAIN structure is wrong (no NULs,
  # leading NUL only, too many NULs): each must fail as a clean 535, and
  # the third strike must drop the connection.
  def test_auth_plain_with_misplaced_nuls_fails_cleanly_and_hits_the_attempt_cap
    with_session(spec_extra: { tls: :implicit, role: :submission }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")

      assert_match(/\A535/, command(client, "AUTH PLAIN #{b64("no-nuls-at-all")}"),
                   "base64 without NUL separators must fail authentication, not crash")
      assert_match(/\A535/, command(client, "AUTH PLAIN #{b64("\0#{EMAIL}")}"),
                   "a missing password field must fail authentication")
      assert_match(/\A421/, command(client, "AUTH PLAIN #{b64("a\0b\0c\0d\0#{PASSWORD}")}"),
                   "extra NULs must fail and the third failure must trip the cap")
      assert_nil client.gets("\r\n"), "auth abuse must drop the connection"
    end
  end

  # A SASL blob past MAX_LINE (the Exim base64d overflow shape): it arrives
  # as fragments, every fragment is refused, and the session stays usable -
  # decoded input is never accumulated across reads.
  def test_auth_plain_blob_past_the_line_cap_is_rejected_without_unbounded_buffering
    with_session(spec_extra: { tls: :implicit, role: :submission }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")

      client.write("AUTH PLAIN #{b64("\xAB".b * 6000)}\r\n") # ~8 kB of base64, 2x MAX_LINE
      client.write("NOOP\r\n")
      replies = []
      replies << read_reply(client) until replies.last&.start_with?("250")

      assert(replies[0..-2].all? { |r| r.start_with?("500", "501", "502", "504") },
             "oversized AUTH fragments must be refused, got #{replies.inspect}")
      assert_match(/\A250/, command(client, "NOOP"), "session must stay usable")
    end
  end

  # AUTH LOGIN values that decode with embedded NULs must be adjudicated as
  # ordinary wrong credentials - never spliced into a store lookup.
  def test_auth_login_values_with_embedded_nuls_fail_cleanly
    with_session(spec_extra: { tls: :implicit, role: :submission }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")

      assert_match(/\A334/, command(client, "AUTH LOGIN"))
      assert_match(/\A334/, command(client, b64("#{EMAIL}\0evil")))
      assert_match(/\A535/, command(client, b64("#{PASSWORD}\0extra")))
      assert_match(/\A250/, command(client, "NOOP"), "session must be usable after the failure")
    end
  end

  # SCRAM initial responses: invalid base64 decodes to "" and a binary blob
  # has no GS2 header - both must earn 501 Malformed, promptly.
  def test_scram_garbage_and_binary_initial_responses_are_refused
    with_session(spec_extra: { tls: :implicit, role: :submission }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")

      assert_match(/\A501/, timed_command(client, "AUTH SCRAM-SHA-256 !!!not-base64!!!"))
      assert_match(/\A501/, timed_command(client, "AUTH SCRAM-SHA-256 #{b64("\xFF".b * 2000)}"))
      assert_match(/\A250/, command(client, "NOOP"))
    end
  end

  # -- ReDoS ------------------------------------------------------------------

  # Worst-case inputs for every regex the command dispatch applies to
  # attacker text (HELO name charset, MAIL/RCPT envelope captures, the
  # control-byte guard), at or near the line cap. Each must be answered
  # inside the budget - the patterns are all single-quantifier/character-
  # class shapes, and this pins that no future edit introduces nesting.
  def test_pathological_regex_inputs_are_answered_promptly
    with_session do |client|
      read_reply(client)

      # HELO charset check: long valid run with a final rejecting byte.
      assert_match(/\A501/, timed_command(client, "EHLO #{"a" * 3500}!"))
      assert_match(/\A250/, timed_command(client, "EHLO client.test"))

      # MAIL FROM capture: spaces + an unterminated <... (no ">" to anchor on).
      assert_match(/\A501/, timed_command(client, "MAIL FROM:#{" " * 1500}<#{"a" * 2000}"))
      # A ">"-flood inside the address position (parses as an empty address
      # plus junk parameters; any prompt, well-formed refusal is the win here).
      assert_match(/\A(?:250|501|555)/, timed_command(client, "MAIL FROM:<#{">" * 3000}"))

      assert_match(/\A250/, timed_command(client, "MAIL FROM:<#{"a" * 3800}>"))
      # RCPT TO with no bracket at all, then a maximal bracketed one.
      assert_match(/\A501/, timed_command(client, "RCPT TO:#{"a" * 3500}"))
      assert_match(/\A5\d\d/, timed_command(client, "RCPT TO:<#{"a" * 3800}>"))
    end
  end

  # The SCRAM client-final extractor (/\A(.*),p=[^,]*\z/m) and attribute
  # splitter, fed a comma flood: rejected promptly as a failed proof.
  def test_scram_client_final_comma_flood_is_rejected_promptly
    with_session(spec_extra: { tls: :implicit, role: :submission }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")

      first = command(client, "AUTH SCRAM-SHA-256 #{b64("n,,n=#{EMAIL},r=abcdefgh")}")
      assert_match(/\A334/, first, "client-first must earn a server-first challenge")

      flood = b64("#{"a," * 1200}p=#{b64("junk")}")
      started = monotonic
      reply = command(client, flood)
      elapsed = monotonic - started

      assert_operator elapsed, :<, REPLY_BUDGET,
                      "comma-flooded client-final took #{elapsed.round(2)}s - possible catastrophic backtracking"
      assert_match(/\A535/, reply, "a comma flood is a failed proof, nothing worse")
    end
  end

  # -- resource-exhaustion DoS ------------------------------------------------

  # Every other accept-side cap disabled so the process-wide connection
  # cap is the only protection in play.
  class OneSlotServer < MailOnRails::SmtpServer
    MAX_CONNECTIONS = 1
    MAX_CONNECTIONS_PER_IP = 0
    AUTH_LOCKOUT_FAILURES = 0
    CONN_RATE_LIMIT = 0
    SESSION_LIFETIME = 0
  end

  # Wire-level proof for SMTP (the unit suites cover ConnLimiter itself):
  # a full house answers 421 and closes, and the slot is reusable once the
  # holder leaves - a flood can never wedge the listener.
  def test_connection_cap_answers_421_at_the_wire_and_the_slot_is_released
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", tcp_server: listener }
    thread = Thread.new { OneSlotServer.run(@store, [ spec ], nil) }
    @cleanup << -> { thread.kill }

    first = TCPSocket.new("127.0.0.1", spec[:port])
    first.timeout = 5
    @cleanup << -> { first.close rescue nil }
    assert_match(/\A220 /, first.gets("\r\n"), "the first connection must be served")

    second = TCPSocket.new("127.0.0.1", spec[:port])
    second.timeout = 5
    @cleanup << -> { second.close rescue nil }
    assert_match(/\A421 4\.7\.0 Error: too many connections/, second.gets("\r\n").to_s,
                 "past the cap a connection must be refused with 421")
    assert_nil second.gets("\r\n"), "the refused connection must be closed"

    first.write("QUIT\r\n")
    first.gets("\r\n") # 221
    first.close

    # The released slot must admit a new peer.
    third = nil
    deadline = monotonic + 5
    loop do
      third = TCPSocket.new("127.0.0.1", spec[:port])
      third.timeout = 5
      @cleanup << -> { third.close rescue nil }
      line = third.gets("\r\n").to_s
      break assert_match(/\A220 /, line) if line.start_with?("220")

      third.close
      flunk "released slot never admitted a new connection" if monotonic > deadline
      sleep 0.05
    end
  end
end
