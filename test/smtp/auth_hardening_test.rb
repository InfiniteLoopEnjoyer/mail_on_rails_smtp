# frozen_string_literal: true

require "test_helper"
require "logger"
require "stringio"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The AUTH path's contract with the log, the transcript and the store:
# credentials never reach the trace however the dispatcher tolerated the
# AUTH line's whitespace, client bytes cannot forge log lines, a store
# outage is a 454 that counts against nobody, and the "?" peer
# placeholder never reaches the store as an address.
class SmtpAuthHardeningTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  # Records the ip: each store call was handed.
  class IpRecordingStore < MailOnRails::Smtp::Store::Memory
    attr_reader :ips

    def initialize(...)
      super
      @ips = []
    end

    def authenticate(email, password, ip: :unset, source: nil)
      @ips << [ :authenticate, ip ]
      super(email, password, ip: ip, source: source)
    end

    def scram_credentials(email, ip: :unset)
      @ips << [ :scram_credentials, ip ]
      super(email, ip: ip)
    end

    def record_auth_failure(email, ip: :unset, source: nil)
      @ips << [ :record_auth_failure, ip ]
      super(email, ip: ip, source: source)
    end
  end

  # The shape Store::Base#db answers when the database is unreachable.
  class OutageStore < MailOnRails::Smtp::Store::Memory
    def authenticate(*, **)
      { error: "PG::ConnectionBad: server closed the connection", code: :internal }
    end
  end

  def setup
    @log = StringIO.new
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(@log))
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def with_session(store: @store, spec_extra: {}, peer_ip: nil)
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :implicit, role: :submission,
             hostname: "mx.test", sender_auth: false, clamav_addr: "", trace: true }.merge(spec_extra)
    @session = MailOnRails::SmtpServer::Session.new(session_socket, store, spec, nil)
    @session.peer_ip = peer_ip if peer_ip
    @auth_failures = 0
    @session.on_auth_failure = -> { @auth_failures += 1 }
    thread = Thread.new { @session.run }
    yield client
  ensure
    client&.close
    thread&.join(5)
    @session&.finalize_honeypot
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

  def plain_token(user = EMAIL, pass = PASSWORD)
    [ "\0#{user}\0#{pass}" ].pack("m0")
  end

  def transcript
    @session.send(:honeypot_transcript).to_s
  end

  # -- L3: redaction follows the dispatcher's tokenization -------------------

  def test_auth_with_leading_whitespace_is_redacted_in_trace_and_transcript
    token = plain_token
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A235/, command(client, " AUTH PLAIN #{token}"), "the dispatcher accepts the line")
      command(client, "QUIT")
    end

    refute_includes @log.string, token, "the credential reached the trace log"
    refute_includes transcript, token, "the credential reached the transcript"
    assert_includes @log.string, "<= AUTH PLAIN [redacted]"
  end

  def test_auth_with_vertical_tab_separators_is_redacted_in_trace_and_transcript
    token = plain_token
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A235/, command(client, "AUTH\vPLAIN\v#{token}"), "the dispatcher accepts the line")
      command(client, "QUIT")
    end

    refute_includes @log.string, token, "the credential reached the trace log"
    refute_includes transcript, token, "the credential reached the transcript"
    assert_includes @log.string, "<= AUTH PLAIN [redacted]"
    # The \v also trips the garbage signature; that event's transcript is
    # the same redacted buffer.
    event = @store.honeypot_events.first
    refute_includes event[:transcript].to_s, token if event
  end

  def test_auth_with_tab_and_mixed_case_is_redacted
    token = plain_token
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A235/, command(client, "auth\tplain\t#{token}"))
      command(client, "QUIT")
    end

    refute_includes @log.string, token
    assert_includes @log.string, "<= AUTH plain [redacted]"
  end

  def test_auth_without_an_initial_response_is_traced_as_is
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A334/, command(client, "AUTH PLAIN"))
      assert_match(/\A235/, command(client, plain_token))
      command(client, "QUIT")
    end

    assert_includes @log.string, "<= AUTH PLAIN ("
    assert_includes @log.string, "<= [redacted] (", "the challenge response is the placeholder"
    refute_includes @log.string, plain_token
  end

  # -- L4: client bytes cannot forge log lines --------------------------------

  def test_bare_lf_and_cr_in_a_command_line_are_flattened_in_the_trace
    with_session do |client|
      read_reply(client)
      command(client, "NOOP\n[mail_on_rails] SMTP auth success for admin@example.test (10.0.0.1)")
      command(client, "NOOP\rforged-cr")
      command(client, "QUIT")
    end

    refute_match(/^\[mail_on_rails\] SMTP auth success for admin/, @log.string, "a forged log line")
    refute_match(/^forged-cr/, @log.string)
    assert_includes @log.string, '<= NOOP\n[mail_on_rails] SMTP auth success'
    assert_includes @log.string, '<= NOOP\nforged-cr'
  end

  def test_username_in_the_auth_failed_line_is_printable_and_bounded
    user = "bob\n[mail_on_rails] SMTP auth success for admin@example.test\x01" + ("x" * 200)
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A535/, command(client, "AUTH PLAIN #{plain_token(user, "wrong")}"))
      command(client, "QUIT")
    end

    refute_match(/^\[mail_on_rails\] SMTP auth success for admin/, @log.string, "a forged log line")
    failed = @log.string[/SMTP auth failed for (\S+) /, 1]
    assert failed, "the failure is still logged"
    assert_match(/\A[[:graph:]]+\z/, failed)
    assert_operator failed.length, :<=, 80
  end

  # -- L5: a store outage is not a wrong password -----------------------------

  def test_store_error_on_plain_is_a_454_that_counts_against_nobody
    store = OutageStore.new(logger: Logger.new(@log))
    with_session(store: store) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      # More attempts than MAX_AUTH_ATTEMPTS allows for failures: none of
      # these may count, so the connection must never be dropped.
      (MailOnRails::SmtpServer::MAX_AUTH_ATTEMPTS + 1).times do
        assert_match(/\A454 4\.7\.0 Temporary authentication failure/, command(client, "AUTH PLAIN #{plain_token}"))
      end
      assert_match(/\A334/, command(client, "AUTH LOGIN"))
      assert_match(/\A334/, command(client, [ EMAIL ].pack("m0")))
      assert_match(/\A454 4\.7\.0/, command(client, [ PASSWORD ].pack("m0")))
      assert_match(/\A221/, command(client, "QUIT"), "the session is still open")
    end

    assert_equal 0, @auth_failures, "a store error must not feed the accept-side lockout"
    assert_equal 0, @session.instance_variable_get(:@auth_attempts), "nor the per-connection cap"
    refute_includes @log.string, "auth failed"
    assert_includes @log.string, "SMTP auth temporary failure for #{EMAIL}"
  end

  # -- I7: the "?" peer placeholder is not an address -------------------------

  def test_unknown_peer_address_reaches_the_store_as_nil
    store = IpRecordingStore.new(logger: Logger.new(@log))
    store.add_account(email: EMAIL, password: PASSWORD)
    with_session(store: store, peer_ip: "?") do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A535/, command(client, "AUTH PLAIN #{plain_token(EMAIL, "wrong")}"))
      # SCRAM: credential lookup, then a bad proof the daemon reports back.
      first = [ "n,,n=#{EMAIL},r=clientnonce" ].pack("m0")
      assert_match(/\A334/, command(client, "AUTH SCRAM-SHA-256 #{first}"))
      final = [ "c=biws,r=clientnoncebogus,p=#{[ "x" * 32 ].pack("m0")}" ].pack("m0")
      assert_match(/\A535/, command(client, final))
      command(client, "QUIT")
    end

    assert_equal %i[authenticate scram_credentials record_auth_failure], store.ips.map(&:first)
    store.ips.each do |call, ip|
      assert_nil ip, "#{call} was handed the placeholder #{ip.inspect} as an address"
    end
  end

  def test_known_peer_address_reaches_the_store_unchanged
    store = IpRecordingStore.new(logger: Logger.new(@log))
    store.add_account(email: EMAIL, password: PASSWORD)
    with_session(store: store) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      assert_match(/\A235/, command(client, "AUTH PLAIN #{plain_token}"))
      command(client, "QUIT")
    end

    assert_equal [ [ :authenticate, "127.0.0.1" ] ], store.ips
  end
end
