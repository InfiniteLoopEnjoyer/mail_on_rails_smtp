# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/smtp_server"
require "mail_on_rails/scram"
require "mail_on_rails/smtp/store/memory"

# The per-connection AUTH budget (2026-11-17 audit, M3).
#
# An AUTH can end without a verdict on the password: the peer's IP is
# locked out, the store is throttling the address, the store is
# unreachable, the account is at its session cap. Those answer 454 and -
# deliberately - are not failures: nothing is reported to the lockout or
# to the store's failure counters, so a client retrying through an outage
# cannot lock its own address out. But they used to cost the connection
# nothing either, so one connection could pipeline AUTH for the whole
# session lifetime, a store read (and an audit row) apiece. Every AUTH
# that does not succeed now spends one of MAX_AUTH_ATTEMPTS, as the IMAP
# session does; the last one is answered 421 and the connection closes.
class SmtpAuthBudgetTest < Minitest::Test
  Scram = MailOnRails::Scram
  MAX = MailOnRails::SmtpServer::MAX_AUTH_ATTEMPTS

  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  # Counts what the session asks of the store, and answers AUTH the way
  # +mode+ says: :throttled / :error as Store::Base does, else for real.
  class CountingStore < MailOnRails::Smtp::Store::Memory
    attr_accessor :mode
    attr_reader :calls

    def initialize(...)
      super
      @calls = Hash.new(0)
    end

    def refusal
      case mode
      when :throttled then { account_id: nil, email: nil, throttled: true, retry_after: 300 }
      when :error then { error: "PG::ConnectionBad: server closed the connection", code: :internal }
      end
    end

    def authenticate(email, password, ip: nil, source: nil)
      @calls[:authenticate] += 1
      refusal || super
    end

    def scram_credentials(email, ip: nil)
      @calls[:scram_credentials] += 1
      refusal || super
    end

    def record_auth_failure(email, ip: nil, source: nil)
      @calls[:record_auth_failure] += 1
      super
    end
  end

  def setup
    @store = CountingStore.new
    @store.add_account(email: EMAIL, password: PASSWORD)
    @lockout_reports = 0
    @locked = false
  end

  def with_session(spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :implicit, role: :submission,
             hostname: "mx.test" }.merge(spec_extra)
    @session = MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, nil)
    @session.on_auth_failure = -> { @lockout_reports += 1 }
    @session.auth_locked = -> { @locked }
    thread = Thread.new { @session.run }
    read_reply(client)
    command(client, "EHLO client.test")
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

  def plain(password = PASSWORD) = "AUTH PLAIN #{[ "\0#{EMAIL}\0#{password}" ].pack("m0")}"
  def scram_first = "AUTH SCRAM-SHA-256 #{[ "n,,n=#{EMAIL},r=clientnonce123" ].pack("m0")}"

  def closed?(client)
    client.gets("\r\n").nil?
  rescue IOError, SystemCallError
    true
  end

  # MAX - 1 temporary refusals, then the 421 and the close - and through
  # all of it nothing reported as a failed password.
  def assert_budget_spent(client, line)
    (MAX - 1).times { |i| assert_match(/\A454 4\.7\.0 /, command(client, line), "attempt #{i + 1}") }
    assert_match(/\A421 4\.7\.0 /, command(client, line), "attempt #{MAX} must be the last")
    assert closed?(client), "the connection must close after the 421"
    assert_equal 0, @lockout_reports, "a temporary refusal must not feed the accept-side lockout"
    assert_equal 0, @store.calls[:record_auth_failure], "nor the store's failure counters"
  end

  test "PLAIN: store-throttled attempts spend the connection's budget" do
    @store.mode = :throttled
    with_session { |client| assert_budget_spent(client, plain) }
    assert_equal MAX, @store.calls[:authenticate]
  end

  test "PLAIN: store-unreachable attempts spend the connection's budget" do
    @store.mode = :error
    with_session { |client| assert_budget_spent(client, plain) }
    assert_equal MAX, @store.calls[:authenticate]
  end

  test "PLAIN: attempts from a locked-out IP spend the connection's budget and never reach the store" do
    @locked = true
    with_session { |client| assert_budget_spent(client, plain) }
    assert_equal 0, @store.calls[:authenticate]
  end

  test "LOGIN: the same budget" do
    @store.mode = :throttled
    with_session do |client|
      MAX.times do |i|
        assert_match(/\A334/, command(client, "AUTH LOGIN #{[ EMAIL ].pack("m0")}"))
        reply = command(client, [ PASSWORD ].pack("m0"))
        assert_match(i < MAX - 1 ? /\A454/ : /\A421/, reply)
      end
      assert closed?(client)
    end
  end

  test "SCRAM: throttled, unreachable and locked-out attempts spend the connection's budget" do
    %i[throttled error locked].each do |mode|
      setup
      @store.mode = mode
      @locked = mode == :locked
      with_session { |client| assert_budget_spent(client, scram_first) }
      assert_equal (mode == :locked ? 0 : MAX), @store.calls[:scram_credentials], mode.to_s
    end
  end

  test "an account at its session cap: right password, still one attempt per refusal" do
    with_session(spec_extra: { max_sessions_per_account: 1 }) do |holder|
      assert_match(/\A235/, command(holder, plain))
      with_session(spec_extra: { max_sessions_per_account: 1 }) do |client|
        (MAX - 1).times { assert_match(/\A454 4\.7\.0 Too many simultaneous sessions/, command(client, plain)) }
        assert_match(/\A421 4\.7\.0 /, command(client, plain))
        assert closed?(client)
      end
    end
    assert_equal 0, @lockout_reports, "the password was right: not a failure"
  end

  # The audit's reproducer: thousands of AUTH pipelined on one connection.
  test "pipelined AUTH on one connection reaches the store MAX times, not thousands" do
    @store.mode = :throttled
    with_session do |client|
      begin
        client.write("#{plain}\r\n" * 3000)
      rescue SystemCallError
        nil # hung up on mid-write: the point
      end
      replies = []
      begin
        while (line = client.gets("\r\n"))
          replies << line
        end
      rescue SystemCallError
        nil # the reset can eat replies in flight; the store count below is the assertion
      end
      assert_operator replies.size, :<=, MAX
    end
    assert_equal MAX, @store.calls[:authenticate]
  end

  test "temporary refusals and wrong passwords draw on the same budget" do
    with_session do |client|
      assert_match(/\A535/, command(client, plain("wrong")))
      @store.mode = :throttled
      assert_match(/\A454/, command(client, plain))
      assert_match(/\A421/, command(client, plain))
      assert closed?(client)
    end
    assert_equal 1, @lockout_reports, "only the wrong password is a failure"
  end

  test "a login that succeeds within the budget still succeeds" do
    with_session do |client|
      @store.mode = :error
      (MAX - 1).times { assert_match(/\A454/, command(client, plain)) }
      @store.mode = nil
      assert_match(/\A235/, command(client, plain))
      assert_match(/\A250/, command(client, "NOOP"))
    end
    assert_equal 0, @lockout_reports
  end
end
