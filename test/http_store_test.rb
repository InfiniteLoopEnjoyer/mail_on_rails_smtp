require "test_helper"
require "logger"
require "mail_on_rails/smtp/store/http"
require "mail_on_rails/smtp/store/contracts"

# The HTTP-backed SMTP store must satisfy the same contract as every other
# store. The fakes below stand in for the host app's two HTTP surfaces with
# the same semantics (the host app's own tests cover the real endpoints).
class FakeInternalApi
  attr_reader :outbound

  def initialize(outbound_limit: 1_000)
    @accounts = {}
    @outbound = []
    @outbound_limit = outbound_limit
  end

  def add_account(email:, password:)
    normalized = email.to_s.strip.downcase
    @accounts[normalized] = { id: @accounts.size + 1, password: password }
    @accounts[normalized][:id]
  end

  def authenticate(email, password)
    account = @accounts[email.to_s.strip.downcase]
    if account && !password.to_s.empty? && account[:password] == password
      { account_id: account[:id], email: email.to_s.strip.downcase }
    else
      { account_id: nil, email: nil }
    end
  end

  def local_rcpts(addresses)
    Array(addresses).map { |a| a.to_s.strip.downcase }.uniq & @accounts.keys
  end

  def queue_outbound(mail_from:, recipients:, data:)
    if @outbound.size + recipients.size > @outbound_limit
      raise MailOnRails::Smtp::InternalApi::Error.new("outbound queueing failed: 507", code: :insufficient_storage)
    end

    recipients.each { |r| @outbound << { mail_from: mail_from, recipient: r, data: data } }
    true
  end
end

class RecordingIngress < MailOnRails::Smtp::IngressClient
  attr_reader :deliveries

  def initialize(accept: true)
    super(url: "http://ingress.test/rails/action_mailbox/relay/inbound_emails", password: "test",
          logger: Logger.new(IO::NULL))
    @accept = accept
    @deliveries = []
  end

  def deliver(source)
    @deliveries << source
    @accept
  end
end

class HttpStoreTest < Minitest::Test
  include MailOnRails::Smtp::Store::Contracts::Smtp

  def build_store(**limits)
    @api = FakeInternalApi.new(**limits)
    @ingress = RecordingIngress.new
    MailOnRails::Smtp::Store::Http.new(api: @api, ingress: @ingress, logger: Logger.new(IO::NULL))
  end

  def create_account(email:, password:)
    store # ensure built
    @api.add_account(email: email, password: password)
  end

  # Beyond the contract (which has no read side for SMTP): the trust stamp
  # must travel with the bytes, out of the sender's reach - here as
  # X-MailOnRails-* headers on the ingress payload, forged copies stripped.
  test "smtp_store stamps trust headers on the ingress payload" do
    account_id
    forged = "X-MailOnRails-Authenticated: #{EMAIL} (forged)\r\nFrom: a@b.test\r\n\r\nbody\r\n"
    store.smtp_store("sender@remote.test", [ EMAIL ], forged, EMAIL, auth_results: "spf=pass dkim=pass")

    source = @ingress.deliveries.last
    assert_includes source, "X-MailOnRails-Authenticated: #{EMAIL}\r\n"
    assert_includes source, "X-MailOnRails-Auth-Results: spf=pass dkim=pass\r\n"
    assert_includes source, "X-Original-To: #{EMAIL}\r\n"
    assert_includes source, "Return-Path: <sender@remote.test>\r\n"
    refute_includes source, "forged"
  end

  test "smtp_store stamps unauthenticated mail as untrusted" do
    account_id
    store.smtp_store("sender@remote.test", [ EMAIL ], MailOnRails::Smtp::Store::Contracts::Smtp::RAW, nil)
    assert_includes @ingress.deliveries.last, "X-MailOnRails-Authenticated: no\r\n"
  end

  test "smtp_store stamps the clean scan verdict on the ingress payload" do
    account_id
    store.smtp_store("sender@remote.test", [ EMAIL ], MailOnRails::Smtp::Store::Contracts::Smtp::RAW, nil,
                     scan_status: "clean")
    assert_includes @ingress.deliveries.last, "X-MailOnRails-Scan: clean\r\n"
  end

  test "quarantine stamps and delivers a review copy to the local recipients" do
    account_id
    store.quarantine("sender@remote.test", [ EMAIL, "stranger@elsewhere.test" ],
                     MailOnRails::Smtp::Store::Contracts::Smtp::RAW, nil,
                     auth_results: "spf=fail", scan_status: "infected", virus: "Eicar-Test-Signature")

    source = @ingress.deliveries.last
    refute_nil source
    assert_includes source, "X-MailOnRails-Scan: infected\r\n"
    assert_includes source, "X-MailOnRails-Virus: Eicar-Test-Signature\r\n"
    assert_includes source, "X-Original-To: #{EMAIL}\r\n"
    refute_includes source, "X-Original-To: stranger@elsewhere.test"
  end

  test "quarantine falls back to the authenticated sender for remote-only submissions" do
    account_id
    store.quarantine(EMAIL, [ "friend@elsewhere.test" ], MailOnRails::Smtp::Store::Contracts::Smtp::RAW, EMAIL,
                     auth_results: nil, scan_status: "unscanned")

    source = @ingress.deliveries.last
    refute_nil source
    assert_includes source, "X-Original-To: #{EMAIL}\r\n"
    assert_includes source, "X-MailOnRails-Scan: unscanned\r\n"
  end

  test "quarantine never raises when the api or ingress is down" do
    account_id
    down = Object.new
    def down.local_rcpts(*) = raise(Errno::ECONNREFUSED)
    broken = MailOnRails::Smtp::Store::Http.new(api: down, ingress: @ingress, logger: Logger.new(IO::NULL))

    assert_nil broken.quarantine("s@remote.test", [ EMAIL ], "raw", nil,
                                 auth_results: nil, scan_status: "infected", virus: "X")

    refusing = MailOnRails::Smtp::Store::Http.new(api: @api, ingress: RecordingIngress.new(accept: false),
                                                  logger: Logger.new(IO::NULL))
    assert_nil refusing.quarantine("s@remote.test", [ EMAIL ], "raw", nil,
                                   auth_results: nil, scan_status: "infected", virus: "X")
  end

  test "smtp_store surfaces an ingress refusal as the internal envelope" do
    account_id
    refusing = MailOnRails::Smtp::Store::Http.new(api: @api, ingress: RecordingIngress.new(accept: false),
                                                  logger: Logger.new(IO::NULL))
    result = refusing.smtp_store("sender@remote.test", [ EMAIL ], MailOnRails::Smtp::Store::Contracts::Smtp::RAW, nil)
    assert_equal :internal, result[:code]
  end

  test "smtp_store surfaces api connection failures as the internal envelope" do
    account_id
    down = Object.new
    def down.local_rcpts(*) = raise(Errno::ECONNREFUSED)
    broken = MailOnRails::Smtp::Store::Http.new(api: down, ingress: @ingress, logger: Logger.new(IO::NULL))
    result = broken.smtp_store("sender@remote.test", [ EMAIL ], MailOnRails::Smtp::Store::Contracts::Smtp::RAW, nil)
    assert_equal :internal, result[:code]
  end

  # -- N4: at-least-once duplication window (documented, pinned) ------------
  #
  # Mixed local+remote recipients queue outbound FIRST; if the ingress then
  # refuses, the session answers 451 and the sending client retries the
  # whole message - so the outbound copies are queued again. Dedupe belongs
  # app-side (where the queue lives); this test pins the daemon's behavior
  # so a change to the ordering or semantics is a conscious one.
  test "smtp_store queues outbound again when the sender retries after an ingress failure" do
    account_id
    refusing = MailOnRails::Smtp::Store::Http.new(api: @api, ingress: RecordingIngress.new(accept: false),
                                                  logger: Logger.new(IO::NULL))
    2.times do # the original attempt, then the sender's retry
      result = refusing.smtp_store(EMAIL, [ EMAIL, "remote@elsewhere.test" ],
                                   MailOnRails::Smtp::Store::Contracts::Smtp::RAW, EMAIL)

      assert_equal :internal, result[:code], "the ingress refusal must tempfail the whole message"
    end

    assert_equal 2, @api.outbound.size,
                 "outbound duplication on retry is the documented at-least-once trade-off"
  end

  # -- failure taxonomy against a real HTTP client ---------------------------
  #
  # A scripted TCP responder exercises MailOnRails::Smtp::InternalApi (the
  # real Net::HTTP client) rather than a stand-in: read timeouts, non-JSON
  # bodies, and auth rejections must all degrade to the store contract's
  # error envelope, never raise into the session.

  # respond: nil hangs forever (never answers); a String is written verbatim.
  def with_fake_http_server(respond)
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      loop do
        conn = server.accept
        while (line = conn.gets) && line != "\r\n"; end # consume request head
        if respond
          conn.write(respond)
          conn.close
        end # else: hold the connection open, never answering
      end
    rescue IOError
      nil
    end
    yield MailOnRails::Smtp::InternalApi.new(url: "http://127.0.0.1:#{server.addr[1]}/internal",
                                             password: "pw", open_timeout: 1, read_timeout: 0.3)
  ensure
    thread&.kill
    server&.close
  end

  def store_backed_by(api)
    MailOnRails::Smtp::Store::Http.new(api: api, ingress: RecordingIngress.new, logger: Logger.new(IO::NULL))
  end

  test "a hung app surfaces as the internal envelope, bounded by the read timeout" do
    with_fake_http_server(nil) do |api|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result = store_backed_by(api).local_rcpts([ "a@b.test" ])
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

      assert_equal :internal, result[:code]
      assert_operator elapsed, :<, 5, "the read timeout must bound a hung app"
    end
  end

  test "a non-json 200 body surfaces as the internal envelope" do
    body = "<html>surprise maintenance page</html>"
    with_fake_http_server("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}") do |api|
      result = store_backed_by(api).authenticate("a@b.test", "pw")

      assert_equal :internal, result[:code]
    end
  end

  test "a 401 names the password variable so it reads as config, not weather" do
    with_fake_http_server("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") do |api|
      result = store_backed_by(api).authenticate("a@b.test", "pw")

      assert_equal :internal, result[:code]
      assert_includes result[:error], "MAIL_ON_RAILS_INTERNAL_API_PASSWORD"
    end
  end

  test "a refused connection surfaces as the internal envelope" do
    closed = TCPServer.new("127.0.0.1", 0)
    port = closed.addr[1]
    closed.close
    api = MailOnRails::Smtp::InternalApi.new(url: "http://127.0.0.1:#{port}/internal",
                                             password: "pw", open_timeout: 1, read_timeout: 1)
    result = store_backed_by(api).local_rcpts([ "a@b.test" ])

    assert_equal :internal, result[:code]
  end
end
