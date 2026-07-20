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
end
