# frozen_string_literal: true

require_relative "test_helper"

# The SMTP runtime adapter: registered with the core runtime on load, and
# its production boot guards. Each failure mode here looks "up" from a
# deploy's point of view, which is exactly why it must fail the boot:
# the self-signed TLS fallback is development-only, and running without a
# virus scanner has to be a decision (SMTP_CLAMAV_OPTIONAL=1), never a
# forgotten env.
class SmtpProtocolTest < Minitest::Test
  TLS_ENV = %w[SMTP_TLS_CERT SMTP_TLS_KEY].freeze

  def teardown
    MailOnRails::Settings.reset!
  end

  def with_tls_env(values)
    previous = TLS_ENV.to_h { |name| [ name, ENV[name] ] }
    TLS_ENV.each { |name| values[name] ? ENV[name] = values[name] : ENV.delete(name) }
    yield
  ensure
    previous.each { |name, value| value ? ENV[name] = value : ENV.delete(name) }
  end

  test "requiring the gem registers :smtp with the runtime" do
    assert MailOnRails::Runtime.registered?(:smtp)
    assert_equal MailOnRails::Smtp::Protocol, MailOnRails::Runtime.adapter(:smtp)
  end

  test "a boot without explicit TLS material raises, naming the pair" do
    with_tls_env({}) do
      error = assert_raises(RuntimeError) { MailOnRails::Smtp::Protocol.require_explicit_tls! }
      assert_match(/SMTP_TLS_CERT/, error.message)
    end
  end

  test "an empty clamd address fails the production boot" do
    MailOnRails::Settings.overrides = { smtp_clamav_addr: "" }
    error = assert_raises(RuntimeError) { MailOnRails::Smtp::Protocol.require_virus_scanner! }
    assert_match(/SMTP_CLAMAV_ADDR/, error.message)
    assert_match(/SMTP_CLAMAV_OPTIONAL/, error.message)
  end

  test "SMTP_CLAMAV_OPTIONAL permits booting without a scanner" do
    MailOnRails::Settings.overrides = { smtp_clamav_addr: "", smtp_clamav_optional: true }
    assert_nil MailOnRails::Smtp::Protocol.require_virus_scanner!
  end

  test "a configured clamd address and explicit TLS pass the whole preflight" do
    MailOnRails::Settings.overrides = { smtp_clamav_addr: "127.0.0.1:3310" }
    with_tls_env("SMTP_TLS_CERT" => "/x/cert.pem", "SMTP_TLS_KEY" => "/x/key.pem") do
      assert_nil MailOnRails::Smtp::Protocol.preflight!
    end
  end
end
