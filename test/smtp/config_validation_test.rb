# frozen_string_literal: true

require "test_helper"
require "tmpdir"
require "logger"
require "stringio"
require "mail_on_rails/netserv/config"
require "mail_on_rails/smtp/daemon"

# Boot-time configuration validation: a bad value must name itself and
# fail the boot / the Daemon.check_config preflight, and
# legal-but-almost-certainly-wrong settings must warn.
class ConfigValidationTest < Minitest::Test
  Config = MailOnRails::Netserv::Config
  Daemon = MailOnRails::Smtp::Daemon

  ENV_PATTERN = /\A(SMTPS?_|RAILS_INBOUND_EMAIL_)/

  def setup
    @saved_env = ENV.to_h.select { |k, _| k.match?(ENV_PATTERN) }
    @saved_env.each_key { |k| ENV.delete(k) }
  end

  def teardown
    ENV.keys.select { |k| k.match?(ENV_PATTERN) }.each { |k| ENV.delete(k) }
    @saved_env.each { |k, v| ENV[k] = v }
  end

  # -- Config typed reads ----------------------------------------------------

  test "int returns the default when unset and parses when set" do
    assert_equal 42, Config.int("SMTP_TEST_INT", 42)
    ENV["SMTP_TEST_INT"] = "7"

    assert_equal 7, Config.int("SMTP_TEST_INT", 42)
  end

  test "int names the variable and the bad value in its error" do
    ENV["SMTP_TEST_INT"] = "many"
    error = assert_raises(Config::Error) { Config.int("SMTP_TEST_INT", 1) }

    assert_includes error.message, "SMTP_TEST_INT"
    assert_includes error.message, '"many"'
  end

  test "int enforces bounds" do
    ENV["SMTP_TEST_INT"] = "-1"
    assert_raises(Config::Error) { Config.int("SMTP_TEST_INT", 1) }

    ENV["SMTP_TEST_INT"] = "99999999"
    assert_raises(Config::Error) { Config.int("SMTP_TEST_INT", 1, max: 100) }
  end

  test "port enforces the tcp range" do
    ENV["SMTP_PORT"] = "0"
    assert_raises(Config::Error) { Config.port("SMTP_PORT", 1025) }

    ENV["SMTP_PORT"] = "70000"
    assert_raises(Config::Error) { Config.port("SMTP_PORT", 1025) }
  end

  # -- Daemon-level validation -----------------------------------------------

  test "duplicate listener ports are a config error" do
    ENV["SMTP_PORT"] = "2525"
    ENV["SMTP_SUBMISSION_PORT"] = "2525"
    error = assert_raises(Config::Error) { Daemon.listeners("127.0.0.1") }

    assert_includes error.message, "distinct"
  end

  test "start raises on a bad port before spawning anything" do
    ENV["SMTP_PORT"] = "not-a-port"

    error = assert_raises(Config::Error) do
      Daemon.start(store: nil, logger: Logger.new(StringIO.new))
    end

    assert_includes error.message, "SMTP_PORT"
  end

  # -- check_config preflight ------------------------------------------------

  def check_config
    logs = StringIO.new
    ok = Daemon.check_config(logger: Logger.new(logs))
    [ ok, logs.string ]
  end

  test "check_config passes a clean configuration and summarizes it" do
    Dir.mktmpdir do |dir|
      ENV["SMTP_TLS_DIR"] = dir

      ok, log = check_config

      assert ok, "clean config must pass: #{log}"
      assert_match(/config OK/, log)
      assert_match(%r{1025/1587/1465}, log)
      refute_match(/warn/i, log, "clean config must not warn")
    end
  end

  test "check_config fails on a bad port" do
    ENV["SMTPS_PORT"] = "nope"

    ok, log = check_config

    refute ok
    assert_match(/SMTPS_PORT/, log)
  end

  test "check_config fails on broken explicit TLS material" do
    ENV["SMTP_TLS_CERT"] = "/nonexistent/fullchain.pem"
    ENV["SMTP_TLS_KEY"] = "/nonexistent/privkey.pem"

    ok, log = check_config

    refute ok
    assert_match(/fullchain\.pem/, log)
  end

  # -- Settings::Check (the CLI `check` report) ------------------------------

  def settings_check
    require "mail_on_rails/settings/check"
    check = MailOnRails::Settings::Check.new
    out = StringIO.new
    ok = check.report(out)
    [ ok, check, out.string ]
  end

  test "settings check warns about the DMARC_ENFORCE=false footgun" do
    # Enforcement is default-on, so the silent spelling trap flipped
    # sides: "false" does not disable it - only "0" does.
    ENV["SMTP_DMARC_ENFORCE"] = "false"

    ok, check, out = settings_check

    assert ok, "a footgun value is a warning, not a failure"
    assert(check.warnings.any? { |w| w.include?("does NOT disable") }, out)
  end

  test "settings check warns when sender auth is disabled" do
    ENV["SMTP_SENDER_AUTH"] = "0"

    ok, check, = settings_check

    assert ok, "disabling sender auth is a warning, not a failure"
    assert(check.warnings.any? { |w| w.include?("without SPF/DKIM/DMARC verification") })
  end

  test "settings check warns about the SENDER_AUTH=false footgun" do
    ENV["SMTP_SENDER_AUTH"] = "false"

    ok, check, = settings_check

    assert ok
    assert(check.warnings.any? { |w| w.include?("does NOT disable") })
  end

  test "settings check reports every bad declared variable as an error" do
    ENV["SMTP_MAX_CONN"] = "many"
    ENV["SMTP_RBL_CACHE_TTL"] = "0"

    ok, check, out = settings_check

    refute ok
    assert_match(/SMTP_MAX_CONN/, out)
    assert_match(/SMTP_RBL_CACHE_TTL/, out)
    assert_operator check.errors.size, :>=, 2
  end

  # -- production posture warnings -------------------------------------------

  # The posture checks fire only with Rails present and in production;
  # this suite is Rails-free, so a stand-in constant flips them on.
  def with_production_rails(extra_env = {})
    saved = extra_env.keys.to_h { |k| [ k, ENV.key?(k) ? ENV[k] : :unset ] }
    extra_env.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    rails = Module.new do
      def self.env
        @env ||= Object.new.tap { |env| def env.production? = true }
      end
    end
    Object.const_set(:Rails, rails)
    yield
  ensure
    Object.send(:remove_const, :Rails)
    saved.each { |k, v| v == :unset ? ENV.delete(k) : ENV[k] = v }
  end

  test "posture warnings stay silent outside production" do
    ok, check, = settings_check

    assert ok
    refute(check.warnings.any? { |w| w.include?("MTA-STS policy mode is testing") })
    refute(check.warnings.any? { |w| w.include?("unsealed inbound email") })
  end

  test "production posture warns when the enforcing defaults are weakened" do
    weakened = {
      "SMTP_DMARC_ENFORCE" => "0",
      "MAILROOM_DMARC_ENFORCE" => "log",
      "MAIL_ON_RAILS_MTA_STS_MODE" => "testing",
      "SMTP_OUTBOUND_REQUIRE_VERIFIED_TLS" => "0"
    }
    with_production_rails(weakened) do
      ok, check, = settings_check

      assert ok, "posture problems are warnings, not failures"
      messages = check.warnings.join("\n")

      assert_match(/DMARC is not enforced/, messages)
      assert_match(/MTA-STS policy mode is testing/, messages)
      assert_match(/outbound TLS is opportunistic and unverified/, messages)
      refute_match(/unsealed inbound email/, messages, "requiring the seal is the default")
      assert_match(/bind all interfaces/, messages)
    end
  end

  test "production posture is quiet on the enforcing defaults (bar the binds and services)" do
    with_production_rails("SMTP_HOST" => "127.0.0.1", "MAIL_ON_RAILS_HOST" => "127.0.0.1",
                          "SMTP_CLAMAV_ADDR" => "clamav:3310") do
      ok, check, = settings_check

      assert ok
      messages = check.warnings.join("\n")

      refute_match(/DMARC is not enforced/, messages)
      refute_match(/MTA-STS policy mode is testing/, messages)
      refute_match(/outbound TLS is opportunistic/, messages)
      refute_match(/rspamd outage lets authenticated submission through/, messages)
    end
  end

  test "production posture warns about the unsealed-mailroom opt-out" do
    with_production_rails("MAILROOM_REQUIRE_SEAL" => "0") do
      ok, check, = settings_check

      assert ok
      assert(check.warnings.any? { |w| w.include?("unsealed inbound email") })
    end
  end

  test "production posture warnings clear under the enforcing overlay" do
    overlay = {
      "SMTP_DMARC_ENFORCE" => "1",
      "MAIL_ON_RAILS_MTA_STS_MODE" => "enforce",
      "SMTP_OUTBOUND_REQUIRE_VERIFIED_TLS" => "1",
      "MAILROOM_REQUIRE_SEAL" => "1",
      "SMTP_HOST" => "127.0.0.1",
      "MAIL_ON_RAILS_HOST" => "127.0.0.1"
    }
    with_production_rails(overlay) do
      ok, check, = settings_check

      assert ok
      messages = check.warnings.join("\n")

      refute_match(/DMARC is not enforced/, messages)
      refute_match(/MTA-STS policy mode is testing/, messages)
      refute_match(/outbound TLS is opportunistic/, messages)
      refute_match(/unsealed inbound email/, messages)
      refute_match(/bind all interfaces/, messages)
    end
  end

  test "production posture warns about fail-open rspamd, cleartext password, and smarthost auth" do
    # A deploy that weakened the enforcing defaults while its services soak:
    # rspamd opted out of fail-closed, outbound TLS back to opportunistic
    # (which is also what silently withholds the smarthost's AUTH).
    services = {
      "SMTP_RSPAMD_ADDR" => "rspamd:11334",
      "SMTP_RSPAMD_PASSWORD" => "s3cret",
      "SMTP_RSPAMD_FAIL_CLOSED" => "0",
      "SMTP_OUTBOUND_REQUIRE_VERIFIED_TLS" => "0",
      "MAIL_ON_RAILS_SMARTHOST" => "relay.example.com:587",
      "MAIL_ON_RAILS_SMARTHOST_USER" => "relay-user"
    }
    with_production_rails(services) do
      ok, check, = settings_check

      assert ok
      messages = check.warnings.join("\n")

      assert_match(/rspamd outage lets authenticated submission through/, messages)
      assert_match(/cleartext HTTP/, messages)
      assert_match(/smarthost AUTH is disabled/, messages)
    end
  end
end
