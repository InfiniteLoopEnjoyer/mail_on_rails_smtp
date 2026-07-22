# frozen_string_literal: true

require "test_helper"
require "tmpdir"
require "logger"
require "stringio"
require "mail_on_rails/smtp/config"
require "mail_on_rails/smtp/daemon"

# Boot-time configuration validation (todo item 10): a bad value must name
# itself and fail the boot / the `bin/server --check-config` preflight, and
# legal-but-almost-certainly-wrong settings must warn.
class ConfigValidationTest < Minitest::Test
  Config = MailOnRails::Smtp::Config
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

  test "run! refuses to start on a bad port" do
    ENV["SMTP_PORT"] = "not-a-port"
    logs = StringIO.new

    error = assert_raises(SystemExit) { Daemon.run!(logger: Logger.new(logs)) }

    refute_predicate error, :success?
    assert_match(/refusing to start/, logs.string)
    assert_match(/SMTP_PORT/, logs.string)
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
      ENV["SMTP_INTERNAL_API_PASSWORD"] = "s3cret"
      ENV["SMTP_INGRESS_PASSWORD"] = "s3cret"

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

  test "check_config warns about the DMARC_ENFORCE=true footgun" do
    Dir.mktmpdir do |dir|
      ENV["SMTP_TLS_DIR"] = dir
      ENV["SMTP_DMARC_ENFORCE"] = "true"

      ok, log = check_config

      assert ok, "a footgun value is a warning, not a failure"
      assert_match(/does NOT enable/, log)
    end
  end

  test "check_config warns when sender auth is disabled" do
    Dir.mktmpdir do |dir|
      ENV["SMTP_TLS_DIR"] = dir
      ENV["SMTP_SENDER_AUTH"] = "0"

      ok, log = check_config

      assert ok, "disabling sender auth is a warning, not a failure"
      assert_match(/without SPF\/DKIM\/DMARC verification/, log)
    end
  end

  test "check_config warns about the SENDER_AUTH=false footgun" do
    Dir.mktmpdir do |dir|
      ENV["SMTP_TLS_DIR"] = dir
      ENV["SMTP_SENDER_AUTH"] = "false"

      ok, log = check_config

      assert ok
      assert_match(/does NOT disable/, log)
    end
  end

  test "check_config warns about missing passwords and unknown worker mode" do
    Dir.mktmpdir do |dir|
      ENV["SMTP_TLS_DIR"] = dir
      ENV["SMTP_WORKER_MODE"] = "ractor"

      ok, log = check_config

      assert ok
      assert_match(/SMTP_INTERNAL_API_PASSWORD is not set/, log)
      assert_match(/SMTP_INGRESS_PASSWORD is not set/, log)
      assert_match(/WORKER_MODE=ractor is not recognized/, log)
    end
  end
end
