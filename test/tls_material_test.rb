# frozen_string_literal: true

require "test_helper"
require "tmpdir"
require "logger"
require "stringio"
require "mail_on_rails/smtp/tls"
require "mail_on_rails/smtp/daemon"

# Boot-time TLS material resolution. Explicitly configured cert/key paths
# that fail to load must be fatal: a mail host that silently degrades to
# plaintext-only looks healthy while refusing STARTTLS, SMTPS, and (since
# AUTH requires encryption) all submission. The self-signed development
# path stays forgiving.
class TlsMaterialTest < Minitest::Test
  TLS = MailOnRails::Smtp::TLS
  ENV_KEYS = %w[MAIL_ON_RAILS_TLS_CERT MAIL_ON_RAILS_TLS_KEY].freeze

  def setup
    @saved_env = ENV_KEYS.to_h { |k| [ k, ENV.delete(k) ] }
  end

  def teardown
    @saved_env.each { |k, v| v ? ENV[k] = v : ENV.delete(k) }
  end

  def null_logger
    Logger.new(IO::NULL)
  end

  # Writes a freshly generated self-signed cert/key pair into a tmpdir.
  def with_valid_pems
    Dir.mktmpdir do |dir|
      pems = TLS.generate_self_signed
      cert = File.join(dir, "cert.pem")
      key = File.join(dir, "key.pem")
      File.write(cert, pems[:cert])
      File.write(key, pems[:key])
      yield cert, key, dir
    end
  end

  test "explicit cert and key paths load and are returned as path material" do
    with_valid_pems do |cert, key, _dir|
      ENV["MAIL_ON_RAILS_TLS_CERT"] = cert
      ENV["MAIL_ON_RAILS_TLS_KEY"] = key

      assert_equal({ cert_path: cert, key_path: key }, TLS.material(logger: null_logger))
    end
  end

  test "explicit paths that do not exist are fatal" do
    ENV["MAIL_ON_RAILS_TLS_CERT"] = "/nonexistent/fullchain.pem"
    ENV["MAIL_ON_RAILS_TLS_KEY"] = "/nonexistent/privkey.pem"

    error = assert_raises(TLS::Error) { TLS.material(logger: null_logger) }
    assert_match(/fullchain\.pem/, error.message, "the message must name the bad path")
  end

  test "explicit paths with unusable contents are fatal" do
    with_valid_pems do |_cert, key, dir|
      garbage = File.join(dir, "garbage.pem")
      File.write(garbage, "not a pem")
      ENV["MAIL_ON_RAILS_TLS_CERT"] = garbage
      ENV["MAIL_ON_RAILS_TLS_KEY"] = key

      assert_raises(TLS::Error) { TLS.material(logger: null_logger) }
    end
  end

  test "a cert paired with the wrong key is fatal" do
    with_valid_pems do |cert, _key, dir|
      other_key = File.join(dir, "other.key")
      File.write(other_key, TLS.generate_self_signed[:key])
      ENV["MAIL_ON_RAILS_TLS_CERT"] = cert
      ENV["MAIL_ON_RAILS_TLS_KEY"] = other_key

      assert_raises(TLS::Error) { TLS.material(logger: null_logger) }
    end
  end

  test "setting only one of cert or key is fatal, not a silent self-signed fallback" do
    ENV["MAIL_ON_RAILS_TLS_CERT"] = "/some/fullchain.pem"

    error = assert_raises(TLS::Error) { TLS.material(logger: null_logger) }
    assert_match(/set together/, error.message)
  end

  test "self-signed dev path stays forgiving and returns nil on failure" do
    assert_nil TLS.material(dir: nil, logger: null_logger)
  end

  test "self-signed dev path still provisions inline pems" do
    Dir.mktmpdir do |dir|
      material = TLS.material(dir: dir, logger: null_logger)

      assert material[:cert] && material[:key], "expected inline PEM material"
      assert_path_exists File.join(dir, "selfsigned.crt")
    end
  end

  test "daemon refuses to start on broken explicit TLS config" do
    ENV["MAIL_ON_RAILS_TLS_CERT"] = "/nonexistent/fullchain.pem"
    ENV["MAIL_ON_RAILS_TLS_KEY"] = "/nonexistent/privkey.pem"
    logs = StringIO.new

    error = assert_raises(SystemExit) do
      MailOnRails::Smtp::Daemon.run!(logger: Logger.new(logs))
    end

    refute_predicate error, :success?, "boot must exit non-zero"
    assert_match(/refusing to start/, logs.string)
    assert_match(/fullchain\.pem/, logs.string, "the log must name the bad path")
  end
end
