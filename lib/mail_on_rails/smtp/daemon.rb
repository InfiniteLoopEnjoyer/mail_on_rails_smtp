# frozen_string_literal: true

require "socket"
require "logger"
require "mail_on_rails/settings"
require "mail_on_rails/netserv/config"
require_relative "../smtp_server"

module MailOnRails
  module Smtp
    # Env-driven runtime for the SMTP server: builds the listener specs and
    # TLS material, then runs the server on a thread inside the host
    # process (the Rails app's Puma, via the :mail_on_rails plugin). The
    # caller injects the store - in the app that's the ActiveRecord-backed
    # MailOnRails::Store::SmtpBackend.
    module Daemon
      # What start returns: the running server plus its thread, with the
      # lifecycle calls the host process needs (readiness before reporting
      # healthy, graceful shutdown from the Puma hooks).
      Handle = Struct.new(:server, :thread, keyword_init: true) do
        def ready? = server.ready?
        def wait_ready(timeout = 15) = server.wait_ready(timeout)
        def shutdown(drain: 5) = server.shutdown(drain: drain)
      end

      module_function

      # Boot preflight: validates the same configuration start would use
      # and logs a one-line summary. Returns true when bootable; fatal
      # problems log an error and return false. (Suspicious-but-runnable
      # settings are Settings::Check's department - the CLI's `check`
      # runs both.)
      def check_config(logger: default_logger)
        Settings.validate_env!
        host = Settings.static(:smtp_host)
        specs = listeners(host)
        tls = Netserv::Tls.for(:smtp).material(dir: Settings.static(:smtp_tls_dir), logger: logger)
        tls_summary = tls ? (tls[:cert_path] ? "from #{tls[:cert_path]}" : "self-signed") : "UNAVAILABLE (plaintext only)"
        logger.info "[mail_on_rails] SMTP config OK: ports #{specs.map { |s| s[:port] }.join("/")} on #{host}, " \
                    "hostname #{specs.first[:hostname]}, TLS #{tls_summary}"
        true
      rescue Netserv::Tls::Error, Netserv::Config::Error => e
        logger.error "[mail_on_rails] SMTP config error: #{e.message}"
        false
      end

      # Starts the server on a named thread and returns a Handle. A server
      # that dies logs the error and its thread ends; the embedding web
      # process carries on serving web requests.
      def start(store:, logger: default_logger, host: nil, tls_dir: nil, hostname: nil)
        # Every declared variable is parsed here so a typo fails the boot
        # (as the old load-time constants did) rather than per connection.
        Settings.validate_env!
        host ||= Settings.static(:smtp_host)
        specs = listeners(host, hostname: hostname)
        tls = tls_material(logger, tls_dir || Settings.static(:smtp_tls_dir))

        logger.info "[mail_on_rails] SMTP #{specs.map { |s| s[:port] }.join("/")} on #{host}"
        server = SmtpServer.new(store, specs, tls)
        thread = Thread.new do
          Thread.current.name = "mail_on_rails_smtp"
          server.run
        rescue StandardError => e
          logger.error "[mail_on_rails] mail_on_rails_smtp died: #{e.class}: #{e.message}"
        end
        Handle.new(server: server, thread: thread)
      end

      def listeners(host, hostname: nil)
        # Announced in the SMTP banner/EHLO (RFC 5321 wants our FQDN; spam
        # filters compare it to the PTR). The host app may pass a callable
        # instead of a string - sessions resolve it per connection, so a
        # changed name applies without a restart.
        hostname ||= Settings.static(:smtp_helo_hostname) || Socket.gethostname
        specs = [
          { host: host, port: Settings.static(:smtp_port), tls: :starttls, role: :mx, hostname: hostname },
          { host: host, port: Settings.static(:smtp_submission_port), tls: :starttls, role: :submission, hostname: hostname },
          { host: host, port: Settings.static(:smtps_port), tls: :implicit, role: :submission, hostname: hostname }
        ]
        # Optional deceptive fingerprint in the 220 greeting - a fake vulnerable
        # product/version to bait scanners. Cosmetic (it doesn't touch
        # Received:/HELO/PTR/DMARC), applied to every listener; unset = the real
        # banner. See Netserv::HoneypotSession.
        if (banner = Settings.static(:honeypot_banner))
          specs.each { |spec| spec[:honeypot_banner] = banner }
        end
        ports = specs.map { |s| s[:port] }
        unless ports.uniq.size == ports.size
          raise Netserv::Config::Error, "listener ports must be distinct, got #{ports.join(", ")}"
        end

        specs
      end

      # Hash of plain strings (PEMs or file paths); nil if unavailable.
      # Production refuses to run plaintext-only: Runtime's boot preflight
      # already fails without explicit cert/key, and this guards a direct
      # Daemon.start the same way - an MX quietly accepting cleartext (and
      # a submission port that can never offer AUTH) must be a hard config
      # error, not a warning line. Development keeps the forgiving path.
      def tls_material(logger, dir)
        material = Netserv::Tls.for(:smtp).material(dir: dir, logger: logger)
        if material.nil? && ENV["RAILS_ENV"] == "production"
          raise Netserv::Config::Error,
                "TLS material unavailable - production refuses plaintext-only SMTP listeners " \
                "(set SMTP_TLS_CERT/SMTP_TLS_KEY)"
        end
        logger.warn "[mail_on_rails] TLS unavailable - plaintext only" if material.nil?
        material
      end

      def default_logger
        Logger.new($stdout, progname: "mail_on_rails_smtp")
      end
    end
  end
end
