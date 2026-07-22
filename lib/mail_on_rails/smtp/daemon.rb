# frozen_string_literal: true

require "socket"
require "logger"
require_relative "config"
require_relative "../smtp_server"
require_relative "tls"
require_relative "store/http"

module MailOnRails
  module Smtp
    # Env-driven runtime for the SMTP server: builds the listener specs, TLS
    # material, and the HTTP-backed store, then runs the server on a thread.
    # Used two ways:
    #
    #   - bin/server in this repo (`Daemon.run!`), the foreground process the
    #     Kamal service runs - no Rails anywhere in the container. With the
    #     default HTTP store this serves sessions from one worker Ractor per
    #     core (see Smtp::Server / Smtp::Worker).
    #   - embedded in a host process via `Daemon.start` (e.g. a Rails app
    #     running the server inside Puma in development, passing its own
    #     store/logger). An injected store keeps sessions on worker threads
    #     in this process - Ractor workers can't share an in-process store.
    module Daemon
      module_function

      def run!(logger: default_logger)
        start(logger: logger).join
        # The server thread only returns once every listener has died - exit
        # non-zero so Docker restarts the container.
        logger.error "[mail_on_rails] SMTP server exited - shutting down"
        exit 1
      rescue TLS::Error, Config::Error => e
        # Misconfiguration must not boot a degraded mail host that looks
        # healthy (explicit TLS falling back to plaintext, a bad port, ...).
        logger.error "[mail_on_rails] #{e.message} - refusing to start"
        exit 1
      end

      # Deploy preflight (`bin/server --check-config`): validates the same
      # configuration boot would use and logs a one-line summary. Returns
      # true when bootable; fatal problems log an error and return false,
      # suspicious-but-runnable settings log warnings.
      def check_config(logger: default_logger)
        host = ENV.fetch("MAIL_ON_RAILS_HOST", "0.0.0.0")
        specs = listeners(host)
        tls = TLS.material(dir: ENV.fetch("MAIL_ON_RAILS_TLS_DIR", "storage/tls"), logger: logger)
        config_warnings(logger)
        tls_summary = tls ? (tls[:cert_path] ? "from #{tls[:cert_path]}" : "self-signed") : "UNAVAILABLE (plaintext only)"
        logger.info "[mail_on_rails] config OK: ports #{specs.map { |s| s[:port] }.join("/")} on #{host}, " \
                    "hostname #{specs.first[:hostname]}, TLS #{tls_summary}"
        true
      rescue TLS::Error, Config::Error => e
        logger.error "[mail_on_rails] config error: #{e.message}"
        false
      end

      # Settings that are legal but almost certainly not what the operator
      # meant - each has caused (or would cause) a quiet runtime failure.
      def config_warnings(logger)
        if ENV["MAIL_ON_RAILS_INTERNAL_API_PASSWORD"].to_s.empty?
          logger.warn "[mail_on_rails] MAIL_ON_RAILS_INTERNAL_API_PASSWORD is not set - " \
                      "the app will refuse credential and recipient checks"
        end
        if ENV["MAIL_ON_RAILS_INGRESS_PASSWORD"].to_s.empty? && ENV["RAILS_INBOUND_EMAIL_PASSWORD"].to_s.empty?
          logger.warn "[mail_on_rails] MAIL_ON_RAILS_INGRESS_PASSWORD is not set - " \
                      "the app will refuse inbound mail"
        end
        mode = ENV["MAIL_ON_RAILS_SMTP_WORKER_MODE"]
        if mode && !%w[thread auto].include?(mode)
          logger.warn "[mail_on_rails] MAIL_ON_RAILS_SMTP_WORKER_MODE=#{mode} is not recognized " \
                      "(\"thread\" or \"auto\") - treating as auto"
        end
        enforce = ENV["MAIL_ON_RAILS_DMARC_ENFORCE"]
        if enforce && enforce != "1" && enforce.match?(/\A(true|yes|on|enabled)\z/i)
          logger.warn "[mail_on_rails] MAIL_ON_RAILS_DMARC_ENFORCE=#{enforce} does NOT enable " \
                      "enforcement - only \"1\" does"
        end
        sender_auth = ENV["MAIL_ON_RAILS_SENDER_AUTH"]
        if sender_auth == "0"
          logger.warn "[mail_on_rails] MAIL_ON_RAILS_SENDER_AUTH=0 - inbound mail is accepted " \
                      "without SPF/DKIM/DMARC verification"
        elsif sender_auth && sender_auth.match?(/\A(false|no|off|disabled)\z/i)
          logger.warn "[mail_on_rails] MAIL_ON_RAILS_SENDER_AUTH=#{sender_auth} does NOT disable " \
                      "verification - only \"0\" does"
        end
      end

      # Starts the server on a named thread and returns it. A server that
      # dies logs the error and its thread ends; callers decide whether that
      # is fatal (run! exits, an embedding web process carries on).
      def start(logger: default_logger, store: nil, host: nil, tls_dir: nil)
        store ||= Store::Http.new(logger: logger)
        host ||= ENV.fetch("MAIL_ON_RAILS_HOST", "0.0.0.0")
        specs = listeners(host)
        tls = tls_material(logger, tls_dir || ENV.fetch("MAIL_ON_RAILS_TLS_DIR", "storage/tls"))

        logger.info "[mail_on_rails] SMTP #{specs.map { |s| s[:port] }.join("/")} on #{host}"
        Thread.new do
          Thread.current.name = "mail_on_rails_smtp"
          SmtpServer.run(store, specs, tls)
        rescue StandardError => e
          logger.error "[mail_on_rails] mail_on_rails_smtp died: #{e.class}: #{e.message}"
        end
      end

      def listeners(host)
        # Announced in the SMTP banner/EHLO (RFC 5321 wants our FQDN; spam
        # filters compare it to the PTR).
        hostname = ENV.fetch("MAIL_ON_RAILS_HELO_HOST") { Socket.gethostname }
        specs = [
          { host: host, port: env_port("MAIL_ON_RAILS_SMTP_PORT", 1025), tls: :starttls, role: :mx, hostname: hostname },
          { host: host, port: env_port("MAIL_ON_RAILS_SMTP_SUBMISSION_PORT", 1587), tls: :starttls, role: :submission, hostname: hostname },
          { host: host, port: env_port("MAIL_ON_RAILS_SMTPS_PORT", 1465), tls: :implicit, role: :submission, hostname: hostname }
        ]
        ports = specs.map { |s| s[:port] }
        unless ports.uniq.size == ports.size
          raise Config::Error, "listener ports must be distinct, got #{ports.join(", ")}"
        end

        specs
      end

      # Hash of plain strings (PEMs or file paths); nil if unavailable.
      def tls_material(logger, dir)
        material = TLS.material(dir: dir, logger: logger)
        logger.warn "[mail_on_rails] TLS unavailable - plaintext only" if material.nil?
        material
      end

      def env_port(name, default)
        Config.port(name, default)
      end

      def default_logger
        Logger.new($stdout, progname: "mail_on_rails_smtp")
      end
    end
  end
end
