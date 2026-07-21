# frozen_string_literal: true

require "socket"
require "logger"
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
        [
          { host: host, port: env_port("MAIL_ON_RAILS_SMTP_PORT", 1025), tls: :starttls, role: :mx, hostname: hostname },
          { host: host, port: env_port("MAIL_ON_RAILS_SMTP_SUBMISSION_PORT", 1587), tls: :starttls, role: :submission, hostname: hostname },
          { host: host, port: env_port("MAIL_ON_RAILS_SMTPS_PORT", 1465), tls: :implicit, role: :submission, hostname: hostname }
        ]
      end

      # Hash of plain strings (PEMs or file paths); nil if unavailable.
      def tls_material(logger, dir)
        material = TLS.material(dir: dir, logger: logger)
        logger.warn "[mail_on_rails] TLS unavailable - plaintext only" if material.nil?
        material
      end

      def env_port(name, default)
        Integer(ENV.fetch(name, default))
      end

      def default_logger
        Logger.new($stdout, progname: "mail_on_rails_smtp")
      end
    end
  end
end
