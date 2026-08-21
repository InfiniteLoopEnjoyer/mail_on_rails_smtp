# frozen_string_literal: true

# The SMTP protocol gem's entry point: loads the server tree and its
# ActiveRecord store, and registers the protocol with MailOnRails::Runtime
# so `plugin :mail_on_rails` / bin/mail_server can start it. Requiring this
# file is what makes SMTP "installed" - a host without it never boots an
# SMTP listener and the runtime rejects `--protocols smtp` with a clear
# message.
#
# The server itself (SmtpServer, Smtp::Daemon, the memory store) stays
# Rails-free and is required directly by the protocol test suites; only
# this glue knows about the ActiveRecord backend.
require "mail_on_rails" # the core gem: models, settings, netserv, runtime
require "socket"
require_relative "smtp/version"
require_relative "smtp/daemon"
require_relative "store/smtp_backend"

module MailOnRails
  module Smtp
    # Runtime adapter: how the core runtime starts, checks and preflights
    # SMTP. See MailOnRails::Runtime.register.
    module Protocol
      module_function

      def start(logger:, tls_dir:)
        Daemon.start(store: Store::SmtpBackend.new, logger: logger, tls_dir: tls_dir,
                     hostname: method(:hostname))
      end

      def check_config(logger:)
        Daemon.check_config(logger: logger)
      end

      # Production boot guards. Each failure mode here looks "up" from a
      # deploy's point of view, which is exactly why it must fail the boot.
      def preflight!
        require_explicit_tls!
        require_virus_scanner!
      end

      # Production must never serve mail on the self-signed development
      # fallback: clients would either refuse the cert or train users to
      # click through warnings. The TLS module fails closed on its own once
      # these are set; a missing pair here fails the boot instead of
      # quietly generating a self-signed cert.
      def require_explicit_tls!
        return if Settings.static(:smtp_tls_cert) || Settings.static(:smtp_tls_key)

        raise "production requires explicit TLS material for the SMTP server " \
              "(self-signed fallback is development-only): set SMTP_TLS_CERT/SMTP_TLS_KEY"
      end

      # The schema default for SMTP_CLAMAV_ADDR is empty - right for
      # development, but in production it means a deploy that forgets one
      # env accepts and stores mail with no virus verdict, and nothing
      # visible breaks. Running unscanned must be a decision
      # (SMTP_CLAMAV_OPTIONAL=1), never a side effect of a missing env.
      def require_virus_scanner!
        return unless Settings[:smtp_clamav_addr].to_s.empty?
        return if Settings.static(:smtp_clamav_optional)

        raise "production requires a virus scanner: set SMTP_CLAMAV_ADDR to a clamd address " \
              "(the Kamal template uses mail_on_rails-clamav:3310), or explicitly opt out of " \
              "scanning with SMTP_CLAMAV_OPTIONAL=1"
      end

      # The name SMTP sessions announce, resolved per connection through
      # the host-provided callable (defaults to the Setting-backed lookup
      # wired by the engine). Falls back to the env/system name - the
      # banner must still go out.
      def hostname
        resolver = MailOnRails.smtp_hostname_resolver
        value = resolver&.call.to_s.strip
        return value unless value.empty?

        Settings.static(:smtp_helo_hostname) || Socket.gethostname
      end
    end
  end

  Runtime.register(:smtp, Smtp::Protocol)
end
