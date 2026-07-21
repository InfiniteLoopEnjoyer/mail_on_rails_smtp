# frozen_string_literal: true

require "digest"
require "logger"
require_relative "../internal_api"
require_relative "../ingress_client"

module MailOnRails
  module Smtp
    module Store
      # The SMTP server's store, implemented entirely over HTTP - the daemon
      # holds no database credentials at all. Credential checks, recipient
      # validation, and outbound queueing go to the host app's private API
      # (InternalApi); accepted inbound mail goes to Action Mailbox's relay
      # ingress (IngressClient) with trust headers stamped on.
      #
      # If the app is unreachable, every operation degrades to the store
      # contract's error envelope and the SMTP session answers a temporary
      # failure - sending servers retry, which is SMTP's own durability
      # buffer (see Store::Contracts).
      class Http
        def initialize(api: nil, ingress: nil, logger: Logger.new($stdout))
          @logger = logger
          @api = api || InternalApi.new
          @ingress = ingress || IngressClient.new(logger: logger)
        end

        # -- worker Ractor support ---------------------------------------------
        # This store is env-configured HTTP clients plus a stdout logger, so
        # each worker Ractor can simply build its own instance; #worker_config
        # advertises that to Server (its presence selects Ractor mode) and
        # .from_config performs the rebuild inside the worker.

        def worker_config
          { store_class: self.class }
        end

        def self.from_config(_config = {})
          new(logger: Logger.new($stdout, progname: "mail_on_rails_smtp"))
        end

        def log(level, message)
          @logger.public_send(level, "[mail_on_rails] #{message}")
          nil
        end

        def authenticate(email, password)
          wrap { @api.authenticate(email.to_s, password.to_s) }
        end

        # Given candidate recipient addresses, returns the subset that maps to
        # a real local account (normalized). Used to reject unknown recipients.
        def local_rcpts(addresses)
          wrap { { local: @api.local_rcpts(addresses) } }
        end

        def smtp_store(mail_from, rcpt_to, data, authenticated_as, auth_results: nil)
          wrap do
            addresses = Array(rcpt_to)
            local_set = @api.local_rcpts(addresses).to_set
            local, remote = addresses.partition { |a| local_set.include?(a.to_s.strip.downcase) }

            next { error: "relay denied", code: :relay_denied } if remote.any? && !authenticated_as

            # Queue outbound first: the app enforces its queue cap there, so a
            # full queue rejects the whole message before anything is accepted.
            if remote.any?
              @api.queue_outbound(mail_from: authenticated_as, recipients: remote.map(&:strip), data: data)
            end

            inbound_id = nil
            if local.any?
              source = @ingress.stamp(data, mail_from: mail_from, rcpt_to: local,
                                      authenticated_as: authenticated_as, auth_results: auth_results)
              next { error: "inbound ingress refused the message", code: :internal } unless @ingress.deliver(source)

              inbound_id = Digest::SHA256.hexdigest(source)[0, 12]
            end

            { id: inbound_id || "outbound", outbound: remote.size }
          end
        end

        private

        # Mirrors the app-side stores' error envelope, without the database.
        def wrap
          yield
        rescue InternalApi::Error => e
          @logger.error("[mail_on_rails] store error: #{e.message}")
          { error: e.message, code: e.code }
        rescue StandardError => e
          @logger.error("[mail_on_rails] store error: #{e.class}: #{e.message}")
          { error: "#{e.class}: #{e.message}", code: :internal }
        end
      end
    end
  end
end
