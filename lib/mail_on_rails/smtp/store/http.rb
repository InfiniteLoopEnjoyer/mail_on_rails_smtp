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
      #
      # Retry policy: deliberately NONE here. This daemon holds no queue and
      # never retries a failed HTTP call - the sending MTA's queue is the
      # retry mechanism, driven by our 4xx replies. Adding daemon-side
      # retries would only delay that signal and double-submit on ambiguous
      # failures.
      #
      # Delivery semantics are at-least-once with two known duplicate
      # windows: (a) a crash after the ingress accepted but before our 250
      # reaches the sender, and (b) mixed local+remote recipients where
      # outbound queueing succeeds and the ingress then fails - the 451
      # makes the sender retry the whole message, so the outbound copies are
      # queued again on every retry until the ingress recovers (pinned in
      # http_store_test.rb; dedupe belongs app-side where the queue lives).
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

        def smtp_store(mail_from, rcpt_to, data, authenticated_as, auth_results: nil, scan_status: nil)
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
                                      authenticated_as: authenticated_as, auth_results: auth_results,
                                      scan_status: scan_status)
              next { error: "inbound ingress refused the message", code: :internal } unless @ingress.deliver(source)

              inbound_id = Digest::SHA256.hexdigest(source)[0, 12]
            end

            { id: inbound_id || "outbound", outbound: remote.size }
          end
        end

        # Best-effort delivery of an infected/unscanned copy to the app for
        # quarantine review, after the SMTP reply (550/451) has already been
        # decided by the scan verdict. Targets the local recipients; for an
        # authenticated remote-only submission, falls back to the sender's
        # own account. Never raises and returns nothing meaningful - a lost
        # review copy is logged, not turned into a different SMTP answer
        # (downgrading a 550 to 451 would make infected senders retry
        # forever; the app-side mailroom dedups retry copies by Message-ID).
        def quarantine(mail_from, rcpt_to, data, authenticated_as, auth_results:, scan_status:, virus: nil)
          local = @api.local_rcpts(Array(rcpt_to))
          targets = local.any? ? local : [ authenticated_as ].compact
          return log(:warn, "quarantine copy dropped: no local target (#{scan_status})") if targets.empty?

          source = @ingress.stamp(data, mail_from: mail_from, rcpt_to: targets,
                                  authenticated_as: authenticated_as, auth_results: auth_results,
                                  scan_status: scan_status, virus: virus)
          log(:error, "quarantine copy refused by ingress (#{scan_status})") unless @ingress.deliver(source)
          nil
        rescue StandardError => e
          log(:error, "quarantine copy failed: #{e.class}: #{e.message}")
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
