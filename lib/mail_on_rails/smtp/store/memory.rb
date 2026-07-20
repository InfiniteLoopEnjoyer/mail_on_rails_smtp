# frozen_string_literal: true

require "monitor"

module MailOnRails
  module Smtp
    module Store
      # In-memory reference implementation of the SMTP side of the store
      # contract (docs/store_contract.md in the main mail_on_rails app repo),
      # with no Rails or database dependency. It exists so protocol behavior
      # can be tested without an app or a database, and it doubles as the
      # executable answer to "what must a store do". Not for production:
      # everything lives (unencrypted, unbounded) in one process's memory.
      #
      # Beyond the contract it exposes test seams: +add_account+ to provision
      # credentials, and +inbound_messages+ / +outbound_messages+ to inspect
      # the spool (the SMTP interface deliberately has no read side).
      class Memory
        attr_reader :inbound_messages, :outbound_messages

        def initialize(spool_limit: 10_000, outbound_limit: 1_000, logger: nil)
          @spool_limit = spool_limit
          @outbound_limit = outbound_limit
          @logger = logger
          @accounts = {} # id => { id:, email:, password: }
          @counters = Hash.new(0)
          @inbound_messages = []
          @outbound_messages = []
          @lock = Monitor.new
        end

        # -- test seams (not part of the contract) -----------------------------

        def add_account(email:, password:)
          @lock.synchronize do
            account = { id: next_id(:account), email: normalize(email), password: password.to_s }
            @accounts[account[:id]] = account
            account[:id]
          end
        end

        # -- shared interface ---------------------------------------------------

        def log(level, message)
          @logger&.public_send(level, "[mail_on_rails] #{message}")
          nil
        end

        def authenticate(email, password)
          @lock.synchronize do
            account = @accounts.values.find { |a| a[:email] == normalize(email) }
            account = nil unless account && !password.to_s.empty? && account[:password] == password.to_s
            { account_id: account&.dig(:id), email: account&.dig(:email) }
          end
        end

        # -- SMTP interface -----------------------------------------------------

        def local_rcpts(addresses)
          @lock.synchronize do
            normalized = Array(addresses).map { |a| normalize(a) }.uniq
            known = @accounts.values.map { |a| a[:email] }
            { local: normalized & known }
          end
        end

        def smtp_store(mail_from, rcpt_to, data, authenticated_as, auth_results: nil)
          @lock.synchronize do
            addresses = Array(rcpt_to)
            known = @accounts.values.map { |a| a[:email] }
            local, remote = addresses.partition { |a| known.include?(normalize(a)) }

            return { error: "relay denied", code: :relay_denied } if remote.any? && !authenticated_as

            if (local.any? && @inbound_messages.size >= @spool_limit) ||
               (remote.any? && @outbound_messages.size + remote.size > @outbound_limit)
              return { error: "spool full", code: :insufficient_storage }
            end

            inbound_id = nil
            if local.any?
              inbound_id = next_id(:inbound)
              @inbound_messages << {
                id: inbound_id, mail_from: mail_from, rcpt_to: local, data: data,
                authenticated_as: authenticated_as, auth_results: auth_results
              }
            end
            remote.each do |recipient|
              @outbound_messages << {
                id: next_id(:outbound), mail_from: authenticated_as, recipient: recipient.strip, data: data
              }
            end
            { id: inbound_id || "outbound", outbound: remote.size }
          end
        end

        private

        def normalize(email)
          email.to_s.strip.downcase
        end

        def next_id(kind)
          @counters[kind] += 1
        end
      end
    end
  end
end
