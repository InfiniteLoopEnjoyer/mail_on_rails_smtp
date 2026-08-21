# frozen_string_literal: true

require "monitor"
require "mail_on_rails/scram"

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
        attr_reader :inbound_messages, :outbound_messages, :quarantined_messages, :honeypot_events,
                    :dmarc_events

        def initialize(spool_limit: 10_000, outbound_limit: 1_000, logger: nil)
          @spool_limit = spool_limit
          @outbound_limit = outbound_limit
          @logger = logger
          @accounts = {} # id => { id:, email:, password:, honeypot: }
          @counters = Hash.new(0)
          @inbound_messages = []
          @outbound_messages = []
          @quarantined_messages = []
          @honeypot_events = []
          @dmarc_events = []
          @banned_cidrs = []
          # Keys the SCRAM decoy material; one random secret per store
          # instance is enough - determinism only has to hold within a
          # process (the app store derives its own from secret_key_base).
          @decoy_secret = OpenSSL::Random.random_bytes(32)
          @lock = Monitor.new
        end

        # -- test seams (not part of the contract) -----------------------------

        # Adds an entry to the accept-side denylist (Netserv::Denylist
        # polls banned_cidrs); empty by default, so bans are opt-in per test.
        def ban_ip(cidr)
          @lock.synchronize { @banned_cidrs << cidr }
        end

        def add_account(email:, password:, honeypot: false, aliases: [])
          @lock.synchronize do
            account = { id: next_id(:account), email: normalize(email), password: password.to_s, honeypot: honeypot,
                        aliases: Array(aliases).map { |a| normalize(a) },
                        scram: Scram.derive(password.to_s) }
            @accounts[account[:id]] = account
            account[:id]
          end
        end

        # -- shared interface ---------------------------------------------------

        def log(level, message)
          @logger&.public_send(level, "[mail_on_rails] #{message}")
          nil
        end

        def banned_cidrs
          @lock.synchronize { @banned_cidrs.dup }
        end

        def authenticate(email, password, ip: nil, source: nil)
          @lock.synchronize do
            account = @accounts.values.find { |a| a[:email] == normalize(email) }
            account = nil unless account && !password.to_s.empty? && account[:password] == password.to_s
            { account_id: account&.dig(:id), email: account&.dig(:email), honeypot: account&.dig(:honeypot) || false }
          end
        end

        # Counts a failure the daemon adjudicated itself (a bad SCRAM
        # proof). This store keeps no throttle counters (the app store
        # does), so recording is a no-op - the method exists for contract
        # parity with the session's scram_failure path.
        def record_auth_failure(email, ip: nil, source: nil)
          {}
        end

        # SCRAM-SHA-256 verifier material for AUTH (never the password
        # itself). An unknown account gets deterministic decoy material
        # instead of a miss, so the exchange can't be used as a username
        # oracle (the proof never verifies).
        def scram_credentials(email, ip: nil)
          @lock.synchronize do
            account = @accounts.values.find { |a| a[:email] == normalize(email) }
            scram = account&.dig(:scram)
            return Scram.decoy_credentials(normalize(email), @decoy_secret) unless scram

            {
              account_id: account[:id],
              email: account[:email],
              salt_base64: [ scram[:salt] ].pack("m0"),
              iterations: scram[:iterations],
              stored_key_base64: [ scram[:stored_key] ].pack("m0"),
              server_key_base64: [ scram[:server_key] ].pack("m0"),
              honeypot: account[:honeypot] || false
            }
          end
        end

        # -- honeypot interface (optional store methods) ------------------------

        def record_honeypot_event(info)
          @lock.synchronize do
            id = next_id(:honeypot)
            @honeypot_events << info.to_h.merge(id: id)
            { id: id }
          end
        end

        def update_honeypot_transcript(id, transcript:)
          @lock.synchronize do
            event = @honeypot_events.find { |e| e[:id] == id }
            event[:transcript] = transcript if event
            {}
          end
        end

        # -- SMTP interface -----------------------------------------------------

        # local: the addresses we host (accounts; the app store adds
        # aliases). unknown_in_local_domain: addresses in a domain we host
        # with no such user - the session answers those 5.1.1 instead of
        # "relaying denied". Here a hosted domain is any domain with at
        # least one account.
        def local_rcpts(addresses)
          @lock.synchronize do
            normalized = Array(addresses).map { |a| normalize(a) }.uniq
            known = @accounts.values.map { |a| a[:email] }
            domains = known.map { |e| e.split("@").last }.uniq
            local = normalized & known
            unknown = (normalized - known).select { |a| domains.include?(a.split("@").last) }
            { local: local, unknown_in_local_domain: unknown }
          end
        end

        def smtp_store(mail_from, rcpt_to, data, authenticated_as, client_ip: nil, helo: nil,
                       auth_results: nil, scan_status: nil, requiretls: false, smtputf8: false, dsn: nil)
          @lock.synchronize do
            addresses = Array(rcpt_to)
            known = @accounts.values.map { |a| a[:email] }
            canaries = @accounts.values.select { |a| a[:honeypot] }.map { |a| a[:email] }
            local, remote = addresses.partition { |a| known.include?(normalize(a)) }
            # Inbound to a canary is blackholed - 250 already sent, nothing stored.
            local -= local.select { |a| canaries.include?(normalize(a)) }

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
                authenticated_as: authenticated_as, client_ip: client_ip, helo: helo,
                auth_results: auth_results, scan_status: scan_status
              }
            end
            # The envelope sender when the login owns it (its address or an
            # alias - send-as-alias), else the authenticated identity: the
            # store never trusts its caller's envelope sender onto the wire.
            owned = [ normalize(authenticated_as) ] + sender_addresses(authenticated_as)
            outbound_sender = owned.include?(normalize(mail_from)) ? normalize(mail_from) : normalize(authenticated_as)
            remote.each do |recipient|
              rcpt_dsn = dsn&.dig(:recipients)&.find { |addr, _| normalize(addr) == normalize(recipient) }&.last
              @outbound_messages << {
                id: next_id(:outbound), mail_from: outbound_sender, recipient: recipient.strip, data: data,
                requiretls: requiretls, smtputf8: smtputf8,
                dsn_ret: dsn&.dig(:ret), dsn_envid: dsn&.dig(:envid),
                dsn_notify: rcpt_dsn&.dig(:notify), dsn_orcpt: rcpt_dsn&.dig(:orcpt)
              }
            end
            { id: inbound_id || "outbound", outbound: remote.size }
          end
        end

        # Best-effort review copy of infected/unscanned mail; the SMTP reply
        # was already decided from the scan verdict, so this records and
        # never fails the caller.
        def quarantine(mail_from, rcpt_to, data, authenticated_as, client_ip: nil, helo: nil,
                       auth_results:, scan_status:, virus: nil)
          @lock.synchronize do
            known = @accounts.values.map { |a| a[:email] }
            local = Array(rcpt_to).map { |a| normalize(a) }.uniq.select { |a| known.include?(a) }
            targets = local.any? ? local : [ authenticated_as ].compact
            if targets.empty?
              log(:warn, "quarantine copy dropped: no local target (#{scan_status})")
              return nil
            end
            @quarantined_messages << {
              id: next_id(:quarantine), mail_from: mail_from, rcpt_to: targets, data: data,
              authenticated_as: authenticated_as, client_ip: client_ip, helo: helo,
              auth_results: auth_results, scan_status: scan_status, virus: virus
            }
            nil
          end
        end

        # The addresses an authenticated account may claim as sender: its
        # own plus its aliases (the MSA authorization set - see the
        # session's permitted_senders).
        def sender_addresses(email)
          @lock.synchronize do
            account = @accounts.values.find { |a| a[:email] == normalize(email) }
            account ? [ account[:email] ] + Array(account[:aliases]) : []
          end
        end

        # One RFC 7489 aggregate-report row, recorded by the session for
        # every evaluated message whose From domain publishes a DMARC
        # record. Best-effort telemetry: records what it can, never fails
        # the caller, always answers nil.
        def dmarc_event(**fields)
          @lock.synchronize { @dmarc_events << fields }
          nil
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
