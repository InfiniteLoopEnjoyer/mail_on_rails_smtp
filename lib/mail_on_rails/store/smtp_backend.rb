# frozen_string_literal: true

require "mail_on_rails/store"
require "mail_on_rails/ingress_seal"
require "mail_on_rails/idn"

module MailOnRails
  module Store
    # The Active Record implementation of the SMTP store contract
    # (lib/mail_on_rails/smtp/store/contracts.rb), used by the in-process
    # SMTP server. Three responsibilities:
    #
    #   - authenticate: shared plumbing from Store::Base, defaulting
    #     source: "smtp" so AUTH attempts land in AuthAttempt and the
    #     shared AuthThrottle budget.
    #   - local_rcpts: RCPT-time recipient verification straight from the
    #     EmailAccount/EmailAlias/Domain tables (what the retired edge
    #     answered from the app-written local_recipients/local_domains
    #     files).
    #   - smtp_store/quarantine: accepted mail. Authenticated submission to
    #     remote recipients rows into SmtpOutboundMessage (drained by
    #     DeliverSmtpOutboundJob); local inbound becomes an
    #     ActionMailbox::InboundEmail routed to MailroomMailbox, with the
    #     connection facts the mailroom trusts stamped as headers first and
    #     an HMAC seal (IngressSeal) proving they came from this edge.
    #     Infected/unscanned mail is filed into Quarantine mailboxes
    #     directly at the model layer.
    #
    # The mailroom's trust boundary is unchanged: it believes the
    # connection-fact headers (Return-Path / X-Original-To /
    # X-MailOnRails-Authenticated / -Client-Ip / -Helo) because the edge -
    # now this process - stripped any wire copies before stamping its own,
    # and it recomputes every *verdict* (rspamd, clamav) itself. The SMTP
    # server's own SPF/DKIM/DMARC results stay a connection-time gate and
    # are deliberately not forwarded as headers.
    class SmtpBackend < Base
      # Headers a remote sender must not be able to forge: stripped from
      # the submitted DATA before we stamp authoritative values from the
      # SMTP session.
      TRUSTED_HEADERS = /\A(X-Original-To|X-MailOnRails-[\w-]+|Return-Path):/i

      def authenticate(email, password, ip: nil, source: "smtp")
        super
      end

      def record_auth_failure(email, ip: nil, source: "smtp")
        super
      end

      # The addresses an authenticated account may claim as sender: its
      # own plus its aliases (RFC 6409 MSA authorization - the session's
      # permitted_senders). [] for an unknown account; the session then
      # falls back to exact-account matching.
      def sender_addresses(email)
        result = db do
          account = EmailAccount.find_by(email: email.to_s.strip.downcase)
          account ? [ account.email ] + account.email_aliases.pluck(:email) : []
        end
        result.is_a?(Array) ? result : []
      end

      # local: hosted addresses (accounts and aliases), normalized.
      # unknown_in_local_domain: no such user, but the domain is one we
      # host - the session answers 5.1.1 instead of "relaying denied".
      def local_rcpts(addresses)
        db do
          normalized = Array(addresses).map { |a| normalize_address(a) }.reject(&:empty?).uniq
          local = normalized.select { |a| hosted_address?(a) }
          unknown = (normalized - local).select do |address|
            (domain = address.split("@").last) && hosted_domain?(domain)
          end
          { local: local, unknown_in_local_domain: unknown }
        end
      end

      def smtp_store(mail_from, rcpt_to, data, authenticated_as, client_ip: nil, helo: nil,
                     auth_results: nil, scan_status: nil, requiretls: false, smtputf8: false, dsn: nil)
        db do
          local, remote = partition_recipients(rcpt_to)
          # Inbound mail to a canary address is blackholed: the RCPT already
          # answered 250 (deception intact), but nothing is stored as real mail
          # for a decoy account. Authenticated canary submission is blackholed
          # earlier, in the session (@honeypot); this covers unauthenticated MX
          # delivery, which never sets that flag.
          local = drop_canary_recipients(local)
          next { error: "relay denied", code: :relay_denied } if remote.any? && !authenticated_as

          if remote.any? && SmtpOutboundMessage.pending.count + remote.size > outbound_limit
            next { error: "outbound queue full", code: :insufficient_storage }
          end

          inbound_id = nil
          if local.any?
            stamped = stamp(data, mail_from: mail_from, rcpt_to: local,
                            authenticated_as: authenticated_as, client_ip: client_ip, helo: helo)
            inbound_id = ActionMailbox::InboundEmail.create_and_extract_message_id!(stamped).id
          end
          # Per-recipient DSN requests arrive keyed by the address as the
          # client wrote it; the queue rows carry normalized addresses.
          rcpt_dsn = (dsn&.dig(:recipients) || {}).transform_keys { |a| a.to_s.strip.downcase }
          outbound_sender = outbound_mail_from(mail_from, authenticated_as)
          SmtpOutboundMessage.transaction do
            remote.each do |recipient|
              SmtpOutboundMessage.create!(mail_from: outbound_sender, recipient: recipient,
                                          data: data, next_attempt_at: Time.current,
                                          requiretls: requiretls, smtputf8: smtputf8,
                                          dsn_ret: dsn&.dig(:ret), dsn_envid: dsn&.dig(:envid),
                                          dsn_notify: rcpt_dsn.dig(recipient, :notify),
                                          dsn_orcpt: rcpt_dsn.dig(recipient, :orcpt))
            end
          end
          { id: inbound_id || "outbound", outbound: remote.size }
        end
      end

      # Best-effort review copy of infected/unscanned mail, filed straight
      # into the Quarantine mailbox of every local recipient account (or
      # the submitter's own on an authenticated remote-only submission).
      # Deduped by Message-ID like MailroomMailbox#quarantine - a sending
      # MTA retries a 451 with the same message for days. The SMTP reply
      # was already decided from the scan verdict, so this records and
      # never fails the caller.
      def quarantine(mail_from, rcpt_to, data, authenticated_as, client_ip: nil, helo: nil,
                     auth_results:, scan_status:, virus: nil)
        result = db do
          local, = partition_recipients(rcpt_to)
          accounts = local.filter_map { |address| resolve_account(address) }.uniq
          if accounts.empty? && authenticated_as
            accounts = [ resolve_account(authenticated_as.to_s.strip.downcase) ].compact
          end
          if accounts.empty?
            log(:warn, "quarantine copy dropped: no local target (#{scan_status})")
            next nil
          end

          stamped = stamp(data, mail_from: mail_from, rcpt_to: local,
                          authenticated_as: authenticated_as, client_ip: client_ip, helo: helo)
          # Angle brackets stripped to match what deliver_raw stores
          # (Mail#message_id is bracketless).
          mid = stamped[/^Message-ID:[ \t]*<([^>]*)>/i, 1].to_s.presence
          accounts.each do |account|
            mailbox = account.quarantine_mailbox
            if mid && mailbox.email_messages.exists?(message_id: mid)
              log(:info, "skipped duplicate quarantine copy for #{account.email} (#{mid})")
              next
            end

            EmailMessage.deliver_raw(mailbox, stamped,
                                     authenticated_as: authenticated_as.to_s.strip.presence,
                                     auth_results: auth_results, scan_status: scan_status, virus_name: virus)
            log(:warn, "quarantined #{scan_status} message for #{account.email}#{" (#{virus})" if virus}")
          end
          nil
        end
        # db turns store errors into an error hash; quarantine's contract
        # is "record if you can, never fail the caller" - flatten to nil.
        result.is_a?(Hash) && result[:error] ? nil : result
      end

      # One RFC 7489 aggregate-report row (rolled up daily by
      # SendDmarcReportsJob). Telemetry riding the acceptance path -
      # records what it can, never fails the caller.
      def dmarc_event(**fields)
        db { DmarcAggregateEvent.record!(**fields) }
        nil
      end

      private

      def hosted_address?(address)
        EmailAccount.exists?(email: address) || EmailAlias.exists?(email: address) || verp_address?(address)
      end

      # A signed VERP sub-address (bounce+m<id>-<mac>@<domain>) counts as
      # local when the domain has its bounce account - asynchronous
      # bounces to return paths we minted must be accepted at RCPT. The
      # MAC check is pure crypto (no extra query), so junk sprayed at
      # bounce+garbage never even reads as a local recipient.
      def verp_address?(address)
        local, _, domain = address.partition("@")
        local.start_with?("#{Domain::BOUNCE_LOCAL_PART}+") &&
          VerpAddress.valid?(address) &&
          EmailAccount.exists?(email: "#{Domain::BOUNCE_LOCAL_PART}@#{domain}")
      end

      # A domain counts as ours when it has a Domain row (the managed set)
      # or when any account/alias lives under it - so "no such user here"
      # stays accurate even for a domain that predates its Domain row.
      def hosted_domain?(domain)
        # matches() is case-insensitive on every adapter (ILIKE on
        # PostgreSQL, CI collation/ASCII-CI LIKE elsewhere) - what
        # hostnames need. "!" as the explicit LIKE escape: SQLite has no
        # default escape character and MySQL double-processes backslashes.
        pattern = "%@#{ActiveRecord::Base.sanitize_sql_like(domain, "!")}"
        Domain.exists?(name: domain) ||
          EmailAccount.where(EmailAccount.arel_table[:email].matches(pattern, "!")).exists? ||
          EmailAlias.where(EmailAlias.arel_table[:email].matches(pattern, "!")).exists?
      end

      def resolve_account(address)
        EmailAccount.find_by(email: address) || EmailAlias.find_by(email: address)&.email_account
      end

      # The Return-Path queued outbound rows carry: the envelope sender
      # when it is an identity the authenticated account owns (its own
      # address or one of its aliases - send-as-alias), else the
      # authenticated identity itself. The session enforces the same rule
      # with a 550, but the store must not rely on its caller: a spoofed
      # envelope sender degrades to the login, never onto the wire.
      def outbound_mail_from(mail_from, authenticated_as)
        account_email = authenticated_as.to_s.strip.downcase
        candidate = normalize_address(mail_from)
        return candidate if candidate == account_email

        account = EmailAccount.find_by(email: account_email)
        account&.email_aliases&.exists?(email: candidate) ? candidate : account_email
      end

      # Drops any local recipient (account or alias) that resolves to a
      # honeypot account, so decoy addresses never accumulate real inbound.
      # Short-circuits on the common case (no canaries configured) so the
      # per-recipient resolve never runs on the hot inbound path unless a
      # canary actually exists.
      def drop_canary_recipients(local)
        return local if local.empty? || !EmailAccount.honeypots.exists?

        local.reject { |address| resolve_account(address)&.honeypot? }
      end

      def partition_recipients(rcpt_to)
        Array(rcpt_to).map { |a| normalize_address(a) }.reject(&:empty?).uniq
                      .partition { |a| hosted_address?(a) }
      end

      # Addresses come in as the client wrote them; hosted domains are
      # stored as A-labels (Domain's HOSTNAME validation requires
      # punycode), so an SMTPUTF8 U-label domain is punycoded before
      # matching - and before it lands on outbound queue rows, whose DNS
      # lookups want A-labels anyway. UTF-8 local parts pass through:
      # accounts are ASCII, so those route to the unknown/relay checks.
      def normalize_address(address)
        address = address.to_s.strip.downcase
        local, at, domain = address.rpartition("@")
        return address if at.empty? || domain.ascii_only?

        "#{local}@#{MailOnRails::Idn.to_ascii(domain)}"
      end

      # Bounds the outbound queue (authenticated senders only, but still).
      def outbound_limit
        Settings[:outbound_limit]
      end

      # The message source with the authoritative trust/routing headers
      # prepended (forged copies stripped): envelope recipients become
      # X-Original-To so mailroom routing sees BCC'd and aliased
      # recipients, Return-Path records the envelope sender,
      # X-MailOnRails-Authenticated whether the sender authenticated (and
      # as whom), and X-MailOnRails-Client-Ip/-Helo the connection facts
      # the mailroom feeds to rspamd.
      def stamp(data, mail_from:, rcpt_to:, authenticated_as:, client_ip:, helo:)
        authenticated = authenticated_as.to_s.strip
        stamped = [ "Return-Path: <#{sanitize_header(mail_from)}>\r\n" ]
        stamped += Array(rcpt_to).map { |rcpt| "X-Original-To: #{sanitize_header(rcpt)}\r\n" }
        stamped << "X-MailOnRails-Authenticated: #{authenticated.empty? ? "no" : sanitize_header(authenticated)}\r\n"
        stamped << "X-MailOnRails-Client-Ip: #{sanitize_header(client_ip)}\r\n" unless client_ip.to_s.strip.empty?
        stamped << "X-MailOnRails-Helo: #{sanitize_header(helo)}\r\n" unless helo.to_s.strip.empty?
        body = stamped.join + strip_trusted_headers(data)
        # Seal the stamped message so the mailroom can prove these headers
        # came from this edge and not from some other ingress route.
        IngressSeal.seal(body) + body
      end

      # Drops CR/LF so an envelope value can't inject extra header lines.
      def sanitize_header(value)
        value.to_s.gsub(/[\r\n]/, " ")
      end

      def strip_trusted_headers(raw)
        header_block, separator, body = raw.to_s.partition(/\r?\n\r?\n/)
        kept = header_block.split(/\r?\n(?![ \t])/).reject { |line| line.match?(TRUSTED_HEADERS) }
        kept.join("\r\n") + separator + body
      end
    end
  end
end
