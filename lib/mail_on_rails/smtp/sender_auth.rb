# frozen_string_literal: true

require_relative "sender_auth/dns"
require_relative "sender_auth/from_header"
require_relative "sender_auth/spf"
require_relative "sender_auth/dkim"
require_relative "sender_auth/dmarc"

module MailOnRails
  module Smtp
    # Sender verification for unauthenticated inbound (MX) mail: SPF, DKIM
    # and DMARC, hand-rolled on plain DNS + OpenSSL. The SMTP server runs
    # this after DATA; the outcome is recorded on the stored message (and
    # can reject outright when DMARC enforcement is enabled).
    module SenderAuth
      Result = Struct.new(:spf, :dkim, :dmarc, keyword_init: true) do
        # Compact Authentication-Results-style value, e.g.
        #   "spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
        # This exact string is stamped on the message and parsed by the UI.
        def summary
          parts = [ "spf=#{spf[:result]}" ]
          parts.last << " smtp.mailfrom=#{spf[:domain]}" unless spf[:domain].to_s.empty?

          passing = dkim.select { |s| s[:result] == :pass }
          parts << "dkim=#{overall_dkim}"
          parts.last << " header.d=#{passing.map { |s| s[:domain] }.uniq.join(",")}" if passing.any?

          parts << "dmarc=#{dmarc[:result]}"
          parts.last << " header.from=#{dmarc[:from_domain]}" unless dmarc[:from_domain].to_s.empty?
          parts.join("; ")
        end

        # The domain owner published p=reject and nothing aligned.
        def dmarc_reject?
          dmarc[:result] == :fail && dmarc[:policy] == :reject
        end

        def from_domain
          dmarc[:from_domain]
        end

        def overall_dkim
          results = dkim.map { |s| s[:result] }
          if results.include?(:pass) then :pass
          elsif results.empty? then :none
          elsif results.include?(:fail) then :fail
          elsif results.include?(:temperror) then :temperror
          else :permerror
          end
        end
      end

      # Reject at SMTP time on DMARC p=reject failures? Off by default:
      # verdicts are recorded either way, and flipping this on should wait
      # until the verifiers have proven themselves against real traffic.
      def self.enforce_dmarc?
        ENV["MAIL_ON_RAILS_DMARC_ENFORCE"] == "1"
      end

      def self.verify(ip:, helo:, mail_from:, data:, resolver: Dns.shared)
        spf = Spf.new(resolver).check(ip: ip, sender: mail_from, helo: helo)
        dkim = Dkim.new(resolver).verify(data)
        dmarc = Dmarc.new(resolver).evaluate(from_domain: from_domain(data), spf: spf, dkim: dkim)
        Result.new(spf: spf, dkim: dkim, dmarc: dmarc)
      end

      # The visible From: header domain - DMARC's subject. Nil when absent,
      # unparseable, or not exactly one address (DMARC has no defined
      # verdict there, and nil makes evaluate return permerror).
      def self.from_domain(data)
        FromHeader.domain(data)
      rescue StandardError
        nil
      end
    end
  end
end
