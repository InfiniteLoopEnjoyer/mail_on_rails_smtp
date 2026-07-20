# frozen_string_literal: true

require_relative "dns"

module MailOnRails
  module Smtp
    module SenderAuth
      # DMARC evaluator (RFC 7489): the check that actually protects the
      # human reading the mail. SPF and DKIM validate domains the user never
      # sees; DMARC requires one of them to *align* with the visible From:
      # header domain, and reports the policy the domain owner asked us to
      # apply when nothing aligns.
      #
      # Returns { result:, policy:, domain:, from_domain: } where result is
      # :pass / :fail / :none (no record) / :permerror / :temperror and
      # policy is the effective disposition on failure (:none / :quarantine
      # / :reject).
      class Dmarc
        def initialize(resolver)
          @resolver = resolver
        end

        # spf: { result:, domain: } from Spf#check.
        # dkim: array of { result:, domain: } from Dkim#verify.
        def evaluate(from_domain:, spf:, dkim:)
          from_domain = from_domain.to_s.downcase
          if from_domain.empty?
            # No single From: domain (missing, multiple, or unparseable) -
            # nothing to align against.
            return { result: :permerror, policy: :none, domain: nil, from_domain: nil }
          end

          record, record_domain = find_record(from_domain)
          return { result: :none, policy: :none, domain: nil, from_domain: from_domain } unless record

          tags = parse_tags(record)
          unless %w[none quarantine reject].include?(tags["p"])
            return { result: :permerror, policy: :none, domain: record_domain, from_domain: from_domain }
          end

          aligned =
            dkim_aligned?(from_domain, dkim, tags.fetch("adkim", "r")) ||
            spf_aligned?(from_domain, spf, tags.fetch("aspf", "r"))

          {
            result: aligned ? :pass : :fail,
            policy: aligned ? :none : effective_policy(tags, from_domain, record_domain),
            domain: record_domain,
            from_domain: from_domain
          }
        rescue Dns::TempError
          { result: :temperror, policy: :none, domain: nil, from_domain: from_domain }
        end

        # The registrable ("organizational") domain. Uses a pragmatic subset
        # of the Public Suffix List: common two-label suffixes plus the
        # default of "last two labels". Wrong for exotic suffixes, but those
        # only loosen relaxed alignment for domains we are unlikely to see.
        MULTI_LABEL_SUFFIXES = %w[
          co.uk org.uk gov.uk ac.uk me.uk net.uk sch.uk
          co.jp or.jp ne.jp ac.jp go.jp
          com.au net.au org.au edu.au gov.au id.au
          com.br net.br org.br gov.br
          co.nz net.nz org.nz govt.nz ac.nz
          co.in net.in org.in co.za org.za net.za gov.za
          com.mx org.mx net.mx gob.mx edu.mx
          com.cn net.cn org.cn gov.cn edu.cn
          com.tw org.tw net.tw edu.tw com.hk org.hk net.hk edu.hk
          co.kr or.kr ne.kr go.kr com.sg org.sg edu.sg gov.sg
          com.my org.my gov.my com.ar org.ar gob.ar com.tr org.tr gov.tr edu.tr
          com.co org.co com.ph org.ph com.pl org.pl com.ua org.ua gov.ua
          co.il org.il ac.il gov.il co.th or.th ac.th go.th
          com.vn org.vn gov.vn com.sa org.sa com.pk org.pk
          co.id or.id ac.id go.id com.ng gov.ng co.ke or.ke go.ke ac.ke
        ].to_set.freeze

        def self.org_domain(domain)
          labels = domain.to_s.downcase.split(".")
          keep = MULTI_LABEL_SUFFIXES.include?(labels.last(2).join(".")) ? 3 : 2
          labels.last(keep).join(".")
        end

        private

        def find_record(from_domain)
          record = dmarc_txt(from_domain)
          return [ record, from_domain ] if record

          org = self.class.org_domain(from_domain)
          if org != from_domain && (record = dmarc_txt(org))
            return [ record, org ]
          end
          nil
        end

        def dmarc_txt(domain)
          records = @resolver.txt("_dmarc.#{domain}").select { |t| t.match?(/\Av=DMARC1(\s*;|\s*\z)/i) }
          records.size == 1 ? records.first : nil # RFC 7489 6.6.3: 0 or >1 -> no record
        end

        def parse_tags(record)
          record.split(";").each_with_object({}) do |pair, tags|
            name, value = pair.split("=", 2)
            tags[name.strip.downcase] = value.to_s.strip.downcase if value
          end
        end

        def dkim_aligned?(from_domain, dkim, mode)
          Array(dkim).any? do |sig|
            sig[:result] == :pass && aligned?(from_domain, sig[:domain], mode)
          end
        end

        def spf_aligned?(from_domain, spf, mode)
          spf && spf[:result] == :pass && aligned?(from_domain, spf[:domain], mode)
        end

        def aligned?(from_domain, other, mode)
          return false if other.to_s.empty?

          if mode == "s"
            from_domain.casecmp?(other)
          else
            self.class.org_domain(from_domain) == self.class.org_domain(other)
          end
        end

        # p= applies to the From: domain itself; sp= (when present on an org
        # domain record) governs subdomains. pct= samples enforcement, with
        # the RFC's downgrade for messages outside the sample.
        def effective_policy(tags, from_domain, record_domain)
          policy = tags["p"]
          if from_domain != record_domain && %w[none quarantine reject].include?(tags["sp"])
            policy = tags["sp"]
          end

          pct = Integer(tags.fetch("pct", "100"), exception: false)
          if pct && pct < 100 && rand(100) >= pct
            policy = { "reject" => "quarantine", "quarantine" => "none" }.fetch(policy, "none")
          end
          policy.to_sym
        end
      end
    end
  end
end
