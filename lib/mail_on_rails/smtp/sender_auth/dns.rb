# frozen_string_literal: true

require "resolv"
require "ipaddr"

module MailOnRails
  module Smtp
    module SenderAuth
      # Minimal DNS client for sender verification (SPF/DKIM/DMARC) lookups.
      # Every method returns an array of strings; a name with no matching
      # records is an empty array.
      #
      # Verifiers accept anything with this five-method interface, so tests
      # inject a hash-backed fake and never touch the network.
      #
      # Limitation: Resolv cannot distinguish NXDOMAIN from SERVFAIL or a
      # timeout (all surface identically), so transient failures look like
      # "no record". That fails open - a DNS outage weakens a verdict to
      # none instead of temperror - which is the safe direction while
      # results are recorded rather than enforced. TempError stays in the
      # interface for resolvers (and fakes) that can tell the difference.
      class Dns
        class TempError < StandardError; end

        TIMEOUT = Integer(ENV.fetch("MAIL_ON_RAILS_DNS_TIMEOUT", 5))

        def initialize
          @dns = Resolv::DNS.new
          @dns.timeouts = TIMEOUT
        end

        # TXT: each record's character-strings joined, one string per record.
        def txt(name)
          resources(name, Resolv::DNS::Resource::IN::TXT).map { |r| r.strings.join }
        end

        def a(name)
          resources(name, Resolv::DNS::Resource::IN::A).map { |r| r.address.to_s }
        end

        def aaaa(name)
          resources(name, Resolv::DNS::Resource::IN::AAAA).map { |r| r.address.to_s }
        end

        # Hostnames sorted by preference.
        def mx(name)
          resources(name, Resolv::DNS::Resource::IN::MX)
            .sort_by(&:preference).map { |r| r.exchange.to_s }
        end

        def ptr(ip)
          reverse = IPAddr.new(ip.to_s).reverse
          resources(reverse, Resolv::DNS::Resource::IN::PTR).map { |r| r.name.to_s }
        rescue IPAddr::InvalidAddressError
          []
        end

        private

        def resources(name, type)
          @dns.getresources(name.to_s, type)
        rescue Resolv::ResolvError, Resolv::ResolvTimeout
          raise TempError, "DNS lookup failed for #{name}"
        end
      end
    end
  end
end
