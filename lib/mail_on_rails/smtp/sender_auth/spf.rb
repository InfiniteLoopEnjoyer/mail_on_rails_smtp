# frozen_string_literal: true

require "ipaddr"
require_relative "dns"

module MailOnRails
  module Smtp
    module SenderAuth
      # SPF evaluator (RFC 7208): answers "was this client IP authorized to
      # use this MAIL FROM domain?" by walking the domain's published SPF
      # record. Results follow the RFC vocabulary:
      #
      #   :pass :fail :softfail :neutral - the record's verdict for this IP
      #   :none      - no (usable) SPF record published
      #   :permerror - record is malformed or exceeds processing limits
      #   :temperror - DNS lookup failed transiently
      class Spf
        MAX_DNS_MECHANISMS = 10 # RFC 7208 4.6.4: include/a/mx/ptr/exists/redirect
        MAX_VOID_LOOKUPS = 2
        MAX_PTR_NAMES = 10
        MAX_MX_NAMES = 10

        class PermError < StandardError; end
        class TempError < StandardError; end

        def initialize(resolver)
          @resolver = resolver
        end

        # sender is the (possibly empty) MAIL FROM address; helo is the
        # HELO/EHLO name used as fallback identity for bounces, per RFC 7208
        # 2.4. Returns { result:, domain: }.
        def check(ip:, sender:, helo:)
          sender = sender.to_s.strip
          sender = "postmaster@#{helo}" unless sender.include?("@")
          domain = sender.split("@").last.to_s.downcase

          # Not a resolvable FQDN -> no SPF to check.
          return { result: :none, domain: domain } unless domain.match?(/\A[a-z0-9.-]+\.[a-z0-9-]+\z/)

          @ip = IPAddr.new(ip.to_s)
          @sender = sender
          @helo = helo.to_s
          @lookups = 0
          @void_lookups = 0

          { result: check_host(domain), domain: domain }
        rescue PermError
          { result: :permerror, domain: domain }
        rescue TempError, Dns::TempError
          { result: :temperror, domain: domain }
        rescue IPAddr::InvalidAddressError
          { result: :none, domain: domain }
        end

        private

        def check_host(domain, depth = 0)
          raise PermError, "include/redirect nesting too deep" if depth > 10

          record = spf_record(domain)
          return :none unless record

          terms = record.split(/ +/).drop(1).reject(&:empty?)
          mechanisms, modifiers = partition_terms(terms)

          mechanisms.each do |qualifier, name, value|
            if match_mechanism?(name, value, domain, depth)
              return { "+" => :pass, "-" => :fail, "~" => :softfail, "?" => :neutral }.fetch(qualifier)
            end
          end

          # redirect= applies only when nothing matched and no "all" is present.
          if (redirect = modifiers["redirect"]) && mechanisms.none? { |_, name, _| name == "all" }
            count_lookup!
            result = check_host(expand(redirect, domain).downcase, depth + 1)
            raise PermError, "redirect target has no SPF record" if result == :none

            return result
          end

          :neutral
        end

        def spf_record(domain)
          records = @resolver.txt(domain).select { |t| t.match?(/\Av=spf1(\s|\z)/i) }
          raise PermError, "multiple SPF records for #{domain}" if records.size > 1

          records.first
        end

        def partition_terms(terms)
          mechanisms = []
          modifiers = {}
          terms.each do |term|
            if (m = term.match(/\A([a-z][a-z0-9_.-]*)=(.*)\z/i))
              modifiers[m[1].downcase] ||= m[2] # first occurrence wins
            elsif (m = term.match(%r{\A([+\-~?]?)([a-z0-9]+)(?::([^/\s]+))?((?:/\d+)?(?://\d+)?)\z}i))
              qualifier = m[1].empty? ? "+" : m[1]
              mechanisms << [ qualifier, m[2].downcase, [ m[3], m[4] ] ]
            else
              raise PermError, "unrecognized SPF term: #{term}"
            end
          end
          [ mechanisms, modifiers ]
        end

        def match_mechanism?(name, (value, cidrs), domain, depth)
          case name
          when "all" then true
          when "ip4", "ip6"
            spec = "#{value}#{cidrs}"
            raise PermError, "#{name} requires an address" if value.nil?

            net = IPAddr.new(spec) rescue raise(PermError, "invalid #{name}: #{spec}")
            right_family?(name, net) && net.include?(@ip)
          when "a"
            count_lookup!
            target = value ? expand(value, domain) : domain
            ip_in?(host_addresses(target), cidrs)
          when "mx"
            count_lookup!
            target = value ? expand(value, domain) : domain
            hosts = void_tracked { @resolver.mx(target) }
            raise PermError, "too many MX names for #{target}" if hosts.size > MAX_MX_NAMES

            hosts.any? { |host| ip_in?(host_addresses(host, count_void: false), cidrs) }
          when "include"
            raise PermError, "include requires a domain" unless value

            count_lookup!
            case check_host(expand(value, domain).downcase, depth + 1)
            when :pass then true
            when :fail, :softfail, :neutral then false
            when :temperror then raise TempError, "include #{value}"
            else raise PermError, "include #{value} unusable"
            end
          when "exists"
            raise PermError, "exists requires a domain" unless value

            count_lookup!
            void_tracked { @resolver.a(expand(value, domain)) }.any?
          when "ptr"
            count_lookup!
            target = (value ? expand(value, domain) : domain).downcase
            validated_ptr_names.any? { |n| n == target || n.end_with?(".#{target}") }
          else
            raise PermError, "unknown mechanism: #{name}"
          end
        end

        def right_family?(name, net)
          name == "ip4" ? net.ipv4? : net.ipv6?
        end

        # A/AAAA records for host, chosen to match the client IP family.
        def host_addresses(host, count_void: true)
          lookup = -> { @ip.ipv4? ? @resolver.a(host) : @resolver.aaaa(host) }
          count_void ? void_tracked(&lookup) : lookup.call
        end

        def ip_in?(addresses, cidrs)
          prefix = @ip.ipv4? ? cidrs[/\A\/(\d+)/, 1] : cidrs[%r{//(\d+)}, 1]
          addresses.any? do |addr|
            net = IPAddr.new(addr) rescue next
            net = net.mask(Integer(prefix)) if prefix
            net.include?(@ip)
          rescue IPAddr::Error
            raise PermError, "invalid CIDR prefix"
          end
        end

        # PTR names for the client IP that also resolve back to it (forward
        # confirmation), per RFC 7208 5.5.
        def validated_ptr_names
          @validated_ptr_names ||= void_tracked { @resolver.ptr(@ip.to_s) }
            .first(MAX_PTR_NAMES)
            .select { |name| host_addresses(name, count_void: false).any? { |a| IPAddr.new(a) == @ip rescue false } }
            .map(&:downcase)
        end

        def count_lookup!
          @lookups += 1
          raise PermError, "too many DNS-querying mechanisms" if @lookups > MAX_DNS_MECHANISMS
        end

        def void_tracked
          result = yield
          if result.empty?
            @void_lookups += 1
            raise PermError, "too many void DNS lookups" if @void_lookups > MAX_VOID_LOOKUPS
          end
          result
        end

        # RFC 7208 7: macro expansion for domain-specs. %{p} is expanded as
        # "unknown" without doing PTR lookups (permitted, and its use is
        # discouraged anyway).
        def expand(spec, domain)
          spec.gsub(/%[%_-]|%\{([a-zA-Z])(\d*)(r?)([.\-+,\/_=]*)\}/) do
            case Regexp.last_match(0)
            when "%%" then "%"
            when "%_" then " "
            when "%-" then "%20"
            else
              letter, digits, reverse, delims = Regexp.last_match.captures
              value = macro_value(letter.downcase, domain)
              parts = value.split(/[#{Regexp.escape(delims.empty? ? "." : delims)}]/)
              parts.reverse! unless reverse.empty?
              parts = parts.last(Integer(digits)) unless digits.empty?
              expanded = parts.join(".")
              letter == letter.upcase ? url_escape(expanded) : expanded
            end
          end.tap do |result|
            raise PermError, "empty domain-spec" if result.empty?
          end
        end

        def macro_value(letter, domain)
          case letter
          when "s" then @sender
          when "l" then @sender.split("@").first.to_s.then { |l| l.empty? ? "postmaster" : l }
          when "o" then @sender.split("@").last.to_s
          when "d" then domain
          when "i" then @ip.ipv4? ? @ip.to_s : @ip.to_string.delete(":").chars.join(".")
          when "p" then "unknown"
          when "v" then @ip.ipv4? ? "in-addr" : "ip6"
          when "h" then @helo
          else raise PermError, "unknown macro %{#{letter}}"
          end
        end

        def url_escape(str)
          str.gsub(/[^A-Za-z0-9\-._~]/) { |c| format("%%%02X", c.ord) }
        end
      end
    end
  end
end
