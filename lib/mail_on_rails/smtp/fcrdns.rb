# frozen_string_literal: true

require "ipaddr"
require "mail_on_rails/settings"
require "mail_on_rails/sender_auth/dns"

module MailOnRails
  module Smtp
    # Forward-confirmed reverse DNS (FCrDNS) facts for a connecting client:
    # the peer IP's PTR name (confirmed by resolving it back to the same
    # IP) and whether the HELO name resolves to the peer. Spam filters
    # score hard on these, so we record them - the confirmed name lands in
    # the Received header, mismatches in the log - but they are advisory
    # only and never refuse mail by themselves (plenty of legitimate small
    # senders fail one or the other).
    #
    # Shaped like Dnsbl: one process-wide instance (see .shared), verdicts
    # cached per [ip, helo] so a busy peer costs one DNS walk per TTL, and
    # every DNS failure reads as "unknown", never as a verdict.
    class FcrDns
      CACHE_TTL = 600
      SWEEP_THRESHOLD = 10_000
      MAX_PTR_NAMES = 10 # bound the forward-confirmation walk

      # ptr_name: the forward-confirmed PTR name (nil: no PTR, or none
      # confirmed). fcrdns: whether any PTR name resolved back to the IP.
      # helo_matches: whether the HELO name resolves to the peer IP - nil
      # when unknowable (address-literal HELO, or DNS failure).
      Result = Struct.new(:ptr_name, :fcrdns, :helo_matches, keyword_init: true)

      SHARED_LOCK = Mutex.new
      def self.shared
        SHARED_LOCK.synchronize { @shared ||= new }
      end

      def initialize(resolver: SenderAuth::Dns.shared, ttl: CACHE_TTL,
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @resolver = resolver
        @ttl = ttl
        @clock = clock
        @cache = {} # [ip, helo] => [Result, expires_at]
        @cache_lock = Mutex.new
      end

      # The Result for this peer, or nil for peers that cannot have public
      # DNS (loopback/private/link-local, unparseable address). Cache
      # access is locked, the DNS walk runs outside the lock (a cache-miss
      # race costs a duplicate walk, never a wrong answer).
      def check(ip, helo: nil)
        addr = public_address(ip)
        return nil unless addr

        key = [ ip.to_s, helo.to_s ]
        cached = :miss
        @cache_lock.synchronize do
          result, expires_at = @cache[key]
          cached = result if expires_at && expires_at > @clock.call
        end
        return cached unless cached == :miss

        result = resolve(addr, ip.to_s, helo.to_s)
        @cache_lock.synchronize do
          now = @clock.call
          sweep(now) if @cache.size >= SWEEP_THRESHOLD
          @cache[key] = [ result, now + @ttl ]
        end
        result
      end

      private

      def resolve(addr, ip, helo)
        confirmed = nil
        names = ptr_names(ip)
        names.first(MAX_PTR_NAMES).each do |name|
          if forward_includes?(name, addr)
            confirmed = name.downcase
            break
          end
        end
        Result.new(ptr_name: confirmed, fcrdns: !confirmed.nil?, helo_matches: helo_matches(helo, addr))
      end

      def ptr_names(ip)
        @resolver.ptr(ip)
      rescue SenderAuth::Dns::TempError
        []
      end

      # nil (not false) when the HELO is an address literal or unresolvable:
      # "no DNS answer" must not read as a lie.
      def helo_matches(helo, addr)
        return nil if helo.empty? || helo.start_with?("[") || helo.match?(/\A[\d.:]+\z/)

        addresses = forward_addresses(helo)
        return nil if addresses.nil? # DNS failure - unknowable

        addresses.any? { |a| a == addr }
      end

      def forward_includes?(name, addr)
        (forward_addresses(name) || []).any? { |a| a == addr }
      end

      # Every A/AAAA for +name+ as IPAddr, [] for an empty answer, nil on
      # DNS failure.
      def forward_addresses(name)
        (@resolver.a(name) + @resolver.aaaa(name)).filter_map do |address|
          IPAddr.new(address)
        rescue IPAddr::InvalidAddressError
          nil
        end
      rescue SenderAuth::Dns::TempError
        nil
      end

      def public_address(ip)
        addr = IPAddr.new(ip.to_s)
        return nil if addr.loopback? || addr.private? || addr.link_local?

        addr
      rescue IPAddr::InvalidAddressError
        nil
      end

      def sweep(now)
        @cache.delete_if { |_key, (_result, expires_at)| expires_at <= now }
      end
    end
  end
end
