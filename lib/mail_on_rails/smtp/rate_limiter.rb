# frozen_string_literal: true

require "ipaddr"

module MailOnRails
  module Smtp
    # Per-IP sliding-window connection rate, answered with an escalating
    # tarpit delay rather than a refusal. Completes the per-IP anti-abuse
    # set: ConnLimiter caps concurrent connections, AuthThrottle locks out
    # credential guessing, and this slows connection churn (bots that open,
    # send, and reconnect fast to stay under the concurrent cap).
    #
    # Within +limit+ connections per +window+ seconds the delay is zero.
    # Each connection beyond the limit doubles it - base_delay, 2x, 4x, ...
    # capped at max_delay - and the delay is served before the banner in
    # the session's worker fiber (a fiber sleep parks nothing but that
    # session), never on an accept thread. A tarpitted connection holds its
    # ConnLimiter slot while it waits, so together with the per-IP
    # concurrent cap C this bounds a flood to C/max_delay connections per
    # second without ever hard-refusing a legitimate burst.
    #
    # Lives on the accept side like the other two (worker Ractors are
    # isolated; round-robin dispatch would undercount an IP by the worker
    # count). A nil/0 limit disables. +clock+ is injectable for tests and
    # must be monotonic.
    class RateLimiter
      BASE_DELAY = 1.0
      MAX_DELAY = 16.0
      OVERAGE_MEMORY = 64 # timestamps kept per IP beyond the limit; deeper is at max delay anyway
      SWEEP_THRESHOLD = 1_000 # purge idle IPs when the table grows past this

      def initialize(limit:, window:, base_delay: BASE_DELAY, max_delay: MAX_DELAY,
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @limit = limit if limit&.positive?
        @window = window.to_f
        @base_delay = base_delay
        @max_delay = max_delay
        @clock = clock
        @entries = {} # ip => connection timestamps within the window, oldest first
        @mutex = Mutex.new
      end

      # Records one connection attempt from +ip+ and returns the tarpit
      # delay in seconds (0.0 while within budget). Every attempt counts,
      # including ones the caller goes on to refuse - a peer bouncing off
      # the concurrent cap is exactly the churn this measures. Loopback
      # peers are exempt (healthchecks and embedded development connect
      # from 127.0.0.1 at machine rates; Postfix likewise exempts
      # $mynetworks from its client rate limits).
      def delay(ip)
        return 0.0 unless @limit && ip
        return 0.0 if loopback?(ip)

        now = @clock.call
        @mutex.synchronize do
          sweep(now) if @entries.size > SWEEP_THRESHOLD
          stamps = (@entries[ip] ||= [])
          stamps.shift while stamps.any? && now - stamps.first > @window
          stamps.shift if stamps.size >= @limit + OVERAGE_MEMORY # bound per-IP memory
          stamps << now
          over = stamps.size - @limit
          if over <= 0
            0.0
          else
            [ @base_delay * (2**[ over - 1, 10 ].min), @max_delay ].min
          end
        end
      end

      private

      def loopback?(ip)
        IPAddr.new(ip).loopback?
      rescue IPAddr::InvalidAddressError
        false # not an IP; still rate-limited under its own key
      end

      # Drops IPs whose every timestamp has aged out of the window.
      def sweep(now)
        @entries.delete_if { |_ip, stamps| stamps.empty? || now - stamps.last > @window }
      end
    end
  end
end
