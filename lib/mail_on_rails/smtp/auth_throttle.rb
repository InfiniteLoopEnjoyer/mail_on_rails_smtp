# frozen_string_literal: true

module MailOnRails
  module Smtp
    # Per-IP lockout for repeated authentication failures. A session can only
    # count its own attempts (MAX_AUTH_ATTEMPTS per connection), so a client
    # that reconnects gets a fresh allowance - and every guess costs the host
    # app an HTTP credential check. This throttle spans connections.
    #
    # Lives on the accept side: worker Ractors are isolated, so shared abuse
    # state cannot live in sessions. Workers report failures upward (directly
    # in thread mode, over a pipe in Ractor mode) and the accept loop refuses
    # connections from locked-out IPs outright with a 421. Tempfail semantics
    # are deliberate: if a NAT/shared IP hosts both an abuser and a
    # legitimate sender, the legitimate mail is delayed for the lockout
    # window, never lost.
    #
    # +limit+ failures within +window+ seconds locks the IP for +window+
    # seconds from its last failure; a quiet gap of +window+ seconds forgives
    # the count. A nil/0 limit disables the throttle. +clock+ is injectable
    # for tests and must be monotonic.
    class AuthThrottle
      SWEEP_THRESHOLD = 1_000 # purge expired entries when the table grows past this

      Entry = Struct.new(:count, :last_at, :locked_until)

      def initialize(limit:, window:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @limit = limit if limit&.positive?
        @window = window.to_f
        @clock = clock
        @entries = {}
        @mutex = Mutex.new
      end

      # Records one failed authentication attempt. Returns :locked on exactly
      # the attempt that trips the lockout, so the caller can log the
      # transition once; further failures while locked (from sessions already
      # in flight) extend the lockout silently.
      def record(ip)
        return nil unless @limit && ip

        now = @clock.call
        @mutex.synchronize do
          sweep(now) if @entries.size > SWEEP_THRESHOLD
          entry = (@entries[ip] ||= Entry.new(0, now, nil))
          entry.count = 0 if now - entry.last_at > @window # quiet period forgives
          entry.count += 1
          entry.last_at = now
          if entry.count >= @limit
            newly = entry.count == @limit
            entry.locked_until = now + @window
            newly ? :locked : nil
          end
        end
      end

      def locked?(ip)
        return false unless @limit && ip

        now = @clock.call
        @mutex.synchronize do
          locked_until = @entries[ip]&.locked_until
          !locked_until.nil? && locked_until > now
        end
      end

      private

      # Drops entries whose lockout and failure window have both expired.
      def sweep(now)
        @entries.delete_if do |_ip, e|
          (e.locked_until.nil? || e.locked_until <= now) && now - e.last_at > @window
        end
      end
    end
  end
end
