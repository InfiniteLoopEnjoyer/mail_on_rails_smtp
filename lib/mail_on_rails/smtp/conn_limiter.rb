# frozen_string_literal: true

module MailOnRails
  module Smtp
    # Caps the number of simultaneously open connections a server will handle,
    # bounding thread and file-descriptor use under a connection flood - both
    # process-wide and per peer IP, so a single address cannot hold every
    # slot (slow-loris style). Lives on the accept side, shared by a server's
    # accept threads; a plain Mutex-guarded counter is sufficient.
    class ConnLimiter
      def initialize(max, per_ip: nil)
        @max = max
        @per_ip_max = per_ip if per_ip&.positive? # nil/0 disables the per-IP cap
        @count = 0
        @per_ip = Hash.new(0)
        @mutex = Mutex.new
      end

      # Tries to reserve a slot for +ip+. Returns true if acquired, false when
      # the process-wide or per-IP cap is hit. A nil ip (peer address was
      # unavailable at accept) counts against the process-wide cap only.
      def acquire(ip = nil)
        @mutex.synchronize do
          return false if @count >= @max
          return false if ip && @per_ip_max && @per_ip[ip] >= @per_ip_max

          @count += 1
          @per_ip[ip] += 1 if ip && @per_ip_max
          true
        end
      end

      # Frees a slot. +ip+ must be the value the matching acquire was called
      # with - callers thread it through the session lifecycle so both sides
      # of the per-IP accounting use the same key.
      def release(ip = nil)
        @mutex.synchronize do
          @count -= 1 if @count.positive?
          if ip && @per_ip_max && @per_ip.key?(ip)
            @per_ip[ip] -= 1
            @per_ip.delete(ip) if @per_ip[ip] <= 0 # the table must not grow with peer history
          end
        end
      end
    end
  end
end
