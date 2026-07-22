# frozen_string_literal: true

require "net/http"

module MailOnRails
  module Smtp
    # A pool of persistent (keep-alive) Net::HTTP connections to one origin,
    # so InternalApi and IngressClient stop paying a TCP (+ TLS) handshake
    # per request. Built per client instance, and clients are built per
    # worker (Store::Http.from_config), so nothing here crosses a Ractor.
    #
    # Concurrency is never capped: an empty pool dials a fresh connection
    # instead of waiting, so a hung app stalls each caller independently for
    # its own read timeout - exactly the behavior of the per-request
    # connections this replaces. Only idle connections are pooled, at most
    # MAX_IDLE; extras are closed on check-in.
    #
    # Fiber/thread safety: checkout is a non-blocking Queue#pop, so two
    # sessions can never share a connection mid-request (a Net::HTTP request
    # is many IO operations, each a scheduler yield point). The Queue also
    # makes check-in/checkout safe across worker threads in thread mode.
    #
    # Failure policy: a request that raises discards its connection and
    # propagates - NEVER retries. Every request here is a POST (not
    # idempotent; a retried queue_outbound or ingress POST double-submits),
    # and the store's documented recovery path is the error envelope -> 451
    # -> the sending MTA retries. Net::HTTP's own stale-socket retry only
    # applies to idempotent methods, so it stays out of the way. The
    # keep-alive timeout is kept short so a connection the app server closed
    # while idle is redialed rather than written into.
    class HttpPool
      MAX_IDLE = 4
      KEEP_ALIVE_TIMEOUT = 2 # seconds; well under typical app-server persistent timeouts

      def initialize(uri, open_timeout:, read_timeout:, max_idle: MAX_IDLE)
        @host = uri.host
        @port = uri.port
        @ssl = uri.scheme == "https"
        @open_timeout = open_timeout
        @read_timeout = read_timeout
        @max_idle = max_idle
        @idle = Queue.new
      end

      def request(req)
        conn = checkout
        begin
          response = conn.request(req)
        rescue Exception # rubocop:disable Lint/RescueException -- Timeout::Error interrupts must also discard the conn
          discard(conn)
          raise
        end
        checkin(conn)
        response
      end

      private

      def checkout
        @idle.pop(true)
      rescue ThreadError
        dial
      end

      def dial
        conn = Net::HTTP.new(@host, @port)
        conn.use_ssl = @ssl
        conn.open_timeout = @open_timeout
        conn.read_timeout = @read_timeout
        conn.keep_alive_timeout = KEEP_ALIVE_TIMEOUT
        conn.start
      end

      # A benign size/push race across threads can briefly overshoot
      # @max_idle by a connection; harmless, so no lock.
      def checkin(conn)
        @idle.size < @max_idle ? @idle << conn : discard(conn)
      end

      def discard(conn)
        conn.finish if conn.started?
      rescue IOError
        nil
      end
    end
  end
end
