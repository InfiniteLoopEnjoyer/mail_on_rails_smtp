# frozen_string_literal: true

require "socket"
require_relative "scheduler"
require_relative "tls"

module MailOnRails
  module Smtp
    # Serves many SMTP sessions on one thread: a dispatcher fiber takes
    # incoming connections and starts a session fiber per connection, all
    # multiplexed by Scheduler. Implicit-TLS handshakes happen here too, so
    # the accept loop never blocks on a slow handshake.
    #
    # Two intake modes, one Worker:
    #
    #   Ractor mode (Worker.spawn_ractor): one Worker per core, each inside
    #   its own Ractor for true parallelism. Sockets cross the boundary as
    #   raw fd numbers over a control pipe ("<fd> <spec index> <tarpit
    #   delay> <peer ip>\n" lines) and are re-wrapped with TCPSocket.for_fd
    #   - fds are
    #   process-global, and integers avoid Ractor IO moves entirely (moved
    #   IOs misbehave under a fiber scheduler on Ruby 4.0.6; see
    #   scheduler.rb). The worker builds its own store and TLS context
    #   inside the Ractor - neither can be shared across the boundary - and
    #   reports each finished session as a "<worker index> <ip>\n" line on
    #   the shared release pipe (the accept side turns those into
    #   ConnLimiter releases, attributed to this worker's inflight table)
    #   and each failed authentication as an "<ip>\n" line on the shared
    #   auth pipe (feeding the accept side's AuthThrottle). The peer IP is
    #   captured accept-side and threaded through, so both sides of the
    #   per-IP accounting use the same key even if the peer vanishes.
    #
    #   Thread mode (Worker#serve_queue): same serving core on a plain
    #   thread, fed [socket, spec] pairs through a Thread::Queue and sharing
    #   the caller's store/limiter directly. Used when a store instance is
    #   injected (tests, embedded development) - an in-process store can't
    #   be rebuilt inside a Ractor.
    class Worker
      # Cap on the implicit-TLS handshake. The session's own idle timeout is
      # only set once the session runs - after TLS.accept - so without this
      # bound a connected-but-silent peer parks the handshake fiber forever
      # and its ConnLimiter slot leaks (TCP keepalive only reaps dead peers,
      # not alive-and-idle ones). Overridable per listener via
      # spec[:handshake_timeout].
      HANDSHAKE_TIMEOUT = 30

      def initialize(store:, session_class:, tls: nil, on_done: nil, on_auth_failure: nil)
        @store = store
        @session_class = session_class
        @tls = tls
        @on_done = on_done               # called with the peer IP per finished session
        @on_auth_failure = on_auth_failure # called with the peer IP per failed AUTH
      end

      # Thread mode entry point. Runs until the queue is closed.
      def serve_queue(queue)
        serve { queue.pop }
      end

      # Ractor mode entry point. Runs until the control pipe's write end
      # closes. specs must be indexable by the dispatched spec index.
      def serve_pipe(control_r, specs)
        serve do
          line = control_r.gets
          if line
            fd, index, delay, ip = line.split
            [ TCPSocket.for_fd(Integer(fd)), specs.fetch(Integer(index)), ip, Float(delay) ]
          end
        end
      end

      # Spawns a Ractor-mode worker and returns [ractor, control_write_io].
      # All arguments must be shareable: session_class is a Class,
      # specs/tls_material/store_config are deep-frozen data,
      # release_fd/ready_port are an Integer and a Port.
      def self.spawn_ractor(session_class:, specs:, tls_material:, store_config:, index:, release_fd:, auth_fd:, ready_port:)
        ractor = Ractor.new(session_class, specs, tls_material, store_config,
                            index, release_fd, auth_fd, ready_port) do |session_class, specs, tls_material, store_config, index, release_fd, auth_fd, ready_port|
          control_r, control_w = IO.pipe
          ready_port.send(control_w.fileno)

          release = IO.for_fd(release_fd)
          release.autoclose = false # the accept side owns this fd
          release.sync = true
          auth = IO.for_fd(auth_fd)
          auth.autoclose = false
          auth.sync = true

          store = store_config.fetch(:store_class).from_config(store_config[:config] || {})
          tls = tls_material && TLS::ContextProvider.new(tls_material)
          # Explicit constant: self inside a Ractor block is the Ractor.
          # Single short pipe writes stay atomic, so workers can share fds.
          Worker.new(store: store, session_class: session_class, tls: tls,
                     on_done: ->(ip) { release.write("#{index} #{ip}\n") },
                     on_auth_failure: ->(ip) { auth.write("#{ip}\n") if ip }).serve_pipe(control_r, specs)
          :worker_exit
        end
        [ ractor, IO.for_fd(ready_port.receive) ]
      end

      private

      # The serving core: dispatcher fiber pulls connections from the
      # supplier (which parks the fiber, not the thread, when idle) until it
      # returns nil. The scheduler's event loop (Scheduler#close) runs
      # explicitly HERE, not in thread-exit cleanup: an error that escapes
      # the rescues in handle must propagate as the worker's real outcome -
      # Server's death policy depends on seeing it - whereas an exception
      # out of thread-exit cleanup is reported and swallowed, leaving the
      # Ractor to terminate with the block's value as if nothing happened.
      def serve(&supplier)
        scheduler = Scheduler.new
        Fiber.set_scheduler(scheduler)
        Fiber.schedule do
          loop do
            socket, spec, ip, delay = supplier.call
            break unless socket

            Fiber.schedule { handle(socket, spec, ip, delay) }
          end
        end
        scheduler.close # serves until every session finishes; re-raises fatal errors
      end

      def handle(socket, spec, ip = nil, delay = nil)
        # Tarpit (RateLimiter's verdict, threaded through dispatch): served
        # before the TLS handshake and banner. sleep under the scheduler
        # parks this session's fiber only, but the connection keeps holding
        # its ConnLimiter slot - that is the cost to the flooding peer.
        sleep(delay) if delay&.positive?
        ctx = @tls&.context
        if spec[:tls] == :implicit && ctx
          socket.timeout = spec[:handshake_timeout] || HANDSHAKE_TIMEOUT if socket.respond_to?(:timeout=)
          socket = TLS.accept(socket, ctx)
        end
        session = @session_class.new(socket, @store, spec, ctx)
        # Sessions that support it report failed AUTHs so the accept side's
        # per-IP throttle sees attempts across connections.
        if ip && @on_auth_failure && session.respond_to?(:on_auth_failure=)
          session.on_auth_failure = -> { @on_auth_failure.call(ip) }
        end
        session.run
      rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
        nil # session logs its own protocol-level errors; this is connection debris
      ensure
        begin
          socket.close
        rescue StandardError
          nil
        end
        @on_done&.call(ip)
      end
    end
  end
end
