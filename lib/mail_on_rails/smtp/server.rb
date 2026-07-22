# frozen_string_literal: true

require "socket"
require "etc"
require_relative "config"
require_relative "conn_limiter"
require_relative "auth_throttle"
require_relative "rate_limiter"
require_relative "tls"
require_relative "worker"

module MailOnRails
  module Smtp
    # Shared listener scaffolding for the SMTP and IMAP servers: one accept
    # thread per listener spec, a pool of session workers, a connection cap,
    # and TLS material handling. Keeping this in one place means the
    # connection-flood and TLS-accept behavior can't drift apart between the
    # two protocols.
    #
    # Sessions do not run on the accept threads. Each accepted socket is
    # handed to a Worker (fiber-scheduled sessions, see worker.rb):
    #
    #   - Ractor mode: one worker Ractor per core, sockets dispatched as fd
    #     numbers over per-worker control pipes, round-robin. Requires a
    #     store that can be rebuilt inside each Ractor, i.e. one that
    #     implements #worker_config (Store::Http does). Session completions
    #     come back as "<worker index> <ip>\n" lines on a shared release
    #     pipe (freeing ConnLimiter slots), authentication failures as
    #     "<ip>\n" lines on a shared auth pipe (feeding AuthThrottle). A
    #     monitor thread per worker enforces the death policy: a worker
    #     Ractor that dies is logged and replaced (its in-flight sessions'
    #     limiter slots swept via the per-worker inflight table), and once
    #     MAX_WORKER_RESPAWNS replacements have been burned the failure is
    #     treated as systemic - the accept loops stop, Server#run returns,
    #     and the daemon exits for the container runtime to restart.
    #   - Thread mode: worker threads popping one shared queue. Used when
    #     the store is an injected in-process instance (tests, embedded
    #     development) or when SMTP_WORKER_MODE=thread.
    #
    # The ConnLimiter, AuthThrottle and RateLimiter always live on the
    # accept side, so the connection caps (process-wide and per-IP), the
    # per-IP auth-failure lockout and the per-IP connection rate stay exact
    # across both modes. Tarpit delays the rate limiter hands out are
    # threaded through dispatch and served by the worker (a fiber sleep
    # before the banner), never on an accept thread.
    #
    # Subclasses define MAX_CONNECTIONS and the protocol specifics:
    # protocol_name, busy_line (sent when the connection cap is hit),
    # listener_label(spec) and session_class.
    class Server
      # Reap dead peers at the TCP layer (Postal's timings): first probe
      # after 50s idle, then every 10s, gone after 5 unanswered probes -
      # ~100s to reclaim a half-open connection's ConnLimiter slot instead
      # of waiting out the sessions' 300s idle timeout.
      KEEPALIVE_IDLE = 50
      KEEPALIVE_INTERVAL = 10
      KEEPALIVE_PROBES = 5

      # Per-IP anti-abuse defaults; protocol subclasses override (with
      # env-driven values). nil/0 disables. Enforced on the accept side -
      # worker Ractors are isolated, so shared abuse state lives here.
      MAX_CONNECTIONS_PER_IP = nil
      AUTH_LOCKOUT_FAILURES = nil
      AUTH_LOCKOUT_SECONDS = 900
      CONN_RATE_LIMIT = nil
      CONN_RATE_WINDOW = 60

      # Worker deaths tolerated per process lifetime before the failure is
      # treated as systemic and the server shuts down (the daemon exits
      # non-zero; the container runtime restarts it with backoff). Ractors
      # are formally experimental, so one crash should not take down every
      # in-flight session - but a crash loop must not hide behind respawns.
      MAX_WORKER_RESPAWNS = 5

      def self.run(store, listeners, tls_material, workers: nil)
        new(store, listeners, tls_material, workers: workers).run
      end

      def initialize(store, listeners, tls_material, workers: nil)
        @store = store
        @listeners = listeners
        @tls_material = tls_material
        @limiter = ConnLimiter.new(self.class::MAX_CONNECTIONS, per_ip: self.class::MAX_CONNECTIONS_PER_IP)
        @throttle = AuthThrottle.new(limit: self.class::AUTH_LOCKOUT_FAILURES,
                                     window: self.class::AUTH_LOCKOUT_SECONDS)
        @rate = RateLimiter.new(limit: self.class::CONN_RATE_LIMIT,
                                window: self.class::CONN_RATE_WINDOW)
        @worker_count = [ workers || Config.int("SMTP_WORKERS", Etc.nprocessors, min: 1), 1 ].max
        @dispatchers = []
        @round_robin = 0
        @mutex = Mutex.new
        @listener_threads = []
        @shutdown = false
      end

      def run
        # Build a context now even in Ractor mode: TLS problems should
        # surface at boot, not on the first connection of each worker.
        tls = @tls_material && TLS::ContextProvider.new(@tls_material)
        mode = worker_mode
        session_specs = build_session_specs
        @dispatchers = mode == :ractor ? spawn_ractor_workers(session_specs) : spawn_thread_workers(tls)

        threads = @listeners.each_with_index.map do |spec, index|
          next if spec[:tls] == :implicit && tls.nil?

          Thread.new(spec, index) { |listener, i| accept_loop(listener, session_specs[i], i) }
        end.compact
        @listener_threads = threads
        shutdown if @shutdown # a boot-time worker death may already have exhausted the budget
        @store.log(:info, "#{protocol_name} listening: #{@listeners.map { |s| listener_label(s) }.join(", ")} " \
                          "(#{@worker_count} #{mode} workers)")
        threads.each(&:join)
      end

      private

      # Ractor mode needs per-Ractor store construction; a store advertises
      # that with #worker_config. Injected instances (Store::Memory, custom
      # embedded stores) fall back to threads, as does an explicit
      # SMTP_WORKER_MODE=thread override.
      def worker_mode
        return :thread if ENV["SMTP_WORKER_MODE"] == "thread"

        @store.respond_to?(:worker_config) ? :ractor : :thread
      end

      # The subset of each listener spec a session needs, deep-frozen so it
      # can cross into worker Ractors.
      def build_session_specs
        @listeners.map do |spec|
          Ractor.make_shareable(spec.slice(:host, :port, :tls, :role, :hostname, :trace, :handshake_timeout))
        end
      end

      def spawn_ractor_workers(session_specs)
        release_r, @release_w = IO.pipe
        auth_r, @auth_w = IO.pipe
        # Per-worker { ip => open sessions } tables, updated under @mutex.
        # They make worker death recoverable: replace_worker sweeps the dead
        # worker's table to free its limiter slots, and release_session
        # treats the table as the source of truth so a swept session's late
        # release line cannot free a slot twice.
        @inflight = Array.new(@worker_count) { Hash.new(0) }
        @respawns = 0
        @spawn_args = {
          session_class: session_class, specs: session_specs,
          tls_material: @tls_material && Ractor.make_shareable(@tls_material.dup),
          store_config: Ractor.make_shareable(@store.worker_config)
        }
        Thread.new { release_loop(release_r) }
        Thread.new { auth_failure_loop(auth_r) }
        Array.new(@worker_count) { |index| spawn_worker(index) }
      end

      # Spawns one worker Ractor plus the monitor thread that applies the
      # death policy; returns the control pipe end used to dispatch to it.
      def spawn_worker(index)
        ractor, control_w = Worker.spawn_ractor(
          **@spawn_args, index: index, release_fd: @release_w.fileno,
          auth_fd: @auth_w.fileno, ready_port: Ractor::Port.new
        )
        control_w.sync = true
        Thread.new { monitor_worker(ractor, index) }
        control_w
      end

      # Waits for a worker Ractor to terminate. :worker_exit means its
      # control pipe closed - an intended shutdown. Anything else (an
      # exception, an early return) would silently drop 1/N of round-robin
      # dispatch from here on, so the death policy steps in.
      def monitor_worker(ractor, index)
        outcome = begin
          ractor.value
        rescue Exception => e # rubocop:disable Lint/RescueException -- worker deaths arrive as exceptions
          e
        end
        handle_worker_death(index, outcome) unless outcome == :worker_exit
      end

      def handle_worker_death(index, cause)
        cause = cause.cause if cause.is_a?(Ractor::RemoteError) && cause.cause
        detail = cause.is_a?(Exception) ? "#{cause.class}: #{cause.message}" : "returned #{cause.inspect}"
        respawns = @mutex.synchronize { @respawns += 1 }
        if respawns > self.class::MAX_WORKER_RESPAWNS
          @store.log(:error, "#{protocol_name} worker #{index} died (#{detail}); " \
                             "respawn budget (#{self.class::MAX_WORKER_RESPAWNS}) exhausted - shutting down")
          shutdown
        else
          @store.log(:error, "#{protocol_name} worker #{index} died (#{detail}); " \
                             "spawning replacement (#{respawns}/#{self.class::MAX_WORKER_RESPAWNS})")
          replace_worker(index)
        end
      end

      def replace_worker(index)
        control_w = spawn_worker(index) # outside the lock: Ractor startup must not stall accepts
        stale = nil
        @mutex.synchronize do
          @dispatchers[index] = control_w
          stale = @inflight[index]
          @inflight[index] = Hash.new(0)
        end
        # Sessions lost with the worker never ran on_done; free their slots.
        # (Their fds leak until process exit - bounded by the respawn budget.)
        stale.each do |ip, count|
          count.times { @limiter.release(ip.empty? ? nil : ip) }
        end
      end

      # Stops the accept loops; Server#run then returns and the daemon exits
      # non-zero for the container runtime to restart. In-flight sessions on
      # surviving workers are abandoned - peers retry, as on a deploy.
      def shutdown
        @shutdown = true
        Array(@listener_threads).each(&:kill)
      end

      def spawn_thread_workers(tls)
        queue = Thread::Queue.new
        @worker_count.times do
          worker = Worker.new(store: @store, session_class: session_class, tls: tls,
                              on_done: ->(ip) { @limiter.release(ip) },
                              on_auth_failure: ->(ip) { record_auth_failure(ip) })
          Thread.new { worker.serve_queue(queue) }
        end
        [ queue ]
      end

      # Every line a worker writes is one finished session
      # ("<worker index> <ip>\n", trailing ip blank when the peer address
      # was unavailable), freeing its ConnLimiter slots.
      def release_loop(release_r)
        while (line = release_r.gets)
          index, ip = line.chomp.split(" ", 2)
          release_session(Integer(index), ip.to_s)
        end
      rescue IOError
        nil
      end

      # The inflight table decides whether the release still counts: a
      # session swept by replace_worker (its worker died) already gave its
      # slot back, so its late release line must be a no-op.
      def release_session(worker_index, ip)
        tracked = @mutex.synchronize do
          inflight = @inflight[worker_index]
          if inflight[ip].positive?
            inflight[ip] -= 1
            inflight.delete(ip) if inflight[ip].zero?
            true
          else
            false
          end
        end
        @limiter.release(ip.empty? ? nil : ip) if tracked
      end

      # Every line a worker writes is one failed authentication ("<ip>\n").
      def auth_failure_loop(auth_r)
        while (line = auth_r.gets)
          ip = line.chomp
          record_auth_failure(ip) unless ip.empty?
        end
      rescue IOError
        nil
      end

      def record_auth_failure(ip)
        return unless @throttle.record(ip) == :locked

        @store.log(:warn, "#{protocol_name} locking out #{ip} for #{self.class::AUTH_LOCKOUT_SECONDS}s " \
                          "after #{self.class::AUTH_LOCKOUT_FAILURES} failed authentication attempts")
      end

      def accept_loop(spec, session_spec, spec_index)
        server = spec[:tcp_server] || TCPServer.new(spec[:host], spec[:port])
        loop do
          socket = server.accept
          tune_keepalive(socket)
          ip = peer_ip(socket)
          delay = @rate.delay(ip) # every attempt counts, even ones refused below
          if @throttle.locked?(ip)
            reject(socket, locked_line) # before acquire: locked IPs must not consume slots
          elsif @limiter.acquire(ip)
            dispatch(socket, session_spec, spec_index, ip, delay)
          else
            reject(socket, busy_line)
          end
        end
      rescue StandardError => e
        @store.log(:error, "#{protocol_name} listener #{spec[:port]} died: #{e.class}: #{e.message}")
      end

      # The whole handoff runs under @mutex so it cannot interleave with
      # replace_worker's dispatcher swap: a dispatch lands either fully
      # before the swap (its inflight entry is then swept) or fully after
      # (and reaches the replacement worker). Control-pipe lines are tiny
      # and workers drain them promptly, so holding the lock across the
      # write does not stall the accept threads.
      def dispatch(socket, session_spec, spec_index, ip, delay = 0.0)
        @mutex.synchronize do
          @round_robin += 1
          worker_index = @round_robin % @dispatchers.size
          target = @dispatchers[worker_index]
          if target.is_a?(Thread::Queue)
            target.push([ socket, session_spec, ip, delay ])
          else
            # The worker Ractor owns the fd from here; keep our IO object
            # from closing it behind the worker's back when GC collects it.
            # The tarpit delay travels before the ip: the ip may be blank,
            # so it must stay the (optional) last field.
            socket.autoclose = false
            target.write("#{socket.fileno} #{spec_index} #{format("%g", delay)} #{ip}\n")
            @inflight[worker_index][ip.to_s] += 1
          end
        end
      rescue StandardError
        @limiter.release(ip)
        begin
          socket.autoclose = true # closing must reclaim the fd we still own
          socket.close
        rescue StandardError
          nil
        end
      end

      # The peer address at accept time, threaded through dispatch and the
      # release path so both sides of the per-IP accounting use the same
      # key. nil when the peer vanished before getpeername.
      def peer_ip(socket)
        socket.remote_address.ip_address
      rescue StandardError
        nil
      end

      # TCP_KEEP* constants are platform-dependent (macOS has no
      # TCP_KEEPIDLE); missing ones just mean kernel-default timings.
      def tune_keepalive(socket)
        socket.setsockopt(:SOCKET, :KEEPALIVE, true)
        socket.setsockopt(:TCP, :KEEPIDLE, KEEPALIVE_IDLE) if Socket.const_defined?(:TCP_KEEPIDLE)
        socket.setsockopt(:TCP, :KEEPINTVL, KEEPALIVE_INTERVAL) if Socket.const_defined?(:TCP_KEEPINTVL)
        socket.setsockopt(:TCP, :KEEPCNT, KEEPALIVE_PROBES) if Socket.const_defined?(:TCP_KEEPCNT)
      rescue SystemCallError
        nil
      end

      def reject(socket, line)
        socket.write("#{line}\r\n")
        socket.close
      rescue StandardError
        nil
      end

      # Sent to connections from locked-out IPs; protocol subclasses may
      # override with a more specific message.
      def locked_line = busy_line
    end
  end
end
