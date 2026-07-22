# frozen_string_literal: true

require "socket"
require "etc"
require_relative "conn_limiter"
require_relative "auth_throttle"
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
    #     come back as "<ip>\n" lines on a shared release pipe (freeing
    #     ConnLimiter slots), authentication failures as "<ip>\n" lines on a
    #     shared auth pipe (feeding AuthThrottle).
    #   - Thread mode: worker threads popping one shared queue. Used when
    #     the store is an injected in-process instance (tests, embedded
    #     development) or when MAIL_ON_RAILS_SMTP_WORKER_MODE=thread.
    #
    # The ConnLimiter and AuthThrottle always live on the accept side, so
    # the connection caps (process-wide and per-IP) and the per-IP
    # auth-failure lockout stay exact across both modes.
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
        @worker_count = [ workers || Integer(ENV.fetch("MAIL_ON_RAILS_SMTP_WORKERS") { Etc.nprocessors }), 1 ].max
        @dispatchers = []
        @round_robin = 0
        @mutex = Mutex.new
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
        @store.log(:info, "#{protocol_name} listening: #{@listeners.map { |s| listener_label(s) }.join(", ")} " \
                          "(#{@worker_count} #{mode} workers)")
        threads.each(&:join)
      end

      private

      # Ractor mode needs per-Ractor store construction; a store advertises
      # that with #worker_config. Injected instances (Store::Memory, custom
      # embedded stores) fall back to threads, as does an explicit
      # MAIL_ON_RAILS_SMTP_WORKER_MODE=thread override.
      def worker_mode
        return :thread if ENV["MAIL_ON_RAILS_SMTP_WORKER_MODE"] == "thread"

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
        Thread.new { release_loop(release_r) }
        Thread.new { auth_failure_loop(auth_r) }
        ready_port = Ractor::Port.new
        store_config = Ractor.make_shareable(@store.worker_config)
        material = @tls_material && Ractor.make_shareable(@tls_material.dup)

        Array.new(@worker_count) do
          _ractor, control_w = Worker.spawn_ractor(
            session_class: session_class, specs: session_specs, tls_material: material,
            store_config: store_config, release_fd: @release_w.fileno,
            auth_fd: @auth_w.fileno, ready_port: ready_port
          )
          control_w.sync = true
          control_w
        end
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

      # Every line a worker writes is one finished session ("<ip>\n", bare
      # newline when the peer address was unavailable), freeing its slots.
      def release_loop(release_r)
        while (line = release_r.gets)
          ip = line.chomp
          @limiter.release(ip.empty? ? nil : ip)
        end
      rescue IOError
        nil
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
          if @throttle.locked?(ip)
            reject(socket, locked_line) # before acquire: locked IPs must not consume slots
          elsif @limiter.acquire(ip)
            dispatch(socket, session_spec, spec_index, ip)
          else
            reject(socket, busy_line)
          end
        end
      rescue StandardError => e
        @store.log(:error, "#{protocol_name} listener #{spec[:port]} died: #{e.class}: #{e.message}")
      end

      def dispatch(socket, session_spec, spec_index, ip)
        target = @mutex.synchronize do
          @round_robin += 1
          @dispatchers[@round_robin % @dispatchers.size]
        end
        if target.is_a?(Thread::Queue)
          target.push([ socket, session_spec, ip ])
        else
          # The worker Ractor owns the fd from here; keep our IO object from
          # closing it behind the worker's back when GC collects it.
          socket.autoclose = false
          target.write("#{socket.fileno} #{spec_index} #{ip}\n")
        end
      rescue StandardError
        @limiter.release(ip)
        begin
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
