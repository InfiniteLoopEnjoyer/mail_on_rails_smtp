# frozen_string_literal: true

require "resolv"
require "ipaddr"
require "socket"

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
      # The transport is our own (UDP with TCP fallback on truncation,
      # straight to the resolv.conf nameservers); only Resolv's wire codec
      # is reused. Two reasons over plain Resolv:
      #
      #   - Resolv's query path is not Ractor-safe (@@identifier class
      #     variable in Resolv::DNS::Message, class-level config caches),
      #     and sessions run inside worker Ractors. The codec is safe as
      #     long as message ids are passed explicitly and resolv is
      #     required by the main Ractor at boot (this file's require).
      #   - Resolv cannot distinguish NXDOMAIN from SERVFAIL or a timeout.
      #     Here NXDOMAIN/no-answer is [], while SERVFAIL, malformed
      #     replies, and unreachable/timing-out nameservers raise
      #     TempError, so a DNS outage reads as temperror rather than
      #     silently weakening a verdict to "no record".
      class Dns
        class TempError < StandardError; end

        TIMEOUT = Integer(ENV.fetch("MAIL_ON_RAILS_DNS_TIMEOUT", 5))
        PORT = 53
        MAX_UDP = 4096

        # Parsed once at boot (this file is required by the main Ractor) and
        # frozen, so worker Ractors can read it. resolv.conf changes need a
        # daemon restart, which container deploys do anyway.
        SYSTEM_NAMESERVERS = begin
          servers = File.readlines("/etc/resolv.conf", chomp: true)
                        .filter_map { |line| line[/\Anameserver\s+(\S+)/, 1] }
          servers.empty? ? [ "127.0.0.1" ] : servers.first(3)
        rescue SystemCallError
          [ "127.0.0.1" ]
        end.freeze

        # port is injectable so tests can stand up a loopback DNS server.
        def initialize(nameservers: SYSTEM_NAMESERVERS, timeout: TIMEOUT, port: PORT)
          @nameservers = nameservers
          @timeout = timeout
          @port = port
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

        def resources(name, typeclass)
          reply = exchange(name.to_s, typeclass)
          case reply.rcode
          when Resolv::DNS::RCode::NoError
            reply.answer.filter_map { |_owner, _ttl, record| record if record.is_a?(typeclass) }
          when Resolv::DNS::RCode::NXDomain
            []
          else
            raise TempError, "DNS rcode #{reply.rcode} for #{name}"
          end
        end

        # Asks each nameserver in turn; first decodable reply wins. Raises
        # TempError once every nameserver has timed out or errored.
        def exchange(name, typeclass)
          id = rand(0x10000)
          payload = build_query(id, name, typeclass)
          errors = []
          @nameservers.each do |server|
            reply = udp_exchange(server, payload, id)
            reply = tcp_exchange(server, payload, id) if reply&.tc == 1
            return reply if reply
          rescue IO::TimeoutError, SystemCallError, SocketError, Resolv::DNS::DecodeError => e
            errors << "#{server}: #{e.class}"
          end
          raise TempError, "DNS lookup failed for #{name} (#{errors.join(", ")})"
        end

        def build_query(id, name, typeclass)
          # Explicit id: the default taps a Ractor-hostile class variable.
          message = Resolv::DNS::Message.new(id)
          message.rd = 1
          message.add_question(Resolv::DNS::Name.create(absolute(name)), typeclass)
          message.encode
        end

        def absolute(name)
          name.end_with?(".") ? name : "#{name}."
        end

        def udp_exchange(server, payload, id)
          socket = UDPSocket.new(Addrinfo.ip(server).afamily)
          socket.timeout = @timeout # honored by IO and by Scheduler in workers
          socket.connect(server, @port)
          socket.send(payload, 0)
          # A few tries: a mismatched id is a stray/spoofed datagram, not
          # the reply. Bounded so a flood can't spin this fiber forever.
          4.times do
            reply = decode(socket.recv(MAX_UDP))
            return reply if reply&.id == id
          end
          nil
        ensure
          socket&.close
        end

        def tcp_exchange(server, payload, id)
          Socket.tcp(server, @port, connect_timeout: @timeout) do |socket|
            socket.timeout = @timeout
            socket.write([ payload.bytesize ].pack("n") + payload)
            length = socket.read(2)&.unpack1("n")
            raise TempError, "DNS TCP reply truncated from #{server}" if length.nil?

            reply = decode(socket.read(length).to_s)
            raise TempError, "DNS TCP reply id mismatch from #{server}" unless reply&.id == id

            reply
          end
        end

        def decode(data)
          Resolv::DNS::Message.decode(data)
        rescue Resolv::DNS::DecodeError
          nil
        end
      end
    end
  end
end
