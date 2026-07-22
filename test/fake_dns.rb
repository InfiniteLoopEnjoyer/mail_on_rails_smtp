# frozen_string_literal: true

require "resolv"
require "socket"

# Scripted fake DNS server on loopback: answers each query via the block
# (query, reply, via) -> reply-ish; :drop swallows the query, a String is
# sent verbatim (for malformed-packet tests). A TCP listener on the same
# port serves the same block for truncation retries. Shared by the
# transport suite and the end-to-end temperror tests.
class FakeDns
  attr_reader :port

  def initialize(&responder)
    @udp = UDPSocket.new
    @udp.bind("127.0.0.1", 0)
    @port = @udp.addr[1]
    @tcp = TCPServer.new("127.0.0.1", @port)
    @responder = responder
    @threads = [ Thread.new { udp_loop }, Thread.new { tcp_loop } ]
  end

  def close
    @threads.each(&:kill)
    @udp.close
    @tcp.close
  end

  private

  def reply_bytes(data, via)
    query = Resolv::DNS::Message.decode(data)
    reply = Resolv::DNS::Message.new(query.id)
    reply.qr = 1
    query.each_question { |name, typeclass| reply.add_question(name, typeclass) }
    result = @responder.call(query, reply, via)
    return nil if result.equal?(:drop) # Message#== can't take a Symbol

    result.is_a?(String) ? result : result.encode
  end

  def udp_loop
    loop do
      data, addr = @udp.recvfrom(4096)
      bytes = reply_bytes(data, :udp)
      @udp.send(bytes, 0, addr[3], addr[1]) if bytes
    end
  end

  def tcp_loop
    loop do
      conn = @tcp.accept
      length = conn.read(2).unpack1("n")
      bytes = reply_bytes(conn.read(length), :tcp)
      conn.write([ bytes.bytesize ].pack("n") + bytes) if bytes
      conn.close
    end
  end
end
