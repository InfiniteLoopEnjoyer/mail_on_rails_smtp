# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# RFC 5321 §4.1.3 address literals for IPv6 peers: the Received trace
# header and the DNSBL rejection name the client as "[IPv6:...]", not a
# bare "[...]" that downstream parsers would read as a malformed IPv4
# literal. The peer address is seeded the way Netserv::Server seeds it
# at accept time, so no IPv6 socket is needed.
class Ipv6LiteralTest < Minitest::Test
  EMAIL = "user@example.test"
  PEER = "2001:db8::25"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  class FakeDnsbl
    def initialize(zone) = @zone = zone
    def listed(_ip) = @zone
  end

  def with_mx_session(peer_ip:, spec_extra: {})
    store = MailOnRails::Smtp::Store::Memory.new
    store.add_account(email: EMAIL, password: "pw-123456")
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", sender_auth: false, fcrdns: nil }.merge(spec_extra)
    session = MailOnRails::SmtpServer::Session.new(session_socket, store, spec, nil)
    session.peer_ip = peer_ip
    thread = Thread.new { session.run }
    yield client
    store
  ensure
    client&.close
    thread&.join(5)
    server&.close
  end

  def read_reply(client)
    lines = []
    while (line = client.gets("\r\n"))
      lines << line
      break if line[3] == " "
    end
    lines.join
  end

  def command(client, line)
    client.write("#{line}\r\n")
    read_reply(client)
  end

  def test_received_header_tags_an_ipv6_peer
    store = with_mx_session(peer_ip: PEER) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      command(client, "RCPT TO:<#{EMAIL}>")
      command(client, "DATA")
      client.write(RAW)
      command(client, ".")
      command(client, "QUIT")
    end

    data = store.inbound_messages.last[:data]
    assert_match(/^Received: from client\.test \(\[IPv6:2001:db8::25\]\)/, data)
  end

  def test_received_header_keeps_the_plain_ipv4_literal
    store = with_mx_session(peer_ip: "203.0.113.9") do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      command(client, "RCPT TO:<#{EMAIL}>")
      command(client, "DATA")
      client.write(RAW)
      command(client, ".")
      command(client, "QUIT")
    end

    data = store.inbound_messages.last[:data]
    assert_match(/^Received: from client\.test \(\[203\.0\.113\.9\]\)/, data)
  end

  def test_dnsbl_rejection_tags_an_ipv6_peer
    with_mx_session(peer_ip: PEER, spec_extra: { dnsbl: FakeDnsbl.new("bl.test") }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      reply = command(client, "MAIL FROM:<sender@remote.test>")
      assert_match(/\A554 5\.7\.1 .*client host \[IPv6:2001:db8::25\] blocked using bl\.test/, reply)
      command(client, "QUIT")
    end
  end
end
