# frozen_string_literal: true

require "test_helper"
require "resolv"
require "socket"
require "fake_dns"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# End-to-end DNS outage behavior (todo item 1 residual): when every lookup
# fails at the real transport (SERVFAIL from a live loopback nameserver),
# verification must degrade to temperror verdicts - visible in the stamped
# Authentication-Results - and the message must still be accepted. A DNS
# outage may never bounce mail or take a session down.
class SenderAuthTemperrorTest < Minitest::Test
  EMAIL = "user@example.test"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody\r\n"

  def setup
    @fake = FakeDns.new do |_query, reply, _via|
      reply.rcode = Resolv::DNS::RCode::ServFail
      reply
    end
    @resolver = MailOnRails::Smtp::SenderAuth::Dns.new(
      nameservers: [ "127.0.0.1" ], timeout: 1, port: @fake.port
    )
  end

  def teardown
    @fake.close
  end

  def test_verify_degrades_to_temperror_verdicts_under_servfail
    result = MailOnRails::Smtp::SenderAuth.verify(
      ip: "192.0.2.9", helo: "client.test", mail_from: "sender@remote.test",
      data: RAW, resolver: @resolver
    )

    assert_match(/spf=temperror/, result.summary)
    assert_match(/dmarc=temperror/, result.summary)
  end

  def test_session_accepts_and_stamps_temperror_when_dns_is_down
    store = MailOnRails::Smtp::Store::Memory.new
    store.add_account(email: EMAIL, password: "pw-123456")

    # Route the session's verification through the failing resolver; the
    # rest of SenderAuth.verify runs for real.
    singleton = MailOnRails::Smtp::SenderAuth.singleton_class
    original = MailOnRails::Smtp::SenderAuth.method(:verify)
    resolver = @resolver
    singleton.define_method(:verify) { |**kwargs| original.call(**kwargs, resolver: resolver) }

    begin
      server = TCPServer.new("127.0.0.1", 0)
      client = TCPSocket.new("127.0.0.1", server.addr[1])
      client.timeout = 5
      session_socket = server.accept
      spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: :mx, hostname: "mx.test" }
      thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, store, spec, nil).run }

      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      command(client, "RCPT TO:<#{EMAIL}>")
      command(client, "DATA")
      client.write(RAW)

      assert_match(/\A250 OK: queued/, command(client, "."),
                   "a DNS outage must not tempfail or reject the message")
      command(client, "QUIT")
      client.close
      thread.join(5)
      server.close
    ensure
      singleton.define_method(:verify, original)
    end

    message = store.inbound_messages.last

    refute_nil message
    assert_match(/spf=temperror/, message[:auth_results])
    assert_match(/dmarc=temperror/, message[:auth_results])
  end

  private

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
end
