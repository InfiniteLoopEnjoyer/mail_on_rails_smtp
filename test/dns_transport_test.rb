# frozen_string_literal: true

require "test_helper"
require "resolv"
require "socket"
require "fake_dns"
require "mail_on_rails/smtp/sender_auth/dns"

# The hand-rolled DNS transport (UDP + TCP-on-truncation over Resolv's wire
# codec) against a scripted loopback nameserver (FakeDns, shared with the
# end-to-end temperror suite). Network-flavored outcomes (NXDOMAIN vs
# SERVFAIL vs timeout vs malformed) are the point: the old Resolv-based
# client collapsed them all into "no record".
class DnsTransportTest < Minitest::Test
  Dns = MailOnRails::Smtp::SenderAuth::Dns

  def teardown
    @fake&.close
  end

  def dns_with(timeout: 2, &responder)
    @fake = FakeDns.new(&responder)
    Dns.new(nameservers: [ "127.0.0.1" ], timeout: timeout, port: @fake.port)
  end

  def add_txt(reply, name, value)
    reply.add_answer(Resolv::DNS::Name.create(name), 300, Resolv::DNS::Resource::IN::TXT.new(value))
  end

  test "txt answers over udp" do
    dns = dns_with do |_query, reply, _via|
      add_txt(reply, "example.com.", "v=spf1 -all")
      reply
    end

    assert_equal [ "v=spf1 -all" ], dns.txt("example.com")
  end

  test "nxdomain is an empty array, not an error" do
    dns = dns_with do |_query, reply, _via|
      reply.rcode = Resolv::DNS::RCode::NXDomain
      reply
    end

    assert_empty dns.txt("nope.example.com")
  end

  test "servfail raises TempError" do
    dns = dns_with do |_query, reply, _via|
      reply.rcode = Resolv::DNS::RCode::ServFail
      reply
    end

    assert_raises(Dns::TempError) { dns.txt("example.com") }
  end

  test "timeout raises TempError" do
    dns = dns_with(timeout: 0.2) { |_q, _r, _via| :drop }

    assert_raises(Dns::TempError) { dns.a("example.com") }
  end

  test "truncated udp reply retries over tcp" do
    dns = dns_with do |_query, reply, via|
      if via == :udp
        reply.tc = 1
      else
        add_txt(reply, "example.com.", "full answer via tcp")
      end
      reply
    end

    assert_equal [ "full answer via tcp" ], dns.txt("example.com")
  end

  test "mx sorts by preference and cname chaff is filtered" do
    dns = dns_with do |_query, reply, _via|
      name = Resolv::DNS::Name.create("example.com.")
      reply.add_answer(name, 300, Resolv::DNS::Resource::IN::CNAME.new(Resolv::DNS::Name.create("alias.example.com.")))
      reply.add_answer(name, 300, Resolv::DNS::Resource::IN::MX.new(20, Resolv::DNS::Name.create("backup.example.com.")))
      reply.add_answer(name, 300, Resolv::DNS::Resource::IN::MX.new(5, Resolv::DNS::Name.create("primary.example.com.")))
      reply
    end

    assert_equal [ "primary.example.com", "backup.example.com" ], dns.mx("example.com")
  end

  test "a aaaa and ptr map record types" do
    dns = dns_with do |query, reply, _via|
      name, typeclass = query.question.first

      # Match on TypeValue: decoded question classes for class-insensitive
      # types (PTR et al) surface under Resolv's TypeN_ClassN alias names.
      case typeclass::TypeValue
      when 1 then reply.add_answer(name, 300, Resolv::DNS::Resource::IN::A.new("192.0.2.7"))
      when 28 then reply.add_answer(name, 300, Resolv::DNS::Resource::IN::AAAA.new("2001:db8::7"))
      when 12 then reply.add_answer(name, 300, Resolv::DNS::Resource::IN::PTR.new(Resolv::DNS::Name.create("mail.example.com.")))
      end
      reply
    end

    assert_equal [ "192.0.2.7" ], dns.a("mail.example.com")
    assert_equal [ "2001:db8::7" ], dns.aaaa("mail.example.com")
    assert_equal [ "mail.example.com" ], dns.ptr("192.0.2.7")
    assert_empty dns.ptr("not-an-ip")
  end

  # -- malformed packets (todo item 1 residual) ------------------------------

  test "a malformed udp reply raises TempError instead of crashing decode" do
    dns = dns_with(timeout: 0.3) { |_q, _r, _via| "\x00\x01garbage that is not DNS".b }

    assert_raises(Dns::TempError) { dns.txt("example.com") }
  end

  test "a malformed tcp reply after truncation raises TempError" do
    dns = dns_with do |_query, reply, via|
      if via == :udp
        reply.tc = 1
        reply
      else
        "these bytes decode as nothing".b
      end
    end

    assert_raises(Dns::TempError) { dns.txt("example.com") }
  end

  test "a reply with a spoofed id is ignored, ending in TempError" do
    dns = dns_with(timeout: 0.3) do |query, _reply, _via|
      forged = Resolv::DNS::Message.new((query.id + 1) & 0xffff)
      forged.qr = 1
      forged
    end

    assert_raises(Dns::TempError) { dns.txt("example.com") }
  end

  test "unreachable nameserver raises TempError" do
    closed = TCPServer.new("127.0.0.1", 0)
    port = closed.addr[1]
    closed.close
    dns = Dns.new(nameservers: [ "127.0.0.1" ], timeout: 0.3, port: port)

    assert_raises(Dns::TempError) { dns.txt("example.com") }
  end
end
