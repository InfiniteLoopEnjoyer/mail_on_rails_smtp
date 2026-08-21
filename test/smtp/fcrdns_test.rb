# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp/fcrdns"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"
require "fake_resolver"

# FCrDNS facts for a connecting client: PTR resolution with forward
# confirmation, plus the HELO-resolves-to-peer check. Advisory only -
# the unit half proves the verdicts and the fail-open posture, the wire
# half proves the confirmed name lands in the Received header.
class FcrDnsTest < Minitest::Test
  IP = "203.0.113.9"

  def checker(ttl: 600, **records)
    MailOnRails::Smtp::FcrDns.new(resolver: FakeResolver.new(records), ttl: ttl)
  end

  def test_confirmed_ptr_and_matching_helo
    result = checker(
      ptr: { IP => [ "mail.remote.test" ] },
      a: { "mail.remote.test" => [ IP ] }
    ).check(IP, helo: "mail.remote.test")

    assert_equal "mail.remote.test", result.ptr_name
    assert result.fcrdns
    assert_equal true, result.helo_matches
  end

  def test_unconfirmed_ptr_fails_fcrdns
    result = checker(
      ptr: { IP => [ "mail.remote.test" ] },
      a: { "mail.remote.test" => [ "198.51.100.1" ] } # PTR name points elsewhere
    ).check(IP, helo: "mail.remote.test")

    assert_nil result.ptr_name
    refute result.fcrdns
    assert_equal false, result.helo_matches
  end

  def test_missing_ptr_fails_fcrdns
    result = checker.check(IP, helo: "mail.remote.test")

    assert_nil result.ptr_name
    refute result.fcrdns
  end

  def test_second_confirmed_ptr_name_counts
    result = checker(
      ptr: { IP => [ "stale.remote.test", "mail.remote.test" ] },
      a: { "mail.remote.test" => [ IP ] }
    ).check(IP, helo: "other.test")

    assert_equal "mail.remote.test", result.ptr_name
    assert result.fcrdns
    assert_equal false, result.helo_matches, "an unrelated resolvable-nowhere HELO is a mismatch"
  end

  def test_aaaa_confirms_an_ipv6_peer
    ip = "2001:db8::25"
    result = checker(
      ptr: { ip => [ "mail.remote.test" ] },
      aaaa: { "mail.remote.test" => [ ip ] }
    ).check(ip, helo: "mail.remote.test")

    assert result.fcrdns
    assert_equal true, result.helo_matches
  end

  def test_address_literal_helo_is_unknowable_not_a_lie
    result = checker(
      ptr: { IP => [ "mail.remote.test" ] },
      a: { "mail.remote.test" => [ IP ] }
    ).check(IP, helo: "[#{IP}]")

    assert_nil result.helo_matches
  end

  def test_dns_failure_reads_as_unknown_never_a_verdict
    result = checker(
      ptr: { IP => :temperror },
      a: { "mail.remote.test" => :temperror }
    ).check(IP, helo: "mail.remote.test")

    refute result.fcrdns
    assert_nil result.helo_matches, "a DNS outage must not read as a HELO mismatch"
  end

  def test_private_and_loopback_peers_are_skipped
    c = checker
    assert_nil c.check("127.0.0.1", helo: "x.test")
    assert_nil c.check("10.0.0.1", helo: "x.test")
    assert_nil c.check("not-an-ip", helo: "x.test")
  end

  def test_verdicts_are_cached_per_ip_and_helo
    calls = 0
    counting = Object.new
    counting.define_singleton_method(:ptr) { |_ip| calls += 1; [ "mail.remote.test" ] }
    counting.define_singleton_method(:a) { |_n| [ IP ] }
    counting.define_singleton_method(:aaaa) { |_n| [] }

    fcrdns = MailOnRails::Smtp::FcrDns.new(resolver: counting)
    2.times { fcrdns.check(IP, helo: "mail.remote.test") }

    assert_equal 1, calls, "the second check must come from the cache"
  end

  # -- wire: the confirmed name decorates the Received header --------------

  EMAIL = "user@example.test"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  # spec[:fcrdns] seam: fixed facts, no DNS (the loopback peer of a wire
  # test would otherwise short-circuit to nil).
  class FixedChecker
    def initialize(result) = @result = result
    def check(_ip, helo: nil) = @result
  end

  def with_mx_session(spec_extra)
    store = MailOnRails::Smtp::Store::Memory.new
    store.add_account(email: EMAIL, password: "pw-123456")
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", sender_auth: false }.merge(spec_extra)
    thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, store, spec, nil).run }
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

  def deliver(client)
    read_reply(client)
    command(client, "EHLO client.test")
    command(client, "MAIL FROM:<sender@remote.test>")
    command(client, "RCPT TO:<#{EMAIL}>")
    command(client, "DATA")
    client.write(RAW)
    command(client, ".")
    command(client, "QUIT")
  end

  def test_received_header_carries_the_confirmed_ptr_name
    result = MailOnRails::Smtp::FcrDns::Result.new(ptr_name: "mail.remote.test", fcrdns: true, helo_matches: true)
    store = with_mx_session(fcrdns: FixedChecker.new(result)) { |client| deliver(client) }

    data = store.inbound_messages.last[:data]
    assert_match(/^Received: from client\.test \(mail\.remote\.test \[127\.0\.0\.1\]\)/, data)
  end

  def test_received_header_says_unknown_when_nothing_confirmed
    result = MailOnRails::Smtp::FcrDns::Result.new(ptr_name: nil, fcrdns: false, helo_matches: false)
    store = with_mx_session(fcrdns: FixedChecker.new(result)) { |client| deliver(client) }

    data = store.inbound_messages.last[:data]
    assert_match(/^Received: from client\.test \(unknown \[127\.0\.0\.1\]\)/, data)
  end

  def test_received_header_keeps_the_bare_address_without_facts
    store = with_mx_session(fcrdns: nil) { |client| deliver(client) }

    data = store.inbound_messages.last[:data]
    assert_match(/^Received: from client\.test \(\[127\.0\.0\.1\]\)/, data)
  end
end
