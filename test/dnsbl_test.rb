# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp/dnsbl"
require_relative "fake_resolver"

class DnsblTest < Minitest::Test
  Dnsbl = MailOnRails::Smtp::Dnsbl

  IP = "192.0.2.15"
  QUERY = "15.2.0.192.bl.test"

  # A resolver that counts lookups, for the cache tests.
  class CountingResolver
    attr_reader :calls

    def initialize(answers = {})
      @answers = answers
      @calls = 0
    end

    def a(name)
      @calls += 1
      Array(@answers[name])
    end
  end

  def checker(records = {}, zones: [ "bl.test" ])
    @now = 0.0
    Dnsbl.new(zones: zones, resolver: FakeResolver.new(records), clock: -> { @now })
  end

  test "listed ip returns the zone" do
    assert_equal "bl.test", checker({ a: { QUERY => [ "127.0.0.2" ] } }).listed(IP)
  end

  test "unlisted ip returns nil" do
    assert_nil checker.listed(IP)
  end

  test "zones are checked in order until one lists" do
    c = Dnsbl.new(zones: %w[one.test two.test],
                  resolver: FakeResolver.new(a: { "15.2.0.192.two.test" => [ "127.0.0.3" ] }))
    assert_equal "two.test", c.listed(IP)
  end

  test "dns temperror fails open" do
    assert_nil checker({ a: { QUERY => :temperror } }).listed(IP)
  end

  test "spamhaus error band is not a listing" do
    assert_nil checker({ a: { QUERY => [ "127.255.255.254" ] } }).listed(IP)
  end

  test "answers outside 127/8 are ignored (wildcard hijack)" do
    assert_nil checker({ a: { QUERY => [ "10.0.0.1", "192.0.2.80" ] } }).listed(IP)
  end

  test "ipv6 peers query nibble labels" do
    name = "#{IPAddr.new("2001:db8::1").reverse.sub(/\.ip6\.arpa\z/, "")}.bl.test"
    assert_equal "bl.test", checker({ a: { name => [ "127.0.0.2" ] } }).listed("2001:db8::1")
  end

  test "verdicts are cached per ip until the ttl expires" do
    resolver = CountingResolver.new(QUERY => [ "127.0.0.2" ])
    @now = 0.0
    c = Dnsbl.new(zones: [ "bl.test" ], resolver: resolver, ttl: 600, clock: -> { @now })

    3.times { assert_equal "bl.test", c.listed(IP) }
    assert_equal 1, resolver.calls

    @now = 601.0
    assert_equal "bl.test", c.listed(IP)
    assert_equal 2, resolver.calls
  end

  test "fail-open verdicts are cached too" do
    resolver = Class.new do
      attr_reader :calls
      def initialize = @calls = 0
      def a(_name)
        @calls += 1
        raise MailOnRails::Smtp::SenderAuth::Dns::TempError, "down"
      end
    end.new
    c = Dnsbl.new(zones: [ "bl.test" ], resolver: resolver, clock: -> { 0.0 })

    2.times { assert_nil c.listed(IP) }
    assert_equal 1, resolver.calls, "a DNS outage must not be re-probed per message"
  end

  test "loopback, private and link-local peers are never queried" do
    resolver = CountingResolver.new
    c = Dnsbl.new(zones: [ "bl.test" ], resolver: resolver)

    [ "127.0.0.1", "10.1.2.3", "192.168.1.9", "fe80::1", "::1" ].each do |ip|
      assert_nil c.listed(ip)
    end
    assert_equal 0, resolver.calls
  end

  test "an unavailable peer address returns nil" do
    assert_nil checker.listed("?") # SessionHelpers#peer_ip fallback
    assert_nil checker.listed(nil)
  end

  test "shared returns nil when no zones are configured" do
    assert_empty Dnsbl::ZONES
    assert_nil Dnsbl.shared
  end
end
