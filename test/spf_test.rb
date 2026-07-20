require "test_helper"
require "mail_on_rails/smtp/sender_auth"
require_relative "fake_resolver"

class SpfTest < Minitest::Test
  def check(records, ip: "1.2.3.4", sender: "bob@example.com", helo: "mail.example.com")
    MailOnRails::Smtp::SenderAuth::Spf.new(FakeResolver.new(records)).check(ip: ip, sender: sender, helo: helo)
  end

  test "ip4 match passes" do
    result = check({ txt: { "example.com" => [ "v=spf1 ip4:1.2.3.4 -all" ] } })
    assert_equal :pass, result[:result]
    assert_equal "example.com", result[:domain]
  end

  test "ip4 cidr match passes" do
    result = check({ txt: { "example.com" => [ "v=spf1 ip4:1.2.3.0/24 -all" ] } })
    assert_equal :pass, result[:result]
  end

  test "-all fails an unlisted ip" do
    result = check({ txt: { "example.com" => [ "v=spf1 ip4:9.9.9.9 -all" ] } })
    assert_equal :fail, result[:result]
  end

  test "~all softfails and ?all is neutral" do
    assert_equal :softfail, check({ txt: { "example.com" => [ "v=spf1 ~all" ] } })[:result]
    assert_equal :neutral, check({ txt: { "example.com" => [ "v=spf1 ?all" ] } })[:result]
  end

  test "no record is none" do
    assert_equal :none, check({ txt: {} })[:result]
  end

  test "multiple spf records is permerror" do
    result = check({ txt: { "example.com" => [ "v=spf1 -all", "v=spf1 +all" ] } })
    assert_equal :permerror, result[:result]
  end

  test "a mechanism resolves the domain" do
    result = check({
      txt: { "example.com" => [ "v=spf1 a -all" ] },
      a: { "example.com" => [ "1.2.3.4" ] }
    })
    assert_equal :pass, result[:result]
  end

  test "mx mechanism resolves mail hosts" do
    result = check({
      txt: { "example.com" => [ "v=spf1 mx -all" ] },
      mx: { "example.com" => [ "mx1.example.com" ] },
      a: { "mx1.example.com" => [ "1.2.3.4" ] }
    })
    assert_equal :pass, result[:result]
  end

  test "include matches when the included record passes" do
    result = check({ txt: {
      "example.com" => [ "v=spf1 include:_spf.example.net -all" ],
      "_spf.example.net" => [ "v=spf1 ip4:1.2.3.4 -all" ]
    } })
    assert_equal :pass, result[:result]
  end

  test "include that fails does not match but evaluation continues" do
    result = check({ txt: {
      "example.com" => [ "v=spf1 include:_spf.example.net ~all" ],
      "_spf.example.net" => [ "v=spf1 -all" ]
    } })
    assert_equal :softfail, result[:result]
  end

  test "redirect hands evaluation to another domain" do
    result = check({ txt: {
      "example.com" => [ "v=spf1 redirect=_spf.example.net" ],
      "_spf.example.net" => [ "v=spf1 ip4:1.2.3.4 -all" ]
    } })
    assert_equal :pass, result[:result]
  end

  test "macro expansion in exists" do
    result = check({
      txt: { "example.com" => [ "v=spf1 exists:%{ir}.%{v}.spf.example.com -all" ] },
      a: { "4.3.2.1.in-addr.spf.example.com" => [ "127.0.0.2" ] }
    })
    assert_equal :pass, result[:result]
  end

  test "self-referencing include hits the lookup limit" do
    result = check({ txt: { "example.com" => [ "v=spf1 include:example.com -all" ] } })
    assert_equal :permerror, result[:result]
  end

  test "too many void lookups is permerror" do
    result = check({ txt: { "example.com" => [ "v=spf1 exists:a.x.com exists:b.x.com exists:c.x.com -all" ] } })
    assert_equal :permerror, result[:result]
  end

  test "empty mail from falls back to postmaster at helo" do
    result = check(
      { txt: { "mail.example.com" => [ "v=spf1 ip4:1.2.3.4 -all" ] } },
      sender: ""
    )
    assert_equal :pass, result[:result]
    assert_equal "mail.example.com", result[:domain]
  end

  test "dns failure is temperror" do
    result = check({ txt: { "example.com" => :temperror } })
    assert_equal :temperror, result[:result]
  end

  test "ipv6 client against ip6 mechanism" do
    result = check(
      { txt: { "example.com" => [ "v=spf1 ip6:2001:db8::/32 -all" ] } },
      ip: "2001:db8::25"
    )
    assert_equal :pass, result[:result]
  end
end
