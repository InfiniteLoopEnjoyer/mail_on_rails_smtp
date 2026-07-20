require "test_helper"
require "mail_on_rails/smtp/sender_auth"
require_relative "fake_resolver"

class DmarcTest < Minitest::Test
  def evaluate(records, from_domain: "example.com", spf: nil, dkim: [])
    spf ||= { result: :none, domain: nil }
    MailOnRails::Smtp::SenderAuth::Dmarc.new(FakeResolver.new(txt: records))
      .evaluate(from_domain: from_domain, spf: spf, dkim: dkim)
  end

  test "aligned dkim pass gives dmarc pass" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject" ] },
      dkim: [ { result: :pass, domain: "example.com" } ]
    )
    assert_equal :pass, result[:result]
    assert_equal :none, result[:policy]
  end

  test "aligned spf pass gives dmarc pass" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject" ] },
      spf: { result: :pass, domain: "mail.example.com" } # relaxed alignment: same org domain
    )
    assert_equal :pass, result[:result]
  end

  test "strict spf alignment rejects a subdomain" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject; aspf=s" ] },
      spf: { result: :pass, domain: "mail.example.com" }
    )
    assert_equal :fail, result[:result]
    assert_equal :reject, result[:policy]
  end

  test "nothing aligned fails with the published policy" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=quarantine" ] },
      spf: { result: :pass, domain: "elsewhere.net" },
      dkim: [ { result: :pass, domain: "elsewhere.net" } ]
    )
    assert_equal :fail, result[:result]
    assert_equal :quarantine, result[:policy]
  end

  test "no record anywhere is none" do
    result = evaluate({})
    assert_equal :none, result[:result]
    assert_equal :none, result[:policy]
  end

  test "subdomain falls back to the org domain record and sp=" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject; sp=quarantine" ] },
      from_domain: "news.example.com"
    )
    assert_equal :fail, result[:result]
    assert_equal :quarantine, result[:policy]
  end

  test "org domain respects common two-label suffixes" do
    assert_equal "example.co.uk", MailOnRails::Smtp::SenderAuth::Dmarc.org_domain("mail.example.co.uk")
    assert_equal "example.com", MailOnRails::Smtp::SenderAuth::Dmarc.org_domain("a.b.example.com")
  end

  test "missing from domain is permerror" do
    result = evaluate({}, from_domain: nil)
    assert_equal :permerror, result[:result]
    assert_equal :none, result[:policy]
  end

  test "multiple dmarc records count as no record" do
    result = evaluate({ "_dmarc.example.com" => [ "v=DMARC1; p=reject", "v=DMARC1; p=none" ] })
    assert_equal :none, result[:result]
  end

  test "pct=0 downgrades reject to quarantine" do
    result = evaluate({ "_dmarc.example.com" => [ "v=DMARC1; p=reject; pct=0" ] })
    assert_equal :fail, result[:result]
    assert_equal :quarantine, result[:policy]
  end

  test "dns failure is temperror" do
    result = evaluate({ "_dmarc.example.com" => :temperror })
    assert_equal :temperror, result[:result]
  end
end
