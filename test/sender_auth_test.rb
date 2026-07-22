require "test_helper"
require "mail_on_rails/smtp/sender_auth"
require_relative "fake_resolver"

class SenderAuthTest < Minitest::Test
  MESSAGE = "From: Alice <alice@example.com>\r\n" \
            "To: bob@example.org\r\n" \
            "Subject: Test\r\n" \
            "\r\n" \
            "Hi.\r\n"

  RECORDS = {
    txt: {
      "example.com" => [ "v=spf1 ip4:1.2.3.4 -all" ],
      "_dmarc.example.com" => [ "v=DMARC1; p=reject" ]
    }
  }.freeze

  def verify(ip:, records: RECORDS, data: MESSAGE)
    MailOnRails::Smtp::SenderAuth.verify(
      ip: ip, helo: "mail.example.com", mail_from: "alice@example.com",
      data: data, resolver: FakeResolver.new(records)
    )
  end

  test "legitimate sender passes spf and dmarc" do
    result = verify(ip: "1.2.3.4")
    assert_equal :pass, result.spf[:result]
    assert_equal :pass, result.dmarc[:result]
    assert_not result.dmarc_reject?
    assert_includes result.summary, "spf=pass smtp.mailfrom=example.com"
    assert_includes result.summary, "dkim=none"
    assert_includes result.summary, "dmarc=pass header.from=example.com"
  end

  test "spoofed sender fails dmarc with reject policy" do
    result = verify(ip: "6.6.6.6")
    assert_equal :fail, result.spf[:result]
    assert_equal :fail, result.dmarc[:result]
    assert result.dmarc_reject?
    assert_equal "example.com", result.from_domain
  end

  test "domain publishing nothing yields none across the board" do
    result = verify(ip: "1.2.3.4", records: { txt: {} })
    assert_equal :none, result.spf[:result]
    assert_equal :none, result.dmarc[:result]
    assert_not result.dmarc_reject?
  end

  test "from domain extraction handles display names and is nil for multiple froms" do
    assert_equal "example.com", MailOnRails::Smtp::SenderAuth.from_domain(MESSAGE)
    two_froms = MESSAGE.sub("From: Alice <alice@example.com>", "From: a@x.com, b@y.com")
    assert_nil MailOnRails::Smtp::SenderAuth.from_domain(two_froms)
    assert_nil MailOnRails::Smtp::SenderAuth.from_domain("Subject: no from\r\n\r\nhi\r\n")
  end

  test "enforcement is off unless SMTP_DMARC_ENFORCE=1" do
    assert_not MailOnRails::Smtp::SenderAuth.enforce_dmarc?
  end
end
