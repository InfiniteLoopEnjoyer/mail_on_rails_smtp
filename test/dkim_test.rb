require "test_helper"
require "mail_on_rails/smtp/sender_auth"
require "dkim"
require_relative "fake_resolver"

class DkimTest < Minitest::Test
  RSA_KEY = OpenSSL::PKey::RSA.new(2048)

  MESSAGE = "From: alice@example.com\r\n" \
            "To: bob@example.org\r\n" \
            "Subject: Hello  world\r\n" \
            "Date: Fri, 10 Jul 2026 12:00:00 +0000\r\n" \
            "\r\n" \
            "A test body.\r\n" \
            "With two lines.\r\n"

  def sign(message = MESSAGE, **options)
    Dkim.sign(message, domain: "example.com", selector: "test", private_key: RSA_KEY, **options).to_s
  end

  def resolver(key = RSA_KEY, extra_tags = "")
    p = [ key.public_to_der ].pack("m0")
    FakeResolver.new(txt: { "test._domainkey.example.com" => [ "v=DKIM1; k=rsa;#{extra_tags} p=#{p}" ] })
  end

  def verify(message, res = resolver)
    MailOnRails::Smtp::SenderAuth::Dkim.new(res).verify(message)
  end

  test "verifies a signature produced by the dkim gem (relaxed/relaxed)" do
    results = verify(sign)
    assert_equal 1, results.size
    assert_equal :pass, results.first[:result], results.first.inspect
    assert_equal "example.com", results.first[:domain]
  end

  test "verifies simple/simple canonicalization" do
    signed = sign(header_canonicalization: "simple", body_canonicalization: "simple")
    assert_equal :pass, verify(signed).first[:result]
  end

  test "tampered body fails with body hash mismatch" do
    tampered = sign.sub("A test body.", "An evil body.")
    result = verify(tampered).first
    assert_equal :fail, result[:result]
    assert_equal "body hash mismatch", result[:detail]
  end

  test "tampered signed header fails" do
    tampered = sign.sub("Subject: Hello  world", "Subject: Free money")
    assert_equal :fail, verify(tampered).first[:result]
  end

  test "unsigned trailing header addition still passes" do
    # Headers not listed in h= are fair game; adding one must not break
    # verification.
    assert_equal :pass, verify(sign.sub("From:", "X-Extra: hi\r\nFrom:")).first[:result]
  end

  test "missing key record is permerror" do
    result = verify(sign, FakeResolver.new(txt: {})).first
    assert_equal :permerror, result[:result]
  end

  test "revoked key (empty p=) is permerror" do
    res = FakeResolver.new(txt: { "test._domainkey.example.com" => [ "v=DKIM1; k=rsa; p=" ] })
    assert_equal :permerror, verify(sign, res).first[:result]
  end

  test "wrong key fails verification" do
    result = verify(sign, resolver(OpenSSL::PKey::RSA.new(2048))).first
    assert_equal :fail, result[:result]
  end

  test "dns failure fetching the key is temperror" do
    res = FakeResolver.new(txt: { "test._domainkey.example.com" => :temperror })
    assert_equal :temperror, verify(sign, res).first[:result]
  end

  test "message without signatures returns no results" do
    assert_empty verify(MESSAGE)
  end

  test "verifies an ed25519-sha256 signature (RFC 8463)" do
    key = OpenSSL::PKey.generate_key("ED25519")
    body = "A test body.\r\n"
    bh = [ OpenSSL::Digest::SHA256.digest(body) ].pack("m0")

    sig_value = "v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=ed; h=from:to:subject; bh=#{bh}; b="
    data = "from:alice@example.com\r\n" \
           "to:bob@example.org\r\n" \
           "subject:Hello world\r\n" \
           "dkim-signature:#{sig_value}"
    signature = key.sign(nil, OpenSSL::Digest::SHA256.digest(data))

    message = "DKIM-Signature: #{sig_value}#{[ signature ].pack("m0")}\r\n" \
              "From: alice@example.com\r\n" \
              "To: bob@example.org\r\n" \
              "Subject: Hello  world\r\n" \
              "\r\n" + body

    res = FakeResolver.new(txt: {
      "ed._domainkey.example.com" => [ "v=DKIM1; k=ed25519; p=#{[ key.raw_public_key ].pack("m0")}" ]
    })
    result = MailOnRails::Smtp::SenderAuth::Dkim.new(res).verify(message).first
    assert_equal :pass, result[:result], result.inspect
  end
end
