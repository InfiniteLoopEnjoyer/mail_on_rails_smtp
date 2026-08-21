# frozen_string_literal: true

require_relative "test_helper"
require "mail_on_rails/ingress_seal"

# Edge cases for the trust boundary, carried over from the retired HTTP
# edge's ingress stamping suite - the same guarantees, now enforced by
# SmtpBackend#stamp. The X-Original-To /
# X-MailOnRails-* / Return-Path headers on stored mail are OURS: whatever
# shape a forged copy arrives in - folded, oddly cased, bare-LF - it must
# be stripped, and no envelope/connection value may smuggle extra header
# lines into the stamp. The mailroom trusts these headers blindly, so
# every hole here is a spoofed sender or recipient there.
class SmtpStampingTest < MailOnRails::Testing::Database::TestCase
  def setup
    super
    @store = MailOnRails::Store::SmtpBackend.new
  end

  def stamp(raw, sender: "s@remote.test", auth: nil, ip: nil, helo: nil, rcpts: [ "u@local.test" ])
    @store.send(:stamp, raw, mail_from: sender, rcpt_to: rcpts,
                             authenticated_as: auth, client_ip: ip, helo: helo)
  end

  test "folded forged trust header is stripped with its continuation" do
    forged = "X-MailOnRails-Authenticated: yes\r\n but-actually-forged-continuation\r\n" \
             "From: a@b.test\r\n\r\nbody\r\n"
    stamped = stamp(forged)

    refute_includes stamped, "but-actually-forged-continuation",
                    "a folded forged header must lose its continuation lines too"
    assert_includes stamped, "X-MailOnRails-Authenticated: no\r\n"
    assert_includes stamped, "From: a@b.test"
  end

  test "mixed-case forged trust headers are stripped" do
    forged = "x-mailonrails-authenticated: admin@local.test\r\n" \
             "X-MAILONRAILS-CLIENT-IP: 6.6.6.6\r\n" \
             "x-original-to: victim@local.test\r\n" \
             "return-path: <fake@local.test>\r\n" \
             "From: a@b.test\r\n\r\nbody\r\n"
    stamped = stamp(forged)

    refute_includes stamped.downcase, "admin@local.test"
    refute_includes stamped.downcase, "victim@local.test"
    refute_includes stamped.downcase, "fake@local.test"
    refute_match(/6\.6\.6\.6/, stamped)
  end

  test "bare-LF forged trust headers are stripped" do
    forged = "X-MailOnRails-Authenticated: forged@local.test\nFrom: a@b.test\n\nbody\n"
    stamped = stamp(forged)

    refute_includes stamped, "forged@local.test"
    assert_includes stamped, "From: a@b.test"
  end

  test "lookalike headers are kept" do
    lookalikes = "X-Original-To-Backup: keep-me-1\r\n" \
                 "X-MailOnRailsish: keep-me-2\r\n" \
                 "NotReturn-Path: keep-me-3\r\n" \
                 "From: a@b.test\r\n\r\nbody\r\n"
    stamped = stamp(lookalikes)

    assert_includes stamped, "keep-me-1"
    assert_includes stamped, "keep-me-2"
    assert_includes stamped, "keep-me-3"
  end

  test "body occurrences of trust headers are left alone" do
    body_hit = "From: a@b.test\r\n\r\nquoting a header X-MailOnRails-Authenticated: admin in the body\r\n"
    stamped = stamp(body_hit)

    assert_includes stamped, "quoting a header X-MailOnRails-Authenticated: admin in the body"
  end

  test "envelope values cannot inject header lines" do
    stamped = stamp("From: a@b.test\r\n\r\nbody\r\n",
                    sender: "evil@x.test>\r\nX-MailOnRails-Authenticated: super-admin",
                    rcpts: [ "u@local.test\r\nBcc: hidden@x.test" ])

    refute_match(/^X-MailOnRails-Authenticated: super-admin/, stamped)
    refute_match(/^Bcc:/, stamped)
    # The CR/LF collapses to spaces inside the legitimate header's value.
    # Return-Path is the first stamped header after the leading seal line.
    assert_match(/^Return-Path: <evil@x\.test> +X-MailOnRails-Authenticated: super-admin>\r\n/, stamped)
  end

  test "the stamped message carries a valid ingress seal over its own bytes" do
    stamped = stamp("From: a@b.test\r\n\r\nbody\r\n", auth: "bob@local.test")

    assert_match(/\AX-MailOnRails-Seal: /, stamped, "the seal must be the first physical line")
    assert MailOnRails::IngressSeal.verify(stamped), "the edge's own seal must verify"
  end

  test "a forged seal in the submitted DATA is stripped and replaced" do
    forged = "X-MailOnRails-Seal: v1; t=1; d=deadbeef\r\nFrom: a@b.test\r\n\r\nbody\r\n"
    stamped = stamp(forged)

    refute_includes stamped, "deadbeef", "the forged seal must not survive stamping"
    assert MailOnRails::IngressSeal.verify(stamped), "the edge re-seals with its own key"
  end

  test "forwarded ip and helo are stamped and forged copies stripped" do
    forged = "X-MailOnRails-Client-Ip: 1.1.1.1\r\nX-MailOnRails-Helo: liar.test\r\n" \
             "From: a@b.test\r\n\r\nbody\r\n"
    stamped = stamp(forged, ip: "203.0.113.9", helo: "real-mx.remote.test")

    assert_includes stamped, "X-MailOnRails-Client-Ip: 203.0.113.9\r\n"
    assert_includes stamped, "X-MailOnRails-Helo: real-mx.remote.test\r\n"
    refute_includes stamped, "1.1.1.1"
    refute_includes stamped, "liar.test"
  end

  test "ip and helo values cannot inject header lines" do
    stamped = stamp("From: a@b.test\r\n\r\nbody\r\n",
                    ip: "203.0.113.9\r\nX-Injected: yes",
                    helo: "mx.test\r\nBcc: hidden@x.test")

    refute_match(/^X-Injected:/, stamped)
    refute_match(/^Bcc:/, stamped)
  end

  test "absent ip and helo emit no such headers" do
    stamped = stamp("From: a@b.test\r\n\r\nbody\r\n")

    refute_match(/^X-MailOnRails-Client-Ip:/, stamped)
    refute_match(/^X-MailOnRails-Helo:/, stamped)
  end

  test "authenticated identity is stamped" do
    stamped = stamp("From: a@b.test\r\n\r\nbody\r\n", auth: "bob@local.test")

    assert_includes stamped, "X-MailOnRails-Authenticated: bob@local.test\r\n"
  end

  test "one X-Original-To per recipient" do
    stamped = stamp("From: a@b.test\r\n\r\nbody\r\n", rcpts: [ "a@local.test", "b@local.test" ])

    assert_includes stamped, "X-Original-To: a@local.test\r\n"
    assert_includes stamped, "X-Original-To: b@local.test\r\n"
  end

  test "every stamped header line is CRLF-terminated and printable" do
    stamped = stamp("From: a@b.test\r\n\r\nbody\r\n",
                    sender: "s@remote.test", auth: "auth@local.test",
                    ip: "203.0.113.9", helo: "mx.remote.test")
    header_block = stamped.split("\r\n\r\n", 2).first

    header_block.split("\r\n").each do |line|
      assert_match(/\A[\x20-\x7e]+\z/, line, "header line #{line.inspect} contains raw control bytes")
    end
  end
end
