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

  # A lone CR is one byte to a \r?\n field split but a line break to the
  # Mail gem (to_crlf rewrites it), so "Subject: hi\rX-Original-To: victim"
  # used to survive as a Subject here and arrive at the mailroom as a
  # second, sealed X-Original-To - delivery into any local mailbox from
  # port 25, and a fan-out past MAX_RECIPIENTS when repeated.
  test "lone-CR spliced forged trust headers are stripped" do
    forged = "Subject: hi\rX-Original-To: victim@local.test\r\n" \
             "X-Original-To: victim2@local.test\rX-MailOnRails-Authenticated: admin@local.test\r\n" \
             "From: a@b.test\r\n\r\nbody\r\n"
    stamped = stamp(forged, sender: "s@remote.test", rcpts: [ "u@local.test" ])
    mail = Mail.new(stamped)

    assert_equal [ "u@local.test" ], Array(mail["X-Original-To"]).map(&:value)
    assert_equal "no", Array(mail["X-MailOnRails-Authenticated"]).map(&:value).join
    refute_match(/victim|admin@local/, stamped)
    assert_includes stamped, "Subject: hi\r\n"
    assert_includes stamped, "From: a@b.test"
  end

  test "stamped output carries no lone CR or bare LF" do
    stamped = stamp("Subject: a\rb\nc\r\nFrom: a@b.test\r\n\r\nline\rline\nline\r\n")

    refute_match(/\r(?!\n)|(?<!\r)\n/, stamped)
    assert_includes stamped, "Subject: a\r\nb\r\nc\r\n"
    assert_includes stamped, "line\r\nline\r\nline\r\n"
    assert MailOnRails::IngressSeal.verify(stamped), "the seal covers the canonical bytes"
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

  # RFC 5322 obs-syntax: the Mail gem (and so the mailroom) reads
  # "Name<WSP>:" as the field Name, so "X-Original-To : victim" would have
  # routed to any local mailbox and "Return-Path : <x>" aimed vacation
  # replies at x. Only the edge's own values may reach the parser.
  test "trust headers with whitespace before the colon are stripped" do
    forged = "X-Original-To : victim1@local.test\r\n" \
             "X-Original-To\t: victim2@local.test\r\n" \
             "X-Original-To \t : victim3@local.test\r\n" \
             "Return-Path : <forged1@evil.test>\r\n" \
             "Return-Path\t\t: <forged2@evil.test>\r\n" \
             "X-MailOnRails-Authenticated : admin@local.test\r\n" \
             "X-MailOnRails-Client-Ip\t: 6.6.6.6\r\n" \
             "From: a@b.test\r\n\r\nbody\r\n"
    stamped = stamp(forged, sender: "s@remote.test", rcpts: [ "u@local.test" ])
    mail = Mail.new(stamped)

    assert_equal [ "u@local.test" ], Array(mail["X-Original-To"]).map(&:value)
    assert_equal "<s@remote.test>", Array(mail["Return-Path"]).map(&:value).join
    assert_equal "no", Array(mail["X-MailOnRails-Authenticated"]).map(&:value).join
    refute_match(/victim\d|forged\d|admin@local|6\.6\.6\.6/, stamped)
    assert_includes stamped, "From: a@b.test"
  end

  test "a fold between the name and the colon is stripped with its continuation" do
    forged = "X-Original-To\r\n : victim@local.test\r\n" \
             "Return-Path\r\n\t: <forged@evil.test>\r\n" \
             "From: a@b.test\r\n\r\nbody\r\n"
    stamped = stamp(forged, sender: "s@remote.test", rcpts: [ "u@local.test" ])

    refute_includes stamped, "victim@local.test"
    refute_includes stamped, "forged@evil.test"
    assert_equal [ "u@local.test" ], Array(Mail.new(stamped)["X-Original-To"]).map(&:value)
  end

  # The Mail gem ends a field name with Ruby's rstrip - NUL, TAB, LF, VT,
  # FF, CR, SP - so "X-Original-To\v: victim" is an X-Original-To to the
  # mailroom. With only [ \t]* tolerated before the colon the strip kept
  # it and the seal covered it: delivery into any local mailbox from one
  # valid RCPT, and a forged Return-Path that replaced the stamped one
  # (the gem collapses that field, last wins).
  GAPS = [ "\v", "\f", "\x00", "\x01", "\x1f", "\x7f", "\xA0".b, " \v", "\v ", "\f\t\v", "\xC2\xA0".b ].freeze

  test "trust headers with a control or other non-printable byte before the colon are stripped" do
    GAPS.each do |gap|
      forged = "From: a@b.test\r\n" \
               "X-Original-To#{gap}: victim@local.test\r\n" \
               "Return-Path#{gap}: <forged@evil.test>\r\n" \
               "X-MailOnRails-Authenticated#{gap}: admin@local.test\r\n" \
               "X-MailOnRails-Client-Ip#{gap}: 6.6.6.6\r\n" \
               "X-MailOnRails-Helo#{gap}: liar.test\r\n" \
               "X-MailOnRails-Seal#{gap}: v1; t=1; d=deadbeef\r\n" \
               "Subject: hi\r\n\r\nbody\r\n"
      stamped = stamp(forged.b, sender: "s@remote.test", rcpts: [ "u@local.test" ], ip: "203.0.113.9", helo: "mx.remote.test")
      mail = Mail.new(stamped)

      assert_equal [ "u@local.test" ], Array(mail["X-Original-To"]).map(&:value), "gap #{gap.inspect}"
      assert_equal [ "<s@remote.test>" ], Array(mail["Return-Path"]).map(&:value), "gap #{gap.inspect}"
      assert_equal [ "no" ], Array(mail["X-MailOnRails-Authenticated"]).map(&:value), "gap #{gap.inspect}"
      assert_equal [ "203.0.113.9" ], Array(mail["X-MailOnRails-Client-Ip"]).map(&:value), "gap #{gap.inspect}"
      refute_match(/victim|forged|admin@local|6\.6\.6\.6|liar\.test|deadbeef/, stamped, "gap #{gap.inspect}")
      assert_includes stamped, "Subject: hi\r\n"
      assert MailOnRails::IngressSeal.verify(stamped)
    end
  end

  test "trust headers with a byte in front of the name are stripped" do
    [ "\v", "\f", "\x01", "\x7f" ].each do |gap|
      forged = "From: a@b.test\r\n#{gap}X-Original-To: victim@local.test\r\n#{gap}Return-Path : <forged@evil.test>\r\n\r\nbody\r\n"
      stamped = stamp(forged.b)

      refute_match(/victim|forged/, stamped, "gap #{gap.inspect}")
    end
  end

  # stamp prepends its headers to whatever it is given. A first line that
  # opens with WSP would read as the continuation of the last stamped
  # header - "X-MailOnRails-Authenticated: no" + " admin@local.test" is an
  # authenticated sender to the mailroom. The session always puts its
  # Received header first; the stamp must not depend on that.
  test "leading whitespace cannot continue the last stamped header" do
    [ " admin@local.test\r\n", "\t\r\n admin@local.test\r\n", "\r\n admin@local.test\r\n" ].each do |opening|
      stamped = stamp("#{opening}From: a@b.test\r\n\r\nbody\r\n")
      mail = Mail.new(stamped)

      assert_equal [ "no" ], Array(mail["X-MailOnRails-Authenticated"]).map(&:value), opening.inspect
      assert_equal [ "u@local.test" ], Array(mail["X-Original-To"]).map(&:value), opening.inspect
      assert_match(/^X-MailOnRails-Authenticated: no\r\n(?![ \t])/, stamped, opening.inspect)
    end
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
