# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "logger"
require "stringio"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"
require "mail_on_rails/sender_auth"
require "mail_on_rails/outbound_data"
require "fake_resolver"

# Regression coverage for the CVE classes an SMTP server is judged against,
# each test driving the real production path (no mocks of the code under
# test). The classes and their representative CVEs:
#
#   crlf_header_inject  - CVE-2026-23829, CVE-2026-45067, CVE-2025-59419:
#                         attacker-controlled envelope/EHLO values must not
#                         inject CR/LF into generated headers or reply lines.
#   address_parse       - CVE-2003-0540, CVE-2000-1129: hostile envelope
#                         addresses (source routes, percent-hack) must parse
#                         consistently between the RCPT ACL and delivery so
#                         they cannot become an open relay.
#   cmd_injection       - CVE-2011-0411 (STARTTLS plaintext injection) and
#                         the CRLF-in-command SMTP-command-injection family.
#   spoofing_dmarc      - CVE-2025-61084, duplicate-From evasion: a forged
#                         From: must not be able to ride a passing SPF into a
#                         DMARC pass.
#   cert_validation     - CVE-2026-46428 (lettre), CVE-2020-1758 (Keycloak):
#                         as an SMTP client, verified-TLS policy must keep
#                         VERIFY_PEER + hostname verification on.
class SmtpCveContentTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: #{EMAIL}\r\nSubject: hi\r\n\r\nbody line\r\n"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(StringIO.new))
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  # -- wire harness (plaintext), copied from the sibling suites ---------------

  def with_session(role: :mx, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: role,
             hostname: "mx.test", sender_auth: false, clamav_addr: "" }.merge(spec_extra)
    thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, nil).run }
    yield client
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

  # A detached Session over a socketpair, for exercising the header/reply
  # builders directly (no server, no live peer).
  def bare_session(spec_extra: {})
    sock, other = UNIXSocket.pair
    @sockets ||= []
    @sockets << sock << other
    spec = { tls: :starttls, role: :mx, hostname: "mx.test" }.merge(spec_extra)
    session = MailOnRails::SmtpServer::Session.new(sock, @store, spec, nil)
    session.peer_ip = "203.0.113.7"
    session
  end

  def teardown
    Array(@sockets).each { |s| s.close rescue nil }
  end

  # =========================================================================
  # Class: crlf_header_inject
  # =========================================================================

  # The generated RFC 5321 Received: trace header echoes the client's EHLO
  # name. The HELO parser's charset gate already blocks CR/LF, but
  # received_header sanitizes again as defense-in-depth: even a @helo_name
  # smuggled past the gate must not break out of the single trace header.
  def test_received_trace_header_cannot_be_crlf_injected_via_helo_name
    session = bare_session
    session.instance_variable_set(:@helo_name, "evil.test\r\nX-Injected: pwned\r\n\r\ninjected body")
    header = session.send(:received_header)

    assert_equal 2, header.scan("\r\n").size,
                 "the trace header must be exactly two wire lines, whatever the helo held"
    refute_match(/\r\nX-Injected/i, header, "no injected header line may appear")
    refute_match(/\r\n\r\n/, header, "no premature header/body separator may be injected")
    # Everything the second line begins with a fold (tab), so the whole thing
    # is one logical header field.
    fields = header.split(/\r\n(?![ \t])/).reject(&:empty?)
    assert_equal 1, fields.size, "the Received: value must remain a single header field"
  end

  # The reply builder flattens every non-printable byte before the wire, so
  # echoed client input can never open a second reply line (CVE-2025-59419
  # shape: CR/LF folded into a protocol line the server emits).
  def test_reply_sanitizer_flattens_cr_lf_and_control_bytes
    session = bare_session
    assert_equal "ok  injected value",
                 session.send(:sanitize_reply, "ok\r\ninjected\tvalue")
    refute_match(/[\r\n]/, session.send(:sanitize_reply, "250\r\nMAIL FROM:<evil>"))
  end

  # =========================================================================
  # Class: address_parse
  # =========================================================================

  # An obsolete source route to a foreign domain must be read as a foreign
  # (unhosted) recipient by the RCPT ACL - never accepted as local - so it
  # is refused as relaying rather than delivered or relayed.
  def test_mx_source_routed_recipient_is_refused_as_relaying
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      reply = command(client, "RCPT TO:<@relay.test:victim@foreign.test>")
      assert_match(/\A550 5\.7\.1 Relaying denied/, reply,
                   "a source-routed foreign recipient must not be accepted or relayed")
      command(client, "QUIT")
    end

    assert_empty @store.inbound_messages
    assert_empty @store.outbound_messages
  end

  # The classic percent-hack (user%elsewhere@hosted): the local part is not
  # the real account, so the RCPT ACL must treat it as an unknown user in the
  # hosted domain (5.1.1) - it must never route to the smuggled "elsewhere".
  def test_mx_percent_hack_recipient_is_an_unknown_local_user_not_a_relay
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      reply = command(client, "RCPT TO:<user%evil.test@example.test>")
      assert_match(/\A550 5\.1\.1 No such user here/, reply,
                   "the percent local-part must not resolve to the real account or relay off-domain")
      command(client, "QUIT")
    end

    assert_empty @store.inbound_messages
    assert_empty @store.outbound_messages
  end

  # When an authenticated sender does queue a percent-hack recipient, the
  # delivery layer must route by the true (final) domain - remote.test - and
  # not by the smuggled "evil.test" embedded in the local part. This is the
  # parse-consistency property between the ACL and the spool.
  def test_authenticated_percent_hack_routes_by_final_domain_not_the_smuggled_one
    with_session(role: :submission, spec_extra: { tls: :implicit }) do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      token = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
      assert_match(/\A235/, command(client, "AUTH PLAIN #{token}"))
      command(client, "MAIL FROM:<#{EMAIL}>")
      assert_match(/\A250/, command(client, "RCPT TO:<victim%evil.test@remote.test>"))
      assert_match(/\A354/, command(client, "DATA"))
      client.write(RAW)
      assert_match(/\A250 2\.0\.0 Ok: queued/, command(client, "."))
      command(client, "QUIT")
    end

    queued = @store.outbound_messages.last
    assert queued, "the authenticated submission must be queued for outbound delivery"
    assert_equal "victim%evil.test@remote.test", queued[:recipient],
                 "the recipient must be spooled verbatim, not rewritten"
    assert_equal "remote.test", queued[:recipient].split("@").last,
                 "delivery routes by the final domain, so the percent-hack cannot redirect it"
  end

  # =========================================================================
  # Class: cmd_injection
  # =========================================================================

  # CVE-2011-0411 / CVE-2021-33515 (STARTTLS plaintext command injection): a
  # command pipelined in the same segment as STARTTLS, before the handshake,
  # must never be executed inside the encrypted session. Either the buffered
  # plaintext breaks the handshake (connection drops), or the handshake
  # completes and the injected command was discarded - both are secure.
  def test_starttls_pipelined_plaintext_command_is_not_executed
    listener = TCPServer.new("127.0.0.1", 0)
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", tcp_server: listener, sender_auth: false, clamav_addr: "" }
    thread = Thread.new { MailOnRails::SmtpServer.run(@store, [ spec ], self.class.tls_material) }
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5

    assert_match(/\A220 /, read_reply(client))
    assert_match(/STARTTLS/, command(client, "EHLO client.test"))

    # Pipeline the STARTTLS and a plaintext EHLO in one write, then read the
    # go-ahead and attempt the handshake.
    client.write("STARTTLS\r\nEHLO injected.test\r\n")
    assert_match(/\A220 /, read_reply(client))

    tls = OpenSSL::SSL::SSLSocket.new(client, OpenSSL::SSL::SSLContext.new)
    tls.sync_close = true
    injected_executed = nil
    begin
      tls.connect
      # Handshake completed: the injected EHLO must have been dropped, so a
      # MAIL FROM with no fresh EHLO is answered 503 (EHLO required).
      reply = command(tls, "MAIL FROM:<a@b.test>")
      injected_executed = !reply.start_with?("503")
      assert_match(/\A503/, reply,
                   "the pre-handshake EHLO must have been discarded (RFC 3207)")
      command(tls, "QUIT")
    rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
      # The buffered plaintext desynchronized the handshake and the
      # connection dropped: the injected command was never reachable.
      injected_executed = false
    end

    refute injected_executed, "a plaintext command injected before the handshake must not run"
  ensure
    tls&.close rescue nil
    client&.close rescue nil
    thread&.kill
    listener&.close rescue nil
  end

  # The OS-command-injection family (Exim CVE-2019-10149 shape) does not apply
  # to the SMTP mail path: no attacker-derived string is ever passed to a
  # shell/exec (verified by audit - the only shell use in the gem is the
  # dev-only clamav Puma plugin, on a fixed container name). There is no
  # runtime behaviour to drive, so it is reported as a finding rather than
  # asserted here.

  # =========================================================================
  # Class: spoofing_dmarc
  # =========================================================================

  # CVE-2025-61084 / duplicate-From evasion: a message with two From: headers
  # (a legitimate one plus a spoofed one) has no single DMARC subject. Even
  # when SPF passes for the envelope domain, DMARC must NOT come back pass -
  # the forged header cannot borrow the envelope's authorization.
  def test_duplicate_from_header_cannot_ride_spf_into_a_dmarc_pass
    records = {
      txt: {
        "example.com" => [ "v=spf1 ip4:1.2.3.4 -all" ],
        "_dmarc.example.com" => [ "v=DMARC1; p=reject" ]
      }
    }
    spoofed = "From: alice@example.com\r\n" \
              "From: attacker@evil.test\r\n" \
              "To: bob@example.org\r\nSubject: hi\r\n\r\nbody\r\n"

    result = MailOnRails::SenderAuth.verify(
      ip: "1.2.3.4", helo: "mail.example.com", mail_from: "alice@example.com",
      data: spoofed, resolver: FakeResolver.new(records)
    )

    assert_equal :pass, result.spf[:result], "SPF still passes for the envelope domain"
    refute_equal :pass, result.dmarc[:result],
                 "a duplicate/forged From: must never yield a DMARC pass"
    assert_equal :permerror, result.dmarc[:result],
                 "no single From: subject makes DMARC a permerror, not a pass"
  end

  # The wire half of the same class: permerror was never a pass, but it was
  # never p=reject either - so an enforcing MX accepted the duplicate-From
  # message that enforcement exists to refuse. Under SMTP_DMARC_ENFORCE=1
  # the session now answers 550 before any verification runs.
  def test_duplicate_from_header_is_refused_at_data_under_dmarc_enforcement
    previous = ENV["SMTP_DMARC_ENFORCE"]
    ENV["SMTP_DMARC_ENFORCE"] = "1"
    singleton = MailOnRails::SenderAuth.singleton_class
    original = MailOnRails::SenderAuth.method(:verify)
    singleton.define_method(:verify) { |**| raise "verification must not be reached" }

    with_session(spec_extra: { sender_auth: true }) do |client|
      read_reply(client)
      command(client, "EHLO mail.example.com")
      command(client, "MAIL FROM:<alice@example.com>")
      command(client, "RCPT TO:<#{EMAIL}>")
      command(client, "DATA")
      client.write("From: alice@example.com\r\nFrom: attacker@evil.test\r\nSubject: hi\r\n\r\nbody\r\n")
      assert_match(/\A550 5\.7\.1 /, command(client, "."))
      command(client, "QUIT")
    end

    assert_empty @store.inbound_messages, "the spoof must not be spooled"
  ensure
    singleton.define_method(:verify, original)
    previous ? ENV["SMTP_DMARC_ENFORCE"] = previous : ENV.delete("SMTP_DMARC_ENFORCE")
  end

  # =========================================================================
  # Class: cert_validation (outbound SMTP client TLS policy)
  # =========================================================================
  #
  # The outbound deliverer lives in the gem's engine (app/models); its full
  # DANE/MTA-STS behaviour is exercised by the admin app's
  # outbound_deliverer_test.rb / dane_test.rb. Here we pin the TLS-context
  # policy itself, which is what CVE-2026-46428 (lettre) and CVE-2020-1758
  # (Keycloak) got wrong: verified transports must keep VERIFY_PEER and
  # hostname verification on.

  def load_outbound_deliverer
    require File.join(Gem.loaded_specs.fetch("mail_on_rails").full_gem_path, "app/models/mail_on_rails/outbound_deliverer") # core model
    MailOnRails::OutboundDeliverer.new(dns: Object.new)
  rescue LoadError => e
    skip "outbound deliverer unavailable in this harness: #{e.message}"
  end

  def test_outbound_verified_context_keeps_peer_and_hostname_verification
    deliverer = load_outbound_deliverer
    ctx = deliverer.send(:pkix_ssl_context)

    assert_equal OpenSSL::SSL::VERIFY_PEER, ctx.verify_mode,
                 "MTA-STS/verified STARTTLS must verify the peer chain"
    assert_equal true, ctx.verify_hostname,
                 "hostname verification must stay on (the lettre CVE-2026-46428 bug)"
    ciphers = ctx.ciphers.map(&:first)
    assert ciphers.any? { |c| c.include?("GCM") || c.include?("CHACHA") },
           "the hardened context must offer AEAD suites"
    refute ciphers.any? { |c| c.include?("CBC") },
           "the hardened context must not offer CBC suites"
  end

  # DANE deliberately runs VERIFY_NONE at the OpenSSL layer because DaneSmtp
  # pins the chain against the TLSA records itself right after the handshake.
  # This documents that the WebPKI knobs are off *by design* here, paired
  # with the explicit Dane.verify! - not a silent disablement.
  def test_outbound_dane_context_defers_to_tlsa_pinning
    deliverer = load_outbound_deliverer
    ctx = deliverer.send(:dane_ssl_context)

    assert_equal OpenSSL::SSL::VERIFY_NONE, ctx.verify_mode,
                 "DANE accepts any chain at the TLS layer; the TLSA match is enforced in DaneSmtp"
    assert_equal false, ctx.verify_hostname
    refute ctx.ciphers.map(&:first).any? { |c| c.include?("CBC") },
           "even the DANE context is pinned to AEAD suites"
  end

  def self.tls_material
    @tls_material ||= MailOnRails::Netserv::Tls.generate_self_signed
  end
end
