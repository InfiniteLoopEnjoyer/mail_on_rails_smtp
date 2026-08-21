# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# Pins the advertised capability surface documented in
# docs/smtp_capability_matrix.md (todo item 15): what EHLO announces in
# each channel state, and what unsupported commands answer. A change here
# must update the matrix, and vice versa.
class SmtpCapabilityTest < Minitest::Test
  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
  end

  def with_session(tls: :starttls, role: :mx, tls_ctx: nil, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: tls, role: role, hostname: "mx.test" }.merge(spec_extra)
    thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, tls_ctx).run }
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

  def ehlo_extensions(client)
    read_reply(client)
    command(client, "EHLO client.test").split("\r\n").drop(1).map { |l| l[4..] }
  end

  def tls_ctx
    @@tls_ctx ||= MailOnRails::Netserv::Tls.context(MailOnRails::Netserv::Tls.generate_self_signed)
  end

  BASE_SET = [ "SIZE #{MailOnRails::SmtpServer::MAX_MESSAGE_BYTES}", "8BITMIME", "PIPELINING",
               "ENHANCEDSTATUSCODES", "CHUNKING",
               "LIMITS RCPTMAX=#{MailOnRails::SmtpServer::MAX_RECIPIENTS} " \
               "MAILMAX=#{MailOnRails::SmtpServer::MAX_MESSAGES_PER_SESSION}",
               "SMTPUTF8" ].freeze

  def test_plaintext_without_tls_material_advertises_the_base_set_only
    with_session do |client|
      extensions = ehlo_extensions(client)

      assert_equal BASE_SET, extensions
    end
  end

  def test_plaintext_with_tls_material_adds_starttls_but_never_auth
    with_session(tls_ctx: tls_ctx) do |client|
      extensions = ehlo_extensions(client)

      assert_includes extensions, "STARTTLS"
      refute(extensions.any? { |e| e.start_with?("AUTH") }, "AUTH must not be offered in the clear")
    end
  end

  def test_encrypted_submission_adds_auth_requiretls_and_dsn_and_drops_starttls
    with_session(tls: :implicit, role: :submission, tls_ctx: tls_ctx) do |client|
      extensions = ehlo_extensions(client)

      assert_includes extensions, "AUTH SCRAM-SHA-256 PLAIN"
      refute(extensions.any? { |e| e.include?("LOGIN") }, "LOGIN must not be advertised")
      assert_includes extensions, "REQUIRETLS", "a TLS session must offer REQUIRETLS (RFC 8689)"
      assert_includes extensions, "DSN", "submission must offer DSN (RFC 3461)"
      refute_includes extensions, "STARTTLS", "STARTTLS must not be offered on an already-encrypted channel"
    end
  end

  def test_encrypted_mx_offers_requiretls_but_never_dsn
    with_session(tls: :implicit, role: :mx, tls_ctx: tls_ctx) do |client|
      extensions = ehlo_extensions(client)

      assert_includes extensions, "REQUIRETLS"
      refute_includes extensions, "DSN", "DSN on MX would be a backscatter/probe oracle"
    end
  end

  def test_plaintext_never_offers_requiretls_or_dsn_on_mx
    with_session(tls_ctx: tls_ctx) do |client|
      extensions = ehlo_extensions(client)

      refute_includes extensions, "REQUIRETLS", "REQUIRETLS is only meaningful on a TLS session"
      refute_includes extensions, "DSN"
    end
  end

  def test_unadvertised_extensions_stay_unadvertised
    with_session(tls: :implicit, tls_ctx: tls_ctx) do |client|
      extensions = ehlo_extensions(client).join(" ")

      %w[ETRN BINARYMIME].each do |unsupported|
        refute_includes extensions, unsupported
      end
    end
  end

  # SMTPUTF8 (RFC 6531) is advertised by default; SMTP_SMTPUTF8=0 (here
  # the spec seam) restores the old refusing posture.
  def test_smtputf8_is_not_advertised_when_disabled
    with_session(spec_extra: { smtputf8: false }) do |client|
      refute_includes ehlo_extensions(client), "SMTPUTF8"
    end
  end

  def test_unsupported_commands_answer_502
    with_session do |client|
      read_reply(client)

      %w[EXPN ETRN TURN XCLIENT].each do |verb|
        assert_match(/\A502 /, command(client, verb), "#{verb} must answer 502")
      end
    end
  end

  def test_help_answers_214
    with_session do |client|
      read_reply(client)

      assert_match(/\A214 2\.0\.0 /, command(client, "HELP"))
    end
  end

  def test_vrfy_answers_252_by_default
    with_session do |client|
      read_reply(client)

      assert_match(/\A252 /, command(client, "VRFY user@example.test"))
    end
  end

  def test_vrfy_answers_502_when_configured
    MailOnRails::Settings.overrides = { smtp_vrfy_response: "502" }
    with_session do |client|
      read_reply(client)

      assert_match(/\A502 /, command(client, "VRFY user@example.test"))
    end
  ensure
    MailOnRails::Settings.reset!
  end
end
