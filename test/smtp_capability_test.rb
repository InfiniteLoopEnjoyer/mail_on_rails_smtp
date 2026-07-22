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

  def with_session(tls: :starttls, role: :mx, tls_ctx: nil)
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: tls, role: role, hostname: "mx.test" }
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
    @@tls_ctx ||= MailOnRails::Smtp::TLS.context(MailOnRails::Smtp::TLS.generate_self_signed)
  end

  def test_plaintext_without_tls_material_advertises_the_base_set_only
    with_session do |client|
      extensions = ehlo_extensions(client)

      assert_equal [ "SIZE #{MailOnRails::SmtpServer::MAX_MESSAGE_BYTES}", "8BITMIME", "PIPELINING" ], extensions
    end
  end

  def test_plaintext_with_tls_material_adds_starttls_but_never_auth
    with_session(tls_ctx: tls_ctx) do |client|
      extensions = ehlo_extensions(client)

      assert_includes extensions, "STARTTLS"
      refute(extensions.any? { |e| e.start_with?("AUTH") }, "AUTH must not be offered in the clear")
    end
  end

  def test_encrypted_channel_adds_auth_and_drops_starttls
    with_session(tls: :implicit, role: :submission, tls_ctx: tls_ctx) do |client|
      extensions = ehlo_extensions(client)

      assert_includes extensions, "AUTH PLAIN LOGIN"
      refute_includes extensions, "STARTTLS", "STARTTLS must not be offered on an already-encrypted channel"
    end
  end

  def test_smtputf8_and_other_unadvertised_extensions_stay_unadvertised
    with_session(tls: :implicit, tls_ctx: tls_ctx) do |client|
      extensions = ehlo_extensions(client).join(" ")

      %w[SMTPUTF8 CHUNKING DSN ENHANCEDSTATUSCODES ETRN].each do |unsupported|
        refute_includes extensions, unsupported
      end
    end
  end

  def test_unsupported_commands_answer_502
    with_session do |client|
      read_reply(client)

      %w[EXPN HELP ETRN TURN BDAT XCLIENT].each do |verb|
        assert_match(/\A502 /, command(client, verb), "#{verb} must answer 502")
      end
    end
  end

  def test_vrfy_answers_252
    with_session do |client|
      read_reply(client)

      assert_match(/\A252 /, command(client, "VRFY user@example.test"))
    end
  end
end
