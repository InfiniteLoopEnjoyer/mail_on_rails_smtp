require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# End-to-end SMTP session over a real loopback socket, backed by the
# contract's reference store - no Rails, no database, no DNS (sender
# verification is stubbed out; this gem has dedicated suites for it).
class SmtpSessionTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def with_session(role: :mx)
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: role, hostname: "mx.test" }
    thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, nil).run }
    yield client
  ensure
    client&.close
    thread&.join(5)
    server&.close
  end

  # One SMTP reply, which may span multiple lines ("250-..." continuations).
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

  # SPF/DKIM/DMARC would do live DNS; return "no verdict" instead
  # (verification has its own suites in this gem).
  def without_sender_verification
    singleton = MailOnRails::Smtp::SenderAuth.singleton_class
    original = MailOnRails::Smtp::SenderAuth.method(:verify)
    singleton.define_method(:verify) { |**| nil }
    yield
  ensure
    singleton.define_method(:verify, original)
  end

  def test_mx_session_accepts_local_mail_end_to_end
    without_sender_verification do
      with_session do |client|
        assert_match(/\A220 mx\.test /, read_reply(client))
        assert_match(/\A250/, command(client, "EHLO client.test"))
        assert_match(/\A250/, command(client, "MAIL FROM:<sender@remote.test>"))
        assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
        assert_match(/\A354/, command(client, "DATA"))
        client.write(RAW)
        assert_match(/\A250 OK: queued/, command(client, "."))
        assert_match(/\A221/, command(client, "QUIT"))
      end
    end

    message = @store.inbound_messages.last
    refute_nil message
    assert_equal [ EMAIL ], message[:rcpt_to]
    assert_equal RAW, message[:data]
    assert_nil message[:authenticated_as], "unauthenticated mail must be stored untrusted"
  end

  def test_mx_session_rejects_unknown_recipient_and_relay
    with_session do |client|
      read_reply(client)
      command(client, "EHLO client.test")
      command(client, "MAIL FROM:<sender@remote.test>")
      assert_match(/\A550/, command(client, "RCPT TO:<stranger@elsewhere.test>"))
      assert_match(/\A503/, command(client, "DATA"))
      command(client, "QUIT")
    end

    assert_empty @store.inbound_messages
    assert_empty @store.outbound_messages
  end

  def test_auth_is_refused_on_an_unencrypted_channel
    with_session(role: :submission) do |client|
      read_reply(client)
      ehlo = command(client, "EHLO client.test")
      refute_match(/AUTH/, ehlo, "AUTH must not be advertised in the clear")
      assert_match(/\A538/, command(client, "AUTH PLAIN AHgAeQ=="))
      command(client, "QUIT")
    end
  end
end
