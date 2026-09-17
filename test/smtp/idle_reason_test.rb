# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "base64"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# What a closing session tells the store about itself for the idle
# accounting (info[:idle], the idle_auto_ban setting): the shape of a
# connection that did no mail work, and nothing for one that did - or
# tried to. Driven through the whole server, since the verdict only
# matters where Server#report_closed hands it over.
class SmtpIdleReasonTest < Minitest::Test
  TLS = MailOnRails::Netserv::Tls

  class RecordingStore < MailOnRails::Smtp::Store::Memory
    attr_reader :closed

    def initialize(*)
      super
      @closed = []
    end

    def record_closed_connection(info)
      @closed << info
      {}
    end
  end

  def setup
    @cleanup = []
    @store = RecordingStore.new
    @store.add_account(email: "bob@example.test", password: "correct-horse-battery")
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def tls_material
    @@tls_material ||= TLS.generate_self_signed
  end

  def start_server(role: :mx, tls: :starttls, **spec_extra)
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close rescue nil }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: tls, role: role,
             hostname: "mx.test", tcp_server: listener }.merge(spec_extra)
    @server = MailOnRails::SmtpServer.new(@store, [ spec ], tls_material)
    thread = Thread.new { @server.run }
    @cleanup << -> { thread.kill }
    @server.wait_ready(5)
    spec
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
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

  def upgrade(client)
    assert_match(/\A220 /, command(client, "STARTTLS"))
    ssl = OpenSSL::SSL::SSLSocket.new(client, OpenSSL::SSL::SSLContext.new)
    ssl.sync_close = true
    ssl.connect
    @cleanup << -> { ssl.close rescue nil }
    ssl
  end

  # Runs one session to its end and returns what the store was told.
  def closed_after(**server_options)
    spec = start_server(**server_options)
    client = connect(spec)
    read_reply(client) unless spec[:tls] == :implicit
    client = yield(client) || client
    client.close
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    sleep 0.02 while @store.closed.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    assert_equal 1, @store.closed.size, "the close must be reported"
    @store.closed.first
  end

  def idle_after(**server_options, &) = closed_after(**server_options, &)[:idle]

  # -- the scanner shapes, MX ------------------------------------------------

  def test_banner_grab_is_silent
    assert_equal "silent", idle_after { |_client| nil }
  end

  def test_ehlo_and_gone_is_greeting_only
    assert_equal "greeting_only", idle_after { |client| command(client, "EHLO scanner.test"); nil }
  end

  def test_a_polite_quit_changes_nothing
    assert_equal "greeting_only", idle_after { |client|
      command(client, "EHLO scanner.test")
      command(client, "QUIT")
      nil
    }
  end

  def test_certificate_grab_is_tls_only
    assert_equal "tls_only", idle_after { |client|
      command(client, "EHLO scanner.test")
      ssl = upgrade(client)
      command(ssl, "EHLO scanner.test")
      command(ssl, "QUIT")
      ssl
    }
  end

  def test_small_talk_without_a_sender_is_no_transaction
    assert_equal "no_transaction", idle_after { |client|
      command(client, "EHLO scanner.test")
      command(client, "NOOP")
      command(client, "RSET")
      command(client, "HELP")
      nil
    }
  end

  def test_an_unknown_verb_is_small_talk_too
    assert_equal "no_transaction", idle_after { |client| command(client, "XYZZY"); nil }
  end

  # The read timeout is a session spec the server does not pass through,
  # so this one drives a bare session.
  def test_holding_the_connection_open_until_the_read_timeout_is_silent
    listener = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", listener.addr[1])
    client.timeout = 5
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: :mx, hostname: "mx.test", timeout: 0.2 }
    session = MailOnRails::SmtpServer::Session.new(listener.accept, @store, spec, nil)
    thread = Thread.new { session.run }

    assert_match(/\A220 /, read_reply(client))
    assert_match(/\A421 /, read_reply(client), "the session gives up on its own")
    thread.join(5)

    assert_equal "silent", session.idle_reason
  ensure
    client&.close
    listener&.close
  end

  # -- trying counts as work, MX ---------------------------------------------

  def test_a_delivered_message_is_not_idle
    info = closed_after { |client|
      command(client, "EHLO sender.test")
      command(client, "MAIL FROM:<alice@sender.test>")
      command(client, "RCPT TO:<bob@example.test>")
      command(client, "DATA")
      command(client, "From: alice@sender.test\r\nSubject: hi\r\n\r\nhello\r\n.")
      nil
    }

    assert_equal 1, info[:messages]
    refute info.key?(:idle)
  end

  def test_an_address_verification_callout_is_not_idle
    refute closed_after { |client|
      command(client, "EHLO verifier.test")
      command(client, "MAIL FROM:<>")
      command(client, "RCPT TO:<bob@example.test>")
      command(client, "QUIT")
      nil
    }.key?(:idle)
  end

  def test_a_callout_survives_the_reset_that_wipes_the_transaction
    refute closed_after { |client|
      command(client, "EHLO verifier.test")
      command(client, "MAIL FROM:<>")
      command(client, "RSET")
      nil
    }.key?(:idle)
  end

  def test_a_refused_mail_from_is_still_an_attempt
    refute closed_after { |client|
      assert_match(/\A503 /, command(client, "MAIL FROM:<alice@sender.test>"), "no EHLO yet")
      nil
    }.key?(:idle)
  end

  def test_a_honeypot_hit_belongs_to_protocol_auto_ban
    refute closed_after { |client| command(client, "GET / HTTP/1.1"); nil }.key?(:idle)
  end

  def test_auth_on_the_mx_is_not_a_login_attempt
    assert_equal "no_transaction", idle_after { |client|
      command(client, "EHLO scanner.test")
      assert_match(/\A503 /, command(client, "AUTH PLAIN AGJvYgBwYXNz"))
      nil
    }
  end

  # -- submission: only AUTH counts ------------------------------------------

  def test_submission_capability_check_is_no_auth
    assert_equal "no_auth", idle_after(role: :submission) { |client|
      command(client, "EHLO scanner.test")
      ssl = upgrade(client)
      command(ssl, "EHLO scanner.test")
      ssl
    }
  end

  def test_submission_mail_from_without_auth_is_still_no_auth
    assert_equal "no_auth", idle_after(role: :submission) { |client|
      command(client, "EHLO scanner.test")
      assert_match(/\A530 /, command(client, "MAIL FROM:<alice@sender.test>"))
      nil
    }
  end

  def test_submission_banner_grab_is_silent
    assert_equal "silent", idle_after(role: :submission) { |_client| nil }
  end

  def test_a_failed_login_belongs_to_auth_auto_ban
    refute closed_after(role: :submission) { |client|
      command(client, "EHLO client.test")
      ssl = upgrade(client)
      command(ssl, "EHLO client.test")
      assert_match(/\A535 /, command(ssl, "AUTH PLAIN #{Base64.strict_encode64("\0bob@example.test\0wrong")}"))
      ssl
    }.key?(:idle)
  end

  def test_a_login_abandoned_mid_challenge_is_an_attempt
    refute closed_after(role: :submission) { |client|
      command(client, "EHLO client.test")
      ssl = upgrade(client)
      command(ssl, "EHLO client.test")
      assert_match(/\A334 /, command(ssl, "AUTH LOGIN"))
      ssl
    }.key?(:idle)
  end

  def test_plaintext_auth_on_the_wrong_security_type_is_an_attempt
    refute closed_after(role: :submission) { |client|
      command(client, "EHLO client.test")
      assert_match(/\A538 /, command(client, "AUTH PLAIN AGJvYgBwYXNz"))
      nil
    }.key?(:idle)
  end

  def test_a_successful_login_is_not_idle
    info = closed_after(role: :submission) { |client|
      command(client, "EHLO client.test")
      ssl = upgrade(client)
      command(ssl, "EHLO client.test")
      assert_match(/\A235 /, command(ssl, "AUTH PLAIN #{Base64.strict_encode64("\0bob@example.test\0correct-horse-battery")}"))
      ssl
    }

    assert_equal "bob@example.test", info[:user]
    refute info.key?(:idle)
  end

  # -- endings that say nothing about the peer ---------------------------------

  def test_a_kicked_session_is_not_idle
    info = closed_after { |client|
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
      sleep 0.02 while @server.connections.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      @server.kick { |_ip| true }
      nil
    }

    refute info.key?(:idle)
  end

  def test_plaintext_at_the_implicit_tls_port_is_a_failed_handshake
    info = closed_after(role: :submission, tls: :implicit) { |client|
      client.write("EHLO scanner.test\r\n")
      nil
    }

    assert_equal "tls_handshake_failed", info[:idle]
  end
end
