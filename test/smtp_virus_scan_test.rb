# frozen_string_literal: true

require "test_helper"
require "logger"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"
require_relative "fake_clamd"

# Virus scanning at the DATA hot path, end-to-end over a loopback session
# against a scripted clamd (see FakeClamd). Policy under test: infected mail
# gets a hard 550 plus a quarantined review copy; an unreachable scanner
# tempfails with 451 (the sending MTA retries, nothing skips scanning) and
# quarantines an "unscanned" copy; clean mail flows through stamped "clean";
# no configured scanner means no scan at all.
class SmtpVirusScanTest < Minitest::Test
  EMAIL = "user@example.test"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: "pw-123456")
  end

  def with_session(spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: :mx, hostname: "mx.test" }.merge(spec_extra)
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

  def without_sender_verification
    singleton = MailOnRails::Smtp::SenderAuth.singleton_class
    original = MailOnRails::Smtp::SenderAuth.method(:verify)
    singleton.define_method(:verify) { |**| nil }
    yield
  ensure
    singleton.define_method(:verify, original)
  end

  def start_data(client)
    read_reply(client)
    command(client, "EHLO client.test")
    command(client, "MAIL FROM:<sender@remote.test>")
    command(client, "RCPT TO:<#{EMAIL}>")
    assert_match(/\A354/, command(client, "DATA"))
  end

  def deliver(spec_extra, raw: RAW)
    without_sender_verification do
      with_session(spec_extra: spec_extra) do |client|
        start_data(client)
        client.write(raw)
        @data_reply = command(client, ".")
        assert_match(/\A250/, command(client, "NOOP"), "session must stay usable after DATA")
        command(client, "QUIT")
      end
    end
    @data_reply
  end

  def test_infected_message_gets_550_and_a_quarantined_review_copy
    FakeClamd.serving(:infected) do |addr|
      reply = deliver({ clamav_addr: addr, clamav_timeout: 2 })

      assert_match(/\A550 5\.7\.1 .*virus.*Eicar-Test-Signature/i, reply)
    end

    assert_empty @store.inbound_messages, "an infected message must never reach the inbound spool"
    copy = @store.quarantined_messages.last
    refute_nil copy, "the 550 must be paired with a review copy"
    assert_equal "infected", copy[:scan_status]
    assert_equal "Eicar-Test-Signature", copy[:virus]
    assert_equal [ EMAIL ], copy[:rcpt_to]
    assert_equal RAW, copy[:data]
  end

  def test_unreachable_scanner_gets_451_and_an_unscanned_quarantine_copy
    closed = TCPServer.new("127.0.0.1", 0)
    port = closed.addr[1]
    closed.close

    reply = deliver({ clamav_addr: "127.0.0.1:#{port}", clamav_timeout: 1 })

    assert_match(/\A451 4\.7\.1 /, reply)
    assert_empty @store.inbound_messages, "unscanned mail must not be accepted"
    copy = @store.quarantined_messages.last
    refute_nil copy
    assert_equal "unscanned", copy[:scan_status]
    assert_nil copy[:virus]
  end

  def test_clean_message_is_accepted_and_stamped_clean
    FakeClamd.serving(:clean) do |addr|
      reply = deliver({ clamav_addr: addr, clamav_timeout: 2 })

      assert_match(/\A250 OK: queued/, reply)
    end

    assert_empty @store.quarantined_messages
    message = @store.inbound_messages.last
    refute_nil message
    assert_equal "clean", message[:scan_status]
  end

  def test_no_configured_scanner_means_no_scan_and_no_stamp
    reply = deliver({})

    assert_match(/\A250 OK: queued/, reply)
    assert_empty @store.quarantined_messages
    assert_nil @store.inbound_messages.last[:scan_status]
  end
end
