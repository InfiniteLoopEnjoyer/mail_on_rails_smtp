# frozen_string_literal: true

require "test_helper"
require "logger"
require "stringio"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The process-wide bound on sessions inside a DATA/BDAT payload
# (MAX_CONCURRENT_DATA): each such session may hold max_message_bytes in
# memory, so the aggregate must not scale with the connection cap. Beyond
# the bound DATA earns a 452 the sender retries; the slot comes back when
# the transfer ends - cleanly or not.
class ConcurrentDataTest < Minitest::Test
  EMAIL = "user@example.test"
  Session = MailOnRails::SmtpServer::Session

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(StringIO.new))
    @store.add_account(email: EMAIL, password: "pw-123456")
    @baseline = Session.data_slots_in_use
    @cleanup = []
  end

  def teardown
    @cleanup.reverse_each(&:call)
  end

  # One direct Session over a loopback pair, with a one-slot cap.
  def open_session(max_concurrent_data: 1)
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: :mx, hostname: "mx.test",
             sender_auth: false, clamav_addr: "", max_concurrent_data: max_concurrent_data }
    thread = Thread.new { Session.new(session_socket, @store, spec, nil).run }
    @cleanup << -> { client.close rescue nil; thread.join(5); server.close rescue nil }
    read_reply(client)
    command(client, "EHLO client.test")
    [ client, thread ]
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

  def envelope(client)
    assert_match(/\A250/, command(client, "MAIL FROM:<a@b.test>"))
    assert_match(/\A250/, command(client, "RCPT TO:<#{EMAIL}>"))
  end

  def test_data_beyond_the_cap_is_deferred_with_452_until_a_transfer_ends
    first, = open_session
    second, = open_session
    envelope(first)
    envelope(second)

    assert_match(/\A354/, command(first, "DATA"))
    assert_equal @baseline + 1, Session.data_slots_in_use
    reply = command(second, "DATA")
    assert_match(/\A452 4\.3\.1 /, reply, "the second transfer must be deferred, not started")
    assert_match(/\A250/, command(second, "RSET"), "the 452 must leave the command stream in sync, no payload state open")
    assert_match(/\A503/, command(second, "DATA"))

    first.write("Subject: x\r\n\r\nbody\r\n")
    assert_match(/\A250/, command(first, "."))
    assert_equal @baseline, Session.data_slots_in_use, "the finished transfer must return its slot"

    envelope(second)
    assert_match(/\A354/, command(second, "DATA"))
    second.write("Subject: y\r\n\r\nbody\r\n")
    assert_match(/\A250/, command(second, "."))
    assert_equal 2, @store.inbound_messages.size
  end

  def test_first_bdat_chunk_beyond_the_cap_is_deferred_and_consumed
    first, = open_session
    second, = open_session
    envelope(first)
    envelope(second)
    assert_match(/\A354/, command(first, "DATA"))

    second.write("BDAT 5\r\nhello")
    assert_match(/\A452 4\.3\.1 /, read_reply(second))
    assert_match(/\A250 2\.0\.0 Ok/, command(second, "NOOP"), "the refused chunk must be consumed for framing")

    first.write("Subject: x\r\n\r\nbody\r\n")
    assert_match(/\A250/, command(first, "."))
    second.write("BDAT 20 LAST\r\nSubject: y\r\n\r\nbody\r\n")
    assert_match(/\A250 2\.0\.0 Ok: queued/, read_reply(second))
    assert_equal @baseline, Session.data_slots_in_use
  end

  def test_a_peer_that_vanishes_mid_data_releases_its_slot
    first, thread = open_session
    envelope(first)
    assert_match(/\A354/, command(first, "DATA"))
    first.write("Subject: partial\r\n")
    first.close
    thread.join(5)

    assert_equal @baseline, Session.data_slots_in_use, "an aborted transfer must not leak its slot"
    second, = open_session
    envelope(second)
    assert_match(/\A354/, command(second, "DATA"))
    second.write("Subject: x\r\n\r\nbody\r\n")
    assert_match(/\A250/, command(second, "."))
  end

  def test_rset_between_bdat_chunks_releases_the_slot
    first, = open_session
    envelope(first)
    first.write("BDAT 5\r\nhello")
    assert_match(/\A250 2\.0\.0 Ok: 5 bytes/, read_reply(first))
    assert_equal @baseline + 1, Session.data_slots_in_use

    assert_match(/\A250/, command(first, "RSET"))
    assert_equal @baseline, Session.data_slots_in_use
  end

  def test_the_default_cap_is_a_small_fixed_number
    assert_equal 16, MailOnRails::SmtpServer::MAX_CONCURRENT_DATA
  end
end
