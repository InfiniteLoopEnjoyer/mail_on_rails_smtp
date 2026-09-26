# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The per-account concurrent-session cap on submission: one stolen
# password worked from many addresses (each under the per-IP cap) must
# not hold unbounded authenticated sessions. Policy under test: the cap
# counts authenticated sessions per account across the process; an AUTH
# over the cap gets 454 (temporary - the client retries) and is not an
# authentication failure; the slot is freed when the session ends.
class SmtpAccountSessionsTest < Minitest::Test
  EMAIL = "user@example.test"
  OTHER = "other@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD)
    @store.add_account(email: OTHER, password: PASSWORD)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  # A loopback session on a spec that caps the account at +max+; returns
  # the client socket (the session thread is cleaned up in teardown).
  def open_session(max:)
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :implicit, role: :submission,
             hostname: "mx.test", max_sessions_per_account: max }
    thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, nil).run }
    @cleanup << -> { client.close }
    @cleanup << -> { thread.join(5) }
    @cleanup << -> { server.close }
    read_reply(client)
    command(client, "EHLO client.test")
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

  def auth(client, email = EMAIL)
    command(client, "AUTH PLAIN #{[ "\0#{email}\0#{PASSWORD}" ].pack("m0")}")
  end

  def test_second_session_for_the_account_is_refused_until_the_first_ends
    first = open_session(max: 1)
    second = open_session(max: 1)

    assert_match(/\A235/, auth(first))
    assert_match(/\A454 4\.7\.0 Too many simultaneous sessions/, auth(second))
    assert_match(/\A235/, auth(second, OTHER), "other accounts are unaffected")

    third = open_session(max: 1)
    assert_match(/\A454/, auth(third))
    command(first, "QUIT")
    sleep 0.05
    assert_match(/\A235/, auth(third), "the slot is freed when the holder quits")
  end

  def test_a_refusal_is_not_an_authentication_failure
    holder = open_session(max: 1)
    assert_match(/\A235/, auth(holder))

    client = open_session(max: 1)
    # MAX_AUTH_ATTEMPTS failures would end the connection with 421;
    # refusals are not failures, so the connection survives them.
    (MailOnRails::SmtpServer::MAX_AUTH_ATTEMPTS + 1).times do
      assert_match(/\A454/, auth(client))
    end
    holder.close
    sleep 0.05
    assert_match(/\A235/, auth(client), "a dropped holder frees its slot")
  end

  def test_refused_session_is_not_authenticated
    holder = open_session(max: 1)
    assert_match(/\A235/, auth(holder))
    client = open_session(max: 1)
    assert_match(/\A454/, auth(client))
    assert_match(/\A530 5\.7\.0/, command(client, "MAIL FROM:<#{EMAIL}>"), "refused session is still unauthenticated")
  end
end
