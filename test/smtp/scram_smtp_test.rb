# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/smtp_server"
require "mail_on_rails/scram"
require "mail_on_rails/smtp/store/memory"

# The SCRAM-SHA-256 AUTH exchange as the SMTP session drives it over the
# RFC 4954 challenge flow. The crypto is pinned against the RFC 7677
# vectors in test/imap/scram_test.rb; this suite covers what the SMTP
# session itself is responsible for - nonce echo, channel-binding
# handling, submission-only gating, and the rule that no failure path may
# leave the session authenticated.
class ScramSmtpTest < Minitest::Test
  Scram = MailOnRails::Scram

  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  # Sessions are built as an implicit-TLS submission listener would, so
  # AUTH is permitted on this (plain) loopback socket.
  def with_session(role: :submission, spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :implicit, role: role,
             hostname: "mx.test" }.merge(spec_extra)
    thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, nil).run }
    client.gets("\r\n") # banner
    command(client, "EHLO client.test")
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

  def drain(client)
    rest = +""
    rest << client.gets("\r\n").to_s while !client.eof?
    rest
  rescue IOError, SystemCallError
    rest
  end

  def b64(str) = [ str ].pack("m0")
  def unb64(str) = str.unpack1("m0")

  # Sends client-first and returns [server-first, bare, raw-reply]:
  # server-first is nil when the server refused to continue.
  def begin_exchange(client, gs2: "n,,", user: EMAIL, cnonce: "clientnonce123")
    bare = "n=#{user},r=#{cnonce}"
    reply = command(client, "AUTH SCRAM-SHA-256 #{b64(gs2 + bare)}")
    return [ nil, bare, reply ] unless reply.start_with?("334 ")

    [ unb64(reply[4..].chomp("\r\n")), bare, reply ]
  end

  # Full client side of the exchange. Overrides let each test corrupt
  # exactly one field of client-final.
  def auth_scram(client, password: PASSWORD, gs2: "n,,", user: EMAIL,
                 cnonce: "clientnonce123", nonce_override: nil, cbind_override: nil)
    server_first, bare, raw = begin_exchange(client, gs2: gs2, user: user, cnonce: cnonce)
    return raw unless server_first

    attrs = server_first.split(",").to_h { |p| [ p[0], p[2..] ] }
    nonce = nonce_override || attrs["r"]
    creds = Scram.derive(password, salt: unb64(attrs["s"]), iterations: attrs["i"].to_i)

    without_proof = "c=#{cbind_override || b64(gs2)},r=#{nonce}"
    auth_message = "#{bare},#{server_first},#{without_proof}"
    proof = client_proof(password, creds, auth_message)

    reply = command(client, b64("#{without_proof},p=#{b64(proof)}"))
    return reply unless reply.start_with?("334 ")

    @server_final = unb64(reply[4..].chomp("\r\n"))
    command(client, "") # RFC 5802's empty client response to server-final
  end

  # ClientProof = ClientKey XOR HMAC(StoredKey, AuthMessage).
  def client_proof(password, creds, auth_message)
    salted = OpenSSL::KDF.pbkdf2_hmac(password, salt: creds[:salt], iterations: creds[:iterations],
                                      length: 32, hash: "SHA256")
    client_key = Scram.hmac(salted, "Client Key")
    Scram.xor(client_key, Scram.hmac(Scram.h(client_key), auth_message))
  end

  # -- the happy path --------------------------------------------------------

  test "scram authenticates and binds the session to the account" do
    with_session do |client|
      assert_match(/\A235/, auth_scram(client))
      # The identity is the account's: a mismatched MAIL FROM is refused.
      assert_match(/\A550 5\.7\.1 Sender address must match/, command(client, "MAIL FROM:<other@example.test>"))
      assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}>"))
    end
  end

  test "scram is advertised alongside plain, and login is not" do
    with_session do |client|
      reply = command(client, "EHLO again.test")
      assert_match(/AUTH SCRAM-SHA-256 PLAIN\r/, reply)
      refute_match(/LOGIN/, reply, "LOGIN is answered for legacy clients but never advertised")
    end
  end

  test "server final carries a verifiable server signature" do
    with_session do |client|
      server_first, bare, = begin_exchange(client)
      attrs = server_first.split(",").to_h { |p| [ p[0], p[2..] ] }
      creds = Scram.derive(PASSWORD, salt: unb64(attrs["s"]), iterations: attrs["i"].to_i)

      without_proof = "c=#{b64("n,,")},r=#{attrs["r"]}"
      auth_message = "#{bare},#{server_first},#{without_proof}"
      proof = client_proof(PASSWORD, creds, auth_message)
      reply = command(client, b64("#{without_proof},p=#{b64(proof)}"))

      assert_match(/\A334 /, reply)
      expected = b64(Scram.server_signature(creds[:server_key], auth_message))
      assert_equal "v=#{expected}", unb64(reply[4..].chomp("\r\n"))
    end
  end

  # -- gating ----------------------------------------------------------------

  test "an mx listener refuses scram like every other auth" do
    with_session(role: :mx) do |client|
      assert_match(/\A503 5\.5\.1 AUTH not available/,
                   command(client, "AUTH SCRAM-SHA-256 #{b64("n,,n=#{EMAIL},r=abc")}"))
    end
  end

  # -- failure paths ---------------------------------------------------------

  test "a wrong password produces a bad proof and does not authenticate" do
    with_session do |client|
      assert_match(/\A535/, auth_scram(client, password: "wrong-password"))
      assert_match(/\A530/, command(client, "MAIL FROM:<#{EMAIL}>"))
    end
  end

  test "a client final that does not echo the server nonce is rejected" do
    with_session do |client|
      assert_match(/\A535/, auth_scram(client, nonce_override: "clientnonce123attackerchosen"))
      assert_match(/\A530/, command(client, "MAIL FROM:<#{EMAIL}>"))
    end
  end

  test "a client final with a mismatched channel binding value is rejected" do
    with_session do |client|
      assert_match(/\A535/, auth_scram(client, cbind_override: b64("y,,")))
      assert_match(/\A530/, command(client, "MAIL FROM:<#{EMAIL}>"))
    end
  end

  test "a client demanding channel binding is refused" do
    with_session do |client|
      assert_match(/\A501 5\.5\.2 Channel binding not supported/, auth_scram(client, gs2: "p=tls-unique,,"))
    end
  end

  test "a client that saw no channel binding support authenticates normally" do
    with_session do |client|
      assert_match(/\A235/, auth_scram(client, gs2: "y,,"))
    end
  end

  test "an unknown account still receives a server-first challenge and fails like a wrong password" do
    with_session do |client|
      server_first, = begin_exchange(client, user: "nobody@example.test")
      assert server_first, "unknown users must get a challenge, not an immediate refusal"
      attrs = server_first.split(",").to_h { |p| [ p[0], p[2..] ] }
      assert attrs["s"], "the decoy challenge must carry a salt"
      assert_operator attrs["i"].to_i, :>=, 4096, "and a realistic iteration count"
    end

    with_session do |client|
      reply = auth_scram(client, user: "nobody@example.test")
      assert_match(/\A535/, reply)
      refute_match(/no such|unknown|notfound/i, reply)
    end
  end

  test "a malformed scram message is refused" do
    with_session do |client|
      assert_match(/\A501 5\.5\.2 Malformed SCRAM message/,
                   command(client, "AUTH SCRAM-SHA-256 #{b64("n,,n=,r=")}"))
    end
  end

  # -- attempt accounting ----------------------------------------------------

  # SCRAM failures never reach the store's password check, so the session
  # counts them itself. Past the cap the connection is dropped, exactly
  # as for PLAIN/LOGIN.
  test "scram failures count toward the auth attempt cap and drop the connection" do
    with_session do |client|
      (MailOnRails::SmtpServer::MAX_AUTH_ATTEMPTS - 1).times do
        assert_match(/\A535/, auth_scram(client, password: "wrong"))
      end

      assert_match(/\A421 4\.7\.0 Error: too many failed login attempts/,
                   auth_scram(client, password: "wrong") + drain(client))
    end
  end

  # A "*" cancellation costs an attempt too: each AUTH SCRAM loop drives a
  # store credential lookup before any recordable failure, so an uncounted
  # cancel would be a free way to grind them.
  test "cancelling repeatedly exhausts the attempt budget" do
    with_session do |client|
      (MailOnRails::SmtpServer::MAX_AUTH_ATTEMPTS - 1).times do
        assert_match(/\A334/, command(client, "AUTH SCRAM-SHA-256"))
        assert_match(/\A501 5\.7\.0 Authentication cancelled/, command(client, "*"))
      end

      assert_match(/\A334/, command(client, "AUTH SCRAM-SHA-256"))
      assert_match(/\A421 4\.7\.0 Error: too many failed login attempts/, command(client, "*") + drain(client))
    end
  end
end
