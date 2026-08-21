# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/smtp_server"
require "mail_on_rails/scram"
require "mail_on_rails/smtp/store/memory"

# SCRAM-SHA-256-PLUS channel binding on the submission listener, over a
# real STARTTLS upgrade (scram_smtp_test.rb covers the unbound exchange on
# plain sockets), plus the STARTTLS plaintext-pipelining defense the
# upgrade itself must provide.
class ScramPlusSmtpTest < Minitest::Test
  Scram = MailOnRails::Scram

  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def self.tls_context
    @tls_context ||= MailOnRails::Netserv::Tls.context(MailOnRails::Netserv::Tls.generate_self_signed)
  end

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  # A submission session on a plaintext STARTTLS listener; yields the raw
  # client socket so tests control the upgrade themselves.
  def plaintext_session
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: :submission,
             hostname: "mx.test" }
    thread = Thread.new do
      MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, self.class.tls_context).run
    end
    @cleanup << -> { client.close }
    @cleanup << -> { thread.join(5) }
    @cleanup << -> { server.close }
    client
  end

  def tls_connect(socket)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    tls = OpenSSL::SSL::SSLSocket.new(socket, ctx)
    tls.sync_close = true
    tls.connect
    tls
  end

  # Upgraded and re-greeted, ready for AUTH.
  def tls_session
    client = plaintext_session
    read_reply(client) # banner
    command(client, "EHLO client.test")
    command(client, "STARTTLS")
    tls = tls_connect(client)
    command(tls, "EHLO client.test")
    tls
  end

  def client_cb_data(tls, type)
    case type
    when "tls-server-end-point"
      OpenSSL::Digest.digest("SHA256", tls.peer_cert.to_der)
    when "tls-exporter"
      tls.export_keying_material("EXPORTER-Channel-Binding", 32, "")
    end
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

  def b64(str) = [ str ].pack("m0")
  def unb64(str) = str.unpack1("m0")

  # Full client side of the AUTH exchange over the RFC 4954 flow.
  def auth_scram(client, mechanism: "SCRAM-SHA-256-PLUS", gs2: "p=tls-server-end-point,,",
                 cb_data: nil, password: PASSWORD, user: EMAIL, cnonce: "clientnonce123")
    bare = "n=#{user},r=#{cnonce}"
    reply = command(client, "AUTH #{mechanism} #{b64(gs2 + bare)}")
    return reply unless reply.start_with?("334 ")

    server_first = unb64(reply[4..].chomp("\r\n"))
    attrs = server_first.split(",").to_h { |p| [ p[0], p[2..] ] }
    creds = Scram.derive(password, salt: unb64(attrs["s"]), iterations: attrs["i"].to_i)

    without_proof = "c=#{b64(gs2.b + cb_data.to_s.b)},r=#{attrs["r"]}"
    auth_message = "#{bare},#{server_first},#{without_proof}"
    proof = client_proof(password, creds, auth_message)

    reply = command(client, b64("#{without_proof},p=#{b64(proof)}"))
    return reply unless reply.start_with?("334 ")

    command(client, "") # RFC 5802's empty client response to server-final
  end

  def client_proof(password, creds, auth_message)
    salted = OpenSSL::KDF.pbkdf2_hmac(password, salt: creds[:salt], iterations: creds[:iterations],
                                      length: 32, hash: "SHA256")
    client_key = Scram.hmac(salted, "Client Key")
    Scram.xor(client_key, Scram.hmac(Scram.h(client_key), auth_message))
  end

  # -- advertisement ---------------------------------------------------------

  test "post-starttls ehlo advertises scram-plus first" do
    client = plaintext_session
    read_reply(client)

    before = command(client, "EHLO client.test")
    refute_match(/AUTH /, before, "no AUTH before the channel is encrypted")

    command(client, "STARTTLS")
    tls = tls_connect(client)
    after = command(tls, "EHLO client.test")

    assert_match(/AUTH SCRAM-SHA-256-PLUS SCRAM-SHA-256 PLAIN\r/, after)
  end

  # -- bound authentication --------------------------------------------------

  test "scram-plus with tls-server-end-point authenticates and submits" do
    client = tls_session
    cb = client_cb_data(client, "tls-server-end-point")

    assert_match(/\A235/, auth_scram(client, cb_data: cb))
    assert_match(/\A250/, command(client, "MAIL FROM:<#{EMAIL}>"))
  end

  test "scram-plus with tls-exporter authenticates" do
    client = tls_session

    assert_equal "TLSv1.3", client.ssl_version
    cb = client_cb_data(client, "tls-exporter")

    assert_match(/\A235/, auth_scram(client, gs2: "p=tls-exporter,,", cb_data: cb))
  end

  # The MITM case: a relayed exchange carries the *other* connection's
  # binding in c=, so the proof must not verify here.
  test "scram-plus with wrong channel binding data is rejected" do
    client = tls_session
    reply = auth_scram(client, cb_data: "x" * 32)

    assert_match(/\A535/, reply)
    assert_match(/\A530/, command(client, "MAIL FROM:<#{EMAIL}>"))
  end

  test "scram-plus with an unsupported binding type is refused" do
    client = tls_session

    assert_match(/\A504 5\.5\.4 Unsupported channel binding type/,
                 auth_scram(client, gs2: "p=tls-unique,,", cb_data: "irrelevant"))
  end

  # -- downgrade detection ---------------------------------------------------

  test "a y gs2 flag over tls is rejected as a downgrade" do
    client = tls_session
    reply = auth_scram(client, mechanism: "SCRAM-SHA-256", gs2: "y,,")

    assert_match(/\A535 5\.7\.8 Channel binding downgrade detected/, reply)
    assert_match(/\A530/, command(client, "MAIL FROM:<#{EMAIL}>"))
  end

  test "a p= header with the non-plus mechanism is refused" do
    client = tls_session
    reply = auth_scram(client, mechanism: "SCRAM-SHA-256",
                       gs2: "p=tls-server-end-point,,",
                       cb_data: client_cb_data(client, "tls-server-end-point"))

    assert_match(/\A501 5\.5\.2 Channel binding requires SCRAM-SHA-256-PLUS/, reply)
  end

  test "unbound scram still authenticates over tls" do
    client = tls_session

    assert_match(/\A235/, auth_scram(client, mechanism: "SCRAM-SHA-256", gs2: "n,,"))
  end

  # -- STARTTLS plaintext pipelining (the CVE-2011-0411 class) ---------------

  # A command pipelined in the same segment as STARTTLS must die with the
  # plaintext buffer, not execute after the handshake. The smuggled EHLO
  # doubles as the probe: had it survived, the session would have a HELO
  # name and MAIL FROM would reach the auth gate (530) instead of the
  # greeting gate (503).
  test "commands pipelined behind starttls are never executed" do
    client = plaintext_session
    read_reply(client)
    command(client, "EHLO client.test")

    client.write("STARTTLS\r\nEHLO smuggled.test\r\n")
    assert_match(/\A220 /, read_reply(client))
    tls = tls_connect(client)

    assert_match(/\A503 5\.5\.1 Send EHLO\/HELO first/, command(tls, "MAIL FROM:<#{EMAIL}>"))
  end
end
