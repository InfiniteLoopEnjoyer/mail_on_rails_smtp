# frozen_string_literal: true

require "test_helper"
require "tmpdir"
require "socket"
require "openssl"
require "logger"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# Server-relevant TLS failure modes (todo item 2). Not tested: expired
# certs / bad SANs / broken chains - this server runs VERIFY_NONE and never
# validates certificates; validity is the connecting client's concern.
class TlsFailureTest < Minitest::Test
  TLS = MailOnRails::Smtp::TLS

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each(&:call)
  end

  def tls_material
    @@tls_material ||= TLS.generate_self_signed
  end

  # -- STARTTLS teardown under a live server ---------------------------------

  def start_server(store)
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close rescue nil }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", tcp_server: listener }
    thread = Thread.new { MailOnRails::SmtpServer.run(store, [ spec ], tls_material, workers: 1) }
    @cleanup << -> { thread.kill }
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

  # Drives a client to the 220 go-ahead, ready to handshake (or not).
  def starttls_go_ahead(spec)
    client = connect(spec)

    assert_match(/\A220 /, read_reply(client))
    assert_match(/STARTTLS/, command(client, "EHLO client.test"))
    assert_match(/\A220 /, command(client, "STARTTLS"))
    client
  end

  def assert_server_still_serves(spec)
    client = connect(spec)

    assert_match(/\A220 /, read_reply(client), "the worker must survive TLS debris")
    assert_match(/\A250[- ]/, command(client, "EHLO after.test"))
    assert_match(/\A221 /, command(client, "QUIT"))
  end

  def test_garbage_after_starttls_tears_down_only_that_connection
    spec = start_server(MailOnRails::Smtp::Store::Memory.new)
    client = starttls_go_ahead(spec)
    client.write("this is not a ClientHello\r\n")

    # The failed handshake must close this connection (EOF or reset)...
    begin
      assert_nil client.gets("\r\n"), "a failed handshake must drop the connection"
    rescue SystemCallError
      # a reset also proves the teardown
    end

    # ...without taking the worker with it.
    assert_server_still_serves(spec)
  end

  def test_disconnect_mid_handshake_is_survived
    spec = start_server(MailOnRails::Smtp::Store::Memory.new)
    client = starttls_go_ahead(spec)
    client.close # vanish exactly when the server expects a ClientHello

    assert_server_still_serves(spec)
  end

  # -- ContextProvider: live cert renewal (the certbot flow) -----------------

  def write_pems(dir, pems)
    cert = File.join(dir, "cert.pem")
    key = File.join(dir, "key.pem")
    File.write(cert, pems[:cert])
    File.write(key, pems[:key])
    [ cert, key ]
  end

  # File mtimes have coarse granularity; force an unmistakable change.
  def bump_mtimes(*paths, by: 10)
    later = Time.now + by
    paths.each { |p| File.utime(later, later, p) }
  end

  def test_context_provider_reloads_renewed_certs_without_restart
    Dir.mktmpdir do |dir|
      cert, key = write_pems(dir, TLS.generate_self_signed)
      provider = TLS::ContextProvider.new(cert_path: cert, key_path: key)
      before = provider.context

      assert_same before, provider.context, "untouched files must keep the cached context"

      write_pems(dir, TLS.generate_self_signed) # "certbot renew"
      bump_mtimes(cert, key)

      refute_same before, provider.context, "renewed files must yield a rebuilt context"
    end
  end

  def test_context_provider_keeps_serving_the_old_cert_through_a_broken_renewal
    Dir.mktmpdir do |dir|
      cert, key = write_pems(dir, TLS.generate_self_signed)
      provider = TLS::ContextProvider.new(cert_path: cert, key_path: key)
      before = provider.context

      File.write(cert, "not a pem") # a renewal caught mid-write
      bump_mtimes(cert, key)

      assert_same before, provider.context, "a broken renewal must not take TLS down"
    end
  end

  def test_context_provider_recovers_once_the_renewal_completes
    Dir.mktmpdir do |dir|
      cert, key = write_pems(dir, TLS.generate_self_signed)
      provider = TLS::ContextProvider.new(cert_path: cert, key_path: key)
      before = provider.context

      File.write(cert, "not a pem")
      bump_mtimes(cert, key)
      provider.context # broken read, keeps the old context

      write_pems(dir, TLS.generate_self_signed) # renewal completes
      bump_mtimes(cert, key, by: 20)

      refute_same before, provider.context, "a completed renewal must be picked up after a broken one"
    end
  end

  def test_static_pem_material_never_reloads
    provider = TLS::ContextProvider.new(tls_material)

    assert_same provider.context, provider.context
  end
end
