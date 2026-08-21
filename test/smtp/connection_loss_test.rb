require "test_helper"
require "logger"
require "stringio"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# A dropped connection must leave a log line - and when the drop races a
# reply, the line must name the reply that was lost: that is the only
# server-side witness when a sender redelivers an already-accepted message.
# Driven through a scripted socket so the transport failure is
# deterministic (a real peer's RST races the server's writes).
class SmtpConnectionLossTest < Minitest::Test
  # Scripted transport: serves canned command lines and raises the
  # configured errors, so the session sees exact failure points.
  class FakeSocket
    def initialize(reads: [], write_error: nil, fail_writes_after: 0)
      @reads = reads
      @write_error = write_error
      @fail_writes_after = fail_writes_after
      @writes = 0
    end

    def gets(_sep, _limit)
      step = @reads.shift
      raise step if step.is_a?(Class) && step <= Exception

      step
    end

    def write(bytes)
      @writes += 1
      raise @write_error if @write_error && @writes > @fail_writes_after

      bytes.bytesize
    end

    def close = nil
  end

  def setup
    @logs = StringIO.new
    @store = MailOnRails::Smtp::Store::Memory.new(logger: Logger.new(@logs, level: Logger::INFO))
  end

  def run_session(socket)
    spec = { host: "127.0.0.1", port: 25, tls: :starttls, role: :mx, hostname: "mx.test" }
    MailOnRails::SmtpServer::Session.new(socket, @store, spec, nil).run
  end

  test "peer reset before any transaction logs at info" do
    run_session(FakeSocket.new(reads: [ Errno::ECONNRESET ]))

    assert_match(/INFO.*SMTP connection lost: Errno::ECONNRESET/, @logs.string)
    refute_match(/WARN/, @logs.string)
  end

  test "reply write failure warns and names the lost reply" do
    # Banner write succeeds; the 250 for NOOP dies on the wire.
    socket = FakeSocket.new(reads: [ "NOOP\r\n" ], write_error: Errno::EPIPE, fail_writes_after: 1)
    run_session(socket)

    assert_match(/WARN.*SMTP connection lost while sending 250 reply: Errno::EPIPE/, @logs.string)
  end

  test "command timeout logs before the 421" do
    run_session(FakeSocket.new(reads: [ IO::TimeoutError ]))

    assert_match(/INFO.*SMTP command timeout \(0 accepted this session/, @logs.string)
  end
end
