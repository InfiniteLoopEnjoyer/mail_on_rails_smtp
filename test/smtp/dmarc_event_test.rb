# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The RFC 7489 aggregate-report evidence trail: every evaluated MX message
# whose From domain publishes a DMARC record lands one store.dmarc_event
# row, with the disposition this receiver actually applied (and the
# local-policy reason when that differs from what the domain published).
class DmarcEventTest < Minitest::Test
  EMAIL = "user@example.test"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  def setup
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: "pw-123456")
  end

  def verdict(result:, policy:, domain: "remote.test")
    MailOnRails::SenderAuth::Result.new(
      spf: { result: :fail, domain: "remote.test" },
      dkim: [ { result: :pass, domain: "other.test" } ],
      dmarc: { result: result, policy: policy, domain: domain, from_domain: "remote.test",
               dkim_aligned: false, spf_aligned: false,
               published: { p: "reject", sp: nil, adkim: "r", aspf: "r", pct: 100 } }
    )
  end

  def stubbing_sender_verification(result)
    singleton = MailOnRails::SenderAuth.singleton_class
    original = MailOnRails::SenderAuth.method(:verify)
    singleton.define_method(:verify) { |**| result }
    yield
  ensure
    singleton.define_method(:verify, original)
  end

  def with_dmarc_enforcement(value)
    previous = ENV["SMTP_DMARC_ENFORCE"]
    ENV["SMTP_DMARC_ENFORCE"] = value
    yield
  ensure
    previous ? ENV["SMTP_DMARC_ENFORCE"] = previous : ENV.delete("SMTP_DMARC_ENFORCE")
  end

  def deliver_mx_message
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", sender_auth: true, fcrdns: nil }
    thread = Thread.new { MailOnRails::SmtpServer::Session.new(session_socket, @store, spec, nil).run }
    read_reply(client)
    command(client, "EHLO client.test")
    command(client, "MAIL FROM:<sender@remote.test>")
    command(client, "RCPT TO:<#{EMAIL}>")
    command(client, "DATA")
    client.write(RAW)
    reply = command(client, ".")
    command(client, "QUIT")
    reply
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

  def test_enforced_reject_records_a_reject_disposition
    with_dmarc_enforcement("1") do
      stubbing_sender_verification(verdict(result: :fail, policy: :reject)) do
        assert_match(/\A550/, deliver_mx_message)
      end
    end

    event = @store.dmarc_events.last
    refute_nil event
    assert_equal "remote.test", event[:policy_domain]
    assert_equal "reject", event[:disposition]
    assert_nil event[:override_reason]
    assert_equal "reject", event[:policy_p]
    assert_equal "other.test=pass", event[:dkim_results]
    assert_equal "fail", event[:spf_result]
  end

  def test_unenforced_reject_records_none_with_a_local_policy_reason
    with_dmarc_enforcement("0") do
      stubbing_sender_verification(verdict(result: :fail, policy: :reject)) do
        assert_match(/\A250/, deliver_mx_message)
      end
    end

    event = @store.dmarc_events.last
    refute_nil event
    assert_equal "none", event[:disposition]
    assert_match(/not enforced/, event[:override_reason])
  end

  def test_pass_records_none_without_a_reason
    stubbing_sender_verification(verdict(result: :pass, policy: :none)) do
      assert_match(/\A250/, deliver_mx_message)
    end

    event = @store.dmarc_events.last
    refute_nil event
    assert_equal "none", event[:disposition]
    assert_nil event[:override_reason]
  end

  def test_quarantine_policy_failure_records_quarantine
    stubbing_sender_verification(verdict(result: :fail, policy: :quarantine)) do
      assert_match(/\A250/, deliver_mx_message)
    end

    assert_equal "quarantine", @store.dmarc_events.last[:disposition]
  end

  def test_no_published_record_means_no_event
    stubbing_sender_verification(verdict(result: :none, policy: :none, domain: nil)) do
      assert_match(/\A250/, deliver_mx_message)
    end

    assert_empty @store.dmarc_events, "a domain with no DMARC record has no rua to report to"
  end

  def test_opt_out_records_nothing
    MailOnRails::Settings.overrides = { smtp_dmarc_reports: false }
    stubbing_sender_verification(verdict(result: :fail, policy: :reject)) do
      deliver_mx_message
    end

    assert_empty @store.dmarc_events
  ensure
    MailOnRails::Settings.reset!
  end
end
