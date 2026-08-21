require "test_helper"
require "mail_on_rails/smtp/store/memory"
require "mail_on_rails/smtp/store/contracts"

# The dependency-free reference store must satisfy the SMTP store contract
# (Store::Contracts) - it's what this gem's session tests run against.
module MemoryStoreConformance
  def build_store(**limits)
    MailOnRails::Smtp::Store::Memory.new(**limits)
  end

  def create_account(email:, password:)
    store.add_account(email: email, password: password)
  end
end

class MemorySmtpStoreTest < Minitest::Test
  include MemoryStoreConformance
  include MailOnRails::Smtp::Store::Contracts::Smtp

  # Beyond the shared contract: the memory store keeps an inbound spool cap
  # (HTTP-backed stores bound inbound on the far side instead).
  def test_smtp_store_enforces_spool_limit
    @store = build_store(spool_limit: 1)
    account_id
    assert_nil store.smtp_store("a@remote.test", [ EMAIL ], RAW, nil)[:code]
    result = store.smtp_store("b@remote.test", [ EMAIL ], RAW, nil)
    assert_equal :insufficient_storage, result[:code]
  end

  # Through the memory store's inspection seam: the trust stamp is
  # persisted with the message.
  def test_smtp_store_persists_the_trust_stamp
    account_id
    store.smtp_store("sender@remote.test", [ EMAIL ], RAW, EMAIL, auth_results: "spf=pass dkim=pass")

    message = store.inbound_messages.last
    assert_equal EMAIL, message[:authenticated_as]
    assert_equal "spf=pass dkim=pass", message[:auth_results]
    assert_equal RAW, message[:data]
  end

  # -- honeypot seams ---------------------------------------------------------

  def test_authenticate_reports_the_canary_flag
    @store = build_store
    store.add_account(email: "real@example.test", password: "pw-123456")
    store.add_account(email: "canary@example.test", password: "pw-123456", honeypot: true)

    refute store.authenticate("real@example.test", "pw-123456")[:honeypot]
    assert store.authenticate("canary@example.test", "pw-123456")[:honeypot]
  end

  def test_inbound_mail_to_a_canary_is_blackholed
    @store = build_store
    store.add_account(email: "canary@example.test", password: "pw-123456", honeypot: true)

    result = store.smtp_store("sender@remote.test", [ "canary@example.test" ], RAW, nil)
    assert_nil result[:code], "RCPT still accepted (deception intact)"
    assert_empty store.inbound_messages, "nothing stored for a canary"
  end

  def test_record_and_update_honeypot_event
    @store = build_store
    id = store.record_honeypot_event(protocol: "smtp", trigger: "canary_auth",
                                     ip: "203.0.113.9", transcript: "partial")[:id]
    store.update_honeypot_transcript(id, transcript: "full")

    assert_equal 1, store.honeypot_events.size
    event = store.honeypot_events.first
    assert_equal "canary_auth", event[:trigger]
    assert_equal "full", event[:transcript]
  end
end
