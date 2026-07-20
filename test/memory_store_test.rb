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
end
