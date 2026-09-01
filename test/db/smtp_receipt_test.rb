# frozen_string_literal: true

require_relative "test_helper"

# SMTP-layer idempotency (todo M12): a message persisted before a 250 the
# sender never read comes back byte-for-byte, and the receipt row keyed by
# the session's digest makes that redelivery a no-op. Exercised through
# the authenticated remote path (SmtpOutboundMessage rows), which needs
# no Action Mailbox; the local path shares the same claim.
class SmtpReceiptTest < MailOnRails::Testing::Database::TestCase
  RAW = "From: user@example.test\r\nSubject: hi\r\n\r\nbody\r\n"
  DIGEST = "a" * 64

  def setup
    super
    # Not in the harness's table list (it predates this table): clean by hand.
    MailOnRails::SmtpReceipt.delete_all
    @store = MailOnRails::Store::SmtpBackend.new
  end

  def store(data = RAW, digest: DIGEST)
    @store.smtp_store("user@example.test", [ "friend@elsewhere.test" ], data, "user@example.test", digest: digest)
  end

  test "claim records a new digest once and refuses it thereafter" do
    assert MailOnRails::SmtpReceipt.claim(DIGEST)
    refute MailOnRails::SmtpReceipt.claim(DIGEST)
    assert MailOnRails::SmtpReceipt.claim("b" * 64)
    assert_equal 2, MailOnRails::SmtpReceipt.count
  end

  test "the same envelope and body twice is stored once and reported as a duplicate" do
    first = store
    refute first[:code], first.inspect
    assert_equal 1, first[:outbound]

    second = store
    assert second[:duplicate], "the redelivery must be flagged"
    assert second[:id], "the session still owes a 250 with an id"
    assert_equal 0, second[:outbound]
    assert_equal 1, MailOnRails::SmtpOutboundMessage.count, "the redelivery must not queue a second copy"
  end

  test "a different body is a different message" do
    store
    result = store(RAW.sub("body", "other body"), digest: "c" * 64)

    refute result[:duplicate]
    assert_equal 2, MailOnRails::SmtpOutboundMessage.count
  end

  test "a store without a digest never dedupes" do
    2.times { refute store(digest: nil)[:duplicate] }
    assert_equal 2, MailOnRails::SmtpOutboundMessage.count
  end

  test "a failed persist releases the receipt so the retry is stored" do
    queue = MailOnRails::SmtpOutboundMessage
    queue.define_singleton_method(:create!) { |**| raise ActiveRecord::StatementInvalid, "db gone" }
    begin
      assert store[:error], "the simulated failure must surface"
    ensure
      queue.singleton_class.remove_method(:create!)
    end
    assert_equal 0, MailOnRails::SmtpReceipt.count, "the claim must roll back with the failed persist"

    refute store[:duplicate], "the sender's retry is a first delivery"
    assert_equal 1, MailOnRails::SmtpOutboundMessage.count
  end

  test "receipts older than the retention window are pruned on claim" do
    MailOnRails::SmtpReceipt.create!(digest: "old" * 21 + "x", created_at: 25.hours.ago)
    MailOnRails::SmtpReceipt.create!(digest: "new" * 21 + "x", created_at: 1.hour.ago)

    assert MailOnRails::SmtpReceipt.claim(DIGEST)

    assert_equal [ "new" * 21 + "x", DIGEST ].sort, MailOnRails::SmtpReceipt.pluck(:digest).sort
  end
end
