# frozen_string_literal: true

require_relative "test_helper"

# Recipient acceptance at the SMTP edge that depends on core models beyond
# the store contract: signed VERP bounce addresses (VerpAddress) and
# internationalized recipient domains matched against punycode Domain
# rows. (The full contract run against this backend, and the inbound path
# that creates ActionMailbox::InboundEmail, live in the admin app's suite -
# they need Action Mailbox/Active Storage, which this harness does not boot.)
class SmtpBackendEdgeTest < MailOnRails::Testing::Database::TestCase
  SENDER = "news@example.test"
  RECIPIENT = "reader@remote.test"
  LIST_MAIL = "From: news@example.test\r\nList-ID: <news.example.test>\r\nSubject: weekly\r\n\r\nhello\r\n"

  def setup
    super
    MailOnRails::Domain.create!(name: "example.test")
    @store = MailOnRails::Store::SmtpBackend.new
  end

  def queue_message(data = LIST_MAIL)
    MailOnRails::SmtpOutboundMessage.create!(mail_from: SENDER, recipient: RECIPIENT,
                                             data: data, next_attempt_at: Time.current)
  end

  test "the edge accepts valid VERP recipients and refuses forgeries" do
    message = queue_message
    address = MailOnRails::VerpAddress.encode(message)

    assert_equal [ address ], @store.local_rcpts([ address ])[:local]

    forged = address.sub(/-\h{12}@/, "-000000000000@")
    result = @store.local_rcpts([ forged ])
    assert_empty result[:local], "a bad MAC must not read as a local recipient"
  end

  test "the store normalizes u-label recipient domains to hosted punycode domains" do
    MailOnRails::Domain.create!(name: "xn--exmple-cua.test") # exämple.test

    result = @store.local_rcpts([ "user@exämple.test" ])

    assert_equal [ "user@xn--exmple-cua.test" ], result[:unknown_in_local_domain],
                 "the U-label domain must match the punycode Domain row (no such user, not relaying denied)"
  end
end
