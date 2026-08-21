# frozen_string_literal: true

module MailOnRails
  module Smtp
    module Store
      # Executable form of the SMTP side of the store contract - the
      # authoritative spec of what a backing store must provide (the IMAP
      # side lives in mail_on_rails/imap/store/contracts.rb). Include
      # Contracts::Smtp in a Minitest test class and provide:
      #
      #   build_store(**limits)              -> the store under test (accepts
      #                                         outbound_limit: for the SMTP
      #                                         contract)
      #   create_account(email:, password:)  -> account id, provisioned however
      #                                         the implementation stores accounts
      #
      # Any store passing this suite is interchangeable in front of the
      # SMTP server - it runs against Store::Memory in this gem, and a host
      # app can run it against its own adapters.
      module Contracts
        module Helpers
          EMAIL = "user@example.test"
          PASSWORD = "correct-horse-battery"

          def store
            @store ||= build_store
          end

          def account_id
            @account_id ||= create_account(email: EMAIL, password: PASSWORD)
          end
        end

        module Shared
          include Helpers

          def test_authenticate_returns_id_and_normalized_email
            account_id
            result = store.authenticate(EMAIL, PASSWORD)
            assert result[:account_id], "expected an account_id"
            assert_equal EMAIL, result[:email]
          end

          def test_authenticate_is_case_and_whitespace_insensitive_on_email
            account_id
            result = store.authenticate("  #{EMAIL.upcase}  ", PASSWORD)
            assert_equal EMAIL, result[:email]
          end

          def test_authenticate_rejects_wrong_password
            account_id
            result = store.authenticate(EMAIL, "wrong")
            assert_nil result[:account_id]
            assert_nil result[:email]
          end

          def test_authenticate_rejects_unknown_account
            result = store.authenticate("nobody@example.test", PASSWORD)
            assert_nil result[:account_id]
            assert_nil result[:email]
          end

          def test_log_returns_nil
            assert_nil store.log(:info, "contract check")
          end

          # MSA authorization (RFC 6409): the addresses an authenticated
          # account may claim as sender - at least its own address; stores
          # with aliases include them.
          def test_sender_addresses_includes_the_account
            account_id
            assert_includes store.sender_addresses(EMAIL), EMAIL
            assert_equal [], store.sender_addresses("nobody@example.test")
          end
        end

        module Smtp
          include Shared

          RAW = "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n"

          def test_local_rcpts_returns_known_normalized_subset
            account_id
            result = store.local_rcpts([ " #{EMAIL.upcase} ", "stranger@example.test" ])
            assert_equal [ EMAIL ], result[:local]
          end

          def test_local_rcpts_flags_unknown_users_in_hosted_domains
            account_id
            result = store.local_rcpts([ "stranger@example.test", "anyone@elsewhere.test" ])
            assert_equal [], result[:local]
            assert_equal [ "stranger@example.test" ], result[:unknown_in_local_domain]
          end

          def test_smtp_store_accepts_local_mail_unauthenticated
            account_id
            result = store.smtp_store("sender@remote.test", [ EMAIL ], RAW, nil)
            assert result[:id], "expected a stored-message id"
            assert_equal 0, result[:outbound]
          end

          def test_smtp_store_denies_relay_for_unauthenticated_remote
            account_id
            result = store.smtp_store("sender@remote.test", [ "victim@elsewhere.test" ], RAW, nil)
            assert_equal :relay_denied, result[:code]
          end

          def test_smtp_store_queues_remote_mail_for_authenticated_sender
            account_id
            result = store.smtp_store(EMAIL, [ "friend@elsewhere.test" ], RAW, EMAIL)
            refute result[:code], "expected success, got #{result.inspect}"
            assert_equal 1, result[:outbound]
          end

          def test_smtp_store_splits_mixed_recipients
            account_id
            result = store.smtp_store(EMAIL, [ EMAIL, "friend@elsewhere.test" ], RAW, EMAIL)
            assert result[:id]
            assert_equal 1, result[:outbound]
          end

          def test_smtp_store_enforces_outbound_limit
            @store = build_store(outbound_limit: 1)
            account_id
            result = store.smtp_store(EMAIL, [ "one@elsewhere.test", "two@elsewhere.test" ], RAW, EMAIL)
            assert_equal :insufficient_storage, result[:code]
          end

          def test_smtp_store_accepts_scan_status
            account_id
            result = store.smtp_store("sender@remote.test", [ EMAIL ], RAW, nil, scan_status: "clean")
            assert result[:id], "expected a stored-message id"
          end

          def test_smtp_store_accepts_client_ip_and_helo
            account_id
            result = store.smtp_store("sender@remote.test", [ EMAIL ], RAW, nil,
                                      client_ip: "203.0.113.9", helo: "mail.remote.test")
            assert result[:id], "expected a stored-message id"
          end

          # The session records the RFC 8689 promise and RFC 3461 requests
          # onto the queued outbound rows; per-recipient requests are keyed
          # by the address as the client wrote it, so the store must match
          # them to its normalized recipients.
          def test_smtp_store_accepts_requiretls_and_dsn_requests
            account_id
            result = store.smtp_store(EMAIL, [ " Friend@Elsewhere.TEST " ], RAW, EMAIL,
                                      requiretls: true,
                                      dsn: { ret: "HDRS", envid: "QQ314159",
                                             recipients: { " Friend@Elsewhere.TEST " =>
                                                           { notify: "SUCCESS,FAILURE", orcpt: "rfc822;friend@elsewhere.test" } } })
            refute result[:code], "expected success, got #{result.inspect}"
            assert_equal 1, result[:outbound]
          end

          # RFC 6531: the session records the client's SMTPUTF8 declaration
          # onto queued outbound rows so the deliverer can honor it.
          def test_smtp_store_accepts_smtputf8_flag
            account_id
            result = store.smtp_store(EMAIL, [ "friend@elsewhere.test" ], RAW, EMAIL, smtputf8: true)
            refute result[:code], "expected success, got #{result.inspect}"
            assert_equal 1, result[:outbound]
          end

          def test_quarantine_returns_nil_for_local_recipients
            account_id
            assert_nil store.quarantine("sender@remote.test", [ EMAIL ], RAW, nil,
                                        auth_results: nil, scan_status: "infected", virus: "Eicar-Test-Signature")
          end

          def test_quarantine_returns_nil_for_authenticated_remote_only_submission
            account_id
            assert_nil store.quarantine(EMAIL, [ "friend@elsewhere.test" ], RAW, EMAIL,
                                        auth_results: nil, scan_status: "unscanned")
          end

          def test_quarantine_returns_nil_when_no_target_exists
            assert_nil store.quarantine("sender@remote.test", [ "stranger@example.test" ], RAW, nil,
                                        auth_results: nil, scan_status: "infected", virus: "X")
          end

          # Best-effort DMARC aggregate-report telemetry: the session records
          # a row per evaluated message and never looks at the result.
          def test_dmarc_event_returns_nil
            assert_nil store.dmarc_event(policy_domain: "example.org", from_domain: "example.org",
                                         source_ip: "203.0.113.9", envelope_from: "a@example.org",
                                         disposition: "none", override_reason: nil,
                                         dkim_aligned: true, spf_aligned: false,
                                         spf_result: "fail", spf_domain: "example.org",
                                         dkim_results: "example.org=pass",
                                         policy_p: "reject", policy_sp: nil,
                                         policy_adkim: "r", policy_aspf: "r", policy_pct: 100)
          end
        end
      end
    end
  end
end
