# frozen_string_literal: true

require "net/http"
require "uri"
require "logger"
require_relative "http_pool"

module MailOnRails
  module Smtp
    # Hands an accepted inbound message to the host Rails app over Action
    # Mailbox's relay ingress - the same HTTP endpoint Postfix/Exim relays
    # use - where it becomes an ActionMailbox::InboundEmail and is routed by
    # the app's mailboxes.
    #
    # Trust model: the X-Original-To / X-MailOnRails-* / Return-Path headers
    # are OURS. Any copy present in the submitted DATA is stripped before we
    # prepend authoritative values from the SMTP session, so the host app's
    # mailroom can trust what it reads. The ingress itself is authenticated
    # with Action Mailbox's ingress password, handed to this daemon as an
    # environment secret.
    class IngressClient
      # Headers a remote sender must not be able to forge: we set them
      # ourselves from the authenticated SMTP session.
      TRUSTED_HEADERS = /\A(X-Original-To|X-MailOnRails-[\w-]+|Return-Path):/i

      OPEN_TIMEOUT = 5
      READ_TIMEOUT = 60 # the far side writes a 25 MB blob before answering

      def initialize(url: default_url, password: default_password, logger: Logger.new($stdout))
        @uri = URI(url)
        @password = password
        @logger = logger
        @pool = HttpPool.new(@uri, open_timeout: OPEN_TIMEOUT, read_timeout: READ_TIMEOUT)
      end

      # POSTs the stamped message; true when the app accepted it. Non-2xx
      # responses return false and connection errors raise - either way the
      # store adapter turns the failure into a 451 so the sending server
      # retries later.
      def deliver(source)
        request = Net::HTTP::Post.new(@uri)
        request.basic_auth("actionmailbox", @password.to_s)
        request.content_type = "message/rfc822"
        request.body = source
        response = @pool.request(request)

        @logger.warn "[mail_on_rails] ingress refused message: #{response.code}" unless response.is_a?(Net::HTTPSuccess)
        response.is_a?(Net::HTTPSuccess)
      end

      # The message source with our authoritative trust/routing headers
      # prepended (forged copies stripped). Envelope recipients become
      # X-Original-To so Action Mailbox routing sees BCC'd and aliased
      # recipients; Return-Path records the envelope sender;
      # X-MailOnRails-Authenticated records whether the sender authenticated
      # (and as whom).
      def stamp(data, mail_from:, rcpt_to:, authenticated_as:, auth_results: nil)
        authenticated = authenticated_as.to_s.strip
        stamped = [ "Return-Path: <#{sanitize_header(mail_from)}>\r\n" ]
        stamped += Array(rcpt_to).map { |rcpt| "X-Original-To: #{sanitize_header(rcpt)}\r\n" }
        stamped << "X-MailOnRails-Authenticated: #{authenticated.empty? ? "no" : authenticated}\r\n"
        unless auth_results.to_s.strip.empty?
          stamped << "X-MailOnRails-Auth-Results: #{sanitize_header(auth_results)}\r\n"
        end
        stamped.join + strip_trusted_headers(data)
      end

      private

      def default_url
        ENV.fetch("MAIL_ON_RAILS_INGRESS_URL") { "http://127.0.0.1:3000/rails/action_mailbox/relay/inbound_emails" }
      end

      # The app's credentials value (action_mailbox.ingress_password);
      # RAILS_INBOUND_EMAIL_PASSWORD is Action Mailbox's own env spelling.
      def default_password
        ENV["MAIL_ON_RAILS_INGRESS_PASSWORD"] || ENV["RAILS_INBOUND_EMAIL_PASSWORD"]
      end

      # Drops CR/LF so an envelope value can't inject extra header lines.
      def sanitize_header(value)
        value.to_s.gsub(/[\r\n]/, " ")
      end

      def strip_trusted_headers(raw)
        header_block, separator, body = raw.to_s.partition(/\r?\n\r?\n/)
        kept = header_block.split(/\r?\n(?![ \t])/).reject { |line| line.match?(TRUSTED_HEADERS) }
        kept.join("\r\n") + separator + body
      end
    end
  end
end
