# frozen_string_literal: true

require "net/http"
require "json"
require "uri"
require_relative "http_pool"

module MailOnRails
  module Smtp
    # HTTP client for the host app's private SMTP API - credential checks,
    # recipient validation, and outbound queueing. With this plus
    # IngressClient, the SMTP daemon needs no database connection.
    #
    # Non-2xx responses raise InternalApi::Error carrying a store-contract
    # error code; connection failures raise their own exceptions. The store
    # turns both into error envelopes (see Store::Contracts).
    class InternalApi
      class Error < StandardError
        attr_reader :code

        def initialize(message, code: :internal)
          super(message)
          @code = code
        end
      end

      OPEN_TIMEOUT = 5
      READ_TIMEOUT = 60 # outbound queueing ships whole messages

      # Timeouts are injectable so tests can exercise the hung-app path
      # without waiting out the production 60s.
      def initialize(url: default_url, password: default_password,
                     open_timeout: OPEN_TIMEOUT, read_timeout: READ_TIMEOUT)
        @base = URI(url.to_s.chomp("/"))
        @password = password
        @pool = HttpPool.new(@base, open_timeout: open_timeout, read_timeout: read_timeout)
      end

      # => { account_id:, email: } (both nil on bad credentials)
      def authenticate(email, password)
        response = post_json("authenticate", email: email, password: password)
        { account_id: response["account_id"], email: response["email"] }
      end

      # => array of normalized local addresses
      def local_rcpts(addresses)
        post_json("rcpt_check", addresses: Array(addresses)).fetch("local")
      end

      # Queues one outbound row per recipient, all-or-nothing. Raises
      # Error(:insufficient_storage) when the app's queue cap is hit.
      def queue_outbound(mail_from:, recipients:, data:)
        query = URI.encode_www_form([ [ "mail_from", mail_from ] ] + recipients.map { |r| [ "rcpt[]", r ] })
        request = Net::HTTP::Post.new("#{@base.path}/outbound_messages?#{query}")
        request.content_type = "message/rfc822"
        request.body = data

        response = perform(request)
        return true if response.is_a?(Net::HTTPSuccess)

        code = response.is_a?(Net::HTTPInsufficientStorage) ? :insufficient_storage : :internal
        raise Error.new("outbound queueing failed: #{describe(response)}", code: code)
      end

      private

      def post_json(endpoint, payload)
        request = Net::HTTP::Post.new("#{@base.path}/#{endpoint}")
        request.content_type = "application/json"
        request.body = JSON.generate(payload)

        response = perform(request)
        raise Error.new("#{endpoint} failed: #{describe(response)}") unless response.is_a?(Net::HTTPSuccess)

        JSON.parse(response.body)
      end

      # A 401 is a configuration error, not weather - say so in the log line
      # instead of leaving it indistinguishable from an app-side 5xx.
      def describe(response)
        hint = response.is_a?(Net::HTTPUnauthorized) ? " (check MAIL_ON_RAILS_INTERNAL_API_PASSWORD)" : ""
        "#{response.code}#{hint}"
      end

      def perform(request)
        # The basic-auth username is fixed by the app's controller.
        request.basic_auth("mail_on_rails", @password.to_s)
        @pool.request(request)
      end

      def default_url
        ENV.fetch("MAIL_ON_RAILS_INTERNAL_API_URL") { "http://127.0.0.1:3000/mail_on_rails/internal" }
      end

      # The host app's internal API password, handed to this daemon as an
      # environment secret.
      def default_password
        ENV["MAIL_ON_RAILS_INTERNAL_API_PASSWORD"]
      end
    end
  end
end
