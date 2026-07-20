# frozen_string_literal: true

require_relative "lib/mail_on_rails/smtp/version"

Gem::Specification.new do |spec|
  spec.name = "mail_on_rails_smtp"
  spec.version = MailOnRails::Smtp::VERSION
  spec.summary = "Standalone SMTP server (RFC 5321 subset) with pluggable stores"
  spec.description = "MX and submission listeners with STARTTLS/implicit TLS, AUTH, " \
                     "SPF/DKIM/DMARC verification of inbound mail, and DoS caps. " \
                     "Persistence goes through any store satisfying the " \
                     "SMTP store contract."
  spec.authors = [ "Tayden Miller" ]
  spec.homepage = "https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.4"

  spec.files = Dir["lib/**/*.rb"] + %w[LICENSE README.md]
  spec.require_paths = [ "lib" ]

  # Used only to parse the From: header for DMARC alignment
  # (SenderAuth.from_domain).
  spec.add_dependency "mail", "~> 2.8"
end
