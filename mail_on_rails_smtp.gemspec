# frozen_string_literal: true

require_relative "lib/mail_on_rails/smtp/version"

Gem::Specification.new do |spec|
  spec.name = "mail_on_rails_smtp"
  spec.version = MailOnRails::Smtp::VERSION
  spec.summary = "The SMTP server for mail_on_rails: MX, submission and SMTPS listeners"
  spec.description = "An SMTP server (RFC 5321 subset with STARTTLS, AUTH PLAIN/LOGIN/SCRAM, " \
                     "SIZE/PIPELINING/CHUNKING/DSN/REQUIRETLS/SMTPUTF8, SPF/DKIM/DMARC/ARC " \
                     "verification, DNSBL, ClamAV and rspamd hooks) that stores mail through " \
                     "the mail_on_rails models gem. Runs inside a Rails app's Puma process " \
                     "(plugin :mail_on_rails) or standalone (bin/mail_server --protocols smtp), " \
                     "with or without the IMAP gem and the admin UI."
  spec.authors = [ "Tayden Miller" ]
  spec.homepage = "https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.4"

  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => spec.homepage
  }

  spec.files = Dir["lib/**/*", "MIT-LICENSE", "README.md"]
  spec.require_paths = [ "lib" ]

  # The models, migrations, settings schema, listener scaffolding
  # (Netserv), sender-auth primitives, runtime and Puma plugin all live in
  # the core gem. Bump the two together.
  spec.add_dependency "mail_on_rails", ">= 0.1.0"
end
