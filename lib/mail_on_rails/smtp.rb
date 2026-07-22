# frozen_string_literal: true

# The mail_on_rails_smtp gem: a standalone SMTP server (RFC 5321 subset) with
# its own listener scaffolding, TLS, and SPF/DKIM/DMARC verification -
# no shared runtime dependency on the IMAP gem. Persistence goes through
# any object satisfying the SMTP store contract
# (MailOnRails::Smtp::Store::Contracts).
require_relative "smtp/version"
require_relative "smtp/server"
require_relative "smtp/session_helpers"
require_relative "smtp/sender_auth"
require_relative "smtp/clamav_client"
require_relative "smtp/store/http"
require_relative "smtp_server"
