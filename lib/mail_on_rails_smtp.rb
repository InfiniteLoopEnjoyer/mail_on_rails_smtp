# frozen_string_literal: true

# Bundler's autorequire target (`gem "mail_on_rails_smtp"`): loading the
# SMTP protocol gem registers SMTP with the core runtime, which is what
# lets `plugin :mail_on_rails` and bin/mail_server serve it.
require "mail_on_rails/smtp"
