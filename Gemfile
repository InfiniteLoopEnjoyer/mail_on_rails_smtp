source "https://rubygems.org"

# Runtime dependencies live in the gemspec (currently none).
gemspec

group :development do
  gem "minitest"

  # Signs test fixtures so the DKIM verifier has something real to check.
  gem "dkim"

  # No longer a runtime dependency (SenderAuth::FromHeader replaced it);
  # kept in tests as the reference to parity-check the From: parser against.
  gem "mail"

  # Deploy this daemon as a Docker container (config/deploy.yml). Kamal
  # brings dotenv, which the deploy config uses to load .env for secrets.
  gem "kamal", require: false
  gem "dotenv", require: false

  # Omakase Ruby styling [https://github.com/rails/rubocop-rails-omakase/]
  gem "rubocop-rails-omakase", require: false

  # Scans the bundle for gems with known CVEs (`bundle exec bundler-audit check --update`).
  gem "bundler-audit", require: false
end
