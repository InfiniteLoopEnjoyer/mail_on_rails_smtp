source "https://rubygems.org"

# Runtime dependencies live in the gemspec (just `mail`).
gemspec

group :development do
  gem "minitest"

  # Signs test fixtures so the DKIM verifier has something real to check.
  gem "dkim"

  # Deploy this daemon as a Docker container (config/deploy.yml). Kamal
  # brings dotenv, which the deploy config uses to load .env for secrets.
  gem "kamal", require: false
  gem "dotenv", require: false

  # Omakase Ruby styling [https://github.com/rails/rubocop-rails-omakase/]
  gem "rubocop-rails-omakase", require: false
end
