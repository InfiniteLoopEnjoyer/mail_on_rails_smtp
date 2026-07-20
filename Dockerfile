# syntax=docker/dockerfile:1
# check=error=true

# Production image for the mail_on_rails_smtp daemon (see config/deploy.yml).
# No Rails, no database - just the Ruby SMTP listeners talking HTTP to the
# host app. Build and run by hand with:
# docker build -t mail_on_rails_smtp .
# docker run -d -p 25:1025 -p 587:1587 -p 465:1465 mail_on_rails_smtp

# Matches the app image's Ruby (see .ruby-version there); the gemspec floor
# is 3.4.
ARG RUBY_VERSION=4.0.6
FROM docker.io/library/ruby:$RUBY_VERSION-slim AS base

WORKDIR /smtp

ENV BUNDLE_DEPLOYMENT="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_WITHOUT="development"

# Throw-away build stage: every dependency is pure Ruby, so no compiler
# toolchain is needed - the stage exists only to drop bundler's caches.
FROM base AS build

# The gemspec is the Gemfile's dependency source and loads version.rb.
COPY Gemfile Gemfile.lock mail_on_rails_smtp.gemspec ./
COPY lib/mail_on_rails/smtp/version.rb lib/mail_on_rails/smtp/version.rb

RUN bundle install && \
    rm -rf ~/.bundle/ "${BUNDLE_PATH}"/ruby/*/cache

COPY . .

# Final stage
FROM base

# Run and own only the runtime files as a non-root user for security (which
# is also why the in-container listener ports stay >1024).
RUN groupadd --system --gid 1000 smtp && \
    useradd smtp --uid 1000 --gid 1000 --create-home --shell /bin/bash
USER 1000:1000

COPY --chown=smtp:smtp --from=build "${BUNDLE_PATH}" "${BUNDLE_PATH}"
COPY --chown=smtp:smtp --from=build /smtp /smtp

EXPOSE 1025 1587 1465
CMD ["bin/server"]