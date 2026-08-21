# mail_on_rails_smtp

[![CI](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp/actions/workflows/ci.yml)
[![Security](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp/actions/workflows/security.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp/actions/workflows/security.yml)
[![Lint](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp/actions/workflows/lint.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](MIT-LICENSE)

The SMTP server for [mail_on_rails](https://github.com/InfiniteLoopEnjoyer/mail_on_rails):
an MX (port 25), submission (587) and SMTPS (465) server that accepts mail
into the core gem's tables. RFC 5321 subset with STARTTLS, AUTH
PLAIN/LOGIN/SCRAM-SHA-256(-PLUS), SIZE / PIPELINING / 8BITMIME / SMTPUTF8 /
CHUNKING / DSN / REQUIRETLS / ENHANCEDSTATUSCODES / LIMITS, SPF/DKIM/DMARC/ARC
verification at DATA time, DNSBL and FCrDNS checks, ClamAV and rspamd
hooks, per-IP connection caps, tarpits and auth lockouts (the core gem's
`Netserv` scaffolding), honeypot detection, and session transcripts for
abnormal sessions.

The three pieces of the stack:

| Gem | Owns |
|---|---|
| [`mail_on_rails`](https://github.com/InfiniteLoopEnjoyer/mail_on_rails) (core) | models, migrations, jobs, mailroom, outbound delivery, settings schema, listener scaffolding, sender-auth primitives, runtime, Puma plugin, CLI |
| **`mail_on_rails_smtp`** (this gem) | the SMTP server and its Active Record store |
| [`mail_on_rails_imap`](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap) | the IMAP server and its Active Record store |

Add only the protocol gems you want. A Rails app with core + this gem is
an SMTP server with no IMAP and no admin UI; the companion
[mail_on_rails_admin](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_admin)
app is the full product (webmail + admin UI + both protocols), deployed
as web / smtp / imap containers from one image.

## Installation

```ruby
# Gemfile
gem "mail_on_rails",      git: "https://github.com/InfiniteLoopEnjoyer/mail_on_rails.git",      branch: "main"
gem "mail_on_rails_smtp", git: "https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp.git", branch: "main"
```

```sh
bin/rails generate mail_on_rails:install   # bin/mail_server + initializer (core gem)
bin/rails db:migrate
```

Requiring the gem (Bundler does it for you) registers SMTP with
`MailOnRails::Runtime`; that is what makes it "installed".

## Running

**Standalone** (its own process or container - the production shape):

```sh
bin/mail_server --protocols smtp          # binds 1025/1587/1465 (>1024: the container runs unprivileged)
bin/mail_server check --protocols smtp    # validate settings/TLS/ports without binding
```

**Inside the web process** (one container for everything):

```ruby
# config/puma.rb
plugin :mail_on_rails
```

```sh
MAIL_ON_RAILS_SERVERS=smtp bin/rails server     # or "smtp,imap", or 0 for UI only
```

Unset, development serves every installed protocol and other environments
serve none in-process (run `bin/mail_server`). `config.mail_on_rails.protocols`
is the initializer equivalent.

**Solid Queue is required.** This gem is only the edge: a
`bin/mail_server` process runs no job worker, and everything after
accept is an Active Job in the core gem - Action Mailbox routing of
accepted mail into mailboxes, outbound delivery
(`DeliverSmtpOutboundJob`, a recurring job every ~15 s), report sending,
DKIM rotation, pruning. Without a Solid Queue supervisor and a recurring
schedule against the same database, inbound mail sits unrouted in
`action_mailbox_inbound_emails` and submitted mail sits unsent in
`smtp_outbound_messages`. The reference schedule is
[mail_on_rails_admin](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_admin)'s
`config/recurring.yml`; run it on a sibling `bin/jobs` process (or the
web role, as that app does). A standalone mode that runs Solid Queue
inside `bin/mail_server` is on the todo list.

## Configuration

Everything is a setting in the core gem's schema (`MailOnRails::Settings`,
`smtp_*` names; see its `docs/settings.md`), layered
`default < ENV < initializer < database`. The essentials:

| Setting | ENV | Default |
|---|---|---|
| `smtp_host`, `smtp_port`, `smtp_submission_port`, `smtps_port` | `SMTP_HOST`, `SMTP_PORT`, `SMTP_SUBMISSION_PORT`, `SMTPS_PORT` | `0.0.0.0`, 1025, 1587, 1465 |
| `smtp_tls_cert`, `smtp_tls_key` | `SMTP_TLS_CERT`, `SMTP_TLS_KEY` | self-signed in development; **required in production** |
| `smtp_helo_hostname` | `SMTP_HELO_HOST` | system hostname |
| `smtp_clamav_addr`, `smtp_rspamd_addr` | `SMTP_CLAMAV_ADDR`, `SMTP_RSPAMD_ADDR` | unset (production refuses to boot without a scanner unless `SMTP_CLAMAV_OPTIONAL=1`) |
| `smtp_max_conn`, `smtp_max_conn_per_ip`, `smtp_conn_rate`, ... | `SMTP_MAX_CONN`, ... | see schema |

## Layout

```
lib/mail_on_rails/smtp.rb              entry: registers MailOnRails::Smtp::Protocol with the runtime
lib/mail_on_rails/smtp_server.rb       the server (sessions, commands, extensions)
lib/mail_on_rails/smtp/daemon.rb       listener specs + TLS material -> a running server
lib/mail_on_rails/smtp/{dnsbl,fcrdns,session_helpers}.rb
lib/mail_on_rails/smtp/store/          the store contract (executable) and the memory store
lib/mail_on_rails/store/smtp_backend.rb the Active Record store (core models)
lib/mail_on_rails/fuzz/smtp*.rb        fuzz harness
test/smtp                              wire/session/CVE/conformance suites (Rails-free)
test/db                                the AR store against the contract (SQLite)
```

The server never touches Active Record or Rails directly: it talks to an
injected store (`docs/store_contract.md` in the core gem). Its live
connections, lockouts and heartbeat are projected into the core gem's ops
tables by `Netserv::OpsSync`, which is how the admin UI shows them from
another container.

## Testing

```sh
bundle exec rake test          # wire + store suites
bundle exec rake test:wire     # Rails-free
bundle exec rake test:db       # DATABASE_URL or SQLite
FUZZ_ROUNDS=25 bundle exec ruby -Ilib lib/mail_on_rails/fuzz/smtp_runner.rb
```

For local development against a core checkout:
`bundle config set --local local.mail_on_rails /path/to/mail_on_rails`.

## License

MIT - see [MIT-LICENSE](MIT-LICENSE).
