# mail_on_rails_smtp

A standalone SMTP server (RFC 5321 subset): MX + submission listeners with
STARTTLS/implicit TLS, AUTH, SPF/DKIM/DMARC verification of inbound mail,
and anti-abuse controls (global and per-IP connection caps, per-IP
auth-failure lockout). Designed as the mail-receiving frontend for a
Rails app.

The daemon holds **no database credentials and no Rails**: credential
checks, recipient validation, and outbound queueing are HTTP calls to the
host app's private API, and accepted inbound mail is POSTed to the app's
Action Mailbox relay ingress. If the app is down, sessions answer
temporary failures and sending servers retry.

Persistence is pluggable: any store satisfying the contract can back the
server. `Store::Memory` is the dependency-free reference implementation,
`Store::Http` the production client, and `Store::Contracts` the
executable (Minitest) spec a custom store must pass.

## Concurrency architecture

Sessions are served by a pool of **worker Ractors** (one per core by
default), each running a single thread whose hand-rolled
**fiber scheduler** (`Smtp::Scheduler`, pure Ruby over `IO.select`)
multiplexes every session on that worker: socket reads, TLS handshakes,
DNS lookups, and store HTTP calls park a fiber, never the thread. Accept
threads stay in the main Ractor with the exact process-wide `ConnLimiter`;
accepted sockets cross to workers as **raw fd numbers over a control
pipe** (fds are process-global, and integer messages sidestep Ractor IO
moves, which Ruby 4.0.6 does not handle reliably under a scheduler -
probes documented in `scheduler.rb`/`worker.rb`). Finished sessions are
reported back as single bytes on a shared release pipe.

Ractor mode engages when the store can be rebuilt inside each worker
(`Store::Http` can - it is env-configured HTTP clients). An injected
store instance (tests, embedded development) falls back to the same
worker/scheduler core on plain threads, so both modes exercise identical
session code. Requires Ruby >= 4.0 in Ractor mode; Ractors are still
formally experimental there.

Companion repos:
[mail_on_rails](https://github.com/InfiniteLoopEnjoyer/mail_on_rails)
(the host Rails app — persistence, internal API, and web UI) and
[mail_on_rails_imap](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap)
(the IMAP server).

## Layout

- `lib/mail_on_rails/smtp/` - the gem: listener scaffolding
  (`Server`/`ConnLimiter`/`TLS`), the serving core (`Worker` sessions on a
  hand-rolled fiber `Scheduler`, one worker Ractor per core in
  production), the SMTP session (`SmtpServer`), `SenderAuth`
  (SPF/DKIM/DMARC), and stores (`Store::Memory` reference implementation,
  `Store::Http` production client, `Store::Contracts` executable contract
  suite).
- `lib/mail_on_rails/smtp/daemon.rb` - env-driven runtime; also embeddable
  in a host process (e.g. inside Puma in development, passing your own
  store and logger).
- `bin/server` - foreground entrypoint the container runs.
- `config/deploy.yml` - Kamal service definition.

## Host app requirements

`Store::Http` expects the host Rails app to expose two authenticated HTTP
surfaces:

- **Action Mailbox relay ingress** (built into Rails) - accepted inbound
  mail is POSTed there with trust headers (`X-Original-To`,
  `X-MailOnRails-Authenticated`, `X-MailOnRails-Auth-Results`,
  `Return-Path`) stamped on, forged copies stripped.
- **A private internal API** - `POST authenticate`, `POST rcpt_check`, and
  `POST outbound_messages` endpoints behind basic auth (see `InternalApi`
  for the exact request/response shapes).

## Configuration (environment)

| Variable | Default | Purpose |
| --- | --- | --- |
| `MAIL_ON_RAILS_INTERNAL_API_URL` | `http://127.0.0.1:3000/mail_on_rails/internal` | App's private API |
| `MAIL_ON_RAILS_INTERNAL_API_PASSWORD` | - | Basic-auth password for it |
| `MAIL_ON_RAILS_INGRESS_URL` | `http://127.0.0.1:3000/rails/action_mailbox/relay/inbound_emails` | Action Mailbox relay ingress |
| `MAIL_ON_RAILS_INGRESS_PASSWORD` | `$RAILS_INBOUND_EMAIL_PASSWORD` | Ingress password |
| `MAIL_ON_RAILS_HOST` | `0.0.0.0` | Bind address |
| `MAIL_ON_RAILS_SMTP_PORT` / `_SMTP_SUBMISSION_PORT` / `_SMTPS_PORT` | `1025` / `1587` / `1465` | Listener ports |
| `MAIL_ON_RAILS_HELO_HOST` | hostname | Banner/EHLO name |
| `MAIL_ON_RAILS_TLS_CERT` / `_TLS_KEY` | - | PEM paths; if set but missing/unloadable the daemon refuses to boot (else self-signed under `MAIL_ON_RAILS_TLS_DIR`, default `storage/tls`) |
| `MAIL_ON_RAILS_TLS_HOSTS` | `localhost` | Comma-separated SANs for the self-signed cert (hostname is always added) |
| `MAIL_ON_RAILS_DMARC_ENFORCE` | off | `1` rejects on DMARC policy |
| `MAIL_ON_RAILS_DNS_TIMEOUT` | `5` | Seconds per DNS lookup in sender verification |
| `MAIL_ON_RAILS_SMTP_MAX_CONN` | `100` | Connection cap |
| `MAIL_ON_RAILS_SMTP_MAX_CONN_PER_IP` | `10` | Concurrent connections per peer IP (`0` disables) |
| `MAIL_ON_RAILS_SMTP_AUTH_LOCKOUT_FAILURES` | `10` | Failed AUTHs per IP before lockout (`0` disables) |
| `MAIL_ON_RAILS_SMTP_AUTH_LOCKOUT_SECONDS` | `900` | Lockout duration; also the failure-decay window |
| `MAIL_ON_RAILS_SMTP_WORKERS` | CPU cores | Session worker count |
| `MAIL_ON_RAILS_SMTP_WORKER_MODE` | auto | `thread` forces thread workers (no Ractors) |
| `MAIL_ON_RAILS_SMTP_TRACE` | off | `1` debug-logs the protocol exchange (credentials redacted, DATA payloads omitted) |

## Sender verification (SPF / DKIM / DMARC)

Unauthenticated mail arriving on the MX port is verified after `DATA` by
`SenderAuth` — hand-rolled SPF (RFC 7208), DKIM verification (RFC 6376,
rsa-sha256 and ed25519-sha256), and DMARC (RFC 7489) on a hand-rolled DNS
client + OpenSSL. The verdict is stamped as a forge-proof
`X-MailOnRails-Auth-Results` header before the message is relayed to the
host app. One caveat to know about:

### DMARC enforcement is OFF by default

A message that fails DMARC under a published `p=reject` policy is still
**delivered** (with the failure recorded); the server only logs
`would reject message ... under DMARC enforcement`. This is deliberate: a
verifier bug should not bounce legitimate mail while the implementation is
young. Once the logs look right against real traffic, enable rejection with:

    MAIL_ON_RAILS_DMARC_ENFORCE=1

With enforcement on, such messages are refused at SMTP time with
`550 5.7.1 Rejected per DMARC policy of <domain>`.

### DNS

Lookups go straight to the `resolv.conf` nameservers over a hand-rolled
transport (UDP, TCP retry on truncation) reusing only Ruby `Resolv`'s
wire codec — plain `Resolv` is not Ractor-safe, and it cannot tell
NXDOMAIN from SERVFAIL or a timeout. This client can: "no record" returns
an empty result, while SERVFAIL/timeouts raise `Dns::TempError` and
verifiers record `temperror` verdicts, so a DNS outage is visible in
`Authentication-Results` instead of silently weakening every verdict to
`none`.

## Test / run

    bundle install
    bin/test        # Rails-free suite (loopback sessions, sender auth, contracts)
    bin/server      # foreground daemon

## Deploy

    bin/kamal deploy -d prod

`config/deploy.yml` is a generic template. Put your real infrastructure
(hosts, registry, domains) in a gitignored destination overlay -
`config/deploy.prod.yml` - and deploy with `-d prod`. Secrets come from
the gitignored `.env` (see `.kamal/secrets-common`); the values must
match the host app's internal API password and Action Mailbox ingress
password.

## License

MIT - see [LICENSE](LICENSE).
