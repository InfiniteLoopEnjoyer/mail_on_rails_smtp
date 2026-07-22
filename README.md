# mail_on_rails_smtp

A standalone SMTP server (RFC 5321 subset): MX + submission listeners with
STARTTLS/implicit TLS, AUTH, SPF/DKIM/DMARC verification of inbound mail,
and anti-abuse controls (global and per-IP connection caps, per-IP
auth-failure lockout). Designed as the mail-receiving frontend for a
Rails app. The supported command/extension surface is documented in
[docs/smtp_capability_matrix.md](docs/smtp_capability_matrix.md).

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
probes documented in `scheduler.rb`/`worker.rb`). Finished sessions and
failed AUTHs are reported back as lines on shared release/auth pipes,
keyed by the accept-time peer IP so the per-IP caps stay exact. A monitor
thread per worker enforces a death policy: a worker Ractor that dies is
logged and replaced (in-flight sessions' connection slots are swept);
after 5 deaths the failure is treated as systemic and the daemon exits
for the container runtime to restart.

Ractor mode engages when the store can be rebuilt inside each worker
(`Store::Http` can - it is env-configured HTTP clients). An injected
store instance (tests, embedded development) falls back to the same
worker/scheduler core on plain threads, so both modes exercise identical
session code. Requires Ruby >= 4.0 in Ractor mode; Ractors are still
formally experimental there.

Companion repos:
[mail_on_rails](https://github.com/InfiniteLoopEnjoyer/mail_on_rails)
(the host Rails app — persistence, internal API, and web UI; see
[The host app](#the-host-app-mail_on_rails) below) and
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

## Delivery guarantees

There is **no local spool**: the only durable step is the HTTP handoff to
the host app, and a message is never ACKed before that handoff succeeds.
Concretely:

- **App down / handoff fails** → the session answers a `4xx` temporary
  failure and stores nothing; the *sending server's* queue is the retry
  mechanism. This daemon never retries an HTTP call itself — a retry here
  would only delay the sender's own retry signal and double-submit on
  ambiguous failures.
- **Disconnect mid-`DATA`** → nothing is stored (at-most-once before the
  commit point).
- **Overall semantics: at-least-once**, with two known duplicate windows:
  a crash after the ingress accepted but before our `250` reached the
  sender, and mixed local+remote recipients where outbound queueing
  succeeds but the ingress then fails — the sender's retry queues the
  outbound copies again. Both are pinned by tests; deduplication belongs
  in the host app, where the queue lives.

## Running more than one instance

The daemon is stateless — accounts, recipients, and mail all live behind
the host app's HTTP surfaces — so horizontal scale is just N containers
with the same configuration:

- Point multiple `MX` records (or an L4/TCP load balancer) at the
  instances; no sticky sessions are needed, since every SMTP session is
  self-contained on one connection.
- The shared dependency and real single point of failure is the **host
  app**; when it is down every instance answers temporary failures and
  senders retry.
- The per-IP caps and auth lockout are **per instance** (accept-side,
  in-process). N instances multiply those thresholds accordingly.
- Deploys have a few seconds of listener downtime per host
  (`.kamal/hooks/pre-app-boot` stops the old container before the new one
  binds the ports); sending servers retry, so mail is delayed, not lost.

## The host app: mail_on_rails

[mail_on_rails](https://github.com/InfiniteLoopEnjoyer/mail_on_rails) is
the other half of the system: a Rails 8 app (Ruby 4.0, PostgreSQL,
Solid Queue/Cache/Cable — no Redis) that owns persistence, the web UI,
and outbound delivery. This daemon is deliberately ignorant of all of
it, so for orientation, this is what sits on the far side of the HTTP
calls:

- **Domain model** — mail identities are `EmailAccount`s (unique
  normalized email + bcrypt password: the credential SMTP AUTH checks),
  each owning IMAP-style `Mailbox` folders (INBOX/Sent/Drafts/Trash/Junk
  auto-provisioned) of `EmailMessage` rows: raw RFC822 bytes plus
  extracted headers, IMAP flags/UIDs, and the verification verdicts this
  daemon stamps. Web-console operators are a separate `User` model (an
  admin login, not a mail identity). There are no domain or alias
  tables — recipient locality is simply "an `EmailAccount` with this
  address exists".
- **The internal API, server-side** (`InternalController`, basic auth):
  `authenticate` runs `EmailAccount.authenticate_by`, returning null
  fields on bad credentials (HTTP 200; a 401 means the *API password* is
  wrong). `rcpt_check` normalizes (strip/downcase/dedup) and returns the
  subset that are existing accounts. `outbound_messages` inserts one
  `SmtpOutboundMessage` row **per remote recipient**, all-or-nothing,
  answering 507 when the pending queue would exceed
  `MAIL_ON_RAILS_OUTBOUND_LIMIT` (default 1000) — which this daemon
  relays to the client as a `452`.
- **Inbound, after the ingress** — Action Mailbox (`:relay` mode) routes
  every accepted message to a single `MailroomMailbox`, which resolves
  recipients from To/Cc/Bcc plus our stamped `X-Original-To` and files
  the message into each local account's INBOX. Our
  `X-MailOnRails-Authenticated` / `X-MailOnRails-Auth-Results` headers
  become the stored message's `authenticated_as` / `auth_results`
  columns, surfaced as sender-verification badges in the UI.
- **Outbound delivery** — a Solid Queue recurring job (in-process in
  Puma) drains the queue every 15 seconds: rows are claimed atomically
  (`pending` → `delivering`) so concurrent runs can't double-send, MX is
  resolved per recipient (RFC 7505 null-MX honored), delivery goes out
  on port 25 with opportunistic STARTTLS (or through a configured
  smarthost), messages are DKIM-signed with per-domain keys
  (`MAIL_ON_RAILS_DKIM_DIR/<domain>.pem`), and transient failures retry
  on a backoff schedule spanning ~22 hours before a minimal DSN bounce
  is delivered into the sender's INBOX.
- **Web UI** — a server-rendered admin console (Hotwire + Tailwind):
  manage accounts and folders, read messages with their verification
  badges. It is not a compose-and-send webmail; sending happens through
  real mail clients submitting to this daemon.
- **IMAP** — the same internal API also carries an IMAP store contract
  (`imap/:op` endpoints backed by `Store::ImapBackend`) consumed by
  [mail_on_rails_imap](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap) —
  the same no-database-in-the-daemon privilege split used here (the IMAP
  daemon cannot touch the outbound spool; this daemon cannot read
  mailboxes).

In development the app runs all three services in one process (the
daemons are path gems mounted as Puma plugins via its `bin/dev`); in
production each is its own Kamal service against the app's PostgreSQL.

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
| `MAIL_ON_RAILS_SENDER_AUTH` | on | `0` skips SPF/DKIM/DMARC verification entirely (local try-outs; mail is stored without a verdict) |
| `MAIL_ON_RAILS_DMARC_ENFORCE` | off | `1` rejects on DMARC policy |
| `MAIL_ON_RAILS_DNS_TIMEOUT` | `5` | Seconds per DNS lookup in sender verification |
| `MAIL_ON_RAILS_DNS_CACHE_TTL` | `60` | Cap in seconds on the per-worker DNS answer cache (record TTLs bind below it; `0` disables) |
| `MAIL_ON_RAILS_RBLS` | - | Comma-separated DNSBL zones (e.g. `zen.spamhaus.org`); unauthenticated MX mail from a listed IP is refused at `MAIL FROM` with `554 5.7.1`. Fails open on DNS trouble |
| `MAIL_ON_RAILS_RBL_CACHE_TTL` | `600` | Seconds a DNSBL verdict is cached per peer IP |
| `MAIL_ON_RAILS_SMTP_MAX_CONN` | `100` | Connection cap |
| `MAIL_ON_RAILS_SMTP_MAX_CONN_PER_IP` | `10` | Concurrent connections per peer IP (`0` disables) |
| `MAIL_ON_RAILS_SMTP_CONN_RATE` | `60` | Connections per peer IP per window before the banner is tarpitted (escalating 1 s → 16 s; loopback exempt; `0` disables) |
| `MAIL_ON_RAILS_SMTP_CONN_RATE_WINDOW` | `60` | Sliding-window seconds for the connection rate |
| `MAIL_ON_RAILS_SMTP_AUTH_LOCKOUT_FAILURES` | `10` | Failed AUTHs per IP before lockout (`0` disables) |
| `MAIL_ON_RAILS_SMTP_AUTH_LOCKOUT_SECONDS` | `900` | Lockout duration; also the failure-decay window |
| `MAIL_ON_RAILS_SMTP_WORKERS` | CPU cores | Session worker count |
| `MAIL_ON_RAILS_SMTP_WORKER_MODE` | auto | `thread` forces thread workers (no Ractors) |
| `MAIL_ON_RAILS_SMTP_TRACE` | off | `1` debug-logs the protocol exchange (credentials redacted, DATA payloads omitted) |

### Feature switches

Every optional subsystem can be turned on or off through the variables
above — nothing needs a code change to try the server out. Two conventions
to know before flipping anything:

- **Flags are read at load time.** Sessions run inside worker Ractors,
  which cannot read `ENV` at runtime, so every switch is parsed when the
  process boots. Changing a variable requires a restart.
- **Values are strict.** Boolean-ish switches accept exactly `1` (enable)
  or `0` (disable); `true`/`false`/`yes`/`off` are ignored, and
  `bin/server --check-config` warns when it spots one of those footguns.

| Feature | Variable | Default | Off when | On when |
| --- | --- | --- | --- | --- |
| SPF/DKIM/DMARC verification | `MAIL_ON_RAILS_SENDER_AUTH` | **on** | `0` | anything else / unset |
| DMARC enforcement (reject on `p=reject` fail) | `MAIL_ON_RAILS_DMARC_ENFORCE` | **off** (record-only) | unset / anything else | `1` |
| DNSBL (RBL) checks | `MAIL_ON_RAILS_RBLS` | **off** | unset / empty | one or more zones, e.g. `zen.spamhaus.org` |
| ClamAV virus scanning | `MAIL_ON_RAILS_CLAMAV_ADDR` | **off** | unset / empty | `host[:port]` of a clamd daemon |
| Per-IP concurrent connection cap | `MAIL_ON_RAILS_SMTP_MAX_CONN_PER_IP` | **on** (10) | `0` | any positive cap |
| Per-IP connection rate tarpit | `MAIL_ON_RAILS_SMTP_CONN_RATE` | **on** (60/window) | `0` | any positive budget |
| Per-IP auth-failure lockout | `MAIL_ON_RAILS_SMTP_AUTH_LOCKOUT_FAILURES` | **on** (10) | `0` | any positive threshold |
| Protocol tracing | `MAIL_ON_RAILS_SMTP_TRACE` | **off** | unset / anything else | `1` |
| Ractor workers | `MAIL_ON_RAILS_SMTP_WORKER_MODE` | **auto** | `thread` (plain threads) | `auto` / unset |

The global connection cap (`MAIL_ON_RAILS_SMTP_MAX_CONN`) cannot be
disabled, only raised. Setting `MAIL_ON_RAILS_SENDER_AUTH=0` stores
inbound mail with no verdict (`auth_results` empty) and makes DMARC
enforcement moot; `--check-config` warns when it is off. Pointing
`MAIL_ON_RAILS_CLAMAV_ADDR` at an unreachable clamd tempfails (`451`)
rather than letting mail skip scanning — only set it for a daemon you
intend to keep running.

### How tests validate on and off

Because flags are load-time constants, tests don't flip `ENV` around a
running server. Each feature instead has a per-listener spec seam that
overrides the env-derived default, and suites cover both states through it:

| Feature | Seam | On/off coverage |
| --- | --- | --- |
| Sender verification | `spec[:sender_auth]` | `test/smtp_session_test.rb` (verify runs when on, skipped and unstamped when off) |
| DMARC enforcement | env (runtime read) | `test/sender_auth_test.rb` (off unless `1`; reject verdicts), `test/dmarc_test.rb` |
| DNSBL | `spec[:dnsbl]` | `test/smtp_session_test.rb` (listed refused / unlisted accepted), `test/dnsbl_test.rb` |
| Virus scanning | `spec[:clamav_addr]` / `spec[:clamav_timeout]` | `test/smtp_virus_scan_test.rb` (clean, infected, unavailable, disabled) |
| Anti-abuse caps | constructor arguments | `test/conn_limiter_test.rb`, `test/rate_limiter_test.rb`, `test/auth_throttle_test.rb` (incl. `0` = disabled) |
| Tracing | `spec[:trace]` | `test/smtp_session_test.rb` |

Boot-time validation and the footgun warnings (`SENDER_AUTH=false`,
`DMARC_ENFORCE=true`, unknown worker modes) are covered by
`test/config_validation_test.rb` against `bin/server --check-config`.

When adding a new toggle, follow the same pattern: read the variable once
at load time, expose a per-listener `spec[:...]` override as the test
seam, warn in `Daemon.config_warnings` when a value looks like a mistake,
and add both an "on" and an "off" test.

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

Answers (including "no record") are cached per worker for up to
`MAIL_ON_RAILS_DNS_CACHE_TTL` seconds (default 60; record TTLs bind below
the cap, failures are never cached), so a burst of messages from one
sender costs one fetch of its SPF/DKIM/DMARC records, not one per message.
The DNSBL checks reuse the same client and add their own per-IP verdict
cache (`MAIL_ON_RAILS_RBL_CACHE_TTL`).

## Test / run

    bundle install
    bin/test                    # Rails-free suite (loopback sessions, sender auth, contracts)
    bin/server                  # foreground daemon
    bin/server --check-config   # deploy preflight: validate env config, exit 0/1

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
