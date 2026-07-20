# mail_on_rails_smtp

A standalone SMTP server (RFC 5321 subset): MX + submission listeners with
STARTTLS/implicit TLS, AUTH, SPF/DKIM/DMARC verification of inbound mail,
and DoS caps. Designed as the mail-receiving frontend for a Rails app.

The daemon holds **no database credentials and no Rails**: credential
checks, recipient validation, and outbound queueing are HTTP calls to the
host app's private API, and accepted inbound mail is POSTed to the app's
Action Mailbox relay ingress. If the app is down, sessions answer
temporary failures and sending servers retry.

Persistence is pluggable: any store satisfying the contract can back the
server. `Store::Memory` is the dependency-free reference implementation,
`Store::Http` the production client, and `Store::Contracts` the
executable (Minitest) spec a custom store must pass.

## Layout

- `lib/mail_on_rails/smtp/` - the gem: listener scaffolding
  (`Server`/`ConnLimiter`/`TLS`), the SMTP session (`SmtpServer`),
  `SenderAuth` (SPF/DKIM/DMARC), and stores (`Store::Memory` reference
  implementation, `Store::Http` production client, `Store::Contracts`
  executable contract suite).
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
| `MAIL_ON_RAILS_TLS_CERT` / `_TLS_KEY` | - | PEM paths (else self-signed under `MAIL_ON_RAILS_TLS_DIR`, default `storage/tls`) |
| `MAIL_ON_RAILS_DMARC_ENFORCE` | off | `1` rejects on DMARC policy |
| `MAIL_ON_RAILS_DNS_TIMEOUT` | `5` | Seconds per DNS lookup in sender verification |
| `MAIL_ON_RAILS_SMTP_MAX_CONN` | `100` | Connection cap |

## Sender verification (SPF / DKIM / DMARC)

Unauthenticated mail arriving on the MX port is verified after `DATA` by
`SenderAuth` — hand-rolled SPF (RFC 7208), DKIM verification (RFC 6376,
rsa-sha256 and ed25519-sha256), and DMARC (RFC 7489) on plain `Resolv` +
OpenSSL. The verdict is stamped as a forge-proof
`X-MailOnRails-Auth-Results` header before the message is relayed to the
host app. Two caveats to know about:

### DMARC enforcement is OFF by default

A message that fails DMARC under a published `p=reject` policy is still
**delivered** (with the failure recorded); the server only logs
`would reject message ... under DMARC enforcement`. This is deliberate: a
verifier bug should not bounce legitimate mail while the implementation is
young. Once the logs look right against real traffic, enable rejection with:

    MAIL_ON_RAILS_DMARC_ENFORCE=1

With enforcement on, such messages are refused at SMTP time with
`550 5.7.1 Rejected per DMARC policy of <domain>`.

### DNS failures fail open

Ruby's `Resolv` cannot distinguish NXDOMAIN from SERVFAIL or a timeout (all
three surface identically, verified empirically — see
`lib/mail_on_rails/smtp/sender_auth/dns.rb`). A transient DNS failure
therefore looks like "no record published": verdicts weaken to `none`
instead of `temperror`, and mail is accepted rather than tempfailed. That
is the safe direction while verdicts are recorded rather than enforced,
but it means a DNS outage temporarily blinds sender verification — worth
revisiting (e.g. a resolver that speaks DNS directly) before leaning
harder on enforcement.

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
