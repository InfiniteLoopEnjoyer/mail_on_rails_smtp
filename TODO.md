# TODO — ideas adopted from Postal analysis

Derived from reviewing [Postal](https://github.com/postalserver/postal)
(MIT, cloned at `/home/deploy/postal`) on 2026-07-21. Each item cites the
Postal source it's based on. Pending review — nothing here is committed
roadmap yet; see README for the existing roadmap these complement.

## Protocol correctness

- [ ] **Strict DATA terminator (CR tracking)** — require a true
  `\r\n.\r\n` to end DATA, not a bare `.` line. Postal tracks
  `@cr_present`/`@previous_cr_present` across lines
  (`app/lib/smtp_server/client.rb:55-64`, terminator check at `:426`).
  Guards against bare-LF smuggling/desync (SMTP smuggling class of bugs).
  Fold into the planned parser rewrite.
- [ ] **Received-header loop detection** — count `Received:` headers
  mentioning our hostname; reject with `550 Loop detected` above a
  threshold (Postal uses > 4, `client.rb:472-477`). Cheap and effective.
- [ ] **Enforce max message size mid-stream** — Postal buffers the whole
  message then checks its 14 MB cap after the fact (`client.rb:465-470`).
  Do better: track bytes during DATA and cut off at the limit instead of
  buffering unbounded input. (Verify what we do today; make it a hard
  in-stream cap either way.)

## Deployability

- [ ] **PROXY protocol v1 support** — needed if the daemon ever sits
  behind a load balancer that would otherwise mask peer IPs (which our
  per-IP rate limiting and RBL roadmap items depend on). Postal's is a
  clean, small reference including the easy-to-get-wrong sequencing of
  delaying the `220` banner until the PROXY line arrives
  (`client.rb:118-132`, `server.rb:117-123`). v1 text form only.
- [ ] **TCP keepalive tuning on the listener** — Postal sets
  `SO_KEEPALIVE` plus `TCP_KEEPIDLE=50`, `TCP_KEEPINTVL=10`,
  `TCP_KEEPCNT=5` (`server.rb:72-89`) so dead peers get reaped at the
  TCP layer. Complements our existing 300s idle timeout.

## Architecture (feeds the existing async-IO roadmap item)

- [ ] **Evaluate nio4r reactor vs fiber scheduler** — Postal's SMTP
  server is a single-threaded `NIO::Selector` reactor with per-connection
  state stashed in `monitor.value` (`server.rb:97-296`): a working,
  readable alternative to the `async`-gem route in our README roadmap.
  Its **non-blocking STARTTLS handshake** (`accept_nonblock` retried via
  `WaitReadable`/`WaitWritable` through the event loop, `server.rb:167-182`)
  is the reference for the hardest part. Caveat noted from their design:
  a single reactor turns any blocking call (DNS! tarpit sleeps!) into a
  full-server stall, so this only pans out together with async DNS.
- [ ] **`@proc` continuation pattern for multi-line states** — Postal
  models DATA and AUTH challenge/response by swapping the line handler
  (`client.rb:409-462`) instead of flag-checking in a big dispatch. Tidy
  structure to adopt in the parser rewrite.

## Test suite (from reviewing Postal's specs)

Postal's SMTP specs (`spec/lib/smtp_server/client/`) drive the protocol
state machine line-by-line with no real socket — same style as our suite.
Their case list is a useful checklist, but the bigger finding is what
they *don't* test.

- [ ] **Adopt Postal's covered protocol cases we may be missing** —
  command-ordering guards (`503` for MAIL-before-HELO, DATA-before-RCPT),
  second `MAIL FROM` resetting the transaction, garbage/empty `RCPT TO`
  → `501`, DATA terminator lacking CR being ignored rather than ending
  DATA (`finished_spec.rb:25-42`), oversized-message `552`, Received-loop
  `550`, AUTH protocol-error and state-reset branches, malformed PROXY
  line → `502` + disconnect. Audit our suite against this list.
- [ ] **Write the hostile-input cases Postal lacks** (nothing to port —
  greenfield): bare-LF wire handling; `..` dot-unstuffing of body lines
  (Postal only tests the terminator dot); MAIL/RCPT parameter parsing
  (`SIZE=`, `BODY=8BITMIME`, `<>` null sender, source routes, missing
  angle brackets); over-long command lines; pipelining; unknown verbs;
  AUTH-before-TLS and STARTTLS-downgrade behavior; CR/LF header
  injection via envelope addresses; address-syntax edges (quoted
  local-parts, IDN/SMTPUTF8, IP-literal domains, multiple `@`);
  malformed MIME/multipart bodies; RFC-2047 encoded-word abuse;
  duplicate/oversized headers. These double as the acceptance tests for
  the parser rewrite.

## Log hygiene

- [ ] **Redact credentials in protocol logs** — Postal flags when the
  next client line will be a password (AUTH LOGIN/PLAIN continuation) and
  logs a placeholder instead (`client.rb:550-561`). Adopt if/when we log
  raw command lines.

## Explicitly NOT adopting from Postal

Recorded so we don't re-litigate later:

- **Its command parser** — `split`-per-line plus regex/`gsub` chains per
  command; exactly the allocation pattern our parser-rewrite roadmap item
  replaces.
- **Its DNS layer** — thin `Resolv` wrapper: no caching, no concurrency,
  and no NXDOMAIN/SERVFAIL/timeout distinction. Validates our plan for a
  direct-UDP resolver.
- **Rate limiting / connection caps / tarpitting / idle timeouts** —
  Postal has none of these (delegates abuse handling to the load
  balancer). Our roadmap items there remain greenfield.
- **Inbound SPF/DKIM/DMARC** — Postal doesn't verify these itself
  (delegates to SpamAssassin/rspamd). Our hand-rolled verifiers already
  go further; keep them.
- **CRAM-MD5 AUTH** — legacy mechanism, weak by design; not worth adding.
