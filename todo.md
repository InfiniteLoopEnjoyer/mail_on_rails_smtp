# TODO

Reliability, security, and feature work for `mail_on_rails_smtp`.

> **Re-triaged 2026-07-22** after a full read of `lib/` and `test/`. The original
> 20-item list read as a generic "production MTA" checklist; this revision grounds
> each item against what the code and tests actually do. Original item numbers are
> kept in parentheses for traceability. Headline changes:
>
> - **Several items were already done or nearly done** (DNS failure harness,
>   outbound-scope docs, HTTP-store error-envelope basics).
> - **Several items belong to the host Rails app, not this daemon** — this daemon
>   deliberately has no queue, no database, and no policy store. Queue durability,
>   dead-lettering, spam scanning, tenant policy, and outbound DKIM are the app's
>   concerns (or moot).
> - **Four concrete, code-level gaps surfaced during the read** that outrank most
>   of the original list. They are now items N1–N4.

## Priority guide

- **P0**: Required before broad production rollout
- **P1**: Strongly recommended for production hardening
- **P2**: Nice to have; small docs/tests

---

## New findings from the code read (not in the original list)

### N1) Implicit-TLS handshake has no timeout — **P0 — DONE 2026-07-22** *(found while assessing #2)*

> **Resolved:** `Worker#handle` now sets a 30 s IO timeout (`HANDSHAKE_TIMEOUT`,
> overridable via `spec[:handshake_timeout]`) on the raw socket before
> `TLS.accept`; the scheduler's `io.timeout` handling raises `IO::TimeoutError`
> into the parked fiber, and the existing `IOError` rescue closes the socket and
> releases the slot. Validated by
> `test_implicit_tls_handshake_timeout_frees_the_slot` in
> `worker_pool_test.rb` (confirmed to fail against the unfixed code).
**What the code does today**
- Port 465 (`tls: :implicit`): `Worker#handle` calls `TLS.accept` **before** the
  session runs, so `set_timeout(300)` has not happened yet. The raw socket's
  `IO#timeout` is nil, and `Scheduler#io_wait` only arms an idle timer when
  `io.timeout` is set. A client that connects and sends nothing (or stalls
  mid-handshake) parks a fiber **forever** and holds a `ConnLimiter` slot
  indefinitely. TCP keepalive only reaps *dead* peers, not alive-and-silent ones —
  100 such connections take the server offline for the cost of 100 idle sockets.
- The STARTTLS path (25/587) is bounded: the 300 s idle timeout is set at session
  start, before the upgrade handshake reads.

**Plan**
- Set an IO timeout on the accepted socket before the implicit-TLS handshake (in
  `Worker#handle` or at accept time), shorter than the session idle timeout —
  30–60 s is conventional for a handshake.
- Test: connect to an implicit-TLS listener, send nothing, assert the slot is
  released within the bound (loopback, short spec-injected timeout).

**Deliverables**
- Fix in `worker.rb` (one or two lines) + a test in `worker_pool_test.rb`.

---

### N2) Dead worker Ractor silently drops 1/N of all future connections — **P0/P1 — DONE 2026-07-22** *(found while assessing #6)*

> **Resolved with respawn-then-fail-fast:** a monitor thread per worker
> Ractor (`Server#monitor_worker` via `Ractor#value`) logs a death at error
> level and spawns a replacement; after `MAX_WORKER_RESPAWNS` (5) deaths per
> process the failure is treated as systemic — the accept loops stop,
> `Server#run` returns, and `Daemon.run!` exits non-zero for the container
> restart. Slot accounting survives death: release-pipe lines now carry the
> worker index, a per-worker inflight table (dispatch runs fully under the
> mutex) is swept on replacement to free lost sessions' global/per-IP slots,
> and the table is the source of truth so late release lines can't
> double-free. **Bonus finding:** deaths were even sneakier than assumed —
> all serving ran inside `Scheduler#close` during *thread-exit cleanup*, so
> a fatal session error was reported-and-swallowed and the Ractor
> "terminated normally" (`:worker_exit`). `Worker#serve` now runs the event
> loop explicitly and `Scheduler#close` is one-shot (guarded even on raise)
> so a half-dead worker can't zombie-serve during cleanup. Validated by two
> tests in `worker_pool_test.rb` (an Exception-raising store kills a live
> worker): respawn + slot sweep proven by two concurrent per-IP slots after
> the death; budget exhaustion proven by `Server#run` returning. Both
> failed against the swallowing behavior before the fix.
**What the code does today**
- `Server#dispatch` round-robins fd numbers over per-Ractor control pipes. If a
  worker Ractor dies (bug, Ractor-mode Ruby regression), writes to its pipe raise
  `EPIPE`, `dispatch` rescues, releases the slot, and closes the socket. There is
  no respawn and no alarm: every Nth connection is silently dropped, forever.

**Plan**
- Pick a policy and test it. Two reasonable options:
  1. **Fail fast**: a dead worker kills the server thread → `Daemon.run!` exits
     non-zero → Docker/Kamal restarts the container. Simplest, matches the
     existing "listener died" philosophy.
  2. **Respawn**: detect the broken pipe, log loudly, spawn a replacement worker.
- Either way, log at error level with enough context to notice in production.

**Deliverables**
- Policy implementation in `server.rb` + a test that kills a worker Ractor and
  asserts the chosen behavior.

---

### N3) TLS misconfiguration silently degrades to plaintext-only — **P0 — DONE 2026-07-22** *(overlaps #10)*

> **Resolved:** `TLS.material` now raises `TLS::Error` when
> `MAIL_ON_RAILS_TLS_CERT`/`_KEY` are set but missing, unloadable, or set
> without the other (`TLS.explicit_material`); the rescue-to-nil forgiveness
> now scopes only the self-signed dev path. `Daemon.run!` catches `TLS::Error`
> and exits 1 with a clear message (embedded `Daemon.start` callers get the
> raise). Validated by `test/tls_material_test.rb` (8 tests: fatal paths,
> valid path material, mismatched cert/key, half-set config, still-forgiving
> dev path, and a `Daemon.run!` refuses-to-start test asserting non-zero exit
> and the logged path — the fatal-path tests confirmed to fail against the
> unfixed code, where the daemon boots plaintext and serves indefinitely).
**What the code does today**
- `Daemon.start` → `TLS.material` rescues *any* error (typo'd cert path,
  unreadable key, malformed PEM), logs a warning, and boots anyway with
  `material = nil`: the SMTPS listener is skipped, STARTTLS is never offered, and
  AUTH is never offered (correctly, since it requires TLS). A one-character typo
  in `MAIL_ON_RAILS_TLS_CERT` turns a production mail host into a
  plaintext-only, no-submission server that *looks* up.

**Plan**
- When `MAIL_ON_RAILS_TLS_CERT`/`_KEY` are explicitly set, treat failure to load
  them as **fatal at boot**. Keep the graceful fallback only for the implicit
  self-signed dev path.

**Deliverables**
- Change in `daemon.rb`/`tls.rb` + config-validation tests (see #10).

---

### N4) Mixed-recipient partial failure double-queues outbound mail — **P1 — DONE 2026-07-22 (with #3)** *(overlaps #16)*
**What the code does today**
- `Store::Http#smtp_store` with both remote and local recipients: it queues
  outbound first, then POSTs inbound to the ingress. If outbound succeeds and the
  ingress then fails, the session answers 451, the sending client retries the
  whole message, and the outbound copies are queued **again**. (Crash between
  ingress success and the SMTP 250 has the same shape — unavoidable SMTP
  at-least-once — but this path duplicates on every retry while the ingress is
  down.)

**Plan**
- Decide: accept duplication (document it), or make `queue_outbound` idempotent
  app-side (e.g. dedupe on a content hash), or split the reply per RFC (not
  really possible — SMTP has one reply per message). Documenting + app-side
  dedupe key is the pragmatic fix.
- Add a test pinning whichever behavior is chosen.

**Deliverables**
- Test in `http_store_test.rb` + a "delivery guarantees" note (see #4).

---

## A) Test coverage gaps — re-triaged

### 1) Real network/DNS failure behavior — **mostly DONE; residual P2**
**Analysis**
- The original premise ("unit tests with FakeResolver cannot prove behavior under
  resolver timeouts, truncation, SERVFAIL") is out of date:
  `test/dns_transport_test.rb` already runs a **scripted loopback nameserver**
  (real UDP + TCP sockets) covering timeouts, UDP→TCP truncation retry,
  NXDOMAIN-vs-SERVFAIL distinction, and unreachable servers.
- The "assert 4xx vs 5xx SMTP outcomes" framing is also wrong for this design:
  DNS failure does **not** tempfail the message — it yields `temperror` verdicts
  that are stamped and delivered (README documents this deliberately).

**Residual work (small)**
- Malformed/garbage DNS packets: what does `Resolv::DNS::Message.decode` raising
  do? (It should surface as no-verdict via `verify_sender`'s rescue, never kill a
  session — pin that with a test.)
- One end-to-end test: resolver raising `Dns::TempError` during a session →
  message still accepted with `temperror` in the stamped
  `X-MailOnRails-Auth-Results`.

---

### 2) TLS failure cases — **P1 — DONE 2026-07-22**

> **Resolved:** `test/tls_failure_test.rb` covers garbage-after-STARTTLS
> (connection torn down, worker survives), mid-handshake disconnect, and the
> previously untested `ContextProvider` renewal flow: renewed cert files are
> picked up live, a broken renewal keeps serving the old context, a
> completed renewal recovers after a broken one, static PEM material never
> reloads. Client-cert validity tests were skipped by design (VERIFY_NONE —
> the client's concern).
**Analysis**
- The original plan (expired certs, bad SAN/CN, invalid chain) tests behavior
  this server doesn't have: it runs `VERIFY_NONE` and never validates client
  certs; cert validity is the *client's* concern. Those tests would assert
  OpenSSL, not this codebase.
- The server-relevant failure modes are different, and one of them is N1 above.

**Revised plan**
- Handshake stall / mid-handshake disconnect: session slot released, worker
  survives (N1 covers the implicit-TLS half; add the STARTTLS half).
- Garbage bytes after `STARTTLS` 220 → clean teardown (the `SSLError → IOError`
  path in `SmtpServer#starttls`).
- `TLS::ContextProvider` live-reload: touch cert/key files, assert a new context
  is served; corrupt the files mid-"renewal", assert the old context keeps
  serving (the rescue path in `ContextProvider#context`). This is load-bearing
  for the Let's Encrypt renewal flow described in `config/deploy.yml` and is
  currently untested.

**Deliverables**
- `test/tls_failure_test.rb` (loopback; the existing `generate_self_signed`
  helper makes fixtures — no fixture generator script needed).

---

### 3) HTTP store failure taxonomy — **P1 — DONE 2026-07-22** *(includes N4)*

> **Resolved:** `InternalApi` gained injectable timeouts and a 401 hint
> (`(check MAIL_ON_RAILS_INTERNAL_API_PASSWORD)`) so auth rejections read as
> config, not weather. New tests drive the REAL Net::HTTP client against a
> scripted TCP responder: hung app (bounded by read timeout), non-JSON 200,
> 401, refused connection — all degrade to the `:internal` envelope. The
> no-retry policy and both at-least-once duplicate windows are now
> documented in the `Store::Http` class comment, and N4 (outbound re-queued
> on sender retry after an ingress failure) is pinned by a test so any
> change to the ordering is a conscious one.
**Analysis**
- Partially done: `http_store_test.rb` covers connection-refused → `:internal` →
  451, ingress refusal → 451, and 507 → `:insufficient_storage` → 452.
- "Define retry/backoff policy" is answered by the architecture: **deliberately
  no retry** — the sending MTA is the retry queue (README, `Store::Http` docs).
  Don't build backoff; document the no-retry policy explicitly and test the
  mapping instead.

**Residual work**
- Read-timeout behavior (`Net::ReadTimeout` after 60 s) → `:internal` → 451, and
  confirm a hung app can't wedge a session longer than the timeout.
- Non-JSON 200 body → `JSON::ParserError` → 451 (pin it).
- 401 from the internal API (wrong password) → currently indistinguishable from
  any 5xx. Consider logging it distinctly — it's a config error, not weather.
- N4 (outbound duplication) is the real taxonomy gap.

**Deliverables**
- Additional cases in `test/http_store_test.rb`; a short "no-retry policy"
  paragraph in the `Store::Http` comment or README.

---

### 4) Crash/restart durability — **downgraded to P2 doc work**
**Analysis**
- The original plan assumed a local queue with commit points. There is none: the
  only durable step is the ingress/API POST, and the code never ACKs before it
  succeeds. The semantics are already deterministic and readable from
  ~15 lines of `Store::Http#smtp_store`: **at-least-once**, with duplicates
  possible if the process dies between ingress success and the SMTP 250 (plus
  the N4 case). Kill-at-phase integration harnesses would be a lot of machinery
  to re-prove what the code structure guarantees.

**Revised plan**
- Write the "delivery guarantees" README section (this part of the original item
  was right): no local spool; tempfail-and-retry when the app is down;
  at-least-once; duplicate windows named explicitly.
- Keep `test_disconnect_mid_data_stores_nothing` (already exists) as the pinned
  at-most-once-before-commit behavior.

---

### 5) Backpressure under sustained load — **folded into #12; soak optional P2**
**Analysis**
- The concrete exposure is not gradual resource creep — sessions are fibers with
  capped buffers — it's that the **global 100-connection cap has no per-IP
  component**: one IP can hold all 100 slots for 300 s each (or forever, via N1).
  That is an anti-abuse feature gap (#12), not a soak-test gap.
- A nightly soak profile is respectable but low-yield for a single-tenant
  personal stack; keep it as an optional P2 once per-IP caps exist.

---

### 6) Ractor race/regression matrix — **kept, focused: see N2, P1**
**Analysis**
- Ractor mode is genuinely the most fragile surface (the code itself documents
  Ruby 4.0.6 workarounds in `scheduler.rb`/`worker.rb`), and existing Ractor
  tests cover only happy paths + the release pipe.
- The highest-value single case is worker death (N2). Deterministic "race tests"
  for fd handoff ordering are hard to make non-flaky and the pipe protocol is
  simple; prefer the death/recovery test plus keeping the existing loopback
  tests running in both modes.
- A CI matrix across Ruby versions is worthwhile the day this has CI at all —
  note there is currently **no CI config in the repo**, which is arguably a
  prerequisite TODO for half this document.

---

### 7) Protocol fuzzing — **P1 — DONE 2026-07-22**

> **Resolved:** `test/smtp_parser_abuse_test.rb` — seeded-PRNG garbage
> sessions (binary, control bytes, invalid UTF-8, junk args, overlong
> lines) with global invariants (every reply well-formed, nothing stored,
> and the parser-crash signature `"SMTP session error"` forbidden in logs),
> plus deterministic edge cases: NUL in commands, overlong-line fragments
> setting no envelope state, a 200-command pipelining blast, garbage-base64
> AUTH and challenge recovery. **Found and fixed one real issue:** EHLO/HELO
> arguments were echoed raw into replies, so a bare LF inside a command
> injected raw lines into our response — `reply`/`multi` now flatten
> unprintable bytes (fix verified to fail without it).
**Analysis**
- Real, but right-size it: the dispatcher is small and the scary cases
  (dot-stuffing smuggling, CRLF split at the chunk cap, overlong lines, flood
  past 2× size cap) are already pinned in `smtp_session_test.rb`.

**Revised plan**
- One deterministic test file (seeded PRNG, not a fuzzing framework): random
  garbage lines, control bytes/NUL, invalid UTF-8, absurd pipelining, base64
  garbage to AUTH continuations, `MAIL FROM` args with CR/LF-adjacent junk.
  Assert: some 4xx/5xx reply or clean disconnect, session never raises through
  `Session#run`, store never receives a partial message.

**Deliverables**
- `test/smtp_parser_abuse_test.rb` (no corpus files needed at this size).

---

### 8) Security hardening edge cases — **P1 — DONE 2026-07-22** *(rate limits shipped with #12)*

> **Resolved:** `test/ingress_stamping_test.rb` pins the trust boundary:
> folded forged trust headers stripped with their continuations, mixed-case
> and bare-LF variants stripped, lookalike headers kept, CR/LF injection
> through envelope values (MAIL FROM / RCPT / auth-results) flattened, and
> every stamped header line verified control-byte-free.
**Analysis**
- Header smuggling defenses exist and are partially tested
  (`IngressClient#strip_trusted_headers` handles folded headers via the
  `\r?\n(?![ \t])` split; forged-copy stripping is tested).
- Auth abuse: `MAX_AUTH_ATTEMPTS = 3` is **per-session** only. Reconnecting
  grants a fresh 3 guesses, and every guess is an HTTP call to the host app —
  unthrottled credential stuffing passes straight through. That's the #12 work.

**Residual work (cheap)**
- Tests: forged *folded* trust header (with continuation line) fully stripped;
  mixed-case `x-mailonrails-*`; bare-LF line endings in the submitted header
  block; CR/LF injection attempts through `MAIL FROM`/`RCPT TO` values reaching
  `sanitize_header`.

**Deliverables**
- Cases added to `test/http_store_test.rb` / a small
  `test/ingress_stamping_test.rb`.

---

### 9) Observability failure modes — **downgraded to P2**
**Analysis**
- The original plan presupposes a metrics system; none exists, and building a
  field dictionary + metric assertions before there is a consumer is inverted.
  Logging is already consistent (every reject/tempfail path logs with peer IP,
  credentials are redacted, DATA is never traced — and *that* is tested).

**Revised plan**
- Defer until something consumes metrics. If/when: a `store.count(event)`-style
  hook is the natural seam, since every interesting path already calls the store.

---

### 10) Config validation — **P1 — DONE 2026-07-22**

> **Resolved:** new `Smtp::Config` module (`Config.int`/`Config.port`) gives
> every env integer a named, bounded, actionable error; used by all listener
> caps, ports, DNS timeout, and worker count. `Daemon.listeners` rejects
> duplicate ports; `Daemon.run!` refuses to start on `Config::Error` (same
> path as `TLS::Error`); `bin/server --check-config` runs the preflight
> (summary line + warnings, exit 0/1) and catches even require-time constant
> failures as one clean line. `Daemon.config_warnings` flags the quiet
> footguns: unset API/ingress passwords, unknown `WORKER_MODE`, and
> `DMARC_ENFORCE=true` (only `"1"` enables). 11 tests in
> `config_validation_test.rb`; all three CLI paths exercised live.
**Analysis**
- Correct and cheap. Today: bad port strings raise a bare `ArgumentError` from
  `Integer()`; a missing internal-API password only surfaces as runtime 451s/535s;
  explicit TLS paths that don't load fall back to plaintext (N3).

**Plan**
- Boot-time validation with clear messages: ports parse, TLS material loads when
  explicitly configured (N3 = fatal), warn loudly when
  `MAIL_ON_RAILS_INTERNAL_API_PASSWORD`/ingress password are unset outside dev.
- `bin/server --check-config`: run the same validation and exit 0/1 — useful as a
  deploy preflight and a Docker HEALTHCHECK-adjacent smoke test.

**Deliverables**
- `test/config_validation_test.rb`; validation in `daemon.rb`; `--check-config`.

---

## B) Features — re-triaged

### 12) Anti-abuse: per-IP caps + auth throttling — **P0 — DONE 2026-07-22** *(absorbs #5, #8-auth)*

> **Resolved:** `ConnLimiter` gained a per-IP concurrent-connection cap
> (`MAIL_ON_RAILS_SMTP_MAX_CONN_PER_IP`, default 10) and a new accept-side
> `AuthThrottle` locks an IP out after repeated failed AUTHs
> (`MAIL_ON_RAILS_SMTP_AUTH_LOCKOUT_FAILURES`/`_SECONDS`, default 10 failures
> / 15 min, quiet-period decay, table sweep). `0` disables either. The
> Ractor boundary is solved by threading the accept-time peer IP through the
> control pipe (`"<fd> <idx> <ip>"`) and back on the now line-based release
> pipe, plus a second auth-failure pipe; sessions report failures via an
> optional `on_auth_failure` writer so `Session.new` signatures are
> unchanged. Locked IPs get `421` at accept (tempfail — shared-IP legit mail
> is delayed, not lost) without consuming a limiter slot. Validated by
> `conn_limiter_test.rb` + `auth_throttle_test.rb` (unit, injected clock)
> and four integration tests in `worker_pool_test.rb` covering both features
> in both worker modes — all four confirmed to fail (second connection
> welcomed with 220) against the unfixed code.
**Analysis**
- The one genuinely missing production feature. Today a single IP can: hold all
  100 connection slots (300 s idle each, or forever via N1), and stuff
  credentials at full speed limited only by 3-per-connection.
- Tarpitting, greylisting, and reputation-hook interfaces from the original item
  are over-scope for this stack — spam policy has a natural home in the host
  app's mailroom. Cut them.

**Plan**
- **Per-IP concurrent connection cap** (e.g. default 10) in/beside `ConnLimiter`.
  Must live on the accept side — worker Ractors are isolated, so session-side
  state can't be shared. `ConnLimiter` already runs accept-side, so this is a
  natural extension of it (acquire/release keyed by IP).
- **Per-IP auth-failure lockout with decay** (e.g. 10 failures → refuse AUTH from
  that IP for 15 min). Same accept-side placement problem: simplest is a small
  mutex-guarded table owned by the accept side, consulted at accept or passed as
  a shared pipe-message; alternatively enforce app-side in the `authenticate`
  endpoint. Choose during implementation — the Ractor boundary is the design
  constraint to solve.
- Config via env with safe defaults; both limits off = current behavior.

**Deliverables**
- Extension of `conn_limiter.rb` (+ session/auth hook) with tests; env knobs
  documented in README.

---

### 17) Operational tooling — **scaled down to a healthcheck, P2**
**Analysis**
- Queue stats/replay/purge belong to the host app (it owns the queue). What this
  daemon lacks is any liveness signal for Docker/Kamal beyond "process exists".

**Plan**
- `bin/healthcheck`: TCP-connect to the MX port, expect a `220` banner, exit 0/1.
  Wire it as the Dockerfile `HEALTHCHECK`/Kamal check.

---

### 15) ESMTP capability matrix — **P2 doc, as originally proposed**
- Small and legit: a table of supported commands/extensions (`SIZE`, `8BITMIME`,
  `PIPELINING`, `STARTTLS`, `AUTH PLAIN LOGIN`; `SMTPUTF8` not advertised;
  unknown commands → 502). A handful of conformance assertions already exist in
  the session tests; extend slightly rather than building a new suite.

---

### 18) HA / horizontal scale — **P2 doc**
**Analysis**
- The daemon is stateless by design (all state is HTTP calls to the app), so the
  original "define stateless/stateful boundaries" work is a paragraph, not a
  project: N instances behind multiple MX records / an L4 LB just work; no sticky
  sessions; the shared dependency and real SPOF is the host app. Note the
  per-deploy downtime window from `.kamal/hooks/pre-app-boot` (stop-old-first) —
  peers retry, but it belongs in the doc.

---

## Resolved / out of scope (with reasons)

- **(11) Outbound relay boundary clarity** — already documented: README and
  `config/deploy.yml` both state outbound queueing is delegated to the host app
  via `POST outbound_messages`. No action.
- **(13) Spam/virus scanning hooks** — the host app receives the complete
  message with auth verdicts stamped; it is the natural scanning/policy point.
  A daemon-side hook would duplicate that seam. Revisit only if pre-DATA
  rejection (saving bandwidth on huge spam) ever matters at this scale.
- **(14) Outbound DKIM signing** — not "deferred": **out of scope permanently
  for this repo**. Outbound transport lives in the host app; signing belongs
  where sending happens.
- **(16) Queue durability / dead-letter** — no queue exists in this daemon;
  inbound durability is the sending MTA's retry queue, outbound durability is
  the host app's queue. The one real artifact (duplication window) is N4.
- **(19) Tenant/domain policy controls** — YAGNI for a single-app personal
  stack; per-account policy already lives behind the internal API
  (`authenticate`, `rcpt_check`), which is the right extension point if ever
  needed.
- **(20) Compliance/audit** — YAGNI now; the pieces that matter are done
  (credential redaction and DATA exclusion in traces, both tested).

---

## Revised execution order

### Phase 1 — before real traffic (P0)
1. **N1** implicit-TLS handshake timeout (small fix, closes an unauthenticated DoS)
2. **N3** fail-fast on explicit TLS config errors (small fix)
3. **12** per-IP connection cap + auth-failure throttle
4. **N2** worker-Ractor death policy (fail-fast is acceptable and cheapest)

### Phase 2 — hardening (P1)
5. **10** config validation + `--check-config`
6. **3 + N4** HTTP store: timeout/non-JSON cases, duplication test, no-retry doc
7. **2** TLS failure tests incl. ContextProvider renewal reload
8. **7** parser abuse test file
9. **8** trust-header edge-case tests
10. ~~CI setup~~ **DONE 2026-07-22** — `.github/workflows/ruby.yml` existed
    but was broken: it ran `bundle exec rake` (no Rakefile exists) with a
    2023-pinned `setup-ruby` that predates Ruby 4.0. Now runs `bin/test` +
    `rubocop --parallel` on `ruby/setup-ruby@v1` (repo is rubocop-clean).

### Phase 3 — docs and polish (P2)
11. **4** delivery-guarantees README section
12. **17** `bin/healthcheck`
13. **15** capability matrix doc
14. **18** HA paragraph
15. **1** DNS malformed-packet + end-to-end temperror tests
16. **5** optional soak profile; **9** metrics hook when a consumer exists
