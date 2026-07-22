# Performance Improvements TODO (mail_on_rails_smtp)

This document captures pinpointed performance risks and concrete remediation steps for `InfiniteLoopEnjoyer/mail_on_rails_smtp`.

## Scope and review notes

- Reviewed key runtime files under `lib/mail_on_rails/smtp/**` and top-level README/config.
- Findings are prioritized by likely impact under real SMTP traffic.
- This is focused on server runtime behavior (session handling, store access, DNS verification, TLS handshake/resource pressure).

---

## 1) Replace O(n) account scans in `Store::Memory` with indexed lookup (High)

### Where

- `lib/mail_on_rails/smtp/store/memory.rb`
  - `authenticate`
  - `local_rcpts`
  - `smtp_store`

### Current issue

Several hot paths scan `@accounts.values` and rebuild email arrays repeatedly:

- `authenticate` uses `@accounts.values.find { ... }`
- `local_rcpts` computes `known = @accounts.values.map { ... }`
- `smtp_store` also computes `known` and does repeated inclusion checks

This creates O(n) behavior for operations that run per session/message and increases allocations under load.

### Change

Add an email index and use O(1) lookups:

- Introduce `@accounts_by_email = { normalized_email => account }`
- Maintain index in `add_account`
- In `authenticate`, resolve account directly via `@accounts_by_email[normalize(email)]`
- In `local_rcpts`, test membership via `@accounts_by_email.key?(email)`
- In `smtp_store`, partition local/remote using hash membership (no rebuilt `known` array)

### Why this helps

- Reduces CPU time for auth/recipient checks as account count grows.
- Reduces temporary array/string allocations and GC pressure.
- Improves latency consistency during bursts.

### Acceptance criteria

- Existing tests continue to pass.
- Add/adjust benchmarks or micro-tests demonstrating improvement for large account counts.

---

## 2) Reduce lock contention in `Store::Memory` (High)

### Where

- `lib/mail_on_rails/smtp/store/memory.rb`

### Current issue

A single monitor (`@lock`) guards most operations. With concurrent sessions, unrelated operations serialize on one lock.

### Change

Option A (preferred for reference store simplicity):

- Keep current lock but minimize work under lock (normalize/preprocess outside lock where safe).

Option B (if keeping high-concurrency in-memory scenarios):

- Split locking by concern:
  - account/index access lock
  - inbound queue lock
  - outbound queue lock
  - counter/id lock (or atomic-ish safe strategy)

### Why this helps

- Increases concurrent throughput when many sessions hit auth + enqueue paths simultaneously.
- Reduces head-of-line blocking in the reference store.

### Acceptance criteria

- No race conditions introduced.
- Contract tests remain green.
- Under concurrent load test, less lock wait time / better throughput.

---

## 3) Add DNS result caching in sender auth (SPF/DKIM/DMARC) (High)

### Where

- `lib/mail_on_rails/smtp/sender_auth/dns.rb`
- Callers in SPF/DKIM/DMARC verification flow (`sender_auth/*`)

### Current issue

Sender verification can perform multiple DNS lookups per message. Even with lookup limits, repeated queries across sessions create latency and network overhead.

### Change

Introduce a bounded, short-TTL cache in DNS resolver layer:

- Cache key: `[record_type, normalized_name]`
- Store value + expiry
- Separate TTL policy:
  - positive answers (e.g. 30–120s)
  - negative/no-answer (shorter, e.g. 15–30s)
- Cache transient failures very briefly (or not at all), to avoid amplifying outages.
- Add max-size + eviction strategy (simple LRU-ish or capped hash with periodic sweep).

### Why this helps

- Cuts repeated network round-trips for common domains.
- Lowers per-message verification latency.
- Stabilizes performance during bursts from same sender domains.

### Acceptance criteria

- Behavior correctness preserved (especially temperror vs no-record semantics).
- Tests cover cache hit/miss, TTL expiry, and negative caching behavior.
- Observable drop in DNS calls/message under repeated-domain load.

---

## 4) Tune implicit TLS handshake timeout defaults (High/Medium depending environment)

### Where

- `lib/mail_on_rails/smtp/worker.rb` (`HANDSHAKE_TIMEOUT = 30`)

### Current issue

Slow clients can occupy connection slots for up to 30 seconds during handshake, increasing slot pressure under abuse or adverse network conditions.

### Change

- Lower default timeout for production (e.g. 10–15s).
- Ensure listener-level override remains available (`spec[:handshake_timeout]`).
- Document recommended values by environment.

### Why this helps

- Frees connection capacity faster.
- Reduces impact of slowloris-like behavior on TLS listeners.

### Acceptance criteria

- Timeout values configurable and documented.
- No regressions for legitimate clients on normal networks.
- Metrics show reduced long-held handshake sessions.

---

## 5) Reduce avoidable allocations in hot paths (Medium)

### Where

- `store/memory.rb` hot methods
- `sender_auth/spf.rb` parsing/normalization path

### Current issue

Frequent `split/downcase/strip/map/uniq` on repeated flows can add allocation pressure.

### Change

- Normalize once per phase and reuse local vars.
- Avoid rebuilding arrays where membership/hash lookup suffices.
- Consider frozen constants for repeated maps where appropriate.

### Why this helps

- Lowers GC churn under sustained throughput.
- Improves p95 latency consistency.

### Acceptance criteria

- Allocation count reduction in benchmark/profiler output.

---

## 6) Validate `ConnLimiter` under high churn for mutex hotspot risk (Medium)

### Where

- `lib/mail_on_rails/smtp/conn_limiter.rb`

### Current issue

`acquire/release` are mutex-guarded and called for every connection lifecycle. Usually fine, but could become a hotspot under very high accept/release rates.

### Change

- Add benchmark/load-test coverage to confirm actual contention.
- Only optimize if proven:
  - shard counters by listener or worker
  - reduce critical section work

### Why this helps

- Prevents premature optimization while still guarding scalability.

### Acceptance criteria

- Data-backed decision from profiling/load test.

---

## 7) Add performance instrumentation/metrics (High, enabling)

### Where

- Session lifecycle and sender-auth paths
- Store calls and TLS handshake sections

### Current issue

Without timing and counters, bottlenecks are hard to verify and tune.

### Change

Add structured metrics for at least:

- SMTP session duration
- TLS handshake duration + timeout count
- DNS lookup latency by record type + outcome
- SPF/DKIM/DMARC verification duration and outcomes
- Store call latency (`authenticate`, `local_rcpts`, `smtp_store`)
- Connection limiter rejects (global/per-IP)

### Why this helps

- Makes performance work measurable.
- Enables safe tuning of limits/timeouts.

### Acceptance criteria

- Metrics emitted in logs and/or monitoring backend.
- Dashboard or query examples for p50/p95/p99 and error rates.

---

## Suggested implementation order

1. **Store::Memory lookup/index optimization**
2. **DNS cache in sender auth resolver**
3. **Metrics instrumentation**
4. **Handshake timeout tuning**
5. **Lock contention refinements (if still needed after metrics)**
6. **ConnLimiter optimization only if benchmark indicates bottleneck**

---

## Validation plan

- Run full test suite (`bin/test`).
- Add focused micro-benchmarks:
  - auth/local_rcpts/smtp_store with growing account counts.
  - repeated SPF/DKIM domain checks with and without cache.
- Run synthetic concurrency load:
  - mixed authenticated/unauthenticated sessions
  - bursty same-domain traffic
  - handshake-slow clients
- Compare before/after:
  - throughput
  - p95/p99 session latency
  - CPU and memory/GC behavior
  - DNS calls per message

---

## Notes

- `Store::Memory` is a reference/test store, not production, but optimizing it still improves test realism and any embedded/dev usage.
- Keep SMTP correctness and RFC behavior unchanged while improving implementation efficiency.
