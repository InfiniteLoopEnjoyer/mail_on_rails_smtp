# Performance Analysis

> Audited 2026-07-22 against `lib/` source.
> Triaged 2026-07-22: each item now carries a **Verdict** (fix / accept) and either a
> mitigation plan or the reason it does not need fixing. Scale context that drives the
> verdicts: `MAX_CONNECTIONS` defaults to **100 total** (`MAIL_ON_RAILS_SMTP_MAX_CONN`),
> 10 per IP, spread across `nprocessors` workers — so a single worker's scheduler
> juggles on the order of **tens of fibers**, not thousands.

---

## 🔴 High Impact

### 1. New TCP connection per HTTP request (`InternalApi#perform`)

**File:** `lib/mail_on_rails/smtp/internal_api.rb` (lines 85–92)

Every call to `perform` — authentication, `rcpt_check`, and `queue_outbound` — opens a **fresh TCP (+ TLS) connection** and immediately closes it. `IngressClient#deliver` (`ingress_client.rb:39`) has the same pattern. For a single-recipient authenticated submission that's **4 sequential connect-request-close cycles** per message:

1. `authenticate`
2. `rcpt_check` (from the `RCPT TO` handler)
3. `rcpt_check` again + `queue_outbound` (inside `smtp_store`)
4. `@ingress.deliver` (if local recipients)

**Verdict: FIX — the one change worth making.** Cost is modest on the default loopback URL (`http://127.0.0.1:3000`, no TLS, ~0.1 ms handshake) but becomes real the moment the app is remote or HTTPS (full TCP + TLS handshake per call, easily 10–100× the request itself).

**✅ DONE 2026-07-22** — implemented as `lib/mail_on_rails/smtp/http_pool.rb`, wired into both `InternalApi` and `IngressClient`. Covered by `test/http_pool_test.rb` (connection-reuse tests proven to fail against the pre-fix code via stash revert-check; full suite green ×2, rubocop clean). Design as planned below, with one refinement: the pool is **elastic** — an empty pool dials a new connection instead of blocking, so concurrency is never capped and a hung app stalls each caller independently for its own read timeout, exactly like the per-request connections it replaces; only idle connections are pooled (max 4).

**Plan:**
- Add a small per-worker **connection pool** of started `Net::HTTP` objects, checked out via a `Queue` (a `Queue` parks the calling *fiber* through the scheduler's `block`/`unblock` hooks, so it composes with the fiber scheduler for free). Pool size 2–4 is plenty at ≤100 total connections.
- **Do not** share one persistent `Net::HTTP` across fibers without checkout: a `Net::HTTP` request is multiple IO operations, each a fiber yield point, so two sessions would interleave writes on one socket mid-request.
- Set `keep_alive_timeout` conservatively (below the Rails/puma persistent-connection timeout) so `Net::HTTP` reconnects rather than writing into a half-closed socket.
- **Never retry a POST on a stale-connection error.** `queue_outbound` and the ingress POST are not idempotent, and `store/http.rb` explicitly documents the no-retry policy (double-submit on ambiguous failure). A stale-connection failure degrades to the existing 451/tempfail path, which is correct — the sending MTA retries.
- Apply the same pool to `IngressClient` (or extract a shared helper).
- Ractor note: build the pool lazily inside the worker (as `Store::Http.from_config` already rebuilds clients per worker), never share sockets across Ractors.

---

### 2. `waiting?` is O(n) and called on every wake event

**File:** `lib/mail_on_rails/smtp/scheduler.rb` (lines 251–256)

```ruby
def waiting?(fiber)
  @blocked.key?(fiber) ||
    @timers.any? { |t| t.fiber == fiber } ||
    @readable.any? { |_, fs| fs.include?(fiber) } ||
    @writable.any? { |_, fs| fs.include?(fiber) }
end
```

Called for every fiber in the `wake` array on every `run_once` iteration; linearly scans the IO sets and `@timers`.

**Verdict: ACCEPT (no fix needed at current scale).**

- The worst case is ~100 fibers *server-wide*, split across workers. A per-tick cost of (woken fibers × ~tens of entries) is microseconds — noise next to the `IO.select` syscall in the same loop.
- More fundamentally, **`IO.select` itself is O(n fds) per tick**, so making `waiting?` O(1) does not change the asymptotic cost of a scheduler tick. If this daemon ever needs thousands of concurrent sessions, the correct move is an epoll/io_uring-based selector (or Ruby's `io-event` gem), not micro-optimizing this guard.
- `waiting?` is a correctness guard against stale cross-thread `unblock` entries. A parallel `Set` of waiting fibers must be kept consistent across five arm/disarm sites in code that is already subtle (the file's comments document several hard-won invariants); the bug risk outweighs an unmeasurable win.

**Revisit if:** `MAIL_ON_RAILS_SMTP_MAX_CONN` is raised into the thousands — and then fix the selector, not this method.

---

## 🟡 Medium Impact

### 3. `select_args` recalculates the timer minimum on every tick

**File:** `lib/mail_on_rails/smtp/scheduler.rb` (lines 217–224)

`@timers.map(&:deadline).min` iterates the timer list on every `IO.select` call, and `@readable.keys + [@wake_r]` / `@writable.keys` allocate fresh arrays every tick.

**Verdict: ACCEPT, with one optional one-liner.** With ≤ ~100 timers per worker, scanning the array is sub-microsecond, and the per-tick array allocations are dwarfed by what `IO.select` itself allocates.

- ✅ The zero-risk tidy is applied (2026-07-22): `select_args` now uses `@timers.min_by(&:deadline).deadline`, dropping the intermediate array from `map(&:deadline)`.
- **Skip** the min-heap: Ruby has no stdlib heap, and `disarm`/`timeout_after` need arbitrary-element delete, which forces an indexed heap — real complexity for no measurable gain at this N.
- **Skip** caching the key arrays: cache invalidation would have to be threaded through every mutation of `@readable`/`@writable`, adding a new class of stale-cache bugs to the scheduler's hottest correctness-critical path.

---

### 4. `disarm` iterates all IO values to clean up a single fiber

**File:** `lib/mail_on_rails/smtp/scheduler.rb` (lines 258–265)

**Verdict: ACCEPT.** Same scale argument as #2: `disarm` scans at most (sessions per worker) hash entries, each holding a 1-element fiber array in practice (a fiber waits on one IO at a time). A reverse `Fiber => IO` map would double the bookkeeping that every arm/disarm site must keep consistent, to save a scan of a few dozen entries. Revisit only together with #2's selector rewrite.

---

### 5. Double HTTP call per inbound message in `smtp_store`

**File:** `lib/mail_on_rails/smtp/store/http.rb` (lines 71–96)

`local_rcpts` is called once per `RCPT TO` (`smtp_server.rb:318`) and then again with the full list inside `smtp_store`, so `rcpt_check` runs **N+1 times** for an N-recipient message.

**Verdict: ACCEPT (deliberate redundancy), revisit only after #1 lands and if measurements say so.**

The duplicate call is doing real work, not just waste:

- **The store is the authority.** `smtp_store` is a store-contract method (shared with `Store::Memory` and the app-side stores, pinned by `store/contracts.rb`); it cannot trust that its caller pre-validated anything.
- **It closes the RCPT→DATA race.** An account deleted between `RCPT TO` and `DATA` is caught by the re-check instead of being mis-accepted.
- **The partition is security-relevant.** The local/remote split drives the `relay_denied` decision. Keeping it inside the store means the relay decision can't be skewed by a stale or buggy caller-side cache.

With #1 fixed, the duplicate costs one small POST on a warm keep-alive connection — on loopback, tens of microseconds. If profiling after #1 still shows this hot, the escape hatch is extending the `smtp_store` contract with an optional caller-supplied known-local hint — but that is a contract change touching `Store::Memory`, the contract tests, and the host app's stores, so it needs its own justification.

---

## 🟢 Low Impact / Worth Noting

### 6. New `UDPSocket` per DNS query (no socket reuse)

**File:** `lib/mail_on_rails/smtp/sender_auth/dns.rb` (lines 125–139)

**Verdict: ACCEPT (won't fix).** Creating and closing a UDP socket is two cheap syscalls (~microseconds); the DNS round-trip it serves is milliseconds. Saving <0.1% of each lookup's latency is not worth the sharing hazard: sessions run concurrently as fibers, and a shared socket would receive *other fibers' replies* — the id-mismatch loop (bounded at 4 tries) would discard them, breaking the other query. Per-fiber reuse would dodge that but adds per-server socket bookkeeping for the same negligible gain.

---

### 7. `@timers` is an unordered array with O(n) `delete`

**File:** `lib/mail_on_rails/smtp/scheduler.rb`

**Verdict: ACCEPT.** `Array#delete` over ≤ ~100 timers is a linear scan in C — effectively free. The code's own comment ("unordered (small N)") records this as a deliberate choice. A min-heap that also supports `disarm`'s arbitrary delete means an indexed heap; see #3 for why that trade is bad here.

---

## Mitigation Plan

| # | Location | Issue | Verdict |
|---|----------|-------|---------|
| 1 | `InternalApi#perform` / `IngressClient#deliver` | New TCP/TLS connection per request | ✅ **Fixed 2026-07-22** — pooled keep-alive connections (`HttpPool`) |
| 2 | `Scheduler#waiting?` | O(n) scan per wakeup | ⏸️ Accept — trivial at ≤100 conns; `IO.select` dominates anyway |
| 3 | `Scheduler#select_args` | Timer-min scan + array allocs per tick | ⏸️ Accept — optional `min_by` one-liner only |
| 4 | `Scheduler#disarm` | O(n IOs) cleanup | ⏸️ Accept — tiny sets, bookkeeping risk > gain |
| 5 | `Store::Http#smtp_store` | Duplicate `rcpt_check` per message | ⏸️ Accept — authoritative re-check, closes TOCTOU, guards relay decision |
| 6 | `Dns#udp_exchange` | New UDP socket per query | ⏸️ Accept — µs syscall vs ms RTT; sharing breaks fiber concurrency |
| 7 | `@timers` array | O(n) delete | ⏸️ Accept — deliberate "small N" choice |

**Phase 1 (✅ done 2026-07-22):** persistent HTTP connection pool for `InternalApi` and `IngressClient` — fiber-safe checkout via `Queue`, conservative `keep_alive_timeout` (2 s), strictly no POST retries (per the store's documented no-retry/double-submit policy), built per client instance so worker Ractor isolation holds. This was the only item with a measurable payoff, and it also cuts the residual cost of #5 to near zero. See `lib/mail_on_rails/smtp/http_pool.rb` and `test/http_pool_test.rb`.

**Phase 2 (✅ done 2026-07-22):** `min_by(&:deadline)` tidy in `select_args`.

**Everything else:** deliberately accepted. The scheduler items (#2, #3, #4, #7) all share one root fact — per-worker fiber counts are capped in the tens by `MAX_CONNECTIONS`, and the tick is dominated by the `IO.select` syscall, which no amount of Ruby-side micro-optimization changes. The trigger to revisit them is raising the connection cap by an order of magnitude, and the right response then is an epoll-based selector, not these point fixes.
