# Performance Analysis

> Audited 2026-07-22 against `lib/` source.

---

## 🔴 High Impact

### 1. New TCP connection per HTTP request (`InternalApi#perform`)

**File:** `lib/mail_on_rails/smtp/internal_api.rb` (lines 73–79)

Every call to `perform` — authentication, `rcpt_check`, and `queue_outbound` — opens a **fresh TCP (+ TLS) connection** and immediately closes it. For a single `smtp_store` call, that's up to **3 sequential round-trips** to the Rails app, each paying the TCP handshake and TLS handshake overhead:

1. `local_rcpts` → `rcpt_check`
2. `queue_outbound` (if remote recipients)
3. `@ingress.deliver` (if local recipients)

**Fix:** Keep a persistent `Net::HTTP` object with `keep_alive_timeout`, or use a thread-local/fiber-local persistent connection pool.

---

### 2. `waiting?` is O(n) and called on every wake event

**File:** `lib/mail_on_rails/smtp/scheduler.rb` (lines 237–241)

```ruby
def waiting?(fiber)
  @blocked.key?(fiber) ||
    @timers.any? { |t| t.fiber == fiber } ||
    @readable.any? { |_, fs| fs.include?(fiber) } ||
    @writable.any? { |_, fs| fs.include?(fiber) }
end
```

This is called for every fiber in the `wake` array on every `run_once` iteration. It linearly scans all IO sets and the entire `@timers` array. Under load (many concurrent sessions), this becomes O(sessions²) per scheduler tick.

**Fix:** Track waiting fibers in a dedicated `Set` that's maintained on `arm_timer`/`disarm`, making `waiting?` O(1).

---

## 🟡 Medium Impact

### 3. `select_args` recalculates the timer minimum on every tick

**File:** `lib/mail_on_rails/smtp/scheduler.rb` (lines 203–210)

```ruby
def select_args
  interval = nil
  unless @timers.empty?
    interval = @timers.map(&:deadline).min - now
    interval = 0 if interval.negative?
  end
  [ @readable.keys + [ @wake_r ], @writable.keys, interval ]
end
```

`@timers.map(&:deadline).min` iterates the entire unordered timer list on every `IO.select` call. Additionally, `@readable.keys + [@wake_r]` and `@writable.keys` allocate fresh arrays every tick.

**Fix:** Keep `@timers` as a min-heap (or sorted array), so the minimum is O(1). Pre-cache the reader/writer key arrays and invalidate them only when the sets change.

---

### 4. `disarm` iterates all IO values to clean up a single fiber

**File:** `lib/mail_on_rails/smtp/scheduler.rb` (lines 244–251)

```ruby
def disarm(fiber, timer)
  @timers.delete(timer) if timer
  @blocked.delete(fiber)
  [ @readable, @writable ].each do |set|
    set.each_value { |fs| fs.delete(fiber) }
    set.delete_if { |_, fs| fs.empty? }
  end
end
```

`disarm` is called in `ensure` blocks in `io_wait`, `kernel_sleep`, and `block` — i.e. on every single IO completion. Scanning all values in `@readable`/`@writable` is O(n IOs). A reverse lookup map (`Fiber => [IO, events]`) would make this O(1).

---

### 5. Double HTTP call per inbound message in `smtp_store`

**File:** `lib/mail_on_rails/smtp/store/http.rb` (lines 57–82)

```ruby
def smtp_store(mail_from, rcpt_to, data, authenticated_as, auth_results: nil)
  wrap do
    addresses = Array(rcpt_to)
    local_set = @api.local_rcpts(addresses).to_set   # HTTP call #1
    local, remote = addresses.partition { ... }
    ...
    if remote.any?
      @api.queue_outbound(...)                        # HTTP call #2
    end
    if local.any?
      ...@ingress.deliver(source)                     # HTTP call #3
    end
```

`local_rcpts` is also called from `SmtpServer`'s `RCPT TO` handler (via `Store::Http#local_rcpts`), so the same `rcpt_check` API call may be made **twice per session** — once to validate the recipient and again inside `smtp_store`. Caching the result per session would eliminate the duplicate.

---

## 🟢 Low Impact / Worth Noting

### 6. New `UDPSocket` per DNS query (no socket reuse)

**File:** `lib/mail_on_rails/smtp/sender_auth/dns.rb` (lines 124–138)

```ruby
def udp_exchange(server, payload, id)
  socket = UDPSocket.new(Addrinfo.ip(server).afamily)
  ...
ensure
  socket&.close
end
```

A new UDP socket is created and destroyed for every DNS lookup. For SPF/DKIM/DMARC verification, a single message can trigger 5–10+ lookups. Reusing a socket per fiber (or per DNS client instance) would reduce syscall overhead.

---

### 7. `@timers` is an unordered array with O(n) `delete`

**File:** `lib/mail_on_rails/smtp/scheduler.rb`

`@timers.delete(timer)` in `disarm` and `timeout_after` is O(n). With many concurrent sessions each having an idle timer, this adds up. Same fix as #3: use a sorted structure (min-heap).

---

## Summary Table

| # | Location | Issue | Impact |
|---|----------|-------|--------|
| 1 | `InternalApi#perform` | New TCP/TLS connection per request | 🔴 High |
| 2 | `Scheduler#waiting?` | O(n) linear scan per wakeup | 🔴 High |
| 3 | `Scheduler#select_args` | Recomputes timer min + allocates arrays every tick | 🟡 Medium |
| 4 | `Scheduler#disarm` | O(n IOs) cleanup per IO completion | 🟡 Medium |
| 5 | `Store::Http#smtp_store` | Duplicate `rcpt_check` HTTP call per session | 🟡 Medium |
| 6 | `Dns#udp_exchange` | New UDP socket per DNS query | 🟢 Low |
| 7 | `@timers` array | O(n) delete on disarm | 🟢 Low |

The biggest wins would come from **persistent HTTP connections** (#1) and making the **scheduler's hot path O(1)** (#2, #3, #4).
