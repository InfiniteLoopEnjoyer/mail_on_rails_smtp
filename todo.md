# TODO

## Test coverage gaps / failure modes to add

1. **Real network/DNS failure behavior (integration)**
   - DNS logic is mostly tested with `FakeResolver`; add integration tests for real resolver behavior under packet loss, truncation fallback, slow nameservers, and malformed replies.

2. **TLS certificate/handshake failure cases**
   - Add coverage for expired certs, wrong SAN/CN, broken chain, renegotiation edge cases, and handshake aborts mid-session.

3. **HTTP store failure taxonomy**
   - Add tests for HTTP transport failures: timeouts, connection resets, partial reads, non-JSON responses, 5xx retry semantics, auth header misconfig, and backoff/jitter behavior.

4. **Crash/restart durability**
   - Add tests for daemon/process restart during in-flight DATA or after accept-before-store; verify message loss/duplication guarantees across crashes.

5. **Backpressure under sustained load**
   - Add stress/soak tests for prolonged high concurrency with mixed slow clients (slowloris-like patterns) and memory growth assertions.

6. **Ractor-specific race/regression matrix**
   - Add failure injection around fd handoff/release-pipe ordering, worker death recovery, and long-run flake detection across Ruby versions.

7. **Protocol abuse/malformed SMTP command fuzzing**
   - Add fuzz tests for command parsing, oversized lines, invalid UTF-8/control bytes, command pipelining abuse, and dot-stuffing edge corruption checks.

8. **Security hardening edge cases**
   - Add tests for header smuggling variants (folded headers, duplicated casing tricks, exotic MIME boundaries) and auth brute-force/rate-limit behaviors.

9. **Observability failure modes**
   - Add tests asserting logging/metrics correctness when failures happen (timeouts, tempfails, policy rejects).

10. **Config validation failures**
   - Add tests for invalid/missing env combos (bad ports, missing passwords, unreadable TLS files, contradictory worker mode settings) with deterministic startup errors.
