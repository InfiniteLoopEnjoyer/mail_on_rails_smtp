# TODO

This document tracks high-impact reliability, security, and feature work needed to move `mail_on_rails_smtp` from early-stage to production-grade operation.

## Priority guide

- **P0**: Required before broad production rollout
- **P1**: Strongly recommended for production hardening
- **P2**: Important enhancements for scale, operability, and future-proofing

---

## A) Test coverage gaps / failure modes

### 1) Real network/DNS failure behavior (integration) — **P0**
**Why needed**
- Sender auth correctness depends on DNS under real network conditions.
- Unit tests with `FakeResolver` are good for logic, but they cannot prove behavior under resolver timeouts, truncation, or SERVFAIL storms.

**Brief plan**
- Add an integration DNS harness with controllable responses (timeouts, truncation, malformed packets, NXDOMAIN/SERVFAIL).
- Add tests for UDP->TCP fallback and timeout boundaries.
- Assert exact SMTP outcomes (`4xx` tempfail vs `5xx` permfail) and auth-results stamping.

**Suggested deliverables**
- `test/integration/dns_integration_test.rb`
- Fixtures for DNS failure scenarios.

---

### 2) TLS certificate/handshake failure cases — **P0**
**Why needed**
- TLS failures are common in production and can become silent reliability or security regressions.
- Current coverage appears focused on happy paths.

**Brief plan**
- Add tests for expired certs, bad SAN/CN, invalid chain, unsupported ciphers/protocol versions, and mid-handshake disconnects.
- Validate clear SMTP responses and connection teardown behavior.

**Suggested deliverables**
- `test/tls_failure_test.rb`
- Scripted cert fixture generator under `test/fixtures/tls/`.

---

### 3) HTTP store failure taxonomy — **P0**
**Why needed**
- The SMTP daemon depends on internal API + ingress availability.
- Network and HTTP failure mapping must be deterministic to avoid message loss or bad retries.

**Brief plan**
- Add failure injection around `Store::Http` calls: connect/read timeouts, resets, non-JSON bodies, auth failures, `429/5xx`, and malformed payloads.
- Define and test retry/backoff/jitter policy (or explicitly no-retry policy).
- Assert mapping to SMTP reply classes (`4xx` transient vs `5xx` permanent).

**Suggested deliverables**
- `test/http_store_failures_test.rb`
- Shared helper for fake upstream behavior matrix.

---

### 4) Crash/restart durability — **P0**
**Why needed**
- Restarts happen during deploys and incidents.
- In-flight DATA handling must have clear guarantees (at-most-once/at-least-once) to avoid loss or duplication surprises.

**Brief plan**
- Add kill/restart tests at critical phases: after `DATA`, before store commit, after store commit, before SMTP ACK.
- Document expected delivery semantics and validate with assertions.

**Suggested deliverables**
- `test/durability_restart_test.rb`
- A short “delivery guarantees” section in `README.md`.

---

### 5) Backpressure under sustained load — **P0**
**Why needed**
- Connection caps are useful, but production failure usually appears as resource exhaustion over time.
- Slow clients can starve worker capacity.

**Brief plan**
- Add soak tests with mixed fast/slow clients and long-lived sessions.
- Track memory/file descriptor growth and scheduler fairness over time.
- Validate connection limiter release behavior under stress.

**Suggested deliverables**
- `test/soak/backpressure_test.rb`
- CI nightly load profile (non-blocking for PRs initially).

---

### 6) Ractor-specific race/regression matrix — **P1**
**Why needed**
- Ractor mode adds concurrency complexity and Ruby-version sensitivity.
- Races in fd handoff/release paths can cause stuck slots or dropped sessions.

**Brief plan**
- Add deterministic race tests for fd handoff, release pipe ordering, and worker crash recovery.
- Run matrix across supported Ruby versions and worker modes (`auto`, `thread`).

**Suggested deliverables**
- `test/worker_ractor_race_test.rb`
- CI matrix job for concurrency modes.

---

### 7) Protocol abuse / malformed SMTP command fuzzing — **P1**
**Why needed**
- SMTP edge services are internet-exposed and receive hostile input.
- Parser robustness bugs can become DoS or bypass vulnerabilities.

**Brief plan**
- Add fuzz/property tests for commands, line endings, oversized input, control bytes, pipelining abuse, and dot-stuffing edge cases.
- Ensure parser failures return safe SMTP errors without crashes.

**Suggested deliverables**
- `test/fuzz/smtp_parser_fuzz_test.rb`
- Corpus seed files for malformed command cases.

---

### 8) Security hardening edge cases — **P1**
**Why needed**
- Trust boundaries rely on correct header sanitation and auth protections.
- Attackers will probe header smuggling and auth endpoint pressure.

**Brief plan**
- Expand tests for folded/duplicated trust headers, unusual casing, MIME/header injection tricks.
- Add rate-limit/lockout behavior tests for auth attempts and per-IP abuse.

**Suggested deliverables**
- `test/security/header_sanitization_test.rb`
- `test/security/auth_rate_limit_test.rb`

---

### 9) Observability failure modes — **P1**
**Why needed**
- Production incidents are solved through logs/metrics, not repros.
- Without assertions, observability can silently degrade.

**Brief plan**
- Define required counters/events for timeout/tempfail/reject/dmarc outcomes.
- Add tests that assert structured log fields and metric emission on failure paths.

**Suggested deliverables**
- `test/observability_failure_test.rb`
- Observability field dictionary in docs.

---

### 10) Config validation failures — **P1**
**Why needed**
- Misconfiguration is a top cause of deployment outages.
- Startup should fail fast with clear diagnostics.

**Brief plan**
- Add startup validation tests for invalid ports, missing secrets, unreadable TLS files, incompatible worker settings.
- Standardize error messages and non-zero exit behavior.

**Suggested deliverables**
- `test/config_validation_test.rb`
- `bin/server --check-config` preflight mode.

---

## B) Missing SMTP/platform features

### 11) Outbound delivery queue/relay engine clarity — **P1**
**Why needed**
- Current architecture appears inbound-first with outbound delegated.
- Teams need explicit boundary clarity to avoid incorrect deployment assumptions.

**Brief plan**
- Document whether outbound MTA behavior is in-scope or delegated to host app/another service.
- If in-scope later: define queue model, retries, MX resolution, bounce handling.

**Suggested deliverables**
- README architecture section update.
- Optional roadmap issue for outbound module.

---

### 12) Anti-abuse controls (rate limiting / tarpitting / greylisting / reputation hooks) — **P0**
**Why needed**
- Internet-facing SMTP must resist spam bursts and credential abuse.
- Connection caps alone are insufficient.

**Brief plan**
- Add configurable per-IP and per-account rate limits.
- Add optional tarpitting/greylisting hooks.
- Add policy hook interface for allow/deny/reputation checks.

**Suggested deliverables**
- `lib/.../policy/abuse_control.rb` + tests
- Env/config options with safe defaults.

---

### 13) Spam/virus scanning integration points — **P1**
**Why needed**
- Most production mail stacks require malware/spam inspection before delivery.
- Even if externalized, integration points should be first-class.

**Brief plan**
- Define pre-ingress scanning hook contract.
- Provide adapters or webhook pattern for rspamd/spamassassin/clamav style verdict ingestion.
- Ensure verdicts propagate into trusted headers/metadata.

**Suggested deliverables**
- `Scan::Adapter` interface + fake adapter tests.
- Docs with example integration topology.

---

### 14) Outbound DKIM signing (if submission scope expands) — **P2**
**Why needed**
- If this service ever sends outbound directly, DKIM signing is required for deliverability.

**Brief plan**
- Keep out-of-scope unless outbound transport is added.
- If added: support key rotation and selector strategy.

**Suggested deliverables**
- Deferred roadmap item with prerequisites.

---

### 15) Extended RFC/ESMTP capability matrix (incl. SMTPUTF8 posture) — **P2**
**Why needed**
- Clients vary widely; unsupported extensions should be explicit.
- Internationalization expectations should be documented.

**Brief plan**
- Publish supported-command/extension matrix.
- Add conformance tests for declared support and explicit reject behavior for unsupported features.

**Suggested deliverables**
- `docs/smtp_capability_matrix.md`
- Capability regression tests.

---

### 16) Queue durability semantics + dead-letter strategy — **P0**
**Why needed**
- Operators need clear recovery paths for poison messages and repeated downstream failures.

**Brief plan**
- Define retry windows, max attempts, and dead-letter behavior where applicable.
- Emit operator-visible identifiers for replay/investigation.

**Suggested deliverables**
- Durability/queue policy doc.
- Failure replay tooling (basic CLI/admin endpoint).

---

### 17) Operational tooling (health/readiness, admin inspection, replay controls) — **P1**
**Why needed**
- Production operations need safe introspection and remediation tools.

**Brief plan**
- Add health/readiness endpoints with dependency checks.
- Add admin-safe interfaces for queue stats and controlled retries/purges.

**Suggested deliverables**
- `bin/healthcheck` or lightweight HTTP admin surface.
- Operator runbook documentation.

---

### 18) HA and horizontal-scale strategy — **P1**
**Why needed**
- Multi-instance deployments need deterministic behavior under failover.

**Brief plan**
- Define stateless/stateful boundaries and required shared components.
- Document load-balancer expectations, sticky-session requirements (if any), and failure modes.

**Suggested deliverables**
- `docs/ha_deployment.md`
- Staging chaos test plan.

---

### 19) Tenant/domain policy controls — **P2**
**Why needed**
- Multi-tenant production systems need per-domain/per-tenant overrides (limits, auth, enforcement).

**Brief plan**
- Add policy lookup hooks in session/auth flow.
- Support domain-scoped toggles for enforcement and routing.

**Suggested deliverables**
- Policy interface + integration tests.
- Config schema for tenant overrides.

---

### 20) Compliance/audit controls — **P2**
**Why needed**
- Enterprises often require retention controls, auditability, and PII-safe logging.

**Brief plan**
- Define audit event schema and retention lifecycle.
- Add configurable redaction/minimization for sensitive fields in logs.

**Suggested deliverables**
- `docs/compliance_and_audit.md`
- Audit/redaction test coverage.

---

## Suggested execution phases

### Phase 1 (P0 baseline)
- Items: 1, 2, 3, 4, 5, 12, 16
- Goal: safe early production rollout with clear failure behavior.

### Phase 2 (P1 hardening)
- Items: 6, 7, 8, 9, 10, 11, 13, 17, 18
- Goal: stronger resilience, diagnostics, and operational maturity.

### Phase 3 (P2 scale/future)
- Items: 14, 15, 19, 20
- Goal: long-term capability expansion and enterprise readiness.
