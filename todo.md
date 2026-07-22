# TODO: SMTP session transcript capture (prod) + local replay

Opt-in recording of full SMTP session transcripts in production
(`SMTP_RECORD_DIR`), plus a `bin/replay` CLI that re-drives a transcript
against a local dev server and diffs live replies against recorded ones.

Transcript format (one file per session, `<ts>-<ip>-<id>.smtp`):
`#` metadata header, `C:` client lines (`c:` for chunks without CRLF),
`S:` server reply lines, `! STARTTLS` / `! EOF` events. AUTH secrets are
never written — `[AUTH-REDACTED]`, replayer substitutes via `--auth`.

## Phase 1 — Recorder

- [ ] `lib/mail_on_rails/smtp/recorder.rb`: per-session file writer
      (`client`/`server`/`event`/`close`); write failures log once,
      never break the session.
- [ ] `Daemon.listeners`: put `record_dir` in each frozen listener spec
      (Ractor workers can't read ENV, same reason as `TRACE_DEFAULT`).
      Warn in `config_warnings` when set but not writable.
- [ ] Hook `SmtpServer::Session`: `handle_chunk` (client bytes, reuse
      `redact_for_trace` + redact-next flag set by `challenge`),
      `reply`/`multi` (server lines), `starttls` event, close in
      `run`'s ensure.

## Phase 2 — Replayer

- [ ] `lib/mail_on_rails/smtp/replayer.rb` + `bin/replay` (stdlib only,
      style of bin/healthcheck): sends `C:` lines, reads one reply per
      recorded `S:` line (turn-taking from the transcript, so pipelining
      replays correctly), diffs replies, real TLS handshake at
      `! STARTTLS` (VERIFY_NONE default), `--strict` exits non-zero
      on mismatch. Flags: `--host --port --auth user:pass --strict`.

## Phase 3 — Tests & docs

- [ ] `test/session_recorder_test.rb` (with_session loopback pattern):
      transcript contents, DATA verbatim incl. dot-stuffing, no
      credentials on disk, overlong-chunk `c:` case.
- [ ] Round-trip test: record against Store::Memory, replay into a
      fresh session, assert identical replies + message stored again.
- [ ] README: enabling capture (Kamal volume), privacy warning
      (transcripts contain full message bodies), replay usage.

## Verification

- `bin/test` — existing tests unaffected when record_dir unset.
- Manual: `SMTP_RECORD_DIR=/tmp/rec bin/server`, send via swaks,
  `bin/replay --port 1025 /tmp/rec/<file>.smtp`.
- `bin/server --check-config` warns on unwritable record dir.

## Out of scope

Replay against production, retention/rotation automation, pcap,
outbound-queue replay, sampling (deferred: `SMTP_RECORD_DATA=0`
envelope-only mode, per-IP filtering).
