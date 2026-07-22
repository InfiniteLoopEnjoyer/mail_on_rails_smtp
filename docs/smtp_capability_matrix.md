# SMTP capability matrix

What this server speaks, advertises, and refuses — pinned by
`test/smtp_capability_test.rb` (a change to either must update the other).
RFC 5321 subset; roles per listener: `:mx` (inbound, like port 25) and
`:submission` (authenticated, like 587/465).

## Commands

| Command | Reply | Notes |
| --- | --- | --- |
| `HELO` / `EHLO` | `250` | EHLO lists the extensions below |
| `STARTTLS` | `220` → handshake | Only when TLS material is loaded and the channel is still plaintext; `454` without material, `503` if already encrypted. RFC 3207: all state is discarded after the upgrade |
| `AUTH PLAIN` / `AUTH LOGIN` | `235` / `535` | Only over an encrypted channel (`538` otherwise); initial-response and challenge forms; `*` cancels (`501`); unknown mechanism `504` |
| `MAIL FROM` | `250` | On submission: requires AUTH (`530`) and the sender must match the authenticated account (`550`) |
| `RCPT TO` | `250` / `550` | Local recipients everywhere; remote recipients only from authenticated submission (never an open relay) |
| `DATA` | `354` → `250` | Dot-stuffing per RFC 5321; bare-LF `.` never terminates (smuggling defense) |
| `RSET`, `NOOP` | `250` | |
| `VRFY` | `252` | Never confirms or denies addresses |
| `QUIT` | `221` | |
| Anything else (`EXPN`, `HELP`, `ETRN`, `BDAT`, `XCLIENT`, …) | `502` | |

## EHLO extensions by channel state

| Channel | Advertised |
| --- | --- |
| Plaintext, no TLS material | `SIZE`, `8BITMIME`, `PIPELINING` |
| Plaintext, TLS material loaded | + `STARTTLS` (never AUTH in the clear) |
| Encrypted (post-STARTTLS or implicit TLS) | + `AUTH PLAIN LOGIN` (no `STARTTLS`) |

Not supported / not advertised: `SMTPUTF8` (8BITMIME bodies are accepted,
but UTF-8 envelope addresses are not negotiated), `CHUNKING`/`BDAT`, `DSN`,
`ENHANCEDSTATUSCODES` (a few replies carry enhanced codes in their text,
but the extension is not negotiated), `ETRN`, `EXPN`.

## Limits (with their SMTP outcome)

| Limit | Value | Outcome |
| --- | --- | --- |
| Message size (`SIZE`) | 25 MB | `552` at the terminator; flooding past 2× drops the connection |
| Command line length | 4096 bytes | over-long lines are rejected, never acted on in fragments |
| Recipients per message | 100 | `452` |
| Messages per session | 100 | `421` |
| AUTH attempts per session | 3 | `421` + disconnect (per-IP lockout spans connections, see README) |
| Connections | 100 global / 10 per IP | `421` at accept |
| Connection rate | 60 per IP per 60 s | escalating pre-banner tarpit, 1 s doubling to 16 s (loopback exempt) |
| DNSBL-listed peer (`MAIL_ON_RAILS_RBLS`) | off by default | `554 5.7.1` at `MAIL FROM` (unauthenticated MX only; fails open on DNS trouble) |
| Session idle timeout | 300 s | disconnect |
| Implicit-TLS handshake timeout | 30 s | disconnect |
| Received-hop loop guard | > 4 own hops | `550 Loop detected` |

Defaults shown; the env-tunable ones are in the README configuration table.
