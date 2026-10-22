# HalimiSOC — Design Document

**Status:** Implemented (as-built)
**Version:** 2.1.0
**Supersedes:** v2.0.0 — adds the nginx parser and Rule E (PRD amendment A9),
  incident source-IP tracking with migration `0003`, transactional rule reload
  and operator user management
**Amended:** Docker json-file envelope parser, UFW block parser and the
  firewall port-scan rule; `container.log` source and `network.firewall.block`
  type join the canonical contract
**Related documents:** `PRD.md`, `AGENTS.md`, `SPEC-AUDIT.md`

> This document describes how HalimiSOC is built. Where it disagrees with the
> draft v1.2.0, this document is correct because it matches the implementation.
> Where a decision here differs from the draft, the reason is recorded — usually
> as an ADR under `docs/decisions/`.

---

## 1. Design goals

HalimiSOC is a lightweight, portable, security-first platform for collecting
infrastructure telemetry and investigating incidents.

Priority order, which is also the tie-breaker for every design decision:

```text
Security
→ Correctness
→ Contract compliance
→ End-to-end functionality
→ Reliability
→ Detection quality
→ Observability
→ Maintainability
→ UI
→ Scalability
```

The implementation is single-node. Distributed infrastructure is avoided until a
measured requirement justifies it.

---

## 2. Architectural principles

### 2.1 Canonical pipeline

```text
Raw telemetry
    ↓
Reader              offset + inode tracking, rotation and truncation handling
    ↓
Line assembler      joins continuation lines, bounds record size
    ↓
Parser              classifies into VALID / MALFORMED / UNSUPPORTED /
                    INCOMPLETE / NON_SECURITY_RELEVANT
    ↓
Normalizer          canonical host, identity, IP, time; strips control chars
    ↓
Validator           enums, bounds, clock skew, schema version
    ↓
Canonical event     the central cross-component contract
    ↓
Idempotent ingestion
    ↓
Deterministic detection
    ↓
Alert
    ↓
Entity-aware correlation
    ↓
Incident
    ↓
Evidence selection
    ↓
AI assistance       optional, advisory, outside the detection path
```

The order is the security contract. In particular, persistence precedes
detection, and detection runs only for an event that was newly inserted.

### 2.2 Trust boundaries

**Trusted (control plane):**

- authenticated identity
- authorization state
- validated rule configuration
- security policy
- application-generated metadata
- validated response permissions
- output schemas

**Untrusted:**

- raw log lines
- agent payloads
- event timestamps
- usernames
- hostnames
- HTTP paths and query strings
- command lines
- filenames
- external enrichment
- model output

Untrusted input is validated at exactly one boundary (`internal/events/validation`)
before it reaches any security-sensitive logic. No downstream component assumes a
parser already normalized anything.

### 2.3 Progressive complexity

MVP, as implemented:

```text
Go API
Go Agent
PostgreSQL
Next.js console
Optional LLM
```

Not present, and not required:

```text
Redis
NATS
Kafka
ClickHouse
Kubernetes
Graph database
Distributed workers
```

Adding any of these requires a documented measured requirement and an ADR.

---

## 3. Repository structure

Structure is defined here once. `AGENTS.md` references it rather than repeating it.

```text
halimisoc/
├── apps/
│   ├── api/                 server entrypoint
│   │   ├── main.go
│   │   └── migrations/      versioned SQL, applied at startup
│   └── agent/               collection agent (single static binary)
│       ├── main.go          flags, lifecycle, signal handling
│       ├── client.go        HTTP client for the API contract
│       ├── reader.go        tailing with rotation/truncation handling
│       ├── spool.go         bounded disk buffer + offset store
│       ├── sender.go        delivery, backoff, spool drain, heartbeat
│       └── producer.go      parse pipeline + simulation
├── internal/
│   ├── events/
│   │   ├── model/           canonical event contract
│   │   ├── parser/          parsers + registry + assembler
│   │   ├── validation/      the untrusted-input boundary
│   │   └── ingest/          ingestion orchestration
│   ├── detection/
│   │   ├── rules/           rule contract and safe loader
│   │   ├── state/           bounded ephemeral detection state
│   │   └── engine/          evaluation
│   ├── correlation/         entity-aware incident assembly
│   ├── incidents/           incident contract and lifecycle
│   ├── alerts/              alert contract and lifecycle
│   ├── auth/                passwords, sessions, CSRF, rate limiting
│   ├── authorization/       RBAC matrix
│   ├── ai/                  optional advisory analyst + provider adapter
│   ├── api/                 HTTP handlers and middleware
│   ├── storage/
│   │   ├── store.go         the persistence contract
│   │   ├── memory/          in-process implementation (tests, demos)
│   │   └── postgres/        production implementation + migrations runner
│   ├── audit/               audit record contract
│   ├── metrics/             dependency-free metrics registry
│   ├── secret/              token generation, hashing, redaction
│   ├── config/              configuration and resource limits
│   └── id/                  ULID generation and validation
├── packages/rules/          detection rules as data
├── apps/web/                Next.js console (backend-for-frontend)
├── tests/                   black-box end-to-end tests
├── docs/                    architecture, API, detection, security, ADRs
├── deploy/                  Dockerfiles and compose
├── scripts/                 dev, demo and security scripts
└── .github/workflows/       CI
```

Dependency direction is one-way: `apps/*` → `internal/*`. No `internal`
package imports an `apps` package. The console has no compile-time dependency at
all: it speaks to the API over HTTP, which is what keeps the API the single
enforcement point for authorization.

---

## 4. Canonical event contract

Package: `internal/events/model`.

### 4.1 Fields

| Field | Type | Notes |
|---|---|---|
| `id` | string | Producer-generated ULID, `evt_` prefixed. Idempotency key. |
| `schema_version` | string | Currently `"1"`. Unknown versions are rejected, never coerced. |
| `type` | string | Closed set, dotted lowercase, e.g. `auth.ssh.login_failed`. |
| `time` | RFC3339 | Source occurrence time. Drives detection windows. |
| `received_at` | RFC3339 | Server receipt time. Server-assigned. |
| `observed_at` | RFC3339 | Agent observation time. |
| `host` | string | Canonical lowercase host identifier. |
| `agent_id` | string | Set by the server from the credential, never trusted from the payload. |
| `source` | string | `auth.log`, `syslog` or `agent`. |
| `source_path` | string | Sanitized relative path. |
| `actor` | string | Lowercased acting identity. |
| `target` | string | Lowercased acted-upon identity. |
| `network.src_ip` | string | Canonical IP, or empty. |
| `network.src_port` | int | 0–65535. |
| `network.dst_ip` | string | Canonical IP. |
| `network.dst_port` | int | 0–65535. |
| `outcome` | string | `success`, `failure` or `unknown`. |
| `severity` | string | Source-declared severity, lowercase. Not a detection verdict. |
| `attributes` | object | Type-specific detail, string→string, max 64 keys, keys allowlisted. |
| `message` | string | Human-readable summary. |
| `raw` | string | Original telemetry line, retained as evidence. |

### 4.2 Closed sets

Event types:

```text
auth.ssh.login_failed      auth.ssh.login_success    auth.ssh.invalid_user
auth.ssh.disconnect        auth.sudo.command         auth.sudo.auth_failed
security.authorized_keys.modified
http.auth.failed           http.auth.success
network.firewall.block
agent.heartbeat            agent.lifecycle
```

`http.auth.success` is reserved for a future login-success heuristic and is not
emitted by any parser yet; keeping it in the closed set now means the contract
does not need a version bump when that heuristic ships.

Severity (lowercase on the wire, case-sensitive on parse — two systems built from
this spec cannot disagree about what `HIGH` means because it is rejected):

```text
low  <  medium  <  high  <  critical
```

Alert status (uppercase): `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `DISMISSED`.

Incident status (uppercase):

```text
NEW → ACKNOWLEDGED → INVESTIGATING → CONTAINED → RESOLVED → CLOSED
      ↘ FALSE_POSITIVE (reachable from any active state)
```

See §7.4 for why this differs from the PRD minimum.

### 4.3 Identity

Identifiers are ULID-shaped: a 48-bit millisecond timestamp followed by 80 bits
of randomness, rendered as 26 Crockford base32 characters with a kind prefix.

| Kind | Prefix | Example |
|---|---|---|
| Event | `evt_` | `evt_01ARZ3NDEKTSV4RRFFQ69G5FAV` |
| Alert | `alt_` | |
| Incident | `inc_` | |
| Agent | `agt_` | |
| Agent token | `tok_` | |
| User | `usr_` | |
| Session | `sess_` | |
| Audit | `aud_` | |

Two properties the pipeline depends on:

1. Lexicographic order matches creation order, so ordering needs no second column.
2. The random tail makes ids unguessable, so a client cannot predict or collide
   with a future id.

Validation is strict and case-sensitive. Crockford base32 excludes `I`, `L`, `O`
and `U` so a human copying an id from a log cannot confuse it with `1`, `1`, `0`
and `V`; accepting lowercase would discard that property.

### 4.4 Idempotency

- The **event id** is the primary idempotency key. Ingestion is
  `INSERT ... ON CONFLICT (id) DO NOTHING`, and the affected-row count is the
  authoritative signal for whether detection should run.
- A **secondary dedupe key** exists to catch a producer that regenerated an id
  for the same physical log line. It is scoped to the emitting host and excludes
  every server-assigned field. It is indexed but deliberately **not** unique,
  because two genuinely distinct log lines can share a message in the same second.

This is what makes replay safe. It is enforced by the database, not by
application convention (ADR-006).

---

## 5. Collection agent

Package: `apps/agent`.

### 5.1 Reader

Log files are not immutable. The reader tracks both a byte offset and the file
inode, and handles three cases explicitly:

| Situation | Handling |
|---|---|
| Same inode, file grew | Resume from the stored offset. |
| Same inode, file shrank | Truncated in place; restart from 0. |
| Different inode | Rotation; reopen the new file from 0. |

Offsets are persisted, so a restart does not re-send the whole file. Re-sending
would be collapsed as duplicates server-side, but replaying gigabytes of history
is a self-inflicted load spike.

### 5.2 Spool

A bounded on-disk buffer of undelivered events.

- Hard byte cap (`-spool-bytes`, default 100 MiB, minimum 1 MiB).
- When over the cap, the **oldest** records are dropped first, roughly half the
  spool per pass, with a counter and a degraded heartbeat so the loss is visible.
- `Ack` rewrites atomically: write to a temporary file, then rename. A crash
  mid-rewrite leaves the previous spool intact rather than truncated.
- A leftover temporary file from an interrupted rewrite is discarded at startup,
  because the canonical file is the trustworthy copy.

### 5.3 Queue and backpressure

Events flow through a bounded channel. When it is full the producer **spills to
disk** rather than blocking.

Blocking would be worse: the collection loop would stall, the log file would grow
faster than it is read, and the agent would silently lose the ability to catch up.
Spilling keeps the offset advancing and counts the overflow.

### 5.4 Delivery

- Exponential backoff, 1s → 60s, with ±20% jitter. Jitter matters even for a
  single agent: several agents recovering from one outage would otherwise retry in
  lockstep and hit the server in bursts.
- A **permanent** rejection (4xx that is not a timeout or rate limit) discards the
  batch and logs it with its size. Retrying forever would block the queue behind a
  payload the server will never accept.
- The spool is drained opportunistically once connectivity returns.

### 5.5 Identity

The agent is stateless: it may be restarted with only a token. It therefore asks
the server who it is (`GET /api/v1/agents/me`) rather than persisting an identity.
A rejected credential (401) is fatal; an unreachable server is not, because that is
exactly the outage the spool exists to survive.

### 5.6 Simulation

`-simulate` emits a deterministic synthetic attack scenario through the same
parser and validation path as live telemetry. It touches no real resource. The
scenario is described in §7.6.

---

## 6. Validation boundary

Package: `internal/events/validation`. This is the single gate between untrusted
telemetry and the trusted pipeline.

### 6.1 Normalization rules

| Field | Rule |
|---|---|
| `host` | Trim, lowercase, strip trailing dot, restrict to DNS-label characters. Anything else is rejected so two spellings of one host cannot split correlation. |
| `actor`, `target` | Trim, lowercase. Control characters are rejected outright: an identity containing them is a log-injection vector. |
| `network.src_ip`, `dst_ip` | Canonicalize via `netip`. Reject unparseable values and IPv6 zone identifiers. |
| `network.*_port` | Range-check 0–65535. |
| `message`, attributes | Strip control characters. Free text is forwarded to the AI prompt and the UI, so it is cleaned rather than merely validated. |
| `source_path` | Clean against a rooted copy, so `..` can never climb above the root. |
| `raw` | Truncate at the byte limit **on a rune boundary**, and mark `raw_truncated=true`. |
| `time` | Normalize to UTC. Reject if more than the clock skew ahead of server time. |
| `received_at` | Always overwritten with server time. |
| `schema_version` | Default to the current version when absent; reject unknown versions. |

### 6.2 Time policy

- **Future** timestamps beyond `HALIMISOC_CLOCK_SKEW` (default 5m) are rejected.
  A forged future timestamp would let an attacker place events outside a sliding
  detection window to evade a threshold, or burst-trigger one.
- **Old** timestamps are accepted without limit. Backfilling from a rotated log is
  legitimate; only the future is bounded.
- A record whose timestamp cannot be parsed falls back to the observation time and
  is marked `timestamp_source=observed`, so an analyst knows to distrust it.

### 6.3 Rejection policy

A malformed event is rejected **individually**; it never fails the batch. One
hostile line in a log stream must not stop the ingestion of the remaining
legitimate events. Rejections are returned with a stable reason code
(`EVENT_MALFORMED`, `UNSUPPORTED_SCHEMA_VERSION`, `EVENT_TIME_OUT_OF_RANGE`,
`EVENT_FIELD_TOO_LARGE`, `EVENT_INVALID`) so the agent can account for them
instead of silently dropping telemetry.

---

## 7. Detection and correlation

### 7.1 Rules are data

Package: `internal/detection/rules`.

Rules are YAML parsed into a strict schema with **unknown fields rejected**, then
validated into a restricted internal representation.

There is deliberately **no expression evaluator**. An operator cannot write a rule
that executes arbitrary logic, because a configuration file that can run code is a
remote code execution surface (ADR-008).

```yaml
id: ssh-bruteforce
version: 1
name: SSH Brute Force
description: Repeated failed SSH authentication from one source address
severity: high
match:
  types: [auth.ssh.login_failed, auth.ssh.invalid_user]
  outcomes: [failure]
threshold:
  count: 5
  window: 60s
group_by: [network.src_ip]
cooldown: 5m
```

**Addressable fields** (a closed allowlist): `host`, `actor`, `target`,
`network.src_ip`, `network.dst_ip`.

Raw evidence, message text and arbitrary attributes are **not** addressable. A rule
that could match on raw log content would let an attacker who controls a log line
control detection.

**Bounds**: `count` 1–100 000; `window` > 0 and ≤ 24h; `cooldown` > 0 and ≤ 24h.

A rule file that fails validation stops the process. The detector never runs a
partially applied rule set: it would be silently running something the operator
does not believe is deployed.

`requires` chaining references are resolved at load time, so a dangling reference
cannot silently disable a rule.

### 7.2 Detection state

Package: `internal/detection/state`.

In-memory and ephemeral (ADR-005). Bounded on four axes:

| Bound | Default | Purpose |
|---|---|---|
| `MaxGroups` | 50 000 | Stops a hostile source exhausting memory through unique grouping keys. |
| `MaxPerGroup` | 1 000 | Bounds per-window retention. |
| `MaxFiringsPerRule` | 10 000 | Bounds chaining history. |
| `MaxFiringAge` | 24h | Time bound. |

Eviction is **deterministic**: the oldest-activity group goes first, ties broken by
key, so two runs over the same input evict the same group.

State is keyed by **event time, not wall-clock time**, so a replay produces the same
outcome as the original delivery.

### 7.3 Evaluation

For each event, for each rule:

1. Does the event match the rule's `types`, `outcomes` and attribute equality?
2. Can it be grouped? **An event missing any `group_by` field is not counted** —
   counting it would attribute activity to a key that does not identify anyone.
3. Record the observation; count events in the window ending at the event time.
4. If below threshold, stop.
5. If `requires` is set, has the prerequisite rule fired recently for the same
   chaining value? An empty value never matches.
6. Is a cooldown active for this rule and group? If so, suppress.
7. Build the alert from **validated, canonical values only**. Raw telemetry is
   never interpolated into the alert reason, so a reason cannot be a log-injection
   vector.

**Severity authority** (ADR-004):

- Event severity is source-declared metadata. It is never used for an alert.
- Alert severity is the rule's severity.
- Incident severity is the maximum over its qualifying alerts.

**Cooldown suppresses the alert, not the evidence.** A qualifying event received
during a cooldown still persists and still contributes to correlation. Event
persistence, alert suppression and correlation are separate concerns.

### 7.4 Correlation

Package: `internal/correlation`.

An alert joins an incident only when it shares a **concrete entity value** — host,
actor or source address — within a bounded window (default 30 minutes).

Correlation never joins on time proximity alone. "Two alerts happened near each
other" is not evidence that they are related, and a wrongly merged incident is
worse than two honest ones (ADR-010).

An empty entity never matches another empty entity: two alerts that both lack a
source IP do not share one.

A shared source address alone never merges two different hosts: one attacker
address probing unrelated machines is not one incident. The address still joins
when the hosts do not conflict (same host, or unknown on either side), which is
what lets host-less alerts correlate without overriding an explicit host
mismatch. Incidents therefore track `source_ips` alongside hosts and actors
(migration `0003`), and the match is against the whole scope, not the first
host recorded: an incident spanning two hosts still matches an alert on either.

Candidate selection is deterministic: most shared entities first, then most recent
activity, then id. So replaying the same alerts in a different order converges on
the same grouping.

Stages are mapped from the rule id by an explicit, total function. An unknown rule
maps to `UNKNOWN` rather than being guessed from its name.

### 7.5 Incident lifecycle

The implemented set is a superset of the PRD minimum. `CONTAINED` is added because
a real investigation needs to record that the immediate threat was stopped before it
is formally resolved; `ACKNOWLEDGED` and `FALSE_POSITIVE` come from the PRD. The
transition graph is forward-only, and a terminal state is never reopened: new
activity creates a new incident, which keeps each investigation's timeline
immutable. `PRD.md` records this amendment.

### 7.6 Shipped rules

| id | severity | Fires when |
|---|---|---|
| `ssh-bruteforce` | high | 5 failed SSH auths from one source within 60s |
| `ssh-login-after-bruteforce` | critical | successful SSH login from a source that just triggered `ssh-bruteforce` |
| `sudo-after-suspicious-login` | high | privileged sudo by an account that just logged in after a brute force |
| `ssh-authorized-keys-modified` | critical | `authorized_keys` changed by an account that just logged in after a brute force |
| `sudo-auth-failure-burst` | high | 3 failed sudo auths for one account within 60s |
| `privileged-command-after-remote-login` | medium | privileged command on a host that recently saw a brute force |
| `http-auth-failure-spike` | medium | 10 HTTP 401/403 responses to one source address within 60s |
| `firewall-port-scan` | medium | 10 firewall-blocked packets from one source address within 5m |

The chained rules are what make them deterministic rather than noisy: a successful
login is only critical if it followed a brute force from the same address.
The HTTP rule is fed by the nginx access-log parser: only 401/403 responses
become `http.auth.failed` events (`http.access` source). Successful requests are
classified non-security-relevant, because an event per 200 response would turn
normal traffic into a self-inflicted load spike.

---

## 8. Ingestion orchestration

Package: `internal/events/ingest`.

```text
validate → persist idempotently → detect → correlate
```

**Persistence precedes detection.** Detection runs only for a newly inserted event.
A duplicate returns the existing identity and never re-enters the engine, so a
replayed batch cannot inflate a sliding-window count into a false alert.

**Correlation failure is a degradation, not an ingestion failure.** Correlation is
enrichment, not a security control: a failure means an alert is ungrouped, not that
an alert was missed. Failing the batch would make the agent retry a request whose
events are already stored, and the retry would be suppressed as a duplicate, so the
incident would still be missing while the caller saw a spurious error. The failure
is recorded in `correlation_errors` and in a metric, and the alert remains visible
ungrouped.

---

## 9. Authentication and authorization

### 9.1 Operators

Argon2id, m=64 MiB, t=3, p=4, encoded as a PHC string. The parameters are encoded
in the hash so they can be raised later without invalidating existing credentials;
`NeedsRehash` upgrades a credential opportunistically on the next successful login.

Passwords are bounded to 12–128 characters. The maximum exists because each
unauthenticated login attempt costs a full Argon2id verification: without a
bound, an 8 KiB password turns the login endpoint into a cheap CPU/RAM denial
of service. Overlong values are rejected before any hashing work happens.

Sessions are **server-side** (ADR-009). A stateless signed cookie cannot be
revoked before it expires, which is unacceptable for an administrative console.

- Cookie: `__Host-halimisoc_session` when secure, else `halimisoc_session` in dev.
  The `__Host-` prefix is browser-enforced (Secure, `Path=/`, no `Domain`), which
  stops a sibling subdomain from setting or overwriting the session.
- The storage id is derived from the token hash, so the server looks a session up
  by the presented cookie without storing or indexing the plaintext token.
- CSRF: a synchroniser token delivered in the login response and echoed in
  `X-CSRF-Token`. A custom header cannot be set by a cross-origin form post.
- Lifetime is two bounds, not one: an absolute TTL (default 12h,
  `HALIMISOC_SESSION_TTL`) and an inactivity timeout (default 2h,
  `HALIMISOC_SESSION_IDLE`, never above the TTL). Activity refreshes
  `last_seen_at` best-effort. A stolen cookie is therefore useful for at most
  the idle window, even when the absolute TTL is long.
- A password change revokes every session for the account, including the
  caller's: the caller logs in again. Keeping old sessions alive across a
  password change would defeat the change.
- If no active administrator remains (all disabled or none exists), bootstrap
  from `HALIMISOC_ADMIN_PASSWORD` creates a recovery admin instead of leaving
  the deployment permanently locked out. It still requires the
  operator-controlled secret and is audited.

Login is rate limited on **two independent keys** — per account and per source
address — so distributed guessing against one account and one host spraying many
accounts are both slowed. The limiter uses progressive backoff with a decay window,
**not** permanent lockout: an attacker who can lock out an operator has turned a
security control into a denial of service.

Failed logins are indistinguishable in response *and* timing whether or not the
account exists; a dummy Argon2id verification is performed for an unknown account.

### 9.2 Agents

A shared enrollment secret (`POST /api/v1/agents/register`) exchanges for a
**per-agent** random token. Only the SHA-256 hash is stored, so a database
disclosure does not yield usable credentials.

Why SHA-256 and not Argon2id: the token is full-entropy, so a password-style KDF
adds cost without adding security. Argon2id is essential for passwords *because*
they are low-entropy.

Rotation invalidates the previous token in the same operation, so a stolen token
does not survive rotation. Revocation revokes the agent and all its tokens.

An agent token grants access only to ingestion, heartbeat and self-inspection. It
is never an operator credential.

Enrollment (`POST /api/v1/agents/register`) is rate limited per source address
and globally for the same reason login is: the shared enrollment secret is
otherwise an online brute-force oracle.

### 9.3 Authorization

Package: `internal/authorization`. Enforced server-side, per permission, never by
hiding UI: an API can be called directly.

```text
ADMIN     full, including rule, agent and user management, and audit access
ANALYST   read everything, change alert and incident status, run analysis
READONLY  read events, alerts, incidents, agents, assets; run analysis
```

The matrix is **fail-closed**: an unknown permission and an unknown role both
deny. Adding a permission without updating the matrix denies access rather than
granting it, so a missing entry cannot silently become a privilege escalation.

### 9.4 Agent-scoped enforcement

- `POST /api/v1/events` sets the event host from the authenticated agent. A payload
  claiming a different host is **rejected**, not silently rewritten: silently
  accepting it would let one compromised agent forge events attributed to any host.
- `POST /api/v1/agents/{id}/heartbeat` checks the path id against the credential.
  The credential is the authority; the path value is an untrusted claim that must
  agree with it.

### 9.5 TOTP second factor (ADR-014)

Opt-in per account. TOTP is RFC 6238/4226: 6 digits, 30s step, SHA1, ±1 step
skew, 20-byte secret, constant-time verification — standard library only, no
new Go dependency.

- The secret is sealed at rest: AES-256-GCM under `HALIMISOC_MFA_KEY`
  (`v1:nonce:ciphertext`); without a key it stores as `plain:` (dev only, with
  a production startup warning). A database-only leak without the env key is
  then insufficient to forge codes.
- Enrollment is setup → enable (verify a code) → 10 single-use backup codes
  returned once; only SHA-256 hashes are stored and a used code is consumed.
  Disabling needs the password plus a current code; an admin can reset a lost
  authenticator (`POST /api/v1/users/{id}/mfa/reset`).
- Login stays one request: `{username, password, totp_code | backup_code}`.
  A correct password with a missing code returns 401 `MFA_REQUIRED` so the UI
  can prompt; a wrong code returns indistinguishable `invalid credentials`.
  Second-factor attempts are throttled per user and per source address.
- TOTP kills password replay but stays relayable inside its validity window,
  which is why passkeys exist alongside it (§9.6).

### 9.6 Passkeys / WebAuthn (ADR-015)

Phishing-resistant sign-in: the credential is bound to the origin, so a fake
console on another origin cannot use it. Minimal stdlib-only verifier, no new
Go dependency.

- COSE ES256 (P-256) only; attestation `none` plus `packed` self-attestation;
  CA attestation (`x5c`), TPM/Android/Apple formats, RSA/OKP keys and
  `UV=false` are rejected with explicit errors.
- RP ID plus an exact origin allowlist (`HALIMISOC_WEBAUTHN_RP_ID`,
  `HALIMISOC_WEBAUTHN_ORIGINS`) are checked on every ceremony; production
  refuses cleartext non-loopback origins at startup.
- Challenges are 32 random bytes, single-use, 5-minute TTL, held in a bounded
  in-memory store (single-node MVP, same rationale as the login limiter).
- Registration is authenticated + CSRF (max 10 keys per account); passwordless
  login (`begin` → platform dialog → `complete`) mints a normal server-side
  session, so TTL, idle, CSRF, revocation and RBAC all apply unchanged. A
  passkey login counts as its own MFA (possession + user verification).
- Clone detection: a presented sign-count at or below the stored count (both
  non-zero) is rejected and audited as a suspected clone.

---

## 10. HTTP API

Base path `/api/v1`. Full reference: `docs/api/`.

```text
GET    /api/v1/health                        liveness, no database access
GET    /api/v1/readiness                     readiness, checks database and rules
GET    /metrics                              Prometheus text format

POST   /api/v1/auth/login
POST   /api/v1/auth/logout                   session + CSRF
GET    /api/v1/auth/session

POST   /api/v1/agents/register               enrollment secret
POST   /api/v1/agents/{id}/heartbeat         agent credential, id must match
GET    /api/v1/agents/me                     agent credential
GET    /api/v1/agents                        operator
GET    /api/v1/agents/{id}                   operator
POST   /api/v1/agents/{id}/rotate            manage_agents + CSRF
POST   /api/v1/agents/{id}/revoke            manage_agents + CSRF

POST   /api/v1/events                        agent
GET    /api/v1/events                        view_events
GET    /api/v1/events/{id}                   view_events

GET    /api/v1/alerts                        view_alerts
GET    /api/v1/alerts/{id}                   view_alerts
PATCH  /api/v1/alerts/{id}/status            change_alert_status + CSRF

GET    /api/v1/incidents                     view_incidents
GET    /api/v1/incidents/{id}                view_incidents
PATCH  /api/v1/incidents/{id}/status         change_incident_status + CSRF
POST   /api/v1/incidents/{id}/analyze        run_ai_analysis

GET    /api/v1/assets                        view_assets
GET    /api/v1/summary                       view_events
GET    /api/v1/rules                         view_events
POST   /api/v1/rules/reload                  manage_rules + CSRF (transactional reload from disk)
POST   /api/v1/rules/validate                manage_rules (dry-run, changes nothing)
GET    /api/v1/rules/{id}                    manage_rules (file body for the editor)
PUT    /api/v1/rules/{id}                    manage_rules + CSRF (atomic save, no auto-reload)
DELETE /api/v1/rules/{id}                    manage_rules + CSRF (refuses the last rule)
GET    /api/v1/audit                         view_audit (admin only)

GET    /api/v1/users                         manage_users (admin only, hashes never serialised)
POST   /api/v1/users                         manage_users + CSRF
PATCH  /api/v1/users/{id}/status            manage_users + CSRF (disable revokes sessions)
```

Bare `/healthz` and `/readyz` are kept as aliases for orchestrators and load
balancers that are conventionally configured with those names.

### 10.1 Error envelope

```json
{ "error": { "code": "EVENT_MALFORMED", "message": "Event payload is invalid." } }
```

Codes: `BAD_REQUEST`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`,
`PAYLOAD_TOO_LARGE`, `RATE_LIMITED`, `INTERNAL_ERROR`, `SERVICE_UNAVAILABLE`.

Stack traces, SQL, filesystem paths and credentials are never returned.

### 10.2 Request handling

- Bodies are read through `MaxBytesReader`, so an oversized payload is rejected
  before it is buffered in full.
- Unknown JSON fields are rejected. A client that sends a field the server does not
  understand has a different contract in mind; silently ignoring it would create two
  incompatible interpretations.
- A second JSON value in the body is rejected.
- Server timeouts: read header 10s, read 30s, write 60s, idle 120s, max header 1 MiB.

### 10.3 Pagination

Cursor pagination on a stable key, default page size 50, maximum 500. A larger
`limit` is clamped rather than rejected.

OFFSET is not used because it degrades linearly and, more importantly, can skip or
repeat rows when new telemetry arrives between two page requests — which is the
normal case for an event feed.

### 10.4 SSE

`GET /api/v1/stream`, designed in ADR-003 and implemented in
`internal/events/stream` with the HTTP surface in `handlers_stream.go`.
Authenticated by the same session cookie, authorization revalidated per event so
revocation terminates an open stream, bounded concurrent connections per session,
and a payload that is a projection of the record rather than the full record.
Keepalives double as a revalidation pass: a subscriber whose session has been
revoked is disconnected on the next tick rather than waiting for the next event
that happens to require its permission.

### 10.5 Metrics

Names defined in `internal/metrics`:

```text
events_received_total      events_processed_total     events_dropped_total
event_duplicate_total      detection_total            detection_latency_ms
alerts_total               incident_created_total     correlation_merge_total
correlation_error_total    detection_state_size       agent_last_heartbeat
ai_requests_total          ai_latency_ms              ai_errors_total
parser_error_total         rule_load_failure_total    clock_skew_anomaly_total
spool_bytes                sse_active_connections
```

---

### 10.6 Console

`apps/web` is a Next.js application that sits between the browser and the API and
holds the operator's session on the server. It is a backend-for-frontend, not a
second API.

**The browser never reaches the Go API.** `HALIMISOC_API_URL` is read only by
server-side code, so there is no origin to give a CORS policy to, no bearer token
in client reach, and no way for an injected script to enumerate the API surface
by making cross-origin calls. Every read is a server component fetch; every write
goes through one of a fixed set of route handlers.

**Session.** `POST /api/auth/login` exchanges credentials for an API session and
stores it, together with the API's CSRF token, in an HttpOnly, `SameSite=Strict`
cookie that JavaScript cannot read. `POST /api/auth/session` reads it back for
server components, and `POST /api/auth/logout` clears it and revokes the API
session. Because the cookie is `HttpOnly`, a script that achieves execution still
cannot exfiltrate the session directly.

**Mutations.** Every state-changing request carries a double-submit CSRF token
compared in constant time, and is dispatched through a closed allowlist of
actions in `/api/proxy`. An action that is not in the table is a `400`, never a
pass-through: the allowlist is the whole of what the browser can ask the server
to do on its behalf.

**Realtime.** The console opens one `EventSource` per tab, at the root layout, so
the connection cap stays meaningful. A stream frame is a hint and never a source
of truth: on a relevant event the route is re-rendered from the server, which
re-runs authorization through exactly the code path a manual reload would take.
A payload is never patched into the view directly, because that would put the
stream's authorization surface behind the UI's, which is strictly weaker.

**CSP.** See `docs/security/configuration.md`. The policy is built per request in
`src/proxy.ts` with a fresh nonce in `script-src` alongside `'strict-dynamic'`;
a static policy cannot admit the App Router's inline flight payload without
`'unsafe-inline'`, and admitting every inline script would defeat the point.
Every route declares `export const dynamic = 'force-dynamic'` because a nonce can
only be applied while a request is in flight.

**Fail-closed configuration.** A production build refuses to serve a session
cookie over cleartext unless the operator has set
`HALIMISOC_WEB_ALLOW_INSECURE_COOKIES=true` to acknowledge it. The guard is a
separate variable rather than something inferred from the environment, because a
guard that relaxed itself whenever it noticed it was running a test would not be
a guard.

## 11. Optional AI

Packages: `internal/ai`, plus `POST /api/v1/incidents/{id}/analyze`.

Governing decision: ADR-004. Three properties are not negotiable.

1. **AI never runs unless explicitly requested.** Nothing in the ingestion,
   detection or correlation path invokes it.
2. **No provider means a computed summary, not an error.** An AI outage must not
   look like a product outage.
3. **The response states its provenance.** `mode`, `grounded` and `advisory` are
   always present.

| Mode | Meaning |
|---|---|
| `DISABLED` | No provider configured; the analysis is computed. |
| `PROVIDER` | A provider produced it and it passed validation. |
| `UNAVAILABLE` | A provider was configured but failed. |
| `REJECTED` | The response failed validation and was discarded. |

`grounded` is `true` only for the computed summary. Free text from a model is never
labelled grounded, because grounding is a property this code cannot verify about
free text.

**Prompt-injection boundary.** Evidence is fenced with explicit markers, every value
is flattened onto a single prefixed line, fence markers and code fences inside data
are rewritten, values are bounded and truncated on a rune boundary, and the standing
system instruction is a constant that states the trust boundary. The evidence block
is built **only** from application-owned records read by identifier; nothing from
the request body is ever part of the input, which makes injection through the
endpoint impossible by construction.

**Provider adapter** is OpenAI-compatible (`/chat/completions`) with zero SDK
dependency, `stream:false`, a pinned low temperature so a summary is repeatable, a
bounded `max_tokens`, and redirects refused so the `Authorization` header cannot be
forwarded to another host.

---

## 11a. Incident webhooks

Package: `internal/notify`, configured by `HALIMISOC_WEBHOOK_URL`.

The notifier follows the same advisory principle as the AI analyst: it observes
the pipeline but is never on it. `PublishIncident` enqueues on creation only;
merges never notify. The queue is bounded (64) and non-blocking, one worker
delivers with a timeout, redirects are refused, the response body is drained to
a 4 KiB bound and discarded, and every outcome lands in
`webhook_sent_total` / `webhook_error_total` / `webhook_dropped_total`.

The payload is incident identity and scope only. Raw evidence never leaves the
platform on a webhook. An invalid URL fails closed at startup.

---

## 12. Storage

Package: `internal/storage`. The interface is pure Go so that detection,
correlation and the API can be tested without a database. PostgreSQL is the
production backend; the memory implementation is for tests and `--no-database`
demos (ADR-002).

### 12.1 Schema invariants

```text
UNIQUE (events.id)                     ingestion idempotency, enforced by the database
UNIQUE (agents.host)                   one agent record per host
UNIQUE (agent_tokens.token_hash)       credential identity
UNIQUE lower(users.username)           case-insensitive, so two accounts cannot
                                       differ only in case
FK events.agent_id  → agents.id        ON DELETE SET NULL
FK agent_tokens.agent_id → agents.id   ON DELETE CASCADE
FK sessions.user_id → users.id         ON DELETE CASCADE
CHECK constraints on every enum column
```

### 12.2 Indexes

Chosen to match the actual read patterns, not invented:

```text
events (id DESC)                       keyset pagination, stable tie-break
events (host, event_time DESC)         per-host timeline
events (actor, event_time DESC)
events (src_ip, event_time DESC)
events (type, event_time DESC)
alerts (id DESC), (status), (severity), (host), (rule_id, rule_version)
incidents (last_seen DESC, id DESC), (status), (severity)
audit_logs (timestamp DESC, id DESC), (actor), (action)
```

### 12.3 Migrations

Versioned SQL in `apps/api/migrations`, applied at startup. Each migration runs in
a transaction together with its bookkeeping insert, so a failure leaves neither a
half-applied schema nor a false success record.

**An applied migration is immutable.** A change is a new file. Editing an applied
migration would silently leave every existing database on the old schema while a
fresh install got the new one, which is the classic way a deployment ends up
running a schema nobody can reproduce. `0002_incident_lifecycle.sql` exists exactly
because of this rule.

### 12.4 Retention

Raw evidence expires before the structured event (ADR-011). Expiry nulls the `raw`
column and sets `raw_expired`, so the structured event — and therefore every alert
and incident that references it — remains valid. The UI must show an expired raw
line as unavailable rather than as an empty log line.

Raw retention may not exceed event retention; startup refuses that combination,
because it would mean raw evidence outliving the event that justifies it.

At event retention the structured event is deleted, together with alerts and
audit rows older than the same cutoff. Alert and incident event ids are
historical references, not foreign keys, so this cannot cascade into an
investigation record. Incidents are operator-owned and are never deleted by
retention. Each pass also prunes detection state older than the maximum rule
window (24 h).

### 12.5 Concurrency

- Event insert uses `ON CONFLICT DO NOTHING` and reads the row count: no
  read-then-write race.
- Status update pins the expected previous status in the `WHERE` clause, so the
  state machine is enforced by the database as well as the domain layer. Without it,
  two concurrent requests could each read `OPEN` and each write a different terminal
  status, and the last writer would silently win.
- Every query is parameterised. No filter value is ever concatenated into SQL.
- The memory implementation clones on every boundary, so a caller cannot mutate
  stored state through a returned pointer.

---

## 13. Configuration and limits

Package: `internal/config`. See `docs/security/configuration.md` for the full table.

Every bound has a default **and** a maximum; a configured value above the maximum is
clamped, not rejected, so a typo cannot remove a bound. A negative or unparseable
value falls back to the default.

Startup is **fail-closed**:

| Condition | Behaviour |
|---|---|
| No database URL and memory storage not explicitly allowed | exit |
| No operator account and no admin password | exit |
| Admin password under 12 characters | exit |
| Production without secure cookies | exit |
| Production with an enrollment secret under 24 characters | exit |
| No rule files, or any invalid rule file | exit |
| No migration files | exit |
| Half-configured AI provider | exit |

A server that starts with a default admin password, or with no detection rules, is
worse than one that does not start, because it looks healthy while being wrong.

---

## 14. Observability

- **Structured logs** (JSON via `log/slog`) with method, path, status, duration and
  peer address. Query strings and bodies are not logged: they carry operator input
  and raw telemetry would otherwise become a log-injection sink.
- **Metrics** in Prometheus text format, dependency-free.
- **Health vs readiness are separate.** Liveness does not touch the database: a
  database outage should not cause an orchestrator to kill an otherwise healthy
  process, because restarting it would not fix the outage and would lose detection
  state. Readiness checks the database and reports the rule count, because serving
  ingestion with zero rules would silently stop detecting while still accepting
  telemetry.
- **Audit log** for login, logout, enrollment, token rotation and revocation, alert
  and incident status changes, analysis requests and bootstrap. `SECURITY.md` states
  plainly that this is not tamper-proof.

---

## 15. Deployment

Single-node, as implemented:

```text
┌──────────────────────┐        ┌────────────────────────┐
│  Reverse proxy (TLS) │───────►│  halimisoc-api         │
└──────────────────────┘        │  127.0.0.1:8080        │
                                └───────────┬────────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    ▼                       ▼                       ▼
             ┌────────────┐          ┌─────────────┐        ┌─────────────┐
             │ PostgreSQL │          │ Web console │        │ AI provider │
             │ loopback   │          │ Next.js     │        │ optional    │
             └────────────┘          └─────────────┘        └─────────────┘
                                            ▲
                                            │ bearer token
                                    ┌───────┴────────┐
                                    │ halimisoc-agent│  (one per monitored host)
                                    └────────────────┘
```

- The API speaks plain HTTP and binds loopback by default; TLS terminates in the
  proxy.
- The console is the only user-facing surface. It reaches the API over the
  container network or loopback, and is published on loopback itself so the
  reverse proxy is still the only thing that terminates TLS.
- PostgreSQL binds loopback.
- Containers run as an unprivileged user with `no-new-privileges` and all
  capabilities dropped; the API image is `scratch` with a read-only root filesystem
  and a `tmpfs` for `/tmp`.
- `/metrics` is unauthenticated and exposes counters only. Restrict it at the proxy.

---

## 16. Known limitations

Stated here rather than left implicit.

1. **Detection state is lost on restart.** A brute-force sequence straddling a
   restart may not alert. Accepted MVP limitation (ADR-005).
2. **Correlation is conservative.** Two alerts with no entity in common never merge,
   even if a human would see them as related. An analyst can link them manually.
3. **No tamper-proof audit.** Audit records are in the same database as everything
   else (see `SECURITY.md`).
4. **Single-tenant.** No tenant isolation.
5. **Agent parsers cover `sshd`, `sudo`, `authorized_keys` changes, nginx
   access logs, Docker json-file envelopes and UFW block records.** Generic
   syslog (cron, systemd, non-UFW iptables/nftables) is not yet implemented:
   a catch-all syslog parser is deliberately avoided, because an event per
   syslog line would turn normal system chatter into stored telemetry.
6. **An agent credential is a bearer token.** Anyone who can read it from the host
   can ingest as that host. Root on a monitored host can also tamper with the logs
   the agent reads; this is inherent and documented.

---

## 17. Definition of done

A feature is done when:

- it works end to end against PostgreSQL, not only in a unit test;
- security-sensitive behaviour has a test that fails without the control;
- every new bound has a default and a maximum;
- a new invariant is documented here or in an ADR;
- `gofmt`, `go vet`, the race-enabled test suite and the end-to-end test pass.

A security property must not be claimed unless it is implemented and tested.
