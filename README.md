# HalimiSOC

> **Lightweight, AI-Assisted Security Operations Center**

HalimiSOC is a portable, security-first security monitoring platform for
homelabs, students, developers, sysadmins and small teams. It collects
infrastructure telemetry, normalizes it into canonical security events, detects
activity with deterministic rules, correlates related alerts into incidents, and
keeps AI firmly in the role of an analyst copilot.

```text
Collect → Normalize → Validate → Detect → Correlate → Investigate → Explain
```

## Why

Raw infrastructure logs are noisy and hard to investigate. Heavy SIEM products
are operationally expensive for small environments. HalimiSOC is built around one
idea: **turn scattered infrastructure logs into understandable security
incidents**, with the detection layer remaining deterministic and explainable.

AI never participates in detection, correlation, severity or authorization.

## Status

This is a working backend vertical slice, not a finished product. What is below
is implemented and covered by tests. What is not implemented is listed as not
implemented.

**Working end to end, verified against PostgreSQL:**

- Canonical event contract with a closed enum set and schema versioning
- Agent: enrollment, log tailing with rotation and truncation handling, bounded
  disk spool, exponential backoff with jitter, heartbeat
- Parsers for `sshd` and `sudo` audit records, an `authorized_keys` change
  parser, an nginx access-log parser, a Docker json-file envelope parser, and
  a UFW firewall-block parser, with a bounded multi-line assembler
- Validation boundary: canonical host/identity/IP, control-character stripping,
  field bounds, clock-skew rejection
- Idempotent ingestion: a replay cannot create a second event or a phantom alert
- Deterministic detection: threshold, sliding window, grouping, cooldown and
  rule chaining, with rules as validated YAML data
- Entity-aware correlation into incidents with an ordered kill-chain narrative
- Authenticated API: sessions with CSRF (absolute TTL plus inactivity timeout),
  agent bearer tokens, RBAC with admin user management, opt-in TOTP second
  factor and passkeys (WebAuthn, including passwordless login), password change
  with session revocation, transactional rule reload, audit log, cursor
  pagination, Prometheus metrics (optional bearer token)
- Eight detection rules covering brute force, suspicious login, privilege
  escalation, persistence, HTTP authentication spikes and firewall port scans
- Safe attack simulation mode that exercises the real parser path
- SSE realtime stream: permission-filtered events, bounded subscribers per
  session, and session revocation that closes the connection
- Next.js console: server-side sessions in HttpOnly cookies, double-submit CSRF,
  a closed server-side allowlist for every mutation, a per-request CSP nonce,
  and overview, events, alerts, incidents, assets, agents, rules and audit views

**Verified end to end:** the synthetic scenario produces 10 events, fires 5
distinct rules, and correlates them into one `critical` incident with 5 stages.
See [Verification](#verification).

- Advisory AI analyst: computed evidence summary always available; optional
  OpenAI-compatible provider, with prompt-injection boundaries and output validation
- Incident webhooks: one `incident.created` POST per new incident, scope-only
  payload, bounded async delivery with metrics
- Rule authoring: admin console UI plus validate/save/delete/reload API with
  atomic saves and transactional reloads
- Versioned migrations with an as-built lifecycle amendment as a separate file

**Not built yet:**

- Additional parsers: generic syslog (cron, systemd, non-UFW firewall drivers).
  The Docker json-file envelope parser above is built; generic syslog stays out
  deliberately — an event per syslog line would turn system chatter into stored
  telemetry.
- Response actions — post-MVP, admin-approved only

## Architecture

```text
Raw telemetry
   │
   ▼
Reader ──► Line assembler ──► Parser ──► Normalizer ──► Canonical event
                                                              │
                                                              ▼
                                                     Idempotent ingestion
                                                              │
                                                              ▼
                                                     Deterministic detection
                                                              │
                                                              ▼
                                                            Alert
                                                              │
                                                              ▼
                                                    Entity-aware correlation
                                                              │
                                                              ▼
                                                          Incident
                                                              │
                                                              ▼
                                          Evidence selection ──► AI (optional)
```

```text
┌──────────────────────────┐
│   HalimiSOC Web          │   server-side session
│   Next.js / TypeScript   │
└────────────┬─────────────┘
             │ REST · SSE
┌────────────▼─────────────┐        ┌─────────────────────┐
│   HalimiSOC API (Go)     │◄──────►│  HalimiSOC Agent    │
│                          │ bearer │   (Go, static)      │
│ ingest · validate        │  token │                     │
│ detect · correlate       │        │ tail · parse        │
│ serve · audit            │        │ spool · backoff     │
└────────────┬─────────────┘        └──────────┬──────────┘
             │                                  │
┌────────────▼─────────────┐              auth.log / secure
│      PostgreSQL          │              syslog
└──────────────────────────┘
```

Detailed pipeline reference: [`docs/architecture/pipeline.md`](docs/architecture/pipeline.md).
Decisions with their trade-offs: [`docs/decisions/`](docs/decisions/).

## Quick start

Requires Go 1.26+ and PostgreSQL 14+. The console additionally requires Node 20+.

```bash
# 1. Create the database role and databases
make db-create

# 2. Copy and review the configuration
cp .env.example .env

# 3. Build
make build

# 4. Run the API (creates the admin account on first start)
make run
```

In a second terminal, run the console and open http://127.0.0.1:3000:

```bash
cd apps/web && npm install && npm run dev
```

In a third terminal, run the synthetic attack scenario through the real
ingestion path:

```bash
make simulate
```

Then read the results:

```bash
# Log in and keep the session cookie
curl -s -c /tmp/hs.jar -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"halimisoc-dev-admin"}'

curl -s -b /tmp/hs.jar 'http://127.0.0.1:8080/api/v1/alerts?limit=20'
curl -s -b /tmp/hs.jar 'http://127.0.0.1:8080/api/v1/incidents?limit=5'
```

Or run the whole demonstration in one command:

```bash
HALIMISOC_DATABASE_URL='postgres://…' scripts/demo/run-demo.sh
```

## Collect real logs

```bash
./bin/halimisoc-agent \
  -server https://halimisoc.example.test \
  -enroll-token "$HALIMISOC_ENROLL_TOKEN" \
  -host "$(hostname)" \
  -file /var/log/auth.log \
  -spool-dir /var/lib/halimisoc/spool \
  -state-dir /var/lib/halimisoc/state
```

One agent tails one file. Run one agent per source class:

```bash
# nginx access log (feeds the HTTP authentication spike rule)
/bin/halimisoc-agent -server https://halimisoc.example.test \
  -enroll-token "$HALIMISOC_ENROLL_TOKEN" -host "$(hostname)" \
  -file /var/log/nginx/access.log \
  -spool-dir /var/lib/halimisoc/spool-nginx -state-dir /var/lib/halimisoc/state-nginx

# Docker container log, json-file driver (inner lines reuse host parsers)
/bin/halimisoc-agent -server https://halimisoc.example.test \
  -enroll-token "$HALIMISOC_ENROLL_TOKEN" -host "$(hostname)" \
  -file /var/lib/docker/containers/<id>/<id>-json.log \
  -spool-dir /var/lib/halimisoc/spool-docker -state-dir /var/lib/halimisoc/state-docker

# Kernel log for UFW blocks (feeds the firewall port-scan rule)
/bin/halimisoc-agent -server https://halimisoc.example.test \
  -enroll-token "$HALIMISOC_ENROLL_TOKEN" -host "$(hostname)" \
  -file /var/log/kern.log \
  -spool-dir /var/lib/halimisoc/spool-kern -state-dir /var/lib/halimisoc/state-kern
```

The agent refuses to send credentials over plain HTTP unless `-insecure` is
passed. Use TLS in any real deployment.

| Flag | Purpose | Default |
|---|---|---|
| `-server` | API base URL | `http://localhost:8080` |
| `-token` / `-enroll-token` | per-agent token, or the enrollment secret | — |
| `-ca-cert` | PEM file with CAs to trust in addition to the system pool | — |
| `-host` | hostname reported to the server | OS hostname |
| `-file` | log file to collect | — |
| `-simulate` | run the synthetic scenario instead of reading a file | false |
| `-spool-dir` | disk buffer used while the server is unreachable | `data/spool` |
| `-state-dir` | persisted read offsets | `data/state` |
| `-batch` | events per request (1–5000) | `100` |
| `-queue` | in-memory events before spilling to disk | `4096` |
| `-spool-bytes` | hard spool size cap | `100 MiB` |

## Deployment

`deploy/docker-compose.yml` runs PostgreSQL, the API, the console and Caddy.
From the repository root:

```bash
cp .env.example .env          # then replace every change-me value
docker compose -f deploy/docker-compose.yml --env-file .env up -d
```

Caddy is the only service bound to a public interface. `HALIMISOC_SITE_ADDRESS`
must resolve to this host and `HALIMISOC_WEBAUTHN_RP_ID` /
`HALIMISOC_WEBAUTHN_ORIGINS` must match the console origin, or passkeys and TLS
issuance will fail.

Tagged releases publish `ghcr.io/<owner>/<repo>-{api,agent,web}:<tag>`. For a
supervised agent install use `deploy/systemd/halimisoc-agent.service`: enroll
once with `-enroll-token` so the credential lands in the state directory, then
start the unit, which authenticates with that persisted token. Put optional
settings such as `HALIMISOC_CA_CERT` in `/etc/halimisoc/agent.env`. Upgrade and
rollback steps: [`docs/operations/upgrade.md`](docs/operations/upgrade.md).

## Detection rules

Rules are YAML data, validated as a whole at startup. A rule file that fails
validation stops the process: the detector never runs a partially applied rule
set.

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

Rule syntax, semantics and the field allowlist:
[`docs/detection/`](docs/detection/).

## Verify

```bash
make check          # gofmt, go vet, unit tests
make test-race      # unit tests with the race detector
make test-e2e       # black-box: agent + API as separate processes
make web-check      # console: typecheck, unit tests, production build
make web-e2e        # console: Playwright against the Go API and PostgreSQL
```

Verification actually performed on this codebase:

```text
unit tests                  all packages pass, race detector clean
end-to-end (PostgreSQL)     PASS  agent → ingest → detect → correlate
console unit tests          PASS  39 tests (session codec, CSRF, API client,
                                   config guard, formatting, volume bucketing)
console end-to-end          PASS  17 tests, production build over Playwright
detection outcome           10 events → 5 alerts (5 distinct rules)
correlation outcome         1 critical incident, 5 ordered stages
idempotency                 replay inserts 0 events, produces 0 alerts
outage behaviour            agent spools and retries, does not exit
parser fuzz                 PASS  ~950k executions, no crashes
```

Coverage of the security-critical logic:

```text
metrics            89.8%      detection/engine 91.0%
detection/rules    87.0%      id               85.2%
detection/state    84.3%      parser           86.7%
validation         81.4%      correlation      83.6%
config             79.2%      auth             79.1%
ingest             82.1%
```

## Security

The security properties this project claims, the ones it explicitly does **not**
claim, and the threat model are documented in [`SECURITY.md`](SECURITY.md).
Hardening and configuration: [`docs/security/configuration.md`](docs/security/configuration.md).

Highlights:

- Passwords hashed with Argon2id (12–128 chars); sessions stored server-side and revocable
- Opt-in TOTP second factor and passkeys (WebAuthn), including passwordless login
- Agent tokens stored only as SHA-256 hashes, rotating invalidates the previous
- CSRF required on every cookie-authenticated state change
- Authorization enforced server-side per permission, never by hiding UI
- An agent cannot ingest events attributed to another host
- Rules cannot execute code, read raw evidence or exceed bounded values
- Every SQL query parameterised
- Secrets never logged; telemetry redacted for credential shapes

## API

Full reference: [`docs/api/`](docs/api/). Readiness: `GET /api/v1/readiness`
reports database health and the number of loaded rules.

```text
POST   /api/v1/auth/login                    operator login (sets session cookie)
GET    /api/v1/auth/session                  current operator and CSRF token
POST   /api/v1/agents/register               enrollment secret -> agent token
GET    /api/v1/agents/me                     agent self-identity
POST   /api/v1/events                        agent event delivery (idempotent)
GET    /api/v1/events                        normalized events, filtered, paginated
GET    /api/v1/alerts                        alerts with evidence ids
GET    /api/v1/incidents                     correlated incidents with stage timeline
POST   /api/v1/incidents/{id}/analyze        advisory AI analysis (CSRF)
POST   /api/v1/rules/reload                  transactional rule reload (admin, CSRF)
GET    /api/v1/users                         operator accounts (admin)
POST   /api/v1/users                         create operator (admin, CSRF)
GET    /api/v1/assets                        asset inventory from agents and events
GET    /api/v1/summary                       overview counters
GET    /api/v1/audit                         audit log (admin only)
GET    /api/v1/health /api/v1/readiness      platform endpoints
GET    /metrics                              Prometheus text format
```

## Configuration

Every setting has a safe default and a hard maximum; a configured value above the
maximum is clamped. See [`.env.example`](.env.example) and
[`docs/security/configuration.md`](docs/security/configuration.md).

## Repository layout

```text
apps/
  api/            server entrypoint, migrations
  agent/          collection agent: reader, spool, sender, simulation
internal/
  events/         model, parser, validation, ingestion
  detection/      rules, state, engine
  correlation/    entity-aware incident assembly
  incidents/      incident contract and lifecycle
  alerts/         alert contract and lifecycle
  auth/           passwords, sessions, CSRF, rate limiting
  authorization/  RBAC matrix
  api/            HTTP handlers and middleware
  storage/        store interface, memory and PostgreSQL implementations
  audit/ config/ id/ metrics/ secret/
packages/rules/   detection rules as data
tests/            black-box end-to-end tests
docs/             architecture, API, detection, security, ADRs
deploy/           Dockerfiles and compose
```

## Development

```bash
make help           # list targets
make test-cover     # coverage summary
make vuln           # govulncheck
make secrets        # gitleaks
make check          # what CI runs
```

CI runs formatting, vet, race tests, the end-to-end test, a vulnerability scan, a
secret scan and both Docker builds. Security findings are never suppressed to
produce a green build; accepted risk is documented.

## Roadmap

1. ~~Agent → ingestion → detection~~ **done**
2. ~~Correlation → incidents~~ **done**
3. ~~Web dashboard (Next.js) and the SSE stream~~ **done**
4. ~~Asset and audit views~~ **done**; ~~rule authoring UI~~ **done**
   (validate → save → reload, admin-only, atomic saves)
5. AI analyst: incident summary, evidence explanation, bounded natural-language
   queries, response recommendations (advisory only)
6. Notification integrations beyond the generic incident webhook

## License

MIT. See [`LICENSE`](LICENSE).

## Author

**Luthfi Halimi**

---

> **HalimiSOC — Watch the infrastructure. Understand the incident.**
