# Security Policy

## Reporting a vulnerability

Do not open a public issue for a security problem.

Report it privately to the maintainer listed in `README.md`. Include what you
did, what happened, what you expected, and the commit you tested. A proof of
concept is welcome; a weaponised exploit is not required.

You will get an acknowledgement, an assessment, and a fix or a reasoned refusal.
Please allow a reasonable embargo before public disclosure.

## Supported versions

The project is pre-1.0. Only the latest commit on the default branch is
supported. There are no backports.

## Security properties this project claims

These are implemented and covered by tests. Nothing else is claimed.

| Property | Where it is enforced |
|---|---|
| Telemetry is validated before it reaches security logic | `internal/events/validation` |
| Ingestion is idempotent; a replay cannot fabricate an alert | `internal/events/ingest`, `UNIQUE(events.id)` |
| Detection is deterministic and AI-independent | `internal/detection/engine` |
| Alert severity comes from the rule, never from the event or the client | `internal/detection/engine` |
| Rules cannot execute code and are rejected wholesale if invalid | `internal/detection/rules` |
| Passwords are Argon2id-hashed; sessions are server-side and revocable | `internal/auth` |
| Passwords are bounded 12–128 chars; overlong is rejected before hashing | `internal/auth/password.go`, `internal/api/handlers_auth.go` |
| TOTP MFA (6-digit/30s/±1 skew) with sealed secrets, single-use codes and single-use backup codes | `internal/mfa`, `internal/api/handlers_mfa.go`, migrations `0004_mfa.sql`, `0006_totp_last_step.sql` |
| Passkeys (WebAuthn, ES256, none/packed, UV required, origin-bound, clone detection) | `internal/webauthn`, `internal/api/handlers_webauthn.go`, migration `0005_passkeys.sql` |
| TOTP setup shows a local QR (no network) plus manual secret | `apps/web/src/components/MfaSettings.tsx` (`react-qr-code`) |
| Sessions expire on absolute TTL and on 2h idle; activity refreshes `last_seen_at` | `internal/api/server.go`, `internal/config` |
| Self password change needs the current password; admin reset is admin-only and both revoke sessions | `internal/api/handlers_users.go` |
| Enrollment is rate-limited per IP/global | `internal/api/handlers_agents.go` |
| Analyze requires CSRF and is throttled per user/global; concurrent LLM calls are bounded | `internal/api/handlers_analyze.go`, `internal/ai` |
| Webhooks sign with HMAC-SHA256 when configured and never target metadata | `internal/notify` |
| AI provider refuses cleartext remote and metadata URLs | `internal/ai/provider.go` |
| `/metrics` accepts a bearer token when configured | `internal/api/handlers_health.go` |
| Agent tokens are stored only as hashes | `internal/auth`, `internal/storage/postgres` |
| State-changing requests require a CSRF token | `internal/api` |
| Authorization is enforced server-side per permission | `internal/authorization` |
| An agent cannot ingest events attributed to another host | `internal/api/handlers_resources.go` |
| Operator management is admin-only; disabling revokes sessions and the last admin is protected | `internal/api/handlers_users.go` |
| Rule reload is admin-only and transactional; invalid sets never replace active rules | `internal/api/handlers_rules.go` |
| Rule authoring is admin-only; save is atomic and activation stays an explicit reload | `internal/api/handlers_rules_author.go` |
| Webhooks fire on incident creation only and never carry raw evidence | `internal/notify` |
| Correlation only merges alerts that share a concrete entity | `internal/correlation` |
| Every query is parameterised | `internal/storage/postgres` |
| The browser never reaches the Go API; sessions live in HttpOnly cookies | `apps/web/src/lib/session`, `apps/web/src/app/api` |
| Console mutations dispatch through a closed action allowlist | `apps/web/src/app/api/proxy` |
| Console responses carry a per-request CSP nonce that their own scripts carry | `apps/web/src/proxy.ts` |
| A production console build refuses insecure cookies without acknowledgement | `apps/web/src/lib/config.ts` |

## Explicitly not claimed

This section exists so that nobody infers a guarantee the project does not make.

- **No tamper-proof audit log.** Audit records live in the same database as
  everything else. An attacker with database write access can alter them.
- **No cryptographic evidence integrity.** Raw evidence is stored as text and is
  not signed or chained.
- **No autonomous response.** The MVP performs no action on a monitored host.
- **No multi-tenancy isolation.** The MVP is single-tenant by design.
- **No guarantee against a root-level attacker on the monitored host.** The
  agent reads logs and holds a credential; root on that host can tamper with
  both.
- **Detection is not complete.** A missed detection is expected behaviour for any
  rule set, and is not treated as a vulnerability in itself.

## Accepted findings

`npm audit` reports five advisories against the console's **development**
toolchain — vitest, vite and esbuild. They are recorded here rather than
suppressed, because a finding that is hidden is a finding nobody will revisit.

```text
npm audit --omit=dev     0 vulnerabilities   the shipped dependency tree
npm audit                5 vulnerabilities   development tooling only
```

- **Production dependencies are clean.** The console image runs
  `.next/standalone`, which bundles only `next`, `react`, `react-dom` and
  `server-only`. The findings do not reach a deployment.
- **The findings are local to a developer's machine**, and the most serious
  (vitest remote code execution) only applies while the vitest API server is
  listening and a developer visits an untrusted page in the same browser.
- **They are not upgraded yet.** vitest 5 pulls vite 8, which
  `@vitejs/plugin-react` does not currently peer-support; installing it would
  require `--legacy-peer-deps`, i.e. an unsupported combination chosen to make a
  scanner green. CI runs `npm audit --omit=dev` so the production tree cannot
  regress silently.

## Threat model summary

Untrusted: raw logs, agent payloads, event timestamps, usernames, hostnames,
paths, command lines, external enrichment and model output.

Trusted: authenticated identity, authorization state, validated rule
configuration, application-generated metadata and output schemas.

A vulnerability report is most interesting when it shows untrusted input
influencing a trusted decision.

## Hardening expectations for operators

- Terminate TLS in front of the API. The API speaks plain HTTP by design.
- Set `HALIMISOC_SECURE_COOKIES=true` in production; startup refuses otherwise.
- Remove `HALIMISOC_ADMIN_PASSWORD` from the environment after the first boot.
- Keep the enrollment secret separate from operator credentials, and rotate it if
  it may have leaked.
- Bind PostgreSQL to loopback and restrict who can read the database.
- If the console is deployed, serve it over HTTPS, leave
  `HALIMISOC_WEB_ALLOW_INSECURE_COOKIES` unset, and point `HALIMISOC_API_URL` at
  a loopback address so the API is never directly reachable from a browser.
