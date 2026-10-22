# Configuration and hardening

Every setting is an environment variable. The server has a safe default for each
one, so an unconfigured process starts bounded and in development mode rather
than starting unbounded and open.

## Fail-closed startup

The process refuses to start when a security-critical setting is missing. This
is deliberate: a server that starts with a default admin password, or with no
detection rules, is worse than one that does not start, because it looks healthy
while being wrong.

| Condition | Behaviour |
|---|---|
| `HALIMISOC_DATABASE_URL` unset and memory storage not explicitly allowed | exit |
| No operator account exists and `HALIMISOC_ADMIN_PASSWORD` unset | exit |
| `HALIMISOC_ADMIN_PASSWORD` shorter than 12 characters | exit |
| `HALIMISOC_ENV=production` and `HALIMISOC_SECURE_COOKIES` false | exit |
| `HALIMISOC_ENV=production` and `HALIMISOC_AGENT_ENROLL_SECRET` under 24 characters | exit |
| No rule files found | exit |
| A rule file fails validation | exit |
| Migration files missing | exit |
| `HALIMISOC_AI_BASE_URL` targeting cloud metadata or cleartext remote (non-loopback http) | exit at provider construction |
| `HALIMISOC_WEBHOOK_URL` targeting cloud metadata or embedding credentials | exit |

## Resource limits

Each bound has a default and a hard maximum. A configured value above the maximum
is clamped, not rejected, so a typo cannot silently remove a bound.

| Setting | Default | Maximum |
|---|---|---|
| HTTP request body | 4 MiB | 16 MiB |
| Events per batch | 1 000 | 5 000 |
| Event field | 4 KiB | 64 KiB |
| Raw line | 8 KiB | 64 KiB |
| Multiline buffer | 64 KiB | 1 MiB |
| In-memory queue | 10 000 | 100 000 |
| Disk spool | 100 MiB | 4 GiB |
| Database result rows | 10 000 | 100 000 |
| Page size | 50 | 500 |
| AI context | 64 KiB | 256 KiB |
| Concurrent AI requests | 2 | 8 |
| SSE connections | 100 | 1 000 |
| Raw evidence retention | 72 h | 90 days |
| Event retention | 720 h | 1 year |

Raw retention may never exceed event retention; startup refuses that
combination, because it would mean raw evidence outliving the event that
justifies it.

## Console

The console is a server-side session holder: the browser only ever receives an
HttpOnly cookie it cannot read, and every mutation passes through a closed
allowlist on the server before it reaches the API. The web session codec
rejects anything outside the token alphabet (`sess_` + base64url, base64url
CSRF, lowercase usernames), so a tampered cookie cannot become header injection
into the server-to-API `Cookie` header.

## Operator MFA (TOTP)

| Setting | Behaviour |
|---|---|
| `HALIMISOC_MFA_KEY` unset | TOTP secrets store as `plain:<base32>`; production warns at startup |
| `HALIMISOC_MFA_KEY` set (base64 32B) | secrets sealed AES-256-GCM `v1:nonce:ct` |
| `POST /auth/mfa/setup` | authenticated + CSRF + step-up (password, plus current code when MFA is enabled); rotates pending secret, returns secret + `otpauth_url` |
| `POST /auth/mfa/enable` | verifies code (±1 step), enables, returns 10 backup codes once (hashes only stored) |
| Login | `{username,password,totp_code\|backup_code}`; missing code -> 401 `MFA_REQUIRED`; backup codes single-use |
| `POST /auth/mfa/disable` | needs password + code; clears secret and backups |
| `POST /users/{id}/mfa/reset` | admin + CSRF lost-authenticator recovery; audited |
| Guessing | per-user/per-IP backoff with 429, audited `MFA_LOGIN_FAILURE`, counted `mfa_failure_total` |

## Passkeys (WebAuthn)

| Setting | Behaviour |
|---|---|
| `HALIMISOC_WEBAUTHN_RP_ID` (dev default `127.0.0.1`) | effective console domain, no port; must be a hostname, never an IP literal — browsers reject IPs as invalid RP IDs. Required explicitly in production. |
| `HALIMISOC_WEBAUTHN_ORIGINS` (dev default both loopback `:3000` origins) | exact allowlist checked against `clientData.origin` on every ceremony. Required explicitly in production. |
| Production with `http://` non-loopback origin | fail closed at startup |
| Algorithms / formats | ES256 only; attestation `none` + `packed` self; anything else rejected |
| Challenges | 32B random, single-use, 5-minute TTL, bounded in-memory store |
| Registration | session + CSRF + step-up (password, plus current code when MFA is enabled) |
| Login | passwordless; success mints a normal session and rotates the sign count; backwards counters rejected as suspected clones |

| Setting | Behaviour |
|---|---|
| `HALIMISOC_WEB_SECURE_COOKIES` unset | defaults to `true` in a production build |
| Production build with `HALIMISOC_WEB_SECURE_COOKIES=false` and no explicit acknowledgement | refuse to serve |
| Production build with `HALIMISOC_WEB_ALLOW_INSECURE_COOKIES=true` | serve over plain HTTP |
| `HALIMISOC_API_URL` | where the console finds the API; never exposed to the browser |

The refusal is deliberate. Serving a session cookie over cleartext means the
session is replayable by anyone on the path, so a production build will not do it
by accident. The acknowledgement exists for the cases that are real rather than
careless — a lab or training environment on a trusted network, and the
end-to-end suite, which drives `http://127.0.0.1` where a `Secure` cookie is
never sent. It is a separate variable rather than something inferred from the
environment on purpose: a guard that relaxed itself whenever it noticed it was
being tested would not be a guard.

Every response carries a `Content-Security-Policy` built per request with a fresh
nonce in `script-src` alongside `'strict-dynamic'`. The policy is assembled in
`src/proxy.ts` rather than in `next.config.ts` because the nonce cannot be known
at build time. `style-src` keeps `'unsafe-inline'`, which the inline `style`
attributes throughout the console require and which is governed separately from
script execution. There is no `upgrade-insecure-requests`, because a deployment
on plain HTTP is a supported configuration and that directive would break it
rather than protect it.

## AI provider

| Setting | Behaviour |
|---|---|
| `HALIMISOC_AI_BASE_URL` and `HALIMISOC_AI_API_KEY` unset | AI disabled; analysis returns the computed summary |
| `HALIMISOC_AI_MODEL` | model name sent to the OpenAI-compatible provider |
| `HALIMISOC_AI_BASE_URL` with `http://` to a non-loopback host | fail closed at startup (the API key would be sniffable) |
| `HALIMISOC_AI_BASE_URL` targeting cloud metadata | fail closed at startup |
| Half-configured provider | fail closed at startup |
| Concurrent provider calls | bounded (default 2); excess degrades to `UNAVAILABLE` instead of queueing |
| `POST /incidents/{id}/analyze` | requires session + `run_ai_analysis` + CSRF; throttled 10 then backoff per user/global with 429 |

Provider credentials stay server-side and are never logged. Detection,
correlation, severity and authorization never depend on the provider.

## Incident webhooks

One `incident.created` POST per new incident. Merges never notify: a merge is
routine correlation output, and notifying per merge would turn one incident
into an alert storm at the receiver.

| Setting | Behaviour |
|---|---|
| `HALIMISOC_WEBHOOK_URL` unset | delivery disabled |
| `HALIMISOC_WEBHOOK_URL` set | `POST` JSON to that URL with a 5s default timeout (`HALIMISOC_WEBHOOK_TIMEOUT`) |
| `HALIMISOC_WEBHOOK_SECRET` set (≥16 chars) | body signed as `X-HalimiSOC-Signature: sha256=<hex HMAC>`; receivers must verify |
| Invalid URL (non-http(s) scheme, embedded credentials, cloud metadata host) | fail closed at startup |

Delivery guarantees, stated plainly:

- The payload carries incident identity and scope only — id, title, severity,
  status, hosts, actors, source addresses, alert count and window. It never
  carries raw evidence: log lines routinely contain usernames and paths that
  have no business leaving the platform on every incident.
- Delivery is asynchronous and bounded (64 queued, one worker, no redirects).
  A full queue drops and counts; a failed delivery counts. Both are visible
  as `webhook_sent_total`, `webhook_error_total` and `webhook_dropped_total`.
- A webhook outage never fails ingestion. Like the AI analyst, notifications
  degrade to metrics rather than errors.

## Production checklist

1. Set `HALIMISOC_ENV=production`.
2. Set `HALIMISOC_SECURE_COOKIES=true` and serve the API over HTTPS only.
3. Set a unique `HALIMISOC_ADMIN_PASSWORD` of 12–128 characters, then
   remove it from the environment once the account exists.
4. Generate `HALIMISOC_MFA_KEY` (`openssl rand -base64 32`) so TOTP secrets are
   AES-256-GCM sealed; without it secrets store as `plain:`.
5. Enroll MFA on every operator (`Settings` -> setup -> verify) and store the
   10 backup codes offline. Use admin `mfa/reset` for lost authenticators.
   Consider registering a passkey per operator as the phishing-resistant factor.
6. Set a random `HALIMISOC_AGENT_ENROLL_SECRET` of at least 24 characters.
7. Set `HALIMISOC_SESSION_IDLE` (default 2h, must not exceed `HALIMISOC_SESSION_TTL`).
8. Set `HALIMISOC_METRICS_TOKEN` or restrict `/metrics` to the monitoring network. The endpoint exposes counters even when open, so never publish it.
9. Set `HALIMISOC_WEBHOOK_SECRET` (≥16 chars) when webhooks are enabled and verify `X-HalimiSOC-Signature` on the receiver.
10. Bind `HALIMISOC_LISTEN_ADDR` to loopback and terminate TLS in a reverse proxy.
11. Bind PostgreSQL to loopback and give the application a least-privilege role.
12. Confirm `/api/v1/readiness` reports `ok` and a non-zero `rules_loaded`.
13. If the console is deployed, serve it over HTTPS and leave
    `HALIMISOC_WEB_ALLOW_INSECURE_COOKIES` unset. Set `HALIMISOC_API_URL` to a
    loopback address so the API is never reachable from the browser.

## Reverse proxy

The API does not trust `X-Forwarded-For` or `Forwarded`. Audit records and rate
limiting use the observed peer address. If the deployment is behind a proxy, the
proxy must be the only reachable client, which binding the API to loopback
achieves.

Trusting forwarded headers without a configured trusted-proxy list would let any
client choose the address recorded in the audit log and used as a rate-limit key.

A starting Caddyfile is provided at `deploy/configs/Caddyfile`. It forwards to
the console only; the browser never reaches the API directly, which is what lets
the API stay on loopback while the console remains the user-facing surface.
Replace `halimisoc.example.test` with the deployment hostname and enable HSTS
only after TLS is confirmed working.

## Secret handling

- Secrets are read from the environment and never written to disk by the server.
- Secrets are never logged. Raw telemetry is redacted for common credential
  shapes before it is stored, and a credential value can be registered for exact
  redaction.
- `.env` is git-ignored. Only `.env.example` with placeholder values is tracked.
- Agent tokens are returned exactly once, at enrollment or rotation. The server
  stores only their hash and cannot recover them.
