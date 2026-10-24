# API reference

Base path: `/api/v1`. All requests and responses are JSON.

## Authentication

Two distinct principals, with two distinct mechanisms. Neither can be used in
place of the other.

**Operators** use a session cookie set by `POST /api/v1/auth/login`. The cookie
is `HttpOnly`, `SameSite=Lax`, and `Secure` when `HALIMISOC_SECURE_COOKIES=true`,
in which case it is named `__Host-halimisoc_session`. State-changing requests
must also send the CSRF token returned by login in the `X-CSRF-Token` header.

**Agents** use `Authorization: Bearer <agent-token>`. Agent tokens are obtained
by enrolling with the shared enrollment secret. A bearer token in a header is not
subject to CSRF, and an agent token grants access only to the ingestion and
heartbeat endpoints.

## Error shape

Every error uses one envelope:

```json
{
  "error": {
    "code": "EVENT_MALFORMED",
    "message": "Event payload is invalid."
  }
}
```

Codes: `BAD_REQUEST`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`,
`PAYLOAD_TOO_LARGE`, `RATE_LIMITED`, `INTERNAL_ERROR`, `SERVICE_UNAVAILABLE`.

Stack traces, SQL, filesystem paths and credentials are never returned.

## Endpoints

### Platform

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/v1/health` | none | Liveness. Does not touch the database. |
| GET | `/api/v1/readiness` | none | Readiness. Checks the database and reports loaded rules. |
| GET | `/metrics` | bearer token when `HALIMISOC_METRICS_TOKEN` is set, else none | Prometheus text format. Counters only. Set the token in production or restrict at the proxy. |

`/healthz` and `/readyz` are kept as aliases for orchestrators that are
conventionally configured with those names.

### Authentication

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/auth/login` | none | Returns the user, a CSRF token and the session expiry. Passwords 12–128 chars; overlong is rejected before hashing. Login and enrollment are rate-limited per account/IP with `Retry-After` on 429. Body accepts optional `totp_code` / `backup_code`; missing second factor returns 401 `MFA_REQUIRED`. |
| POST | `/api/v1/auth/logout` | session + CSRF | Revokes the session server-side. |
| GET | `/api/v1/auth/session` | session | Returns the current user and CSRF token. |
| POST | `/api/v1/auth/password` | session + CSRF | Self password change `{"current_password","new_password"}`; revokes all sessions including the caller. |
| GET | `/api/v1/auth/mfa/status` | session | `{"enabled","enrolled_at"}`. |
| POST | `/api/v1/auth/mfa/setup` | session + CSRF + step-up | Body `{"password","code"}`; `code` is required when MFA is already enabled. Generates a sealed TOTP secret, returns `{"secret","otpauth_url"}`. Rotates pending secret. |
| POST | `/api/v1/auth/mfa/enable` | session + CSRF | Body `{"code"}`; enables MFA and returns 10 single-use `backup_codes` (once). |
| POST | `/api/v1/auth/mfa/disable` | session + CSRF | Body `{"password","code"}`; clears secret and backups. |

### Passkeys (WebAuthn)

Phishing-resistant sign-in. Registration is authenticated; login is
passwordless and mints a normal session. Only ES256 keys, `none`/`packed`
self-attestation, user verification required. Challenges are single-use,
5-minute TTL.

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/auth/webauthn/register/begin` | session + CSRF + step-up | Body `{"name","password","code"}`; `code` is required when MFA is enabled. Returns challenge + `rp` + `excludeCredentials`. |
| POST | `/api/v1/auth/webauthn/register/complete` | session + CSRF | Body `{"challenge","id","name","transports","response":{"clientDataJSON","attestationObject"}}`; max 10 keys. |
| GET | `/api/v1/auth/webauthn/credentials` | session | Lists own keys (no public material). |
| DELETE | `/api/v1/auth/webauthn/credentials/{id}` | session + CSRF | Deletes own key; warns when removing the last second factor. |
| POST | `/api/v1/auth/webauthn/login/begin` | none (throttled) | Body `{"username"}`; unknown users get a generic 400. |
| POST | `/api/v1/auth/webauthn/login/complete` | none (throttled) | Verifies assertion + clone detection, mints a session. |

### Agents

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/agents/register` | enrollment secret | Returns the agent token once. Rate-limited per IP/global; brute-force returns 429. |
| GET | `/api/v1/agents/me` | agent | Returns the calling agent's own record. |
| POST | `/api/v1/agents/{id}/heartbeat` | agent | Body optional. The id must match the credential. |
| GET | `/api/v1/agents` | `view_agents` | |
| GET | `/api/v1/agents/{id}` | `view_agents` | |
| POST | `/api/v1/agents/{id}/rotate` | `manage_agents` + CSRF | Invalidates the old token, returns a new one. |
| POST | `/api/v1/agents/{id}/revoke` | `manage_agents` + CSRF | Revokes the agent and all its tokens. |

### Events

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/events` | agent | Body `{"events": [...]}`. Idempotent per event id. |
| GET | `/api/v1/events` | `view_events` | Filters: `host`, `actor`, `source_ip`, `type`, `severity`, `since`, `until`. |
| GET | `/api/v1/events/{id}` | `view_events` | |

The ingestion response reports `received`, `inserted`, `duplicates` and a
`rejected` list. A rejected event never fails the whole batch: one hostile line
must not stop the rest of a log stream from being ingested.

### Alerts

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/v1/alerts` | `view_alerts` | Filters: `status`, `severity`, `host`, `rule_id`. |
| GET | `/api/v1/alerts/{id}` | `view_alerts` | |
| PATCH | `/api/v1/alerts/{id}/status` | `change_alert_status` + CSRF | `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `DISMISSED`. |

### Incidents

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/v1/incidents` | `view_incidents` | |
| GET | `/api/v1/incidents/{id}` | `view_incidents` | Includes stages, alerts and evidence ids. |
| PATCH | `/api/v1/incidents/{id}/status` | `change_incident_status` + CSRF | `NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`. |
| POST | `/api/v1/incidents/{id}/analyze` | `run_ai_analysis` + CSRF | Advisory analysis. Returns the computed summary when no provider is configured. Throttled per user/global (10 then backoff, 429); concurrent provider calls are bounded and degrade to `UNAVAILABLE`. |

### Inventory and overview

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/v1/assets` | `view_assets` | Derived from enrolled agents and their events. |
| GET | `/api/v1/summary` | `view_events` | Counters for the overview screen. |
| GET | `/api/v1/rules` | `view_events` | The loaded rule set and its versions. |
| POST | `/api/v1/rules/reload` | `manage_rules` + CSRF | Transactional reload from disk; an invalid set leaves the previous rules active. |
| GET | `/api/v1/audit` | `view_audit` | Admin only. |

### Users

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/v1/users` | `manage_users` | Every operator account; password hashes are never serialised. |
| POST | `/api/v1/users` | `manage_users` + CSRF | Body `{"username","password","role"}`; password 12–128 characters. |
| PATCH | `/api/v1/users/{id}/status` | `manage_users` + CSRF | Body `{"disabled":true}`; revokes the account's sessions. Self-disable and disabling the last active admin return `409`. |
| PATCH | `/api/v1/users/{id}/password` | `manage_users` + CSRF | Admin reset `{"new_password"}` for another account; revokes the target's sessions. Cannot target self (use `/auth/password`). |
| POST | `/api/v1/users/{id}/mfa/reset` | `manage_users` + CSRF | Clears a lost authenticator (secret + backups); target re-enrolls. |

### Rule authoring

Authoring is validate, then save, then reload — three explicit steps. Saving
writes the file; only a reload activates the set, and a reload validates the
whole set before swapping, so a bad save can never silently stop detection.

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/rules/validate` | `manage_rules` | Body `{"yaml":"..."}`; dry-run, changes nothing. |
| GET | `/api/v1/rules/{id}` | `manage_rules` | Returns the file body for the editor. |
| PUT | `/api/v1/rules/{id}` | `manage_rules` + CSRF | Body `{"yaml":"..."}`; the document must hold exactly the path id. `201` on create, `200` on replace. |
| DELETE | `/api/v1/rules/{id}` | `manage_rules` + CSRF | Deleting the last rule returns `409`. |

## Pagination

List endpoints use cursor pagination. Pass `limit` and, from the previous
response, `next_cursor`. The default page size is 50 and the maximum is 500; a
larger `limit` is clamped rather than rejected.

Cursor pagination is used rather than offsets because offset pagination skips or
repeats rows when new telemetry arrives between two requests, which is the normal
case for an event feed.

A request that supplies a cursor but resolves to no rows returns
`400 BAD_REQUEST` rather than an empty page: the API only issues `next_cursor`
when a further page exists, so the anchor was purged or forged. An empty page
would be indistinguishable from "nothing matches these filters".

## Collection shapes

Every list endpoint answers with its collection as a JSON **array**, including
when the answer is empty:

```json
{"events": [], "next_cursor": "evt_01J…"}
{"alerts": []}
{"agents": []}
```

A Go caller cannot see a violation of this, because `encoding/json` decodes a
`null` into a nil slice and matches keys case-insensitively. Clients in other
languages cannot, so the keys are lowercase snake_case and an empty result is `[]`
rather than `null`. `next_cursor` is omitted once there is no further page.

## Status transitions

Alert and incident lifecycles are enforced server-side and are forward-only.
A terminal state cannot be reopened; new activity produces a new record, which
keeps each timeline immutable. A transition that the state machine rejects
returns `409 CONFLICT`.
