import 'server-only'

import { config } from './config'
import type { WebSession } from './session'
import type {
  Agent,
  Alert,
  AlertPage,
  Analysis,
  AuditEntry,
  Event,
  EventPage,
  Incident,
  IncidentPage,
  RuleView,
  SessionInfo,
  Severity,
  Summary,
} from './types'

// The server-side client for the HalimiSOC API.
//
// Every dashboard page and route handler uses this. It is the only place that
// knows the API's address, and it is never imported by a client component: the
// `server-only` import above makes a mistake that would leak the API address to
// the browser a build error rather than a subtle configuration disclosure.

/** An error carrying the API's stable error code. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }

  /** True when the session is gone and the UI should send the operator to login. */
  get isAuthFailure(): boolean {
    return this.status === 401
  }
}

interface RequestOptions {
  /** The caller's session, when the request needs authentication. */
  session?: WebSession | null
  method?: string
  body?: unknown
  /** A signal so a route handler can cancel a request when the client leaves. */
  signal?: AbortSignal
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { session, method = 'GET', body, signal } = options

  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  if (session) {
    // The API session is presented as the API's own cookie. This server holds it
    // so the browser does not have to, and so the API never has to be reachable
    // from the browser. Both values were validated on decode (see session.ts),
    // but re-check the alphabet here so a caller that constructs a WebSession
    // by hand cannot turn it into header injection.
    if (!/^sess_[A-Za-z0-9_-]{1,200}$/.test(session.apiSession)) {
      throw new ApiError(401, 'UNAUTHORIZED', 'Not signed in.')
    }
    if (!/^[A-Za-z0-9_-]{1,256}$/.test(session.apiCsrf)) {
      throw new ApiError(401, 'UNAUTHORIZED', 'Not signed in.')
    }
    headers['Cookie'] = `${config.apiCookieName}=${session.apiSession}`
    if (method !== 'GET' && method !== 'HEAD') {
      headers['X-CSRF-Token'] = session.apiCsrf
    }
  }

  // A timeout bounds a hung API. Without it a stalled upstream would hold the
  // request open until the platform's own timeout, and the operator would see a
  // spinner instead of an error.
  const timeout = AbortSignal.timeout(config.requestTimeoutMs)
  const combined = signal ? AbortSignal.any([signal, timeout]) : timeout

  let response: Response
  try {
    response = await fetch(`${config.apiUrl}/api/v1${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: combined,
      // The dashboard is a live view. Next's fetch cache would serve a stale
      // incident list to an operator who is looking at an active incident.
      cache: 'no-store',
    })
  } catch (cause) {
    throw new ApiError(503, 'API_UNREACHABLE', 'The HalimiSOC API is not reachable.')
  }

  if (response.status === 204) return undefined as T

  const text = await response.text()
  let parsed: unknown = undefined
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      // A non-JSON body from the API is a contract violation. It is reported as
      // an upstream error rather than surfaced raw, because the body could be an
      // HTML error page containing infrastructure detail.
      if (response.ok) {
        throw new ApiError(response.status, 'INVALID_RESPONSE', 'The API returned a malformed response.')
      }
    }
  }

  if (!response.ok) {
    const envelope = parsed as { error?: { code?: string; message?: string } } | undefined
    throw new ApiError(
      response.status,
      envelope?.error?.code ?? 'UNKNOWN',
      envelope?.error?.message ?? 'The request failed.',
    )
  }

  return parsed as T
}

// --- Authentication -------------------------------------------------------

/** Exchanges credentials for an API session. */
export async function login(
  username: string,
  password: string,
  totpCode?: string,
  backupCode?: string,
): Promise<SessionInfo & { apiCookie: string }> {
  const response = await fetch(`${config.apiUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      username,
      password,
      ...(totpCode ? { totp_code: totpCode } : {}),
      ...(backupCode ? { backup_code: backupCode } : {}),
    }),
    cache: 'no-store',
  })

  const text = await response.text()
  let parsed: unknown
  try {
    parsed = text ? JSON.parse(text) : undefined
  } catch {
    parsed = undefined
  }

  if (!response.ok) {
    const envelope = parsed as { error?: { code?: string; message?: string } } | undefined
    throw new ApiError(
      response.status,
      envelope?.error?.code ?? 'LOGIN_FAILED',
      envelope?.error?.message ?? 'Login failed.',
    )
  }

  // Extract the session value from Set-Cookie without a cookie library: the API
  // sets exactly one session cookie and its value is all this app needs.
  const setCookie = response.headers.get('set-cookie') ?? ''
  const apiCookie = extractSessionCookie(setCookie)
  if (!apiCookie) {
    throw new ApiError(500, 'NO_SESSION_COOKIE', 'The API did not return a session.')
  }

  const info = parsed as SessionInfo
  return { ...info, apiCookie }
}

/** Extracts the API session value from a Set-Cookie header. */
export function extractSessionCookie(setCookie: string): string | null {
  // matchAll so a future second cookie cannot make the parser pick the wrong one.
  const matches = [...setCookie.matchAll(/(?:^|,\s*)([^=;,\s]+)=([^;,\s]*)/g)]
  for (const match of matches) {
    const name = match[1]
    const value = match[2]
    if (!name || value === undefined) continue
    if (name === '__Host-halimisoc_session' || name === 'halimisoc_session') {
      if (value === '') return null
      return value
    }
  }
  return null
}

/** Revokes the API session the dashboard holds. */
export async function logout(session: WebSession): Promise<void> {
  await request('/auth/logout', { session, method: 'POST' })
}

// --- Reads ----------------------------------------------------------------

export function getSummary(session: WebSession, signal?: AbortSignal) {
  return request<Summary>('/summary', { session, signal })
}

export function listEvents(
  session: WebSession,
  params: {
    host?: string
    actor?: string
    sourceIp?: string
    type?: string
    severity?: string
    since?: string
    limit?: number
    cursor?: string
  } = {},
  signal?: AbortSignal,
) {
  return request<EventPage>(`/events${query(params)}`, { session, signal })
}

export function getEvent(session: WebSession, id: string, signal?: AbortSignal) {
  return request<Event>(`/events/${encodeURIComponent(id)}`, { session, signal })
}

export function listAlerts(
  session: WebSession,
  params: { status?: string; severity?: string; host?: string; ruleId?: string; limit?: number; cursor?: string } = {},
  signal?: AbortSignal,
) {
  return request<AlertPage>(`/alerts${query(params)}`, { session, signal })
}

export function getAlert(session: WebSession, id: string, signal?: AbortSignal) {
  return request<Alert>(`/alerts/${encodeURIComponent(id)}`, { session, signal })
}

export function listIncidents(
  session: WebSession,
  params: { limit?: number; cursor?: string } = {},
  signal?: AbortSignal,
) {
  return request<IncidentPage>(`/incidents${query(params)}`, { session, signal })
}

export function getIncident(session: WebSession, id: string, signal?: AbortSignal) {
  return request<Incident>(`/incidents/${encodeURIComponent(id)}`, { session, signal })
}

export function listAgents(session: WebSession, signal?: AbortSignal) {
  return request<{ agents: Agent[] }>('/agents', { session, signal })
}

export function listRules(session: WebSession, signal?: AbortSignal) {
  return request<{ rules: RuleView[] }>('/rules', { session, signal })
}

export function listAudit(
  session: WebSession,
  params: { limit?: number; cursor?: string } = {},
  signal?: AbortSignal,
) {
  return request<{ entries: AuditEntry[]; next_cursor?: string }>(`/audit${query(params)}`, { session, signal })
}

export function listAssets(session: WebSession, signal?: AbortSignal) {
  return request<{
    assets: Array<{
      host: string
      agent_id?: string
      status: string
      os?: string
      agent_version?: string
      last_heartbeat?: string
      event_count: number
    }>
  }>('/assets', { session, signal })
}

// --- Mutations ------------------------------------------------------------

export function updateAlertStatus(session: WebSession, id: string, status: string) {
  return request<Alert>(`/alerts/${encodeURIComponent(id)}/status`, { session, method: 'PATCH', body: { status } })
}

export function updateIncidentStatus(session: WebSession, id: string, status: string) {
  return request<Incident>(`/incidents/${encodeURIComponent(id)}/status`, {
    session,
    method: 'PATCH',
    body: { status },
  })
}

export function analyzeIncident(session: WebSession, id: string) {
  return request<Analysis>(`/incidents/${encodeURIComponent(id)}/analyze`, { session, method: 'POST' })
}

export function rotateAgentToken(session: WebSession, id: string) {
  return request<{ agent_id: string; agent_token: string; token_id: string }>(
    `/agents/${encodeURIComponent(id)}/rotate`,
    { session, method: 'POST' },
  )
}

export function revokeAgent(session: WebSession, id: string) {
  return request<{ status: string }>(`/agents/${encodeURIComponent(id)}/revoke`, { session, method: 'POST' })
}

export interface RuleDoc {
  id: string
  version: number
  name: string
  severity: Severity
}

/** Dry-runs one YAML document: no state changes, so the server needs no CSRF. */
export function validateRuleDoc(session: WebSession, yaml: string) {
  return request<{ valid: boolean; rule: RuleDoc }>('/rules/validate', { session, method: 'POST', body: { yaml } })
}

export function getRuleBody(session: WebSession, id: string) {
  return request<{ id: string; yaml: string }>(`/rules/${encodeURIComponent(id)}`, { session })
}

export function saveRule(session: WebSession, id: string, yaml: string) {
  return request<{ rule: RuleDoc; status: string }>(`/rules/${encodeURIComponent(id)}`, {
    session,
    method: 'PUT',
    body: { yaml },
  })
}

export function deleteRule(session: WebSession, id: string) {
  return request<{ status: string }>(`/rules/${encodeURIComponent(id)}`, { session, method: 'DELETE' })
}

export function reloadRules(session: WebSession) {
  return request<{ rules: number; status: string }>('/rules/reload', { session, method: 'POST' })
}

export function mfaStatus(session: WebSession, signal?: AbortSignal) {
  return request<{ enabled: boolean; enrolled_at?: string }>('/auth/mfa/status', { session, signal })
}

export function mfaSetup(session: WebSession, password: string, code?: string) {
  return request<{ secret: string; otpauth_url: string }>('/auth/mfa/setup', {
    session,
    method: 'POST',
    body: { password, code },
  })
}

export function mfaEnable(session: WebSession, code: string) {
  return request<{ backup_codes: string[] }>('/auth/mfa/enable', { session, method: 'POST', body: { code } })
}

export function mfaDisable(session: WebSession, password: string, code: string) {
  return request<{ status: string }>('/auth/mfa/disable', {
    session,
    method: 'POST',
    body: { password, code },
  })
}

export interface PasskeySummary {
  id: string
  name?: string
  created_at: string
  last_used_at?: string
  sign_count: number
  transports?: string[]
}

export function listPasskeys(session: WebSession, signal?: AbortSignal) {
  return request<{ passkeys: PasskeySummary[] }>('/auth/webauthn/credentials', { session, signal })
}

export function passkeyRegisterBegin(session: WebSession, password: string, code?: string) {
  return request<{
    challenge: string
    rp: { id: string; name: string }
    user: { id: string; name: string; displayName: string }
    excludeCredentials: Array<{ type: string; id: string }>
  }>('/auth/webauthn/register/begin', { session, method: 'POST', body: { password, code } })
}

export function passkeyRegisterComplete(
  session: WebSession,
  payload: { challenge: string; id: string; name: string; transports: string[]; clientDataJSON: string; attestationObject: string },
) {
  return request<{ credential_id: string; name: string }>('/auth/webauthn/register/complete', {
    session,
    method: 'POST',
    body: {
      challenge: payload.challenge,
      id: payload.id,
      name: payload.name,
      transports: payload.transports,
      response: {
        clientDataJSON: payload.clientDataJSON,
        attestationObject: payload.attestationObject,
      },
    },
  })
}

export function deletePasskey(session: WebSession, id: string) {
  return request<{ status: string }>(`/auth/webauthn/credentials/${encodeURIComponent(id)}`, {
    session,
    method: 'DELETE',
  })
}

// --- Helpers --------------------------------------------------------------

/** Builds a query string from defined, non-empty parameters. */
function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === '') continue
    // The parameter names are the API's (snake_case); the UI's are camelCase, so
    // the mapping is explicit rather than a silent rename.
    const apiKey = key === 'sourceIp' ? 'source_ip' : key === 'ruleId' ? 'rule_id' : key
    search.set(apiKey, String(value))
  }
  const encoded = search.toString()
  return encoded ? `?${encoded}` : ''
}
