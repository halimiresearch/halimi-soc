import { NextResponse } from 'next/server'
import {
  analyzeIncident,
  ApiError,
  deletePasskey,
  deleteRule,
  getRuleBody,
  mfaDisable,
  mfaEnable,
  mfaSetup,
  passkeyRegisterBegin,
  passkeyRegisterComplete,
  reloadRules,
  revokeAgent,
  rotateAgentToken,
  saveRule,
  updateAlertStatus,
  updateIncidentStatus,
  validateRuleDoc,
} from '@/lib/api'
import { verifyCsrf } from '@/lib/csrf'
import { readSession } from '@/lib/session'
import type { WebSession } from '@/lib/session'

// The BFF proxy for UI mutations.
//
// Reads go through server components, which never expose the API session. This
// route exists for the mutations a client component drives with a `fetch`: alert
// and incident status changes, agent rotation and revocation, and analysis.
//
// Design notes:
//
//  * The dispatch table below is a closed allowlist. A generic "forward any path"
//    proxy would let a page reach any endpoint the API exposes, including ones the
//    UI has no reason to touch, and would make the UI's effective permission
//    surface invisible.
//  * It calls the typed client rather than re-implementing the request. One place
//    knows how to present the API session and its CSRF token, so the two cannot
//    drift.
//  * The CSRF token is required, because this route is authenticated by a cookie.
//  * The upstream status and stable code are preserved so the UI can react to a
//    conflict or a permission failure accurately.

type Dispatch = (session: WebSession, id: string, payload: Record<string, unknown>) => Promise<unknown>

const ACTIONS: Record<string, Dispatch> = {
  'alert.status': (session, id, payload) => {
    const status = readStatus(payload)
    return updateAlertStatus(session, id, status)
  },
  'incident.status': (session, id, payload) => {
    const status = readStatus(payload)
    return updateIncidentStatus(session, id, status)
  },
  'incident.analyze': (session, id) => analyzeIncident(session, id),
  'agent.rotate': (session, id) => rotateAgentToken(session, id),
  'agent.revoke': (session, id) => revokeAgent(session, id),
  'rules.validate': (session, _id, payload) => validateRuleDoc(session, readYaml(payload)),
  'rules.get': (session, id) => getRuleBody(session, id),
  'rules.save': (session, id, payload) => saveRule(session, id, readYaml(payload)),
  'rules.delete': (session, id) => deleteRule(session, id),
  'rules.reload': (session) => reloadRules(session),
  'mfa.setup': (session, _id, payload) => mfaSetup(session, readPassword(payload), readOptionalCode(payload)),
  'mfa.enable': (session, _id, payload) => mfaEnable(session, readCode(payload)),
  'mfa.disable': (session, _id, payload) => {
    const password = typeof payload.password === 'string' ? payload.password : ''
    if (!password) throw new ApiError(400, 'BAD_REQUEST', 'Current password is required.')
    return mfaDisable(session, password, readCode(payload))
  },
  'passkey.register.begin': (session, _id, payload) =>
    passkeyRegisterBegin(session, readPassword(payload), readOptionalCode(payload)),
  'passkey.register.complete': (session, _id, payload) => {
    const challenge = typeof payload.challenge === 'string' ? payload.challenge : ''
    const id = typeof payload.id === 'string' ? payload.id : ''
    const name = typeof payload.name === 'string' ? payload.name : ''
    const transports = Array.isArray(payload.transports)
      ? (payload.transports as unknown[]).filter((t): t is string => typeof t === 'string').slice(0, 8)
      : []
    const response = payload.response as { clientDataJSON?: unknown; attestationObject?: unknown } | undefined
    const clientDataJSON = response && typeof response.clientDataJSON === 'string' ? response.clientDataJSON : ''
    const attestationObject =
      response && typeof response.attestationObject === 'string' ? response.attestationObject : ''
    if (!challenge || !id || !clientDataJSON || !attestationObject) {
      throw new ApiError(400, 'BAD_REQUEST', 'Challenge and attestation are required.')
    }
    if (id.length > 2048 || clientDataJSON.length > 131072 || attestationObject.length > 262144) {
      throw new ApiError(400, 'BAD_REQUEST', 'Attestation too large.')
    }
    return passkeyRegisterComplete(session, {
      challenge,
      id,
      name,
      transports,
      clientDataJSON,
      attestationObject,
    })
  },
  'passkey.delete': (session, id) => deletePasskey(session, id),
}

function readPassword(payload: Record<string, unknown>): string {
  const password = payload.password
  if (typeof password !== 'string' || password.length === 0 || password.length > 1024) {
    throw new ApiError(400, 'BAD_REQUEST', 'Current password is required.')
  }
  return password
}

function readOptionalCode(payload: Record<string, unknown>): string | undefined {
  const code = payload.code
  if (code === undefined || code === null || code === '') return undefined
  if (typeof code !== 'string' || code.length > 64) {
    throw new ApiError(400, 'BAD_REQUEST', 'Invalid verification code.')
  }
  return code.trim()
}

function readCode(payload: Record<string, unknown>): string {
  const code = payload.code
  if (typeof code !== 'string' || code.trim().length === 0 || code.length > 64) {
    throw new ApiError(400, 'BAD_REQUEST', 'A verification code is required.')
  }
  return code.trim()
}

// Actions that carry their input in the payload rather than the URL: a YAML
// document has no place in a resource id, and neither do MFA/passkey
// ceremonies, which address the caller's own account rather than a URL id.
const PAYLOAD_ACTIONS = new Set([
  'rules.validate',
  'rules.reload',
  'mfa.setup',
  'mfa.enable',
  'mfa.disable',
  'passkey.register.begin',
  'passkey.register.complete',
])

function readYaml(payload: Record<string, unknown>): string {
  const yaml = payload.yaml
  if (typeof yaml !== 'string' || yaml.length === 0 || yaml.length > 65536) {
    throw new ApiError(400, 'BAD_REQUEST', 'A YAML document is required.')
  }
  return yaml
}

function readStatus(payload: Record<string, unknown>): string {
  const status = payload.status
  if (typeof status !== 'string' || status.length === 0 || status.length > 32) {
    throw new ApiError(400, 'BAD_REQUEST', 'A status is required.')
  }
  return status.toUpperCase()
}

export async function POST(request: Request) {
  return handle(request)
}

export async function PATCH(request: Request) {
  return handle(request)
}

async function handle(request: Request): Promise<Response> {
  if (!(await verifyCsrf(request))) {
    return NextResponse.json(
      { error: { code: 'FORBIDDEN', message: 'Invalid or missing CSRF token.' } },
      { status: 403 },
    )
  }

  const session = await readSession()
  if (!session) {
    return NextResponse.json({ error: { code: 'UNAUTHORIZED', message: 'Not signed in.' } }, { status: 401 })
  }

  let body: { action?: unknown; id?: unknown; payload?: unknown }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return NextResponse.json({ error: { code: 'BAD_REQUEST', message: 'Invalid request body.' } }, { status: 400 })
  }

  const action = typeof body.action === 'string' ? body.action : ''
  const id = typeof body.id === 'string' ? body.id : ''
  const payload =
    typeof body.payload === 'object' && body.payload !== null ? (body.payload as Record<string, unknown>) : {}

  const dispatch = Object.prototype.hasOwnProperty.call(ACTIONS, action) ? ACTIONS[action] : undefined
  if (!dispatch) {
    return NextResponse.json({ error: { code: 'BAD_REQUEST', message: 'Unknown action.' } }, { status: 400 })
  }
  if (!PAYLOAD_ACTIONS.has(action) && (!id || id.length > 128)) {
    return NextResponse.json({ error: { code: 'BAD_REQUEST', message: 'A resource id is required.' } }, { status: 400 })
  }

  try {
    const result = await dispatch(session, id, payload)
    return NextResponse.json(result ?? { status: 'ok' })
  } catch (error) {
    if (error instanceof ApiError) {
      return NextResponse.json({ error: { code: error.code, message: error.message } }, { status: error.status })
    }
    return NextResponse.json(
      { error: { code: 'INTERNAL_ERROR', message: 'The request failed.' } },
      { status: 500 },
    )
  }
}
