'use client'

import { useEffect, useState } from 'react'
import { registerCredential, webauthnSupported } from '@/lib/webauthn'

// Passkey management: register platform authenticators, list and delete.
// Registration uses attestation "none" server-side; only ES256 keys accepted.
export function PasskeySettings({
  initialKeys,
  mfaEnabled,
}: {
  initialKeys: Array<{ id: string; name?: string }>
  mfaEnabled: boolean
}) {
  const [keys, setKeys] = useState(initialKeys)
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // Same SSR concern as the login form: decide after mount.
  const [canUsePasskey, setCanUsePasskey] = useState(false)
  useEffect(() => {
    setCanUsePasskey(webauthnSupported())
  }, [])

  async function call(action: string, payload: Record<string, unknown>) {
    const res = await fetch('/api/proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-halimisoc-csrf': csrfToken() },
      body: JSON.stringify({ action, id: '', payload }),
    })
    const parsed = (await res.json()) as { error?: { message?: string } } & Record<string, unknown>
    if (!res.ok) throw new Error(parsed?.error?.message ?? 'The request failed.')
    return parsed as Record<string, unknown>
  }

  // Authenticated deletion dispatches through the closed proxy allowlist with
  // the DB id in the resource slot.
  async function remove(id: string) {
    const res = await fetch('/api/proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-halimisoc-csrf': csrfToken() },
      body: JSON.stringify({ action: 'passkey.delete', id, payload: {} }),
    })
    if (!res.ok) {
      const parsed = (await res.json()) as { error?: { message?: string } }
      throw new Error(parsed?.error?.message ?? 'Delete failed.')
    }
  }

  return (
    <section>
      <h2>Passkeys</h2>
      <p className="dim">Phishing-resistant sign-in for this account. User verification is required.</p>
      {error ? (
        <div className="error-banner" role="alert">
          {error}
        </div>
      ) : null}

      {keys.length === 0 ? <p className="dim">No passkeys registered.</p> : null}
      <ul>
        {keys.map((k) => (
          <li key={k.id} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span>{k.name || 'Passkey'}</span>
            <button
              disabled={busy}
              onClick={async () => {
                setBusy(true)
                setError(null)
                try {
                  await remove(k.id)
                  setKeys((prev) => prev.filter((x) => x.id !== k.id))
                } catch (e) {
                  setError(e instanceof Error ? e.message : 'Delete failed.')
                } finally {
                  setBusy(false)
                }
              }}
            >
              Delete
            </button>
          </li>
        ))}
      </ul>

      {canUsePasskey ? (
        <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
          <input
            aria-label="Passkey name"
            placeholder="e.g. laptop"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <input
            type="password"
            aria-label="Password for passkey registration"
            placeholder="Current password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {mfaEnabled ? (
            <input
              aria-label="Code for passkey registration"
              placeholder="6-digit code"
              value={code}
              onChange={(e) => setCode(e.target.value.trim())}
            />
          ) : null}
          <button
            disabled={busy || !password || (mfaEnabled && !code)}
            onClick={async () => {
              setBusy(true)
              setError(null)
              try {
                const begin = (await call('passkey.register.begin', {
                  password,
                  code: mfaEnabled ? code : undefined,
                })) as {
                  challenge: string
                  rp: { id: string; name: string }
                  user: { id: string; name: string; displayName: string }
                  excludeCredentials: Array<{ type: string; id: string }>
                }
                const cred = await registerCredential(begin)
                const done = (await call('passkey.register.complete', {
                  challenge: begin.challenge,
                  id: cred.id,
                  name,
                  transports: cred.transports,
                  response: {
                    clientDataJSON: cred.clientDataJSON,
                    attestationObject: cred.attestationObject,
                  },
                })) as { credential_id?: string }
                if (done?.credential_id) {
                  setKeys((prev) => [...prev, { id: done.credential_id as string, name }])
                  setName('')
                }
              } catch (e) {
                setError(e instanceof Error ? e.message : 'Registration failed.')
              } finally {
                setBusy(false)
              }
            }}
          >
            Register this device
          </button>
        </div>
      ) : (
        <p className="dim">This browser does not support WebAuthn.</p>
      )}
    </section>
  )
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)halimisoc_csrf=([^;]*)/)
  return match?.[1] ? decodeURIComponent(match[1]) : ''
}
