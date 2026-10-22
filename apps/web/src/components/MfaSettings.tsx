'use client'

import { useState } from 'react'
import QRCode from 'react-qr-code'

// Self-service MFA enrollment.
//
// The secret is shown once with its otpauth:// URL for manual entry into any
// TOTP app. Backup codes are shown once after verification and must be stored
// offline: the server keeps only their hashes.
export function MfaSettings({ initialEnabled }: { initialEnabled: boolean }) {
  const [enabled, setEnabled] = useState<boolean>(initialEnabled)
  const [secret, setSecret] = useState<string | null>(null)
  const [otpauth, setOtpauth] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function call(action: string, payload: Record<string, unknown>) {
    setBusy(true)
    setError(null)
    try {
      const res = await fetch('/api/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-halimisoc-csrf': csrfToken() },
        body: JSON.stringify({ action, id: '', payload }),
      })
      const parsed = (await res.json()) as { error?: { message?: string } } & Record<string, unknown>
      if (!res.ok) {
        setError(parsed?.error?.message ?? 'The request failed.')
        return null
      }
      return parsed
    } finally {
      setBusy(false)
    }
  }

  return (
    <section>
      <h2>Multi-factor authentication</h2>
      <p className="dim">
        TOTP 6-digit, 30-second step. {enabled ? 'Enabled on this account.' : 'Not enabled.'}
      </p>
      {error ? (
        <div className="error-banner" role="alert">
          {error}
        </div>
      ) : null}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
        <input
          type="password"
          aria-label="Password for MFA setup"
          placeholder="Current password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {enabled ? (
          <input
            aria-label="Code for MFA setup"
            placeholder="6-digit code"
            value={code}
            onChange={(e) => setCode(e.target.value.trim())}
          />
        ) : null}
        <button
          disabled={busy || !password || (enabled && !code)}
          onClick={async () => {
            const out = (await call('mfa.setup', { password, code: enabled ? code : undefined })) as {
              secret?: string
              otpauth_url?: string
            } | null
            if (out) {
              setSecret(out.secret ?? null)
              setOtpauth(out.otpauth_url ?? null)
              setBackupCodes(null)
            }
          }}
        >
          Start setup / rotate
        </button>
      </div>

      {secret ? (
        <div className="card" style={{ marginBottom: 12 }}>
          <p>Scan with your authenticator app, then verify with a code. Secret shown once:</p>
          {otpauth ? (
            <div style={{ background: '#fff', padding: 12, display: 'inline-block', borderRadius: 8 }}>
              <QRCode value={otpauth} size={180} />
            </div>
          ) : null}
          <p>
            <code style={{ wordBreak: 'break-all' }}>{secret}</code>
          </p>
          {otpauth ? (
            <p className="dim" style={{ wordBreak: 'break-all' }}>
              {otpauth}
            </p>
          ) : null}
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <input
              aria-label="Verification code"
              placeholder="6-digit code"
              value={code}
              onChange={(e) => setCode(e.target.value.trim())}
            />
            <button
              disabled={busy || !code}
              onClick={async () => {
                const out = (await call('mfa.enable', { code })) as { backup_codes?: string[] } | null
                if (out?.backup_codes) {
                  setBackupCodes(out.backup_codes)
                  setEnabled(true)
                  setSecret(null)
                }
              }}
            >
              Verify and enable
            </button>
          </div>
        </div>
      ) : null}

      {backupCodes ? (
        <div className="card" role="alert" style={{ marginBottom: 12 }}>
          <p>Backup codes — store offline, each works once:</p>
          <ul>
            {backupCodes.map((c) => (
              <li key={c}>
                <code>{c}</code>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="card">
        <p>Disable (needs password + current code):</p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input
            type="password"
            aria-label="Current password"
            placeholder="Current password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <input
            aria-label="Current code"
            placeholder="6-digit code"
            value={code}
            onChange={(e) => setCode(e.target.value.trim())}
          />
          <button
            disabled={busy || !password || !code}
            onClick={async () => {
              const out = await call('mfa.disable', { password, code })
              if (out) {
                setEnabled(false)
                setPassword('')
              }
            }}
          >
            Disable MFA
          </button>
        </div>
      </div>
    </section>
  )
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)halimisoc_csrf=([^;]*)/)
  return match?.[1] ? decodeURIComponent(match[1]) : ''
}
