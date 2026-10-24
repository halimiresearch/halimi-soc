import { MfaSettings } from '@/components/MfaSettings'
import { PasskeySettings } from '@/components/PasskeySettings'
import { Shell } from '@/components/Shell'
import { ErrorBanner } from '@/components/ErrorState'
import { listPasskeys, mfaStatus } from '@/lib/api'
import { requireSession } from '@/lib/guard'

// Operator security settings (MFA enrollment + passkeys).
export const dynamic = 'force-dynamic'

export default async function SettingsPage() {
  const session = await requireSession()

  let enabled = false
  let keys: Array<{ id: string; name?: string }> = []
  let error: unknown = null

  // A failed read must not render as "MFA not enabled": the operator would
  // believe a control is off when the API is simply unreachable.
  try {
    const [status, list] = await Promise.all([mfaStatus(session), listPasskeys(session)])
    enabled = status.enabled
    keys = list.passkeys.map((k) => ({ id: k.id, name: k.name }))
  } catch (cause) {
    error = cause
  }

  return (
    <Shell title="Settings" subtitle="Account security" username={session.username} role={session.role} active="settings">
      {error ? <ErrorBanner error={error} /> : null}
      {error ? null : (
        <>
          <MfaSettings initialEnabled={enabled} />
          <PasskeySettings initialKeys={keys} mfaEnabled={enabled} />
        </>
      )}
    </Shell>
  )
}
