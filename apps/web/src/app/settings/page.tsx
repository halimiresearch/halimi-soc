import { MfaSettings } from '@/components/MfaSettings'
import { PasskeySettings } from '@/components/PasskeySettings'
import { Shell } from '@/components/Shell'
import { listPasskeys, mfaStatus } from '@/lib/api'
import { requireSession } from '@/lib/guard'

// Operator security settings (MFA enrollment + passkeys).
export const dynamic = 'force-dynamic'

export default async function SettingsPage() {
  const session = await requireSession()
  let enabled = false
  try {
    const st = await mfaStatus(session)
    enabled = st.enabled
  } catch {
    enabled = false
  }
  let keys: Array<{ id: string; name?: string }> = []
  try {
    const list = await listPasskeys(session)
    keys = list.passkeys.map((k) => ({ id: k.id, name: k.name }))
  } catch {
    keys = []
  }

  return (
    <Shell title="Settings" subtitle="Account security" username={session.username} role={session.role} active="settings">
      <MfaSettings initialEnabled={enabled} />
      <PasskeySettings initialKeys={keys} mfaEnabled={enabled} />
    </Shell>
  )
}
