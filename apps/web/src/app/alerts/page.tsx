import Link from 'next/link'
import { Shell } from '@/components/Shell'
import { EmptyState, SeverityBadge, StatusBadge } from '@/components/Badges'
import { ErrorBanner } from '@/components/ErrorState'
import { AlertActions } from '@/components/AlertActions'
import { listAlerts } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import { formatTime } from '@/lib/format'
import { SEVERITIES } from '@/lib/types'
import type { AlertStatus } from '@/lib/types'

// The alert list.
//
// Filters live in the URL so a filtered view can be bookmarked, shared with a
// colleague and reached from the overview's severity counters.
//
// The severity filter is validated against the known set before it reaches the
// API. The API validates it too, but rejecting it here means an invalid link
// renders an explanation rather than a 400 from upstream.

export const dynamic = 'force-dynamic'

const STATUSES: AlertStatus[] = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'DISMISSED']

interface SearchParams {
  severity?: string
  status?: string
  host?: string
  rule_id?: string
  cursor?: string
}

export default async function AlertsPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const session = await requireSession()
  const params = await searchParams

  const severity = SEVERITIES.find((s) => s === params.severity)
  const status = STATUSES.find((s) => s === params.status)
  const host = sanitizeFilter(params.host)
  const ruleId = sanitizeFilter(params.rule_id)
  const cursor = sanitizeFilter(params.cursor)

  let alerts: Awaited<ReturnType<typeof listAlerts>>['alerts'] = []
  let nextCursor: string | undefined
  let error: unknown = null

  try {
    const page = await listAlerts(session, { severity, status, host, ruleId, cursor, limit: 100 })
    alerts = page.alerts
    nextCursor = page.next_cursor
  } catch (cause) {
    error = cause
  }

  // Cursor navigation keeps the filters in the URL, so a page can be linked
  // and reloaded without re-applying them.
  const filterHref = (overrides: Record<string, string | undefined>) => {
    const query = new URLSearchParams()
    for (const [key, value] of Object.entries({
      severity,
      status,
      host,
      rule_id: ruleId,
      ...overrides,
    })) {
      if (value) query.set(key, value)
    }
    const encoded = query.toString()
    return encoded ? `?${encoded}` : '?'
  }

  const canMutate = session.role === 'ADMIN' || session.role === 'ANALYST'

  return (
    <Shell
      title="Alerts"
      subtitle="Deterministic detections, newest first"
      username={session.username}
      role={session.role}
      active="alerts"
      counts={{ alerts: alerts.length }}
    >
      {error ? <ErrorBanner error={error} /> : null}

      <form className="card" method="get">
        <div className="card-header">
          <h2 className="card-title">Filters</h2>
          <div className="button-row">
            <button type="submit" className="small primary">
              Apply
            </button>
            <Link href="/alerts" className="dim" style={{ alignSelf: 'center', fontSize: 12 }}>
              Reset
            </Link>
          </div>
        </div>
        <div style={{ padding: 16 }} className="filters">
          <div>
            <label htmlFor="severity">Severity</label>
            <select id="severity" name="severity" defaultValue={severity ?? ''}>
              <option value="">Any</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="status">Status</label>
            <select id="status" name="status" defaultValue={status ?? ''}>
              <option value="">Any</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="host">Host</label>
            <input id="host" name="host" defaultValue={host ?? ''} placeholder="web-01" />
          </div>
          <div>
            <label htmlFor="rule_id">Rule id</label>
            <input id="rule_id" name="rule_id" defaultValue={ruleId ?? ''} placeholder="ssh-bruteforce" />
          </div>
        </div>
      </form>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            {alerts.length} alert{alerts.length === 1 ? '' : 's'}
          </h2>
          {!canMutate ? (
            <span className="dim" style={{ fontSize: 12 }}>
              Your role can view alerts but not change their status.
            </span>
          ) : null}
        </div>

        {alerts.length === 0 ? (
          <EmptyState
            title="No alerts match these filters"
            hint="Detection is deterministic: an alert appears only when a rule's threshold is crossed inside its window."
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Alert</th>
                  <th>Status</th>
                  <th>Rule</th>
                  <th>Entity</th>
                  <th>Evidence</th>
                  <th>Window</th>
                  <th>Raised</th>
                  {canMutate ? <th>Action</th> : null}
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td>
                      <div>{alert.title}</div>
                      <div className="mono dim">{alert.id}</div>
                      <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                        {alert.reason}
                      </div>
                    </td>
                    <td>
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="mono nowrap">
                      {alert.rule_id}
                      <span className="dim">@{alert.rule_version}</span>
                    </td>
                    <td className="mono">
                      {alert.host ? <div>host {alert.host}</div> : null}
                      {alert.actor ? <div>user {alert.actor}</div> : null}
                      {alert.src_ip ? <div>ip {alert.src_ip}</div> : null}
                      {!alert.host && !alert.actor && !alert.src_ip ? '—' : null}
                    </td>
                    <td className="nowrap">
                      <span title={alert.event_ids.join('\n')}>{alert.event_ids.length} event(s)</span>
                    </td>
                    <td className="dim nowrap" style={{ fontSize: 12 }}>
                      {alert.count} in {alert.window_start === alert.window_end ? 'window' : ''}
                      <div>{formatTime(alert.window_end)}</div>
                    </td>
                    <td className="nowrap muted">{formatTime(alert.created_at)}</td>
                    {canMutate ? (
                      <td>
                        <AlertActions id={alert.id} status={alert.status} />
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {cursor || nextCursor ? (
        <nav className="button-row" aria-label="Pagination" style={{ marginTop: 12 }}>
          {cursor ? (
            <a href={filterHref({})} className="small">
              Newest
            </a>
          ) : null}
          {nextCursor ? (
            <a href={filterHref({ cursor: nextCursor })} className="small">
              Older alerts
            </a>
          ) : null}
        </nav>
      ) : null}
    </Shell>
  )
}

/** Trims a filter value and drops an implausibly long one. */
function sanitizeFilter(value: string | undefined): string | undefined {
  if (!value) return undefined
  const trimmed = value.trim()
  if (!trimmed || trimmed.length > 128) return undefined
  return trimmed
}
