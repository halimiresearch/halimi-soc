import { Shell } from '@/components/Shell'
import { EmptyState, SeverityBadge } from '@/components/Badges'
import { ErrorBanner } from '@/components/ErrorState'
import { EventDetail } from '@/components/EventDetail'
import { listEvents } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import { formatTime } from '@/lib/format'
import { SEVERITIES } from '@/lib/types'

// The event explorer.
//
// This is the raw normalized telemetry view. It is the layer an analyst drops to
// when an alert's summary is not enough, so it exposes the canonical fields rather
// than a paraphrase.
//
// Raw evidence is fetched only for the events actually rendered, and only when the
// row is expanded, so a page of events does not pull a page of log lines.

export const dynamic = 'force-dynamic'

interface SearchParams {
  host?: string
  actor?: string
  source_ip?: string
  type?: string
  severity?: string
  cursor?: string
}

export default async function EventsPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const session = await requireSession()
  const params = await searchParams

  const severity = SEVERITIES.find((s) => s === params.severity)
  const host = sanitize(params.host)
  const actor = sanitize(params.actor)
  const sourceIp = sanitize(params.source_ip)
  const type = sanitize(params.type)
  const cursor = sanitize(params.cursor)

  let events: Awaited<ReturnType<typeof listEvents>>['events'] = []
  let nextCursor: string | undefined
  let error: unknown = null

  try {
    const page = await listEvents(session, { severity, host, actor, sourceIp, type, cursor, limit: 100 })
    events = page.events
    nextCursor = page.next_cursor
  } catch (cause) {
    error = cause
  }

  const filterHref = (overrides: Record<string, string | undefined>) => {
    const query = new URLSearchParams()
    for (const [key, value] of Object.entries({
      severity,
      type,
      host,
      actor,
      source_ip: sourceIp,
      ...overrides,
    })) {
      if (value) query.set(key, value)
    }
    const encoded = query.toString()
    return encoded ? `?${encoded}` : '?'
  }

  return (
    <Shell
      title="Events"
      subtitle="Normalized telemetry with raw evidence retained"
      username={session.username}
      role={session.role}
      active="events"
    >
      {error ? <ErrorBanner error={error} /> : null}

      <form className="card" method="get">
        <div className="card-header">
          <h2 className="card-title">Filters</h2>
          <div className="button-row">
            <button type="submit" className="small primary">
              Apply
            </button>
            <a href="/events" className="dim" style={{ alignSelf: 'center', fontSize: 12 }}>
              Reset
            </a>
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
            <label htmlFor="type">Event type</label>
            <input id="type" name="type" defaultValue={type ?? ''} placeholder="auth.ssh.login_failed" />
          </div>
          <div>
            <label htmlFor="host">Host</label>
            <input id="host" name="host" defaultValue={host ?? ''} placeholder="web-01" />
          </div>
          <div>
            <label htmlFor="actor">Actor</label>
            <input id="actor" name="actor" defaultValue={actor ?? ''} placeholder="root" />
          </div>
          <div>
            <label htmlFor="source_ip">Source IP</label>
            <input id="source_ip" name="source_ip" defaultValue={sourceIp ?? ''} placeholder="203.0.113.7" />
          </div>
        </div>
      </form>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">{events.length} event(s)</h2>
          <span className="dim" style={{ fontSize: 12 }}>
            Newest first. Expand a row for its retained raw line.
          </span>
        </div>

        {events.length === 0 ? (
          <EmptyState
            title="No events match these filters"
            hint="Events appear as agents deliver telemetry. A rejected event is reported to the agent, not stored."
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Time</th>
                  <th>Type</th>
                  <th>Host</th>
                  <th>Actor</th>
                  <th>Source IP</th>
                  <th>Outcome</th>
                  <th>Id</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id}>
                    <td>
                      <SeverityBadge severity={event.severity} />
                    </td>
                    <td className="nowrap muted">{formatTime(event.time)}</td>
                    <td className="mono nowrap">{event.type}</td>
                    <td className="mono">{event.host}</td>
                    <td className="mono">{event.actor || '—'}</td>
                    <td className="mono">{event.network?.src_ip || '—'}</td>
                    <td className="dim">{event.outcome || '—'}</td>
                    <td className="mono dim nowrap" style={{ fontSize: 11 }}>
                      {event.id}
                    </td>
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
              Older events
            </a>
          ) : null}
        </nav>
      ) : null}

      <EventDetail events={events} />
    </Shell>
  )
}

function sanitize(value: string | undefined): string | undefined {
  if (!value) return undefined
  const trimmed = value.trim()
  if (!trimmed || trimmed.length > 128) return undefined
  return trimmed
}
