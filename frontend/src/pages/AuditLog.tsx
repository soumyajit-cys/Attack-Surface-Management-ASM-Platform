import { useCallback, useEffect, useState } from 'react'
import { useToast } from '../components/ui/Toaster'
import { api, getApiErrorMessage } from '../lib/api'
import type { AuditLogEntry } from '../lib/types'
import { History, Loader2, Search } from 'lucide-react'

const PAGE_SIZE = 20

/** datetime-local → ISO (treated as UTC; the labels say so). */
function toUtcIso(value: string): string | undefined {
  if (!value) return undefined
  const date = new Date(`${value}Z`)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}

function formatDetails(details: Record<string, unknown>): string {
  const entries = Object.entries(details)
  if (entries.length === 0) return '—'
  return entries.map(([key, value]) => `${key}=${String(value)}`).join(', ')
}

export function AuditLog() {
  const { addToast } = useToast()
  const [entries, setEntries] = useState<AuditLogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [action, setAction] = useState('')
  const [actor, setActor] = useState('')
  const [actorSince, setActorSince] = useState('')
  const [actorUntil, setActorUntil] = useState('')
  const [ip, setIp] = useState('')

  const fetchEntries = useCallback(
    async (targetPage: number) => {
      const localFilters = {
        page: targetPage,
        page_size: PAGE_SIZE,
        action: action.trim() || undefined,
        actor: actor.trim() || undefined,
        since: toUtcIso(actorSince),
        until: toUtcIso(actorUntil),
        ip: ip.trim() || undefined,
      }
      setLoading(true)
      setError(null)
      try {
        const data = await api.getAuditLogs(localFilters)
        setEntries(data.items)
        setTotal(data.total)
        setPage(targetPage)
      } catch (err) {
        const message = getApiErrorMessage(err)
        setError(message)
        setEntries([])
        setTotal(0)
        addToast({ type: 'error', title: 'Failed to load audit log', message })
      } finally {
        setLoading(false)
      }
    },
    [action, actor, actorSince, actorUntil, ip, addToast],
  )

  useEffect(() => {
    fetchEntries(1)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const handleApply = (e: React.FormEvent) => {
    e.preventDefault()
    fetchEntries(1)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Audit Log</h1>
          <p className="text-gray-600">Sensitive actions recorded for your organization</p>
        </div>
      </div>

      <div className="card">
        <div className="p-6 border-b border-gray-200">
          <form onSubmit={handleApply} className="grid grid-cols-1 gap-3 sm:grid-cols-6">
            <input
              type="text"
              value={action}
              onChange={(e) => setAction(e.target.value)}
              className="input"
              aria-label="Filter by action"
              placeholder="action (e.g. user.login)"
            />
            <input
              type="text"
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              className="input"
              aria-label="Filter by actor"
              placeholder="actor"
            />
            <input
              type="datetime-local"
              value={actorSince}
              onChange={(e) => setActorSince(e.target.value)}
              className="input"
              aria-label="Since (UTC)"
              title="Since (UTC)"
            />
            <input
              type="datetime-local"
              value={actorUntil}
              onChange={(e) => setActorUntil(e.target.value)}
              className="input"
              aria-label="Until (UTC)"
              title="Until (UTC)"
            />
            <input
              type="text"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              className="input"
              aria-label="Filter by IP"
              placeholder="IP"
            />
            <button type="submit" className="btn-primary flex items-center justify-center gap-2">
              <Search className="w-4 h-4" />
              Apply
            </button>
          </form>
        </div>

        {error && (
          <div role="alert" className="mx-6 mt-4 p-4 bg-red-50 border border-red-300 rounded-md text-red-800">
            <p className="font-medium">Failed to load the audit log</p>
            <p className="text-sm">{error}</p>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Time
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actor
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Action
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  IP
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Details
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {loading && (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-gray-500">
                    <Loader2 className="w-6 h-6 animate-spin inline-block text-primary-600" />
                  </td>
                </tr>
              )}
              {!loading && entries.length === 0 && !error && (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-gray-500">
                    No audit log entries{total === 0 && !action && !actor && !ip ? ' yet.' : ' match these filters.'}
                  </td>
                </tr>
              )}
              {entries.map((entry) => (
                <tr key={entry.id} className="hover:bg-gray-50">
                  <td className="px-4 py-4 text-gray-500 whitespace-nowrap">
                    {new Date(entry.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-4 font-medium text-gray-900">{entry.actor ?? '—'}</td>
                  <td className="px-4 py-4">
                    <span className="font-mono text-sm text-gray-900">{entry.action}</span>
                  </td>
                  <td className="px-4 py-4 text-gray-500 font-mono text-sm">{entry.ip_address ?? '—'}</td>
                  <td className="px-4 py-4 text-gray-500 text-sm">{formatDetails(entry.details)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between">
          <p className="text-sm text-gray-500">
            {total} entrie{total === 1 ? 's' : 's'} · Page {page} of {totalPages}
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              className="btn-secondary"
              disabled={loading || page <= 1}
              onClick={() => fetchEntries(page - 1)}
            >
              Previous
            </button>
            <button
              type="button"
              className="btn-secondary"
              disabled={loading || page >= totalPages}
              onClick={() => fetchEntries(page + 1)}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      <p className="text-xs text-gray-400 flex items-center gap-1.5">
        <History className="w-3.5 h-3.5" />
        Audit entries are visible to organization managers only. Rows already contain the recorded
        source IP where one was captured.
      </p>
    </div>
  )
}
