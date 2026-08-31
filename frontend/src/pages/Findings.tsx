import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useToast } from '../components/ui/Toaster'
import { api, getApiErrorMessage } from '../lib/api'
import type { Finding } from '../lib/types'
import { SEVERITY_COLORS } from '../lib/types'
import { Search, Loader2, ChevronLeft, ChevronRight } from 'lucide-react'

const PAGE_SIZE = 20

export function Findings() {
  const navigate = useNavigate()
  const { addToast } = useToast()
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')

  const fetchFindings = async () => {
    setLoading(true)
    try {
      const data = await api.getFindings({ page, page_size: PAGE_SIZE, severity: severityFilter || undefined })
      setFindings(data.items)
      setTotal(data.total)
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to load findings', message: getApiErrorMessage(error) })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchFindings() }, [page, severityFilter])

  const filteredFindings = findings.filter(f =>
    f.title.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Findings</h1>
          <p className="text-gray-600">Security findings across your assets</p>
        </div>
      </div>

      <div className="card">
        <div className="p-4 border-b border-gray-200 flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search findings..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input pl-10"
            />
          </div>
          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setPage(1) }}
            className="input w-40"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Title</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Category</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Asset</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredFindings.map((finding) => (
                <tr
                  key={finding.id}
                  className="hover:bg-gray-50 cursor-pointer"
                  onClick={() => navigate(`/findings/${finding.id}`)}
                  role="link"
                  tabIndex={0}
                  onKeyDown={(e) => { if (e.key === 'Enter') navigate(`/findings/${finding.id}`) }}
                >
                  <td className="px-4 py-4">
                    <p className="font-medium text-gray-900">{finding.title}</p>
                    <p className="text-sm text-gray-500 truncate max-w-xs">{finding.description}</p>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`badge ${SEVERITY_COLORS[finding.severity] || 'badge-info'}`}>
                      {finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-gray-500 capitalize">{finding.category.replace('_', ' ')}</td>
                  <td className="px-4 py-4 text-gray-500">{finding.asset_name || `Asset #${finding.asset_id}`}</td>
                  <td className="px-4 py-4 text-gray-500">{new Date(finding.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
              {loading && (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-gray-500">
                    <Loader2 className="w-6 h-6 animate-spin inline-block text-primary-600" />
                  </td>
                </tr>
              )}
              {!loading && filteredFindings.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-gray-500">
                    No findings found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="px-4 py-3 flex items-center justify-between border-t border-gray-200">
          <p className="text-sm text-gray-500">
            Showing {((page - 1) * PAGE_SIZE) + 1} to {Math.min(page * PAGE_SIZE, total)} of {total} findings
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(page - 1)}
              disabled={page === 1}
              className="p-2 rounded-lg hover:bg-gray-100 disabled:opacity-50"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-3 py-1 text-sm font-medium text-gray-700">
              Page {page} of {Math.ceil(total / PAGE_SIZE)}
            </span>
            <button
              onClick={() => setPage(page + 1)}
              disabled={page >= Math.ceil(total / PAGE_SIZE)}
              className="p-2 rounded-lg hover:bg-gray-100 disabled:opacity-50"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
