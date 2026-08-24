import React, { useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import { Search, Filter, Loader2, AlertTriangle, ChevronLeft, ChevronRight, AlertCircle, MinusCircle, Info } from 'lucide-react'

interface Finding {
  id: number
  asset_id: number
  title: string
  severity: string
  category: string
  description: string
  recommendation: string
  created_at: string
}

const severityColors: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

const severityIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  critical: AlertTriangle,
  high: AlertTriangle,
  medium: AlertCircle,
  low: MinusCircle,
  info: Info,
}

export function Findings() {
  const { addToast } = useToast()
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)

  const fetchFindings = async () => {
    setLoading(true)
    try {
      // Mock data
      setFindings([
        { id: 1, asset_id: 1, title: 'Open Port 443', severity: 'low', category: 'network_exposure', description: 'Port 443 (https) is open', recommendation: 'Ensure this port is intentionally exposed', created_at: '2024-01-20T10:00:00Z' },
        { id: 2, asset_id: 1, title: 'Missing CSP Header', severity: 'medium', category: 'security_headers', description: 'Content Security Policy not set', recommendation: 'Implement a restrictive Content-Security-Policy header', created_at: '2024-01-20T10:00:00Z' },
        { id: 3, asset_id: 1, title: 'SSL Certificate Expiring Soon', severity: 'high', category: 'tls', description: 'Certificate expires within 30 days', recommendation: 'Renew the SSL certificate before expiration', created_at: '2024-01-20T10:00:00Z' },
        { id: 4, asset_id: 2, title: 'Open Port 22', severity: 'critical', category: 'network_exposure', description: 'Port 22 (ssh) is open', recommendation: 'Restrict SSH access to authorized IPs only', created_at: '2024-01-19T10:00:00Z' },
      ])
      setTotal(4)
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to load findings' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchFindings() }, [page, severityFilter])

  const severityBadges: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
  }

  const filteredFindings = findings.filter(f =>
    f.title.toLowerCase().includes(search.toLowerCase()) &&
    (!severityFilter || f.severity === severityFilter)
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
            onChange={(e) => setSeverityFilter(e.target.value)}
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
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredFindings.map((finding) => (
                <tr key={finding.id} className="hover:bg-gray-50 cursor-pointer" onClick={() => setSelectedFinding(finding)}>
                  <td className="px-4 py-4">
                    <p className="font-medium text-gray-900">{finding.title}</p>
                    <p className="text-sm text-gray-500 truncate max-w-xs">{finding.description}</p>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`badge ${severityColors[finding.severity] || 'badge-info'}`}>
                      {finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-gray-500 capitalize">{finding.category.replace('_', ' ')}</td>
                  <td className="px-4 py-4 text-gray-500">Asset #{finding.asset_id}</td>
                  <td className="px-4 py-4 text-gray-500">{new Date(finding.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-4">
                    <button className="p-2 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700" onClick={(e) => { e.stopPropagation(); setSelectedFinding(finding); }}>
                      View
                    </button>
                  </td>
                </tr>
              ))}
              {filteredFindings.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-gray-500">
                    No findings found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {selectedFinding && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
            <div className="bg-white rounded-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto">
              <div className="p-6 border-b border-gray-200 flex items-center justify-between sticky top-0 bg-white">
                <h2 className="text-xl font-bold">Finding Details</h2>
                <button onClick={() => setSelectedFinding(null)} className="p-2 rounded-lg hover:bg-gray-100">Close</button>
              </div>
              <div className="p-6 space-y-6">
                <div>
                  <div className="flex items-center gap-3 mb-4">
                    <h3 className="text-xl font-bold text-gray-900">{selectedFinding.title}</h3>
                    <span className={`badge ${severityColors[selectedFinding.severity] || 'badge-info'}`}>
                      {selectedFinding.severity.toUpperCase()}
                    </span>
                  </div>
                  <span className="text-sm text-gray-500">{selectedFinding.category.replace('_', ' ')}</span>
                </div>

                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Description</h4>
                  <p className="text-gray-600">{selectedFinding.description || 'No description provided'}</p>
                </div>

                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Recommendation</h4>
                  <p className="text-gray-600 bg-gray-50 p-4 rounded-lg">{selectedFinding.recommendation || 'No recommendation provided'}</p>
                </div>

                <div className="grid grid-cols-2 gap-4 text-sm text-gray-600">
                  <div><span className="text-gray-500">Asset ID:</span> {selectedFinding.asset_id}</div>
                  <div><span className="text-gray-500">Created:</span> {new Date(selectedFinding.created_at).toLocaleString()}</div>
                  <div><span className="text-gray-500">Severity:</span> {selectedFinding.severity}</div>
                  <div><span className="text-gray-500">Category:</span> {selectedFinding.category}</div>
                </div>

                <div className="flex justify-end gap-2 pt-4 border-t border-gray-200">
                  <button onClick={() => setSelectedFinding(null)} className="btn-secondary">Close</button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Pagination */}
        <div className="px-4 py-3 flex items-center justify-between border-t border-gray-200">
          <p className="text-sm text-gray-500">
            Showing {((page - 1) * pageSize) + 1} to {Math.min(page * pageSize, total)} of {total} findings
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
              Page {page} of {Math.ceil(total / pageSize)}
            </span>
            <button
              onClick={() => setPage(page + 1)}
              disabled={page >= Math.ceil(total / pageSize)}
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