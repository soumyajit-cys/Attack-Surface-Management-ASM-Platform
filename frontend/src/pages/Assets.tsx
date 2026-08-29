import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import { Search, ArrowUp, ArrowDown } from 'lucide-react'

interface Asset {
  id: number
  name: string
  criticality: string
  created_at: string
  updated_at: string
  domains_count: number
  findings_count: number
  open_ports: number
  risk_score: number
}

export function Assets() {
  const navigate = useNavigate()
  const { addToast } = useToast()
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [criticalityFilter, setCriticalityFilter] = useState('')
  const [sortBy, setSortBy] = useState<'name' | 'criticality' | 'findings' | 'risk'>('name')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')

  const fetchAssets = async () => {
    setLoading(true)
    try {
      const data = await api.getAssets({ page: 1, page_size: 100, search: search || undefined, criticality: criticalityFilter || undefined })
      setAssets(data.items)
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to load assets', message: error.message })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchAssets() }, [search, criticalityFilter])

  const handleSort = (field: 'name' | 'criticality' | 'findings' | 'risk') => {
    if (sortBy === field) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(field)
      setSortDir('asc')
    }
  }

  const filteredAssets = assets
    .sort((a, b) => {
      const key: 'name' | 'criticality' | 'findings_count' | 'risk_score' =
        sortBy === 'findings' ? 'findings_count' : sortBy === 'risk' ? 'risk_score' : sortBy
      let aVal: string | number = a[key]
      let bVal: string | number = b[key]
      if (typeof aVal === 'string') aVal = aVal.toLowerCase()
      if (typeof bVal === 'string') bVal = bVal.toLowerCase()
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1
      return 0
    })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Assets</h1>
          <p className="text-gray-600">Manage your asset inventory</p>
        </div>
      </div>

      <div className="card">
        <div className="p-4 border-b border-gray-200 flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search assets..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input pl-10"
            />
          </div>
          <select
            value={criticalityFilter}
            onChange={(e) => setCriticalityFilter(e.target.value)}
            className="input w-40"
          >
            <option value="">All Criticality</option>
            <option value="prod">Production</option>
            <option value="staging">Staging</option>
            <option value="dev">Development</option>
            <option value="test">Test</option>
          </select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  <button onClick={() => handleSort('name')} className="flex items-center gap-1 hover:text-gray-700">
                    Name
                    {sortBy === 'name' && (sortDir === 'asc' ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />)}
                  </button>
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  <button onClick={() => handleSort('criticality')} className="flex items-center gap-1 hover:text-gray-700">
                    Criticality
                    {sortBy === 'criticality' && (sortDir === 'asc' ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />)}
                  </button>
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domains</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Findings</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Open Ports</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  <button onClick={() => handleSort('risk')} className="flex items-center gap-1 hover:text-gray-700">
                    Risk Score
                    {sortBy === 'risk' && (sortDir === 'asc' ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />)}
                  </button>
                </th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredAssets.map((asset) => (
                <tr key={asset.id} className="hover:bg-gray-50">
                  <td className="px-4 py-4">
                    <div className="font-medium text-gray-900">{asset.name}</div>
                    <div className="text-sm text-gray-500">{new Date(asset.created_at).toLocaleDateString()}</div>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`badge ${asset.criticality === 'prod' ? 'badge-critical' : asset.criticality === 'staging' ? 'badge-high' : asset.criticality === 'dev' ? 'badge-info' : 'badge-low'}`}>
                      {asset.criticality.charAt(0).toUpperCase() + asset.criticality.slice(1)}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-gray-900">{asset.domains_count}</td>
                  <td className="px-4 py-4 text-gray-900">{asset.findings_count}</td>
                  <td className="px-4 py-4 text-gray-900">{asset.open_ports}</td>
                  <td className="px-4 py-4">
                    <span className={`font-medium ${asset.risk_score >= 7 ? 'text-danger-600' : asset.risk_score >= 4 ? 'text-warning-600' : 'text-success-600'}`}>
                      {asset.risk_score.toFixed(1)}/10
                    </span>
                  </td>
                  <td className="px-4 py-4 text-right">
                    <button
                      onClick={() => navigate(`/assets/${asset.id}`)}
                      className="btn-secondary text-sm"
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
              {!loading && filteredAssets.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-gray-500">
                    No assets found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}