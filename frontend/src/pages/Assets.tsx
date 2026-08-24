import React, { useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import { Server, Search, Filter, Plus, Loader2, MoreHorizontal, Trash2, Edit, Eye, ArrowUp, ArrowDown } from 'lucide-react'

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
  const { addToast } = useToast()
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [criticalityFilter, setCriticalityFilter] = useState('')
  const [sortBy, setSortBy] = useState<'name' | 'criticality' | 'findings' | 'risk'>('name')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [showModal, setShowModal] = useState(false)
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null)

  const fetchAssets = async () => {
    setLoading(true)
    try {
      // Mock data for now
      setAssets([
        { id: 1, name: 'example.com', criticality: 'prod', created_at: '2024-01-15', updated_at: '2024-01-20', domains_count: 3, findings_count: 12, open_ports: 8, risk_score: 7.2 },
        { id: 2, name: 'api.example.com', criticality: 'prod', created_at: '2024-02-01', updated_at: '2024-02-15', domains_count: 2, findings_count: 8, open_ports: 5, risk_score: 6.8 },
        { id: 3, name: 'staging.example.com', criticality: 'staging', created_at: '2024-03-10', updated_at: '2024-03-20', domains_count: 1, findings_count: 3, open_ports: 2, risk_score: 3.4 },
        { id: 4, name: 'dev.example.com', criticality: 'dev', created_at: '2024-04-01', updated_at: '2024-04-10', domains_count: 1, findings_count: 1, open_ports: 1, risk_score: 1.2 },
      ])
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to load assets' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchAssets() }, [])

  const handleSort = (field: 'name' | 'criticality' | 'findings' | 'risk') => {
    if (sortBy === field) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(field)
      setSortDir('asc')
    }
  }

  const filteredAssets = assets
    .filter((a) => a.name.toLowerCase().includes(search.toLowerCase()))
    .filter((a) => !criticalityFilter || a.criticality === criticalityFilter)
    .sort((a, b) => {
      let aVal = a[sortBy], bVal = b[sortBy]
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
        <button className="btn-primary flex items-center gap-2" onClick={() => { setEditingAsset(null); setShowModal(true); }}>
          <Plus className="w-4 h-4" />
          Add Asset
        </button>
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
                    <div className="flex items-center justify-end gap-2">
                      <button className="p-2 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700" title="View">
                        <Eye className="w-4 h-4" />
                      </button>
                      <button className="p-2 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700" title="Edit" onClick={() => { setEditingAsset(asset); setShowModal(true); }}>
                        <Edit className="w-4 h-4" />
                      </button>
                      <button className="p-2 rounded-lg hover:bg-danger-100 text-danger-500 hover:text-danger-700" title="Delete">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredAssets.length === 0 && (
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

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white rounded-xl max-w-md w-full mx-4 p-6">
            <h2 className="text-xl font-bold mb-4">{editingAsset ? 'Edit Asset' : 'Add Asset'}</h2>
            <form onSubmit={(e) => { e.preventDefault(); setShowModal(false); }} className="space-y-4">
              <div>
                <label className="label">Asset Name</label>
                <input type="text" className="input" placeholder="example.com" defaultValue={editingAsset?.name || ''} required />
              </div>
              <div>
                <label className="label">Criticality</label>
                <select className="input" defaultValue={editingAsset?.criticality || 'dev'}>
                  <option value="prod">Production</option>
                  <option value="staging">Staging</option>
                  <option value="dev">Development</option>
                  <option value="test">Test</option>
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button type="button" onClick={() => setShowModal(false)} className="btn-secondary">Cancel</button>
                <button type="submit" className="btn-primary">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}