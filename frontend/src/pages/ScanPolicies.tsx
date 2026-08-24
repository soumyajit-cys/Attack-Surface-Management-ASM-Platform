import React, { useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import { Plus, Loader2, Play, RefreshCw, Clock, Calendar, Trash2, Edit, Eye } from 'lucide-react'

interface ScanPolicy {
  id: number
  name: string
  asset_id: number
  frequency: string
  cron_expression: string | null
  scope: string
  is_active: boolean
  last_run_at: string | null
  next_run_at: string | null
}

export function ScanPolicies() {
  const { addToast } = useToast()
  const [policies, setPolicies] = useState<ScanPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<ScanPolicy | null>(null)

  const fetchPolicies = async () => {
    // Mock data
    setPolicies([
      { id: 1, name: 'Daily Production Scan', asset_id: 1, frequency: 'daily', cron_expression: null, scope: 'full', is_active: true, last_run_at: '2024-01-20T06:00:00Z', next_run_at: '2024-01-21T06:00:00Z' },
      { id: 2, name: 'Weekly Staging Scan', asset_id: 2, frequency: 'weekly', cron_expression: '0 2 * * 1', scope: 'passive', is_active: true, last_run_at: '2024-01-15T02:00:00Z', next_run_at: '2024-01-22T02:00:00Z' },
    ])
    setLoading(false)
  }

  useEffect(() => { fetchPolicies() }, [])

  const handleRunNow = async (policyId: number) => {
    try {
      await api.runScanPolicy(policyId)
      addToast({ type: 'success', title: 'Scan triggered', message: 'Scan has been queued' })
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to run scan', message: error.response?.data?.detail })
    }
  }

  const handleDelete = async (policyId: number) => {
    if (!confirm('Delete this scan policy?')) return
    try {
      setPolicies(policies.filter(p => p.id !== policyId))
      addToast({ type: 'success', title: 'Policy deleted' })
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to delete', message: error.response?.data?.detail })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scan Policies</h1>
          <p className="text-gray-600">Configure scheduled continuous scanning</p>
        </div>
        <button className="btn-primary flex items-center gap-2" onClick={() => { setEditingPolicy(null); setShowModal(true); }}>
          <Plus className="w-4 h-4" />
          Create Policy
        </button>
      </div>

      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Asset</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Frequency</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scope</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Run</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Next Run</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {policies.map((policy) => (
                <tr key={policy.id} className="hover:bg-gray-50">
                  <td className="px-4 py-4 font-medium text-gray-900">{policy.name}</td>
                  <td className="px-4 py-4 text-gray-500">Asset #{policy.asset_id}</td>
                  <td className="px-4 py-4">
                    <span className="badge badge-info">{policy.frequency}</span>
                    {policy.cron_expression && <span className="ml-2 text-xs text-gray-500 font-mono">{policy.cron_expression}</span>}
                  </td>
                  <td className="px-4 py-4">
                    <span className={`badge ${policy.scope === 'full' ? 'badge-critical' : policy.scope === 'active' ? 'badge-high' : 'badge-info'}`}>
                      {policy.scope}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`flex items-center gap-1 badge ${policy.is_active ? 'badge-success' : 'badge-low'}`}>
                      {policy.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-gray-500">
                    {policy.last_run_at ? new Date(policy.last_run_at).toLocaleString() : 'Never'}
                  </td>
                  <td className="px-4 py-4 text-gray-500">
                    {policy.next_run_at ? new Date(policy.next_run_at).toLocaleString() : 'Not scheduled'}
                  </td>
                  <td className="px-4 py-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button className="p-2 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700" title="Run Now" onClick={() => { /* handleRunNow(policy.id) */ }}>
                        <Play className="w-4 h-4" />
                      </button>
                      <button className="p-2 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700" title="Edit" onClick={() => { setEditingPolicy(policy); setShowModal(true); }}>
                        <Edit className="w-4 h-4" />
                      </button>
                      <button className="p-2 rounded-lg hover:bg-danger-100 text-danger-500 hover:text-danger-700" title="Delete" onClick={() => handleDelete(policy.id)}>
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white rounded-xl max-w-md w-full mx-4 p-6">
            <h2 className="text-xl font-bold mb-4">{editingPolicy ? 'Edit Policy' : 'Create Scan Policy'}</h2>
            <form onSubmit={(e) => { e.preventDefault(); setShowModal(false); }} className="space-y-4">
              <div>
                <label className="label">Policy Name</label>
                <input type="text" className="input" placeholder="Daily Production Scan" defaultValue={editingPolicy?.name || ''} required />
              </div>
              <div>
                <label className="label">Asset ID</label>
                <input type="number" className="input" placeholder="1" defaultValue={editingPolicy?.asset_id || ''} required />
              </div>
              <div>
                <label className="label">Frequency</label>
                <select className="input" defaultValue={editingPolicy?.frequency || 'daily'}>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                  <option value="custom_cron">Custom Cron</option>
                </select>
              </div>
              <div>
                <label className="label">Scope</label>
                <select className="input" defaultValue={editingPolicy?.scope || 'full'}>
                  <option value="full">Full (Passive + Active)</option>
                  <option value="passive">Passive Only</option>
                  <option value="active">Active Only</option>
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