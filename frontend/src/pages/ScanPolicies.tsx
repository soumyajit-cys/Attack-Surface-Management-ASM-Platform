import React, { useEffect, useState } from 'react'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import { Plus, Loader2, Play, Trash2, Edit } from 'lucide-react'

interface ScanPolicy {
  id: number
  asset_id: number
  name: string
  frequency: string
  cron_expression: string | null
  scope: string
  is_active: boolean
  last_run_at: string | null
  next_run_at: string | null
}

interface AssetOption {
  id: number
  name: string
}

export function ScanPolicies() {
  const { addToast } = useToast()
  const [policies, setPolicies] = useState<ScanPolicy[]>([])
  const [assets, setAssets] = useState<AssetOption[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<ScanPolicy | null>(null)
  const [saving, setSaving] = useState(false)

  const [formName, setFormName] = useState('')
  const [formAssetId, setFormAssetId] = useState(1)
  const [formFrequency, setFormFrequency] = useState('daily')
  const [formCron, setFormCron] = useState('')
  const [formScope, setFormScope] = useState('full')

  const fetchPolicies = async () => {
    setLoading(true)
    try {
      const data = await api.getScanPolicies()
      setPolicies(data)
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to load scan policies', message: error.message })
    } finally {
      setLoading(false)
    }
  }

  const fetchAssets = async () => {
    try {
      const data = await api.getAssets({ page: 1, page_size: 100 })
      setAssets(data.items)
    } catch {
      setAssets([])
    }
  }

  useEffect(() => { fetchPolicies(); fetchAssets() }, [])

  const handleRunNow = async (policyId: number) => {
    try {
      await api.runScanPolicy(policyId)
      addToast({ type: 'success', title: 'Scan triggered', message: 'Scan has been queued' })
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to run scan', message: error.message })
    }
  }

  const handleDelete = async (policyId: number) => {
    if (!confirm('Delete this scan policy?')) return
    try {
      await api.deleteScanPolicy(policyId)
      setPolicies(policies.filter(p => p.id !== policyId))
      addToast({ type: 'success', title: 'Policy deleted' })
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to delete', message: error.message })
    }
  }

  const openCreateModal = () => {
    setEditingPolicy(null)
    setFormName('')
    setFormAssetId(assets[0]?.id ?? 1)
    setFormFrequency('daily')
    setFormCron('')
    setFormScope('full')
    setShowModal(true)
  }

  const openEditModal = (policy: ScanPolicy) => {
    setEditingPolicy(policy)
    setFormName(policy.name)
    setFormAssetId(policy.asset_id)
    setFormFrequency(policy.frequency)
    setFormCron(policy.cron_expression || '')
    setFormScope(policy.scope)
    setShowModal(true)
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      const base = {
        name: formName,
        asset_id: formAssetId,
        frequency: formFrequency,
        scope: formScope,
        cron_expression: formFrequency === 'custom_cron' ? formCron || null : null,
      }
      if (editingPolicy) {
        await api.updateScanPolicy(editingPolicy.id, {
          name: base.name,
          frequency: base.frequency,
          scope: base.scope,
          cron_expression: base.cron_expression ?? undefined,
        })
      } else {
        await api.createScanPolicy(base)
      }
      setShowModal(false)
      addToast({ type: 'success', title: editingPolicy ? 'Policy updated' : 'Policy created' })
      fetchPolicies()
    } catch (error: any) {
      addToast({ type: 'error', title: 'Failed to save policy', message: error.message })
    } finally {
      setSaving(false)
    }
  }

  const assetName = (assetId: number) => {
    const found = assets.find(a => a.id === assetId)
    return found ? found.name : `Asset #${assetId}`
  }

  if (loading && policies.length === 0) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scan Policies</h1>
          <p className="text-gray-600">Configure scheduled continuous scanning</p>
        </div>
        <button className="btn-primary flex items-center gap-2" onClick={openCreateModal}>
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
                  <td className="px-4 py-4 text-gray-500">{assetName(policy.asset_id)}</td>
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
                      <button className="p-2 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700" title="Run Now" onClick={() => handleRunNow(policy.id)}>
                        <Play className="w-4 h-4" />
                      </button>
                      <button className="p-2 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700" title="Edit" onClick={() => openEditModal(policy)}>
                        <Edit className="w-4 h-4" />
                      </button>
                      <button className="p-2 rounded-lg hover:bg-danger-100 text-danger-500 hover:text-danger-700" title="Delete" onClick={() => handleDelete(policy.id)}>
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {policies.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-gray-500">
                    No scan policies yet. Click "Create Policy" to get started.
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
            <h2 className="text-xl font-bold mb-4">{editingPolicy ? 'Edit Policy' : 'Create Scan Policy'}</h2>
            <form onSubmit={handleSave} className="space-y-4">
              <div>
                <label className="label">Policy Name</label>
                <input type="text" className="input" placeholder="Daily Production Scan" value={formName} onChange={(e) => setFormName(e.target.value)} required />
              </div>
              <div>
                <label className="label">Asset</label>
                <select className="input" value={formAssetId} onChange={(e) => setFormAssetId(Number(e.target.value))} required>
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>{a.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label">Frequency</label>
                <select className="input" value={formFrequency} onChange={(e) => setFormFrequency(e.target.value)}>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                  <option value="custom_cron">Custom Cron</option>
                </select>
              </div>
              {formFrequency === 'custom_cron' && (
                <div>
                  <label className="label">Cron Expression</label>
                  <input type="text" className="input font-mono" placeholder="0 2 * * 1" value={formCron} onChange={(e) => setFormCron(e.target.value)} required />
                </div>
              )}
              <div>
                <label className="label">Scope</label>
                <select className="input" value={formScope} onChange={(e) => setFormScope(e.target.value)}>
                  <option value="full">Full (Passive + Active)</option>
                  <option value="passive">Passive Only</option>
                  <option value="active">Active Only</option>
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button type="button" onClick={() => setShowModal(false)} className="btn-secondary">Cancel</button>
                <button type="submit" className="btn-primary" disabled={saving}>
                  {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Save'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}