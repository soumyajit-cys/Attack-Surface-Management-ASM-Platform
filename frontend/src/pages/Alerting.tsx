import React, { useEffect, useState } from 'react'
import { useToast } from '../components/ui/Toaster'
import { api, getApiErrorMessage } from '../lib/api'
import type { AlertIntegration, DigestConfig } from '../lib/types'
import { MessageSquare, Plus, Trash2, Check, AlertTriangle, Zap, TestTube2 } from 'lucide-react'

const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export function Alerting() {
  const { addToast } = useToast()
  const [integrations, setIntegrations] = useState<AlertIntegration[]>([])
  const [digestConfig, setDigestConfig] = useState<DigestConfig | null>(null)
  const [digestExists, setDigestExists] = useState(false)
  const [showIntegrationModal, setShowIntegrationModal] = useState(false)
  const [showDigestModal, setShowDigestModal] = useState(false)
  const [loading, setLoading] = useState(true)
  const [formData, setFormData] = useState({
    name: '',
    channel: 'slack',
    webhook_url: '',
    secret: '',
    min_severity: 'high',
  })

  const fetchData = async () => {
    setLoading(true)
    try {
      const [integrationsData, digest] = await Promise.allSettled([
        api.listAlertIntegrations(),
        api.getDigestConfig(),
      ])
      if (integrationsData.status === 'fulfilled') setIntegrations(integrationsData.value)
      if (digest.status === 'fulfilled') {
        setDigestConfig(digest.value)
        setDigestExists(true)
      } else {
        setDigestConfig(null)
        setDigestExists(false)
      }
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to load alerting config', message: getApiErrorMessage(error) })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchData() }, [])

  const handleCreateIntegration = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await api.createAlertIntegration({
        name: formData.name,
        channel: formData.channel,
        webhook_url: formData.webhook_url,
        min_severity: formData.min_severity,
        secret: formData.secret || undefined,
      })
      setShowIntegrationModal(false)
      setFormData({ name: '', channel: 'slack', webhook_url: '', secret: '', min_severity: 'high' })
      addToast({ type: 'success', title: 'Integration created' })
      fetchData()
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to create', message: getApiErrorMessage(error) })
    }
  }

  const handleTestIntegration = async (integration: AlertIntegration) => {
    try {
      await api.testAlertIntegration(integration.id)
      addToast({ type: 'success', title: 'Test sent', message: `Test alert sent to ${integration.name}` })
    } catch (error) {
      addToast({ type: 'error', title: 'Test failed', message: getApiErrorMessage(error) })
    }
  }

  const handleDeleteIntegration = async (id: number) => {
    if (!confirm('Delete this integration?')) return
    try {
      await api.deleteAlertIntegration(id)
      setIntegrations(integrations.filter(i => i.id !== id))
      addToast({ type: 'success', title: 'Integration deleted' })
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to delete', message: getApiErrorMessage(error) })
    }
  }

  const handleSaveDigest = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!digestConfig) return
    try {
      const payload = {
        frequency: digestConfig.frequency,
        day_of_week: digestConfig.day_of_week,
        hour_utc: digestConfig.hour_utc,
        recipient_emails: digestConfig.recipient_emails,
        min_severity: digestConfig.min_severity,
      }
      if (digestExists) {
        await api.updateDigestConfig({ ...payload, is_active: digestConfig.is_active })
      } else {
        await api.createDigestConfig(payload)
      }
      setShowDigestModal(false)
      setDigestExists(true)
      addToast({ type: 'success', title: 'Digest config saved' })
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to save', message: getApiErrorMessage(error) })
    }
  }

  const resetIntegrationForm = () =>
    setFormData({ name: '', channel: 'slack', webhook_url: '', secret: '', min_severity: 'high' })

  if (loading) {
    return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-12 w-12 border-4 border-primary-600 border-t-transparent" /></div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Alerting</h1>
          <p className="text-gray-600">Configure notification channels and email digests</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="p-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Notification Integrations</h2>
            <button className="btn-primary text-sm" onClick={() => { resetIntegrationForm(); setShowIntegrationModal(true); }}>
              <Plus className="w-4 h-4" />
              Add Integration
            </button>
          </div>
          <div className="divide-y divide-gray-200">
            {integrations.map((integration) => (
              <div key={integration.id} className="p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div className="flex items-center gap-4">
                  <div className={`p-3 rounded-lg ${integration.channel === 'slack' ? 'bg-blue-100' : 'bg-purple-100'}`}>
                    {integration.channel === 'slack' ? (
                      <Zap className="w-5 h-5 text-blue-600" />
                    ) : (
                      <MessageSquare className="w-5 h-5 text-purple-600" />
                    )}
                  </div>
                  <div>
                    <p className="font-medium text-gray-900">{integration.name}</p>
                    <p className="text-sm text-gray-500 capitalize">{integration.channel} · {integration.min_severity} severity</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`flex items-center gap-1 badge ${integration.is_active ? 'badge-success' : 'badge-low'}`}>
                    {integration.is_active ? <Check className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                    {integration.is_active ? 'Active' : 'Inactive'}
                  </span>
                  <button className="p-2 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700" onClick={() => handleTestIntegration(integration)} aria-label={`Test ${integration.name}`} title="Test">
                    <TestTube2 className="w-4 h-4" />
                  </button>
                  <button className="p-2 rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-700" onClick={() => handleDeleteIntegration(integration.id)} aria-label={`Delete ${integration.name}`} title="Delete">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
            {integrations.length === 0 && (
              <div className="p-8 text-center text-gray-500">No integrations configured</div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="p-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Email Digest</h2>
            <button className="btn-primary text-sm" onClick={() => { if (!digestConfig) setDigestConfig({ frequency: 'weekly', day_of_week: 1, hour_utc: 9, recipient_emails: '', min_severity: 'medium', is_active: true }); setShowDigestModal(true); }}>
              {digestConfig ? 'Configure' : 'Set Up Digest'}
            </button>
          </div>
          <div className="p-4">
            {digestConfig ? (
              <div className="space-y-3 text-sm">
                <p><span className="font-medium">Status:</span> {digestConfig.is_active ? <span className="badge badge-success">Active</span> : <span className="badge badge-low">Inactive</span>}</p>
                <p><span className="font-medium">Frequency:</span> {digestConfig.frequency}</p>
                <p><span className="font-medium">Day:</span> {DAYS[digestConfig.day_of_week]}</p>
                <p><span className="font-medium">Time (UTC):</span> {digestConfig.hour_utc}:00</p>
                <p><span className="font-medium">Min Severity:</span> {digestConfig.min_severity}</p>
                <p><span className="font-medium">Recipients:</span> {digestConfig.recipient_emails}</p>
                <button className="btn-secondary text-sm mt-2" onClick={() => setShowDigestModal(true)}>Edit</button>
              </div>
            ) : (
              <p className="text-gray-500">No digest configured. Click "Set Up Digest" to configure.</p>
            )}
          </div>
        </div>
      </div>

      {showIntegrationModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-xl max-w-md w-full p-6">
            <h2 className="text-xl font-bold mb-4">Add Integration</h2>
            <form onSubmit={handleCreateIntegration} className="space-y-4">
              <div>
                <label className="label">Name</label>
                <input type="text" className="input" value={formData.name} onChange={(e) => setFormData({...formData, name: e.target.value})} placeholder="Security Team Slack" required />
              </div>
              <div>
                <label className="label">Channel</label>
                <select className="input" value={formData.channel} onChange={(e) => setFormData({...formData, channel: e.target.value})}>
                  <option value="slack">Slack</option>
                  <option value="discord">Discord</option>
                </select>
              </div>
              <div>
                <label className="label">Webhook URL</label>
                <input type="url" className="input" value={formData.webhook_url} onChange={(e) => setFormData({...formData, webhook_url: e.target.value})} placeholder="https://hooks.slack.com/services/..." required />
              </div>
              <div>
                <label className="label">Secret (optional)</label>
                <input type="text" className="input" value={formData.secret} onChange={(e) => setFormData({...formData, secret: e.target.value})} placeholder="Webhook secret for verification" />
              </div>
              <div>
                <label className="label">Minimum Severity</label>
                <select className="input" value={formData.min_severity} onChange={(e) => setFormData({...formData, min_severity: e.target.value})}>
                  {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button type="button" onClick={() => { setShowIntegrationModal(false); resetIntegrationForm(); }} className="btn-secondary">Cancel</button>
                <button type="submit" className="btn-primary">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showDigestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-xl max-w-md w-full p-6 max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">{digestExists ? 'Edit Digest Config' : 'Configure Email Digest'}</h2>
            <form onSubmit={handleSaveDigest} className="space-y-4">
              <div>
                <label className="label">Frequency</label>
                <select className="input" value={digestConfig?.frequency || 'weekly'} onChange={(e) => setDigestConfig({...digestConfig, frequency: e.target.value} as DigestConfig)}>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
              <div>
                <label className="label">Day of Week</label>
                <select className="input" value={digestConfig?.day_of_week || 1} onChange={(e) => setDigestConfig({...digestConfig, day_of_week: parseInt(e.target.value)} as DigestConfig)}>
                  {DAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
                </select>
              </div>
              <div>
                <label className="label">Hour (UTC)</label>
                <input type="number" className="input" min="0" max="23" value={digestConfig?.hour_utc || 9} onChange={(e) => setDigestConfig({...digestConfig, hour_utc: parseInt(e.target.value)} as DigestConfig)} />
              </div>
              <div>
                <label className="label">Recipient Emails (comma-separated)</label>
                <input type="text" className="input" value={digestConfig?.recipient_emails || ''} onChange={(e) => setDigestConfig({...digestConfig, recipient_emails: e.target.value} as DigestConfig)} placeholder="security@example.com,admin@example.com" required />
              </div>
              <div>
                <label className="label">Minimum Severity</label>
                <select className="input" value={digestConfig?.min_severity || 'medium'} onChange={(e) => setDigestConfig({...digestConfig, min_severity: e.target.value} as DigestConfig)}>
                  {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="digest-active" checked={digestConfig?.is_active ?? false} onChange={(e) => setDigestConfig({...digestConfig, is_active: e.target.checked} as DigestConfig)} />
                <label htmlFor="digest-active" className="text-sm text-gray-700">Active</label>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button type="button" onClick={() => setShowDigestModal(false)} className="btn-secondary">Cancel</button>
                <button type="submit" className="btn-primary">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
