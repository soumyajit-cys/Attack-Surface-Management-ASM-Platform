import React, { useEffect, useState } from 'react'
import { useToast } from '../components/ui/Toaster'
import { api, getApiErrorMessage } from '../lib/api'
import type { Invitation, APIKey, DigestConfig } from '../lib/types'
import { Plus, Trash2, Copy } from 'lucide-react'

const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export function Organizations() {
  const { addToast } = useToast()
  const [invitations, setInvitations] = useState<Invitation[]>([])
  const [apiKeys, setApiKeys] = useState<APIKey[]>([])
  const [digestConfig, setDigestConfig] = useState<DigestConfig | null>(null)
  const [digestExists, setDigestExists] = useState(false)
  const [showInviteModal, setShowInviteModal] = useState(false)
  const [showKeyModal, setShowKeyModal] = useState(false)
  const [showDigestModal, setShowDigestModal] = useState(false)
  const [newInviteEmail, setNewInviteEmail] = useState('')
  const [newInviteRole, setNewInviteRole] = useState('analyst')
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyScopes, setNewKeyScopes] = useState('read')
  const [newKeyExpiresDays, setNewKeyExpiresDays] = useState('')
  const [newKey, setNewKey] = useState('')
  const [loading, setLoading] = useState(true)

  const fetchData = async () => {
    setLoading(true)
    try {
      const [invitationsData, apiKeysData, digest] = await Promise.allSettled([
        api.listInvitations(),
        api.listApiKeys(),
        api.getDigestConfig(),
      ])
      if (invitationsData.status === 'fulfilled') setInvitations(invitationsData.value)
      if (apiKeysData.status === 'fulfilled') setApiKeys(apiKeysData.value)
      if (digest.status === 'fulfilled') {
        setDigestConfig(digest.value)
        setDigestExists(true)
      } else {
        setDigestConfig(null)
        setDigestExists(false)
      }
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to load organization settings', message: getApiErrorMessage(error) })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchData() }, [])

  const handleCreateInvitation = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await api.createInvitation(newInviteEmail, newInviteRole)
      setShowInviteModal(false)
      setNewInviteEmail('')
      addToast({ type: 'success', title: 'Invitation sent', message: `Invited ${newInviteEmail} as ${newInviteRole}` })
      fetchData()
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to create invitation', message: getApiErrorMessage(error) })
    }
  }

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const response = await api.createApiKey({
        name: newKeyName,
        scopes: newKeyScopes,
        expires_days: newKeyExpiresDays ? parseInt(newKeyExpiresDays) : undefined,
      })
      setNewKey(response.key)
      setNewKeyName('')
      setNewKeyExpiresDays('')
      fetchData()
      addToast({ type: 'success', title: 'API key created', message: "Copy the key now - it won't be shown again" })
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to create API key', message: getApiErrorMessage(error) })
    }
  }

  const handleRevokeKey = async (keyId: number) => {
    if (!confirm('Revoke this API key? This cannot be undone.')) return
    try {
      await api.deleteApiKey(keyId)
      setApiKeys(apiKeys.filter(k => k.id !== keyId))
      addToast({ type: 'success', title: 'API key revoked' })
    } catch (error) {
      addToast({ type: 'error', title: 'Failed to revoke key', message: getApiErrorMessage(error) })
    }
  }

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key)
    addToast({ type: 'success', title: 'Copied!', message: 'API key copied to clipboard' })
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

  if (loading) {
    return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-12 w-12 border-4 border-primary-600 border-t-transparent" /></div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Organization Settings</h1>
          <p className="text-gray-600">Manage your organization, users, and integrations</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card">
          <div className="p-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Team Invitations</h2>
            <button className="btn-primary text-sm" onClick={() => setShowInviteModal(true)}>
              <Plus className="w-4 h-4" />
              Invite
            </button>
          </div>
          <div className="divide-y divide-gray-200">
            {invitations.map((inv) => (
              <div key={inv.id} className="p-4 flex items-center justify-between">
                <div>
                  <p className="font-medium text-gray-900">{inv.email}</p>
                  <p className="text-sm text-gray-500 capitalize">{inv.role} · Expires {new Date(inv.expires_at).toLocaleDateString()}</p>
                </div>
                <span className="badge badge-info">{inv.status}</span>
              </div>
            ))}
            {invitations.length === 0 && (
              <div className="p-8 text-center text-gray-500">No pending invitations</div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="p-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">API Keys</h2>
            <button className="btn-primary text-sm" onClick={() => { setNewKey(''); setShowKeyModal(true); }}>
              <Plus className="w-4 h-4" />
              Create Key
            </button>
          </div>
          <div className="divide-y divide-gray-200">
            {apiKeys.map((key) => (
              <div key={key.id} className="p-4 flex items-center justify-between">
                <div>
                  <p className="font-medium text-gray-900">{key.name}</p>
                  <p className="text-sm text-gray-500 font-mono">{key.key_prefix}_••••••••</p>
                  <p className="text-xs text-gray-400 mt-1">
                    Scopes: {key.scopes} · {key.is_active ? 'Active' : 'Revoked'} · {key.last_used_at ? `Last used: ${new Date(key.last_used_at).toLocaleDateString()}` : 'Never used'}
                  </p>
                </div>
                <button
                  onClick={() => handleRevokeKey(key.id)}
                  className="btn-danger text-sm"
                  disabled={!key.is_active}
                >
                  <Trash2 className="w-4 h-4" />
                  Revoke
                </button>
              </div>
            ))}
            {apiKeys.length === 0 && (
              <div className="p-8 text-center text-gray-500">No API keys created yet</div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="p-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Email Digest</h2>
            <button className="btn-primary text-sm" onClick={() => { if (!digestConfig) setDigestConfig({ frequency: 'weekly', day_of_week: 1, hour_utc: 9, recipient_emails: '', min_severity: 'medium', is_active: true }); setShowDigestModal(true); }}>
              {digestConfig ? 'Configure' : 'Set Up'}
            </button>
          </div>
          <div className="p-4">
            {digestConfig ? (
              <div className="space-y-3 text-sm">
                <p><span className="font-medium">Status:</span> {digestConfig.is_active ? 'Active' : 'Inactive'}</p>
                <p><span className="font-medium">Frequency:</span> {digestConfig.frequency}</p>
                <p><span className="font-medium">Day:</span> {DAYS[digestConfig.day_of_week]}</p>
                <p><span className="font-medium">Time (UTC):</span> {digestConfig.hour_utc}:00</p>
                <p><span className="font-medium">Min Severity:</span> {digestConfig.min_severity}</p>
                <p><span className="font-medium">Recipients:</span> {digestConfig.recipient_emails}</p>
                <button className="btn-secondary text-sm mt-2" onClick={() => setShowDigestModal(true)}>
                  Edit Configuration
                </button>
              </div>
            ) : (
              <p className="text-gray-500">No digest configured. Click "Set Up" to configure weekly security digests.</p>
            )}
          </div>
        </div>
      </div>

      {showInviteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-xl max-w-md w-full p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">Invite Team Member</h2>
              <button onClick={() => setShowInviteModal(false)} className="p-2 rounded-lg hover:bg-gray-100" aria-label="Close">✕</button>
            </div>
            <form onSubmit={handleCreateInvitation} className="space-y-4">
              <div>
                <label className="label">Email</label>
                <input type="email" className="input" value={newInviteEmail} onChange={(e) => setNewInviteEmail(e.target.value)} required />
              </div>
              <div>
                <label className="label">Role</label>
                <select className="input" value={newInviteRole} onChange={(e) => setNewInviteRole(e.target.value)}>
                  <option value="viewer">Viewer</option>
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button type="button" onClick={() => setShowInviteModal(false)} className="btn-secondary">Cancel</button>
                <button type="submit" className="btn-primary">Send Invitation</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showKeyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-xl max-w-md w-full p-6">
            {newKey ? (
              <div className="space-y-4">
                <h2 className="text-xl font-bold mb-4">API Key Created</h2>
                <div className="bg-gray-100 p-4 rounded-lg font-mono text-sm break-all">{newKey}</div>
                <p className="text-sm text-gray-600">Copy this key now. It won't be shown again.</p>
                <div className="flex justify-end gap-2">
                  <button onClick={() => handleCopyKey(newKey)} className="btn-secondary flex items-center gap-2">
                    <Copy className="w-4 h-4" />
                    Copy
                  </button>
                  <button onClick={() => { setShowKeyModal(false); setNewKey(''); }} className="btn-primary">Done</button>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-bold">Create API Key</h2>
                  <button onClick={() => setShowKeyModal(false)} className="p-2 rounded-lg hover:bg-gray-100" aria-label="Close">✕</button>
                </div>
                <form onSubmit={handleCreateApiKey} className="space-y-4">
                  <div>
                    <label className="label">Key Name</label>
                    <input type="text" className="input" value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)} placeholder="CI/CD Pipeline" required />
                  </div>
                  <div>
                    <label className="label">Scopes</label>
                    <select className="input" value={newKeyScopes} onChange={(e) => setNewKeyScopes(e.target.value)}>
                      <option value="read">Read Only</option>
                      <option value="read,write">Read & Write</option>
                      <option value="read,write,admin">Full Access</option>
                    </select>
                  </div>
                  <div>
                    <label className="label">Expires In (days, optional)</label>
                    <input type="number" className="input" value={newKeyExpiresDays} onChange={(e) => setNewKeyExpiresDays(e.target.value)} placeholder="365" min="1" />
                  </div>
                  <div className="flex justify-end gap-2 pt-4">
                    <button type="button" onClick={() => setShowKeyModal(false)} className="btn-secondary">Cancel</button>
                    <button type="submit" className="btn-primary">Create Key</button>
                  </div>
                </form>
              </div>
            )}
          </div>
        </div>
      )}

      {showDigestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-xl max-w-md w-full p-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">{digestExists ? 'Edit Digest Config' : 'Configure Email Digest'}</h2>
              <button onClick={() => setShowDigestModal(false)} className="p-2 rounded-lg hover:bg-gray-100" aria-label="Close">✕</button>
            </div>
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
