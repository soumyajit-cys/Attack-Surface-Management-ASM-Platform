import React, { useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { useToast } from '../components/ui/Toaster'
import { api } from '../lib/api'
import { TwoFactorSection } from '../components/TwoFactorSection'
import { ChangePasswordCard } from '../components/ChangePasswordCard'
import {
  User,
  Lock,
  Bell,
  Shield,
  Palette,
  Moon,
  Sun,
  Globe,
  Loader2,
  AlertTriangle,
  Sliders,
  Trash2,
  Eye,
  EyeOff,
} from 'lucide-react'

export function Settings() {
  const { user } = useAuth()
  const { addToast } = useToast()
  const [activeTab, setActiveTab] = useState<
    'profile' | 'security' | 'notifications' | 'appearance' | 'danger' | 'providers'
  >('profile')
  const [profileData, setProfileData] = useState({
    username: user?.username || '',
    email: user?.email || '',
  })
  const [saving, setSaving] = useState(false)

  const handleProfileSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    addToast({
      type: 'info',
      title: 'Profile update not yet available',
      message: 'Profile editing will be available in a future release.',
    })
    setSaving(false)
  }

  // ── enrichment provider state ─────────────────────────────────────────
  const [providers, setProviders] = useState<
    {
      name: string
      provider_type: string
      has_key: boolean
      is_active: boolean
    }[]
  >([])
  const [providersLoading, setProvidersLoading] = useState(false)
  const [providerForm, setProviderForm] = useState<{
    name: string
    provider_type: string
    api_key: string
    is_active: boolean
    acknowledge_data_sharing: boolean
  }>({
    name: '',
    provider_type: '',
    api_key: '',
    is_active: true,
    acknowledge_data_sharing: false,
  })
  const [showKey, setShowKey] = useState(false)
  const [upsertSaving, setUpsertSaving] = useState(false)
  const [editMode, setEditMode] = useState(false)
  const [editingName, setEditingName] = useState<string | null>(null)

  const hasEnrichmentManage = () => user?.permissions?.includes('enrichment:manage') ?? false

  const loadProviders = async () => {
    if (!hasEnrichmentManage()) return
    setProvidersLoading(true)
    try {
      const data = await api.listEnrichmentProviders()
      setProviders(data)
    } catch {
      addToast({ type: 'error', title: 'Failed to load providers' })
    } finally {
      setProvidersLoading(false)
    }
  }

  const handleProviderSave = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!providerForm.acknowledge_data_sharing && providerForm.is_active) {
      addToast({
        type: 'error',
        title: 'Data sharing acknowledgement required',
        message: 'Enabling a third-party provider requires acknowledge_data_sharing.',
      })
      return
    }
    setUpsertSaving(true)
    try {
      await api.upsertEnrichmentProvider(providerForm.name, {
        provider_type: providerForm.provider_type,
        api_key: providerForm.api_key || undefined,
        is_active: providerForm.is_active,
        acknowledge_data_sharing: providerForm.acknowledge_data_sharing,
      })
      setEditMode(false)
      setEditingName(null)
      setProviderForm({
        name: '',
        provider_type: '',
        api_key: '',
        is_active: true,
        acknowledge_data_sharing: false,
      })
      await loadProviders()
      addToast({
        type: 'success',
        title: 'Provider updated',
        message: 'Key material is never returned or logged.',
      })
    } catch (err: any) {
      addToast({
        type: 'error',
        title: 'Failed to save provider',
        message: err.response?.data?.error?.message || String(err),
      })
    } finally {
      setUpsertSaving(false)
    }
  }

  const handleProviderDelete = async (name: string) => {
    if (!window.confirm(`Delete provider "${name}"?`)) return
    try {
      await api.deleteEnrichmentProvider(name)
      await loadProviders()
      addToast({ type: 'success', title: 'Provider deleted' })
    } catch {
      addToast({ type: 'error', title: 'Failed to delete provider' })
    }
  }

  const handleEditProvider = (p: {
    name: string
    provider_type: string
    has_key: boolean
    is_active: boolean
  }) => {
    setEditMode(true)
    setEditingName(p.name)
    setProviderForm({
      name: p.name,
      provider_type: p.provider_type,
      api_key: '',
      is_active: p.is_active,
      acknowledge_data_sharing: false,
    })
  }

  // Load providers whenever the Providers tab is shown.
  useEffect(() => {
    if (activeTab === 'providers' && hasEnrichmentManage()) {
      void loadProviders()
    }
  }, [activeTab])

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'security', label: 'Security', icon: Lock },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'appearance', label: 'Appearance', icon: Palette },
    { id: 'danger', label: 'Danger Zone', icon: Shield },
    ...(hasEnrichmentManage() ? [{ id: 'providers', label: 'Providers', icon: Sliders }] : []),
  ]

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-600">Manage your account preferences</p>
      </div>

      <div className="card">
        <div className="border-b border-gray-200">
          <nav className="flex gap-8 px-6" aria-label="Settings tabs" role="tablist">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                role="tab"
                aria-selected={activeTab === tab.id}
                aria-controls={`panel-${tab.id}`}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.id
                    ? 'border-primary-600 text-primary-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                <span className="flex items-center gap-2">
                  <tab.icon className="w-4 h-4" />
                  {tab.label}
                </span>
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6" role="tabpanel" id={`panel-${activeTab}`}>
          {activeTab === 'profile' && (
            <form onSubmit={handleProfileSave} className="space-y-6 max-w-md">
              <h3 className="text-lg font-semibold text-gray-900">Profile Information</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="label">Username</label>
                  <input
                    type="text"
                    className="input"
                    value={profileData.username}
                    onChange={(e) => setProfileData({ ...profileData, username: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <label className="label">Email</label>
                  <input
                    type="email"
                    className="input"
                    value={profileData.email}
                    onChange={(e) => setProfileData({ ...profileData, email: e.target.value })}
                    required
                  />
                </div>
              </div>
              <div>
                <label className="label">Role</label>
                <select className="input" value={user?.role} disabled>
                  <option value="admin">Admin</option>
                  <option value="analyst">Analyst</option>
                  <option value="viewer">Viewer</option>
                </select>
                <p className="text-sm text-gray-500 mt-1">
                  Role is assigned by your organization admin
                </p>
              </div>
              <div className="flex justify-end pt-4">
                <button type="submit" className="btn-primary" disabled={saving}>
                  {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Save Changes'}
                </button>
              </div>
            </form>
          )}

          {activeTab === 'security' && (
            <ChangePasswordCard totpEnabled={user?.totp_enabled === true} />
          )}

          {activeTab === 'security' && <TwoFactorSection />}

          {activeTab === 'notifications' && (
            <div className="space-y-6 max-w-md">
              <h3 className="text-lg font-semibold text-gray-900">Email Notifications</h3>
              <p className="text-sm text-gray-500">
                Notification preferences are managed through the Alerting page. Configure
                integrations and email digests there.
              </p>
              <div className="space-y-4">
                {[
                  {
                    id: 'scan_complete',
                    label: 'Scan completed',
                    description: 'Receive notification when a scan finishes',
                  },
                  {
                    id: 'finding_critical',
                    label: 'Critical findings',
                    description: 'Alerted immediately when critical findings are discovered',
                  },
                  {
                    id: 'finding_high',
                    label: 'High severity findings',
                    description: 'Daily summary of high severity findings',
                  },
                  {
                    id: 'scan_failed',
                    label: 'Scan failures',
                    description: 'Notified when a scan fails to complete',
                  },
                  {
                    id: 'weekly_digest',
                    label: 'Weekly digest',
                    description: 'Weekly summary of all findings and scan activity',
                  },
                ].map((notif) => (
                  <div
                    key={notif.id}
                    className="flex items-center justify-between p-4 border border-gray-200 rounded-lg"
                  >
                    <div>
                      <p className="font-medium text-gray-900">{notif.label}</p>
                      <p className="text-sm text-gray-500">{notif.description}</p>
                    </div>
                    <span className="text-xs text-gray-400">Configured via Alerting</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'appearance' && (
            <div className="space-y-6 max-w-md">
              <h3 className="text-lg font-semibold text-gray-900">Theme</h3>
              <div className="grid grid-cols-3 gap-4">
                {[
                  { id: 'light', label: 'Light', icon: Sun, active: true },
                  { id: 'dark', label: 'Dark', icon: Moon, active: false },
                  { id: 'system', label: 'System', icon: Globe, active: false },
                ].map((theme) => (
                  <button
                    key={theme.id}
                    disabled={!theme.active}
                    className={`p-4 border-2 rounded-lg text-center transition-colors ${
                      theme.active
                        ? 'border-primary-600 bg-primary-50'
                        : 'border-gray-200 opacity-50 cursor-not-allowed'
                    }`}
                  >
                    <theme.icon className="w-6 h-6 mx-auto mb-2 text-gray-600" />
                    <p className="font-medium">{theme.label}</p>
                    {!theme.active && <p className="text-xs text-gray-400 mt-1">Coming soon</p>}
                  </button>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'danger' && (
            <div className="space-y-6 max-w-md border-t border-danger-200 pt-6">
              <div className="p-4 bg-danger-50 border border-danger-200 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-danger-100 rounded-lg">
                    <AlertTriangle className="w-5 h-5 text-danger-600" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-danger-700">Danger Zone</h3>
                    <p className="text-sm text-danger-600">
                      These actions are irreversible. Please proceed with caution.
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900">Delete Account</h4>
                      <p className="text-sm text-gray-500">
                        Permanently delete your account and all associated data
                      </p>
                    </div>
                    <button
                      className="btn-danger"
                      onClick={() =>
                        addToast({
                          type: 'info',
                          title: 'Not available',
                          message: 'Account deletion will be available in a future release.',
                        })
                      }
                    >
                      Delete Account
                    </button>
                  </div>
                </div>

                <div className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900">Revoke All Sessions</h4>
                      <p className="text-sm text-gray-500">
                        Log out from all devices and revoke all API keys
                      </p>
                    </div>
                    <button
                      className="btn-secondary"
                      onClick={async () => {
                        try {
                          const keys = await api.listApiKeys()
                          for (const key of keys) {
                            if (key.is_active) await api.deleteApiKey(key.id)
                          }
                          addToast({ type: 'success', title: 'All API keys revoked' })
                        } catch {
                          addToast({ type: 'error', title: 'Failed to revoke keys' })
                        }
                      }}
                    >
                      Revoke All
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'providers' && (
            <div
              className="space-y-6 max-w-2xl"
              data-testid="enrichment-providers-section"
              aria-label="Enrichment providers"
            >
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-gray-900">Enrichment Providers</h3>
                <button
                  className="btn-secondary text-sm"
                  onClick={() => {
                    void loadProviders()
                  }}
                  data-testid="providers-refresh"
                >
                  {providersLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Refresh'}
                </button>
              </div>

              <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-800">
                Enabling a third-party provider sends registered domain names to that provider. The
                API key is Fernet-encrypted at rest and is never returned by the API or written to
                logs.
                <br />
                <br />
                <strong>Stored keys are not yet consumed by any active provider.</strong> Enabling a
                provider here records its config; actual enrichment calls are implemented
                per-provider in a future release.
              </div>

              {/* Provider list */}
              <div className="space-y-3">
                {providers.length === 0 && !providersLoading && (
                  <p className="text-sm text-gray-500" data-testid="providers-empty">
                    No enrichment providers configured.
                  </p>
                )}
                {providers.map((p) => (
                  <div
                    key={p.name}
                    className="p-4 border border-gray-200 rounded-lg flex items-center justify-between"
                    data-testid={`provider-row-${p.name}`}
                  >
                    <div>
                      <p className="font-medium text-gray-900">{p.name}</p>
                      <p className="text-sm text-gray-500">
                        {p.provider_type} · {p.has_key ? 'key set' : 'no key'}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-xs px-2 py-1 rounded ${
                          p.is_active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'
                        }`}
                      >
                        {p.is_active ? 'active' : 'inactive'}
                      </span>
                      <button
                        className="btn-secondary text-xs"
                        onClick={() => handleEditProvider(p)}
                        data-testid={`provider-edit-${p.name}`}
                      >
                        Edit
                      </button>
                      <button
                        className="btn-danger text-xs"
                        onClick={() => handleProviderDelete(p.name)}
                        data-testid={`provider-delete-${p.name}`}
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {/* Add / edit provider form */}
              <form
                onSubmit={handleProviderSave}
                className="space-y-4 border border-gray-200 rounded-lg p-4"
                data-testid="provider-form"
              >
                <h4 className="font-medium text-gray-900">
                  {editMode && editingName ? `Edit provider: ${editingName}` : 'Add provider'}
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="label" htmlFor="provider-name">
                      Provider name
                    </label>
                    <input
                      id="provider-name"
                      type="text"
                      className="input"
                      value={providerForm.name}
                      onChange={(e) => setProviderForm({ ...providerForm, name: e.target.value })}
                      required
                      disabled={editMode}
                      data-testid="provider-name-input"
                    />
                  </div>
                  <div>
                    <label className="label" htmlFor="provider-type">
                      Provider type
                    </label>
                    <input
                      id="provider-type"
                      type="text"
                      className="input"
                      value={providerForm.provider_type}
                      onChange={(e) =>
                        setProviderForm({
                          ...providerForm,
                          provider_type: e.target.value,
                        })
                      }
                      required
                      data-testid="provider-type-input"
                    />
                  </div>
                </div>
                <div>
                  <label className="label" htmlFor="provider-api-key">
                    API key
                  </label>
                  <div className="relative">
                    <input
                      id="provider-api-key"
                      type={showKey ? 'text' : 'password'}
                      className="input pr-10"
                      value={providerForm.api_key}
                      onChange={(e) =>
                        setProviderForm({
                          ...providerForm,
                          api_key: e.target.value,
                        })
                      }
                      placeholder="Leave empty to keep the existing key"
                      data-testid="provider-key-input"
                    />
                    <button
                      type="button"
                      className="absolute right-2 top-2 text-gray-400"
                      onClick={() => setShowKey(!showKey)}
                      aria-label={showKey ? 'Hide key' : 'Show key'}
                    >
                      {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={providerForm.is_active}
                      onChange={(e) =>
                        setProviderForm({
                          ...providerForm,
                          is_active: e.target.checked,
                        })
                      }
                      data-testid="provider-active-checkbox"
                    />
                    Active
                  </label>
                  <label className="flex items-start gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={providerForm.acknowledge_data_sharing}
                      onChange={(e) =>
                        setProviderForm({
                          ...providerForm,
                          acknowledge_data_sharing: e.target.checked,
                        })
                      }
                      required={providerForm.is_active}
                      data-testid="provider-ack-checkbox"
                    />
                    <span>
                      I acknowledge that enabling this third-party provider will send registered
                      domain names to it.
                    </span>
                  </label>
                </div>
                <div className="flex justify-end">
                  <button
                    type="submit"
                    className="btn-primary"
                    disabled={upsertSaving}
                    data-testid="provider-save-button"
                  >
                    {upsertSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Save Provider'}
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
