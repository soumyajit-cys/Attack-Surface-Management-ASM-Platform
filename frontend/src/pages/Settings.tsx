import React, { useState } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { useToast } from '../components/ui/Toaster'
import { User, Lock, Bell, Shield, Palette, Moon, Sun, Globe, Key, Trash2, Loader2, AlertTriangle } from 'lucide-react'

export function Settings() {
  const { user, refreshUser } = useAuth()
  const { addToast } = useToast()
  const [activeTab, setActiveTab] = useState<'profile' | 'security' | 'notifications' | 'appearance' | 'danger'>('profile')
  const [profileData, setProfileData] = useState({ username: user?.username || '', email: user?.email || '' })
  const [passwordData, setPasswordData] = useState({ current: '', new: '', confirm: '' })
  const [saving, setSaving] = useState(false)

  const handleProfileSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    // Mock save
    setTimeout(() => {
      setSaving(false)
      addToast({ type: 'success', title: 'Profile updated' })
    }, 500)
  }

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault()
    if (passwordData.new !== passwordData.confirm) {
      addToast({ type: 'error', title: 'Passwords do not match' })
      return
    }
    if (passwordData.new.length < 8) {
      addToast({ type: 'error', title: 'Password must be at least 8 characters' })
      return
    }
    setSaving(true)
    // Mock
    setTimeout(() => {
      setSaving(false)
      setPasswordData({ current: '', new: '', confirm: '' })
      addToast({ type: 'success', title: 'Password changed' })
    }, 500)
  }

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'security', label: 'Security', icon: Lock },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'appearance', label: 'Appearance', icon: Palette },
    { id: 'danger', label: 'Danger Zone', icon: Shield },
  ]

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-600">Manage your account preferences</p>
      </div>

      <div className="card">
        <div className="border-b border-gray-200">
          <nav className="flex gap-8 px-6" aria-label="Settings tabs">
            {tabs.map((tab) => (
              <button
                key={tab.id}
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

        <div className="p-6">
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
                    onChange={(e) => setProfileData({...profileData, username: e.target.value})}
                    required
                  />
                </div>
                <div>
                  <label className="label">Email</label>
                  <input
                    type="email"
                    className="input"
                    value={profileData.email}
                    onChange={(e) => setProfileData({...profileData, email: e.target.value})}
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
                <p className="text-sm text-gray-500 mt-1">Role is assigned by your organization admin</p>
              </div>
              <div className="flex justify-end pt-4">
                <button type="submit" className="btn-primary" disabled={saving}>
                  {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Save Changes'}
                </button>
              </div>
            </form>
          )}

          {activeTab === 'security' && (
            <form onSubmit={handlePasswordChange} className="space-y-6 max-w-md">
              <h3 className="text-lg font-semibold text-gray-900">Change Password</h3>
              <div>
                <label className="label">Current Password</label>
                <input
                  type="password"
                  className="input"
                  value={passwordData.current}
                  onChange={(e) => setPasswordData({...passwordData, current: e.target.value})}
                  required
                />
              </div>
              <div>
                <label className="label">New Password</label>
                <input
                  type="password"
                  className="input"
                  value={passwordData.new}
                  onChange={(e) => setPasswordData({...passwordData, new: e.target.value})}
                  required
                  minLength={8}
                />
                <p className="text-sm text-gray-500 mt-1">Must be at least 8 characters</p>
              </div>
              <div>
                <label className="label">Confirm New Password</label>
                <input
                  type="password"
                  className="input"
                  value={passwordData.confirm}
                  onChange={(e) => setPasswordData({...passwordData, confirm: e.target.value})}
                  required
                />
              </div>
              <div className="flex justify-end pt-4">
                <button type="submit" className="btn-primary" disabled={saving}>
                  {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Update Password'}
                </button>
              </div>
            </form>
          )}

          {activeTab === 'notifications' && (
            <div className="space-y-6 max-w-md">
              <h3 className="text-lg font-semibold text-gray-900">Email Notifications</h3>
              <div className="space-y-4">
                {[
                  { id: 'scan_complete', label: 'Scan completed', description: 'Receive notification when a scan finishes' },
                  { id: 'finding_critical', label: 'Critical findings', description: 'Alerted immediately when critical findings are discovered' },
                  { id: 'finding_high', label: 'High severity findings', description: 'Daily summary of high severity findings' },
                  { id: 'scan_failed', label: 'Scan failures', description: 'Notified when a scan fails to complete' },
                  { id: 'weekly_digest', label: 'Weekly digest', description: 'Weekly summary of all findings and scan activity' },
                ].map((notif) => (
                  <div key={notif.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                    <div>
                      <p className="font-medium text-gray-900">{notif.label}</p>
                      <p className="text-sm text-gray-500">{notif.description}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" className="sr-only peer" defaultChecked />
                      <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                    </label>
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
                  { id: 'light', label: 'Light', icon: Sun },
                  { id: 'dark', label: 'Dark', icon: Moon },
                  { id: 'system', label: 'System', icon: Globe },
                ].map((theme) => (
                  <button
                    key={theme.id}
                    className={`p-4 border-2 rounded-lg text-center transition-colors ${
                      theme.id === 'light' ? 'border-primary-600 bg-primary-50' : 'border-gray-200 hover:border-gray-300'
                    }`}
                  >
                    <theme.icon className="w-6 h-6 mx-auto mb-2 text-gray-600" />
                    <p className="font-medium">{theme.label}</p>
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
                    <p className="text-sm text-danger-600">These actions are irreversible. Please proceed with caution.</p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900">Delete Account</h4>
                      <p className="text-sm text-gray-500">Permanently delete your account and all associated data</p>
                    </div>
                    <button className="btn-danger">Delete Account</button>
                  </div>
                </div>

                <div className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900">Revoke All Sessions</h4>
                      <p className="text-sm text-gray-500">Log out from all devices and revoke all API keys</p>
                    </div>
                    <button className="btn-secondary">Revoke All</button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}