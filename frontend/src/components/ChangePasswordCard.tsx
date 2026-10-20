import React, { useState } from 'react'
import { api, getApiErrorMessage, getApiErrorCode } from '../lib/api'
import { useToast } from '../components/ui/Toaster'
import { Loader2 } from 'lucide-react'

interface ChangeError {
  title: string
  message: string
}

/** Map a failed POST /auth/change-password to a clear inline error state. */
function mapChangeError(error: unknown): ChangeError {
  const code = getApiErrorCode(error)
  if (code === 'password_reuse') {
    return {
      title: 'New password rejected',
      message: 'The new password must differ from the current password.',
    }
  }
  if (code === 'invalid_credentials' || code === 'auth_unavailable') {
    // Both a wrong current password/2FA code and an engaged lockout return the
    // identical 401 envelope (shared login counters), so the hint covers both.
    return {
      title: 'Change failed',
      message:
        'Incorrect current password or 2FA/recovery code. Repeated failures lock the account or IP temporarily — wait a minute before trying again.',
    }
  }
  return { title: 'Change failed', message: getApiErrorMessage(error) }
}

/** Settings > Security "Change Password" block (task: item 7).
 *
 * current + new password; the TOTP/recovery field renders ONLY when the
 * signed-in user has 2FA enabled. Password reuse and the shared-login 401
 * (which includes lockout) each get their own explicit inline error state.
 */
export function ChangePasswordCard({ totpEnabled }: { totpEnabled: boolean }) {
  const { addToast } = useToast()
  const [current, setCurrent] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [code, setCode] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<ChangeError | null>(null)

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault()
    if (newPassword !== confirm) {
      setError({
        title: 'Passwords do not match',
        message: 'The confirmation does not match the new password.',
      })
      return
    }
    if (newPassword.length < 8) {
      setError({
        title: 'Password too short',
        message: 'Password must be at least 8 characters.',
      })
      return
    }
    setSaving(true)
    setError(null)
    try {
      await api.changePassword({
        current_password: current,
        new_password: newPassword,
        ...(totpEnabled && code ? { code: code.trim() } : {}),
      })
      addToast({
        type: 'success',
        title: 'Password changed',
        message: 'Other sessions were signed out; this one stays signed in.',
      })
      setCurrent('')
      setNewPassword('')
      setConfirm('')
      setCode('')
    } catch (err) {
      const mapped = mapChangeError(err)
      setError(mapped)
      addToast({ type: 'error', title: mapped.title, message: mapped.message })
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={handlePasswordChange} className="space-y-5 max-w-md" data-testid="change-password-card">
      <h3 className="text-lg font-semibold text-gray-900">Change Password</h3>

      {error && (
        <div role="alert" className="p-4 bg-red-50 border border-red-300 rounded-md text-red-800">
          <p className="font-medium">{error.title}</p>
          <p className="text-sm">{error.message}</p>
        </div>
      )}

      <div>
        <label className="label">Current Password</label>
        <input
          type="password"
          className="input"
          aria-label="Current Password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          required
          autoComplete="current-password"
        />
      </div>
      <div>
        <label className="label">New Password</label>
        <input
          type="password"
          className="input"
          aria-label="New Password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          required
          minLength={8}
          autoComplete="new-password"
        />
        <p className="text-sm text-gray-500 mt-1">Must be at least 8 characters</p>
      </div>
      <div>
        <label className="label">Confirm New Password</label>
        <input
          type="password"
          className="input"
          aria-label="Confirm New Password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
          autoComplete="new-password"
        />
      </div>
      {totpEnabled && (
        <div>
          <label className="label">Authenticator or recovery code</label>
          <input
            type="text"
            className="input font-mono"
            aria-label="Authenticator or recovery code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            required
            minLength={1}
            maxLength={32}
            placeholder="6-digit code or recovery code"
          />
          <p className="text-sm text-gray-500 mt-1">
            Required because two-factor authentication is enabled on your account.
          </p>
        </div>
      )}
      <div className="flex justify-end pt-2">
        <button type="submit" className="btn-primary flex items-center gap-2" disabled={saving}>
          {saving && <Loader2 className="w-4 h-4 animate-spin" />}
          Update Password
        </button>
      </div>
    </form>
  )
}
