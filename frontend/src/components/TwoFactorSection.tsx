import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, getApiErrorMessage } from '../lib/api'
import { useToast } from '../components/ui/Toaster'
import { RecoveryCodesDisplay } from '../components/RecoveryCodesDisplay'
import { Loader2 } from 'lucide-react'

/** Settings > Security 2FA block: status, disable, regenerate. Enabling
 *  happens on the dedicated setup page so the QR/secret flow stays intact. */
export function TwoFactorSection() {
  const { addToast } = useToast()
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [loading, setLoading] = useState(false)

  const refresh = async () => {
    try {
      const me = await api.getMe()
      setEnabled(!!(me as { totp_enabled?: boolean }).totp_enabled)
    } catch {
      setEnabled(null)
    }
  }

  useEffect(() => {
    refresh()
  }, [])

  const handleDisable = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await api.disable2fa(password, code)
      setEnabled(false)
      setPassword('')
      setCode('')
      addToast({ type: 'success', title: 'Two-factor disabled' })
    } catch (error) {
      addToast({ type: 'error', title: 'Disable failed', message: getApiErrorMessage(error) })
    } finally {
      setLoading(false)
    }
  }

  const handleRegenerate = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const result = await api.regenerate2faCodes(password, code)
      setCodes(result.recovery_codes)
      setPassword('')
      setCode('')
      addToast({ type: 'success', title: 'New recovery codes issued' })
    } catch (error) {
      addToast({ type: 'error', title: 'Regeneration failed', message: getApiErrorMessage(error) })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6 max-w-md mt-8">
      <h3 className="text-lg font-semibold text-gray-900">Two-factor authentication</h3>
      {enabled === null ? (
        <p className="text-sm text-gray-500">Loading…</p>
      ) : enabled ? (
        <div className="space-y-4">
          <p className="text-sm text-gray-600">
            Two-factor authentication is <strong>enabled</strong> on your account.
          </p>
          {codes ? (
            <RecoveryCodesDisplay codes={codes} />
          ) : (
            <>
              <form onSubmit={handleDisable} className="space-y-4">
                <div>
                  <label className="label">Password</label>
                  <input
                    type="password"
                    className="input"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label className="label">Current code or recovery code</label>
                  <input
                    type="text"
                    className="input"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    required
                  />
                </div>
                <button type="submit" className="btn-secondary" disabled={loading}>
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Disable 2FA'}
                </button>
              </form>
              <form onSubmit={handleRegenerate} className="space-y-4">
                <button type="submit" className="btn-secondary" disabled={loading}>
                  Regenerate recovery codes
                </button>
              </form>
            </>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          <p className="text-sm text-gray-600">
            Two-factor authentication is <strong>not enabled</strong>.
          </p>
          <Link to="/setup-2fa" className="btn-primary inline-block">
            Set up 2FA
          </Link>
        </div>
      )}
    </div>
  )
}
