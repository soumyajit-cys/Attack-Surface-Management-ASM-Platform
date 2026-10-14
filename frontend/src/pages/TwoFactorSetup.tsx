import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { QRCodeSVG } from 'qrcode.react'
import { api, getApiErrorMessage } from '../lib/api'
import { useToast } from '../components/ui/Toaster'
import { RecoveryCodesDisplay } from '../components/RecoveryCodesDisplay'
import { Shield, Loader2 } from 'lucide-react'

/** Mandatory 2FA enrollment. Works with a full session or the restricted
 *  enroll_2fa token issued under require_2fa. The secret is shown once. */
export function TwoFactorSetup() {
  const navigate = useNavigate()
  const { addToast } = useToast()
  const [password, setPassword] = useState('')
  const [secret, setSecret] = useState<string | null>(null)
  const [uri, setUri] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [loading, setLoading] = useState(false)

  const handleEnroll = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const result = await api.enroll2fa(password)
      setSecret(result.secret)
      setUri(result.otpauth_uri)
    } catch (error) {
      addToast({ type: 'error', title: 'Enrollment failed', message: getApiErrorMessage(error) })
    } finally {
      setLoading(false)
    }
  }

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const result = await api.confirm2fa(code.trim())
      setCodes(result.recovery_codes)
      addToast({ type: 'success', title: 'Two-factor enabled' })
    } catch (error) {
      addToast({ type: 'error', title: 'Confirmation failed', message: getApiErrorMessage(error) })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary-600 to-purple-600 flex items-center justify-center mx-auto">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 mt-4">
            Set up two-factor authentication
          </h1>
        </div>

        <div className="card p-6">
          {codes ? (
            <div className="space-y-4">
              <RecoveryCodesDisplay codes={codes} />
              <button type="button" className="btn-primary w-full" onClick={() => navigate('/')}>
                Done
              </button>
            </div>
          ) : secret && uri ? (
            <div className="space-y-4">
              <p className="text-sm text-gray-600">
                Scan this code with your authenticator app, then enter the 6-digit code below.
              </p>
              <div className="flex justify-center bg-white p-4 rounded">
                <QRCodeSVG value={uri} size={192} />
              </div>
              <p className="text-sm text-gray-500">
                Can&apos;t scan? Enter this secret manually:{' '}
                <code className="font-mono select-all">{secret}</code>
              </p>
              <form onSubmit={handleConfirm} className="space-y-4">
                <div>
                  <label htmlFor="confirm-code" className="label">
                    Authenticator code
                  </label>
                  <input
                    id="confirm-code"
                    type="text"
                    inputMode="numeric"
                    className="input tracking-widest"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder="6-digit code"
                    required
                    disabled={loading}
                  />
                </div>
                <button type="submit" className="btn-primary w-full" disabled={loading}>
                  {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Confirm and enable'}
                </button>
              </form>
            </div>
          ) : (
            <form onSubmit={handleEnroll} className="space-y-5">
              <div>
                <label htmlFor="setup-password" className="label">
                  Confirm your password
                </label>
                <input
                  id="setup-password"
                  type="password"
                  className="input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  disabled={loading}
                />
              </div>
              <button type="submit" className="btn-primary w-full" disabled={loading}>
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Start setup'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}
