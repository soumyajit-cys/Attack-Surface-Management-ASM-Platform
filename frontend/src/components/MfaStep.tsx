import React, { useState } from 'react'
import { Loader2 } from 'lucide-react'

interface MfaStepProps {
  onSubmit: (code: string) => Promise<void>
  loading?: boolean
}

/** Six-digit TOTP step with a "use a recovery code" toggle. Pure presentational
 *  except for the submit callback, so unit tests drive it without a backend. */
export function MfaStep({ onSubmit, loading }: MfaStepProps) {
  const [code, setCode] = useState('')
  const [useRecovery, setUseRecovery] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    try {
      await onSubmit(code.trim())
    } catch {
      setError('Invalid code. Try again or use a recovery code.')
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      <div>
        <label htmlFor="mfa-code" className="label">
          {useRecovery ? 'Recovery code' : 'Authenticator code'}
        </label>
        <input
          id="mfa-code"
          type="text"
          inputMode={useRecovery ? 'text' : 'numeric'}
          autoComplete="one-time-code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          className="input tracking-widest"
          placeholder={useRecovery ? 'Enter a recovery code' : 'Enter the 6-digit code'}
          required
          disabled={loading}
        />
      </div>
      {error && (
        <p role="alert" className="text-sm text-danger-600">
          {error}
        </p>
      )}
      <button type="submit" className="btn-primary w-full py-3" disabled={loading}>
        {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Verify'}
      </button>
      <button
        type="button"
        className="text-sm text-primary-600 hover:text-primary-500"
        onClick={() => {
          setUseRecovery(!useRecovery)
          setCode('')
        }}
      >
        {useRecovery ? 'Use authenticator app instead' : 'Use a recovery code instead'}
      </button>
    </form>
  )
}
