import { useEffect, useRef, useState } from 'react'
import { Loader2, Lock } from 'lucide-react'

import { api, getApiErrorMessage, setStepUpRequiredHandler } from '../lib/api'

/**
 * Global step-up re-authentication dialog (v1.6.x).
 *
 * Mounted once in App; registers itself as the api-client step-up
 * handler. When any request is answered with `403 step_up_required`
 * this dialog opens; a successful `POST /auth/step-up` resolves the
 * pending promise and the api client retries the original request once.
 */
export default function StepUpDialog() {
  const [open, setOpen] = useState(false)
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const resolveRef = useRef<(() => void) | null>(null)
  const rejectRef = useRef<((reason?: unknown) => void) | null>(null)

  useEffect(() => {
    setStepUpRequiredHandler(
      () =>
        new Promise<void>((resolve, reject) => {
          resolveRef.current = resolve
          rejectRef.current = reject
          setOpen(true)
        }),
    )
    return () => setStepUpRequiredHandler(null)
  }, [])

  const close = (reject: boolean) => {
    if (reject) rejectRef.current?.(new Error('Step-up cancelled'))
    else resolveRef.current?.()
    resolveRef.current = null
    rejectRef.current = null
    setOpen(false)
    setBusy(false)
    setError(null)
    setPassword('')
    setTotpCode('')
  }

  if (!open) return null

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.stepUp(password, totpCode || undefined)
      close(false)
    } catch (err) {
      setError(getApiErrorMessage(err, 'Step-up verification failed'))
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-full max-w-sm rounded-lg bg-white p-6 shadow-lg">
        <div className="mb-4 flex items-center gap-2">
          <Lock className="h-5 w-5 text-slate-700" />
          <h2 className="text-lg font-semibold">Confirm it's you</h2>
        </div>
        <p className="mb-4 text-sm text-slate-600">
          This action is sensitive. Re-enter your password to continue for the next 5 minutes.
        </p>
        <form onSubmit={submit}>
          <label className="mb-1 block text-sm font-medium" htmlFor="stepup-password">
            Current password
          </label>
          <input
            id="stepup-password"
            type="password"
            autoFocus
            disabled={busy}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="mb-3 w-full rounded border border-slate-300 px-3 py-2 text-sm"
          />
          <label className="mb-1 block text-sm font-medium" htmlFor="stepup-code">
            2FA code <span className="font-normal text-slate-500">(if enabled)</span>
          </label>
          <input
            id="stepup-code"
            type="text"
            inputMode="numeric"
            disabled={busy}
            value={totpCode}
            onChange={(event) => setTotpCode(event.target.value)}
            className="mb-3 w-full rounded border border-slate-300 px-3 py-2 text-sm"
          />
          {error && (
            <div
              role="alert"
              className="mb-3 rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700"
            >
              {error}
            </div>
          )}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              className="btn-secondary rounded px-3 py-2 text-sm"
              disabled={busy}
              onClick={() => close(true)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary flex items-center gap-2 rounded px-3 py-2 text-sm"
              disabled={busy || password.length === 0}
            >
              {busy && <Loader2 className="h-4 w-4 animate-spin" />}
              Verify
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
