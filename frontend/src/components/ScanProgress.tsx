import { useEffect, useRef, useState } from 'react'
import { Loader2, MinusCircle, Ban } from 'lucide-react'

import {
  subscribeScanEvents,
  type ScanEvent,
  type ScanEventConnectionStatus,
  type ScanEventData,
  TERMINAL_EVENT_KINDS,
} from '../lib/scanEvents'
import { api } from '../lib/api'

const POLL_INTERVAL_MS = 3000

const PHASE_LABELS: Record<string, string> = {
  discovery: 'Discovery',
  scanning: 'Scanning',
  findings: 'Findings',
  changes: 'Change detection',
}

const COUNT_LABELS: Record<string, string> = {
  subdomains_discovered: 'subdomains',
  ports_open: 'open ports',
  ports_total: 'ports probed',
  ssl_scanned: 'ssl hosts',
  ssl_issues: 'ssl issues',
  header_scanned: 'header hosts',
  header_issues: 'header issues',
  findings: 'findings',
  changes: 'changes',
}

interface ScanProgressProps {
  scanId: number
  initialStatus: string
  /** Called once when the stream/poll reports a terminal state. */
  onTerminal?: () => void
}

/**
 * Live phase progress for one scan row: subscribes to the SSE
 * `GET /scans/{id}/events` stream (Authorization header only, never a
 * query-string token) and renders phase-by-phase progress (queued →
 * running → per-phase counts → completion/failure, including
 * `phase_unavailable` markers). If the stream cannot connect after the
 * client's own 3 attempts (429/4xx/network), it falls back to polling
 * `GET /scans/{id}` on a short interval.
 */
export function ScanProgress({ scanId, initialStatus, onTerminal }: ScanProgressProps) {
  const [phase, setPhase] = useState<string | null>(null)
  const [counts, setCounts] = useState<Record<string, number> | null>(null)
  const [unavailable, setUnavailable] = useState<string[]>([])
  const [status, setStatus] = useState<string>(initialStatus)
  const [connection, setConnection] = useState<ScanEventConnectionStatus>('connecting')
  // true once a terminal state is known — stops the stream AND polling
  const [done, setDone] = useState(TERMINAL_EVENT_KINDS.has(initialStatus))
  const terminalNotified = useRef(false)
  const unmounted = useRef(false)

  function notifyTerminal() {
    if (terminalNotified.current) return
    terminalNotified.current = true
    onTerminal?.()
  }

  function applyEvent(event: string, data: ScanEventData | null) {
    if (data?.phase) {
      setPhase(data.phase)
      if (!data.status) setStatus('running')
    }
    if (data?.counts && Object.keys(data.counts).length > 0) {
      setCounts(data.counts)
    }
    if (data?.code === 'module_unavailable' && data.phase) {
      setUnavailable((prev) =>
        prev.includes(data.phase as string) ? prev : [...prev, data.phase as string],
      )
    }
    if (data?.status) setStatus(data.status)
    if (event === 'failed') setStatus('failed')
    if (event === 'completed') setStatus('completed')
    if (event === 'skipped') setStatus('skipped')
    if (event === 'failed' || event === 'completed' || event === 'skipped') {
      setDone(true)
      notifyTerminal()
    }
  }

  useEffect(() => {
    unmounted.current = false
    if (done) return
    let aborted = false
    const handle = subscribeScanEvents({
      scanId,
      getToken: () => api.getAccessToken(),
      refresh: () => api.refreshTokenOnce(),
      onEvent: (event: ScanEvent) => {
        if (aborted) return
        applyEvent(event.event, event.data)
      },
      onStatus: (s: ScanEventConnectionStatus) => {
        if (aborted) return
        setConnection(s)
        if (s === 'done') {
          setDone(true)
          notifyTerminal()
        }
      },
    })
    return () => {
      aborted = true
      handle.abort()
    }
  }, [scanId, done])

  // Fallback: the stream client gave up connecting → poll the REST route.
  useEffect(() => {
    if (connection !== 'polling' || done) return
    const timer = window.setInterval(async () => {
      if (unmounted.current) return
      try {
        const scan = await api.getScan(scanId)
        setStatus(scan.status)
        if (TERMINAL_EVENT_KINDS.has(scan.status)) {
          setDone(true)
          notifyTerminal()
        }
      } catch {
        // keep polling; toast-level error handling stays on the page
      }
    }, POLL_INTERVAL_MS)
    return () => window.clearInterval(timer)
  }, [connection, scanId, done])

  useEffect(
    () => () => {
      unmounted.current = true
    },
    [],
  )

  if (connection === 'polling') {
    return (
      <div data-testid="scan-progress" className="text-xs text-gray-500 flex items-center gap-1">
        <Loader2 className="w-3 h-3 animate-spin" />
        <span data-testid="scan-progress-status">{status}</span>
        <span>· polling</span>
        {phase && <span>· {phaseLabel(phase)}</span>}
        <CountsText counts={counts} />
        <UnavailableText unavailable={unavailable} />
      </div>
    )
  }

  return (
    <div
      data-testid="scan-progress"
      className="text-xs text-gray-600 flex items-center gap-1 flex-wrap"
    >
      {!done && <Loader2 className="w-3 h-3 animate-spin text-primary-600" />}
      {done && status === 'completed' && <MinusCircle className="w-3 h-3 text-green-600" />}
      {done && (status === 'failed' || status === 'skipped') && (
        <Ban className="w-3 h-3 text-red-500" />
      )}
      <span data-testid="scan-progress-status">{status}</span>
      {!done && phase && <span>· {phaseLabel(phase)}</span>}
      <CountsText counts={counts} />
      <UnavailableText unavailable={unavailable} />
    </div>
  )
}

function phaseLabel(phase: string): string {
  return PHASE_LABELS[phase] ?? phase
}

function CountsText({ counts }: { counts: Record<string, number> | null }) {
  if (!counts || Object.keys(counts).length === 0) return null
  return (
    <span data-testid="scan-progress-counts">
      {Object.entries(counts)
        .map(([key, value]) => `${value} ${COUNT_LABELS[key] ?? key}`)
        .join(' · ')}
    </span>
  )
}

function UnavailableText({ unavailable }: { unavailable: string[] }) {
  return (
    <>
      {unavailable.map((p) => (
        <span key={p} className="text-amber-700">
          · {p} unavailable
        </span>
      ))}
    </>
  )
}
