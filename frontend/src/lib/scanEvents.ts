/**
 * Live scan progress client.
 *
 * Transports, tried in order:
 *  1. WebSocket  `GET /api/v1/scans/{id}/ws`  (authenticated via ``?token=``
 *     because browsers cannot set custom WebSocket headers; the backend also
 *     accepts an ``Authorization`` header for non-browser clients).
 *  2. Server-Sent Events ``GET /api/v1/scans/{id}/events`` (fetch + ReadableStream).
 *  3. Polling fallback ``GET /scans/{id}`` (handled by the caller, ScanProgress,
 *     which is notified via ``onStatus('polling')``).
 *
 * Every transport is authenticated, tenant-scoped and org-checked by the
 * backend; a token in a query string is the WebSocket fallback only and is
 * validated identically to a bearer header.
 *
 * Behavior:
 * - parses `text/event-stream`-style frames (id/event/data + `: heartbeat`
 *   comments, which are ignored — heartbeats are keepalive bytes sent by the
 *   server);
 * - reconnects automatically with exponential backoff and remembers the last
 *   `id:` in a `Last-Event-ID` query parameter, so the server resumes without
 *   duplicates;
 * - on a 401 it refreshes the token ONCE and reconnects;
 * - after `maxFailedConnects` (default 3) failed connection attempts it
 *   reports the `polling` status and STOPS (the caller falls back to
 *   regular polling);
 * - stops cleanly after a terminal event (completed/failed/skipped);
 * - `abort()` is the unmount path: in-flight fetch/ws is aborted and the
 *   body reader / socket is closed.
 */
import { API_PREFIX } from './api'

export interface ScanEventData {
  status?: string
  phase?: string
  code?: string
  counts?: Record<string, number>
  started_at?: string | null
  completed_at?: string | null
}

export interface ScanEvent {
  id?: string
  event: string
  data: ScanEventData | null
}

export type ScanEventConnectionStatus = 'connecting' | 'open' | 'reconnecting' | 'polling' | 'done'

export const TERMINAL_EVENT_KINDS = new Set(['completed', 'failed', 'skipped'])

export interface ScanEventOptions {
  scanId: number
  /** Called just before building each request's Authorization header / ws token. */
  getToken: () => string | null
  /** Invoked once on the first 401 (token refresh), then reconnect. */
  refresh: () => Promise<void> | void
  onEvent: (event: ScanEvent) => void
  onStatus: (status: ScanEventConnectionStatus) => void
  /** Failed connection attempts before falling back to the next transport / polling. */
  maxFailedConnects?: number
  initialBackoffMs?: number
  maxBackoffMs?: number
  /** Injectable fetch (tests). Defaults to global fetch. */
  fetchImpl?: typeof fetch
  /** Injectable WebSocket constructor (tests). Defaults to the global one. */
  WebSocketImpl?: typeof WebSocket
}

export interface ScanEventConnection {
  abort: () => void
}

/** Parse one `text/event-stream` block (between blank lines). */
export function parseSseBlock(block: string): ScanEvent | null {
  const lines = block.split('\n')
  let id: string | undefined
  let event: string | undefined
  const data: string[] = []
  let hasComment = false
  for (const line of lines) {
    if (line.startsWith(':')) {
      hasComment = true
    } else if (line.startsWith('id:')) {
      id = line.slice(3).trim()
    } else if (line.startsWith('event:')) {
      event = line.slice(6).trim()
    } else if (line.startsWith('data:')) {
      data.push(line.slice(5).trim())
    }
  }
  if (event === undefined && data.length === 0) return null
  let parsed: ScanEventData | null = null
  if (data.length > 0) {
    try {
      parsed = JSON.parse(data.join('\n')) as ScanEventData
    } catch {
      parsed = null
    }
  }
  if (event === undefined && !parsed) {
    // comment-only block (heartbeat) carries nothing
    return hasComment ? null : null
  }
  return { id, event: event ?? 'message', data: parsed }
}

/** Result of running one transport: whether it reached a terminal event. */
type TransportOutcome = 'terminal' | 'polling' | 'aborted'

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

/** Whether a WebSocket implementation is available to use. */
function webSocketAvailable(WebSocketImpl?: typeof WebSocket): boolean {
  return Boolean(WebSocketImpl ?? (typeof globalThis !== 'undefined' && globalThis.WebSocket))
}

/**
 * Run one WebSocket transport session. Resolves:
 *  - 'terminal' when a terminal event was delivered (caller stops),
 *  - 'polling' when this transport gave up (caller tries the next transport),
 *  - 'aborted' when the caller unmounted.
 */
async function runWebSocket({
  scanId,
  getToken,
  onEvent,
  onStatus,
  maxFailedConnects,
  initialBackoffMs,
  maxBackoffMs,
  WebSocketImpl,
  signal,
}: {
  scanId: number
  getToken: () => string | null
  onEvent: (event: ScanEvent) => void
  onStatus: (status: ScanEventConnectionStatus) => void
  maxFailedConnects: number
  initialBackoffMs: number
  maxBackoffMs: number
  WebSocketImpl?: typeof WebSocket
  signal: AbortSignal
}): Promise<TransportOutcome> {
  const Ws = WebSocketImpl ?? globalThis.WebSocket
  let lastEventId: string | undefined
  let failures = 0
  let backoff = initialBackoffMs
  let aborted = false
  let outcome: TransportOutcome | null = null
  let settle!: () => void
  const settled = new Promise<void>((resolve) => {
    settle = resolve
  })

  signal.addEventListener(
    'abort',
    () => {
      aborted = true
      settle()
    },
    { once: true },
  )

  const finish = (next: TransportOutcome) => {
    if (outcome === null) {
      outcome = next
      settle()
    }
    return outcome
  }

  while (!aborted && outcome === null) {
    const token = getToken()
    if (!token) {
      // No credentials: nothing to authenticate with; hand off to polling.
      return 'polling'
    }
    const qs = [
      `token=${encodeURIComponent(token)}`,
      lastEventId ? `lastEventId=${encodeURIComponent(lastEventId)}` : '',
    ]
      .filter(Boolean)
      .join('&')
    const url = `${API_PREFIX}/scans/${scanId}/ws?${qs}`

    onStatus('connecting')
    let ws: WebSocket
    try {
      ws = new Ws(url)
    } catch {
      failures += 1
      if (failures >= maxFailedConnects) {
        return finish('polling')
      }
      onStatus('reconnecting')
      await sleep(backoff)
      backoff = Math.min(backoff * 2, maxBackoffMs)
      continue
    }

    ws.onopen = () => {
      onStatus('open')
      failures = 0
      backoff = initialBackoffMs
    }
    ws.onmessage = (event: MessageEvent) => {
      const block = typeof event.data === 'string' ? event.data : String(event.data)
      const parsed = parseSseBlock(block)
      if (!parsed) return
      if (parsed.id) lastEventId = parsed.id
      onEvent(parsed)
      if (parsed.event && TERMINAL_EVENT_KINDS.has(parsed.event)) {
        finish('terminal')
      }
    }
    ws.onerror = () => {
      // Transport errors are counted via onclose, which always fires next.
    }
    ws.onclose = () => {
      if (aborted || outcome !== null) {
        // Already finalized (terminal / aborted); nothing more to do.
        return
      }
      failures += 1
      if (failures >= maxFailedConnects) {
        finish('polling')
        return
      }
      onStatus('reconnecting')
      settle() // let the loop recreate the socket
    }

    // Wait for this session to settle (terminal, transport failure, or abort).
    await settled
  }

  if (aborted) return 'aborted'
  return outcome ?? 'polling'
}

/**
 * Run one Server-Sent Events session (the pre-existing fetch transport).
 * Resolves 'terminal' | 'polling' | 'aborted', same contract as runWebSocket.
 */
async function runSse({
  scanId,
  getToken,
  refresh,
  onEvent,
  onStatus,
  maxFailedConnects,
  initialBackoffMs,
  maxBackoffMs,
  fetchImpl,
  signal,
}: {
  scanId: number
  getToken: () => string | null
  refresh: () => Promise<void> | void
  onEvent: (event: ScanEvent) => void
  onStatus: (status: ScanEventConnectionStatus) => void
  maxFailedConnects: number
  initialBackoffMs: number
  maxBackoffMs: number
  fetchImpl: typeof fetch
  signal: AbortSignal
}): Promise<TransportOutcome> {
  let lastEventId: string | undefined
  let refreshed = false
  let failures = 0
  let backoff = initialBackoffMs
  let aborted = false

  signal.addEventListener(
    'abort',
    () => {
      aborted = true
    },
    { once: true },
  )

  while (!aborted) {
    let response: Response | null = null
    try {
      response = await fetchImpl(`${API_PREFIX}/scans/${scanId}/events`, {
        headers: {
          Authorization: `Bearer ${getToken() ?? ''}`,
          Accept: 'text/event-stream',
          ...(lastEventId ? { 'Last-Event-ID': lastEventId } : {}),
        },
        signal,
        credentials: 'same-origin',
      })
    } catch {
      response = null
    }

    if (aborted) return 'aborted'

    if (!response || !response.ok) {
      const status = response?.status
      failures += 1
      if (status === 401 && !refreshed) {
        refreshed = true
        try {
          await refresh()
        } catch {
          // refresh failed: keep counting
        }
      }
      if (failures >= maxFailedConnects) return 'polling'
      onStatus('reconnecting')
      await sleep(backoff)
      backoff = Math.min(backoff * 2, maxBackoffMs)
      continue
    }

    // connection open: read the stream
    onStatus('open')
    failures = 0
    backoff = initialBackoffMs
    const endedCleanly = await readStream(response, (event) => {
      if (event.id) lastEventId = event.id
      onEvent(event)
      if (event.event && TERMINAL_EVENT_KINDS.has(event.event)) {
        return true // caller asks to stop
      }
      return false
    })
    if (aborted) return 'aborted'
    if (endedCleanly.terminal) {
      return 'terminal'
    }
    // server closed without a terminal event: reconnect and resume
    onStatus('reconnecting')
    await sleep(backoff)
    backoff = Math.min(backoff * 2, maxBackoffMs)
  }
  return 'polling'
}

async function readStream(
  response: Response,
  onEvent: (event: ScanEvent) => boolean, // returns true to stop
): Promise<{ terminal: boolean }> {
  if (!response.body) return { terminal: false }
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let terminal = false
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let separator = buffer.indexOf('\n\n')
      while (separator !== -1) {
        const block = buffer.slice(0, separator)
        buffer = buffer.slice(separator + 2)
        const event = parseSseBlock(block)
        if (event && onEvent(event)) {
          terminal = true
          break
        }
        separator = buffer.indexOf('\n\n')
      }
      if (terminal) break
    }
  } catch {
    // reader error or abort — handled by the connection loop
  } finally {
    try {
      reader.cancel()
    } catch {
      // already released
    }
  }
  return { terminal }
}

export function subscribeScanEvents(options: ScanEventOptions): ScanEventConnection {
  const {
    scanId,
    getToken,
    refresh,
    onEvent,
    onStatus,
    maxFailedConnects = 3,
    initialBackoffMs = 500,
    maxBackoffMs = 5000,
    fetchImpl = fetch,
    WebSocketImpl,
  } = options

  const controller = new AbortController()
  let aborted = false

  onStatus('connecting')

  function abort() {
    aborted = true
    controller.abort()
  }

  void (async () => {
    // 1. WebSocket (preferred real-time transport).
    if (webSocketAvailable(WebSocketImpl)) {
      const outcome = await runWebSocket({
        scanId,
        getToken,
        onEvent,
        onStatus,
        maxFailedConnects,
        initialBackoffMs,
        maxBackoffMs,
        WebSocketImpl,
        signal: controller.signal,
      })
      if (outcome === 'terminal') {
        if (!aborted) onStatus('done')
        return
      }
      if (aborted) return
    }
    // 2. Server-Sent Events fallback (only reached when WebSocket was
    // unavailable or gave up; keeps a real-time fallback before polling).
    const sseOutcome = await runSse({
      scanId,
      getToken,
      refresh,
      onEvent,
      onStatus,
      maxFailedConnects,
      initialBackoffMs,
      maxBackoffMs,
      fetchImpl,
      signal: controller.signal,
    })
    if (sseOutcome === 'terminal') {
      if (!aborted) onStatus('done')
      return
    }
    if (aborted) return
    // 3. All real-time transports gave up: the caller polls GET /scans/{id}.
    onStatus('polling')
  })()

  return { abort }
}
