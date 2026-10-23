/**
 * Live scan progress client — `fetch` + `ReadableStream`, never EventSource
 * (EventSource cannot send the Authorization header, and we never accept a
 * token in a query string).
 *
 * Behavior:
 * - parses `text/event-stream` frames (id/event/data + `: heartbeat`
 *   comments, which are ignored — heartbeats are just keepalive bytes);
 * - reconnects automatically with exponential backoff and remembers the
 *   last `id:` in a `Last-Event-ID` header, so the server resumes without
 *   duplicates;
 * - on a 401 it refreshes the token ONCE and reconnects (each failed
 *   attempt, 401 included, counts toward the fallback cap);
 * - after `maxFailedConnects` (default 3) failed connection attempts it
 *   reports the `polling` status and STOPS (the caller falls back to
 *   regular polling, e.g. the Scans page);
 * - stops cleanly after a terminal event (completed/failed/skipped);
 * - `abort()` is the unmount path: in-flight fetch is aborted via the
 *   AbortController signal and the body reader is cancelled.
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
  /** Called just before building each request's Authorization header. */
  getToken: () => string | null
  /** Invoked once on the first 401 (token refresh), then reconnect. */
  refresh: () => Promise<void> | void
  onEvent: (event: ScanEvent) => void
  onStatus: (status: ScanEventConnectionStatus) => void
  /** Failed connection attempts before falling back to polling. */
  maxFailedConnects?: number
  initialBackoffMs?: number
  maxBackoffMs?: number
  /** Injectable fetch (tests). Defaults to global fetch. */
  fetchImpl?: typeof fetch
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
  } = options

  const controller = new AbortController()
  let aborted = false
  let refreshed = false // 401-refresh is once-only per subscription
  let failures = 0

  onStatus('connecting')

  function abort() {
    aborted = true
    controller.abort()
  }

  async function run(): Promise<void> {
    let lastEventId: string | undefined
    let backoff = initialBackoffMs
    while (!aborted) {
      let response: Response | null = null
      try {
        response = await fetchImpl(`${API_PREFIX}/scans/${scanId}/events`, {
          headers: {
            Authorization: `Bearer ${getToken() ?? ''}`,
            Accept: 'text/event-stream',
            ...(lastEventId ? { 'Last-Event-ID': lastEventId } : {}),
          },
          signal: controller.signal,
          credentials: 'same-origin',
        })
      } catch {
        // network failure before a response: counts as a failed connect
        response = null
      }

      if (aborted) return

      if (!response || !response.ok) {
        const status = response?.status
        failures += 1
        if (status === 401 && !refreshed) {
          // refresh once and reconnect — the refresh attempt itself still
          // counts as a failed connection toward the fallback cap
          refreshed = true
          try {
            await refresh()
          } catch {
            // refresh failed: keep counting
          }
        }
        if (failures >= maxFailedConnects) {
          onStatus('polling')
          return
        }
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
      if (aborted) return
      if (endedCleanly.terminal) {
        onStatus('done')
        return
      }
      // server closed without a terminal event (max duration, crash, proxy
      // timeout): reconnect and resume from Last-Event-ID
      onStatus('reconnecting')
      await sleep(backoff)
      backoff = Math.min(backoff * 2, maxBackoffMs)
    }
  }

  void run()

  return { abort }
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
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
