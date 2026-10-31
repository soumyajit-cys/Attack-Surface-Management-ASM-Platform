// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { subscribeScanEvents, type ScanEvent, type ScanEventConnectionStatus } from './scanEvents'

// ── scripted fake fetch: a ReadableStream we control from the test ─────────

class FakeStream {
  controller: ReadableStreamDefaultController<Uint8Array> | null = null
  cancelled = false
  ended = false

  toReadable(): ReadableStream<Uint8Array> {
    return new ReadableStream({
      start: (controller) => {
        this.controller = controller
      },
      cancel: () => {
        this.cancelled = true
      },
    })
  }

  push(text: string) {
    this.controller?.enqueue(new TextEncoder().encode(text))
  }

  end() {
    this.ended = true
    this.controller?.close()
  }
}

interface FakeResponseInit {
  status: number
  stream?: FakeStream
}

function fakeFetchFactory(responses: FakeResponseInit[]) {
  const calls: Array<{ url: string; headers: Record<string, string> }> = []
  const fetchImpl = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const headers: Record<string, string> = {}
    const raw = new Headers(init?.headers)
    raw.forEach((value, key) => {
      headers[key] = value
    })
    calls.push({ url: String(url), headers })
    if (responses.length === 0) {
      throw new TypeError('scripted responses exhausted')
    }
    const item = responses.shift() as FakeResponseInit
    // Emulate real fetch: aborting the request signal tears the body
    // stream down (a pending reader.read() then cannot deliver data).
    const signal = init?.signal as AbortSignal | undefined
    if (signal && item.stream) {
      if (signal.aborted) item.stream.cancelled = true
      signal.addEventListener('abort', () => {
        const stream = item.stream as FakeStream
        stream.cancelled = true
        try {
          stream.controller?.close()
        } catch {
          // already errored/escaped; the reader then sees it
        }
      })
    }
    return {
      ok: item.status >= 200 && item.status < 300,
      status: item.status,
      headers: new Headers({ 'content-type': 'text/event-stream' }),
      body: item.stream ? item.stream.toReadable() : null,
    } as unknown as Response
  })
  return { calls, fetchImpl }
}

const base = {
  scanId: 42,
  getToken: () => 'token-1',
  refresh: vi.fn(async () => undefined),
  fetchTicket: vi.fn(async () => 'ticket-1'),
  onEvent: vi.fn(),
  onStatus: vi.fn(),
  initialBackoffMs: 1,
  maxBackoffMs: 4,
}

beforeEach(() => {
  vi.useFakeTimers()
  base.refresh.mockClear()
  base.fetchTicket.mockClear()
  base.onEvent.mockClear()
  base.onStatus.mockClear()
})

afterEach(() => {
  vi.useRealTimers()
})

async function flush(times = 8) {
  for (let i = 0; i < times; i++) {
    await vi.advanceTimersByTimeAsync(1)
  }
}

describe('subscribeScanEvents — fetch + ReadableStream (never EventSource)', () => {
  it('delivers events in order, ignores comment heartbeats, opens with the run token', async () => {
    const stream = new FakeStream()
    const { calls, fetchImpl } = fakeFetchFactory([{ status: 200, stream }])
    const events: Array<[string, unknown]> = []
    const conn = subscribeScanEvents({
      ...base,
      onEvent: (e: ScanEvent) => events.push([e.event, e.data]),
      fetchImpl: fetchImpl as unknown as typeof fetch,
    })
    await flush()
    stream.push(
      ': heartbeat\n\n' +
        'event: snapshot\ndata: {"status":"queued"}\n\n' +
        'id: 1718-1\nevent: queued\ndata: {"status":"queued"}\n\n',
    )
    await flush(4)
    stream.end()
    await flush(4)
    conn.abort()
    expect(events.map(([e]) => e)).toEqual(['snapshot', 'queued'])
    expect(events[0][1]).toEqual({ status: 'queued' })
    expect(events[1][1]).toEqual({ status: 'queued' })
    expect(calls[0].url.endsWith('/scans/42/events')).toBe(true)
    expect(calls[0].headers['authorization']).toBe('Bearer token-1')
    expect(calls[0].url).not.toContain('token')
    expect(calls[0].headers['last-event-id']).toBeUndefined()
    // a connection that produced events counts as open (failure reset)
    expect(base.onStatus).toHaveBeenCalledWith('open')
  })

  it('reconnect sends Last-Event-ID when the stream ends without a terminal event', async () => {
    const first = new FakeStream()
    const second = new FakeStream()
    const { calls, fetchImpl } = fakeFetchFactory([
      { status: 200, stream: first },
      { status: 200, stream: second },
    ])
    const conn = subscribeScanEvents({ ...base, fetchImpl: fetchImpl as unknown as typeof fetch })
    await flush()
    first.push('id: 1718-2\nevent: running\ndata: {"status":"running"}\n\n')
    await flush(4)
    first.end() // server closed (e.g. max duration), no terminal event
    await flush(24) // reconnect backoff + second attempt
    expect(calls.length).toBeGreaterThanOrEqual(2)
    expect(calls[1].headers['last-event-id']).toBe('1718-2')
    second.end()
    await flush(4)
    conn.abort()
  })

  it('cannot connect 3 times: it falls back to polling and stops retrying', async () => {
    const { fetchImpl } = fakeFetchFactory([{ status: 503 }, { status: 503 }, { status: 503 }])
    const conn = subscribeScanEvents({ ...base, fetchImpl: fetchImpl as unknown as typeof fetch })
    await flush(32)
    conn.abort()
    expect(base.onStatus).toHaveBeenCalledWith('polling')
    expect(fetchImpl).toHaveBeenCalledTimes(3)
  })

  it('abort on unmount: no more fetches and the body stream is cancelled', async () => {
    const stream = new FakeStream()
    const { fetchImpl } = fakeFetchFactory([{ status: 200, stream }])
    const conn = subscribeScanEvents({ ...base, fetchImpl: fetchImpl as unknown as typeof fetch })
    await flush()
    stream.push('event: snapshot\ndata: {"status":"queued"}\n\n')
    await flush(4)
    conn.abort()
    await flush(4)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
    expect(stream.cancelled).toBe(true)
  })

  it('on 401 it refreshes the token once and reconnects', async () => {
    const retry = new FakeStream()
    const { fetchImpl } = fakeFetchFactory([{ status: 401 }, { status: 200, stream: retry }])
    const conn = subscribeScanEvents({ ...base, fetchImpl: fetchImpl as unknown as typeof fetch })
    await flush()
    retry.push('event: snapshot\ndata: {"status":"running"}\n\n')
    await flush(4)
    retry.push('id: 1718-9\nevent: completed\ndata: {"status":"completed"}\n\n')
    await flush(6)
    expect(base.refresh).toHaveBeenCalledTimes(1)
    expect(fetchImpl).toHaveBeenCalledTimes(2)
    expect(base.onStatus).toHaveBeenCalledWith('open')
    expect(base.onStatus).toHaveBeenCalledWith('done')
    conn.abort()
  })

  it('the 401-refresh path is once-only: a second 401 counts as a failure', async () => {
    const { fetchImpl } = fakeFetchFactory([{ status: 401 }, { status: 401 }, { status: 401 }])
    const conn = subscribeScanEvents({ ...base, fetchImpl: fetchImpl as unknown as typeof fetch })
    await flush(32)
    conn.abort()
    expect(base.refresh).toHaveBeenCalledTimes(1)
    expect(fetchImpl).toHaveBeenCalledTimes(3)
    expect(base.onStatus).toHaveBeenCalledWith('polling')
  })

  it('a terminal event closes the loop (no further requests)', async () => {
    const stream = new FakeStream()
    const { fetchImpl } = fakeFetchFactory([{ status: 200, stream }])
    const conn = subscribeScanEvents({ ...base, fetchImpl: fetchImpl as unknown as typeof fetch })
    await flush()
    stream.push('event: snapshot\ndata: {"status":"running"}\n\n')
    await flush(4)
    stream.push('id: 1718-9\nevent: completed\ndata: {"status":"completed"}\n\n')
    await flush(10)
    expect(base.onStatus).toHaveBeenCalledWith('done')
    await flush(40)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
    conn.abort()
  })
})

// ── WebSocket transport (jsdom has no WebSocket, so we inject a fake) ──────

interface MessageEventLike {
  data: string
}

class FakeSocket {
  url: string
  readyState = 1 // OPEN
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEventLike) => void) | null = null
  onclose: (() => void) | null = null
  constructor(url: string) {
    this.url = url
  }
  close() {
    this.readyState = 3 // CLOSED
    if (this.onclose) this.onclose()
  }
}

function wsBase() {
  return {
    ...base,
    maxFailedConnects: 2,
    initialBackoffMs: 1,
    maxBackoffMs: 2,
  }
}

describe('subscribeScanEvents — WebSocket transport', () => {
  afterEach(() => {
    base.refresh.mockClear()
    base.onEvent.mockClear()
    base.onStatus.mockClear()
  })

  it('connects with the token, delivers events, ignores heartbeat comments, and ends on done', async () => {
    const sockets: FakeSocket[] = []
    const FakeSocketImpl = vi.fn((url: string) => {
      const socket = new FakeSocket(url)
      sockets.push(socket)
      return socket
    })
    const events: Array<[string, unknown]> = []
    const statuses: ScanEventConnectionStatus[] = []
    subscribeScanEvents({
      ...wsBase(),
      WebSocketImpl: FakeSocketImpl as unknown as typeof WebSocket,
      onEvent: (e: ScanEvent) => events.push([e.event, e.data]),
      onStatus: (s: ScanEventConnectionStatus) => statuses.push(s),
    })
    await flush(4)
    expect(sockets).toHaveLength(1)
    expect(sockets[0].url).toContain('/scans/42/ws')
    expect(sockets[0].url).toContain('ticket=ticket-1')
    expect(sockets[0].url).not.toContain('token')
    expect(sockets[0].url).not.toContain('lastEventId')
    // the socket is open
    sockets[0].onopen!()
    await flush(4)
    expect(statuses).toContain('open')
    // a heartbeat comment carries no event
    if (sockets[0].onmessage) sockets[0].onmessage({ data: ': heartbeat\n\n' })
    await flush(4)
    expect(events).toHaveLength(0)
    // real events are delivered
    if (sockets[0].onmessage)
      sockets[0].onmessage({
        data: 'event: snapshot\ndata: {"status":"queued"}\n\n',
      })
    await flush(4)
    if (sockets[0].onmessage)
      sockets[0].onmessage({
        data: 'id: 1718-1\nevent: queued\ndata: {"status":"queued"}\n\n',
      })
    await flush(4)
    expect(events.map(([e]) => e)).toEqual(['snapshot', 'queued'])
    // a terminal event ends the stream with `done`
    if (sockets[0].onmessage)
      sockets[0].onmessage({
        data: 'event: completed\ndata: {"status":"completed"}\n\n',
      })
    await flush(4)
    expect(statuses).toContain('done')
    expect(events.map(([e]) => e).includes('completed')).toBe(true)
  })

  it('a terminal event stops delivery and reports done (no further events)', async () => {
    const sockets: FakeSocket[] = []
    const FakeSocketImpl = vi.fn((url: string) => {
      const socket = new FakeSocket(url)
      sockets.push(socket)
      return socket
    })
    const events: ScanEvent[] = []
    const statuses: ScanEventConnectionStatus[] = []
    subscribeScanEvents({
      ...wsBase(),
      WebSocketImpl: FakeSocketImpl as unknown as typeof WebSocket,
      onEvent: (e) => events.push(e),
      onStatus: (s) => statuses.push(s),
    })
    await flush(4)
    sockets[0].onopen!()
    await flush(4)
    if (sockets[0].onmessage)
      sockets[0].onmessage({
        data: 'event: failed\ndata: {"status":"failed"}\n\n',
      })
    await flush(4)
    expect(statuses).toContain('done')
    // nothing after terminal
    expect(events.map((e) => e.event)).toEqual(['failed'])
  })

  it('websocket failure falls through to SSE, then to polling when both fail', async () => {
    const sockets: FakeSocket[] = []
    const FakeSocketImpl = vi.fn((url: string) => {
      const socket = new FakeSocket(url)
      sockets.push(socket)
      return socket
    })
    const fetchImpl = vi.fn(async () => {
      throw new Error('down')
    })
    const statuses: ScanEventConnectionStatus[] = []
    subscribeScanEvents({
      ...wsBase(),
      maxFailedConnects: 1,
      WebSocketImpl: FakeSocketImpl as unknown as typeof WebSocket,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      onEvent: vi.fn(),
      onStatus: (s: ScanEventConnectionStatus) => statuses.push(s),
    })
    await flush(4)
    expect(sockets).toHaveLength(1)
    // the websocket transport gives up immediately
    sockets[0].close()
    await flush(20)
    // both real-time transports failed → polling
    expect(statuses).toContain('polling')
    // SSE was attempted after websocket gave up
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })
})
