// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen } from '@testing-library/react'

import { ScanProgress } from './ScanProgress'

interface ScanEventData {
  status?: string
  phase?: string
  code?: string
  counts?: Record<string, number>
  started_at?: string | null
  completed_at?: string | null
}

interface FakeEvent {
  id?: string
  event: string
  data: ScanEventData | null
}

type Status = 'connecting' | 'open' | 'reconnecting' | 'polling' | 'done'

const mocked = vi.hoisted(() => {
  const holder = {
    args: null as null | {
      scanId: number
      onEvent: (e: FakeEvent) => void
      onStatus: (s: Status) => void
    },
  }
  return {
    holder,
    abort: vi.fn(),
    refresh: vi.fn(async () => undefined),
    getScan: vi.fn(async () => ({
      scan_id: 42,
      target: 'example.com',
      status: 'running',
      error: null,
    })),
  }
})

vi.mock('../lib/scanEvents', () => ({
  TERMINAL_EVENT_KINDS: new Set(['completed', 'failed', 'skipped']),
  subscribeScanEvents: (args: {
    scanId: number
    onEvent: (e: FakeEvent) => void
    onStatus: (s: Status) => void
  }) => {
    mocked.holder.args = args
    return { abort: mocked.abort }
  },
}))

vi.mock('../lib/api', () => ({
  api: {
    getAccessToken: () => 'access-token',
    refreshTokens: mocked.refresh,
    getScan: mocked.getScan,
  },
  getApiErrorMessage: vi.fn(() => 'load failed'),
}))

beforeEach(() => {
  vi.useFakeTimers()
  mocked.holder.args = null
})

afterEach(() => {
  cleanup()
  mocked.abort.mockClear()
  mocked.getScan.mockClear()
  mocked.refresh.mockClear()
})

function emit(event: string, data: ScanEventData | null, id?: string) {
  act(() => {
    mocked.holder.args?.onEvent({ event, data, id })
  })
}

function emitStatus(s: Status) {
  act(() => {
    mocked.holder.args?.onStatus(s)
  })
}

describe('ScanProgress — live scan progress from a mocked stream', () => {
  it('renders phase progress as events arrive (queued → running → phases with counts → completed)', async () => {
    render(<ScanProgress scanId={42} initialStatus="pending" />)
    expect(mocked.holder.args?.scanId).toBe(42)

    emit('snapshot', { status: 'queued', started_at: null, completed_at: null })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(screen.getByTestId('scan-progress')).toHaveTextContent(/queued/i)

    emit('running', { status: 'running' })
    expect(screen.getByTestId('scan-progress')).toHaveTextContent(/running/i)

    emit('phase_started', { phase: 'discovery' })
    expect(screen.getByTestId('scan-progress')).toHaveTextContent(/discovery/i)

    emit('phase_finished', {
      phase: 'discovery',
      counts: { subdomains_discovered: 7 },
    })
    expect(screen.getByTestId('scan-progress')).toHaveTextContent(/discovery/i)
    expect(screen.getByTestId('scan-progress')).toHaveTextContent('7')

    emit('phase_unavailable', { phase: 'ssl', code: 'module_unavailable' })
    expect(screen.getByTestId('scan-progress')).toHaveTextContent(/ssl unavailable/i)

    emit('completed', { status: 'completed', counts: { findings: 3 } })
    expect(screen.getByTestId('scan-progress')).toHaveTextContent(/completed/i)
  })

  it('falls back to polling when the stream cannot connect 3 times and then polls scan status', async () => {
    render(<ScanProgress scanId={42} initialStatus="running" />)
    emitStatus('polling')
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(screen.getByTestId('scan-progress')).toHaveTextContent(/polling/i)
    const polls = mocked.getScan.mock.calls.length
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(mocked.getScan.mock.calls.length).toBeGreaterThan(polls)
  })

  it('calls onTerminal when the stream reports a terminal event', async () => {
    const onTerminal = vi.fn()
    render(<ScanProgress scanId={42} initialStatus="running" onTerminal={onTerminal} />)
    emit('completed', { status: 'completed', counts: { findings: 0 } })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1)
    })
    expect(onTerminal).toHaveBeenCalled()
    expect(screen.getByTestId('scan-progress')).toHaveTextContent(/completed/i)
  })

  it('unmount aborts the stream (and stops polling)', async () => {
    const { unmount } = render(<ScanProgress scanId={42} initialStatus="running" />)
    unmount()
    expect(mocked.abort).toHaveBeenCalled()
    const polls = mocked.getScan.mock.calls.length
    await act(async () => {
      await vi.advanceTimersByTimeAsync(6001)
    })
    expect(mocked.getScan.mock.calls.length).toBe(polls)
  })
})
