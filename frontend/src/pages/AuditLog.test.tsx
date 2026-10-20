// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { describe, expect, it, vi, afterEach } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'

import { AuditLog } from './AuditLog'

vi.mock('../lib/api', () => ({
  api: {
    getAuditLogs: vi.fn().mockResolvedValue({ total: 0, page: 1, page_size: 20, items: [] }),
  },
  getApiErrorMessage: vi.fn(() => 'load failed'),
}))

vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ addToast: vi.fn() }),
}))

import { api } from '../lib/api'

afterEach(cleanup)

const now = Date.now()
const entry = (id: number, action: string, detail: Record<string, unknown>) => ({
  id,
  actor: 'audita',
  action,
  details: detail,
  ip_address: '203.0.113.50',
  created_at: new Date(now - id * 60000).toISOString(),
})

describe('AuditLog page', () => {
  it('renders rows and pagination info', async () => {
    vi.mocked(api.getAuditLogs).mockResolvedValue({
      total: 2,
      page: 1,
      page_size: 20,
      items: [
        entry(2, 'user.login', { method: 'password' }),
        entry(1, 'api_key.created', { name: 'ci' }),
      ],
    })
    render(<AuditLog />)

    expect(await screen.findByText('user.login')).toBeInTheDocument()
    expect(screen.getByText('api_key.created')).toBeInTheDocument()
    expect(screen.getByText('name=ci')).toBeInTheDocument()
    expect(screen.getByText(/2 entries · page 1 of 1/i)).toBeInTheDocument()
    // org-scope hint present
    expect(screen.getByText(/organization managers only/i)).toBeInTheDocument()
  })

  it('shows the empty state when no entries match', async () => {
    vi.mocked(api.getAuditLogs).mockResolvedValue({
      total: 0,
      page: 1,
      page_size: 20,
      items: [],
    })
    render(<AuditLog />)

    expect(
      await screen.findByText(/no audit log entries yet/i),
    ).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('shows an inline error state on API failure', async () => {
    vi.mocked(api.getAuditLogs).mockRejectedValue(new Error('boom'))
    render(<AuditLog />)

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/failed to load the audit log/i)
    expect(alert).toHaveTextContent('load failed')
  })

  it('applies filters and re-queries from page 1', async () => {
    vi.mocked(api.getAuditLogs).mockResolvedValue({
      total: 0,
      page: 1,
      page_size: 20,
      items: [],
    })
    render(<AuditLog />)
    await screen.findByText(/no audit log entries yet/i)

    fireEvent.change(screen.getByLabelText(/filter by action/i), {
      target: { value: 'user.login' },
    })
    fireEvent.change(screen.getByLabelText(/since \(utc\)/i), {
      target: { value: '2026-10-01T10:30' },
    })
    fireEvent.change(screen.getByLabelText(/filter by ip/i), {
      target: { value: '203.0.113.50' },
    })
    fireEvent.click(screen.getByRole('button', { name: /apply/i }))
    await screen.findByText(/no audit log entries match these filters/i)

    // explicit assertion on the last request's params
    const last = vi.mocked(api.getAuditLogs).mock.calls.at(-1)?.[0]
    expect(last).toMatchObject({
      page: 1,
      action: 'user.login',
      ip: '203.0.113.50',
      since: new Date('2026-10-01T10:30Z').toISOString(),
    })
  })
})
