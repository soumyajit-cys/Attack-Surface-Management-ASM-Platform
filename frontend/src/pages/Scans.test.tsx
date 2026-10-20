// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { describe, expect, it, vi, afterEach } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'

import { Scans } from './Scans'

vi.mock('../lib/api', () => ({
  api: {
    getScans: vi.fn().mockResolvedValue({ total: 0, page: 1, page_size: 50, items: [] }),
    listVerifiedDomains: vi.fn().mockResolvedValue({ items: [] }),
  },
  getApiErrorMessage: vi.fn(() => 'load failed'),
}))

vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ addToast: vi.fn() }),
}))

import { api } from '../lib/api'

afterEach(cleanup)

describe('Scans page — unavailable_phases warning', () => {
  it('renders the warning banner when scanner phases are unavailable', async () => {
    vi.mocked(api.getScans).mockResolvedValue({
      total: 0,
      page: 1,
      page_size: 50,
      items: [],
      unavailable_phases: ['ssl', 'header'],
    })
    render(<Scans />)

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/some scan phases did not run/i)
    expect(alert).toHaveTextContent(/ssl, header/)
    // points the operator at the failed-import logs
    expect(alert).toHaveTextContent(/failed imports/i)
  })

  it('renders no warning when every phase is available', async () => {
    vi.mocked(api.getScans).mockResolvedValue({
      total: 0,
      page: 1,
      page_size: 50,
      items: [],
      unavailable_phases: [],
    })
    render(<Scans />)

    await screen.findByText(/no scans found/i)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByTestId('unavailable-phases-warning')).not.toBeInTheDocument()
  })
})
