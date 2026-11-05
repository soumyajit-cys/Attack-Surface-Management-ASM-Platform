// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { describe, expect, it, vi, afterEach, beforeEach } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'

import { Settings } from './Settings'

vi.mock('../lib/api', () => ({
  api: {
    listEnrichmentProviders: vi.fn().mockResolvedValue([]),
    upsertEnrichmentProvider: vi.fn().mockResolvedValue({}),
    deleteEnrichmentProvider: vi.fn().mockResolvedValue(undefined),
  },
  getApiErrorMessage: vi.fn(() => 'load failed'),
}))

vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ addToast: vi.fn() }),
}))

vi.mock('../contexts/AuthContext', () => ({
  useAuth: vi.fn(),
}))

import { api } from '../lib/api'
import { useAuth } from '../contexts/AuthContext'

afterEach(cleanup)

function renderSettings(user: { permissions: string[] } | null) {
  vi.mocked(useAuth).mockReturnValue({ user } as any)
  return render(<Settings />)
}

describe('Settings page — enrichment providers (Phase 2.1)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('hides the Providers tab for users without enrichment:manage', () => {
    renderSettings({ permissions: ['scans:read'] })
    expect(screen.queryByRole('tab', { name: /providers/i })).not.toBeInTheDocument()
  })

  it('shows the Providers tab for users with enrichment:manage', () => {
    renderSettings({ permissions: ['enrichment:manage'] })
    expect(screen.getByRole('tab', { name: /providers/i })).toBeInTheDocument()
  })

  it('renders empty state when no providers are configured', async () => {
    renderSettings({ permissions: ['enrichment:manage'] })
    fireEvent.click(screen.getByRole('tab', { name: /providers/i }))
    expect(await screen.findByText('No enrichment providers configured.')).toBeInTheDocument()
  })

  it('renders provider rows with edit and delete actions', async () => {
    vi.mocked(api.listEnrichmentProviders).mockResolvedValue([
      { name: 'shodan', provider_type: 'shodan', has_key: true, is_active: true, created_at: null, updated_at: null },
      { name: 'censys', provider_type: 'censys', has_key: false, is_active: false, created_at: null, updated_at: null },
    ])
    renderSettings({ permissions: ['enrichment:manage'] })
    fireEvent.click(screen.getByRole('tab', { name: /providers/i }))

    await screen.findByText('shodan')
    expect(await screen.findByText(/key set/)).toBeInTheDocument()
    expect(await screen.findByText(/no key/)).toBeInTheDocument()
    expect(screen.getByTestId('provider-edit-shodan')).toBeInTheDocument()
    expect(screen.getByTestId('provider-delete-shodan')).toBeInTheDocument()
  })

  it('add provider submit sends correct payload and clears key from state', async () => {
    vi.mocked(api.listEnrichmentProviders).mockResolvedValue([])
    vi.mocked(api.upsertEnrichmentProvider).mockResolvedValue({
      name: 'shodan',
      provider_type: 'shodan',
      has_key: true,
      is_active: true,
      created_at: null,
      updated_at: null,
    })
    renderSettings({ permissions: ['enrichment:manage'] })
    fireEvent.click(screen.getByRole('tab', { name: /providers/i }))

    fireEvent.change(screen.getByTestId('provider-name-input'), { target: { value: 'shodan' } })
    fireEvent.change(screen.getByTestId('provider-type-input'), { target: { value: 'shodan' } })
    fireEvent.change(screen.getByTestId('provider-key-input'), {
      target: { value: 'super-secret-key' },
    })
    fireEvent.click(screen.getByTestId('provider-ack-checkbox'))
    fireEvent.click(screen.getByTestId('provider-save-button'))

    await vi.waitFor(() => {
      expect(api.upsertEnrichmentProvider).toHaveBeenCalledWith('shodan', {
        provider_type: 'shodan',
        api_key: 'super-secret-key',
        is_active: true,
        acknowledge_data_sharing: true,
      })
    })
  })

  it('requires acknowledge_data_sharing to enable a third-party provider', async () => {
    vi.mocked(api.listEnrichmentProviders).mockResolvedValue([])
    renderSettings({ permissions: ['enrichment:manage'] })
    fireEvent.click(screen.getByRole('tab', { name: /providers/i }))

    fireEvent.change(screen.getByTestId('provider-name-input'), { target: { value: 'shodan' } })
    fireEvent.change(screen.getByTestId('provider-type-input'), { target: { value: 'shodan' } })
    fireEvent.change(screen.getByTestId('provider-key-input'), { target: { value: 'key' } })
    // Do NOT check the acknowledgement box; leave is_active checked (default)
    fireEvent.click(screen.getByTestId('provider-save-button'))

    expect(api.upsertEnrichmentProvider).not.toHaveBeenCalled()
  })

  it('edit provider does not prefill the stored key', async () => {
    vi.mocked(api.listEnrichmentProviders).mockResolvedValue([
      { name: 'shodan', provider_type: 'shodan', has_key: true, is_active: true, created_at: null, updated_at: null },
    ])
    renderSettings({ permissions: ['enrichment:manage'] })
    fireEvent.click(screen.getByRole('tab', { name: /providers/i }))

    await screen.findByText('shodan')
    fireEvent.click(screen.getByTestId('provider-edit-shodan'))

    // The name field is disabled in edit mode; the key field must be empty.
    expect((screen.getByTestId('provider-key-input') as HTMLInputElement).value).toBe('')
    expect(screen.getByTestId('provider-name-input')).toHaveAttribute('disabled')
  })

  it('delete provider calls window.confirm and the API', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(api.listEnrichmentProviders).mockResolvedValue([
      { name: 'shodan', provider_type: 'shodan', has_key: true, is_active: true, created_at: null, updated_at: null },
    ])
    renderSettings({ permissions: ['enrichment:manage'] })
    fireEvent.click(screen.getByRole('tab', { name: /providers/i }))

    await screen.findByText('shodan')
    fireEvent.click(screen.getByTestId('provider-delete-shodan'))

    expect(window.confirm).toHaveBeenCalledWith('Delete provider "shodan"?')
    expect(api.deleteEnrichmentProvider).toHaveBeenCalledWith('shodan')
    vi.spyOn(window, 'confirm').mockRestore()
  })

  it('delete provider does not call API when user cancels confirmation', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    vi.mocked(api.listEnrichmentProviders).mockResolvedValue([
      { name: 'shodan', provider_type: 'shodan', has_key: true, is_active: true, created_at: null, updated_at: null },
    ])
    renderSettings({ permissions: ['enrichment:manage'] })
    fireEvent.click(screen.getByRole('tab', { name: /providers/i }))

    await screen.findByText('shodan')
    fireEvent.click(screen.getByTestId('provider-delete-shodan'))

    expect(api.deleteEnrichmentProvider).not.toHaveBeenCalled()
    vi.spyOn(window, 'confirm').mockRestore()
  })

  it('refresh button reloads providers', async () => {
    vi.mocked(api.listEnrichmentProviders)
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([
        { name: 'crt_sh', provider_type: 'crt_sh', has_key: false, is_active: true },
      ])
    renderSettings({ permissions: ['enrichment:manage'] })
    fireEvent.click(screen.getByRole('tab', { name: /providers/i }))

    expect(await screen.findByText('No enrichment providers configured.')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('providers-refresh'))
    expect(await screen.findByText('crt_sh')).toBeInTheDocument()
  })
})
