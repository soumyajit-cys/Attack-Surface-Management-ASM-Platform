// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { describe, expect, it, vi, afterEach } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import { Findings } from './Findings'

vi.mock('../lib/api', () => ({
  api: {
    getFindings: vi.fn().mockResolvedValue({ total: 0, page: 1, page_size: 20, items: [] }),
  },
  getApiErrorMessage: vi.fn(() => 'load failed'),
}))

vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ addToast: vi.fn() }),
}))

import { api } from '../lib/api'

afterEach(cleanup)

function renderWithRouter(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>)
}

describe('Findings page', () => {
  it('renders empty state when no findings', async () => {
    vi.mocked(api.getFindings).mockResolvedValue({ total: 0, page: 1, page_size: 20, items: [] })
    renderWithRouter(<Findings />)

    expect(await screen.findByText('No findings found')).toBeInTheDocument()
  })

  it('renders email-security findings with remediation text', async () => {
    vi.mocked(api.getFindings).mockResolvedValue({
      total: 2,
      page: 1,
      page_size: 20,
      items: [
        {
          id: 1,
          title: 'SPF record not published',
          severity: 'low',
          category: 'email_security',
          description:
            'No SPF (v=spf1) TXT record found for example.com. Receiving mail servers cannot verify that senders are authorized, enabling email spoofing.',
          recommendation:
            'Publish an SPF TXT record at the domain apex authorizing your legitimate mail sources (e.g. v=spf1 mx -all).',
          confidence: 0.95,
          dedupe_key: 'email_security:spf_missing:example.com',
          asset_id: 1,
          asset_name: 'example.com',
          created_at: '2026-11-07T00:00:00Z',
        },
        {
          id: 2,
          title: 'DMARC record not published',
          severity: 'low',
          category: 'email_security',
          description:
            'No DMARC (v=DMARC1) TXT record found at _dmarc.example.com. Receivers cannot enforce alignment or receive aggregate/forensic reports.',
          recommendation:
            'Publish a DMARC TXT record at _dmarc.example.com starting with p=none;rua=mailto:dmarc-reports@example.com, then progress to p=quarantine and p=reject.',
          confidence: 0.95,
          dedupe_key: 'email_security:dmarc_missing',
          asset_id: 1,
          asset_name: 'example.com',
          created_at: '2026-11-07T00:00:00Z',
        },
      ],
    })
    renderWithRouter(<Findings />)

    await screen.findByText('SPF record not published')
    await screen.findByText('DMARC record not published')
    const emailSecCategories = await screen.findAllByText(/email security/i)
    expect(emailSecCategories.length).toBe(2)
    const badges = await screen.findAllByText('Low')
    expect(badges.length).toBeGreaterThan(0)
  })

  it('displays severity badges for email-security findings', async () => {
    vi.mocked(api.getFindings).mockResolvedValue({
      total: 1,
      page: 1,
      page_size: 20,
      items: [
        {
          id: 1,
          title: 'SPF record not published',
          severity: 'low',
          category: 'email_security',
          description: 'No SPF record found',
          recommendation: 'Publish SPF',
          confidence: 0.95,
          dedupe_key: 'email_security:spf_missing:example.com',
          asset_id: 1,
          asset_name: 'example.com',
          created_at: '2026-11-07T00:00:00Z',
        },
      ],
    })
    renderWithRouter(<Findings />)

    await screen.findByText('SPF record not published')
    const badges = await screen.findAllByText('Low')
    expect(badges.length).toBeGreaterThan(0)
  })

  it('shows confidence in description for email findings', async () => {
    vi.mocked(api.getFindings).mockResolvedValue({
      total: 1,
      page: 1,
      page_size: 20,
      items: [
        {
          id: 1,
          title: 'SPF record not published',
          severity: 'low',
          category: 'email_security',
          description: 'No SPF record found',
          recommendation: 'Publish SPF',
          confidence: 0.95,
          dedupe_key: 'email_security:spf_missing:example.com',
          asset_id: 1,
          asset_name: 'example.com',
          created_at: '2026-11-07T00:00:00Z',
        },
      ],
    })
    renderWithRouter(<Findings />)

    await screen.findByText('SPF record not published')
  })

  it('renders subdomain_takeover findings with remediation text', async () => {
    vi.mocked(api.getFindings).mockResolvedValue({
      total: 2,
      page: 1,
      page_size: 20,
      items: [
        {
          id: 1,
          title: 'Subdomain takeover: www.example.com → GitHub Pages',
          severity: 'high',
          category: 'subdomain_takeover',
          description:
            'www.example.com CNAME chain points to GitHub Pages (www.example.com.github.io), which appears unclaimed.',
          recommendation:
            'Remove the dangling DNS record first. If the service is still needed, re-provision the resource and re-point the CNAME.',
          confidence: 0.85,
          dedupe_key: 'subdomain_takeover:GitHub Pages:www.example.com',
          asset_id: 1,
          asset_name: 'example.com',
          created_at: '2026-11-07T00:00:00Z',
        },
        {
          id: 2,
          title: 'Subdomain takeover: assets.example.com → Heroku',
          severity: 'medium',
          category: 'subdomain_takeover',
          description:
            'assets.example.com CNAME chain points to Heroku (assets.example.com.herokuapp.com), which appears unclaimed.',
          recommendation:
            'Remove the dangling DNS record first. If the service is still needed, re-provision the resource and re-point the CNAME.',
          confidence: 0.6,
          dedupe_key: 'subdomain_takeover:Heroku:assets.example.com',
          asset_id: 1,
          asset_name: 'example.com',
          created_at: '2026-11-07T00:00:00Z',
        },
      ],
    })
    renderWithRouter(<Findings />)

    await screen.findByText(/Subdomain takeover: www.example.com → GitHub Pages/)
    await screen.findByText(/Subdomain takeover: assets.example.com → Heroku/)
    expect(await screen.findAllByText(/Subdomain takeover/)).toHaveLength(2)
    const highBadges = await screen.findAllByText('High')
    expect(highBadges.length).toBeGreaterThan(0)
    const mediumBadges = await screen.findAllByText('Medium')
    expect(mediumBadges.length).toBeGreaterThan(0)
  })

  it('displays remediation text for takeover findings', async () => {
    vi.mocked(api.getFindings).mockResolvedValue({
      total: 1,
      page: 1,
      page_size: 20,
      items: [
        {
          id: 1,
          title: 'Subdomain takeover: www.example.com → GitHub Pages',
          severity: 'high',
          category: 'subdomain_takeover',
          description:
            'www.example.com CNAME chain points to GitHub Pages (www.example.com.github.io), which appears unclaimed.',
          recommendation:
            'Remove the dangling DNS record first. If the service is still needed, re-provision the resource and re-point the CNAME.',
          confidence: 0.85,
          dedupe_key: 'subdomain_takeover:GitHub Pages:www.example.com',
          asset_id: 1,
          asset_name: 'example.com',
          created_at: '2026-11-07T00:00:00Z',
        },
      ],
    })
    renderWithRouter(<Findings />)

    await screen.findByText('Subdomain takeover: www.example.com → GitHub Pages')
    expect(document.body.textContent).toContain(
      'www.example.com CNAME chain points to GitHub Pages',
    )
    expect(document.body.textContent).toContain('which appears unclaimed')
  })
})
