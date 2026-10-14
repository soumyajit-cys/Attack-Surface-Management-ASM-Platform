// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { describe, expect, it, vi, afterEach } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'

import { RecoveryCodesDisplay } from './RecoveryCodesDisplay'

afterEach(cleanup)

const CODES = Array.from({ length: 10 }, (_, i) => `ABCD${String(i).padStart(12, '0')}`)

describe('RecoveryCodesDisplay (one-time codes)', () => {
  it('renders every code exactly once', () => {
    render(<RecoveryCodesDisplay codes={CODES} />)
    const list = screen.getByRole('list', { name: /recovery codes/i })
    expect(list.children).toHaveLength(10)
    for (const code of CODES) {
      expect(screen.getByText(code)).toBeInTheDocument()
    }
  })

  it('copies all codes to the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    render(<RecoveryCodesDisplay codes={CODES} />)
    fireEvent.click(screen.getByRole('button', { name: /copy all/i }))
    expect(writeText).toHaveBeenCalledWith(CODES.join('\n'))
    expect(await screen.findByRole('button', { name: /copied/i })).toBeInTheDocument()
  })

  it('offers a download with the codes file name', () => {
    const createObjectURL = vi.fn().mockReturnValue('blob:fake')
    const revokeObjectURL = vi.fn()
    globalThis.URL.createObjectURL = createObjectURL
    globalThis.URL.revokeObjectURL = revokeObjectURL
    const clickSpy = vi.fn()
    const realCreate = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation(((tag: string) => {
      const el = realCreate(tag)
      if (tag === 'a') el.click = clickSpy
      return el
    }) as typeof document.createElement)
    render(<RecoveryCodesDisplay codes={CODES} />)
    fireEvent.click(screen.getByRole('button', { name: /download/i }))
    expect(createObjectURL).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalled()
  })
})
