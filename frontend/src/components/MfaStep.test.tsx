// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { describe, expect, it, vi, afterEach } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'

import { MfaStep } from './MfaStep'

afterEach(cleanup)

describe('MfaStep (login 2FA step)', () => {
  it('submits the trimmed 6-digit code', async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined)
    render(<MfaStep onSubmit={onSubmit} />)
    fireEvent.change(screen.getByLabelText(/authenticator code/i), {
      target: { value: ' 123456 ' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^verify$/i }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('123456'))
  })

  it('toggles to the recovery-code field', () => {
    render(<MfaStep onSubmit={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: /recovery code instead/i }))
    expect(screen.getByLabelText(/recovery code/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /authenticator app instead/i }))
    expect(screen.getByLabelText(/authenticator code/i)).toBeInTheDocument()
  })

  it('shows an alert on rejection', async () => {
    render(<MfaStep onSubmit={vi.fn().mockRejectedValue(new Error('no'))} />)
    fireEvent.change(screen.getByLabelText(/authenticator code/i), {
      target: { value: '000000' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^verify$/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid code/i)
  })
})
