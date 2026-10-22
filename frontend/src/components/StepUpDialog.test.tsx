// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom/vitest'

import { getStepUpRequiredHandler, setStepUpRequiredHandler } from '../lib/api'
import StepUpDialog from './StepUpDialog'

// The dialog owns the global handler registration; tests drive it
// through the registration accessors exactly as the api client does.
vi.mock('../lib/api', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../lib/api')>()
  return {
    ...mod,
    api: {
      ...mod.api,
      stepUp: vi.fn().mockResolvedValue({ message: 'Step-up verified' }),
    },
    getApiErrorMessage: vi.fn().mockReturnValue('Invalid credentials'),
  }
})

afterEach(() => {
  cleanup()
  setStepUpRequiredHandler(null)
  vi.resetAllMocks()
})

describe('StepUpDialog', () => {
  it('registers a handler on mount and clears it on unmount', () => {
    const { unmount } = render(<StepUpDialog />)
    expect(getStepUpRequiredHandler()).toBeTypeOf('function')
    expect(screen.queryByText("Confirm it's you")).not.toBeInTheDocument()
    unmount()
    expect(getStepUpRequiredHandler()).toBeNull()
  })

  it('opens on the handler call and resolves after a successful step-up', async () => {
    const { api } = await import('../lib/api')
    const stepUp = vi.mocked(api.stepUp)
    stepUp.mockResolvedValue({ message: 'Step-up verified' })

    render(<StepUpDialog />)
    const handler = getStepUpRequiredHandler()!
    const pending = handler()
    // Dialog opened when the handler was invoked.
    expect(await screen.findByText("Confirm it's you")).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Current password'), {
      target: { value: 'password123' },
    })
    fireEvent.click(screen.getByRole('button', { name: /verify/i }))

    await expect(pending).resolves.toBeUndefined()
    await waitFor(() => {
      expect(stepUp).toHaveBeenCalledWith('password123', undefined)
    })
    expect(screen.queryByText("Confirm it's you")).not.toBeInTheDocument()
  })

  it('includes the 2FA code in the payload when entered', async () => {
    const { api } = await import('../lib/api')
    const stepUp = vi.mocked(api.stepUp)
    stepUp.mockResolvedValue({ message: 'Step-up verified' })

    render(<StepUpDialog />)
    const pending = getStepUpRequiredHandler()!()
    await screen.findByText("Confirm it's you")
    fireEvent.change(screen.getByLabelText('Current password'), {
      target: { value: 'password123' },
    })
    fireEvent.change(screen.getByLabelText(/2FA code/), {
      target: { value: '123456' },
    })
    fireEvent.click(screen.getByRole('button', { name: /verify/i }))

    await expect(pending).resolves.toBeUndefined()
    await waitFor(() => {
      expect(stepUp).toHaveBeenCalledWith('password123', '123456')
    })
  })

  it('shows an error and only rejects when cancelled', async () => {
    const { api } = await import('../lib/api')
    const stepUp = vi.mocked(api.stepUp)
    stepUp.mockRejectedValueOnce(new Error('wrong password'))

    render(<StepUpDialog />)
    let settled = false
    const pending = getStepUpRequiredHandler()!()
    pending.finally(() => {
      settled = true
    })
    await screen.findByText("Confirm it's you")

    fireEvent.change(screen.getByLabelText('Current password'), {
      target: { value: 'wrong-pass' },
    })
    fireEvent.click(screen.getByRole('button', { name: /verify/i }))

    await screen.findByRole('alert')
    expect(screen.getByText('Invalid credentials')).toBeInTheDocument()
    expect(screen.getByText("Confirm it's you")).toBeInTheDocument()
    await waitFor(() => expect(stepUp).toHaveBeenCalled())
    expect(settled).toBe(false) // request still pending until the user decides

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    await expect(pending).rejects.toThrow('Step-up cancelled')
    expect(screen.queryByText("Confirm it's you")).not.toBeInTheDocument()
  })

  it('cannot open twice concurrently without resolving the first', async () => {
    render(<StepUpDialog />)
    const handler = getStepUpRequiredHandler()!
    void handler()
    expect(screen.getByText("Confirm it's you")).toBeInTheDocument()
    // A second step-up demand reuses the same open dialog.
    expect(() => handler()).not.toThrow()
  })
})
