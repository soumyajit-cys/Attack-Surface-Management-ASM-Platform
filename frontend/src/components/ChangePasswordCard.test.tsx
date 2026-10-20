// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { describe, expect, it, vi, afterEach } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { AxiosError, AxiosHeaders } from 'axios'

import { ChangePasswordCard } from './ChangePasswordCard'

vi.mock('../lib/api', () => ({
  api: { changePassword: vi.fn().mockResolvedValue({ message: 'Password changed' }) },
  getApiErrorMessage: vi.fn(() => 'Something went wrong'),
}))
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ addToast: vi.fn() }),
}))

import { api, getApiErrorCode, getApiErrorMessage } from '../lib/api'

afterEach(cleanup)

function envelopeError(status: number, code: string, message: string): unknown {
  // Shape-faithful AxiosError: getApiErrorCode/getApiErrorMessage read the
  // v1 envelope on error.response.data.
  const err = new AxiosError(message, String(status), undefined, undefined, {
    status,
    statusText: '',
    headers: new AxiosHeaders(),
    config: { headers: new AxiosHeaders() },
    data: { error: { code, message } },
  })
  vi.mocked(getApiErrorCode).mockImplementation((e) =>
    axiosIsEnvelope(e) ? code : undefined,
  )
  vi.mocked(getApiErrorMessage).mockImplementation((e) =>
    axiosIsEnvelope(e) ? message : 'Something went wrong',
  )
  return err

  function axiosIsEnvelope(e: unknown): boolean {
    return e === err
  }
}

async function fill(label: RegExp, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } })
}

describe('ChangePasswordCard', () => {
  it('hides the 2FA field when 2FA is not enabled', () => {
    render(<ChangePasswordCard totpEnabled={false} />)
    expect(screen.getByLabelText(/current password/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/new password/i)).toBeInTheDocument()
    expect(
      screen.queryByLabelText(/authenticator or recovery code/i),
    ).not.toBeInTheDocument()
  })

  it('shows the required 2FA field when 2FA is enabled', async () => {
    render(<ChangePasswordCard totpEnabled={true} />)
    const codeInput = screen.getByLabelText(/authenticator or recovery code/i)
    expect(codeInput).toBeRequired()

    await fill(/current password/i, 'password123')
    await fill(/new password/i, 'brandnewpass1')
    await fill(/confirm new password/i, 'brandnewpass1')
    fireEvent.change(codeInput, { target: { value: '654321' } })
    fireEvent.click(screen.getByRole('button', { name: /update password/i }))

    await waitFor(() => expect(api.changePassword).toHaveBeenCalled())
    expect(vi.mocked(api.changePassword)).toHaveBeenCalledWith(
      expect.objectContaining({
        current_password: 'password123',
        new_password: 'brandnewpass1',
        code: '654321',
      }),
    )
    // everything cleared after success
    expect(screen.getByLabelText(/current password/i)).toHaveValue('')
    expect(screen.getByLabelText(/authenticator or recovery code/i)).toHaveValue('')
  })

  it('omits the code field from the payload when 2FA is off', async () => {
    render(<ChangePasswordCard totpEnabled={false} />)
    await fill(/current password/i, 'password123')
    await fill(/new password/i, 'brandnewpass1')
    await fill(/confirm new password/i, 'brandnewpass1')
    fireEvent.click(screen.getByRole('button', { name: /update password/i }))

    await waitFor(() => expect(api.changePassword).toHaveBeenCalled())
    const payload = vi.mocked(api.changePassword).mock.calls[0][0]
    expect(payload).not.toHaveProperty('code')
  })

  it('blocks submission client-side when confirm mismatches', async () => {
    render(<ChangePasswordCard totpEnabled={false} />)
    await fill(/current password/i, 'password123')
    await fill(/new password/i, 'brandnewpass1')
    await fill(/confirm new password/i, 'different99')
    fireEvent.click(screen.getByRole('button', { name: /update password/i }))

    expect(api.changePassword).not.toHaveBeenCalled()
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /passwords do not match/i,
    )
  })

  it('renders the password_reuse error inline', async () => {
    vi.mocked(api.changePassword).mockRejectedValueOnce(
      envelopeError(400, 'password_reuse', 'New password must differ from the current password'),
    )
    render(<ChangePasswordCard totpEnabled={false} />)
    await fill(/current password/i, 'password123')
    await fill(/new password/i, 'password123')
    await fill(/confirm new password/i, 'password123')
    fireEvent.click(screen.getByRole('button', { name: /update password/i }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/new password rejected/i)
    expect(alert).toHaveTextContent(/must differ from the current password/i)
  })

  it('renders the 401 lockout error state', async () => {
    vi.mocked(api.changePassword).mockRejectedValueOnce(
      envelopeError(401, 'invalid_credentials', 'Invalid credentials'),
    )
    render(<ChangePasswordCard totpEnabled={false} />)
    await fill(/current password/i, 'wrongpass1')
    await fill(/new password/i, 'brandnewpass1')
    await fill(/confirm new password/i, 'brandnewpass1')
    fireEvent.click(screen.getByRole('button', { name: /update password/i }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/incorrect current password/i)
    // explicit lockout hint — the 401 shares lockout counters with login
    expect(alert).toHaveTextContent(/lock the account or ip temporarily/i)
  })
})
