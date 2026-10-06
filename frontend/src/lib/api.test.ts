import { describe, expect, it } from 'vitest'
import { AxiosError } from 'axios'

import { API_PREFIX, getApiErrorMessage } from './api'

function axiosErrorWithData(data: unknown): AxiosError {
  const err = new AxiosError('request failed')
  err.response = {
    data,
    status: 400,
    statusText: 'Bad Request',
    headers: {},
    config: {},
  } as AxiosError['response']
  return err
}

describe('api client smoke', () => {
  it('defaults to the versioned API prefix', () => {
    expect(API_PREFIX).toBe('/api/v1')
  })

  it('unwraps the v1 error envelope', () => {
    expect(getApiErrorMessage(axiosErrorWithData({ error: { message: 'boom' } }))).toBe('boom')
  })

  it('falls back for unknown errors', () => {
    expect(getApiErrorMessage(null, 'fallback')).toBe('fallback')
    expect(getApiErrorMessage(new Error('plain'), 'fallback')).toBe('fallback')
  })
})
