// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from 'vitest'
import { AxiosAdapter, AxiosError, AxiosResponse, InternalAxiosRequestConfig } from 'axios'

import {
  API_PREFIX,
  api,
  getApiErrorMessage,
  getStepUpRequiredHandler,
  setStepUpRequiredHandler,
} from './api'

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

type Plan = { status: number; data?: unknown }

/** Swap the api client's transport adapter for a scripted fake. */
function withAdapter(script: (path: string) => Plan, calls: string[]): { restore: () => void } {
  const client = (
    api as unknown as {
      client: { defaults: { adapter?: AxiosAdapter } }
    }
  ).client
  const previous = client.defaults.adapter
  client.defaults.adapter = (async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
    const path = config.url ?? ''
    calls.push(path)
    const plan = script(path) ?? { status: 200, data: { ok: true } }
    const response = {
      data: plan.data ?? {},
      status: plan.status,
      statusText: '',
      headers: {},
      config,
    } as AxiosResponse
    if (plan.status >= 400) {
      // The full internal config (with axios's transform/adapter
      // functions) stays on the error so the retry chain keeps request
      // identity; tests must catch raw AxiosErrors and assert via
      // toMatchObject/expect(...).toBeNull() so function-carrying
      // payloads never escape into vitest's strict-clone task transport.
      throw new AxiosError('failed', 'ERR_BAD_REQUEST', config, {}, response)
    }
    return response
  }) as AxiosAdapter
  return { restore: () => void (client.defaults.adapter = previous) }
}

describe('step-up retry integration', () => {
  afterEach(() => {
    setStepUpRequiredHandler(null)
    vi.restoreAllMocks()
  })

  it('retries the original request once after a successful step-up', async () => {
    const calls: string[] = []
    let sensitiveCalls = 0
    const state = withAdapter((path) => {
      if (path === '/organizations/2fa-requirement') {
        sensitiveCalls += 1
        if (sensitiveCalls === 1) {
          return {
            status: 403,
            data: { error: { code: 'step_up_required', message: 'no' } },
          }
        }
        return { status: 200, data: { require_2fa: true } }
      }
      if (path === '/auth/step-up') {
        return { status: 200, data: { message: 'Step-up verified' } }
      }
      return { status: 200 }
    }, calls)
    // A real handler like the one StepUpDialog registers.
    setStepUpRequiredHandler(async () => {
      await api.stepUp('password123')
    })

    const result = await api.setRequire2fa(true)

    expect(result).toEqual({ require_2fa: true })
    expect(sensitiveCalls).toBe(2)
    expect(calls).toEqual([
      '/organizations/2fa-requirement',
      '/auth/step-up',
      '/organizations/2fa-requirement',
    ])
    state.restore()
  })

  it('reopens the dialog when the access token rotates between step-up and the protected action', async () => {
    // The step-up marker is server-side, bound to the access jti
    // presented at grant time. When the api client refreshes the token
    // (new jti) before the retry reaches the server, the backend answers
    // 403 step_up_required again: the dialog REOPENS for a fresh
    // re-verification instead of surfacing an opaque error. Bounded by
    // STEPUP_MAX_RETRIES per original request so it can never loop.
    const calls: string[] = []
    let protectedCalls = 0
    const state = withAdapter((path) => {
      if (path === '/organizations/2fa-requirement') {
        protectedCalls += 1
        if (protectedCalls <= 2) {
          return {
            status: 403,
            data: { error: { code: 'step_up_required', message: 'no' } },
          }
        }
        return { status: 200, data: { require_2fa: true } }
      }
      if (path === '/auth/step-up') {
        return { status: 200, data: { message: 'Step-up verified' } }
      }
      return { status: 200 }
    }, calls)
    let dialogOpens = 0
    setStepUpRequiredHandler(async () => {
      dialogOpens += 1
      await api.stepUp('password123')
    })

    // Catch raw AxiosErrors at the boundary: their config carries axios
    // functions, which vitest would try to structured-clone into the
    // main thread inside a failing task update (DataCloneError). The
    // assertions below then reduce the failure to a plain string.
    let thrown: unknown = null
    let result: unknown
    try {
      result = await api.setRequire2fa(true)
    } catch (err) {
      thrown = err
    }

    expect(thrown).toBeNull()
    expect(result).toEqual({ require_2fa: true })
    // 403 -> verify -> 403 (token rotated) -> verify again -> 200.
    expect(dialogOpens).toBe(2)
    expect(protectedCalls).toBe(3)
    expect(calls).toEqual([
      '/organizations/2fa-requirement',
      '/auth/step-up',
      '/organizations/2fa-requirement',
      '/auth/step-up',
      '/organizations/2fa-requirement',
    ])
    state.restore()
  })

  it('stops reopening the dialog after the retry bound and surfaces the error', async () => {
    const calls: string[] = []
    let protectedCalls = 0
    const state = withAdapter((path) => {
      if (path === '/organizations/2fa-requirement') {
        protectedCalls += 1
        return {
          status: 403,
          data: { error: { code: 'step_up_required', message: 'no' } },
        }
      }
      if (path === '/auth/step-up') {
        return { status: 200, data: { message: 'Step-up verified' } }
      }
      return { status: 200 }
    }, calls)
    let dialogOpens = 0
    setStepUpRequiredHandler(async () => {
      dialogOpens += 1
      await api.stepUp('password123')
    })

    await expect(api.setRequire2fa(true)).rejects.toMatchObject({
      response: { status: 403 },
    })
    // Initial + STEPUP_MAX_RETRIES(3) attempts, then the error surfaces.
    expect(protectedCalls).toBe(4)
    expect(dialogOpens).toBe(3)
    state.restore()
  })

  it('surfaces 403 step_up_required untouched without a handler', async () => {
    const calls: string[] = []
    const state = withAdapter(
      () => ({
        status: 403,
        data: { error: { code: 'step_up_required', message: 'no' } },
      }),
      calls,
    )
    setStepUpRequiredHandler(null)
    expect(getStepUpRequiredHandler()).toBeNull()

    await expect(api.setRequire2fa(true)).rejects.toMatchObject({
      response: { status: 403 },
    })
    expect(calls).toEqual(['/organizations/2fa-requirement'])
    state.restore()
  })
})
