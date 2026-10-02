/**
 * Tests for the API client's token handling. These assert the security
 * properties the design depends on, not implementation trivia.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import MockAdapter from 'axios-mock-adapter'
import axios from 'axios'
import {
  api,
  clearTokens,
  getAccessToken,
  getRefreshToken,
  normaliseError,
  registerUnauthorizedHandler,
  setAccessToken,
  setTokens,
} from '../api/client'

let mock: MockAdapter

beforeEach(() => {
  clearTokens()
  mock = new MockAdapter(api)
})

describe('token storage', () => {
  it('keeps the access token in memory and never writes it to localStorage', () => {
    setTokens({ access: 'access-abc', refresh: 'refresh-xyz' })

    expect(getAccessToken()).toBe('access-abc')

    // The whole of localStorage must not contain the access token.
    const dump = JSON.stringify(window.localStorage)
    expect(dump).not.toContain('access-abc')
    expect(window.localStorage.getItem('secureshare.refresh')).toBeNull()
  })

  it('persists only the refresh token, and only in sessionStorage', () => {
    setTokens({ access: 'access-abc', refresh: 'refresh-xyz' })
    expect(getRefreshToken()).toBe('refresh-xyz')
    expect(window.sessionStorage.getItem('secureshare.refresh')).toBe('refresh-xyz')
    expect(JSON.stringify(window.localStorage)).not.toContain('refresh-xyz')
  })

  it('clears both tokens on logout', () => {
    setTokens({ access: 'a', refresh: 'b' })
    clearTokens()
    expect(getAccessToken()).toBeNull()
    expect(getRefreshToken()).toBeNull()
    expect(window.sessionStorage.getItem('secureshare.refresh')).toBeNull()
  })
})

describe('request interceptor', () => {
  it('attaches a bearer token when one is set', async () => {
    setAccessToken('token-123')
    mock.onGet('/files/').reply((config) => {
      expect(config.headers?.Authorization).toBe('Bearer token-123')
      return [200, { count: 0, next: null, previous: null, results: [] }]
    })
    await api.get('/files/')
    expect(mock.history.get).toHaveLength(1)
  })

  it('sends no Authorization header when signed out', async () => {
    mock.onGet('/files/').reply((config) => {
      expect(config.headers?.Authorization).toBeUndefined()
      return [401, { error: 'AUTHENTICATION_FAILED', message: 'nope' }]
    })
    await expect(api.get('/files/')).rejects.toBeDefined()
  })
})

describe('error normalisation', () => {
  it('maps a known error code to a friendly message', () => {
    const error = Object.assign(new Error('x'), {
      isAxiosError: true,
      response: {
        status: 410,
        data: { error: 'SHARE_LINK_EXPIRED', message: 'raw server text', request_id: 'req-1' },
      },
      config: {},
      toJSON: () => ({}),
    })
    const result = normaliseError(error)
    expect(result.code).toBe('SHARE_LINK_EXPIRED')
    expect(result.message).toBe('This link has expired.')
    expect(result.requestId).toBe('req-1')
  })

  it('flattens DRF field errors', () => {
    const error = Object.assign(new Error('x'), {
      isAxiosError: true,
      response: {
        status: 400,
        data: {
          error: 'VALIDATION_ERROR',
          message: 'Invalid input.',
          details: { recipient: ['No such recipient.'] },
        },
      },
      config: {},
      toJSON: () => ({}),
    })
    expect(normaliseError(error).fieldErrors).toEqual({ recipient: 'No such recipient.' })
  })

  it('reports a network failure without inventing a status', () => {
    const error = Object.assign(new Error('Network Error'), {
      isAxiosError: true,
      response: undefined,
      config: {},
      toJSON: () => ({}),
    })
    const result = normaliseError(error)
    expect(result.code).toBe('NETWORK_ERROR')
    expect(result.status).toBeNull()
  })

  it('never leaks a raw non-axios error to the user', () => {
    const result = normaliseError(new Error('psycopg.OperationalError at /home/user/app'))
    expect(result.message).toBe('Something went wrong.')
    expect(result.message).not.toContain('psycopg')
  })
})

describe('401 handling', () => {
  it('invokes the unauthorized handler when no refresh token exists', async () => {
    const onUnauthorized = vi.fn()
    registerUnauthorizedHandler(onUnauthorized)
    setAccessToken('stale')

    mock.onGet('/files/').reply(401, { error: 'AUTHENTICATION_FAILED', message: 'expired' })

    await expect(api.get('/files/')).rejects.toBeDefined()
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
    expect(getAccessToken()).toBeNull()
    registerUnauthorizedHandler(null)
  })

  it('does not try to refresh a failed login', async () => {
    const onUnauthorized = vi.fn()
    registerUnauthorizedHandler(onUnauthorized)
    setTokens({ access: 'a', refresh: 'r' })

    mock.onPost('/auth/login/').reply(401, { error: 'INVALID_CREDENTIALS', message: 'bad' })

    await expect(api.post('/auth/login/', {})).rejects.toBeDefined()
    expect(onUnauthorized).not.toHaveBeenCalled()
    registerUnauthorizedHandler(null)
  })

  it('refreshes once and retries the original request', async () => {
    setTokens({ access: 'old-access', refresh: 'refresh-1' })

    // The refresh call goes through a bare axios instance, so stub that too.
    const rootMock = new MockAdapter(axios)
    rootMock.onPost('/api/auth/refresh/').reply(200, { access: 'new-access' })

    let attempts = 0
    mock.onGet('/files/').reply((config) => {
      attempts += 1
      if (attempts === 1) {
        return [401, { error: 'AUTHENTICATION_FAILED', message: 'expired' }]
      }
      expect(config.headers?.Authorization).toBe('Bearer new-access')
      return [200, { count: 0, next: null, previous: null, results: [] }]
    })

    const response = await api.get('/files/')
    expect(response.status).toBe(200)
    expect(attempts).toBe(2)
    expect(getAccessToken()).toBe('new-access')
    rootMock.restore()
  })

  it('gives up and signs out when the refresh itself is rejected', async () => {
    const onUnauthorized = vi.fn()
    registerUnauthorizedHandler(onUnauthorized)
    setTokens({ access: 'old', refresh: 'revoked' })

    const rootMock = new MockAdapter(axios)
    rootMock.onPost('/api/auth/refresh/').reply(401, { error: 'TOKEN_INVALID', message: 'no' })
    mock.onGet('/files/').reply(401, { error: 'AUTHENTICATION_FAILED', message: 'expired' })

    await expect(api.get('/files/')).rejects.toBeDefined()
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
    expect(getAccessToken()).toBeNull()
    expect(getRefreshToken()).toBeNull()
    rootMock.restore()
    registerUnauthorizedHandler(null)
  })
})
