/**
 * Centralised Axios client.
 *
 * Token handling policy
 * ---------------------
 * The access token lives in memory only. It is never written to localStorage,
 * so an XSS payload cannot read it out of persistent storage and it dies with
 * the tab. The refresh token is persisted in sessionStorage: a deliberate,
 * documented trade-off so a page reload does not log the user out. It is
 * scoped to the tab, cleared on logout, and is the only credential on disk.
 *
 * A cookie-based refresh token (HttpOnly + SameSite) would be stronger, but
 * the backend issues refresh tokens in the JSON body, and inventing a cookie
 * flow the server does not implement would be fake work.
 */
import axios, {
  AxiosError,
  AxiosHeaders,
  type AxiosInstance,
  type AxiosRequestConfig,
  type InternalAxiosRequestConfig,
} from 'axios'
import type { ApiErrorBody, AuthTokens } from '../types/api'

const REFRESH_STORAGE_KEY = 'secureshare.refresh'

let accessToken: string | null = null
let onUnauthorized: (() => void) | null = null

export function setAccessToken(token: string | null): void {
  accessToken = token
}

export function getAccessToken(): string | null {
  return accessToken
}

export function setRefreshToken(token: string | null): void {
  try {
    if (token) window.sessionStorage.setItem(REFRESH_STORAGE_KEY, token)
    else window.sessionStorage.removeItem(REFRESH_STORAGE_KEY)
  } catch {
    /* storage can be unavailable in private modes; the session stays in memory */
  }
}

export function getRefreshToken(): string | null {
  try {
    return window.sessionStorage.getItem(REFRESH_STORAGE_KEY)
  } catch {
    return null
  }
}

export function setTokens(tokens: AuthTokens | null): void {
  setAccessToken(tokens?.access ?? null)
  setRefreshToken(tokens?.refresh ?? null)
}

export function clearTokens(): void {
  setTokens(null)
}

/** Registered by AuthProvider so a hard 401 can bounce the user to /login. */
export function registerUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler
}

export const api: AxiosInstance = axios.create({
  baseURL: '/api',
  timeout: 60_000,
  // Relative URL: the browser talks to whatever origin served the app, and
  // nginx (prod) or the Vite proxy (dev) forwards to Django. Never localhost.
  headers: { Accept: 'application/json' },
})

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (accessToken) {
    const headers = AxiosHeaders.from(config.headers)
    headers.set('Authorization', `Bearer ${accessToken}`)
    config.headers = headers
  }
  return config
})

interface RetriableConfig extends AxiosRequestConfig {
  _retried?: boolean
}

let refreshInFlight: Promise<string | null> | null = null

/** Refresh once and let every queued 401 await the same promise. */
async function refreshAccessToken(): Promise<string | null> {
  const refresh = getRefreshToken()
  if (!refresh) return null

  if (!refreshInFlight) {
    refreshInFlight = axios
      .post<{ access: string; refresh?: string }>(
        '/api/auth/refresh/',
        { refresh },
        { headers: { 'Content-Type': 'application/json' } },
      )
      .then((response) => {
        setAccessToken(response.data.access)
        if (response.data.refresh) setRefreshToken(response.data.refresh)
        return response.data.access
      })
      .catch(() => {
        clearTokens()
        return null
      })
      .finally(() => {
        refreshInFlight = null
      })
  }
  return refreshInFlight
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError<ApiErrorBody>) => {
    const original = error.config as (RetriableConfig & InternalAxiosRequestConfig) | undefined
    const status = error.response?.status
    const url = original?.url ?? ''

    const isAuthEndpoint =
      url.includes('/auth/login') ||
      url.includes('/auth/refresh') ||
      url.includes('/auth/register')

    if (status === 401 && original && !original._retried && !isAuthEndpoint) {
      original._retried = true
      const fresh = await refreshAccessToken()
      if (fresh) {
        const headers = AxiosHeaders.from(original.headers)
        headers.set('Authorization', `Bearer ${fresh}`)
        original.headers = headers
        return api.request(original)
      }
      clearTokens()
      onUnauthorized?.()
    }
    return Promise.reject(error)
  },
)

/** Normalised, user-presentable error. Never surfaces raw server internals. */
export interface NormalisedError {
  code: string
  message: string
  status: number | null
  retryAfter?: number
  fieldErrors?: Record<string, string>
  requestId?: string
}

const FRIENDLY: Record<string, string> = {
  RATE_LIMIT_EXCEEDED: 'Too many attempts. Please wait and try again.',
  AUTHENTICATION_FAILED: 'Your session has expired. Please sign in again.',
  INVALID_CREDENTIALS: 'Email or password is incorrect.',
  ACCOUNT_LOCKED: 'This account is temporarily locked after repeated failures.',
  ACCOUNT_DISABLED: 'This account has been disabled.',
  PERMISSION_DENIED: 'You do not have permission to do that.',
  ACCESS_DENIED: 'You do not have permission to do that.',
  FILE_NOT_FOUND: 'That file does not exist or you cannot access it.',
  FILE_TOO_LARGE: 'That file is larger than the upload limit.',
  UNSUPPORTED_FILE_TYPE: 'That file type is not allowed.',
  SHARE_LINK_NOT_FOUND: 'This link is not valid.',
  SHARE_LINK_EXPIRED: 'This link has expired.',
  SHARE_LINK_REVOKED: 'This link has been revoked by its owner.',
  SHARE_LINK_DOWNLOAD_LIMIT_REACHED: 'This link has reached its download limit.',
  SHARE_LINK_PASSWORD_REQUIRED: 'This link is password protected.',
  SHARE_LINK_PASSWORD_INVALID: 'That password is not correct.',
  SHARE_LINK_LOCKED: 'Too many password attempts. Try again later.',
  FILE_INTEGRITY_ERROR: 'This file failed its integrity check and cannot be served.',
}

export function normaliseError(error: unknown): NormalisedError {
  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError<ApiErrorBody>
    const status = axiosError.response?.status ?? null
    const body = axiosError.response?.data

    if (!axiosError.response) {
      return {
        code: 'NETWORK_ERROR',
        message: 'Cannot reach the server. Check your connection and try again.',
        status: null,
      }
    }

    const code = body?.error ?? 'REQUEST_FAILED'
    const fieldErrors: Record<string, string> = {}
    if (body?.details) {
      for (const [key, value] of Object.entries(body.details)) {
        fieldErrors[key] = Array.isArray(value) ? value.join(' ') : String(value)
      }
    }
    return {
      code,
      message: FRIENDLY[code] ?? body?.message ?? 'Something went wrong.',
      status,
      retryAfter: body?.retry_after,
      fieldErrors: Object.keys(fieldErrors).length ? fieldErrors : undefined,
      requestId: body?.request_id,
    }
  }
  return { code: 'UNKNOWN', message: 'Something went wrong.', status: null }
}

/**
 * Reads a Blob as text. `Blob.text()` is unavailable on older Safari/Edge and
 * in jsdom, so fall back to FileReader rather than assume it exists.
 */
function readBlobText(blob: Blob): Promise<string> {
  if (typeof blob.text === 'function') return blob.text()
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(reader.error ?? new Error('Could not read response'))
    reader.readAsText(blob)
  })
}

/**
 * When a request uses `responseType: 'blob'`, an error body also arrives as a
 * Blob, so `normaliseError` cannot see the JSON. This reads the Blob back as
 * text and re-normalises it.
 */
export async function normaliseBlobError(error: unknown): Promise<NormalisedError> {
  const base = normaliseError(error)
  if (!axios.isAxiosError(error)) return base
  const data: unknown = error.response?.data
  if (!(data instanceof Blob)) return base
  try {
    const text = await readBlobText(data)
    const body = JSON.parse(text) as ApiErrorBody
    const code = body.error ?? base.code
    return {
      code,
      message: FRIENDLY[code] ?? body.message ?? base.message,
      status: error.response?.status ?? null,
      retryAfter: body.retry_after,
      requestId: body.request_id,
    }
  } catch {
    return base
  }
}
