import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import {
  clearTokens,
  getRefreshToken,
  registerUnauthorizedHandler,
  setTokens,
} from '../api/client'
import { authApi } from '../api/endpoints'
import type { User } from '../types/api'

interface AuthState {
  user: User | null
  /** True until the initial session restore finishes. */
  initialising: boolean
  isAuthenticated: boolean
  isAdmin: boolean
  sessionExpired: boolean
  login: (email: string, password: string) => Promise<User>
  register: (data: {
    email: string
    password: string
    password_confirm: string
    full_name: string
  }) => Promise<User>
  logout: () => Promise<void>
  refreshUser: () => Promise<void>
  dismissSessionExpired: () => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [initialising, setInitialising] = useState(true)
  const [sessionExpired, setSessionExpired] = useState(false)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  // A 401 that survives a refresh attempt means the session is genuinely gone.
  useEffect(() => {
    registerUnauthorizedHandler(() => {
      if (!mounted.current) return
      setUser(null)
      setSessionExpired(true)
    })
    return () => registerUnauthorizedHandler(null)
  }, [])

  // Restore the session on first load using the tab-scoped refresh token.
  useEffect(() => {
    let cancelled = false
    async function restore() {
      const refresh = getRefreshToken()
      if (!refresh) {
        if (!cancelled) setInitialising(false)
        return
      }
      try {
        // Exchange the refresh token for an access token, then load the user.
        const response = await fetch('/api/auth/refresh/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh }),
        })
        if (!response.ok) throw new Error('refresh rejected')
        const data = (await response.json()) as { access: string; refresh?: string }
        setTokens({ access: data.access, refresh: data.refresh ?? refresh })
        const profile = await authApi.me()
        if (!cancelled) setUser(profile)
      } catch {
        clearTokens()
      } finally {
        if (!cancelled) setInitialising(false)
      }
    }
    void restore()
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (email: string, password: string) => {
    const data = await authApi.login({ email, password })
    setTokens(data.tokens)
    setUser(data.user)
    setSessionExpired(false)
    return data.user
  }, [])

  const register = useCallback(
    async (payload: {
      email: string
      password: string
      password_confirm: string
      full_name: string
    }) => {
      const data = await authApi.register(payload)
      setTokens(data.tokens)
      setUser(data.user)
      setSessionExpired(false)
      return data.user
    },
    [],
  )

  const logout = useCallback(async () => {
    const refresh = getRefreshToken()
    try {
      await authApi.logout(refresh)
    } catch {
      /* the local session is cleared regardless of the server's answer */
    }
    clearTokens()
    setUser(null)
    setSessionExpired(false)
  }, [])

  const refreshUser = useCallback(async () => {
    const profile = await authApi.me()
    setUser(profile)
  }, [])

  const value = useMemo<AuthState>(
    () => ({
      user,
      initialising,
      isAuthenticated: Boolean(user),
      isAdmin: user?.role === 'ADMIN',
      sessionExpired,
      login,
      register,
      logout,
      refreshUser,
      dismissSessionExpired: () => setSessionExpired(false),
    }),
    [user, initialising, sessionExpired, login, register, logout, refreshUser],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside an AuthProvider')
  return context
}
