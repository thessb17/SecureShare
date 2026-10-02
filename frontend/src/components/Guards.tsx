import { Navigate, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAuth } from '../context/AuthContext'
import { Spinner } from './ui'

/**
 * Route guards are a convenience, never a security control: the backend
 * authorises every request independently. Removing these components changes
 * what the UI shows, not what the API permits.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { isAuthenticated, initialising } = useAuth()
  const location = useLocation()

  if (initialising) return <Spinner label="Restoring session" />
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }
  return <>{children}</>
}

export function RequireAdmin({ children }: { children: ReactNode }) {
  const { isAuthenticated, isAdmin, initialising } = useAuth()
  const location = useLocation()

  if (initialising) return <Spinner label="Checking permissions" />
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }
  if (!isAdmin) return <Navigate to="/app" replace />
  return <>{children}</>
}

export function RedirectIfAuthenticated({ children }: { children: ReactNode }) {
  const { isAuthenticated, initialising } = useAuth()
  if (initialising) return <Spinner label="Loading" />
  if (isAuthenticated) return <Navigate to="/app" replace />
  return <>{children}</>
}
