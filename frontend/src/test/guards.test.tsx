/**
 * Route guards are a UX convenience, not the security boundary — the backend
 * authorises every request independently (see backend/tests/test_phase9_admin.py).
 * These tests use the real AuthProvider with a mocked network so the session
 * restore path is exercised rather than stubbed out.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import MockAdapter from 'axios-mock-adapter'
import { api, clearTokens } from '../api/client'
import { RedirectIfAuthenticated, RequireAdmin, RequireAuth } from '../components/Guards'
import { AuthProvider } from '../context/AuthContext'
import type { User } from '../types/api'

const ADMIN: User = {
  id: 'u-admin',
  email: 'admin@example.com',
  full_name: 'Ada Admin',
  role: 'ADMIN',
  is_active: true,
}

const NORMAL: User = { ...ADMIN, id: 'u-user', email: 'user@example.com', role: 'USER' }

let mock: MockAdapter

/** Puts the provider into a signed-in state through its real restore path. */
function signInAs(user: User) {
  window.sessionStorage.setItem('secureshare.refresh', 'refresh-token')
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      new Response(JSON.stringify({ access: 'access-token' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  )
  mock.onGet('/users/me/').reply(200, user)
}

beforeEach(() => {
  clearTokens()
  mock = new MockAdapter(api)
})

afterEach(() => {
  mock.restore()
  vi.unstubAllGlobals()
})

function renderAt(path: string, element: React.ReactNode) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route path={path} element={element} />
          <Route path="/login" element={<p>Sign-in page</p>} />
          <Route path="/app" element={<p>User dashboard</p>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('RequireAuth', () => {
  it('sends an anonymous visitor to the sign-in page', async () => {
    renderAt(
      '/app/files',
      <RequireAuth>
        <p>Secret files</p>
      </RequireAuth>,
    )
    expect(await screen.findByText('Sign-in page')).toBeInTheDocument()
    expect(screen.queryByText('Secret files')).not.toBeInTheDocument()
  })

  it('renders the page once the session is restored', async () => {
    signInAs(NORMAL)
    renderAt(
      '/app/files',
      <RequireAuth>
        <p>Secret files</p>
      </RequireAuth>,
    )
    expect(await screen.findByText('Secret files')).toBeInTheDocument()
  })
})

describe('RedirectIfAuthenticated', () => {
  it('shows the login form to an anonymous visitor', async () => {
    renderAt(
      '/login',
      <RedirectIfAuthenticated>
        <p>Login form</p>
      </RedirectIfAuthenticated>,
    )
    expect(await screen.findByText('Login form')).toBeInTheDocument()
  })

  it('bounces a signed-in user away from the login form', async () => {
    signInAs(NORMAL)
    renderAt(
      '/login',
      <RedirectIfAuthenticated>
        <p>Login form</p>
      </RedirectIfAuthenticated>,
    )
    expect(await screen.findByText('User dashboard')).toBeInTheDocument()
    expect(screen.queryByText('Login form')).not.toBeInTheDocument()
  })
})

describe('RequireAdmin', () => {
  it('never renders admin content for an anonymous visitor', async () => {
    renderAt(
      '/app/admin',
      <RequireAdmin>
        <p>Admin console</p>
      </RequireAdmin>,
    )
    expect(await screen.findByText('Sign-in page')).toBeInTheDocument()
    expect(screen.queryByText('Admin console')).not.toBeInTheDocument()
  })

  it('redirects a signed-in USER away from the admin console', async () => {
    signInAs(NORMAL)
    renderAt(
      '/app/admin',
      <RequireAdmin>
        <p>Admin console</p>
      </RequireAdmin>,
    )
    expect(await screen.findByText('User dashboard')).toBeInTheDocument()
    expect(screen.queryByText('Admin console')).not.toBeInTheDocument()
  })

  it('renders the admin console for an ADMIN', async () => {
    signInAs(ADMIN)
    renderAt(
      '/app/admin',
      <RequireAdmin>
        <p>Admin console</p>
      </RequireAdmin>,
    )
    expect(await screen.findByText('Admin console')).toBeInTheDocument()
  })
})
