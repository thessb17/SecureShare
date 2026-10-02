import { useState } from 'react'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useTheme } from '../context/ThemeContext'
import { Logo } from './ui'

const NAV = [
  { to: '/app', label: 'Dashboard', end: true },
  { to: '/app/files', label: 'My Files' },
  { to: '/app/upload', label: 'Upload' },
  { to: '/app/shared-with-me', label: 'Shared with me' },
  { to: '/app/links', label: 'Share Links' },
  { to: '/app/audit', label: 'Activity' },
]

function navClass({ isActive }: { isActive: boolean }): string {
  return [
    'block rounded-lg px-3 py-2 text-sm font-medium transition',
    isActive
      ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/10 dark:text-brand-300'
      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100',
  ].join(' ')
}

export default function Layout() {
  const { user, isAdmin, logout } = useAuth()
  const { theme, toggle } = useTheme()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)

  async function handleLogout() {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex min-h-full flex-col bg-slate-50 dark:bg-slate-950">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50
          focus:rounded focus:bg-brand-600 focus:px-4 focus:py-2 focus:text-white"
      >
        Skip to content
      </a>

      <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/90 backdrop-blur dark:border-slate-800 dark:bg-slate-900/90">
        <div className="mx-auto flex h-14 max-w-7xl items-center gap-3 px-4">
          <Link to="/app" className="flex items-center gap-2">
            <Logo />
            <span className="text-sm font-bold tracking-tight text-slate-900 dark:text-slate-100">
              SecureShare
            </span>
          </Link>

          <button
            type="button"
            className="ml-auto rounded-lg p-2 text-slate-500 hover:bg-slate-100 md:hidden dark:hover:bg-slate-800"
            onClick={() => setMenuOpen((open) => !open)}
            aria-expanded={menuOpen}
            aria-label="Toggle navigation"
          >
            ☰
          </button>

          <div className="ml-auto hidden items-center gap-2 md:flex">
            <button
              type="button"
              onClick={toggle}
              className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
              title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            >
              {theme === 'dark' ? '☀' : '☾'}
            </button>
            <Link
              to="/app/profile"
              className="max-w-[18ch] truncate rounded-lg px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              {user?.full_name || user?.email}
            </Link>
            <button
              type="button"
              onClick={handleLogout}
              className="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto flex w-full max-w-7xl flex-1 gap-6 px-4 py-6">
        <nav
          aria-label="Main"
          className={`${menuOpen ? 'block' : 'hidden'} w-full shrink-0 md:block md:w-56`}
        >
          <div className="space-y-1">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={navClass}
                onClick={() => setMenuOpen(false)}
              >
                {item.label}
              </NavLink>
            ))}
            {isAdmin && (
              <>
                <p className="px-3 pb-1 pt-4 text-xs font-semibold uppercase tracking-wide text-slate-400">
                  Admin
                </p>
                <NavLink to="/app/admin" end className={navClass} onClick={() => setMenuOpen(false)}>
                  Overview
                </NavLink>
                <NavLink to="/app/admin/users" className={navClass} onClick={() => setMenuOpen(false)}>
                  Users
                </NavLink>
                <NavLink to="/app/admin/events" className={navClass} onClick={() => setMenuOpen(false)}>
                  Security Events
                </NavLink>
              </>
            )}
            <div className="pt-4 md:hidden">
              <button
                type="button"
                onClick={handleLogout}
                className="w-full rounded-lg px-3 py-2 text-left text-sm font-medium text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                Sign out
              </button>
            </div>
          </div>
        </nav>

        <main id="main" className={`${menuOpen ? 'hidden' : 'block'} min-w-0 flex-1 md:block`}>
          <Outlet />
        </main>
      </div>

      <footer className="border-t border-slate-200 py-4 dark:border-slate-800">
        <p className="mx-auto max-w-7xl px-4 text-xs text-slate-400">
          SecureShare — files encrypted at rest with AES-256-GCM; data keys wrapped with RSA-OAEP.
        </p>
      </footer>
    </div>
  )
}
