import { useMemo, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { normaliseError } from '../api/client'
import { authApi } from '../api/endpoints'
import { Alert, Badge, Button, Card, Input } from '../components/ui'
import { useAuth } from '../context/AuthContext'
import { useTheme } from '../context/ThemeContext'
import { formatDate } from '../utils/format'

function strengthChecks(password: string) {
  return [
    { label: 'At least 12 characters', ok: password.length >= 12 },
    { label: 'An uppercase letter', ok: /[A-Z]/.test(password) },
    { label: 'A lowercase letter', ok: /[a-z]/.test(password) },
    { label: 'A number', ok: /\d/.test(password) },
    { label: 'A symbol', ok: /[^A-Za-z0-9]/.test(password) },
  ]
}

export default function Profile() {
  const { user, logout } = useAuth()
  const { theme, toggle } = useTheme()
  const navigate = useNavigate()

  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<{ tone: 'green' | 'red'; text: string } | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  const [revoking, setRevoking] = useState(false)
  const [revokeMessage, setRevokeMessage] = useState<string | null>(null)

  const checks = useMemo(() => strengthChecks(next), [next])
  const strong = checks.every((check) => check.ok)
  const mismatch = confirm.length > 0 && confirm !== next

  async function changePassword(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setMessage(null)
    setFieldErrors({})
    try {
      await authApi.changePassword({
        current_password: current,
        new_password: next,
        new_password_confirm: confirm,
      })
      // The server bumps the token version, so every session including this
      // one is invalidated. Sign the user out rather than leave a dead tab.
      setMessage({
        tone: 'green',
        text: 'Password changed. All sessions were signed out — please sign in again.',
      })
      setCurrent('')
      setNext('')
      setConfirm('')
      window.setTimeout(async () => {
        await logout()
        navigate('/login', { replace: true })
      }, 1800)
    } catch (caught) {
      const normalised = normaliseError(caught)
      setMessage({ tone: 'red', text: normalised.message })
      setFieldErrors(normalised.fieldErrors ?? {})
    } finally {
      setBusy(false)
    }
  }

  async function revokeSessions() {
    setRevoking(true)
    setRevokeMessage(null)
    try {
      await authApi.revokeSessions()
      setRevokeMessage('Every session was revoked. Signing you out…')
      window.setTimeout(async () => {
        await logout()
        navigate('/login', { replace: true })
      }, 1500)
    } catch (caught) {
      setRevokeMessage(normaliseError(caught).message)
    } finally {
      setRevoking(false)
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Profile &amp; security
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Account details and the controls that protect them.
        </p>
      </header>

      <Card title="Account">
        <dl className="space-y-3 text-sm">
          <div className="flex justify-between gap-4">
            <dt className="text-slate-500 dark:text-slate-400">Name</dt>
            <dd className="font-medium text-slate-900 dark:text-slate-100">{user?.full_name}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-slate-500 dark:text-slate-400">Email</dt>
            <dd className="break-all font-medium text-slate-900 dark:text-slate-100">
              {user?.email}
            </dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-slate-500 dark:text-slate-400">Role</dt>
            <dd>
              <Badge tone={user?.role === 'ADMIN' ? 'blue' : 'slate'}>{user?.role}</Badge>
            </dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-slate-500 dark:text-slate-400">Status</dt>
            <dd>
              <Badge tone={user?.is_active ? 'green' : 'red'}>
                {user?.is_active ? 'Active' : 'Disabled'}
              </Badge>
            </dd>
          </div>
          {user?.created_at && (
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500 dark:text-slate-400">Member since</dt>
              <dd className="font-medium text-slate-900 dark:text-slate-100">
                {formatDate(user.created_at)}
              </dd>
            </div>
          )}
          {user?.last_login && (
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500 dark:text-slate-400">Last sign-in</dt>
              <dd className="font-medium text-slate-900 dark:text-slate-100">
                {formatDate(user.last_login)}
              </dd>
            </div>
          )}
        </dl>
      </Card>

      <Card title="Change password">
        <form onSubmit={changePassword} className="space-y-4" noValidate>
          {message && <Alert tone={message.tone}>{message.text}</Alert>}
          <Input
            label="Current password"
            type="password"
            autoComplete="current-password"
            required
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            error={fieldErrors.current_password}
          />
          <Input
            label="New password"
            type="password"
            autoComplete="new-password"
            required
            value={next}
            onChange={(event) => setNext(event.target.value)}
            error={fieldErrors.new_password}
          />
          <ul className="space-y-1" aria-label="Password requirements">
            {checks.map((check) => (
              <li
                key={check.label}
                className={`flex items-center gap-2 text-xs ${
                  check.ok
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : 'text-slate-500 dark:text-slate-400'
                }`}
              >
                <span aria-hidden="true">{check.ok ? '✓' : '○'}</span>
                {check.label}
              </li>
            ))}
          </ul>
          <Input
            label="Confirm new password"
            type="password"
            autoComplete="new-password"
            required
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            error={mismatch ? 'Passwords do not match.' : fieldErrors.new_password_confirm}
          />
          <Button type="submit" loading={busy} disabled={!current || !strong || mismatch}>
            Change password
          </Button>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Passwords are hashed with Argon2id. Changing yours immediately invalidates every
            access and refresh token issued to this account.
          </p>
        </form>
      </Card>

      <Card title="Sessions">
        {revokeMessage && <Alert tone="amber">{revokeMessage}</Alert>}
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Signing out everywhere increments your token version, which immediately rejects
          every JWT issued before now — including tokens stolen from another device.
        </p>
        <div className="mt-4">
          <Button variant="danger" loading={revoking} onClick={revokeSessions}>
            Sign out of all sessions
          </Button>
        </div>
      </Card>

      <Card title="How your account is protected">
        <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
          <li>• Passwords hashed with Argon2id — never stored or logged in plaintext.</li>
          <li>• Repeated failed sign-ins lock the account temporarily.</li>
          <li>• Sign-in, password and sharing endpoints are individually rate limited.</li>
          <li>• Access tokens live in memory only; they are never written to localStorage.</li>
          <li>• Every security-relevant action is written to an append-only audit log.</li>
        </ul>
      </Card>

      <Card title="Appearance">
        <div className="flex items-center justify-between">
          <p className="text-sm text-slate-600 dark:text-slate-400">
            Currently using {theme} mode.
          </p>
          <Button variant="secondary" onClick={toggle}>
            Switch to {theme === 'dark' ? 'light' : 'dark'} mode
          </Button>
        </div>
      </Card>
    </div>
  )
}
