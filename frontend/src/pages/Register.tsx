import { useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import AuthShell from '../components/AuthShell'
import { Alert, Button, Input } from '../components/ui'
import { normaliseError } from '../api/client'
import { useAuth } from '../context/AuthContext'

/** Mirrors the server policy so users get feedback before submitting. */
function passwordChecks(password: string) {
  return [
    { label: 'At least 12 characters', ok: password.length >= 12 },
    { label: 'An uppercase letter', ok: /[A-Z]/.test(password) },
    { label: 'A lowercase letter', ok: /[a-z]/.test(password) },
    { label: 'A number', ok: /\d/.test(password) },
    { label: 'A symbol', ok: /[^A-Za-z0-9]/.test(password) },
  ]
}

export default function Register() {
  const { register } = useAuth()
  const navigate = useNavigate()

  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [submitting, setSubmitting] = useState(false)

  const checks = useMemo(() => passwordChecks(password), [password])
  const strong = checks.every((check) => check.ok)
  const mismatch = confirm.length > 0 && confirm !== password

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setFieldErrors({})
    setSubmitting(true)
    try {
      await register({
        email,
        password,
        password_confirm: confirm,
        full_name: fullName,
      })
      navigate('/app', { replace: true })
    } catch (caught) {
      const normalised = normaliseError(caught)
      setError(normalised.message)
      setFieldErrors(normalised.fieldErrors ?? {})
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <AuthShell
      title="Create your account"
      subtitle="Files you upload are encrypted before they touch disk."
      footer={
        <>
          Already registered?{' '}
          <Link to="/login" className="font-medium text-brand-600 hover:underline">
            Sign in
          </Link>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        {error && <Alert tone="red">{error}</Alert>}
        <Input
          label="Full name"
          autoComplete="name"
          required
          value={fullName}
          onChange={(event) => setFullName(event.target.value)}
          error={fieldErrors.full_name}
        />
        <Input
          label="Email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          error={fieldErrors.email}
        />
        <Input
          label="Password"
          type="password"
          autoComplete="new-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          error={fieldErrors.password}
        />
        <ul className="space-y-1" aria-label="Password requirements">
          {checks.map((check) => (
            <li
              key={check.label}
              className={`flex items-center gap-2 text-xs ${
                check.ok ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-400'
              }`}
            >
              <span aria-hidden="true">{check.ok ? '✓' : '○'}</span>
              {check.label}
            </li>
          ))}
        </ul>
        <Input
          label="Confirm password"
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
          error={mismatch ? 'Passwords do not match.' : fieldErrors.password_confirm}
        />
        <Button
          type="submit"
          loading={submitting}
          disabled={!strong || mismatch || !email || !fullName}
          className="w-full"
        >
          Create account
        </Button>
      </form>
    </AuthShell>
  )
}
