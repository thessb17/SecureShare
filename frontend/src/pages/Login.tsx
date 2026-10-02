import { useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import AuthShell from '../components/AuthShell'
import { Alert, Button, Input } from '../components/ui'
import { normaliseError } from '../api/client'
import { useAuth } from '../context/AuthContext'
import { safeInternalPath } from '../utils/navigation'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  // Never navigate to an unvalidated target: see utils/navigation.ts.
  const from = safeInternalPath((location.state as { from?: string } | null)?.from)

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setFieldErrors({})
    setSubmitting(true)
    try {
      await login(email, password)
      navigate(from, { replace: true })
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
      title="Sign in"
      subtitle="Access your encrypted files."
      footer={
        <>
          No account?{' '}
          <Link to="/register" className="font-medium text-brand-600 hover:underline">
            Create one
          </Link>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        {error && <Alert tone="red">{error}</Alert>}
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
          autoComplete="current-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          error={fieldErrors.password}
        />
        <div className="flex justify-end">
          <Link to="/forgot-password" className="text-sm text-brand-600 hover:underline">
            Forgot password?
          </Link>
        </div>
        <Button type="submit" loading={submitting} className="w-full">
          Sign in
        </Button>
      </form>
    </AuthShell>
  )
}
