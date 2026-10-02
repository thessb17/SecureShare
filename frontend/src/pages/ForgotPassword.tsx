import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import AuthShell from '../components/AuthShell'
import { Alert, Button, Input } from '../components/ui'
import { normaliseError } from '../api/client'
import { authApi } from '../api/endpoints'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [sent, setSent] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await authApi.requestPasswordReset(email)
      setSent(true)
    } catch (caught) {
      const normalised = normaliseError(caught)
      // A 429 is worth showing; anything else must not reveal whether the
      // address exists, so the generic confirmation is shown instead.
      if (normalised.code === 'RATE_LIMIT_EXCEEDED') setError(normalised.message)
      else setSent(true)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <AuthShell
      title="Reset your password"
      subtitle="We'll email a reset link if the address is registered."
      footer={
        <Link to="/login" className="font-medium text-brand-600 hover:underline">
          Back to sign in
        </Link>
      }
    >
      {sent ? (
        <Alert tone="green" title="Check your inbox">
          If an account exists for <strong>{email}</strong>, a reset link is on its way.
          The link expires shortly for your security.
        </Alert>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          {error && <Alert tone="red">{error}</Alert>}
          <Input
            label="Email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            hint="For your privacy we show the same message whether or not the account exists."
          />
          <Button type="submit" loading={submitting} className="w-full">
            Send reset link
          </Button>
        </form>
      )}
    </AuthShell>
  )
}
