import { Link, useLocation } from 'react-router-dom'
import { Logo } from '../components/ui'

interface ErrorState {
  title?: string
  message?: string
  requestId?: string
}

/**
 * Route-level error page for failures that are not a 404 — for example a
 * backend outage. It deliberately shows no stack trace and no server detail.
 */
export default function ErrorPage() {
  const location = useLocation()
  const state = (location.state as ErrorState | null) ?? {}

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-50 px-4 dark:bg-slate-950">
      <Logo className="h-10 w-10" />
      <p className="mt-6 text-sm font-semibold text-rose-600">Something went wrong</p>
      <h1 className="mt-2 text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
        {state.title ?? 'We could not complete that request'}
      </h1>
      <p className="mt-2 max-w-md text-center text-sm text-slate-500 dark:text-slate-400">
        {state.message ??
          'The server could not be reached or returned an unexpected response. Your files are unaffected — nothing is modified unless a request succeeds.'}
      </p>
      {state.requestId && (
        <p className="mt-3 font-mono text-xs text-slate-400">Request ID: {state.requestId}</p>
      )}
      <div className="mt-6 flex gap-3">
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
        >
          Try again
        </button>
        <Link
          to="/app"
          className="rounded-lg px-4 py-2 text-sm font-semibold text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-white dark:text-slate-200 dark:ring-slate-700"
        >
          Back to dashboard
        </Link>
      </div>
    </div>
  )
}
