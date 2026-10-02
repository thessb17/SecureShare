import { Link } from 'react-router-dom'
import { Logo } from '../components/ui'
import { useAuth } from '../context/AuthContext'

export default function NotFound() {
  const { isAuthenticated } = useAuth()
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-50 px-4 dark:bg-slate-950">
      <Logo className="h-10 w-10" />
      <p className="mt-6 text-sm font-semibold text-brand-600">404</p>
      <h1 className="mt-2 text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
        Page not found
      </h1>
      <p className="mt-2 max-w-md text-center text-sm text-slate-500 dark:text-slate-400">
        This address does not exist. If you followed a share link, it may have expired or been
        revoked — ask the sender for a new one.
      </p>
      <div className="mt-6 flex gap-3">
        <Link
          to={isAuthenticated ? '/app' : '/'}
          className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
        >
          {isAuthenticated ? 'Back to dashboard' : 'Back to home'}
        </Link>
        {!isAuthenticated && (
          <Link
            to="/login"
            className="rounded-lg px-4 py-2 text-sm font-semibold text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-white dark:text-slate-200 dark:ring-slate-700"
          >
            Sign in
          </Link>
        )}
      </div>
    </div>
  )
}
