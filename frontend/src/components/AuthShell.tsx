import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Logo } from './ui'

/** Centred card used by every unauthenticated page. */
export default function AuthShell({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string
  subtitle?: string
  children: ReactNode
  footer?: ReactNode
}) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-50 px-4 py-10 dark:bg-slate-950">
      <Link to="/" className="mb-6 flex items-center gap-2">
        <Logo className="h-8 w-8" />
        <span className="text-lg font-bold tracking-tight text-slate-900 dark:text-slate-100">
          SecureShare
        </span>
      </Link>
      <main className="w-full max-w-md rounded-xl bg-white p-7 shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{subtitle}</p>}
        <div className="mt-6">{children}</div>
      </main>
      {footer && <div className="mt-5 text-sm text-slate-500 dark:text-slate-400">{footer}</div>}
    </div>
  )
}
