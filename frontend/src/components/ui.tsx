import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react'
import { forwardRef, useId } from 'react'

// ----------------------------------------------------------------- Button
type Variant = 'primary' | 'secondary' | 'danger' | 'ghost'

const VARIANTS: Record<Variant, string> = {
  primary:
    'bg-brand-600 text-white hover:bg-brand-700 focus-visible:outline-brand-600 disabled:bg-brand-300',
  secondary:
    'bg-white text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-slate-50 ' +
    'dark:bg-slate-800 dark:text-slate-100 dark:ring-slate-700 dark:hover:bg-slate-700',
  danger:
    'bg-rose-600 text-white hover:bg-rose-700 focus-visible:outline-rose-600 disabled:bg-rose-300',
  ghost:
    'text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800',
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  loading?: boolean
  children: ReactNode
}

export function Button({
  variant = 'primary',
  loading = false,
  disabled,
  className = '',
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2
        text-sm font-semibold transition focus-visible:outline focus-visible:outline-2
        focus-visible:outline-offset-2 disabled:cursor-not-allowed disabled:opacity-70
        ${VARIANTS[variant]} ${className}`}
    >
      {loading && (
        <span
          aria-hidden="true"
          className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
        />
      )}
      {children}
    </button>
  )
}

// ----------------------------------------------------------------- Input
interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string
  error?: string
  hint?: string
}

export const Input = forwardRef<HTMLInputElement, FieldProps>(function Input(
  { label, error, hint, id, className = '', ...rest },
  ref,
) {
  const generated = useId()
  const inputId = id ?? generated
  const describedBy = [error ? `${inputId}-error` : null, hint ? `${inputId}-hint` : null]
    .filter(Boolean)
    .join(' ')

  return (
    <div className="space-y-1.5">
      <label htmlFor={inputId} className="block text-sm font-medium text-slate-700 dark:text-slate-200">
        {label}
      </label>
      <input
        {...rest}
        id={inputId}
        ref={ref}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy || undefined}
        className={`block w-full rounded-lg border-0 px-3 py-2 text-sm text-slate-900 shadow-sm
          ring-1 ring-inset placeholder:text-slate-400 focus:ring-2 focus:ring-inset
          dark:bg-slate-800 dark:text-slate-100
          ${error
            ? 'ring-rose-400 focus:ring-rose-500'
            : 'ring-slate-300 focus:ring-brand-600 dark:ring-slate-700'}
          ${className}`}
      />
      {hint && !error && (
        <p id={`${inputId}-hint`} className="text-xs text-slate-500 dark:text-slate-400">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${inputId}-error`} role="alert" className="text-xs font-medium text-rose-600 dark:text-rose-400">
          {error}
        </p>
      )}
    </div>
  )
})

// ----------------------------------------------------------------- Select
interface SelectProps {
  label: string
  value: string
  onChange: (value: string) => void
  options: { value: string; label: string }[]
  hint?: string
  id?: string
}

export function Select({ label, value, onChange, options, hint, id }: SelectProps) {
  const generated = useId()
  const selectId = id ?? generated
  return (
    <div className="space-y-1.5">
      <label htmlFor={selectId} className="block text-sm font-medium text-slate-700 dark:text-slate-200">
        {label}
      </label>
      <select
        id={selectId}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="block w-full rounded-lg border-0 px-3 py-2 text-sm text-slate-900 shadow-sm
          ring-1 ring-inset ring-slate-300 focus:ring-2 focus:ring-inset focus:ring-brand-600
          dark:bg-slate-800 dark:text-slate-100 dark:ring-slate-700"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {hint && <p className="text-xs text-slate-500 dark:text-slate-400">{hint}</p>}
    </div>
  )
}

// ----------------------------------------------------------------- Card
export function Card({
  children,
  className = '',
  title,
  action,
}: {
  children: ReactNode
  className?: string
  title?: ReactNode
  action?: ReactNode
}) {
  return (
    <section
      className={`rounded-xl bg-white shadow-sm ring-1 ring-slate-200
        dark:bg-slate-900 dark:ring-slate-800 ${className}`}
    >
      {(title || action) && (
        <header className="flex items-center justify-between gap-4 border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  )
}

// ----------------------------------------------------------------- Badge
type Tone = 'green' | 'amber' | 'red' | 'slate' | 'blue'

const TONES: Record<Tone, string> = {
  green: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300',
  amber: 'bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/10 dark:text-amber-300',
  red: 'bg-rose-50 text-rose-700 ring-rose-600/20 dark:bg-rose-500/10 dark:text-rose-300',
  slate: 'bg-slate-100 text-slate-700 ring-slate-500/20 dark:bg-slate-700/40 dark:text-slate-300',
  blue: 'bg-brand-50 text-brand-700 ring-brand-600/20 dark:bg-brand-500/10 dark:text-brand-300',
}

export function Badge({ tone = 'slate', children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium
        ring-1 ring-inset ${TONES[tone]}`}
    >
      {children}
    </span>
  )
}

// ----------------------------------------------------------------- Alert
export function Alert({
  tone = 'red',
  title,
  children,
}: {
  tone?: Tone
  title?: string
  children: ReactNode
}) {
  return (
    <div role="alert" className={`rounded-lg px-4 py-3 text-sm ring-1 ring-inset ${TONES[tone]}`}>
      {title && <p className="font-semibold">{title}</p>}
      <div className={title ? 'mt-0.5' : ''}>{children}</div>
    </div>
  )
}

// ----------------------------------------------------------------- misc
export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-12 text-sm text-slate-500 dark:text-slate-400">
      <span
        aria-hidden="true"
        className="h-5 w-5 animate-spin rounded-full border-2 border-slate-300 border-t-brand-600"
      />
      <span role="status">{label}…</span>
    </div>
  )
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-center">
      <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</p>
      <p className="max-w-sm text-sm text-slate-500 dark:text-slate-400">{description}</p>
      {action && <div className="mt-3">{action}</div>}
    </div>
  )
}

export function Modal({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
}) {
  if (!open) return null
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-xl bg-white shadow-xl dark:bg-slate-900"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800"
          >
            ✕
          </button>
        </header>
        <div className="max-h-[70vh] overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  )
}

/** Small shield mark used as the product logo. */
export function Logo({ className = 'h-7 w-7' }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <path
        d="M12 2.5 4.5 5.8v5.3c0 4.6 3.2 8.9 7.5 10.4 4.3-1.5 7.5-5.8 7.5-10.4V5.8L12 2.5Z"
        className="fill-brand-600"
      />
      <path d="m8.6 12.1 2.4 2.4 4.5-4.6" stroke="white" strokeWidth="1.9"
        strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
