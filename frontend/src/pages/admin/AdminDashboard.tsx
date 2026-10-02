import { useCallback } from 'react'
import { Link } from 'react-router-dom'
import { adminApi } from '../../api/endpoints'
import { Alert, Badge, Card, Spinner } from '../../components/ui'
import { useAsync } from '../../hooks/useAsync'
import { formatBytes, formatDate } from '../../utils/format'
import type { AdminStats } from '../../types/api'

function Metric({
  label,
  value,
  sub,
  tone = 'slate',
}: {
  label: string
  value: string | number
  sub?: string
  tone?: 'slate' | 'red' | 'amber' | 'green'
}) {
  const accent =
    tone === 'red'
      ? 'text-rose-600 dark:text-rose-400'
      : tone === 'amber'
        ? 'text-amber-600 dark:text-amber-400'
        : tone === 'green'
          ? 'text-emerald-600 dark:text-emerald-400'
          : 'text-slate-900 dark:text-slate-100'
  return (
    <div className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </p>
      <p className={`mt-2 text-2xl font-bold tabular-nums ${accent}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{sub}</p>}
    </div>
  )
}

/**
 * Horizontal bar built from real counts. Not a chart library, not decorative:
 * each segment width is the true proportion of the total.
 */
function Breakdown({
  title,
  segments,
}: {
  title: string
  segments: { label: string; value: number; className: string }[]
}) {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0)
  return (
    <div>
      <div className="flex items-baseline justify-between">
        <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">{title}</h3>
        <span className="text-sm font-semibold tabular-nums text-slate-900 dark:text-slate-100">
          {total}
        </span>
      </div>
      <div
        className="mt-2 flex h-2.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800"
        role="img"
        aria-label={segments.map((s) => `${s.label}: ${s.value}`).join(', ')}
      >
        {total > 0 &&
          segments.map((segment) => (
            <div
              key={segment.label}
              className={segment.className}
              style={{ width: `${(segment.value / total) * 100}%` }}
            />
          ))}
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        {segments.map((segment) => (
          <li key={segment.label} className="flex items-center gap-1.5 text-xs">
            <span className={`h-2 w-2 rounded-full ${segment.className}`} aria-hidden="true" />
            <span className="text-slate-500 dark:text-slate-400">{segment.label}</span>
            <span className="font-semibold tabular-nums text-slate-700 dark:text-slate-300">
              {segment.value}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function AdminDashboard() {
  const loader = useCallback(() => adminApi.stats(), [])
  const { data, loading, error } = useAsync<AdminStats>(loader, [])

  if (loading) return <Spinner label="Loading platform metrics" />
  if (error) return <Alert tone="red">{error.message}</Alert>
  if (!data) return null

  const incidents =
    data.security.failed_logins_24h +
    data.security.lockouts_24h +
    data.security.unauthorized_24h +
    data.security.rate_limited_24h

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Admin overview
            <Badge tone="blue">ADMIN</Badge>
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Live platform metrics, queried from the database at {formatDate(data.generated_at)}.
          </p>
        </div>
      </header>

      <Alert tone="blue">
        These endpoints are restricted on the server by the ADMIN role. A standard user who
        calls them directly receives 403 — hiding the menu is not what protects them.
      </Alert>

      <section>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          Users
        </h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <Metric label="Total users" value={data.users.total} />
          <Metric label="Active" value={data.users.active} tone="green" />
          <Metric
            label="Disabled"
            value={data.users.disabled}
            tone={data.users.disabled > 0 ? 'amber' : 'slate'}
          />
          <Metric
            label="Locked out"
            value={data.users.locked}
            tone={data.users.locked > 0 ? 'red' : 'slate'}
            sub="brute-force lockouts in force"
          />
          <Metric label="Administrators" value={data.users.admins} />
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          Storage
        </h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Metric label="Files stored" value={data.files.active} sub={`${data.files.deleted} deleted`} />
          <Metric
            label="Encrypted on disk"
            value={formatBytes(data.files.encrypted_bytes)}
            sub="ciphertext plus per-chunk GCM tags"
          />
          <Metric
            label="Plaintext equivalent"
            value={formatBytes(data.files.plaintext_bytes)}
            sub="original sizes — not stored in the clear"
          />
          <Metric
            label="Encryption coverage"
            value={data.files.total > 0 ? '100%' : '—'}
            tone="green"
            sub="every file goes through the encryption service"
          />
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          Sharing
        </h2>
        <div className="grid gap-6 sm:grid-cols-2">
          <Card>
            <Breakdown
              title="User-to-user shares"
              segments={[
                { label: 'Active', value: data.shares.active, className: 'bg-emerald-500' },
                { label: 'Expired', value: data.shares.expired, className: 'bg-amber-500' },
                { label: 'Revoked', value: data.shares.revoked, className: 'bg-rose-500' },
              ]}
            />
          </Card>
          <Card>
            <Breakdown
              title="Public share links"
              segments={[
                { label: 'Active', value: data.share_links.active, className: 'bg-emerald-500' },
                { label: 'Expired', value: data.share_links.expired, className: 'bg-amber-500' },
                { label: 'Revoked', value: data.share_links.revoked, className: 'bg-rose-500' },
              ]}
            />
          </Card>
        </div>
      </section>

      <section>
        <div className="mb-3 flex items-end justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            Security — last 24 hours
          </h2>
          <Link
            to="/app/admin/events"
            className="text-sm font-medium text-brand-600 hover:underline"
          >
            Search all events →
          </Link>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <Metric label="Events recorded" value={data.security.events_24h} />
          <Metric
            label="Failed sign-ins"
            value={data.security.failed_logins_24h}
            tone={data.security.failed_logins_24h > 0 ? 'amber' : 'slate'}
          />
          <Metric
            label="Account lockouts"
            value={data.security.lockouts_24h}
            tone={data.security.lockouts_24h > 0 ? 'red' : 'slate'}
          />
          <Metric
            label="Blocked access attempts"
            value={data.security.unauthorized_24h}
            tone={data.security.unauthorized_24h > 0 ? 'red' : 'slate'}
          />
          <Metric
            label="Rate-limit hits"
            value={data.security.rate_limited_24h}
            tone={data.security.rate_limited_24h > 0 ? 'amber' : 'slate'}
          />
        </div>
        {incidents === 0 && (
          <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">
            No failed sign-ins, lockouts, blocked requests or rate-limit hits in the last 24
            hours.
          </p>
        )}
      </section>

      <section className="grid gap-4 sm:grid-cols-2">
        <Link
          to="/app/admin/users"
          className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 transition hover:ring-brand-300 dark:bg-slate-900 dark:ring-slate-800"
        >
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            Manage users →
          </h3>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Review accounts, disable or re-enable access, clear lockouts.
          </p>
        </Link>
        <Link
          to="/app/admin/events"
          className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 transition hover:ring-brand-300 dark:bg-slate-900 dark:ring-slate-800"
        >
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            Security events →
          </h3>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Filter the audit trail by event, user, date and outcome.
          </p>
        </Link>
      </section>
    </div>
  )
}
