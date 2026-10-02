import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { Alert, Badge, Card, EmptyState, Spinner } from '../components/ui'
import { formatBytes, formatRelative } from '../utils/format'
import { useAuth } from '../context/AuthContext'
import type { DashboardStats } from '../types/api'

function Stat({
  label,
  value,
  sub,
  to,
}: {
  label: string
  value: string | number
  sub?: string
  to?: string
}) {
  const body = (
    <div className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 transition hover:ring-brand-300 dark:bg-slate-900 dark:ring-slate-800">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </p>
      <p className="mt-2 text-2xl font-bold tabular-nums text-slate-900 dark:text-slate-100">
        {value}
      </p>
      {sub && <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{sub}</p>}
    </div>
  )
  return to ? (
    <Link to={to} className="block focus-visible:outline-none">
      {body}
    </Link>
  ) : (
    body
  )
}

const ACTION_LABELS: Record<string, string> = {
  LOGIN_SUCCESS: 'Signed in',
  LOGIN_FAILURE: 'Failed sign-in',
  LOGOUT: 'Signed out',
  USER_REGISTERED: 'Account created',
  PASSWORD_CHANGED: 'Password changed',
  FILE_UPLOADED: 'Uploaded a file',
  FILE_DOWNLOADED: 'Downloaded a file',
  FILE_DELETED: 'Deleted a file',
  FILE_VIEWED: 'Viewed file details',
  FILE_SHARED: 'Shared a file',
  SHARE_REVOKED: 'Revoked a share',
  SHARE_MODIFIED: 'Changed a share',
  SHARE_LINK_CREATED: 'Created a share link',
  SHARE_LINK_REVOKED: 'Revoked a share link',
  SHARE_LINK_DOWNLOAD: 'Link download',
  SHARE_LINK_ACCESSED: 'Link opened',
  TOKEN_REFRESHED: 'Session refreshed',
  TOKENS_REVOKED: 'Sessions revoked',
}

export default function Dashboard() {
  const { user } = useAuth()
  const { data, loading, error } = useAsync<DashboardStats>(
    () => api.get<DashboardStats>('/dashboard/stats/').then((r) => r.data),
    [],
  )

  if (loading) return <Spinner label="Loading your dashboard" />
  if (error) return <Alert tone="red">{error.message}</Alert>
  if (!data) return null

  const firstName = user?.full_name?.split(' ')[0] || 'there'

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Welcome back, {firstName}
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Every figure below is read live from your account.
        </p>
      </header>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Files stored"
          value={data.files.active}
          sub={data.files.deleted > 0 ? `${data.files.deleted} deleted` : 'all encrypted at rest'}
          to="/app/files"
        />
        <Stat
          label="Encrypted storage"
          value={formatBytes(data.files.encrypted_bytes)}
          sub={`${formatBytes(data.files.plaintext_bytes)} of plaintext`}
        />
        <Stat
          label="Shared with others"
          value={data.shares.outgoing_active}
          sub={`${data.shares.incoming_active} shared with you`}
          to="/app/files"
        />
        <Stat
          label="Active links"
          value={data.links.active}
          sub={`${data.links.total_downloads} link downloads`}
          to="/app/links"
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2" title="Recent activity">
          {data.recent_activity.length === 0 ? (
            <EmptyState
              title="Nothing recorded yet"
              description="Your audit trail fills up as you upload, share and download files."
            />
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {data.recent_activity.map((entry) => (
                <li key={entry.id} className="flex items-center justify-between gap-3 py-2.5">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-800 dark:text-slate-200">
                      {ACTION_LABELS[entry.action] ?? entry.action.replaceAll('_', ' ').toLowerCase()}
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {formatRelative(entry.timestamp)}
                    </p>
                  </div>
                  <Badge tone={entry.success ? 'green' : 'red'}>
                    {entry.success ? 'OK' : 'Failed'}
                  </Badge>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-4 border-t border-slate-100 pt-3 dark:border-slate-800">
            <Link to="/app/audit" className="text-sm font-medium text-brand-600 hover:underline">
              View the full activity log →
            </Link>
          </div>
        </Card>

        <div className="space-y-6">
          <Card title="Quick actions">
            <div className="space-y-2">
              <Link
                to="/app/upload"
                className="block rounded-lg bg-brand-600 px-4 py-2.5 text-center text-sm font-semibold text-white hover:bg-brand-700"
              >
                Upload a file
              </Link>
              <Link
                to="/app/files"
                className="block rounded-lg px-4 py-2.5 text-center text-sm font-semibold text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-slate-50 dark:text-slate-200 dark:ring-slate-700 dark:hover:bg-slate-800"
              >
                Manage my files
              </Link>
              <Link
                to="/app/links"
                className="block rounded-lg px-4 py-2.5 text-center text-sm font-semibold text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-slate-50 dark:text-slate-200 dark:ring-slate-700 dark:hover:bg-slate-800"
              >
                Review share links
              </Link>
            </div>
          </Card>

          <Card title="Share hygiene">
            <dl className="space-y-2.5 text-sm">
              <div className="flex justify-between">
                <dt className="text-slate-500 dark:text-slate-400">Expired shares</dt>
                <dd className="font-semibold tabular-nums text-slate-800 dark:text-slate-200">
                  {data.shares.outgoing_expired}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500 dark:text-slate-400">Revoked shares</dt>
                <dd className="font-semibold tabular-nums text-slate-800 dark:text-slate-200">
                  {data.shares.outgoing_revoked}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500 dark:text-slate-400">Expired links</dt>
                <dd className="font-semibold tabular-nums text-slate-800 dark:text-slate-200">
                  {data.links.expired}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500 dark:text-slate-400">Revoked links</dt>
                <dd className="font-semibold tabular-nums text-slate-800 dark:text-slate-200">
                  {data.links.revoked}
                </dd>
              </div>
            </dl>
          </Card>
        </div>
      </div>
    </div>
  )
}
