import { Fragment, useCallback, useState } from 'react'
import { adminApi } from '../../api/endpoints'
import { Alert, Badge, Button, EmptyState, Input, Select, Spinner } from '../../components/ui'
import { useAsync } from '../../hooks/useAsync'
import { formatDate } from '../../utils/format'
import type { AuditEntry, Paginated } from '../../types/api'

const EVENTS = [
  { value: '', label: 'All events' },
  { value: 'LOGIN_SUCCESS', label: 'Sign-in succeeded' },
  { value: 'LOGIN_FAILURE', label: 'Sign-in failed' },
  { value: 'ACCOUNT_LOCKED', label: 'Account locked' },
  { value: 'ACCOUNT_DISABLED', label: 'Account disabled' },
  { value: 'UNAUTHORIZED_ACCESS_ATTEMPT', label: 'Unauthorized access attempt' },
  { value: 'UNAUTHORIZED_FILE_ACCESS', label: 'Unauthorized file access' },
  { value: 'UNAUTHORIZED_SHARE_ACCESS', label: 'Unauthorized share access' },
  { value: 'RATE_LIMIT_TRIGGERED', label: 'Rate limit triggered' },
  { value: 'SHARE_LINK_PASSWORD_FAILURE', label: 'Share password failure' },
  { value: 'SHARE_LINK_LOCKED', label: 'Share link locked' },
  { value: 'FILE_INTEGRITY_FAILURE', label: 'File integrity failure' },
  { value: 'ADMIN_ACTION', label: 'Administrative action' },
  { value: 'FILE_UPLOADED', label: 'File uploaded' },
  { value: 'FILE_DOWNLOADED', label: 'File downloaded' },
  { value: 'FILE_DELETED', label: 'File deleted' },
  { value: 'FILE_SHARED', label: 'File shared' },
]

const OUTCOMES = [
  { value: '', label: 'Any outcome' },
  { value: 'true', label: 'Succeeded' },
  { value: 'false', label: 'Failed' },
]

const WINDOWS = [
  { value: '', label: 'All time' },
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
]

function sinceIso(window: string): string | undefined {
  if (!window) return undefined
  const hours = window === '1h' ? 1 : window === '24h' ? 24 : window === '7d' ? 168 : 720
  return new Date(Date.now() - hours * 3_600_000).toISOString()
}

function severityTone(severity: string, success: boolean) {
  if (severity === 'CRITICAL') return 'red' as const
  if (severity === 'WARNING') return 'amber' as const
  return success ? ('green' as const) : ('red' as const)
}

export default function AdminEvents() {
  const [action, setAction] = useState('')
  const [actor, setActor] = useState('')
  const [outcome, setOutcome] = useState('')
  const [window, setWindow] = useState('24h')
  const [securityOnly, setSecurityOnly] = useState(false)
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState<string | null>(null)

  const loader = useCallback(
    () =>
      adminApi.securityEvents({
        page,
        page_size: 50,
        action: action || undefined,
        actor: actor || undefined,
        success: outcome || undefined,
        since: sinceIso(window),
        ...(securityOnly ? { security_only: 'true' } : {}),
      }),
    [action, actor, outcome, window, securityOnly, page],
  )
  const { data, loading, error } = useAsync<Paginated<AuditEntry>>(loader, [
    action,
    actor,
    outcome,
    window,
    securityOnly,
    page,
  ])

  const entries = data?.results ?? []

  function reset<T>(setter: (value: T) => void) {
    return (value: T) => {
      setPage(1)
      setter(value)
    }
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Security events
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          The full audit trail across every account.{' '}
          {data ? `${data.count} matching event${data.count === 1 ? '' : 's'}.` : ''}
        </p>
      </header>

      {error && <Alert tone="red">{error.message}</Alert>}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Select label="Event" value={action} onChange={reset(setAction)} options={EVENTS} />
        <Input
          label="User"
          type="search"
          placeholder="email contains…"
          value={actor}
          onChange={(event) => {
            setPage(1)
            setActor(event.target.value)
          }}
        />
        <Select label="Outcome" value={outcome} onChange={reset(setOutcome)} options={OUTCOMES} />
        <Select label="Period" value={window} onChange={reset(setWindow)} options={WINDOWS} />
      </div>

      <label className="flex w-fit items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
        <input
          type="checkbox"
          checked={securityOnly}
          onChange={(event) => {
            setPage(1)
            setSecurityOnly(event.target.checked)
          }}
          className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-600"
        />
        Security-relevant events only (failures, lockouts, blocked access, admin actions)
      </label>

      {loading ? (
        <Spinner label="Searching the audit log" />
      ) : entries.length === 0 ? (
        <div className="rounded-xl bg-white ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <EmptyState
            title="No events match"
            description="Widen the period or clear a filter. An empty result is a real result — nothing is invented here."
          />
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-800">
              <caption className="sr-only">Security events</caption>
              <thead className="bg-slate-50 dark:bg-slate-800/50">
                <tr>
                  {['When', 'Event', 'User', 'Outcome', 'Source IP', 'Object', ''].map(
                    (heading, i) => (
                      <th
                        key={heading || i}
                        scope="col"
                        className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400"
                      >
                        {heading}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {entries.map((entry) => {
                  const open = expanded === entry.id
                  return (
                    <Fragment key={entry.id}>
                      <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                        <td className="whitespace-nowrap px-4 py-2.5 text-xs text-slate-600 dark:text-slate-400">
                          {formatDate(entry.timestamp)}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5">
                          <code className="font-mono text-xs text-slate-800 dark:text-slate-200">
                            {entry.action}
                          </code>
                        </td>
                        <td className="max-w-[14rem] truncate px-4 py-2.5 text-xs text-slate-600 dark:text-slate-400">
                          {entry.actor?.email ?? <span className="italic">anonymous</span>}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5">
                          <Badge tone={severityTone(entry.severity, entry.success)}>
                            {entry.success ? 'OK' : 'FAIL'}
                          </Badge>
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-slate-600 dark:text-slate-400">
                          {entry.ip_address ?? '—'}
                        </td>
                        <td className="max-w-[10rem] truncate px-4 py-2.5 text-xs text-slate-600 dark:text-slate-400">
                          {entry.object_type || '—'}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5 text-right">
                          <button
                            type="button"
                            onClick={() => setExpanded(open ? null : entry.id)}
                            aria-expanded={open}
                            className="rounded px-2 py-1 text-xs font-medium text-brand-700 hover:bg-brand-50 dark:text-brand-400 dark:hover:bg-brand-500/10"
                          >
                            {open ? 'Hide' : 'Inspect'}
                          </button>
                        </td>
                      </tr>
                      {open && (
                        <tr>
                          <td colSpan={7} className="bg-slate-50 px-4 py-3 dark:bg-slate-800/40">
                            <dl className="grid gap-3 text-xs sm:grid-cols-2">
                              <div>
                                <dt className="text-slate-500 dark:text-slate-400">Severity</dt>
                                <dd className="font-medium text-slate-800 dark:text-slate-200">
                                  {entry.severity}
                                </dd>
                              </div>
                              <div>
                                <dt className="text-slate-500 dark:text-slate-400">Actor role</dt>
                                <dd className="font-medium text-slate-800 dark:text-slate-200">
                                  {entry.actor?.role ?? '—'}
                                </dd>
                              </div>
                              <div className="sm:col-span-2">
                                <dt className="text-slate-500 dark:text-slate-400">Message</dt>
                                <dd className="text-slate-800 dark:text-slate-200">
                                  {entry.message || '—'}
                                </dd>
                              </div>
                              <div className="sm:col-span-2">
                                <dt className="text-slate-500 dark:text-slate-400">User agent</dt>
                                <dd className="break-all font-mono text-slate-700 dark:text-slate-300">
                                  {entry.user_agent || '—'}
                                </dd>
                              </div>
                              <div className="sm:col-span-2">
                                <dt className="text-slate-500 dark:text-slate-400">Metadata</dt>
                                <dd>
                                  <pre className="mt-1 overflow-x-auto rounded bg-white p-2 font-mono text-[11px] text-slate-700 ring-1 ring-slate-200 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-700">
                                    {JSON.stringify(entry.metadata, null, 2)}
                                  </pre>
                                </dd>
                              </div>
                            </dl>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>

          <nav
            className="flex items-center justify-between border-t border-slate-200 px-4 py-3 dark:border-slate-800"
            aria-label="Pagination"
          >
            <Button
              variant="secondary"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              Previous
            </Button>
            <span className="text-sm text-slate-500 dark:text-slate-400">Page {page}</span>
            <Button variant="secondary" onClick={() => setPage((p) => p + 1)} disabled={!data?.next}>
              Next
            </Button>
          </nav>
        </div>
      )}
    </div>
  )
}
