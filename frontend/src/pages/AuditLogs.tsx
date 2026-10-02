import { useCallback, useState } from 'react'
import { auditApi } from '../api/endpoints'
import { Alert, Badge, Button, EmptyState, Select, Spinner } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { formatDate } from '../utils/format'
import type { AuditEntry, Paginated } from '../types/api'

const ACTIONS = [
  { value: '', label: 'All activity' },
  { value: 'LOGIN_SUCCESS', label: 'Successful sign-in' },
  { value: 'LOGIN_FAILURE', label: 'Failed sign-in' },
  { value: 'LOGOUT', label: 'Sign-out' },
  { value: 'PASSWORD_CHANGED', label: 'Password changed' },
  { value: 'FILE_UPLOADED', label: 'File uploaded' },
  { value: 'FILE_DOWNLOADED', label: 'File downloaded' },
  { value: 'FILE_DELETED', label: 'File deleted' },
  { value: 'FILE_SHARED', label: 'File shared' },
  { value: 'SHARE_REVOKED', label: 'Share revoked' },
  { value: 'SHARE_LINK_CREATED', label: 'Share link created' },
  { value: 'SHARE_LINK_DOWNLOAD', label: 'Share link download' },
  { value: 'SHARE_LINK_REVOKED', label: 'Share link revoked' },
]

const OUTCOMES = [
  { value: '', label: 'Any outcome' },
  { value: 'true', label: 'Succeeded' },
  { value: 'false', label: 'Failed' },
]

const WINDOWS = [
  { value: '', label: 'All time' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
]

function sinceIso(window: string): string | undefined {
  if (!window) return undefined
  const hours = window === '24h' ? 24 : window === '7d' ? 24 * 7 : 24 * 30
  return new Date(Date.now() - hours * 3_600_000).toISOString()
}

export default function AuditLogs() {
  const [action, setAction] = useState('')
  const [outcome, setOutcome] = useState('')
  const [window, setWindow] = useState('')
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState<string | null>(null)

  const loader = useCallback(
    () =>
      auditApi.list({
        page,
        page_size: 25,
        action: action || undefined,
        success: outcome || undefined,
        since: sinceIso(window),
      }),
    [action, outcome, window, page],
  )
  const { data, loading, error } = useAsync<Paginated<AuditEntry>>(loader, [
    action,
    outcome,
    window,
    page,
  ])

  const entries = data?.results ?? []

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Activity log
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Your own audit trail. Entries are append-only — nobody, including you, can edit or
          delete them through the API.
        </p>
      </header>

      <div className="grid gap-3 sm:grid-cols-3">
        <Select
          label="Event"
          value={action}
          onChange={(value) => {
            setPage(1)
            setAction(value)
          }}
          options={ACTIONS}
        />
        <Select
          label="Outcome"
          value={outcome}
          onChange={(value) => {
            setPage(1)
            setOutcome(value)
          }}
          options={OUTCOMES}
        />
        <Select
          label="Period"
          value={window}
          onChange={(value) => {
            setPage(1)
            setWindow(value)
          }}
          options={WINDOWS}
        />
      </div>

      {error && <Alert tone="red">{error.message}</Alert>}

      {loading ? (
        <Spinner label="Loading activity" />
      ) : entries.length === 0 ? (
        <div className="rounded-xl bg-white ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <EmptyState
            title="No matching events"
            description="Try widening the filters, or come back after uploading or sharing a file."
          />
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {entries.map((entry) => {
              const open = expanded === entry.id
              const hasMetadata = Object.keys(entry.metadata ?? {}).length > 0
              return (
                <li key={entry.id}>
                  <div className="flex flex-wrap items-center gap-3 px-4 py-3">
                    <Badge tone={entry.success ? 'green' : 'red'}>
                      {entry.success ? 'OK' : 'FAIL'}
                    </Badge>
                    <span className="font-mono text-xs text-slate-700 dark:text-slate-300">
                      {entry.action}
                    </span>
                    <span className="text-sm text-slate-500 dark:text-slate-400">
                      {entry.message || entry.object_type || '—'}
                    </span>
                    <span className="ml-auto whitespace-nowrap text-xs text-slate-400">
                      {formatDate(entry.timestamp)}
                    </span>
                    {hasMetadata && (
                      <button
                        type="button"
                        onClick={() => setExpanded(open ? null : entry.id)}
                        aria-expanded={open}
                        className="rounded px-2 py-1 text-xs font-medium text-brand-700 hover:bg-brand-50 dark:text-brand-400 dark:hover:bg-brand-500/10"
                      >
                        {open ? 'Hide' : 'Details'}
                      </button>
                    )}
                  </div>
                  {open && (
                    <div className="border-t border-slate-100 bg-slate-50 px-4 py-3 dark:border-slate-800 dark:bg-slate-800/40">
                      <dl className="grid gap-2 text-xs sm:grid-cols-2">
                        <div>
                          <dt className="text-slate-500 dark:text-slate-400">Severity</dt>
                          <dd className="font-medium text-slate-800 dark:text-slate-200">
                            {entry.severity}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-slate-500 dark:text-slate-400">Source IP</dt>
                          <dd className="font-mono text-slate-800 dark:text-slate-200">
                            {entry.ip_address ?? '—'}
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
                    </div>
                  )}
                </li>
              )
            })}
          </ul>

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
            <span className="text-sm text-slate-500 dark:text-slate-400">
              {data?.count ?? 0} event{data?.count === 1 ? '' : 's'} · page {page}
            </span>
            <Button variant="secondary" onClick={() => setPage((p) => p + 1)} disabled={!data?.next}>
              Next
            </Button>
          </nav>
        </div>
      )}
    </div>
  )
}
