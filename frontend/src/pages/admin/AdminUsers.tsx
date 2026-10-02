import { useCallback, useState } from 'react'
import { normaliseError } from '../../api/client'
import { adminApi } from '../../api/endpoints'
import { Alert, Badge, Button, EmptyState, Input, Modal, Select, Spinner } from '../../components/ui'
import { useAsync } from '../../hooks/useAsync'
import { useAuth } from '../../context/AuthContext'
import { formatDate } from '../../utils/format'
import type { AdminUser, Paginated } from '../../types/api'

const FILTERS = [
  { value: '', label: 'All accounts' },
  { value: 'active', label: 'Active' },
  { value: 'disabled', label: 'Disabled' },
  { value: 'locked', label: 'Locked out' },
  { value: 'admin', label: 'Administrators' },
]

export default function AdminUsers() {
  const { user: me } = useAuth()
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(1)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [banner, setBanner] = useState<{ tone: 'green' | 'red'; text: string } | null>(null)
  const [pending, setPending] = useState<AdminUser | null>(null)
  const [reason, setReason] = useState('')

  const loader = useCallback(
    () => adminApi.users({ search: search || undefined, status: status || undefined, page }),
    [search, status, page],
  )
  const { data, loading, error, reload } = useAsync<Paginated<AdminUser>>(loader, [
    search,
    status,
    page,
  ])

  async function applyToggle() {
    if (!pending) return
    setBusyId(pending.id)
    setBanner(null)
    try {
      const updated = await adminApi.setUserActive(pending.id, !pending.is_active, reason)
      setBanner({
        tone: 'green',
        text: `${updated.email} is now ${updated.is_active ? 'active' : 'disabled'}. The action was written to the audit log.`,
      })
      setPending(null)
      setReason('')
      reload()
    } catch (caught) {
      const normalised = normaliseError(caught)
      setBanner({ tone: 'red', text: normalised.fieldErrors?.is_active ?? normalised.message })
    } finally {
      setBusyId(null)
    }
  }

  async function unlock(target: AdminUser) {
    setBusyId(target.id)
    setBanner(null)
    try {
      await adminApi.unlockUser(target.id)
      setBanner({ tone: 'green', text: `Lockout cleared for ${target.email}.` })
      reload()
    } catch (caught) {
      setBanner({ tone: 'red', text: normaliseError(caught).message })
    } finally {
      setBusyId(null)
    }
  }

  const users = data?.results ?? []

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          User management
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          {data ? `${data.count} account${data.count === 1 ? '' : 's'}` : 'Loading'} · password
          hashes and tokens are never exposed through this API.
        </p>
      </header>

      {banner && <Alert tone={banner.tone}>{banner.text}</Alert>}
      {error && <Alert tone="red">{error.message}</Alert>}

      <div className="grid gap-3 sm:grid-cols-2">
        <Input
          label="Search"
          type="search"
          placeholder="Email or name…"
          value={search}
          onChange={(event) => {
            setPage(1)
            setSearch(event.target.value)
          }}
        />
        <Select
          label="Status"
          value={status}
          onChange={(value) => {
            setPage(1)
            setStatus(value)
          }}
          options={FILTERS}
        />
      </div>

      {loading ? (
        <Spinner label="Loading accounts" />
      ) : users.length === 0 ? (
        <div className="rounded-xl bg-white ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <EmptyState title="No matching accounts" description="Try a different search or filter." />
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-800">
              <caption className="sr-only">Registered accounts</caption>
              <thead className="bg-slate-50 dark:bg-slate-800/50">
                <tr>
                  {['User', 'Role', 'Status', 'Files', 'Failed logins', 'Last sign-in', ''].map(
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
                {users.map((row) => {
                  const self = row.id === me?.id
                  return (
                    <tr key={row.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                      <td className="max-w-[18rem] px-4 py-3">
                        <p className="truncate text-sm font-medium text-slate-900 dark:text-slate-100">
                          {row.full_name}
                        </p>
                        <p className="truncate text-xs text-slate-500 dark:text-slate-400">
                          {row.email}
                          {self && ' (you)'}
                        </p>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3">
                        <Badge tone={row.role === 'ADMIN' ? 'blue' : 'slate'}>{row.role}</Badge>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          <Badge tone={row.is_active ? 'green' : 'red'}>
                            {row.is_active ? 'Active' : 'Disabled'}
                          </Badge>
                          {row.is_locked && <Badge tone="amber">Locked</Badge>}
                        </div>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-sm tabular-nums text-slate-600 dark:text-slate-400">
                        {row.file_count}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-sm tabular-nums text-slate-600 dark:text-slate-400">
                        {row.failed_login_count}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                        {row.last_login ? formatDate(row.last_login) : 'Never'}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-right">
                        <div className="flex justify-end gap-1">
                          {row.is_locked && (
                            <button
                              type="button"
                              onClick={() => unlock(row)}
                              disabled={busyId === row.id}
                              className="rounded px-2 py-1 text-xs font-medium text-amber-700 hover:bg-amber-50 disabled:opacity-50 dark:text-amber-400 dark:hover:bg-amber-500/10"
                            >
                              Unlock
                            </button>
                          )}
                          {!self && (
                            <button
                              type="button"
                              onClick={() => {
                                setReason('')
                                setPending(row)
                              }}
                              disabled={busyId === row.id}
                              className={`rounded px-2 py-1 text-xs font-medium disabled:opacity-50 ${
                                row.is_active
                                  ? 'text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-500/10'
                                  : 'text-emerald-700 hover:bg-emerald-50 dark:text-emerald-400 dark:hover:bg-emerald-500/10'
                              }`}
                            >
                              {row.is_active ? 'Disable' : 'Re-enable'}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
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

      <Modal
        open={Boolean(pending)}
        onClose={() => setPending(null)}
        title={pending?.is_active ? 'Disable account' : 'Re-enable account'}
      >
        <p className="text-sm text-slate-600 dark:text-slate-300">
          {pending?.is_active ? (
            <>
              Disable <strong>{pending?.email}</strong>? They are signed out immediately —
              every issued token is invalidated — and cannot sign in again until re-enabled.
              Their files stay encrypted and intact.
            </>
          ) : (
            <>
              Re-enable <strong>{pending?.email}</strong>? They will be able to sign in again.
            </>
          )}
        </p>
        <div className="mt-4">
          <Input
            label="Reason (recorded in the audit log)"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="e.g. offboarding request #214"
            maxLength={200}
          />
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setPending(null)}>
            Cancel
          </Button>
          <Button
            variant={pending?.is_active ? 'danger' : 'primary'}
            loading={busyId === pending?.id}
            onClick={applyToggle}
          >
            {pending?.is_active ? 'Disable account' : 'Re-enable account'}
          </Button>
        </div>
      </Modal>
    </div>
  )
}
