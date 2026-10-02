import { useCallback, useState } from 'react'
import { Link } from 'react-router-dom'
import { normaliseError } from '../api/client'
import { linksApi, sharingApi } from '../api/endpoints'
import { Alert, Badge, EmptyState, Select, Spinner } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { formatBytes, formatDate } from '../utils/format'
import type { FileShare, Paginated, ShareLink } from '../types/api'

const STATUSES = [
  { value: '', label: 'All statuses' },
  { value: 'active', label: 'Active' },
  { value: 'expired', label: 'Expired' },
  { value: 'revoked', label: 'Revoked' },
]

function statusTone(status: string) {
  if (status === 'ACTIVE') return 'green' as const
  if (status === 'REVOKED') return 'red' as const
  return 'amber' as const
}

export default function ShareLinks() {
  const [status, setStatus] = useState('')
  const [banner, setBanner] = useState<{ tone: 'green' | 'red'; text: string } | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)

  const linkLoader = useCallback(
    () => linksApi.list(status ? { status } : undefined),
    [status],
  )
  const {
    data: links,
    loading: linksLoading,
    error: linksError,
    reload: reloadLinks,
  } = useAsync<Paginated<ShareLink>>(linkLoader, [status])

  const sharesLoader = useCallback(() => sharingApi.mySharesOut(), [])
  const {
    data: shares,
    loading: sharesLoading,
    reload: reloadShares,
  } = useAsync<Paginated<FileShare>>(sharesLoader, [])

  async function revokeLink(link: ShareLink) {
    setBusyId(link.id)
    setBanner(null)
    try {
      await linksApi.revoke(link.id)
      setBanner({ tone: 'green', text: 'Link revoked. It stops working immediately.' })
      reloadLinks()
    } catch (caught) {
      setBanner({ tone: 'red', text: normaliseError(caught).message })
    } finally {
      setBusyId(null)
    }
  }

  async function revokeShare(share: FileShare) {
    setBusyId(share.id)
    setBanner(null)
    try {
      await sharingApi.revokeShare(share.id)
      setBanner({ tone: 'green', text: `Access for ${share.recipient.email} was revoked.` })
      reloadShares()
    } catch (caught) {
      setBanner({ tone: 'red', text: normaliseError(caught).message })
    } finally {
      setBusyId(null)
    }
  }

  const linkRows = links?.results ?? []
  const shareRows = shares?.results ?? []

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Share Links
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Everything you have shared. Raw tokens are never shown again — only a short,
          log-safe prefix.
        </p>
      </header>

      {banner && <Alert tone={banner.tone}>{banner.text}</Alert>}
      {linksError && <Alert tone="red">{linksError.message}</Alert>}

      <section className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
            Public links
          </h2>
          <div className="w-48">
            <Select label="Filter" value={status} onChange={setStatus} options={STATUSES} />
          </div>
        </div>

        {linksLoading ? (
          <Spinner label="Loading links" />
        ) : linkRows.length === 0 ? (
          <div className="rounded-xl bg-white ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
            <EmptyState
              title="No public links"
              description="Open a file and choose Share to create a link with an expiry and a download limit."
            />
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-800">
                <caption className="sr-only">Public share links you created</caption>
                <thead className="bg-slate-50 dark:bg-slate-800/50">
                  <tr>
                    {['File', 'Token', 'Downloads', 'Expires', 'Protection', 'Status', ''].map(
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
                  {linkRows.map((link) => (
                    <tr key={link.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                      <td className="max-w-[16rem] px-4 py-3">
                        <Link
                          to={`/app/files/${link.file.id}`}
                          className="block truncate text-sm font-medium text-brand-700 hover:underline dark:text-brand-400"
                        >
                          {link.file.filename}
                        </Link>
                        <span className="text-xs text-slate-500 dark:text-slate-400">
                          {formatBytes(link.file.size)}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3">
                        <code className="font-mono text-xs text-slate-600 dark:text-slate-400">
                          …{link.token_prefix}
                        </code>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-sm tabular-nums text-slate-600 dark:text-slate-400">
                        {link.download_count}
                        {link.max_downloads ? ` / ${link.max_downloads}` : ' / ∞'}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                        {formatDate(link.expires_at)}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3">
                        {link.password_protected ? (
                          <Badge tone="blue">Password</Badge>
                        ) : (
                          <span className="text-xs text-slate-400">None</span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3">
                        <Badge tone={statusTone(link.status)}>{link.status}</Badge>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-right">
                        {link.is_active && (
                          <button
                            type="button"
                            onClick={() => revokeLink(link)}
                            disabled={busyId === link.id}
                            className="rounded px-2 py-1 text-xs font-medium text-rose-600 hover:bg-rose-50 disabled:opacity-50 dark:hover:bg-rose-500/10"
                          >
                            {busyId === link.id ? 'Revoking…' : 'Revoke'}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
          Shared with specific people
        </h2>
        {sharesLoading ? (
          <Spinner label="Loading shares" />
        ) : shareRows.length === 0 ? (
          <div className="rounded-xl bg-white ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
            <EmptyState
              title="No direct shares"
              description="Grant another SecureShare user access from a file's Share page."
            />
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-800">
                <caption className="sr-only">Files you shared with other users</caption>
                <thead className="bg-slate-50 dark:bg-slate-800/50">
                  <tr>
                    {['File', 'Recipient', 'Permission', 'Expires', 'Status', ''].map(
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
                  {shareRows.map((share) => (
                    <tr key={share.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                      <td className="max-w-[16rem] px-4 py-3">
                        <Link
                          to={`/app/files/${share.file.id}`}
                          className="block truncate text-sm font-medium text-brand-700 hover:underline dark:text-brand-400"
                        >
                          {share.file.filename}
                        </Link>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                        {share.recipient.email}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3">
                        <Badge tone={share.permission === 'DOWNLOAD' ? 'green' : 'amber'}>
                          {share.permission}
                        </Badge>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                        {share.expires_at ? formatDate(share.expires_at) : 'No expiry'}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3">
                        <Badge tone={statusTone(share.status)}>{share.status}</Badge>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-right">
                        {share.is_active && (
                          <button
                            type="button"
                            onClick={() => revokeShare(share)}
                            disabled={busyId === share.id}
                            className="rounded px-2 py-1 text-xs font-medium text-rose-600 hover:bg-rose-50 disabled:opacity-50 dark:hover:bg-rose-500/10"
                          >
                            {busyId === share.id ? 'Revoking…' : 'Revoke'}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>
    </div>
  )
}
