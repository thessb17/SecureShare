import { useCallback, useState } from 'react'
import { Link } from 'react-router-dom'
import { normaliseBlobError } from '../api/client'
import { sharingApi } from '../api/endpoints'
import { Alert, Badge, EmptyState, Spinner } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { filenameFromDisposition, formatBytes, formatDate, saveBlob } from '../utils/format'
import type { FileShare, Paginated } from '../types/api'

export default function SharedWithMe() {
  const loader = useCallback(() => sharingApi.sharedWithMe(), [])
  const { data, loading, error, reload } = useAsync<Paginated<FileShare>>(loader, [])
  const [busyId, setBusyId] = useState<string | null>(null)
  const [banner, setBanner] = useState<{ tone: 'green' | 'red'; text: string } | null>(null)

  async function handleDownload(share: FileShare) {
    setBusyId(share.id)
    setBanner(null)
    try {
      const response = await sharingApi.downloadShared(share.file.id)
      const name = filenameFromDisposition(
        response.headers['content-disposition'] as string | undefined,
        share.file.filename,
      )
      saveBlob(response.data, name)
      setBanner({ tone: 'green', text: `Downloaded ${name}.` })
      reload()
    } catch (caught) {
      setBanner({ tone: 'red', text: (await normaliseBlobError(caught)).message })
    } finally {
      setBusyId(null)
    }
  }

  const shares = data?.results ?? []

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Shared with me
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Files other people granted you access to. You cannot re-share them — the server
          refuses that.
        </p>
      </header>

      {banner && <Alert tone={banner.tone}>{banner.text}</Alert>}
      {error && <Alert tone="red">{error.message}</Alert>}

      {loading ? (
        <Spinner label="Loading shared files" />
      ) : shares.length === 0 ? (
        <div className="rounded-xl bg-white ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <EmptyState
            title="Nothing shared with you yet"
            description="When someone shares a file with your account it will appear here."
          />
        </div>
      ) : (
        <ul className="grid gap-4 sm:grid-cols-2">
          {shares.map((share) => {
            const canDownload = share.permission === 'DOWNLOAD' && share.is_active
            return (
              <li
                key={share.id}
                className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h2 className="truncate text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {share.file.filename}
                    </h2>
                    <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                      from {share.owner.email}
                    </p>
                  </div>
                  <Badge tone={share.permission === 'DOWNLOAD' ? 'green' : 'amber'}>
                    {share.permission}
                  </Badge>
                </div>

                <dl className="mt-3 space-y-1 text-xs text-slate-500 dark:text-slate-400">
                  <div className="flex justify-between">
                    <dt>Size</dt>
                    <dd className="tabular-nums">{formatBytes(share.file.size)}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Shared</dt>
                    <dd>{formatDate(share.created_at)}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Expires</dt>
                    <dd>{share.expires_at ? formatDate(share.expires_at) : 'No expiry'}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Status</dt>
                    <dd>{share.status}</dd>
                  </div>
                </dl>

                <div className="mt-4 flex items-center gap-2">
                  {canDownload ? (
                    <button
                      type="button"
                      onClick={() => handleDownload(share)}
                      disabled={busyId === share.id}
                      className="rounded-lg bg-brand-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-brand-700 disabled:opacity-60"
                    >
                      {busyId === share.id ? 'Downloading…' : 'Download'}
                    </button>
                  ) : (
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      {share.is_active ? 'View-only — download is blocked' : 'No longer available'}
                    </span>
                  )}
                  {share.is_active && (
                    <Link
                      to={`/app/files/${share.file.id}`}
                      className="rounded-lg px-3 py-1.5 text-xs font-semibold text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-slate-50 dark:text-slate-200 dark:ring-slate-700 dark:hover:bg-slate-800"
                    >
                      Details
                    </Link>
                  )}
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
