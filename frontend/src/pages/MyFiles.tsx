import { useCallback, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { normaliseBlobError } from '../api/client'
import { filesApi } from '../api/endpoints'
import { Alert, Badge, Button, EmptyState, Input, Modal, Spinner } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import {
  fileKindLabel,
  filenameFromDisposition,
  formatBytes,
  formatDate,
  saveBlob,
} from '../utils/format'
import type { Paginated, StoredFile } from '../types/api'

export default function MyFiles() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [banner, setBanner] = useState<{ tone: 'green' | 'red'; text: string } | null>(null)
  const [pendingDelete, setPendingDelete] = useState<StoredFile | null>(null)

  const loader = useCallback(
    () => filesApi.list({ page, page_size: 20, search: search || undefined }),
    [page, search],
  )
  const { data, loading, error, reload } = useAsync<Paginated<StoredFile>>(loader, [page, search])

  async function handleDownload(file: StoredFile) {
    setBusyId(file.id)
    setBanner(null)
    try {
      const response = await filesApi.download(file.id)
      const name = filenameFromDisposition(
        response.headers['content-disposition'] as string | undefined,
        file.filename,
      )
      saveBlob(response.data, name)
      setBanner({ tone: 'green', text: `Decrypted and downloaded ${name}.` })
    } catch (caught) {
      setBanner({ tone: 'red', text: (await normaliseBlobError(caught)).message })
    } finally {
      setBusyId(null)
    }
  }

  async function confirmDelete() {
    if (!pendingDelete) return
    const target = pendingDelete
    setBusyId(target.id)
    try {
      await filesApi.remove(target.id)
      setBanner({ tone: 'green', text: `${target.filename} was deleted.` })
      setPendingDelete(null)
      reload()
    } catch (caught) {
      setBanner({ tone: 'red', text: (await normaliseBlobError(caught)).message })
    } finally {
      setBusyId(null)
    }
  }

  const files = data?.results ?? []
  const totalPages = data ? Math.max(1, Math.ceil(data.count / 20)) : 1

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            My Files
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {data ? `${data.count} file${data.count === 1 ? '' : 's'}` : 'Loading'} · stored
            encrypted, decrypted only when you download.
          </p>
        </div>
        <Button onClick={() => navigate('/app/upload')}>Upload a file</Button>
      </header>

      <div className="max-w-sm">
        <Input
          label="Search"
          type="search"
          placeholder="Filename…"
          value={search}
          onChange={(event) => {
            setPage(1)
            setSearch(event.target.value)
          }}
        />
      </div>

      {banner && <Alert tone={banner.tone}>{banner.text}</Alert>}
      {error && <Alert tone="red">{error.message}</Alert>}

      {loading ? (
        <Spinner label="Loading your files" />
      ) : files.length === 0 ? (
        <div className="rounded-xl bg-white ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <EmptyState
            title={search ? 'No files match that search' : 'No files yet'}
            description={
              search
                ? 'Try a different filename.'
                : 'Upload your first file — it is encrypted with AES-256-GCM before it reaches disk.'
            }
            action={!search && <Button onClick={() => navigate('/app/upload')}>Upload a file</Button>}
          />
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-800">
              <caption className="sr-only">Files you own</caption>
              <thead className="bg-slate-50 dark:bg-slate-800/50">
                <tr>
                  {['Filename', 'Size', 'Type', 'Uploaded', 'Encryption', ''].map((heading, i) => (
                    <th
                      key={heading || i}
                      scope="col"
                      className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {files.map((file) => (
                  <tr key={file.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="max-w-xs px-4 py-3">
                      <Link
                        to={`/app/files/${file.id}`}
                        className="block truncate text-sm font-medium text-brand-700 hover:underline dark:text-brand-400"
                        title={file.filename}
                      >
                        {file.filename}
                      </Link>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-sm tabular-nums text-slate-600 dark:text-slate-400">
                      {formatBytes(file.size)}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                      {fileKindLabel(file.mime_type, file.extension)}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                      {formatDate(file.created_at)}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      {file.encryption.encrypted ? (
                        <Badge tone="green">🔒 {file.encryption.algorithm ?? 'AES-256-GCM'}</Badge>
                      ) : (
                        <Badge tone="red">Not encrypted</Badge>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-right">
                      <div className="flex justify-end gap-1">
                        <button
                          type="button"
                          onClick={() => handleDownload(file)}
                          disabled={busyId === file.id}
                          className="rounded px-2 py-1 text-xs font-medium text-brand-700 hover:bg-brand-50 disabled:opacity-50 dark:text-brand-400 dark:hover:bg-brand-500/10"
                        >
                          {busyId === file.id ? 'Working…' : 'Download'}
                        </button>
                        <Link
                          to={`/app/files/${file.id}`}
                          className="rounded px-2 py-1 text-xs font-medium text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
                        >
                          Details
                        </Link>
                        <Link
                          to={`/app/files/${file.id}/share`}
                          className="rounded px-2 py-1 text-xs font-medium text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
                        >
                          Share
                        </Link>
                        <button
                          type="button"
                          onClick={() => setPendingDelete(file)}
                          className="rounded px-2 py-1 text-xs font-medium text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-500/10"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
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
                Page {page} of {totalPages}
              </span>
              <Button
                variant="secondary"
                onClick={() => setPage((p) => p + 1)}
                disabled={!data?.next}
              >
                Next
              </Button>
            </nav>
          )}
        </div>
      )}

      <Modal open={Boolean(pendingDelete)} onClose={() => setPendingDelete(null)} title="Delete file">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          Delete <strong>{pendingDelete?.filename}</strong>? Active shares and links for
          this file stop working immediately.
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setPendingDelete(null)}>
            Cancel
          </Button>
          <Button variant="danger" loading={busyId === pendingDelete?.id} onClick={confirmDelete}>
            Delete permanently
          </Button>
        </div>
      </Modal>
    </div>
  )
}
