import { useCallback, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { normaliseBlobError, normaliseError } from '../api/client'
import { filesApi } from '../api/endpoints'
import { Alert, Badge, Button, Card, Modal, Spinner } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import {
  fileKindLabel,
  filenameFromDisposition,
  formatBytes,
  formatDate,
  saveBlob,
} from '../utils/format'
import type { StoredFile } from '../types/api'

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5 border-b border-slate-100 py-2.5 last:border-0 sm:flex-row sm:justify-between sm:gap-6 dark:border-slate-800">
      <dt className="text-sm text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="break-all text-sm font-medium text-slate-900 sm:text-right dark:text-slate-100">
        {value}
      </dd>
    </div>
  )
}

export default function FileDetails() {
  const { fileId = '' } = useParams()
  const navigate = useNavigate()
  const [busy, setBusy] = useState(false)
  const [banner, setBanner] = useState<{ tone: 'green' | 'red'; text: string } | null>(null)
  const [confirming, setConfirming] = useState(false)

  const loader = useCallback(() => filesApi.get(fileId), [fileId])
  const { data: file, loading, error } = useAsync<StoredFile>(loader, [fileId])

  async function handleDownload() {
    if (!file) return
    setBusy(true)
    setBanner(null)
    try {
      const response = await filesApi.download(file.id)
      const name = filenameFromDisposition(
        response.headers['content-disposition'] as string | undefined,
        file.filename,
      )
      saveBlob(response.data, name)
      setBanner({ tone: 'green', text: 'Decrypted and downloaded. Integrity verified.' })
    } catch (caught) {
      setBanner({ tone: 'red', text: (await normaliseBlobError(caught)).message })
    } finally {
      setBusy(false)
    }
  }

  async function handleDelete() {
    if (!file) return
    setBusy(true)
    try {
      await filesApi.remove(file.id)
      navigate('/app/files', { replace: true })
    } catch (caught) {
      setBanner({ tone: 'red', text: normaliseError(caught).message })
      setBusy(false)
      setConfirming(false)
    }
  }

  if (loading) return <Spinner label="Loading file" />
  if (error) {
    return (
      <div className="space-y-4">
        <Alert tone="red">{error.message}</Alert>
        <Link to="/app/files" className="text-sm font-medium text-brand-600 hover:underline">
          ← Back to my files
        </Link>
      </div>
    )
  }
  if (!file) return null

  const scan = file.malware_scan

  return (
    <div className="space-y-5">
      <nav aria-label="Breadcrumb">
        <Link to="/app/files" className="text-sm font-medium text-brand-600 hover:underline">
          ← My Files
        </Link>
      </nav>

      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="break-all text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            {file.filename}
          </h1>
          <p className="mt-1 flex flex-wrap items-center gap-2">
            <Badge tone="slate">{fileKindLabel(file.mime_type, file.extension)}</Badge>
            <Badge tone="slate">{formatBytes(file.size)}</Badge>
            {file.encryption.encrypted ? (
              <Badge tone="green">🔒 {file.encryption.algorithm}</Badge>
            ) : (
              <Badge tone="red">Not encrypted</Badge>
            )}
            {file.access.is_owner ? (
              <Badge tone="blue">You own this</Badge>
            ) : (
              <Badge tone="amber">Shared with you</Badge>
            )}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {file.access.can_download && (
            <Button onClick={handleDownload} loading={busy}>
              Download
            </Button>
          )}
          {file.access.is_owner && (
            <>
              <Button variant="secondary" onClick={() => navigate(`/app/files/${file.id}/share`)}>
                Share
              </Button>
              <Button variant="danger" onClick={() => setConfirming(true)}>
                Delete
              </Button>
            </>
          )}
        </div>
      </header>

      {banner && <Alert tone={banner.tone}>{banner.text}</Alert>}

      {!file.access.can_download && file.access.can_view && (
        <Alert tone="amber" title="View-only access">
          The owner granted you VIEW permission, so you can see this file's metadata but the
          server will refuse a download request.
        </Alert>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="File">
          <dl>
            <Row label="Filename" value={file.filename} />
            <Row label="Plaintext size" value={formatBytes(file.size)} />
            <Row label="Encrypted size" value={formatBytes(file.encrypted_size)} />
            <Row label="Detected type" value={file.mime_type} />
            <Row label="Extension" value={file.extension || '—'} />
            <Row label="Status" value={file.status} />
            <Row label="Uploaded" value={formatDate(file.created_at)} />
            <Row label="Last modified" value={formatDate(file.updated_at)} />
            <Row label="Downloads" value={file.download_count} />
            <Row
              label="Last downloaded"
              value={file.last_downloaded_at ? formatDate(file.last_downloaded_at) : 'Never'}
            />
            {file.owner && !file.access.is_owner && (
              <Row label="Owner" value={file.owner.email} />
            )}
          </dl>
        </Card>

        <div className="space-y-6">
          <Card title="Encryption">
            <dl>
              <Row
                label="At rest"
                value={
                  file.encryption.encrypted ? (
                    <span className="text-emerald-600 dark:text-emerald-400">Encrypted</span>
                  ) : (
                    <span className="text-rose-600">Not encrypted</span>
                  )
                }
              />
              <Row label="Cipher" value={file.encryption.algorithm ?? '—'} />
              <Row label="Key wrapping" value={file.encryption.key_wrapping_algorithm ?? '—'} />
              <Row label="Encrypted chunks" value={file.encryption.chunk_count ?? '—'} />
            </dl>
            <p className="mt-3 text-xs leading-relaxed text-slate-500 dark:text-slate-400">
              This file has its own data encryption key. The key is stored wrapped with
              RSA-OAEP and is never written, logged or returned in plaintext. Each chunk
              carries its own GCM authentication tag, so modified ciphertext is rejected
              rather than served.
            </p>
          </Card>

          <Card title="Integrity &amp; scanning">
            <dl>
              <Row
                label="SHA-256 (plaintext)"
                value={
                  <code className="font-mono text-xs">
                    {file.checksum_sha256
                      ? `${file.checksum_sha256.slice(0, 16)}…${file.checksum_sha256.slice(-8)}`
                      : '—'}
                  </code>
                }
              />
              <Row label="Malware scan" value={scan.status} />
              <Row
                label="Scanner"
                value={scan.scanner_enabled ? 'ClamAV enabled' : 'Not configured in this deployment'}
              />
              <Row label="Scanned at" value={scan.scanned_at ? formatDate(scan.scanned_at) : '—'} />
            </dl>
          </Card>
        </div>
      </div>

      <Modal open={confirming} onClose={() => setConfirming(false)} title="Delete file">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          Delete <strong>{file.filename}</strong>? Every share and public link for this file
          stops working immediately.
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setConfirming(false)}>
            Cancel
          </Button>
          <Button variant="danger" loading={busy} onClick={handleDelete}>
            Delete permanently
          </Button>
        </div>
      </Modal>
    </div>
  )
}
