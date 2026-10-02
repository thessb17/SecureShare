import { useRef, useState, type ChangeEvent, type DragEvent } from 'react'
import { Link } from 'react-router-dom'
import { normaliseError } from '../api/client'
import { filesApi } from '../api/endpoints'
import { Alert, Badge, Button, Card } from '../components/ui'
import { formatBytes } from '../utils/format'
import type { StoredFile } from '../types/api'

/** Mirrors the server limit; the server re-checks and is the real authority. */
const MAX_BYTES = 100 * 1024 * 1024

export default function Upload() {
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [progress, setProgress] = useState(0)
  const [uploading, setUploading] = useState(false)
  const [uploaded, setUploaded] = useState<StoredFile | null>(null)
  const [error, setError] = useState<string | null>(null)

  function choose(candidate: File | null) {
    setError(null)
    setUploaded(null)
    setProgress(0)
    if (!candidate) {
      setFile(null)
      return
    }
    if (candidate.size === 0) {
      setError('That file is empty.')
      setFile(null)
      return
    }
    if (candidate.size > MAX_BYTES) {
      setError(`That file is ${formatBytes(candidate.size)}; the limit is ${formatBytes(MAX_BYTES)}.`)
      setFile(null)
      return
    }
    setFile(candidate)
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setDragging(false)
    choose(event.dataTransfer.files?.[0] ?? null)
  }

  function onPick(event: ChangeEvent<HTMLInputElement>) {
    choose(event.target.files?.[0] ?? null)
  }

  async function startUpload() {
    if (!file) return
    setUploading(true)
    setError(null)
    setProgress(0)
    try {
      const stored = await filesApi.upload(file, setProgress)
      setUploaded(stored)
      setFile(null)
      if (inputRef.current) inputRef.current.value = ''
    } catch (caught) {
      const normalised = normaliseError(caught)
      const detail = normalised.fieldErrors?.file
      setError(detail ? `${normalised.message} ${detail}` : normalised.message)
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-5">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Upload a file
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Your file is encrypted on the server before any bytes are written to disk.
        </p>
      </header>

      {uploaded && (
        <Alert tone="green" title="Upload complete">
          <p>
            <strong>{uploaded.filename}</strong> ({formatBytes(uploaded.size)}) is
            stored encrypted.
          </p>
          <p className="mt-1.5 flex flex-wrap items-center gap-2">
            <Badge tone="green">🔒 Encrypted with {uploaded.encryption.algorithm ?? 'AES-256-GCM'}</Badge>
            {uploaded.encryption.key_wrapping_algorithm && (
              <Badge tone="blue">Key wrapped with {uploaded.encryption.key_wrapping_algorithm}</Badge>
            )}
          </p>
          <p className="mt-3 flex gap-3">
            <Link
              to={`/app/files/${uploaded.id}`}
              className="font-medium text-brand-700 hover:underline dark:text-brand-400"
            >
              View details
            </Link>
            <Link
              to={`/app/files/${uploaded.id}/share`}
              className="font-medium text-brand-700 hover:underline dark:text-brand-400"
            >
              Share it
            </Link>
          </p>
        </Alert>
      )}

      {error && <Alert tone="red">{error}</Alert>}

      <Card>
        <div
          onDragOver={(event) => {
            event.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`rounded-xl border-2 border-dashed px-6 py-12 text-center transition ${
            dragging
              ? 'border-brand-500 bg-brand-50 dark:bg-brand-500/10'
              : 'border-slate-300 dark:border-slate-700'
          }`}
        >
          <p className="text-sm font-medium text-slate-700 dark:text-slate-200">
            Drag a file here
          </p>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">or</p>
          <button
            type="button"
            onClick={() => inputRef.current?.click()}
            className="mt-3 rounded-lg bg-white px-4 py-2 text-sm font-semibold text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:ring-slate-700"
          >
            Choose a file
          </button>
          <input
            ref={inputRef}
            type="file"
            className="sr-only"
            onChange={onPick}
            aria-label="Choose a file to upload"
          />
          <p className="mt-4 text-xs text-slate-500 dark:text-slate-400">
            Up to {formatBytes(MAX_BYTES)}. The server verifies the real file type from its
            magic bytes, not from the name or the browser's claim.
          </p>
        </div>

        {file && (
          <div className="mt-5 rounded-lg bg-slate-50 p-4 dark:bg-slate-800/60">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-slate-900 dark:text-slate-100">
                  {file.name}
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {formatBytes(file.size)} · browser reports {file.type || 'unknown type'}
                </p>
              </div>
              {!uploading && (
                <button
                  type="button"
                  onClick={() => choose(null)}
                  className="text-xs font-medium text-slate-500 hover:text-slate-700 dark:hover:text-slate-200"
                >
                  Remove
                </button>
              )}
            </div>

            {uploading && (
              <div className="mt-3">
                <div
                  className="h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700"
                  role="progressbar"
                  aria-valuenow={progress}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-label="Upload progress"
                >
                  <div
                    className="h-full rounded-full bg-brand-600 transition-all"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
                  {progress < 100
                    ? `Uploading… ${progress}%`
                    : 'Transfer complete — encrypting on the server…'}
                </p>
              </div>
            )}

            <div className="mt-4 flex justify-end">
              <Button onClick={startUpload} loading={uploading}>
                Encrypt and upload
              </Button>
            </div>
          </div>
        )}
      </Card>

      <Card title="What happens to this file">
        <ol className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
          <li>1. The server checks the real content type from the file's magic bytes.</li>
          <li>2. A fresh 256-bit data encryption key is generated from the OS CSPRNG.</li>
          <li>3. The file is sealed chunk by chunk with AES-256-GCM, each chunk with its own nonce.</li>
          <li>4. The data key is wrapped with RSA-OAEP; the plaintext key is never stored.</li>
          <li>5. Only ciphertext reaches disk — the upload's plaintext is discarded.</li>
        </ol>
      </Card>
    </div>
  )
}
