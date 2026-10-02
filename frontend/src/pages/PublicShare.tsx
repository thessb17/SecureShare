import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { normaliseBlobError, normaliseError, type NormalisedError } from '../api/client'
import { publicShareApi } from '../api/endpoints'
import { Alert, Badge, Button, Input, Logo } from '../components/ui'
import { filenameFromDisposition, formatBytes, formatCountdown, saveBlob } from '../utils/format'
import type { PublicShareInfo } from '../types/api'

/**
 * Anonymous landing page for /s/<token>.
 *
 * The token stays in component state and is never persisted. Nothing here is
 * trusted: expiry, download limits, revocation and the password are all
 * re-checked by the server on the download request itself.
 */
export default function PublicShare() {
  const { token = '' } = useParams()

  const [info, setInfo] = useState<PublicShareInfo | null>(null)
  const [grant, setGrant] = useState<string | null>(null)
  const [loadError, setLoadError] = useState<NormalisedError | null>(null)
  const [loading, setLoading] = useState(true)

  const [password, setPassword] = useState('')
  const [verifying, setVerifying] = useState(false)
  const [passwordError, setPasswordError] = useState<string | null>(null)

  const [downloading, setDownloading] = useState(false)
  const [downloadError, setDownloadError] = useState<string | null>(null)
  const [downloaded, setDownloaded] = useState<string | null>(null)
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null)

  const load = useCallback(
    async (withGrant?: string) => {
      setLoading(true)
      setLoadError(null)
      try {
        const result = await publicShareApi.info(token, withGrant ?? grant ?? undefined)
        setInfo(result)
        setSecondsLeft(result.expires_in_seconds ?? null)
      } catch (caught) {
        setLoadError(normaliseError(caught))
      } finally {
        setLoading(false)
      }
    },
    [token, grant],
  )

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token])

  // Live countdown so a visitor can see the link ageing out. The interval is
  // keyed on whether a countdown exists at all, not on its current value, so
  // it is created once per link rather than once per second.
  const counting = secondsLeft !== null
  useEffect(() => {
    if (!counting) return undefined
    const timer = window.setInterval(() => {
      setSecondsLeft((value) => (value === null ? null : Math.max(0, value - 1)))
    }, 1000)
    return () => window.clearInterval(timer)
  }, [counting])

  async function submitPassword(event: FormEvent) {
    event.preventDefault()
    setVerifying(true)
    setPasswordError(null)
    try {
      const result = await publicShareApi.verifyPassword(token, password)
      setGrant(result.grant)
      setPassword('')
      await load(result.grant)
    } catch (caught) {
      setPasswordError(normaliseError(caught).message)
    } finally {
      setVerifying(false)
    }
  }

  async function startDownload() {
    setDownloading(true)
    setDownloadError(null)
    setDownloaded(null)
    try {
      const response = await publicShareApi.download(token, grant ? { grant } : {})
      const name = filenameFromDisposition(
        response.headers['content-disposition'] as string | undefined,
        info?.filename ?? 'download',
      )
      saveBlob(response.data, name)
      setDownloaded(name)
      await load()
    } catch (caught) {
      // A Blob responseType means the error body arrives as a Blob; read it.
      const normalised = await normaliseBlobError(caught)
      setDownloadError(normalised.message)
      await load()
    } finally {
      setDownloading(false)
    }
  }

  const expired = secondsLeft !== null && secondsLeft <= 0

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-50 px-4 py-10 dark:bg-slate-950">
      <Link to="/" className="mb-6 flex items-center gap-2">
        <Logo className="h-8 w-8" />
        <span className="text-lg font-bold tracking-tight text-slate-900 dark:text-slate-100">
          SecureShare
        </span>
      </Link>

      <main className="w-full max-w-lg rounded-xl bg-white p-7 shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
        {loading && (
          <p className="py-8 text-center text-sm text-slate-500 dark:text-slate-400" role="status">
            Checking this link…
          </p>
        )}

        {!loading && loadError && (
          <div className="space-y-4">
            <h1 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              This link cannot be opened
            </h1>
            <Alert tone={loadError.code === 'SHARE_LINK_EXPIRED' ? 'amber' : 'red'}>
              {loadError.message}
            </Alert>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Ask the person who sent it to issue a new one.
            </p>
          </div>
        )}

        {/* The server answers with password_required and nothing else until
            the password is verified, so no filename leaks beforehand. */}
        {!loading && !loadError && info?.password_required && !info.filename && (
          <form onSubmit={submitPassword} className="space-y-4" noValidate>
            <h1 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              This file is password protected
            </h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Enter the password you were given. Attempts are rate limited.
            </p>
            {passwordError && <Alert tone="red">{passwordError}</Alert>}
            <Input
              label="Password"
              type="password"
              autoComplete="off"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            <Button type="submit" loading={verifying} className="w-full">
              Unlock
            </Button>
          </form>
        )}

        {!loading && !loadError && info && info.filename && (
          <div className="space-y-5">
            <header>
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
                Shared with you
              </p>
              <h1 className="mt-1 break-all text-xl font-semibold text-slate-900 dark:text-slate-100">
                {info.filename}
              </h1>
              <p className="mt-2 flex flex-wrap gap-2">
                <Badge tone="slate">{formatBytes(info.size)}</Badge>
                <Badge tone="slate">{info.mime_type}</Badge>
                {info.encryption?.encrypted && (
                  <Badge tone="green">🔒 {info.encryption.algorithm}</Badge>
                )}
                {grant && <Badge tone="blue">Unlocked</Badge>}
              </p>
            </header>

            <dl className="space-y-2 rounded-lg bg-slate-50 p-4 text-sm dark:bg-slate-800/60">
              <div className="flex justify-between">
                <dt className="text-slate-500 dark:text-slate-400">Expires</dt>
                <dd
                  className={`font-medium ${
                    expired ? 'text-rose-600' : 'text-slate-900 dark:text-slate-100'
                  }`}
                >
                  {formatCountdown(secondsLeft)}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500 dark:text-slate-400">Downloads remaining</dt>
                <dd className="font-medium tabular-nums text-slate-900 dark:text-slate-100">
                  {info.max_downloads === null || info.max_downloads === undefined
                    ? 'Unlimited'
                    : `${info.downloads_remaining ?? 0} of ${info.max_downloads}`}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500 dark:text-slate-400">Permission</dt>
                <dd className="font-medium text-slate-900 dark:text-slate-100">
                  {info.permission}
                </dd>
              </div>
            </dl>

            {downloaded && (
              <Alert tone="green" title="Download complete">
                {downloaded} was decrypted and verified before it reached you.
              </Alert>
            )}
            {downloadError && <Alert tone="red">{downloadError}</Alert>}

            {info.permission === 'DOWNLOAD' ? (
              <Button
                onClick={startDownload}
                loading={downloading}
                disabled={expired || info.downloads_remaining === 0}
                className="w-full"
              >
                {expired
                  ? 'Link expired'
                  : info.downloads_remaining === 0
                    ? 'Download limit reached'
                    : 'Download file'}
              </Button>
            ) : (
              <Alert tone="amber" title="View only">
                The owner shared the details of this file but not the file itself.
              </Alert>
            )}

            <p className="text-center text-xs text-slate-400">
              The owner can revoke this link at any time. Every check happens on the server.
            </p>
          </div>
        )}
      </main>

      <footer className="mt-6 text-xs text-slate-400">
        Sent to you via SecureShare ·{' '}
        <Link to="/" className="hover:underline">
          what is this?
        </Link>
      </footer>
    </div>
  )
}
