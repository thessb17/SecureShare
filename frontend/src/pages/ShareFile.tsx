import { useCallback, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { normaliseError } from '../api/client'
import { filesApi, linksApi, sharingApi } from '../api/endpoints'
import { Alert, Badge, Button, Card, Input, Select, Spinner } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { formatBytes, formatDate } from '../utils/format'
import type {
  FileShare,
  Paginated,
  Permission,
  ShareLink,
  ShareLinkCreated,
  StoredFile,
} from '../types/api'

const PERMISSIONS = [
  { value: 'VIEW', label: 'VIEW — see metadata only, cannot download' },
  { value: 'DOWNLOAD', label: 'DOWNLOAD — can download the file' },
]

const USER_EXPIRY = [
  { value: 'never', label: 'No expiry' },
  { value: '1h', label: '1 hour' },
  { value: '6h', label: '6 hours' },
  { value: '24h', label: '24 hours' },
  { value: '3d', label: '3 days' },
  { value: '7d', label: '7 days' },
]

const LINK_EXPIRY = USER_EXPIRY.filter((option) => option.value !== 'never')

export default function ShareFile() {
  const { fileId = '' } = useParams()

  const fileLoader = useCallback(() => filesApi.get(fileId), [fileId])
  const { data: file, loading: fileLoading, error: fileError } = useAsync<StoredFile>(
    fileLoader,
    [fileId],
  )

  const sharesLoader = useCallback(() => filesApi.shares(fileId), [fileId])
  const {
    data: shares,
    loading: sharesLoading,
    reload: reloadShares,
  } = useAsync<Paginated<FileShare>>(sharesLoader, [fileId])

  const linksLoader = useCallback(() => filesApi.links(fileId), [fileId])
  const {
    data: links,
    loading: linksLoading,
    reload: reloadLinks,
  } = useAsync<Paginated<ShareLink>>(linksLoader, [fileId])

  // --- user-to-user form -------------------------------------------------
  const [recipient, setRecipient] = useState('')
  const [permission, setPermission] = useState<Permission>('VIEW')
  const [userExpiry, setUserExpiry] = useState('never')
  const [userBusy, setUserBusy] = useState(false)
  const [userMessage, setUserMessage] = useState<{ tone: 'green' | 'red'; text: string } | null>(
    null,
  )

  async function submitUserShare(event: FormEvent) {
    event.preventDefault()
    setUserBusy(true)
    setUserMessage(null)
    try {
      const share = await sharingApi.shareWithUser(fileId, {
        recipient,
        permission,
        expires_in: userExpiry,
      })
      setUserMessage({
        tone: 'green',
        text: `Shared with ${share.recipient.email} (${share.permission}).`,
      })
      setRecipient('')
      reloadShares()
    } catch (caught) {
      const normalised = normaliseError(caught)
      const detail = normalised.fieldErrors?.recipient
      setUserMessage({ tone: 'red', text: detail ?? normalised.message })
    } finally {
      setUserBusy(false)
    }
  }

  async function revokeShare(share: FileShare) {
    try {
      await sharingApi.revokeShare(share.id)
      setUserMessage({ tone: 'green', text: `Access for ${share.recipient.email} was revoked.` })
      reloadShares()
    } catch (caught) {
      setUserMessage({ tone: 'red', text: normaliseError(caught).message })
    }
  }

  async function changeSharePermission(share: FileShare, next: Permission) {
    try {
      await sharingApi.updateShare(share.id, { permission: next })
      setUserMessage({
        tone: 'green',
        text: `${share.recipient.email} now has ${next} permission.`,
      })
      reloadShares()
    } catch (caught) {
      setUserMessage({ tone: 'red', text: normaliseError(caught).message })
    }
  }

  // --- public link form --------------------------------------------------
  const [linkExpiry, setLinkExpiry] = useState('24h')
  const [linkPermission, setLinkPermission] = useState<Permission>('DOWNLOAD')
  const [maxDownloads, setMaxDownloads] = useState('')
  const [linkPassword, setLinkPassword] = useState('')
  const [linkBusy, setLinkBusy] = useState(false)
  const [created, setCreated] = useState<ShareLinkCreated | null>(null)
  const [linkError, setLinkError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  async function submitLink(event: FormEvent) {
    event.preventDefault()
    setLinkBusy(true)
    setLinkError(null)
    setCreated(null)
    setCopied(false)
    try {
      const parsedLimit = maxDownloads.trim() === '' ? null : Number(maxDownloads)
      if (parsedLimit !== null && (!Number.isInteger(parsedLimit) || parsedLimit < 1)) {
        setLinkError('The download limit must be a whole number of at least 1.')
        return
      }
      const result = await linksApi.create(fileId, {
        expires_in: linkExpiry,
        permission: linkPermission,
        max_downloads: parsedLimit,
        ...(linkPassword ? { password: linkPassword } : {}),
      })
      setCreated(result)
      setLinkPassword('')
      setMaxDownloads('')
      reloadLinks()
    } catch (caught) {
      const normalised = normaliseError(caught)
      const detail =
        normalised.fieldErrors?.password ??
        normalised.fieldErrors?.max_downloads ??
        normalised.fieldErrors?.expires_at
      setLinkError(detail ?? normalised.message)
    } finally {
      setLinkBusy(false)
    }
  }

  async function revokeLink(link: ShareLink) {
    try {
      await linksApi.revoke(link.id)
      reloadLinks()
    } catch (caught) {
      setLinkError(normaliseError(caught).message)
    }
  }

  const shareUrl = created ? `${window.location.origin}/s/${created.token}` : ''

  if (fileLoading) return <Spinner label="Loading file" />
  if (fileError) {
    return (
      <div className="space-y-4">
        <Alert tone="red">{fileError.message}</Alert>
        <Link to="/app/files" className="text-sm font-medium text-brand-600 hover:underline">
          ← Back to my files
        </Link>
      </div>
    )
  }
  if (!file) return null

  if (!file.access.is_owner) {
    return (
      <div className="space-y-4">
        <Alert tone="red" title="Only the owner can share this file">
          Re-sharing a file you received is refused by the server.
        </Alert>
        <Link to="/app/files" className="text-sm font-medium text-brand-600 hover:underline">
          ← Back to my files
        </Link>
      </div>
    )
  }

  const activeShares = shares?.results ?? []
  const activeLinks = links?.results ?? []

  return (
    <div className="space-y-6">
      <nav aria-label="Breadcrumb">
        <Link to={`/app/files/${fileId}`} className="text-sm font-medium text-brand-600 hover:underline">
          ← {file.filename}
        </Link>
      </nav>

      <header>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Share this file
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          {file.filename} · {formatBytes(file.size)} · every rule below is enforced by the server
          on each request.
        </p>
      </header>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* ------------------------------------------------ user-to-user */}
        <Card title="Share with a SecureShare user">
          <form onSubmit={submitUserShare} className="space-y-4" noValidate>
            {userMessage && <Alert tone={userMessage.tone === 'green' ? 'green' : 'red'}>{userMessage.text}</Alert>}
            <Input
              label="Recipient email"
              type="email"
              required
              value={recipient}
              onChange={(event) => setRecipient(event.target.value)}
              hint="For privacy, an unknown and a disabled account return the same message."
            />
            <Select
              label="Permission"
              value={permission}
              onChange={(value) => setPermission(value as Permission)}
              options={PERMISSIONS}
            />
            <Select
              label="Expires"
              value={userExpiry}
              onChange={setUserExpiry}
              options={USER_EXPIRY}
            />
            <Button type="submit" loading={userBusy} disabled={!recipient}>
              Grant access
            </Button>
          </form>

          <div className="mt-6 border-t border-slate-100 pt-4 dark:border-slate-800">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              People with access
            </h3>
            {sharesLoading ? (
              <p className="mt-2 text-sm text-slate-500">Loading…</p>
            ) : activeShares.length === 0 ? (
              <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                You have not shared this file with anyone.
              </p>
            ) : (
              <ul className="mt-2 divide-y divide-slate-100 dark:divide-slate-800">
                {activeShares.map((share) => (
                  <li key={share.id} className="py-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-slate-900 dark:text-slate-100">
                          {share.recipient.email}
                        </p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          {share.expires_at
                            ? `Expires ${formatDate(share.expires_at)}`
                            : 'No expiry'}
                          {share.access_count > 0 && ` · accessed ${share.access_count}×`}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge
                          tone={
                            share.status === 'ACTIVE'
                              ? 'green'
                              : share.status === 'REVOKED'
                                ? 'red'
                                : 'amber'
                          }
                        >
                          {share.status}
                        </Badge>
                        {share.is_active && (
                          <>
                            <button
                              type="button"
                              onClick={() =>
                                changeSharePermission(
                                  share,
                                  share.permission === 'VIEW' ? 'DOWNLOAD' : 'VIEW',
                                )
                              }
                              className="rounded px-2 py-1 text-xs font-medium text-brand-700 hover:bg-brand-50 dark:text-brand-400 dark:hover:bg-brand-500/10"
                            >
                              {share.permission === 'VIEW' ? 'Allow download' : 'Make view-only'}
                            </button>
                            <button
                              type="button"
                              onClick={() => revokeShare(share)}
                              className="rounded px-2 py-1 text-xs font-medium text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-500/10"
                            >
                              Revoke
                            </button>
                          </>
                        )}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>

        {/* ------------------------------------------------ public link */}
        <Card title="Create a public link">
          <form onSubmit={submitLink} className="space-y-4" noValidate>
            {linkError && <Alert tone="red">{linkError}</Alert>}
            <Select
              label="Expires after"
              value={linkExpiry}
              onChange={setLinkExpiry}
              options={LINK_EXPIRY}
              hint="Public links must expire — there is no 'never' option."
            />
            <Select
              label="Permission"
              value={linkPermission}
              onChange={(value) => setLinkPermission(value as Permission)}
              options={PERMISSIONS}
            />
            <Input
              label="Download limit"
              type="number"
              min={1}
              placeholder="Unlimited"
              value={maxDownloads}
              onChange={(event) => setMaxDownloads(event.target.value)}
              hint="Counted atomically on the server, so parallel requests cannot overshoot it."
            />
            <Input
              label="Password (optional)"
              type="password"
              autoComplete="new-password"
              value={linkPassword}
              onChange={(event) => setLinkPassword(event.target.value)}
              hint="Hashed with Argon2id. It is never stored or logged in plaintext."
            />
            <Button type="submit" loading={linkBusy}>
              Create link
            </Button>
          </form>

          {created && (
            <div className="mt-5 rounded-lg bg-amber-50 p-4 ring-1 ring-inset ring-amber-600/20 dark:bg-amber-500/10">
              <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
                Copy this link now — it is shown only once
              </p>
              <p className="mt-1 text-xs text-amber-800 dark:text-amber-300">{created.warning}</p>
              <div className="mt-3 flex gap-2">
                <input
                  readOnly
                  value={shareUrl}
                  aria-label="Share link URL"
                  onFocus={(event) => event.target.select()}
                  className="min-w-0 flex-1 rounded-lg border-0 bg-white px-3 py-2 font-mono text-xs text-slate-800 ring-1 ring-inset ring-amber-300 dark:bg-slate-900 dark:text-slate-100"
                />
                <Button
                  variant="secondary"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(shareUrl)
                      setCopied(true)
                    } catch {
                      setCopied(false)
                    }
                  }}
                >
                  {copied ? 'Copied' : 'Copy'}
                </Button>
              </div>
              <p className="mt-2 text-xs text-amber-800 dark:text-amber-300">
                Expires {formatDate(created.expires_at)} ·{' '}
                {created.max_downloads ? `${created.max_downloads} download(s)` : 'unlimited downloads'}{' '}
                · {created.permission}
              </p>
            </div>
          )}

          <div className="mt-6 border-t border-slate-100 pt-4 dark:border-slate-800">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Links for this file
            </h3>
            {linksLoading ? (
              <p className="mt-2 text-sm text-slate-500">Loading…</p>
            ) : activeLinks.length === 0 ? (
              <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                No public links exist for this file.
              </p>
            ) : (
              <ul className="mt-2 divide-y divide-slate-100 dark:divide-slate-800">
                {activeLinks.map((link) => (
                  <li key={link.id} className="flex flex-wrap items-center justify-between gap-2 py-3">
                    <div className="min-w-0">
                      <p className="font-mono text-xs text-slate-700 dark:text-slate-300">
                        …{link.token_prefix}
                      </p>
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        {link.download_count}
                        {link.max_downloads ? ` / ${link.max_downloads}` : ''} downloads
                        {link.expires_at && ` · expires ${formatDate(link.expires_at)}`}
                        {link.password_protected && ' · password protected'}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge
                        tone={
                          link.status === 'ACTIVE'
                            ? 'green'
                            : link.status === 'REVOKED'
                              ? 'red'
                              : 'amber'
                        }
                      >
                        {link.status}
                      </Badge>
                      {link.is_active && (
                        <button
                          type="button"
                          onClick={() => revokeLink(link)}
                          className="rounded px-2 py-1 text-xs font-medium text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-500/10"
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}
