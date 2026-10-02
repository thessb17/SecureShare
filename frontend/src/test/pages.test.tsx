/**
 * Page tests against mocked HTTP responses shaped exactly like the real DRF
 * serializers. They verify what the user actually sees, including the
 * negative cases (view-only, expired link, download limit reached).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import MockAdapter from 'axios-mock-adapter'
import { api, clearTokens } from '../api/client'
import { AuthProvider } from '../context/AuthContext'
import { ThemeProvider } from '../context/ThemeContext'
import Login from '../pages/Login'
import PublicShare from '../pages/PublicShare'
import Upload from '../pages/Upload'
import type { PublicShareInfo, StoredFile } from '../types/api'

let mock: MockAdapter

beforeEach(() => {
  clearTokens()
  mock = new MockAdapter(api)
})

afterEach(() => {
  mock.restore()
  vi.unstubAllGlobals()
})

function wrap(path: string, routes: React.ReactNode) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ThemeProvider>
        <AuthProvider>
          <Routes>{routes}</Routes>
        </AuthProvider>
      </ThemeProvider>
    </MemoryRouter>,
  )
}

const FILE: StoredFile = {
  id: 'f-1',
  filename: 'quarterly-report.pdf',
  size: 2_097_152,
  encrypted_size: 2_097_700,
  mime_type: 'application/pdf',
  extension: 'pdf',
  checksum_sha256: 'a'.repeat(64),
  status: 'ACTIVE',
  owner: { id: 'u-1', email: 'owner@example.com', full_name: 'Owner' },
  encryption: {
    encrypted: true,
    algorithm: 'AES-256-GCM',
    key_wrapping_algorithm: 'RSA-OAEP-SHA256',
    chunk_count: 3,
  },
  malware_scan: { status: 'SKIPPED', scanned: false, scanned_at: null, scanner_enabled: false },
  access: { can_view: true, can_download: true, via: 'OWNER', is_owner: true },
  download_count: 0,
  last_downloaded_at: null,
  created_at: '2026-10-01T10:00:00Z',
  updated_at: '2026-10-01T10:00:00Z',
}

// --------------------------------------------------------------- Login
describe('Login', () => {
  it('shows the server message when credentials are rejected', async () => {
    mock.onPost('/auth/login/').reply(401, {
      error: 'INVALID_CREDENTIALS',
      message: 'Invalid credentials.',
    })
    wrap('/login', <Route path="/login" element={<Login />} />)

    await userEvent.type(screen.getByLabelText('Email'), 'nobody@example.com')
    await userEvent.type(screen.getByLabelText('Password'), 'wrong-password')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Email or password is incorrect.')
  })

  it('surfaces a lockout distinctly from a bad password', async () => {
    mock.onPost('/auth/login/').reply(403, {
      error: 'ACCOUNT_LOCKED',
      message: 'Account locked.',
    })
    wrap('/login', <Route path="/login" element={<Login />} />)

    await userEvent.type(screen.getByLabelText('Email'), 'locked@example.com')
    await userEvent.type(screen.getByLabelText('Password'), 'Whatever123!')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('temporarily locked')
  })

  it('shows a rate-limit message rather than a generic failure', async () => {
    mock.onPost('/auth/login/').reply(429, {
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests.',
      retry_after: 60,
    })
    wrap('/login', <Route path="/login" element={<Login />} />)

    await userEvent.type(screen.getByLabelText('Email'), 'user@example.com')
    await userEvent.type(screen.getByLabelText('Password'), 'Whatever123!')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Too many attempts')
  })
})

// --------------------------------------------------------------- Upload
describe('Upload', () => {
  it('rejects an oversized file in the browser before any request is sent', async () => {
    wrap('/app/upload', <Route path="/app/upload" element={<Upload />} />)

    const input = screen.getByLabelText('Choose a file to upload') as HTMLInputElement
    const huge = new File(['x'], 'huge.bin', { type: 'application/octet-stream' })
    Object.defineProperty(huge, 'size', { value: 200 * 1024 * 1024 })

    await userEvent.upload(input, huge)

    expect(await screen.findByRole('alert')).toHaveTextContent('the limit is')
    expect(mock.history.post).toHaveLength(0)
  })

  it('confirms the encryption algorithm reported by the server after upload', async () => {
    mock.onPost('/files/upload/').reply(201, FILE)
    wrap('/app/upload', <Route path="/app/upload" element={<Upload />} />)

    const input = screen.getByLabelText('Choose a file to upload') as HTMLInputElement
    await userEvent.upload(
      input,
      new File(['%PDF-1.4 test'], 'quarterly-report.pdf', { type: 'application/pdf' }),
    )
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt and upload' }))

    expect(await screen.findByText(/Encrypted with AES-256-GCM/)).toBeInTheDocument()
    expect(screen.getByText(/Key wrapped with RSA-OAEP-SHA256/)).toBeInTheDocument()
  })

  it('shows the server error when the file type is refused', async () => {
    mock.onPost('/files/upload/').reply(400, {
      error: 'UNSUPPORTED_FILE_TYPE',
      message: 'That type is not allowed.',
      details: { file: ['Detected content type application/x-dosexec is not permitted.'] },
    })
    wrap('/app/upload', <Route path="/app/upload" element={<Upload />} />)

    const input = screen.getByLabelText('Choose a file to upload') as HTMLInputElement
    await userEvent.upload(input, new File(['MZ'], 'invoice.pdf.exe', { type: 'application/pdf' }))
    await userEvent.click(screen.getByRole('button', { name: 'Encrypt and upload' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('not allowed')
  })
})

// --------------------------------------------------------------- PublicShare
describe('PublicShare', () => {
  const route = <Route path="/s/:token" element={<PublicShare />} />

  it('shows file details and a working download button for a live link', async () => {
    const info: PublicShareInfo = {
      filename: 'contract.pdf',
      size: 1024,
      mime_type: 'application/pdf',
      permission: 'DOWNLOAD',
      expires_at: '2026-10-03T10:00:00Z',
      expires_in_seconds: 3600,
      max_downloads: 2,
      download_count: 0,
      downloads_remaining: 2,
      password_required: false,
      encryption: {
        encrypted: true,
        algorithm: 'AES-256-GCM',
        key_wrapping_algorithm: 'RSA-OAEP-SHA256',
        chunk_count: 1,
      },
    }
    mock.onGet('/share/tok123/').reply(200, info)
    wrap('/s/tok123', route)

    expect(await screen.findByText('contract.pdf')).toBeInTheDocument()
    expect(screen.getByText('2 of 2')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Download file' })).toBeEnabled()
  })

  it('asks for a password without revealing the filename', async () => {
    mock.onGet('/share/tok456/').reply(200, { password_required: true })
    wrap('/s/tok456', route)

    expect(await screen.findByText('This file is password protected')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    expect(screen.queryByText(/\.pdf/)).not.toBeInTheDocument()
  })

  it('reports an invalid password without unlocking', async () => {
    mock.onGet('/share/tok456/').reply(200, { password_required: true })
    mock.onPost('/share/tok456/verify-password/').reply(403, {
      error: 'SHARE_LINK_PASSWORD_INVALID',
      message: 'Wrong.',
    })
    wrap('/s/tok456', route)

    await userEvent.type(await screen.findByLabelText('Password'), 'guess')
    await userEvent.click(screen.getByRole('button', { name: 'Unlock' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('That password is not correct.')
  })

  it('explains an expired link instead of offering a download', async () => {
    mock.onGet('/share/gone/').reply(410, {
      error: 'SHARE_LINK_EXPIRED',
      message: 'Expired.',
    })
    wrap('/s/gone', route)

    expect(await screen.findByText('This link cannot be opened')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('This link has expired.')
    expect(screen.queryByRole('button', { name: /Download/ })).not.toBeInTheDocument()
  })

  it('explains a revoked link', async () => {
    mock.onGet('/share/revoked/').reply(410, {
      error: 'SHARE_LINK_REVOKED',
      message: 'Revoked.',
    })
    wrap('/s/revoked', route)

    expect(await screen.findByRole('alert')).toHaveTextContent('revoked by its owner')
  })

  it('disables the button once the download limit is exhausted', async () => {
    mock.onGet('/share/used/').reply(200, {
      filename: 'contract.pdf',
      size: 1024,
      mime_type: 'application/pdf',
      permission: 'DOWNLOAD',
      expires_in_seconds: 600,
      max_downloads: 2,
      download_count: 2,
      downloads_remaining: 0,
      password_required: false,
    })
    wrap('/s/used', route)

    const button = await screen.findByRole('button', { name: 'Download limit reached' })
    expect(button).toBeDisabled()
  })

  it('offers no download at all for a VIEW-only link', async () => {
    mock.onGet('/share/viewonly/').reply(200, {
      filename: 'contract.pdf',
      size: 1024,
      mime_type: 'application/pdf',
      permission: 'VIEW',
      expires_in_seconds: 600,
      max_downloads: null,
      download_count: 0,
      downloads_remaining: null,
      password_required: false,
    })
    wrap('/s/viewonly', route)

    expect(await screen.findByText('View only')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Download file/ })).not.toBeInTheDocument()
  })

  it('reports the limit error returned mid-download', async () => {
    mock.onGet('/share/race/').reply(200, {
      filename: 'contract.pdf',
      size: 1024,
      mime_type: 'application/pdf',
      permission: 'DOWNLOAD',
      expires_in_seconds: 600,
      max_downloads: 1,
      download_count: 0,
      downloads_remaining: 1,
      password_required: false,
    })
    mock.onPost('/share/race/download/').reply(
      410,
      new Blob(
        [JSON.stringify({ error: 'SHARE_LINK_DOWNLOAD_LIMIT_REACHED', message: 'Gone.' })],
        { type: 'application/json' },
      ),
    )
    wrap('/s/race', route)

    await userEvent.click(await screen.findByRole('button', { name: 'Download file' }))

    await waitFor(() =>
      expect(screen.getByText('This link has reached its download limit.')).toBeInTheDocument(),
    )
  })
})
