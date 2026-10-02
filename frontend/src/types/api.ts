/**
 * Types mirroring the SecureShare REST API.
 *
 * These are transcribed from the DRF serializers in
 * backend/{accounts,files,sharing,audit,dashboard}/serializers.py — if a field
 * is not listed there, it is not listed here.
 */

export type Role = 'USER' | 'ADMIN'
export type Permission = 'VIEW' | 'DOWNLOAD'
export type FileStatus = 'ACTIVE' | 'DELETED' | 'QUARANTINED'
export type ShareStatus = 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'EXHAUSTED'

export interface User {
  id: string
  email: string
  full_name: string
  role: Role
  is_active: boolean
  is_email_verified?: boolean
  created_at?: string
  last_login?: string | null
}

export interface UserSummary {
  id: string
  email: string
  full_name: string
}

export interface AuthTokens {
  access: string
  refresh: string
}

export interface LoginResponse {
  user: User
  tokens: AuthTokens
}

/** FileSerializer.get_encryption */
export interface EncryptionInfo {
  encrypted: boolean
  algorithm: string | null
  key_wrapping_algorithm: string | null
  chunk_count: number | null
}

/** FileSerializer.get_access — the backend's own authorization decision. */
export interface AccessInfo {
  can_view: boolean
  can_download: boolean
  via: string
  is_owner: boolean
}

export interface MalwareScanInfo {
  status: string
  scanned: boolean
  scanned_at: string | null
  scanner_enabled: boolean
}

/** files.serializers.FileSerializer */
export interface StoredFile {
  id: string
  filename: string
  size: number
  encrypted_size: number
  mime_type: string
  extension: string
  checksum_sha256: string
  status: FileStatus
  owner: UserSummary | null
  encryption: EncryptionInfo
  malware_scan: MalwareScanInfo
  access: AccessInfo
  download_count: number
  last_downloaded_at: string | null
  created_at: string
  updated_at: string
}

/** sharing.serializers.SharedFileSummarySerializer */
export interface SharedFileSummary {
  id: string
  filename: string
  size: number
  mime_type: string
  created_at: string
}

/** sharing.serializers.FileShareSerializer */
export interface FileShare {
  id: string
  file: SharedFileSummary
  owner: UserSummary
  recipient: UserSummary
  permission: Permission
  status: ShareStatus
  is_active: boolean
  created_at: string
  updated_at: string
  expires_at: string | null
  revoked_at: string | null
  last_accessed_at: string | null
  access_count: number
}

/** sharing.serializers.ShareLinkSerializer — never carries the raw token. */
export interface ShareLink {
  id: string
  file: SharedFileSummary
  created_by: UserSummary | null
  token_prefix: string
  permission: Permission
  status: ShareStatus
  is_active: boolean
  expires_at: string | null
  expires_in_seconds: number | null
  max_downloads: number | null
  download_count: number
  downloads_remaining: number | null
  password_protected: boolean
  access_count: number
  last_accessed_at: string | null
  last_downloaded_at: string | null
  revoked_at: string | null
  created_at: string
  updated_at: string
}

/** POST /api/files/<id>/share-link/ — the only response carrying the token. */
export interface ShareLinkCreated {
  share_link: ShareLink
  token: string
  url: string
  expires_at: string | null
  permission: Permission
  max_downloads: number | null
  warning: string
}

/** sharing.serializers.PublicShareLinkSerializer — deliberately minimal. */
export interface PublicShareInfo {
  filename?: string
  size?: number
  mime_type?: string
  permission?: Permission
  expires_at?: string | null
  expires_in_seconds?: number | null
  max_downloads?: number | null
  download_count?: number
  downloads_remaining?: number | null
  password_required?: boolean
  encryption?: EncryptionInfo
}

/** audit.serializers.AuditLogSerializer */
export interface AuditActor {
  id: string | null
  email: string
  role: string
}

export interface AuditEntry {
  id: string
  timestamp: string
  action: string
  severity: string
  success: boolean
  actor: AuditActor | null
  object_type: string
  object_id: string
  ip_address: string | null
  user_agent: string
  message: string
  metadata: Record<string, unknown>
}

export interface Paginated<T> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

export interface ApiErrorBody {
  error: string
  message: string
  request_id?: string
  retry_after?: number
  details?: Record<string, string[] | string>
}

export type ExpiryPreset = '1h' | '6h' | '24h' | '3d' | '7d' | 'custom' | 'never'

/** dashboard.views.DashboardStatsView */
export interface DashboardStats {
  files: {
    total: number
    active: number
    deleted: number
    plaintext_bytes: number
    encrypted_bytes: number
  }
  shares: {
    outgoing_active: number
    outgoing_expired: number
    outgoing_revoked: number
    incoming_active: number
  }
  links: {
    active: number
    expired: number
    revoked: number
    total_downloads: number
  }
  recent_activity: {
    id: string
    action: string
    success: boolean
    object_type: string
    object_id: string
    timestamp: string
    metadata: Record<string, unknown>
  }[]
}

/** dashboard.views.AdminStatsView */
export interface AdminStats {
  users: { total: number; active: number; disabled: number; admins: number; locked: number }
  files: {
    total: number
    active: number
    deleted: number
    encrypted_bytes: number
    plaintext_bytes: number
  }
  shares: { active: number; expired: number; revoked: number }
  share_links: { active: number; expired: number; revoked: number }
  security: {
    events_24h: number
    failed_logins_24h: number
    lockouts_24h: number
    unauthorized_24h: number
    rate_limited_24h: number
  }
  generated_at: string
}

/** dashboard.admin_views.AdminUserSerializer — no password hash, no tokens. */
export interface AdminUser {
  id: string
  email: string
  full_name: string
  role: Role
  is_active: boolean
  is_email_verified: boolean
  created_at: string
  last_login: string | null
  failed_login_count: number
  locked_until: string | null
  is_locked: boolean
  file_count: number
}
