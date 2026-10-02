/** Every backend call the app makes. No mock data, no fabricated responses. */
import { api } from './client'
import type {
  AdminStats,
  AdminUser,
  AuditEntry,
  FileShare,
  LoginResponse,
  Paginated,
  Permission,
  PublicShareInfo,
  ShareLink,
  ShareLinkCreated,
  StoredFile,
  User,
} from '../types/api'

// ---------------------------------------------------------------- auth
export const authApi = {
  register: (data: {
    email: string
    password: string
    password_confirm: string
    full_name: string
  }) => api.post<LoginResponse>('/auth/register/', data).then((r) => r.data),

  login: (data: { email: string; password: string }) =>
    api.post<LoginResponse>('/auth/login/', data).then((r) => r.data),

  logout: (refresh: string | null) =>
    api.post('/auth/logout/', refresh ? { refresh } : {}).then((r) => r.data),

  me: () => api.get<User>('/users/me/').then((r) => r.data),

  changePassword: (data: {
    current_password: string
    new_password: string
    new_password_confirm: string
  }) => api.post('/auth/change-password/', data).then((r) => r.data),

  requestPasswordReset: (email: string) =>
    api.post('/auth/password-reset/', { email }).then((r) => r.data),

  confirmPasswordReset: (data: {
    token: string
    new_password: string
    new_password_confirm: string
  }) => api.post('/auth/password-reset/confirm/', data).then((r) => r.data),

  revokeSessions: () => api.post('/auth/revoke-sessions/').then((r) => r.data),
}

// ---------------------------------------------------------------- files
export const filesApi = {
  list: (params?: { page?: number; page_size?: number; search?: string }) =>
    api.get<Paginated<StoredFile>>('/files/', { params }).then((r) => r.data),

  get: (id: string) => api.get<StoredFile>(`/files/${id}/`).then((r) => r.data),

  upload: (file: File, onProgress?: (percent: number) => void) => {
    const form = new FormData()
    form.append('file', file)
    return api
      .post<StoredFile>('/files/upload/', form, {
        onUploadProgress: (event) => {
          if (onProgress && event.total) {
            onProgress(Math.round((event.loaded * 100) / event.total))
          }
        },
      })
      .then((r) => r.data)
  },

  /** Streams the decrypted file as a Blob so the browser can save it. */
  download: (id: string) =>
    api.get<Blob>(`/files/${id}/download/`, { responseType: 'blob' }),

  remove: (id: string) => api.delete(`/files/${id}/`).then((r) => r.data),

  shares: (id: string) =>
    api.get<Paginated<FileShare>>(`/files/${id}/shares/`).then((r) => r.data),

  links: (id: string) =>
    api.get<Paginated<ShareLink>>(`/files/${id}/share-links/`).then((r) => r.data),
}

// ---------------------------------------------------------------- sharing
export const sharingApi = {
  shareWithUser: (
    fileId: string,
    data: { recipient: string; permission: Permission; expires_in?: string; expires_at?: string },
  ) => api.post<FileShare>(`/files/${fileId}/share/`, data).then((r) => r.data),

  mySharesOut: () => api.get<Paginated<FileShare>>('/shares/').then((r) => r.data),

  sharedWithMe: () =>
    api.get<Paginated<FileShare>>('/shared-with-me/').then((r) => r.data),

  updateShare: (
    shareId: string,
    data: { permission?: Permission; expires_in?: string; expires_at?: string | null },
  ) => api.patch<FileShare>(`/shares/${shareId}/`, data).then((r) => r.data),

  revokeShare: (shareId: string) => api.delete(`/shares/${shareId}/`).then((r) => r.data),

  downloadShared: (fileId: string) =>
    api.get<Blob>(`/files/${fileId}/download/`, { responseType: 'blob' }),
}

// ---------------------------------------------------------------- share links
export const linksApi = {
  create: (
    fileId: string,
    data: {
      expires_in?: string
      expires_at?: string
      max_downloads?: number | null
      permission?: Permission
      password?: string
    },
  ) => api.post<ShareLinkCreated>(`/files/${fileId}/share-link/`, data).then((r) => r.data),

  list: (params?: { file?: string; status?: string }) =>
    api.get<Paginated<ShareLink>>('/share-links/', { params }).then((r) => r.data),

  get: (id: string) => api.get<ShareLink>(`/share-links/${id}/`).then((r) => r.data),

  update: (
    id: string,
    data: {
      permission?: Permission
      expires_in?: string
      expires_at?: string | null
      max_downloads?: number | null
      password?: string | null
    },
  ) => api.patch<ShareLink>(`/share-links/${id}/`, data).then((r) => r.data),

  revoke: (id: string) => api.delete(`/share-links/${id}/`).then((r) => r.data),
}

// ---------------------------------------------------------------- public share
export const publicShareApi = {
  info: (token: string, grant?: string) =>
    api
      .get<PublicShareInfo>(`/share/${encodeURIComponent(token)}/`, {
        headers: grant ? { 'X-Share-Grant': grant } : undefined,
      })
      .then((r) => r.data),

  verifyPassword: (token: string, password: string) =>
    api
      .post<{ password_required: boolean; grant: string; expires_in: number }>(
        `/share/${encodeURIComponent(token)}/verify-password/`,
        { password },
      )
      .then((r) => r.data),

  download: (token: string, body: { grant?: string; password?: string }) =>
    api.post<Blob>(`/share/${encodeURIComponent(token)}/download/`, body, {
      responseType: 'blob',
    }),
}

// ---------------------------------------------------------------- audit
export const auditApi = {
  list: (params?: {
    action?: string
    success?: string
    since?: string
    object_id?: string
    page?: number
    page_size?: number
  }) => api.get<Paginated<AuditEntry>>('/audit-logs/', { params }).then((r) => r.data),
}

// ---------------------------------------------------------------- admin
export const adminApi = {
  stats: () => api.get<AdminStats>('/admin/stats/').then((r) => r.data),

  users: (params?: { search?: string; status?: string; page?: number }) =>
    api.get<Paginated<AdminUser>>('/admin/users/', { params }).then((r) => r.data),

  setUserActive: (userId: string, isActive: boolean, reason?: string) =>
    api
      .patch<AdminUser>(`/admin/users/${userId}/`, { is_active: isActive, reason })
      .then((r) => r.data),

  unlockUser: (userId: string) =>
    api.post<AdminUser>(`/admin/users/${userId}/unlock/`).then((r) => r.data),

  securityEvents: (params?: {
    action?: string
    actor?: string
    success?: string
    since?: string
    until?: string
    page?: number
    page_size?: number
  }) => api.get<Paginated<AuditEntry>>('/admin/security-events/', { params }).then((r) => r.data),
}
