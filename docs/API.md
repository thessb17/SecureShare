# SecureShare — API Reference

Base URL `/api/`. **44 operations across 37 paths.**

This document is generated from the live OpenAPI schema, so it cannot drift
from the implementation. The interactive versions are the authority:

| | |
| --- | --- |
| Swagger UI | `/api/docs/` |
| ReDoc | `/api/redoc/` |
| Raw schema | `/api/schema/` (OpenAPI 3.0.3) |

Regenerate with `python manage.py spectacular --file openapi.yaml`.

---

## Authentication

All authenticated endpoints use a JWT bearer token:

```
Authorization: Bearer <access_token>
```

| Token | Lifetime | Storage |
| --- | --- | --- |
| Access | 15 minutes | JavaScript memory only |
| Refresh | 1 day | `sessionStorage` |

`POST /api/auth/login/` returns both:

```json
{
  "user": { "id": "uuid", "email": "...", "role": "USER" },
  "tokens": {
    "access": "eyJhbGciOi...",
    "refresh": "eyJhbGciOi...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

Note the nesting: tokens are under `tokens`, not at the top level.

Every token embeds a `tv` (token version) claim. Logout, a password change or
an administrative disable increments the user's version, which invalidates
every outstanding token for that user immediately.

---

## Conventions

**Identifiers** are UUIDs, never sequential integers.

**Errors** share one shape:

```json
{
  "error": "VALIDATION_ERROR",
  "request_id": "88d59eabc5054eaf8c44140b4274a5ac",
  "message": "The submitted data is invalid.",
  "details": { "password_confirm": ["This field is required."] }
}
```

`request_id` also appears in the server log, which is how a user-visible error
is traced without exposing internals.

| Status | Meaning here |
| --- | --- |
| `400` | Validation failed |
| `401` | Missing, malformed or expired credentials |
| `403` | Authenticated but not permitted |
| `404` | Not found **or** not yours — deliberately indistinguishable |
| `410` | Gone: link expired, revoked, or download limit reached |
| `413` | Upload exceeds the size cap |
| `415` | File type not permitted (based on sniffed content) |
| `429` | Rate limited |
| `503` | A dependency is unavailable (e.g. keys unusable) |

**404 rather than 403** on another user's resource is intentional: a 403 would
confirm the record exists.

**Rate limits** (per scope, default production values):

| Scope | Limit |
| --- | --- |
| Login | 10/min |
| Registration | 5/hour |
| Anonymous | 120/hour |
| Authenticated | 2000/hour |
| Upload | 60/hour |
| Download | 300/hour |
| Share access | 60/hour |

nginx adds its own edge limits: 5r/m on auth, 20r/m on share, 30r/s general.

---

## Endpoints

### Admin

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/admin/actions/` | bearer | admin_actions_list |
| `GET` | `/api/admin/security-events/` | bearer | admin_security_events_list |
| `GET` | `/api/admin/stats/` | bearer | admin_stats_retrieve |
| `GET` | `/api/admin/test/` | bearer | admin_test_retrieve |
| `GET` | `/api/admin/users/` | bearer | admin_users_list |
| `GET` | `/api/admin/users/{user_id}/` | bearer | admin_users_retrieve |
| `PATCH` | `/api/admin/users/{user_id}/` | bearer | admin_users_partial_update |
| `POST` | `/api/admin/users/{user_id}/unlock/` | bearer | admin_users_unlock_create |

### Audit

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/audit-logs/` | bearer | audit_logs_list |

### Authentication

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/api/auth/change-password/` | bearer | auth_change_password_create |
| `POST` | `/api/auth/login/` | bearer | auth_login_create |
| `POST` | `/api/auth/logout/` | bearer | auth_logout_create |
| `POST` | `/api/auth/password-reset/` | bearer | auth_password_reset_create |
| `POST` | `/api/auth/password-reset/confirm/` | bearer | auth_password_reset_confirm_create |
| `POST` | `/api/auth/refresh/` | bearer | auth_refresh_create |
| `POST` | `/api/auth/register/` | bearer | auth_register_create |
| `POST` | `/api/auth/revoke-sessions/` | bearer | auth_revoke_sessions_create |
| `POST` | `/api/auth/verify-email/` | bearer | auth_verify_email_create |
| `POST` | `/api/auth/verify-email/confirm/` | bearer | auth_verify_email_confirm_create |

### Dashboard

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/dashboard/stats/` | bearer | dashboard_stats_retrieve |

### Files

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/files/` | bearer | files_list |
| `POST` | `/api/files/upload/` | bearer | files_upload_create |
| `DELETE` | `/api/files/{file_id}/` | bearer | files_destroy |
| `GET` | `/api/files/{file_id}/` | bearer | files_retrieve |
| `GET` | `/api/files/{file_id}/download/` | bearer | files_download_retrieve |

### Public share

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/share/{token}/` | bearer | share_retrieve |
| `POST` | `/api/share/{token}/download/` | bearer | share_download_create |
| `POST` | `/api/share/{token}/verify-password/` | bearer | share_verify_password_create |

### Share links

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/api/files/{file_id}/share-link/` | bearer | files_share_link_create |
| `GET` | `/api/files/{file_id}/share-links/` | bearer | files_share_links_list |
| `GET` | `/api/share-links/` | bearer | share_links_list |
| `DELETE` | `/api/share-links/{link_id}/` | bearer | share_links_destroy |
| `GET` | `/api/share-links/{link_id}/` | bearer | share_links_retrieve |
| `PATCH` | `/api/share-links/{link_id}/` | bearer | share_links_partial_update |

### Sharing

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/api/files/{file_id}/share/` | bearer | files_share_create |
| `GET` | `/api/files/{file_id}/shares/` | bearer | files_shares_list |
| `GET` | `/api/shared-with-me/` | bearer | shared_with_me_list |
| `GET` | `/api/shares/` | bearer | shares_list |
| `DELETE` | `/api/shares/{share_id}/` | bearer | shares_destroy |
| `GET` | `/api/shares/{share_id}/` | bearer | shares_retrieve |
| `PATCH` | `/api/shares/{share_id}/` | bearer | shares_partial_update |

### System

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/health/` | bearer | health |

### Users

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/users/me/` | bearer | users_me_retrieve |
| `PATCH` | `/api/users/me/` | bearer | users_me_partial_update |

---

## Worked examples

### Register

```bash
curl -X POST https://host/api/auth/register/ \
  -H 'Content-Type: application/json' \
  -d '{"email":"a@example.com","password":"StrongPassw0rd!2024",
       "password_confirm":"StrongPassw0rd!2024","full_name":"Alice"}'
```

`password_confirm` is required.

### Upload

```bash
curl -X POST https://host/api/files/upload/ \
  -H "Authorization: Bearer $ACCESS" \
  -F "file=@report.pdf;type=application/pdf"
```

The endpoint is `/api/files/upload/`. `/api/files/` is list-only and rejects
POST with 405.

The declared `Content-Type` is **not** trusted — the real type is sniffed with
libmagic, and a mismatch against the allow-list returns 415. Filenames are
reduced to a safe basename: `../../../etc/passwd.pdf` is stored as
`passwd.pdf`.

Response includes the encryption metadata actually used:

```json
{
  "id": "bd00b1b8-aa33-4d55-995f-dcb2c46dff77",
  "filename": "report.pdf",
  "size": 62, "encrypted_size": 118,
  "mime_type": "application/pdf",
  "checksum_sha256": "bb407bef...",
  "encryption": {
    "encrypted": true,
    "algorithm": "AES-256-GCM-STREAM-V1",
    "key_wrapping_algorithm": "RSA-OAEP-SHA256-MGF1-SHA256",
    "chunk_count": 1
  },
  "malware_scan": { "status": "SKIPPED", "scanner_enabled": false }
}
```

No endpoint ever returns a DEK, a private key, or a storage path.

### Create a public link

```bash
curl -X POST https://host/api/files/<file_id>/share-link/ \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{"expires_in_seconds":3600,"max_downloads":2,"password":"linkpass123"}'
```

The raw token is returned **once**, at creation. Only a SHA-256 hash is stored,
so it cannot be recovered later — reissue the link instead.

### Use a password-protected link

```bash
# 1. exchange the password for a short-lived grant
curl -X POST https://host/api/share/<token>/verify-password/ \
  -H 'Content-Type: application/json' -d '{"password":"linkpass123"}'
# -> { "grant": "..." }

# 2. present the grant
curl -H "X-Share-Grant: <grant>" https://host/api/share/<token>/download/ -o file.pdf
```

Grants last 10 minutes and are bound to one link. Five wrong passwords lock
that link for 15 minutes.

Download limits are claimed with a single conditional `UPDATE`, so concurrent
requests cannot both take the last slot. Verified with 10 parallel threads:
exactly one 200, nine 410.

---

## What the API will not do

- Return a private key or a plaintext DEK through any endpoint.
- Expose filesystem paths.
- Trust a client-supplied MIME type or filename.
- Confirm whether an email address is registered during login or reset.
- Accept `role` as a writable field on a user-facing serializer.
- Serve the encrypted object store over HTTP.
