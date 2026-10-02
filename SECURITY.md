# Security Policy & Model — SecureShare

This document describes what SecureShare defends against, how, and where the
boundaries are. Evidence that these controls actually work lives in
[`backend/security/SECURITY_TESTING.md`](backend/security/SECURITY_TESTING.md).

---

## Reporting a vulnerability

Do **not** open a public issue. Email the maintainer with:

- what you found and where,
- reproduction steps or a proof of concept,
- the impact you think it has.

Expect acknowledgement within 72 hours. Please give us 90 days before public
disclosure. We will credit you unless you ask us not to.

---

## 1. Cryptography

| Property | Choice | Rationale |
|---|---|---|
| File encryption | **AES-256-GCM**, streamed in chunks | authenticated encryption — confidentiality *and* integrity in one pass |
| Data key (DEK) | 256-bit, `secrets.token_bytes(32)`, **one per file** | compromise of one file's key reveals nothing about any other |
| Nonce | 96-bit, `nonce_prefix(8B) ‖ counter(4B)`, unique per chunk | GCM nonce reuse is catastrophic; the counter makes reuse structurally impossible within a file, and the random prefix makes it impossible across files |
| AAD | header ‖ chunk counter ‖ final flag ‖ context(file id, object id) | chunks cannot be reordered, truncated, duplicated or transplanted into another file |
| DEK wrapping | **RSA-OAEP**, SHA-256 with MGF1-SHA-256 | padding oracle resistant; no PKCS#1 v1.5 |
| RSA key size | 4096-bit default, **< 2048 rejected at load** | |
| Password hashing | **Argon2id** (memory-hard), Django's `Argon2PasswordHasher` | resists GPU/ASIC cracking; used for both account and share-link passwords |
| Checksums | SHA-256 | integrity verification of plaintext end to end |
| Tokens | `secrets.token_urlsafe(32)` = 256 bits CSPRNG | |

All primitives come from the **`cryptography`** library (OpenSSL bindings).
No algorithm is hand-implemented.

**Explicitly not used anywhere for security:** ECB mode, static/reused IVs,
MD5, SHA-1, PKCS#1 v1.5 encryption, custom "encryption", `random` for secrets,
or rolling our own KDF.

### Key management

- The RSA private key is read from `RSA_PRIVATE_KEY_PATH` or
  `RSA_PRIVATE_KEY_PEM` at startup; optionally passphrase-protected via
  `RSA_PRIVATE_KEY_PASSPHRASE`.
- It is **never** returned by an endpoint, never serialized into a response,
  never written to a log, and never baked into a Docker image (it is mounted
  read-only at runtime).
- Each wrapped DEK records the `key_id` (SHA-256 fingerprint of the public key)
  that wrapped it, so **rotation** is possible without re-encrypting file
  bodies: point `RSA_PRIVATE_KEY_PATH` at the new key and list the old one in
  `RSA_RETIRED_PRIVATE_KEY_PATHS`.

---

## 2. Authentication & authorization

- Custom **UUID** user model — no sequential, enumerable user IDs.
- **JWT** access (short-lived) + refresh, signed with a key separate from
  `SECRET_KEY`. Tokens carry a `tv` (token-version) claim; changing a password
  or revoking sessions bumps it and instantly invalidates every issued token.
- Every authenticated request re-checks that the account is active and not
  locked out — a valid signature alone is not sufficient.
- **Account lockout** after `LOGIN_FAILURE_LIMIT` failures within a window,
  plus per-scope DRF throttles on login, registration and password reset.
- **Strong password policy**: minimum length, complexity, common-password
  and similarity checks.
- **RBAC**: `USER` and `ADMIN` roles enforced by DRF permission classes on the
  server. The role is never writable by the client; a normal user receives
  `403` from `/api/admin/test/` and every other admin-only route.
- **Authorization is never delegated to the frontend.** There is no UI-only
  gate anywhere; removing the React layer entirely changes no access decision.

### Enumeration resistance

Login, registration, password reset and recipient lookup return identical
responses whether or not the account exists. An unauthorized but *existing*
file returns **404**, exactly like a file that never existed — while still
recording an `UNAUTHORIZED_FILE_ACCESS` audit event internally.

---

## 3. File upload and storage

- Validation pipeline, in order: size → filename sanitisation → extension
  allow-list → **magic-byte sniffing** → declared-vs-detected MIME agreement →
  archive inspection (entry count + expansion ratio, i.e. zip-bomb guards) →
  optional ClamAV scan.
- **The client's `Content-Type` and filename are never trusted.** The stored
  MIME type is the detected one; the stored filename is sanitised and the
  object name on disk is unrelated to it.
- Files are written to `storage/encrypted/<random-object-id>` where the object
  id is `secrets.token_urlsafe(32)`. **Filesystem paths are never exposed** via
  the API, and object ids are validated against a strict pattern before any
  path is constructed, so `../` traversal cannot occur.
- Writes are **atomic**: ciphertext goes to a temp file and is renamed on
  success; any failure cleans up and leaves no partial object.
- Ciphertext files are mode `0600` inside a `0700` directory.
- nginx is configured to **refuse** to serve `/storage/` — bytes only leave
  through the API, after an authorization decision and decryption.
- Malware scanning honours `CLAMAV_FAIL_CLOSED`: if the scanner is unreachable,
  the upload is **rejected** rather than silently accepted.

---

## 4. Sharing

### User-to-user shares
Permission (`VIEW` / `DOWNLOAD`), optional expiry, owner-only modification,
immediate revocation. A recipient cannot re-share, cannot escalate their own
permission, and cannot see any other file. Deleting a file revokes its shares.

### Public share links
| Control | Implementation |
|---|---|
| Token | 256-bit CSPRNG (`secrets.token_urlsafe(32)`). Never a UUID, sequence, timestamp, username or predictable hash. |
| At rest | Only `SHA-256(token)` is stored, plus a 12-hex `token_prefix` **of the hash** for safe correlation in logs. A database dump yields no usable links. |
| Disclosure | The raw token is returned exactly once, in the creation response. No endpoint can retrieve it again. |
| Expiry | `1h / 6h / 24h / 3d / 7d / custom`, evaluated server-side against `expires_at` on every request. JS timers are cosmetic. |
| Download limit | unlimited / 1 / 5 / 10 / custom, claimed with a single conditional SQL `UPDATE`; two simultaneous requests can never both succeed. |
| Password | optional, hashed with Argon2id, verified in constant time, exchanged for a short-lived signed grant scoped to that one link. |
| Brute force | per-link attempt counter in Redis; after `SHARE_LINK_PASSWORD_MAX_ATTEMPTS` the link locks (429) — and stays locked even for the correct password — for `SHARE_LINK_PASSWORD_LOCKOUT_SECONDS`. |
| Revocation | `revoked_at` checked on every request; effective immediately, no cache to wait out. |
| Scope | A link grants access to exactly one file, read-only, and is useless as a bearer token for the authenticated API. |

Every state check is re-derived from the database per request, so tampering
with a row (`download_count`, `permission`, `revoked_at`, `password_hash`) does
not produce a bypass — a corrupted `password_hash` fails **closed**.

---

## 5. Audit logging

Append-only log of security-relevant events: authentication, role changes,
file upload/download/delete, unauthorized access attempts, share creation and
revocation, share-link access/download/expiry/revocation/password failure, and
download-limit exhaustion.

Each entry records actor, role, action, object, outcome, IP, user agent,
request id and a metadata blob. Ordinary users can read only their own entries
and have **no** API path to modify or delete any entry; the Django admin
registration is read-only.

**Never recorded, in the database or in logs:** plaintext passwords, share-link
passwords, raw share tokens, JWTs, encryption keys (wrapped or unwrapped), or
plaintext file contents. A logging filter (`core/logging.py`) redacts known
sensitive keys from every log record as a second line of defence, and a test
asserts that secrets used during the suite never appear in captured output.

---

## 6. Transport & application hardening

| Control | Setting |
|---|---|
| HTTPS | nginx terminates TLS 1.2/1.3, forward-secret suites only, session tickets off |
| HSTS | `max-age=31536000; includeSubDomains; preload` |
| TLS redirect | `SECURE_SSL_REDIRECT=True`, `SECURE_PROXY_SSL_HEADER` behind nginx |
| Cookies | `Secure`, `HttpOnly`, `SameSite=Lax` |
| CSP | `default-src 'none'` plus explicit allowances |
| Framing | `X-Frame-Options: DENY`, `frame-ancestors 'none'` |
| MIME sniffing | `X-Content-Type-Options: nosniff` on every response |
| Referrer | `strict-origin-when-cross-origin`; `no-referrer` on share-link routes |
| CORS | explicit `CORS_ALLOWED_ORIGINS`; `CORS_ALLOW_ALL_ORIGINS` is **rejected** in production |
| Hosts | explicit `ALLOWED_HOSTS`; wildcard refused at startup |
| Debug | `DEBUG=False` by default; production raises `ImproperlyConfigured` if forced on |
| Errors | structured JSON `{error, message, request_id}`; no stack traces, no SQL, no internal paths |
| Rate limits | DRF per-scope throttles + nginx `limit_req` zones |
| Container | non-root user, no build toolchain at runtime, `no-new-privileges`, read-only key mounts |

`python manage.py check --deploy` against production settings reports
**0 issues, 0 silenced**.

---

## 7. Secrets handling

- No secret is hard-coded. Everything comes from the environment.
- `.env`, `*.pem`, `*.key`, `keys/` and `nginx/certs/*` are gitignored;
  `.env.example` documents every variable with placeholder values.
- `SECRET_KEY` and `JWT_SIGNING_KEY` are distinct, must be ≥ 50 characters, and
  production refuses to start with the development defaults.
- The Docker build context excludes `.env` and key material; keys are mounted
  read-only at runtime rather than copied into the image.

---

## 8. Known limitations

These are deliberate, documented boundaries — not oversights.

1. **Server-side encryption, not end-to-end.** The server holds the RSA private
   key, so a fully compromised server can decrypt files. Defending against that
   requires client-side encryption, where the server never sees the DEK.
2. **Database columns are not encrypted.** Filenames, sizes, timestamps and
   audit metadata are stored in plaintext. Use volume/disk encryption for the
   database.
3. **No HSM/KMS integration.** The private key sits in a file or environment
   variable. The key-provider abstraction with rotation support is the hook a
   KMS backend would plug into.
4. **Lockout and throttle state lives in Redis.** Flushing Redis clears it; run
   Redis with AOF persistence (the compose file does).
5. **A mid-stream download failure does not refund a claimed slot.** This is
   fail-closed on purpose: refunding would let an attacker farm downloads by
   aborting connections.
6. **Audit log is append-only by policy, not cryptographically chained.** A
   database superuser could alter history. Hash-chaining or shipping to a
   write-once sink would close this.
7. **ClamAV socket transport is not exercised in CI** (no daemon in the test
   environment); the fail-open/fail-closed decision logic is covered.
8. **No frontend yet**, so no `npm audit` results and no browser-side
   protections are claimed.

---

## 9. OWASP Top 10 (2021) coverage

| Risk | Status |
|---|---|
| A01 Broken Access Control | Server-side permission classes, ownership checks, UUID ids, 404-not-403 for unauthorized existing objects. Tested for IDOR and privilege escalation. |
| A02 Cryptographic Failures | AES-256-GCM + RSA-OAEP via `cryptography`; Argon2id; TLS 1.2+; no weak primitives. |
| A03 Injection | Django ORM everywhere, no string-built SQL; filenames sanitised; `Content-Disposition` header injection blocked and unit-tested. |
| A04 Insecure Design | Envelope encryption, fail-closed scanning, atomic download claims, enumeration-resistant responses. |
| A05 Security Misconfiguration | `DEBUG=False` default, prod startup assertions, `check --deploy` clean, hardened containers and nginx. |
| A06 Vulnerable Components | pip-audit in the security script: 0 CVEs across both requirements files. |
| A07 Auth Failures | Argon2id, lockout, throttling, token versioning, strong password policy, no user enumeration. |
| A08 Integrity Failures | AES-GCM tags + SHA-256 checksums; AAD binds chunk order and file identity; tampering yields 422, never plaintext. |
| A09 Logging Failures | Comprehensive audit log with redaction; secrets never recorded; failures logged as well as successes. |
| A10 SSRF | No user-controlled outbound requests in the backend. |
