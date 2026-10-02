# SecureShare — Architecture

How the system is put together, and why each boundary exists.

---

## 1. Request path

```
                             ┌─────────────────────────────────────────┐
                             │              Browser                     │
                             │  React SPA · access token in memory      │
                             │  refresh token in sessionStorage         │
                             └────────────────┬────────────────────────┘
                                              │ HTTPS (TLS 1.2 / 1.3)
                                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  nginx — edge (the only container with published ports)                 │
│  · terminates TLS, redirects :80 → :443                                 │
│  · security headers (HSTS, nosniff, DENY, Referrer-Policy, …)           │
│  · limit_req  auth 5r/m · share 20r/m · general 30r/s                   │
│  · 100 MB body cap, streaming (no buffering) on upload/download         │
│  · refuses /storage/ and dotfiles outright                              │
└───────────────┬─────────────────────────────────┬───────────────────────┘
                │ /  (everything else)            │ /api/  /static/
                ▼                                 ▼
┌───────────────────────────────┐   ┌─────────────────────────────────────┐
│  frontend container           │   │  api container (gunicorn, uid 10001)│
│  nginx:alpine, uid 101        │   │                                     │
│  read-only root filesystem    │   │   Django REST Framework             │
│  serves the built Vite bundle │   │   ├── Authentication  JWT bearer    │
│  SPA history fallback         │   │   ├── Authorization   permissions   │
│  (no secrets, no API keys)    │   │   ├── Validation      serializers   │
└───────────────────────────────┘   │   ├── Services        business rules│
                                    │   └── Encryption service            │
                                    └──┬──────────┬───────────┬───────────┘
                                       │          │           │
                     ┌─────────────────┘          │           └──────────────┐
                     ▼                            ▼                          ▼
        ┌────────────────────┐     ┌─────────────────────┐     ┌────────────────────────┐
        │ PostgreSQL         │     │ Redis               │     │ Encrypted object store │
        │ users, files,      │     │ cache · throttles   │     │ ciphertext only,       │
        │ shares, audit log  │     │ Celery broker       │     │ mode 0700, never       │
        │ metadata + wrapped │     │                     │     │ web-reachable          │
        │ DEKs (no plaintext)│     │                     │     │                        │
        └────────────────────┘     └─────────┬───────────┘     └────────────────────────┘
                                             │
                               ┌─────────────┴─────────────┐
                               ▼                           ▼
                      ┌─────────────────┐        ┌──────────────────┐
                      │ celery worker   │        │ celery beat      │
                      │ async tasks     │        │ scheduled jobs   │
                      └─────────────────┘        └──────────────────┘

        RSA private key: bind-mounted read-only at /run/secrets/rsa_private.pem
        Never baked into an image. Never returned by any endpoint.
```

Seven containers. Only `nginx` publishes ports (8080, 8443). PostgreSQL, Redis,
the API, the workers and the encrypted store are reachable only on the internal
Docker network.

---

## 2. Layers inside the API

Request → middleware → URL route → view → permission → serializer → service →
model/storage. Business rules live in services, not views, so the same rule
holds however it is reached.

| Layer | Location | Responsibility |
| --- | --- | --- |
| Middleware | `core/middleware.py` | request id, security headers, structured access log |
| Permissions | `core/permissions.py` | `IsAdmin`, ownership, share-grant checks |
| Throttles | `core/throttling.py`, `*/throttles.py` | per-scope rate limits backed by Redis |
| Serializers | `*/serializers.py` | input validation, output shaping, field whitelisting |
| Services | `*/services.py`, `sharing/link_services.py` | business rules, transactions |
| Crypto | `security/crypto.py`, `security/keys.py` | the only place encryption happens |
| Storage | `security/storage.py` | content-addressed ciphertext on disk |
| Audit | `audit/services.py` | append-only event record |

**One encryption implementation.** `security/crypto.py` is the single module
that performs cryptography. Files, shares and admin paths all call it. There is
no second code path and no hand-rolled algorithm.

---

## 3. Authentication

Stateless JWT bearer tokens issued by `djangorestframework-simplejwt`.

- **Access token** — 15 minutes, sent as `Authorization: Bearer …`, held only
  in JavaScript memory. Lost on refresh, which is intentional.
- **Refresh token** — 1 day, kept in `sessionStorage`, exchanged at
  `/api/auth/refresh/`.
- **Passwords** — Argon2id (`Argon2PasswordHasher`). Never logged, never
  returned, never recoverable.
- **Lockout** — repeated failures lock the account for `LOGIN_LOCKOUT_SECONDS`
  (default 900). Login responses do not reveal whether the address exists.
- **Revocation** — every user row carries a `token_version` embedded in each
  token as `tv`. Disabling a user, changing a password or an admin action
  increments it, and every previously issued token stops validating at once.
  This is what gives a stateless design an immediate kill switch.

Tokens are never written to logs or the database in raw form.

---

## 4. Authorization

Enforced in the backend. The React app hides what a user cannot do, but hiding
is cosmetic — every decision is re-made server-side.

Three independent questions on each file request:

1. **Authenticated?** → else 401.
2. **Owner?** → full rights.
3. **Holder of a valid grant?** → a `FileShare` with the needed permission, or a
   valid share-link grant. Otherwise the file behaves as if it does not exist.

Non-owners receive **404, not 403**, on another user's file. A 403 would confirm
the row exists; 404 leaks nothing.

Roles are `USER` and `ADMIN`. Admin endpoints sit behind `IsAdmin`; a normal
user gets 403, an anonymous caller 401. `role` is not a writable field on any
user-facing serializer, so privilege cannot be self-granted.

---

## 5. Encryption and key wrapping

Envelope encryption. Every file gets its own key; that key is itself encrypted.

```
upload
  │
  ├─ DEK = secrets.token_bytes(32)                 ← fresh 256-bit key per file
  ├─ ciphertext = AES-256-GCM(DEK, plaintext)      ← streamed in chunks
  ├─ wrapped = RSA-OAEP-SHA256(public_key, DEK)    ← 384 bytes for RSA-3072
  ├─ store ciphertext on disk, wrapped DEK in PostgreSQL
  └─ discard the plaintext DEK                      ← never persisted anywhere

download
  │
  ├─ authorize the caller
  ├─ DEK = RSA-OAEP-decrypt(private_key, wrapped)
  ├─ stream-decrypt, verifying the GCM tag of every chunk
  └─ any tag mismatch → abort, no partial plaintext returned
```

**Container format** (`security/crypto.py`):

| Field | Value |
| --- | --- |
| Magic | `SSENC1` |
| Header | `>6sBBI16s8s` — 36 bytes: magic, version, algorithm id, chunk size, stream id, nonce prefix |
| Algorithm | `AES-256-GCM-STREAM-V1` |
| Key wrap | `RSA-OAEP-SHA256-MGF1-SHA256` |
| DEK | 32 bytes from `secrets.token_bytes` |
| Nonce | 12 bytes = 8-byte random prefix ‖ 4-byte chunk counter |
| Tag | 16 bytes per chunk |
| Frame | `u32 length ‖ ciphertext+tag` |
| AAD | header ‖ counter ‖ final-chunk flag ‖ caller context |

Three properties this buys:

- **Nonce uniqueness.** The prefix is random per file and the counter is unique
  per chunk, so no (key, nonce) pair repeats — the failure mode that breaks GCM.
- **Chunk-level integrity.** Each chunk authenticates its own position and
  whether it is final, so truncation, reordering and splicing are all detected,
  not just bit flips.
- **Context binding.** The AAD ties ciphertext to the logical object, so a blob
  cannot be transplanted to another record.

The private key is read from a path given by configuration. It is never baked
into an image, never returned by an endpoint, and never logged. Rotation is
supported via `RSA_RETIRED_PRIVATE_KEY_PATHS`: each wrapped DEK records the key
id that sealed it, so old files stay readable after a new key is issued.

---

## 6. Storage

Ciphertext lives in a content-addressed tree outside the web root:

```
storage/encrypted/GU/dr/GUdrewIV0hLv80fu6y9JLiylJJdsHXcguu-CbL0hCCY
```

- Directory mode `0700`, owned by the application account.
- The object id is random, not derived from the filename, so nothing about the
  content leaks through the path.
- Original filenames are metadata in PostgreSQL, never path components — this
  is what makes traversal (`../../etc/passwd`) structurally impossible rather
  than merely filtered.
- nginx refuses `/storage/` outright. Ciphertext only leaves through the API,
  after authorization, decrypted in a stream.

Uploads are validated on content, not on what the client claims: size cap
(25 MB default), extension allow-list, and libmagic sniffing of the real type.
A `.exe` renamed to `.pdf` is rejected on the sniffed type.

---

## 7. Sharing

Two mechanisms, deliberately distinct.

**Direct share** — owner grants a named user `VIEW` or `DOWNLOAD` on one file.
`VIEW` does not imply download; the download endpoint re-checks. Only the owner
may modify or revoke. A partial unique index enforces one active share per
(file, recipient).

**Public link** — an unauthenticated URL:

| Property | Implementation |
| --- | --- |
| Token | `secrets.token_urlsafe(32)` — 256 bits of entropy |
| Storage | SHA-256 `token_hash`; the raw token is never stored |
| Lookup | 12-hex `token_prefix` index, then hash comparison |
| Expiry | required; default 24 h, capped at 30 days |
| Download limit | optional; enforced atomically |
| Password | optional; Argon2id, 5 attempts then a 900 s lockout |
| Grant | verifying the password returns a short-lived `X-Share-Grant` token (10 min), salted `secureshare.share-link-grant.v1` |
| Revocation | immediate; a revoked link 404s |

The download limit is a single conditional `UPDATE`:

```sql
UPDATE ... SET download_count = download_count + 1
WHERE id = … AND (max_downloads IS NULL OR download_count < max_downloads)
```

The database decides the winner, so concurrent requests cannot both claim the
last slot. Verified under 10 parallel threads: exactly one 200, nine 410.

---

## 8. Audit logging

`AuditLog` is append-only at the ORM level: `update()` and `delete()` raise
`AuditLogImmutableError`, and `save()` on an existing row raises. Ordinary users
cannot reach other users' records; the admin console exposes a filtered view.

Logged: authentication outcomes, uploads, downloads, share creation and
revocation, link access, admin actions, authorization failures.
Never logged: passwords, raw tokens, encryption keys, file contents.

---

## 9. Frontend

React 18 + TypeScript + Vite + Tailwind, React Router, one centralised Axios
client (`src/api/client.ts`) that attaches the bearer token, refreshes on 401
once, and routes all errors through a single handler.

The bundle contains no secrets. All API calls use **relative** `/api` paths, so
the proxy decides where the backend is — Vite in development, nginx in
production. The browser is never assumed to be on the same host as the API.

An ESLint rule bans `localStorage` for token storage. Access tokens stay in
memory; only the refresh token touches `sessionStorage`, which is cleared when
the tab closes. This is a deliberate trade-off: it is JavaScript-reachable, and
is listed as a residual risk in `THREAT_MODEL.md`.

---

## 10. Why these boundaries

| Boundary | Reason |
| --- | --- |
| nginx is the only published service | one place to reason about TLS, headers and rate limits |
| Frontend is a separate container | a static bundle needs no database, no secrets, no Python |
| Crypto in one module | a second implementation is a second set of bugs |
| Services separate from views | the same rule applies however the code is reached |
| Ciphertext outside the web root | a web-server misconfiguration cannot expose it |
| Append-only audit | an attacker who gains a session still cannot erase the trail |
| 404 instead of 403 | a status code should not confirm that a record exists |
