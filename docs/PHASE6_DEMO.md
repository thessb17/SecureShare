# Phase 6 Demo — Secure Public Share Links

Everything below is a **real transcript** captured from a running SecureShare
instance (Django + PostgreSQL 17 + Redis). Nothing is illustrative or
hand-written: the JSON, headers, database rows and audit entries were copied
from the terminal. Identifiers differ between runs.

Two ways to reproduce:

```bash
# A. scripted - 53 assertions, exits non-zero on any failure
python scripts/demo_phase6.py --base-url http://127.0.0.1:8000

# B. by hand - the curl walkthrough below
```

> Registration is throttled on purpose, so running the script twice in quick
> succession from the same IP exits with `HTTP 429` and an explanation. That is
> the anti-abuse control working. Wait out the window, or in a dev environment:
> `redis-cli --scan --pattern '*throttle*' | xargs -r redis-cli DEL`.

---

## 0. Start the stack

```bash
docker compose up -d --build          # or run the services locally
docker compose exec api python manage.py migrate
curl -s localhost:8000/api/health/
```

```json
{"status":"ok","version":"0.6.0","database":"ok","redis":"ok","cache":"ok","storage":"ok","encryption_keys":"ok"}
```

The health endpoint actually round-trips a query to PostgreSQL, a `SET`/`GET`
to Redis, a write/read/delete to the object store and an unwrap with the RSA
key — it is not a hard-coded `{"status":"ok"}`.

---

## 1. Register and upload a file

```bash
API=http://127.0.0.1:8000/api
PW='Demo!Passphrase#2026'

TOK=$(curl -s -X POST $API/auth/register/ -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"'"$PW"'","password_confirm":"'"$PW"'","full_name":"Curl Demo"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["tokens"]["access"])')

printf 'Hello from SecureShare Phase 6.\n' > report.txt
curl -s -X POST $API/files/upload/ -H "Authorization: Bearer $TOK" \
     -F "file=@report.txt;type=text/plain"
```

```json
{
    "id": "31ad1002-a548-4b0f-8864-80e4bf933c63",
    "filename": "report.txt",
    "size": 32,
    "encrypted_size": 88,
    "mime_type": "text/plain",
    "checksum_sha256": "032f7b2dacf0f7583fbb9228871f7289f987cc3790655370e8321d8b1238a2d0",
    "status": "ACTIVE",
    "encryption": {
        "encrypted": true,
        "algorithm": "AES-256-GCM-STREAM-V1",
        "key_wrapping_algorithm": "RSA-OAEP-SHA256-MGF1-SHA256",
        "chunk_count": 1
    },
    "malware_scan": { "status": "SKIPPED" }
}
```

`mime_type` was sniffed from the magic bytes, not taken from the client. The
response contains no `stored_object_id` and no filesystem path.

---

## 2. Create a public share link

24-hour expiry, one download, password protected:

```bash
FID=31ad1002-a548-4b0f-8864-80e4bf933c63
curl -s -X POST $API/files/$FID/share-link/ -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"expires_in":"24h","max_downloads":1,"permission":"DOWNLOAD","password":"Sh4re-Link!Secret"}'
```

```json
{
    "share_link": {
        "id": "2fecca4b-da9c-432e-ade8-a2c969f3d0a3",
        "file": { "id": "31ad1002-...", "filename": "report.txt", "size": 32 },
        "token_prefix": "1776dd09fb84",
        "permission": "DOWNLOAD",
        "status": "ACTIVE",
        "expires_at": "2026-10-02T20:11:11.503830Z",
        "expires_in_seconds": 86399,
        "max_downloads": 1,
        "download_count": 0,
        "downloads_remaining": 1,
        "password_protected": true,
        "revoked_at": null
    },
    "token": "Vi5LXBgNrv6EIlv8FsyijH-elkzuZEh-23LGtPWdLYg",
    "url": "http://localhost:5173/share/Vi5LXBgNrv6EIlv8FsyijH-elkzuZEh-23LGtPWdLYg",
    "expires_at": "2026-10-02T20:11:11.503830Z",
    "permission": "DOWNLOAD",
    "max_downloads": 1,
    "warning": "Store this link now - the token is not recoverable later."
}
```

**`token` appears in this response and never again.** `GET /api/share-links/<id>/`
returns `token_prefix` only.

Expiry presets: `1h`, `6h`, `24h`, `3d`, `7d`, or `custom` with an explicit
`expires_at`. Download limits: omit `max_downloads` for unlimited, or pass
`1`, `5`, `10`, or any positive integer.

---

## 3. What the database actually stores

```
--- the row as stored in PostgreSQL ---
id               = 2fecca4b-da9c-432e-ade8-a2c969f3d0a3
token_hash       = 1776dd09fb8459b4808a4a8a3010fdd4228434548f89521f78378d8157c42414
token_prefix     = 1776dd09fb84
permission       = DOWNLOAD
expires_at       = 2026-10-02 20:11:11.503830+00:00
max_downloads    = 1
download_count   = 1
password_hash    = argon2$argon2id$v=19$m=102400,t=2,p=8$...<truncated>
revoked_at       = None

raw token present anywhere in the row?  False
```

- The token is a 256-bit CSPRNG value (`secrets.token_urlsafe(32)`); only its
  SHA-256 digest is stored, so a database dump cannot be replayed as links.
- `token_prefix` is the first 12 hex chars **of the hash** — safe to log and
  enough to correlate audit events with a link.
- The share password is Argon2id, the same hasher as account passwords.

---

## 4. Anonymous access — the full password flow

**4.1 Metadata is withheld until the password is proven**

```bash
curl -s $API/share/$TOKEN/
```
```json
{"password_required": true, "message": "This share link is password protected."}
```

Note what is *not* leaked: filename, size, owner, or even whether the link has
downloads left.

**4.2 Download without a password → 401**

```json
{"error":"SHARE_LINK_PASSWORD_REQUIRED","request_id":"bb041b5d...","message":"This share link is password protected."}
```

**4.3 Wrong password → 403, no bytes**

```json
{"error":"SHARE_LINK_PASSWORD_INVALID","request_id":"5bf6586b...","message":"The supplied password is incorrect."}
```

**4.4 Correct password → short-lived signed grant**

```bash
curl -s -X POST $API/share/$TOKEN/verify-password/ \
  -H 'Content-Type: application/json' -d '{"password":"Sh4re-Link!Secret"}'
```
```json
{"password_required": true, "grant": "eyJsaW5rIjoiMmZlY2NhNGItZGE5...", "expires_in": 600}
```

The grant is a Django-signed, link-scoped, 10-minute token. It means the
password does not have to be re-sent on each call, and it is useless for any
other link.

**4.5 Metadata unlocked**

```bash
curl -s $API/share/$TOKEN/ -H "X-Share-Grant: $GRANT"
```
```json
{
    "filename": "report.txt",
    "size": 32,
    "mime_type": "text/plain",
    "permission": "DOWNLOAD",
    "expires_at": "2026-10-02T20:11:11.503830Z",
    "expires_in_seconds": 86389,
    "max_downloads": 1,
    "download_count": 0,
    "downloads_remaining": 1,
    "password_required": true,
    "encryption": {"encrypted": true, "algorithm": "AES-256-GCM-STREAM-V1"}
}
```

**4.6 Download**

```bash
curl -s -D - -X POST $API/share/$TOKEN/download/ \
  -H 'Content-Type: application/json' -d "{\"grant\":\"$GRANT\"}" -o got.txt
```
```http
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Disposition: attachment; filename="report.txt"; filename*=UTF-8''report.txt
X-Content-Type-Options: nosniff
Cache-Control: no-store, private
X-Share-Downloads-Remaining: 0
```
```
$ diff report.txt got.txt && echo "bytes identical to the original"
bytes identical to the original
```

The file was decrypted on the fly: DEK unwrapped with RSA-OAEP, ciphertext
streamed through AES-256-GCM with per-chunk tag verification.

**4.7 The limit bites**

```json
{"error":"SHARE_LINK_DOWNLOAD_LIMIT_REACHED","request_id":"1f01e874...","message":"The download limit for this share link has been reached."}
```
HTTP 410 Gone. The link object still exists but can never serve bytes again.

---

## 5. Audit trail for that one link

```
20:11:11  SHARE_LINK_CREATED          success=True  actor=demo@example.com  ip=127.0.0.1
          meta={"file_id":"31ad1002-...","filename":"report.txt","expires_at":"2026-10-02T20:11:11.503830+00:00",
                "permission":"DOWNLOAD","token_prefix":"1776dd09fb84","max_downloads":1,"password_protected":true}
20:11:21  SHARE_LINK_ACCESSED         success=True  actor=anonymous         ip=127.0.0.1
          meta={"file_id":"31ad1002-...","unlocked":false,"token_prefix":"1776dd09fb84","password_protected":true}
20:11:21  SHARE_LINK_PASSWORD_FAILURE success=False actor=anonymous         ip=127.0.0.1
          meta={"token_prefix":"1776dd09fb84","failed_attempts":1}
20:11:21  SHARE_LINK_ACCESSED         success=True  actor=anonymous         ip=127.0.0.1
          meta={"file_id":"31ad1002-...","unlocked":true,"token_prefix":"1776dd09fb84","password_protected":true}
20:11:21  SHARE_LINK_DOWNLOAD         success=True  actor=anonymous         ip=127.0.0.1
          meta={"file_id":"31ad1002-...","filename":"report.txt","token_prefix":"1776dd09fb84",
                "max_downloads":1,"download_count":1}
20:11:21  DOWNLOAD_LIMIT_REACHED      success=True  actor=anonymous         ip=127.0.0.1
          meta={"token_prefix":"1776dd09fb84","max_downloads":1,"download_count":1}
20:11:21  DOWNLOAD_LIMIT_REACHED      success=False actor=anonymous         ip=127.0.0.1
          meta={"status":"EXHAUSTED","file_id":"31ad1002-...","token_prefix":"1776dd09fb84",
                "max_downloads":1,"download_count":1}

raw token in ANY audit row?       False
share password in ANY audit row?  False
```

`DOWNLOAD_LIMIT_REACHED` fires once with `success=True` when the final slot is
consumed (the link is now exhausted) and again with `success=False` for every
later attempt that is refused.

`SHARE_LINK_EXPIRED` and `SHARE_LINK_REVOKED` are emitted on the corresponding
paths; see `scripts/demo_phase6.py` sections 5 and 8.

---

## 6. Attack scenarios, live

Output from `python scripts/demo_phase6.py` against the running server:

```
0. Service health (real DB / Redis / storage / key probes)
----------------------------------------------------------
  200 {"status":"ok","version":"0.6.0","database":"ok","redis":"ok","cache":"ok","storage":"ok","encryption_keys":"ok"}
  [PASS] health endpoint reports ok
  [PASS] database probe ok
  [PASS] redis probe ok
  [PASS] storage probe ok
  [PASS] encryption_keys probe ok

1. Account + authentication
---------------------------
  [PASS] owner registered
  [PASS] JWT issued

2. Upload + envelope encryption (AES-256-GCM / RSA-OAEP)
--------------------------------------------------------
  [PASS] file uploaded (201)
  file id 391360b7-2bad-4dea-a14d-d6861781e265
  [PASS] server detected the MIME type
  [PASS] checksum matches the plaintext
  [PASS] stored encrypted (AES-256-GCM-STREAM-V1)
  [PASS] no storage path in the response

3. Create a public share link (24h, 2 downloads)
------------------------------------------------
  [PASS] link created (201)
  url     http://localhost:5173/share/4LVS45WXEIOp_kX9GP3Y6gxQlGq-miVgykS0oNl4yPI
  expires 2026-10-02T20:24:48.122056Z
  [PASS] token is 256-bit url-safe
  [PASS] token prefix stored, not the token
  [PASS] raw token not returned again

4. Anonymous access with the link
---------------------------------
  [PASS] stranger reads metadata
  [PASS] filename exposed, internals hidden
  [PASS] download 1 succeeds (200)
  [PASS] bytes are byte-identical to the original
  [PASS] remaining counter returned
  [PASS] download 2 succeeds
  [PASS] download 3 blocked by the limit (SHARE_LINK_DOWNLOAD_LIMIT_REACHED)

5. Invalid / guessed tokens
---------------------------
  [PASS] random guess rejected (404)
  [PASS] truncated real token rejected (404)
  [PASS] token hash rejected (404)
  [PASS] file uuid rejected (404)

6. Password protected link, wrong password, lockout
---------------------------------------------------
  [PASS] metadata hidden until unlocked
  [PASS] download without password -> 401
  [PASS] wrong password -> 403 (SHARE_LINK_PASSWORD_INVALID)
  [PASS] correct password -> grant
  [PASS] download with grant succeeds
  [PASS] downloaded bytes are correct
  [PASS] brute force ends in a lockout (codes=[403, 403, 403, 403, 429])
  [PASS] correct password also locked out

7. Concurrent download race (max_downloads = 1)
-----------------------------------------------
  [PASS] exactly one request won (200s=1 410s=9)

8. Revocation takes effect immediately
--------------------------------------
  [PASS] link works before revocation
  [PASS] revoke returns 204
  [PASS] revoked link is gone (SHARE_LINK_REVOKED)

9. Authorization boundaries
---------------------------
  [PASS] stranger cannot create a link for this file
  [PASS] stranger cannot revoke the link
  [PASS] anonymous cannot manage links
  [PASS] share token is not a bearer token
  [PASS] normal user cannot reach the admin endpoint

10. Audit trail (no secrets recorded)
-------------------------------------
  [PASS] SHARE_LINK_CREATED recorded
  [PASS] SHARE_LINK_ACCESSED recorded
  [PASS] SHARE_LINK_DOWNLOAD recorded
  [PASS] SHARE_LINK_REVOKED recorded
  [PASS] DOWNLOAD_LIMIT_REACHED recorded
  [PASS] SHARE_LINK_PASSWORD_FAILURE recorded
  [PASS] raw share token never logged
  [PASS] link password never logged
  [PASS] account password never logged

All demo checks passed.
```

### Why the race result is believable

`max_downloads=1`, ten simultaneous HTTP requests, **exactly one** 200 and nine
410s. The counter is never read into Python and written back. One statement
decides:

```sql
UPDATE sharing_sharelink
   SET download_count = download_count + 1
 WHERE id = %s AND revoked_at IS NULL
   AND (expires_at IS NULL OR expires_at > now())
   AND (max_downloads IS NULL OR download_count < max_downloads)
```

The request proceeds only if that UPDATE affected exactly one row. PostgreSQL's
row lock serialises the contenders. `tests/test_race_detection_sanity.py` runs
the same harness against a deliberately unsafe implementation and asserts that
it *does* overcount — proof the harness can detect a race rather than just
never seeing one.

---

## 7. Revocation and expiry

```bash
curl -s -X DELETE $API/share-links/$LINK_ID/ -H "Authorization: Bearer $TOK" -o /dev/null -w '%{http_code}\n'
# 204
curl -s $API/share/$TOKEN/
# {"error":"SHARE_LINK_REVOKED","message":"This share link has been revoked."}   HTTP 410
```

Revocation is a `revoked_at` timestamp checked on **every** request, so it is
effective immediately — there is no cache to wait out.

Expiry is evaluated against `expires_at` in the database on every request. The
only role of JavaScript is to display a countdown; deleting the timer in
devtools changes nothing. A Celery beat job (`expire-share-links`) marks stale
rows for reporting, but access control never depends on that job having run.

---

## 8. Endpoint reference

### Owner (JWT required)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/files/<id>/share-link/` | create a link — returns the raw token **once** |
| `GET` | `/api/share-links/?file=&status=` | list your links (filterable) |
| `GET` | `/api/files/<id>/share-links/` | links for one file |
| `GET` | `/api/share-links/<id>/` | one link (no raw token) |
| `PATCH` | `/api/share-links/<id>/` | change expiry / limit / permission / password |
| `DELETE` | `/api/share-links/<id>/` | revoke immediately (204) |

### Public (no authentication)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/share/<token>/` | metadata (withheld if locked) |
| `POST` | `/api/share/<token>/verify-password/` | exchange password for a grant |
| `POST` | `/api/share/<token>/download/` | decrypt and stream the file |

### Error codes

| HTTP | Code | Meaning |
|---|---|---|
| 404 | `SHARE_LINK_NOT_FOUND` | unknown/malformed token (identical body for every miss) |
| 410 | `SHARE_LINK_EXPIRED` | past `expires_at` |
| 410 | `SHARE_LINK_REVOKED` | owner revoked it |
| 410 | `SHARE_LINK_DOWNLOAD_LIMIT_REACHED` | no slots left |
| 401 | `SHARE_LINK_PASSWORD_REQUIRED` | password needed |
| 403 | `SHARE_LINK_PASSWORD_INVALID` | wrong password |
| 403 | `SHARE_PERMISSION_DENIED` | VIEW-only link used to download |
| 429 | `SHARE_LINK_LOCKED` | too many password attempts |
| 422 | `FILE_INTEGRITY_FAILURE` | AES-GCM tag mismatch — ciphertext tampered with |
