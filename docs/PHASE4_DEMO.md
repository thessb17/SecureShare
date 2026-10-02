# Phase 4 Demo — Secure Upload, Encrypted Storage, Download

Real transcripts from a running SecureShare instance. Identifiers differ
between runs; nothing below is hand-written illustration.

```bash
API=http://127.0.0.1:8000/api
TOK=$(curl -s -X POST $API/auth/register/ -H 'Content-Type: application/json' \
  -d '{"email":"p4@example.com","password":"Demo!Passphrase#2026","password_confirm":"Demo!Passphrase#2026","full_name":"P4"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["tokens"]["access"])')
```

---

## 1. The validation pipeline rejects bad input

### A disguised executable — `.pdf` extension, ELF magic bytes

```bash
printf '\x7fELF\x02\x01\x01\x00payload-here-pretending-to-be-a-pdf' > evil.pdf
curl -X POST $API/files/upload/ -H "Authorization: Bearer $TOK" \
     -F "file=@evil.pdf;type=application/pdf"
```
```json
{"error":"UNSUPPORTED_FILE_TYPE","request_id":"e45958aa...","message":"The detected content type of this file is not allowed."}
```
`HTTP 415`

The client said `application/pdf` and the filename said `.pdf`. Neither is
trusted: the first bytes are sniffed and the real type wins.

### A disallowed extension

```bash
printf 'MZ\x90\x00 fake exe' > bad.exe
curl -X POST $API/files/upload/ -H "Authorization: Bearer $TOK" -F "file=@bad.exe"
```
```json
{"error":"UNSUPPORTED_FILE_TYPE","message":"This file type is not allowed."}
```
`HTTP 415`

Both rejections are recorded as `FILE_UPLOAD_REJECTED` audit events.

### The rest of the pipeline

| Check | Behaviour |
|---|---|
| Size | `> MAX_UPLOAD_SIZE` → 413 `FILE_TOO_LARGE`, streamed so an oversized body is cut off early |
| Filename | sanitised; directory components, control characters and quotes stripped |
| Extension | allow-list; double extensions (`report.pdf.exe`) resolved to the **last** one |
| Magic bytes | first `SNIFF_SIZE` bytes checked against known signatures |
| Declared vs detected | mismatch → 415 |
| Archives | entry count (`MAX_ZIP_ENTRIES`) and expansion ratio (`MAX_ZIP_EXPANSION_RATIO`) → zip-bomb guard |
| Malware | optional ClamAV; with `CLAMAV_FAIL_CLOSED=True` an unreachable scanner **rejects** the upload |

---

## 2. A legitimate upload

```bash
head -c 1500 /dev/urandom | base64 > notes.txt
curl -X POST $API/files/upload/ -H "Authorization: Bearer $TOK" \
     -F "file=@notes.txt;type=text/plain"
```
```json
{
    "id": "8909608c-6d29-42d8-869e-fb0953a9ffb4",
    "filename": "notes.txt",
    "size": 2027,
    "encrypted_size": 2083,
    "mime_type": "text/plain",
    "extension": "txt",
    "checksum_sha256": "ae8f2cabfa5df1108ed12e2916b9a03c236068b4549b20b9907d085001a61500",
    "status": "ACTIVE",
    "owner": {"id": "52739424-...", "email": "p4@example.com", "full_name": "P4"},
    "encryption": {
        "encrypted": true,
        "algorithm": "AES-256-GCM-STREAM-V1",
        "key_wrapping_algorithm": "RSA-OAEP-SHA256-MGF1-SHA256",
        "chunk_count": 1
    },
    "malware_scan": {"status": "SKIPPED"}
}
```

Note the response contains **no** `stored_object_id` and no filesystem path.

---

## 3. What is actually written to disk

```
stored_object_id : k_E3jtLKaBVJsKX8u6f8U3eNOzMys_56rM2s0U6BUKc
on-disk path     : storage/encrypted/k_/E3/k_E3jtLKaBVJsKX8u6f8U3eNOzMys_56rM2s0U6BUKc
file mode        : 0o600
dir  k_/E3       : 0o700
dir  k_          : 0o700
root mode        : 0o700
plaintext bytes  : 2027      ciphertext bytes: 2083
container magic  : b'SSENC1'
plaintext visible in ciphertext? False
algorithm        : AES-256-GCM-STREAM-V1
key wrapping     : RSA-OAEP-SHA256-MGF1-SHA256
wrapped DEK      : ab04e55bc115e9d9a8f99c931cf8e2cd0e2e341a1198260b55a4d2a7...  (384 bytes)
key_id           : 5f3f30c0a58d2ae747b456f46cf70372
sha256(original) : 20c8058ffb144fad77666c2272b0044523d35862d908dbf9a991beee15d00c9c
stored checksum  : 20c8058ffb144fad77666c2272b0044523d35862d908dbf9a991beee15d00c9c
```

- The object name is `secrets.token_urlsafe(32)` — unrelated to the filename,
  the owner or any sequence. Two uploads of the same file land in different
  objects under different keys.
- The 56-byte overhead is the `SSENC1` header (36 B) + per-chunk length prefix
  and GCM tag.
- The wrapped DEK is 384 bytes = RSA-3072/4096 OAEP output, stored in the
  database, not on the filesystem next to the ciphertext.
- `key_id` identifies which RSA key wrapped this DEK, which is what makes key
  rotation possible without re-encrypting file bodies.

### Container format

```
header  struct ">6sBBI16s8s"  = 36 bytes
        "SSENC1" | version | alg | chunk_size | stream_id(16B) | nonce_prefix(8B)
frame   u32 length || ciphertext+tag        (repeated)
nonce   nonce_prefix ‖ u32 counter          (unique per chunk)
AAD     header ‖ counter ‖ final_flag ‖ context(file_id, object_id)
```

Binding the counter, the final-chunk flag and the file identity into the AAD
means chunks cannot be reordered, dropped, duplicated, or moved between files
without the GCM tag check failing.

---

## 4. Download round-trip

```bash
curl -s -D - -H "Authorization: Bearer $TOK" $API/files/$FID/download/ -o back.txt
```
```http
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Disposition: attachment; filename="notes.txt"; filename*=UTF-8''notes.txt
X-Content-Type-Options: nosniff
Cache-Control: no-store, private
```
```
$ cmp notes.txt back.txt && echo "round-trip byte-identical: YES"
round-trip byte-identical: YES
```

`Content-Disposition` carries both an ASCII-safe `filename=` and an RFC 5987
`filename*=` form. Carriage returns, newlines, quotes and backslashes are
stripped from the filename before it reaches the header — header injection is
unit-tested in `tests/test_audit_and_hardening.py::test_content_disposition_cannot_be_injected`.

---

## 5. Tamper with the ciphertext

Flip a single bit in the stored object, then ask for it again:

```
flipped 1 bit at offset 60
download after tampering -> HTTP 422  FILE_INTEGRITY_ERROR - The stored file failed its integrity check and cannot be served.
```

Server log:
```
ERROR    secureshare.security file_integrity_failure
INFO     secureshare.audit    FILE_INTEGRITY_FAILURE
WARNING  django.request       Unprocessable Content: /api/files/<id>/download/
```

The AES-GCM tag check fails and **no plaintext is emitted** — not even the
chunks before the damaged one, because the response is only committed after
the first chunk authenticates. This is the property that makes "encrypted at
rest" mean something: an attacker with write access to the object store cannot
silently substitute content.

---

## 6. Authorization

A second account tries the same file id:

```
GET    /api/files/<id>/           -> HTTP 404
GET    /api/files/<id>/download/  -> HTTP 404
DELETE /api/files/<id>/           -> HTTP 404
```

**404, not 403.** A 403 would confirm the file exists, which is an enumeration
oracle. Internally the attempt is still recorded:

```
INFO     secureshare.audit    UNAUTHORIZED_FILE_ACCESS
WARNING  secureshare.security UNAUTHORIZED_FILE_ACCESS
```

> This was a real bug found while writing the Phase 6 tests: the view returned
> 403 for an existing-but-unauthorized file. Fixed in
> `files/views.py::get_file_for_access`.

---

## 7. Delete

```
DELETE /api/files/<id>/   -> HTTP 204
GET    /api/files/<id>/   -> HTTP 404
```

Delete is a soft delete: `status=DELETED` and `deleted_at` are set, the row
stays for audit purposes, and any share links or user-to-user shares pointing
at the file are revoked immediately. The Celery task
`files.tasks.purge_deleted_objects` removes the ciphertext after a retention
window:

```python
purge_deleted_objects(older_than_minutes=60)   # returns the number of objects removed; idempotent
```

---

## 8. Audit events in this phase

| Event | When |
|---|---|
| `FILE_UPLOADED` | successful upload |
| `FILE_UPLOAD_REJECTED` | any validation failure (with the reason, never the file bytes) |
| `FILE_DOWNLOADED` | successful download |
| `FILE_DELETED` | soft delete |
| `UNAUTHORIZED_FILE_ACCESS` | a user touched a file they do not own |
| `FILE_INTEGRITY_FAILURE` | GCM tag or checksum mismatch |

---

## 9. Endpoints

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/files/upload/` | multipart; full validation pipeline |
| `GET` | `/api/files/` | owner's files, paginated |
| `GET` | `/api/files/<id>/` | metadata |
| `GET` | `/api/files/<id>/download/` | decrypt + stream |
| `DELETE` | `/api/files/<id>/` | soft delete, revokes shares |

Error codes: `FILE_TOO_LARGE` (413), `UNSUPPORTED_FILE_TYPE` (415),
`INVALID_FILENAME` (400), `MALFORMED_UPLOAD` (400), `MALWARE_DETECTED` (422),
`FILE_NOT_FOUND` (404), `FILE_INTEGRITY_ERROR` (422).
