# SecureShare — Security Audit

**Date:** 2 October 2026
**Version audited:** 0.6.0
**Auditor:** project author (self-assessment — see §9)

This is an internal review by the person who wrote the code. It is not an
independent audit, and it does not certify the system as secure. It records
what was tested, what was found, what was fixed and what remains.

---

## 1. Methodology

Five techniques, applied together because each misses what the others catch:

| Technique | What it covers | Tooling |
| --- | --- | --- |
| Automated static analysis | Insecure patterns in source | Bandit, Ruff |
| Dependency analysis | Known CVEs in third-party code | pip-audit, npm audit |
| Security unit tests | Specific attacks, pinned as regressions | 245 pytest tests marked `security` |
| Live black-box probing | The deployed stack, over HTTP | curl + scripted probes against Docker |
| Manual code review | Logic flaws tools cannot see | Reading every security-relevant module |

The live probes ran against the real Docker stack with production settings —
`DEBUG=False`, real throttles, nginx edge, TLS — not against a test harness.

**What this audit does not include:** independent review, penetration testing by
a third party, formal verification, cryptographic proof, fuzzing at scale, or
real-browser testing. Scope is the application, not the host or the network.

---

## 2. Attack surfaces

| # | Surface | Exposure | Primary risks |
| --- | --- | --- | --- |
| S1 | Registration / login / refresh | Anonymous | Brute force, enumeration, token abuse |
| S2 | File upload | Authenticated | Traversal, MIME spoofing, oversized, malware |
| S3 | File read / download / delete | Authenticated | IDOR, horizontal escalation |
| S4 | Direct sharing | Authenticated | Unauthorised grant, recipient escalation |
| S5 | Public share links | **Anonymous** | Token guessing, expiry/limit bypass, password brute force |
| S6 | Admin API | Authenticated (ADMIN) | Vertical escalation |
| S7 | Audit log | Authenticated | Tampering, cross-user disclosure |
| S8 | Static frontend | Anonymous | Secret leakage in the bundle, XSS |
| S9 | nginx edge | Anonymous | Header gaps, store exposure, rate-limit failure |

S5 is the highest-risk surface: unauthenticated, bearer-based, and the most
likely to be shared beyond its intended recipient.

---

## 3. Vulnerabilities tested

### 3.1 Authentication

| Test | Result |
| --- | --- |
| Password brute force | Argon2id + lockout 900 s + throttle 10/min + nginx 5r/m. **Measured: 19 of 25 burst requests rejected with 429** |
| Weak passwords | Django validators reject short, common and numeric-only passwords |
| User enumeration | Login with unknown vs. known address returns identical shape; registration does not confirm existence |
| Token expiry | Access 15 min, refresh 1 day; expired tokens rejected |
| Refresh abuse | Refresh rotates; `token_version` invalidates on logout, password change and admin disable |
| Logout effectiveness | Version bump invalidates every outstanding token immediately |
| Lockout bypass | Lockout is stored server-side on the user row, not in a cookie or token |
| Authentication bypass | No endpoint accepts an unauthenticated caller where it should not — verified across all 44 operations |

### 3.2 Authorization

Live results against the running stack, user B attacking user A's file:

| Attack | Expected | Measured |
| --- | --- | --- |
| B reads A's file | denied | **404** |
| B downloads A's file | denied | **404** |
| B deletes A's file | denied | **404** |
| Anonymous reads A's file | denied | **401** |
| USER → `/api/admin/stats/` | denied | **403** |
| USER → `/api/admin/users/` | denied | **403** |
| USER → `/api/admin/security-events/` | denied | **403** |
| USER → `/api/admin/actions/` | denied | **403** |
| Anonymous → each admin endpoint | denied | **401** |
| Self-promotion `PATCH {"role":"ADMIN"}` | ignored | **200, role still `USER`** |
| Recipient modifies/revokes a share | denied | 403 |

404 rather than 403 on another user's file is deliberate: a 403 confirms the
record exists.

The self-promotion case is worth noting: the request returns 200 because other
fields in the payload are valid and were applied. `role` is simply not a
writable field, so it is discarded. Verified by re-reading the profile.

### 3.3 File security

| Attack | Payload | Measured |
| --- | --- | --- |
| Path traversal | `../../../etc/passwd.pdf` | Stored as **`passwd.pdf`** |
| Windows traversal | `..\..\win.pdf` | Stored as **`win.pdf`** |
| Absolute path | `/etc/shadow.pdf` | Stored as **`shadow.pdf`** |
| Script in filename | `<script>x</script>.pdf` | Stored as **`script_.pdf`** |
| MIME spoofing | PE binary (`MZ…`) named `invoice.pdf`, declared `application/pdf` | **415 UNSUPPORTED_FILE_TYPE** |
| Shell script | `script.sh`, declared `text/plain` | **415** |
| Executable | `app.exe` | **415** |
| Oversized | 30 MB against a 25 MB cap | **413 FILE_TOO_LARGE** |
| Direct storage access | `GET /storage/…` | **404** at the edge |

Filenames never become path components; the storage path is a random
content-addressed id. Traversal is structurally impossible, not filtered.

### 3.4 Cryptography

Measured directly against the encryption service:

| Property | Measurement |
| --- | --- |
| Algorithm | `AES-256-GCM-STREAM-V1`, key wrap `RSA-OAEP-SHA256-MGF1-SHA256`, RSA-3072 |
| Unique DEK per file | 5 encryptions of identical plaintext → **5 distinct wrapped DEKs** |
| Unique nonce per file | → **5 distinct nonce prefixes** |
| Non-deterministic ciphertext | identical plaintext twice → **ciphertexts differ** |
| Tamper: header byte | **IntegrityError** |
| Tamper: first ciphertext byte | **IntegrityError** |
| Tamper: middle byte | **IntegrityError** |
| Tamper: final byte (GCM tag) | **IntegrityError** |
| Truncated tail | **IntegrityError** |
| Truncated final frame | **IntegrityError** |
| Wrong AAD context | **IntegrityError** |
| Wrong DEK | **IntegrityError** |
| Plaintext DEK on the result object | **absent** — `EncryptionResult` exposes only `wrapped_dek`, never the plaintext key |

No custom cryptography. No ECB, no static IV, no MD5 or SHA-1 for security
purposes. Randomness is `secrets` throughout.

### 3.5 Share links

| Attack | Mitigation | Verified |
| --- | --- | --- |
| Token guessing | 256-bit `secrets.token_urlsafe(32)` | Yes |
| Token theft from the database | Only SHA-256 `token_hash` is stored | Yes |
| Expiry bypass | Server-side check on every access | Yes |
| Revocation bypass | Revoked link 404s immediately | Yes |
| Download-limit race | Single conditional `UPDATE`; database arbitrates | **10 parallel threads → exactly 1× 200, 9× 410** |
| Third download past a limit of 2 | Rejected | Yes |
| Password brute force | Argon2id, 5 attempts, 900 s lockout, scoped per link | Yes |
| Grant reuse across links | Grant salt binds to one link | Yes |
| Token in referrer | `Referrer-Policy: no-referrer` on share routes | Yes |
| Deleted file still reachable | Link 404s `SHARE_LINK_NOT_FOUND` | Yes |

### 3.6 Web security

| Attack | Measured |
| --- | --- |
| SQL injection — `' OR '1'='1` | **400**, no error leak |
| SQL injection — `'; DROP TABLE accounts_user;--` | **400**; table intact afterwards (subsequent query 200) |
| SQL injection — `1 UNION SELECT NULL--` | **400** |
| SQL injection — search parameter | **200**, treated as a literal string |
| Stored XSS — `<script>alert(1)</script>` as a name | Stored, returned **JSON-escaped** under `application/json` + `nosniff`; React escapes on render |
| CSRF | JWT bearer only; a session cookie alone yields 401 |
| CORS | Explicit allow-list; `CORS_ALLOW_ALL_ORIGINS` never enabled in production |
| Security headers | HSTS, nosniff, `X-Frame-Options: DENY`, Referrer-Policy, Permissions-Policy, COOP — all present |
| Server banner | nginx version **not** advertised |
| Info disclosure | `DEBUG=False`; generic errors with a request id |
| Open redirect | `safeInternalPath()` rejects external targets |
| Unknown API route | 404 JSON, not the SPA shell |

---

## 4. Tool results

| Tool | Scope | Result |
| --- | --- | --- |
| **Bandit** | 7,885 LOC, app code excluding tests | **0 high, 1 medium, 13 low** |
| **pip-audit** | `requirements.txt` + `requirements-dev.txt` | **No known vulnerabilities** |
| **Ruff** | Whole backend | **All checks passed** |
| **npm audit** (`--omit=dev`) | Production frontend dependencies | **2 moderate** |
| **pytest** | Backend | **542 passed**, of which **245 marked `security`** |
| **Coverage** | Backend | **90.3%** (3,904 statements, 378 missed) |
| **vitest** | Frontend | **53 passed** across 4 files |

**Bandit medium — B104, `config/settings/dev.py:17`.** Binding to `0.0.0.0` in
the development settings module. Intentional: the dev server must be reachable
from outside a container. Production binds behind nginx and never exposes the
API port. Accepted, not suppressed.

**npm audit — 2 moderate, both `react-router` 6.30.6.**
- `GHSA-wrjc-x8rr-h8h6` (open redirect) — mitigated in application code by
  `safeInternalPath()` in `frontend/src/utils/navigation.ts`, covered by 19
  tests. Post-login redirects to external origins are rejected.
- `GHSA-337j-9hxr-rhxg` — reachable only in framework/RSC mode. This app uses
  `BrowserRouter`, so the path does not exist here.

Both are accepted with reasons rather than silenced. Upgrading would be a major
version change for no reduction in real exposure.

---

## 5. Findings

Six genuine defects were found during this review. All six are fixed and
covered by regression tests.

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| F1 | Health endpoint reported a node that could not decrypt as healthy | **High** | Fixed |
| F2 | Docker stack served no frontend — every non-API route 404'd | **Medium** | Fixed |
| F3 | Container crash-loop from repo-relative paths resolving under `/` | Medium | Fixed |
| F4 | Paths resolved against the process working directory | Medium | Fixed |
| F5 | `docker compose` unusable from a pristine `.env.example` | Low | Fixed |
| F6 | `celery beat` permanently unhealthy from an inherited healthcheck | Low | Fixed |
| F7 | `.gitignore` negations that could never fire | Low | Fixed |

### F1 — False-healthy node (High)

`core/health.py:_check_encryption_keys` asserted only that the public key had
loaded. A read-only bind mount preserves host ownership, so a `0600` key owned
by uid 1000 is unreadable by the container's uid 10001. The consequence:

- uploads returned **201** (only the public key is needed to wrap a DEK);
- every download returned **503 DECRYPTION_UNAVAILABLE**;
- `/api/health/` still reported `"encryption_keys": "ok"`.

A load balancer would have kept routing traffic to a node that could not
decrypt a single file.

**Remediation:** the check now performs a real wrap → unwrap round trip on a
throwaway 32-byte DEK, which also catches a mismatched pair, a wrong passphrase
and a truncated PEM.

**Verified by negative control on the live stack:**

| Key state | `/api/health/` | Container |
| --- | --- | --- |
| `gid 1000`, mode `0600` | `503 degraded`, `"encryption_keys":"error"` | not healthy |
| `gid 10001`, mode `0640` | `200 ok` | `Up (healthy)` |

Three regression tests in `backend/tests/test_health.py`.

### F2 — Frontend absent from the container stack (Medium)

`docker-compose.yml` had no frontend service and nginx ended with
`location / { return 404; }`. `docker compose up` produced an API-only stack:
every page returned 404 in a browser. The end-to-end suite did not catch it
because it is an API suite and only exercises `/api/...`.

**Remediation:** added `frontend/Dockerfile` (multi-stage build → nginx:alpine,
non-root uid 101, read-only root filesystem), a `frontend` service, a frontend
upstream, and SPA proxying with history fallback. Added `scripts/verify_edge.py`
— 33 checks covering exactly the layer the API suite cannot see.

### F3 / F4 / F5 — Configuration path defects

`PROJECT_ROOT` is `/` inside the image, so `MEDIA_ROOT=./storage/media` became
`/storage/media` and gunicorn died with `PermissionError`. Separately, relative
paths resolved against the process working directory, so the documented
`cd backend && python manage.py runserver` failed with
`KeyManagementError: No RSA key material configured`. And `POSTGRES_PASSWORD`
was required by Compose but absent from `.env.example`, so the documented first
run failed immediately.

**Remediation:** `config/env.py:get_path()` gained `relative_to`; settings anchor
to `PROJECT_ROOT`; Compose pins `MEDIA_ROOT`, `LOG_DIR`, `STATIC_ROOT`;
`.env.example` gained a documented Compose block. Regression: `TestEnvPathResolution`.

### F6 — Permanently unhealthy scheduler (Low)

`beat` inherited the image `HEALTHCHECK`, which curls port 8000 — a port the
scheduler never listens on. The container reported unhealthy forever, and any
`depends_on: service_healthy` on it would have deadlocked.

**Remediation:** an explicit probe asserting PID 1 is still the scheduler and
that it has flushed its schedule within 600 s.

### F7 — Dead `.gitignore` negations (Low)

`keys/` and `storage/` excluded whole directories. Git does not descend into an
excluded directory, so `!keys/README.md` and `!storage/.gitkeep` could never
fire — key-management documentation would have been missing from a clone.
Changed to `keys/*` and `storage/*`; verified by planting 13 secrets and
artifacts in a scratch repository and confirming all stayed ignored.

---

## 6. OWASP Top 10 (2021)

| ID | Category | Controls | Assessment |
| --- | --- | --- | --- |
| **A01** | Broken Access Control | Backend-enforced ownership and grants; `IsAdmin`; UUIDs; 404 not 403; `role` not writable | Addressed — verified live |
| **A02** | Cryptographic Failures | AES-256-GCM, RSA-OAEP-SHA256, Argon2id, TLS 1.2+, per-file DEK, no plaintext keys at rest | Addressed |
| **A03** | Injection | ORM parameterisation; libmagic content sniffing; output escaping; `nosniff` | Addressed |
| **A04** | Insecure Design | Envelope encryption, append-only audit, atomic download claims, threat model | Addressed — server can still decrypt, by design |
| **A05** | Security Misconfiguration | `DEBUG=False`, `check --deploy` clean, non-root containers, read-only frontend FS, no banner | Addressed — **F1, F2, F3, F6 were all failures in this category** |
| **A06** | Vulnerable Components | pip-audit clean; npm audit 2 moderate, both reasoned; pinned versions | Addressed with documented exceptions |
| **A07** | Identification & Authentication | Argon2id, lockout, throttles, short-lived tokens, `token_version` revocation | Addressed |
| **A08** | Software & Data Integrity | GCM tags per chunk, AAD binding, SHA-256 checksums, lockfile integrity | Addressed |
| **A09** | Logging & Monitoring | Append-only audit, structured logs, request ids, security events | Partial — no alerting or SIEM |
| **A10** | SSRF | No user-supplied URL is ever fetched server-side | Not applicable |

A05 is the honest weak point: four of the seven findings were misconfiguration,
and three of those only appeared once the system was actually deployed rather
than read. Static review would not have found them.

---

## 7. Residual risk

| Risk | Severity | Why it remains |
| --- | --- | --- |
| RSA private key on disk | **High** | Simplicity. Production should use a KMS or HSM. Compromise exposes every file; loss makes every file unrecoverable |
| Server can decrypt | Medium | Inherent to server-side encryption. Not end-to-end |
| Refresh token in `sessionStorage` | Medium | JavaScript-reachable. The alternative trades XSS for CSRF exposure |
| Malware scanning off by default | Medium | ClamAV hook exists but is disabled; uploads are not scanned unless enabled |
| Share link is a bearer token | Medium | Anyone holding it has what it grants, until expiry or revocation |
| Self-signed certificate locally | Low | Production must install a real certificate |
| 2 moderate npm advisories | Low | Both reasoned above |
| No alerting on security events | Low | Events are recorded but nothing watches them |
| Distributed brute force | Low | Rate limits are per-IP |
| No independent audit | — | This document is a self-assessment |

---

## 8. Recommendations

Ordered by value, for anyone taking this further:

1. Move the private key to a KMS or HSM. This is the single highest-value change.
2. Enable ClamAV, or state clearly that uploads are unscanned.
3. Add alerting on repeated authorization failures and lockouts.
4. Add a real-browser test layer (Playwright) for the flows only a browser exercises.
5. Commission an independent review before any real-world use.
6. Add continuous dependency scanning rather than point-in-time audits.

---

## 9. Final status

**Tested and working:** authentication with lockout and revocation,
backend-enforced authorization, AES-256-GCM envelope encryption with per-file
keys and verified tamper detection, upload validation on sniffed content,
direct and public sharing with expiry, download limits, password protection and
revocation, append-only audit logging, admin RBAC, rate limiting, security
headers, TLS termination, and a seven-container Docker deployment.

**Measured:** 542 backend tests (245 security-marked) at 90.3% coverage,
53 frontend tests, 136/136 functional end-to-end checks, 33/33 edge checks,
0 high-severity Bandit findings, no known dependency vulnerabilities in Python.

**This system is not certified secure.** It is a student project that applies
established cryptographic primitives correctly as far as its tests demonstrate,
with controls verified against a running deployment rather than asserted. It
has known residual risks, listed above and not minimised. It has not been
independently audited and should not be used to protect real sensitive data
without one.

The most useful thing this audit produced is not the list of passing checks. It
is F1 — a health endpoint that reported success on a node that could not
perform its core function. Everything looked fine until the capability itself
was tested. That is the lesson worth carrying forward: check the capability,
not its preconditions.
