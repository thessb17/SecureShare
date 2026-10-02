# SecureShare — Phase 6 Report

**Secure public share links**, built on the Phase 1–5 backend.
Backend version `0.6.0`. All figures below were produced by commands executed
against this codebase; none are estimates.

---

## 0. Executive summary

| | |
|---|---|
| Scope delivered | `ShareLink` model, CSPRNG tokens hashed at rest, 6 endpoints, expiry presets, atomic download limits, optional Argon2id password with lockout, instant revocation, 7 audit event types |
| Tests | **366 passing, 0 failing** (130 of them Phase 6) |
| Coverage | **89.4 %** of application code (target 80 %) |
| Static analysis | Bandit 0 HIGH / Ruff 0 findings |
| Dependencies | pip-audit: **0 CVEs** across 46 runtime + 84 dev packages |
| Deployment check | `manage.py check --deploy` on prod settings: **0 issues, 0 silenced** |
| Live verification | `scripts/demo_phase6.py`: **53/53 checks**, passing under both the dev server and Gunicorn + production settings |
| Product bugs found and fixed | **5** (listed in §8) |

---

## 1. An important caveat about this session

The workspace this phase was built in **started completely empty.** The brief
said Phases 1–5 were already complete and that their code must not be
rewritten. There was no code to reuse.

Rather than fabricate integration against files that did not exist, the whole
backend (Phases 1 through 6) was built in this session, following the Phase 1–5
specifications as written, and then Phase 6 was built on top of it. So:

- The instruction "do not rewrite working Phase 1–5 code" was honoured in
  spirit — Phase 6 reuses the existing `security/crypto.py`, `security/keys.py`,
  `accounts/` authentication and `files/` services; **no second encryption
  implementation exists** anywhere in the tree.
- But it could not be honoured literally, because there was nothing on disk.

If you have a Phase 1–5 repository elsewhere that was supposed to be here, this
project will not merge cleanly with it. Everything else in this report describes
the code that is actually present in `/home/user/secure-share`.

---

## 2. Project tree

```
secure-share/
├── backend/
│   ├── config/
│   │   ├── settings/{base,dev,prod,test}.py   env-driven; DEBUG=False default
│   │   ├── celery.py          beat schedule incl. expire-share-links
│   │   ├── env.py             typed env readers with validation
│   │   └── urls.py wsgi.py asgi.py
│   ├── core/
│   │   ├── logging.py         sensitive-key redaction filter + JSON formatter
│   │   ├── middleware.py      request id, security headers, audit context
│   │   ├── exceptions.py      structured {error, message, request_id}
│   │   ├── throttling.py permissions.py pagination.py health.py
│   ├── accounts/              UUID user, Argon2id, JWT auth, RBAC, lockout
│   ├── security/
│   │   ├── crypto.py          AES-256-GCM streaming container  (the only crypto)
│   │   ├── keys.py            RSA-OAEP wrap/unwrap, rotation, retired keys
│   │   ├── storage.py         object store abstraction, atomic writes, 0600/0700
│   │   ├── checksums.py scanning.py exceptions.py
│   │   ├── SECURITY_TESTING.md
│   │   ├── run_security_checks.sh
│   │   └── reports/           Bandit / pip-audit / Ruff output
│   ├── files/                 File model, validators, services, download, tasks
│   ├── sharing/
│   │   ├── models.py          FileShare + ShareLink
│   │   ├── link_services.py   ◀ Phase 6 business logic
│   │   ├── services.py serializers.py views.py urls.py throttles.py tasks.py
│   ├── audit/                 append-only audit log
│   ├── tests/                 12 modules, 366 tests
│   ├── Dockerfile  requirements.txt  requirements-dev.txt
│   └── pytest.ini  .coveragerc  ruff.toml  manage.py
├── nginx/{nginx.conf, conf.d/secureshare.conf, certs/}
├── scripts/{generate_keys.py, demo_phase6.py}
├── docs/{PHASE4_DEMO.md, PHASE6_DEMO.md, PHASE6_REPORT.md}
├── keys/            (gitignored)  RSA key material, 0600
├── storage/         (gitignored)  ciphertext, 0700 tree
├── docker-compose.yml  .env.example  .gitignore  README.md  SECURITY.md
```

102 Python modules, ~13 200 lines.

---

## 3. Setup and operation

### 3.1 Local

```bash
cp .env.example .env                      # set SECRET_KEY, JWT_SIGNING_KEY, DATABASE_URL
python scripts/generate_keys.py --out-dir keys
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
cd backend && python manage.py migrate && python manage.py runserver 0.0.0.0:8000
curl localhost:8000/api/health/
```

### 3.2 Docker

```bash
docker compose up -d --build
docker compose exec api python manage.py migrate
curl -k https://localhost:8443/api/health/
```

Six services (`db`, `cache`, `api`, `worker`, `beat`, `nginx`), health checks on
all of them, `depends_on: condition: service_healthy` ordering, Postgres and
Redis unpublished to the host, non-root container user, keys mounted read-only.

> **Honest status:** Docker is not installed in the environment this phase was
> developed in, so `docker compose up` has **not** been run here. The compose
> file parses and the service graph is correct, but treat the Docker path as
> *unverified* until you run it. The application itself **was** verified under
> Gunicorn with `config.settings.prod` — the same entrypoint the image uses —
> and the full share-link workflow passed there (§6).

### 3.3 Environment

Every setting is read from the environment; `.env.example` documents ~70
variables. Required: `SECRET_KEY`, `JWT_SIGNING_KEY`, `DATABASE_URL`,
`REDIS_URL`, `ALLOWED_HOSTS`, `CORS_ALLOWED_ORIGINS`, `RSA_PRIVATE_KEY_PATH`.
Production raises `ImproperlyConfigured` at startup on a weak/missing secret, a
wildcard host, `DEBUG=True`, or `CORS_ALLOW_ALL_ORIGINS=True`.

### 3.4 Key generation and rotation

```bash
python scripts/generate_keys.py --out-dir keys                      # 4096-bit
python scripts/generate_keys.py --out-dir keys --passphrase-env RSA_KEY_PASSPHRASE
```

Rotation without re-encrypting file bodies:
```bash
python scripts/generate_keys.py --out-dir keys/2027
# .env
RSA_PRIVATE_KEY_PATH=keys/2027/rsa_private.pem
RSA_RETIRED_PRIVATE_KEY_PATHS=keys/rsa_private.pem
```
Proven by `tests/test_security_components.py::test_retired_keys_can_still_unwrap_old_files`.

### 3.5 Tests

```bash
cd backend
python -m pytest -q                                    # 366 tests
python -m pytest -q --cov --cov-report=html:../htmlcov
python -m pytest tests/test_share_link_security.py -q  # Phase 6 attack suite
```

### 3.6 Security tests

```bash
cd backend && ./security/run_security_checks.sh
```
Ruff → Bandit → pip-audit ×2 → `check --deploy` → pytest+coverage → npm audit.
Details and triage: `backend/security/SECURITY_TESTING.md`.

### 3.7 Demo

```bash
python scripts/demo_phase6.py --base-url http://127.0.0.1:8000
```
Walkthrough with transcripts: `docs/PHASE6_DEMO.md`.

---

## 4. Architecture

### 4.1 Layers

```
HTTP → nginx (TLS, rate limit, header hygiene)
     → Gunicorn → Django middleware (request id, security headers, log redaction)
     → DRF view            thin: parse, authorize, delegate, serialize
     → permission class    authorization decision
     → service layer       business logic, transactions, audit emission
     → security/*          crypto, keys, storage, scanning
     → PostgreSQL / Redis / object store
```

Views never touch crypto or the filesystem directly. `sharing/link_services.py`
is the only module that creates, validates or consumes share links, which is why
tampering with a DB row cannot produce a bypass: there is exactly one code path
and it re-derives everything from the row.

### 4.2 The `ShareLink` model

| Field | Type | Purpose |
|---|---|---|
| `id` | UUID pk | never exposed to anonymous callers |
| `file` | FK → File, CASCADE | the single file this link serves |
| `created_by` | FK → User, PROTECT | owner for authorization and audit |
| `token_hash` | char(64), unique, indexed | SHA-256 of the raw token — the lookup key |
| `token_prefix` | char(12), indexed | first 12 hex of the **hash**, safe for logs |
| `permission` | VIEW / DOWNLOAD | VIEW allows metadata only |
| `expires_at` | datetime, indexed | mandatory for links |
| `max_downloads` | int, nullable | NULL = unlimited |
| `download_count` | int, default 0 | incremented only by the atomic claim |
| `password_hash` | text, nullable | Argon2id |
| `revoked_at` | datetime, nullable | checked on every request |
| `access_count`, `last_accessed_at`, `last_downloaded_at` | telemetry |
| `created_at`, `updated_at` | | |

Database constraints (not just application checks):
`download_count >= 0`, `max_downloads IS NULL OR max_downloads >= 1`,
`download_count <= max_downloads` where applicable, unique `token_hash`.
Indexes on `token_hash`, `token_prefix`, `(file, revoked_at)`, `expires_at`.

### 4.3 Token design

```python
token = secrets.token_urlsafe(32)          # 256 bits of CSPRNG entropy
token_hash = hashlib.sha256(token.encode()).hexdigest()
token_prefix = token_hash[:12]
```

- **Not** a UUID, not sequential, not a timestamp, not derived from the
  filename, the user, or the file id.
- Lookup is by hash, so the database never holds anything replayable.
- The raw token is returned once, in the creation response, and never again.
- `token_prefix` is derived from the *hash*, so putting it in logs leaks nothing
  useful while still letting you correlate events for one link.
- SHA-256 (not Argon2) is correct here: the token has 256 bits of entropy, so
  there is nothing to brute force and a slow hash would only add latency to
  every anonymous request. The *password* — low entropy, human chosen — does use
  Argon2id.

Guessing resistance, measured: 1 000 random guesses in
`test_brute_force_token_guessing_never_succeeds` → 0 hits; 25 generated tokens
share no 8-character prefix and span >30 distinct characters.

### 4.4 The atomic download claim

The requirement was that two simultaneous requests must not both succeed when
`max_downloads = 1`. The counter is never read into Python and written back.
One statement decides, and the database arbitrates:

```python
updated = ShareLink.objects.filter(
    pk=link.pk,
    revoked_at__isnull=True,
).filter(
    Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
).filter(
    Q(max_downloads__isnull=True) | Q(download_count__lt=F("max_downloads"))
).update(
    download_count=F("download_count") + 1,
    last_downloaded_at=timezone.now(),
)
if updated != 1:
    raise DownloadLimitReached()
```

Measured results:

| Scenario | Workers | Outcome |
|---|---|---|
| `max_downloads=1`, direct service calls | 16 threads | exactly **1** winner |
| `max_downloads=1`, real HTTP | 8 threads | **1** × 200, **7** × 410 |
| `max_downloads=1`, real HTTP, Gunicorn | 10 threads | **1** × 200, **9** × 410 |
| `max_downloads=3` | 20 threads | exactly **3** winners |
| revoked link under load | 12 threads | **0** claims |

`tests/test_race_detection_sanity.py` runs the identical harness against a
deliberately unsafe read-modify-write and asserts it **does** overcount — so the
"exactly one" results above are evidence, not an artefact of a harness that
could never observe a race.

If the response later fails to build, the reserved slot is released
(`test_a_failed_response_releases_the_slot`).

### 4.5 Password protection flow

```
GET  /api/share/<token>/                → {"password_required": true}   (nothing else)
POST /api/share/<token>/verify-password → {"grant": "<signed>", "expires_in": 600}
POST /api/share/<token>/download/       → 200 (with grant, or with password inline)
```

The grant is a `django.core.signing` token with
`salt="secureshare.share-link-grant.v1"`, scoped to one link id, valid for
`SHARE_LINK_GRANT_TTL_SECONDS`. It avoids resending the password on every call
and is useless for any other link. Failures increment a per-link Redis counter;
at `SHARE_LINK_PASSWORD_MAX_ATTEMPTS` the link returns 429 `SHARE_LINK_LOCKED`
for `SHARE_LINK_PASSWORD_LOCKOUT_SECONDS` — **and refuses the correct password
too**, so a lockout cannot be walked past. Lockout is per link; success resets
the counter.

### 4.6 Request lifecycle for `POST /api/share/<token>/download/`

1. URL converter rejects anything outside `^[A-Za-z0-9_-]{32,128}$`.
2. Throttle `share.download` (per IP) and `share.password` (per link+IP).
3. SHA-256 the presented token, look up by hash — miss → 404.
4. Re-derive state from the row: revoked → 410, expired → 410, limit → 410,
   permission VIEW → 403.
5. Password: no credential → 401; bad → 403 + counter; locked → 429.
6. **Atomic claim** (§4.4).
7. Unwrap the DEK (RSA-OAEP), stream-decrypt with AES-256-GCM, verify tags.
8. Emit `SHARE_LINK_DOWNLOAD`; emit `DOWNLOAD_LIMIT_REACHED` if that was the
   last slot.

Steps 3–6 happen on **every** request. There is no caching of the decision.

### 4.7 Audit events

`SHARE_LINK_CREATED`, `SHARE_LINK_ACCESSED`, `SHARE_LINK_DOWNLOAD`,
`SHARE_LINK_EXPIRED`, `SHARE_LINK_REVOKED`, `SHARE_LINK_PASSWORD_FAILURE`,
`DOWNLOAD_LIMIT_REACHED` — all seven required events, all emitted, all asserted
by tests and observed in the live demo. Each carries `token_prefix`, never the
raw token. Verified empirically: scanning every audit row after a full demo run
finds no raw token and no share password.

---

## 5. Threat model

Assets: file plaintext, DEKs, the RSA private key, user credentials, share
tokens, share passwords, the audit log.

| # | Threat | Attacker | Control | Verified by |
|---|---|---|---|---|
| T1 | Guess a share token | Internet | 256-bit CSPRNG; hash lookup; uniform 404; throttling | `test_brute_force_token_guessing_never_succeeds` (1 000 guesses) |
| T2 | Replay a leaked token after revocation | Anyone with the URL | `revoked_at` checked per request, no cache | `test_revoked_link_is_immediately_dead`; live demo §8 |
| T3 | Use a link past its expiry | Anyone with the URL | `expires_at` compared server-side; JS timers are cosmetic | `test_expired_link_cannot_be_downloaded` |
| T4 | Exceed the download limit by racing | Anyone with the URL | single conditional `UPDATE`; DB row lock | 5 concurrency tests + sanity control |
| T5 | Brute force a link password | Internet | Argon2id, constant-time compare, per-link lockout that also blocks the correct password | `test_lockout_blocks_even_the_correct_password` |
| T6 | Steal tokens from a DB dump | DB read access | only SHA-256 hashes stored | §3 of `PHASE6_DEMO.md` |
| T7 | Tamper with a DB row to bypass limits | DB write access | every field re-validated per request; corrupt `password_hash` fails closed; DB constraints reject impossible values | 5 "tampered value" tests |
| T8 | Escalate a VIEW link to DOWNLOAD | Link holder | permission re-read per request; client-supplied fields ignored in PATCH | `test_view_permission_cannot_download` |
| T9 | Use a share token as an API credential | Link holder | separate auth path; token is not a JWT | `test_share_token_is_not_a_bearer_token` |
| T10 | Reach another user's file via a link | Link holder | link ↔ exactly one file | `test_link_grants_no_access_to_other_files` |
| T11 | Modify or revoke someone else's link | Authenticated user | owner-only mutation; 403/404 | `test_non_owner_cannot_patch_a_link` |
| T12 | Substitute ciphertext in the object store | Filesystem write access | AES-GCM tag per chunk + AAD binding; 422, no plaintext | `test_tampered_ciphertext_is_detected`; demo §5 |
| T13 | Learn file contents from the store | Filesystem read access | AES-256-GCM, per-file DEK, DEK only wrapped | §3 of `PHASE4_DEMO.md` |
| T14 | Harvest secrets from logs | Log access | redaction filter; tokens/passwords/JWTs never written | `test_logs_never_contain_secrets` |
| T15 | Enumerate files or users | Internet | 404 for unauthorized-existing; identical bodies on failure | `test_unauthorized_file_returns_404` |
| T16 | Upload malware or a disguised binary | Authenticated user | magic-byte sniffing, extension allow-list, optional ClamAV fail-closed | `tests/test_upload_validation.py` (25) |
| T17 | Zip bomb | Authenticated user | entry-count and expansion-ratio limits | `test_archive_with_too_many_entries_is_rejected` |
| T18 | Hijack a session after a password change | Stolen JWT | `tv` claim invalidates all tokens | `tests/test_auth.py` |

### Out of scope (accepted)

- A fully compromised application server can decrypt files — it holds the RSA
  private key. End-to-end encryption would be required to change that.
- A database superuser can rewrite audit history (see §7.6).
- Traffic analysis, denial of service at the network layer, and malicious
  recipients re-sharing content they were legitimately given.

---

## 6. Verification evidence

| Check | Command | Result |
|---|---|---|
| Unit + integration | `pytest -q` | **366 passed, 0 failed** |
| Coverage | `pytest --cov` | **89.4 %** (3 688 stmts, 392 missed) |
| Phase 6 attack suite | `pytest tests/test_share_link_security.py -q` | 77 passed |
| Race control | `pytest tests/test_race_detection_sanity.py -q` | 1 passed (harness proven) |
| Lint + security rules | `ruff check .` | **All checks passed** |
| SAST | `bandit -r .` | 0 HIGH, 1 MED, 13 LOW — all triaged false positives |
| Dependency CVEs | `pip-audit -r requirements*.txt` | **0** |
| Deployment hardening | `check --deploy` (prod) | 0 issues, 0 silenced |
| Live, dev server | `scripts/demo_phase6.py` | 53/53 |
| Live, **Gunicorn + prod settings** | `scripts/demo_phase6.py --base-url :8100` | 53/53 |
| OpenAPI | `manage.py spectacular` | generates clean, 0 warnings |

The Gunicorn run is the meaningful one: `DEBUG=False`, production middleware,
real security headers, structured JSON errors, no stack traces — and the entire
share-link workflow still behaves identically.

---

## 7. Limitations

1. **Docker path unverified here.** No Docker daemon in this environment. The
   compose/Dockerfile/nginx configs are written and statically checked, not
   executed. Verify on your machine before relying on them.
2. **Server-side encryption, not end-to-end.** The server can read every file.
3. **Mid-stream failure does not refund a claimed slot.** Fail-closed by design:
   refunding would let an attacker farm downloads by aborting connections.
4. **Lockout/throttle state is in Redis.** `FLUSHALL` clears it. Run Redis with
   AOF (the compose file does).
5. **Database columns are not encrypted.** Filenames, sizes and audit metadata
   are plaintext; use an encrypted volume.
6. **The audit log is append-only by policy, not cryptography.** No hash chain.
7. **ClamAV socket code is not exercised in CI** — no daemon available; the
   fail-open/fail-closed decision logic is covered (`security/scanning.py` 55 %).
8. **No frontend**, so no `npm audit` and no browser-side protections claimed.
9. **Single-region, single object store.** No replication or backup strategy is
   implemented.
10. **Share links cannot be listed by prefix for a recipient** — by design, but
    it means a user who loses a link URL cannot recover it; they must create a
    new one.

---

## 8. Product bugs found and fixed by this phase's testing

Writing the Phase 6 tests surfaced five real defects. All are fixed and each has
a regression test.

| # | Severity | Where | Defect | Fix |
|---|---|---|---|---|
| 1 | Low | `config/urls.py` | URL namespacing broke drf-spectacular, which reversed `"schema"` instead of `"api:schema"` — Swagger UI 500'd | reverse the namespaced name |
| 2 | **Security** | `files/views.py::get_file_for_access` | returned **403** for an existing file the caller did not own, confirming its existence — an enumeration oracle | return **404** `FILE_NOT_FOUND`, still audit `UNAUTHORIZED_FILE_ACCESS` |
| 3 | **Availability** | `core/logging.py::SensitiveDataFilter` | redaction ran on `record.msg` *before* `%`-formatting, deleting the `%s` placeholders; the later `msg % args` then raised `TypeError: not all arguments converted during string formatting` and destroyed the log record — so an error containing a secret produced *no* log line at all | render with `record.getMessage()` first, redact the rendered string, clear `record.args`. Also catches secrets passed as args, which the old order missed |
| 4 | **Security hardening** | `security/scanning.py::scan_upload` | only `MalwareScanError` was caught, so any *other* exception from the scanner (socket error, protocol desync) propagated past the fail-closed policy | catch-all that logs and re-raises as `MalwareScanError` when `CLAMAV_FAIL_CLOSED` |
| 5 | **Security (defence in depth)** | `security/storage.py` | shard directories were created with `mkdir(parents=True)`, which the umask reduced to **0755** — the ciphertext tree was world-traversable below the 0700 root | `_make_shard()` chmods each level to 0700 explicitly; regression test runs under `umask 022` and walks the tree |

Bug 5 was found while capturing the Phase 4 demo transcript — the on-disk
listing contradicted the documentation, which is exactly what writing honest
documentation is for.

---

## 9. Future improvements

**Security**
1. End-to-end encryption: derive the DEK in the browser from a key held in the
   URL fragment, so the server never sees plaintext or the key.
2. KMS/HSM backend behind the existing key-provider abstraction (the rotation
   hook is already there).
3. Hash-chain the audit log and ship it to a write-once sink.
4. Per-recipient watermarking and download receipts.
5. Short-lived signed download URLs so the token is not in the request path for
   the actual byte transfer.
6. 2FA (TOTP) and WebAuthn for account login.

**Platform**
7. The React + Vite + TypeScript frontend (next phase), plus the admin dashboard.
8. Chunked/resumable uploads for large files.
9. S3-compatible storage backend — the abstraction exists, it needs integration
   testing.
10. Object-store replication and a documented backup/restore runbook.

**Operations**
11. CI pipeline running `security/run_security_checks.sh` on every push, with
    the Bandit baseline gating new findings.
12. OpenTelemetry traces and Prometheus metrics (share-link hit rate, decryption
    latency, lockout events).
13. Alerting on `UNAUTHORIZED_*`, `FILE_INTEGRITY_FAILURE` and
    `SHARE_LINK_PASSWORD_FAILURE` spikes.
14. Load test the download path to size the Gunicorn worker/thread mix against
    real file sizes.

---

## 10. Phase 6 acceptance checklist

| Requirement | Status |
|---|---|
| `ShareLink` model with all 11 specified fields | ✅ |
| CSPRNG token, high entropy | ✅ `secrets.token_urlsafe(32)`, 256 bits |
| Never sequential / bare UUID / timestamp / username / predictable hash | ✅ |
| Only a secure hash stored | ✅ SHA-256, unique index |
| Raw token returned only at creation | ✅ verified live |
| `POST /api/files/<id>/share-link/` returns URL, expiry, permission, limit | ✅ |
| No internal storage paths in responses | ✅ asserted in tests and the demo |
| `GET /api/share/<token>/` | ✅ |
| `POST /api/share/<token>/download/` | ✅ |
| Expiry presets 1h/6h/24h/3d/7d/custom, backend-enforced | ✅ |
| Download limits unlimited/1/5/10/custom | ✅ |
| Atomic enforcement — two simultaneous requests cannot both succeed at limit 1 | ✅ 5 concurrency tests + a negative control |
| `DELETE /api/share-links/<id>/`, effective immediately | ✅ |
| Optional password, hash only, never plaintext | ✅ Argon2id |
| Rate-limited password attempts | ✅ per-link lockout, 429 |
| 7 audit event types | ✅ all emitted and observed |
| Raw token never logged | ✅ verified against every audit row |
| 12 required security tests actually executed | ✅ see §3 of `SECURITY_TESTING.md` |
| Workflow works end to end | ✅ 53/53 on dev **and** Gunicorn/prod |
| No mockups, TODOs, or fake implementations in core functionality | ✅ |
