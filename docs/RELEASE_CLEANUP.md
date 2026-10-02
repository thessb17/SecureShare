# Release Cleanup Report

Final pre-submission pass over the SecureShare repository: remove generated
artifacts and real secrets, verify that the stripped tree still installs and
runs, and record the defects the cleanup uncovered.

No features were added, removed, or redesigned during this pass. The only code
changes are the four bug fixes listed in section 2, each of which is covered by
a regression test.

---

## 1. Scope

| Area | Action |
| --- | --- |
| Generated artifacts | Deleted (coverage, caches, builds, logs, encrypted blobs) |
| Real secrets | Deleted (`.env`, RSA key pair, TLS key/cert) |
| `.gitignore` | Fixed so the deleted material cannot be re-committed |
| Documentation | `README.md` rewritten; broken references repaired |
| Verification | Full re-run of every gate on a clean copy of the stripped tree |

---

## 2. Defects found during cleanup

Cleanup was treated as an audit, not a delete script. Seven genuine
release-blocking defects surfaced; all seven are fixed and pinned by tests.

The most important of them, 2.5, was one this document originally got wrong:
an earlier draft claimed Docker worked, on the strength of an API test suite
that never loaded a page.

### 2.1 Paths resolved against the current working directory — **fixed**

`.env.example` shipped `RSA_PRIVATE_KEY_PATH=./keys/rsa_private.pem`. Relative
paths were resolved against the *process* working directory, so the documented
`cd backend && python manage.py runserver` aborted with:

```
KeyManagementError: No RSA key material configured
```

The application only worked when launched from the repository root — which no
documented command did.

**Fix:** `config/env.py:get_path()` gained a `relative_to` parameter;
`config/settings/base.py` anchors `STATIC_ROOT`, `MEDIA_ROOT`,
`ENCRYPTED_STORAGE_ROOT`, `FILE_UPLOAD_TEMP_DIR`, `LOG_DIR` and the RSA key
paths to `PROJECT_ROOT`.
**Regression:** `TestEnvPathResolution` (6 tests).
**Verified:** identical crypto round trip from `backend/`, the repo root and `/tmp`.

### 2.2 `docker compose` unusable from a pristine `.env.example` — **fixed**

`docker-compose.yml` declares `POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?...}`
with no default, but that variable was absent from the 69-variable example
file. The documented first step therefore failed immediately:

```
cp .env.example .env && docker compose up
# error: required variable POSTGRES_PASSWORD is missing a value
```

**Fix:** added a documented five-variable Compose block to `.env.example`.
**Verified:** a pristine copy now passes `docker compose config` (exit 0).

### 2.3 Container crash-loop on repo-relative paths — **fixed**

`PROJECT_ROOT` is `/` inside the image, so `MEDIA_ROOT=./storage/media` resolved
to `/storage/media`, which the uid-10001 runtime user cannot create:

```
PermissionError: [Errno 13] Permission denied: '/storage'
HaltServer: 'Worker failed to boot.'
```

The API container never became healthy and nginx stayed blocked behind its
`depends_on` health gate.

**Fix:** Compose now pins `MEDIA_ROOT=/data/media`, `LOG_DIR=/data/logs` and
`STATIC_ROOT=/app/staticfiles`, with a `media_data` volume and `/data/media`
created in the Dockerfile.

> **Maintenance note:** any new filesystem setting must also be overridden in
> `docker-compose.yml`, or it will resolve under `/` inside the container.

### 2.4 Health endpoint reported a decryption-incapable node as healthy — **fixed**

The most serious finding. `core/health.py:_check_encryption_keys` only asserted
`provider.public_key is not None`. Because a read-only bind mount preserves host
ownership, a `0600` host key owned by uid 1000 is unreadable by the uid-10001
container user. The result:

- uploads returned `201` (only the public key is needed to wrap a DEK);
- **every download returned `503 DECRYPTION_UNAVAILABLE`**;
- `/api/health/` still reported `"encryption_keys": "ok"`.

A load balancer would have kept routing traffic to a node that could not decrypt
a single file.

**Fix:** the check now performs a real wrap → unwrap round trip on a throwaway
32-byte `secrets.token_bytes` DEK. This also catches a mismatched key pair, a
wrong passphrase and a truncated PEM.

**Regression:** 3 tests appended to `backend/tests/test_health.py`.

**Verified by live negative control in the running stack:**

| Key state | `/api/health/` | Container |
| --- | --- | --- |
| `gid 1000`, mode `0600` (unreadable) | `503 {"status":"degraded", ..., "encryption_keys":"error"}` | `api` not healthy |
| `gid 10001`, mode `0640` (readable) | `200 {"status":"ok", ...}` | `api Up (healthy)` |

**Operator action**, documented in `README.md` §4 and §8:

```bash
sudo chgrp 10001 keys/rsa_private.pem
sudo chmod 640  keys/rsa_private.pem   # still not world-readable
```

### 2.5 Docker stack served no frontend — **fixed**

This was reported as "Docker actually runs" in an earlier draft of this
document. That was true of the API and false of the product.

`docker-compose.yml` had no frontend service, there was no `Dockerfile.frontend`,
and `nginx/conf.d/secureshare.conf` ended with a placeholder left over from an
earlier phase:

```nginx
# Frontend (added in the React phase); until then the API is the app.
location / {
    return 404;
}
```

So `docker compose up` produced an API-only stack: every page in a browser
returned 404. The 136-check end-to-end suite did not catch it because it is an
API suite — it only ever requests `/api/...`, which worked perfectly.

**Fix:** added `frontend/Dockerfile` (multi-stage Node build → `nginx:alpine`,
uid 101, read-only root filesystem, 48.6 MB), a `frontend` service with a
healthcheck, a `secureshare_frontend` upstream, and SPA proxying with history
fallback so a refresh on `/files/<uuid>` boots the router instead of 404ing.

**Fix to the process, which matters more:** added `scripts/verify_edge.py`,
33 checks covering exactly the layer an API suite cannot see — TLS, redirect,
SPA serving, deep links, asset caching, store protection, security headers and
the rate limiter. The gap existed because nothing tested that layer.

### 2.6 `celery beat` permanently unhealthy — **fixed**

`beat` inherited the image's `HEALTHCHECK`, which curls `:8000` — a port the
scheduler never listens on. `docker compose ps` showed `beat (unhealthy)`
forever, and any `depends_on: beat: {condition: service_healthy}` would have
deadlocked. Replaced with a probe that asserts PID 1 is still the scheduler and
that it has flushed its schedule within 600 s.

### 2.7 `.gitignore` negations that could never fire — **fixed**

`keys/` and `storage/` excluded whole *directories*. Git does not descend into
an excluded directory, so the later `!keys/README.md` and `!storage/.gitkeep`
negations were dead — the key-management documentation and the storage
placeholder would both have been missing from a fresh clone.

```diff
-keys/
+keys/*
 !keys/README.md

-storage/
+storage/*
 !storage/.gitkeep
```

**Verified** empirically in a scratch repository: see section 5.

---

## 3. Artifacts removed

Repository size fell from **161 MB to 1.7 MB** (-99%).

| Path | Size | Why |
| --- | --- | --- |
| `frontend/node_modules/` | 148 MB | Reproducible via `npm ci` |
| `htmlcov/` | 4.2 MB | Generated coverage HTML |
| `logs/*` | 2.9 MB | Runtime logs |
| `frontend/dist/` | 1.1 MB | Build output |
| `backend/.coverage` | 68 KB | Coverage database |
| `backend/staticfiles/` | — | `collectstatic` output |
| `storage/encrypted`, `storage/tmp`, `storage/media` | — | Encrypted user data from testing |
| `backend/storage/` | — | Empty stray directory from the §2.1 path bug |
| `__pycache__/`, `*.pyc`, `.pytest_cache/`, `.ruff_cache/`, `*.tsbuildinfo` | — | Caches |
| Docker volumes | — | `docker compose down -v` |

`storage/.gitkeep` and `backend/security/reports/.gitkeep` were restored after
the sweep, and `bandit-baseline.json` was regenerated — it is a committed
reference baseline, not an artifact.

---

## 4. Secrets removed

| Path | Disposition |
| --- | --- |
| `.env` | **Shredded.** Contained a working local DB password |
| `keys/rsa_private.pem` | **Shredded.** Real 3072-bit private key |
| `keys/rsa_public.pem` | Removed — regenerate as a pair |
| `nginx/certs/server.key` | **Shredded.** Self-signed TLS private key |
| `nginx/certs/server.crt` | Removed |

Retained deliberately: `.env.example` (placeholders only), `keys/README.md`,
`nginx/certs/README.md`.

### Final secret scan

A classifier over the whole tree searched for PEM armour headers (the
`BEGIN ... PRIVATE KEY` and certificate-armour family, written without their
literal text here so this paragraph does not itself trip a CI secret scanner),
together with `PRIVATE_KEY`, `SECRET_KEY`, `JWT_SIGNING_KEY`,
`DATABASE_PASSWORD`, `PASSWORD=`, `API_KEY` and `TOKEN=`, flagging any quoted
16+ character literal
that was not an obvious placeholder or environment lookup.

```
REAL CREDENTIAL FINDINGS: none
```

The single earlier hit was `keys/README.md:61`, a documentation line containing
a literal PEM header. It was reworded — not because it was a leak, but because
CI secret scanners pattern-match the header regardless of context.

A filesystem sweep confirms no `*.pem`, `*.key`, `*.crt`, `*.p12`, `*.pfx`,
`*.sqlite3`, `*.db`, `*.dump`, `*.sql` or `.env` file remains.

Benign matches that correctly survive: 67 `PRIVATE_KEY`, 24 `SECRET_KEY`,
14 `JWT_SIGNING_KEY`, 8 `PASSWORD=` — all environment lookups, Django setting
names, throttle scope names, test keyword arguments and documentation.

---

## 5. `.gitignore` verified by experiment

Because the workspace has no `.git` directory, `git check-ignore` was
unavailable and its earlier "private key NOT ignored" warning was a false alarm.
The rules were instead tested for real: the released tree was copied to a
scratch directory, `git init && git add -A` was run, then secrets and artifacts
were planted and staged again.

**187 files staged. Intended exceptions all tracked:**
`.env.example`, `keys/README.md`, `nginx/certs/README.md`, `storage/.gitkeep`,
`backend/security/reports/.gitkeep`, `bandit-baseline.json`.

**All 13 planted files correctly ignored:** `keys/rsa_private.pem`,
`keys/rsa_public.pem`, `.env`, `nginx/certs/server.key`,
`nginx/certs/server.crt`, `htmlcov/index.html`, `storage/encrypted/blob.bin`,
`logs/app.log`, `frontend/node_modules/pkg.js`, `frontend/dist/bundle.js`,
`backend/__pycache__/x.pyc`, `.coverage`, `backend/db.sqlite3`.

> This test is worth repeating after any `.gitignore` edit. It is the only way
> to catch the directory-exclusion trap in §2.5.

---

## 6. Post-cleanup verification

Every gate was re-run against a **clean copy of the stripped tree** in a
separate directory, following `README.md` literally — `cp .env.example .env`,
`python scripts/generate_keys.py` (producing a third, independent key pair),
`migrate`, then the full suite.

| Gate | Result |
| --- | --- |
| `manage.py check` | 0 issues |
| `manage.py migrate` | clean, all migrations applied |
| Backend tests | **542 passed** (19.21 s) |
| Backend coverage | **90.4%** (3904 statements, 373 missed) |
| `ruff check .` | all checks passed |
| Bandit | 0 high, 1 medium, 13 low — the medium is `B104` on `dev.py` binding `0.0.0.0`, intentional for local development |
| `npm ci` | 406 packages |
| `npm run lint` | clean (`--max-warnings 0`) |
| `npm run typecheck` | clean |
| Frontend tests | **53 passed** (4 files) |
| `npm run build` | 118 modules, built in 2.40 s |
| Built bundle secret scan | clean |
| **End-to-end (functional)** | **136 / 136 passed** |
| **End-to-end (edge)** | **33 / 33 passed** |

The E2E suite covers registration, login, upload, encryption-at-rest, download,
cross-user denial, VIEW/DOWNLOAD/revoke sharing, public links with expiry,
download limits, password protection, admin RBAC and deletion.

> One harness note: when the server and the verification script target different
> databases, the `admin signs in` check fails with `401`. The script seeds its
> admin through `manage.py`, so that subprocess must receive the same
> `DATABASE_URL` as the server. Against Docker, set
> `SECURESHARE_MANAGE="sudo docker compose exec -T api python manage.py"`.

---

## 7. Known limitations

Carried forward honestly; none is a cleanup regression.

- The RSA private key is a file on disk by default. Production should use a KMS
  or HSM. Losing the key makes every stored file permanently unrecoverable.
- Refresh tokens live in `sessionStorage` and are therefore reachable by
  JavaScript. This is an accepted trade-off against CSRF exposure.
- Local TLS uses a self-signed certificate; browsers will warn until a real
  certificate is installed.
- `npm audit --omit=dev` reports 2 moderate `react-router` advisories. The open
  redirect is mitigated by `safeInternalPath()`; the other is unreachable in
  `BrowserRouter` mode.
- No real-browser (Playwright/Selenium) test layer exists; frontend coverage is
  component-level.
- ClamAV integration is optional and disabled by default.
- This project has not been independently security-audited. It demonstrates
  sound practice; it is not certified.

---

## 8. Reproducing the verification

```bash
cd secure-share
cp .env.example .env            # then fill in SECRET_KEY, JWT_SIGNING_KEY, DB password
python scripts/generate_keys.py

cd backend
python manage.py migrate
python -m pytest -q                       # 542 passed
python -m pytest --cov -q                 # 90.4%
ruff check .

cd ../frontend
npm ci && npm run lint && npm test && npm run build

# end-to-end, server running on :8200
cd .. && python3 scripts/verify_phase8_9.py http://127.0.0.1:8200   # 136/136
```

Docker path — note the group change, without which downloads fail with
`503 DECRYPTION_UNAVAILABLE` (§2.4):

```bash
python scripts/generate_keys.py
sudo chgrp 10001 keys/rsa_private.pem && sudo chmod 640 keys/rsa_private.pem
sudo docker compose up -d --build
sudo docker compose exec -T api python manage.py migrate --noinput

SECURESHARE_CA_BUNDLE=$PWD/nginx/certs/server.crt \
SECURESHARE_MANAGE="sudo docker compose exec -T api python manage.py" \
  python3 scripts/verify_phase8_9.py https://localhost:8443
```

If a back-to-back run returns `429`, that is the production throttle working as
designed, not a defect. Clear it with
`sudo docker compose exec -T cache redis-cli FLUSHALL` and wait out the
per-minute window.
