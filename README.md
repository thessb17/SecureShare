# SecureShare

**End-to-end encrypted file sharing.** Django REST backend, React frontend,
PostgreSQL, Redis, Celery, nginx. Every uploaded file is encrypted with its own
AES-256-GCM key; that key is wrapped with RSA-OAEP-SHA256 and the plaintext is
never written to disk.

Built as a cybersecurity internship project. The cryptography uses the Python
`cryptography` library — nothing is hand-rolled.

> **No secrets ship with this repository.** There is no `.env` and no RSA key
> pair in the source tree. You generate your own in steps 3 and 4 below.

---

## 1. Requirements

| | Version | Notes |
|---|---|---|
| Python | 3.12+ | Backend |
| Node.js | 20+ | Frontend (npm 10+) |
| PostgreSQL | 16+ | Primary datastore (17 used in Docker) |
| Redis | 7+ | Cache, throttle counters, Celery broker |
| libmagic | — | Content-based MIME detection (`libmagic1` on Debian/Ubuntu) |
| OpenSSL | — | Only to mint a local TLS certificate |

For the Docker path you need only **Docker Engine 24+** with the Compose v2
plugin. Nothing has to be installed globally beyond that.

```bash
# Debian / Ubuntu host prerequisites for the local (non-Docker) path
sudo apt-get install -y postgresql redis-server libmagic1
```

---

## 2. Installation

```bash
git clone <your-repository-url> secure-share
cd secure-share
```

**Backend**

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt     # tests, linters, security scanners
cd ..
```

**Frontend**

```bash
cd frontend
npm ci                                   # reproducible install from the lockfile
cd ..
```

---

## 3. Environment configuration

```bash
cp .env.example .env
```

Then edit `.env`. The values you **must** change:

| Variable | What to set |
|---|---|
| `SECRET_KEY` | `python -c "import secrets;print(secrets.token_urlsafe(50))"` |
| `JWT_SIGNING_KEY` | a second, *different* value from the same command |
| `DATABASE_URL` | replace `change-me` with your PostgreSQL password |
| `POSTGRES_PASSWORD` | **Docker only** — must match the password in `DATABASE_URL` |
| `ALLOWED_HOSTS` | your hostname(s) in production |
| `CORS_ALLOWED_ORIGINS` / `CSRF_TRUSTED_ORIGINS` | your frontend origin — never `*` |

Create the database role and database:

```bash
sudo -u postgres psql -c "CREATE ROLE secureshare LOGIN PASSWORD 'your-password' CREATEDB;"
sudo -u postgres createdb -O secureshare secureshare
```

`.env` is listed in `.gitignore`. Never commit it.

---

## 4. RSA key generation

The repository deliberately contains no key material. Generate your own:

```bash
python scripts/generate_keys.py
```

This writes `keys/rsa_private.pem` (mode `0600`) and `keys/rsa_public.pem`,
prints a short public-key fingerprint, and never prints key material. Options:

```bash
python scripts/generate_keys.py --key-size 4096
RSA_PRIVATE_KEY_PASSPHRASE='…' python scripts/generate_keys.py \
  --passphrase-env RSA_PRIVATE_KEY_PASSPHRASE
```

> **Docker users:** the container runs as uid/gid `10001`, so a `0600` key
> owned by your host user is unreadable inside the container. Grant the
> container's group read access — it stays non-world-readable:
>
> ```bash
> sudo chgrp 10001 keys/rsa_private.pem && sudo chmod 640 keys/rsa_private.pem
> ```
>
> If you skip this, `GET /api/health/` reports
> `"encryption_keys": "error"` and the `api` container stays unhealthy —
> uploads would otherwise succeed while every download failed.

**Losing `rsa_private.pem` makes every stored file permanently unrecoverable.**
Back it up separately from the database. See `keys/README.md` for rotation and
for using a KMS/HSM instead of a file.

---

## 5. Database migration

```bash
cd backend
python manage.py migrate
python manage.py check               # 0 issues expected
cd ..
```

To create an administrator:

```bash
cd backend && python manage.py shell -c "
from django.contrib.auth import get_user_model
U = get_user_model()
u = U.objects.create_user(email='admin@example.com', password='<strong-password>', full_name='Admin')
u.role = 'ADMIN'; u.save(update_fields=['role'])
"
```

---

## 6. Backend startup

Development:

```bash
cd backend
set -a && source ../.env && set +a
python manage.py runserver 0.0.0.0:8000
```

Production (Gunicorn, `DEBUG=False`):

```bash
cd backend
set -a && source ../.env && set +a
export DJANGO_SETTINGS_MODULE=config.settings.prod
gunicorn config.wsgi:application --bind 0.0.0.0:8000 \
  --workers 3 --threads 4 --worker-class gthread --timeout 120
```

Background workers (optional — used for retention sweeps and scans):

```bash
celery -A config worker -l info
celery -A config beat   -l info
```

Verify:

```bash
curl -s http://127.0.0.1:8000/api/health/
# {"status":"ok","version":"0.6.0","database":"ok","redis":"ok","cache":"ok","storage":"ok","encryption_keys":"ok"}
```

---

## 7. Frontend startup

```bash
cd frontend
npm run dev -- --host 0.0.0.0        # http://localhost:5173
```

The dev server proxies `/api` to the backend, so the browser only ever talks to
one origin. Point it elsewhere with `VITE_API_TARGET`:

```bash
VITE_API_TARGET=http://127.0.0.1:8000 npm run dev -- --host 0.0.0.0
```

Production bundle:

```bash
npm run build                         # -> frontend/dist, served by nginx
```

---

## 8. Docker startup

```bash
cp .env.example .env                  # then edit as in §3 (incl. POSTGRES_PASSWORD)
python scripts/generate_keys.py
sudo chgrp 10001 keys/rsa_private.pem && sudo chmod 640 keys/rsa_private.pem

# TLS certificate for nginx (self-signed, local use only)
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout nginx/certs/server.key -out nginx/certs/server.crt \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 nginx/certs/server.key

docker compose up -d --build
docker compose exec api python manage.py migrate
```

Seven services start: `db`, `cache`, `api`, `worker`, `beat`, `frontend`,
`nginx`. Only nginx publishes ports — PostgreSQL, Redis, the API, the Celery
processes and the frontend are reachable only on the internal network.

Then open **https://localhost:8443** in a browser. nginx serves the React
bundle from the `frontend` container and proxies `/api` to Django, so the whole
product runs from Compose — not just the API.

```bash
docker compose ps                                  # all should be healthy
curl -k https://127.0.0.1:8443/api/health/         # through nginx
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/api/health/   # 301 -> https
docker compose down                                # add -v to drop the volumes too
```

Verify the deployment rather than assuming it:

```bash
# The edge, against the UNMODIFIED production config - 33 checks
SECURESHARE_CA_BUNDLE=./nginx/certs/server.crt \
  python3 scripts/verify_edge.py https://localhost:8443

# Functional end-to-end - 136 checks, using the relaxed-limit test overlay
sudo docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
SECURESHARE_MANAGE="sudo docker compose exec -T api python manage.py" \
  python3 scripts/verify_phase8_9.py http://127.0.0.1:8100
```

Two runs, because they test different things. The production rate limits
(5 auth requests per minute at the edge) are tight by design, and a suite that
fires 136 requests in four seconds trips them — that is the limiter working,
not a defect. So functional behaviour is checked with limits relaxed, and
`verify_edge.py` separately proves the real limiter rejects a burst. Never use
the test overlay for a real deployment: it publishes the API port directly.

| Variable | Default | Purpose |
|---|---|---|
| `HTTP_PORT` | `8080` | Host port for nginx :80 (redirects to HTTPS) |
| `HTTPS_PORT` | `8443` | Host port for nginx :443 |
| `DJANGO_SETTINGS_MODULE` | `config.settings.prod` | Settings module in-container |

---

## 9. Test commands

**Backend**

```bash
cd backend
python manage.py check
pytest -q                                    # full suite
pytest --cov --cov-report=term               # with coverage
pytest -m security                           # security tests only
```

`pytest.ini` passes `--ds=config.settings.test`, so the suite always runs
against the test settings even if you have sourced `.env` (which exports
`DJANGO_SETTINGS_MODULE=config.settings.dev`).

**Frontend**

```bash
cd frontend
npm run lint
npm run typecheck
npm test
npm run build
```

**Security tooling**

```bash
cd backend
ruff check .
bandit -r . -x ./tests
pip-audit -r requirements.txt -r requirements-dev.txt
./security/run_security_checks.sh            # all of the above, exits non-zero on regression
cd ../frontend && npm audit
```

**End-to-end against a running deployment**

```bash
python3 scripts/verify_phase8_9.py http://127.0.0.1:8000       # local backend
python3 scripts/verify_phase8_9.py http://127.0.0.1:5173       # through the Vite proxy

# against the Docker stack (trusts the local self-signed cert as its own CA;
# certificate verification stays enabled)
SECURESHARE_CA_BUNDLE=nginx/certs/server.crt \
SECURESHARE_MANAGE="docker compose exec -T api python manage.py" \
  python3 scripts/verify_phase8_9.py https://localhost:8443
```

136 checks covering registration, login, upload, encryption, download
integrity, IDOR, sharing, public links, expiry, download limits, revocation,
audit logging, admin RBAC and response headers. Running it repeatedly against
production settings will trip the rate limiter (HTTP 429) — that is the
throttle working, not a failure. Clear the counters between runs:

```bash
redis-cli --scan --pattern '*throttle*' | xargs -r redis-cli DEL
```

---

## 10. Demo workflow

1. **Register two accounts** — User A and User B — at `/register`.
2. **A uploads a PDF** at `/app/upload`. The result shows
   `AES-256-GCM` and `RSA-OAEP-SHA256`. The plaintext is never written to disk;
   `storage/encrypted/` holds only ciphertext.
3. **A downloads it** from `/app/files` — the file opens normally, byte-for-byte
   identical to the original.
4. **B is denied.** Signed in as B, requesting A's file returns `404` — not
   `403`, so the API does not confirm the file exists.
5. **A shares with B as VIEW.** B now sees the metadata but the download
   endpoint still refuses.
6. **A upgrades the share to DOWNLOAD.** B can now download.
7. **A revokes the share.** B immediately loses both download and metadata access.
8. **A creates a public link** with a 1-hour expiry, a 2-download limit and a
   password.
9. **In a separate session** open `/s/<token>`: the filename is hidden until the
   password is supplied, then downloads 1 and 2 succeed and **the third is
   rejected** with `SHARE_LINK_DOWNLOAD_LIMIT_REACHED`.
10. **A revokes the link** — it returns `410` thereafter.
11. **Audit trail** at `/app/audit` shows every action. B cannot see A's entries,
    and no write verb is accepted on the endpoint.
12. **Admin console** at `/app/admin` (ADMIN role only). A normal user gets
    `403` from every `/api/admin/*` endpoint. Disabling an account invalidates
    its existing tokens immediately and emits an `ADMIN_ACTION` audit event.

`scripts/verify_phase8_9.py` performs exactly this workflow over HTTP.

---

## 11. Security architecture

```
Browser ──HTTPS──> nginx ──> Gunicorn / Django REST
                     │            │
                     │            ├─ Authentication   JWT (access 15 min, rotating refresh)
                     │            ├─ Authorization    permission classes, object-level
                     │            ├─ Validation       size, extension, magic-byte MIME
                     │            ├─ Encryption       AES-256-GCM + RSA-OAEP key wrapping
                     │            └─ Audit            append-only, immutable
                     │                 │
                     └─ static ──┐     ├──> PostgreSQL   metadata, wrapped DEKs
                                 │     ├──> Redis        cache, throttles, Celery
                                 └─────┴──> Encrypted store  ciphertext only, outside the web root
```

**Envelope encryption.** Each upload gets a fresh 256-bit DEK from
`secrets.token_bytes`. The file is encrypted in 1 MiB frames with AES-256-GCM,
each frame having a unique nonce (8-byte random prefix ‖ 32-bit counter) and
AAD binding the header, frame index, final-frame flag and file identity — so
frames cannot be reordered, truncated or swapped between files. The DEK is then
wrapped with RSA-OAEP-SHA256 and only the wrapped form is stored. The plaintext
DEK is never persisted, never logged, and is not even returned by the
encryption service's result object.

**Authentication.** Argon2id password hashing. JWTs carry a `token_version`
claim; changing a password, revoking sessions or disabling an account bumps it
and invalidates every issued token at once. Failed logins are counted and
lock the account temporarily. The API is Bearer-only — a Django session cookie
alone is rejected with 401.

**Authorization is enforced server-side, always.** React route guards are a
usability affordance, not a security boundary. Unauthorised access to another
user's file returns `404` rather than `403` to avoid an existence oracle.

**Share links.** Tokens are `secrets.token_urlsafe(32)`. Only a SHA-256 hash is
stored, plus a 12-hex prefix for log correlation; the raw token appears exactly
once, in the creation response. Optional passwords are Argon2id-hashed and
rate-limited. The download counter is decremented by a single conditional
`UPDATE` that re-checks revocation, expiry and the limit in the same statement,
so concurrent requests cannot exceed the cap — proven by a 10-thread race test.

**Audit logging** is append-only: `AuditLog.objects.update()` and `.delete()`
raise. No endpoint accepts a write verb, and not even an administrator can
delete a record through the API.

**Transport and headers.** HSTS, CSP, `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy` on every
response. CORS is an explicit allow-list; `CORS_ALLOW_ALL_ORIGINS` is never
enabled. The encrypted object store sits outside the web root and nginx returns
404 for any direct request to it.

### Honest limitations

This project has not been independently audited and makes no claim of absolute
security. Known residual risks:

- The refresh token is held in `sessionStorage`, so it is reachable by
  JavaScript; a successful XSS could steal it. The structural fix is an
  `HttpOnly` cookie.
- The RSA private key is a file on disk in the default deployment. Production
  should use a KMS or HSM.
- `npm audit` reports advisories in `react-router` 6.30.6 with no patched 6.x
  release. The exploitable one (open redirect via backslash) is neutralised in
  application code by `src/utils/navigation.ts`; the other does not apply to
  this app's routing mode. Details in `docs/PHASE8_REPORT.md` §6.
- ClamAV scanning is optional and disabled by default.

Full detail: `SECURITY.md`, `docs/PHASE6_REPORT.md`,
`backend/security/SECURITY_TESTING.md`.

---

## 12. Portfolio screenshots

The repository intentionally does **not** ship fabricated screenshots. For a portfolio or internship submission, capture screenshots from your own verified local/Docker run and place them under `docs/screenshots/`.

Recommended captures are listed in [`docs/SCREENSHOTS.md`](docs/SCREENSHOTS.md). The screenshot filenames can then be added to this README with standard Markdown image links.

## 13. Submission checklist

Before publishing the repository, follow [`docs/SUBMISSION_CHECKLIST.md`](docs/SUBMISSION_CHECKLIST.md). In particular, confirm that `.env`, private keys, uploaded files, databases, logs, `node_modules`, virtual environments and TLS private keys are absent from Git.

## Documentation map

| File | Contents |
|---|---|
| `SECURITY.md` | Threat model, controls, key management, disclosure policy |
| `keys/README.md` | Key generation, rotation, backup, KMS guidance |
| `nginx/certs/README.md` | TLS certificate setup |
| `docs/PHASE4_DEMO.md` | Encryption and download walkthrough |
| `docs/PHASE6_DEMO.md`, `docs/PHASE6_REPORT.md` | Sharing, 18-row threat model, bug log |
| `docs/PHASE8_REPORT.md` | Frontend build, 136-check live verification, dependency advisories |
| `docs/PHASE9_REPORT.md` | Admin console, RBAC evidence, defects found |
| `docs/ARCHITECTURE.md` | Request path, layers, crypto design, why each boundary exists |
| `docs/SECURITY_AUDIT.md` | Methodology, attack surfaces, measured results, 7 findings, OWASP, residual risk |
| `docs/THREAT_MODEL.md` | Assets, attackers, trust boundaries, threats, residual risks |
| `docs/DEPLOYMENT.md` | Production deployment, backup and recovery, troubleshooting, checklist |
| `docs/API.md` | 44 operations, generated from the live OpenAPI schema |
| `docs/DEMO.md` | Full workflow with the status codes it actually returns |
| `docs/INTERNSHIP_DEMO_SCRIPT.md` | 12-beat, 10-15 minute presentation script |
| `docs/VIVA_QA.md` | 40 questions and answers across the whole stack |
| `docs/RELEASE_CLEANUP.md` | Final release audit: what was removed and verified |
| `backend/security/SECURITY_TESTING.md` | Static analysis and scanner configuration |
| `/api/docs/` | OpenAPI / Swagger UI (live) |

## License

This project is released under the [MIT License](LICENSE). Third-party dependencies and assets remain under their respective licenses. See the documentation and dependency metadata for attribution details.
