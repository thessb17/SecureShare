# SecureShare — Deployment

Everything in this document was executed against the stack it describes. Where
a step has a trap, the trap is written down next to it.

---

## 1. What gets deployed

Seven containers:

| Service | Image | Published | Health check |
| --- | --- | --- | --- |
| `nginx` | `nginx:1.27-alpine` | **8080 → 80, 8443 → 443** | `GET /healthz` |
| `frontend` | `secureshare/frontend:0.6.0` (48.6 MB) | internal only | `GET /healthz` |
| `api` | `secureshare/api:0.6.0` (264 MB) | internal only | `GET /api/health/` |
| `worker` | `secureshare/api:0.6.0` | internal only | `celery inspect ping` |
| `beat` | `secureshare/api:0.6.0` | internal only | PID + schedule freshness |
| `db` | `postgres:17-alpine` | internal only | `pg_isready` |
| `cache` | `redis:7-alpine` | internal only | `redis-cli ping` |

**Only nginx is published.** PostgreSQL, Redis, the API and the workers are
reachable only on the internal Docker network. Verified:

```
nginx     0.0.0.0:8080->80/tcp, 0.0.0.0:8443->443/tcp
api       8000/tcp          (internal)
db        5432/tcp          (internal)
cache     6379/tcp          (internal)
frontend  8080/tcp          (internal)
```

Volumes: `pg_data`, `redis_data`, `storage_data`, `media_data`, `logs_data`.

Startup is dependency-ordered. `api` waits for `db` and `cache` to report
healthy; `nginx` waits for `api` **and** `frontend`.

---

## 2. Prerequisites

- Docker Engine 24+ and the Compose v2 plugin
- 2 GB RAM, 5 GB disk
- Ports 8080 and 8443 free (configurable via `HTTP_PORT` / `HTTPS_PORT`)

---

## 3. First deployment

### 3.1 Configuration

```bash
cp .env.example .env
```

Set these before anything else:

| Variable | How to generate |
| --- | --- |
| `SECRET_KEY` | `python -c "import secrets; print(secrets.token_urlsafe(50))"` |
| `JWT_SIGNING_KEY` | same, a **different** value |
| `POSTGRES_PASSWORD` | a long random string |
| `DATABASE_URL` | must embed the same password |
| `ALLOWED_HOSTS` | your real hostname(s) |
| `CORS_ALLOWED_ORIGINS` | your real frontend origin(s) |

> `POSTGRES_PASSWORD` is declared in `docker-compose.yml` as
> `${POSTGRES_PASSWORD:?...}` with no default. If it is missing, Compose fails
> immediately rather than starting with a blank password.

Never set `DEBUG=True`, and never set `CORS_ALLOW_ALL_ORIGINS=True`, in a
deployed environment.

### 3.2 Key material

```bash
python scripts/generate_keys.py
```

Produces `keys/rsa_private.pem` (3072-bit, mode 0600) and `keys/rsa_public.pem`.

**Then the step that is easy to miss:**

```bash
sudo chgrp 10001 keys/rsa_private.pem
sudo chmod 640  keys/rsa_private.pem
```

The container runs as uid/gid **10001**, and a read-only bind mount preserves
host ownership. Without this, the container can read the 0644 public key but
not the 0600 private key. The failure is deceptive: **uploads succeed with 201**
(wrapping needs only the public key) while **every download returns 503
`DECRYPTION_UNAVAILABLE`**. `0640` keeps the key non-world-readable.

The health endpoint now catches this — it performs a real wrap/unwrap round
trip, so a node in this state reports `degraded` instead of `ok`.

### 3.3 TLS certificates

Production, with a real certificate:

```bash
cp /path/to/fullchain.pem nginx/certs/server.crt
cp /path/to/privkey.pem   nginx/certs/server.key
chmod 640 nginx/certs/server.key
```

Local testing, self-signed:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout nginx/certs/server.key -out nginx/certs/server.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Browsers will warn on a self-signed certificate. That warning is correct — do
not teach users to click through it, and never disable TLS verification in a
client to work around it. Tooling should trust the certificate explicitly
instead:

```bash
SECURESHARE_CA_BUNDLE=./nginx/certs/server.crt python3 scripts/verify_edge.py https://localhost:8443
```

An ACME challenge location is already configured at
`/.well-known/acme-challenge/` for Let's Encrypt.

### 3.4 Build and start

```bash
sudo docker compose build
sudo docker compose up -d
sudo docker compose exec -T api python manage.py migrate --noinput
```

Expected:

```
NAME       STATUS
api        Up (healthy)
beat       Up (healthy)
cache      Up (healthy)
db         Up (healthy)
frontend   Up (healthy)
nginx      Up (healthy)
worker     Up (healthy)
```

### 3.5 Create the first administrator

```bash
sudo docker compose exec -T api python manage.py createsuperuser
```

---

## 4. Verifying the deployment

Do not assume it works because the containers started. Three checks:

```bash
# 1. Health, through TLS
curl --cacert nginx/certs/server.crt https://localhost:8443/api/health/
# {"status":"ok","version":"0.6.0","database":"ok","redis":"ok",
#  "cache":"ok","storage":"ok","encryption_keys":"ok"}

# 2. The edge: TLS, SPA, headers, store protection, rate limiting (33 checks)
SECURESHARE_CA_BUNDLE=./nginx/certs/server.crt \
  python3 scripts/verify_edge.py https://localhost:8443

# 3. Functional end-to-end (136 checks)
sudo docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
SECURESHARE_MANAGE="sudo docker compose exec -T api python manage.py" \
  python3 scripts/verify_phase8_9.py http://127.0.0.1:8100
```

`encryption_keys: ok` means a wrap/unwrap round trip succeeded, not merely that
a file exists.

### Why the functional suite uses an overlay

Production limits are tight on purpose: nginx allows 5 auth requests per minute
per IP; Django allows 5 registrations per hour. The functional suite issues
~136 requests, including ~15 authentications, in about four seconds. It trips
the limiter and reports 429 on checks whose behaviour is correct.

So the two concerns are tested separately:

- `docker-compose.test.yml` relaxes the limits and publishes the API on 8100,
  for **functional** behaviour.
- `scripts/verify_edge.py` runs against the **unmodified** production stack and
  asserts the limiter really does reject a burst. Measured: 19 of 25 rejected.

Both are required. The overlay must never be used for a real deployment — it
publishes the API directly, bypassing TLS.

---

## 5. Backup and recovery

### What must be backed up

| Item | Location | Lose it and… |
| --- | --- | --- |
| **RSA private key** | `keys/rsa_private.pem` | **Every stored file is permanently unrecoverable** |
| PostgreSQL | `pg_data` volume | Users, metadata, wrapped DEKs, audit log gone |
| Encrypted storage | `storage_data` volume | File contents gone |
| `.env` | repository root | Sessions invalid; `SECRET_KEY` loss breaks signed data |

> **The key and the database are useless apart.** The database holds wrapped
> DEKs; the key unwraps them. A backup missing either cannot restore a file.
> Back up all three, and store the key separately from the data it protects.

### Taking a backup

```bash
# Database
sudo docker compose exec -T db pg_dump -U secureshare secureshare | gzip > backup-db-$(date +%F).sql.gz

# Encrypted blobs
sudo docker run --rm -v secureshare_storage_data:/data -v "$PWD":/backup alpine \
  tar czf /backup/backup-storage-$(date +%F).tar.gz -C /data .

# Key material -- encrypt it, and keep it somewhere else
gpg --symmetric --cipher-algo AES256 keys/rsa_private.pem
```

### Restoring

```bash
sudo docker compose up -d db
gunzip -c backup-db-2026-10-02.sql.gz | sudo docker compose exec -T db psql -U secureshare secureshare
sudo docker run --rm -v secureshare_storage_data:/data -v "$PWD":/backup alpine \
  tar xzf /backup/backup-storage-2026-10-02.tar.gz -C /data
# restore keys/rsa_private.pem, then re-apply the uid 10001 group change
sudo chgrp 10001 keys/rsa_private.pem && sudo chmod 640 keys/rsa_private.pem
sudo docker compose up -d
```

Verify with `/api/health/` before declaring the restore good. If
`encryption_keys` is not `ok`, downloads will fail even though uploads work.

### Key rotation

Generate a new pair, then keep the old private key listed in
`RSA_RETIRED_PRIVATE_KEY_PATHS`. Each wrapped DEK records the key id that
sealed it, so existing files stay readable. **Deleting a retired key destroys
every file still wrapped with it.**

---

## 6. Operations

```bash
sudo docker compose logs -f api            # follow one service
sudo docker compose ps                     # health of all seven
sudo docker compose restart api            # restart one service
sudo docker compose down                   # stop, keep data
sudo docker compose down -v                # stop and DELETE ALL VOLUMES
```

`down -v` destroys the database and the encrypted store. There is no undo.

Updating:

```bash
git pull
sudo docker compose build
sudo docker compose up -d
sudo docker compose exec -T api python manage.py migrate --noinput
```

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Uploads 201 but **downloads 503** | Container cannot read the private key | `sudo chgrp 10001 keys/rsa_private.pem && sudo chmod 640` |
| `/api/health/` says `encryption_keys: error` | Same, or a mismatched pair | Check the key pair and its ownership |
| Compose exits: `POSTGRES_PASSWORD is missing` | Not set in `.env` | Set it; it has no default by design |
| `api` restarting, `PermissionError: '/storage'` | A path setting resolving under `/` | Override it in `docker-compose.yml`; `PROJECT_ROOT` is `/` in the image |
| Browser shows 404 on every page | Frontend service not running | `docker compose ps frontend`; check it is healthy |
| `beat` unhealthy | Schedule file stale or process gone | `docker compose logs beat` |
| 429 during a test run | The rate limiter working | Use the test overlay for functional runs |
| Certificate warning in a browser | Self-signed certificate | Install a real one; do not disable verification |

A useful rule when debugging: the edge returns 404 for anything it will not
serve, including the encrypted store and dotfiles. A 404 from `/storage/` is
correct behaviour, not a routing bug.

---

## 8. Production checklist

- [ ] `DEBUG=False`
- [ ] `SECRET_KEY` and `JWT_SIGNING_KEY` are distinct, random, 50+ characters
- [ ] `ALLOWED_HOSTS` lists only real hostnames
- [ ] `CORS_ALLOWED_ORIGINS` is an explicit list; `CORS_ALLOW_ALL_ORIGINS` unset
- [ ] A real TLS certificate is installed
- [ ] `python manage.py check --deploy` reports 0 issues
- [ ] The private key is `0640`, group 10001, and backed up **off-host**
- [ ] Database and storage backups are scheduled and a restore has been rehearsed
- [ ] Only nginx publishes ports
- [ ] The test overlay is **not** in use
- [ ] `/api/health/` reports `encryption_keys: ok`
- [ ] `scripts/verify_edge.py` passes against the production configuration
- [ ] Log retention and review are configured
- [ ] ClamAV enabled, or the decision not to scan uploads is recorded

---

## 9. Known limitations

- The RSA private key is a file on disk. Production should use a KMS or HSM.
- The server can decrypt files; this is not end-to-end encryption.
- Malware scanning is off by default.
- Rate limits are per-IP, so a distributed attack is not stopped.
- Security events are recorded but nothing alerts on them.
- No automated certificate renewal is wired up, though the ACME location exists.
- Single-node only; no clustering or failover guidance.
