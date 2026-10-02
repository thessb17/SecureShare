# SecureShare — Demo Walkthrough

The complete workflow, with the status codes it actually returns. Every line
below was executed against the running stack on 2 October 2026.

---

## Setup

```bash
cd secure-share
cp .env.example .env            # fill in SECRET_KEY, JWT_SIGNING_KEY, DB password
python scripts/generate_keys.py
sudo chgrp 10001 keys/rsa_private.pem && sudo chmod 640 keys/rsa_private.pem
sudo docker compose up -d
sudo docker compose exec -T api python manage.py migrate --noinput
```

Open `https://localhost:8443`. A self-signed certificate warning is expected.

---

## The workflow

| # | Action | Status | What it proves |
| --- | --- | --- | --- |
| 1 | Alice registers | `201` | Account creation, Argon2id hashing |
| 2 | Bob registers | `201` | |
| 3 | Alice uploads `demo.pdf` | `201` | Encrypted with `AES-256-GCM-STREAM-V1` |
| 4 | Alice downloads it back | `200` | **Byte-identical** to the original |
| 5 | Bob opens Alice's file | **`404`** | Not `403` — the status does not confirm it exists |
| 6 | Alice shares VIEW with Bob | `201` | |
| 7 | Bob views the metadata | `200` | The grant works |
| 8 | Bob tries to download | **`403`** | VIEW does not imply DOWNLOAD |
| 9 | Alice upgrades to DOWNLOAD | `200` | |
| 10 | Bob downloads | `200` | **Byte-identical** |
| 11 | Alice revokes the share | `204` | |
| 12 | Bob opens the file again | **`404`** | Access is gone immediately |
| 13 | Alice creates a public link: 1 hour, 2 downloads, password | `201` | Raw token returned **once** |
| 14 | Anonymous visitor opens the link | `200` | Password gate, no file yet |
| 15 | Wrong password | **`403`** | |
| 16 | Correct password | `200` | Returns a 10-minute grant |
| 17 | Download #1 | `200` | Identical |
| 18 | Download #2 | `200` | Identical |
| 19 | **Download #3** | **`410 SHARE_LINK_DOWNLOAD_LIMIT_REACHED`** | The cap holds |
| 20 | Alice revokes the link | `204` | |
| 21 | The link afterwards | **`410`** | Dead |

---

## Proving the file is really encrypted

While a file exists, look at what is on disk:

```bash
sudo docker compose exec -T api sh -c 'find /data/storage -type f | head -1'
# /data/storage/GU/dr/GUdrewIV0hLv80fu6y9JLiylJJdsHXcguu-CbL0hCCY

sudo docker compose exec -T api sh -c 'head -c 6 $(find /data/storage -type f | head -1)'
# SSENC1
```

Three things to notice:

- The path is a random content-addressed id. The filename is nowhere in it, so
  traversal is structurally impossible rather than filtered out.
- The file begins with the `SSENC1` container magic, not `%PDF`.
- Searching the blob for text from the original document finds nothing.

Measured on a 394-byte PDF: 394 bytes of plaintext → 450 bytes of ciphertext.
The 56-byte difference is the 36-byte header, the frame length and the GCM tag.

---

## Showing the attacks fail

Each of these was run against the live stack:

```bash
# SQL injection in the login field
curl -X POST .../api/auth/login/ -d '{"email":"'"'"' OR '"'"'1'"'"'='"'"'1","password":"x"}'
# 400 -- and the table is still there afterwards

# Path traversal in the upload filename
curl -F "file=@x.pdf;filename=../../../etc/passwd.pdf" .../api/files/upload/
# 201, stored as "passwd.pdf"

# A Windows executable renamed to look like a PDF
curl -F "file=@evil.exe;filename=invoice.pdf;type=application/pdf" .../api/files/upload/
# 415 UNSUPPORTED_FILE_TYPE -- the content is sniffed, the claim ignored

# A normal user reaching for the admin API
curl -H "Authorization: Bearer $USER_TOKEN" .../api/admin/stats/
# 403

# Self-promotion
curl -X PATCH -H "Authorization: Bearer $USER_TOKEN" -d '{"role":"ADMIN"}' .../api/users/me/
# 200 -- but the role is unchanged: `role` is not a writable field

# The encrypted store, directly
curl .../storage/
# 404 -- nginx refuses it outright
```

---

## Tamper detection

Flip a single bit anywhere in a stored blob and the download fails rather than
returning corrupted data. Measured across eight variants — header byte, first
ciphertext byte, a middle byte, the final GCM tag byte, a truncated tail, a
truncated final frame, a wrong AAD context, and a wrong DEK — **every one
raised `IntegrityError`**. No partial plaintext is ever returned.

---

## Health as a real signal

```bash
curl --cacert nginx/certs/server.crt https://localhost:8443/api/health/
# {"status":"ok","version":"0.6.0","database":"ok","redis":"ok",
#  "cache":"ok","storage":"ok","encryption_keys":"ok"}
```

`encryption_keys: ok` means a wrap/unwrap round trip on a throwaway key
succeeded — not merely that a key file exists. This distinction was a real bug:
an earlier version checked only that the public key had loaded, so a node that
could not decrypt anything still reported healthy. Uploads returned 201 and
every download returned 503.

To see the difference, break the key permissions deliberately:

```bash
sudo chgrp 1000 keys/rsa_private.pem && sudo chmod 600 keys/rsa_private.pem
sudo docker compose restart api && sleep 25
curl -sk https://localhost:8443/api/health/
# {"status":"degraded", ... "encryption_keys":"error"}   <- and api is not healthy

sudo chgrp 10001 keys/rsa_private.pem && sudo chmod 640 keys/rsa_private.pem
sudo docker compose restart api && sleep 25
# back to "ok"
```

---

## Automated verification

```bash
# Functional behaviour -- 136 checks
sudo docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
SECURESHARE_MANAGE="sudo docker compose exec -T api python manage.py" \
  python3 scripts/verify_phase8_9.py http://127.0.0.1:8100
# All 136 checks passed.

# The edge, against the UNMODIFIED production config -- 33 checks
SECURESHARE_CA_BUNDLE=./nginx/certs/server.crt \
  python3 scripts/verify_edge.py https://localhost:8443
# All 33 edge checks passed.  (19 of 25 burst requests rejected with 429)
```

The functional suite uses a relaxed-limit overlay because 136 requests in four
seconds would otherwise trip the production rate limiter — which is the limiter
working, not a fault. The edge script then verifies that the real limiter does
reject a burst. Both runs are needed; neither alone is sufficient.
