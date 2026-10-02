# SecureShare — Viva Questions & Answers

40 questions across cryptography, authentication, authorization, web security,
infrastructure and design. Answers are specific to this codebase, so you can
point at the file that implements each one.

---

## Cryptography — symmetric

### 1. Why AES-256-GCM rather than AES-CBC?

GCM is authenticated encryption: it produces a 16-byte tag that detects any
modification. CBC provides confidentiality but no integrity, so an attacker can
flip ciphertext bits and the plaintext changes in a predictable way — the
padding-oracle family of attacks. With GCM, tampering fails loudly. Measured
here: flipping any single bit raises `IntegrityError`, and no partial plaintext
is returned.

### 2. What is a nonce, and what happens if you reuse one?

A number used once, per key. GCM derives its keystream from (key, nonce), so
reusing a pair with the same key XORs two plaintexts together — an attacker who
knows one recovers the other. Worse, nonce reuse in GCM leaks the authentication
subkey, which lets an attacker forge valid tags. It is the single most dangerous
mistake in GCM.

### 3. How do you guarantee nonce uniqueness here?

The 12-byte nonce is an 8-byte random prefix, generated per file with
`secrets.token_bytes(8)`, concatenated with a 4-byte chunk counter. The prefix
makes it unique across files; the counter makes it unique across chunks within
a file. Because every file also gets a fresh DEK, a repeat would require both a
key collision and a counter collision.

### 4. Why encrypt in chunks rather than all at once?

Memory. A single-shot encryption holds the whole file in RAM; a 25 MB upload
with ten concurrent users is 250 MB. Chunking streams it. It also lets each
chunk carry its own tag, so corruption is detected at the chunk that is wrong
rather than only at the end.

### 5. If each chunk is authenticated separately, can an attacker reorder them?

No, and this is why the AAD matters. Each chunk's additional authenticated data
includes the header, the chunk counter and a final-chunk flag. A chunk moved to
a different position fails its tag check because the counter no longer matches.
The final flag prevents truncation — dropping the last chunk is detected
because no chunk claims to be final. Verified: truncated tail and truncated
final frame both raise `IntegrityError`.

### 6. What is AAD and what did you bind into it?

Additional Authenticated Data is authenticated but not encrypted. Here it is
header ‖ chunk counter ‖ final flag ‖ caller context. The context ties
ciphertext to its logical object, so a blob cannot be transplanted onto another
database record and decrypted. Decrypting with the wrong context raises
`IntegrityError`.

### 7. Walk through the file format.

36-byte header, `struct ">6sBBI16s8s"`: magic `SSENC1`, format version,
algorithm id, chunk size, a 16-byte stream id, and the 8-byte nonce prefix.
Then frames, each `u32 length ‖ ciphertext+tag`. The magic lets us reject
foreign data immediately; the version field means the format can change without
breaking old files.

---

## Cryptography — asymmetric and envelope

### 8. What is envelope encryption and why use it?

Encrypt data with a fast symmetric key (the DEK), then encrypt that key with a
slower asymmetric key. You get RSA's key-management properties with AES's
speed. RSA can only encrypt a few hundred bytes anyway — RSA-3072 with OAEP
caps out around 318 — so encrypting a 25 MB file directly is not even possible.

### 9. Why RSA-OAEP rather than PKCS#1 v1.5?

PKCS#1 v1.5 is vulnerable to Bleichenbacher's adaptive chosen-ciphertext
attack: error messages act as an oracle that recovers plaintext. OAEP adds
randomised padding with a provable security reduction. We use
`RSA-OAEP-SHA256-MGF1-SHA256`.

### 10. What exactly is stored where?

The ciphertext goes to a content-addressed file on disk. The **wrapped** DEK
goes into PostgreSQL alongside the key id that sealed it. The plaintext DEK
exists only in process memory, for the duration of one request, and is never
written anywhere. `EncryptionResult` deliberately exposes `wrapped_dek` and no
plaintext key.

### 11. Someone dumps your database. What can they read?

Nothing useful. They get wrapped DEKs, Argon2id password hashes, SHA-256 share
token hashes and metadata. Unwrapping needs the RSA private key, which is not
in the database. They would also need the ciphertext, which is on a different
volume. Both together, without the key, still yield nothing.

### 12. Someone gets the private key. What then?

Every file ever uploaded is readable, if they also have the ciphertext. That is
why it is the top-ranked residual risk in the threat model, and why the
recommendation is a KMS or HSM in production. There is no mitigation inside the
application for a leaked root key.

### 13. How does key rotation work without breaking old files?

Each wrapped DEK records the key id that sealed it. A new pair becomes active
for new files; the old private key stays listed in
`RSA_RETIRED_PRIVATE_KEY_PATHS` so existing files still unwrap. Deleting a
retired key permanently destroys every file still wrapped with it.

### 14. Why 3072-bit RSA?

Roughly 128-bit security, matching AES-256-GCM's practical strength and NIST's
recommendation beyond 2030. 2048 is the enforced minimum; the generator warns
below 3072.

---

## Authentication

### 15. Why Argon2id for passwords?

It is memory-hard, so GPU and ASIC attacks lose their advantage — the attacker
must supply RAM per guess, not just compute. Argon2id combines Argon2i's
side-channel resistance with Argon2d's GPU resistance and won the Password
Hashing Competition. Django's `Argon2PasswordHasher` handles per-password salts
automatically.

### 16. Why not SHA-256 for passwords?

It is designed to be fast, which is exactly wrong for passwords — a modern GPU
does billions of SHA-256 hashes per second. Password hashing needs to be
deliberately slow and memory-hungry.

### 17. What is in your JWT, and what is deliberately not?

Claims: user id, role, `tv` (token version), issuer, issued-at and expiry.
Not included: anything secret. A JWT is signed, not encrypted — anyone holding
it can read the payload. Passwords, keys and file contents never go near it.

### 18. JWTs are stateless. How do you log someone out?

A `token_version` integer on the user row, mirrored in every token as `tv`.
Authentication compares them and rejects a mismatch. Logout, a password change
or an administrative disable increments the version, which kills every
outstanding token for that user instantly. One integer buys a stateless design
an immediate kill switch.

### 19. Where does the frontend keep tokens, and why?

The access token lives in JavaScript memory only — it disappears on refresh,
which is intentional. The refresh token is in `sessionStorage`, cleared when
the tab closes. An ESLint rule bans `localStorage` for this.

This is a trade-off, not a best practice. `sessionStorage` is readable by any
JavaScript on the page, so XSS can steal the refresh token. The alternative —
an httpOnly cookie — removes that risk but introduces CSRF exposure and
complicates a token-based API. I chose this and listed it as a residual risk
rather than pretending it is free.

### 20. How do you resist brute force?

Four layers: Argon2id makes each guess expensive; the account locks for 900
seconds after repeated failures; DRF throttles login to 10/min; nginx limits
auth endpoints to 5r/m per IP. Measured: 19 of 25 burst requests rejected with
429. A slow distributed attack across many IPs is not stopped — that is
documented, not hidden.

### 21. How do you avoid leaking whether an account exists?

Login returns the same error shape for an unknown address and a wrong password.
Registration does not confirm whether an address is taken. Password reset
responds identically either way. Timing is not formally equalised, which is
noted as a limitation.

---

## Authorization

### 22. Where is authorization enforced, and why does that matter?

In the backend, in service-layer code, on every request. The React app hides
controls the user cannot use, but that is cosmetic. I demonstrate this by
calling the API directly with a normal user's token: `/api/admin/stats/`
returns 403 even though the UI never shows the link. If authorization lived
only in React, `curl` would defeat it entirely.

### 23. What is IDOR and how is it prevented?

Insecure Direct Object Reference: changing an identifier in a URL to reach
someone else's data. Prevented by re-checking ownership or an explicit grant on
every access — never assuming that holding an id implies permission. UUIDs make
guessing impractical, but UUIDs are not the control; the check is.

### 24. Why 404 instead of 403 for another user's file?

A 403 confirms the record exists. An attacker enumerating ids could map which
ones are real. 404 is indistinguishable from "no such file", so nothing leaks.

### 25. How is privilege escalation prevented?

Admin endpoints sit behind an `IsAdmin` permission class; a normal user gets
403, anonymous gets 401. `role` is not a writable field on any user-facing
serializer. `PATCH /api/users/me/ {"role":"ADMIN"}` returns 200 — because other
valid fields in the payload were applied — but the role is unchanged. That is
worth demonstrating, because the 200 looks alarming until you re-read the
profile.

### 26. Can a share recipient re-share or revoke?

No. Only the owner may modify or revoke. A recipient attempting either gets
403. A partial unique index enforces one active share per (file, recipient).

---

## Web security

### 27. How are you protected against SQL injection?

The Django ORM parameterises every query; user input never becomes SQL syntax.
There is no string-built SQL in application code. Tested live with
`' OR '1'='1`, `'; DROP TABLE accounts_user;--` and a `UNION SELECT` — all
return 400, and the table is still there afterwards.

### 28. And XSS?

React escapes interpolated values by default, and the codebase uses no
`dangerouslySetInnerHTML`. API responses are `application/json` with
`X-Content-Type-Options: nosniff`, so a browser will not reinterpret them as
HTML. Registering with the name `<script>alert(1)</script>` stores it, returns
it JSON-escaped, and renders it as literal text.

### 29. Why is there no CSRF token?

CSRF depends on the browser attaching credentials automatically — cookies. This
API authenticates only with an `Authorization: Bearer` header, which a browser
never adds on its own. A cross-site form post arrives with no token and is
rejected with 401. Presenting a session cookie alone also yields 401. There is
nothing for an attacker to replay.

### 30. How is CORS configured?

An explicit origin allow-list from configuration. `CORS_ALLOW_ALL_ORIGINS` is
never enabled in production. Wildcard CORS with credentials would let any site
read authenticated responses.

### 31. Which security headers, and what does each do?

HSTS (forces HTTPS on later visits), `X-Content-Type-Options: nosniff` (stops
MIME sniffing), `X-Frame-Options: DENY` (clickjacking), `Referrer-Policy`
(stops URL leakage — `no-referrer` on share routes so tokens never appear in a
Referer header), `Permissions-Policy` (disables camera, microphone,
geolocation), and `Cross-Origin-Opener-Policy`. The nginx version banner is
suppressed.

### 32. How is rate limiting implemented at both tiers?

DRF throttles per scope, backed by Redis, keyed by user or IP — login 10/min,
registration 5/hour, anonymous 120/hour. nginx adds `limit_req` zones at the
edge: 5r/m on auth, 20r/m on share, 30r/s general, plus `limit_conn` per IP.
The edge stops floods before they reach Python; the application layer enforces
business-level limits.

---

## File handling

### 33. How do you stop path traversal?

Filenames never become path components. The stored object id is random and
content-addressed, and the original name is metadata in the database. Uploading
`../../../etc/passwd.pdf` stores a file named `passwd.pdf` at a random path.
The attack is structurally impossible rather than filtered — there is no string
to sanitise.

### 34. Why not trust the Content-Type header?

It is attacker-controlled. We sniff the actual bytes with libmagic and check
the result against an allow-list. A Windows PE binary renamed `invoice.pdf` and
declared `application/pdf` returns 415.

### 35. What else is validated on upload?

Size (25 MB application cap, 100 MB at nginx), extension allow-list, sniffed
MIME type, and archive entry limits to resist zip bombs. Oversized uploads
return 413. Malware scanning via ClamAV is available but **disabled by
default** — files are not scanned unless it is switched on, which the
documentation states plainly.

---

## Sharing

### 36. How are share tokens generated and stored?

`secrets.token_urlsafe(32)` — 256 bits from a cryptographically secure source,
not `random`. Only a SHA-256 hash is stored, with a 12-hex prefix for index
lookup. The raw token is shown once at creation and cannot be recovered from
the database.

### 37. Two people click the last download simultaneously. What happens?

Exactly one succeeds. The claim is a single conditional UPDATE —
`SET download_count = download_count + 1 WHERE id = … AND download_count <
max_downloads` — so the database arbitrates under its own locking. Tested with
ten parallel threads: one 200, nine 410. Read-then-write in Python would have
raced.

### 38. How are link passwords protected?

Argon2id, same as account passwords, never stored in plaintext. Five failed
attempts lock that specific link for 900 seconds. Verifying returns a
short-lived grant (10 minutes), salted and bound to one link, so a grant from
one link cannot be replayed against another.

---

## Infrastructure and design

### 39. Why is the frontend a separate container?

A built React bundle is static files. It needs no Python, no database and no
secrets, so it has no business sharing a runtime with the API. Separating them
means the frontend image is 48.6 MB against 264 MB, runs as uid 101 with a
read-only root filesystem, and can be scaled or cached independently. nginx
proxies `/` to it and `/api` to Django.

Worth being honest about: this was missing until late. The Compose stack had no
frontend service and nginx had `location / { return 404; }` left over from an
earlier phase. The API end-to-end suite never caught it because it only
exercises `/api`. That is why `scripts/verify_edge.py` exists — it checks the
layer the API suite cannot see.

### 40. What is the most interesting bug you found, and what did it teach you?

The health check. It verified that the RSA **public** key had loaded, and
reported `encryption_keys: ok`. But the container runs as uid 10001, and a
read-only bind mount preserves host ownership, so a `0600` key owned by uid
1000 was unreadable inside the container.

The failure mode was the dangerous kind. Uploads returned 201, because wrapping
a DEK only needs the public key. Every download returned 503. And health still
said everything was fine — so a load balancer would have kept routing traffic
to a node that could not decrypt a single file.

The fix was to make the check perform a real wrap/unwrap round trip on a
throwaway key, which also catches a mismatched pair, a wrong passphrase and a
truncated PEM. I verified it with a negative control: break the permissions,
health goes to `degraded` and the container stops being healthy; restore them,
it returns to `ok`.

The lesson generalises beyond this project: **check the capability, not its
preconditions.** A key file existing is not the same as being able to decrypt
with it. Of the seven defects found in the final audit, five only surfaced once
the system was actually deployed and exercised — reading the code would never
have found them.

---

## Rapid-fire

| Question | Answer |
| --- | --- |
| DEK? | Data Encryption Key — the per-file AES-256 key |
| Why one DEK per file? | Compromising one file's key does not compromise any other |
| GCM tag size? | 16 bytes |
| Nonce size? | 12 bytes (8 random prefix + 4 counter) |
| Wrapped DEK size? | 384 bytes for RSA-3072 |
| Access token lifetime? | 15 minutes |
| Refresh token lifetime? | 1 day |
| Lockout duration? | 900 seconds |
| Upload cap? | 25 MB application, 100 MB nginx |
| Share token entropy? | 256 bits |
| Default link expiry? | 24 hours, capped at 30 days |
| Why Redis? | Cache, throttle counters, Celery broker |
| Why Celery? | Expiring links, purging deleted ciphertext, audit retention |
| Why PostgreSQL? | Transactions, partial unique indexes, conditional updates for the atomic counter |
| Backend coverage? | 90.3%, 542 tests, 245 security-tagged |
| Can audit logs be deleted? | No — `update()` and `delete()` raise at the ORM level |
| Is this end-to-end encrypted? | **No.** The server can decrypt; that boundary is documented |
| Is it production-ready? | Not without a KMS, malware scanning, alerting and an independent audit |
