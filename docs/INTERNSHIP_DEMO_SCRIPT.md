# SecureShare — Internship Demo Script

**Duration:** 10–15 minutes
**Audience:** technical supervisor / evaluation panel

Timings assume you have rehearsed once. The script is written so that if you
run short, you cut beat 11; if you run long, you skip the attack demos in
beat 8 and simply state the results.

---

## Before you start

- [ ] `sudo docker compose up -d` — all **seven** containers healthy
- [ ] `sudo docker compose ps` output visible in a terminal
- [ ] Browser open at `https://localhost:8443`, certificate warning already clicked through
- [ ] Two browser profiles (or one normal + one private window) for Alice and Bob
- [ ] A real PDF on the desktop, named something recognisable
- [ ] A second terminal in the project root
- [ ] `docs/SECURITY_AUDIT.md` open in an editor tab

**Rehearse the failure.** If a container is unhealthy mid-demo, say what you
see and run `docker compose logs <service>`. Debugging calmly in front of a
panel reads better than pretending nothing happened.

---

## Beat 1 — What it is and why (0:00–1:00)

> "SecureShare is a file-sharing platform where the server stores nothing in
> plaintext. Every file is encrypted with its own AES-256 key, and that key is
> itself encrypted with an RSA public key. The private key is the only way back.
>
> I built it in twelve phases. What I want to show you is not that it runs —
> it's what broke when I actually tested it, because that's where the learning
> was."

Set the expectation early that you will talk about defects. It reframes the
rest of the demo from *demonstration* to *engineering*.

---

## Beat 2 — The running system (1:00–2:00)

```bash
sudo docker compose ps
```

> "Seven containers. Note the ports column: only nginx publishes anything —
> 8080 and 8443. PostgreSQL, Redis, the API and both Celery processes are
> internal to the Docker network. There is no route from the internet to the
> database."

```bash
curl --cacert nginx/certs/server.crt https://localhost:8443/api/health/
```

> "Every dependency reports ok. I'll come back to `encryption_keys` — that one
> has a story."

---

## Beat 3 — Register and upload (2:00–3:30)

In the browser as Alice: register, log in, upload the PDF.

> "The upload returns the encryption metadata: AES-256-GCM-STREAM-V1, wrapped
> with RSA-OAEP-SHA256. That's not a label I typed in — it's what the service
> actually used."

---

## Beat 4 — Prove it is encrypted (3:30–5:00)

This is the beat that earns credibility. Do it in the terminal.

```bash
sudo docker compose exec -T api sh -c 'find /data/storage -type f | head -1'
sudo docker compose exec -T api sh -c 'head -c 6 $(find /data/storage -type f | head -1)'
```

> "The path is a random id — the filename appears nowhere in it, so path
> traversal isn't filtered, it's structurally impossible. The file starts with
> `SSENC1`, our container magic, not `%PDF`. And if I grep the blob for text
> from the document, there's nothing there."

Download the file in the browser and open it.

> "Same bytes back. Encrypt, store, authorize, decrypt, stream — end to end."

---

## Beat 5 — Authorization (5:00–6:30)

Log in as Bob in the second window. Paste the URL of Alice's file.

> "404. Not 403 — and that's deliberate. A 403 would confirm the file exists.
> Bob learns nothing."

Alice shares VIEW with Bob. Bob can see the metadata but the download returns
**403**.

> "VIEW doesn't imply DOWNLOAD. The download endpoint re-checks; it doesn't
> trust that the UI only showed a button it was allowed to show."

Alice upgrades to DOWNLOAD → Bob downloads. Alice revokes → Bob gets 404 again.

---

## Beat 6 — Public links (6:30–8:00)

Alice creates a link: 1 hour, **2 downloads**, password protected.

> "The raw token is shown once. We only store a SHA-256 hash, so even with the
> database you can't reconstruct the link."

In a private window: wrong password → 403. Correct password → a 10-minute
grant. Download once, twice, then a third time:

> "**410, download limit reached.** That counter is incremented by a single
> conditional UPDATE, so the database decides the winner. I tested it with ten
> parallel threads: exactly one success, nine rejections. Two requests can't
> both claim the last slot."

Alice revokes the link → 410.

---

## Beat 7 — Admin and audit (8:00–9:00)

Log in as the admin. Show the dashboard, user management, security events.

Then, in the terminal, as Bob:

```bash
curl -H "Authorization: Bearer $BOB_TOKEN" https://localhost:8443/api/admin/stats/
# 403
```

> "The React app hides the admin pages from Bob, but hiding is cosmetic. The
> API refuses him directly. Authorization is enforced on the backend — the
> frontend is a convenience, never a control."

Mention audit immutability:

> "Audit records are append-only at the ORM level. `update()` and `delete()`
> raise. An attacker who gets a session still can't erase the trail."

---

## Beat 8 — Attacks that fail (9:00–10:30)

Pick two or three. Run them live if time allows; otherwise show the table in
`SECURITY_AUDIT.md`.

```bash
# executable disguised as a PDF
curl -F "file=@evil.exe;filename=invoice.pdf;type=application/pdf" ...
# 415 -- content sniffed with libmagic, the declared type ignored

# path traversal
# filename "../../../etc/passwd.pdf" is stored as "passwd.pdf"

# SQL injection
# "'; DROP TABLE accounts_user;--" -> 400, table intact
```

> "245 of the 542 backend tests are tagged `security`. These aren't one-off
> manual checks — they're regressions that fail the build if someone
> reintroduces the hole."

---

## Beat 9 — The bug worth talking about (10:30–12:00)

**This is the most important beat. Do not cut it.**

> "The health endpoint used to check that the RSA public key had loaded. That
> passed. But the container runs as uid 10001, and a read-only bind mount keeps
> the host's ownership — so a 0600 key owned by my user was unreadable inside
> the container.
>
> The result was the worst kind of failure. Uploads returned 201, because
> wrapping a key only needs the *public* key. Every download returned 503. And
> health still said `encryption_keys: ok`. A load balancer would have kept
> sending traffic to a node that couldn't decrypt a single file."

Demonstrate it if you have the time:

```bash
sudo chgrp 1000 keys/rsa_private.pem && sudo chmod 600 keys/rsa_private.pem
sudo docker compose restart api && sleep 25
curl -sk https://localhost:8443/api/health/
# {"status":"degraded", ..., "encryption_keys":"error"}
```

> "The fix was to make the check do a real wrap/unwrap round trip on a
> throwaway key. The lesson generalises: **test the capability, not its
> preconditions.** A key file existing is not the same as being able to decrypt.
> I found five more defects the same way — all of them only appeared once the
> thing was actually deployed and exercised, not when I read the code."

Restore it before moving on.

---

## Beat 10 — Verification and numbers (12:00–13:30)

```bash
SECURESHARE_CA_BUNDLE=./nginx/certs/server.crt python3 scripts/verify_edge.py https://localhost:8443
```

> "33 edge checks against the unmodified production config — TLS, headers, SPA
> routing, the encrypted store refusing to be served, and the rate limiter
> actually rejecting a burst: 19 of 25 requests get a 429.
>
> Separately, 136 functional end-to-end checks. Those run with the limits
> relaxed, because 136 requests in four seconds would trip a limiter that's
> correctly configured for humans. So I test function with limits off, and I
> test the limiter itself with limits on. Neither run alone would be honest."

The numbers, stated plainly:

| | |
| --- | --- |
| Backend tests | 542 passed (245 security-tagged) |
| Coverage | 90.3% |
| Frontend tests | 53 passed |
| End-to-end | 136/136 functional, 33/33 edge |
| Bandit | 0 high, 1 medium (documented), 13 low |
| pip-audit | No known vulnerabilities |
| npm audit | 2 moderate, both reasoned |

---

## Beat 11 — Limitations (13:30–14:30)

> "What I would not claim:
>
> This is **not end-to-end encrypted.** The server can decrypt, because it has
> to in order to serve a download. A malicious operator could read everything.
>
> The private key is a file on disk. Production should use a KMS or HSM. If
> that key is lost, every file is permanently unrecoverable — that's by design,
> but it's a real operational risk.
>
> The refresh token sits in `sessionStorage`, which JavaScript can read. The
> alternative is a cookie, which trades XSS exposure for CSRF exposure. I chose
> this one and documented why.
>
> Malware scanning is off by default. And none of this has been independently
> audited."

---

## Beat 12 — Close (14:30–15:00)

> "Twelve phases, seven containers, real cryptography from the `cryptography`
> library — nothing hand-rolled. Everything I've shown you I ran today.
>
> The thing I'd take to the next project isn't the AES code. It's that a system
> can pass every test you wrote and still be broken in a way you didn't think to
> check. The health endpoint taught me that."

---

## Likely questions

| Question | Short answer |
| --- | --- |
| "Why not encrypt in the browser?" | True E2EE needs client-side key management and breaks server-side sharing. Different product; I documented the boundary. |
| "What if the private key leaks?" | Every file is exposed. That's why it's the top residual risk and why production should use a KMS. |
| "Why 404 instead of 403?" | A 403 confirms the resource exists. 404 leaks nothing. |
| "Is 90% coverage enough?" | Coverage says lines ran, not that behaviour is right. The 245 security tests matter more than the number. |
| "What would you do next?" | Move the key to a KMS, enable ClamAV, add a Playwright layer, get an independent review. |
| "Did you use AI?" | Answer honestly, and be ready to explain any file you're asked about — line by line. |

---

## If something breaks

Say what you see, read the log, fix it or move on. A panel learns more from
watching you debug than from a demo that never stumbles. The one thing not to
do is claim something works when the screen says otherwise.
