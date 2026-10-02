# SecureShare — Threat Model

Scope: the SecureShare application, its data stores and its container
deployment. The host operating system, the hypervisor and the physical network
are out of scope and assumed to be managed separately.

This document is written to be useful rather than reassuring. Where a control
is partial, it says so.

---

## 1. Assets

| # | Asset | Why it matters | Impact if lost |
| --- | --- | --- | --- |
| A1 | Uploaded file contents | The product exists to protect them | Direct breach of user data |
| A2 | RSA private key | Unwraps every DEK ever issued | Total compromise of all stored files |
| A3 | Data encryption keys (DEKs) | One per file | Compromise of the files they seal |
| A4 | User credentials | Account takeover | Impersonation, access to that user's files |
| A5 | JWT signing key | Forged tokens for any user, any role | Full authentication bypass |
| A6 | Share links and tokens | Bearer access to a file | Unauthorised access while valid |
| A7 | Audit log | Evidence of what happened | Undetected or undisprovable incidents |
| A8 | File metadata | Filenames, sizes, ownership, timestamps | Information disclosure |
| A9 | Database credentials | Direct access to A3, A4, A7, A8 | Near-total compromise |
| A10 | Availability | Service is usable | Denial of service |

**Dependency worth stating plainly:** A2 protects A3, which protects A1. The
RSA private key is the root of the whole scheme. Losing it to an attacker
exposes every file. Losing it to carelessness makes every file permanently
unreadable — there is no recovery path, by design.

---

## 2. Attackers

| # | Attacker | Capability | Motivation |
| --- | --- | --- | --- |
| T1 | Anonymous internet user | Can reach the public surface: registration, login, public share links | Opportunistic access, account takeover |
| T2 | Authenticated user | Valid account, knows the API, can craft requests directly | Reach other users' files, escalate to admin |
| T3 | Share-link recipient | Holds a link, may hold its password | Exceed what the link grants: more downloads, after expiry, other files |
| T4 | Network observer | Sees traffic between browser and server | Harvest credentials, tokens, file contents |
| T5 | Malicious uploader | Valid account, uploads hostile content | Code execution, stored XSS, traversal, resource exhaustion |
| T6 | Compromised database | Read access to PostgreSQL only | Read file contents from the database |
| T7 | Compromised storage volume | Read access to the ciphertext tree only | Read file contents from disk |
| T8 | Insider with host access | Reads the filesystem, including key material | Everything |
| T9 | Supply-chain attacker | Controls a dependency | Arbitrary code in the application |

---

## 3. Trust boundaries

```
      ┌────────────────────── UNTRUSTED ──────────────────────┐
      │  Browser, client JavaScript, every request header,    │
      │  every uploaded byte, every claimed MIME type         │
      └───────────────────────────┬───────────────────────────┘
                                  │  B1: TLS + input validation
      ┌───────────────────────────▼───────────────────────────┐
      │  nginx edge — TLS, rate limits, security headers      │
      └───────────────────────────┬───────────────────────────┘
                                  │  B2: internal network only
      ┌───────────────────────────▼───────────────────────────┐
      │  Django API — authN, authZ, crypto                    │
      │  ┌──────────────────── B3 ──────────────────────────┐ │
      │  │  Key material: private key readable only by the  │ │
      │  │  app account; plaintext DEK lives in memory for  │ │
      │  │  the duration of one request and is never        │ │
      │  │  written down                                    │ │
      │  └──────────────────────────────────────────────────┘ │
      └───────┬──────────────────┬───────────────────┬────────┘
              │ B4               │ B4                │ B5
      ┌───────▼──────┐  ┌────────▼───────┐  ┌────────▼────────┐
      │ PostgreSQL   │  │ Redis          │  │ Ciphertext tree │
      │ no plaintext │  │ no file data   │  │ no keys         │
      │ no raw tokens│  │                │  │ mode 0700       │
      └──────────────┘  └────────────────┘  └─────────────────┘
```

- **B1** Nothing from the client is trusted: not the filename, not the MIME
  type, not any header, not the authorization the UI believes it has.
- **B2** Only nginx is published. The API is not directly reachable from
  outside the Docker network.
- **B3** The private key is readable by one OS account. A plaintext DEK exists
  only in process memory, for one request.
- **B4** The stores hold ciphertext and hashes. Neither can decrypt anything on
  its own.
- **B5** The ciphertext tree is never served by a web server.

---

## 4. Threats and mitigations

### Authentication (T1, T2)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Password brute force | Argon2id; lockout after repeated failures (900 s); login throttle 10/min; nginx 5r/m | A slow distributed attack across many IPs is not stopped |
| Credential stuffing | Same controls; password validators reject weak and common passwords | No breached-password corpus check |
| User enumeration | Login, registration and reset return the same shape and timing regardless of existence | Not formally timing-analysed |
| Token theft via XSS | React escapes by default; no `dangerouslySetInnerHTML`; access token in memory only | Refresh token in `sessionStorage` is JS-reachable — **accepted risk** |
| Token replay after logout | `token_version` increments; all prior tokens die immediately | Access token remains valid for ≤15 min if the version is not bumped |
| Forged tokens | HMAC-SHA256 over a 50+ char signing key from the environment | Key compromise (A5) defeats this entirely |

### Authorization (T2, T3)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| IDOR on files | Every access re-checks ownership or grant; UUID identifiers; 404 not 403 | — |
| Horizontal escalation | Enforced in services, not views, so every path shares one rule | — |
| Vertical escalation | `IsAdmin` on all admin routes; `role` not writable on any user serializer | — |
| Frontend-only trust | Backend re-decides everything; verified by calling the API directly | — |
| Recipient modifying a share | Only the owner may update or revoke | — |

### File handling (T5)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Path traversal | Filenames are never path components; object ids are random | — |
| MIME spoofing | libmagic sniffs actual content; the client's claim is ignored | — |
| Dangerous executables | Extension allow-list plus sniffed type | A permitted type with embedded macros is still accepted |
| Oversized upload | 25 MB application cap, 100 MB nginx cap | — |
| Zip bomb | Entry count and ratio limits (`MAX_ZIP_ENTRIES` 5000) | Not a full recursive unpack analysis |
| Malware | Optional ClamAV hook | **Disabled by default** — files are not scanned unless enabled |
| Stored XSS via filename | Escaped on output; `nosniff`; downloads are attachments | — |

### Cryptography (T6, T7)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Weak algorithm | AES-256-GCM and RSA-OAEP-SHA256 from the `cryptography` library; nothing hand-written | — |
| Nonce reuse | Random 8-byte prefix per file ‖ 4-byte chunk counter | — |
| Key reuse across files | A fresh DEK per file | — |
| Tampered ciphertext | GCM tag per chunk, AAD binds position and finality | — |
| Plaintext key at rest | DEKs are stored only wrapped; the plaintext exists in memory for one request | A memory-capable attacker can read it |
| Database compromise (T6) | Rows hold wrapped DEKs; without A2 they are useless | — |
| Storage compromise (T7) | Blobs are ciphertext; without A2 they are useless | — |
| Both plus the key (T8) | — | **Not mitigated.** Host compromise is game over |

### Share links (T1, T3)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Token guessing | 256-bit `secrets.token_urlsafe(32)` | — |
| Token theft from the database | Only a SHA-256 hash is stored | — |
| Expiry bypass | Checked server-side on every access | — |
| Download-limit race | Single conditional `UPDATE`; the database arbitrates | — |
| Password brute force | Argon2id; 5 attempts then 900 s lockout, per link | — |
| Link forwarding | Expiry, download cap, optional password, revocation | **A link is a bearer token.** Anyone holding it has what it grants |
| Referrer leakage | `Referrer-Policy: no-referrer` on share routes | — |

### Transport and web (T4)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Eavesdropping | TLS 1.2/1.3, forward-secret suites only, HSTS | Local deployment uses a self-signed certificate |
| SQL injection | Django ORM parameterises everything; no string-built SQL in application code | — |
| CSRF | JWT bearer only; a session cookie alone yields 401, so there is nothing for a browser to replay | — |
| CORS abuse | Explicit origin allow-list; `CORS_ALLOW_ALL_ORIGINS` is never enabled in production | — |
| Clickjacking | `X-Frame-Options: DENY` | — |
| Information disclosure | `DEBUG=False` in production; errors are generic with a request id | — |
| Open redirect | `safeInternalPath()` rejects external targets after login | — |

### Availability (T1, T5)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Request flooding | nginx `limit_req` and `limit_conn`; DRF per-scope throttles | No upstream DDoS protection |
| Large-upload exhaustion | Size caps at both tiers; streaming, so files are not held in memory | — |
| Slowloris | nginx timeouts | — |

### Supply chain (T9)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Vulnerable dependency | pip-audit and npm audit in the security script; pinned versions; lockfile | Audits are point-in-time, not continuous |
| Malicious package | Lockfile with integrity hashes | No signature verification or vendoring |

---

## 5. Explicitly out of scope

Honest boundaries, not oversights:

- **Not end-to-end encrypted.** The server can decrypt files, because it must
  to serve a download. A malicious or compromised server operator can read
  everything. True E2EE would require client-side keys and a different product.
- **Host compromise is total.** An attacker with root on the host reads the key
  and the database.
- **No protection against a malicious administrator.** Admins can disable
  accounts and read audit logs by design.
- **No anti-forensics resistance.** Deleted ciphertext is unlinked, not
  cryptographically shredded.
- **No rate limiting across distributed sources.** Limits are per-IP.
- **No formal verification.** The cryptography uses well-reviewed primitives
  correctly as far as the tests demonstrate, but the system has not been
  independently audited or proved correct.

---

## 6. Residual risks, ranked

| Risk | Severity | Why it remains |
| --- | --- | --- |
| Private key on disk | **High** | Simplicity for a project deployment. Production should use a KMS or HSM |
| Refresh token in `sessionStorage` | Medium | Reachable by JavaScript. The alternative, a cookie, trades XSS exposure for CSRF exposure; the mitigation is to keep XSS out |
| Server can decrypt | Medium | Inherent to server-side encryption |
| Malware scanning off by default | Medium | ClamAV is heavy; the hook exists and is documented |
| Self-signed certificate locally | Low | Production must install a real certificate |
| 2 moderate npm advisories | Low | `react-router`; one mitigated by `safeInternalPath()`, the other unreachable in `BrowserRouter` mode |
| No breached-password check | Low | Would need an external corpus or API |
| Distributed brute force | Low | Per-IP limits only |

---

## 7. What would change my assessment

Signals that should trigger a re-review rather than a reassurance:

- Any code path that writes a plaintext DEK, or a key, to disk or a log.
- Any endpoint returning key material, or a stack trace, in production.
- A second encryption implementation appearing anywhere in the tree.
- `CORS_ALLOW_ALL_ORIGINS = True`, or TLS verification disabled, in any
  committed configuration.
- Audit records becoming mutable.
- A share token stored in raw form.
