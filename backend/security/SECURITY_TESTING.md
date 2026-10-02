# SecureShare — Security Testing

Everything in this document was executed against the code in this repository.
Raw tool output lives in [`security/reports/`](./reports). Re-run everything with:

```bash
cd backend
./security/run_security_checks.sh
```

Last run: Phase 6 (backend `0.6.0`), Python 3.13, Django 5.2.17, DRF 3.18.1, cryptography 50.0.2.

---

## 1. Summary

| Gate | Tool | Result |
|---|---|---|
| Automated test suite | pytest + pytest-django | **366 passed / 0 failed** |
| Backend coverage | pytest-cov | **89.4 %** (target ≥ 80 %) |
| Static security analysis | Bandit 1.9 | **0 HIGH, 1 MEDIUM, 13 LOW** — all triaged below, none exploitable |
| Linting incl. security rules | Ruff (`S` = flake8-bandit ruleset) | **0 findings** |
| Dependency CVEs (runtime) | pip-audit | **0 vulnerabilities** across 46 resolved packages |
| Dependency CVEs (dev) | pip-audit | **0 vulnerabilities** across 84 resolved packages |
| Deployment hardening | `manage.py check --deploy` (prod settings) | **0 issues, 0 silenced** |
| Live end-to-end attack/abuse run | `scripts/demo_phase6.py` | **53 / 53 checks passed** |

`npm audit` is **not applicable yet** — the React frontend is a later phase and no
`package.json` exists. The command is pre-wired in `run_security_checks.sh` and will
start reporting as soon as `frontend/` lands.

---

## 2. Test suite

```bash
cd backend
python -m pytest -q --cov --cov-report=term-missing
```

```
366 passed, 264 warnings in 19.62s
TOTAL   3688 statements   392 missed   89.4%
```

### Coverage by area

| Module group | Coverage | Notes |
|---|---|---|
| `accounts/` (auth, JWT, RBAC) | 94 % | |
| `files/` (upload, validation, download) | 92 % | |
| `sharing/` (shares + share links) | 94 % | `link_services.py` 98.8 % |
| `security/crypto.py` (AES-GCM / RSA-OAEP) | 97 % | |
| `security/keys.py` | 85 % | |
| `security/storage.py` | 80 % | uncovered lines are the optional S3 backend |
| `security/scanning.py` | 55 % | uncovered lines are the ClamAV **socket transport**, which needs a live `clamd`; the policy logic (fail-open/fail-closed) is covered |
| `audit/`, `core/` | 93 % | |

Lines that remain uncovered are concentrated in code paths that need external
infrastructure (S3, a running ClamAV daemon) rather than untested logic.

### Security-relevant test files

| File | Tests | What it proves |
|---|---:|---|
| `tests/test_auth.py` | 36 | registration, login, lockout, throttling, password policy, Argon2id, token revocation |
| `tests/test_rbac.py` | 12 | USER cannot reach ADMIN endpoints; role cannot be self-assigned |
| `tests/test_crypto.py` | 32 | AES-256-GCM, unique DEK/nonce per file, RSA-OAEP wrapping, tamper detection |
| `tests/test_files.py` | 44 | upload validation pipeline, IDOR, path traversal, checksum integrity |
| `tests/test_sharing.py` | 29 | user-to-user shares, permission escalation, expiry, revocation |
| `tests/test_share_links.py` | 53 | **Phase 6** happy paths + CRUD + presets + limits |
| `tests/test_share_link_security.py` | 77 | **Phase 6** attack scenarios (table below) |
| `tests/test_audit_and_hardening.py` | 27 | audit immutability, log redaction, security headers, error shape |
| `tests/test_security_components.py` | 26 | key rotation, passphrase keys, weak-key rejection, storage permissions, scanner fail-closed |
| `tests/test_upload_validation.py` | 25 | magic-byte sniffing, extension/MIME mismatch, zip bombs, entry-count guard |
| `tests/test_race_detection_sanity.py` | 1 | proves the concurrency harness can actually observe a race (negative control) |

---

## 3. Phase 6 attack scenarios — required list, all executed

Every item the brief demanded is a real, executed test.

| # | Scenario | Test | Result |
|---|---|---|---|
| 1 | Invalid token | `test_unknown_token_is_rejected`, `test_malformed_tokens_are_rejected` | 404 `SHARE_LINK_NOT_FOUND`, identical body to a revoked-link 404 (no oracle) |
| 2 | Expired token | `test_expired_link_cannot_be_read/downloaded` | 410 `SHARE_LINK_EXPIRED`, enforced server side from `expires_at` |
| 3 | Revoked token | `test_revoked_link_is_immediately_dead` | 410 `SHARE_LINK_REVOKED`, effective on the next request |
| 4 | Download limit | `test_download_limit_is_enforced`, `test_limit_of_one_allows_exactly_one` | 410 `SHARE_LINK_DOWNLOAD_LIMIT_REACHED` on attempt *n+1* |
| 5 | **Concurrent download race** | `test_two_simultaneous_downloads_cannot_both_succeed`, `test_concurrent_claims_cannot_exceed_the_limit_of_one` (16 threads), `test_concurrent_downloads_respect_a_limit_of_three` (20 threads) | exactly 1 / exactly 1 / exactly 3 winners — never more |
| 6 | Password protection | `test_password_protected_link_requires_a_password` | metadata withheld, 401 `SHARE_LINK_PASSWORD_REQUIRED` |
| 7 | Wrong password | `test_wrong_password_is_rejected` | 403 `SHARE_LINK_PASSWORD_INVALID`, no file bytes |
| 8 | Brute-force throttling | `test_repeated_failures_lock_the_link`, `test_lockout_blocks_even_the_correct_password`, `test_lockout_is_scoped_to_one_link` | 429 `SHARE_LINK_LOCKED` at attempt *N*; correct password also refused while locked; other links unaffected |
| 9 | Token guessing | `test_brute_force_token_guessing_never_succeeds` (1 000 guesses), `test_tokens_do_not_share_a_predictable_prefix`, `test_tokens_use_a_wide_alphabet` | 0 hits; 25 tokens share no 8-char prefix; >30 distinct characters |
| 10 | Unauthorized link modification | `test_non_owner_cannot_patch_a_link`, `test_recipient_cannot_extend_a_link` | 403/404; owner-only mutation |
| 11 | Authorization bypass | `test_share_token_is_not_a_bearer_token`, `test_link_grants_no_access_to_other_files`, `test_view_permission_cannot_download` | token is useless as a JWT; one link ⇒ exactly one file; VIEW ⇒ 403 on download |
| 12 | Tampered database values | `test_tampered_download_count_is_re_validated`, `test_tampered_permission_is_re_validated`, `test_plaintext_password_hash_fails_closed`, `test_swapped_token_hash`, `test_backdated_revoked_at` | every request re-derives authorization from the DB row; a plaintext `password_hash` fails **closed** |
| 13 | Ciphertext tampering | `test_tampered_ciphertext_is_detected` | AES-GCM tag failure ⇒ 422 + `FILE_INTEGRITY_FAILURE` audit event; no plaintext emitted |
| 14 | Token/password leakage | `test_creation_is_audited_without_the_raw_token`, `test_logs_never_contain_secrets` | raw token, share password and JWTs never appear in audit rows or log output |

### Concurrency harness (so the race result is trustworthy)

`test_race_detection_sanity.py` is a **negative control**: it runs the same
threaded harness against a deliberately unsafe read-modify-write and asserts
that it *does* overcount. The harness therefore demonstrably can see a race,
which is what makes the "exactly one winner" results meaningful.

Harness: `pytest.mark.django_db(transaction=True)` (real commits, no wrapping
transaction) + `threading.Barrier` so all workers fire simultaneously +
a fresh `APIClient` and DB connection per thread.

The slot claim itself is a single conditional statement, so the database — not
Python — arbitrates:

```sql
UPDATE sharing_sharelink
   SET download_count = download_count + 1
 WHERE id = %s
   AND revoked_at IS NULL
   AND (expires_at IS NULL OR expires_at > now())
   AND (max_downloads IS NULL OR download_count < max_downloads)
```

A claim succeeds only when the UPDATE reports exactly one affected row. The
same guarantee was reproduced over real HTTP in the live demo (10 concurrent
requests, `max_downloads=1` → `200s=1 410s=9`).

---

## 4. Static analysis — Bandit

```bash
python -m bandit -r . -x ./tests,./staticfiles
```

```
Total lines of code: 7348
Severity: High: 0   Medium: 1   Low: 13
```

Full report: [`security/reports/bandit.txt`](./reports/bandit.txt).
Baseline for CI: [`security/reports/bandit-baseline.json`](./reports/bandit-baseline.json)
(use `bandit -b security/reports/bandit-baseline.json` to fail only on *new* findings).

### Triage — all 14 findings

| ID | Location | Bandit says | Verdict |
|---|---|---|---|
| B104 (MED) | `config/settings/dev.py:17` | binding to all interfaces | **False positive / dev only.** `0.0.0.0` is an entry in the *development* `ALLOWED_HOSTS` default. `config/settings/prod.py` requires an explicit allow-list and refuses to boot with a wildcard. |
| B105 ×4 | `accounts/serializers.py:85,131,135,162` | hardcoded password | **False positive.** These are validation *error messages* ("The two password fields do not match."). |
| B105 | `accounts/tokens.py:47` | hardcoded password | **False positive.** The literal is `"Bearer"`, the auth scheme name. |
| B105 | `config/settings/base.py:231` | hardcoded password | **False positive.** The literal is the SimpleJWT setting key `"token_type"`. |
| B105 ×3 | `sharing/link_services.py:469,471,472` | hardcoded password | **False positive.** Audit markers `"set"` / `""` / `"removed"` written to the change log *instead of* the password, which is exactly the control we want. |
| B105 | `sharing/views.py:60` | hardcoded password | **False positive.** HTTP header *name* `X-Share-Password`. |
| B105 ×3 | `sharing/views.py:422,463,475` | hardcoded password | **False positive.** The literals are `"True"`/`"False"` in `password_required` response payloads. |

**Zero true positives.** Note what Bandit did *not* find: no `eval`/`exec`, no
`subprocess` with `shell=True`, no `pickle`, no MD5/SHA-1 used for security, no
`verify=False`, no hardcoded cryptographic key material, no `assert` used for
authorization, no SQL string interpolation.

---

## 5. Linting with security rules — Ruff

`backend/ruff.toml` enables `S` (flake8-bandit), plus `B` (bugbear), `DTZ`
(timezone-naive datetimes — relevant because every expiry decision is a
datetime comparison), `T20` (stray `print`), `SIM`, `A`, `C4`, `I`, `E`, `W`, `F`, `RUF`.

```bash
python -m ruff check .
All checks passed!
```

Findings fixed while reaching zero (not suppressed):

- 11 unused imports and 7 unsorted import blocks removed.
- 4 `if key in data` lookups replaced with `data.get(key, ...)`.
- 3 `pytest.raises(Exception)` assertions narrowed to `SecurityError`, so a
  test can no longer pass because of an unrelated crash.
- 2 dict comprehensions simplified; 29 stale `# noqa` comments removed.

The 7 remaining suppressions are all inline, single-rule and carry a reason
(e.g. `# noqa: S505 - deliberately weak: the provider must reject it`), so a
reviewer sees the justification at the call site. `ruff format` is intentionally
**not** part of the gate — the codebase uses hand-wrapped 95-column formatting.

---

## 6. Dependency vulnerabilities — pip-audit

```bash
python -m pip_audit -r requirements.txt       # No known vulnerabilities found
python -m pip_audit -r requirements-dev.txt   # No known vulnerabilities found
```

| File | Packages resolved | Vulnerabilities |
|---|---:|---:|
| `requirements.txt` (runtime) | 46 | **0** |
| `requirements-dev.txt` (tooling) | 84 | **0** |

JSON: [`pip-audit-prod.json`](./reports/pip-audit-prod.json),
[`pip-audit-dev.json`](./reports/pip-audit-dev.json).

> Auditing the *sandbox interpreter* instead of the requirements files reports
> CVEs in `nltk`, `tornado`, `urllib3` and `pip`. Those packages are pre-installed
> in the development container and are **not** SecureShare dependencies — none of
> them appear in either requirements file or in the Docker image, which installs
> only `requirements.txt`. Always audit the requirements files, not the ambient
> environment.

Security-critical pins: `cryptography==50.0.2`, `Django==5.2.17` (LTS line),
`djangorestframework==3.18.1`, `argon2-cffi==25.1.0`, `psycopg==3.3.6`.

---

## 7. Django deployment hardening

```bash
DJANGO_SETTINGS_MODULE=config.settings.prod ... python manage.py check --deploy
System check identified no issues (0 silenced).
```

Zero warnings, nothing silenced. The settings that earn that result:

| Control | Setting |
|---|---|
| Debug off | `DEBUG = False` (default everywhere; prod **raises** if forced on) |
| HSTS | `SECURE_HSTS_SECONDS = 31536000`, `INCLUDE_SUBDOMAINS`, `PRELOAD` |
| TLS redirect | `SECURE_SSL_REDIRECT = True`, `SECURE_PROXY_SSL_HEADER` for nginx |
| Cookies | `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `HttpOnly`, `SameSite=Lax` |
| Sniffing / framing | `X-Content-Type-Options: nosniff`, `X_FRAME_OPTIONS = DENY` |
| Referrer | `same-origin` |
| CSP | `default-src 'none'` + explicit allowances, via custom middleware |
| Host header | explicit `ALLOWED_HOSTS`; wildcards rejected at startup |
| CORS | explicit `CORS_ALLOWED_ORIGINS`; `CORS_ALLOW_ALL_ORIGINS` is **blocked** in prod |
| Secrets | `SECRET_KEY`/`JWT_SIGNING_KEY` must be set, ≥ 50 chars, and not the dev value |

A startup self-check in `config/settings/prod.py` raises `ImproperlyConfigured`
rather than booting insecurely — tested by `test_audit_and_hardening.py`.

---

## 8. Manual / live verification

`python scripts/demo_phase6.py` drives the **running** server over HTTP and
asserts 53 conditions, including the abuse cases: limit exhaustion, four classes
of bad token, password lockout, a 10-thread download race, immediate revocation,
cross-user authorization, and a scan of the audit log proving no raw token,
share password or account password was ever recorded. Latest run: **all passed**.
Transcript in [`docs/PHASE6_DEMO.md`](../../docs/PHASE6_DEMO.md).

---

## 9. Known gaps and limitations

1. **ClamAV transport is untested in CI** — `CLAMAV_ENABLED=False` by default and
   no `clamd` runs in the test environment. The decision logic is covered; the
   socket code is not. With `CLAMAV_FAIL_CLOSED=True` an unreachable scanner
   rejects the upload rather than letting it through.
2. **Mid-stream download failure does not refund a claimed slot.** If the
   connection drops after the slot is claimed but before the last byte, the
   download still counts. Fail-closed by choice; a compensating refund would
   let an attacker farm free downloads by aborting connections.
3. **Password lockout state lives in Redis.** Flushing Redis clears lockout
   counters. Use a persistent Redis (AOF) in production.
4. **No rate limiting at the edge yet.** DRF throttles cover the API; the nginx
   config ships `limit_req` zones but tuning them for real traffic is deployment work.
5. **At-rest encryption protects the object store, not the database.** Filenames,
   sizes and audit metadata are stored in plaintext columns; wrapped DEKs and
   file bytes are encrypted. Use disk-level encryption for the DB volume.
6. **No HSM/KMS integration.** The RSA private key is loaded from a file or
   environment variable. `keys.py` already supports key rotation with retired
   keys, which is the hook a KMS backend would plug into.
7. **`npm audit` pending** the frontend phase.
