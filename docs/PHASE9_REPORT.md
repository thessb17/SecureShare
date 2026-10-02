# Phase 9 — Admin & Security Dashboard: Completion Report

**Status: complete and verified.**
**Date of record:** 2 October 2026

Phase 9 adds an administrative console. The guiding constraint was that it
must be *backend-enforced* and *real*: no figure on any admin screen is
computed anywhere but in a database aggregate, and hiding a menu item is
never treated as access control.

---

## 1. Surface

### 1.1 Endpoints (`backend/dashboard/`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/dashboard/stats/` | Per-user dashboard (any authenticated user) |
| `GET` | `/api/admin/stats/` | Platform-wide metrics |
| `GET` | `/api/admin/users/` | User list; `?search=`, `?status=` |
| `GET` | `/api/admin/users/<uuid>/` | One user |
| `PATCH` | `/api/admin/users/<uuid>/` | Disable / re-enable |
| `POST` | `/api/admin/users/<uuid>/unlock/` | Clear a lockout |
| `GET` | `/api/admin/security-events/` | Event search |
| `GET` | `/api/admin/actions/` | `ADMIN_ACTION` feed |

Every `/api/admin/*` route carries an `IsAdmin` permission class. The React
console (`AdminDashboard`, `AdminUsers`, `AdminEvents`) is a renderer for these
endpoints and holds no authority of its own.

### 1.2 Metrics, and where each number comes from

| Section | Fields | Source |
|---|---|---|
| `users` | `total, active, disabled, admins, locked` | `User.objects` counts, `locked` = `locked_until__gt=now` |
| `files` | `total, active, deleted, encrypted_bytes, plaintext_bytes` | `File.objects` counts and `Sum` over non-deleted rows |
| `shares` | `active, expired, revoked` | `FileShare` bucketed on `revoked_at` / `expires_at` |
| `share_links` | `active, expired, revoked, total_downloads` | `ShareLink` likewise |
| `security` | `events_24h, failed_logins_24h, lockouts_24h, unauthorized_24h, rate_limited_24h` | `AuditLog` filtered by action within a rolling 24 h |

`test_admin_stats_counts_match_the_database` asserts each count equals a
freshly-computed ORM aggregate, so the figures cannot drift from reality.

---

## 2. Test results

### 2.1 New module: `backend/tests/test_phase9_admin.py` — **57 passed**

| Group | Tests | What it establishes |
|---|---|---|
| Access control | 15 | USER gets 403 and anonymous 401 on every admin endpoint; a USER cannot disable, unlock or self-promote; **`role` is not writable through this API even for an admin** |
| Metrics are real | 9 | Counts equal DB aggregates; disabling moves the `disabled` bucket; lockouts counted; shares bucketed correctly; failed logins counted inside the 24 h window and events outside it excluded; dashboard stats scoped per caller |
| User management | 10 | Disable/re-enable round trip; **a disabled account's existing access token stops working immediately**; an admin cannot disable themselves; lockouts clear; payloads never contain credentials; search and status filters; real per-user file counts; clean 404; input validation |
| Audit of admin acts | 5 | Disable, enable and unlock each emit `ADMIN_ACTION` carrying operation, target, reason, actor and IP; **a no-op update emits nothing** (no fabricated history); the action feed contains only `ADMIN_ACTION` |
| Event search | 11 | Filter by action, actor, outcome and date range; `security_only`; events span all users; newest-first; read-only to every write verb; **not even an admin can delete an audit record through the API**; malformed dates rejected; no tokens or key material in the payload |
| Console contracts | 6 | The exact payload shape each admin and dashboard screen renders |
| Harness | 1 | The suite genuinely runs under `config.settings.test` (§4.2) |

### 2.2 Full backend suite

```
533 passed, 378 warnings in 22.64s
TOTAL   3890 stmts   379 missed   90.3% coverage
```

Target was 80 %. Run twice — once in a clean shell and once with the project
`.env` exported — with identical results (see §4.2).

### 2.3 Live HTTP verification

`scripts/verify_phase8_9.py` sections 10 and 11 exercise the console against
the running server. From the passing run:

```
10. Admin APIs are backend-enforced (vertical escalation)
  PASS  USER gets 403 on /api/admin/stats/            PASS  anonymous gets 401 ...
  PASS  USER gets 403 on /api/admin/users/            PASS  anonymous gets 401 ...
  PASS  USER gets 403 on /api/admin/security-events/  PASS  anonymous gets 401 ...
  PASS  USER gets 403 on /api/admin/actions/          PASS  anonymous gets 401 ...
  PASS  USER gets 403 on /api/admin/test/             PASS  anonymous gets 401 ...
  PASS  USER cannot disable another account
  PASS  USER cannot unlock another account

11. Admin console with a real ADMIN account
  PASS  admin reads platform stats
  PASS  admin stats counts real users / real files / encrypted bytes on disk
  PASS  user list never exposes 'password' / 'token_version' / 'argon2' / 'pbkdf2'
  PASS  admin user search filters            PASS  admin user status filter works
  PASS  admin disables user B
  PASS  B's existing token stops working once disabled
  PASS  disabled B cannot sign in
  PASS  the disable emitted an ADMIN_ACTION event
  PASS  the ADMIN_ACTION names the operation and the target
  PASS  the ADMIN_ACTION records the acting admin
  PASS  admin re-enables user B              PASS  re-enabled B can sign in again
  PASS  admin cannot disable their own account
  PASS  admin can filter to security-relevant events / by user / by outcome
  PASS  security events never contain <account password> / <share password> / <raw token>
```

---

## 3. Security properties established

| Property | How it is enforced | Evidence |
|---|---|---|
| Admin APIs are closed to normal users | `IsAdmin` permission class on the view | 10 parametrised tests + 10 live checks |
| Hiding UI is not access control | The React guard and the server check are independent; tests call the API directly with a USER token | `test_normal_user_is_refused_every_admin_endpoint` |
| Privilege escalation is impossible through this surface | `role` is excluded from the writable fields | `test_role_is_not_writable_even_by_an_admin_through_this_endpoint` |
| Disabling takes effect immediately | Disable bumps `token_version`, invalidating issued JWTs | `test_disabling_an_account_invalidates_its_issued_tokens` |
| An admin cannot lock the platform out of itself | Self-disable returns 400 | `test_admin_cannot_disable_their_own_account` |
| Credentials never appear in admin payloads | Explicit serializer field list | 2 tests scanning the raw response body |
| Audit records resist tampering | `AuditLogQuerySet.update/delete` raise `AuditLogImmutableError`; no write verb is routed | `test_security_events_are_read_only`, `test_admin_cannot_delete_an_audit_record_through_the_api` |
| Admin actions are attributable | Every mutation emits `ADMIN_ACTION` with actor, target, operation, reason and IP | 3 tests |
| History is not fabricated | A no-op update writes no event | `test_a_no_op_update_does_not_fabricate_an_audit_event` |
| Filters cannot silently mislead | Unparseable dates are rejected, not ignored | `test_a_malformed_date_filter_is_rejected_not_silently_ignored` |

A note on the immutability guard: it is strong enough that the *tests* cannot
backdate a row through the ORM either. The historical fixtures in this module
use raw SQL via a `backdate()` helper, with a comment recording that nothing
in the application itself can perform that update.

---

## 4. Two defects found and fixed in this phase

### 4.1 A malformed date filter silently returned everything

Described in `docs/PHASE8_REPORT.md` §4.2. Found while writing
`test_a_malformed_date_filter_does_not_error` — the test passed, which was
itself the warning sign: it asserted a 200 while the filter was being quietly
discarded. An administrator investigating an incident would have been shown
the full log believing it was date-scoped. Now rejected with a 400, and a `+`
lost to URL decoding is tolerated.

### 4.2 The test suite could silently run against dev settings

**The more serious of the two.** `pytest.ini` declares
`DJANGO_SETTINGS_MODULE = config.settings.test`, but that ini key is only a
*default* — an exported environment variable beats it. The project `.env`
contains `DJANGO_SETTINGS_MODULE=config.settings.dev`, so any developer who
had sourced it (entirely normal when running the dev server) would run the
**entire suite against development settings**: `DEBUG = True`, the real Redis
cache instead of LocMemCache, production CORS origins and real throttle rates.

It surfaced here as three failures — `test_cors_rejects_unknown_origins`,
`test_celery_app_is_configured` and `test_brute_force_token_guessing_never_succeeds`
— in a run where `.env` happened to be sourced. The failures were the lucky
part. The danger was the other 530 tests that still passed while no longer
testing what they claimed to.

Fixed by adding `--ds=config.settings.test` to `addopts` in `pytest.ini`; a
command-line option outranks the environment variable. Guarded by
`test_the_suite_really_runs_against_the_test_settings`, which asserts on three
values unique to the test settings module. The suite now produces identical
results with and without `.env` exported:

```
clean shell        533 passed, 90.3% coverage
with .env exported 533 passed, 90.3% coverage
```

---

## 5. Static analysis

| Tool | Result |
|---|---|
| `ruff check .` | **All checks passed** |
| `bandit -r . -x ./tests` | **0 HIGH, 1 MEDIUM, 13 LOW** — unchanged from the Phase 6 baseline. The single MEDIUM is `B104` on `config/settings/dev.py:17` (binding `0.0.0.0` in the **development** server), reviewed and accepted. |
| `pip-audit -r requirements.txt -r requirements-dev.txt` | **No known vulnerabilities found** |
| `npm audit` | 5 moderate; see `docs/PHASE8_REPORT.md` §6 for the per-advisory assessment and the application-level mitigation |

---

## 6. Honest limitations

- **There is no admin UI for granting roles, by design.** `role` is read-only
  through the API; promoting a user is a deliberate out-of-band operation
  (`manage.py` / Django admin). This narrows the escalation surface but means
  role changes are not captured in the `ADMIN_ACTION` feed — they appear only
  in the Django admin log or shell history. A reviewer should know that.
- **Metrics are computed per request.** On a large deployment the 24-hour
  aggregates over `AuditLog` would need caching or a rollup table. At the
  scale this project targets, the queries are indexed and fast, and caching
  was rejected as premature in favour of figures that cannot be stale.
- **`locked` counts accounts whose `locked_until` is in the future**; it does
  not distinguish an automatic lockout from an administrative one.
- Admin screens were verified via API and jsdom component tests. There is no
  real-browser test of the console.
- The 24-hour security counters are a rolling window from "now", not calendar
  days, so they will not match a day-boundary report.
