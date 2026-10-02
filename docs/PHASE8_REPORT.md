# Phase 8 — React Frontend: Completion Report

**Status: complete and verified against the real backend.**
**Date of record:** 2 October 2026

Every figure below came from a command executed in this workspace. No result
is estimated or carried over from a previous phase.

---

## 1. What was built

A complete React 19 + Vite 6 + TypeScript + Tailwind + React Router 6 + Axios
single-page application in `frontend/`, talking to the real Django API. There
are **no mock APIs, no fixture data and no placeholder screens** — every number
rendered is fetched from a live endpoint, and every button issues a real
request.

### 1.1 Pages (17 + 3 admin)

| Route | Component | Purpose |
|---|---|---|
| `/` | `Landing` | Public marketing / entry page |
| `/login` | `Login` | Sign in, lockout and rate-limit messaging |
| `/register` | `Register` | Account creation with live password policy feedback |
| `/forgot-password` | `ForgotPassword` | Reset request (no account enumeration) |
| `/app` | `Dashboard` | Real counts, storage, shares, links, recent activity |
| `/app/files` | `MyFiles` | Name, size, type, created, encryption status, actions |
| `/app/upload` | `Upload` | Drag-drop + picker, progress, validation, result |
| `/app/files/:id` | `FileDetails` | Metadata, encryption detail, access, history |
| `/app/files/:id/share` | `ShareFile` | User-to-user share + public link builder |
| `/app/shared-with-me` | `SharedWithMe` | Inbound shares and their permissions |
| `/app/share-links` | `ShareLinks` | Link inventory, status, revocation |
| `/app/audit` | `AuditLogs` | The caller's own audit trail, filterable |
| `/app/profile` | `Profile` | Profile, password change, session revocation |
| `/s/:token` | `PublicShare` | Anonymous recipient view |
| `/app/admin` | `AdminDashboard` | Platform metrics (ADMIN only) |
| `/app/admin/users` | `AdminUsers` | User management (ADMIN only) |
| `/app/admin/events` | `AdminEvents` | Security event search (ADMIN only) |
| `*` | `NotFound` | 404 |
| — | `ErrorPage` / `ErrorBoundary` | Render-error containment |

All routes except the landing/auth area are lazy-loaded: the build emits **15
route chunks** alongside the main bundle.

### 1.2 Security posture of the client

| Concern | Decision |
|---|---|
| Access token | **Memory only.** Never written to any web storage. |
| Refresh token | `sessionStorage` under `secureshare.refresh`. A deliberate, documented trade-off — the backend returns the refresh token in the JSON body, and `sessionStorage` dies with the tab. See §5. |
| Enforcement of `localStorage` ban | `eslint.config.js` has a `no-restricted-globals` rule on `localStorage`; `client.test.ts` asserts the access token never appears there. |
| 401 handling | A single refresh in flight, with a queue; concurrent 401s wait for one refresh rather than stampeding. A failed refresh signs the user out and shows `SessionExpiredBanner`. |
| Login 401 | Deliberately does **not** trigger a refresh attempt. |
| Authorization | Route guards are **convenience only**. Every check in §3 is enforced server-side and tested there. |
| Redirect targets | Funnelled through `safeInternalPath()` — see §6. |
| Error text | Server error codes are mapped through a `FRIENDLY` table; raw server strings are never rendered. |

---

## 2. Gate results

Executed on 2 October 2026.

| Gate | Command | Result |
|---|---|---|
| Types | `npm run typecheck` (`tsc -b --force`) | **clean** |
| Lint | `npm run lint` (`eslint . --max-warnings 0`) | **clean, 0 problems** |
| Unit/component tests | `npx vitest run` | **53 passed / 53**, 4 files, 4.02 s |
| Production build | `npm run build` | **success**, vite 6.4.3, 118 modules, 2.15 s |

Build output:

```
dist/index.html                           0.70 kB │ gzip:  0.41 kB
dist/assets/index-B5sXTb0F.css           27.87 kB │ gzip:  5.40 kB
dist/assets/index-DzDbTpQj.js           263.94 kB │ gzip: 86.46 kB
  + 15 lazily-loaded route chunks (0.54 kB – 9.30 kB)
```

### 2.1 Test inventory (53)

| File | Count | Covers |
|---|---|---|
| `src/test/client.test.ts` | 13 | Token storage policy, interceptors, error normalisation, the full 401/refresh matrix |
| `src/test/guards.test.tsx` | 7 | `RequireAuth` / `RequireAdmin` / `RedirectIfAuthenticated` for anonymous, USER and ADMIN, driven through the **real** `AuthProvider` restore path |
| `src/test/pages.test.tsx` | 14 | Login (bad credentials, `ACCOUNT_LOCKED`, `RATE_LIMIT_EXCEEDED`), Upload (client-side oversize rejection sends zero requests, AES-256-GCM confirmation, `UNSUPPORTED_FILE_TYPE`), PublicShare (live, password prompt, wrong password, expired, revoked, limit exhausted, VIEW-only, limit hit mid-download) |
| `src/test/navigation.test.ts` | 19 | Open-redirect guard (§6) |

---

## 3. Verification against the real backend

A dedicated harness, **`scripts/verify_phase8_9.py`**, drives the live API over
HTTP with a real PDF. It registers its own users each run, so it depends on no
pre-seeded state.

It was executed against **three** different front doors, and passed all
**136** checks in each:

| Target | What it proves |
|---|---|
| `http://127.0.0.1:8100` — Gunicorn, `config.settings.prod` | The API behaves correctly with `DEBUG = False` and production middleware. |
| `http://127.0.0.1:5173` — Vite dev server | The exact path a developer's browser takes: relative `/api` → dev proxy → Django. |
| `http://127.0.0.1:4173` — built `dist/` + reverse proxy | The **production bundle** is served correctly, SPA deep links resolve, and `/api` proxying works as nginx will do it. |

```
==============================================================
All 136 checks passed.
==============================================================
```

### 3.1 What those 136 checks cover

1. **Health** — `/api/health/` reports db, redis, storage and encryption keys OK.
2. **Auth** — registration, login, wrong-password rejection, `users/me`, anonymous rejection, and that no response body contains a password field.
3. **Dashboard** — the stats payload has the exact shape the React dashboard renders, and a brand-new account correctly reads zero.
4. **Upload / encryption** — a real PDF uploads; the response reports `AES-256-GCM-STREAM-V1` and `RSA-OAEP-SHA256-MGF1-SHA256`; ciphertext exceeds plaintext; and the payload leaks none of `stored_object_id`, `wrapped_dek`, a filesystem path, or key material.
5. **Download** — byte-for-byte round trip (`downloaded == original`), valid PDF magic, filename in `Content-Disposition`.
6. **Authorization** — B cannot read, download or delete A's private file; anonymous cannot either; B's listing is empty.
7. **User-to-user sharing** — VIEW grants metadata but **not** download; B cannot re-share, cannot escalate the permission, cannot delete the share; A upgrades to DOWNLOAD and B succeeds; A revokes and B loses both download and metadata access.
8. **Public links** — 1-hour expiry, 2-download limit, password. Locked state hides the filename; a wrong password is refused; the correct one returns a grant; downloads 1 and 2 succeed and **download 3 is rejected with `SHARE_LINK_DOWNLOAD_LIMIT_REACHED` (410)**; a guessed token 404s; a revoked link 410s; B cannot revoke A's link.
9. **Audit** — A reads their own trail; it contains `FILE_UPLOADED`, `FILE_SHARED`, `SHARE_LINK_CREATED`; it contains neither the account password, the share password, the raw token nor key material; B cannot see A's entries; POST/PUT/PATCH/DELETE are all refused.
10. **Admin RBAC** — a normal USER receives **403** on all five admin endpoints and anonymous receives **401**; a USER cannot disable or unlock an account.
11. **Admin console** — covered in the Phase 9 report.
12. **Response hardening** — `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `X-Frame-Options`, `Content-Security-Policy` and `Permissions-Policy` all present; no traceback on an unknown id; JSON (not HTML) for an unknown route.
13. **Deletion** — the file disappears and links to it stop resolving.

---

## 4. Two real defects found and fixed during verification

### 4.1 jsdom `Blob` has no `.text()` — download errors degraded silently

File downloads use `responseType: 'blob'`, so an error response arrives as a
Blob rather than JSON. `normaliseBlobError` called `blob.text()` directly.
That method is absent in jsdom *and in Safari < 14 and legacy Edge*, so the
parse failed and every blob error collapsed to the generic
`REQUEST_FAILED` — a user who hit a download limit would have been told
"Something went wrong" instead of the real reason.

Fixed by adding a `readBlobText()` helper in `src/api/client.ts` that prefers
`blob.text()` and falls back to `FileReader.readAsText`. This fixes real
browsers, not just the test environment.

### 4.2 A malformed date filter silently disabled the admin filter

`AdminSecurityEventsView` used `if since and (parsed := parse_datetime(since))`.
An unparseable value made the condition false and the filter was **dropped
without comment** — an administrator would see the entire event log while the
UI indicated a date range was active. That is a misleading-security-control
defect, not a cosmetic one.

Now `_parse_bound()` raises `ValidationError` for an unusable value, and
tolerates a `+` that URL decoding turned into a space. Covered by
`test_a_malformed_date_filter_is_rejected_not_silently_ignored` and
`test_a_plus_lost_to_url_decoding_is_still_understood`.

---

## 5. Honest limitations

- **The refresh token is reachable by JavaScript.** It lives in
  `sessionStorage`, so a successful XSS could steal it. The structural fix is a
  `HttpOnly; Secure; SameSite` refresh cookie, which requires a backend change
  that is out of scope for this phase. Mitigations in place: a strict CSP, the
  access token never leaving memory, `sessionStorage` being cleared when the
  tab closes, and `token_version` invalidation on password change and
  session revocation. **This is a known residual risk, not a solved problem.**
- Route guards in React are a usability affordance. They are not a security
  boundary and are not relied upon as one; §3.6, §3.7 and §3.10 verify the
  server refuses independently.
- The verification harness checks HTTP behaviour and the DOM through jsdom. It
  is not a real-browser test — there is no Playwright/Cypress layer, so visual
  rendering, actual drag-and-drop gestures and cross-browser behaviour remain
  manually verified only.
- `scripts/serve_dist.py` approximates nginx for local verification. It is a
  test harness, **not** production infrastructure; the real deployment path is
  the nginx config exercised in Phase 11.

---

## 6. Dependency advisories (`npm audit`)

5 moderate advisories, 2 of which reach production code. **We are already on
the newest release of every affected package in its current major line** — no
patched version exists short of a breaking major upgrade, which the project
brief forbids taking blindly.

| Package | Advisory | Reaches prod? | Assessment and action |
|---|---|---|---|
| `react-router` 6.30.6 | [GHSA-wrjc-x8rr-h8h6](https://github.com/advisories/GHSA-wrjc-x8rr-h8h6) — open redirect via backslash in `<Link>` / `useNavigate` | **Yes** | **Mitigated in application code.** Every redirect target now passes through `safeInternalPath()` (`src/utils/navigation.ts`), which accepts only a single-slash-rooted local path and rejects protocol-relative, backslash, absolute-URL, scheme-injection, control-character and percent-encoded variants. 19 tests in `navigation.test.ts`, including an assertion that the result can never resolve to a foreign origin. |
| `react-router` 6.30.6 | [GHSA-337j-9hxr-rhxg](https://github.com/advisories/GHSA-337j-9hxr-rhxg) — constructor injection via `deserializeErrors()` | **No** | The vulnerable path is React Router's framework/RSC server-data mode. This app uses `BrowserRouter` in library mode with no server-side data APIs, so `deserializeErrors()` is never reached. |
| `vitest`, `@vitest/mocker` 3.2.7 | [GHSA-82fw-gwwq-j7x9](https://github.com/advisories/GHSA-82fw-gwwq-j7x9) — path traversal in the dev server | **No** | Dev dependency; never built into `dist/` and never run in production. |

The fixed versions are `react-router-dom@7` and a vitest major. Both are
breaking changes and are recorded as deliberate deferrals here rather than
being applied unverified. Re-evaluated in Phase 10.

---

## 7. Reproducing this

```bash
# backend (terminal 1)
cd backend
set -a && source ../.env && set +a
export DJANGO_SETTINGS_MODULE=config.settings.prod SECURE_SSL_REDIRECT=False
export ALLOWED_HOSTS=127.0.0.1,localhost,0.0.0.0
gunicorn config.wsgi:application --bind 0.0.0.0:8100 --workers 3 --threads 4 \
  --worker-class gthread

# frontend (terminal 2)
cd frontend && npm install
npm run typecheck && npm run lint && npx vitest run && npm run build
VITE_API_TARGET=http://127.0.0.1:8100 npm run dev -- --host 0.0.0.0

# live verification (terminal 3) - any of the three front doors
python3 scripts/verify_phase8_9.py http://127.0.0.1:8100   # API direct
python3 scripts/verify_phase8_9.py http://127.0.0.1:5173   # via Vite
python3 scripts/serve_dist.py 4173 http://127.0.0.1:8100 & # built bundle
python3 scripts/verify_phase8_9.py http://127.0.0.1:4173
```

If the harness exits 3, the register/share throttles have tripped from a
previous run. Clear them:

```bash
redis-cli --scan --pattern '*throttle*' | xargs -r redis-cli DEL
```
