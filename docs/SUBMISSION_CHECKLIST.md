# SecureShare GitHub submission checklist

## Repository hygiene
- [ ] Only the `secure-share/` project directory is included in the archive.
- [ ] No `.env` or other secret configuration files are committed.
- [ ] No RSA private/public key material is committed.
- [ ] No TLS private key/certificate generated for local use is committed.
- [ ] No uploaded/encrypted runtime files are committed.
- [ ] No database, Redis dump, logs, virtual environment, `node_modules`, or build output is committed.
- [ ] Accidental workspace files are absent.

## Verification
- [ ] Generate fresh local environment values from `.env.example`.
- [ ] Generate fresh RSA keys locally.
- [ ] Run backend checks/tests.
- [ ] Run frontend lint, typecheck, tests and build.
- [ ] Run the documented security checks.
- [ ] Run the live verification script against the intended deployment mode.

## Presentation
- [ ] Add only real, sanitized screenshots under `docs/screenshots/`.
- [ ] Confirm README commands match the current repository.
- [ ] Confirm the documentation links work.
- [ ] Confirm `LICENSE` is present.
- [ ] Confirm the repository is public/private according to the intended submission rules.

## Final Git check
Run `git status`, then inspect `git ls-files` and search the staged tree for secrets before the first push.
