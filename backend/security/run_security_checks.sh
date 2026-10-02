#!/usr/bin/env bash
# Run every security gate used in security/SECURITY_TESTING.md.
# Usage:  cd backend && ./security/run_security_checks.sh
set -uo pipefail

cd "$(dirname "$0")/.."
REPORTS="security/reports"
mkdir -p "$REPORTS"
status=0

hr() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
note() { printf '   %s\n' "$1"; }
fail() { printf '\033[31m   FAILED: %s\033[0m\n' "$1"; status=1; }

hr "1/6 Ruff (lint + flake8-bandit security rules)"
if python -m ruff check . --output-format concise | tee "$REPORTS/ruff.txt"; then
  note "clean"
else
  fail "ruff reported findings"
fi

hr "2/6 Bandit (static security analysis)"
python -m bandit -r . -x ./tests,./staticfiles,./security/reports \
  -f txt -o "$REPORTS/bandit.txt" -q
python -m bandit -r . -x ./tests,./staticfiles,./security/reports \
  -f json -o "$REPORTS/bandit-latest.json" -q
python - <<'PY' || status=1
import json, sys
totals = json.load(open("security/reports/bandit-latest.json"))["metrics"]["_totals"]
high, medium, low = (totals[f"SEVERITY.{level}"] for level in ("HIGH", "MEDIUM", "LOW"))
print(f"   HIGH={high} MEDIUM={medium} LOW={low}  (see security/reports/bandit.txt)")
sys.exit(1 if high else 0)   # only HIGH blocks; MED/LOW are triaged in SECURITY_TESTING.md
PY

hr "3/6 pip-audit (dependency CVEs)"
python -m pip_audit -r requirements.txt --progress-spinner off \
  | tee "$REPORTS/pip-audit-prod.txt" || fail "runtime dependencies have CVEs"
python -m pip_audit -r requirements-dev.txt --progress-spinner off \
  | tee "$REPORTS/pip-audit-dev.txt" || fail "dev dependencies have CVEs"

hr "4/6 Django deployment check (production settings)"
DJANGO_SETTINGS_MODULE=config.settings.prod \
SECRET_KEY="${SECRET_KEY:-$(python -c 'import secrets;print(secrets.token_urlsafe(50))')}" \
JWT_SIGNING_KEY="${JWT_SIGNING_KEY:-$(python -c 'import secrets;print(secrets.token_urlsafe(50))')}" \
DATABASE_URL="${DATABASE_URL:-postgresql://u:p@127.0.0.1:5432/secureshare}" \
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}" \
ALLOWED_HOSTS="${ALLOWED_HOSTS:-secureshare.example.com}" \
CSRF_TRUSTED_ORIGINS="${CSRF_TRUSTED_ORIGINS:-https://secureshare.example.com}" \
CORS_ALLOWED_ORIGINS="${CORS_ALLOWED_ORIGINS:-https://secureshare.example.com}" \
PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-https://secureshare.example.com}" \
  python manage.py check --deploy 2>&1 | tee "$REPORTS/django-check-deploy.txt" \
  || fail "deployment check reported issues"

hr "5/6 Test suite with coverage"
python -m pytest -q --cov --cov-report=term:skip-covered \
  --cov-report=html:../htmlcov || fail "tests failed"

hr "6/6 npm audit (frontend)"
if [ -f ../frontend/package.json ]; then
  (cd ../frontend && npm audit --audit-level=high | tee "../backend/$REPORTS/npm-audit.txt") \
    || fail "npm audit reported high severity issues"
else
  note "skipped - no frontend/package.json yet (frontend is a later phase)"
fi

hr "Result"
[ "$status" -eq 0 ] && printf '\033[32m   All security gates passed.\033[0m\n' \
                    || printf '\033[31m   One or more gates failed.\033[0m\n'
printf '   Reports: backend/%s\n\n' "$REPORTS"
exit "$status"
