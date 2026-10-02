#!/usr/bin/env python3
"""Verify the nginx edge of a running SecureShare stack.

The functional end-to-end suite (scripts/verify_phase8_9.py) checks application
behaviour and is run with the test overlay, which relaxes rate limits. This
script covers what that overlay deliberately switches off, and must be run
against the UNMODIFIED production stack:

    sudo docker compose up -d
    SECURESHARE_CA_BUNDLE=./nginx/certs/server.crt \
        python3 scripts/verify_edge.py https://localhost:8443

It asserts that the edge:

  * terminates TLS and redirects plain HTTP to HTTPS
  * serves the React bundle, with SPA history fallback on deep links
  * routes /api to Django without the SPA shadowing it
  * refuses to serve the encrypted object store
  * applies the security headers
  * actually enforces the request rate limit (a burst must be rejected)

Certificate verification is never disabled. Point SECURESHARE_CA_BUNDLE at the
self-signed certificate and it is trusted as its own CA.
"""

from __future__ import annotations

import os
import ssl
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://localhost:8443").rstrip("/")

_CA = os.environ.get("SECURESHARE_CA_BUNDLE")
SSL_CONTEXT = ssl.create_default_context(cafile=_CA) if _CA else None

PASSED: list[str] = []
FAILED: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> bool:
    if condition:
        PASSED.append(label)
        print(f"  \033[32mPASS\033[0m  {label}")
    else:
        FAILED.append(f"{label} :: {detail}")
        print(f"  \033[31mFAIL\033[0m  {label}   {detail}")
    return bool(condition)


def fetch(
    path: str,
    *,
    method: str = "GET",
    follow: bool = True,
) -> tuple[int, bytes, dict[str, str]]:
    """Return (status, body, lowercased headers). Never raises on HTTP errors."""
    url = path if path.startswith("http") else BASE + path
    req = urllib.request.Request(url, method=method)

    opener_args: list = []
    if SSL_CONTEXT is not None:
        opener_args.append(urllib.request.HTTPSHandler(context=SSL_CONTEXT))
    if not follow:

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None

        opener_args.append(_NoRedirect)

    opener = urllib.request.build_opener(*opener_args)
    try:
        with opener.open(req, timeout=20) as resp:
            return (
                resp.status,
                resp.read(),
                {k.lower(): v for k, v in resp.headers.items()},
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            exc.read(),
            {k.lower(): v for k, v in exc.headers.items()},
        )
    except urllib.error.URLError as exc:
        return 0, str(exc).encode(), {}


def main() -> int:
    print(f"\n\033[1mSecureShare edge verification\033[0m  ({BASE})\n")

    # -- 1. TLS and redirect ------------------------------------------------
    print("\033[1m1. TLS termination\033[0m")
    status, _, _ = fetch("/api/health/")
    check("HTTPS endpoint answers", status == 200, str(status))

    http_base = BASE.replace("https://", "http://").replace(":8443", ":8080")
    status, _, headers = fetch(f"{http_base}/api/health/", follow=False)
    check(
        "plain HTTP is redirected to HTTPS",
        status in (301, 308) and headers.get("location", "").startswith("https://"),
        f"{status} {headers.get('location', '')}",
    )

    # -- 2. SPA -------------------------------------------------------------
    print("\n\033[1m2. Single-page application\033[0m")
    status, body, headers = fetch("/")
    check("root serves the SPA shell", status == 200 and b'id="root"' in body, str(status))
    check(
        "root is HTML, not JSON",
        headers.get("content-type", "").startswith("text/html"),
        headers.get("content-type", ""),
    )

    asset = None
    marker = b'src="/assets/'
    if marker in body:
        start = body.index(marker) + len('src="')
        asset = body[start : body.index(b'"', start)].decode()
    check("index references a hashed asset bundle", asset is not None, str(asset))

    if asset:
        status, abody, headers = fetch(asset)
        check("asset bundle downloads", status == 200 and len(abody) > 1000, str(status))
        check(
            "asset bundle is immutably cacheable",
            "immutable" in headers.get("cache-control", ""),
            headers.get("cache-control", ""),
        )
        check(
            "exactly one Cache-Control header",
            headers.get("cache-control", "").count("max-age") == 1,
            headers.get("cache-control", ""),
        )

    for deep in ("/login", "/files", "/s/anytoken", "/admin/users"):
        status, body, _ = fetch(deep)
        check(
            f"deep link {deep} falls back to the SPA",
            status == 200 and b'id="root"' in body,
            str(status),
        )

    # -- 3. API routing -----------------------------------------------------
    print("\n\033[1m3. API routing\033[0m")
    status, body, headers = fetch("/api/health/")
    check(
        "/api/health/ returns JSON, not the SPA",
        status == 200 and headers.get("content-type", "").startswith("application/json"),
        headers.get("content-type", ""),
    )
    check("health reports ok", b'"status":"ok"' in body.replace(b" ", b""), body[:120].decode(errors="replace"))
    check(
        "encryption keys usable (wrap/unwrap round trip)",
        b'"encryption_keys":"ok"' in body.replace(b" ", b""),
        body[:200].decode(errors="replace"),
    )

    status, _, _ = fetch("/api/no-such-route/")
    check("unknown API route 404s as JSON route, not SPA", status == 404, str(status))

    # -- 4. Encrypted store is not web-reachable ----------------------------
    print("\n\033[1m4. Encrypted object store\033[0m")
    for path in ("/storage/", "/storage/encrypted/", "/.env"):
        status, _, _ = fetch(path)
        check(f"{path} is not served", status in (403, 404), str(status))

    # A path that looks like a file must 404 rather than returning the SPA
    # shell. The decisive assertion is that no key material comes back.
    for path in ("/keys/rsa_private.pem", "/server.key", "/backend/.env"):
        status, body, _ = fetch(path)
        check(f"{path} 404s instead of serving the SPA", status == 404, str(status))
        check(
            f"{path} returns no key material",
            b"PRIVATE KEY" not in body and b"BEGIN" not in body,
            body[:80].decode(errors="replace"),
        )

    # -- 5. Security headers ------------------------------------------------
    print("\n\033[1m5. Security headers\033[0m")
    _, _, headers = fetch("/")
    expected = {
        "strict-transport-security": "max-age=",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "",
        "permissions-policy": "",
    }
    for name, needle in expected.items():
        value = headers.get(name, "")
        check(f"{name} present", bool(value) and needle in value, value or "absent")
    check("server version is not advertised", "nginx/" not in headers.get("server", ""), headers.get("server", ""))

    # -- 6. The rate limiter actually limits --------------------------------
    # This is the check the test overlay deliberately disables. Production
    # nginx allows 5 auth requests/minute with burst=5, so a rapid burst of
    # login attempts must start being rejected.
    print("\n\033[1m6. Rate limiting (production configuration)\033[0m")
    codes: list[int] = []
    for _ in range(25):
        status, _, _ = fetch("/api/auth/login/", method="POST")
        codes.append(status)
    rejected = sum(1 for c in codes if c == 429)
    check(
        "a rapid burst of auth requests is rate limited",
        rejected > 0,
        f"no 429 in 25 requests; codes={sorted(set(codes))}",
    )
    check(
        "limiter rejects rather than failing open",
        rejected >= 5,
        f"only {rejected} of 25 rejected",
    )
    print(f"         ({rejected} of 25 burst requests rejected with 429)")

    # -- summary ------------------------------------------------------------
    print(f"\n{'=' * 62}")
    if FAILED:
        print(f"\033[31m{len(FAILED)} of {len(PASSED) + len(FAILED)} checks FAILED\033[0m")
        for item in FAILED:
            print(f"  - {item}")
        print(f"{'=' * 62}\n")
        return 1
    print(f"\033[32mAll {len(PASSED)} edge checks passed.\033[0m")
    print(f"{'=' * 62}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
