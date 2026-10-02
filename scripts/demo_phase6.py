#!/usr/bin/env python3
"""Phase 6 end-to-end demonstration against a RUNNING SecureShare server.

    python scripts/demo_phase6.py [--base-url http://127.0.0.1:8000]

Nothing here is simulated: every step is a real HTTP request against the live
API, hitting PostgreSQL, Redis and the encryption engine. The script exits
non-zero if any expectation fails, so it doubles as a smoke test.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import secrets
import sys

import requests

PASSWORD = "Demo!Passphrase#2026"
LINK_PASSWORD = "Sh4re-Link!Secret"

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
failures: list[str] = []


def section(title: str) -> None:
    print(f"\n{BOLD}{title}{RESET}\n" + "-" * len(title))


def check(label: str, condition: bool, detail: str = "") -> None:
    mark = f"{GREEN}PASS{RESET}" if condition else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {label}" + (f" {DIM}({detail}){RESET}" if detail else ""))
    if not condition:
        failures.append(label)


def register(session: requests.Session, api: str, label: str) -> tuple[str, str]:
    """Register a throwaway account and return (email, access token).

    Registration is deliberately throttled, so a second demo run from the same
    IP within the window gets a 429. That is the control working correctly -
    report it clearly instead of dying on a KeyError.
    """
    email = f"{label}-{secrets.token_hex(4)}@example.com"
    response = session.post(
        f"{api}/auth/register/",
        json={"email": email, "password": PASSWORD, "password_confirm": PASSWORD,
              "full_name": f"Demo {label}"},
        timeout=15,
    )
    if response.status_code == 429:
        retry = response.json().get("retry_after", "a while")
        print(f"\n{RED}Registration is rate limited (HTTP 429).{RESET}")
        print("This is the anti-abuse throttle doing its job, not a failure.")
        print(f"Retry in ~{retry}s, or clear the counters in a dev environment:")
        print("  redis-cli --scan --pattern '*throttle*' | xargs -r redis-cli DEL")
        sys.exit(3)
    if response.status_code != 201:
        print(f"{RED}Registration failed: HTTP {response.status_code} {response.text[:200]}{RESET}")
        sys.exit(3)
    return email, response.json()["tokens"]["access"]


def build_pdf(text: str) -> bytes:
    content = f"BT /F1 18 Tf 20 100 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>"
        ),
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for index, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode() + b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode()
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    api = f"{base}/api"

    owner = requests.Session()
    public = requests.Session()  # never authenticated - a stranger with a link

    # ---------------------------------------------------------------- health
    section("0. Service health (real DB / Redis / storage / key probes)")
    health = requests.get(f"{api}/health/", timeout=10)
    print(f"  {DIM}{health.status_code} {health.text}{RESET}")
    check("health endpoint reports ok", health.json().get("status") == "ok")
    for dependency in ("database", "redis", "storage", "encryption_keys"):
        check(f"{dependency} probe ok", health.json().get(dependency) == "ok")

    # ------------------------------------------------------------- accounts
    section("1. Account + authentication")
    email, access = register(owner, api, "owner")
    owner.headers["Authorization"] = f"Bearer {access}"
    check("owner registered", bool(email))
    check("JWT issued", bool(access))

    # --------------------------------------------------------------- upload
    section("2. Upload + envelope encryption (AES-256-GCM / RSA-OAEP)")
    pdf = build_pdf("SecureShare Phase 6 demo document")
    digest = hashlib.sha256(pdf).hexdigest()
    upload = owner.post(
        f"{api}/files/upload/",
        files={"file": ("phase6-demo.pdf", pdf, "application/pdf")},
        timeout=30,
    )
    check("file uploaded", upload.status_code == 201, str(upload.status_code))
    file_id = upload.json()["id"]
    print(f"  {DIM}file id {file_id}{RESET}")
    check("server detected the MIME type", upload.json()["mime_type"] == "application/pdf")
    check("checksum matches the plaintext", upload.json()["checksum_sha256"] == digest)
    check("stored encrypted", upload.json()["encryption"]["encrypted"] is True,
          upload.json()["encryption"]["algorithm"])
    check("no storage path in the response", "stored_object_id" not in upload.text)

    # --------------------------------------------------------- create a link
    section("3. Create a public share link (24h, 2 downloads)")
    created = owner.post(
        f"{api}/files/{file_id}/share-link/",
        json={"expires_in": "24h", "max_downloads": 2, "permission": "DOWNLOAD"},
        timeout=15,
    )
    check("link created", created.status_code == 201, str(created.status_code))
    payload = created.json()
    token = payload["token"]
    link_id = payload["share_link"]["id"]
    print(f"  {DIM}url     {payload['url']}{RESET}")
    print(f"  {DIM}expires {payload['expires_at']}{RESET}")
    check("token is 256-bit url-safe", len(token) >= 43)
    check("token prefix stored, not the token",
          payload["share_link"]["token_prefix"] == hashlib.sha256(token.encode()).hexdigest()[:12])
    check("raw token not returned again",
          token not in owner.get(f"{api}/share-links/{link_id}/", timeout=10).text)

    # ------------------------------------------------------ anonymous access
    section("4. Anonymous access with the link")
    metadata = public.get(f"{api}/share/{token}/", timeout=10)
    check("stranger reads metadata", metadata.status_code == 200)
    check("filename exposed, internals hidden",
          metadata.json().get("filename") == "phase6-demo.pdf"
          and "stored_object_id" not in metadata.text)

    first = public.post(f"{api}/share/{token}/download/", json={}, timeout=30)
    check("download 1 succeeds", first.status_code == 200, str(first.status_code))
    check("bytes are byte-identical to the original",
          hashlib.sha256(first.content).hexdigest() == digest)
    check("remaining counter returned", first.headers.get("X-Share-Downloads-Remaining") == "1")

    second = public.post(f"{api}/share/{token}/download/", json={}, timeout=30)
    check("download 2 succeeds", second.status_code == 200)
    third = public.post(f"{api}/share/{token}/download/", json={}, timeout=30)
    check("download 3 blocked by the limit", third.status_code == 410,
          third.json().get("error", ""))

    # ------------------------------------------------------------- bad token
    section("5. Invalid / guessed tokens")
    for label, bad in (
        ("random guess", secrets.token_urlsafe(32)),
        ("truncated real token", token[:-1]),
        ("token hash", hashlib.sha256(token.encode()).hexdigest()),
        ("file uuid", file_id.replace("-", "")),
    ):
        response = public.get(f"{api}/share/{bad}/", timeout=10)
        check(f"{label} rejected", response.status_code == 404, str(response.status_code))

    # ------------------------------------------------------ password + brute
    section("6. Password protected link, wrong password, lockout")
    protected = owner.post(
        f"{api}/files/{file_id}/share-link/",
        json={"expires_in": "1h", "password": LINK_PASSWORD},
        timeout=15,
    ).json()
    ptoken = protected["token"]

    locked_meta = public.get(f"{api}/share/{ptoken}/", timeout=10)
    check("metadata hidden until unlocked",
          locked_meta.json().get("password_required") is True
          and "filename" not in locked_meta.json())
    check("download without password -> 401",
          public.post(f"{api}/share/{ptoken}/download/", json={}, timeout=15).status_code == 401)
    wrong = public.post(f"{api}/share/{ptoken}/download/",
                        json={"password": "wrong-guess"}, timeout=15)
    check("wrong password -> 403", wrong.status_code == 403, wrong.json().get("error", ""))

    grant_response = public.post(f"{api}/share/{ptoken}/verify-password/",
                                 json={"password": LINK_PASSWORD}, timeout=15)
    check("correct password -> grant", grant_response.status_code == 200)
    grant = grant_response.json()["grant"]
    unlocked = public.post(f"{api}/share/{ptoken}/download/",
                           json={"grant": grant}, timeout=30)
    check("download with grant succeeds", unlocked.status_code == 200)
    check("downloaded bytes are correct",
          hashlib.sha256(unlocked.content).hexdigest() == digest)

    brute = owner.post(
        f"{api}/files/{file_id}/share-link/",
        json={"expires_in": "1h", "password": LINK_PASSWORD}, timeout=15,
    ).json()["token"]
    codes = [
        public.post(f"{api}/share/{brute}/verify-password/",
                    json={"password": f"guess-{index}"}, timeout=15).status_code
        for index in range(5)
    ]
    check("brute force ends in a lockout", codes[-1] == 429, f"codes={codes}")
    check("correct password also locked out",
          public.post(f"{api}/share/{brute}/verify-password/",
                      json={"password": LINK_PASSWORD}, timeout=15).status_code == 429)

    # ----------------------------------------------------------- concurrency
    section("7. Concurrent download race (max_downloads = 1)")
    racy = owner.post(
        f"{api}/files/{file_id}/share-link/",
        json={"expires_in": "1h", "max_downloads": 1}, timeout=15,
    ).json()["token"]

    def attempt(_: int) -> int:
        session = requests.Session()
        return session.post(f"{api}/share/{racy}/download/", json={}, timeout=60).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(pool.map(attempt, range(10)))
    check("exactly one request won", statuses.count(200) == 1,
          f"200s={statuses.count(200)} 410s={statuses.count(410)}")

    # ------------------------------------------------------------- revocation
    section("8. Revocation takes effect immediately")
    revoke_token = owner.post(
        f"{api}/files/{file_id}/share-link/", json={"expires_in": "1h"}, timeout=15
    ).json()
    rtoken = revoke_token["token"]
    check("link works before revocation",
          public.get(f"{api}/share/{rtoken}/", timeout=10).status_code == 200)
    deleted = owner.delete(f"{api}/share-links/{revoke_token['share_link']['id']}/", timeout=10)
    check("revoke returns 204", deleted.status_code == 204)
    after = public.get(f"{api}/share/{rtoken}/", timeout=10)
    check("revoked link is gone", after.status_code == 410, after.json().get("error", ""))

    # ------------------------------------------------------------ authz checks
    section("9. Authorization boundaries")
    other = requests.Session()
    _other_email, other_access = register(other, api, "other")
    other.headers["Authorization"] = f"Bearer {other_access}"

    check("stranger cannot create a link for this file",
          other.post(f"{api}/files/{file_id}/share-link/", json={}, timeout=10).status_code
          in (403, 404))
    check("stranger cannot revoke the link",
          other.delete(f"{api}/share-links/{link_id}/", timeout=10).status_code == 403)
    check("anonymous cannot manage links",
          public.delete(f"{api}/share-links/{link_id}/", timeout=10).status_code == 401)
    check("share token is not a bearer token",
          requests.get(f"{api}/users/me/", headers={"Authorization": f"Bearer {token}"},
                       timeout=10).status_code == 401)
    check("normal user cannot reach the admin endpoint",
          owner.get(f"{api}/admin/test/", timeout=10).status_code == 403)

    # ---------------------------------------------------------------- audit
    section("10. Audit trail (no secrets recorded)")
    logs = owner.get(f"{api}/audit-logs/?page_size=100", timeout=15).json()
    actions = [entry["action"] for entry in logs["results"]]
    for expected in ("SHARE_LINK_CREATED", "SHARE_LINK_ACCESSED", "SHARE_LINK_DOWNLOAD",
                     "SHARE_LINK_REVOKED", "DOWNLOAD_LIMIT_REACHED",
                     "SHARE_LINK_PASSWORD_FAILURE"):
        check(f"{expected} recorded", expected in actions)
    blob = str(logs)
    check("raw share token never logged", token not in blob and ptoken not in blob)
    check("link password never logged", LINK_PASSWORD not in blob)
    check("account password never logged", PASSWORD not in blob)

    # --------------------------------------------------------------- summary
    print()
    if failures:
        print(f"{RED}{BOLD}{len(failures)} CHECK(S) FAILED{RESET}")
        for item in failures:
            print(f"  - {item}")
        return 1
    print(f"{GREEN}{BOLD}All demo checks passed.{RESET}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except requests.ConnectionError:
        print(f"{RED}Could not reach the API. Start it first:{RESET}")
        print("  cd backend && python manage.py runserver 0.0.0.0:8000")
        sys.exit(2)
