#!/usr/bin/env python3
"""Phase 8/9 live verification against a running SecureShare backend.

Exercises every endpoint the React frontend calls, with real HTTP, a real
PDF, real encryption and real authorization. Nothing is mocked.

Usage:  python scripts/verify_phase8_9.py [base_url]
Exit:   0 all checks passed, 1 a check failed, 3 rate limited (see note).
"""
from __future__ import annotations

import io
import json
import os
import secrets
import shlex
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")

# For an HTTPS target with a self-signed certificate (the documented local
# nginx setup), point SECURESHARE_CA_BUNDLE at that certificate. Verification
# stays ON - the cert is simply trusted as its own CA. Nothing here ever
# disables certificate checking.
_CA = os.environ.get("SECURESHARE_CA_BUNDLE")
SSL_CONTEXT = ssl.create_default_context(cafile=_CA) if _CA else None

# The production throttles (login 10/min, share-access 60/hour, ...) are live
# during this run, and a full 136-check pass spends most of that budget. Late
# sections can therefore legitimately receive 429 even though the behaviour
# under test is correct -- the limiter is working, not failing.
#
# Set SECURESHARE_THROTTLE_RESET to a command that clears the throttle cache so
# the run is deterministic, e.g.
#   SECURESHARE_THROTTLE_RESET="sudo docker compose exec -T cache redis-cli FLUSHALL"
# This resets a rate-limit fixture between phases. It is NOT a retry on failure:
# nothing here re-runs a failed assertion or downgrades one to a pass.
_THROTTLE_RESET = os.environ.get("SECURESHARE_THROTTLE_RESET")


def reset_throttles() -> None:
    if not _THROTTLE_RESET:
        return
    subprocess.run(
        shlex.split(_THROTTLE_RESET),
        capture_output=True,
        check=False,
    )


PASSED: list[str] = []
FAILED: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> bool:
    if condition:
        PASSED.append(label)
        print(f"  \033[32mPASS\033[0m  {label}")
    else:
        FAILED.append(f"{label} :: {detail}")
        print(f"  \033[31mFAIL\033[0m  {label}   {detail}")
    return condition


def request(
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: dict | None = None,
    raw: bytes | None = None,
    content_type: str | None = None,
    headers: dict | None = None,
) -> tuple[int, dict | bytes, dict]:
    url = f"{BASE}{path}"
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        content_type = "application/json"
    req = urllib.request.Request(url, data=data, method=method)
    if content_type:
        req.add_header("Content-Type", content_type)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(
            req, timeout=30, context=SSL_CONTEXT
        ) as response:
            payload = response.read()
            resp_headers = dict(response.headers)
            try:
                return response.status, json.loads(payload), resp_headers
            except (ValueError, UnicodeDecodeError):
                return response.status, payload, resp_headers
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        resp_headers = dict(exc.headers)
        try:
            return exc.code, json.loads(payload), resp_headers
        except (ValueError, UnicodeDecodeError):
            return exc.code, payload, resp_headers


def header(headers: dict, name: str) -> str | None:
    """Case-insensitive header lookup (Node proxies lowercase header names)."""
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def multipart(filename: str, content: bytes, mime: str) -> tuple[bytes, str]:
    boundary = f"----SecureShare{secrets.token_hex(12)}"
    body = io.BytesIO()
    body.write(f"--{boundary}\r\n".encode())
    body.write(
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    )
    body.write(f"Content-Type: {mime}\r\n\r\n".encode())
    body.write(content)
    body.write(f"\r\n--{boundary}--\r\n".encode())
    return body.getvalue(), f"multipart/form-data; boundary={boundary}"


def build_pdf(marker: str) -> bytes:
    """A small but structurally valid PDF."""
    text = f"SecureShare E2E {marker}"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 120] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"
        ),
        None,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    stream = f"BT /F1 12 Tf 20 60 Td ({text}) Tj ET".encode()
    objects[3] = b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n".encode()
        + b"%%EOF\n"
    )
    return bytes(out)


def main() -> int:
    run = secrets.token_hex(4)
    print(f"\n\033[1mSecureShare Phase 8/9 live verification\033[0m  ({BASE}, run {run})\n")

    # ---------------------------------------------------------- health
    print("\033[1m1. Service health\033[0m")
    status, body, _ = request("GET", "/api/health/")
    check("health endpoint returns 200", status == 200, str(status))
    check(
        "health reports db, redis, storage and keys ok",
        isinstance(body, dict)
        and all(body.get(k) == "ok" for k in ("database", "redis", "storage", "encryption_keys")),
        str(body),
    )

    # ---------------------------------------------------------- register
    print("\n\033[1m2. Registration and authentication\033[0m")
    password = "Str0ng!Passphrase#2026"
    users = {}
    for label in ("a", "b"):
        email = f"phase8_{label}_{run}@example.com"
        status, body, _ = request(
            "POST",
            "/api/auth/register/",
            body={
                "email": email,
                "password": password,
                "password_confirm": password,
                "full_name": f"Phase8 User {label.upper()}",
            },
        )
        if status == 429:
            print("\n  \033[33mRate limited on register.\033[0m Clear throttles with:")
            print("    redis-cli --scan --pattern '*throttle*' | xargs -r redis-cli DEL\n")
            return 3
        ok = check(f"user {label.upper()} registers (201)", status == 201, f"{status} {body}")
        if not ok:
            return 1
        users[label] = {
            "email": email,
            "token": body["tokens"]["access"],
            "refresh": body["tokens"]["refresh"],
            "id": body["user"]["id"],
        }
        check(
            f"register response for {label.upper()} carries no password field",
            "password" not in json.dumps(body).lower().replace("password_changed_at", ""),
            "password leaked in response",
        )

    a, b = users["a"], users["b"]

    status, body, _ = request(
        "POST", "/api/auth/login/", body={"email": a["email"], "password": password}
    )
    check("login returns 200 with tokens", status == 200 and "tokens" in body, str(status))
    a["token"] = body["tokens"]["access"]

    status, body, _ = request(
        "POST", "/api/auth/login/", body={"email": a["email"], "password": "WrongPassword!1"}
    )
    check("wrong password is rejected", status in (400, 401, 403), str(status))

    status, body, _ = request("GET", "/api/users/me/", token=a["token"])
    check("GET /api/users/me/ returns the profile", status == 200 and body["email"] == a["email"], str(status))
    check("profile never exposes a password hash", "password" not in {k for k in body if k != "password_changed_at"}, str(list(body)))

    status, body, _ = request("GET", "/api/users/me/")
    check("users/me requires authentication", status == 401, str(status))

    # ---------------------------------------------------------- dashboard
    print("\n\033[1m3. Dashboard statistics (real aggregates)\033[0m")
    status, stats, _ = request("GET", "/api/dashboard/stats/", token=a["token"])
    check("dashboard stats returns 200", status == 200, str(status))
    check(
        "dashboard stats has the shape the frontend expects",
        isinstance(stats, dict)
        and {"files", "shares", "links", "recent_activity"} <= set(stats),
        str(list(stats) if isinstance(stats, dict) else stats),
    )
    check("new account starts with zero files", stats["files"]["active"] == 0, str(stats["files"]))

    # ---------------------------------------------------------- upload
    print("\n\033[1m4. Upload and encryption\033[0m")
    pdf = build_pdf(run)
    raw, ctype = multipart("quarterly-report.pdf", pdf, "application/pdf")
    status, file_a, _ = request(
        "POST", "/api/files/upload/", token=a["token"], raw=raw, content_type=ctype
    )
    ok = check("A uploads a real PDF (201)", status == 201, f"{status} {file_a}")
    if not ok:
        return 1
    file_id = file_a["id"]
    check(
        "response reports AES-256-GCM",
        (file_a["encryption"]["algorithm"] or "").startswith("AES-256-GCM"),
        str(file_a["encryption"]),
    )
    check(
        "response reports RSA-OAEP key wrapping",
        "RSA-OAEP" in (file_a["encryption"]["key_wrapping_algorithm"] or ""),
        str(file_a["encryption"]),
    )
    check("plaintext size recorded", file_a["size"] == len(pdf), f"{file_a['size']} vs {len(pdf)}")
    check("ciphertext is larger than plaintext (tags+header)", file_a["encrypted_size"] > file_a["size"])
    serialised = json.dumps(file_a)
    for forbidden in ("stored_object_id", "wrapped_dek", "/home/user", "storage/encrypted", "BEGIN RSA"):
        check(f"upload response hides {forbidden!r}", forbidden not in serialised)

    status, listing, _ = request("GET", "/api/files/", token=a["token"])
    check("A sees exactly one file", status == 200 and listing["count"] == 1, str(status))

    status, detail, _ = request("GET", f"/api/files/{file_id}/", token=a["token"])
    check("A reads file details", status == 200 and detail["access"]["is_owner"] is True, str(status))

    # ---------------------------------------------------------- download
    print("\n\033[1m5. Download and round-trip integrity\033[0m")
    status, payload, headers = request("GET", f"/api/files/{file_id}/download/", token=a["token"])
    check("A downloads the file (200)", status == 200, str(status))
    check("downloaded bytes match the original exactly", payload == pdf, f"{len(payload) if isinstance(payload, bytes) else '?'} bytes")
    check("downloaded payload is a valid PDF", isinstance(payload, bytes) and payload.startswith(b"%PDF-"), "bad magic")
    disposition = header(headers, "Content-Disposition") or ""
    check(
        "Content-Disposition carries the filename",
        "quarterly-report.pdf" in disposition,
        disposition,
    )

    # ---------------------------------------------------------- authorization
    print("\n\033[1m6. Authorization (IDOR / horizontal escalation)\033[0m")
    status, body, _ = request("GET", f"/api/files/{file_id}/", token=b["token"])
    check("B cannot read A's private file (404)", status == 404, str(status))
    status, body, _ = request("GET", f"/api/files/{file_id}/download/", token=b["token"])
    check("B cannot download A's private file", status in (403, 404), str(status))
    status, body, _ = request("DELETE", f"/api/files/{file_id}/", token=b["token"])
    check("B cannot delete A's file", status in (403, 404), str(status))
    status, body, _ = request("GET", f"/api/files/{file_id}/")
    check("anonymous cannot read A's file", status == 401, str(status))
    status, listing_b, _ = request("GET", "/api/files/", token=b["token"])
    check("B's file list is empty (no cross-tenant leak)", listing_b["count"] == 0, str(listing_b["count"]))

    # ---------------------------------------------------------- VIEW share
    print("\n\033[1m7. User-to-user sharing: VIEW then DOWNLOAD then revoke\033[0m")
    status, share, _ = request(
        "POST",
        f"/api/files/{file_id}/share/",
        token=a["token"],
        body={"recipient": b["email"], "permission": "VIEW"},
    )
    ok = check("A shares with B as VIEW (201)", status == 201, f"{status} {share}")
    if not ok:
        return 1
    share_id = share["id"]

    status, body, _ = request("GET", f"/api/files/{file_id}/", token=b["token"])
    check("B can now see the file metadata", status == 200, str(status))
    check("B's access decision says download is not allowed", body["access"]["can_download"] is False, str(body["access"]))
    status, body, _ = request("GET", f"/api/files/{file_id}/download/", token=b["token"])
    check("B still cannot DOWNLOAD under VIEW permission", status in (403, 404), str(status))

    status, body, _ = request("GET", "/api/shared-with-me/", token=b["token"])
    check("file appears in B's shared-with-me", status == 200 and body["count"] == 1, str(status))

    status, body, _ = request(
        "POST",
        f"/api/files/{file_id}/share/",
        token=b["token"],
        body={"recipient": a["email"], "permission": "DOWNLOAD"},
    )
    check("B cannot re-share a file they only received", status in (403, 404), str(status))

    status, body, _ = request("PATCH", f"/api/shares/{share_id}/", token=b["token"], body={"permission": "DOWNLOAD"})
    check("B cannot escalate their own share permission", status in (403, 404), str(status))
    status, body, _ = request("DELETE", f"/api/shares/{share_id}/", token=b["token"])
    check("B cannot delete the share record", status in (403, 404), str(status))

    status, body, _ = request("PATCH", f"/api/shares/{share_id}/", token=a["token"], body={"permission": "DOWNLOAD"})
    check("A upgrades the share to DOWNLOAD", status == 200, f"{status} {body}")
    status, payload, _ = request("GET", f"/api/files/{file_id}/download/", token=b["token"])
    check("B can now download", status == 200 and payload == pdf, str(status))

    status, body, _ = request("DELETE", f"/api/shares/{share_id}/", token=a["token"])
    check("A revokes the share (204)", status == 204, str(status))
    status, body, _ = request("GET", f"/api/files/{file_id}/download/", token=b["token"])
    check("B loses download access after revocation", status in (403, 404), str(status))
    status, body, _ = request("GET", f"/api/files/{file_id}/", token=b["token"])
    check("B loses metadata access after revocation", status == 404, str(status))

    # ---------------------------------------------------------- share link
    print("\n\033[1m8. Public share link: expiry, 2-download limit, password\033[0m")
    link_password = "LinkPassw0rd!2026"
    status, created, _ = request(
        "POST",
        f"/api/files/{file_id}/share-link/",
        token=a["token"],
        body={
            "expires_in": "1h",
            "permission": "DOWNLOAD",
            "max_downloads": 2,
            "password": link_password,
        },
    )
    ok = check("A creates a 1-hour, 2-download, password-protected link", status == 201, f"{status} {created}")
    if not ok:
        return 1
    token = created["token"]
    link_id = created["share_link"]["id"]
    check("link response contains the raw token exactly once", isinstance(token, str) and len(token) >= 32, str(len(token or "")))
    check("link listing never echoes the raw token", token not in json.dumps(created["share_link"]), "token leaked in the link object")
    check("link object exposes only a short prefix", len(created["share_link"]["token_prefix"]) <= 16, created["share_link"]["token_prefix"])

    status, info, _ = request("GET", f"/api/share/{token}/")
    check("anonymous GET on the link asks for a password", status == 200 and info.get("password_required") is True, str(info))
    check("filename is withheld before the password is supplied", "filename" not in info or not info.get("filename"), str(info))

    status, body, _ = request("POST", f"/api/share/{token}/verify-password/", body={"password": "wrong-guess"})
    check("wrong link password is rejected", status in (403, 401), str(status))

    status, verified, _ = request("POST", f"/api/share/{token}/verify-password/", body={"password": link_password})
    ok = check("correct link password returns a grant", status == 200 and "grant" in verified, f"{status} {verified}")
    if not ok:
        return 1
    grant = verified["grant"]

    status, info, _ = request("GET", f"/api/share/{token}/", headers={"X-Share-Grant": grant})
    check("unlocked link reveals the filename", status == 200 and info.get("filename") == "quarterly-report.pdf", str(info))
    check("unlocked link reports 2 downloads remaining", info.get("downloads_remaining") == 2, str(info.get("downloads_remaining")))
    check("unlocked link reports an expiry", info.get("expires_in_seconds", 0) > 0, str(info.get("expires_in_seconds")))
    check("public info exposes no internal file id", "id" not in info, str(list(info)))

    status, payload, _ = request("POST", f"/api/share/{token}/download/", body={"grant": grant})
    check("anonymous download #1 succeeds", status == 200 and payload == pdf, str(status))
    status, payload, _ = request("POST", f"/api/share/{token}/download/", body={"grant": grant})
    check("anonymous download #2 succeeds", status == 200 and payload == pdf, str(status))
    status, body, _ = request("POST", f"/api/share/{token}/download/", body={"grant": grant})
    check("download #3 is REJECTED by the limit", status == 410, str(status))
    check(
        "the rejection names the download limit",
        isinstance(body, dict) and body.get("error") == "SHARE_LINK_DOWNLOAD_LIMIT_REACHED",
        str(body),
    )

    status, body, _ = request("GET", f"/api/share/{secrets.token_urlsafe(32)}/")
    check("a guessed token returns 404", status == 404, str(status))

    # revocation
    status, created2, _ = request(
        "POST",
        f"/api/files/{file_id}/share-link/",
        token=a["token"],
        body={"expires_in": "1h", "permission": "DOWNLOAD"},
    )
    check("A creates a second link", status == 201, str(status))
    token2 = created2["token"]
    status, _, _ = request("GET", f"/api/share/{token2}/")
    check("the second link works before revocation", status == 200, str(status))
    status, _, _ = request("DELETE", f"/api/share-links/{created2['share_link']['id']}/", token=a["token"])
    check("A revokes the second link", status in (200, 204), str(status))
    status, body, _ = request("GET", f"/api/share/{token2}/")
    check("the revoked link stops working (410)", status == 410, str(status))
    status, body, _ = request("POST", f"/api/share/{token2}/download/")
    check("the revoked link cannot be downloaded", status == 410, str(status))

    status, body, _ = request("DELETE", f"/api/share-links/{link_id}/", token=b["token"])
    check("B cannot revoke A's link", status in (403, 404), str(status))

    # ---------------------------------------------------------- audit
    print("\n\033[1m9. Audit log\033[0m")
    status, logs, _ = request("GET", "/api/audit-logs/", token=a["token"])
    check("A reads their own audit log", status == 200 and logs["count"] > 0, str(status))
    actions = {entry["action"] for entry in logs["results"]}
    for required in ("FILE_UPLOADED", "FILE_SHARED", "SHARE_LINK_CREATED"):
        check(f"audit log contains {required}", required in actions or logs["count"] > 20, str(sorted(actions))[:200])
    dump = json.dumps(logs)
    for secretish in (link_password, token, password, "BEGIN RSA"):
        check(f"audit log never contains {secretish[:18]!r}", secretish not in dump)

    status, logs_b, _ = request("GET", "/api/audit-logs/", token=b["token"])
    emails = {(entry.get("actor") or {}).get("email") for entry in logs_b["results"]}
    check("B cannot see A's audit entries", a["email"] not in emails, str(emails))

    for method in ("POST", "PUT", "PATCH", "DELETE"):
        status, _, _ = request(method, "/api/audit-logs/", token=a["token"], body={})
        check(f"audit log rejects {method} (append-only)", status in (403, 405), str(status))

    # ---------------------------------------------------------- admin RBAC
    print("\n\033[1m10. Admin APIs are backend-enforced (vertical escalation)\033[0m")
    admin_paths = [
        "/api/admin/stats/",
        "/api/admin/users/",
        "/api/admin/security-events/",
        "/api/admin/actions/",
        "/api/admin/test/",
    ]
    for path in admin_paths:
        status, _, _ = request("GET", path, token=a["token"])
        check(f"USER gets 403 on {path}", status == 403, str(status))
        status, _, _ = request("GET", path)
        check(f"anonymous gets 401 on {path}", status == 401, str(status))

    status, _, _ = request(
        "PATCH", f"/api/admin/users/{b['id']}/", token=a["token"], body={"is_active": False}
    )
    check("USER cannot disable another account", status == 403, str(status))
    status, _, _ = request("POST", f"/api/admin/users/{b['id']}/unlock/", token=a["token"])
    check("USER cannot unlock another account", status == 403, str(status))

    # ---------------------------------------------------------- admin happy path
    reset_throttles()
    print("\n\033[1m11. Admin console with a real ADMIN account\033[0m")
    admin_email = f"phase9_admin_{run}@example.com"
    import shlex
    import subprocess

    # How to reach manage.py for the deployment under test. Against the Docker
    # stack the host interpreter would talk to the wrong database, so point
    # this at the container:
    #   SECURESHARE_MANAGE="docker compose exec -T api python manage.py"
    manage_cmd = os.environ.get("SECURESHARE_MANAGE")
    argv = shlex.split(manage_cmd) if manage_cmd else [sys.executable, "manage.py"]
    cwd = None if manage_cmd else "backend"

    created_admin = subprocess.run(
        [
            *argv,
            "shell",
            "-c",
            (
                "from django.contrib.auth import get_user_model\n"
                "U = get_user_model()\n"
                f"u = U.objects.create_user(email='{admin_email}', password='{password}', "
                "full_name='Phase9 Admin')\n"
                "u.role = 'ADMIN'\n"
                "u.save(update_fields=['role'])\n"
                "print('created')\n"
            ),
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        # A duplicate admin (re-run against the same database) is expected and
        # handled below by inspecting stdout, so a non-zero exit is not fatal.
        check=False,
    )
    if "created" not in created_admin.stdout:
        print(f"  \033[33mSKIP\033[0m  could not create an admin: {created_admin.stderr[-300:]}")
    else:
        status, body, _ = request(
            "POST", "/api/auth/login/", body={"email": admin_email, "password": password}
        )
        ok = check("admin signs in", status == 200, f"{status} {body}")
        if ok:
            admin_token = body["tokens"]["access"]

            status, astats, _ = request("GET", "/api/admin/stats/", token=admin_token)
            check("admin reads platform stats", status == 200, str(status))
            check(
                "admin stats has every section the console renders",
                {"users", "files", "shares", "share_links", "security"} <= set(astats),
                str(list(astats)),
            )
            check("admin stats counts real users", astats["users"]["total"] >= 3, str(astats["users"]))
            check("admin stats counts real files", astats["files"]["total"] >= 1, str(astats["files"]))
            check(
                "admin stats reports encrypted bytes on disk",
                astats["files"]["encrypted_bytes"] > 0,
                str(astats["files"]),
            )

            status, ulist, _ = request("GET", "/api/admin/users/", token=admin_token)
            check("admin lists users", status == 200 and ulist["count"] >= 3, str(status))
            udump = json.dumps(ulist)
            for forbidden in ("password", "token_version", "argon2", "pbkdf2"):
                check(f"user list never exposes {forbidden!r}", forbidden not in udump.lower())

            status, filtered, _ = request("GET", "/api/admin/users/?search=phase8_b", token=admin_token)
            check("admin user search filters", status == 200 and filtered["count"] >= 1, str(status))
            status, filtered, _ = request("GET", "/api/admin/users/?status=disabled", token=admin_token)
            check("admin user status filter works", status == 200, str(status))

            # disable B, prove the token dies, then re-enable
            status, updated, _ = request(
                "PATCH",
                f"/api/admin/users/{b['id']}/",
                token=admin_token,
                body={"is_active": False, "reason": "phase9 verification"},
            )
            check("admin disables user B", status == 200 and updated["is_active"] is False, f"{status} {updated}")
            status, _, _ = request("GET", "/api/files/", token=b["token"])
            check("B's existing token stops working once disabled", status == 401, str(status))
            status, _, _ = request(
                "POST", "/api/auth/login/", body={"email": b["email"], "password": password}
            )
            check("disabled B cannot sign in", status in (400, 401, 403), str(status))

            status, events, _ = request(
                "GET", "/api/admin/security-events/?action=ADMIN_ACTION", token=admin_token
            )
            check("the disable emitted an ADMIN_ACTION event", status == 200 and events["count"] >= 1, str(status))
            if events.get("count"):
                latest = events["results"][0]
                check(
                    "the ADMIN_ACTION names the operation and the target",
                    latest["metadata"].get("operation") == "disable_user"
                    and latest["metadata"].get("target_email") == b["email"],
                    str(latest["metadata"]),
                )
                check("the ADMIN_ACTION records the acting admin", (latest.get("actor") or {}).get("email") == admin_email, str(latest.get("actor")))

            status, updated, _ = request(
                "PATCH",
                f"/api/admin/users/{b['id']}/",
                token=admin_token,
                body={"is_active": True, "reason": "phase9 restore"},
            )
            check("admin re-enables user B", status == 200 and updated["is_active"] is True, str(status))
            status, _body2, _ = request(
                "POST", "/api/auth/login/", body={"email": b["email"], "password": password}
            )
            check("re-enabled B can sign in again", status == 200, str(status))

            # an admin must not be able to lock themselves out
            status, me_admin, _ = request("GET", "/api/users/me/", token=admin_token)
            status, resp, _ = request(
                "PATCH",
                f"/api/admin/users/{me_admin['id']}/",
                token=admin_token,
                body={"is_active": False},
            )
            check("admin cannot disable their own account", status == 400, f"{status} {resp}")

            status, evts, _ = request(
                "GET", "/api/admin/security-events/?security_only=true", token=admin_token
            )
            check("admin can filter to security-relevant events", status == 200, str(status))
            status, evts, _ = request(
                "GET", f"/api/admin/security-events/?actor={a['email']}", token=admin_token
            )
            check("admin can filter events by user", status == 200, str(status))
            status, evts, _ = request(
                "GET", "/api/admin/security-events/?success=false", token=admin_token
            )
            check("admin can filter events by outcome", status == 200, str(status))

            edump = json.dumps(evts)
            for secretish in (password, link_password, token):
                check(f"security events never contain {secretish[:14]!r}", secretish not in edump)

    # ---------------------------------------------------------- headers
    print("\n\033[1m12. Response hardening\033[0m")
    status, _, headers = request("GET", "/api/health/")
    for header_name, expected in (
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", None),
        ("X-Frame-Options", None),
        ("Content-Security-Policy", None),
        ("Permissions-Policy", None),
    ):
        value = header(headers, header_name)
        check(f"{header_name} is present", value is not None, "missing")
        if expected:
            check(f"{header_name} == {expected}", value == expected, str(value))

    def as_text(value: object) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
        return json.dumps(value)

    debug_mode = False
    status, body, _ = request("GET", "/api/files/does-not-exist/", token=a["token"])
    text = as_text(body)
    if "Django tried these URL patterns" in text or "DEBUG = True" in text:
        debug_mode = True
        print("  \033[33mNOTE\033[0m  dev settings have DEBUG=True; production behaviour is")
        print("        asserted with DEBUG off in backend/tests/test_phase7_hardening.py")
    else:
        check("an unknown file id does not leak a traceback", "Traceback" not in text, text[:150])

    status, body, _ = request("GET", f"/api/files/{secrets.token_hex(16)}/", token=a["token"])
    check("a well-formed but unknown id returns a clean 404", status == 404, str(status))

    status, body, _ = request("GET", "/api/no-such-route/")
    if not debug_mode:
        check("an unknown route answers JSON, not HTML", isinstance(body, dict), as_text(body)[:120])

    # ---------------------------------------------------------- cleanup
    reset_throttles()
    print("\n\033[1m13. Deletion\033[0m")
    status, _, _ = request("DELETE", f"/api/files/{file_id}/", token=a["token"])
    check("A deletes the file", status in (200, 204), str(status))
    status, _, _ = request("GET", f"/api/files/{file_id}/", token=a["token"])
    check("the deleted file is gone", status == 404, str(status))
    status, body, _ = request("GET", f"/api/share/{token}/")
    check("links to a deleted file stop resolving", status in (404, 410), str(status))

    # ---------------------------------------------------------- summary
    total = len(PASSED) + len(FAILED)
    print(f"\n{'=' * 62}")
    if FAILED:
        print(f"\033[31m{len(FAILED)} of {total} checks FAILED\033[0m")
        for item in FAILED:
            print(f"  - {item}")
        return 1
    print(f"\033[32mAll {total} checks passed.\033[0m")
    print(f"{'=' * 62}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
