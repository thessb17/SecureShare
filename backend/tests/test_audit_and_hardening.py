"""Audit-trail integrity, secret hygiene, response hardening and Celery tasks."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest
from django.conf import settings
from django.utils import timezone

from audit.constants import AuditAction
from audit.models import AuditLog, AuditLogImmutableError
from sharing.models import FileShare, ShareLink
from tests.conftest import SHARE_PASSWORD, STRONG_PASSWORD

pytestmark = pytest.mark.django_db


# ===========================================================================
# Audit log integrity
# ===========================================================================
def test_audit_entries_cannot_be_modified(client_a, file_a):
    event = AuditLog.objects.filter(action=AuditAction.FILE_UPLOADED).first()
    assert event is not None
    event.message = "nothing to see here"
    with pytest.raises(AuditLogImmutableError):
        event.save()

    event.refresh_from_db()
    assert event.message != "nothing to see here"


def test_audit_entries_record_actor_ip_and_request_id(client_a, file_a):
    event = AuditLog.objects.filter(action=AuditAction.FILE_UPLOADED).first()
    assert event.actor_email == "alice@example.com"
    assert event.actor_role == "USER"
    assert event.ip_address is not None
    assert event.request_id


def test_audit_api_requires_authentication(api_client):
    assert api_client.get("/api/audit-logs/").status_code == 401


def test_users_see_only_their_own_audit_trail(client_a, client_b, file_a):
    body_a = client_a.get("/api/audit-logs/").data
    assert body_a["count"] >= 1
    assert all(
        item["actor"] is None or item["actor"]["email"] == "alice@example.com"
        for item in body_a["results"]
    )

    body_b = client_b.get("/api/audit-logs/").data
    assert body_b["count"] == 0


def test_admin_sees_the_whole_audit_trail(admin_client, client_a, file_a):
    body = admin_client.get("/api/audit-logs/").data
    actions = {item["action"] for item in body["results"]}
    assert AuditAction.FILE_UPLOADED in actions


def test_audit_log_endpoint_is_read_only(client_a, file_a):
    assert client_a.post("/api/audit-logs/", {}, format="json").status_code in (403, 405)
    assert client_a.put("/api/audit-logs/", {}, format="json").status_code in (403, 405)
    assert client_a.delete("/api/audit-logs/").status_code in (403, 405)


# ===========================================================================
# Secret hygiene across the whole audit trail
# ===========================================================================
def test_no_secret_material_is_ever_persisted_in_audit_logs(
    api_client, client_a, anonymous_client, create_share_link, file_a
):
    """End-to-end sweep: run the sensitive flows, then grep every audit row."""
    api_client.post(
        "/api/auth/login/",
        {"email": "alice@example.com", "password": STRONG_PASSWORD},
        format="json",
    )
    api_client.post(
        "/api/auth/login/",
        {"email": "alice@example.com", "password": "Wrong!Password123"},
        format="json",
    )
    payload, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    anonymous_client.get(f"/api/share/{token}/")
    anonymous_client.post(
        f"/api/share/{token}/download/", {"password": "guess-me"}, format="json"
    )
    anonymous_client.post(
        f"/api/share/{token}/download/", {"password": SHARE_PASSWORD}, format="json"
    )

    link = ShareLink.objects.get(pk=payload["share_link"]["id"])
    forbidden = [
        token,                       # raw share token
        SHARE_PASSWORD,              # share password
        STRONG_PASSWORD,             # account password
        "guess-me",                  # attempted password
        link.password_hash,          # even the hash stays out of the log
        link.token_hash,             # full digest (only the prefix is logged)
        file_a.stored_object_id,     # storage object id
    ]

    blob = json.dumps(
        list(
            AuditLog.objects.values(
                "message", "metadata", "actor_email", "object_id", "user_agent"
            )
        ),
        default=str,
    )
    for secret in forbidden:
        assert secret not in blob, f"{secret!r} leaked into the audit log"


def test_login_attempts_never_store_the_password(api_client, user_a):
    from audit.models import LoginAttempt

    api_client.post(
        "/api/auth/login/",
        {"email": user_a.email, "password": STRONG_PASSWORD},
        format="json",
    )
    blob = json.dumps(list(LoginAttempt.objects.values()), default=str)
    assert STRONG_PASSWORD not in blob


def test_jwt_tokens_are_not_written_to_audit_logs(api_client, user_a):
    response = api_client.post(
        "/api/auth/login/",
        {"email": user_a.email, "password": STRONG_PASSWORD},
        format="json",
    )
    access = response.data["tokens"]["access"]
    blob = json.dumps(list(AuditLog.objects.values()), default=str)
    assert access not in blob
    assert access.split(".")[2] not in blob  # not even the signature


def test_log_filter_redacts_sensitive_keys():
    """The logging filter scrubs secrets from structured log records."""
    import logging

    from core.logging import SensitiveDataFilter

    record = logging.LogRecord(
        name="secureshare",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="auth attempt password=%s token=%s",
        args=("hunter2", "abc.def.ghi"),
        exc_info=None,
    )
    record.password = "hunter2"
    record.share_token = "raw-token-value"
    record.authorization = "Bearer abc.def.ghi"

    assert SensitiveDataFilter().filter(record) is True
    assert record.password == "[REDACTED]"
    assert record.share_token == "[REDACTED]"
    assert record.authorization == "[REDACTED]"
    assert "hunter2" not in record.getMessage()
    assert "abc.def.ghi" not in record.getMessage()


# ===========================================================================
# Response hardening
# ===========================================================================
def test_security_headers_are_present_on_api_responses(api_client):
    response = api_client.get("/api/health/")
    assert response["X-Content-Type-Options"] == "nosniff"
    assert response["X-Frame-Options"] == "DENY"
    assert response["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in response
    assert "frame-ancestors 'none'" in response["Content-Security-Policy"]
    assert response["X-Request-ID"]


def test_server_banner_is_not_disclosed(api_client):
    response = api_client.get("/api/health/")
    assert "X-Powered-By" not in response
    assert "Django" not in response.get("Server", "")


def test_errors_are_structured_json_without_stack_traces(client_a):
    response = client_a.get("/api/files/00000000-0000-0000-0000-000000000000/")
    assert response.status_code == 404
    assert response["Content-Type"].startswith("application/json")
    body = response.json()
    assert set(body) >= {"error", "message", "request_id"}
    assert "Traceback" not in json.dumps(body)
    assert "django" not in json.dumps(body).lower()


def test_validation_errors_do_not_echo_secrets(api_client):
    response = api_client.post(
        "/api/auth/register/",
        {"email": "not-an-email", "password": "sup3r-S3cret-value!", "password_confirm": "x"},
        format="json",
    )
    assert response.status_code == 400
    assert "sup3r-S3cret-value!" not in json.dumps(response.json())


def test_debug_is_off_and_sql_is_not_leaked(client_a):
    assert settings.DEBUG is False
    response = client_a.get("/api/files/?page_size=notanumber")
    assert b"SELECT" not in response.content
    assert b"psycopg" not in response.content


def test_cors_rejects_unknown_origins(api_client):
    allowed = api_client.get(
        "/api/health/", HTTP_ORIGIN="https://app.secureshare.local"
    )
    assert allowed.get("Access-Control-Allow-Origin") == "https://app.secureshare.local"

    blocked = api_client.get("/api/health/", HTTP_ORIGIN="https://evil.example.com")
    assert blocked.get("Access-Control-Allow-Origin") is None
    assert settings.CORS_ALLOW_ALL_ORIGINS is False


def test_download_responses_disable_caching_and_sniffing(client_a, file_a):
    response = client_a.get(f"/api/files/{file_a.id}/download/")
    assert response["X-Content-Type-Options"] == "nosniff"
    assert "no-store" in response.get("Cache-Control", "")
    assert "attachment" in response["Content-Disposition"]


@pytest.mark.parametrize(
    "hostile",
    [
        'we"ird.pdf',
        "line\r\nInjected-Header: evil.pdf",
        "back\\slash.pdf",
        'quote"; filename="other.pdf',
        "üñïçødé.pdf",
    ],
)
def test_content_disposition_cannot_be_injected(hostile):
    """Header construction is hardened against quote/CRLF injection."""
    from files.download import content_disposition

    header = content_disposition(hostile)
    assert "\r" not in header and "\n" not in header
    assert header.count('filename="') == 1
    assert header.startswith("attachment;")
    # The CR/LF is removed, so nothing can escape the quoted filename value.
    assert "Injected-Header: evil.pdf\r\n" not in header


def test_download_header_is_safe_for_an_odd_filename(client_a, pdf_bytes):
    from tests.conftest import upload_file

    response = client_a.post(
        "/api/files/upload/",
        {"file": upload_file("we;ird name (v2).pdf", pdf_bytes, "application/pdf")},
        format="multipart",
    )
    assert response.status_code == 201, response.data
    download = client_a.get(f"/api/files/{response.data['id']}/download/")
    header = download["Content-Disposition"]
    assert header.count('filename="') == 1
    assert "\n" not in header and "\r" not in header


# ===========================================================================
# Celery maintenance tasks
# ===========================================================================
def test_expire_share_links_task_audits_once_per_link(create_share_link, file_a):
    from sharing.tasks import expire_share_links

    payload, _ = create_share_link(file_a.id)
    ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(
        expires_at=timezone.now() - timedelta(minutes=1)
    )

    assert expire_share_links() == 1
    assert expire_share_links() == 0  # idempotent
    assert AuditLog.objects.filter(action=AuditAction.SHARE_LINK_EXPIRED).count() == 1


def test_expire_file_shares_task(client_a, file_a, user_b):
    from sharing.tasks import expire_file_shares

    response = client_a.post(
        f"/api/files/{file_a.id}/share/",
        {"recipient": user_b.email, "permission": "VIEW"},
        format="json",
    )
    FileShare.objects.filter(pk=response.data["id"]).update(
        expires_at=timezone.now() - timedelta(minutes=1)
    )
    assert expire_file_shares() == 1
    assert AuditLog.objects.filter(action=AuditAction.SHARE_EXPIRED).exists()


def test_purge_task_removes_only_long_dead_links(create_share_link, file_a):
    from sharing.tasks import purge_expired_share_links

    keep, _ = create_share_link(file_a.id)
    purge, _ = create_share_link(file_a.id)

    ShareLink.objects.filter(pk=purge["share_link"]["id"]).update(
        expires_at=timezone.now() - timedelta(days=400)
    )
    removed = purge_expired_share_links(retention_days=30)
    assert removed == 1
    assert ShareLink.objects.filter(pk=keep["share_link"]["id"]).exists()
    assert not ShareLink.objects.filter(pk=purge["share_link"]["id"]).exists()


def test_tasks_are_registered_with_celery():
    from config.celery import app

    registered = set(app.tasks.keys())
    for name in (
        "sharing.tasks.expire_share_links",
        "sharing.tasks.expire_file_shares",
        "sharing.tasks.purge_expired_share_links",
    ):
        assert name in registered
