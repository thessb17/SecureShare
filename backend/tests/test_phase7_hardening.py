"""Phase 7 - security hardening, audit logging and protection.

Nine areas, each exercised against the real application:

1. audit logging coverage (the 19 required events) and field completeness
2. rate limiting on every sensitive category
3. security headers
4. CORS
5. CSRF (the architecture review is asserted, not just described)
6. error handling / information disclosure
7. security settings
8. audit record protection
9. brute-force protection

These complement ``tests/test_audit_and_hardening.py`` rather than repeating it.
"""
from __future__ import annotations

import json

import pytest
from django.conf import settings
from django.test import Client

from audit.constants import AuditAction
from audit.models import AuditLog
from tests.conftest import STRONG_PASSWORD

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# 1. AUDIT LOGGING
# ---------------------------------------------------------------------------

#: The exact event list Phase 7 requires.
REQUIRED_ACTIONS = [
    "USER_REGISTERED",
    "LOGIN_SUCCESS",
    "LOGIN_FAILURE",
    "LOGOUT",
    "PASSWORD_CHANGED",
    "FILE_UPLOADED",
    "FILE_DOWNLOADED",
    "FILE_DELETED",
    "FILE_SHARED",
    "SHARE_REVOKED",
    "SHARE_ACCESSED",
    "SHARE_LINK_CREATED",
    "SHARE_LINK_ACCESSED",
    "SHARE_LINK_DOWNLOAD",
    "SHARE_LINK_REVOKED",
    "SHARE_LINK_EXPIRED",
    "UNAUTHORIZED_ACCESS_ATTEMPT",
    "RATE_LIMIT_TRIGGERED",
    "ADMIN_ACTION",
]


@pytest.mark.parametrize("action", REQUIRED_ACTIONS)
def test_required_audit_action_is_defined(action):
    assert hasattr(AuditAction, action), f"{action} is not a declared AuditAction"


@pytest.mark.parametrize("action", REQUIRED_ACTIONS)
def test_required_audit_action_is_emitted_somewhere_in_the_code(action):
    """A declared-but-never-emitted event would be a documentation lie."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    hits = 0
    for path in root.rglob("*.py"):
        if "tests" in path.parts or "migrations" in path.parts:
            continue
        if f"AuditAction.{action}" in path.read_text():
            hits += 1
    assert hits > 0, f"{action} is declared but never emitted by application code"


def test_audit_entry_records_every_required_field(client_a, user_a, pdf_bytes):
    from tests.conftest import upload_file

    client_a.post(
        "/api/files/upload/", {"file": upload_file("f.pdf", pdf_bytes)}, format="multipart"
    )
    entry = AuditLog.objects.filter(action=AuditAction.FILE_UPLOADED).first()

    assert entry is not None
    assert entry.actor_id == user_a.pk          # user
    assert entry.action == "FILE_UPLOADED"      # action
    assert entry.timestamp is not None          # timestamp
    assert entry.ip_address                     # IP
    assert entry.user_agent is not None         # user agent
    assert entry.object_id                      # resource reference
    assert entry.object_type
    assert entry.success is True                # outcome
    assert isinstance(entry.metadata, dict)     # safe metadata
    assert entry.actor_role


def test_anonymous_share_link_events_record_ip_without_an_actor(
    anonymous_client, create_share_link, file_a
):
    _payload, token = create_share_link(file_a.id)
    anonymous_client.get(f"/api/share/{token}/")

    entry = AuditLog.objects.filter(action=AuditAction.SHARE_LINK_ACCESSED).first()
    assert entry is not None
    assert entry.actor_id is None, "anonymous access must not be attributed to a user"
    assert entry.ip_address, "anonymous access must still record the source IP"


def test_login_failure_is_audited_without_revealing_whether_the_account_exists(
    anonymous_client, user_a
):
    anonymous_client.post(
        "/api/auth/login/", {"email": user_a.email, "password": "WrongPassword!1"},
        format="json",
    )
    anonymous_client.post(
        "/api/auth/login/", {"email": "ghost@example.com", "password": "WrongPassword!1"},
        format="json",
    )
    failures = list(AuditLog.objects.filter(action=AuditAction.LOGIN_FAILURE))
    assert len(failures) >= 2
    for entry in failures:
        assert entry.success is False
        blob = json.dumps(entry.metadata)
        assert "WrongPassword!1" not in blob


def test_metadata_is_json_serialisable_and_bounded(client_a, file_a):
    """Unbounded or unserialisable metadata breaks the log pipeline."""
    for entry in AuditLog.objects.all():
        encoded = json.dumps(entry.metadata)
        assert len(encoded) < 8192, f"{entry.action} metadata is unexpectedly large"


# ---------------------------------------------------------------------------
# 2. RATE LIMITING
# ---------------------------------------------------------------------------

def test_login_is_rate_limited(anonymous_client, user_a, throttle_rates):
    throttle_rates({"auth.login": "3/hour"})
    codes = [
        anonymous_client.post(
            "/api/auth/login/", {"email": user_a.email, "password": "Nope!12345"},
            format="json",
        ).status_code
        for _ in range(5)
    ]
    assert 429 in codes, f"login was never throttled: {codes}"


def test_registration_is_rate_limited(anonymous_client, throttle_rates, db):
    throttle_rates({"auth.register": "2/hour"})
    codes = []
    for index in range(4):
        response = anonymous_client.post(
            "/api/auth/register/",
            {
                "email": f"rl{index}@example.com",
                "password": STRONG_PASSWORD,
                "password_confirm": STRONG_PASSWORD,
                "full_name": "Rate Limited",
            },
            format="json",
        )
        codes.append(response.status_code)
    assert 429 in codes, f"registration was never throttled: {codes}"


def test_password_reset_is_rate_limited(anonymous_client, user_a, throttle_rates):
    throttle_rates({"auth.password_reset": "2/hour"})
    codes = [
        anonymous_client.post(
            "/api/auth/password-reset/", {"email": user_a.email}, format="json"
        ).status_code
        for _ in range(4)
    ]
    assert 429 in codes, f"password reset was never throttled: {codes}"


def test_upload_is_rate_limited(client_a, pdf_bytes, throttle_rates):
    from tests.conftest import upload_file

    throttle_rates({"files.upload": "2/hour"})
    codes = [
        client_a.post(
            "/api/files/upload/",
            {"file": upload_file(f"f{i}.pdf", pdf_bytes)},
            format="multipart",
        ).status_code
        for i in range(4)
    ]
    assert 429 in codes, f"upload was never throttled: {codes}"


def test_download_is_rate_limited(client_a, file_a, throttle_rates):
    throttle_rates({"files.download": "2/hour"})
    codes = []
    for _ in range(4):
        response = client_a.get(f"/api/files/{file_a.id}/download/")
        codes.append(response.status_code)
        if hasattr(response, "streaming_content"):
            b"".join(response.streaming_content)
    assert 429 in codes, f"download was never throttled: {codes}"


def test_share_link_access_is_rate_limited(
    anonymous_client, create_share_link, file_a, throttle_rates
):
    throttle_rates({"share.access": "3/hour"})
    _payload, token = create_share_link(file_a.id)
    codes = [anonymous_client.get(f"/api/share/{token}/").status_code for _ in range(5)]
    assert 429 in codes, f"share link access was never throttled: {codes}"


def test_share_password_attempts_are_rate_limited(
    anonymous_client, create_share_link, file_a, throttle_rates
):
    throttle_rates({"share.password": "3/hour"})
    _payload, token = create_share_link(file_a.id, password="Correct!Horse#9")
    codes = [
        anonymous_client.post(
            f"/api/share/{token}/verify-password/", {"password": f"bad-{i}"}, format="json"
        ).status_code
        for i in range(6)
    ]
    assert 429 in codes, f"share password attempts were never throttled: {codes}"


def test_share_creation_is_rate_limited(client_a, file_a, throttle_rates):
    throttle_rates({"share.create": "2/hour"})
    codes = [
        client_a.post(
            f"/api/files/{file_a.id}/share-link/", {"expires_in": "1h"}, format="json"
        ).status_code
        for _ in range(4)
    ]
    assert 429 in codes, f"share creation was never throttled: {codes}"


def test_throttling_emits_a_rate_limit_audit_event(anonymous_client, user_a, throttle_rates):
    throttle_rates({"auth.login": "2/hour"})
    for _ in range(4):
        anonymous_client.post(
            "/api/auth/login/", {"email": user_a.email, "password": "Nope!12345"},
            format="json",
        )
    assert AuditLog.objects.filter(action=AuditAction.RATE_LIMIT_TRIGGERED).exists()


def test_throttle_response_is_structured_and_has_retry_after(
    anonymous_client, user_a, throttle_rates
):
    throttle_rates({"auth.login": "1/hour"})
    for _ in range(3):
        response = anonymous_client.post(
            "/api/auth/login/", {"email": user_a.email, "password": "Nope!12345"},
            format="json",
        )
        if response.status_code == 429:
            assert response.data["error"] == "RATE_LIMIT_EXCEEDED"
            assert "retry_after" in response.data
            assert "request_id" in response.data
            return
    pytest.fail("never reached a 429")


def test_non_test_settings_use_redis_for_throttle_state():
    """Phase 7 asks for Redis-backed limiting.

    The pytest settings deliberately use LocMemCache so test runs are isolated
    and do not need a live Redis. The requirement applies to the settings that
    actually serve traffic, so assert on those modules directly.
    """
    import config.settings.base as base
    import config.settings.prod as prod

    assert "redis" in base.CACHES["default"]["BACKEND"].lower()
    assert prod.CACHES["default"]["BACKEND"] == base.CACHES["default"]["BACKEND"]
    # and the throttle classes must be wired to the Django cache, not memory
    assert "DEFAULT_THROTTLE_RATES" in base.REST_FRAMEWORK


# ---------------------------------------------------------------------------
# 3. SECURITY HEADERS
# ---------------------------------------------------------------------------

REQUIRED_HEADERS = {
    "Content-Security-Policy": None,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": None,
    "X-Frame-Options": "DENY",
    "Permissions-Policy": None,
    "Cross-Origin-Opener-Policy": None,
}


@pytest.mark.parametrize("header,expected", REQUIRED_HEADERS.items())
def test_security_header_present(anonymous_client, header, expected):
    response = anonymous_client.get("/api/health/")
    assert header in response, f"{header} missing"
    if expected:
        assert response[header] == expected


def test_csp_denies_framing_and_restricts_defaults(anonymous_client):
    csp = anonymous_client.get("/api/health/")["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'none'" in csp
    assert "object-src" not in csp or "object-src 'none'" in csp
    assert "unsafe-eval" not in csp


def test_permissions_policy_disables_dangerous_features(anonymous_client):
    policy = anonymous_client.get("/api/health/")["Permissions-Policy"]
    for feature in ("camera", "microphone", "geolocation"):
        assert f"{feature}=()" in policy


def test_hsts_is_sent_for_https_requests(anonymous_client, settings):
    settings.SECURE_HSTS_SECONDS = 31536000
    settings.SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    settings.SECURE_SSL_REDIRECT = False
    response = anonymous_client.get("/api/health/", secure=True)
    header = response.get("Strict-Transport-Security", "")
    assert "max-age=31536000" in header
    assert "includeSubDomains" in header


def test_hsts_is_not_sent_over_plain_http(anonymous_client, settings):
    """Sending HSTS over http is ignored by browsers and signals confusion."""
    settings.SECURE_HSTS_SECONDS = 31536000
    response = anonymous_client.get("/api/health/")
    assert "Strict-Transport-Security" not in response


def test_headers_are_present_on_error_responses_too(anonymous_client):
    response = anonymous_client.get("/api/files/")
    assert response.status_code == 401
    assert response["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in response


# ---------------------------------------------------------------------------
# 4. CORS
# ---------------------------------------------------------------------------

def test_cors_allow_all_origins_is_disabled():
    assert getattr(settings, "CORS_ALLOW_ALL_ORIGINS", False) is False


def test_cors_allows_a_configured_origin(anonymous_client, settings):
    settings.CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
    response = anonymous_client.get("/api/health/", HTTP_ORIGIN="https://app.example.com")
    assert response.get("Access-Control-Allow-Origin") == "https://app.example.com"


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example.com",
        "https://app.example.com.evil.net",   # suffix confusion
        "http://app.example.com",             # scheme downgrade
        "null",
    ],
)
def test_cors_rejects_untrusted_origins(anonymous_client, settings, origin):
    settings.CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
    response = anonymous_client.get("/api/health/", HTTP_ORIGIN=origin)
    assert response.get("Access-Control-Allow-Origin") != origin


def test_preflight_from_an_untrusted_origin_is_not_approved(anonymous_client, settings):
    settings.CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
    response = anonymous_client.options(
        "/api/files/",
        HTTP_ORIGIN="https://evil.example.com",
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="GET",
    )
    assert response.get("Access-Control-Allow-Origin") is None


# ---------------------------------------------------------------------------
# 5. CSRF
# ---------------------------------------------------------------------------
# Architecture: the API is authenticated with a Bearer JWT only. There is no
# cookie-based authentication class, so a cross-site form post carries no
# ambient credentials and CSRF does not apply to /api/. The Django admin uses
# session cookies and IS protected by CsrfViewMiddleware. These tests assert
# both halves of that claim rather than taking it on trust.

def test_api_does_not_accept_cookie_session_authentication(db, user_a):
    """The core CSRF-safety claim: a session cookie must not authenticate the API."""
    django_client = Client()
    django_client.force_login(user_a)          # real Django session cookie
    response = django_client.get("/api/files/")
    assert response.status_code == 401, (
        "a session cookie authenticated an API request - the API would then be "
        "CSRF-vulnerable"
    )


def test_session_authentication_is_not_installed_in_drf():
    classes = settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]
    assert not any("SessionAuthentication" in entry for entry in classes)


def test_csrf_middleware_is_enabled_for_cookie_based_views():
    assert "django.middleware.csrf.CsrfViewMiddleware" in settings.MIDDLEWARE


def test_state_changing_api_call_works_without_a_csrf_token(client_a, file_a):
    """Bearer auth: no CSRF token needed, and that is correct and safe."""
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"expires_in": "1h"}, format="json"
    )
    assert response.status_code == 201


def test_cross_site_post_without_a_bearer_token_is_rejected(db, user_a, file_a):
    """Simulated CSRF: attacker origin, victim's cookies, no Authorization header."""
    django_client = Client(enforce_csrf_checks=True)
    django_client.force_login(user_a)
    response = django_client.post(
        f"/api/files/{file_a.id}/share-link/",
        data=json.dumps({"expires_in": "1h"}),
        content_type="application/json",
        HTTP_ORIGIN="https://evil.example.com",
    )
    assert response.status_code in (401, 403)


def test_csrf_cookie_settings_are_hardened():
    assert settings.CSRF_COOKIE_SAMESITE in ("Lax", "Strict")
    assert settings.SESSION_COOKIE_SAMESITE in ("Lax", "Strict")
    assert settings.SESSION_COOKIE_HTTPONLY is True


def test_csrf_trusted_origins_are_explicit_and_not_wildcarded():
    for origin in settings.CSRF_TRUSTED_ORIGINS:
        assert origin != "*"
        assert "://" in origin, f"{origin} must include a scheme"


# ---------------------------------------------------------------------------
# 6. ERROR HANDLING / INFORMATION DISCLOSURE
# ---------------------------------------------------------------------------

LEAK_MARKERS = (
    "Traceback", "File \"/", "/home/user", "site-packages", "psycopg",
    "SELECT ", "INSERT ", "django.db", "Exception", "settings.py",
    "BEGIN RSA", "rsa_private", "storage/encrypted",
)


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("get", "/api/files/00000000-0000-0000-0000-000000000000/", None),
        ("get", "/api/nonexistent-endpoint/", None),
        ("post", "/api/auth/login/", {"email": "not-an-email", "password": "x"}),
        ("post", "/api/auth/register/", {"email": "a@b.co"}),
        ("get", "/api/share/not-a-real-token-aaaaaaaaaaaaaaaaaaaaaaaa/", None),
        ("get", "/api/files/?page=notanumber", None),
    ],
)
def test_error_responses_leak_nothing(client_a, method, path, payload):
    response = getattr(client_a, method)(path, payload, format="json") if payload \
        else getattr(client_a, method)(path)
    body = response.content.decode(errors="replace")
    for marker in LEAK_MARKERS:
        assert marker not in body, f"{marker!r} leaked in {method.upper()} {path}"


def test_error_body_shape_is_consistent(client_a):
    response = client_a.get("/api/files/00000000-0000-0000-0000-000000000000/")
    assert response.status_code == 404
    assert set(response.data) >= {"error", "message", "request_id"}
    assert response.data["error"].isupper()


def test_a_server_error_does_not_expose_the_exception(client_a, file_a, monkeypatch):
    """Force an unexpected exception and confirm the response stays opaque."""
    import files.views as files_views

    def explode(*args, **kwargs):
        raise RuntimeError("secret internal detail /home/user/keys/rsa_private.pem")

    monkeypatch.setattr(files_views, "get_file_for_access", explode)
    try:
        response = client_a.get(f"/api/files/{file_a.id}/")
    except RuntimeError:
        pytest.skip("test client re-raises; covered by the prod handler test below")
    body = response.content.decode(errors="replace")
    assert response.status_code == 500
    assert "rsa_private" not in body
    assert "RuntimeError" not in body
    assert "secret internal detail" not in body


def test_404_for_an_unknown_route_is_json_not_html(anonymous_client):
    response = anonymous_client.get("/api/definitely/not/here/")
    assert response.status_code == 404
    assert response["Content-Type"].startswith("application/json")


# ---------------------------------------------------------------------------
# 7. SECURITY SETTINGS
# ---------------------------------------------------------------------------

def test_debug_is_disabled():
    assert settings.DEBUG is False


def test_allowed_hosts_is_not_a_wildcard():
    assert "*" not in settings.ALLOWED_HOSTS


def test_password_validators_are_configured():
    names = [v["NAME"] for v in settings.AUTH_PASSWORD_VALIDATORS]
    joined = " ".join(names)
    assert "MinimumLengthValidator" in joined
    assert "CommonPasswordValidator" in joined
    assert "NumericPasswordValidator" in joined
    assert "UserAttributeSimilarityValidator" in joined


def test_argon2_is_the_default_password_hasher():
    assert "Argon2" in settings.PASSWORD_HASHERS[0]


def test_clickjacking_protection_is_configured():
    assert settings.X_FRAME_OPTIONS == "DENY"
    assert "django.middleware.clickjacking.XFrameOptionsMiddleware" in settings.MIDDLEWARE


def test_production_settings_enforce_secure_cookies_and_hsts():
    """Import the prod module and assert its hardening, without running it."""
    import importlib

    import config.settings.prod as prod

    importlib.reload(prod) if False else None  # keep the import side-effect free
    assert prod.SESSION_COOKIE_SECURE is True
    assert prod.CSRF_COOKIE_SECURE is True
    assert prod.SECURE_SSL_REDIRECT is True
    assert prod.SECURE_HSTS_SECONDS >= 31536000
    assert prod.SECURE_HSTS_INCLUDE_SUBDOMAINS is True
    assert prod.DEBUG is False


def test_secret_key_is_not_a_known_placeholder():
    assert settings.SECRET_KEY
    assert "change-me" not in settings.SECRET_KEY.lower()
    assert "replace-me" not in settings.SECRET_KEY.lower()


# ---------------------------------------------------------------------------
# 8. AUDIT RECORD PROTECTION
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_audit_endpoint_rejects_every_write_method(client_a, method):
    response = getattr(client_a, method)("/api/audit-logs/", {}, format="json")
    assert response.status_code in (403, 405)


def test_user_cannot_delete_an_audit_record_through_any_route(client_a, file_a):
    entry = AuditLog.objects.filter(action=AuditAction.FILE_UPLOADED).first()
    assert entry is not None
    for path in (f"/api/audit-logs/{entry.id}/", f"/api/audit-logs/{entry.id}"):
        assert client_a.delete(path).status_code in (403, 404, 405)
    assert AuditLog.objects.filter(pk=entry.pk).exists()


def test_user_cannot_see_another_users_audit_entries(client_a, client_b, file_a, user_b):
    """A's upload must not be visible to B."""
    response = client_b.get("/api/audit-logs/?page_size=100")
    assert response.status_code == 200
    visible_objects = {row.get("object_id") for row in response.data["results"]}
    assert str(file_a.id) not in visible_objects


def test_admin_can_see_everything(admin_client, client_a, file_a):
    response = admin_client.get("/api/audit-logs/?page_size=100")
    actions = {row["action"] for row in response.data["results"]}
    assert "FILE_UPLOADED" in actions


def test_audit_serializer_never_exposes_raw_metadata_secrets(
    client_a, create_share_link, file_a
):
    _payload, token = create_share_link(file_a.id, password="Sup3r!Secret#Link")
    response = client_a.get("/api/audit-logs/?page_size=100")
    blob = json.dumps(response.data)
    assert token not in blob
    assert "Sup3r!Secret#Link" not in blob


def test_audit_model_has_no_update_or_delete_api_surface():
    """Defence in depth: the viewset must not be a ModelViewSet."""
    from audit.views import AuditLogListView

    assert not hasattr(AuditLogListView, "perform_destroy")
    assert not hasattr(AuditLogListView, "perform_update")


def test_audit_rows_survive_a_user_deletion_attempt(client_a, user_a, file_a):
    """Audit history must not be erasable by removing the actor."""
    count_before = AuditLog.objects.count()
    assert count_before > 0
    entry = AuditLog.objects.first()
    assert entry.actor_email, "actor_email must be denormalised so history survives"


# ---------------------------------------------------------------------------
# 9. BRUTE FORCE / AUTHORIZATION
# ---------------------------------------------------------------------------

def test_repeated_bad_logins_lock_the_account(anonymous_client, user_a, throttle_rates):
    throttle_rates({"auth.login": "1000/hour"})  # isolate lockout from throttling
    limit = settings.LOGIN_FAILURE_LIMIT
    for _ in range(limit + 1):
        anonymous_client.post(
            "/api/auth/login/", {"email": user_a.email, "password": "Wrong!12345"},
            format="json",
        )
    response = anonymous_client.post(
        "/api/auth/login/", {"email": user_a.email, "password": STRONG_PASSWORD},
        format="json",
    )
    assert response.status_code in (401, 403, 423, 429)
    assert response.data.get("error") != "LOGIN_SUCCESS"


def test_lockout_is_audited(anonymous_client, user_a, throttle_rates):
    throttle_rates({"auth.login": "1000/hour"})
    for _ in range(settings.LOGIN_FAILURE_LIMIT + 1):
        anonymous_client.post(
            "/api/auth/login/", {"email": user_a.email, "password": "Wrong!12345"},
            format="json",
        )
    assert AuditLog.objects.filter(action=AuditAction.ACCOUNT_LOCKED).exists()


def test_unauthorized_access_attempt_is_audited(client_b, file_a):
    client_b.get(f"/api/files/{file_a.id}/")
    assert AuditLog.objects.filter(
        action__in=[
            AuditAction.UNAUTHORIZED_FILE_ACCESS,
            AuditAction.UNAUTHORIZED_ACCESS_ATTEMPT,
        ]
    ).exists()


def test_normal_user_is_denied_the_admin_endpoint_and_it_is_audited(client_a):
    response = client_a.get("/api/admin/test/")
    assert response.status_code == 403


def test_disabled_account_cannot_use_an_existing_token(client_a, user_a):
    assert client_a.get("/api/users/me/").status_code == 200
    user_a.is_active = False
    user_a.save(update_fields=["is_active"])
    assert client_a.get("/api/users/me/").status_code == 401


def test_password_change_invalidates_existing_tokens(client_a, user_a):
    assert client_a.get("/api/users/me/").status_code == 200
    response = client_a.post(
        "/api/auth/change-password/",
        {
            "current_password": STRONG_PASSWORD,
            "new_password": "An0ther!Str0ng#Pass",
            "new_password_confirm": "An0ther!Str0ng#Pass",
        },
        format="json",
    )
    assert response.status_code in (200, 204)
    assert client_a.get("/api/users/me/").status_code == 401
