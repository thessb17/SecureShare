"""Phase 2: authentication, password policy, lockout, JWT lifecycle."""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from audit.constants import AuditAction
from audit.models import AuditLog, LoginAttempt
from tests.conftest import STRONG_PASSWORD

User = get_user_model()
pytestmark = pytest.mark.django_db

REGISTER_URL = "/api/auth/register/"
LOGIN_URL = "/api/auth/login/"
REFRESH_URL = "/api/auth/refresh/"
LOGOUT_URL = "/api/auth/logout/"
CHANGE_PASSWORD_URL = "/api/auth/change-password/"
ME_URL = "/api/users/me/"


def register(client, email="new@example.com", password=STRONG_PASSWORD, **extra):
    payload = {
        "email": email,
        "password": password,
        "password_confirm": extra.pop("password_confirm", password),
        "full_name": extra.pop("full_name", "New User"),
    }
    payload.update(extra)
    return client.post(REGISTER_URL, payload, format="json")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
def test_registration_creates_user_and_returns_tokens(api_client):
    response = register(api_client)
    assert response.status_code == 201, response.data
    assert response.data["user"]["email"] == "new@example.com"
    assert response.data["user"]["role"] == "USER"
    assert response.data["tokens"]["access"]
    assert response.data["tokens"]["refresh"]
    # No password material is ever echoed back.
    assert STRONG_PASSWORD not in str(response.data)
    assert "password" not in response.data["user"]

    user = User.objects.get(email="new@example.com")
    # The password is stored as an Argon2id hash, never in plaintext.
    assert user.password.startswith("argon2")
    assert STRONG_PASSWORD not in user.password
    assert user.check_password(STRONG_PASSWORD)


def test_registration_audits_the_event(api_client):
    register(api_client)
    assert AuditLog.objects.filter(action=AuditAction.USER_REGISTERED, success=True).exists()


def test_duplicate_registration_is_rejected(api_client, user_a):
    response = register(api_client, email=user_a.email)
    assert response.status_code == 409
    assert response.data["error"] == "EMAIL_ALREADY_REGISTERED"


def test_registration_normalises_email_case(api_client):
    assert register(api_client, email="MiXeD@Example.COM").status_code == 201
    assert User.objects.filter(email="mixed@example.com").exists()


@pytest.mark.parametrize(
    "password",
    [
        "short1!A",          # too short
        "alllowercase123!",  # no uppercase
        "ALLUPPERCASE123!",  # no lowercase
        "NoDigitsHere!!!!",  # no digit
        "NoSymbols12345A",   # no symbol
        "password",          # common + weak
        "12345678901234",    # numeric only
    ],
)
def test_weak_passwords_are_rejected(api_client, password):
    response = register(api_client, email=f"weak-{abs(hash(password))}@example.com",
                        password=password)
    assert response.status_code == 400
    assert response.data["error"] == "VALIDATION_ERROR"
    assert not User.objects.filter(email__startswith="weak-").exists()


def test_password_confirmation_must_match(api_client):
    response = register(api_client, password_confirm="Different!Pass#2026")
    assert response.status_code == 400


def test_registration_cannot_self_assign_admin_role(api_client):
    response = register(api_client, email="escalate@example.com", role="ADMIN")
    assert response.status_code == 201
    assert User.objects.get(email="escalate@example.com").role == "USER"


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
def test_login_succeeds_with_valid_credentials(api_client, user_a):
    response = api_client.post(
        LOGIN_URL, {"email": user_a.email, "password": STRONG_PASSWORD}, format="json"
    )
    assert response.status_code == 200
    assert response.data["tokens"]["access"]
    assert LoginAttempt.objects.filter(email=user_a.email, successful=True).exists()
    assert AuditLog.objects.filter(action=AuditAction.LOGIN_SUCCESS).exists()


def test_login_fails_with_wrong_password(api_client, user_a):
    response = api_client.post(
        LOGIN_URL, {"email": user_a.email, "password": "Wrong!Password123"},
        format="json",
    )
    assert response.status_code == 401
    assert response.data["error"] == "INVALID_CREDENTIALS"
    assert AuditLog.objects.filter(action=AuditAction.LOGIN_FAILURE).exists()


def test_login_with_unknown_account_returns_identical_error(api_client, user_a):
    unknown = api_client.post(
        LOGIN_URL, {"email": "ghost@example.com", "password": "Wrong!Password123"},
        format="json",
    )
    known = api_client.post(
        LOGIN_URL, {"email": user_a.email, "password": "Wrong!Password123"},
        format="json",
    )
    # No user enumeration: same status code and same message.
    assert unknown.status_code == known.status_code == 401
    assert unknown.data["error"] == known.data["error"]
    assert unknown.data["message"] == known.data["message"]


def test_disabled_account_cannot_log_in(api_client, user_a):
    user_a.is_active = False
    user_a.save(update_fields=["is_active"])
    response = api_client.post(
        LOGIN_URL, {"email": user_a.email, "password": STRONG_PASSWORD}, format="json"
    )
    assert response.status_code == 403
    assert response.data["error"] == "ACCOUNT_DISABLED"


def test_account_locks_after_repeated_failures(api_client, user_a):
    for _ in range(settings.LOGIN_FAILURE_LIMIT):
        api_client.post(
            LOGIN_URL, {"email": user_a.email, "password": "Wrong!Password123"},
            format="json",
        )
    user_a.refresh_from_db()
    assert user_a.is_locked

    # Even the correct password is refused while locked.
    response = api_client.post(
        LOGIN_URL, {"email": user_a.email, "password": STRONG_PASSWORD}, format="json"
    )
    assert response.status_code == 423
    assert response.data["error"] == "ACCOUNT_LOCKED"
    assert AuditLog.objects.filter(action=AuditAction.ACCOUNT_LOCKED).exists()


def test_locked_account_hides_lockout_from_attackers(api_client, user_a):
    user_a.lock(600)
    response = api_client.post(
        LOGIN_URL, {"email": user_a.email, "password": "Wrong!Password123"},
        format="json",
    )
    # Someone who does not know the password only sees the generic error.
    assert response.status_code == 401
    assert response.data["error"] == "INVALID_CREDENTIALS"


def test_successful_login_resets_failure_counter(api_client, user_a):
    api_client.post(
        LOGIN_URL, {"email": user_a.email, "password": "Wrong!Password123"},
        format="json",
    )
    user_a.refresh_from_db()
    assert user_a.failed_login_count == 1

    api_client.post(
        LOGIN_URL, {"email": user_a.email, "password": STRONG_PASSWORD}, format="json"
    )
    user_a.refresh_from_db()
    assert user_a.failed_login_count == 0


def test_login_endpoint_is_rate_limited(api_client, user_a, throttle_rates):
    throttle_rates({"auth.login": "3/min"})
    statuses = [
        api_client.post(
            LOGIN_URL, {"email": user_a.email, "password": "Wrong!Password123"},
            format="json",
        ).status_code
        for _ in range(5)
    ]
    assert 429 in statuses
    assert statuses[-1] == 429


def test_registration_endpoint_is_rate_limited(api_client, throttle_rates):
    throttle_rates({"auth.register": "2/hour"})
    codes = [register(api_client, email=f"r{i}@example.com").status_code for i in range(4)]
    assert 429 in codes


# ---------------------------------------------------------------------------
# JWT lifecycle
# ---------------------------------------------------------------------------
def test_me_endpoint_requires_authentication(api_client):
    response = api_client.get(ME_URL)
    assert response.status_code == 401
    assert response.data["error"] == "AUTHENTICATION_REQUIRED"


def test_me_endpoint_returns_the_current_user(client_a, user_a):
    response = client_a.get(ME_URL)
    assert response.status_code == 200
    assert response.data["email"] == user_a.email
    assert "password" not in response.data


def test_invalid_token_is_rejected(api_client):
    api_client.credentials(HTTP_AUTHORIZATION="Bearer not-a-real-token")
    assert api_client.get(ME_URL).status_code == 401


def test_tampered_token_signature_is_rejected(api_client, user_a):
    from accounts.tokens import create_tokens_for_user

    token = create_tokens_for_user(user_a)["access"]
    header, payload, signature = token.split(".")
    forged = f"{header}.{payload}.{signature[:-3]}abc"
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {forged}")
    assert api_client.get(ME_URL).status_code == 401


def test_expired_access_token_is_rejected(api_client, user_a):
    token = AccessToken.for_user(user_a)
    token["tv"] = user_a.token_version
    token.set_exp(lifetime=timedelta(seconds=-30))
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    assert api_client.get(ME_URL).status_code == 401


def test_refresh_rotates_and_blacklists_the_old_token(api_client, user_a):
    login = api_client.post(
        LOGIN_URL, {"email": user_a.email, "password": STRONG_PASSWORD}, format="json"
    )
    refresh = login.data["tokens"]["refresh"]

    first = api_client.post(REFRESH_URL, {"refresh": refresh}, format="json")
    assert first.status_code == 200
    assert first.data["access"]

    # Replaying the rotated refresh token must fail.
    replay = api_client.post(REFRESH_URL, {"refresh": refresh}, format="json")
    assert replay.status_code == 400
    assert replay.data["error"] == "INVALID_TOKEN"


def test_logout_blacklists_the_refresh_token(api_client, user_a, authenticate):
    login = api_client.post(
        LOGIN_URL, {"email": user_a.email, "password": STRONG_PASSWORD}, format="json"
    )
    tokens = login.data["tokens"]
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

    response = api_client.post(LOGOUT_URL, {"refresh": tokens["refresh"]}, format="json")
    assert response.status_code == 200
    assert AuditLog.objects.filter(action=AuditAction.LOGOUT).exists()

    reuse = APIClientFactory().post(REFRESH_URL, {"refresh": tokens["refresh"]}, format="json")
    assert reuse.status_code == 400


def APIClientFactory():
    from rest_framework.test import APIClient

    return APIClient()


def test_logout_rejects_another_users_refresh_token(client_a, user_b):
    other_refresh = str(RefreshToken.for_user(user_b))
    response = client_a.post(LOGOUT_URL, {"refresh": other_refresh}, format="json")
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Password change / reset
# ---------------------------------------------------------------------------
def test_change_password_requires_the_current_password(client_a):
    response = client_a.post(
        CHANGE_PASSWORD_URL,
        {
            "current_password": "Wrong!Password123",
            "new_password": "Brand!NewPass#2026",
            "new_password_confirm": "Brand!NewPass#2026",
        },
        format="json",
    )
    assert response.status_code == 401
    assert response.data["error"] == "INVALID_CREDENTIALS"


def test_change_password_rejects_weak_new_password(client_a):
    response = client_a.post(
        CHANGE_PASSWORD_URL,
        {
            "current_password": STRONG_PASSWORD,
            "new_password": "weak",
            "new_password_confirm": "weak",
        },
        format="json",
    )
    assert response.status_code == 400


def test_change_password_revokes_existing_tokens(api_client, user_a):
    from accounts.tokens import create_tokens_for_user

    tokens = create_tokens_for_user(user_a)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

    response = api_client.post(
        CHANGE_PASSWORD_URL,
        {
            "current_password": STRONG_PASSWORD,
            "new_password": "Brand!NewPass#2026",
            "new_password_confirm": "Brand!NewPass#2026",
        },
        format="json",
    )
    assert response.status_code == 200
    assert response.data["tokens"]["access"]
    assert AuditLog.objects.filter(action=AuditAction.PASSWORD_CHANGED, success=True).exists()

    # The old access token is now invalid (token_version was bumped).
    assert api_client.get(ME_URL).status_code == 401

    user_a.refresh_from_db()
    assert user_a.check_password("Brand!NewPass#2026")


def test_password_reset_request_does_not_reveal_account_existence(api_client, user_a):
    known = api_client.post(
        "/api/auth/password-reset/", {"email": user_a.email}, format="json"
    )
    unknown = api_client.post(
        "/api/auth/password-reset/", {"email": "nobody@example.com"}, format="json"
    )
    assert known.status_code == unknown.status_code == 202
    assert known.data == unknown.data


def test_password_reset_confirm_flow(api_client, user_a):
    from django.utils.encoding import force_bytes
    from django.utils.http import urlsafe_base64_encode

    from accounts.tokens import password_reset_token_generator

    uid = urlsafe_base64_encode(force_bytes(user_a.pk))
    token = password_reset_token_generator.make_token(user_a)

    response = api_client.post(
        "/api/auth/password-reset/confirm/",
        {
            "uid": uid,
            "token": token,
            "new_password": "Reset!Password#2026",
            "new_password_confirm": "Reset!Password#2026",
        },
        format="json",
    )
    assert response.status_code == 200
    user_a.refresh_from_db()
    assert user_a.check_password("Reset!Password#2026")

    # The single-use token cannot be replayed.
    replay = api_client.post(
        "/api/auth/password-reset/confirm/",
        {
            "uid": uid,
            "token": token,
            "new_password": "Another!Password#2026",
            "new_password_confirm": "Another!Password#2026",
        },
        format="json",
    )
    assert replay.status_code == 400


def test_revoke_sessions_invalidates_all_tokens(api_client, user_a):
    from accounts.tokens import create_tokens_for_user

    tokens = create_tokens_for_user(user_a)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
    assert api_client.get(ME_URL).status_code == 200

    response = api_client.post("/api/auth/revoke-sessions/", {}, format="json")
    assert response.status_code == 200
    assert api_client.get(ME_URL).status_code == 401
