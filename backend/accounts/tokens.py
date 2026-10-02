"""JWT issuance plus password-reset / email-verification tokens."""
from __future__ import annotations

from typing import Any

from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core import signing
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)
from rest_framework_simplejwt.tokens import RefreshToken

EMAIL_VERIFICATION_SALT = "secureshare.email-verification.v1"


class SecurePasswordResetTokenGenerator(PasswordResetTokenGenerator):
    """Reset tokens are invalidated by a password change *and* by token rotation."""

    def _make_hash_value(self, user: Any, timestamp: int) -> str:
        login_timestamp = (
            ""
            if user.last_login is None
            else user.last_login.replace(microsecond=0, tzinfo=None)
        )
        return (
            f"{user.pk}{user.password}{login_timestamp}{timestamp}"
            f"{user.is_active}{user.token_version}"
        )


password_reset_token_generator = SecurePasswordResetTokenGenerator()


def create_tokens_for_user(user: Any) -> dict[str, Any]:
    """Issue an access/refresh pair carrying the role and token version."""
    refresh = RefreshToken.for_user(user)
    refresh["role"] = user.role
    refresh["tv"] = user.token_version
    access = refresh.access_token
    access["role"] = user.role
    access["tv"] = user.token_version
    return {
        "access": str(access),
        "refresh": str(refresh),
        "token_type": "Bearer",
        "expires_in": int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()),
    }


def blacklist_all_refresh_tokens(user: Any) -> int:
    """Blacklist every outstanding refresh token of a user."""
    count = 0
    for token in OutstandingToken.objects.filter(user=user):
        _, created = BlacklistedToken.objects.get_or_create(token=token)
        count += int(created)
    return count


def make_email_verification_token(user: Any) -> str:
    return signing.dumps(
        {"uid": str(user.pk), "email": user.email},
        salt=EMAIL_VERIFICATION_SALT,
    )


def read_email_verification_token(token: str) -> dict[str, str]:
    """Raises ``django.core.signing.BadSignature`` / ``SignatureExpired``."""
    return signing.loads(
        token,
        salt=EMAIL_VERIFICATION_SALT,
        max_age=settings.EMAIL_VERIFICATION_TIMEOUT,
    )
