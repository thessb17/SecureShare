"""JWT authentication with account-state and token-version enforcement."""
from __future__ import annotations

from typing import Any

from drf_spectacular.extensions import OpenApiAuthenticationExtension
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed


class SecureJWTAuthentication(JWTAuthentication):
    """Adds three checks on top of signature/expiry validation.

    1. the account must still be enabled (``is_active``);
    2. the account must not be locked out;
    3. the ``tv`` (token version) claim must match the user record, which is how
       password changes and "revoke all sessions" invalidate issued tokens.
    """

    def get_user(self, validated_token: Any):
        user = super().get_user(validated_token)

        if getattr(user, "is_locked", False):
            raise AuthenticationFailed(
                "This account is temporarily locked.", code="account_locked"
            )

        claimed_version = validated_token.get("tv")
        if claimed_version is None or int(claimed_version) != int(user.token_version):
            raise AuthenticationFailed(
                "This token has been revoked.", code="token_revoked"
            )
        return user


class SecureJWTScheme(OpenApiAuthenticationExtension):
    """Teach drf-spectacular about the custom authenticator.

    Without this the generated OpenAPI document silently omits the security
    scheme for every protected endpoint and Swagger UI offers no "Authorize"
    button.
    """

    target_class = "accounts.authentication.SecureJWTAuthentication"
    name = "BearerAuth"

    def get_security_definition(self, auto_schema: Any) -> dict[str, Any]:
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": (
                "Access token from POST /api/auth/login/. "
                "Send as: Authorization: Bearer <access token>."
            ),
        }
