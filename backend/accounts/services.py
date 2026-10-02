"""Authentication service: credential verification, lockout and auditing.

Keeping this logic out of the views means the same rules apply to any future
entry point (management commands, admin tooling, a GraphQL layer...).
"""
from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.utils.translation import gettext as _

from audit.constants import AuditAction
from audit.services import record_event, record_login_attempt
from core.exceptions import APIError
from core.request_meta import get_client_ip

logger = logging.getLogger("secureshare.security")
User = get_user_model()

#: Hashing a dummy password for unknown accounts keeps the response time of
#: "user does not exist" indistinguishable from "wrong password".
_DUMMY_HASH = make_password(secrets.token_urlsafe(32))

GENERIC_LOGIN_ERROR = _("Invalid email address or password.")


class InvalidCredentials(APIError):
    status_code = 401
    error_code = "INVALID_CREDENTIALS"
    default_detail = GENERIC_LOGIN_ERROR


class AccountLocked(APIError):
    status_code = 423
    error_code = "ACCOUNT_LOCKED"
    default_detail = _(
        "This account is temporarily locked after repeated failed sign-in attempts."
    )


class AccountDisabled(APIError):
    status_code = 403
    error_code = "ACCOUNT_DISABLED"
    default_detail = _("This account has been disabled.")


@dataclass(frozen=True)
class AuthenticationResult:
    user: Any


class AuthenticationService:
    """Verifies credentials and maintains brute-force counters."""

    @staticmethod
    def authenticate(*, email: str, password: str, request: Any = None):
        normalised = (email or "").strip().lower()
        user = User.objects.filter(email=normalised).first()

        if user is None:
            # Constant-ish work to avoid a user-enumeration timing oracle.
            check_password(password, _DUMMY_HASH)
            record_login_attempt(
                email=normalised, successful=False, request=request, reason="unknown_user"
            )
            record_event(
                action=AuditAction.LOGIN_FAILURE,
                request=request,
                success=False,
                message="Login failed: unknown account.",
                metadata={"email": normalised, "reason": "unknown_user"},
            )
            raise InvalidCredentials()

        password_ok = user.check_password(password)

        if user.is_locked:
            record_login_attempt(
                email=normalised,
                successful=False,
                request=request,
                user=user,
                reason="locked",
            )
            record_event(
                action=AuditAction.LOGIN_FAILURE,
                request=request,
                user=None,
                success=False,
                message="Login rejected: account locked.",
                metadata={
                    "email": normalised,
                    "reason": "locked",
                    "retry_after_seconds": user.lock_expires_in,
                },
            )
            # Only confirm the lockout to a client that proved it knows the
            # password; everyone else gets the generic error.
            if password_ok:
                raise AccountLocked(
                    details={"retry_after_seconds": user.lock_expires_in}
                )
            raise InvalidCredentials()

        if not password_ok:
            locked = user.register_failed_login()
            record_login_attempt(
                email=normalised,
                successful=False,
                request=request,
                user=user,
                reason="bad_password",
            )
            record_event(
                action=AuditAction.LOGIN_FAILURE,
                request=request,
                success=False,
                message="Login failed: invalid password.",
                metadata={
                    "email": normalised,
                    "reason": "bad_password",
                    "failed_attempts": user.failed_login_count,
                },
            )
            if locked:
                record_event(
                    action=AuditAction.ACCOUNT_LOCKED,
                    request=request,
                    success=False,
                    message="Account locked after repeated failed sign-in attempts.",
                    object_type="user",
                    object_id=user.pk,
                    object_owner=user,
                    metadata={
                        "email": normalised,
                        "lock_seconds": settings.LOGIN_LOCKOUT_SECONDS,
                    },
                )
            raise InvalidCredentials()

        if not user.is_active:
            record_login_attempt(
                email=normalised,
                successful=False,
                request=request,
                user=user,
                reason="disabled",
            )
            record_event(
                action=AuditAction.LOGIN_FAILURE,
                request=request,
                success=False,
                message="Login rejected: account disabled.",
                metadata={"email": normalised, "reason": "disabled"},
            )
            raise AccountDisabled()

        user.register_successful_login(ip_address=get_client_ip(request))
        record_login_attempt(
            email=normalised, successful=True, request=request, user=user
        )
        record_event(
            action=AuditAction.LOGIN_SUCCESS,
            request=request,
            user=user,
            message="Login successful.",
            object_type="user",
            object_id=user.pk,
            object_owner=user,
        )
        return AuthenticationResult(user=user)
