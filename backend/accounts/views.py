"""Authentication, account and RBAC endpoints."""
from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.serializers import (
    ChangePasswordSerializer,
    EmailVerificationConfirmSerializer,
    LoginSerializer,
    LogoutSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    RefreshSerializer,
    RegistrationSerializer,
    TokenPairSerializer,
    UserSerializer,
)
from accounts.services import AuthenticationService, InvalidCredentials
from accounts.throttles import (
    ChangePasswordThrottle,
    LoginThrottle,
    PasswordResetThrottle,
    RefreshThrottle,
    RegistrationThrottle,
)
from accounts.tokens import (
    blacklist_all_refresh_tokens,
    create_tokens_for_user,
    make_email_verification_token,
    password_reset_token_generator,
    read_email_verification_token,
)
from audit.constants import AuditAction
from audit.services import record_event
from core.exceptions import APIError, ConflictError
from core.permissions import IsActiveUser, IsAdminRole

logger = logging.getLogger("secureshare")
security_logger = logging.getLogger("secureshare.security")
User = get_user_model()

GENERIC_RESET_RESPONSE = {
    "detail": (
        "If an account exists for that address, a password reset link has been sent."
    )
}


class InvalidToken(APIError):
    status_code = status.HTTP_400_BAD_REQUEST
    error_code = "INVALID_TOKEN"
    default_detail = "The supplied token is invalid or has expired."


@extend_schema(tags=["Authentication"])
class RegisterView(APIView):
    """``POST /api/auth/register/`` - create a USER account."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [RegistrationThrottle]
    throttle_scope = "auth.register"

    @extend_schema(
        request=RegistrationSerializer,
        responses={
            201: OpenApiResponse(description="Account created; JWT pair returned."),
            409: OpenApiResponse(description="Email already registered."),
        },
    )
    def post(self, request: Request) -> Response:
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        if User.objects.filter(email=email).exists():
            record_event(
                action=AuditAction.USER_REGISTERED,
                request=request,
                success=False,
                message="Registration rejected: email already in use.",
                metadata={"email": email},
            )
            raise ConflictError(
                "An account with this email address already exists.",
                error_code="EMAIL_ALREADY_REGISTERED",
            )

        user = serializer.save()
        record_event(
            action=AuditAction.USER_REGISTERED,
            request=request,
            user=user,
            message="Account registered.",
            object_type="user",
            object_id=user.pk,
            object_owner=user,
            metadata={"email": user.email, "role": user.role},
        )
        _send_verification_email(user, request)

        return Response(
            {
                "user": UserSerializer(user).data,
                "tokens": create_tokens_for_user(user),
                "email_verification_required": not user.is_email_verified,
            },
            status=status.HTTP_201_CREATED,
        )


@extend_schema(tags=["Authentication"])
class LoginView(APIView):
    """``POST /api/auth/login/`` - exchange credentials for a JWT pair."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [LoginThrottle]
    throttle_scope = "auth.login"

    @extend_schema(
        request=LoginSerializer,
        responses={
            200: TokenPairSerializer,
            401: OpenApiResponse(description="Invalid credentials."),
            423: OpenApiResponse(description="Account locked."),
            429: OpenApiResponse(description="Too many attempts."),
        },
    )
    def post(self, request: Request) -> Response:
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = AuthenticationService.authenticate(
            email=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
            request=request,
        )
        return Response(
            {
                "user": UserSerializer(result.user).data,
                "tokens": create_tokens_for_user(result.user),
            }
        )


@extend_schema(tags=["Authentication"])
class TokenRefreshView(APIView):
    """``POST /api/auth/refresh/`` - rotate the refresh token."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [RefreshThrottle]
    throttle_scope = "auth.refresh"

    @extend_schema(request=RefreshSerializer, responses={200: TokenPairSerializer})
    def post(self, request: Request) -> Response:
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            token = RefreshToken(serializer.validated_data["refresh"])
        except TokenError as exc:
            raise InvalidToken("The refresh token is invalid or has expired.") from exc

        user = User.objects.filter(pk=token.get("user_id")).first()
        if user is None or not user.is_active or user.is_locked:
            raise InvalidToken("The refresh token is no longer valid.")
        if int(token.get("tv", -1)) != int(user.token_version):
            raise InvalidToken("The refresh token has been revoked.")

        # Rotation: the presented token is blacklisted and a new pair issued.
        try:
            token.blacklist()
        except AttributeError:  # pragma: no cover - blacklist app always on
            pass

        record_event(
            action=AuditAction.TOKEN_REFRESHED,
            request=request,
            user=user,
            message="Access token refreshed.",
            object_type="user",
            object_id=user.pk,
            object_owner=user,
        )
        return Response(create_tokens_for_user(user))


@extend_schema(tags=["Authentication"])
class LogoutView(APIView):
    """``POST /api/auth/logout/`` - blacklist the presented refresh token."""

    permission_classes = [IsActiveUser]

    @extend_schema(request=LogoutSerializer, responses={200: OpenApiResponse()})
    def post(self, request: Request) -> Response:
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            token = RefreshToken(serializer.validated_data["refresh"])
            if str(token.get("user_id")) != str(request.user.pk):
                raise InvalidToken("The refresh token does not belong to this user.")
            token.blacklist()
        except TokenError as exc:
            raise InvalidToken("The refresh token is invalid or has expired.") from exc

        record_event(
            action=AuditAction.LOGOUT,
            request=request,
            user=request.user,
            message="User signed out.",
            object_type="user",
            object_id=request.user.pk,
            object_owner=request.user,
        )
        return Response({"detail": "Signed out."})


@extend_schema(tags=["Authentication"])
class RevokeSessionsView(APIView):
    """``POST /api/auth/revoke-sessions/`` - invalidate every issued token."""

    permission_classes = [IsActiveUser]

    @extend_schema(request=None, responses={200: TokenPairSerializer})
    def post(self, request: Request) -> Response:
        user = request.user
        revoked = blacklist_all_refresh_tokens(user)
        user.revoke_tokens()
        record_event(
            action=AuditAction.TOKENS_REVOKED,
            request=request,
            user=user,
            message="All sessions revoked.",
            object_type="user",
            object_id=user.pk,
            object_owner=user,
            metadata={"blacklisted_refresh_tokens": revoked},
        )
        return Response(
            {"detail": "All sessions revoked.", "tokens": create_tokens_for_user(user)}
        )


@extend_schema(tags=["Authentication"])
class ChangePasswordView(APIView):
    """``POST /api/auth/change-password/``."""

    permission_classes = [IsActiveUser]
    throttle_classes = [ChangePasswordThrottle]
    throttle_scope = "auth.change_password"

    @extend_schema(request=ChangePasswordSerializer, responses={200: TokenPairSerializer})
    def post(self, request: Request) -> Response:
        serializer = ChangePasswordSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = request.user

        if not user.check_password(serializer.validated_data["current_password"]):
            record_event(
                action=AuditAction.PASSWORD_CHANGED,
                request=request,
                user=user,
                success=False,
                message="Password change rejected: current password incorrect.",
                object_type="user",
                object_id=user.pk,
                object_owner=user,
            )
            raise InvalidCredentials("The current password is incorrect.")

        user.set_password(serializer.validated_data["new_password"])
        user.mark_password_changed()
        blacklist_all_refresh_tokens(user)

        record_event(
            action=AuditAction.PASSWORD_CHANGED,
            request=request,
            user=user,
            message="Password changed; all previous sessions revoked.",
            object_type="user",
            object_id=user.pk,
            object_owner=user,
        )
        return Response(
            {
                "detail": "Password updated. Previous sessions were revoked.",
                "tokens": create_tokens_for_user(user),
            }
        )


@extend_schema(tags=["Authentication"])
class PasswordResetRequestView(APIView):
    """``POST /api/auth/password-reset/`` - always returns the same response."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]
    throttle_scope = "auth.password_reset"

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses={202: OpenApiResponse(description="Generic acknowledgement.")},
    )
    def post(self, request: Request) -> Response:
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        user = User.objects.filter(email=email, is_active=True).first()

        record_event(
            action=AuditAction.PASSWORD_RESET_REQUESTED,
            request=request,
            user=user,
            message="Password reset requested.",
            object_type="user",
            object_id=user.pk if user else "",
            object_owner=user,
            metadata={"email": email, "account_exists": bool(user)},
        )

        if user is not None:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = password_reset_token_generator.make_token(user)
            reset_url = (
                f"{settings.FRONTEND_BASE_URL}/reset-password?uid={uid}&token={token}"
            )
            _send_mail_safely(
                subject="SecureShare password reset",
                message=(
                    "A password reset was requested for your SecureShare account.\n\n"
                    f"Reset link (valid for {settings.PASSWORD_RESET_TIMEOUT // 60} "
                    f"minutes): {reset_url}\n\n"
                    "If you did not request this, you can ignore this email."
                ),
                recipient=user.email,
            )
        # Identical response whether or not the account exists.
        return Response(GENERIC_RESET_RESPONSE, status=status.HTTP_202_ACCEPTED)


@extend_schema(tags=["Authentication"])
class PasswordResetConfirmView(APIView):
    """``POST /api/auth/password-reset/confirm/``."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]
    throttle_scope = "auth.password_reset"

    @extend_schema(request=PasswordResetConfirmSerializer, responses={200: OpenApiResponse()})
    def post(self, request: Request) -> Response:
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            user_id = force_str(urlsafe_base64_decode(data["uid"]))
            user = User.objects.get(pk=user_id)
        except Exception as exc:
            raise InvalidToken("The reset link is invalid or has expired.") from exc

        if not password_reset_token_generator.check_token(user, data["token"]):
            record_event(
                action=AuditAction.PASSWORD_RESET_COMPLETED,
                request=request,
                success=False,
                message="Password reset rejected: invalid token.",
                object_type="user",
                object_id=user.pk,
                object_owner=user,
            )
            raise InvalidToken("The reset link is invalid or has expired.")

        serializer._validate_password_policy(data["new_password"], user)
        user.set_password(data["new_password"])
        user.mark_password_changed()
        blacklist_all_refresh_tokens(user)

        record_event(
            action=AuditAction.PASSWORD_RESET_COMPLETED,
            request=request,
            user=user,
            message="Password reset completed; all sessions revoked.",
            object_type="user",
            object_id=user.pk,
            object_owner=user,
        )
        return Response({"detail": "Password updated. You can now sign in."})


@extend_schema(tags=["Authentication"])
class EmailVerificationRequestView(APIView):
    permission_classes = [IsActiveUser]
    throttle_classes = [PasswordResetThrottle]
    throttle_scope = "auth.password_reset"

    @extend_schema(request=None, responses={202: OpenApiResponse()})
    def post(self, request: Request) -> Response:
        _send_verification_email(request.user, request)
        return Response(
            {"detail": "Verification email sent."}, status=status.HTTP_202_ACCEPTED
        )


@extend_schema(tags=["Authentication"])
class EmailVerificationConfirmView(APIView):
    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]
    throttle_scope = "auth.password_reset"

    @extend_schema(request=EmailVerificationConfirmSerializer, responses={200: OpenApiResponse()})
    def post(self, request: Request) -> Response:
        serializer = EmailVerificationConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            payload = read_email_verification_token(serializer.validated_data["token"])
        except signing.BadSignature as exc:
            raise InvalidToken("The verification link is invalid or has expired.") from exc

        user = User.objects.filter(pk=payload.get("uid"), email=payload.get("email")).first()
        if user is None:
            raise InvalidToken("The verification link is invalid or has expired.")

        if not user.is_email_verified:
            user.is_email_verified = True
            user.save(update_fields=["is_email_verified", "updated_at"])
        record_event(
            action=AuditAction.EMAIL_VERIFIED,
            request=request,
            user=user,
            message="Email address verified.",
            object_type="user",
            object_id=user.pk,
            object_owner=user,
        )
        return Response({"detail": "Email address verified."})


@extend_schema(tags=["Users"])
class CurrentUserView(RetrieveUpdateAPIView):
    """``GET/PATCH /api/users/me/``."""

    serializer_class = UserSerializer
    permission_classes = [IsActiveUser]
    http_method_names = ["get", "patch", "head", "options"]

    def get_object(self):
        return self.request.user


@extend_schema(tags=["Admin"])
class AdminTestView(APIView):
    """``GET /api/admin/test/`` - proves RBAC is enforced server-side."""

    permission_classes = [IsAdminRole]

    @extend_schema(
        responses={
            200: OpenApiResponse(description="Administrator access confirmed."),
            403: OpenApiResponse(description="Administrator privileges required."),
        }
    )
    def get(self, request: Request) -> Response:
        record_event(
            action=AuditAction.ADMIN_ACTION,
            request=request,
            user=request.user,
            message="Administrative endpoint accessed.",
            metadata={"endpoint": "admin/test"},
        )
        return Response(
            {
                "status": "ok",
                "message": "Administrator access confirmed.",
                "user": UserSerializer(request.user).data,
            }
        )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _send_mail_safely(*, subject: str, message: str, recipient: str) -> None:
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient],
            fail_silently=False,
        )
    except Exception:
        logger.warning("Unable to send transactional email", exc_info=True)


def _send_verification_email(user: Any, request: Request) -> None:
    token = make_email_verification_token(user)
    url = f"{settings.FRONTEND_BASE_URL}/verify-email?token={token}"
    _send_mail_safely(
        subject="Verify your SecureShare email address",
        message=f"Confirm your email address by opening: {url}",
        recipient=user.email,
    )
    record_event(
        action=AuditAction.EMAIL_VERIFICATION_SENT,
        request=request,
        user=user,
        message="Verification email sent.",
        object_type="user",
        object_id=user.pk,
        object_owner=user,
    )
