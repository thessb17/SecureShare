"""Admin console APIs: user management and security event search.

Authorization is enforced here, on the server, by ``IsAdminRole``. The React
admin routes are a convenience only - a normal USER calling these endpoints
directly receives 403 regardless of what the frontend renders.

Every administrative mutation writes an ``ADMIN_ACTION`` audit event.
"""
from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.db.models import Count, Q, QuerySet
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers, status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from audit.constants import AuditAction, AuditSeverity
from audit.models import AuditLog
from audit.serializers import AuditLogSerializer
from audit.services import record_event
from core.pagination import DefaultPagination
from core.permissions import IsActiveUser, IsAdminRole

User = get_user_model()


def _parse_bound(value: str, field: str) -> Any:
    """Parse an ISO-8601 filter bound, or reject it.

    A bad timestamp must not be ignored: silently dropping the filter would
    show an administrator the whole log while the UI claims a date range is
    applied. A space is tolerated where a "+" was lost to URL decoding.
    """
    parsed = parse_datetime(value) or parse_datetime(value.replace(" ", "+", 1))
    if parsed is None:
        raise ValidationError({field: ["Expected an ISO-8601 timestamp."]})
    return parsed


class AdminUserSerializer(serializers.ModelSerializer):
    """Account state only. No password hash, no tokens, no secrets."""

    file_count = serializers.IntegerField(read_only=True)
    is_locked = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "full_name",
            "role",
            "is_active",
            "is_email_verified",
            "created_at",
            "last_login",
            "failed_login_count",
            "locked_until",
            "is_locked",
            "file_count",
        )
        read_only_fields = fields

    def get_is_locked(self, obj: Any) -> bool:
        return bool(obj.locked_until and obj.locked_until > timezone.now())


class AdminUserListView(ListAPIView):
    serializer_class = AdminUserSerializer
    permission_classes = [IsActiveUser, IsAdminRole]
    pagination_class = DefaultPagination

    @extend_schema(
        tags=["Admin"],
        parameters=[
            OpenApiParameter("search", str, description="Match email or full name."),
            OpenApiParameter("status", str, description="active | disabled | locked | admin"),
        ],
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().get(request, *args, **kwargs)

    def get_queryset(self) -> QuerySet:
        queryset = User.objects.annotate(
            file_count=Count("files", filter=Q(files__deleted_at__isnull=True))
        ).order_by("-created_at")

        params = self.request.query_params
        search = (params.get("search") or "").strip()
        if search:
            queryset = queryset.filter(
                Q(email__icontains=search[:254]) | Q(full_name__icontains=search[:254])
            )

        state = (params.get("status") or "").strip().lower()
        if state == "active":
            queryset = queryset.filter(is_active=True)
        elif state == "disabled":
            queryset = queryset.filter(is_active=False)
        elif state == "locked":
            queryset = queryset.filter(locked_until__gt=timezone.now())
        elif state == "admin":
            queryset = queryset.filter(role="ADMIN")
        return queryset


class AdminUserDetailView(APIView):
    """Read a user, or enable/disable the account."""

    permission_classes = [IsActiveUser, IsAdminRole]
    serializer_class = AdminUserSerializer

    def _get_user(self, user_id: str) -> Any:
        try:
            return User.objects.annotate(
                file_count=Count("files", filter=Q(files__deleted_at__isnull=True))
            ).get(pk=user_id)
        except (User.DoesNotExist, ValueError, TypeError) as exc:
            raise NotFound("No such user.") from exc

    @extend_schema(tags=["Admin"], responses={200: AdminUserSerializer})
    def get(self, request: Request, user_id: str) -> Response:
        return Response(AdminUserSerializer(self._get_user(user_id)).data)

    @extend_schema(tags=["Admin"], responses={200: AdminUserSerializer})
    def patch(self, request: Request, user_id: str) -> Response:
        target = self._get_user(user_id)
        payload = request.data if isinstance(request.data, dict) else {}

        if "is_active" not in payload:
            raise ValidationError({"is_active": ["This field is required."]})
        desired = payload.get("is_active")
        if not isinstance(desired, bool):
            raise ValidationError({"is_active": ["Must be a boolean."]})

        # An admin must not be able to lock themselves out of the console.
        if target.pk == request.user.pk and desired is False:
            raise ValidationError(
                {"is_active": ["You cannot disable your own administrator account."]}
            )

        reason = str(payload.get("reason") or "")[:200]
        previous = target.is_active
        if previous != desired:
            target.is_active = desired
            update_fields = ["is_active"]
            # Disabling must also invalidate issued JWTs, otherwise the account
            # stays usable until the access token expires.
            if desired is False and hasattr(target, "token_version"):
                target.token_version = target.token_version + 1
                update_fields.append("token_version")
            target.save(update_fields=update_fields)

            record_event(
                action=AuditAction.ADMIN_ACTION,
                request=request,
                user=request.user,
                success=True,
                severity=AuditSeverity.WARNING,
                object_type="user",
                object_id=str(target.pk),
                object_owner=target,
                message=("Account disabled" if desired is False else "Account enabled"),
                metadata={
                    "operation": "disable_user" if desired is False else "enable_user",
                    "target_email": target.email,
                    "previous_is_active": previous,
                    "new_is_active": desired,
                    "reason": reason,
                },
            )
            record_event(
                action=(
                    AuditAction.ACCOUNT_DISABLED
                    if desired is False
                    else AuditAction.ACCOUNT_UNLOCKED
                ),
                request=request,
                user=request.user,
                success=True,
                object_type="user",
                object_id=str(target.pk),
                object_owner=target,
                metadata={"target_email": target.email, "reason": reason},
            )

        target.refresh_from_db()
        target.file_count = User.objects.annotate(
            file_count=Count("files", filter=Q(files__deleted_at__isnull=True))
        ).get(pk=target.pk).file_count
        return Response(AdminUserSerializer(target).data)


class AdminUserUnlockView(APIView):
    """Clear a lockout without changing the password."""

    permission_classes = [IsActiveUser, IsAdminRole]
    serializer_class = AdminUserSerializer

    @extend_schema(tags=["Admin"], responses={200: AdminUserSerializer})
    def post(self, request: Request, user_id: str) -> Response:
        try:
            target = User.objects.get(pk=user_id)
        except (User.DoesNotExist, ValueError, TypeError) as exc:
            raise NotFound("No such user.") from exc

        was_locked = bool(target.locked_until and target.locked_until > timezone.now())
        target.locked_until = None
        target.failed_login_count = 0
        target.save(update_fields=["locked_until", "failed_login_count"])

        record_event(
            action=AuditAction.ADMIN_ACTION,
            request=request,
            user=request.user,
            success=True,
            severity=AuditSeverity.WARNING,
            object_type="user",
            object_id=str(target.pk),
            object_owner=target,
            message="Account lockout cleared",
            metadata={
                "operation": "unlock_user",
                "target_email": target.email,
                "was_locked": was_locked,
            },
        )
        target.file_count = 0
        return Response(AdminUserSerializer(target).data, status=status.HTTP_200_OK)


class AdminSecurityEventsView(ListAPIView):
    """Searchable security event feed across every user."""

    serializer_class = AuditLogSerializer
    permission_classes = [IsActiveUser, IsAdminRole]
    pagination_class = DefaultPagination

    @extend_schema(
        tags=["Admin"],
        parameters=[
            OpenApiParameter("action", str, description="Exact audit action."),
            OpenApiParameter("actor", str, description="Match actor email."),
            OpenApiParameter("success", str, description="true | false"),
            OpenApiParameter("severity", str),
            OpenApiParameter("since", str, description="ISO-8601 lower bound."),
            OpenApiParameter("until", str, description="ISO-8601 upper bound."),
            OpenApiParameter("security_only", str, description="true to show only security events."),
        ],
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().get(request, *args, **kwargs)

    def get_queryset(self) -> QuerySet:
        queryset = AuditLog.objects.select_related("actor").order_by("-timestamp")
        params = self.request.query_params

        action = (params.get("action") or "").strip()
        if action:
            queryset = queryset.filter(action=action.upper()[:48])

        actor = (params.get("actor") or "").strip()
        if actor:
            queryset = queryset.filter(actor_email__icontains=actor[:254])

        success = params.get("success")
        if success not in (None, ""):
            queryset = queryset.filter(success=success.lower() in {"1", "true", "yes"})

        severity = (params.get("severity") or "").strip()
        if severity:
            queryset = queryset.filter(severity=severity.upper()[:16])

        since = params.get("since")
        if since:
            queryset = queryset.filter(timestamp__gte=_parse_bound(since, "since"))

        until = params.get("until")
        if until:
            queryset = queryset.filter(timestamp__lte=_parse_bound(until, "until"))

        if (params.get("security_only") or "").lower() in {"1", "true", "yes"}:
            queryset = queryset.filter(
                Q(success=False)
                | Q(
                    action__in=[
                        AuditAction.UNAUTHORIZED_ACCESS_ATTEMPT,
                        AuditAction.UNAUTHORIZED_FILE_ACCESS,
                        AuditAction.UNAUTHORIZED_SHARE_ACCESS,
                        AuditAction.RATE_LIMIT_TRIGGERED,
                        AuditAction.ACCOUNT_LOCKED,
                        AuditAction.LOGIN_FAILURE,
                        AuditAction.SHARE_LINK_PASSWORD_FAILURE,
                        AuditAction.FILE_INTEGRITY_FAILURE,
                        AuditAction.MALWARE_DETECTED,
                        AuditAction.ADMIN_ACTION,
                    ]
                )
            )
        return queryset


class AdminActionListView(ListAPIView):
    """Just the ADMIN_ACTION trail - who did what to whom."""

    serializer_class = AuditLogSerializer
    permission_classes = [IsActiveUser, IsAdminRole]
    pagination_class = DefaultPagination

    @extend_schema(tags=["Admin"])
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().get(request, *args, **kwargs)

    def get_queryset(self) -> QuerySet:
        return (
            AuditLog.objects.filter(action=AuditAction.ADMIN_ACTION)
            .select_related("actor")
            .order_by("-timestamp")
        )
