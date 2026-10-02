"""Aggregate statistics for the dashboard and the admin console.

Every number is computed from the database with an aggregate query. Nothing
here is estimated, cached-with-a-guess or hard-coded: if a figure cannot be
derived it is simply not returned.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.contrib.auth import get_user_model
from django.db.models import Count, Q, Sum
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from audit.constants import AuditAction
from audit.models import AuditLog
from core.permissions import IsActiveUser, IsAdminRole
from files.models import File, FileStatus
from sharing.models import FileShare, ShareLink

User = get_user_model()


def _share_buckets(queryset: Any, now: Any) -> dict[str, int]:
    """Split a share/link queryset into active / expired / revoked counts."""
    aggregate = queryset.aggregate(
        revoked=Count("pk", filter=Q(revoked_at__isnull=False)),
        expired=Count(
            "pk", filter=Q(revoked_at__isnull=True, expires_at__lte=now)
        ),
        active=Count(
            "pk",
            filter=Q(revoked_at__isnull=True)
            & (Q(expires_at__isnull=True) | Q(expires_at__gt=now)),
        ),
    )
    return {key: value or 0 for key, value in aggregate.items()}


class DashboardStatsView(APIView):
    """Per-user totals for the signed-in account only."""

    permission_classes = [IsActiveUser]

    @extend_schema(
        tags=["Dashboard"],
        description="Real aggregate counts for the authenticated user.",
        responses={200: dict},
    )
    def get(self, request: Request) -> Response:
        user = request.user
        now = timezone.now()

        files = File.objects.filter(owner=user)
        file_totals = files.aggregate(
            total=Count("pk"),
            active=Count("pk", filter=Q(status=FileStatus.ACTIVE, deleted_at__isnull=True)),
            deleted=Count("pk", filter=Q(deleted_at__isnull=False)),
            plaintext_bytes=Sum("file_size", filter=Q(deleted_at__isnull=True)),
            encrypted_bytes=Sum("encrypted_size", filter=Q(deleted_at__isnull=True)),
        )

        shares_out = _share_buckets(FileShare.objects.filter(owner=user), now)
        shares_in = FileShare.objects.filter(recipient=user).active().count()
        links = _share_buckets(ShareLink.objects.filter(created_by=user), now)

        link_downloads = (
            ShareLink.objects.filter(created_by=user).aggregate(total=Sum("download_count"))
        )["total"] or 0

        recent = (
            AuditLog.objects.for_user(user)
            .select_related("actor")
            .order_by("-timestamp")[:8]
        )

        return Response(
            {
                "files": {
                    "total": file_totals["total"] or 0,
                    "active": file_totals["active"] or 0,
                    "deleted": file_totals["deleted"] or 0,
                    "plaintext_bytes": file_totals["plaintext_bytes"] or 0,
                    "encrypted_bytes": file_totals["encrypted_bytes"] or 0,
                },
                "shares": {
                    "outgoing_active": shares_out["active"],
                    "outgoing_expired": shares_out["expired"],
                    "outgoing_revoked": shares_out["revoked"],
                    "incoming_active": shares_in,
                },
                "links": {
                    "active": links["active"],
                    "expired": links["expired"],
                    "revoked": links["revoked"],
                    "total_downloads": link_downloads,
                },
                "recent_activity": [
                    {
                        "id": str(entry.id),
                        "action": entry.action,
                        "success": entry.success,
                        "object_type": entry.object_type,
                        "object_id": entry.object_id,
                        "timestamp": entry.timestamp.isoformat(),
                        "metadata": entry.metadata,
                    }
                    for entry in recent
                ],
            }
        )


class AdminStatsView(APIView):
    """Platform-wide totals. ADMIN only, enforced here on the server."""

    permission_classes = [IsActiveUser, IsAdminRole]

    @extend_schema(
        tags=["Admin"],
        description="Real platform metrics. Requires the ADMIN role.",
        responses={200: dict},
    )
    def get(self, request: Request) -> Response:
        now = timezone.now()
        day_ago = now - timedelta(hours=24)

        users = User.objects.aggregate(
            total=Count("pk"),
            active=Count("pk", filter=Q(is_active=True)),
            disabled=Count("pk", filter=Q(is_active=False)),
            admins=Count("pk", filter=Q(role="ADMIN")),
            locked=Count("pk", filter=Q(locked_until__gt=now)),
        )

        files = File.objects.aggregate(
            total=Count("pk"),
            active=Count("pk", filter=Q(status=FileStatus.ACTIVE, deleted_at__isnull=True)),
            deleted=Count("pk", filter=Q(deleted_at__isnull=False)),
            encrypted_bytes=Sum("encrypted_size", filter=Q(deleted_at__isnull=True)),
            plaintext_bytes=Sum("file_size", filter=Q(deleted_at__isnull=True)),
        )

        shares = _share_buckets(FileShare.objects.all(), now)
        links = _share_buckets(ShareLink.objects.all(), now)

        events_24h = AuditLog.objects.filter(timestamp__gte=day_ago)
        failed_logins = events_24h.filter(action=AuditAction.LOGIN_FAILURE).count()
        lockouts = events_24h.filter(action=AuditAction.ACCOUNT_LOCKED).count()
        unauthorized = events_24h.filter(
            action__in=[
                AuditAction.UNAUTHORIZED_ACCESS_ATTEMPT,
                AuditAction.UNAUTHORIZED_FILE_ACCESS,
                AuditAction.UNAUTHORIZED_SHARE_ACCESS,
            ]
        ).count()
        rate_limited = events_24h.filter(action=AuditAction.RATE_LIMIT_TRIGGERED).count()

        return Response(
            {
                "users": {
                    "total": users["total"] or 0,
                    "active": users["active"] or 0,
                    "disabled": users["disabled"] or 0,
                    "admins": users["admins"] or 0,
                    "locked": users["locked"] or 0,
                },
                "files": {
                    "total": files["total"] or 0,
                    "active": files["active"] or 0,
                    "deleted": files["deleted"] or 0,
                    "encrypted_bytes": files["encrypted_bytes"] or 0,
                    "plaintext_bytes": files["plaintext_bytes"] or 0,
                },
                "shares": {
                    "active": shares["active"],
                    "expired": shares["expired"],
                    "revoked": shares["revoked"],
                },
                "share_links": {
                    "active": links["active"],
                    "expired": links["expired"],
                    "revoked": links["revoked"],
                },
                "security": {
                    "events_24h": events_24h.count(),
                    "failed_logins_24h": failed_logins,
                    "lockouts_24h": lockouts,
                    "unauthorized_24h": unauthorized,
                    "rate_limited_24h": rate_limited,
                },
                "generated_at": now.isoformat(),
            }
        )
