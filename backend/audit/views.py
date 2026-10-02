"""Read-only audit log API.

Ordinary users may read events where they are the actor **or** the owner of the
object the event refers to. Administrators may read everything. There is no
write/update/delete endpoint - the trail is append-only.
"""
from __future__ import annotations

from django.utils.dateparse import parse_datetime
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.generics import ListAPIView

from audit.models import AuditLog
from audit.serializers import AuditLogSerializer
from core.permissions import IsActiveUser


@extend_schema(
    tags=["Audit"],
    parameters=[
        OpenApiParameter("action", str, description="Filter by audit action."),
        OpenApiParameter("success", bool, description="Filter by outcome."),
        OpenApiParameter("object_id", str, description="Filter by object id."),
        OpenApiParameter("since", str, description="ISO-8601 lower bound."),
    ],
    description="List audit events visible to the authenticated user.",
)
class AuditLogListView(ListAPIView):
    serializer_class = AuditLogSerializer
    permission_classes = [IsActiveUser]

    def get_queryset(self):
        user = self.request.user
        queryset = AuditLog.objects.all()
        if not user.is_admin:
            queryset = queryset.for_user(user)

        params = self.request.query_params
        action = params.get("action")
        if action:
            queryset = queryset.filter(action=action.upper()[:48])
        success = params.get("success")
        if success is not None and success != "":
            queryset = queryset.filter(success=success.lower() in {"1", "true", "yes"})
        object_id = params.get("object_id")
        if object_id:
            queryset = queryset.filter(object_id=object_id[:64])
        object_type = params.get("object_type")
        if object_type:
            queryset = queryset.filter(object_type=object_type[:32])
        since = params.get("since")
        if since:
            parsed = parse_datetime(since)
            if parsed is not None:
                queryset = queryset.filter(timestamp__gte=parsed)
        return queryset.select_related("actor")
