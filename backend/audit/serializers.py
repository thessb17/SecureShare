from __future__ import annotations

from rest_framework import serializers

from audit.models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    """Read-only projection of an audit event (no internal identifiers)."""

    actor = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = (
            "id",
            "timestamp",
            "action",
            "severity",
            "success",
            "actor",
            "object_type",
            "object_id",
            "ip_address",
            "user_agent",
            "message",
            "metadata",
        )
        read_only_fields = fields

    def get_actor(self, obj: AuditLog) -> dict[str, str] | None:
        if not obj.actor_email:
            return None
        return {
            "id": str(obj.actor_id) if obj.actor_id else None,
            "email": obj.actor_email,
            "role": obj.actor_role,
        }
