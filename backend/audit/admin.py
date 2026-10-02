from __future__ import annotations

from typing import Any

from django.contrib import admin

from audit.models import AuditLog, LoginAttempt


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "action", "severity", "success", "actor_email", "object_type")
    list_filter = ("action", "severity", "success")
    search_fields = ("actor_email", "object_id", "message")
    readonly_fields = tuple(field.name for field in AuditLog._meta.fields)

    def has_add_permission(self, request: Any) -> bool:
        return False

    def has_change_permission(self, request: Any, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: Any, obj: Any = None) -> bool:
        return False


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ("created_at", "email", "successful", "ip_address", "reason")
    list_filter = ("successful",)
    search_fields = ("email", "ip_address")
    readonly_fields = tuple(field.name for field in LoginAttempt._meta.fields)

    def has_add_permission(self, request: Any) -> bool:
        return False

    def has_change_permission(self, request: Any, obj: Any = None) -> bool:
        return False
