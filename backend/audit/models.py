"""Append-only audit log.

Immutability is enforced at three levels:

1. ``AuditLog.save()`` refuses to update an existing row.
2. ``AuditLog.delete()`` and ``AuditLogQuerySet.delete()`` raise.
3. No API endpoint exposes write/update/delete operations; ordinary users can
   only read the events they are the actor or the object owner of.

A production deployment should additionally revoke UPDATE/DELETE from the
application database role and ship the log to an append-only sink
(see SECURITY.md -> "Audit logging").
"""
from __future__ import annotations

import uuid
from typing import Any

from django.conf import settings
from django.db import models

from audit.constants import AuditAction, AuditSeverity


class AuditLogImmutableError(Exception):
    """Raised when something attempts to mutate or delete an audit record."""


class AuditLogQuerySet(models.QuerySet):
    def delete(self) -> None:  # type: ignore[override]
        raise AuditLogImmutableError("Audit records cannot be deleted.")

    def update(self, **kwargs: Any) -> int:  # type: ignore[override]
        raise AuditLogImmutableError("Audit records cannot be modified.")

    def for_user(self, user) -> "AuditLogQuerySet":
        """Events an ordinary user is allowed to read."""
        return self.filter(models.Q(actor=user) | models.Q(object_owner=user))


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    action = models.CharField(max_length=48, choices=AuditAction.choices, db_index=True)
    severity = models.CharField(
        max_length=16, choices=AuditSeverity.choices, default=AuditSeverity.INFO
    )
    success = models.BooleanField(default=True)

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_events",
    )
    # Snapshots so the trail survives account deletion.
    actor_email = models.CharField(max_length=254, blank=True)
    actor_role = models.CharField(max_length=16, blank=True)

    #: Owner of the object the event is about (lets owners read events that
    #: other users triggered on their files).
    object_owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_events_on_owned_objects",
    )
    object_type = models.CharField(max_length=32, blank=True, db_index=True)
    object_id = models.CharField(max_length=64, blank=True, db_index=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    request_id = models.CharField(max_length=64, blank=True)

    message = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    objects = AuditLogQuerySet.as_manager()

    class Meta:
        ordering = ("-timestamp",)
        verbose_name = "audit event"
        verbose_name_plural = "audit events"
        indexes = [
            models.Index(fields=("action", "-timestamp")),
            models.Index(fields=("actor", "-timestamp")),
            models.Index(fields=("object_type", "object_id")),
            models.Index(fields=("success", "-timestamp")),
            models.Index(fields=("object_owner", "-timestamp")),
        ]

    def __str__(self) -> str:  # pragma: no cover - admin convenience
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.action}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise AuditLogImmutableError("Audit records are append-only.")
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        raise AuditLogImmutableError("Audit records cannot be deleted.")


class LoginAttempt(models.Model):
    """Per-attempt authentication record backing lockout decisions."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.CharField(max_length=254, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="login_attempts",
    )
    successful = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    reason = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("email", "-created_at")),
            models.Index(fields=("ip_address", "-created_at")),
            models.Index(fields=("successful", "-created_at")),
        ]

    def __str__(self) -> str:  # pragma: no cover
        state = "success" if self.successful else "failure"
        return f"{self.email} {state} @ {self.created_at:%Y-%m-%d %H:%M:%S}"
