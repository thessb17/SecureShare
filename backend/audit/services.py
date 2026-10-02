"""Audit recording service.

The single entry point used by every app. It guarantees that:

* secrets (passwords, JWTs, share tokens, DEKs) never reach the database;
* an audit failure can never break the user-facing request;
* every event is mirrored to the structured ``secureshare.audit`` log stream.
"""
from __future__ import annotations

import logging
from typing import Any

from django.db import DatabaseError

from audit.constants import DEFAULT_SEVERITY, SECURITY_ACTIONS, AuditAction, AuditSeverity
from audit.models import AuditLog, LoginAttempt
from core.logging import SENSITIVE_KEYS, redact_structure
from core.request_meta import get_client_ip, get_user_agent

logger = logging.getLogger("secureshare.audit")
security_logger = logging.getLogger("secureshare.security")

MAX_METADATA_KEYS = 30
MAX_VALUE_LENGTH = 512


def _sanitise_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Drop sensitive keys, redact values and bound the payload size."""
    if not metadata:
        return {}
    cleaned: dict[str, Any] = {}
    for key, value in list(metadata.items())[:MAX_METADATA_KEYS]:
        if not isinstance(key, str) or key.lower() in SENSITIVE_KEYS:
            continue
        value = redact_structure(value)
        if isinstance(value, str) and len(value) > MAX_VALUE_LENGTH:
            value = value[:MAX_VALUE_LENGTH] + "...[truncated]"
        cleaned[key] = value
    return cleaned


def record_event(
    *,
    action: AuditAction | str,
    request: Any = None,
    user: Any = None,
    success: bool = True,
    message: str = "",
    object_type: str = "",
    object_id: Any = "",
    object_owner: Any = None,
    metadata: dict[str, Any] | None = None,
    severity: AuditSeverity | str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditLog | None:
    """Persist one audit event. Never raises."""
    try:
        actor = user
        if actor is None and request is not None:
            candidate = getattr(request, "user", None)
            if candidate is not None and getattr(candidate, "is_authenticated", False):
                actor = candidate
        if actor is not None and not getattr(actor, "is_authenticated", True):
            actor = None

        resolved_severity = severity or DEFAULT_SEVERITY.get(
            action, AuditSeverity.INFO
        )
        if not success and resolved_severity == AuditSeverity.INFO:
            resolved_severity = AuditSeverity.WARNING

        event = AuditLog(
            action=str(action),
            severity=str(resolved_severity),
            success=success,
            actor=actor,
            actor_email=(getattr(actor, "email", "") or "")[:254],
            actor_role=(getattr(actor, "role", "") or "")[:16],
            object_owner=object_owner,
            object_type=object_type[:32],
            object_id=str(object_id)[:64] if object_id else "",
            ip_address=ip_address or get_client_ip(request),
            user_agent=(user_agent if user_agent is not None else get_user_agent(request))[:255],
            request_id=str(getattr(request, "request_id", "") or "")[:64],
            message=message[:255],
            metadata=_sanitise_metadata(metadata),
        )
        event.save()

        log_payload = {
            "audit_action": event.action,
            "audit_id": str(event.id),
            "success": success,
            "actor_id": str(actor.pk) if actor is not None else None,
            "object_type": event.object_type,
            "object_id": event.object_id,
            "client_ip": event.ip_address,
            "request_id": event.request_id,
            "event_data": event.metadata,
        }
        logger.info(event.action, extra=log_payload)
        if action in SECURITY_ACTIONS or not success:
            security_logger.warning(event.action, extra=log_payload)
        return event
    except DatabaseError:
        logger.error("Failed to persist audit event", exc_info=True)
    except Exception:
        logger.error("Unexpected audit failure", exc_info=True)
    return None


def record_login_attempt(
    *,
    email: str,
    successful: bool,
    request: Any = None,
    user: Any = None,
    reason: str = "",
) -> LoginAttempt | None:
    """Record one authentication attempt (never stores the password)."""
    try:
        return LoginAttempt.objects.create(
            email=(email or "")[:254].lower(),
            user=user if getattr(user, "pk", None) else None,
            successful=successful,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            reason=reason[:64],
        )
    except Exception:
        logger.error("Failed to persist login attempt", exc_info=True)
        return None
