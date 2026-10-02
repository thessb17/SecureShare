"""User-to-user sharing service (Phase 5).

All authorization decisions live here so that views cannot accidentally skip
one: only the file owner may create, modify or revoke a share (administrators
may revoke as a moderation action, which is audited as an ADMIN_ACTION).
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError as DBIntegrityError
from django.db import transaction
from django.utils import timezone

from audit.constants import AuditAction
from audit.services import record_event
from files.models import File
from sharing.exceptions import (
    InvalidRecipient,
    ShareAccessDenied,
    ShareAlreadyExists,
)
from sharing.models import FileShare, SharePermission

logger = logging.getLogger("secureshare")
User = get_user_model()


class ShareService:
    """Create, modify and revoke user-to-user shares."""

    # ------------------------------------------------------------------
    @staticmethod
    def resolve_recipient(email: str, *, owner: Any) -> Any:
        normalised = (email or "").strip().lower()
        if not normalised:
            raise InvalidRecipient("A recipient email address is required.")
        recipient = User.objects.filter(email=normalised).first()
        if recipient is None or not recipient.is_active:
            # Same error for "unknown" and "disabled": no account enumeration.
            raise InvalidRecipient(
                "No active SecureShare account exists for that email address."
            )
        if recipient.pk == owner.pk:
            raise InvalidRecipient("You cannot share a file with yourself.")
        return recipient

    @staticmethod
    def validate_expiry(expires_at: Any) -> Any:
        if expires_at is None:
            return None
        now = timezone.now()
        if expires_at <= now:
            raise InvalidRecipient(
                "The expiry must be in the future.",
                error_code="INVALID_EXPIRY",
            )
        max_ttl = timedelta(seconds=int(settings.FILE_SHARE_MAX_TTL_SECONDS))
        if expires_at > now + max_ttl:
            raise InvalidRecipient(
                f"The expiry cannot be more than {max_ttl.days} days in the future.",
                error_code="INVALID_EXPIRY",
            )
        return expires_at

    # ------------------------------------------------------------------
    @classmethod
    def create_share(
        cls,
        *,
        file_obj: File,
        actor: Any,
        recipient_email: str,
        permission: str = SharePermission.VIEW,
        expires_at: Any = None,
        request: Any = None,
    ) -> FileShare:
        if file_obj.owner_id != actor.pk:
            # Sharing is an owner-only capability, even for administrators.
            record_event(
                action=AuditAction.UNAUTHORIZED_SHARE_ACCESS,
                request=request,
                user=actor,
                success=False,
                message="Share creation denied: requester is not the file owner.",
                object_type="file",
                object_id=file_obj.id,
                object_owner=file_obj.owner,
            )
            raise ShareAccessDenied("Only the file owner can share this file.")

        recipient = cls.resolve_recipient(recipient_email, owner=actor)
        expires_at = cls.validate_expiry(expires_at)

        try:
            with transaction.atomic():
                share = FileShare.objects.create(
                    file=file_obj,
                    owner=actor,
                    recipient=recipient,
                    permission=permission,
                    expires_at=expires_at,
                )
        except DBIntegrityError as exc:
            raise ShareAlreadyExists(
                "This file is already shared with that recipient. "
                "Modify the existing share instead."
            ) from exc

        record_event(
            action=AuditAction.FILE_SHARED,
            request=request,
            user=actor,
            message="File shared with another user.",
            object_type="file_share",
            object_id=share.id,
            object_owner=file_obj.owner,
            metadata={
                "file_id": str(file_obj.id),
                "filename": file_obj.original_filename,
                "recipient_id": str(recipient.pk),
                "recipient_email": recipient.email,
                "permission": permission,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )
        return share

    # ------------------------------------------------------------------
    @staticmethod
    def assert_can_manage(share: FileShare, actor: Any, *, request: Any = None,
                          allow_admin: bool = True) -> None:
        is_owner = share.owner_id == actor.pk
        is_admin = bool(getattr(actor, "is_admin", False)) and allow_admin
        if is_owner or is_admin:
            return
        record_event(
            action=AuditAction.UNAUTHORIZED_SHARE_ACCESS,
            request=request,
            user=actor,
            success=False,
            message="Share management denied.",
            object_type="file_share",
            object_id=share.id,
            object_owner=share.owner,
            metadata={"reason": "not_share_owner"},
        )
        raise ShareAccessDenied()

    @classmethod
    def modify_share(
        cls,
        *,
        share: FileShare,
        actor: Any,
        permission: str | None = None,
        expires_at: Any = ...,
        request: Any = None,
    ) -> FileShare:
        # Recipients must never be able to upgrade their own permission.
        cls.assert_can_manage(share, actor, request=request, allow_admin=False)

        changes: dict[str, Any] = {}
        if permission is not None and permission != share.permission:
            changes["permission"] = {"from": share.permission, "to": permission}
            share.permission = permission
        if expires_at is not ...:
            validated = cls.validate_expiry(expires_at)
            if validated != share.expires_at:
                changes["expires_at"] = {
                    "from": share.expires_at.isoformat() if share.expires_at else None,
                    "to": validated.isoformat() if validated else None,
                }
                share.expires_at = validated

        if changes:
            share.save(update_fields=["permission", "expires_at", "updated_at"])
            record_event(
                action=AuditAction.SHARE_MODIFIED,
                request=request,
                user=actor,
                message="Share updated.",
                object_type="file_share",
                object_id=share.id,
                object_owner=share.owner,
                metadata={"file_id": str(share.file_id), "changes": changes},
            )
        return share

    @classmethod
    def revoke_share(
        cls, *, share: FileShare, actor: Any, request: Any = None
    ) -> FileShare:
        cls.assert_can_manage(share, actor, request=request)
        already = share.is_revoked
        share.revoke()
        if not already:
            record_event(
                action=AuditAction.SHARE_REVOKED,
                request=request,
                user=actor,
                message="Share revoked.",
                object_type="file_share",
                object_id=share.id,
                object_owner=share.owner,
                metadata={
                    "file_id": str(share.file_id),
                    "recipient_id": str(share.recipient_id),
                    "by_admin": bool(
                        getattr(actor, "is_admin", False) and actor.pk != share.owner_id
                    ),
                },
            )
        return share
