"""Central authorization decision for a file.

Every code path that touches file content goes through :func:`resolve_file_access`
so ownership, user-to-user shares (Phase 5) and admin overrides are evaluated
consistently on the server.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from django.utils import timezone


class AccessVia(StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    SHARE = "SHARE"
    SHARE_LINK = "SHARE_LINK"
    NONE = "NONE"


@dataclass(frozen=True)
class AccessDecision:
    can_view: bool
    can_download: bool
    via: AccessVia
    share: Any | None = None

    @property
    def granted(self) -> bool:
        return self.can_view or self.can_download


DENIED = AccessDecision(can_view=False, can_download=False, via=AccessVia.NONE)


def resolve_file_access(user: Any, file: Any) -> AccessDecision:
    """Return what ``user`` may do with ``file``."""
    if user is None or not getattr(user, "is_authenticated", False):
        return DENIED
    if file is None or file.is_deleted:
        return DENIED

    if file.owner_id == user.pk:
        return AccessDecision(can_view=True, can_download=True, via=AccessVia.OWNER)

    if getattr(user, "is_admin", False):
        # Administrators can inspect and remove any file; every such access is
        # audited as an ADMIN_ACTION.
        return AccessDecision(can_view=True, can_download=True, via=AccessVia.ADMIN)

    share = _active_share_for(user, file)
    if share is not None:
        from sharing.models import SharePermission

        return AccessDecision(
            can_view=True,
            can_download=share.permission == SharePermission.DOWNLOAD,
            via=AccessVia.SHARE,
            share=share,
        )
    return DENIED


def _active_share_for(user: Any, file: Any):
    from django.db.models import Q

    from sharing.models import FileShare

    now = timezone.now()
    return (
        FileShare.objects.filter(file=file, recipient=user, revoked_at__isnull=True)
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .order_by("-created_at")
        .first()
    )
