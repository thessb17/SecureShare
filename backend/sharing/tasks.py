"""Celery maintenance for shares and share links.

Expiry is always enforced *at request time* as well; these tasks only keep the
data tidy and emit one audit event per link when it lapses.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from audit.constants import AuditAction
from audit.services import record_event
from sharing.models import FileShare, ShareLink

logger = logging.getLogger("secureshare")


@shared_task(name="sharing.tasks.expire_share_links")
def expire_share_links() -> int:
    """Audit links that have just lapsed (idempotent, one event per link)."""
    now = timezone.now()
    lapsed = ShareLink.objects.filter(
        revoked_at__isnull=True,
        expires_at__isnull=False,
        expires_at__lte=now,
        expiry_event_recorded=False,
    ).select_related("file", "file__owner")[:500]

    count = 0
    for link in lapsed:
        record_event(
            action=AuditAction.SHARE_LINK_EXPIRED,
            success=True,
            message="Share link expired.",
            object_type="share_link",
            object_id=link.id,
            object_owner=link.file.owner,
            metadata={
                "token_prefix": link.token_prefix,
                "file_id": str(link.file_id),
                "download_count": link.download_count,
            },
        )
        ShareLink.objects.filter(pk=link.pk).update(expiry_event_recorded=True)
        count += 1
    if count:
        logger.info("Share links expired", extra={"count": count})
    return count


@shared_task(name="sharing.tasks.expire_file_shares")
def expire_file_shares() -> int:
    """Audit user-to-user shares that have lapsed."""
    now = timezone.now()
    lapsed = FileShare.objects.filter(
        revoked_at__isnull=True, expires_at__isnull=False, expires_at__lte=now
    ).select_related("file", "owner")[:500]

    count = 0
    for share in lapsed:
        record_event(
            action=AuditAction.SHARE_EXPIRED,
            success=True,
            message="User share expired.",
            object_type="file_share",
            object_id=share.id,
            object_owner=share.owner,
            metadata={"file_id": str(share.file_id)},
        )
        count += 1
    return count


@shared_task(name="sharing.tasks.purge_expired_share_links")
def purge_expired_share_links(retention_days: int | None = None) -> int:
    """Delete revoked/expired links after the retention window."""
    days = int(retention_days or settings.SHARE_LINK_RETENTION_DAYS)
    cutoff = timezone.now() - timedelta(days=days)
    deleted, _ = ShareLink.objects.filter(
        Q(revoked_at__lt=cutoff) | Q(expires_at__lt=cutoff)
    ).delete()
    if deleted:
        logger.info("Purged stale share links", extra={"deleted": deleted})
        record_event(
            action=AuditAction.SYSTEM_MAINTENANCE,
            message="Expired share links purged.",
            object_type="share_link",
            metadata={"deleted": deleted, "retention_days": days},
        )
    return deleted
