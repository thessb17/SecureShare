"""Account maintenance tasks."""
from __future__ import annotations

import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone

from audit.models import LoginAttempt

logger = logging.getLogger("secureshare")

LOGIN_ATTEMPT_RETENTION_DAYS = 90


@shared_task(name="accounts.tasks.purge_stale_login_attempts")
def purge_stale_login_attempts(retention_days: int = LOGIN_ATTEMPT_RETENTION_DAYS) -> int:
    """Delete login attempt rows older than the retention window."""
    cutoff = timezone.now() - timedelta(days=retention_days)
    deleted, _ = LoginAttempt.objects.filter(created_at__lt=cutoff).delete()
    if deleted:
        logger.info("Purged stale login attempts", extra={"deleted": deleted})
    return deleted
