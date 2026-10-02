"""Background maintenance for encrypted objects."""
from __future__ import annotations

import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone

from files.models import File, FileStatus
from security.exceptions import StorageError
from security.storage import get_storage

logger = logging.getLogger("secureshare")


@shared_task(name="files.tasks.purge_deleted_objects")
def purge_deleted_objects(older_than_minutes: int = 60) -> int:
    """Remove ciphertext left behind by a failed delete (idempotent)."""
    cutoff = timezone.now() - timedelta(minutes=older_than_minutes)
    storage = get_storage()
    removed = 0
    queryset = File.objects.filter(
        status=FileStatus.DELETED, deleted_at__lt=cutoff
    ).only("id", "stored_object_id")
    for file_obj in queryset.iterator():
        try:
            if storage.exists(file_obj.stored_object_id) and storage.delete(
                file_obj.stored_object_id
            ):
                removed += 1
        except StorageError:
            logger.warning("Could not purge encrypted object", exc_info=True)
    if removed:
        logger.info("Purged orphaned encrypted objects", extra={"removed": removed})
    return removed
