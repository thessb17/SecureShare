"""Celery application for SecureShare background work."""
from __future__ import annotations

import os

from celery import Celery
from celery.utils.log import get_task_logger

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

app = Celery("secureshare")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

logger = get_task_logger(__name__)


@app.task(name="config.health_check", bind=True)
def health_check(self) -> dict[str, str]:
    """Trivial task used by /api/health/ and the test-suite to prove Celery
    is correctly wired (broker, serializer, routing)."""
    return {"status": "ok", "task_id": str(self.request.id or "eager")}
