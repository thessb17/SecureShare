"""Phase 1: project foundation, dependencies and health endpoint."""
from __future__ import annotations

import pytest
from django.conf import settings
from django.db import connections

pytestmark = pytest.mark.django_db


def test_health_endpoint_reports_every_dependency(api_client):
    response = api_client.get("/api/health/")
    assert response.status_code in (200, 503)
    body = response.json()
    for key in ("status", "database", "redis", "cache", "storage", "encryption_keys"):
        assert key in body
    assert body["database"] == "ok"
    assert body["storage"] == "ok"
    assert body["encryption_keys"] == "ok"


def test_health_endpoint_requires_no_authentication(api_client):
    assert api_client.get("/api/health/").status_code in (200, 503)


def test_database_connection_is_live():
    with connections["default"].cursor() as cursor:
        cursor.execute("SELECT 1")
        assert cursor.fetchone()[0] == 1


def test_celery_app_is_configured():
    from config.celery import app, health_check

    assert app.main == "secureshare"
    assert app.conf.task_serializer == "json"
    assert "json" in app.conf.accept_content
    # CELERY_TASK_ALWAYS_EAGER is enabled in test settings.
    result = health_check.delay()
    assert result.get(timeout=10)["status"] == "ok"


def test_celery_beat_schedule_contains_maintenance_tasks():
    schedule = settings.CELERY_BEAT_SCHEDULE
    assert "expire-share-links" in schedule
    assert schedule["expire-share-links"]["task"] == "sharing.tasks.expire_share_links"


def test_openapi_schema_is_served(api_client):
    response = api_client.get("/api/schema/")
    assert response.status_code == 200
    assert b"SecureShare API" in response.content


def test_swagger_ui_is_served(api_client):
    assert api_client.get("/api/docs/").status_code == 200


def test_debug_is_disabled_in_test_and_prod_profiles():
    assert settings.DEBUG is False


# ---------------------------------------------------------------------------
# Regression: the probe must detect a private key it cannot actually use
# ---------------------------------------------------------------------------
@pytest.mark.django_db
def test_health_reports_error_when_the_private_key_is_unusable(api_client, monkeypatch):
    """A node that can encrypt but not decrypt must not report healthy.

    Found against the Docker stack: the private key was bind-mounted 0600
    owned by the host uid, so the container user could not read it. Uploads
    succeeded, every download returned 503, and /api/health/ still said
    "encryption_keys": "ok" - so an orchestrator would keep routing traffic
    to a node that could not decrypt anything.
    """
    from security.exceptions import KeyManagementError
    from security.keys import RSAKeyProvider

    def _no_private_key(self, key_id=None):
        raise KeyManagementError("No RSA private key is available to this process.")

    monkeypatch.setattr(RSAKeyProvider, "private_key", _no_private_key)

    response = api_client.get("/api/health/")
    assert response.status_code == 503
    assert response.data["encryption_keys"] == "error"
    assert response.data["status"] == "degraded"


@pytest.mark.django_db
def test_health_reports_error_when_the_key_pair_is_mismatched(api_client, monkeypatch):
    """A public key that does not match the private key must be caught."""
    from security.crypto import EnvelopeEncryptionService

    monkeypatch.setattr(
        EnvelopeEncryptionService,
        "unwrap_file_key",
        lambda self, wrapped, key_id=None: b"\x00" * 32,
    )

    response = api_client.get("/api/health/")
    assert response.status_code == 503
    assert response.data["encryption_keys"] == "error"


@pytest.mark.django_db
def test_health_is_ok_when_the_key_pair_round_trips(api_client):
    response = api_client.get("/api/health/")
    assert response.status_code == 200
    assert response.data["encryption_keys"] == "ok"
    assert response.data["status"] == "ok"
