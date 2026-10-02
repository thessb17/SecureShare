"""Dependency health endpoint.

The checks are real: a SQL round-trip, a Redis PING, a cache write/read, a
storage probe and an encryption-key load. Component failures are reported as
``error`` without leaking the underlying exception message.
"""
from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db import connections
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from core.throttling import ScopedAnonRateThrottle

logger = logging.getLogger("secureshare")


def _check_database() -> str:
    try:
        with connections["default"].cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception:
        logger.warning("Health check: database unavailable", exc_info=True)
        return "error"
    return "ok"


def _check_redis() -> str:
    try:
        import redis

        client = redis.Redis.from_url(
            settings.REDIS_URL, socket_connect_timeout=2, socket_timeout=2
        )
        if client.ping():
            return "ok"
        return "error"
    except Exception:
        logger.warning("Health check: redis unavailable", exc_info=True)
        return "error"


def _check_cache() -> str:
    try:
        cache.set("health:probe", "1", timeout=10)
        return "ok" if cache.get("health:probe") == "1" else "error"
    except Exception:
        logger.warning("Health check: cache unavailable", exc_info=True)
        return "error"


def _check_storage() -> str:
    try:
        from security.storage import get_storage

        return "ok" if get_storage().health_check() else "error"
    except Exception:
        logger.warning("Health check: storage unavailable", exc_info=True)
        return "error"


def _check_encryption_keys() -> str:
    """Verify the node can both wrap and *unwrap* a data encryption key.

    Checking only the public key is not enough. A deployment whose private
    key is present but unreadable - the classic case being a bind-mounted
    secret owned by a different uid than the container user - will encrypt
    uploads happily and then fail every download with a 503. That node would
    report healthy and keep receiving traffic.

    A full round trip on a throwaway 32-byte key also catches a mismatched
    key pair, a wrong passphrase and a truncated PEM. It costs one RSA
    operation against an already-cached key.
    """
    try:
        import secrets as _secrets

        from security.crypto import get_encryption_service
        from security.keys import get_key_provider

        provider = get_key_provider()
        if provider.public_key is None:
            logger.warning("Health check: no RSA public key available")
            return "error"

        service = get_encryption_service()
        probe = _secrets.token_bytes(32)
        wrapped, key_id = service.wrap_file_key(probe)
        if service.unwrap_file_key(wrapped, key_id) != probe:
            logger.error("Health check: RSA key round trip returned wrong plaintext")
            return "error"
        return "ok"
    except Exception:
        logger.warning("Health check: encryption keys unusable", exc_info=True)
        return "error"


class HealthView(APIView):
    """``GET /api/health/`` - liveness/readiness probe for every dependency."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedAnonRateThrottle]

    @extend_schema(
        operation_id="health",
        tags=["System"],
        auth=[],
        description=(
            "Reports the live status of the database, Redis, cache backend, "
            "encrypted object storage and the RSA key material. Returns 503 "
            "when any dependency is unhealthy."
        ),
        responses={200: dict, 503: dict},
    )
    def get(self, request: Request) -> Response:
        components = {
            "database": _check_database(),
            "redis": _check_redis(),
            "cache": _check_cache(),
            "storage": _check_storage(),
            "encryption_keys": _check_encryption_keys(),
        }
        healthy = all(value == "ok" for value in components.values())
        payload = {
            "status": "ok" if healthy else "degraded",
            "version": settings.SPECTACULAR_SETTINGS["VERSION"],
            **components,
        }
        return Response(
            payload,
            status=status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
        )
