"""Helpers for extracting trustworthy request metadata."""
from __future__ import annotations

import ipaddress
import re
from typing import Final

from django.conf import settings
from django.http import HttpRequest

MAX_USER_AGENT_LENGTH: Final[int] = 255

#: /api/share/<token>/... - the token is a credential and must never be logged.
_SHARE_TOKEN_PATH = re.compile(r"(/api/share/)[^/]+")


def get_client_ip(request: HttpRequest | None) -> str | None:
    """Return the client IP.

    ``X-Forwarded-For`` is only honoured for as many hops as the deployment
    declares via ``TRUSTED_PROXY_COUNT``; otherwise an attacker could spoof an
    arbitrary IP and evade per-IP rate limiting or poison the audit trail.
    """
    if request is None:
        return None

    proxy_count = int(getattr(settings, "TRUSTED_PROXY_COUNT", 0) or 0)
    if proxy_count > 0:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            parts = [part.strip() for part in forwarded.split(",") if part.strip()]
            if len(parts) >= proxy_count:
                candidate = parts[-proxy_count]
                if _is_valid_ip(candidate):
                    return candidate

    remote = request.META.get("REMOTE_ADDR")
    return remote if remote and _is_valid_ip(remote) else remote or None


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def get_user_agent(request: HttpRequest | None) -> str:
    if request is None:
        return ""
    return (request.META.get("HTTP_USER_AGENT") or "")[:MAX_USER_AGENT_LENGTH]


def safe_path(path: str) -> str:
    """Redact credentials embedded in a URL path before logging it."""
    return _SHARE_TOKEN_PATH.sub(r"\1[REDACTED]", path)
