"""Throttles for sharing endpoints.

Public endpoints are keyed on the client IP; the password endpoint is keyed on
(token digest, IP) so guessing one link's password cannot exhaust the quota of
another link - and the raw token never appears in a cache key.
"""
from __future__ import annotations

from typing import Any

from rest_framework.throttling import SimpleRateThrottle

from core.request_meta import get_client_ip
from core.throttling import IPScopedThrottle, UserScopedThrottle


class ShareCreateThrottle(UserScopedThrottle):
    scope = "share.create"


class ShareAccessThrottle(IPScopedThrottle):
    scope = "share.access"


class ShareDownloadThrottle(IPScopedThrottle):
    scope = "share.download"


class SharePasswordThrottle(SimpleRateThrottle):
    scope = "share.password"

    def get_cache_key(self, request: Any, view: Any) -> str | None:
        from sharing.link_services import hash_token

        token = (view.kwargs or {}).get("token", "")
        ident = f"{hash_token(token)[:16]}:{get_client_ip(request) or 'unknown'}"
        return self.cache_format % {"scope": self.scope, "ident": ident}
