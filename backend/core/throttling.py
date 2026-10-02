"""Reusable throttle classes.

Two identities are used:

* **IP based** for unauthenticated/public endpoints (login, registration,
  public share links) - the only identity available before authentication.
* **User based** for authenticated endpoints, so one noisy user cannot exhaust
  the quota of everyone behind the same NAT.
"""
from __future__ import annotations

from typing import Any

from rest_framework.throttling import AnonRateThrottle, SimpleRateThrottle

from core.request_meta import get_client_ip


class ScopedAnonRateThrottle(AnonRateThrottle):
    """Default anonymous throttle that honours the proxy configuration."""

    def get_ident(self, request: Any) -> str:  # type: ignore[override]
        return get_client_ip(request) or "unknown"


class IPScopedThrottle(SimpleRateThrottle):
    """Throttle keyed on the client IP for a named scope."""

    scope = "anon"

    def get_cache_key(self, request: Any, view: Any) -> str | None:
        return self.cache_format % {
            "scope": self.scope,
            "ident": get_client_ip(request) or "unknown",
        }


class UserScopedThrottle(SimpleRateThrottle):
    """Throttle keyed on the authenticated user (falls back to IP)."""

    scope = "user"

    def get_cache_key(self, request: Any, view: Any) -> str | None:
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            ident = str(user.pk)
        else:
            ident = get_client_ip(request) or "unknown"
        return self.cache_format % {"scope": self.scope, "ident": ident}
