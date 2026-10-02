"""Security and observability middleware."""
from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse

from core.request_meta import get_client_ip, safe_path

logger = logging.getLogger("secureshare")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class RequestIDMiddleware:
    """Attach a correlation id to every request/response."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        incoming = request.META.get("HTTP_X_REQUEST_ID", "")
        request_id = incoming if _REQUEST_ID_RE.match(incoming or "") else uuid.uuid4().hex
        request.request_id = request_id
        response = self.get_response(request)
        response["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware:
    """Apply headers Django does not set natively.

    ``Strict-Transport-Security``, ``Secure`` cookies and the HTTPS redirect are
    handled by ``django.middleware.security.SecurityMiddleware`` and only take
    effect when the deployment actually terminates TLS (see prod settings).
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        response.setdefault("Content-Security-Policy", settings.CONTENT_SECURITY_POLICY)
        response.setdefault("Permissions-Policy", settings.PERMISSIONS_POLICY)
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("Referrer-Policy", settings.SECURE_REFERRER_POLICY)
        response.setdefault("Cross-Origin-Resource-Policy", "same-site")
        response.setdefault("X-Frame-Options", "DENY")
        # Downloads must never be rendered inline by the browser.
        if response.get("Content-Disposition", "").startswith("attachment"):
            response["X-Download-Options"] = "noopen"
        # Do not advertise the server stack.
        if "Server" in response:
            del response["Server"]
        return response


class RequestLogMiddleware:
    """Log one structured line per request.

    Query strings are dropped and share tokens in the path are redacted, so no
    credential ever reaches the log files.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        started = time.monotonic()
        response = self.get_response(request)
        duration_ms = round((time.monotonic() - started) * 1000, 2)

        user = getattr(request, "user", None)
        user_id = str(user.pk) if getattr(user, "is_authenticated", False) else None

        logger.info(
            "http_request",
            extra={
                "request_id": getattr(request, "request_id", None),
                "method": request.method,
                "path": safe_path(request.path),
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "client_ip": get_client_ip(request),
                "user_id": user_id,
            },
        )
        return response
