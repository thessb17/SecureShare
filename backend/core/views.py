"""Project level error views (JSON, never HTML tracebacks)."""
from __future__ import annotations

from typing import Any

from django.http import HttpRequest, JsonResponse


def not_found_view(request: HttpRequest, exception: Exception | None = None) -> Any:
    return JsonResponse(
        {
            "error": "NOT_FOUND",
            "message": "The requested resource could not be found.",
            "request_id": getattr(request, "request_id", None),
        },
        status=404,
    )


def server_error_view(request: HttpRequest) -> Any:
    return JsonResponse(
        {
            "error": "INTERNAL_ERROR",
            "message": "An unexpected error occurred. The incident has been logged.",
            "request_id": getattr(request, "request_id", None),
        },
        status=500,
    )
