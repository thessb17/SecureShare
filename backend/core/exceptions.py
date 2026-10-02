"""Structured API errors.

Every error leaving the API has the shape::

    {"error": "ACCESS_DENIED", "message": "...", "request_id": "..."}

Internal details (tracebacks, SQL, filesystem paths, cryptographic internals)
are logged server-side and never serialised into a response.
"""
from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import SuspiciousOperation
from django.http import Http404
from rest_framework import exceptions as drf_exceptions
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler

logger = logging.getLogger("secureshare")
security_logger = logging.getLogger("secureshare.security")


class APIError(drf_exceptions.APIException):
    """Base class for all SecureShare API errors."""

    status_code = status.HTTP_400_BAD_REQUEST
    error_code = "BAD_REQUEST"
    default_detail = "The request could not be processed."

    def __init__(
        self,
        message: str | None = None,
        *,
        error_code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.error_code = error_code or self.error_code
        if status_code is not None:
            self.status_code = status_code
        self.details = details or {}
        super().__init__(message or self.default_detail)


class ValidationFailed(APIError):
    error_code = "VALIDATION_ERROR"
    default_detail = "The submitted data is invalid."


class AccessDenied(APIError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "ACCESS_DENIED"
    default_detail = "You do not have permission to access this resource."


class AuthenticationRequired(APIError):
    status_code = status.HTTP_401_UNAUTHORIZED
    error_code = "AUTHENTICATION_REQUIRED"
    default_detail = "Authentication credentials were not provided."


class ResourceNotFound(APIError):
    status_code = status.HTTP_404_NOT_FOUND
    error_code = "NOT_FOUND"
    default_detail = "The requested resource could not be found."


class ConflictError(APIError):
    status_code = status.HTTP_409_CONFLICT
    error_code = "CONFLICT"
    default_detail = "The request conflicts with the current state."


class ServiceUnavailable(APIError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    error_code = "SERVICE_UNAVAILABLE"
    default_detail = "The service is temporarily unavailable."


#: DRF exception class -> (error code, http status override or None)
_DRF_ERROR_CODES: dict[type[Exception], str] = {
    drf_exceptions.NotAuthenticated: "AUTHENTICATION_REQUIRED",
    drf_exceptions.AuthenticationFailed: "AUTHENTICATION_FAILED",
    drf_exceptions.PermissionDenied: "ACCESS_DENIED",
    drf_exceptions.NotFound: "NOT_FOUND",
    drf_exceptions.MethodNotAllowed: "METHOD_NOT_ALLOWED",
    drf_exceptions.NotAcceptable: "NOT_ACCEPTABLE",
    drf_exceptions.UnsupportedMediaType: "UNSUPPORTED_MEDIA_TYPE",
    drf_exceptions.Throttled: "RATE_LIMIT_EXCEEDED",
    drf_exceptions.ParseError: "INVALID_REQUEST",
    drf_exceptions.ValidationError: "VALIDATION_ERROR",
}

_GENERIC_MESSAGES = {
    "AUTHENTICATION_REQUIRED": "Authentication credentials were not provided.",
    "AUTHENTICATION_FAILED": "Invalid or expired credentials.",
    "ACCESS_DENIED": "You do not have permission to access this resource.",
    "NOT_FOUND": "The requested resource could not be found.",
    "RATE_LIMIT_EXCEEDED": "Too many requests. Please try again later.",
    "INTERNAL_ERROR": "An unexpected error occurred. The incident has been logged.",
}


def _error_code_for(exc: Exception) -> str:
    for exc_type, code in _DRF_ERROR_CODES.items():
        if isinstance(exc, exc_type):
            return code
    return "ERROR"


def _flatten_validation_detail(detail: Any) -> Any:
    if isinstance(detail, dict):
        return {key: _flatten_validation_detail(value) for key, value in detail.items()}
    if isinstance(detail, list):
        return [_flatten_validation_detail(item) for item in detail]
    return str(detail)


def _first_message(detail: Any) -> str | None:
    if isinstance(detail, str):
        return detail
    if isinstance(detail, dict):
        for value in detail.values():
            message = _first_message(value)
            if message:
                return message
    if isinstance(detail, (list, tuple)):
        for value in detail:
            message = _first_message(value)
            if message:
                return message
    return None


def structured_exception_handler(exc: Exception, context: dict[str, Any]) -> Response:
    """DRF exception handler producing the SecureShare error envelope."""
    request = context.get("request")
    request_id = getattr(request, "request_id", None)

    if isinstance(exc, Http404):
        exc = drf_exceptions.NotFound()
    elif isinstance(exc, DjangoPermissionDenied):
        exc = drf_exceptions.PermissionDenied()
    elif isinstance(exc, SuspiciousOperation):
        exc = drf_exceptions.ParseError("Malformed request.")

    response = drf_exception_handler(exc, context)

    if response is None:
        # Unhandled server-side failure: log everything, expose nothing.
        logger.exception(
            "Unhandled exception while processing request",
            extra={
                "request_id": request_id,
                "path": getattr(request, "path", None),
                "method": getattr(request, "method", None),
            },
        )
        if settings.DEBUG:
            raise exc
        return Response(
            {
                "error": "INTERNAL_ERROR",
                "message": _GENERIC_MESSAGES["INTERNAL_ERROR"],
                "request_id": request_id,
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    error_code = getattr(exc, "error_code", None) or _error_code_for(exc)
    detail = getattr(exc, "detail", None)

    payload: dict[str, Any] = {"error": error_code, "request_id": request_id}

    if isinstance(exc, drf_exceptions.ValidationError):
        payload["message"] = "The submitted data is invalid."
        payload["details"] = _flatten_validation_detail(detail)
    else:
        message = _first_message(detail) or _GENERIC_MESSAGES.get(
            error_code, "The request could not be processed."
        )
        payload["message"] = message
        extra_details = getattr(exc, "details", None)
        if extra_details:
            payload["details"] = extra_details

    if isinstance(exc, drf_exceptions.Throttled):
        payload["message"] = _GENERIC_MESSAGES["RATE_LIMIT_EXCEEDED"]
        if exc.wait is not None:
            payload["retry_after"] = int(exc.wait)
            response["Retry-After"] = str(int(exc.wait))
        _record_rate_limit_event(request, context)

    if isinstance(exc, (drf_exceptions.NotAuthenticated,
                        drf_exceptions.AuthenticationFailed,
                        drf_exceptions.PermissionDenied)):
        security_logger.info(
            "authorization_failure",
            extra={
                "request_id": request_id,
                "error_code": error_code,
                "path": _safe_path(request),
                "method": getattr(request, "method", None),
            },
        )

    response.data = payload
    return response


def _safe_path(request: Any) -> str | None:
    from core.request_meta import safe_path

    path = getattr(request, "path", None)
    return safe_path(path) if path else None


def _record_rate_limit_event(request: Any, context: dict[str, Any]) -> None:
    """Persist a RATE_LIMIT_TRIGGERED audit event (best effort)."""
    try:
        from audit.constants import AuditAction
        from audit.services import record_event

        view = context.get("view")
        record_event(
            action=AuditAction.RATE_LIMIT_TRIGGERED,
            request=request,
            success=False,
            message="Request rejected by rate limiting.",
            metadata={
                "view": view.__class__.__name__ if view else None,
                "scope": getattr(view, "throttle_scope", None),
            },
        )
    except Exception:  # pragma: no cover - auditing must not break responses
        logger.warning("Failed to record rate limit audit event", exc_info=True)
