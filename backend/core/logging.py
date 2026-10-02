"""Structured logging with hard redaction of secrets.

Three logical streams are used across the project:

``secureshare``           - application events
``secureshare.security``  - security relevant events (authn/authz failures...)
``secureshare.audit``     - mirror of the audit trail persisted in PostgreSQL

Nothing that could contain a password, JWT, share token, DEK or private key is
allowed to reach a handler: :class:`SensitiveDataFilter` scrubs both the
formatted message and structured ``extra`` fields.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import re
from typing import Any, Final

#: Keys whose values are always replaced, regardless of nesting.
SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "password1",
        "password2",
        "new_password",
        "old_password",
        "current_password",
        "confirm_password",
        "share_password",
        "token",
        "share_token",
        "raw_token",
        "access",
        "refresh",
        "access_token",
        "refresh_token",
        "authorization",
        "auth",
        "jwt",
        "secret",
        "secret_key",
        "signing_key",
        "api_key",
        "dek",
        "wrapped_dek",
        "private_key",
        "rsa_private_key",
        "passphrase",
        "grant",
        "cookie",
        "set-cookie",
        "x-share-password",
        "x-share-grant",
    }
)

REDACTED: Final[str] = "[REDACTED]"

_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # Bearer <jwt>
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}", re.UNICODE),
    # key=value / "key": "value" for sensitive keys
    re.compile(
        r"(?i)\b("
        + "|".join(sorted(re.escape(k) for k in SENSITIVE_KEYS))
        + r")\b(\"?\s*[:=]\s*\"?)([^\s,;&\"'}\]]+)",
        re.UNICODE,
    ),
    # JWT shaped strings anywhere in the message
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    # PEM blocks
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
               re.DOTALL),
)


def redact_text(value: str) -> str:
    """Remove secret-looking substrings from a free-form string."""
    redacted = _PATTERNS[0].sub(r"\1 " + REDACTED, value)
    redacted = _PATTERNS[1].sub(r"\1\2" + REDACTED, redacted)
    redacted = _PATTERNS[2].sub(REDACTED, redacted)
    redacted = _PATTERNS[3].sub(REDACTED, redacted)
    return redacted


def redact_structure(value: Any, _depth: int = 0) -> Any:
    """Recursively redact sensitive keys inside dicts/lists."""
    if _depth > 6:
        return REDACTED
    if isinstance(value, dict):
        return {
            key: (
                REDACTED
                if isinstance(key, str) and key.lower() in SENSITIVE_KEYS
                else redact_structure(item, _depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_structure(item, _depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class SensitiveDataFilter(logging.Filter):
    """Logging filter that scrubs secrets from messages, args and extras."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if record.args:
                # Render first, then redact: redaction can remove the %s
                # placeholders, which would make a later ``msg % args`` raise
                # and break the whole log record. Rendering also catches
                # secrets that were passed as arguments rather than inline.
                try:
                    rendered = record.getMessage()
                except Exception:  # pragma: no cover - malformed log call
                    rendered = str(record.msg)
                record.msg = redact_text(rendered)
                record.args = ()
            elif isinstance(record.msg, str):
                record.msg = redact_text(record.msg)
            elif isinstance(record.msg, (dict, list, tuple)):
                record.msg = redact_structure(record.msg)

            for key in list(vars(record)):
                if key.lower() in SENSITIVE_KEYS:
                    setattr(record, key, REDACTED)
                elif key == "event_data":
                    record.event_data = redact_structure(record.event_data)
        except Exception:  # pragma: no cover - logging must never break requests
            return True
        return True


class JsonLogFormatter(logging.Formatter):
    """Minimal dependency-free JSON formatter."""

    RESERVED = frozenset(
        {
            "args", "asctime", "created", "exc_info", "exc_text", "filename",
            "funcName", "levelname", "levelno", "lineno", "module", "msecs",
            "message", "msg", "name", "pathname", "process", "processName",
            "relativeCreated", "stack_info", "thread", "threadName", "taskName",
        }
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": dt.datetime.fromtimestamp(
                record.created, tz=dt.timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key in self.RESERVED or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = str(value)
        if record.exc_info:
            payload["exception_type"] = getattr(
                record.exc_info[0], "__name__", "Exception"
            )
            # Full tracebacks are kept for the application stream only; they are
            # never surfaced through the API.
            payload["traceback"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)
