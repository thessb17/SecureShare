"""Typed environment variable helpers.

Settings modules must never hard-code secrets, credentials or hosts; every
deployment-specific value flows through this module so that misconfiguration
fails loudly at start-up instead of silently falling back to insecure values.
"""
from __future__ import annotations

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

_TRUE_VALUES = {"1", "true", "yes", "on", "y", "t"}
_FALSE_VALUES = {"0", "false", "no", "off", "n", "f", ""}


def get_str(name: str, default: str | None = None, *, required: bool = False) -> str:
    """Return an environment string, raising when a required value is absent."""
    value = os.environ.get(name)
    if value is None or value == "":
        if required and default is None:
            raise ImproperlyConfigured(
                f"Environment variable {name!r} is required but was not set."
            )
        return default if default is not None else ""
    return value


def get_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalised = raw.strip().lower()
    if normalised in _TRUE_VALUES:
        return True
    if normalised in _FALSE_VALUES:
        return False
    raise ImproperlyConfigured(
        f"Environment variable {name!r} must be a boolean, got {raw!r}."
    )


def get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ImproperlyConfigured(
            f"Environment variable {name!r} must be an integer, got {raw!r}."
        ) from exc


def get_list(name: str, default: tuple[str, ...] = ()) -> list[str]:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def get_path(name: str, default: Path, *, relative_to: Path | None = None) -> Path:
    """Read a filesystem path from the environment.

    A relative value is resolved against ``relative_to`` (the project root)
    rather than the process working directory. Without this, the documented
    ``./keys/rsa_private.pem`` style values in .env.example only work when the
    app happens to be started from the project root - running ``manage.py``
    from ``backend/`` would silently fail to find the file.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return Path(default)
    path = Path(raw.strip()).expanduser()
    if not path.is_absolute() and relative_to is not None:
        path = Path(relative_to) / path
    return path
