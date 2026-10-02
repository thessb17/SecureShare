"""Local development settings.

Still secure-by-default: nothing here weakens authentication, authorization or
cryptography - it only makes local iteration practical.
"""
from __future__ import annotations

from config import env

from .base import *
from .base import CORS_ALLOWED_ORIGINS, INSTALLED_APPS  # noqa: F401

DEBUG = env.get_bool("DEBUG", True)

ALLOWED_HOSTS = env.get_list(
    "ALLOWED_HOSTS",
    ("localhost", "127.0.0.1", "[::1]", "0.0.0.0", "testserver"),  # noqa: S104 - dev only
)

DJANGO_ADMIN_ENABLED = env.get_bool("DJANGO_ADMIN_ENABLED", True)

# HTTPS-only protections stay off locally (there is no TLS terminator).
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0

EMAIL_BACKEND = env.get_str(
    "EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend"
)
