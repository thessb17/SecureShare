"""Production settings: hardened, HTTPS-aware, fail-fast on misconfiguration."""
from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured

from config import env

from .base import *
from .base import ALLOWED_HOSTS, CORS_ALLOWED_ORIGINS, SECRET_KEY

DEBUG = False

if not ALLOWED_HOSTS:
    raise ImproperlyConfigured("ALLOWED_HOSTS must be set in production.")
if SECRET_KEY.startswith("dev-only-"):
    raise ImproperlyConfigured("A real SECRET_KEY must be provided in production.")
if not CORS_ALLOWED_ORIGINS:
    raise ImproperlyConfigured(
        "CORS_ALLOWED_ORIGINS must list the exact frontend origins in production."
    )

# --- HTTPS dependent headers (require TLS termination in front of gunicorn) --
SECURE_SSL_REDIRECT = env.get_bool("SECURE_SSL_REDIRECT", True)
SECURE_HSTS_SECONDS = env.get_int("SECURE_HSTS_SECONDS", 31_536_000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env.get_bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", True)
SECURE_HSTS_PRELOAD = env.get_bool("SECURE_HSTS_PRELOAD", True)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True

# Database TLS should be required when the DB is not on localhost.
DATABASES["default"].setdefault("OPTIONS", {})
DATABASES["default"]["OPTIONS"]["sslmode"] = env.get_str("DB_SSLMODE", "require")

DJANGO_ADMIN_ENABLED = env.get_bool("DJANGO_ADMIN_ENABLED", False)
