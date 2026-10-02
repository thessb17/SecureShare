"""Test settings: isolated cache, eager Celery, deterministic crypto fixtures.

Password hashing stays on Argon2id (the production hasher) with reduced cost
parameters so password-policy and lockout behaviour is tested for real while
the suite remains fast.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from config import env

from .base import *

DEBUG = False
SECRET_KEY = "test-secret-key-not-used-outside-pytest"  # noqa: S105 # nosec B105
JWT_SIGNING_KEY = "test-jwt-signing-key-not-used-outside-pytest"  # nosec B105
SIMPLE_JWT = {**SIMPLE_JWT, "SIGNING_KEY": JWT_SIGNING_KEY}

ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]

_TMP = Path(tempfile.mkdtemp(prefix="secureshare-tests-"))
ENCRYPTED_STORAGE_ROOT = _TMP / "encrypted"
FILE_UPLOAD_TEMP_DIR = str(_TMP / "tmp")
MEDIA_ROOT = _TMP / "media"
for _d in (ENCRYPTED_STORAGE_ROOT, Path(FILE_UPLOAD_TEMP_DIR), MEDIA_ROOT):
    _d.mkdir(parents=True, exist_ok=True)

# Log to stderr only; the audit *database* table is what tests assert on.
LOG_TO_FILE = False
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"redact_secrets": {"()": "core.logging.SensitiveDataFilter"}},
    "formatters": {"console": {"format": "%(levelname)s %(name)s %(message)s"}},
    "handlers": {
        "console": {
            "level": "ERROR",
            "class": "logging.StreamHandler",
            "formatter": "console",
            "filters": ["redact_secrets"],
        }
    },
    "root": {"handlers": ["console"], "level": "ERROR"},
}

# Local-memory cache keeps throttle/lockout state isolated per test process.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "secureshare-tests",
    }
}

CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

# Throttling is effectively disabled by default and re-enabled per-test with
# ``override_settings`` in the rate-limit test modules.
REST_FRAMEWORK = {
    **REST_FRAMEWORK,
    "DEFAULT_THROTTLE_RATES": dict.fromkeys(REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"], "100000/hour"),
}

PASSWORD_HASHERS = [
    "accounts.hashers.TestArgon2PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
]

CLAMAV_ENABLED = False
CORS_ALLOWED_ORIGINS = ["http://localhost:5173", "https://app.secureshare.local"]
PUBLIC_SHARE_BASE_URL = "https://app.secureshare.local"

# RSA keys for the test-suite are generated once per session by conftest.py and
# injected through these settings.
RSA_PRIVATE_KEY_PEM = env.get_str("RSA_PRIVATE_KEY_PEM")
RSA_PUBLIC_KEY_PEM = env.get_str("RSA_PUBLIC_KEY_PEM")
