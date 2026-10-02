"""Base Django settings for SecureShare.

Secure-by-default: DEBUG is off, hosts/origins are explicit allow-lists, and all
secrets are read from the environment. Environment-specific modules (dev/prod/
test) only relax or tighten what they must.
"""
from __future__ import annotations

import secrets
from datetime import timedelta
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

from config import env

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent

# .env at the repository root wins; a backend/.env is supported for local runs.
load_dotenv(PROJECT_ROOT / ".env", override=False)
load_dotenv(BACKEND_DIR / ".env", override=False)

BASE_DIR = BACKEND_DIR

# ---------------------------------------------------------------------------
# Core security
# ---------------------------------------------------------------------------
DEBUG = env.get_bool("DEBUG", False)

SECRET_KEY = env.get_str("SECRET_KEY")
if not SECRET_KEY:
    if DEBUG:
        # Ephemeral key: acceptable only for local development.
        SECRET_KEY = "dev-only-" + secrets.token_urlsafe(50)
    else:
        raise ImproperlyConfigured(
            "SECRET_KEY must be set when DEBUG is disabled. See .env.example."
        )

ALLOWED_HOSTS = env.get_list("ALLOWED_HOSTS", ("localhost", "127.0.0.1", "[::1]"))

# Behind nginx/other TLS terminator.
USE_X_FORWARDED_HOST = env.get_bool("USE_X_FORWARDED_HOST", False)
if env.get_bool("TRUST_PROXY_SSL_HEADER", False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Number of reverse proxies in front of the app. Used to pick the correct
# client IP from X-Forwarded-For (never trust the full chain blindly).
TRUSTED_PROXY_COUNT = env.get_int("TRUSTED_PROXY_COUNT", 0)

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "drf_spectacular",
]

LOCAL_APPS = [
    "core.apps.CoreConfig",
    "accounts.apps.AccountsConfig",
    "audit.apps.AuditConfig",
    "files.apps.FilesConfig",
    "sharing.apps.SharingConfig",
    "dashboard.apps.DashboardConfig",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "core.middleware.RequestIDMiddleware",
    "core.middleware.SecurityHeadersMiddleware",
    "core.middleware.RequestLogMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BACKEND_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# Database (PostgreSQL via DATABASE_URL)
# ---------------------------------------------------------------------------
import dj_database_url  # noqa: E402  (import after env bootstrap)

DATABASE_URL = env.get_str(
    "DATABASE_URL",
    "postgresql://secureshare:devpassword_local_only@127.0.0.1:5432/secureshare",
)
DATABASES = {
    "default": dj_database_url.parse(
        DATABASE_URL,
        conn_max_age=env.get_int("DB_CONN_MAX_AGE", 60),
        conn_health_checks=True,
    )
}
if DATABASES["default"].get("ENGINE", "").endswith("postgresql"):
    DATABASES["default"].setdefault("OPTIONS", {})
    DATABASES["default"]["OPTIONS"].setdefault(
        "sslmode", env.get_str("DB_SSLMODE", "prefer")
    )

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.User"

# ---------------------------------------------------------------------------
# Redis / cache / Celery
# ---------------------------------------------------------------------------
REDIS_URL = env.get_str("REDIS_URL", "redis://127.0.0.1:6379/0")

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": env.get_str("CACHE_URL", REDIS_URL),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "IGNORE_EXCEPTIONS": False,
        },
        "KEY_PREFIX": "secureshare",
    }
}

CELERY_BROKER_URL = env.get_str("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = env.get_str("CELERY_RESULT_BACKEND", REDIS_URL)
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TIMEZONE = "UTC"
CELERY_ENABLE_UTC = True
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_WORKER_HIJACK_ROOT_LOGGER = False
CELERY_TASK_ALWAYS_EAGER = env.get_bool("CELERY_TASK_ALWAYS_EAGER", False)
CELERY_BEAT_SCHEDULE = {
    "expire-share-links": {
        "task": "sharing.tasks.expire_share_links",
        "schedule": float(env.get_int("SHARE_LINK_EXPIRY_SWEEP_SECONDS", 300)),
    },
    "purge-expired-share-links": {
        "task": "sharing.tasks.purge_expired_share_links",
        "schedule": float(env.get_int("SHARE_LINK_PURGE_SWEEP_SECONDS", 86400)),
    },
    "purge-stale-login-attempts": {
        "task": "accounts.tasks.purge_stale_login_attempts",
        "schedule": float(env.get_int("LOGIN_ATTEMPT_PURGE_SECONDS", 86400)),
    },
}

# ---------------------------------------------------------------------------
# Password hashing & policy
# ---------------------------------------------------------------------------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]

MIN_PASSWORD_LENGTH = env.get_int("MIN_PASSWORD_LENGTH", 12)

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": MIN_PASSWORD_LENGTH},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    {"NAME": "accounts.validators.PasswordComplexityValidator"},
    {"NAME": "accounts.validators.MaximumLengthValidator"},
]

# ---------------------------------------------------------------------------
# Authentication / JWT
# ---------------------------------------------------------------------------
JWT_SIGNING_KEY = env.get_str("JWT_SIGNING_KEY") or SECRET_KEY

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=env.get_int("JWT_ACCESS_MINUTES", 15)),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=env.get_int("JWT_REFRESH_DAYS", 1)),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": False,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": JWT_SIGNING_KEY,
    "AUDIENCE": None,
    "ISSUER": env.get_str("JWT_ISSUER", "secureshare"),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "TOKEN_TYPE_CLAIM": "token_type",
    "JTI_CLAIM": "jti",
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
}

# Account lockout (brute-force protection)
LOGIN_FAILURE_LIMIT = env.get_int("LOGIN_FAILURE_LIMIT", 5)
LOGIN_FAILURE_WINDOW_SECONDS = env.get_int("LOGIN_FAILURE_WINDOW_SECONDS", 900)
LOGIN_LOCKOUT_SECONDS = env.get_int("LOGIN_LOCKOUT_SECONDS", 900)

PASSWORD_RESET_TIMEOUT = env.get_int("PASSWORD_RESET_TIMEOUT_SECONDS", 3600)
EMAIL_VERIFICATION_TIMEOUT = env.get_int("EMAIL_VERIFICATION_TIMEOUT_SECONDS", 86400)

# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "accounts.authentication.SecureJWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    "DEFAULT_PARSER_CLASSES": (
        "rest_framework.parsers.JSONParser",
        "rest_framework.parsers.MultiPartParser",
        "rest_framework.parsers.FormParser",
    ),
    "DEFAULT_PAGINATION_CLASS": "core.pagination.DefaultPagination",
    "PAGE_SIZE": 25,
    "EXCEPTION_HANDLER": "core.exceptions.structured_exception_handler",
    "DEFAULT_THROTTLE_CLASSES": (
        "core.throttling.ScopedAnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "anon": env.get_str("THROTTLE_ANON", "120/hour"),
        "user": env.get_str("THROTTLE_USER", "2000/hour"),
        "auth.login": env.get_str("THROTTLE_LOGIN", "10/min"),
        "auth.register": env.get_str("THROTTLE_REGISTER", "5/hour"),
        "auth.refresh": env.get_str("THROTTLE_REFRESH", "60/hour"),
        "auth.password_reset": env.get_str("THROTTLE_PASSWORD_RESET", "5/hour"),
        "auth.change_password": env.get_str("THROTTLE_CHANGE_PASSWORD", "10/hour"),
        "files.upload": env.get_str("THROTTLE_UPLOAD", "60/hour"),
        "files.download": env.get_str("THROTTLE_DOWNLOAD", "300/hour"),
        "share.create": env.get_str("THROTTLE_SHARE_CREATE", "60/hour"),
        "share.access": env.get_str("THROTTLE_SHARE_ACCESS", "60/hour"),
        "share.download": env.get_str("THROTTLE_SHARE_DOWNLOAD", "60/hour"),
        "share.password": env.get_str("THROTTLE_SHARE_PASSWORD", "10/hour"),
    },
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "UNAUTHENTICATED_USER": "django.contrib.auth.models.AnonymousUser",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "SecureShare API",
    "DESCRIPTION": (
        "Secure file sharing platform: envelope encryption (AES-256-GCM + "
        "RSA-OAEP), RBAC, user-to-user sharing, expiring public share links "
        "and tamper-evident audit logging."
    ),
    "VERSION": "0.6.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "SCHEMA_PATH_PREFIX": "/api",
    "SERVE_PERMISSIONS": ["rest_framework.permissions.AllowAny"],
    "SECURITY": [{"BearerAuth": []}],
    "ENUM_NAME_OVERRIDES": {
        "ShareLinkExpiryPresetEnum": "sharing.serializers.SHARE_LINK_EXPIRY_CHOICES",
        "FileShareExpiryPresetEnum": "sharing.serializers.FILE_SHARE_EXPIRY_CHOICES",
    },
    "APPEND_COMPONENTS": {
        "securitySchemes": {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }
    },
}

# ---------------------------------------------------------------------------
# CORS / CSRF
# ---------------------------------------------------------------------------
CORS_ALLOWED_ORIGINS = env.get_list(
    "CORS_ALLOWED_ORIGINS", ("http://localhost:5173", "http://127.0.0.1:5173")
)
CORS_ALLOW_CREDENTIALS = env.get_bool("CORS_ALLOW_CREDENTIALS", False)
CORS_ALLOW_ALL_ORIGINS = False  # never enabled; explicit allow-list only
CORS_ALLOW_HEADERS = (
    "accept",
    "authorization",
    "content-type",
    "origin",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
    "x-share-password",
    "x-share-grant",
    "x-request-id",
)
CORS_EXPOSE_HEADERS = ("x-request-id", "content-disposition")
CSRF_TRUSTED_ORIGINS = env.get_list("CSRF_TRUSTED_ORIGINS", tuple(CORS_ALLOWED_ORIGINS))

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_HTTPONLY = False  # readable by SPA when session auth is used
CSRF_COOKIE_SAMESITE = "Lax"

# ---------------------------------------------------------------------------
# Security headers (HTTPS-dependent flags are enabled in prod settings)
# ---------------------------------------------------------------------------
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

CONTENT_SECURITY_POLICY = env.get_str(
    "CONTENT_SECURITY_POLICY",
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; connect-src 'self'; font-src 'self' data:",
)
PERMISSIONS_POLICY = env.get_str(
    "PERMISSIONS_POLICY",
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
    "microphone=(), payment=(), usb=(), interest-cohort=()",
)

# ---------------------------------------------------------------------------
# Static / media / uploads
# ---------------------------------------------------------------------------
STATIC_URL = "static/"
STATIC_ROOT = env.get_path(
    "STATIC_ROOT", BACKEND_DIR / "staticfiles", relative_to=PROJECT_ROOT
)
MEDIA_ROOT = env.get_path(
    "MEDIA_ROOT", PROJECT_ROOT / "storage" / "media", relative_to=PROJECT_ROOT
)
MEDIA_URL = "media/"

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
    },
}

# Encrypted object storage (never served by nginx / never inside the web root)
ENCRYPTED_STORAGE_BACKEND = env.get_str(
    "ENCRYPTED_STORAGE_BACKEND", "security.storage.LocalEncryptedStorage"
)
ENCRYPTED_STORAGE_ROOT = env.get_path(
    "ENCRYPTED_STORAGE_ROOT",
    PROJECT_ROOT / "storage" / "encrypted",
    relative_to=PROJECT_ROOT,
)
FILE_UPLOAD_TEMP_DIR = str(
    env.get_path(
        "FILE_UPLOAD_TEMP_DIR",
        PROJECT_ROOT / "storage" / "tmp",
        relative_to=PROJECT_ROOT,
    )
)
FILE_UPLOAD_PERMISSIONS = 0o600
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o700
# Anything above this size is streamed to a temp file instead of buffered in RAM.
FILE_UPLOAD_MAX_MEMORY_SIZE = env.get_int("FILE_UPLOAD_MAX_MEMORY_SIZE", 1_048_576)
DATA_UPLOAD_MAX_MEMORY_SIZE = env.get_int("DATA_UPLOAD_MAX_MEMORY_SIZE", 2_621_440)
DATA_UPLOAD_MAX_NUMBER_FIELDS = 100
DATA_UPLOAD_MAX_NUMBER_FILES = 10

MAX_UPLOAD_SIZE = env.get_int("MAX_UPLOAD_SIZE", 26_214_400)  # 25 MiB
ALLOWED_UPLOAD_EXTENSIONS = [
    ext.lower().lstrip(".")
    for ext in env.get_list(
        "ALLOWED_UPLOAD_EXTENSIONS",
        (
            "pdf", "png", "jpg", "jpeg", "txt", "csv",
            "docx", "xlsx", "pptx", "zip",
        ),
    )
]
ALLOWED_UPLOAD_MIME_TYPES = env.get_list(
    "ALLOWED_UPLOAD_MIME_TYPES",
    (
        "application/pdf",
        "image/png",
        "image/jpeg",
        "text/plain",
        "text/csv",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/zip",
    ),
)
# Extensions that must never be accepted, including inside double extensions.
BLOCKED_UPLOAD_EXTENSIONS = env.get_list(
    "BLOCKED_UPLOAD_EXTENSIONS",
    (
        "exe", "dll", "so", "dylib", "bat", "cmd", "com", "cpl", "scr", "msi",
        "jar", "js", "mjs", "vbs", "vbe", "ps1", "psm1", "sh", "bash", "zsh",
        "php", "phtml", "phar", "asp", "aspx", "jsp", "jspx", "cgi", "pl", "py",
        "rb", "lnk", "reg", "hta", "wsf", "svg", "html", "htm", "xhtml", "shtml",
    ),
)

# Files below this size are decrypted fully (so integrity failures are reported
# as a clean API error); larger files are streamed chunk-by-chunk.
DOWNLOAD_BUFFER_THRESHOLD = env.get_int("DOWNLOAD_BUFFER_THRESHOLD", 8_388_608)
ENCRYPTION_CHUNK_SIZE = env.get_int("ENCRYPTION_CHUNK_SIZE", 1_048_576)

# ---------------------------------------------------------------------------
# Envelope encryption keys (RSA key wrapping)
# ---------------------------------------------------------------------------
RSA_PRIVATE_KEY_PATH = str(
    env.get_path(
        "RSA_PRIVATE_KEY_PATH",
        PROJECT_ROOT / "keys" / "rsa_private.pem",
        relative_to=PROJECT_ROOT,
    )
)
RSA_PUBLIC_KEY_PATH = str(
    env.get_path(
        "RSA_PUBLIC_KEY_PATH",
        PROJECT_ROOT / "keys" / "rsa_public.pem",
        relative_to=PROJECT_ROOT,
    )
)
# Optional inline PEM (e.g. injected by a secret manager) - takes precedence.
RSA_PRIVATE_KEY_PEM = env.get_str("RSA_PRIVATE_KEY_PEM")
RSA_PUBLIC_KEY_PEM = env.get_str("RSA_PUBLIC_KEY_PEM")
RSA_PRIVATE_KEY_PASSPHRASE = env.get_str("RSA_PRIVATE_KEY_PASSPHRASE")
# Retired private keys kept only to unwrap previously wrapped DEKs (rotation).
RSA_RETIRED_PRIVATE_KEY_PATHS = [
    str(_p if Path(_p).is_absolute() else PROJECT_ROOT / _p)
    for _p in env.get_list("RSA_RETIRED_PRIVATE_KEY_PATHS")
]

# ---------------------------------------------------------------------------
# Malware scanning (ClamAV) - disabled unless explicitly turned on
# ---------------------------------------------------------------------------
CLAMAV_ENABLED = env.get_bool("CLAMAV_ENABLED", False)
CLAMAV_HOST = env.get_str("CLAMAV_HOST", "clamav")
CLAMAV_PORT = env.get_int("CLAMAV_PORT", 3310)
CLAMAV_TIMEOUT_SECONDS = env.get_int("CLAMAV_TIMEOUT_SECONDS", 30)
CLAMAV_FAIL_CLOSED = env.get_bool("CLAMAV_FAIL_CLOSED", True)

# ---------------------------------------------------------------------------
# Sharing (Phase 5 user-to-user, Phase 6 public links)
# ---------------------------------------------------------------------------
PUBLIC_SHARE_BASE_URL = env.get_str(
    "PUBLIC_SHARE_BASE_URL", "http://localhost:5173"
).rstrip("/")
SHARE_LINK_TOKEN_BYTES = env.get_int("SHARE_LINK_TOKEN_BYTES", 32)  # 256-bit
SHARE_LINK_MAX_TTL_SECONDS = env.get_int("SHARE_LINK_MAX_TTL_SECONDS", 2_592_000)
SHARE_LINK_DEFAULT_TTL_SECONDS = env.get_int("SHARE_LINK_DEFAULT_TTL_SECONDS", 86_400)
SHARE_LINK_MAX_DOWNLOADS_CAP = env.get_int("SHARE_LINK_MAX_DOWNLOADS_CAP", 10_000)
SHARE_LINK_PASSWORD_MAX_ATTEMPTS = env.get_int("SHARE_LINK_PASSWORD_MAX_ATTEMPTS", 5)
SHARE_LINK_PASSWORD_LOCKOUT_SECONDS = env.get_int(
    "SHARE_LINK_PASSWORD_LOCKOUT_SECONDS", 900
)
SHARE_LINK_GRANT_TTL_SECONDS = env.get_int("SHARE_LINK_GRANT_TTL_SECONDS", 600)
SHARE_LINK_MIN_PASSWORD_LENGTH = env.get_int("SHARE_LINK_MIN_PASSWORD_LENGTH", 8)
SHARE_LINK_RETENTION_DAYS = env.get_int("SHARE_LINK_RETENTION_DAYS", 30)
FILE_SHARE_MAX_TTL_SECONDS = env.get_int("FILE_SHARE_MAX_TTL_SECONDS", 7_776_000)

# ---------------------------------------------------------------------------
# Email (password reset / verification architecture)
# ---------------------------------------------------------------------------
EMAIL_BACKEND = env.get_str(
    "EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend"
)
EMAIL_HOST = env.get_str("EMAIL_HOST", "localhost")
EMAIL_PORT = env.get_int("EMAIL_PORT", 25)
EMAIL_HOST_USER = env.get_str("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = env.get_str("EMAIL_HOST_PASSWORD")
EMAIL_USE_TLS = env.get_bool("EMAIL_USE_TLS", False)
DEFAULT_FROM_EMAIL = env.get_str("DEFAULT_FROM_EMAIL", "no-reply@secureshare.local")
FRONTEND_BASE_URL = env.get_str("FRONTEND_BASE_URL", PUBLIC_SHARE_BASE_URL)

# ---------------------------------------------------------------------------
# i18n / tz
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Logging: application / security / audit streams, with secret redaction
# ---------------------------------------------------------------------------
LOG_DIR = env.get_path("LOG_DIR", PROJECT_ROOT / "logs", relative_to=PROJECT_ROOT)
LOG_LEVEL = env.get_str("LOG_LEVEL", "INFO").upper()
LOG_TO_FILE = env.get_bool("LOG_TO_FILE", True)

for _directory in (ENCRYPTED_STORAGE_ROOT, Path(FILE_UPLOAD_TEMP_DIR), MEDIA_ROOT):
    Path(_directory).mkdir(parents=True, exist_ok=True, mode=0o700)
if LOG_TO_FILE:
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True, mode=0o700)


def _file_handler(filename: str, level: str = "INFO") -> dict:
    return {
        "level": level,
        "class": "logging.handlers.RotatingFileHandler",
        "filename": str(Path(LOG_DIR) / filename),
        "maxBytes": 10_485_760,
        "backupCount": 5,
        "formatter": "json",
        "filters": ["redact_secrets"],
    }


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "redact_secrets": {"()": "core.logging.SensitiveDataFilter"},
    },
    "formatters": {
        "json": {"()": "core.logging.JsonLogFormatter"},
        "console": {
            "format": "%(asctime)s %(levelname)-8s %(name)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "level": LOG_LEVEL,
            "class": "logging.StreamHandler",
            "formatter": "console",
            "filters": ["redact_secrets"],
        },
        **(
            {
                "app_file": _file_handler("application.log", LOG_LEVEL),
                "security_file": _file_handler("security.log"),
                "audit_file": _file_handler("audit.log"),
            }
            if LOG_TO_FILE
            else {}
        ),
    },
    "root": {
        "handlers": ["console"] + (["app_file"] if LOG_TO_FILE else []),
        "level": LOG_LEVEL,
    },
    "loggers": {
        "django": {
            "handlers": ["console"] + (["app_file"] if LOG_TO_FILE else []),
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "django.db.backends": {"level": "WARNING", "propagate": True},
        "secureshare": {
            "handlers": ["console"] + (["app_file"] if LOG_TO_FILE else []),
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "secureshare.security": {
            "handlers": ["console"] + (["security_file"] if LOG_TO_FILE else []),
            "level": "INFO",
            "propagate": False,
        },
        "secureshare.audit": {
            "handlers": ["console"] + (["audit_file"] if LOG_TO_FILE else []),
            "level": "INFO",
            "propagate": False,
        },
    },
}

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
DJANGO_ADMIN_ENABLED = env.get_bool("DJANGO_ADMIN_ENABLED", False)
DJANGO_ADMIN_URL = env.get_str("DJANGO_ADMIN_URL", "django-admin/").lstrip("/")
APPEND_SLASH = True
