# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# SecureShare API image - multi-stage, non-root, no build toolchain at runtime
# ---------------------------------------------------------------------------

FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install --no-install-recommends -y \
        build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install -r requirements.txt


# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=config.settings.prod

# libmagic1 -> MIME sniffing; libpq5 -> psycopg; curl -> container healthcheck.
# No compilers in the runtime layer.
RUN apt-get update && apt-get install --no-install-recommends -y \
        libmagic1 libpq5 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 secureshare \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin secureshare

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=secureshare:secureshare . /app

# Runtime directories owned by the unprivileged user. 0700 on storage: only the
# application account may read ciphertext.
RUN mkdir -p /app/staticfiles /data/storage /data/logs /data/tmp /data/media \
    && chown -R secureshare:secureshare /app/staticfiles /data \
    && chmod 700 /data/storage

USER secureshare

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8000/api/health/ || exit 1

# 1 worker handles ~N concurrent downloads; gthread keeps streaming responses
# cheap. --max-requests recycles workers to bound memory growth.
CMD ["gunicorn", "config.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--worker-class", "gthread", \
     "--threads", "4", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--forwarded-allow-ips", "*"]
