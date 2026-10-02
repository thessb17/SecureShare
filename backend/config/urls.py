"""Root URL configuration.

Every API route lives under /api/. The encrypted storage directory is never
routed - objects are only reachable through authenticated, authorized views.
"""
from __future__ import annotations

from django.conf import settings
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from core.health import HealthView
from core.views import not_found_view, server_error_view

api_patterns = [
    path("health/", HealthView.as_view(), name="health"),
    path("", include("accounts.urls")),
    path("", include("files.urls")),
    path("", include("sharing.urls")),
    path("", include("audit.urls")),
    path("", include("dashboard.urls")),
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "docs/",
        SpectacularSwaggerView.as_view(url_name="api:schema"),
        name="swagger-ui",
    ),
    path(
        "redoc/",
        SpectacularRedocView.as_view(url_name="api:schema"),
        name="redoc",
    ),
]

urlpatterns = [path("api/", include((api_patterns, "api")))]

if settings.DJANGO_ADMIN_ENABLED:
    from django.contrib import admin

    urlpatterns.append(path(settings.DJANGO_ADMIN_URL, admin.site.urls))

handler404 = not_found_view
handler500 = server_error_view
