from __future__ import annotations

from typing import Any

from django.contrib import admin

from sharing.models import FileShare, ShareLink


@admin.register(FileShare)
class FileShareAdmin(admin.ModelAdmin):
    list_display = ("file", "owner", "recipient", "permission", "expires_at", "revoked_at")
    list_filter = ("permission",)
    search_fields = ("file__original_filename", "owner__email", "recipient__email")
    readonly_fields = ("id", "created_at", "updated_at", "access_count", "last_accessed_at")


@admin.register(ShareLink)
class ShareLinkAdmin(admin.ModelAdmin):
    """The token hash is never editable and the raw token is not stored."""

    list_display = (
        "token_prefix",
        "file",
        "created_by",
        "permission",
        "expires_at",
        "download_count",
        "max_downloads",
        "revoked_at",
    )
    list_filter = ("permission",)
    search_fields = ("token_prefix", "file__original_filename", "created_by__email")
    readonly_fields = (
        "id",
        "token_prefix",
        "download_count",
        "access_count",
        "created_at",
        "updated_at",
        "last_accessed_at",
        "last_downloaded_at",
    )
    exclude = ("token_hash", "password_hash")

    def has_add_permission(self, request: Any) -> bool:
        return False
