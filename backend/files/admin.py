from __future__ import annotations

from typing import Any

from django.contrib import admin

from files.models import File, FileEncryptionMetadata


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = (
        "original_filename",
        "owner",
        "file_size",
        "mime_type",
        "status",
        "malware_scan_status",
        "created_at",
    )
    list_filter = ("status", "malware_scan_status", "mime_type")
    search_fields = ("original_filename", "owner__email", "checksum_sha256")
    readonly_fields = ("id", "stored_object_id", "checksum_sha256", "encrypted_checksum_sha256")

    def has_add_permission(self, request: Any) -> bool:
        return False


@admin.register(FileEncryptionMetadata)
class FileEncryptionMetadataAdmin(admin.ModelAdmin):
    """Key material is never rendered: only algorithm identifiers."""

    list_display = ("file", "algorithm", "key_wrapping_algorithm", "key_id", "created_at")
    readonly_fields = ("id", "file", "algorithm", "key_wrapping_algorithm", "key_id",
                       "chunk_size", "chunk_count", "created_at")
    exclude = ("wrapped_dek", "nonce", "aad_context")

    def has_add_permission(self, request: Any) -> bool:
        return False

    def has_change_permission(self, request: Any, obj: Any = None) -> bool:
        return False
