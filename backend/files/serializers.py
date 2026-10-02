"""File serializers.

Explicitly excluded from every payload: ``stored_object_id``, wrapped DEKs,
nonces/headers, filesystem paths and any key material.
"""
from __future__ import annotations

from typing import Any

from django.conf import settings
from rest_framework import serializers

from files.access import AccessVia, resolve_file_access
from files.models import File


class FileOwnerSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    email = serializers.EmailField(read_only=True)
    full_name = serializers.CharField(read_only=True)


class FileSerializer(serializers.ModelSerializer):
    """Safe metadata projection of a file."""

    filename = serializers.CharField(source="original_filename", read_only=True)
    size = serializers.IntegerField(source="file_size", read_only=True)
    owner = FileOwnerSerializer(read_only=True)
    encryption = serializers.SerializerMethodField()
    malware_scan = serializers.SerializerMethodField()
    access = serializers.SerializerMethodField()

    class Meta:
        model = File
        fields = (
            "id",
            "filename",
            "size",
            "encrypted_size",
            "mime_type",
            "extension",
            "checksum_sha256",
            "status",
            "owner",
            "encryption",
            "malware_scan",
            "access",
            "download_count",
            "last_downloaded_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields

    def get_encryption(self, obj: File) -> dict[str, Any]:
        metadata = getattr(obj, "encryption", None)
        return {
            "encrypted": metadata is not None,
            "algorithm": getattr(metadata, "algorithm", None),
            "key_wrapping_algorithm": getattr(metadata, "key_wrapping_algorithm", None),
            "chunk_count": getattr(metadata, "chunk_count", None),
        }

    def get_malware_scan(self, obj: File) -> dict[str, Any]:
        return {
            "status": obj.malware_scan_status,
            "scanned": obj.scanned_at is not None,
            "scanned_at": obj.scanned_at,
            "scanner_enabled": bool(settings.CLAMAV_ENABLED),
        }

    def get_access(self, obj: File) -> dict[str, Any]:
        request = self.context.get("request")
        user = getattr(request, "user", None)
        decision = resolve_file_access(user, obj)
        return {
            "can_view": decision.can_view,
            "can_download": decision.can_download,
            "via": str(decision.via),
            "is_owner": decision.via == AccessVia.OWNER,
        }


class FileUploadSerializer(serializers.Serializer):
    """Multipart upload payload. Real validation happens in the service layer."""

    file = serializers.FileField(write_only=True)
