"""Sharing serializers (user-to-user shares and public share links)."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.conf import settings
from django.utils import timezone
from rest_framework import serializers

from sharing.link_services import EXPIRY_PRESETS
from sharing.models import FileShare, ShareLink, SharePermission

#: presets accepted for public share links (an expiry is mandatory)
SHARE_LINK_EXPIRY_CHOICES = (*EXPIRY_PRESETS.keys(), "custom")
#: user-to-user shares may additionally be open ended
FILE_SHARE_EXPIRY_CHOICES = (*SHARE_LINK_EXPIRY_CHOICES, "never")
EXPIRY_CHOICES = SHARE_LINK_EXPIRY_CHOICES


def resolve_expiry(
    *,
    expires_in: str | None,
    expires_at: Any,
    default_seconds: int | None,
    max_seconds: int,
    allow_never: bool,
) -> Any:
    """Turn a preset ("1h", "7d", "custom", "never") into a concrete datetime."""
    now = timezone.now()

    if expires_in == "never":
        if not allow_never:
            raise serializers.ValidationError(
                {"expires_in": "Public share links must have an expiry."}
            )
        return None

    if expires_in and expires_in != "custom":
        seconds = EXPIRY_PRESETS.get(expires_in)
        if seconds is None:
            raise serializers.ValidationError({"expires_in": "Unsupported preset."})
        return now + timedelta(seconds=seconds)

    if expires_in == "custom" and expires_at is None:
        raise serializers.ValidationError(
            {"expires_at": "A custom expiry requires an explicit expires_at value."}
        )

    if expires_at is None:
        if default_seconds is None:
            return None
        return now + timedelta(seconds=default_seconds)

    if expires_at <= now:
        raise serializers.ValidationError(
            {"expires_at": "The expiry must be in the future."}
        )
    if expires_at > now + timedelta(seconds=max_seconds):
        raise serializers.ValidationError(
            {
                "expires_at": (
                    "The expiry exceeds the maximum allowed lifetime of "
                    f"{max_seconds // 3600} hours."
                )
            }
        )
    return expires_at


class UserSummarySerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    email = serializers.EmailField(read_only=True)
    full_name = serializers.CharField(read_only=True)


class SharedFileSummarySerializer(serializers.Serializer):
    """Minimal, safe file projection embedded in share payloads."""

    id = serializers.UUIDField(read_only=True)
    filename = serializers.CharField(source="original_filename", read_only=True)
    size = serializers.IntegerField(source="file_size", read_only=True)
    mime_type = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)


# ---------------------------------------------------------------------------
# Phase 5 - user to user
# ---------------------------------------------------------------------------
class FileShareSerializer(serializers.ModelSerializer):
    file = SharedFileSummarySerializer(read_only=True)
    owner = UserSummarySerializer(read_only=True)
    recipient = UserSummarySerializer(read_only=True)
    status = serializers.CharField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = FileShare
        fields = (
            "id",
            "file",
            "owner",
            "recipient",
            "permission",
            "status",
            "is_active",
            "created_at",
            "updated_at",
            "expires_at",
            "revoked_at",
            "last_accessed_at",
            "access_count",
        )
        read_only_fields = fields


class FileShareCreateSerializer(serializers.Serializer):
    recipient = serializers.EmailField()
    permission = serializers.ChoiceField(
        choices=SharePermission.choices, default=SharePermission.VIEW
    )
    expires_in = serializers.ChoiceField(
        choices=FILE_SHARE_EXPIRY_CHOICES, required=False, allow_null=True
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        attrs["expires_at"] = resolve_expiry(
            expires_in=attrs.get("expires_in"),
            expires_at=attrs.get("expires_at"),
            default_seconds=None,  # user-to-user shares may be open ended
            max_seconds=int(settings.FILE_SHARE_MAX_TTL_SECONDS),
            allow_never=True,
        )
        return attrs


class FileShareUpdateSerializer(serializers.Serializer):
    permission = serializers.ChoiceField(
        choices=SharePermission.choices, required=False
    )
    expires_in = serializers.ChoiceField(
        choices=FILE_SHARE_EXPIRY_CHOICES, required=False, allow_null=True
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if not attrs:
            raise serializers.ValidationError("No changes were supplied.")
        if "expires_in" in attrs or "expires_at" in attrs:
            attrs["expires_at"] = resolve_expiry(
                expires_in=attrs.get("expires_in"),
                expires_at=attrs.get("expires_at"),
                default_seconds=None,
                max_seconds=int(settings.FILE_SHARE_MAX_TTL_SECONDS),
                allow_never=True,
            )
        return attrs


# ---------------------------------------------------------------------------
# Phase 6 - public share links
# ---------------------------------------------------------------------------
class ShareLinkSerializer(serializers.ModelSerializer):
    """Owner-facing representation. Never contains the raw token."""

    file = SharedFileSummarySerializer(read_only=True)
    created_by = UserSummarySerializer(read_only=True)
    status = serializers.CharField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    password_protected = serializers.BooleanField(
        source="requires_password", read_only=True
    )
    downloads_remaining = serializers.IntegerField(read_only=True, allow_null=True)
    expires_in_seconds = serializers.IntegerField(read_only=True, allow_null=True)

    class Meta:
        model = ShareLink
        fields = (
            "id",
            "file",
            "created_by",
            "token_prefix",
            "permission",
            "status",
            "is_active",
            "expires_at",
            "expires_in_seconds",
            "max_downloads",
            "download_count",
            "downloads_remaining",
            "password_protected",
            "access_count",
            "last_accessed_at",
            "last_downloaded_at",
            "revoked_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class ShareLinkCreateSerializer(serializers.Serializer):
    permission = serializers.ChoiceField(
        choices=SharePermission.choices, default=SharePermission.DOWNLOAD
    )
    expires_in = serializers.ChoiceField(
        choices=SHARE_LINK_EXPIRY_CHOICES, required=False, allow_null=True,
        help_text="1h | 6h | 24h | 3d | 7d | custom",
    )
    expires_at = serializers.DateTimeField(
        required=False, allow_null=True, help_text="Required when expires_in=custom."
    )
    max_downloads = serializers.IntegerField(
        required=False, allow_null=True, min_value=1,
        help_text="Omit or null for unlimited downloads.",
    )
    password = serializers.CharField(
        required=False, allow_blank=True, write_only=True, trim_whitespace=False,
        max_length=128,
    )

    def validate_max_downloads(self, value: int | None) -> int | None:
        if value is None:
            return None
        cap = int(settings.SHARE_LINK_MAX_DOWNLOADS_CAP)
        if value > cap:
            raise serializers.ValidationError(
                f"The download limit cannot exceed {cap}."
            )
        return value

    def validate_password(self, value: str) -> str:
        if value and len(value) < int(settings.SHARE_LINK_MIN_PASSWORD_LENGTH):
            raise serializers.ValidationError(
                "The link password must be at least "
                f"{settings.SHARE_LINK_MIN_PASSWORD_LENGTH} characters long."
            )
        return value

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        attrs["expires_at"] = resolve_expiry(
            expires_in=attrs.get("expires_in"),
            expires_at=attrs.get("expires_at"),
            default_seconds=int(settings.SHARE_LINK_DEFAULT_TTL_SECONDS),
            max_seconds=int(settings.SHARE_LINK_MAX_TTL_SECONDS),
            allow_never=False,
        )
        return attrs


class ShareLinkUpdateSerializer(serializers.Serializer):
    permission = serializers.ChoiceField(
        choices=SharePermission.choices, required=False
    )
    expires_in = serializers.ChoiceField(
        choices=SHARE_LINK_EXPIRY_CHOICES, required=False, allow_null=True
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    max_downloads = serializers.IntegerField(
        required=False, allow_null=True, min_value=1
    )
    password = serializers.CharField(
        required=False, allow_blank=True, allow_null=True, write_only=True,
        trim_whitespace=False, max_length=128,
    )

    def validate_max_downloads(self, value: int | None) -> int | None:
        return ShareLinkCreateSerializer().validate_max_downloads(value)

    def validate_password(self, value: str | None) -> str | None:
        if value:
            return ShareLinkCreateSerializer().validate_password(value)
        return value

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if not attrs:
            raise serializers.ValidationError("No changes were supplied.")
        if "expires_in" in attrs or "expires_at" in attrs:
            attrs["expires_at"] = resolve_expiry(
                expires_in=attrs.get("expires_in"),
                expires_at=attrs.get("expires_at"),
                default_seconds=int(settings.SHARE_LINK_DEFAULT_TTL_SECONDS),
                max_seconds=int(settings.SHARE_LINK_MAX_TTL_SECONDS),
                allow_never=False,
            )
        return attrs


class ShareLinkCreatedSerializer(serializers.Serializer):
    """Creation response - the only time the raw token is ever returned."""

    share_link = ShareLinkSerializer(read_only=True)
    token = serializers.CharField(read_only=True)
    url = serializers.CharField(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True, allow_null=True)
    permission = serializers.CharField(read_only=True)
    max_downloads = serializers.IntegerField(read_only=True, allow_null=True)
    warning = serializers.CharField(read_only=True)


class PublicShareLinkSerializer(serializers.Serializer):
    """What an anonymous visitor may see about a link."""

    filename = serializers.CharField(read_only=True)
    size = serializers.IntegerField(read_only=True)
    mime_type = serializers.CharField(read_only=True)
    permission = serializers.CharField(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True, allow_null=True)
    expires_in_seconds = serializers.IntegerField(read_only=True, allow_null=True)
    max_downloads = serializers.IntegerField(read_only=True, allow_null=True)
    download_count = serializers.IntegerField(read_only=True)
    downloads_remaining = serializers.IntegerField(read_only=True, allow_null=True)
    password_required = serializers.BooleanField(read_only=True)
    encryption = serializers.DictField(read_only=True)


class SharePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        write_only=True, trim_whitespace=False, max_length=128
    )


class ShareDownloadRequestSerializer(serializers.Serializer):
    password = serializers.CharField(
        required=False, allow_blank=True, write_only=True,
        trim_whitespace=False, max_length=128,
    )
    grant = serializers.CharField(required=False, allow_blank=True, write_only=True)
