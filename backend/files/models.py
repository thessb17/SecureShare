"""File metadata and envelope-encryption metadata.

The database stores **metadata only**: no plaintext, no plaintext DEK, no file
path. ``stored_object_id`` is an opaque CSPRNG token resolved to a path by the
storage backend and is never exposed through the API.
"""
from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class FileStatus(models.TextChoices):
    PENDING = "PENDING", "Pending"
    ACTIVE = "ACTIVE", "Active"
    FAILED = "FAILED", "Failed"
    DELETED = "DELETED", "Deleted"


class MalwareScanStatus(models.TextChoices):
    NOT_SCANNED = "NOT_SCANNED", "Not scanned"
    SKIPPED = "SKIPPED", "Skipped (scanner disabled)"
    CLEAN = "CLEAN", "Clean"
    INFECTED = "INFECTED", "Infected"
    ERROR = "ERROR", "Scanner error"


class FileQuerySet(models.QuerySet):
    def active(self) -> "FileQuerySet":
        return self.filter(deleted_at__isnull=True, status=FileStatus.ACTIVE)

    def owned_by(self, user) -> "FileQuerySet":
        return self.filter(owner=user)

    def shared_with(self, user) -> "FileQuerySet":
        """Files an active, unexpired share grants this user access to."""
        now = timezone.now()
        return self.filter(
            shares__recipient=user,
            shares__revoked_at__isnull=True,
        ).filter(
            models.Q(shares__expires_at__isnull=True) | models.Q(shares__expires_at__gt=now)
        )

    def visible_to(self, user) -> "FileQuerySet":
        if getattr(user, "is_admin", False):
            return self
        return self.filter(
            models.Q(owner=user)
            | (
                models.Q(shares__recipient=user, shares__revoked_at__isnull=True)
                & (
                    models.Q(shares__expires_at__isnull=True)
                    | models.Q(shares__expires_at__gt=timezone.now())
                )
            )
        ).distinct()


class File(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="files"
    )

    #: Sanitised display name. Never used to build a filesystem path.
    original_filename = models.CharField(max_length=255)
    #: Opaque CSPRNG storage key (never returned by the API).
    stored_object_id = models.CharField(max_length=64, unique=True, editable=False)

    file_size = models.BigIntegerField(help_text="Plaintext size in bytes")
    encrypted_size = models.BigIntegerField(default=0)
    mime_type = models.CharField(max_length=127, help_text="Server-detected MIME type")
    declared_mime_type = models.CharField(
        max_length=127, blank=True, help_text="Client supplied value (untrusted)"
    )
    extension = models.CharField(max_length=16, blank=True)

    checksum_sha256 = models.CharField(
        max_length=64, help_text="SHA-256 of the plaintext, computed before encryption"
    )
    encrypted_checksum_sha256 = models.CharField(max_length=64, blank=True)

    status = models.CharField(
        max_length=16, choices=FileStatus.choices, default=FileStatus.PENDING, db_index=True
    )
    malware_scan_status = models.CharField(
        max_length=16,
        choices=MalwareScanStatus.choices,
        default=MalwareScanStatus.NOT_SCANNED,
    )
    malware_signature = models.CharField(max_length=128, blank=True)
    scanned_at = models.DateTimeField(null=True, blank=True)

    download_count = models.PositiveIntegerField(default=0)
    last_downloaded_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True)

    objects = FileQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("owner", "-created_at")),
            models.Index(fields=("owner", "status")),
            models.Index(fields=("deleted_at",)),
            models.Index(fields=("checksum_sha256",)),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(file_size__gte=0), name="file_size_non_negative"
            )
        ]

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.original_filename} ({self.id})"

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None or self.status == FileStatus.DELETED

    @property
    def is_available(self) -> bool:
        return self.status == FileStatus.ACTIVE and self.deleted_at is None

    def mark_deleted(self) -> None:
        self.status = FileStatus.DELETED
        self.deleted_at = timezone.now()
        self.save(update_fields=["status", "deleted_at", "updated_at"])

    def register_download(self) -> None:
        File.objects.filter(pk=self.pk).update(
            download_count=models.F("download_count") + 1,
            last_downloaded_at=timezone.now(),
        )


class FileEncryptionMetadata(models.Model):
    """Envelope-encryption parameters for exactly one file.

    ``nonce`` holds the 36-byte AEAD stream header written at the start of the
    encrypted object. It embeds the 8-byte random nonce prefix; the nonce of
    chunk *i* is ``prefix || uint32be(i)``, so every chunk of every file uses a
    unique nonce. Keeping a copy here lets decryption detect a storage object
    that was swapped for another one.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.OneToOneField(
        File, on_delete=models.CASCADE, related_name="encryption"
    )
    algorithm = models.CharField(max_length=48)
    key_wrapping_algorithm = models.CharField(max_length=48)
    key_id = models.CharField(
        max_length=32, db_index=True, help_text="Fingerprint of the wrapping RSA key"
    )
    wrapped_dek = models.BinaryField(
        help_text="RSA-OAEP wrapped data encryption key (never the raw DEK)"
    )
    nonce = models.BinaryField(help_text="AEAD stream header (contains the nonce prefix)")
    chunk_size = models.PositiveIntegerField()
    chunk_count = models.PositiveIntegerField(default=1)
    aad_context = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "file encryption metadata"
        verbose_name_plural = "file encryption metadata"

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.algorithm} metadata for {self.file_id}"

    @property
    def nonce_prefix(self) -> bytes:
        return bytes(self.nonce)[-8:]
