"""Sharing models.

``FileShare``  - authenticated user-to-user grant (Phase 5).
``ShareLink``  - public, tokenised, expiring, download-limited link (Phase 6).

Secrets are never stored in the clear:

* the share-link token is kept as a SHA-256 hash of a 256-bit CSPRNG value
  (a fast hash is correct here - the token has full entropy, so there is
  nothing to brute force; the hash only protects against database disclosure);
* the optional link password is stored with Django's configured password
  hasher (Argon2id), because user chosen passwords are low entropy.
"""
from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from files.models import File


class SharePermission(models.TextChoices):
    VIEW = "VIEW", "View metadata only"
    DOWNLOAD = "DOWNLOAD", "View and download"


class ShareStatus(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    EXPIRED = "EXPIRED", "Expired"
    REVOKED = "REVOKED", "Revoked"
    EXHAUSTED = "EXHAUSTED", "Download limit reached"
    FILE_DELETED = "FILE_DELETED", "File deleted"


class FileShareQuerySet(models.QuerySet):
    def active(self) -> "FileShareQuerySet":
        now = timezone.now()
        return self.filter(revoked_at__isnull=True).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
        )

    def for_recipient(self, user) -> "FileShareQuerySet":
        return self.filter(recipient=user)

    def for_owner(self, user) -> "FileShareQuerySet":
        return self.filter(owner=user)


class FileShare(models.Model):
    """A grant of access on one file to one registered user."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name="shares")
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="shares_created"
    )
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="shares_received",
    )
    permission = models.CharField(
        max_length=16, choices=SharePermission.choices, default=SharePermission.VIEW
    )

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)

    last_accessed_at = models.DateTimeField(null=True, blank=True)
    access_count = models.PositiveIntegerField(default=0)

    objects = FileShareQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("recipient", "-created_at")),
            models.Index(fields=("owner", "-created_at")),
            models.Index(fields=("file", "recipient")),
            models.Index(fields=("expires_at",)),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=("file", "recipient"),
                condition=models.Q(revoked_at__isnull=True),
                name="unique_active_share_per_recipient",
            ),
            models.CheckConstraint(
                condition=~models.Q(owner=models.F("recipient")),
                name="share_owner_is_not_recipient",
            ),
        ]

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.file_id} -> {self.recipient_id} ({self.permission})"

    # -- state -------------------------------------------------------------
    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @property
    def is_expired(self) -> bool:
        return bool(self.expires_at and self.expires_at <= timezone.now())

    @property
    def is_active(self) -> bool:
        return not self.is_revoked and not self.is_expired

    @property
    def status(self) -> str:
        if self.is_revoked:
            return ShareStatus.REVOKED
        if self.is_expired:
            return ShareStatus.EXPIRED
        return ShareStatus.ACTIVE

    @property
    def allows_download(self) -> bool:
        return self.is_active and self.permission == SharePermission.DOWNLOAD

    def revoke(self) -> None:
        if self.revoked_at is None:
            self.revoked_at = timezone.now()
            self.save(update_fields=["revoked_at", "updated_at"])

    def register_access(self) -> None:
        FileShare.objects.filter(pk=self.pk).update(
            access_count=models.F("access_count") + 1,
            last_accessed_at=timezone.now(),
        )


class ShareLinkQuerySet(models.QuerySet):
    def active(self) -> "ShareLinkQuerySet":
        now = timezone.now()
        return (
            self.filter(revoked_at__isnull=True)
            .filter(models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now))
            .filter(
                models.Q(max_downloads__isnull=True)
                | models.Q(download_count__lt=models.F("max_downloads"))
            )
        )

    def expired(self) -> "ShareLinkQuerySet":
        return self.filter(
            revoked_at__isnull=True,
            expires_at__isnull=False,
            expires_at__lte=timezone.now(),
        )


class ShareLink(models.Model):
    """A public, unauthenticated, capability-style link to one file."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name="share_links")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="share_links_created",
    )

    #: SHA-256 hex digest of the raw token. The raw token is shown exactly once.
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    #: First 12 hex chars of the *hash* - a non-secret handle for support/audit.
    token_prefix = models.CharField(max_length=16, db_index=True, editable=False)

    permission = models.CharField(
        max_length=16, choices=SharePermission.choices, default=SharePermission.DOWNLOAD
    )
    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)
    max_downloads = models.PositiveIntegerField(
        null=True, blank=True, help_text="NULL means unlimited"
    )
    download_count = models.PositiveIntegerField(default=0)
    #: Argon2id hash of the optional link password (never the plaintext).
    password_hash = models.CharField(max_length=256, blank=True, default="")

    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    access_count = models.PositiveIntegerField(default=0)
    last_accessed_at = models.DateTimeField(null=True, blank=True)
    last_downloaded_at = models.DateTimeField(null=True, blank=True)
    #: Set by the Celery sweep so SHARE_LINK_EXPIRED is audited exactly once.
    expiry_event_recorded = models.BooleanField(default=False)

    objects = ShareLinkQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("created_by", "-created_at")),
            models.Index(fields=("file", "-created_at")),
            models.Index(fields=("expires_at",)),
            models.Index(fields=("revoked_at",)),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(max_downloads__isnull=True)
                | models.Q(max_downloads__gt=0),
                name="share_link_max_downloads_positive",
            ),
        ]

    def __str__(self) -> str:  # pragma: no cover
        return f"ShareLink({self.token_prefix}) -> {self.file_id}"

    # -- state -------------------------------------------------------------
    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @property
    def is_expired(self) -> bool:
        return bool(self.expires_at and self.expires_at <= timezone.now())

    @property
    def is_exhausted(self) -> bool:
        return self.max_downloads is not None and self.download_count >= self.max_downloads

    @property
    def is_active(self) -> bool:
        return not (self.is_revoked or self.is_expired or self.is_exhausted)

    @property
    def status(self) -> str:
        if self.is_revoked:
            return ShareStatus.REVOKED
        if self.is_expired:
            return ShareStatus.EXPIRED
        if self.is_exhausted:
            return ShareStatus.EXHAUSTED
        return ShareStatus.ACTIVE

    @property
    def requires_password(self) -> bool:
        return bool(self.password_hash)

    @property
    def downloads_remaining(self) -> int | None:
        if self.max_downloads is None:
            return None
        return max(self.max_downloads - self.download_count, 0)

    @property
    def expires_in_seconds(self) -> int | None:
        if self.expires_at is None:
            return None
        return max(int((self.expires_at - timezone.now()).total_seconds()), 0)

    @property
    def allows_download(self) -> bool:
        return self.permission == SharePermission.DOWNLOAD

    def revoke(self) -> None:
        if self.revoked_at is None:
            self.revoked_at = timezone.now()
            self.save(update_fields=["revoked_at", "updated_at"])

    def register_access(self) -> None:
        ShareLink.objects.filter(pk=self.pk).update(
            access_count=models.F("access_count") + 1,
            last_accessed_at=timezone.now(),
        )
