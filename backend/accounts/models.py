"""Custom user model with UUID primary key, roles and lockout state."""
from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone

from accounts.managers import UserManager


class Role(models.TextChoices):
    USER = "USER", "User"
    ADMIN = "ADMIN", "Administrator"


class User(AbstractBaseUser, PermissionsMixin):
    """SecureShare account.

    Passwords are stored exclusively as Argon2id hashes (see
    ``settings.PASSWORD_HASHERS``) - plaintext is never persisted or logged.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True, max_length=254)
    full_name = models.CharField(max_length=150, blank=True)
    role = models.CharField(
        max_length=16, choices=Role.choices, default=Role.USER, db_index=True
    )

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)

    # --- brute force protection ------------------------------------------
    failed_login_count = models.PositiveIntegerField(default=0)
    last_failed_login_at = models.DateTimeField(null=True, blank=True)
    locked_until = models.DateTimeField(null=True, blank=True)

    # --- session / token revocation --------------------------------------
    #: Bumped on password change or explicit revocation; JWTs carrying an old
    #: value are rejected by ``SecureJWTAuthentication``.
    token_version = models.PositiveIntegerField(default=0)
    password_changed_at = models.DateTimeField(null=True, blank=True)

    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS: list[str] = []

    objects = UserManager()

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("role", "is_active")),
            models.Index(fields=("-created_at",)),
        ]

    def __str__(self) -> str:  # pragma: no cover
        return self.email

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    # -- roles -------------------------------------------------------------
    @property
    def is_admin(self) -> bool:
        """Authoritative role check used by every permission class."""
        return self.role == Role.ADMIN or self.is_superuser

    # -- lockout -----------------------------------------------------------
    @property
    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > timezone.now())

    @property
    def lock_expires_in(self) -> int:
        if not self.is_locked:
            return 0
        return int((self.locked_until - timezone.now()).total_seconds())

    def lock(self, seconds: int | None = None) -> None:
        seconds = seconds or settings.LOGIN_LOCKOUT_SECONDS
        self.locked_until = timezone.now() + timedelta(seconds=seconds)
        self.save(update_fields=["locked_until", "updated_at"])

    def unlock(self) -> None:
        self.locked_until = None
        self.failed_login_count = 0
        self.save(update_fields=["locked_until", "failed_login_count", "updated_at"])

    def register_failed_login(self) -> bool:
        """Count a failed attempt; returns True when the account got locked."""
        now = timezone.now()
        window = timedelta(seconds=settings.LOGIN_FAILURE_WINDOW_SECONDS)
        if self.last_failed_login_at and now - self.last_failed_login_at > window:
            self.failed_login_count = 1
        else:
            self.failed_login_count += 1
        self.last_failed_login_at = now

        locked = False
        if self.failed_login_count >= settings.LOGIN_FAILURE_LIMIT:
            self.locked_until = now + timedelta(seconds=settings.LOGIN_LOCKOUT_SECONDS)
            locked = True
        self.save(
            update_fields=[
                "failed_login_count",
                "last_failed_login_at",
                "locked_until",
                "updated_at",
            ]
        )
        return locked

    def register_successful_login(self, ip_address: str | None = None) -> None:
        self.failed_login_count = 0
        self.last_failed_login_at = None
        self.locked_until = None
        self.last_login = timezone.now()
        self.last_login_ip = ip_address
        self.save(
            update_fields=[
                "failed_login_count",
                "last_failed_login_at",
                "locked_until",
                "last_login",
                "last_login_ip",
                "updated_at",
            ]
        )

    # -- credentials -------------------------------------------------------
    def mark_password_changed(self) -> None:
        """Invalidate every issued JWT and record the rotation timestamp."""
        self.token_version += 1
        self.password_changed_at = timezone.now()
        self.failed_login_count = 0
        self.locked_until = None
        self.save(
            update_fields=[
                "password",
                "token_version",
                "password_changed_at",
                "failed_login_count",
                "locked_until",
                "updated_at",
            ]
        )

    def revoke_tokens(self) -> None:
        self.token_version += 1
        self.save(update_fields=["token_version", "updated_at"])
