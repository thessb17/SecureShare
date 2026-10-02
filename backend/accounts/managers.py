from __future__ import annotations

from typing import Any

from django.contrib.auth.base_user import BaseUserManager
from django.db import models


class UserQuerySet(models.QuerySet):
    def active(self) -> "UserQuerySet":
        return self.filter(is_active=True)

    def admins(self) -> "UserQuerySet":
        return self.filter(role="ADMIN")


class UserManager(BaseUserManager.from_queryset(UserQuerySet)):  # type: ignore[misc]
    """Email-based user manager (there is no username field)."""

    use_in_migrations = True

    def _create_user(self, email: str, password: str | None, **extra: Any):
        if not email:
            raise ValueError("An email address is required.")
        email = self.normalize_email(email).strip().lower()
        user = self.model(email=email, **extra)
        # set_password hashes with Argon2id; the plaintext never touches the DB.
        user.set_password(password)
        user.full_clean(exclude=["password", "last_login"])
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra: Any):
        extra.setdefault("role", "USER")
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra)

    def create_superuser(self, email: str, password: str | None = None, **extra: Any):
        extra.setdefault("role", "ADMIN")
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        extra.setdefault("is_active", True)
        extra.setdefault("is_email_verified", True)
        if extra["is_staff"] is not True or extra["is_superuser"] is not True:
            raise ValueError("Superusers must have is_staff=True and is_superuser=True.")
        return self._create_user(email, password, **extra)
