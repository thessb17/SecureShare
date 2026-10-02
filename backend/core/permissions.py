"""Shared DRF permission classes.

Authorization is always enforced here (and in the service layer) - never in
the frontend.
"""
from __future__ import annotations

from typing import Any

from rest_framework.permissions import BasePermission


class IsActiveUser(BasePermission):
    """Authenticated, enabled and not locked out."""

    message = "You do not have permission to access this resource."

    def has_permission(self, request: Any, view: Any) -> bool:
        user = getattr(request, "user", None)
        return bool(
            user
            and user.is_authenticated
            and user.is_active
            and not getattr(user, "is_locked", False)
        )


class IsAdminRole(IsActiveUser):
    """Only accounts carrying the ADMIN role (or Django superusers)."""

    message = "Administrator privileges are required for this operation."

    def has_permission(self, request: Any, view: Any) -> bool:
        if not super().has_permission(request, view):
            return False
        return bool(getattr(request.user, "is_admin", False))


class IsOwnerOrAdmin(IsActiveUser):
    """Object-level ownership check (``owner`` attribute) or admin role."""

    def has_object_permission(self, request: Any, view: Any, obj: Any) -> bool:
        user = request.user
        if getattr(user, "is_admin", False):
            return True
        owner = getattr(obj, "owner", None) or getattr(obj, "created_by", None)
        return owner is not None and owner.pk == user.pk
