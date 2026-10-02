from __future__ import annotations

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from accounts.models import User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    ordering = ("-created_at",)
    list_display = ("email", "role", "is_active", "is_email_verified", "created_at")
    list_filter = ("role", "is_active", "is_email_verified")
    search_fields = ("email", "full_name")
    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
        "last_login",
        "password_changed_at",
        "token_version",
        "failed_login_count",
        "last_failed_login_at",
        "last_login_ip",
    )
    fieldsets = (
        (None, {"fields": ("id", "email", "password")}),
        ("Profile", {"fields": ("full_name",)}),
        ("Roles", {"fields": ("role", "is_active", "is_staff", "is_superuser", "groups")}),
        (
            "Security",
            {
                "fields": (
                    "is_email_verified",
                    "failed_login_count",
                    "last_failed_login_at",
                    "locked_until",
                    "token_version",
                    "password_changed_at",
                    "last_login_ip",
                )
            },
        ),
        ("Timestamps", {"fields": ("created_at", "updated_at", "last_login")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "full_name", "role", "password1", "password2"),
            },
        ),
    )
