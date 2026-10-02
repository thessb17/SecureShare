"""Account serializers.

Note: ``role`` is **never** writable from the API - privilege escalation by
mass assignment is impossible.
"""
from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """Safe public projection of an account."""

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "full_name",
            "role",
            "is_active",
            "is_email_verified",
            "created_at",
            "last_login",
            "password_changed_at",
        )
        read_only_fields = (
            "id",
            "email",
            "role",
            "is_active",
            "is_email_verified",
            "created_at",
            "last_login",
            "password_changed_at",
        )

    def validate_full_name(self, value: str) -> str:
        return value.strip()[:150]


class TokenPairSerializer(serializers.Serializer):
    """Documentation-only representation of the JWT pair."""

    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)
    token_type = serializers.CharField(read_only=True)
    expires_in = serializers.IntegerField(read_only=True)


class PasswordPolicyMixin:
    """Applies AUTH_PASSWORD_VALIDATORS and surfaces every failure."""

    def _validate_password_policy(self, password: str, user: Any = None) -> str:
        try:
            validate_password(password, user)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages)) from exc
        return password


class RegistrationSerializer(PasswordPolicyMixin, serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    full_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    password = serializers.CharField(
        write_only=True, trim_whitespace=False, max_length=128
    )
    password_confirm = serializers.CharField(
        write_only=True, trim_whitespace=False, max_length=128
    )

    def validate_email(self, value: str) -> str:
        return value.strip().lower()

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "The two password fields do not match."}
            )
        candidate = User(
            email=attrs["email"], full_name=attrs.get("full_name", "")
        )
        self._validate_password_policy(attrs["password"], candidate)
        return attrs

    def create(self, validated_data: dict[str, Any]):
        return User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            full_name=validated_data.get("full_name", "").strip(),
            role="USER",  # role is assigned by the server, never by the client
        )


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(
        write_only=True, trim_whitespace=False, max_length=128
    )


class RefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField(write_only=True)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(write_only=True)


class ChangePasswordSerializer(PasswordPolicyMixin, serializers.Serializer):
    current_password = serializers.CharField(
        write_only=True, trim_whitespace=False, max_length=128
    )
    new_password = serializers.CharField(
        write_only=True, trim_whitespace=False, max_length=128
    )
    new_password_confirm = serializers.CharField(
        write_only=True, trim_whitespace=False, max_length=128
    )

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "The two password fields do not match."}
            )
        if attrs["new_password"] == attrs["current_password"]:
            raise serializers.ValidationError(
                {"new_password": "The new password must differ from the current one."}
            )
        user = self.context["request"].user
        self._validate_password_policy(attrs["new_password"], user)
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)

    def validate_email(self, value: str) -> str:
        return value.strip().lower()


class PasswordResetConfirmSerializer(PasswordPolicyMixin, serializers.Serializer):
    uid = serializers.CharField(max_length=64)
    token = serializers.CharField(max_length=128, write_only=True)
    new_password = serializers.CharField(
        write_only=True, trim_whitespace=False, max_length=128
    )
    new_password_confirm = serializers.CharField(
        write_only=True, trim_whitespace=False, max_length=128
    )

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "The two password fields do not match."}
            )
        return attrs


class EmailVerificationConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=512, write_only=True)
