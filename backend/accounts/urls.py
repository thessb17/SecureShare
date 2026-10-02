from __future__ import annotations

from django.urls import path

from accounts.views import (
    AdminTestView,
    ChangePasswordView,
    CurrentUserView,
    EmailVerificationConfirmView,
    EmailVerificationRequestView,
    LoginView,
    LogoutView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    RegisterView,
    RevokeSessionsView,
    TokenRefreshView,
)

urlpatterns = [
    path("auth/register/", RegisterView.as_view(), name="auth-register"),
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="auth-refresh"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path(
        "auth/change-password/", ChangePasswordView.as_view(), name="auth-change-password"
    ),
    path(
        "auth/password-reset/",
        PasswordResetRequestView.as_view(),
        name="auth-password-reset",
    ),
    path(
        "auth/password-reset/confirm/",
        PasswordResetConfirmView.as_view(),
        name="auth-password-reset-confirm",
    ),
    path(
        "auth/verify-email/",
        EmailVerificationRequestView.as_view(),
        name="auth-verify-email",
    ),
    path(
        "auth/verify-email/confirm/",
        EmailVerificationConfirmView.as_view(),
        name="auth-verify-email-confirm",
    ),
    path(
        "auth/revoke-sessions/", RevokeSessionsView.as_view(), name="auth-revoke-sessions"
    ),
    path("users/me/", CurrentUserView.as_view(), name="users-me"),
    path("admin/test/", AdminTestView.as_view(), name="admin-test"),
]
