"""Authentication specific throttles (brute-force resistance)."""
from __future__ import annotations

from core.throttling import IPScopedThrottle, UserScopedThrottle


class LoginThrottle(IPScopedThrottle):
    scope = "auth.login"


class RegistrationThrottle(IPScopedThrottle):
    scope = "auth.register"


class RefreshThrottle(IPScopedThrottle):
    scope = "auth.refresh"


class PasswordResetThrottle(IPScopedThrottle):
    scope = "auth.password_reset"


class ChangePasswordThrottle(UserScopedThrottle):
    scope = "auth.change_password"
