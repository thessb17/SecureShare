"""Audit action catalogue and severities."""
from __future__ import annotations

from django.db import models


class AuditAction(models.TextChoices):
    # --- accounts / authentication (Phase 2) ---------------------------------
    USER_REGISTERED = "USER_REGISTERED", "User registered"
    LOGIN_SUCCESS = "LOGIN_SUCCESS", "Login success"
    LOGIN_FAILURE = "LOGIN_FAILURE", "Login failure"
    LOGOUT = "LOGOUT", "Logout"
    TOKEN_REFRESHED = "TOKEN_REFRESHED", "Token refreshed"
    TOKENS_REVOKED = "TOKENS_REVOKED", "All sessions revoked"
    PASSWORD_CHANGED = "PASSWORD_CHANGED", "Password changed"
    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED", "Password reset requested"
    PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED", "Password reset completed"
    EMAIL_VERIFICATION_SENT = "EMAIL_VERIFICATION_SENT", "Email verification sent"
    EMAIL_VERIFIED = "EMAIL_VERIFIED", "Email verified"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED", "Account locked"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED", "Account unlocked"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED", "Account disabled"

    # --- files (Phase 4) -----------------------------------------------------
    FILE_UPLOADED = "FILE_UPLOADED", "File uploaded"
    FILE_UPLOAD_REJECTED = "FILE_UPLOAD_REJECTED", "File upload rejected"
    FILE_DOWNLOADED = "FILE_DOWNLOADED", "File downloaded"
    FILE_VIEWED = "FILE_VIEWED", "File metadata viewed"
    FILE_DELETED = "FILE_DELETED", "File deleted"
    FILE_INTEGRITY_FAILURE = "FILE_INTEGRITY_FAILURE", "File integrity failure"
    UNAUTHORIZED_FILE_ACCESS = "UNAUTHORIZED_FILE_ACCESS", "Unauthorized file access"
    MALWARE_DETECTED = "MALWARE_DETECTED", "Malware detected"

    # --- user-to-user sharing (Phase 5) -------------------------------------
    FILE_SHARED = "FILE_SHARED", "File shared"
    SHARE_ACCESSED = "SHARE_ACCESSED", "Share accessed"
    SHARE_MODIFIED = "SHARE_MODIFIED", "Share modified"
    SHARE_REVOKED = "SHARE_REVOKED", "Share revoked"
    SHARE_EXPIRED = "SHARE_EXPIRED", "Share expired"
    UNAUTHORIZED_SHARE_ACCESS = "UNAUTHORIZED_SHARE_ACCESS", "Unauthorized share access"

    # --- public share links (Phase 6) ---------------------------------------
    SHARE_LINK_CREATED = "SHARE_LINK_CREATED", "Share link created"
    SHARE_LINK_ACCESSED = "SHARE_LINK_ACCESSED", "Share link accessed"
    SHARE_LINK_DOWNLOAD = "SHARE_LINK_DOWNLOAD", "Share link download"
    SHARE_LINK_MODIFIED = "SHARE_LINK_MODIFIED", "Share link modified"
    SHARE_LINK_EXPIRED = "SHARE_LINK_EXPIRED", "Share link expired"
    SHARE_LINK_REVOKED = "SHARE_LINK_REVOKED", "Share link revoked"
    SHARE_LINK_PASSWORD_FAILURE = (
        "SHARE_LINK_PASSWORD_FAILURE",
        "Share link password failure",
    )
    SHARE_LINK_LOCKED = "SHARE_LINK_LOCKED", "Share link locked after failed attempts"
    SHARE_LINK_INVALID_TOKEN = "SHARE_LINK_INVALID_TOKEN", "Invalid share token used"
    DOWNLOAD_LIMIT_REACHED = "DOWNLOAD_LIMIT_REACHED", "Download limit reached"

    # --- platform ------------------------------------------------------------
    UNAUTHORIZED_ACCESS_ATTEMPT = (
        "UNAUTHORIZED_ACCESS_ATTEMPT",
        "Unauthorized access attempt",
    )
    RATE_LIMIT_TRIGGERED = "RATE_LIMIT_TRIGGERED", "Rate limit triggered"
    ADMIN_ACTION = "ADMIN_ACTION", "Administrative action"
    SYSTEM_MAINTENANCE = "SYSTEM_MAINTENANCE", "System maintenance task"


class AuditSeverity(models.TextChoices):
    INFO = "INFO", "Informational"
    WARNING = "WARNING", "Warning"
    CRITICAL = "CRITICAL", "Critical"


#: Actions that are always security-relevant (mirrored to the security log).
SECURITY_ACTIONS = frozenset(
    {
        AuditAction.LOGIN_FAILURE,
        AuditAction.ACCOUNT_LOCKED,
        AuditAction.ACCOUNT_DISABLED,
        AuditAction.UNAUTHORIZED_ACCESS_ATTEMPT,
        AuditAction.UNAUTHORIZED_FILE_ACCESS,
        AuditAction.UNAUTHORIZED_SHARE_ACCESS,
        AuditAction.RATE_LIMIT_TRIGGERED,
        AuditAction.MALWARE_DETECTED,
        AuditAction.FILE_INTEGRITY_FAILURE,
        AuditAction.SHARE_LINK_PASSWORD_FAILURE,
        AuditAction.SHARE_LINK_LOCKED,
        AuditAction.SHARE_LINK_INVALID_TOKEN,
        AuditAction.DOWNLOAD_LIMIT_REACHED,
    }
)

DEFAULT_SEVERITY = {
    **dict.fromkeys(AuditAction, AuditSeverity.INFO),
    AuditAction.LOGIN_FAILURE: AuditSeverity.WARNING,
    AuditAction.ACCOUNT_LOCKED: AuditSeverity.CRITICAL,
    AuditAction.ACCOUNT_DISABLED: AuditSeverity.CRITICAL,
    AuditAction.UNAUTHORIZED_ACCESS_ATTEMPT: AuditSeverity.WARNING,
    AuditAction.UNAUTHORIZED_FILE_ACCESS: AuditSeverity.WARNING,
    AuditAction.UNAUTHORIZED_SHARE_ACCESS: AuditSeverity.WARNING,
    AuditAction.RATE_LIMIT_TRIGGERED: AuditSeverity.WARNING,
    AuditAction.MALWARE_DETECTED: AuditSeverity.CRITICAL,
    AuditAction.FILE_INTEGRITY_FAILURE: AuditSeverity.CRITICAL,
    AuditAction.SHARE_LINK_PASSWORD_FAILURE: AuditSeverity.WARNING,
    AuditAction.SHARE_LINK_LOCKED: AuditSeverity.CRITICAL,
    AuditAction.SHARE_LINK_INVALID_TOKEN: AuditSeverity.WARNING,
    AuditAction.DOWNLOAD_LIMIT_REACHED: AuditSeverity.WARNING,
}
