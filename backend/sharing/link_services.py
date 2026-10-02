"""Public share-link service (Phase 6).

Security model
--------------
* **Token**: 256 bits from :func:`secrets.token_urlsafe` (``SHARE_LINK_TOKEN_BYTES``
  = 32). The raw value is returned exactly once, at creation; the database only
  stores ``sha256(token)``. A fast hash is the right primitive here because the
  token already has full entropy - there is no dictionary to search - while
  Argon2id is used for the *user chosen* link password.
* **Lookup** is an indexed equality match on the digest, so an attacker cannot
  learn anything from timing, and unknown tokens are indistinguishable from
  malformed ones (both 404 with an identical body).
* **Expiry / download limits / revocation** are enforced server-side on every
  request. The download counter is incremented with a single conditional SQL
  UPDATE, which makes concurrent "last download" races impossible.
* **Password attempts** are rate limited per (link, IP) and per link, and the
  raw token is never written to a log or an audit record.
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
from typing import Any, Final

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core import signing
from django.core.cache import cache
from django.db.models import F, Q
from django.utils import timezone

from audit.constants import AuditAction
from audit.services import record_event
from core.request_meta import get_client_ip
from files.models import File
from sharing.exceptions import (
    ShareAccessDenied,
    ShareLinkDownloadLimitReached,
    ShareLinkExpired,
    ShareLinkLocked,
    ShareLinkNotFound,
    ShareLinkRevoked,
    SharePasswordInvalid,
    SharePasswordRequired,
)
from sharing.models import ShareLink, SharePermission

logger = logging.getLogger("secureshare")
security_logger = logging.getLogger("secureshare.security")

#: base64url alphabet; 32 bytes -> 43 chars. Accept a sane range.
TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{32,128}$")

EXPIRY_PRESETS: Final[dict[str, int]] = {
    "1h": 3600,
    "6h": 21600,
    "24h": 86400,
    "3d": 259200,
    "7d": 604800,
}

GRANT_SALT: Final[str] = "secureshare.share-link-grant.v1"


def generate_token() -> str:
    """256-bit URL-safe token from the OS CSPRNG."""
    return secrets.token_urlsafe(int(settings.SHARE_LINK_TOKEN_BYTES))


def hash_token(raw_token: str) -> str:
    """SHA-256 hex digest of a share token (never reversible to the token)."""
    return hashlib.sha256((raw_token or "").encode("utf-8")).hexdigest()


class ShareLinkService:
    """Create, resolve, protect and revoke public share links."""

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------
    @staticmethod
    def build_share_url(raw_token: str) -> str:
        base = settings.PUBLIC_SHARE_BASE_URL.rstrip("/")
        return f"{base}/share/{raw_token}"

    @classmethod
    def create(
        cls,
        *,
        file_obj: File,
        creator: Any,
        permission: str = SharePermission.DOWNLOAD,
        expires_at: Any = None,
        max_downloads: int | None = None,
        password: str | None = None,
        request: Any = None,
    ) -> tuple[ShareLink, str]:
        """Create a link. Returns ``(link, raw_token)``; the token is shown once."""
        if file_obj.owner_id != creator.pk:
            record_event(
                action=AuditAction.UNAUTHORIZED_SHARE_ACCESS,
                request=request,
                user=creator,
                success=False,
                message="Share link creation denied: requester is not the owner.",
                object_type="file",
                object_id=file_obj.id,
                object_owner=file_obj.owner,
            )
            raise ShareAccessDenied("Only the file owner can create a share link.")

        raw_token = generate_token()
        digest = hash_token(raw_token)

        link = ShareLink.objects.create(
            file=file_obj,
            created_by=creator,
            token_hash=digest,
            token_prefix=digest[:12],
            permission=permission,
            expires_at=expires_at,
            max_downloads=max_downloads,
            password_hash=make_password(password) if password else "",
        )

        record_event(
            action=AuditAction.SHARE_LINK_CREATED,
            request=request,
            user=creator,
            message="Public share link created.",
            object_type="share_link",
            object_id=link.id,
            object_owner=file_obj.owner,
            metadata={
                "file_id": str(file_obj.id),
                "filename": file_obj.original_filename,
                "permission": permission,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "max_downloads": max_downloads,
                "password_protected": bool(password),
                # Non-secret handle: a prefix of the SHA-256 digest, not the token.
                "token_prefix": link.token_prefix,
            },
        )
        return link, raw_token

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------
    @classmethod
    def resolve(cls, raw_token: str, *, request: Any = None) -> ShareLink:
        """Validate a token and return the usable link, or raise."""
        token = (raw_token or "").strip()
        if not TOKEN_RE.match(token):
            cls._audit_invalid_token(token, request, reason="malformed")
            raise ShareLinkNotFound()

        digest = hash_token(token)
        link = (
            ShareLink.objects.select_related("file", "file__owner", "created_by")
            .filter(token_hash=digest)
            .first()
        )
        if link is None:
            cls._audit_invalid_token(token, request, reason="unknown")
            raise ShareLinkNotFound()

        if link.file.is_deleted:
            record_event(
                action=AuditAction.SHARE_LINK_ACCESSED,
                request=request,
                success=False,
                message="Share link access failed: the file was deleted.",
                object_type="share_link",
                object_id=link.id,
                object_owner=link.file.owner,
                metadata={"token_prefix": link.token_prefix, "reason": "file_deleted"},
            )
            raise ShareLinkNotFound()

        if link.is_revoked:
            cls._audit_state(link, request, AuditAction.SHARE_LINK_REVOKED,
                             "Share link access denied: revoked.")
            raise ShareLinkRevoked()

        if link.is_expired:
            cls._audit_state(link, request, AuditAction.SHARE_LINK_EXPIRED,
                             "Share link access denied: expired.")
            raise ShareLinkExpired()

        if link.is_exhausted:
            cls._audit_state(link, request, AuditAction.DOWNLOAD_LIMIT_REACHED,
                             "Share link access denied: download limit reached.")
            raise ShareLinkDownloadLimitReached()

        return link

    @staticmethod
    def _audit_invalid_token(token: str, request: Any, *, reason: str) -> None:
        # Only a prefix of the *hash* of the attempted token is recorded.
        record_event(
            action=AuditAction.SHARE_LINK_INVALID_TOKEN,
            request=request,
            success=False,
            message="Invalid share token presented.",
            object_type="share_link",
            metadata={
                "reason": reason,
                "attempted_token_hash_prefix": hash_token(token)[:12] if token else "",
                "token_length": len(token or ""),
            },
        )

    @staticmethod
    def _audit_state(link: ShareLink, request: Any, action: str, message: str) -> None:
        record_event(
            action=action,
            request=request,
            success=False,
            message=message,
            object_type="share_link",
            object_id=link.id,
            object_owner=link.file.owner,
            metadata={
                "token_prefix": link.token_prefix,
                "file_id": str(link.file_id),
                "status": link.status,
                "download_count": link.download_count,
                "max_downloads": link.max_downloads,
            },
        )

    # ------------------------------------------------------------------
    # Password protection
    # ------------------------------------------------------------------
    @staticmethod
    def _failure_keys(link: ShareLink, request: Any) -> tuple[str, str]:
        ip = get_client_ip(request) or "unknown"
        return (
            f"sharelink:pwfail:{link.id}:{ip}",
            f"sharelink:pwfail:{link.id}:global",
        )

    @classmethod
    def is_locked(cls, link: ShareLink, request: Any) -> bool:
        per_ip_key, global_key = cls._failure_keys(link, request)
        limit = int(settings.SHARE_LINK_PASSWORD_MAX_ATTEMPTS)
        per_ip = int(cache.get(per_ip_key) or 0)
        global_count = int(cache.get(global_key) or 0)
        # The global budget absorbs distributed guessing from many IPs.
        return per_ip >= limit or global_count >= limit * 5

    @classmethod
    def _register_failure(cls, link: ShareLink, request: Any) -> int:
        timeout = int(settings.SHARE_LINK_PASSWORD_LOCKOUT_SECONDS)
        counts = []
        for key in cls._failure_keys(link, request):
            try:
                counts.append(cache.incr(key))
            except ValueError:
                cache.set(key, 1, timeout)
                counts.append(1)
        return counts[0]

    @classmethod
    def _clear_failures(cls, link: ShareLink, request: Any) -> None:
        for key in cls._failure_keys(link, request):
            cache.delete(key)

    @classmethod
    def issue_grant(cls, link: ShareLink) -> str:
        """Short-lived proof that the password was verified for this link."""
        return signing.dumps(
            {"link": str(link.id), "tp": link.token_prefix}, salt=GRANT_SALT
        )

    @classmethod
    def verify_grant(cls, link: ShareLink, grant: str | None) -> bool:
        if not grant:
            return False
        try:
            payload = signing.loads(
                grant,
                salt=GRANT_SALT,
                max_age=int(settings.SHARE_LINK_GRANT_TTL_SECONDS),
            )
        except signing.BadSignature:
            return False
        return payload.get("link") == str(link.id) and payload.get("tp") == link.token_prefix

    @classmethod
    def password_satisfied(
        cls,
        link: ShareLink,
        *,
        password: str | None,
        grant: str | None,
        request: Any = None,
    ) -> bool:
        """Non-raising check used by the metadata endpoint."""
        if not link.requires_password:
            return True
        if cls.verify_grant(link, grant):
            return True
        if not password:
            return False
        if cls.is_locked(link, request):
            return False
        return check_password(password, link.password_hash)

    @classmethod
    def authorize(
        cls,
        link: ShareLink,
        *,
        password: str | None,
        grant: str | None,
        request: Any = None,
    ) -> None:
        """Enforce password protection, with lockout and auditing."""
        if not link.requires_password:
            return

        if cls.verify_grant(link, grant):
            return

        if cls.is_locked(link, request):
            record_event(
                action=AuditAction.SHARE_LINK_LOCKED,
                request=request,
                success=False,
                message="Share link temporarily locked after repeated failures.",
                object_type="share_link",
                object_id=link.id,
                object_owner=link.file.owner,
                metadata={"token_prefix": link.token_prefix},
            )
            raise ShareLinkLocked()

        if not password:
            raise SharePasswordRequired()

        if check_password(password, link.password_hash):
            cls._clear_failures(link, request)
            return

        failures = cls._register_failure(link, request)
        record_event(
            action=AuditAction.SHARE_LINK_PASSWORD_FAILURE,
            request=request,
            success=False,
            message="Incorrect share link password.",
            object_type="share_link",
            object_id=link.id,
            object_owner=link.file.owner,
            metadata={"token_prefix": link.token_prefix, "failed_attempts": failures},
        )
        if failures >= int(settings.SHARE_LINK_PASSWORD_MAX_ATTEMPTS):
            record_event(
                action=AuditAction.SHARE_LINK_LOCKED,
                request=request,
                success=False,
                message="Share link locked after repeated password failures.",
                object_type="share_link",
                object_id=link.id,
                object_owner=link.file.owner,
                metadata={"token_prefix": link.token_prefix, "failed_attempts": failures},
            )
            raise ShareLinkLocked()
        raise SharePasswordInvalid()

    # ------------------------------------------------------------------
    # Download accounting (race-free)
    # ------------------------------------------------------------------
    @staticmethod
    def claim_download_slot(link: ShareLink) -> bool:
        """Atomically reserve one download.

        The whole decision is a single ``UPDATE ... WHERE`` statement, so two
        concurrent requests on a link with ``max_downloads=1`` can never both
        succeed: PostgreSQL re-evaluates the predicate against the
        freshly-committed row, and the loser matches zero rows.
        """
        now = timezone.now()
        updated = (
            ShareLink.objects.filter(pk=link.pk, revoked_at__isnull=True)
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
            .filter(
                Q(max_downloads__isnull=True) | Q(download_count__lt=F("max_downloads"))
            )
            .update(
                download_count=F("download_count") + 1,
                last_downloaded_at=now,
                updated_at=now,
            )
        )
        return updated == 1

    @staticmethod
    def release_download_slot(link: ShareLink) -> None:
        """Give a reserved slot back when the transfer could not be produced."""
        ShareLink.objects.filter(pk=link.pk, download_count__gt=0).update(
            download_count=F("download_count") - 1, updated_at=timezone.now()
        )

    # ------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------
    @staticmethod
    def assert_can_manage(link: ShareLink, actor: Any, *, request: Any = None) -> None:
        if link.created_by_id == actor.pk or getattr(actor, "is_admin", False):
            return
        record_event(
            action=AuditAction.UNAUTHORIZED_SHARE_ACCESS,
            request=request,
            user=actor,
            success=False,
            message="Share link management denied.",
            object_type="share_link",
            object_id=link.id,
            object_owner=link.file.owner,
            metadata={"reason": "not_link_owner", "token_prefix": link.token_prefix},
        )
        raise ShareAccessDenied("You do not have permission to manage this share link.")

    @classmethod
    def update(
        cls,
        *,
        link: ShareLink,
        actor: Any,
        permission: str | None = None,
        expires_at: Any = ...,
        max_downloads: Any = ...,
        password: Any = ...,
        request: Any = None,
    ) -> ShareLink:
        cls.assert_can_manage(link, actor, request=request)
        changes: dict[str, Any] = {}
        fields: list[str] = []

        if permission is not None and permission != link.permission:
            changes["permission"] = {"from": link.permission, "to": permission}
            link.permission = permission
            fields.append("permission")

        if expires_at is not ... and expires_at != link.expires_at:
            changes["expires_at"] = {
                "from": link.expires_at.isoformat() if link.expires_at else None,
                "to": expires_at.isoformat() if expires_at else None,
            }
            link.expires_at = expires_at
            link.expiry_event_recorded = False
            fields.extend(["expires_at", "expiry_event_recorded"])

        if max_downloads is not ... and max_downloads != link.max_downloads:
            changes["max_downloads"] = {
                "from": link.max_downloads,
                "to": max_downloads,
            }
            link.max_downloads = max_downloads
            fields.append("max_downloads")

        if password is not ...:
            if password:
                link.password_hash = make_password(password)
                changes["password"] = "set"  # noqa: S105 - audit marker
            else:
                link.password_hash = ""
                changes["password"] = "removed"  # noqa: S105 - audit marker
            fields.append("password_hash")

        if fields:
            fields.append("updated_at")
            link.save(update_fields=sorted(set(fields)))
            record_event(
                action=AuditAction.SHARE_LINK_MODIFIED,
                request=request,
                user=actor,
                message="Share link updated.",
                object_type="share_link",
                object_id=link.id,
                object_owner=link.file.owner,
                metadata={
                    "token_prefix": link.token_prefix,
                    "file_id": str(link.file_id),
                    "changes": changes,
                },
            )
        return link

    @classmethod
    def revoke(cls, *, link: ShareLink, actor: Any, request: Any = None) -> ShareLink:
        cls.assert_can_manage(link, actor, request=request)
        already = link.is_revoked
        link.revoke()
        if not already:
            record_event(
                action=AuditAction.SHARE_LINK_REVOKED,
                request=request,
                user=actor,
                message="Share link revoked.",
                object_type="share_link",
                object_id=link.id,
                object_owner=link.file.owner,
                metadata={
                    "token_prefix": link.token_prefix,
                    "file_id": str(link.file_id),
                    "downloads_used": link.download_count,
                    "by_admin": bool(
                        getattr(actor, "is_admin", False)
                        and actor.pk != link.created_by_id
                    ),
                },
            )
        return link
