"""Sharing domain API errors.

Status code policy for public links: a caller can only reach these states by
already possessing a 256-bit token, so distinguishing EXPIRED / REVOKED /
LIMIT_REACHED leaks nothing while being far more useful than a blanket 404.
An unknown token always returns 404 with the same body, so tokens cannot be
probed for existence.
"""
from __future__ import annotations

from rest_framework import status

from core.exceptions import APIError


# --- user-to-user shares ---------------------------------------------------
class ShareNotFound(APIError):
    status_code = status.HTTP_404_NOT_FOUND
    error_code = "SHARE_NOT_FOUND"
    default_detail = "The requested share could not be found."


class ShareAccessDenied(APIError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "ACCESS_DENIED"
    default_detail = "You do not have permission to manage this share."


class InvalidRecipient(APIError):
    status_code = status.HTTP_400_BAD_REQUEST
    error_code = "INVALID_RECIPIENT"
    default_detail = "The recipient is not a valid SecureShare account."


class ShareAlreadyExists(APIError):
    status_code = status.HTTP_409_CONFLICT
    error_code = "SHARE_ALREADY_EXISTS"
    default_detail = "This file is already shared with that recipient."


# --- public share links ----------------------------------------------------
class ShareLinkNotFound(APIError):
    status_code = status.HTTP_404_NOT_FOUND
    error_code = "SHARE_LINK_NOT_FOUND"
    default_detail = "This share link is not valid."


class ShareLinkExpired(APIError):
    status_code = status.HTTP_410_GONE
    error_code = "SHARE_LINK_EXPIRED"
    default_detail = "This share link has expired."


class ShareLinkRevoked(APIError):
    status_code = status.HTTP_410_GONE
    error_code = "SHARE_LINK_REVOKED"
    default_detail = "This share link has been revoked."


class ShareLinkDownloadLimitReached(APIError):
    status_code = status.HTTP_410_GONE
    error_code = "SHARE_LINK_DOWNLOAD_LIMIT_REACHED"
    default_detail = "The download limit for this share link has been reached."


class SharePasswordRequired(APIError):
    status_code = status.HTTP_401_UNAUTHORIZED
    error_code = "SHARE_LINK_PASSWORD_REQUIRED"
    default_detail = "This share link is password protected."


class SharePasswordInvalid(APIError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "SHARE_LINK_PASSWORD_INVALID"
    default_detail = "The supplied password is incorrect."


class ShareLinkLocked(APIError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    error_code = "SHARE_LINK_LOCKED"
    default_detail = (
        "Too many incorrect password attempts. This link is temporarily locked."
    )


class SharePermissionDenied(APIError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "SHARE_PERMISSION_DENIED"
    default_detail = "This share link does not allow downloading."
