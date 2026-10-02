from __future__ import annotations

from core.throttling import UserScopedThrottle


class FileUploadThrottle(UserScopedThrottle):
    scope = "files.upload"


class FileDownloadThrottle(UserScopedThrottle):
    scope = "files.download"
