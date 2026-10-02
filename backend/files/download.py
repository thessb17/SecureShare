"""Shared helper that turns a decrypted file into a safe HTTP response.

Used by the authenticated download endpoint (Phase 4) and by the public
share-link download endpoint (Phase 6).
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from django.conf import settings
from django.http import HttpResponse, StreamingHttpResponse

from files.models import File
from files.services import FileService

_HEADER_UNSAFE = re.compile(r'[\r\n"\\]')


def content_disposition(filename: str) -> str:
    """RFC 6266/5987 attachment header, safe against header injection."""
    cleaned = _HEADER_UNSAFE.sub("", filename).strip() or "download"
    ascii_fallback = cleaned.encode("ascii", "ignore").decode("ascii") or "download"
    return (
        f'attachment; filename="{ascii_fallback}"; '
        f"filename*=UTF-8''{quote(cleaned, safe='')}"
    )


def build_download_response(
    *,
    file_obj: File,
    service: FileService,
    request: Any = None,
) -> HttpResponse | StreamingHttpResponse:
    """Decrypt and return the file as an attachment.

    Files up to ``DOWNLOAD_BUFFER_THRESHOLD`` are decrypted fully first so an
    integrity failure can still be reported as a clean JSON error. Larger files
    are streamed chunk-by-chunk (bounded memory); a tamper detection mid-stream
    aborts the transfer instead of delivering corrupted bytes.
    """
    threshold = int(getattr(settings, "DOWNLOAD_BUFFER_THRESHOLD", 8_388_608))

    if file_obj.file_size <= threshold:
        payload = service.read_plaintext(file_obj, request=request)
        response: HttpResponse | StreamingHttpResponse = HttpResponse(
            payload.content, content_type=payload.mime_type
        )
        response["Content-Length"] = str(payload.size)
    else:
        response = StreamingHttpResponse(
            service.iter_plaintext(file_obj), content_type=file_obj.mime_type
        )
        response["Content-Length"] = str(file_obj.file_size)

    response["Content-Disposition"] = content_disposition(file_obj.original_filename)
    response["X-Content-Type-Options"] = "nosniff"
    response["Cache-Control"] = "no-store, private"
    response["X-SecureShare-Encryption"] = "AES-256-GCM"
    return response
