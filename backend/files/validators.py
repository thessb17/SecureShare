"""Upload validation: filenames, size, extensions, MIME and magic bytes.

Nothing the client says is trusted: the filename is sanitised, the declared
``Content-Type`` is recorded but ignored for decisions, and the real type is
detected from the file's own bytes.
"""
from __future__ import annotations

import logging
import re
import unicodedata
import zipfile
from dataclasses import dataclass
from typing import Any, BinaryIO, Final

from django.conf import settings

from files.exceptions import (
    FileTooLarge,
    InvalidFilename,
    MalformedUpload,
    UnsupportedFileType,
)

logger = logging.getLogger("secureshare.security")

MAX_FILENAME_LENGTH: Final[int] = 255
SNIFF_SIZE: Final[int] = 8192

#: Bidirectional/format control characters used for filename spoofing
#: (e.g. "invoice\u202Egnp.exe" renders as "invoice exe.png").
DANGEROUS_UNICODE: Final[frozenset[str]] = frozenset(
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u200b\ufeff"
)

WINDOWS_RESERVED: Final[frozenset[str]] = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

FILENAME_SAFE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._ ()\-\[\]&+,']")

#: Magic byte signatures. Keys are canonical extensions.
SIGNATURES: Final[dict[str, tuple[bytes, ...]]] = {
    "pdf": (b"%PDF-",),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
    "zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    "docx": (b"PK\x03\x04",),
    "xlsx": (b"PK\x03\x04",),
    "pptx": (b"PK\x03\x04",),
    "gif": (b"GIF87a", b"GIF89a"),
}

EXTENSION_MIME_MAP: Final[dict[str, tuple[str, ...]]] = {
    "pdf": ("application/pdf",),
    "png": ("image/png",),
    "jpg": ("image/jpeg",),
    "jpeg": ("image/jpeg",),
    "txt": ("text/plain",),
    "csv": ("text/csv", "text/plain"),
    "zip": ("application/zip", "application/x-zip-compressed"),
    "docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",),
    "pptx": (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
}

OOXML_MARKERS: Final[dict[str, str]] = {
    "docx": "word/",
    "xlsx": "xl/",
    "pptx": "ppt/",
}

#: Zip bomb heuristic: reject archives whose declared uncompressed size is more
#: than this multiple of the compressed upload.
MAX_ZIP_EXPANSION_RATIO: Final[int] = 100
MAX_ZIP_ENTRIES: Final[int] = 5000


@dataclass(frozen=True)
class ValidatedUpload:
    filename: str
    extension: str
    detected_mime: str
    declared_mime: str
    size: int


# ---------------------------------------------------------------------------
# Filename handling
# ---------------------------------------------------------------------------
def sanitize_filename(raw_name: str | None) -> str:
    """Return a safe display filename or raise :class:`InvalidFilename`.

    Rejects: path traversal, absolute paths, null bytes, control characters,
    bidi/format spoofing characters, reserved device names, and names that are
    empty after sanitisation. The result is **never** used as a storage path.
    """
    if raw_name is None:
        raise InvalidFilename("A filename is required.")

    name = str(raw_name)
    if "\x00" in name:
        raise InvalidFilename("The filename contains a null byte.")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise InvalidFilename("The filename contains control characters.")
    if any(char in DANGEROUS_UNICODE for char in name):
        raise InvalidFilename("The filename contains disallowed Unicode characters.")

    name = unicodedata.normalize("NFKC", name)

    # Strip any directory component the client may have sent, for both
    # POSIX and Windows separators, then reject traversal leftovers.
    if "/" in name or "\\" in name:
        name = re.split(r"[\\/]", name)[-1]
    if name in {"", ".", ".."} or name.strip() in {"", ".", ".."}:
        raise InvalidFilename("The filename is not valid.")
    if name.startswith("~") or ":" in name:
        raise InvalidFilename("The filename is not valid.")

    name = name.strip().strip(".")
    if not name:
        raise InvalidFilename("The filename is not valid.")

    stem = name.split(".")[0].lower()
    if stem in WINDOWS_RESERVED:
        raise InvalidFilename("The filename uses a reserved device name.")

    # Replace anything outside a conservative safe set.
    cleaned = FILENAME_SAFE_RE.sub("_", name)
    cleaned = re.sub(r"_{3,}", "__", cleaned).strip()
    if not cleaned or cleaned in {".", ".."}:
        raise InvalidFilename("The filename is not valid.")

    if len(cleaned) > MAX_FILENAME_LENGTH:
        head, _, tail = cleaned.rpartition(".")
        suffix = f".{tail}" if head else ""
        cleaned = (head or cleaned)[: MAX_FILENAME_LENGTH - len(suffix)] + suffix
    return cleaned


def split_extensions(filename: str) -> list[str]:
    parts = [part for part in filename.lower().split(".")[1:] if part]
    return parts


def get_extension(filename: str) -> str:
    parts = split_extensions(filename)
    return parts[-1] if parts else ""


def validate_extension(filename: str) -> str:
    allowed = {ext.lower() for ext in settings.ALLOWED_UPLOAD_EXTENSIONS}
    blocked = {ext.lower() for ext in settings.BLOCKED_UPLOAD_EXTENSIONS}
    extensions = split_extensions(filename)

    if not extensions:
        raise UnsupportedFileType("The file must have an extension.")

    final = extensions[-1]
    # Double extension abuse: report.pdf.exe, invoice.png.php, archive.zip.js
    for inner in extensions[:-1]:
        if inner in blocked:
            raise UnsupportedFileType(
                "Filenames containing executable extensions are not allowed."
            )
    if final in blocked:
        raise UnsupportedFileType("This file type is not allowed.")
    if final not in allowed:
        raise UnsupportedFileType(
            f"Files of type '.{final}' are not allowed. Allowed types: "
            + ", ".join(sorted(allowed))
        )
    return final


# ---------------------------------------------------------------------------
# Content inspection
# ---------------------------------------------------------------------------
def _read_head(stream: BinaryIO, size: int = SNIFF_SIZE) -> bytes:
    stream.seek(0)
    head = stream.read(size)
    stream.seek(0)
    return head


def _looks_like_text(head: bytes) -> bool:
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        try:
            head.decode("latin-1")
        except UnicodeDecodeError:
            return False
    return True


def _detect_ooxml_subtype(stream: BinaryIO) -> str | None:
    """Distinguish docx/xlsx/pptx/zip by inspecting the archive content."""
    stream.seek(0)
    try:
        with zipfile.ZipFile(stream) as archive:
            names = archive.namelist()
            if len(names) > MAX_ZIP_ENTRIES:
                raise MalformedUpload("The archive contains too many entries.")
            total_uncompressed = sum(info.file_size for info in archive.infolist())
            compressed = sum(info.compress_size for info in archive.infolist()) or 1
            if total_uncompressed // compressed > MAX_ZIP_EXPANSION_RATIO:
                raise MalformedUpload(
                    "The archive has a suspicious compression ratio and was rejected."
                )
            if "[Content_Types].xml" in names:
                for subtype, marker in OOXML_MARKERS.items():
                    if any(name.startswith(marker) for name in names):
                        return subtype
            return "zip"
    except zipfile.BadZipFile:
        return None
    finally:
        stream.seek(0)


def detect_mime_type(stream: BinaryIO, extension: str) -> str:
    """Determine the MIME type from the bytes themselves.

    Uses libmagic when available and falls back to an explicit signature table,
    so detection works in minimal containers too.
    """
    head = _read_head(stream)
    if not head:
        raise MalformedUpload("The uploaded file is empty.")

    detected: str | None = None
    try:
        import magic  # type: ignore[import-untyped]

        detected = magic.from_buffer(head, mime=True)
    except Exception:
        detected = None

    is_zip = head.startswith(b"PK\x03\x04")
    if is_zip:
        subtype = _detect_ooxml_subtype(stream)
        if subtype in OOXML_MARKERS:
            return EXTENSION_MIME_MAP[subtype][0]
        if subtype == "zip":
            return "application/zip"
        raise MalformedUpload("The archive could not be parsed.")

    for ext, signatures in SIGNATURES.items():
        if any(head.startswith(sig) for sig in signatures):
            mapped = EXTENSION_MIME_MAP.get(ext)
            if mapped:
                return mapped[0]

    if detected and detected not in {"application/octet-stream", "text/plain"}:
        return detected

    if _looks_like_text(head):
        return "text/csv" if extension == "csv" else "text/plain"

    return detected or "application/octet-stream"


def validate_content_type(detected_mime: str, extension: str) -> None:
    allowed_mimes = {mime.lower() for mime in settings.ALLOWED_UPLOAD_MIME_TYPES}
    if detected_mime.lower() not in allowed_mimes:
        raise UnsupportedFileType(
            "The detected content type of this file is not allowed."
        )
    expected = EXTENSION_MIME_MAP.get(extension)
    if expected and detected_mime.lower() not in {mime.lower() for mime in expected}:
        raise UnsupportedFileType(
            "The file content does not match its extension."
        )


def validate_size(size: int | None) -> int:
    max_size = int(settings.MAX_UPLOAD_SIZE)
    if size is None:
        raise MalformedUpload("The upload size could not be determined.")
    if size <= 0:
        raise MalformedUpload("The uploaded file is empty.")
    if size > max_size:
        raise FileTooLarge(
            f"The file exceeds the maximum upload size of {max_size} bytes."
        )
    return int(size)


def validate_upload(uploaded_file: Any) -> ValidatedUpload:
    """Run the full validation pipeline and return normalised metadata."""
    if uploaded_file is None:
        raise MalformedUpload("No file was submitted.")

    size = validate_size(getattr(uploaded_file, "size", None))
    filename = sanitize_filename(getattr(uploaded_file, "name", None))
    extension = validate_extension(filename)

    declared = (getattr(uploaded_file, "content_type", "") or "")[:127]
    detected = detect_mime_type(uploaded_file, extension)
    validate_content_type(detected, extension)

    return ValidatedUpload(
        filename=filename,
        extension=extension,
        detected_mime=detected,
        declared_mime=declared,
        size=size,
    )
