"""Deeper coverage of the upload validation pipeline and storage maintenance."""
from __future__ import annotations

import io
import zipfile
from datetime import timedelta

import pytest
from django.utils import timezone

from files.exceptions import FileTooLarge, MalformedUpload, UnsupportedFileType
from files.validators import (
    detect_mime_type,
    get_extension,
    split_extensions,
    validate_content_type,
    validate_extension,
    validate_size,
)
from tests.conftest import PNG_1X1, build_pdf

pytestmark = pytest.mark.django_db


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Extension handling
# ---------------------------------------------------------------------------
def test_extension_helpers():
    assert get_extension("report.PDF") == "pdf"
    assert split_extensions("archive.tar.gz") == ["tar", "gz"]
    assert validate_extension("notes.txt") == "txt"


@pytest.mark.parametrize(
    "filename", ["evil.exe", "script.sh", "lib.so", "page.html", "macro.docm", "noext"]
)
def test_disallowed_extensions_are_rejected(filename):
    with pytest.raises(UnsupportedFileType):
        validate_extension(filename)


@pytest.mark.parametrize("filename", ["invoice.pdf.exe", "photo.png.js", "a.pdf.zip.sh"])
def test_double_extensions_are_rejected(filename):
    with pytest.raises(UnsupportedFileType):
        validate_extension(filename)


# ---------------------------------------------------------------------------
# Content sniffing
# ---------------------------------------------------------------------------
def test_pdf_is_detected_from_its_signature():
    assert detect_mime_type(io.BytesIO(build_pdf()), "pdf") == "application/pdf"


def test_png_is_detected_from_its_signature():
    assert detect_mime_type(io.BytesIO(PNG_1X1), "png") == "image/png"


def test_plain_text_is_detected():
    assert detect_mime_type(io.BytesIO(b"just some text\n"), "txt") == "text/plain"


def test_csv_is_detected_by_extension_hint():
    assert detect_mime_type(io.BytesIO(b"a,b,c\n1,2,3\n"), "csv") == "text/csv"


def test_empty_upload_is_rejected_by_the_sniffer():
    with pytest.raises(MalformedUpload):
        detect_mime_type(io.BytesIO(b""), "txt")


def test_plain_zip_is_detected():
    payload = make_zip({"readme.txt": b"hello"})
    assert detect_mime_type(io.BytesIO(payload), "zip") == "application/zip"


def test_docx_is_distinguished_from_a_plain_zip():
    payload = make_zip(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<document/>",
        }
    )
    detected = detect_mime_type(io.BytesIO(payload), "docx")
    assert "wordprocessingml" in detected


def test_zip_bomb_ratio_is_rejected():
    """A highly compressible archive is refused rather than decompressed."""
    payload = make_zip({"bomb.txt": b"0" * 5_000_000})
    with pytest.raises(MalformedUpload):
        detect_mime_type(io.BytesIO(payload), "zip")


def test_archive_with_too_many_entries_is_rejected():
    from files.validators import MAX_ZIP_ENTRIES

    payload = make_zip(
        {f"f{index}.txt": b"x" for index in range(MAX_ZIP_ENTRIES + 10)}
    )
    with pytest.raises(MalformedUpload):
        detect_mime_type(io.BytesIO(payload), "zip")


def test_corrupt_archive_is_rejected():
    with pytest.raises(MalformedUpload):
        detect_mime_type(io.BytesIO(b"PK\x03\x04corrupted-not-a-zip"), "zip")


# ---------------------------------------------------------------------------
# Content-type / extension agreement
# ---------------------------------------------------------------------------
def test_content_type_must_match_the_extension():
    validate_content_type("application/pdf", "pdf")
    with pytest.raises(UnsupportedFileType):
        validate_content_type("image/png", "pdf")


def test_disallowed_content_type_is_rejected():
    with pytest.raises(UnsupportedFileType):
        validate_content_type("application/x-dosexec", "pdf")


# ---------------------------------------------------------------------------
# Size
# ---------------------------------------------------------------------------
def test_size_validation(settings):
    settings.MAX_UPLOAD_SIZE = 1000
    assert validate_size(999) == 999
    with pytest.raises(MalformedUpload):
        validate_size(0)
    with pytest.raises(MalformedUpload):
        validate_size(None)
    with pytest.raises(FileTooLarge):
        validate_size(1001)


# ---------------------------------------------------------------------------
# Storage maintenance task
# ---------------------------------------------------------------------------
def test_purge_task_removes_orphaned_ciphertext(client_a, file_a):
    from files.models import File, FileStatus
    from files.tasks import purge_deleted_objects
    from security.storage import get_storage

    storage = get_storage()
    object_id = file_a.stored_object_id
    assert storage.exists(object_id)

    # Simulate a delete whose storage step failed: row marked deleted, object left.
    File.objects.filter(pk=file_a.pk).update(
        status=FileStatus.DELETED,
        deleted_at=timezone.now() - timedelta(hours=2),
    )

    assert purge_deleted_objects(older_than_minutes=60) == 1
    assert not storage.exists(object_id)
    # Idempotent: a second run finds nothing left to do.
    assert purge_deleted_objects(older_than_minutes=60) == 0


def test_purge_task_keeps_recently_deleted_objects(client_a, file_a):
    from files.models import File, FileStatus
    from files.tasks import purge_deleted_objects
    from security.storage import get_storage

    File.objects.filter(pk=file_a.pk).update(
        status=FileStatus.DELETED, deleted_at=timezone.now()
    )
    assert purge_deleted_objects(older_than_minutes=60) == 0
    assert get_storage().exists(file_a.stored_object_id)
