"""Phase 4: secure upload, encrypted storage, listing, download, deletion."""
from __future__ import annotations

import hashlib
import uuid

import pytest
from django.conf import settings

from audit.constants import AuditAction
from audit.models import AuditLog
from files.models import File, FileStatus
from security.exceptions import SecurityError
from security.storage import get_storage
from tests.conftest import EICAR_TEST_STRING, PNG_1X1, build_pdf, upload_file

pytestmark = pytest.mark.django_db

UPLOAD_URL = "/api/files/upload/"


def object_path(object_id: str):
    """Locate the ciphertext on disk (storage shards two levels deep)."""
    return get_storage()._path_for(object_id)


def do_upload(client, name="report.pdf", content=None, content_type="application/pdf"):
    payload = content if content is not None else build_pdf()
    return client.post(
        UPLOAD_URL, {"file": upload_file(name, payload, content_type)}, format="multipart"
    )


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------
def test_upload_requires_authentication(api_client):
    assert do_upload(api_client).status_code == 401


def test_upload_encrypts_and_persists_metadata(client_a, user_a, pdf_bytes):
    response = do_upload(client_a, content=pdf_bytes)
    assert response.status_code == 201, response.data

    body = response.data
    assert body["filename"] == "report.pdf"
    assert body["size"] == len(pdf_bytes)
    assert body["mime_type"] == "application/pdf"
    assert body["checksum_sha256"] == hashlib.sha256(pdf_bytes).hexdigest()
    assert body["encryption"]["encrypted"] is True
    assert body["encryption"]["algorithm"].startswith("AES-256-GCM")

    file_obj = File.objects.get(pk=body["id"])
    assert file_obj.owner == user_a
    assert file_obj.status == FileStatus.ACTIVE
    assert file_obj.encryption.wrapped_dek
    assert len(file_obj.encryption.nonce) == 36  # stream header with nonce prefix


def test_upload_response_never_leaks_storage_internals(client_a):
    body = do_upload(client_a).data
    serialized = str(body)
    assert "stored_object_id" not in body
    assert "wrapped_dek" not in serialized
    assert "nonce" not in serialized
    assert str(settings.ENCRYPTED_STORAGE_ROOT) not in serialized
    assert "/storage/" not in serialized


def test_stored_bytes_are_ciphertext_not_plaintext(client_a, pdf_bytes):
    body = do_upload(client_a, content=pdf_bytes).data
    file_obj = File.objects.get(pk=body["id"])
    with get_storage().open(file_obj.stored_object_id) as handle:
        raw = handle.read()
    assert raw[:6] == b"SSENC1"
    assert b"%PDF" not in raw
    assert b"SecureShare encrypted demo document" not in raw
    assert raw != pdf_bytes


def test_stored_object_id_is_random_and_unrelated_to_the_filename(client_a):
    first = File.objects.get(pk=do_upload(client_a, name="payroll.pdf").data["id"])
    second = File.objects.get(pk=do_upload(client_a, name="payroll.pdf").data["id"])
    assert first.stored_object_id != second.stored_object_id
    assert "payroll" not in first.stored_object_id
    assert str(first.id) not in first.stored_object_id
    assert len(first.stored_object_id) >= 32


def test_two_uploads_of_the_same_bytes_use_different_keys(client_a, pdf_bytes):
    first = File.objects.get(pk=do_upload(client_a, content=pdf_bytes).data["id"])
    second = File.objects.get(pk=do_upload(client_a, content=pdf_bytes).data["id"])
    assert first.encryption.wrapped_dek != second.encryption.wrapped_dek
    assert first.encryption.nonce != second.encryption.nonce
    assert first.checksum_sha256 == second.checksum_sha256  # same plaintext


def test_upload_records_an_audit_event(client_a):
    body = do_upload(client_a).data
    event = AuditLog.objects.filter(
        action=AuditAction.FILE_UPLOADED, object_id=str(body["id"])
    ).first()
    assert event is not None
    assert event.success is True
    assert "%PDF" not in str(event.metadata)


def test_upload_rejects_oversized_file(client_a, settings):
    settings.MAX_UPLOAD_SIZE = 1024
    response = do_upload(client_a, content=b"%PDF-1.4\n" + b"A" * 4096)
    assert response.status_code == 413
    assert response.data["error"] == "FILE_TOO_LARGE"
    assert File.objects.count() == 0


def test_upload_rejects_empty_file(client_a):
    response = do_upload(client_a, content=b"")
    assert response.status_code == 400
    assert File.objects.count() == 0


def test_upload_rejects_disallowed_extension(client_a):
    response = do_upload(client_a, name="evil.exe", content=b"MZ\x90\x00binary",
                         content_type="application/octet-stream")
    assert response.status_code == 415
    assert response.data["error"] == "UNSUPPORTED_FILE_TYPE"


def test_upload_rejects_double_extension_attack(client_a, pdf_bytes):
    response = do_upload(client_a, name="invoice.pdf.exe", content=pdf_bytes)
    assert response.status_code == 415


@pytest.mark.parametrize(
    "filename",
    [
        "file\x00.pdf",            # null byte
        "report\r\n.pdf",          # CR/LF header injection
        "con.pdf",                 # Windows device name
        "...",
        "\u202eexe.pdf",           # right-to-left override spoofing
        "",
        "..",
    ],
)
def test_filename_validator_rejects_dangerous_names(filename):
    from files.exceptions import InvalidFilename
    from files.validators import sanitize_filename

    with pytest.raises(InvalidFilename):
        sanitize_filename(filename)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("../../etc/passwd.pdf", "passwd.pdf"),
        ("..\\..\\windows\\system32\\evil.pdf", "evil.pdf"),
        ("/absolute/path/file.pdf", "file.pdf"),
    ],
)
def test_filename_validator_strips_directory_components(raw, expected):
    """Traversal is neutralised: only a bare basename survives."""
    from files.validators import sanitize_filename

    cleaned = sanitize_filename(raw)
    assert cleaned == expected
    assert "/" not in cleaned and "\\" not in cleaned and ".." not in cleaned


def test_sanitised_filename_cannot_escape_the_storage_root(client_a, pdf_bytes):
    """Even if a traversal name reached the API, no file lands outside storage."""
    response = do_upload(client_a, name="../../../../tmp/pwned.pdf", content=pdf_bytes)
    if response.status_code == 201:
        stored = File.objects.get(pk=response.data["id"])
        assert ".." not in stored.original_filename
        assert "/" not in stored.stored_object_id
        assert "\\" not in stored.stored_object_id
    else:
        assert response.status_code in (400, 415)


def test_upload_detects_content_type_spoofing_via_magic_bytes(client_a):
    """A PE binary renamed to .pdf with a PDF content-type must be rejected."""
    response = do_upload(
        client_a, name="malware.pdf", content=b"MZ\x90\x00\x03" + b"\x00" * 500
    )
    assert response.status_code == 415
    assert response.data["error"] == "UNSUPPORTED_FILE_TYPE"
    assert File.objects.count() == 0


def test_client_supplied_mime_type_is_not_trusted(client_a, pdf_bytes):
    """The client claims text/plain; the server detects application/pdf."""
    response = do_upload(client_a, name="report.pdf", content=pdf_bytes,
                         content_type="text/plain")
    assert response.status_code == 201
    assert response.data["mime_type"] == "application/pdf"
    stored = File.objects.get(pk=response.data["id"])
    assert stored.declared_mime_type == "text/plain"
    assert stored.mime_type == "application/pdf"


def test_filename_is_sanitised_but_preserved_for_display(client_a, pdf_bytes):
    response = do_upload(client_a, name="my report (final).pdf", content=pdf_bytes)
    assert response.status_code == 201
    assert response.data["filename"] == "my report (final).pdf"


def test_png_upload_is_accepted(client_a):
    response = do_upload(client_a, name="pixel.png", content=PNG_1X1,
                         content_type="image/png")
    assert response.status_code == 201
    assert response.data["mime_type"] == "image/png"


def test_eicar_is_rejected_when_the_scanner_is_enabled(client_a, settings, monkeypatch):
    """With a scanner enabled the EICAR sample is rejected, not stored.

    The ClamAV daemon is not available in CI, so the scanner transport is
    substituted - the upload pipeline, rejection path and audit trail under
    test are the real ones.
    """
    from files import services as files_services
    from security.scanning import ScanResult, ScanStatus

    settings.CLAMAV_ENABLED = True

    def fake_scan(stream):
        data = stream.read()
        stream.seek(0)
        if EICAR_TEST_STRING in data:
            return ScanResult(
                status=ScanStatus.INFECTED,
                scanned=True,
                signature="Eicar-Test-Signature",
            )
        return ScanResult(status=ScanStatus.CLEAN, scanned=True)

    monkeypatch.setattr(files_services, "scan_upload", fake_scan)
    response = do_upload(client_a, name="eicar.txt", content=EICAR_TEST_STRING,
                         content_type="text/plain")
    assert response.status_code == 422
    assert response.data["error"] == "MALWARE_DETECTED"
    assert File.objects.filter(status=FileStatus.ACTIVE).count() == 0
    assert AuditLog.objects.filter(action=AuditAction.MALWARE_DETECTED).exists()


def test_failed_upload_leaves_no_orphaned_ciphertext(client_a, isolated_storage, monkeypatch):
    """If persistence fails after the ciphertext is written, it is removed."""
    from files import models as files_models

    original_create = files_models.FileEncryptionMetadata.objects.create

    def boom(*args, **kwargs):
        raise RuntimeError("database exploded")

    monkeypatch.setattr(files_models.FileEncryptionMetadata.objects, "create", boom)
    response = do_upload(client_a)
    monkeypatch.setattr(files_models.FileEncryptionMetadata.objects, "create", original_create)

    assert response.status_code == 500
    assert b"Traceback" not in response.content
    assert b"database exploded" not in response.content

    leftovers = [p for p in isolated_storage.rglob("*") if p.is_file()]
    assert leftovers == [], f"orphaned ciphertext left behind: {leftovers}"
    assert File.objects.count() == 0


# ---------------------------------------------------------------------------
# Listing / detail
# ---------------------------------------------------------------------------
def test_list_only_returns_the_callers_files(client_a, client_b, user_b, make_file):
    do_upload(client_a, name="mine.pdf")
    make_file(user_b, name="theirs.pdf")

    body = client_a.get("/api/files/").data
    names = [item["filename"] for item in body["results"]]
    assert names == ["mine.pdf"]


def test_list_is_paginated(client_a):
    for index in range(3):
        do_upload(client_a, name=f"doc{index}.pdf")
    body = client_a.get("/api/files/?page_size=2").data
    assert body["count"] == 3
    assert len(body["results"]) == 2


def test_detail_requires_ownership(client_b, client_a, file_a):
    """A stranger gets exactly the same answer as for a non-existent id."""
    stranger = client_b.get(f"/api/files/{file_a.id}/")
    missing = client_b.get(f"/api/files/{uuid.uuid4()}/")
    assert stranger.status_code == missing.status_code == 404
    assert stranger.data["error"] == missing.data["error"] == "FILE_NOT_FOUND"
    assert stranger.data["message"] == missing.data["message"]
    assert AuditLog.objects.filter(
        action=AuditAction.UNAUTHORIZED_FILE_ACCESS
    ).exists()


def test_detail_for_unknown_id_returns_404(client_a):
    response = client_a.get(f"/api/files/{uuid.uuid4()}/")
    assert response.status_code == 404
    assert response.data["error"] == "FILE_NOT_FOUND"


def test_detail_rejects_malformed_uuid(client_a):
    assert client_a.get("/api/files/not-a-uuid/").status_code == 404


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
def test_owner_downloads_the_exact_original_bytes(client_a, file_a, pdf_bytes):
    response = client_a.get(f"/api/files/{file_a.id}/download/")
    assert response.status_code == 200
    content = b"".join(response.streaming_content) if response.streaming else response.content
    assert content == pdf_bytes
    assert hashlib.sha256(content).hexdigest() == file_a.checksum_sha256
    assert 'attachment; filename="report.pdf"' in response["Content-Disposition"]
    assert response["X-Content-Type-Options"] == "nosniff"


def test_download_increments_the_counter_and_audits(client_a, file_a):
    client_a.get(f"/api/files/{file_a.id}/download/")
    file_a.refresh_from_db()
    assert file_a.download_count == 1
    assert file_a.last_downloaded_at is not None
    assert AuditLog.objects.filter(
        action=AuditAction.FILE_DOWNLOADED, object_id=str(file_a.id)
    ).exists()


def test_download_requires_authentication(api_client, file_a):
    assert api_client.get(f"/api/files/{file_a.id}/download/").status_code == 401


def test_download_by_another_user_is_denied(client_b, file_a):
    response = client_b.get(f"/api/files/{file_a.id}/download/")
    assert response.status_code == 404
    assert AuditLog.objects.filter(
        action=AuditAction.UNAUTHORIZED_FILE_ACCESS
    ).exists()


def test_download_detects_tampered_ciphertext(client_a, file_a):
    """Flipping a byte in encrypted storage must fail closed, not serve data."""
    path = object_path(file_a.stored_object_id)
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 0xFF
    path.write_bytes(bytes(raw))

    response = client_a.get(f"/api/files/{file_a.id}/download/")
    if response.status_code == 200:
        with pytest.raises(SecurityError):
            b"".join(response.streaming_content)
    else:
        assert response.status_code == 422
        assert response.data["error"] == "FILE_INTEGRITY_ERROR"
    assert AuditLog.objects.filter(action=AuditAction.FILE_INTEGRITY_FAILURE).exists()


def test_download_detects_swapped_ciphertext_between_files(client_a, pdf_bytes):
    """AAD binds ciphertext to its row: swapping objects is detected."""
    first = File.objects.get(pk=do_upload(client_a, name="a.pdf", content=pdf_bytes).data["id"])
    second = File.objects.get(
        pk=do_upload(client_a, name="b.pdf", content=build_pdf("second")).data["id"]
    )
    first_path = object_path(first.stored_object_id)
    second_path = object_path(second.stored_object_id)
    first_path.write_bytes(second_path.read_bytes())

    response = client_a.get(f"/api/files/{first.id}/download/")
    if response.status_code == 200:
        with pytest.raises(SecurityError):
            b"".join(response.streaming_content)
    else:
        assert response.status_code == 422


def test_download_of_missing_object_fails_cleanly(client_a, file_a):
    get_storage().delete(file_a.stored_object_id)
    response = client_a.get(f"/api/files/{file_a.id}/download/")
    assert response.status_code in (410, 422, 500)
    assert "Traceback" not in str(response.content)


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------
def test_owner_can_delete_a_file(client_a, file_a):
    object_id = file_a.stored_object_id
    response = client_a.delete(f"/api/files/{file_a.id}/")
    assert response.status_code == 204

    file_a.refresh_from_db()
    assert file_a.deleted_at is not None
    assert file_a.status == FileStatus.DELETED
    assert not get_storage().exists(object_id)  # ciphertext is really gone
    assert AuditLog.objects.filter(
        action=AuditAction.FILE_DELETED, object_id=str(file_a.id)
    ).exists()


def test_deleted_file_is_not_listed_or_downloadable(client_a, file_a):
    client_a.delete(f"/api/files/{file_a.id}/")
    assert client_a.get("/api/files/").data["count"] == 0
    assert client_a.get(f"/api/files/{file_a.id}/").status_code == 404
    assert client_a.get(f"/api/files/{file_a.id}/download/").status_code == 404


def test_other_users_cannot_delete_a_file(client_b, file_a):
    response = client_b.delete(f"/api/files/{file_a.id}/")
    assert response.status_code == 404
    file_a.refresh_from_db()
    assert file_a.deleted_at is None


def test_upload_is_rate_limited(client_a, throttle_rates):
    throttle_rates({"files.upload": "2/hour"})
    codes = [do_upload(client_a, name=f"f{i}.pdf").status_code for i in range(4)]
    assert 429 in codes
