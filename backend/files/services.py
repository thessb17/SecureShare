"""File lifecycle service: encrypt-on-upload, decrypt-on-download, secure delete.

This is the only place that touches both the cryptographic engine and the
storage backend; views stay thin and contain no cryptography.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any, BinaryIO, Iterator

from django.db import transaction
from django.utils import timezone

from audit.constants import AuditAction
from audit.services import record_event
from core.exceptions import APIError, ServiceUnavailable
from files.exceptions import (
    EncryptedObjectMissing,
    FileIntegrityError,
    MalformedUpload,
    MalwareDetectedError,
    ScannerUnavailable,
    StorageFailure,
)
from files.models import File, FileEncryptionMetadata, FileStatus, MalwareScanStatus
from files.validators import ValidatedUpload, validate_upload
from security.crypto import (
    EnvelopeEncryptionService,
    build_aad_context,
    get_encryption_service,
)
from security.exceptions import (
    DecryptionError,
    IntegrityError,
    KeyManagementError,
    MalwareScanError,
    ObjectNotFound,
    StorageError,
)
from security.scanning import ScanResult, ScanStatus, scan_upload
from security.storage import EncryptedObjectStorage, get_storage

logger = logging.getLogger("secureshare")
security_logger = logging.getLogger("secureshare.security")


@dataclass(frozen=True)
class DecryptedPayload:
    """In-memory plaintext plus the metadata needed to build a response."""

    content: bytes
    filename: str
    mime_type: str
    size: int


class FileService:
    """Upload, download and delete encrypted files."""

    def __init__(
        self,
        storage: EncryptedObjectStorage | None = None,
        crypto: EnvelopeEncryptionService | None = None,
    ) -> None:
        self._storage = storage
        self._crypto = crypto

    @property
    def storage(self) -> EncryptedObjectStorage:
        return self._storage or get_storage()

    @property
    def crypto(self) -> EnvelopeEncryptionService:
        return self._crypto or get_encryption_service()

    # ------------------------------------------------------------------
    # Upload
    # ------------------------------------------------------------------
    def upload(self, *, owner: Any, uploaded_file: Any, request: Any = None) -> File:
        validated = self._validate(uploaded_file, owner=owner, request=request)
        scan = self._scan(uploaded_file, owner=owner, request=request, validated=validated)

        file_id = uuid.uuid4()
        object_id = self.storage.allocate_object_id()
        context = build_aad_context(str(file_id), object_id)

        uploaded_file.seek(0)
        stored = False
        try:
            with self.storage.write(object_id) as destination:
                result = self.crypto.encrypt_file(
                    uploaded_file, destination, context=context
                )
            stored = True

            if result.plaintext_size != validated.size:
                raise MalformedUpload("The upload was truncated during transfer.")

            with transaction.atomic():
                file_obj = File.objects.create(
                    id=file_id,
                    owner=owner,
                    original_filename=validated.filename,
                    stored_object_id=object_id,
                    file_size=result.plaintext_size,
                    encrypted_size=result.ciphertext_size,
                    mime_type=validated.detected_mime,
                    declared_mime_type=validated.declared_mime,
                    extension=validated.extension,
                    checksum_sha256=result.plaintext_sha256,
                    encrypted_checksum_sha256=result.ciphertext_sha256,
                    status=FileStatus.ACTIVE,
                    malware_scan_status=_scan_status_to_model(scan.status),
                    malware_signature=scan.signature[:128],
                    scanned_at=timezone.now() if scan.scanned else None,
                )
                FileEncryptionMetadata.objects.create(
                    file=file_obj,
                    algorithm=result.algorithm,
                    key_wrapping_algorithm=result.key_wrapping_algorithm,
                    key_id=result.key_id,
                    wrapped_dek=result.wrapped_dek,
                    nonce=result.header,
                    chunk_size=result.chunk_size,
                    chunk_count=result.chunk_count,
                    aad_context=context.decode("utf-8", "replace")[:255],
                )
        except Exception as exc:
            # Never leave an orphaned ciphertext behind.
            if stored:
                self._safe_delete_object(object_id)
            if not isinstance(exc, APIError):
                logger.exception("Upload failed during encryption or persistence")
            record_event(
                action=AuditAction.FILE_UPLOAD_REJECTED,
                request=request,
                user=owner,
                success=False,
                message="Upload failed after validation.",
                metadata={
                    "filename": validated.filename,
                    "reason": getattr(exc, "error_code", exc.__class__.__name__),
                },
            )
            if isinstance(exc, (StorageError, OSError)):
                raise StorageFailure() from exc
            raise

        record_event(
            action=AuditAction.FILE_UPLOADED,
            request=request,
            user=owner,
            message="File uploaded and encrypted.",
            object_type="file",
            object_id=file_obj.id,
            object_owner=owner,
            metadata={
                "filename": file_obj.original_filename,
                "size": file_obj.file_size,
                "mime_type": file_obj.mime_type,
                "declared_mime_type": file_obj.declared_mime_type,
                "algorithm": result.algorithm,
                "key_wrapping_algorithm": result.key_wrapping_algorithm,
                "chunk_count": result.chunk_count,
                "malware_scan_status": file_obj.malware_scan_status,
                "plaintext_sha256": file_obj.checksum_sha256,
            },
        )
        return file_obj

    def _validate(self, uploaded_file: Any, *, owner: Any, request: Any) -> ValidatedUpload:
        try:
            return validate_upload(uploaded_file)
        except APIError as exc:
            attempted = getattr(uploaded_file, "name", "")
            record_event(
                action=AuditAction.FILE_UPLOAD_REJECTED,
                request=request,
                user=owner,
                success=False,
                message="Upload rejected by validation.",
                metadata={
                    "reason": exc.error_code,
                    # repr() neutralises control characters before storage.
                    "attempted_filename": repr(str(attempted))[:200],
                    "declared_mime_type": getattr(uploaded_file, "content_type", ""),
                    "declared_size": getattr(uploaded_file, "size", None),
                },
            )
            raise

    def _scan(
        self,
        uploaded_file: Any,
        *,
        owner: Any,
        request: Any,
        validated: ValidatedUpload,
    ) -> ScanResult:
        try:
            result = scan_upload(uploaded_file)
        except MalwareScanError as exc:
            record_event(
                action=AuditAction.FILE_UPLOAD_REJECTED,
                request=request,
                user=owner,
                success=False,
                message="Upload rejected: malware scanner unavailable (fail-closed).",
                metadata={"filename": validated.filename},
            )
            raise ScannerUnavailable() from exc

        if result.is_infected:
            record_event(
                action=AuditAction.MALWARE_DETECTED,
                request=request,
                user=owner,
                success=False,
                message="Upload rejected: malware detected.",
                metadata={
                    "filename": validated.filename,
                    "signature": result.signature,
                },
            )
            raise MalwareDetectedError(
                f"The file was rejected by the malware scanner ({result.signature})."
            )
        return result

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------
    def iter_plaintext(self, file_obj: File) -> Iterator[bytes]:
        """Yield authenticated plaintext chunks for an active file."""
        metadata = self._encryption_metadata(file_obj)
        dek = self._unwrap(metadata)
        context = build_aad_context(str(file_obj.id), file_obj.stored_object_id)

        try:
            stream: BinaryIO = self.storage.open(file_obj.stored_object_id)
        except ObjectNotFound as exc:
            raise EncryptedObjectMissing() from exc
        except StorageError as exc:
            raise StorageFailure() from exc

        try:
            yield from self.crypto.decrypt_file(
                stream,
                dek=dek,
                context=context,
                expected_header=bytes(metadata.nonce),
                expected_plaintext_sha256=file_obj.checksum_sha256,
            )
        finally:
            stream.close()

    def read_plaintext(self, file_obj: File, *, request: Any = None) -> DecryptedPayload:
        """Fully decrypt a file in memory, mapping crypto failures to API errors."""
        try:
            content = b"".join(self.iter_plaintext(file_obj))
        except IntegrityError as exc:
            self._record_integrity_failure(file_obj, request, str(exc))
            raise FileIntegrityError() from exc
        except DecryptionError as exc:
            self._record_integrity_failure(file_obj, request, "decryption_failed")
            raise FileIntegrityError() from exc

        return DecryptedPayload(
            content=content,
            filename=file_obj.original_filename,
            mime_type=file_obj.mime_type,
            size=len(content),
        )

    def _record_integrity_failure(self, file_obj: File, request: Any, detail: str) -> None:
        security_logger.error(
            "file_integrity_failure",
            extra={"file_id": str(file_obj.id), "detail": detail[:200]},
        )
        record_event(
            action=AuditAction.FILE_INTEGRITY_FAILURE,
            request=request,
            success=False,
            message="Authenticated decryption failed for a stored file.",
            object_type="file",
            object_id=file_obj.id,
            object_owner=file_obj.owner,
            metadata={"filename": file_obj.original_filename},
        )

    def _encryption_metadata(self, file_obj: File) -> FileEncryptionMetadata:
        metadata = FileEncryptionMetadata.objects.filter(file=file_obj).first()
        if metadata is None:
            security_logger.error(
                "missing_encryption_metadata", extra={"file_id": str(file_obj.id)}
            )
            raise EncryptedObjectMissing(
                "Encryption metadata for this file is unavailable."
            )
        return metadata

    def _unwrap(self, metadata: FileEncryptionMetadata) -> bytes:
        try:
            return self.crypto.unwrap_file_key(bytes(metadata.wrapped_dek), metadata.key_id)
        except KeyManagementError as exc:
            logger.error("Key material unavailable for unwrapping", exc_info=True)
            raise ServiceUnavailable(
                "Decryption is temporarily unavailable.",
                error_code="DECRYPTION_UNAVAILABLE",
            ) from exc
        except DecryptionError as exc:
            raise FileIntegrityError(
                "The stored key material for this file is invalid."
            ) from exc

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------
    def delete(self, *, file_obj: File, actor: Any, request: Any = None) -> None:
        """Soft-delete the record, crypto-shred the DEK and remove the object."""
        object_id = file_obj.stored_object_id
        revoked_shares = 0
        revoked_links = 0

        with transaction.atomic():
            locked = File.objects.select_for_update().get(pk=file_obj.pk)
            if locked.is_deleted:
                return
            locked.mark_deleted()
            revoked_shares, revoked_links = _revoke_all_sharing(locked)
            # Destroying the wrapped DEK makes any residual ciphertext
            # permanently undecryptable (crypto-shredding).
            FileEncryptionMetadata.objects.filter(file=locked).delete()

        object_removed = self._safe_delete_object(object_id)

        record_event(
            action=AuditAction.FILE_DELETED,
            request=request,
            user=actor,
            success=True,
            message="File deleted.",
            object_type="file",
            object_id=file_obj.id,
            object_owner=file_obj.owner,
            metadata={
                "filename": file_obj.original_filename,
                "encrypted_object_removed": object_removed,
                "revoked_shares": revoked_shares,
                "revoked_share_links": revoked_links,
                "by_admin": bool(
                    getattr(actor, "is_admin", False) and actor.pk != file_obj.owner_id
                ),
            },
        )

    def _safe_delete_object(self, object_id: str) -> bool:
        try:
            return self.storage.delete(object_id)
        except StorageError:
            logger.error(
                "Failed to delete encrypted object; scheduled for purge",
                exc_info=True,
            )
            return False


def _revoke_all_sharing(file_obj: File) -> tuple[int, int]:
    """Revoke every share and public link of a file (import kept local)."""
    from sharing.models import FileShare, ShareLink

    now = timezone.now()
    shares = FileShare.objects.filter(file=file_obj, revoked_at__isnull=True).update(
        revoked_at=now
    )
    links = ShareLink.objects.filter(file=file_obj, revoked_at__isnull=True).update(
        revoked_at=now
    )
    return shares, links


def _scan_status_to_model(status: ScanStatus) -> str:
    mapping = {
        ScanStatus.CLEAN: MalwareScanStatus.CLEAN,
        ScanStatus.INFECTED: MalwareScanStatus.INFECTED,
        ScanStatus.SKIPPED: MalwareScanStatus.SKIPPED,
        ScanStatus.ERROR: MalwareScanStatus.ERROR,
        ScanStatus.NOT_SCANNED: MalwareScanStatus.NOT_SCANNED,
    }
    return str(mapping.get(status, MalwareScanStatus.NOT_SCANNED))


_SERVICE: FileService | None = None


def get_file_service() -> FileService:
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = FileService()
    return _SERVICE
