"""File domain API errors (structured, no internal detail)."""
from __future__ import annotations

from rest_framework import status

from core.exceptions import APIError


class FileNotFound(APIError):
    status_code = status.HTTP_404_NOT_FOUND
    error_code = "FILE_NOT_FOUND"
    default_detail = "The requested file could not be found."


class FileAccessDenied(APIError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "ACCESS_DENIED"
    default_detail = "You do not have permission to access this file."


class FileTooLarge(APIError):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    error_code = "FILE_TOO_LARGE"
    default_detail = "The uploaded file exceeds the maximum allowed size."


class InvalidFilename(APIError):
    status_code = status.HTTP_400_BAD_REQUEST
    error_code = "INVALID_FILENAME"
    default_detail = "The provided filename is not acceptable."


class UnsupportedFileType(APIError):
    status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    error_code = "UNSUPPORTED_FILE_TYPE"
    default_detail = "This file type is not allowed."


class MalformedUpload(APIError):
    status_code = status.HTTP_400_BAD_REQUEST
    error_code = "MALFORMED_UPLOAD"
    default_detail = "The upload could not be processed."


class MalwareDetectedError(APIError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_code = "MALWARE_DETECTED"
    default_detail = "The uploaded file was rejected by the malware scanner."


class ScannerUnavailable(APIError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    error_code = "MALWARE_SCANNER_UNAVAILABLE"
    default_detail = (
        "Uploads are temporarily unavailable because the malware scanner "
        "cannot be reached."
    )


class FileIntegrityError(APIError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_code = "FILE_INTEGRITY_ERROR"
    default_detail = (
        "The stored file failed its integrity check and cannot be served."
    )


class EncryptedObjectMissing(APIError):
    status_code = status.HTTP_410_GONE
    error_code = "ENCRYPTED_OBJECT_MISSING"
    default_detail = "The encrypted object backing this file is no longer available."


class StorageFailure(APIError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    error_code = "STORAGE_UNAVAILABLE"
    default_detail = "Encrypted storage is temporarily unavailable."
