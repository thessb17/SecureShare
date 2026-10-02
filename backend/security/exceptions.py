"""Internal security exceptions (never serialised directly to clients)."""
from __future__ import annotations


class SecurityError(Exception):
    """Base class for cryptography/storage failures."""


class KeyManagementError(SecurityError):
    """RSA key material missing, malformed or too weak."""


class EncryptionError(SecurityError):
    """Failure while encrypting data."""


class DecryptionError(SecurityError):
    """Failure while decrypting data (wrong key, malformed container...)."""


class IntegrityError(DecryptionError):
    """Authenticated decryption failed: the data has been tampered with."""


class StorageError(SecurityError):
    """Encrypted object storage failure."""


class ObjectNotFound(StorageError):
    """The requested encrypted object does not exist."""


class MalwareScanError(SecurityError):
    """The malware scanner could not complete the scan."""


class MalwareDetected(SecurityError):
    """The scanner positively identified malware."""

    def __init__(self, signature: str) -> None:
        self.signature = signature
        super().__init__(f"Malware signature detected: {signature}")
