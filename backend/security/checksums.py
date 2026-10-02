"""SHA-256 integrity helpers.

MD5 and SHA-1 are never used anywhere in this project.
"""
from __future__ import annotations

import hashlib
from typing import BinaryIO, Final

DEFAULT_CHUNK_SIZE: Final[int] = 1_048_576


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 digest of an in-memory payload."""
    return hashlib.sha256(data).hexdigest()


def sha256_stream(stream: BinaryIO, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Hex SHA-256 digest of a stream, read incrementally (constant memory)."""
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(chunk_size), b""):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_upload(uploaded_file, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Digest a Django ``UploadedFile`` without loading it fully into memory."""
    digest = hashlib.sha256()
    uploaded_file.seek(0)
    for chunk in uploaded_file.chunks(chunk_size):
        digest.update(chunk)
    uploaded_file.seek(0)
    return digest.hexdigest()
