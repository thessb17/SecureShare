"""Envelope encryption engine (AES-256-GCM + RSA-OAEP).

Design
------
Every file gets its **own** 256-bit Data Encryption Key (DEK). The DEK encrypts
the plaintext with AES-256-GCM and is then wrapped with RSA-OAEP (SHA-256,
MGF1-SHA-256) using the server key pair. Only the wrapped DEK is persisted::

    plaintext --AES-256-GCM(DEK)--> ciphertext  -> encrypted object storage
        DEK   --RSA-OAEP(pub)-----> wrapped DEK -> PostgreSQL metadata

Streaming container format
--------------------------
AES-GCM must not be used on unbounded data in a single call, and large uploads
must not be buffered in RAM, so ciphertext is written as a framed, chunked AEAD
container (comparable to Tink's streaming AEAD)::

    header  := magic(6) | version(1) | alg(1) | chunk_size(4) |
               stream_id(16) | nonce_prefix(8)            = 36 bytes
    frame_i := len(4) | AES-GCM(key=DEK,
                                nonce = nonce_prefix || counter_i,
                                aad   = header || counter_i || final_flag || ctx)

* each chunk has a **unique** nonce (random 8-byte prefix ‖ 32-bit counter);
* the AAD binds every chunk to the header, to its position, to whether it is
  the last chunk, and to an application context string (file id + object id),
  so reordering, truncation, appending, splicing chunks between files and
  swapping whole storage objects between database rows are all detected;
* an empty plaintext still produces one authenticated final chunk.

No cryptographic primitive is implemented by hand - everything comes from the
``cryptography`` package. ECB, static IVs, MD5 and SHA-1 are never used.
"""
from __future__ import annotations

import hmac
import logging
import secrets
import struct
from dataclasses import dataclass
from typing import BinaryIO, Final, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

from security.checksums import sha256_bytes
from security.exceptions import (
    DecryptionError,
    EncryptionError,
    IntegrityError,
    KeyManagementError,
)
from security.keys import RSAKeyProvider, get_key_provider

logger = logging.getLogger("secureshare.security")

# --- container constants ---------------------------------------------------
MAGIC: Final[bytes] = b"SSENC1"
FORMAT_VERSION: Final[int] = 1
ALG_AES_256_GCM_CHUNKED: Final[int] = 1

DEK_SIZE: Final[int] = 32  # 256-bit
NONCE_SIZE: Final[int] = 12  # 96-bit, the AES-GCM standard nonce length
NONCE_PREFIX_SIZE: Final[int] = 8
COUNTER_SIZE: Final[int] = 4
TAG_SIZE: Final[int] = 16
STREAM_ID_SIZE: Final[int] = 16

HEADER_FORMAT: Final[str] = ">6sBBI16s8s"
HEADER_SIZE: Final[int] = struct.calcsize(HEADER_FORMAT)  # 36
MAX_CHUNKS: Final[int] = 2**32 - 1
MIN_CHUNK_SIZE: Final[int] = 4096
MAX_CHUNK_SIZE: Final[int] = 64 * 1024 * 1024

ALGORITHM: Final[str] = "AES-256-GCM"
CONTAINER_ALGORITHM: Final[str] = "AES-256-GCM-STREAM-V1"
KEY_WRAP_ALGORITHM: Final[str] = "RSA-OAEP-SHA256-MGF1-SHA256"

CONTEXT_PREFIX: Final[bytes] = b"secureshare:v1:"


def build_aad_context(*parts: str) -> bytes:
    """Build the additional-authenticated-data context for a file.

    Binding the ciphertext to immutable identifiers (file UUID + storage object
    id) means a ciphertext cannot be moved to another database row.
    """
    return CONTEXT_PREFIX + ":".join(str(part) for part in parts).encode("utf-8")


@dataclass(frozen=True)
class EncryptionResult:
    """Everything the database must persist about one encryption operation."""

    algorithm: str
    key_wrapping_algorithm: str
    key_id: str
    wrapped_dek: bytes
    header: bytes
    chunk_size: int
    chunk_count: int
    plaintext_size: int
    ciphertext_size: int
    plaintext_sha256: str
    ciphertext_sha256: str

    @property
    def nonce_prefix(self) -> bytes:
        """The 8-byte random prefix; per-chunk nonce = prefix ‖ counter."""
        return self.header[-NONCE_PREFIX_SIZE:]


class EnvelopeEncryptionService:
    """Stateless service implementing the envelope-encryption scheme."""

    def __init__(self, key_provider: RSAKeyProvider | None = None) -> None:
        self._key_provider = key_provider

    # -- key handling ------------------------------------------------------
    @property
    def key_provider(self) -> RSAKeyProvider:
        return self._key_provider or get_key_provider()

    @staticmethod
    def generate_file_key() -> bytes:
        """Fresh 256-bit DEK from the OS CSPRNG. Never reused across files."""
        return secrets.token_bytes(DEK_SIZE)

    @staticmethod
    def generate_nonce_prefix() -> bytes:
        return secrets.token_bytes(NONCE_PREFIX_SIZE)

    def wrap_file_key(self, dek: bytes) -> tuple[bytes, str]:
        """RSA-OAEP(SHA-256/MGF1-SHA-256) wrap. Returns (wrapped_dek, key_id)."""
        if len(dek) != DEK_SIZE:
            raise EncryptionError("DEK must be exactly 256 bits.")
        provider = self.key_provider
        try:
            wrapped = provider.public_key.encrypt(
                dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise EncryptionError("Failed to wrap the data encryption key.") from exc
        return wrapped, provider.active_key_id

    def unwrap_file_key(self, wrapped_dek: bytes, key_id: str | None = None) -> bytes:
        """RSA-OAEP unwrap using the private key matching ``key_id``."""
        private_key = self.key_provider.private_key(key_id)
        try:
            dek = private_key.decrypt(
                bytes(wrapped_dek),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except KeyManagementError:
            raise
        except Exception as exc:
            raise DecryptionError("Failed to unwrap the data encryption key.") from exc
        if len(dek) != DEK_SIZE:
            raise DecryptionError("Unwrapped key has an unexpected length.")
        return dek

    # -- checksums ---------------------------------------------------------
    @staticmethod
    def calculate_checksum(data: bytes) -> str:
        return sha256_bytes(data)

    # -- container helpers -------------------------------------------------
    @staticmethod
    def _build_header(chunk_size: int, stream_id: bytes, nonce_prefix: bytes) -> bytes:
        return struct.pack(
            HEADER_FORMAT,
            MAGIC,
            FORMAT_VERSION,
            ALG_AES_256_GCM_CHUNKED,
            chunk_size,
            stream_id,
            nonce_prefix,
        )

    @staticmethod
    def _parse_header(header: bytes) -> tuple[int, bytes, bytes]:
        if len(header) != HEADER_SIZE:
            raise IntegrityError("Encrypted object header is truncated.")
        magic, version, alg, chunk_size, stream_id, nonce_prefix = struct.unpack(
            HEADER_FORMAT, header
        )
        if magic != MAGIC:
            raise IntegrityError("Encrypted object has an invalid magic value.")
        if version != FORMAT_VERSION:
            raise IntegrityError("Unsupported encrypted container version.")
        if alg != ALG_AES_256_GCM_CHUNKED:
            raise IntegrityError("Unsupported encryption algorithm identifier.")
        if not (MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE):
            raise IntegrityError("Encrypted object declares an invalid chunk size.")
        return chunk_size, stream_id, nonce_prefix

    @staticmethod
    def _nonce(nonce_prefix: bytes, counter: int) -> bytes:
        return nonce_prefix + struct.pack(">I", counter)

    @staticmethod
    def _aad(header: bytes, counter: int, final: bool, context: bytes) -> bytes:
        return (
            header
            + struct.pack(">I", counter)
            + (b"\x01" if final else b"\x00")
            + context
        )

    # -- encryption --------------------------------------------------------
    def encrypt_file(
        self,
        source: BinaryIO,
        destination: BinaryIO,
        *,
        context: bytes,
        dek: bytes | None = None,
        chunk_size: int | None = None,
    ) -> EncryptionResult:
        """Encrypt ``source`` into ``destination`` and return the metadata.

        Memory usage is bounded by ``chunk_size`` regardless of file size.
        """
        import hashlib

        chunk_size = int(chunk_size or getattr(settings, "ENCRYPTION_CHUNK_SIZE", 1_048_576))
        if not (MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE):
            raise EncryptionError("Configured chunk size is out of range.")

        dek = dek or self.generate_file_key()
        if len(dek) != DEK_SIZE:
            raise EncryptionError("DEK must be exactly 256 bits.")

        nonce_prefix = self.generate_nonce_prefix()
        stream_id = secrets.token_bytes(STREAM_ID_SIZE)
        header = self._build_header(chunk_size, stream_id, nonce_prefix)

        aesgcm = AESGCM(dek)
        plaintext_digest = hashlib.sha256()
        ciphertext_digest = hashlib.sha256()

        destination.write(header)
        ciphertext_digest.update(header)
        ciphertext_size = len(header)
        plaintext_size = 0
        counter = 0

        pending = source.read(chunk_size)
        while True:
            lookahead = source.read(chunk_size)
            final = not lookahead
            if counter > MAX_CHUNKS:
                raise EncryptionError("Input exceeds the maximum supported size.")

            nonce = self._nonce(nonce_prefix, counter)
            aad = self._aad(header, counter, final, context)
            try:
                blob = aesgcm.encrypt(nonce, pending, aad)
            except Exception as exc:
                raise EncryptionError("AES-GCM encryption failed.") from exc

            frame = struct.pack(">I", len(blob)) + blob
            destination.write(frame)
            ciphertext_digest.update(frame)
            ciphertext_size += len(frame)

            plaintext_digest.update(pending)
            plaintext_size += len(pending)
            counter += 1

            if final:
                break
            pending = lookahead

        wrapped_dek, key_id = self.wrap_file_key(dek)

        return EncryptionResult(
            algorithm=CONTAINER_ALGORITHM,
            key_wrapping_algorithm=KEY_WRAP_ALGORITHM,
            key_id=key_id,
            wrapped_dek=wrapped_dek,
            header=header,
            chunk_size=chunk_size,
            chunk_count=counter,
            plaintext_size=plaintext_size,
            ciphertext_size=ciphertext_size,
            plaintext_sha256=plaintext_digest.hexdigest(),
            ciphertext_sha256=ciphertext_digest.hexdigest(),
        )

    # -- decryption --------------------------------------------------------
    def decrypt_file(
        self,
        source: BinaryIO,
        *,
        dek: bytes,
        context: bytes,
        expected_header: bytes | None = None,
        expected_plaintext_sha256: str | None = None,
    ) -> Iterator[bytes]:
        """Yield authenticated plaintext chunks.

        Raises :class:`IntegrityError` on any tampering (ciphertext, tag, AAD,
        header, chunk order, truncation, trailing data, wrong context) and on a
        final SHA-256 mismatch. Corrupted data is never yielded: a chunk is only
        emitted after its GCM tag has been verified.
        """
        import hashlib

        header = source.read(HEADER_SIZE)
        if expected_header is not None and not hmac.compare_digest(
            bytes(header), bytes(expected_header)
        ):
            raise IntegrityError(
                "Encrypted object header does not match the stored metadata."
            )
        chunk_size, _stream_id, nonce_prefix = self._parse_header(bytes(header))

        aesgcm = AESGCM(dek)
        plaintext_digest = hashlib.sha256()
        counter = 0

        frame = self._read_frame(source, chunk_size)
        if frame is None:
            raise IntegrityError("Encrypted object contains no authenticated chunks.")

        while frame is not None:
            lookahead = self._read_frame(source, chunk_size)
            final = lookahead is None
            nonce = self._nonce(nonce_prefix, counter)
            aad = self._aad(bytes(header), counter, final, context)
            try:
                plaintext = aesgcm.decrypt(nonce, frame, aad)
            except InvalidTag as exc:
                raise IntegrityError(
                    "Authenticated decryption failed: the data has been modified."
                ) from exc
            except Exception as exc:
                raise DecryptionError("Decryption failed.") from exc

            plaintext_digest.update(plaintext)
            yield plaintext

            counter += 1
            frame = lookahead

        if expected_plaintext_sha256 is not None:
            digest = plaintext_digest.hexdigest()
            if not hmac.compare_digest(digest, expected_plaintext_sha256):
                raise IntegrityError(
                    "Decrypted content does not match the recorded SHA-256 checksum."
                )

    @staticmethod
    def _read_frame(source: BinaryIO, chunk_size: int) -> bytes | None:
        length_bytes = source.read(4)
        if not length_bytes:
            return None
        if len(length_bytes) != 4:
            raise IntegrityError("Encrypted object is truncated (frame header).")
        (length,) = struct.unpack(">I", length_bytes)
        if length < TAG_SIZE or length > chunk_size + TAG_SIZE:
            raise IntegrityError("Encrypted object declares an invalid frame length.")
        blob = source.read(length)
        if len(blob) != length:
            raise IntegrityError("Encrypted object is truncated (frame body).")
        return blob

    # -- convenience wrappers ---------------------------------------------
    def encrypt_bytes(
        self, plaintext: bytes, *, context: bytes, dek: bytes | None = None
    ) -> tuple[bytes, EncryptionResult]:
        """Encrypt an in-memory payload; returns (container_bytes, metadata)."""
        import io

        source, destination = io.BytesIO(plaintext), io.BytesIO()
        result = self.encrypt_file(source, destination, context=context, dek=dek)
        return destination.getvalue(), result

    def decrypt_bytes(
        self,
        container: bytes,
        *,
        dek: bytes,
        context: bytes,
        expected_header: bytes | None = None,
        expected_plaintext_sha256: str | None = None,
    ) -> bytes:
        import io

        return b"".join(
            self.decrypt_file(
                io.BytesIO(container),
                dek=dek,
                context=context,
                expected_header=expected_header,
                expected_plaintext_sha256=expected_plaintext_sha256,
            )
        )


_SERVICE: EnvelopeEncryptionService | None = None


def get_encryption_service() -> EnvelopeEncryptionService:
    """Return the process-wide encryption service."""
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = EnvelopeEncryptionService()
    return _SERVICE
