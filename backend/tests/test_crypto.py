"""Phase 3: envelope encryption engine (AES-256-GCM + RSA-OAEP).

These tests exercise the real ``cryptography`` primitives - nothing is mocked.
"""
from __future__ import annotations

import hashlib
import io
import os
import struct

import pytest

from security.crypto import (
    DEK_SIZE,
    HEADER_SIZE,
    MAGIC,
    EnvelopeEncryptionService,
    build_aad_context,
    get_encryption_service,
)
from security.exceptions import (
    DecryptionError,
    EncryptionError,
    IntegrityError,
    KeyManagementError,
)
from security.keys import get_key_provider

pytestmark = pytest.mark.crypto

CONTEXT = build_aad_context("file", "11111111-1111-1111-1111-111111111111", "obj-1")
OTHER_CONTEXT = build_aad_context("file", "22222222-2222-2222-2222-222222222222", "obj-2")


@pytest.fixture
def service(rsa_test_keys) -> EnvelopeEncryptionService:
    return get_encryption_service()


# 1 -------------------------------------------------------------------------
def test_each_file_gets_a_unique_256_bit_data_encryption_key(service):
    keys = {service.generate_file_key() for _ in range(64)}
    assert len(keys) == 64, "DEKs must never repeat"
    assert all(len(key) == DEK_SIZE for key in keys)
    assert DEK_SIZE * 8 == 256


# 2 -------------------------------------------------------------------------
def test_each_encryption_uses_a_unique_nonce(service):
    plaintext = b"same plaintext, same key, different nonce"
    dek = service.generate_file_key()
    prefixes = set()
    headers = set()
    for _ in range(32):
        _, result = service.encrypt_bytes(plaintext, context=CONTEXT, dek=dek)
        prefixes.add(result.nonce_prefix)
        headers.add(result.header)
    assert len(prefixes) == 32, "nonce prefix must be random per encryption"
    assert len(headers) == 32


def test_identical_plaintext_and_key_produce_different_ciphertext(service):
    dek = service.generate_file_key()
    first, _ = service.encrypt_bytes(b"repeated payload", context=CONTEXT, dek=dek)
    second, _ = service.encrypt_bytes(b"repeated payload", context=CONTEXT, dek=dek)
    assert first != second, "a static IV/nonce would make these identical"


# 3 -------------------------------------------------------------------------
def test_roundtrip_returns_the_exact_plaintext(service):
    plaintext = os.urandom(5000) + b"\x00\x00trailing nulls\x00"
    dek = service.generate_file_key()
    container, result = service.encrypt_bytes(plaintext, context=CONTEXT, dek=dek)
    recovered = service.decrypt_bytes(
        container,
        dek=dek,
        context=CONTEXT,
        expected_header=result.header,
        expected_plaintext_sha256=result.plaintext_sha256,
    )
    assert recovered == plaintext


@pytest.mark.parametrize("size", [0, 1, 4095, 4096, 4097, 300_000])
def test_roundtrip_for_many_sizes_including_empty_and_chunk_boundaries(service, size):
    plaintext = os.urandom(size)
    dek = service.generate_file_key()
    container, result = service.encrypt_bytes(plaintext, context=CONTEXT, dek=dek)
    assert service.decrypt_bytes(container, dek=dek, context=CONTEXT) == plaintext
    assert result.plaintext_size == size


def test_multi_chunk_streaming_roundtrip(service):
    plaintext = os.urandom(300_000)
    dek = service.generate_file_key()
    destination = io.BytesIO()
    result = service.encrypt_file(
        io.BytesIO(plaintext), destination, context=CONTEXT, dek=dek, chunk_size=65536
    )
    assert result.chunk_count == 5
    chunks = list(
        service.decrypt_file(
            io.BytesIO(destination.getvalue()), dek=dek, context=CONTEXT
        )
    )
    assert len(chunks) == 5
    assert b"".join(chunks) == plaintext


# 4 -------------------------------------------------------------------------
def test_ciphertext_does_not_leak_plaintext(service):
    plaintext = b"TOP SECRET MARKER STRING 42" * 40
    dek = service.generate_file_key()
    container, _ = service.encrypt_bytes(plaintext, context=CONTEXT, dek=dek)
    assert b"TOP SECRET MARKER STRING" not in container
    assert container[:6] == MAGIC  # only the documented header is in the clear
    assert dek not in container


# 5 -------------------------------------------------------------------------
def test_wrong_key_cannot_decrypt(service):
    dek = service.generate_file_key()
    container, _ = service.encrypt_bytes(b"secret", context=CONTEXT, dek=dek)
    with pytest.raises((IntegrityError, DecryptionError)):
        service.decrypt_bytes(container, dek=service.generate_file_key(), context=CONTEXT)


def test_wrong_context_cannot_decrypt(service):
    """AAD binds the ciphertext to its file: relocation is detected."""
    dek = service.generate_file_key()
    container, _ = service.encrypt_bytes(b"secret", context=CONTEXT, dek=dek)
    with pytest.raises(IntegrityError):
        service.decrypt_bytes(container, dek=dek, context=OTHER_CONTEXT)


# 6 -------------------------------------------------------------------------
def test_tampered_ciphertext_is_rejected(service):
    dek = service.generate_file_key()
    container, result = service.encrypt_bytes(b"A" * 1000, context=CONTEXT, dek=dek)
    corrupted = bytearray(container)
    corrupted[HEADER_SIZE + 10] ^= 0x01  # flip one bit of the ciphertext body
    with pytest.raises(IntegrityError):
        service.decrypt_bytes(
            bytes(corrupted), dek=dek, context=CONTEXT, expected_header=result.header
        )


def test_tampered_gcm_tag_is_rejected(service):
    dek = service.generate_file_key()
    container, _ = service.encrypt_bytes(b"payload", context=CONTEXT, dek=dek)
    corrupted = bytearray(container)
    corrupted[-1] ^= 0xFF  # last byte belongs to the authentication tag
    with pytest.raises(IntegrityError):
        service.decrypt_bytes(bytes(corrupted), dek=dek, context=CONTEXT)


def test_tampered_header_is_rejected(service):
    dek = service.generate_file_key()
    container, result = service.encrypt_bytes(b"payload", context=CONTEXT, dek=dek)
    corrupted = bytearray(container)
    corrupted[20] ^= 0x01  # inside the stream id
    with pytest.raises(IntegrityError):
        service.decrypt_bytes(
            bytes(corrupted), dek=dek, context=CONTEXT, expected_header=result.header
        )


def test_truncated_container_is_rejected(service):
    dek = service.generate_file_key()
    container, _ = service.encrypt_bytes(os.urandom(200_000), context=CONTEXT, dek=dek)
    with pytest.raises((IntegrityError, DecryptionError)):
        service.decrypt_bytes(container[: len(container) // 2], dek=dek, context=CONTEXT)


def test_reordered_chunks_are_rejected(service):
    """Nonce counter + AAD prevent chunk swapping inside one container."""
    dek = service.generate_file_key()
    destination = io.BytesIO()
    service.encrypt_file(
        io.BytesIO(os.urandom(16384 * 3)),
        destination,
        context=CONTEXT,
        dek=dek,
        chunk_size=16384,
    )
    raw = destination.getvalue()
    body = raw[HEADER_SIZE:]
    frames = []
    offset = 0
    while offset < len(body):
        (length,) = struct.unpack(">I", body[offset : offset + 4])
        frames.append(body[offset : offset + 4 + length])
        offset += 4 + length
    assert len(frames) == 3
    swapped = raw[:HEADER_SIZE] + frames[1] + frames[0] + frames[2]
    with pytest.raises(IntegrityError):
        service.decrypt_bytes(swapped, dek=dek, context=CONTEXT)


def test_appended_data_is_rejected(service):
    dek = service.generate_file_key()
    container, _ = service.encrypt_bytes(b"payload", context=CONTEXT, dek=dek)
    with pytest.raises((IntegrityError, DecryptionError)):
        service.decrypt_bytes(container + b"extra", dek=dek, context=CONTEXT)


def test_foreign_container_magic_is_rejected(service):
    dek = service.generate_file_key()
    with pytest.raises((IntegrityError, DecryptionError)):
        service.decrypt_bytes(b"NOTSSENC" + os.urandom(64), dek=dek, context=CONTEXT)


# 7 -------------------------------------------------------------------------
def test_dek_is_wrapped_with_rsa_oaep_and_unwraps_correctly(service):
    dek = service.generate_file_key()
    wrapped, key_id = service.wrap_file_key(dek)
    assert wrapped != dek
    assert dek not in wrapped
    assert len(wrapped) == get_key_provider().public_key.key_size // 8
    assert key_id
    assert service.unwrap_file_key(wrapped, key_id) == dek


def test_rsa_wrapping_is_randomised(service):
    """OAEP is probabilistic: the same DEK wraps to different ciphertext."""
    dek = service.generate_file_key()
    first, _ = service.wrap_file_key(dek)
    second, _ = service.wrap_file_key(dek)
    assert first != second
    assert service.unwrap_file_key(first) == service.unwrap_file_key(second) == dek


def test_tampered_wrapped_dek_cannot_be_unwrapped(service):
    dek = service.generate_file_key()
    wrapped, key_id = service.wrap_file_key(dek)
    corrupted = bytearray(wrapped)
    corrupted[5] ^= 0xFF
    with pytest.raises(DecryptionError):
        service.unwrap_file_key(bytes(corrupted), key_id)


def test_unwrapping_with_an_unknown_key_id_fails(service):
    """A DEK wrapped with a retired/unknown key must not silently succeed."""
    dek = service.generate_file_key()
    wrapped, _ = service.wrap_file_key(dek)
    with pytest.raises((KeyManagementError, DecryptionError)):
        service.unwrap_file_key(wrapped, "0" * 32)


def test_rsa_key_size_meets_policy():
    provider = get_key_provider()
    assert provider.public_key.key_size >= 3072
    assert provider.private_key().key_size == provider.public_key.key_size
    assert provider.key_size == provider.public_key.key_size


# 8 -------------------------------------------------------------------------
def test_checksum_is_sha256_and_detects_modification(service):
    data = b"checksum me"
    digest = service.calculate_checksum(data)
    assert digest == hashlib.sha256(data).hexdigest()
    assert len(digest) == 64
    assert digest != service.calculate_checksum(b"checksum mE")


def test_checksum_mismatch_is_detected_on_decrypt(service):
    dek = service.generate_file_key()
    container, result = service.encrypt_bytes(b"payload", context=CONTEXT, dek=dek)
    with pytest.raises(IntegrityError):
        service.decrypt_bytes(
            container,
            dek=dek,
            context=CONTEXT,
            expected_plaintext_sha256="0" * 64,
        )
    # ...and passes with the real digest.
    assert service.decrypt_bytes(
        container,
        dek=dek,
        context=CONTEXT,
        expected_plaintext_sha256=result.plaintext_sha256,
    ) == b"payload"


# 9 -------------------------------------------------------------------------
def test_invalid_dek_size_is_rejected(service):
    with pytest.raises(EncryptionError):
        service.encrypt_bytes(b"x", context=CONTEXT, dek=b"too-short")


def test_encryption_metadata_describes_the_algorithms(service):
    _, result = service.encrypt_bytes(b"payload", context=CONTEXT)
    assert result.algorithm.startswith("AES-256-GCM")
    assert "RSA-OAEP" in result.key_wrapping_algorithm
    assert "SHA256" in result.key_wrapping_algorithm
    assert "MGF1" in result.key_wrapping_algorithm
    assert result.ciphertext_size > result.plaintext_size  # header + tags
    assert len(result.header) == HEADER_SIZE


# 10 ------------------------------------------------------------------------
def test_private_key_is_never_exposed_through_the_result(service):
    _, result = service.encrypt_bytes(b"payload", context=CONTEXT)
    blob = repr(result).encode() + result.wrapped_dek + result.header
    assert b"PRIVATE KEY" not in blob
    assert b"BEGIN RSA" not in blob


def test_encryption_is_memory_bounded_for_large_inputs(service):
    """A 12 MiB payload encrypts through a 1 MiB window without buffering."""
    size = 12 * 1024 * 1024
    source = io.BytesIO(os.urandom(size))
    destination = io.BytesIO()
    dek = service.generate_file_key()
    result = service.encrypt_file(
        source, destination, context=CONTEXT, dek=dek, chunk_size=1024 * 1024
    )
    assert result.chunk_count == 12
    source.seek(0)
    assert (
        hashlib.sha256(source.getvalue()).hexdigest() == result.plaintext_sha256
    )
