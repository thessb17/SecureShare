"""Unit tests for the security building blocks: keys, storage, checksums, scanner."""
from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

from security.checksums import sha256_bytes, sha256_stream, sha256_upload
from security.exceptions import KeyManagementError, ObjectNotFound, StorageError
from security.keys import get_key_provider, public_key_fingerprint, reset_key_cache
from security.storage import (
    LocalEncryptedStorage,
    generate_object_id,
    get_storage,
    reset_storage_cache,
    validate_object_id,
)


# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------
def test_sha256_helpers_agree():
    import hashlib

    data = os.urandom(100_000)
    expected = hashlib.sha256(data).hexdigest()
    assert sha256_bytes(data) == expected
    assert sha256_stream(io.BytesIO(data), chunk_size=4096) == expected


def test_sha256_stream_is_incremental_and_upload_helper_rewinds():
    stream = io.BytesIO(b"payload")
    assert sha256_stream(stream) == sha256_bytes(b"payload")
    assert stream.tell() == len(b"payload")  # caller owns the cursor


def test_sha256_upload_handles_django_files():
    from django.core.files.uploadedfile import SimpleUploadedFile

    upload = SimpleUploadedFile("a.txt", b"hello world", content_type="text/plain")
    assert sha256_upload(upload) == sha256_bytes(b"hello world")
    # The helper must leave the upload readable for the caller.
    assert upload.read() == b"hello world"


# ---------------------------------------------------------------------------
# Object ids
# ---------------------------------------------------------------------------
def test_object_ids_are_random_hex_and_unique():
    ids = {generate_object_id() for _ in range(500)}
    assert len(ids) == 500
    for object_id in list(ids)[:20]:
        assert len(object_id) >= 32
        # URL-safe base64 alphabet, nothing that could traverse a path.
        assert all(char.isalnum() or char in "-_" for char in object_id)
        assert "/" not in object_id and "." not in object_id


@pytest.mark.parametrize(
    "bad",
    ["", "../../etc/passwd", "abc/def", "AB" * 40 + "/", "zz", "../..", "a b"],
)
def test_malicious_object_ids_are_rejected(bad):
    with pytest.raises(StorageError):
        validate_object_id(bad)


# ---------------------------------------------------------------------------
# Local encrypted storage
# ---------------------------------------------------------------------------
def test_storage_roundtrip_and_permissions(tmp_path):
    storage = LocalEncryptedStorage(tmp_path / "enc")
    object_id = storage.allocate_object_id()

    with storage.write(object_id) as handle:
        handle.write(b"ciphertext-bytes")

    assert storage.exists(object_id)
    with storage.open(object_id) as handle:
        assert handle.read() == b"ciphertext-bytes"
    assert storage.size(object_id) == len(b"ciphertext-bytes")

    path = storage._path_for(object_id)
    assert oct(path.stat().st_mode)[-3:] == "600"
    assert oct(path.parent.parent.parent.stat().st_mode)[-3:] == "700"


def test_storage_write_is_atomic_on_failure(tmp_path):
    storage = LocalEncryptedStorage(tmp_path / "enc")
    object_id = storage.allocate_object_id()

    with pytest.raises(RuntimeError), storage.write(object_id) as handle:
        handle.write(b"partial")
        raise RuntimeError("upload aborted")

    assert not storage.exists(object_id)
    # No temporary artefact is left behind either.
    leftovers = [p for p in (tmp_path / "enc").rglob("*") if p.is_file()]
    assert leftovers == []


def test_storage_delete_is_idempotent(tmp_path):
    storage = LocalEncryptedStorage(tmp_path / "enc")
    object_id = storage.allocate_object_id()
    with storage.write(object_id) as handle:
        handle.write(b"data")

    assert storage.delete(object_id) is True
    assert storage.delete(object_id) is False
    assert storage.exists(object_id) is False


def test_opening_a_missing_object_raises(tmp_path):
    storage = LocalEncryptedStorage(tmp_path / "enc")
    with pytest.raises(ObjectNotFound):
        storage.open(generate_object_id())


def test_storage_refuses_to_escape_its_root(tmp_path):
    storage = LocalEncryptedStorage(tmp_path / "enc")
    for hostile in ("../escape", "..%2f..%2fetc", "/etc/passwd"):
        with pytest.raises(StorageError):
            storage._path_for(hostile)


def test_get_storage_is_cached_and_resettable(settings, tmp_path):
    settings.ENCRYPTED_STORAGE_ROOT = tmp_path / "one"
    reset_storage_cache()
    first = get_storage()
    assert get_storage() is first

    settings.ENCRYPTED_STORAGE_ROOT = tmp_path / "two"
    reset_storage_cache()
    assert get_storage() is not first


# ---------------------------------------------------------------------------
# RSA key provider
# ---------------------------------------------------------------------------
def test_key_provider_exposes_only_what_is_needed(rsa_test_keys):
    provider = get_key_provider()
    assert provider.has_private_key is True
    assert provider.key_size >= 3072
    assert provider.active_key_id == public_key_fingerprint(provider.public_key)
    assert len(provider.active_key_id) == 32


def test_key_provider_rejects_a_missing_configuration(settings):
    settings.RSA_PRIVATE_KEY_PEM = ""
    settings.RSA_PUBLIC_KEY_PEM = ""
    settings.RSA_PRIVATE_KEY_PATH = "/nonexistent/private.pem"
    settings.RSA_PUBLIC_KEY_PATH = "/nonexistent/public.pem"
    reset_key_cache()
    with pytest.raises(KeyManagementError):
        get_key_provider()
    reset_key_cache()


def test_key_provider_rejects_a_weak_key(settings, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - deliberately weak: the provider must reject it
    path = tmp_path / "weak.pem"
    path.write_bytes(
        weak.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    settings.RSA_PRIVATE_KEY_PEM = ""
    settings.RSA_PRIVATE_KEY_PATH = str(path)
    reset_key_cache()
    with pytest.raises(KeyManagementError):
        get_key_provider()
    reset_key_cache()


def test_passphrase_protected_key_is_supported(settings, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    path = tmp_path / "protected.pem"
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"s3cret-pass"),
        )
    )
    settings.RSA_PRIVATE_KEY_PEM = ""
    settings.RSA_PRIVATE_KEY_PATH = str(path)
    settings.RSA_PRIVATE_KEY_PASSPHRASE = "s3cret-pass"
    reset_key_cache()

    provider = get_key_provider()
    assert provider.has_private_key

    # The wrong passphrase must fail closed.
    settings.RSA_PRIVATE_KEY_PASSPHRASE = "wrong"
    reset_key_cache()
    with pytest.raises(KeyManagementError):
        get_key_provider()
    reset_key_cache()


def test_retired_keys_can_still_unwrap_old_files(settings, tmp_path, rsa_test_keys):
    """Key rotation keeps previously wrapped DEKs readable."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from security.crypto import EnvelopeEncryptionService

    def write_key(name: str):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        path = tmp_path / name
        path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        return path

    old_path = write_key("old.pem")
    new_path = write_key("new.pem")

    settings.RSA_PRIVATE_KEY_PEM = ""
    settings.RSA_PRIVATE_KEY_PASSPHRASE = ""
    settings.RSA_PRIVATE_KEY_PATH = str(old_path)
    settings.RSA_RETIRED_PRIVATE_KEY_PATHS = []
    reset_key_cache()

    service = EnvelopeEncryptionService()
    dek = service.generate_file_key()
    wrapped, old_key_id = service.wrap_file_key(dek)

    # Rotate: the old key becomes a retired unwrap-only key.
    settings.RSA_PRIVATE_KEY_PATH = str(new_path)
    settings.RSA_RETIRED_PRIVATE_KEY_PATHS = [str(old_path)]
    reset_key_cache()

    rotated = EnvelopeEncryptionService()
    assert rotated.key_provider.active_key_id != old_key_id
    assert rotated.unwrap_file_key(wrapped, old_key_id) == dek  # still readable

    new_wrapped, new_key_id = rotated.wrap_file_key(dek)
    assert new_key_id == rotated.key_provider.active_key_id
    assert rotated.unwrap_file_key(new_wrapped, new_key_id) == dek

    settings.RSA_RETIRED_PRIVATE_KEY_PATHS = []
    reset_key_cache()


# ---------------------------------------------------------------------------
# Malware scanner plumbing
# ---------------------------------------------------------------------------
def test_scanner_is_skipped_when_disabled(settings):
    from security.scanning import ScanStatus, get_scanner, scan_upload

    settings.CLAMAV_ENABLED = False
    scanner = get_scanner()
    result = scan_upload(io.BytesIO(b"harmless"))
    assert result.status is ScanStatus.SKIPPED
    assert result.is_infected is False
    assert scanner is not None


def test_scanner_failure_is_fail_closed(settings, monkeypatch):
    """With CLAMAV_FAIL_CLOSED the upload is refused when the scanner is down."""
    from security import scanning
    from security.exceptions import MalwareScanError

    settings.CLAMAV_ENABLED = True
    settings.CLAMAV_FAIL_CLOSED = True

    class BrokenScanner(scanning.BaseScanner):
        def scan(self, stream):
            raise OSError("clamd unreachable")

    monkeypatch.setattr(scanning, "get_scanner", lambda: BrokenScanner())
    with pytest.raises(MalwareScanError):
        scanning.scan_upload(io.BytesIO(b"data"))


def test_scanner_failure_can_fail_open(settings, monkeypatch):
    from security import scanning

    settings.CLAMAV_ENABLED = True
    settings.CLAMAV_FAIL_CLOSED = False

    class BrokenScanner(scanning.BaseScanner):
        def scan(self, stream):
            raise OSError("clamd unreachable")

    monkeypatch.setattr(scanning, "get_scanner", lambda: BrokenScanner())
    result = scanning.scan_upload(io.BytesIO(b"data"))
    assert result.status is scanning.ScanStatus.ERROR


def test_shard_directories_are_not_world_readable(tmp_path):
    """Regression: shard dirs were created with the umask default (0755).

    The 0700 root already blocks traversal, but the whole ciphertext tree
    should stay private even if the service runs with a permissive umask.
    """
    import os
    import stat as stat_module

    previous = os.umask(0o022)  # the permissive umask that exposed the bug
    try:
        storage = LocalEncryptedStorage(root=tmp_path / "objects")
        object_id = generate_object_id()
        with storage.write(object_id) as handle:
            handle.write(b"ciphertext")

        path = storage._path_for(object_id)
        assert stat_module.S_IMODE(path.stat().st_mode) == 0o600

        directory = path.parent
        while directory != storage.root:
            mode = stat_module.S_IMODE(directory.stat().st_mode)
            assert mode == 0o700, f"{directory} is {oct(mode)}, expected 0o700"
            directory = directory.parent
        assert stat_module.S_IMODE(storage.root.stat().st_mode) == 0o700
    finally:
        os.umask(previous)


# ---------------------------------------------------------------------------
# Regression: relative paths in .env must not depend on the working directory
# ---------------------------------------------------------------------------
class TestEnvPathResolution:
    """`.env.example` ships values like ``./keys/rsa_private.pem``.

    Those were previously resolved against the process working directory, so
    the documented configuration worked when the server was started from the
    project root and silently failed (`No RSA key material configured`) when
    ``manage.py`` was run from ``backend/`` - the way the README tells you to
    run it. Relative values are now anchored to the project root.
    """

    def test_relative_value_is_anchored_to_the_given_root(self, monkeypatch, tmp_path):
        from config import env

        monkeypatch.setenv("SS_TEST_PATH", "./keys/rsa_private.pem")
        resolved = env.get_path("SS_TEST_PATH", tmp_path / "unused", relative_to=tmp_path)
        assert resolved == tmp_path / "keys" / "rsa_private.pem"
        assert resolved.is_absolute()

    def test_absolute_value_is_left_alone(self, monkeypatch, tmp_path):
        from config import env

        monkeypatch.setenv("SS_TEST_PATH", "/etc/secureshare/key.pem")
        resolved = env.get_path("SS_TEST_PATH", tmp_path, relative_to=tmp_path)
        assert resolved == Path("/etc/secureshare/key.pem")

    def test_resolution_does_not_depend_on_the_working_directory(
        self, monkeypatch, tmp_path
    ):
        from config import env

        monkeypatch.setenv("SS_TEST_PATH", "./storage/encrypted")
        monkeypatch.chdir(tmp_path)
        from_tmp = env.get_path("SS_TEST_PATH", tmp_path, relative_to=Path("/srv/app"))
        monkeypatch.chdir("/")
        from_root = env.get_path("SS_TEST_PATH", tmp_path, relative_to=Path("/srv/app"))
        assert from_tmp == from_root == Path("/srv/app/storage/encrypted")

    def test_unset_value_falls_back_to_the_default(self, monkeypatch, tmp_path):
        from config import env

        monkeypatch.delenv("SS_TEST_PATH", raising=False)
        assert env.get_path("SS_TEST_PATH", tmp_path / "d", relative_to=tmp_path) == tmp_path / "d"

    def test_blank_value_falls_back_to_the_default(self, monkeypatch, tmp_path):
        from config import env

        monkeypatch.setenv("SS_TEST_PATH", "   ")
        assert env.get_path("SS_TEST_PATH", tmp_path / "d", relative_to=tmp_path) == tmp_path / "d"

    def test_configured_key_and_storage_paths_are_absolute(self, settings):
        """Whatever the environment supplied, the live settings are absolute."""
        assert Path(settings.RSA_PRIVATE_KEY_PATH).is_absolute()
        assert Path(settings.RSA_PUBLIC_KEY_PATH).is_absolute()
        assert Path(settings.ENCRYPTED_STORAGE_ROOT).is_absolute()
        assert Path(settings.FILE_UPLOAD_TEMP_DIR).is_absolute()
        assert Path(settings.MEDIA_ROOT).is_absolute()
