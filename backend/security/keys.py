"""RSA key management for DEK wrapping.

Key material is **never** hard-coded and never returned through the API. It is
loaded from one of (in order of precedence):

1. ``RSA_PRIVATE_KEY_PEM`` / ``RSA_PUBLIC_KEY_PEM`` environment variables -
   how a secret manager (AWS Secrets Manager, Vault, Azure Key Vault) would
   inject the key at runtime.
2. ``RSA_PRIVATE_KEY_PATH`` / ``RSA_PUBLIC_KEY_PATH`` files mounted with 0600
   permissions (Docker secrets / Kubernetes secret volumes).

Rotation: every wrapped DEK records the ``key_id`` (SHA-256 fingerprint of the
public key) used to wrap it. Retired private keys listed in
``RSA_RETIRED_PRIVATE_KEY_PATHS`` stay loadable for unwrapping while new files
are wrapped with the active key only.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings

from security.exceptions import KeyManagementError

logger = logging.getLogger("secureshare.security")

#: Smallest RSA modulus accepted. 3072 bits is the project default.
MIN_RSA_KEY_SIZE: Final[int] = 2048
RECOMMENDED_RSA_KEY_SIZE: Final[int] = 3072


def public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """Stable, non-secret identifier for a public key (SHA-256 of the DER SPKI)."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:32]


@dataclass(frozen=True)
class RSAKeyProvider:
    """Holds the active key pair plus any retired keys used for unwrapping."""

    public_key: rsa.RSAPublicKey
    active_key_id: str
    _private_keys: dict[str, rsa.RSAPrivateKey]

    # -- loading -----------------------------------------------------------
    @classmethod
    def from_settings(cls) -> "RSAKeyProvider":
        private_pem = _read_private_source()
        passphrase = getattr(settings, "RSA_PRIVATE_KEY_PASSPHRASE", "") or None

        private_keys: dict[str, rsa.RSAPrivateKey] = {}
        public_key: rsa.RSAPublicKey | None = None
        active_key_id: str | None = None

        if private_pem:
            private_key = _load_private_key(private_pem, passphrase)
            public_key = private_key.public_key()
            active_key_id = public_key_fingerprint(public_key)
            private_keys[active_key_id] = private_key

        if public_key is None:
            public_pem = _read_public_source()
            if not public_pem:
                raise KeyManagementError(
                    "No RSA key material configured. Run scripts/generate_keys.py "
                    "and set RSA_PRIVATE_KEY_PATH / RSA_PUBLIC_KEY_PATH."
                )
            public_key = _load_public_key(public_pem)
            active_key_id = public_key_fingerprint(public_key)

        for retired_path in getattr(settings, "RSA_RETIRED_PRIVATE_KEY_PATHS", []):
            pem = _read_file(Path(retired_path))
            if not pem:
                logger.warning("Retired RSA key path is unreadable", extra={
                    "key_path_configured": True
                })
                continue
            retired = _load_private_key(pem, passphrase)
            private_keys[public_key_fingerprint(retired.public_key())] = retired

        assert active_key_id is not None  # nosec B101 - guarded above
        return cls(
            public_key=public_key,
            active_key_id=active_key_id,
            _private_keys=private_keys,
        )

    # -- access ------------------------------------------------------------
    def private_key(self, key_id: str | None = None) -> rsa.RSAPrivateKey:
        """Return the private key able to unwrap a DEK wrapped with ``key_id``."""
        if not self._private_keys:
            raise KeyManagementError(
                "No RSA private key is available to this process."
            )
        if key_id:
            key = self._private_keys.get(key_id)
            if key is None:
                raise KeyManagementError(
                    "No private key matching the requested key id is configured."
                )
            return key
        return self._private_keys[self.active_key_id]

    @property
    def has_private_key(self) -> bool:
        return bool(self._private_keys)

    @property
    def key_size(self) -> int:
        return self.public_key.key_size


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------
def _read_file(path: Path) -> bytes | None:
    try:
        if path.is_file():
            return path.read_bytes()
    except OSError:
        logger.warning("Unable to read RSA key file", exc_info=False)
    return None


def _read_private_source() -> bytes | None:
    inline = getattr(settings, "RSA_PRIVATE_KEY_PEM", "")
    if inline:
        return inline.encode() if isinstance(inline, str) else inline
    path = getattr(settings, "RSA_PRIVATE_KEY_PATH", "")
    return _read_file(Path(path)) if path else None


def _read_public_source() -> bytes | None:
    inline = getattr(settings, "RSA_PUBLIC_KEY_PEM", "")
    if inline:
        return inline.encode() if isinstance(inline, str) else inline
    path = getattr(settings, "RSA_PUBLIC_KEY_PATH", "")
    return _read_file(Path(path)) if path else None


def _load_private_key(pem: bytes, passphrase: str | None) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(
            pem, password=passphrase.encode() if passphrase else None
        )
    except Exception as exc:
        raise KeyManagementError("RSA private key could not be loaded.") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyManagementError("Configured private key is not an RSA key.")
    _validate_key_size(key.key_size)
    return key


def _load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem)
    except Exception as exc:
        raise KeyManagementError("RSA public key could not be loaded.") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyManagementError("Configured public key is not an RSA key.")
    _validate_key_size(key.key_size)
    return key


def _validate_key_size(size: int) -> None:
    if size < MIN_RSA_KEY_SIZE:
        raise KeyManagementError(
            f"RSA key size {size} is below the {MIN_RSA_KEY_SIZE}-bit minimum."
        )


# ---------------------------------------------------------------------------
# Process level cache (keyed on the configured source so tests stay isolated)
# ---------------------------------------------------------------------------
_PROVIDER_CACHE: dict[str, RSAKeyProvider] = {}


def _cache_key() -> str:
    parts = [
        str(getattr(settings, "RSA_PRIVATE_KEY_PEM", "") or "")[:64],
        str(getattr(settings, "RSA_PUBLIC_KEY_PEM", "") or "")[:64],
        str(getattr(settings, "RSA_PRIVATE_KEY_PATH", "") or ""),
        str(getattr(settings, "RSA_PUBLIC_KEY_PATH", "") or ""),
        ",".join(getattr(settings, "RSA_RETIRED_PRIVATE_KEY_PATHS", [])),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def get_key_provider() -> RSAKeyProvider:
    """Return the cached :class:`RSAKeyProvider` for the current configuration."""
    key = _cache_key()
    provider = _PROVIDER_CACHE.get(key)
    if provider is None:
        provider = RSAKeyProvider.from_settings()
        _PROVIDER_CACHE[key] = provider
        logger.info(
            "RSA key material loaded",
            extra={
                "key_id": provider.active_key_id,
                "key_size": provider.key_size,
                "has_private_key": provider.has_private_key,
            },
        )
    return provider


def reset_key_cache() -> None:
    """Clear the provider cache (used by tests and key-rotation tooling)."""
    _PROVIDER_CACHE.clear()
