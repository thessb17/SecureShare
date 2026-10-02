#!/usr/bin/env python3
"""Generate the RSA key pair used to wrap per-file AES data encryption keys.

    python scripts/generate_keys.py                    # 3072-bit, ./keys/
    python scripts/generate_keys.py --key-size 4096
    python scripts/generate_keys.py --passphrase-env RSA_PRIVATE_KEY_PASSPHRASE
    python scripts/generate_keys.py --force            # rotate (see --help)

Security notes
--------------
* The private key is written with 0600 permissions into a directory that is
  listed in .gitignore - **never commit it**.
* Nothing is printed except the public-key fingerprint; key material is never
  echoed to stdout or to a log.
* For production use a KMS/HSM (AWS KMS, Azure Key Vault, HashiCorp Vault,
  PKCS#11) instead of a file on disk; see SECURITY.md -> "Key management".
* Rotation: generate a new pair, move the previous private key path into
  RSA_RETIRED_PRIVATE_KEY_PATHS so existing wrapped DEKs stay unwrappable, and
  restart the application. New uploads are wrapped with the new key.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "The 'cryptography' package is required: pip install cryptography\n"
    )
    raise SystemExit(2)

DEFAULT_KEY_SIZE = 3072
MIN_KEY_SIZE = 2048


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:32]


def generate(
    out_dir: Path, key_size: int, passphrase: str | None, force: bool
) -> tuple[Path, Path, str]:
    private_path = out_dir / "rsa_private.pem"
    public_path = out_dir / "rsa_public.pem"

    if (private_path.exists() or public_path.exists()) and not force:
        raise SystemExit(
            f"Refusing to overwrite existing keys in {out_dir}. "
            "Use --force only when you intend to rotate (keep the old private "
            "key in RSA_RETIRED_PRIVATE_KEY_PATHS so existing files stay "
            "readable)."
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase.encode())

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Create with restrictive permissions from the start (no race window).
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private_pem)
    public_path.write_bytes(public_pem)
    os.chmod(public_path, 0o644)

    return private_path, public_path, fingerprint(private_key.public_key())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--out-dir",
        default=str(Path(__file__).resolve().parents[1] / "keys"),
        help="Directory for rsa_private.pem / rsa_public.pem (default: ./keys)",
    )
    parser.add_argument("--key-size", type=int, default=DEFAULT_KEY_SIZE)
    parser.add_argument(
        "--passphrase-env",
        default=None,
        help="Name of an environment variable holding the private key passphrase.",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite existing keys.")
    args = parser.parse_args()

    if args.key_size < MIN_KEY_SIZE:
        parser.error(f"--key-size must be at least {MIN_KEY_SIZE}")

    passphrase = os.environ.get(args.passphrase_env) if args.passphrase_env else None
    if args.passphrase_env and not passphrase:
        parser.error(f"Environment variable {args.passphrase_env} is empty.")

    private_path, public_path, key_id = generate(
        Path(args.out_dir), args.key_size, passphrase, args.force
    )

    print("RSA key pair generated")
    print(f"  private key : {private_path} (mode 0600, never commit this)")
    print(f"  public key  : {public_path}")
    print(f"  key size    : {args.key_size} bits")
    print(f"  key id      : {key_id}")
    print(f"  encrypted   : {'yes' if passphrase else 'no'}")
    print()
    print("Add to your .env:")
    print(f"  RSA_PRIVATE_KEY_PATH={private_path}")
    print(f"  RSA_PUBLIC_KEY_PATH={public_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
