# `keys/` — RSA key material

**This directory is intentionally empty in the repository.**

SecureShare uses envelope encryption. Every uploaded file gets its own random
AES-256-GCM data encryption key (DEK); that DEK is then wrapped with an
RSA-OAEP-SHA256 public key and stored alongside the ciphertext. The matching
private key is the only thing that can unwrap it.

No private key is distributed with this project, and none ever should be.
Anyone holding `rsa_private.pem` can decrypt every file in the store.

---

## Generate your own pair

From the project root, after installing the backend requirements:

```bash
python scripts/generate_keys.py
```

That writes:

| File | Mode | Purpose |
|---|---|---|
| `keys/rsa_private.pem` | `0600` | Unwraps DEKs on download. **Never commit. Never transmit. Never log.** |
| `keys/rsa_public.pem` | `0644` | Wraps a DEK on upload. Not secret. |

The directory itself is created `0700`. The script prints a short public-key
fingerprint (the "key id") and **never** prints key material.

Default size is 3072 bits. For a stronger key:

```bash
python scripts/generate_keys.py --key-size 4096
```

To encrypt the private key at rest with a passphrase:

```bash
export RSA_PRIVATE_KEY_PASSPHRASE='…'
python scripts/generate_keys.py --passphrase-env RSA_PRIVATE_KEY_PASSPHRASE
```

Then set the same variable in your environment so the app can open the key.

## Point the application at the keys

`.env` (copied from `.env.example`) already contains the default paths:

```ini
RSA_PRIVATE_KEY_PATH=./keys/rsa_private.pem
RSA_PUBLIC_KEY_PATH=./keys/rsa_public.pem
```

Alternatively supply the PEM inline from a secret manager, which is preferable
in production because nothing touches the container filesystem:

```ini
# The full PEM contents on one line, newlines escaped as \n.
# (Written without a literal PEM header here so that repository secret
#  scanners do not flag this documentation as a leaked key.)
RSA_PRIVATE_KEY_PEM="<entire contents of rsa_private.pem>"
```

---

## Rotation

Generating a new pair does **not** re-wrap existing files — their DEKs are
still sealed to the old public key. To rotate without losing access:

1. Move the current private key aside, e.g. `keys/rsa_private.2026.pem`.
2. Generate a new pair: `python scripts/generate_keys.py --force`.
3. Keep the old key readable so historical files still open:
   ```ini
   RSA_RETIRED_PRIVATE_KEY_PATHS=./keys/rsa_private.2026.pem
   ```
4. Restart the application. New uploads are wrapped with the new key; old ones
   continue to unwrap with the retired key.

Retire a key only once nothing references it. Deleting a private key that
still has wrapped DEKs pointing at it **permanently destroys those files.**

---

## Production

A PEM on a disk is adequate for development and for this project's scope. It
is not what you should run in production. Prefer a KMS or HSM — AWS KMS, Azure
Key Vault, Google Cloud KMS, HashiCorp Vault, or a PKCS#11 device — so the
private key never exists as a readable file. See `SECURITY.md` → *Key
management* and `docs/DEPLOYMENT.md` → *Backup and recovery*.

**Back up the private key separately from the database and the encrypted
object store, and verify the backup.** The three together are what make a
restore possible:

- encrypted objects without the private key → unrecoverable ciphertext
- private key without the database → no file metadata or wrapped DEKs
- database without the private key → wrapped DEKs that cannot be opened

There is no recovery path if the private key is lost. That is a property of
the design, not a defect.
