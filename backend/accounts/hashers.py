"""Password hashers.

Production uses ``django.contrib.auth.hashers.Argon2PasswordHasher`` (Argon2id)
with Django's defaults. The subclass below only lowers the cost parameters for
the test-suite so the real algorithm is still exercised at a practical speed.
"""
from __future__ import annotations

from django.contrib.auth.hashers import Argon2PasswordHasher


class TestArgon2PasswordHasher(Argon2PasswordHasher):
    """Argon2id with reduced cost - **test settings only**."""

    algorithm = "argon2"
    time_cost = 1
    memory_cost = 8192  # 8 MiB
    parallelism = 1
