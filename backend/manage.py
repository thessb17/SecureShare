#!/usr/bin/env python
"""Django management entry point for the SecureShare backend."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    backend_dir = Path(__file__).resolve().parent
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:  # pragma: no cover - defensive
        raise ImportError(
            "Could not import Django. Activate the virtualenv and install "
            "backend/requirements.txt first."
        ) from exc

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
