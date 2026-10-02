"""Optional ClamAV malware scanning.

Honesty rule: when ClamAV is disabled or unreachable the file is recorded as
``SKIPPED``/``ERROR`` - never as ``CLEAN``. The API and the audit trail report
the real scanner state so nobody can believe a file was scanned when it was not.

``CLAMAV_FAIL_CLOSED=true`` (default) rejects uploads when scanning is enabled
but the daemon cannot be reached.
"""
from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass
from enum import StrEnum
from typing import BinaryIO, Final

from django.conf import settings

from security.exceptions import MalwareScanError

logger = logging.getLogger("secureshare.security")

INSTREAM_CHUNK: Final[int] = 65536


class ScanStatus(StrEnum):
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"
    NOT_SCANNED = "NOT_SCANNED"


@dataclass(frozen=True)
class ScanResult:
    status: ScanStatus
    scanned: bool
    signature: str = ""
    detail: str = ""

    @property
    def is_infected(self) -> bool:
        return self.status is ScanStatus.INFECTED


class BaseScanner:
    name = "base"

    def scan(self, stream: BinaryIO) -> ScanResult:  # pragma: no cover - interface
        raise NotImplementedError


class DisabledScanner(BaseScanner):
    """Used when ``CLAMAV_ENABLED=false``."""

    name = "disabled"

    def scan(self, stream: BinaryIO) -> ScanResult:
        return ScanResult(
            status=ScanStatus.SKIPPED,
            scanned=False,
            detail="Malware scanning is disabled (CLAMAV_ENABLED=false).",
        )


class ClamAVScanner(BaseScanner):
    """clamd INSTREAM client (no third-party dependency)."""

    name = "clamav"

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        timeout: int | None = None,
    ) -> None:
        self.host = host or settings.CLAMAV_HOST
        self.port = int(port or settings.CLAMAV_PORT)
        self.timeout = int(timeout or settings.CLAMAV_TIMEOUT_SECONDS)

    def ping(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                sock.sendall(b"zPING\0")
                return sock.recv(64).strip(b"\0") == b"PONG"
        except OSError:
            return False

    def scan(self, stream: BinaryIO) -> ScanResult:
        stream.seek(0)
        try:
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(b"zINSTREAM\0")
                while True:
                    chunk = stream.read(INSTREAM_CHUNK)
                    if not chunk:
                        break
                    sock.sendall(struct.pack(">I", len(chunk)) + chunk)
                sock.sendall(struct.pack(">I", 0))
                response = self._read_response(sock)
        except OSError as exc:
            raise MalwareScanError("The malware scanner is unreachable.") from exc
        finally:
            stream.seek(0)

        if response.endswith("OK"):
            return ScanResult(status=ScanStatus.CLEAN, scanned=True, detail=response)
        if "FOUND" in response:
            signature = response.split(":", 1)[-1].replace("FOUND", "").strip()
            return ScanResult(
                status=ScanStatus.INFECTED,
                scanned=True,
                signature=signature,
                detail=response,
            )
        raise MalwareScanError(f"Unexpected scanner response: {response}")

    @staticmethod
    def _read_response(sock: socket.socket) -> str:
        buffer = b""
        while b"\0" not in buffer:
            data = sock.recv(4096)
            if not data:
                break
            buffer += data
        return buffer.strip(b"\0").decode("utf-8", "replace").strip()


def get_scanner() -> BaseScanner:
    if getattr(settings, "CLAMAV_ENABLED", False):
        return ClamAVScanner()
    return DisabledScanner()


def scan_upload(stream: BinaryIO) -> ScanResult:
    """Scan an upload, honouring the fail-open/fail-closed policy."""
    scanner = get_scanner()
    try:
        return scanner.scan(stream)
    except MalwareScanError as exc:
        if getattr(settings, "CLAMAV_FAIL_CLOSED", True):
            raise
        logger.warning("Malware scan failed; failing open per configuration")
        return ScanResult(
            status=ScanStatus.ERROR,
            scanned=False,
            detail=str(exc),
        )
    except Exception as exc:
        # Any unexpected transport/runtime error is treated exactly like a
        # scanner failure so the fail-closed policy cannot be bypassed by an
        # exception type nobody anticipated.
        logger.exception("Malware scanner raised an unexpected error")
        if getattr(settings, "CLAMAV_FAIL_CLOSED", True):
            raise MalwareScanError("The malware scanner is unavailable.") from exc
        return ScanResult(
            status=ScanStatus.ERROR, scanned=False, detail="scanner error"
        )
