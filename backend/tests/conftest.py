"""Shared pytest fixtures for the SecureShare backend test-suite."""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Callable

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient

User = get_user_model()

STRONG_PASSWORD = "Str0ng!Passphrase#2026"
OTHER_PASSWORD = "An0ther!Passphrase#2026"
SHARE_PASSWORD = "Sh4re-Link!Secret"


# ---------------------------------------------------------------------------
# Test data builders
# ---------------------------------------------------------------------------
def build_pdf(text: str = "SecureShare encrypted demo document") -> bytes:
    """Return a small but structurally valid PDF (correct xref offsets)."""
    content = f"BT /F1 18 Tf 20 100 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"
        ),
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for index, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_offset = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode()
    return bytes(out)


PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)

EICAR_TEST_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode()


def upload_file(name: str, content: bytes, content_type: str = "application/pdf"):
    return SimpleUploadedFile(name, content, content_type=content_type)


# ---------------------------------------------------------------------------
# Environment fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def rsa_test_keys(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Guarantee usable RSA key material for the whole session.

    Uses the configured key files when they exist (mirrors a real deployment),
    otherwise generates an ephemeral 3072-bit pair in a temp directory so the
    suite runs anywhere, including CI.
    """
    from security.keys import reset_key_cache

    configured = Path(settings.RSA_PRIVATE_KEY_PATH or "")
    if settings.RSA_PRIVATE_KEY_PEM or configured.is_file():
        reset_key_cache()
        return

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key_dir = tmp_path_factory.mktemp("rsa-keys")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_path = key_dir / "rsa_private.pem"
    public_path = key_dir / "rsa_public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    settings.RSA_PRIVATE_KEY_PATH = str(private_path)
    settings.RSA_PUBLIC_KEY_PATH = str(public_path)
    reset_key_cache()


@pytest.fixture(autouse=True)
def clear_cache_between_tests():
    """Throttle counters and share-link lockouts must not leak across tests."""
    cache.clear()
    yield
    cache.clear()


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, settings):
    """Give every test its own encrypted-object storage root."""
    from security.storage import reset_storage_cache

    root = tmp_path / "encrypted"
    root.mkdir(parents=True, exist_ok=True)
    settings.ENCRYPTED_STORAGE_ROOT = root
    reset_storage_cache()
    yield root
    reset_storage_cache()


# ---------------------------------------------------------------------------
# Users and clients
# ---------------------------------------------------------------------------
@pytest.fixture
def throttle_rates(monkeypatch) -> Callable[[dict[str, str]], None]:
    """Temporarily set DRF throttle rates for the current test.

    ``override_settings(REST_FRAMEWORK=...)`` does **not** work for throttles:
    ``SimpleRateThrottle.THROTTLE_RATES`` is bound to the settings dict at
    import time, so the class attribute has to be patched instead.
    """

    def _apply(rates: dict[str, str]) -> None:
        from rest_framework.throttling import SimpleRateThrottle

        patched = dict(SimpleRateThrottle.THROTTLE_RATES)
        patched.update(rates)
        monkeypatch.setattr(SimpleRateThrottle, "THROTTLE_RATES", patched)

    return _apply


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


@pytest.fixture
def make_user(db) -> Callable[..., Any]:
    def _make(email: str, password: str = STRONG_PASSWORD, **extra: Any):
        role = extra.pop("role", "USER")
        return User.objects.create_user(
            email=email, password=password, role=role, **extra
        )

    return _make


@pytest.fixture
def user_a(make_user):
    return make_user("alice@example.com")


@pytest.fixture
def user_b(make_user):
    return make_user("bob@example.com")


@pytest.fixture
def user_c(make_user):
    return make_user("carol@example.com")


@pytest.fixture
def admin_user(make_user):
    return make_user("admin@example.com", role="ADMIN", is_staff=True)


@pytest.fixture
def authenticate() -> Callable[[APIClient, Any], APIClient]:
    """Attach a valid JWT for ``user`` to ``client``."""

    def _authenticate(client: APIClient, user: Any) -> APIClient:
        from accounts.tokens import create_tokens_for_user

        tokens = create_tokens_for_user(user)
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        return client

    return _authenticate


@pytest.fixture
def client_a(user_a, authenticate) -> APIClient:
    # A dedicated client instance: the ``api_client`` fixture must stay
    # anonymous so tests can assert on unauthenticated access.
    return authenticate(APIClient(), user_a)


@pytest.fixture
def client_b(user_b, authenticate) -> APIClient:
    return authenticate(APIClient(), user_b)


@pytest.fixture
def client_c(user_c, authenticate) -> APIClient:
    return authenticate(APIClient(), user_c)


@pytest.fixture
def admin_client(admin_user, authenticate) -> APIClient:
    return authenticate(APIClient(), admin_user)


@pytest.fixture
def anonymous_client() -> APIClient:
    return APIClient()


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
@pytest.fixture
def pdf_bytes() -> bytes:
    return build_pdf()


@pytest.fixture
def uploaded_pdf(client_a, pdf_bytes):
    """Upload a PDF as user A through the real API and return the response body."""
    response = client_a.post(
        "/api/files/upload/",
        {"file": upload_file("report.pdf", pdf_bytes)},
        format="multipart",
    )
    assert response.status_code == 201, response.data
    return response.data


@pytest.fixture
def file_a(uploaded_pdf):
    from files.models import File

    return File.objects.get(pk=uploaded_pdf["id"])


@pytest.fixture
def make_file():
    """Create an encrypted file for an arbitrary owner (service layer)."""

    def _make(owner: Any, name: str = "document.pdf", content: bytes | None = None):
        from files.services import get_file_service

        payload = content if content is not None else build_pdf(f"file for {owner.email}")
        return get_file_service().upload(
            owner=owner, uploaded_file=upload_file(name, payload), request=None
        )

    return _make


# ---------------------------------------------------------------------------
# Share links (Phase 6)
# ---------------------------------------------------------------------------
@pytest.fixture
def create_share_link(client_a):
    """Create a public share link through the API; returns (payload, token)."""

    def _create(file_id: Any, **body: Any):
        response = client_a.post(
            f"/api/files/{file_id}/share-link/", body, format="json"
        )
        assert response.status_code == 201, response.data
        return response.data, response.data["token"]

    return _create
