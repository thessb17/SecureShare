"""Phase 6: public share links - functional behaviour.

Covers creation, token handling, metadata access, download, expiry presets,
download limits, revocation and password protection through the real HTTP API.
"""
from __future__ import annotations

import re
from datetime import timedelta

import pytest
from django.conf import settings
from django.utils import timezone

from audit.constants import AuditAction
from audit.models import AuditLog
from sharing.link_services import hash_token
from sharing.models import ShareLink
from tests.conftest import SHARE_PASSWORD

pytestmark = pytest.mark.django_db


def public_get(client, token, **headers):
    return client.get(f"/api/share/{token}/", **headers)


def public_download(client, token, data=None, **headers):
    return client.post(f"/api/share/{token}/download/", data or {}, format="json", **headers)


def body_of(response) -> bytes:
    if getattr(response, "streaming", False):
        return b"".join(response.streaming_content)
    return response.content


# ===========================================================================
# Creation
# ===========================================================================
def test_owner_can_create_a_share_link(client_a, file_a):
    response = client_a.post(f"/api/files/{file_a.id}/share-link/", {}, format="json")
    assert response.status_code == 201, response.data

    data = response.data
    assert data["token"]
    assert data["url"].endswith(data["token"])
    assert data["permission"] == "DOWNLOAD"
    assert data["expires_at"] is not None
    assert "warning" in data
    assert data["share_link"]["password_protected"] is False
    assert data["share_link"]["download_count"] == 0


def test_share_link_creation_requires_authentication(api_client, file_a):
    response = api_client.post(f"/api/files/{file_a.id}/share-link/", {}, format="json")
    assert response.status_code == 401


def test_only_the_owner_can_create_a_share_link(client_b, client_a, file_a, user_b):
    # Even a user who has the file shared with them cannot mint a public link.
    client_a.post(
        f"/api/files/{file_a.id}/share/",
        {"recipient": user_b.email, "permission": "DOWNLOAD"},
        format="json",
    )
    response = client_b.post(f"/api/files/{file_a.id}/share-link/", {}, format="json")
    assert response.status_code == 403
    assert response.data["error"] == "ACCESS_DENIED"
    assert ShareLink.objects.count() == 0


def test_token_is_high_entropy_and_url_safe(create_share_link, file_a):
    _, token = create_share_link(file_a.id)
    assert re.fullmatch(r"[A-Za-z0-9_-]+", token)
    # 32 random bytes -> 43 base64url characters -> 256 bits of entropy.
    assert len(token) >= 43
    assert settings.SHARE_LINK_TOKEN_BYTES >= 32


def test_only_the_token_hash_is_stored(create_share_link, file_a):
    payload, token = create_share_link(file_a.id)
    link = ShareLink.objects.get(pk=payload["share_link"]["id"])
    assert link.token_hash == hash_token(token)
    assert token not in link.token_hash
    assert link.token_prefix == link.token_hash[:12]
    # The raw token appears nowhere in the database row.
    row = str(link.__dict__)
    assert token not in row


def test_tokens_are_unique_across_links(client_a, file_a):
    tokens = set()
    for _ in range(10):
        response = client_a.post(f"/api/files/{file_a.id}/share-link/", {}, format="json")
        tokens.add(response.data["token"])
    assert len(tokens) == 10


def test_token_is_not_derived_from_the_file_or_user(create_share_link, file_a, user_a):
    _, token = create_share_link(file_a.id)
    assert str(file_a.id) not in token
    assert str(user_a.pk) not in token
    assert user_a.email.split("@")[0] not in token
    assert str(int(timezone.now().timestamp()))[:6] not in token


def test_token_is_never_returned_again_after_creation(client_a, create_share_link, file_a):
    payload, token = create_share_link(file_a.id)
    link_id = payload["share_link"]["id"]

    detail = client_a.get(f"/api/share-links/{link_id}/")
    assert detail.status_code == 200
    assert token not in str(detail.data)
    assert "token" not in detail.data
    assert detail.data["token_prefix"] == hash_token(token)[:12]

    listing = client_a.get("/api/share-links/")
    assert token not in str(listing.data)


def test_share_link_response_never_exposes_storage_internals(create_share_link, file_a):
    payload, _ = create_share_link(file_a.id)
    serialized = str(payload)
    for forbidden in ("stored_object_id", "wrapped_dek", "token_hash", "password_hash",
                      "/storage/", "nonce"):
        assert forbidden not in serialized


def test_creation_is_audited_without_the_raw_token(create_share_link, file_a):
    _payload, token = create_share_link(file_a.id)
    event = AuditLog.objects.filter(action=AuditAction.SHARE_LINK_CREATED).first()
    assert event is not None
    assert token not in str(event.metadata)
    assert token not in (event.message or "")
    assert event.metadata["token_prefix"] == hash_token(token)[:12]


# ===========================================================================
# Expiration presets
# ===========================================================================
@pytest.mark.parametrize(
    "preset,seconds",
    [("1h", 3600), ("6h", 21600), ("24h", 86400), ("3d", 259200), ("7d", 604800)],
)
def test_expiry_presets_are_applied_by_the_backend(client_a, file_a, preset, seconds):
    before = timezone.now()
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"expires_in": preset}, format="json"
    )
    assert response.status_code == 201
    link = ShareLink.objects.get(pk=response.data["share_link"]["id"])
    delta = link.expires_at - before
    assert timedelta(seconds=seconds - 60) <= delta <= timedelta(seconds=seconds + 60)


def test_custom_expiry_is_accepted(client_a, file_a):
    target = timezone.now() + timedelta(hours=10)
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/",
        {"expires_in": "custom", "expires_at": target.isoformat()},
        format="json",
    )
    assert response.status_code == 201
    link = ShareLink.objects.get(pk=response.data["share_link"]["id"])
    assert abs((link.expires_at - target).total_seconds()) < 2


def test_custom_expiry_requires_a_value(client_a, file_a):
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"expires_in": "custom"}, format="json"
    )
    assert response.status_code == 400


def test_expiry_in_the_past_is_rejected(client_a, file_a):
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/",
        {
            "expires_in": "custom",
            "expires_at": (timezone.now() - timedelta(minutes=1)).isoformat(),
        },
        format="json",
    )
    assert response.status_code == 400


def test_expiry_beyond_the_maximum_is_rejected(client_a, file_a):
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/",
        {
            "expires_in": "custom",
            "expires_at": (timezone.now() + timedelta(days=400)).isoformat(),
        },
        format="json",
    )
    assert response.status_code == 400


def test_links_cannot_be_created_without_an_expiry(client_a, file_a):
    """A link with no expiry at all is refused; the default TTL applies."""
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"expires_in": "never"}, format="json"
    )
    assert response.status_code == 400

    default = client_a.post(f"/api/files/{file_a.id}/share-link/", {}, format="json")
    link = ShareLink.objects.get(pk=default.data["share_link"]["id"])
    assert link.expires_at is not None


# ===========================================================================
# Download limit configuration
# ===========================================================================
@pytest.mark.parametrize("limit", [1, 5, 10, 37])
def test_download_limit_presets_are_stored(client_a, file_a, limit):
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"max_downloads": limit}, format="json"
    )
    assert response.status_code == 201
    assert response.data["max_downloads"] == limit
    assert response.data["share_link"]["downloads_remaining"] == limit


def test_unlimited_downloads_when_no_limit_is_given(create_share_link, file_a):
    payload, _ = create_share_link(file_a.id)
    assert payload["max_downloads"] is None
    assert payload["share_link"]["downloads_remaining"] is None


def test_download_limit_must_be_positive(client_a, file_a):
    assert client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"max_downloads": 0}, format="json"
    ).status_code == 400
    assert client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"max_downloads": -5}, format="json"
    ).status_code == 400


def test_download_limit_cap_is_enforced(client_a, file_a, settings):
    settings.SHARE_LINK_MAX_DOWNLOADS_CAP = 10
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"max_downloads": 11}, format="json"
    )
    assert response.status_code == 400


# ===========================================================================
# Anonymous metadata access
# ===========================================================================
def test_anonymous_visitor_can_read_link_metadata(anonymous_client, create_share_link,
                                                  file_a, pdf_bytes):
    _, token = create_share_link(file_a.id)
    response = public_get(anonymous_client, token)
    assert response.status_code == 200
    assert response.data["filename"] == "report.pdf"
    assert response.data["size"] == len(pdf_bytes)
    assert response.data["permission"] == "DOWNLOAD"
    assert response.data["password_required"] is False
    assert response.data["encryption"]["encrypted"] is True


def test_metadata_never_exposes_internal_identifiers(anonymous_client, create_share_link,
                                                     file_a):
    _, token = create_share_link(file_a.id)
    body = str(public_get(anonymous_client, token).data)
    for forbidden in ("stored_object_id", "owner", "file_id", "/storage/",
                      str(file_a.stored_object_id)):
        assert forbidden not in body


def test_metadata_access_is_audited(anonymous_client, create_share_link, file_a):
    _, token = create_share_link(file_a.id)
    public_get(anonymous_client, token)
    event = AuditLog.objects.filter(action=AuditAction.SHARE_LINK_ACCESSED).first()
    assert event is not None
    assert token not in str(event.metadata)


def test_access_count_is_tracked(anonymous_client, create_share_link, file_a):
    payload, token = create_share_link(file_a.id)
    public_get(anonymous_client, token)
    public_get(anonymous_client, token)
    link = ShareLink.objects.get(pk=payload["share_link"]["id"])
    assert link.access_count == 2
    assert link.last_accessed_at is not None


# ===========================================================================
# Anonymous download
# ===========================================================================
def test_anonymous_visitor_can_download_through_the_link(anonymous_client,
                                                         create_share_link, file_a,
                                                         pdf_bytes):
    payload, token = create_share_link(file_a.id)
    response = public_download(anonymous_client, token)
    assert response.status_code == 200
    assert body_of(response) == pdf_bytes
    assert 'attachment; filename="report.pdf"' in response["Content-Disposition"]
    assert response["X-Content-Type-Options"] == "nosniff"

    link = ShareLink.objects.get(pk=payload["share_link"]["id"])
    assert link.download_count == 1
    assert link.last_downloaded_at is not None
    assert AuditLog.objects.filter(action=AuditAction.SHARE_LINK_DOWNLOAD).exists()


def test_download_is_audited_without_the_raw_token(anonymous_client, create_share_link,
                                                   file_a):
    _, token = create_share_link(file_a.id)
    public_download(anonymous_client, token)
    event = AuditLog.objects.filter(action=AuditAction.SHARE_LINK_DOWNLOAD).first()
    assert token not in str(event.metadata)
    assert token not in (event.message or "")


def test_view_only_link_cannot_be_downloaded(anonymous_client, client_a, file_a):
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"permission": "VIEW"}, format="json"
    )
    token = response.data["token"]

    assert public_get(anonymous_client, token).status_code == 200
    download = public_download(anonymous_client, token)
    assert download.status_code == 403
    assert download.data["error"] == "SHARE_PERMISSION_DENIED"
    assert AuditLog.objects.filter(
        action=AuditAction.UNAUTHORIZED_SHARE_ACCESS
    ).exists()


def test_download_get_method_is_not_allowed(anonymous_client, create_share_link, file_a):
    _, token = create_share_link(file_a.id)
    assert anonymous_client.get(f"/api/share/{token}/download/").status_code == 405


def test_remaining_downloads_header_is_returned(anonymous_client, create_share_link,
                                                file_a):
    _, token = create_share_link(file_a.id, max_downloads=3)
    first = public_download(anonymous_client, token)
    assert first["X-Share-Downloads-Remaining"] == "2"
    second = public_download(anonymous_client, token)
    assert second["X-Share-Downloads-Remaining"] == "1"


def test_unlimited_link_reports_unlimited_remaining(anonymous_client, create_share_link,
                                                    file_a):
    _, token = create_share_link(file_a.id)
    response = public_download(anonymous_client, token)
    assert response["X-Share-Downloads-Remaining"] == "unlimited"


def test_deleting_the_file_kills_the_link(anonymous_client, client_a, create_share_link,
                                          file_a):
    _, token = create_share_link(file_a.id)
    client_a.delete(f"/api/files/{file_a.id}/")

    assert public_get(anonymous_client, token).status_code == 404
    assert public_download(anonymous_client, token).status_code == 404


# ===========================================================================
# Management
# ===========================================================================
def test_owner_can_list_their_links(client_a, create_share_link, file_a):
    create_share_link(file_a.id)
    create_share_link(file_a.id)
    body = client_a.get("/api/share-links/").data
    assert body["count"] == 2


def test_links_of_other_users_are_not_listed(client_b, create_share_link, file_a):
    create_share_link(file_a.id)
    assert client_b.get("/api/share-links/").data["count"] == 0


def test_owner_can_update_permission_and_limits(client_a, create_share_link, file_a):
    payload, _ = create_share_link(file_a.id, max_downloads=5)
    link_id = payload["share_link"]["id"]

    response = client_a.patch(
        f"/api/share-links/{link_id}/",
        {"permission": "VIEW", "max_downloads": 2},
        format="json",
    )
    assert response.status_code == 200
    assert response.data["permission"] == "VIEW"
    assert response.data["max_downloads"] == 2
    assert AuditLog.objects.filter(action=AuditAction.SHARE_LINK_MODIFIED).exists()


def test_owner_can_shorten_the_expiry(client_a, anonymous_client, create_share_link,
                                      file_a):
    payload, _token = create_share_link(file_a.id, expires_in="7d")
    link_id = payload["share_link"]["id"]
    new_expiry = timezone.now() + timedelta(minutes=1)

    response = client_a.patch(
        f"/api/share-links/{link_id}/",
        {"expires_in": "custom", "expires_at": new_expiry.isoformat()},
        format="json",
    )
    assert response.status_code == 200
    link = ShareLink.objects.get(pk=link_id)
    assert abs((link.expires_at - new_expiry).total_seconds()) < 2


def test_owner_can_add_a_password_afterwards(client_a, anonymous_client,
                                             create_share_link, file_a):
    payload, token = create_share_link(file_a.id)
    link_id = payload["share_link"]["id"]
    assert public_download(anonymous_client, token).status_code == 200

    client_a.patch(
        f"/api/share-links/{link_id}/", {"password": SHARE_PASSWORD}, format="json"
    )
    blocked = public_download(anonymous_client, token)
    assert blocked.status_code == 401
    assert blocked.data["error"] == "SHARE_LINK_PASSWORD_REQUIRED"


def test_revocation_takes_effect_immediately(client_a, anonymous_client,
                                             create_share_link, file_a):
    payload, token = create_share_link(file_a.id)
    link_id = payload["share_link"]["id"]
    assert public_get(anonymous_client, token).status_code == 200

    response = client_a.delete(f"/api/share-links/{link_id}/")
    assert response.status_code == 204

    metadata = public_get(anonymous_client, token)
    assert metadata.status_code == 410
    assert metadata.data["error"] == "SHARE_LINK_REVOKED"
    download = public_download(anonymous_client, token)
    assert download.status_code == 410
    assert AuditLog.objects.filter(action=AuditAction.SHARE_LINK_REVOKED).exists()


def test_admin_can_revoke_any_link(admin_client, create_share_link, file_a):
    payload, _ = create_share_link(file_a.id)
    link_id = payload["share_link"]["id"]
    assert admin_client.delete(f"/api/share-links/{link_id}/").status_code == 204
    assert ShareLink.objects.get(pk=link_id).revoked_at is not None


def test_file_share_links_endpoint_lists_links_for_one_file(client_a, create_share_link,
                                                            file_a, make_file, user_a):
    create_share_link(file_a.id)
    other = make_file(user_a, name="other.pdf")
    create_share_link(other.id)

    body = client_a.get(f"/api/files/{file_a.id}/share-links/").data
    assert body["count"] == 1


# ===========================================================================
# Password protection (happy paths)
# ===========================================================================
def test_password_protected_link_hides_metadata_until_unlocked(anonymous_client,
                                                               create_share_link, file_a):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    response = public_get(anonymous_client, token)
    assert response.status_code == 200
    assert response.data["password_required"] is True
    assert "filename" not in response.data
    assert "size" not in response.data


def test_correct_password_header_unlocks_metadata(anonymous_client, create_share_link,
                                                  file_a):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    response = public_get(anonymous_client, token, HTTP_X_SHARE_PASSWORD=SHARE_PASSWORD)
    assert response.status_code == 200
    assert response.data["filename"] == "report.pdf"
    assert response.data["password_required"] is True


def test_verify_password_returns_a_grant(anonymous_client, create_share_link, file_a,
                                         pdf_bytes):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    response = anonymous_client.post(
        f"/api/share/{token}/verify-password/", {"password": SHARE_PASSWORD},
        format="json",
    )
    assert response.status_code == 200
    grant = response.data["grant"]
    assert grant
    assert SHARE_PASSWORD not in grant

    # The grant works in place of the password.
    download = public_download(anonymous_client, token, {"grant": grant})
    assert download.status_code == 200
    assert body_of(download) == pdf_bytes


def test_download_with_correct_password_in_body(anonymous_client, create_share_link,
                                                file_a, pdf_bytes):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    response = public_download(anonymous_client, token, {"password": SHARE_PASSWORD})
    assert response.status_code == 200
    assert body_of(response) == pdf_bytes


def test_password_is_stored_only_as_a_hash(create_share_link, file_a):
    payload, _ = create_share_link(file_a.id, password=SHARE_PASSWORD)
    link = ShareLink.objects.get(pk=payload["share_link"]["id"])
    assert link.password_hash
    assert SHARE_PASSWORD not in link.password_hash
    assert link.password_hash.startswith("argon2")
    assert str(payload).count(SHARE_PASSWORD) == 0


def test_short_password_is_rejected(client_a, file_a):
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"password": "abc"}, format="json"
    )
    assert response.status_code == 400


def test_password_can_be_removed_by_the_owner(client_a, anonymous_client,
                                              create_share_link, file_a):
    payload, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    link_id = payload["share_link"]["id"]

    client_a.patch(f"/api/share-links/{link_id}/", {"password": ""}, format="json")
    assert public_download(anonymous_client, token).status_code == 200
