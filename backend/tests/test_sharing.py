"""Phase 5: authenticated user-to-user sharing."""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from django.utils import timezone

from audit.constants import AuditAction
from audit.models import AuditLog
from sharing.models import FileShare, SharePermission

pytestmark = pytest.mark.django_db


def share_url(file_id) -> str:
    return f"/api/files/{file_id}/share/"


def create_share(client, file_id, recipient_email, permission="DOWNLOAD", **extra):
    payload = {"recipient": recipient_email, "permission": permission, **extra}
    return client.post(share_url(file_id), payload, format="json")


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------
def test_owner_can_share_a_file(client_a, file_a, user_b):
    response = create_share(client_a, file_a.id, user_b.email)
    assert response.status_code == 201, response.data
    assert response.data["recipient"]["email"] == user_b.email
    assert response.data["permission"] == "DOWNLOAD"
    assert response.data["is_active"] is True

    share = FileShare.objects.get(pk=response.data["id"])
    assert share.owner_id == file_a.owner_id
    assert share.recipient_id == user_b.pk
    assert AuditLog.objects.filter(action=AuditAction.FILE_SHARED).exists()


def test_share_requires_authentication(api_client, file_a, user_b):
    assert create_share(api_client, file_a.id, user_b.email).status_code == 401


def test_non_owner_cannot_share_a_file(client_b, file_a, user_c):
    """Even a user the file was shared with cannot re-share it."""
    response = create_share(client_b, file_a.id, user_c.email)
    assert response.status_code == 404  # existence is not confirmed


def test_recipient_of_a_share_cannot_reshare(client_a, client_b, file_a, user_b, user_c):
    create_share(client_a, file_a.id, user_b.email)
    response = create_share(client_b, file_a.id, user_c.email)
    assert response.status_code == 403
    assert response.data["error"] == "ACCESS_DENIED"
    assert AuditLog.objects.filter(
        action=AuditAction.UNAUTHORIZED_SHARE_ACCESS
    ).exists()


def test_admin_cannot_create_a_share_for_someone_elses_file(admin_client, file_a, user_b):
    response = create_share(admin_client, file_a.id, user_b.email)
    assert response.status_code == 403


def test_sharing_with_an_unknown_account_does_not_leak_existence(
    client_a, file_a, user_b
):
    unknown = create_share(client_a, file_a.id, "ghost@example.com")
    disabled_user = user_b
    disabled_user.is_active = False
    disabled_user.save(update_fields=["is_active"])
    disabled = create_share(client_a, file_a.id, disabled_user.email)

    assert unknown.status_code == disabled.status_code == 400
    assert unknown.data["error"] == disabled.data["error"] == "INVALID_RECIPIENT"
    assert unknown.data["message"] == disabled.data["message"]


def test_cannot_share_with_yourself(client_a, file_a, user_a):
    response = create_share(client_a, file_a.id, user_a.email)
    assert response.status_code == 400
    assert response.data["error"] == "INVALID_RECIPIENT"


def test_duplicate_share_is_rejected(client_a, file_a, user_b):
    assert create_share(client_a, file_a.id, user_b.email).status_code == 201
    duplicate = create_share(client_a, file_a.id, user_b.email)
    assert duplicate.status_code == 409
    assert duplicate.data["error"] == "SHARE_ALREADY_EXISTS"


def test_share_expiry_in_the_past_is_rejected(client_a, file_a, user_b):
    past = (timezone.now() - timedelta(hours=1)).isoformat()
    response = create_share(
        client_a, file_a.id, user_b.email, expires_in="custom", expires_at=past
    )
    assert response.status_code == 400


def test_share_expiry_beyond_the_cap_is_rejected(client_a, file_a, user_b, settings):
    settings.FILE_SHARE_MAX_TTL_SECONDS = 3600
    far = (timezone.now() + timedelta(days=365)).isoformat()
    response = create_share(
        client_a, file_a.id, user_b.email, expires_in="custom", expires_at=far
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Recipient access
# ---------------------------------------------------------------------------
def test_recipient_sees_the_file_in_shared_with_me(client_a, client_b, file_a, user_b):
    create_share(client_a, file_a.id, user_b.email)
    body = client_b.get("/api/shared-with-me/").data
    assert body["count"] == 1
    assert body["results"][0]["file"]["filename"] == "report.pdf"
    # The recipient never sees storage internals.
    assert "stored_object_id" not in str(body)


def test_shared_with_me_does_not_include_other_peoples_shares(
    client_a, client_c, file_a, user_b
):
    create_share(client_a, file_a.id, user_b.email)
    assert client_c.get("/api/shared-with-me/").data["count"] == 0


def test_recipient_with_download_permission_can_download(
    client_a, client_b, file_a, user_b, pdf_bytes
):
    create_share(client_a, file_a.id, user_b.email, permission="DOWNLOAD")
    response = client_b.get(f"/api/files/{file_a.id}/download/")
    assert response.status_code == 200
    content = b"".join(response.streaming_content) if response.streaming else response.content
    assert content == pdf_bytes
    assert AuditLog.objects.filter(action=AuditAction.SHARE_ACCESSED).exists()


def test_recipient_with_view_permission_cannot_download(
    client_a, client_b, file_a, user_b
):
    create_share(client_a, file_a.id, user_b.email, permission="VIEW")
    metadata = client_b.get(f"/api/files/{file_a.id}/")
    assert metadata.status_code == 200

    download = client_b.get(f"/api/files/{file_a.id}/download/")
    assert download.status_code == 403
    assert download.data["error"] == "SHARE_PERMISSION_DENIED"
    assert AuditLog.objects.filter(
        action=AuditAction.UNAUTHORIZED_FILE_ACCESS
    ).exists()


def test_recipient_cannot_delete_the_shared_file(client_a, client_b, file_a, user_b):
    create_share(client_a, file_a.id, user_b.email, permission="DOWNLOAD")
    response = client_b.delete(f"/api/files/{file_a.id}/")
    assert response.status_code in (403, 404)
    file_a.refresh_from_db()
    assert file_a.deleted_at is None


def test_recipient_cannot_list_the_shares_of_the_file(client_a, client_b, file_a, user_b):
    create_share(client_a, file_a.id, user_b.email)
    response = client_b.get(f"/api/files/{file_a.id}/shares/")
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Expiry and revocation
# ---------------------------------------------------------------------------
def test_expired_share_denies_access(client_a, client_b, file_a, user_b):
    response = create_share(
        client_a,
        file_a.id,
        user_b.email,
        expires_in="custom",
        expires_at=(timezone.now() + timedelta(minutes=5)).isoformat(),
    )
    share = FileShare.objects.get(pk=response.data["id"])

    # Backend-enforced expiry: move the stored timestamp into the past.
    FileShare.objects.filter(pk=share.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert client_b.get(f"/api/files/{file_a.id}/download/").status_code == 404
    assert client_b.get("/api/shared-with-me/").data["count"] == 0


def test_owner_can_revoke_a_share_and_access_stops_immediately(
    client_a, client_b, file_a, user_b
):
    share_id = create_share(client_a, file_a.id, user_b.email).data["id"]
    assert client_b.get(f"/api/files/{file_a.id}/download/").status_code == 200

    response = client_a.delete(f"/api/shares/{share_id}/")
    assert response.status_code == 204

    assert client_b.get(f"/api/files/{file_a.id}/download/").status_code == 404
    assert client_b.get("/api/shared-with-me/").data["count"] == 0
    assert AuditLog.objects.filter(action=AuditAction.SHARE_REVOKED).exists()


def test_recipient_cannot_revoke_a_share(client_a, client_b, file_a, user_b):
    share_id = create_share(client_a, file_a.id, user_b.email).data["id"]
    response = client_b.delete(f"/api/shares/{share_id}/")
    assert response.status_code == 403
    assert FileShare.objects.get(pk=share_id).revoked_at is None


def test_stranger_cannot_see_or_touch_a_share(client_c, client_a, file_a, user_b):
    share_id = create_share(client_a, file_a.id, user_b.email).data["id"]
    assert client_c.get(f"/api/shares/{share_id}/").status_code == 404
    assert client_c.delete(f"/api/shares/{share_id}/").status_code == 404
    assert client_c.patch(
        f"/api/shares/{share_id}/", {"permission": "DOWNLOAD"}, format="json"
    ).status_code == 404


def test_admin_can_revoke_a_share_as_moderation(admin_client, client_a, file_a, user_b):
    share_id = create_share(client_a, file_a.id, user_b.email).data["id"]
    assert admin_client.delete(f"/api/shares/{share_id}/").status_code == 204
    assert FileShare.objects.get(pk=share_id).revoked_at is not None


def test_deleting_the_file_revokes_its_shares(client_a, client_b, file_a, user_b):
    create_share(client_a, file_a.id, user_b.email)
    client_a.delete(f"/api/files/{file_a.id}/")
    assert client_b.get("/api/shared-with-me/").data["count"] == 0
    assert client_b.get(f"/api/files/{file_a.id}/download/").status_code == 404


# ---------------------------------------------------------------------------
# Modification / privilege escalation
# ---------------------------------------------------------------------------
def test_owner_can_change_the_permission(client_a, client_b, file_a, user_b):
    share_id = create_share(client_a, file_a.id, user_b.email, permission="VIEW").data["id"]
    assert client_b.get(f"/api/files/{file_a.id}/download/").status_code == 403

    response = client_a.patch(
        f"/api/shares/{share_id}/", {"permission": "DOWNLOAD"}, format="json"
    )
    assert response.status_code == 200
    assert response.data["permission"] == "DOWNLOAD"
    assert client_b.get(f"/api/files/{file_a.id}/download/").status_code == 200
    assert AuditLog.objects.filter(action=AuditAction.SHARE_MODIFIED).exists()


def test_recipient_cannot_escalate_their_own_permission(client_a, client_b, file_a, user_b):
    """The core Phase 5 privilege-escalation test."""
    share_id = create_share(client_a, file_a.id, user_b.email, permission="VIEW").data["id"]

    response = client_b.patch(
        f"/api/shares/{share_id}/", {"permission": "DOWNLOAD"}, format="json"
    )
    assert response.status_code == 403
    assert FileShare.objects.get(pk=share_id).permission == SharePermission.VIEW
    assert client_b.get(f"/api/files/{file_a.id}/download/").status_code == 403


def test_admin_cannot_change_a_share_permission(admin_client, client_a, file_a, user_b):
    share_id = create_share(client_a, file_a.id, user_b.email, permission="VIEW").data["id"]
    response = admin_client.patch(
        f"/api/shares/{share_id}/", {"permission": "DOWNLOAD"}, format="json"
    )
    assert response.status_code == 403
    assert FileShare.objects.get(pk=share_id).permission == SharePermission.VIEW


def test_recipient_cannot_extend_the_expiry(client_a, client_b, file_a, user_b):
    share_id = create_share(
        client_a,
        file_a.id,
        user_b.email,
        expires_in="custom",
        expires_at=(timezone.now() + timedelta(hours=1)).isoformat(),
    ).data["id"]
    response = client_b.patch(
        f"/api/shares/{share_id}/",
        {"expires_in": "custom", "expires_at": (timezone.now() + timedelta(days=7)).isoformat()},
        format="json",
    )
    assert response.status_code == 403


def test_patch_with_unknown_share_id_returns_404(client_a):
    response = client_a.patch(
        f"/api/shares/{uuid.uuid4()}/", {"permission": "VIEW"}, format="json"
    )
    assert response.status_code == 404


def test_share_payload_never_exposes_internal_fields(client_a, file_a, user_b):
    body = create_share(client_a, file_a.id, user_b.email).data
    serialized = str(body)
    for forbidden in ("stored_object_id", "wrapped_dek", "token_hash", "password"):
        assert forbidden not in serialized


def test_my_shares_lists_only_my_shares(client_a, client_b, client_c, file_a,
                                        user_b, make_file, user_c):
    create_share(client_a, file_a.id, user_b.email)
    other_file = make_file(user_c, name="carol.pdf")
    from sharing.services import ShareService

    ShareService.create_share(
        file_obj=other_file, actor=user_c, recipient_email=user_b.email
    )

    body = client_a.get("/api/shares/").data
    assert body["count"] == 1
    assert body["results"][0]["recipient"]["email"] == user_b.email
