"""Phase 2: role based access control enforced on the server."""
from __future__ import annotations

import pytest

from audit.constants import AuditAction
from audit.models import AuditLog

pytestmark = pytest.mark.django_db

ADMIN_URL = "/api/admin/test/"


def test_anonymous_cannot_reach_admin_endpoint(api_client):
    response = api_client.get(ADMIN_URL)
    assert response.status_code == 401
    assert response.data["error"] == "AUTHENTICATION_REQUIRED"


def test_normal_user_cannot_reach_admin_endpoint(client_a):
    response = client_a.get(ADMIN_URL)
    assert response.status_code == 403
    assert response.data["error"] == "ACCESS_DENIED"


def test_admin_can_reach_admin_endpoint(admin_client, admin_user):
    response = admin_client.get(ADMIN_URL)
    assert response.status_code == 200
    assert response.data["user"]["role"] == "ADMIN"
    assert AuditLog.objects.filter(action=AuditAction.ADMIN_ACTION).exists()


def test_role_cannot_be_escalated_through_the_profile_endpoint(client_a, user_a):
    response = client_a.patch("/api/users/me/", {"role": "ADMIN"}, format="json")
    assert response.status_code == 200
    user_a.refresh_from_db()
    assert user_a.role == "USER"
    assert client_a.get(ADMIN_URL).status_code == 403


def test_is_active_flag_is_not_writable_through_the_api(client_a, user_a):
    client_a.patch("/api/users/me/", {"is_active": False}, format="json")
    user_a.refresh_from_db()
    assert user_a.is_active is True


def test_disabled_user_token_is_rejected(api_client, user_a, authenticate):
    authenticate(api_client, user_a)
    assert api_client.get("/api/users/me/").status_code == 200
    user_a.is_active = False
    user_a.save(update_fields=["is_active"])
    assert api_client.get("/api/users/me/").status_code == 401


def test_locked_user_token_is_rejected(api_client, user_a, authenticate):
    authenticate(api_client, user_a)
    user_a.lock(600)
    assert api_client.get("/api/users/me/").status_code == 401


def test_superuser_without_admin_role_is_still_admin(make_user, authenticate):
    from rest_framework.test import APIClient

    root = make_user("root@example.com", role="USER", is_superuser=True, is_staff=True)
    client = authenticate(APIClient(), root)
    assert client.get(ADMIN_URL).status_code == 200
