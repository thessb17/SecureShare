"""Phase 9: admin / security dashboard.

Covers the two things that matter: the numbers are real (derived from the
database, not invented), and the endpoints are closed to everyone but ADMIN
regardless of what the React UI chooses to render.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.urls import reverse
from django.utils import timezone

from audit.constants import AuditAction
from audit.models import AuditLog
from files.models import File
from sharing.models import FileShare, ShareLink

pytestmark = pytest.mark.security

User = get_user_model()


def backdate(entry: AuditLog, when) -> None:
    """Move an audit row back in time.

    AuditLog blocks UPDATE through the ORM on purpose, so a historical
    fixture has to go around it with raw SQL. Nothing in the application can
    do this - that is the point of the immutability guard.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE audit_auditlog SET timestamp = %s WHERE id = %s", [when, str(entry.id)]
        )


ADMIN_ENDPOINTS = [
    "/api/admin/stats/",
    "/api/admin/users/",
    "/api/admin/security-events/",
    "/api/admin/actions/",
]


# ---------------------------------------------------------------------------
# 1. Access control: only ADMIN, enforced on the server
# ---------------------------------------------------------------------------
@pytest.mark.django_db
@pytest.mark.parametrize("path", ADMIN_ENDPOINTS)
def test_normal_user_is_refused_every_admin_endpoint(client_a, path):
    response = client_a.get(path)
    assert response.status_code == 403, f"{path} leaked to a USER"


@pytest.mark.django_db
@pytest.mark.parametrize("path", ADMIN_ENDPOINTS)
def test_anonymous_is_refused_every_admin_endpoint(anonymous_client, path):
    response = anonymous_client.get(path)
    assert response.status_code == 401, f"{path} leaked to an anonymous caller"


@pytest.mark.django_db
@pytest.mark.parametrize("path", ADMIN_ENDPOINTS)
def test_admin_is_allowed_every_admin_endpoint(admin_client, path):
    assert admin_client.get(path).status_code == 200


@pytest.mark.django_db
def test_user_cannot_disable_another_account(client_a, user_b):
    response = client_a.patch(
        f"/api/admin/users/{user_b.id}/", {"is_active": False}, format="json"
    )
    assert response.status_code == 403
    user_b.refresh_from_db()
    assert user_b.is_active is True


@pytest.mark.django_db
def test_user_cannot_unlock_another_account(client_a, user_b):
    user_b.locked_until = timezone.now() + timedelta(minutes=10)
    user_b.save(update_fields=["locked_until"])

    assert client_a.post(f"/api/admin/users/{user_b.id}/unlock/").status_code == 403

    user_b.refresh_from_db()
    assert user_b.locked_until is not None, "a USER cleared a lockout"


@pytest.mark.django_db
def test_user_cannot_promote_themselves_through_the_admin_api(client_a, user_a):
    response = client_a.patch(
        f"/api/admin/users/{user_a.id}/", {"role": "ADMIN", "is_active": True}, format="json"
    )
    assert response.status_code == 403
    user_a.refresh_from_db()
    assert user_a.role == "USER"


@pytest.mark.django_db
def test_role_is_not_writable_even_by_an_admin_through_this_endpoint(admin_client, user_a):
    """Privilege grants are deliberately out of scope for this API."""
    response = admin_client.patch(
        f"/api/admin/users/{user_a.id}/", {"is_active": True, "role": "ADMIN"}, format="json"
    )
    assert response.status_code == 200
    user_a.refresh_from_db()
    assert user_a.role == "USER", "role was mutated through an endpoint that must not allow it"


# ---------------------------------------------------------------------------
# 2. Metrics are real
# ---------------------------------------------------------------------------
@pytest.mark.django_db
def test_admin_stats_counts_match_the_database(admin_client, user_a, user_b, file_a):
    response = admin_client.get("/api/admin/stats/")
    assert response.status_code == 200
    data = response.data

    assert data["users"]["total"] == User.objects.count()
    assert data["users"]["active"] == User.objects.filter(is_active=True).count()
    assert data["users"]["disabled"] == User.objects.filter(is_active=False).count()
    assert data["users"]["admins"] == User.objects.filter(role="ADMIN").count()
    assert data["files"]["total"] == File.objects.count()
    assert data["files"]["encrypted_bytes"] == sum(
        f.encrypted_size for f in File.objects.filter(deleted_at__isnull=True)
    )


@pytest.mark.django_db
def test_admin_stats_reflects_a_newly_disabled_user(admin_client, user_b):
    before = admin_client.get("/api/admin/stats/").data["users"]["disabled"]
    user_b.is_active = False
    user_b.save(update_fields=["is_active"])
    after = admin_client.get("/api/admin/stats/").data["users"]["disabled"]
    assert after == before + 1


@pytest.mark.django_db
def test_admin_stats_counts_locked_accounts(admin_client, user_a):
    assert admin_client.get("/api/admin/stats/").data["users"]["locked"] == 0
    user_a.locked_until = timezone.now() + timedelta(minutes=5)
    user_a.save(update_fields=["locked_until"])
    assert admin_client.get("/api/admin/stats/").data["users"]["locked"] == 1


@pytest.mark.django_db
def test_admin_stats_buckets_shares_by_real_state(
    admin_client, user_a, user_b, user_c, make_user, file_a
):
    # A partial unique index allows only one *active* share per
    # (file, recipient), so each bucket needs its own recipient.
    now = timezone.now()
    fourth = make_user(email="bucket4@example.com")

    FileShare.objects.create(file=file_a, owner=user_a, recipient=user_b, permission="VIEW")
    expired = FileShare.objects.create(
        file=file_a, owner=user_a, recipient=user_c, permission="VIEW"
    )
    FileShare.objects.filter(pk=expired.pk).update(expires_at=now - timedelta(hours=1))
    revoked = FileShare.objects.create(
        file=file_a, owner=user_a, recipient=fourth, permission="VIEW"
    )
    FileShare.objects.filter(pk=revoked.pk).update(revoked_at=now)

    shares = admin_client.get("/api/admin/stats/").data["shares"]
    assert shares["active"] == 1
    assert shares["expired"] == 1
    assert shares["revoked"] == 1


@pytest.mark.django_db
def test_admin_stats_counts_failed_logins_in_the_last_day(admin_client, api_client, user_a):
    before = admin_client.get("/api/admin/stats/").data["security"]["failed_logins_24h"]
    api_client.post(
        reverse("api:auth-login"),
        {"email": user_a.email, "password": "definitely-not-the-password"},
        format="json",
    )
    after = admin_client.get("/api/admin/stats/").data["security"]["failed_logins_24h"]
    assert after == before + 1


@pytest.mark.django_db
def test_admin_stats_ignores_events_older_than_the_window(admin_client, user_a):
    old = AuditLog.objects.create(
        action=AuditAction.LOGIN_FAILURE,
        actor=user_a,
        actor_email=user_a.email,
        success=False,
    )
    backdate(old, timezone.now() - timedelta(days=3))

    recent = AuditLog.objects.create(
        action=AuditAction.LOGIN_FAILURE,
        actor=user_a,
        actor_email=user_a.email,
        success=False,
    )
    assert recent.pk is not None

    data = admin_client.get("/api/admin/stats/").data
    assert data["security"]["failed_logins_24h"] == 1


@pytest.mark.django_db
def test_dashboard_stats_are_scoped_to_the_caller(client_a, client_b, user_a, file_a):
    a_data = client_a.get("/api/dashboard/stats/").data
    b_data = client_b.get("/api/dashboard/stats/").data

    assert a_data["files"]["active"] == 1
    assert b_data["files"]["active"] == 0, "B saw A's files in the dashboard totals"
    assert a_data["files"]["encrypted_bytes"] > 0
    assert b_data["files"]["encrypted_bytes"] == 0


@pytest.mark.django_db
def test_dashboard_recent_activity_only_shows_the_callers_events(client_a, client_b, user_a, user_b):
    AuditLog.objects.create(
        action=AuditAction.FILE_UPLOADED,
        actor=user_a,
        actor_email=user_a.email,
        success=True,
    )
    entries = client_b.get("/api/dashboard/stats/").data["recent_activity"]
    assert all(entry["action"] != "FILE_UPLOADED" for entry in entries)


@pytest.mark.django_db
def test_dashboard_requires_authentication(anonymous_client):
    assert anonymous_client.get("/api/dashboard/stats/").status_code == 401


# ---------------------------------------------------------------------------
# 3. User management
# ---------------------------------------------------------------------------
@pytest.mark.django_db
def test_admin_can_disable_and_re_enable_an_account(admin_client, user_b):
    response = admin_client.patch(
        f"/api/admin/users/{user_b.id}/",
        {"is_active": False, "reason": "offboarding"},
        format="json",
    )
    assert response.status_code == 200
    assert response.data["is_active"] is False
    user_b.refresh_from_db()
    assert user_b.is_active is False

    response = admin_client.patch(
        f"/api/admin/users/{user_b.id}/", {"is_active": True}, format="json"
    )
    assert response.status_code == 200
    user_b.refresh_from_db()
    assert user_b.is_active is True


@pytest.mark.django_db
def test_disabling_an_account_invalidates_its_issued_tokens(admin_client, client_b, user_b):
    assert client_b.get("/api/files/").status_code == 200

    admin_client.patch(f"/api/admin/users/{user_b.id}/", {"is_active": False}, format="json")

    assert client_b.get("/api/files/").status_code == 401, (
        "a disabled account kept working with its existing access token"
    )


@pytest.mark.django_db
def test_admin_cannot_disable_their_own_account(admin_client, admin_user):
    response = admin_client.patch(
        f"/api/admin/users/{admin_user.id}/", {"is_active": False}, format="json"
    )
    assert response.status_code == 400
    admin_user.refresh_from_db()
    assert admin_user.is_active is True


@pytest.mark.django_db
def test_admin_can_clear_a_lockout(admin_client, user_b):
    user_b.locked_until = timezone.now() + timedelta(minutes=30)
    user_b.failed_login_count = 9
    user_b.save(update_fields=["locked_until", "failed_login_count"])

    response = admin_client.post(f"/api/admin/users/{user_b.id}/unlock/")
    assert response.status_code == 200

    user_b.refresh_from_db()
    assert user_b.locked_until is None
    assert user_b.failed_login_count == 0


@pytest.mark.django_db
def test_user_payload_never_contains_credentials(admin_client, user_a):
    body = admin_client.get("/api/admin/users/").content.decode().lower()
    for marker in ("password", "argon2", "pbkdf2", "token_version", "refresh", "access_token"):
        assert marker not in body, f"admin user list exposed {marker!r}"


@pytest.mark.django_db
def test_user_detail_never_contains_credentials(admin_client, user_a):
    body = admin_client.get(f"/api/admin/users/{user_a.id}/").content.decode().lower()
    for marker in ("password", "argon2", "pbkdf2", "token_version"):
        assert marker not in body, f"admin user detail exposed {marker!r}"


@pytest.mark.django_db
def test_user_search_matches_email_and_name(admin_client, make_user):
    make_user(email="findme@example.com", full_name="Zebra Stripes")

    by_email = admin_client.get("/api/admin/users/?search=findme")
    assert by_email.data["count"] == 1

    by_name = admin_client.get("/api/admin/users/?search=Zebra")
    assert by_name.data["count"] == 1

    assert admin_client.get("/api/admin/users/?search=no-such-person").data["count"] == 0


@pytest.mark.django_db
def test_user_status_filters(admin_client, user_a, user_b):
    user_b.is_active = False
    user_b.save(update_fields=["is_active"])

    disabled = admin_client.get("/api/admin/users/?status=disabled").data
    assert disabled["count"] == 1
    assert disabled["results"][0]["email"] == user_b.email

    assert admin_client.get("/api/admin/users/?status=admin").data["count"] == User.objects.filter(
        role="ADMIN"
    ).count()


@pytest.mark.django_db
def test_user_rows_report_a_real_file_count(admin_client, user_a, file_a):
    rows = admin_client.get(f"/api/admin/users/?search={user_a.email}").data["results"]
    assert rows[0]["file_count"] == 1


@pytest.mark.django_db
def test_unknown_user_id_is_a_clean_404(admin_client):
    response = admin_client.get("/api/admin/users/00000000-0000-0000-0000-000000000000/")
    assert response.status_code == 404
    assert "Traceback" not in response.content.decode()


@pytest.mark.django_db
def test_is_active_must_be_supplied_and_boolean(admin_client, user_b):
    assert admin_client.patch(f"/api/admin/users/{user_b.id}/", {}, format="json").status_code == 400
    assert (
        admin_client.patch(
            f"/api/admin/users/{user_b.id}/", {"is_active": "maybe"}, format="json"
        ).status_code
        == 400
    )


# ---------------------------------------------------------------------------
# 4. Every admin mutation is audited
# ---------------------------------------------------------------------------
@pytest.mark.django_db
def test_disabling_a_user_emits_admin_action(admin_client, admin_user, user_b):
    admin_client.patch(
        f"/api/admin/users/{user_b.id}/",
        {"is_active": False, "reason": "policy violation"},
        format="json",
    )
    entry = AuditLog.objects.filter(action=AuditAction.ADMIN_ACTION).latest("timestamp")

    assert entry.actor_id == admin_user.id
    assert entry.actor_email == admin_user.email
    assert entry.object_type == "user"
    assert entry.object_id == str(user_b.id)
    assert entry.metadata["operation"] == "disable_user"
    assert entry.metadata["target_email"] == user_b.email
    assert entry.metadata["reason"] == "policy violation"
    assert entry.success is True
    assert entry.ip_address is not None


@pytest.mark.django_db
def test_enabling_a_user_emits_admin_action(admin_client, user_b):
    user_b.is_active = False
    user_b.save(update_fields=["is_active"])

    admin_client.patch(f"/api/admin/users/{user_b.id}/", {"is_active": True}, format="json")

    entry = AuditLog.objects.filter(action=AuditAction.ADMIN_ACTION).latest("timestamp")
    assert entry.metadata["operation"] == "enable_user"


@pytest.mark.django_db
def test_unlocking_a_user_emits_admin_action(admin_client, user_b):
    user_b.locked_until = timezone.now() + timedelta(minutes=10)
    user_b.save(update_fields=["locked_until"])

    admin_client.post(f"/api/admin/users/{user_b.id}/unlock/")

    entry = AuditLog.objects.filter(action=AuditAction.ADMIN_ACTION).latest("timestamp")
    assert entry.metadata["operation"] == "unlock_user"
    assert entry.metadata["was_locked"] is True


@pytest.mark.django_db
def test_a_no_op_update_does_not_fabricate_an_audit_event(admin_client, user_b):
    before = AuditLog.objects.filter(action=AuditAction.ADMIN_ACTION).count()
    admin_client.patch(f"/api/admin/users/{user_b.id}/", {"is_active": True}, format="json")
    after = AuditLog.objects.filter(action=AuditAction.ADMIN_ACTION).count()
    assert after == before, "an unchanged account produced a spurious ADMIN_ACTION"


@pytest.mark.django_db
def test_admin_action_feed_lists_only_admin_actions(admin_client, user_b):
    admin_client.patch(f"/api/admin/users/{user_b.id}/", {"is_active": False}, format="json")
    response = admin_client.get("/api/admin/actions/")
    assert response.status_code == 200
    assert response.data["count"] >= 1
    assert {row["action"] for row in response.data["results"]} == {"ADMIN_ACTION"}


# ---------------------------------------------------------------------------
# 5. Security event search
# ---------------------------------------------------------------------------
@pytest.mark.django_db
def test_security_events_can_be_filtered_by_action(admin_client, user_a):
    AuditLog.objects.create(
        action=AuditAction.LOGIN_FAILURE, actor=user_a, actor_email=user_a.email, success=False
    )
    AuditLog.objects.create(
        action=AuditAction.FILE_UPLOADED, actor=user_a, actor_email=user_a.email, success=True
    )

    response = admin_client.get("/api/admin/security-events/?action=LOGIN_FAILURE")
    assert response.status_code == 200
    assert {row["action"] for row in response.data["results"]} == {"LOGIN_FAILURE"}


@pytest.mark.django_db
def test_security_events_can_be_filtered_by_actor(admin_client, user_a, user_b):
    AuditLog.objects.create(
        action=AuditAction.FILE_UPLOADED, actor=user_a, actor_email=user_a.email, success=True
    )
    AuditLog.objects.create(
        action=AuditAction.FILE_UPLOADED, actor=user_b, actor_email=user_b.email, success=True
    )

    response = admin_client.get(f"/api/admin/security-events/?actor={user_a.email}")
    emails = {(row["actor"] or {}).get("email") for row in response.data["results"]}
    assert emails == {user_a.email}


@pytest.mark.django_db
def test_security_events_can_be_filtered_by_outcome(admin_client, user_a):
    AuditLog.objects.create(
        action=AuditAction.LOGIN_FAILURE, actor=user_a, actor_email=user_a.email, success=False
    )
    response = admin_client.get("/api/admin/security-events/?success=false")
    assert all(row["success"] is False for row in response.data["results"])


@pytest.mark.django_db
def test_security_events_can_be_filtered_by_date_range(admin_client, user_a):
    old = AuditLog.objects.create(
        action=AuditAction.LOGIN_SUCCESS, actor=user_a, actor_email=user_a.email, success=True
    )
    backdate(old, timezone.now() - timedelta(days=10))
    AuditLog.objects.create(
        action=AuditAction.LOGIN_SUCCESS, actor=user_a, actor_email=user_a.email, success=True
    )

    # Assert on identity rather than totals: the admin's own sign-in also
    # writes an event, so a bare count would be brittle and uninformative.
    since = (timezone.now() - timedelta(days=1)).isoformat()
    recent_ids = {
        row["id"]
        for row in admin_client.get(f"/api/admin/security-events/?since={since}").data["results"]
    }
    assert str(old.id) not in recent_ids, "a 10-day-old event leaked into a 1-day window"

    until = (timezone.now() - timedelta(days=5)).isoformat()
    old_rows = admin_client.get(f"/api/admin/security-events/?until={until}").data["results"]
    assert [row["id"] for row in old_rows] == [str(old.id)]


@pytest.mark.django_db
def test_security_only_filter_excludes_routine_success(admin_client, user_a):
    AuditLog.objects.create(
        action=AuditAction.FILE_VIEWED, actor=user_a, actor_email=user_a.email, success=True
    )
    AuditLog.objects.create(
        action=AuditAction.UNAUTHORIZED_FILE_ACCESS,
        actor=user_a,
        actor_email=user_a.email,
        success=False,
    )

    response = admin_client.get("/api/admin/security-events/?security_only=true")
    actions = {row["action"] for row in response.data["results"]}
    assert "UNAUTHORIZED_FILE_ACCESS" in actions
    assert "FILE_VIEWED" not in actions


@pytest.mark.django_db
def test_security_events_span_every_user(admin_client, user_a, user_b):
    AuditLog.objects.create(
        action=AuditAction.FILE_UPLOADED, actor=user_a, actor_email=user_a.email, success=True
    )
    AuditLog.objects.create(
        action=AuditAction.FILE_UPLOADED, actor=user_b, actor_email=user_b.email, success=True
    )
    emails = {
        (row["actor"] or {}).get("email")
        for row in admin_client.get("/api/admin/security-events/").data["results"]
    }
    assert {user_a.email, user_b.email} <= emails


@pytest.mark.django_db
def test_security_events_are_newest_first(admin_client, user_a):
    for _ in range(3):
        AuditLog.objects.create(
            action=AuditAction.LOGIN_SUCCESS,
            actor=user_a,
            actor_email=user_a.email,
            success=True,
        )
    rows = admin_client.get("/api/admin/security-events/").data["results"]
    stamps = [row["timestamp"] for row in rows]
    assert stamps == sorted(stamps, reverse=True)


@pytest.mark.django_db
def test_security_events_are_read_only(admin_client):
    for method in ("post", "put", "patch", "delete"):
        response = getattr(admin_client, method)("/api/admin/security-events/", {}, format="json")
        assert response.status_code in (403, 405), f"{method} was accepted on the event feed"


@pytest.mark.django_db
def test_admin_cannot_delete_an_audit_record_through_the_api(admin_client, user_a):
    entry = AuditLog.objects.create(
        action=AuditAction.LOGIN_SUCCESS, actor=user_a, actor_email=user_a.email, success=True
    )
    for path in (
        f"/api/audit-logs/{entry.id}/",
        f"/api/admin/security-events/{entry.id}/",
    ):
        assert admin_client.delete(path).status_code in (403, 404, 405)
    assert AuditLog.objects.filter(pk=entry.pk).exists()


@pytest.mark.django_db
def test_a_malformed_date_filter_is_rejected_not_silently_ignored(admin_client):
    """A dropped filter would show the admin everything while the UI claims
    a date range is active. Rejecting is the honest behaviour."""
    response = admin_client.get("/api/admin/security-events/?since=not-a-date")
    assert response.status_code == 400
    assert "since" in response.data.get("details", response.data)


@pytest.mark.django_db
def test_a_plus_lost_to_url_decoding_is_still_understood(admin_client, user_a):
    """An unencoded "+00:00" offset arrives as " 00:00"; treat it as the
    offset it obviously is rather than dropping the filter."""
    stamp = (timezone.now() - timedelta(days=1)).isoformat().replace("+", " ")
    response = admin_client.get(f"/api/admin/security-events/?since={stamp}")
    assert response.status_code == 200


@pytest.mark.django_db
def test_event_search_does_not_expose_raw_tokens_or_passwords(admin_client, user_a, file_a):
    AuditLog.objects.create(
        action=AuditAction.SHARE_LINK_CREATED,
        actor=user_a,
        actor_email=user_a.email,
        success=True,
        metadata={"token_prefix": "abc123def456"},
    )
    body = admin_client.get("/api/admin/security-events/").content.decode()
    for marker in ("BEGIN RSA", "wrapped_dek", "password_hash", "token_hash"):
        assert marker not in body


# ---------------------------------------------------------------------------
# 6. Shape contracts the React console relies on
# ---------------------------------------------------------------------------
@pytest.mark.django_db
def test_admin_stats_exposes_every_section_the_console_renders(admin_client):
    data = admin_client.get("/api/admin/stats/").data
    assert {"users", "files", "shares", "share_links", "security", "generated_at"} <= set(data)
    assert {"total", "active", "disabled", "admins", "locked"} <= set(data["users"])
    assert {"total", "active", "deleted", "encrypted_bytes", "plaintext_bytes"} <= set(data["files"])
    assert {
        "events_24h",
        "failed_logins_24h",
        "lockouts_24h",
        "unauthorized_24h",
        "rate_limited_24h",
    } <= set(data["security"])


@pytest.mark.django_db
def test_dashboard_stats_exposes_every_section_the_dashboard_renders(client_a):
    data = client_a.get("/api/dashboard/stats/").data
    assert {"files", "shares", "links", "recent_activity"} <= set(data)
    assert {"total", "active", "deleted", "plaintext_bytes", "encrypted_bytes"} <= set(data["files"])
    assert {
        "outgoing_active",
        "outgoing_expired",
        "outgoing_revoked",
        "incoming_active",
    } <= set(data["shares"])
    assert {"active", "expired", "revoked", "total_downloads"} <= set(data["links"])


@pytest.mark.django_db
def test_dashboard_counts_link_downloads(client_a, user_a, file_a):
    link = ShareLink.objects.create(
        file=file_a,
        created_by=user_a,
        token_hash="f" * 64,
        token_prefix="abc123def456",
        permission="DOWNLOAD",
        expires_at=timezone.now() + timedelta(hours=1),
        download_count=4,
    )
    assert link.pk is not None
    data = client_a.get("/api/dashboard/stats/").data
    assert data["links"]["total_downloads"] == 4
    assert data["links"]["active"] == 1


# ---------------------------------------------------------------------------
# 7. The harness itself
# ---------------------------------------------------------------------------
def test_the_suite_really_runs_against_the_test_settings(settings):
    """Guards the ``--ds`` entry in pytest.ini addopts.

    ``DJANGO_SETTINGS_MODULE`` in pytest.ini is only a *default*; an exported
    value beats it. A developer who has sourced the project .env (normal when
    running the dev server) would otherwise run this whole suite against
    config.settings.dev -- DEBUG on, the real Redis cache, production CORS
    origins. Most tests would still pass, which is the dangerous part: the
    results would not mean what they appear to mean.

    These three assertions are unique to config.settings.test.
    """
    assert settings.SECRET_KEY == "test-secret-key-not-used-outside-pytest"
    assert settings.DEBUG is False
    assert "locmem" in settings.CACHES["default"]["BACKEND"].lower()
    assert settings.CELERY_TASK_ALWAYS_EAGER is True
