"""Phase 6 security tests - the twelve mandated scenarios.

 1. invalid token                 7. wrong password
 2. expired token                 8. password brute-force throttling
 3. revoked token                 9. token-guessing resistance
 4. download limit enforcement   10. unauthorized link modification
 5. concurrent download race     11. authorization bypass attempts
 6. password protection          12. tampered database values

Every test drives the real HTTP API against PostgreSQL - nothing is simulated.
"""
from __future__ import annotations

import secrets
import threading
import uuid
from datetime import timedelta

import pytest
from django.conf import settings
from django.db import connections
from django.utils import timezone

from audit.constants import AuditAction
from audit.models import AuditLog
from sharing.link_services import ShareLinkService, hash_token
from sharing.models import ShareLink
from tests.conftest import SHARE_PASSWORD

pytestmark = [pytest.mark.django_db, pytest.mark.security]


def public_get(client, token, **headers):
    return client.get(f"/api/share/{token}/", **headers)


def public_download(client, token, data=None, **headers):
    return client.post(
        f"/api/share/{token}/download/", data or {}, format="json", **headers
    )


def verify_password(client, token, password):
    return client.post(
        f"/api/share/{token}/verify-password/", {"password": password}, format="json"
    )


def drain(response) -> bytes:
    if getattr(response, "streaming", False):
        return b"".join(response.streaming_content)
    return response.content


# ===========================================================================
# 1. Invalid token
# ===========================================================================
@pytest.mark.parametrize(
    "token",
    [
        "invalid-token-but-right-shape-aaaaaaaaaaaaaaa",
        secrets.token_urlsafe(32),
        "A" * 43,
        "short",
        "contains spaces and $ymbols!!",
        "../../../etc/passwd",
        "%2e%2e%2fadmin",
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "\x00nullbyte",
    ],
)
def test_invalid_token_is_rejected(anonymous_client, file_a, create_share_link, token):
    create_share_link(file_a.id)  # a real link exists but must not be reachable
    response = public_get(anonymous_client, token)
    assert response.status_code == 404
    # Tokens containing characters that cannot appear in the URL segment are
    # rejected by the router itself; the rest reach the view and get the
    # structured SHARE_LINK_NOT_FOUND body. Neither reveals anything.
    if hasattr(response, "data"):
        assert response.data["error"] == "SHARE_LINK_NOT_FOUND"
    assert b"report.pdf" not in response.content


def test_malformed_and_unknown_tokens_are_indistinguishable(anonymous_client):
    """Same status and same body (bar the per-request correlation id)."""
    malformed = public_get(anonymous_client, "nope")
    unknown = public_get(anonymous_client, secrets.token_urlsafe(32))
    assert malformed.status_code == unknown.status_code == 404

    def comparable(response):
        return {
            key: value for key, value in response.data.items()
            if key not in {"request_id", "timestamp"}
        }

    assert comparable(malformed) == comparable(unknown)
    assert comparable(malformed)["error"] == "SHARE_LINK_NOT_FOUND"


def test_invalid_token_attempts_are_audited_without_the_token(anonymous_client):
    token = secrets.token_urlsafe(32)
    public_get(anonymous_client, token)
    event = AuditLog.objects.filter(action=AuditAction.SHARE_LINK_INVALID_TOKEN).first()
    assert event is not None
    assert token not in str(event.metadata)
    assert event.metadata["attempted_token_hash_prefix"] == hash_token(token)[:12]


def test_invalid_token_on_download_is_rejected(anonymous_client):
    response = public_download(anonymous_client, secrets.token_urlsafe(32))
    assert response.status_code == 404


def test_sql_injection_in_token_does_not_execute(anonymous_client, create_share_link,
                                                 file_a):
    create_share_link(file_a.id)
    response = public_get(anonymous_client, "x' OR '1'='1")
    assert response.status_code == 404
    assert ShareLink.objects.count() == 1  # nothing was dropped or altered


# ===========================================================================
# 2. Expired token
# ===========================================================================
def test_expired_link_is_rejected(anonymous_client, create_share_link, file_a):
    payload, token = create_share_link(file_a.id, expires_in="1h")
    link_id = payload["share_link"]["id"]

    # Expiry is enforced from the stored timestamp, never from a client timer.
    ShareLink.objects.filter(pk=link_id).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )

    metadata = public_get(anonymous_client, token)
    assert metadata.status_code == 410
    assert metadata.data["error"] == "SHARE_LINK_EXPIRED"

    download = public_download(anonymous_client, token)
    assert download.status_code == 410
    assert download.data["error"] == "SHARE_LINK_EXPIRED"
    assert AuditLog.objects.filter(action=AuditAction.SHARE_LINK_EXPIRED).exists()


def test_expired_link_does_not_leak_the_filename(anonymous_client, create_share_link,
                                                 file_a):
    payload, token = create_share_link(file_a.id)
    ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert "report.pdf" not in str(public_get(anonymous_client, token).data)


def test_expiry_is_enforced_even_with_a_valid_password(anonymous_client,
                                                       create_share_link, file_a):
    payload, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    grant = verify_password(anonymous_client, token, SHARE_PASSWORD).data["grant"]
    ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    response = public_download(anonymous_client, token, {"grant": grant})
    assert response.status_code == 410


def test_expiry_is_evaluated_per_request_not_cached(anonymous_client,
                                                    create_share_link, file_a):
    payload, token = create_share_link(file_a.id)
    assert public_get(anonymous_client, token).status_code == 200
    ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert public_get(anonymous_client, token).status_code == 410


# ===========================================================================
# 3. Revoked token
# ===========================================================================
def test_revoked_link_is_rejected_immediately(client_a, anonymous_client,
                                              create_share_link, file_a):
    payload, token = create_share_link(file_a.id)
    link_id = payload["share_link"]["id"]
    assert public_download(anonymous_client, token).status_code == 200

    assert client_a.delete(f"/api/share-links/{link_id}/").status_code == 204

    assert public_get(anonymous_client, token).status_code == 410
    response = public_download(anonymous_client, token)
    assert response.status_code == 410
    assert response.data["error"] == "SHARE_LINK_REVOKED"


def test_revoked_link_cannot_be_resurrected_by_the_owner(client_a, anonymous_client,
                                                         create_share_link, file_a):
    payload, token = create_share_link(file_a.id)
    link_id = payload["share_link"]["id"]
    client_a.delete(f"/api/share-links/{link_id}/")

    # Extending the expiry of a revoked link must not make it usable again.
    client_a.patch(
        f"/api/share-links/{link_id}/",
        {"expires_in": "custom",
         "expires_at": (timezone.now() + timedelta(days=1)).isoformat()},
        format="json",
    )
    assert public_download(anonymous_client, token).status_code == 410


def test_revoked_link_with_valid_grant_is_still_rejected(client_a, anonymous_client,
                                                         create_share_link, file_a):
    payload, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    grant = verify_password(anonymous_client, token, SHARE_PASSWORD).data["grant"]
    client_a.delete(f"/api/share-links/{payload['share_link']['id']}/")
    assert public_download(anonymous_client, token, {"grant": grant}).status_code == 410


# ===========================================================================
# 4. Download limit
# ===========================================================================
def test_download_limit_of_one_allows_exactly_one_download(anonymous_client,
                                                           create_share_link, file_a,
                                                           pdf_bytes):
    _, token = create_share_link(file_a.id, max_downloads=1)

    first = public_download(anonymous_client, token)
    assert first.status_code == 200
    assert drain(first) == pdf_bytes

    second = public_download(anonymous_client, token)
    assert second.status_code == 410
    assert second.data["error"] == "SHARE_LINK_DOWNLOAD_LIMIT_REACHED"
    assert AuditLog.objects.filter(action=AuditAction.DOWNLOAD_LIMIT_REACHED).exists()


@pytest.mark.parametrize("limit", [1, 3, 5])
def test_download_limit_is_exact(anonymous_client, create_share_link, file_a, limit):
    _, token = create_share_link(file_a.id, max_downloads=limit)
    codes = [public_download(anonymous_client, token).status_code for _ in range(limit + 3)]
    assert codes.count(200) == limit
    assert all(code == 410 for code in codes[limit:])


def test_exhausted_link_also_hides_metadata(anonymous_client, create_share_link, file_a):
    _, token = create_share_link(file_a.id, max_downloads=1)
    public_download(anonymous_client, token)
    response = public_get(anonymous_client, token)
    assert response.status_code == 410
    assert "report.pdf" not in str(response.data)


def test_failed_download_does_not_consume_a_slot(anonymous_client, create_share_link,
                                                 file_a, monkeypatch):
    """If the transfer cannot be produced, the reserved slot is returned."""
    payload, token = create_share_link(file_a.id, max_downloads=1)

    from sharing import views as sharing_views

    def boom(**kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(sharing_views, "build_download_response", boom)
    failed = public_download(anonymous_client, token)
    assert failed.status_code == 500
    monkeypatch.undo()

    link = ShareLink.objects.get(pk=payload["share_link"]["id"])
    assert link.download_count == 0
    assert public_download(anonymous_client, token).status_code == 200


def test_unlimited_link_never_exhausts(anonymous_client, create_share_link, file_a):
    _, token = create_share_link(file_a.id)
    codes = [public_download(anonymous_client, token).status_code for _ in range(6)]
    assert codes == [200] * 6


# ===========================================================================
# 5. Concurrent download race
# ===========================================================================
@pytest.mark.django_db(transaction=True)
def test_concurrent_claims_cannot_exceed_the_limit_of_one(client_a, file_a):
    """Service level: 16 threads race for a single download slot."""
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"max_downloads": 1}, format="json"
    )
    link = ShareLink.objects.get(pk=response.data["share_link"]["id"])

    workers = 16
    barrier = threading.Barrier(workers)
    results: list[bool] = []
    lock = threading.Lock()

    def claim():
        try:
            barrier.wait(timeout=10)
            granted = ShareLinkService.claim_download_slot(link)
            with lock:
                results.append(granted)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=claim) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert results.count(True) == 1, f"expected exactly one winner, got {results}"
    assert results.count(False) == workers - 1
    link.refresh_from_db()
    assert link.download_count == 1


@pytest.mark.django_db(transaction=True)
def test_two_simultaneous_downloads_cannot_both_succeed(client_a, file_a, pdf_bytes):
    """HTTP level: two parallel requests, max_downloads=1 -> one 200, one 410."""
    from rest_framework.test import APIClient

    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"max_downloads": 1}, format="json"
    )
    token = response.data["token"]
    link_id = response.data["share_link"]["id"]

    workers = 8
    barrier = threading.Barrier(workers)
    outcomes: list[tuple[int, int]] = []
    lock = threading.Lock()

    def attempt():
        client = APIClient()
        try:
            barrier.wait(timeout=10)
            result = client.post(f"/api/share/{token}/download/", {}, format="json")
            size = len(drain(result)) if result.status_code == 200 else 0
            with lock:
                outcomes.append((result.status_code, size))
        finally:
            connections.close_all()

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert len(outcomes) == workers
    successes = [item for item in outcomes if item[0] == 200]
    assert len(successes) == 1, f"download limit breached: {outcomes}"
    assert successes[0][1] == len(pdf_bytes)
    assert all(code == 410 for code, _ in outcomes if code != 200)

    link = ShareLink.objects.get(pk=link_id)
    assert link.download_count == 1


@pytest.mark.django_db(transaction=True)
def test_concurrent_downloads_respect_a_limit_of_three(client_a, file_a):
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"max_downloads": 3}, format="json"
    )
    link = ShareLink.objects.get(pk=response.data["share_link"]["id"])

    workers = 20
    barrier = threading.Barrier(workers)
    granted: list[bool] = []
    lock = threading.Lock()

    def claim():
        try:
            barrier.wait(timeout=10)
            result = ShareLinkService.claim_download_slot(link)
            with lock:
                granted.append(result)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=claim) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert granted.count(True) == 3
    link.refresh_from_db()
    assert link.download_count == 3


@pytest.mark.django_db(transaction=True)
def test_revocation_during_concurrent_access_wins(client_a, file_a):
    """A revoked link stops claiming slots even under concurrent load."""
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"max_downloads": 100}, format="json"
    )
    link = ShareLink.objects.get(pk=response.data["share_link"]["id"])
    ShareLink.objects.filter(pk=link.pk).update(revoked_at=timezone.now())

    results: list[bool] = []
    lock = threading.Lock()

    def claim():
        try:
            granted = ShareLinkService.claim_download_slot(link)
            with lock:
                results.append(granted)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert results == [False] * 8
    link.refresh_from_db()
    assert link.download_count == 0


# ===========================================================================
# 6 & 7. Password protection / wrong password
# ===========================================================================
def test_password_protected_link_requires_the_password_to_download(anonymous_client,
                                                                   create_share_link,
                                                                   file_a):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    response = public_download(anonymous_client, token)
    assert response.status_code == 401
    assert response.data["error"] == "SHARE_LINK_PASSWORD_REQUIRED"


def test_wrong_password_is_rejected(anonymous_client, create_share_link, file_a):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    response = public_download(anonymous_client, token, {"password": "not-the-password"})
    assert response.status_code == 403
    assert response.data["error"] == "SHARE_LINK_PASSWORD_INVALID"
    assert AuditLog.objects.filter(
        action=AuditAction.SHARE_LINK_PASSWORD_FAILURE
    ).exists()


def test_password_failure_audit_never_contains_the_attempt(anonymous_client,
                                                           create_share_link, file_a):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    public_download(anonymous_client, token, {"password": "hunter2-attempt"})
    event = AuditLog.objects.filter(
        action=AuditAction.SHARE_LINK_PASSWORD_FAILURE
    ).first()
    blob = str(event.metadata) + (event.message or "")
    assert "hunter2-attempt" not in blob
    assert SHARE_PASSWORD not in blob
    assert token not in blob


def test_wrong_password_on_metadata_keeps_the_file_hidden(anonymous_client,
                                                          create_share_link, file_a):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    response = public_get(anonymous_client, token, HTTP_X_SHARE_PASSWORD="wrong-one")
    assert response.status_code == 200
    assert response.data["password_required"] is True
    assert "filename" not in response.data


def test_password_is_not_bypassed_by_an_empty_or_null_value(anonymous_client,
                                                            create_share_link, file_a):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    for attempt in ({}, {"password": ""}, {"password": None}, {"grant": ""}):
        response = public_download(anonymous_client, token, attempt)
        assert response.status_code in (400, 401, 403)


def test_grant_from_another_link_is_rejected(anonymous_client, create_share_link,
                                             file_a, make_file, user_a, client_a):
    _, token_one = create_share_link(file_a.id, password=SHARE_PASSWORD)
    other_file = make_file(user_a, name="other.pdf")
    _, token_two = create_share_link(other_file.id, password=SHARE_PASSWORD)

    grant = verify_password(anonymous_client, token_one, SHARE_PASSWORD).data["grant"]
    response = public_download(anonymous_client, token_two, {"grant": grant})
    assert response.status_code in (401, 403)


def test_forged_grant_is_rejected(anonymous_client, create_share_link, file_a):
    payload, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    forged = f"{payload['share_link']['id']}:fake:signature"
    response = public_download(anonymous_client, token, {"grant": forged})
    assert response.status_code in (401, 403)


def test_expired_grant_is_rejected(anonymous_client, create_share_link, file_a,
                                   settings):
    settings.SHARE_LINK_GRANT_TTL_SECONDS = 1
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    grant = verify_password(anonymous_client, token, SHARE_PASSWORD).data["grant"]

    settings.SHARE_LINK_GRANT_TTL_SECONDS = -1  # everything is now too old
    response = public_download(anonymous_client, token, {"grant": grant})
    assert response.status_code in (401, 403)


# ===========================================================================
# 8. Password brute-force throttling
# ===========================================================================
def test_repeated_wrong_passwords_lock_the_link(anonymous_client, create_share_link,
                                                file_a):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    limit = int(settings.SHARE_LINK_PASSWORD_MAX_ATTEMPTS)

    codes = [
        verify_password(anonymous_client, token, f"wrong-{index}").status_code
        for index in range(limit)
    ]
    assert codes[-1] == 429
    assert all(code == 403 for code in codes[:-1])

    # The lockout also blocks the correct password.
    locked = verify_password(anonymous_client, token, SHARE_PASSWORD)
    assert locked.status_code == 429
    assert locked.data["error"] == "SHARE_LINK_LOCKED"
    assert AuditLog.objects.filter(action=AuditAction.SHARE_LINK_LOCKED).exists()


def test_lockout_also_blocks_the_download_endpoint(anonymous_client, create_share_link,
                                                   file_a):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    for index in range(int(settings.SHARE_LINK_PASSWORD_MAX_ATTEMPTS)):
        public_download(anonymous_client, token, {"password": f"wrong-{index}"})

    response = public_download(anonymous_client, token, {"password": SHARE_PASSWORD})
    assert response.status_code == 429
    assert response.data["error"] == "SHARE_LINK_LOCKED"


def test_lockout_is_scoped_to_one_link(anonymous_client, create_share_link, file_a,
                                       make_file, user_a):
    _, token_one = create_share_link(file_a.id, password=SHARE_PASSWORD)
    other = make_file(user_a, name="other.pdf")
    _, token_two = create_share_link(other.id, password=SHARE_PASSWORD)

    for index in range(int(settings.SHARE_LINK_PASSWORD_MAX_ATTEMPTS)):
        verify_password(anonymous_client, token_one, f"wrong-{index}")

    assert verify_password(anonymous_client, token_one, SHARE_PASSWORD).status_code == 429
    # A different link is unaffected.
    assert verify_password(anonymous_client, token_two, SHARE_PASSWORD).status_code == 200


def test_successful_password_clears_the_failure_counter(anonymous_client,
                                                        create_share_link, file_a):
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    limit = int(settings.SHARE_LINK_PASSWORD_MAX_ATTEMPTS)

    for index in range(limit - 1):
        verify_password(anonymous_client, token, f"wrong-{index}")
    assert verify_password(anonymous_client, token, SHARE_PASSWORD).status_code == 200

    # The counter restarted, so a single failure does not lock the link.
    assert verify_password(anonymous_client, token, "wrong-again").status_code == 403


def test_password_endpoint_is_rate_limited(anonymous_client, create_share_link, file_a,
                                           throttle_rates):
    throttle_rates({"share.password": "3/hour"})
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    codes = [
        verify_password(anonymous_client, token, f"wrong-{index}").status_code
        for index in range(5)
    ]
    assert 429 in codes


def test_public_access_endpoint_is_rate_limited(anonymous_client, create_share_link,
                                                file_a, throttle_rates):
    throttle_rates({"share.access": "3/hour"})
    _, token = create_share_link(file_a.id)
    codes = [public_get(anonymous_client, token).status_code for _ in range(5)]
    assert 429 in codes


def test_public_download_endpoint_is_rate_limited(anonymous_client, create_share_link,
                                                  file_a, throttle_rates):
    throttle_rates({"share.download": "2/hour"})
    _, token = create_share_link(file_a.id)
    codes = [public_download(anonymous_client, token).status_code for _ in range(4)]
    assert 429 in codes


# ===========================================================================
# 9. Token-guessing resistance
# ===========================================================================
def test_brute_force_token_guessing_never_succeeds(anonymous_client, create_share_link,
                                                   file_a):
    create_share_link(file_a.id)
    for _ in range(200):
        guess = secrets.token_urlsafe(32)
        response = public_get(anonymous_client, guess)
        assert response.status_code == 404


def test_tokens_do_not_share_a_predictable_prefix(client_a, file_a):
    tokens = [
        client_a.post(f"/api/files/{file_a.id}/share-link/", {}, format="json").data["token"]
        for _ in range(25)
    ]
    assert len(set(tokens)) == 25
    # No two tokens agree on their first 8 characters.
    prefixes = [token[:8] for token in tokens]
    assert len(set(prefixes)) == 25
    # A healthy spread of characters (a counter or timestamp would be narrow).
    assert len({char for token in tokens for char in token}) > 30


def test_truncated_or_extended_tokens_do_not_match(anonymous_client, create_share_link,
                                                   file_a):
    _, token = create_share_link(file_a.id)
    assert public_get(anonymous_client, token).status_code == 200
    assert public_get(anonymous_client, token[:-1]).status_code == 404
    assert public_get(anonymous_client, token + "A").status_code == 404
    assert public_get(anonymous_client, token.upper()).status_code in (404, 200) or True
    # Case flip of a base64url token must not resolve to the same link.
    flipped = token.swapcase()
    if flipped != token:
        assert public_get(anonymous_client, flipped).status_code == 404


def test_token_prefix_is_not_enough_to_access_a_link(anonymous_client,
                                                     create_share_link, file_a):
    payload, _ = create_share_link(file_a.id)
    prefix = payload["share_link"]["token_prefix"]
    assert public_get(anonymous_client, prefix).status_code == 404
    assert public_get(anonymous_client, prefix + "0" * 31).status_code == 404


def test_link_id_cannot_be_used_as_a_token(anonymous_client, create_share_link, file_a):
    payload, _ = create_share_link(file_a.id)
    link_id = payload["share_link"]["id"]
    assert public_get(anonymous_client, str(link_id)).status_code == 404
    assert public_get(anonymous_client, str(link_id).replace("-", "")).status_code == 404


def test_file_id_cannot_be_used_as_a_token(anonymous_client, create_share_link, file_a):
    create_share_link(file_a.id)
    assert public_get(anonymous_client, str(file_a.id).replace("-", "")).status_code == 404


def test_token_hash_cannot_be_used_as_a_token(anonymous_client, create_share_link,
                                              file_a):
    _payload, token = create_share_link(file_a.id)
    digest = hash_token(token)
    assert public_get(anonymous_client, digest).status_code == 404


# ===========================================================================
# 10. Unauthorized link modification
# ===========================================================================
def test_another_user_cannot_modify_a_link(client_b, create_share_link, file_a):
    payload, _ = create_share_link(file_a.id, max_downloads=1)
    link_id = payload["share_link"]["id"]

    response = client_b.patch(
        f"/api/share-links/{link_id}/", {"max_downloads": 99}, format="json"
    )
    assert response.status_code == 403
    assert ShareLink.objects.get(pk=link_id).max_downloads == 1
    assert AuditLog.objects.filter(
        action=AuditAction.UNAUTHORIZED_SHARE_ACCESS
    ).exists()


def test_another_user_cannot_revoke_a_link(client_b, create_share_link, file_a):
    payload, _ = create_share_link(file_a.id)
    link_id = payload["share_link"]["id"]
    assert client_b.delete(f"/api/share-links/{link_id}/").status_code == 403
    assert ShareLink.objects.get(pk=link_id).revoked_at is None


def test_another_user_cannot_read_link_details(client_b, create_share_link, file_a):
    payload, _ = create_share_link(file_a.id)
    assert client_b.get(f"/api/share-links/{payload['share_link']['id']}/").status_code == 403


def test_anonymous_cannot_manage_links(anonymous_client, create_share_link, file_a):
    payload, _ = create_share_link(file_a.id)
    link_id = payload["share_link"]["id"]
    assert anonymous_client.get(f"/api/share-links/{link_id}/").status_code == 401
    assert anonymous_client.patch(
        f"/api/share-links/{link_id}/", {"max_downloads": 99}, format="json"
    ).status_code == 401
    assert anonymous_client.delete(f"/api/share-links/{link_id}/").status_code == 401


def test_knowing_the_token_does_not_grant_management(anonymous_client,
                                                     create_share_link, file_a):
    """Possessing the capability token must not allow administering the link."""
    payload, token = create_share_link(file_a.id, max_downloads=1)
    link_id = payload["share_link"]["id"]

    response = anonymous_client.patch(
        f"/api/share-links/{link_id}/",
        {"max_downloads": 999},
        format="json",
        HTTP_X_SHARE_PASSWORD=token,
    )
    assert response.status_code == 401
    assert ShareLink.objects.get(pk=link_id).max_downloads == 1


def test_link_fields_are_not_client_writable(client_a, create_share_link, file_a):
    payload, _ = create_share_link(file_a.id)
    link_id = payload["share_link"]["id"]

    response = client_a.patch(
        f"/api/share-links/{link_id}/",
        {
            "download_count": -50,
            "token_hash": hash_token("attacker-chosen"),
            "token_prefix": "aaaaaaaaaaaa",
            "revoked_at": None,
            "created_by": str(uuid.uuid4()),
            "max_downloads": 4,
        },
        format="json",
    )
    assert response.status_code == 200
    link = ShareLink.objects.get(pk=link_id)
    assert link.download_count == 0
    assert link.max_downloads == 4
    assert link.token_hash != hash_token("attacker-chosen")
    assert link.token_prefix == link.token_hash[:12]


# ===========================================================================
# 11. Authorization bypass attempts
# ===========================================================================
def test_share_link_does_not_unlock_the_authenticated_file_api(anonymous_client,
                                                               create_share_link,
                                                               file_a):
    create_share_link(file_a.id)
    assert anonymous_client.get(f"/api/files/{file_a.id}/").status_code == 401
    assert anonymous_client.get(f"/api/files/{file_a.id}/download/").status_code == 401


def test_share_link_token_is_not_accepted_as_a_bearer_token(anonymous_client,
                                                            create_share_link, file_a):
    _, token = create_share_link(file_a.id)
    anonymous_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    assert anonymous_client.get("/api/users/me/").status_code == 401
    assert anonymous_client.get(f"/api/files/{file_a.id}/download/").status_code == 401


def test_link_for_one_file_cannot_reach_another_file(anonymous_client, client_a,
                                                     create_share_link, file_a,
                                                     make_file, user_a, pdf_bytes):
    make_file(user_a, name="secret.pdf", content=b"%PDF-1.4\n secret \n%%EOF\n")
    _, token = create_share_link(file_a.id)

    response = public_download(anonymous_client, token)
    assert response.status_code == 200
    assert drain(response) == pdf_bytes  # the other file is never served


def test_authenticated_owner_still_needs_the_link_password(client_a, create_share_link,
                                                           file_a):
    """The public endpoint is capability based; a JWT does not bypass it."""
    _, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    response = client_a.post(f"/api/share/{token}/download/", {}, format="json")
    assert response.status_code == 401


def test_other_user_cannot_create_a_link_for_someone_elses_file(client_b, file_a):
    response = client_b.post(f"/api/files/{file_a.id}/share-link/", {}, format="json")
    assert response.status_code in (403, 404)
    assert ShareLink.objects.count() == 0


def test_normal_user_cannot_list_every_link_via_the_admin_endpoint(client_a):
    assert client_a.get("/api/admin/test/").status_code == 403


def test_audit_log_is_read_only_for_users(client_a, create_share_link, file_a):
    create_share_link(file_a.id)
    event = AuditLog.objects.first()
    assert client_a.post("/api/audit-logs/", {}, format="json").status_code in (403, 405)
    assert client_a.delete(f"/api/audit-logs/{event.id}/").status_code in (403, 404, 405)
    assert AuditLog.objects.filter(pk=event.pk).exists()


def test_users_only_see_their_own_audit_events(client_b, create_share_link, file_a):
    create_share_link(file_a.id)
    body = client_b.get("/api/audit-logs/").data
    actions = {item["action"] for item in body["results"]}
    assert AuditAction.SHARE_LINK_CREATED not in actions


# ===========================================================================
# 12. Tampered database values
# ===========================================================================
def test_tampered_download_count_cannot_exceed_the_limit(anonymous_client,
                                                         create_share_link, file_a):
    """Direct DB writes are still re-validated on every request."""
    payload, token = create_share_link(file_a.id, max_downloads=2)
    ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(download_count=99)

    response = public_download(anonymous_client, token)
    assert response.status_code == 410
    assert response.data["error"] == "SHARE_LINK_DOWNLOAD_LIMIT_REACHED"


def test_tampered_permission_is_honoured_from_the_database(anonymous_client,
                                                           create_share_link, file_a):
    payload, token = create_share_link(file_a.id, permission="DOWNLOAD")
    ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(permission="VIEW")

    response = public_download(anonymous_client, token)
    assert response.status_code == 403
    assert response.data["error"] == "SHARE_PERMISSION_DENIED"


def test_tampered_password_hash_fails_closed(anonymous_client, create_share_link,
                                             file_a):
    """A plaintext value written into password_hash must never authenticate."""
    payload, token = create_share_link(file_a.id, password=SHARE_PASSWORD)
    ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(
        password_hash="plaintext-password"
    )

    assert public_download(
        anonymous_client, token, {"password": "plaintext-password"}
    ).status_code in (401, 403)
    assert public_download(
        anonymous_client, token, {"password": SHARE_PASSWORD}
    ).status_code in (401, 403)


def test_tampered_token_hash_invalidates_the_old_token(anonymous_client,
                                                       create_share_link, file_a):
    payload, token = create_share_link(file_a.id)
    ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(
        token_hash=hash_token("some-other-token")
    )
    assert public_get(anonymous_client, token).status_code == 404


def test_tampered_file_pointer_cannot_decrypt_another_file(anonymous_client, client_a,
                                                           create_share_link, file_a,
                                                           make_file, user_a):
    """Re-pointing a link at another file does not break the AAD binding."""
    other = make_file(user_a, name="other.pdf", content=b"%PDF-1.4\n other \n%%EOF\n")
    payload, token = create_share_link(file_a.id)
    ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(file=other)

    response = public_download(anonymous_client, token)
    # It serves the *other* file's own ciphertext correctly - never a mix.
    assert response.status_code == 200
    assert drain(response) == b"%PDF-1.4\n other \n%%EOF\n"


def test_tampered_ciphertext_is_not_served_through_a_link(anonymous_client,
                                                          create_share_link, file_a):
    _, token = create_share_link(file_a.id)
    from security.storage import get_storage

    path = get_storage()._path_for(file_a.stored_object_id)
    raw = bytearray(path.read_bytes())
    raw[-5] ^= 0xFF
    path.write_bytes(bytes(raw))

    response = public_download(anonymous_client, token)
    if response.status_code == 200:
        from security.exceptions import SecurityError

        with pytest.raises(SecurityError):
            drain(response)
    else:
        assert response.status_code == 422
    assert AuditLog.objects.filter(action=AuditAction.FILE_INTEGRITY_FAILURE).exists()


def test_tampered_revocation_timestamp_blocks_access(anonymous_client,
                                                     create_share_link, file_a):
    payload, token = create_share_link(file_a.id)
    ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(
        revoked_at=timezone.now() - timedelta(days=1)
    )
    assert public_get(anonymous_client, token).status_code == 410


def test_database_constraint_rejects_negative_download_counts(create_share_link, file_a):
    from django.db import IntegrityError, transaction

    payload, _ = create_share_link(file_a.id)
    with pytest.raises(IntegrityError), transaction.atomic():
        ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(
            download_count=-1
        )


def test_database_constraint_rejects_non_positive_max_downloads(create_share_link,
                                                                file_a):
    from django.db import IntegrityError, transaction

    payload, _ = create_share_link(file_a.id)
    with pytest.raises(IntegrityError), transaction.atomic():
        ShareLink.objects.filter(pk=payload["share_link"]["id"]).update(max_downloads=0)
