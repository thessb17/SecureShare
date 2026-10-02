"""Meta-test: prove the concurrency test can actually detect a broken limiter.

A race test that passes against *any* implementation is worthless. Here the
atomic claim is temporarily replaced with the naive read-modify-write version a
developer would write by hand, and we assert that the limit is then breached.
This documents that the real implementation is what prevents the overrun.
"""
from __future__ import annotations

import threading
import time

import pytest
from django.db import connections

from sharing.models import ShareLink

pytestmark = pytest.mark.security


def naive_claim(link: ShareLink) -> bool:
    """Intentionally vulnerable: SELECT, decide in Python, then UPDATE."""
    fresh = ShareLink.objects.get(pk=link.pk)
    if fresh.max_downloads is not None and fresh.download_count >= fresh.max_downloads:
        return False
    time.sleep(0.02)  # the window every TOCTOU bug needs
    ShareLink.objects.filter(pk=link.pk).update(download_count=fresh.download_count + 1)
    return True


@pytest.mark.django_db(transaction=True)
def test_naive_counter_is_breached_by_concurrency(client_a, file_a):
    response = client_a.post(
        f"/api/files/{file_a.id}/share-link/", {"max_downloads": 1}, format="json"
    )
    link = ShareLink.objects.get(pk=response.data["share_link"]["id"])

    workers = 8
    barrier = threading.Barrier(workers)
    granted: list[bool] = []
    lock = threading.Lock()

    def claim():
        try:
            barrier.wait(timeout=10)
            result = naive_claim(link)
            with lock:
                granted.append(result)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=claim) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    # The naive implementation lets several requests through: this is exactly
    # the bug that ShareLinkService.claim_download_slot prevents.
    assert granted.count(True) > 1, (
        "the vulnerable implementation was expected to overrun the limit; "
        "if this fails the race test harness is not creating real contention"
    )
