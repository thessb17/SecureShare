from __future__ import annotations

from django.urls import path

from sharing.views import (
    FileShareCreateView,
    FileShareLinkListView,
    FileShareListView,
    MySharesListView,
    PublicShareDownloadView,
    PublicShareLinkView,
    PublicSharePasswordView,
    ShareDetailView,
    SharedWithMeListView,
    ShareLinkCreateView,
    ShareLinkDetailView,
    ShareLinkListView,
)

urlpatterns = [
    # --- Phase 5: user to user -------------------------------------------
    path("files/<uuid:file_id>/share/", FileShareCreateView.as_view(), name="file-share"),
    path(
        "files/<uuid:file_id>/shares/",
        FileShareListView.as_view(),
        name="file-share-list",
    ),
    path("shares/", MySharesListView.as_view(), name="share-list"),
    path("shares/<uuid:share_id>/", ShareDetailView.as_view(), name="share-detail"),
    path("shared-with-me/", SharedWithMeListView.as_view(), name="shared-with-me"),
    # --- Phase 6: public share links (management) ------------------------
    path(
        "files/<uuid:file_id>/share-link/",
        ShareLinkCreateView.as_view(),
        name="share-link-create",
    ),
    path(
        "files/<uuid:file_id>/share-links/",
        FileShareLinkListView.as_view(),
        name="file-share-link-list",
    ),
    path("share-links/", ShareLinkListView.as_view(), name="share-link-list"),
    path(
        "share-links/<uuid:link_id>/",
        ShareLinkDetailView.as_view(),
        name="share-link-detail",
    ),
    # --- Phase 6: public share links (anonymous) -------------------------
    path("share/<str:token>/", PublicShareLinkView.as_view(), name="public-share"),
    path(
        "share/<str:token>/verify-password/",
        PublicSharePasswordView.as_view(),
        name="public-share-password",
    ),
    path(
        "share/<str:token>/download/",
        PublicShareDownloadView.as_view(),
        name="public-share-download",
    ),
]
