from __future__ import annotations

from django.urls import path

from files.views import (
    FileDetailView,
    FileDownloadView,
    FileListView,
    FileUploadView,
)

urlpatterns = [
    path("files/", FileListView.as_view(), name="file-list"),
    path("files/upload/", FileUploadView.as_view(), name="file-upload"),
    path("files/<uuid:file_id>/", FileDetailView.as_view(), name="file-detail"),
    path(
        "files/<uuid:file_id>/download/",
        FileDownloadView.as_view(),
        name="file-download",
    ),
]
