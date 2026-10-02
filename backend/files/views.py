"""Authenticated file APIs: upload, list, detail, download, delete."""
from __future__ import annotations

import logging
from typing import Any

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from audit.constants import AuditAction
from audit.services import record_event
from core.permissions import IsActiveUser
from files.access import AccessDecision, AccessVia, resolve_file_access
from files.download import build_download_response
from files.exceptions import FileAccessDenied, FileNotFound
from files.models import File
from files.serializers import FileSerializer, FileUploadSerializer
from files.services import get_file_service
from files.throttles import FileDownloadThrottle, FileUploadThrottle

logger = logging.getLogger("secureshare")


def get_file_for_access(
    request: Request, file_id: Any, *, need_download: bool = False
) -> tuple[File, AccessDecision]:
    """Fetch a file and enforce authorization, auditing every denial."""
    file_obj = (
        File.objects.select_related("owner", "encryption")
        .filter(pk=file_id, deleted_at__isnull=True)
        .first()
    )
    if file_obj is None or not file_obj.is_available:
        raise FileNotFound()

    decision = resolve_file_access(request.user, file_obj)
    if not decision.can_view:
        record_event(
            action=AuditAction.UNAUTHORIZED_FILE_ACCESS,
            request=request,
            user=request.user,
            success=False,
            message="Access denied to a file owned by another user.",
            object_type="file",
            object_id=file_obj.id,
            object_owner=file_obj.owner,
            metadata={"reason": "not_authorized"},
        )
        # Deliberately a 404, not a 403: a 403 would confirm that this file id
        # exists, turning the endpoint into an existence oracle for attackers
        # enumerating UUIDs. The denial is still recorded in the audit log.
        raise FileNotFound()

    if need_download and not decision.can_download:
        record_event(
            action=AuditAction.UNAUTHORIZED_FILE_ACCESS,
            request=request,
            user=request.user,
            success=False,
            message="Download denied: the share grants view-only access.",
            object_type="file",
            object_id=file_obj.id,
            object_owner=file_obj.owner,
            metadata={"reason": "view_only_permission", "via": str(decision.via)},
        )
        raise FileAccessDenied(
            "This file was shared with view-only permission.",
            error_code="SHARE_PERMISSION_DENIED",
        )
    return file_obj, decision


@extend_schema(tags=["Files"])
class FileUploadView(APIView):
    """``POST /api/files/upload/`` - validate, scan, encrypt and store."""

    permission_classes = [IsActiveUser]
    parser_classes = [MultiPartParser, FormParser]
    throttle_classes = [FileUploadThrottle]
    throttle_scope = "files.upload"

    @extend_schema(
        request={"multipart/form-data": FileUploadSerializer},
        responses={
            201: FileSerializer,
            400: OpenApiResponse(description="INVALID_FILENAME / MALFORMED_UPLOAD"),
            413: OpenApiResponse(description="FILE_TOO_LARGE"),
            415: OpenApiResponse(description="UNSUPPORTED_FILE_TYPE"),
            422: OpenApiResponse(description="MALWARE_DETECTED"),
        },
        description=(
            "Upload a file. The server validates size, filename, extension and "
            "magic bytes, optionally runs ClamAV, then encrypts the content with "
            "a per-file AES-256-GCM key whose DEK is wrapped with RSA-OAEP."
        ),
    )
    def post(self, request: Request) -> Response:
        serializer = FileUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        file_obj = get_file_service().upload(
            owner=request.user,
            uploaded_file=serializer.validated_data["file"],
            request=request,
        )
        return Response(
            FileSerializer(file_obj, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )


@extend_schema(
    tags=["Files"],
    parameters=[
        OpenApiParameter("q", str, description="Case-insensitive filename search."),
        OpenApiParameter(
            "ordering",
            str,
            description="created_at | -created_at | filename | size (prefix with - to reverse).",
        ),
    ],
)
class FileListView(ListAPIView):
    """``GET /api/files/`` - the authenticated user's own files."""

    serializer_class = FileSerializer
    permission_classes = [IsActiveUser]

    ORDERING_MAP = {
        "created_at": "created_at",
        "-created_at": "-created_at",
        "filename": "original_filename",
        "-filename": "-original_filename",
        "size": "file_size",
        "-size": "-file_size",
    }

    def get_queryset(self):
        queryset = (
            File.objects.active()
            .owned_by(self.request.user)
            .select_related("owner", "encryption")
        )
        search = self.request.query_params.get("q")
        if search:
            queryset = queryset.filter(original_filename__icontains=search[:120])
        ordering = self.ORDERING_MAP.get(
            self.request.query_params.get("ordering", "-created_at"), "-created_at"
        )
        return queryset.order_by(ordering)


@extend_schema(tags=["Files"])
class FileDetailView(APIView):
    """``GET /api/files/<id>/`` and ``DELETE /api/files/<id>/``."""

    permission_classes = [IsActiveUser]

    @extend_schema(
        responses={200: FileSerializer, 403: OpenApiResponse(), 404: OpenApiResponse()}
    )
    def get(self, request: Request, file_id: Any) -> Response:
        file_obj, decision = get_file_for_access(request, file_id)
        if decision.via == AccessVia.SHARE:
            record_event(
                action=AuditAction.SHARE_ACCESSED,
                request=request,
                user=request.user,
                message="Shared file metadata viewed.",
                object_type="file",
                object_id=file_obj.id,
                object_owner=file_obj.owner,
                metadata={"share_id": str(decision.share.id) if decision.share else None},
            )
        return Response(FileSerializer(file_obj, context={"request": request}).data)

    @extend_schema(responses={204: OpenApiResponse(description="File deleted.")})
    def delete(self, request: Request, file_id: Any) -> Response:
        file_obj, decision = get_file_for_access(request, file_id)
        if decision.via not in (AccessVia.OWNER, AccessVia.ADMIN):
            record_event(
                action=AuditAction.UNAUTHORIZED_FILE_ACCESS,
                request=request,
                user=request.user,
                success=False,
                message="Delete denied: only the owner or an administrator may delete.",
                object_type="file",
                object_id=file_obj.id,
                object_owner=file_obj.owner,
                metadata={"reason": "delete_requires_ownership"},
            )
            raise FileAccessDenied("Only the owner can delete this file.")

        get_file_service().delete(file_obj=file_obj, actor=request.user, request=request)
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(tags=["Files"])
class FileDownloadView(APIView):
    """``GET /api/files/<id>/download/`` - authorize, decrypt, stream."""

    permission_classes = [IsActiveUser]
    throttle_classes = [FileDownloadThrottle]
    throttle_scope = "files.download"

    @extend_schema(
        responses={
            200: OpenApiResponse(description="Decrypted file stream (attachment)."),
            403: OpenApiResponse(description="ACCESS_DENIED / SHARE_PERMISSION_DENIED"),
            404: OpenApiResponse(description="FILE_NOT_FOUND"),
            410: OpenApiResponse(description="ENCRYPTED_OBJECT_MISSING"),
            422: OpenApiResponse(description="FILE_INTEGRITY_ERROR"),
        }
    )
    def get(self, request: Request, file_id: Any) -> Any:
        file_obj, decision = get_file_for_access(request, file_id, need_download=True)
        service = get_file_service()

        response = build_download_response(
            file_obj=file_obj, service=service, request=request
        )
        file_obj.register_download()

        record_event(
            action=AuditAction.FILE_DOWNLOADED,
            request=request,
            user=request.user,
            message="File downloaded and decrypted.",
            object_type="file",
            object_id=file_obj.id,
            object_owner=file_obj.owner,
            metadata={
                "filename": file_obj.original_filename,
                "size": file_obj.file_size,
                "via": str(decision.via),
                "share_id": str(decision.share.id) if decision.share else None,
            },
        )
        if decision.via == AccessVia.SHARE:
            record_event(
                action=AuditAction.SHARE_ACCESSED,
                request=request,
                user=request.user,
                message="Shared file downloaded.",
                object_type="file",
                object_id=file_obj.id,
                object_owner=file_obj.owner,
                metadata={"share_id": str(decision.share.id) if decision.share else None},
            )
        elif decision.via == AccessVia.ADMIN:
            record_event(
                action=AuditAction.ADMIN_ACTION,
                request=request,
                user=request.user,
                message="Administrator downloaded a user's file.",
                object_type="file",
                object_id=file_obj.id,
                object_owner=file_obj.owner,
            )
        return response
