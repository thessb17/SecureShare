"""Sharing APIs.

Phase 5 - authenticated user-to-user shares.
Phase 6 - public, tokenised share links (anonymous access).
"""
from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from audit.constants import AuditAction
from audit.services import record_event
from core.permissions import IsActiveUser
from files.download import build_download_response
from files.models import File
from files.services import get_file_service
from files.views import get_file_for_access
from sharing.exceptions import (
    ShareAccessDenied,
    ShareLinkDownloadLimitReached,
    ShareLinkExpired,
    ShareLinkRevoked,
    ShareNotFound,
    SharePermissionDenied,
)
from sharing.link_services import ShareLinkService
from sharing.models import FileShare, ShareLink
from sharing.serializers import (
    FileShareCreateSerializer,
    FileShareSerializer,
    FileShareUpdateSerializer,
    PublicShareLinkSerializer,
    ShareDownloadRequestSerializer,
    ShareLinkCreatedSerializer,
    ShareLinkCreateSerializer,
    ShareLinkSerializer,
    ShareLinkUpdateSerializer,
    SharePasswordSerializer,
)
from sharing.services import ShareService
from sharing.throttles import (
    ShareAccessThrottle,
    ShareCreateThrottle,
    ShareDownloadThrottle,
    SharePasswordThrottle,
)

logger = logging.getLogger("secureshare")

PASSWORD_HEADER = "X-Share-Password"  # noqa: S105 - header name, not a secret
GRANT_HEADER = "X-Share-Grant"


def _encryption_info(file_obj: File) -> dict[str, Any]:
    try:
        metadata = file_obj.encryption
    except ObjectDoesNotExist:
        return {"encrypted": False, "algorithm": None}
    return {"encrypted": True, "algorithm": metadata.algorithm}


# ===========================================================================
# Phase 5 - user to user sharing
# ===========================================================================
@extend_schema(tags=["Sharing"])
class FileShareCreateView(APIView):
    """``POST /api/files/<id>/share/`` - share a file with a registered user."""

    permission_classes = [IsActiveUser]
    throttle_classes = [ShareCreateThrottle]
    throttle_scope = "share.create"

    @extend_schema(
        request=FileShareCreateSerializer,
        responses={
            201: FileShareSerializer,
            400: OpenApiResponse(description="INVALID_RECIPIENT / VALIDATION_ERROR"),
            403: OpenApiResponse(description="Only the owner may share a file."),
            409: OpenApiResponse(description="SHARE_ALREADY_EXISTS"),
        },
    )
    def post(self, request: Request, file_id: Any) -> Response:
        file_obj, _ = get_file_for_access(request, file_id)
        serializer = FileShareCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        share = ShareService.create_share(
            file_obj=file_obj,
            actor=request.user,
            recipient_email=data["recipient"],
            permission=data["permission"],
            expires_at=data.get("expires_at"),
            request=request,
        )
        return Response(
            FileShareSerializer(share).data, status=status.HTTP_201_CREATED
        )


@extend_schema(tags=["Sharing"])
class FileShareListView(ListAPIView):
    """``GET /api/files/<id>/shares/`` - shares created for one file."""

    serializer_class = FileShareSerializer
    permission_classes = [IsActiveUser]

    def get_queryset(self):
        file_obj, _decision = get_file_for_access(self.request, self.kwargs["file_id"])
        if file_obj.owner_id != self.request.user.pk and not getattr(
            self.request.user, "is_admin", False
        ):
            raise ShareAccessDenied("Only the owner can list the shares of this file.")
        return (
            FileShare.objects.filter(file=file_obj)
            .select_related("file", "owner", "recipient")
            .order_by("-created_at")
        )


@extend_schema(tags=["Sharing"])
class MySharesListView(ListAPIView):
    """``GET /api/shares/`` - shares the authenticated user created."""

    serializer_class = FileShareSerializer
    permission_classes = [IsActiveUser]

    def get_queryset(self):
        queryset = FileShare.objects.for_owner(self.request.user).select_related(
            "file", "owner", "recipient"
        )
        if self.request.query_params.get("status") == "active":
            queryset = queryset.active()
        return queryset.order_by("-created_at")


@extend_schema(tags=["Sharing"])
class SharedWithMeListView(ListAPIView):
    """``GET /api/shared-with-me/`` - active shares addressed to the caller."""

    serializer_class = FileShareSerializer
    permission_classes = [IsActiveUser]

    def get_queryset(self):
        return (
            FileShare.objects.for_recipient(self.request.user)
            .active()
            .filter(file__deleted_at__isnull=True)
            .select_related("file", "owner", "recipient")
            .order_by("-created_at")
        )


@extend_schema(tags=["Sharing"])
class ShareDetailView(APIView):
    """``PATCH`` / ``DELETE /api/shares/<id>/``."""

    permission_classes = [IsActiveUser]

    def get_object(self, share_id: Any) -> FileShare:
        share = (
            FileShare.objects.select_related("file", "owner", "recipient")
            .filter(pk=share_id)
            .first()
        )
        if share is None:
            raise ShareNotFound()
        user = self.request.user
        # Recipients may read their own share but never manage it.
        if share.owner_id != user.pk and share.recipient_id != user.pk and not getattr(
            user, "is_admin", False
        ):
            raise ShareNotFound()
        return share

    @extend_schema(responses={200: FileShareSerializer})
    def get(self, request: Request, share_id: Any) -> Response:
        return Response(FileShareSerializer(self.get_object(share_id)).data)

    @extend_schema(request=FileShareUpdateSerializer, responses={200: FileShareSerializer})
    def patch(self, request: Request, share_id: Any) -> Response:
        share = self.get_object(share_id)
        serializer = FileShareUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        updated = ShareService.modify_share(
            share=share,
            actor=request.user,
            permission=data.get("permission"),
            expires_at=data.get("expires_at", ...),
            request=request,
        )
        return Response(FileShareSerializer(updated).data)

    @extend_schema(responses={204: OpenApiResponse(description="Share revoked.")})
    def delete(self, request: Request, share_id: Any) -> Response:
        share = self.get_object(share_id)
        ShareService.revoke_share(share=share, actor=request.user, request=request)
        return Response(status=status.HTTP_204_NO_CONTENT)


# ===========================================================================
# Phase 6 - public share links (management)
# ===========================================================================
@extend_schema(tags=["Share links"])
class ShareLinkCreateView(APIView):
    """``POST /api/files/<id>/share-link/`` - mint a public link."""

    permission_classes = [IsActiveUser]
    throttle_classes = [ShareCreateThrottle]
    throttle_scope = "share.create"

    @extend_schema(
        request=ShareLinkCreateSerializer,
        responses={
            201: ShareLinkCreatedSerializer,
            403: OpenApiResponse(description="Only the owner may create a link."),
        },
        description=(
            "Creates a capability-style public link. The raw 256-bit token is "
            "returned **once** in this response; only its SHA-256 digest is "
            "stored. Expiry is mandatory and capped by SHARE_LINK_MAX_TTL_SECONDS."
        ),
    )
    def post(self, request: Request, file_id: Any) -> Response:
        file_obj, _ = get_file_for_access(request, file_id)
        serializer = ShareLinkCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        link, raw_token = ShareLinkService.create(
            file_obj=file_obj,
            creator=request.user,
            permission=data["permission"],
            expires_at=data.get("expires_at"),
            max_downloads=data.get("max_downloads"),
            password=data.get("password") or None,
            request=request,
        )
        return Response(
            {
                "share_link": ShareLinkSerializer(link).data,
                "token": raw_token,
                "url": ShareLinkService.build_share_url(raw_token),
                "expires_at": link.expires_at,
                "permission": link.permission,
                "max_downloads": link.max_downloads,
                "warning": (
                    "Store this link now - the token is not recoverable later."
                ),
            },
            status=status.HTTP_201_CREATED,
        )


@extend_schema(
    tags=["Share links"],
    parameters=[
        OpenApiParameter("file", str, description="Filter by file UUID."),
        OpenApiParameter("status", str, description="active | inactive"),
    ],
)
class ShareLinkListView(ListAPIView):
    """``GET /api/share-links/`` - links created by the authenticated user."""

    serializer_class = ShareLinkSerializer
    permission_classes = [IsActiveUser]

    def get_queryset(self):
        queryset = ShareLink.objects.filter(created_by=self.request.user).select_related(
            "file", "created_by"
        )
        file_id = self.request.query_params.get("file")
        if file_id:
            queryset = queryset.filter(file_id=file_id)
        state = self.request.query_params.get("status")
        if state == "active":
            queryset = queryset.active()
        elif state == "inactive":
            active_ids = ShareLink.objects.active().values_list("id", flat=True)
            queryset = queryset.exclude(id__in=active_ids)
        return queryset.order_by("-created_at")


@extend_schema(tags=["Share links"])
class FileShareLinkListView(ListAPIView):
    """``GET /api/files/<id>/share-links/`` - links for one file."""

    serializer_class = ShareLinkSerializer
    permission_classes = [IsActiveUser]

    def get_queryset(self):
        file_obj, _ = get_file_for_access(self.request, self.kwargs["file_id"])
        if file_obj.owner_id != self.request.user.pk and not getattr(
            self.request.user, "is_admin", False
        ):
            raise ShareAccessDenied(
                "Only the owner can list the share links of this file."
            )
        return (
            ShareLink.objects.filter(file=file_obj)
            .select_related("file", "created_by")
            .order_by("-created_at")
        )


@extend_schema(tags=["Share links"])
class ShareLinkDetailView(APIView):
    """``GET`` / ``PATCH`` / ``DELETE /api/share-links/<id>/``."""

    permission_classes = [IsActiveUser]

    def get_object(self, link_id: Any) -> ShareLink:
        link = (
            ShareLink.objects.select_related("file", "file__owner", "created_by")
            .filter(pk=link_id)
            .first()
        )
        if link is None:
            raise ShareNotFound("The requested share link could not be found.")
        return link

    @extend_schema(responses={200: ShareLinkSerializer})
    def get(self, request: Request, link_id: Any) -> Response:
        link = self.get_object(link_id)
        ShareLinkService.assert_can_manage(link, request.user, request=request)
        return Response(ShareLinkSerializer(link).data)

    @extend_schema(request=ShareLinkUpdateSerializer, responses={200: ShareLinkSerializer})
    def patch(self, request: Request, link_id: Any) -> Response:
        link = self.get_object(link_id)
        serializer = ShareLinkUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        updated = ShareLinkService.update(
            link=link,
            actor=request.user,
            permission=data.get("permission"),
            expires_at=data.get("expires_at", ...),
            max_downloads=data.get("max_downloads", ...),
            password=data.get("password", ...),
            request=request,
        )
        return Response(ShareLinkSerializer(updated).data)

    @extend_schema(responses={204: OpenApiResponse(description="Link revoked.")})
    def delete(self, request: Request, link_id: Any) -> Response:
        link = self.get_object(link_id)
        ShareLinkService.revoke(link=link, actor=request.user, request=request)
        return Response(status=status.HTTP_204_NO_CONTENT)


# ===========================================================================
# Phase 6 - public share links (anonymous access)
# ===========================================================================
@extend_schema(tags=["Public share"])
class PublicShareLinkView(APIView):
    """``GET /api/share/<token>/`` - metadata for an anonymous visitor."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [ShareAccessThrottle]
    throttle_scope = "share.access"

    @extend_schema(
        responses={
            200: PublicShareLinkSerializer,
            404: OpenApiResponse(description="SHARE_LINK_NOT_FOUND"),
            410: OpenApiResponse(
                description="SHARE_LINK_EXPIRED / SHARE_LINK_REVOKED / "
                "SHARE_LINK_DOWNLOAD_LIMIT_REACHED"
            ),
            429: OpenApiResponse(description="RATE_LIMIT_EXCEEDED"),
        },
        description=(
            "Returns the file metadata behind a share token. For password "
            "protected links the response only contains `password_required: true` "
            "until the password is supplied via the X-Share-Password header or a "
            "grant obtained from /verify-password/."
        ),
    )
    def get(self, request: Request, token: str) -> Response:
        link = ShareLinkService.resolve(token, request=request)
        link.register_access()

        password = request.headers.get(PASSWORD_HEADER)
        grant = request.headers.get(GRANT_HEADER)
        satisfied = ShareLinkService.password_satisfied(
            link, password=password, grant=grant, request=request
        )

        record_event(
            action=AuditAction.SHARE_LINK_ACCESSED,
            request=request,
            message="Share link metadata accessed.",
            object_type="share_link",
            object_id=link.id,
            object_owner=link.file.owner,
            metadata={
                "token_prefix": link.token_prefix,
                "file_id": str(link.file_id),
                "password_protected": link.requires_password,
                "unlocked": satisfied,
            },
        )

        if link.requires_password and not satisfied:
            return Response(
                {
                    "password_required": True,
                    "message": "This share link is password protected.",
                }
            )

        payload = {
            "filename": link.file.original_filename,
            "size": link.file.file_size,
            "mime_type": link.file.mime_type,
            "permission": link.permission,
            "expires_at": link.expires_at,
            "expires_in_seconds": link.expires_in_seconds,
            "max_downloads": link.max_downloads,
            "download_count": link.download_count,
            "downloads_remaining": link.downloads_remaining,
            "password_required": link.requires_password,
            "encryption": _encryption_info(link.file),
        }
        return Response(PublicShareLinkSerializer(payload).data)


@extend_schema(tags=["Public share"])
class PublicSharePasswordView(APIView):
    """``POST /api/share/<token>/verify-password/`` - exchange a password for a grant."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [SharePasswordThrottle]
    throttle_scope = "share.password"

    @extend_schema(
        request=SharePasswordSerializer,
        responses={
            200: OpenApiResponse(description="Short-lived grant token."),
            403: OpenApiResponse(description="SHARE_LINK_PASSWORD_INVALID"),
            429: OpenApiResponse(description="SHARE_LINK_LOCKED / RATE_LIMIT_EXCEEDED"),
        },
    )
    def post(self, request: Request, token: str) -> Response:
        link = ShareLinkService.resolve(token, request=request)
        if not link.requires_password:
            return Response({"password_required": False, "grant": None})

        serializer = SharePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ShareLinkService.authorize(
            link,
            password=serializer.validated_data["password"],
            grant=None,
            request=request,
        )
        return Response(
            {
                "password_required": True,
                "grant": ShareLinkService.issue_grant(link),
                "expires_in": int(settings.SHARE_LINK_GRANT_TTL_SECONDS),
            }
        )


@extend_schema(tags=["Public share"])
class PublicShareDownloadView(APIView):
    """``POST /api/share/<token>/download/`` - decrypt and stream the file."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [ShareDownloadThrottle]
    throttle_scope = "share.download"

    @extend_schema(
        request=ShareDownloadRequestSerializer,
        responses={
            200: OpenApiResponse(description="Decrypted file stream (attachment)."),
            401: OpenApiResponse(description="SHARE_LINK_PASSWORD_REQUIRED"),
            403: OpenApiResponse(
                description="SHARE_LINK_PASSWORD_INVALID / SHARE_PERMISSION_DENIED"
            ),
            404: OpenApiResponse(description="SHARE_LINK_NOT_FOUND"),
            410: OpenApiResponse(
                description="SHARE_LINK_EXPIRED / SHARE_LINK_REVOKED / "
                "SHARE_LINK_DOWNLOAD_LIMIT_REACHED"
            ),
            429: OpenApiResponse(description="SHARE_LINK_LOCKED / RATE_LIMIT_EXCEEDED"),
        },
        description=(
            "Download limits are enforced with a single atomic SQL UPDATE, so "
            "concurrent requests can never exceed max_downloads."
        ),
    )
    def post(self, request: Request, token: str) -> Any:
        link = ShareLinkService.resolve(token, request=request)

        if not link.allows_download:
            record_event(
                action=AuditAction.UNAUTHORIZED_SHARE_ACCESS,
                request=request,
                success=False,
                message="Download denied: the link grants view-only access.",
                object_type="share_link",
                object_id=link.id,
                object_owner=link.file.owner,
                metadata={"token_prefix": link.token_prefix, "permission": link.permission},
            )
            raise SharePermissionDenied()

        serializer = ShareDownloadRequestSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data.get("password") or request.headers.get(
            PASSWORD_HEADER
        )
        grant = serializer.validated_data.get("grant") or request.headers.get(
            GRANT_HEADER
        )
        ShareLinkService.authorize(
            link, password=password, grant=grant, request=request
        )

        # --- atomic reservation of one download slot ----------------------
        if not ShareLinkService.claim_download_slot(link):
            link.refresh_from_db()
            if link.is_revoked:
                raise ShareLinkRevoked()
            if link.is_expired:
                raise ShareLinkExpired()
            record_event(
                action=AuditAction.DOWNLOAD_LIMIT_REACHED,
                request=request,
                success=False,
                message="Download rejected: the link download limit is exhausted.",
                object_type="share_link",
                object_id=link.id,
                object_owner=link.file.owner,
                metadata={
                    "token_prefix": link.token_prefix,
                    "download_count": link.download_count,
                    "max_downloads": link.max_downloads,
                },
            )
            raise ShareLinkDownloadLimitReached()

        try:
            response = build_download_response(
                file_obj=link.file, service=get_file_service(), request=request
            )
        except Exception:
            # Nothing was delivered: give the reserved slot back.
            ShareLinkService.release_download_slot(link)
            raise

        link.file.register_download()
        link.refresh_from_db(fields=["download_count"])

        record_event(
            action=AuditAction.SHARE_LINK_DOWNLOAD,
            request=request,
            message="File downloaded through a public share link.",
            object_type="share_link",
            object_id=link.id,
            object_owner=link.file.owner,
            metadata={
                "token_prefix": link.token_prefix,
                "file_id": str(link.file_id),
                "filename": link.file.original_filename,
                "download_count": link.download_count,
                "max_downloads": link.max_downloads,
            },
        )
        if link.is_exhausted:
            record_event(
                action=AuditAction.DOWNLOAD_LIMIT_REACHED,
                request=request,
                success=True,
                message="Share link reached its download limit.",
                object_type="share_link",
                object_id=link.id,
                object_owner=link.file.owner,
                metadata={
                    "token_prefix": link.token_prefix,
                    "download_count": link.download_count,
                    "max_downloads": link.max_downloads,
                },
            )

        remaining = link.downloads_remaining
        response["X-Share-Downloads-Remaining"] = (
            "unlimited" if remaining is None else str(remaining)
        )
        return response
