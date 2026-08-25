import os

from django.conf import settings
from django.http import FileResponse, Http404
from django.db import transaction
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, status
from rest_framework.exceptions import PermissionDenied
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_datatables.filters import DatatablesFilterBackend
from sentry_sdk import capture_exception

from apps.console.storage.models import CoreStorage
from apps._tasks.integration.storage.tasks import (
    delete_storage_requested,
    validate_local_storage,
)
from .filters import CoreStorageLocalFilter
from .permissions import CoreStorageLocalPermissions
from .serializers import CoreStorageReadSerializer, CoreStorageWriteSerializer
from ...utils.api_filters import DateRangeFilter
from ...utils.api_helpers import visible_nodes
from ...utils.api_permissions import member_has_perm
from ...utils.api_serializers import ReadWriteSerializerMixin


class CoreStorageLocalView(ReadWriteSerializerMixin, viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreStorageLocalPermissions,)
    read_serializer_class = CoreStorageReadSerializer
    write_serializer_class = CoreStorageWriteSerializer
    all_fields = [f.name for f in CoreStorage._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreStorageLocalFilter
    search_fields = ["name", "type__code", "type__name"]

    def get_queryset(self):
        member = self.request.user.member
        query = Q(account=member.get_current_account(), type__code="local")
        # A deletion lease may already be mutating a point. Keep the durable
        # request out of every interactive action until it completes or is
        # restored to ACTIVE because deletion protection deferred it.
        query &= ~Q(status=CoreStorage.Status.DELETE_REQUESTED)
        queryset = CoreStorage.objects.filter(query)
        return queryset

    @staticmethod
    def _publish_after_commit(task, storage_id):
        def publish():
            try:
                task.apply_async(args=[storage_id])
            except Exception as error:
                # The PENDING/DELETE_REQUESTED row is the durable recovery source;
                # Beat republishes it after a transient broker outage.
                capture_exception(error)

        transaction.on_commit(publish)

    def destroy(self, request, *args, **kwargs):
        storage = self.get_object()
        storage.delete_requested()
        self._publish_after_commit(delete_storage_requested, storage.pk)
        return Response(
            {"detail": "Local Storage deletion was scheduled."},
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["get"])
    def validate(self, request, pk=None):
        storage = self.get_object()
        # The API records intent only. The RW worker resolves the configured path
        # from this account-scoped row and never accepts a path via Celery.
        storage.status = CoreStorage.Status.PENDING
        storage.save(update_fields=["status", "modified"])
        self._publish_after_commit(validate_local_storage, storage.pk)
        return Response(
            {
                "detail": (
                    "Local Storage validation was scheduled. The destination "
                    "will become Active only after the storage worker verifies it."
                )
            },
            status=status.HTTP_202_ACCEPTED,
        )


class LocalStorageFileDownloadView(APIView):
    """Streams a 'Local Storage' backup zip through the app. Local backups have no
    provider URL to redirect to, so generate_download_url() points here instead.
    Account-scoped and confined to LOCAL_STORAGE_ROOT; anything else is a 404."""

    permission_classes = (IsAuthenticated,)

    def get(self, request, stored_backup_id):
        from apps.console.backup.models import (
            CoreWebsiteBackupStoragePoints,
            CoreDatabaseBackupStoragePoints,
            CoreWordPressBackupStoragePoints,
            CoreBasecampBackupStoragePoints,
        )

        account = request.user.member.get_current_account()
        if not member_has_perm(request, "backup_download"):
            raise PermissionDenied("You do not have permission to download backups.")

        allowed_nodes = visible_nodes(request.user.member)

        stored_backup = None
        for model, node_lookup in (
                (CoreWebsiteBackupStoragePoints, "backup__website__node"),
                (CoreDatabaseBackupStoragePoints, "backup__database__node"),
                (CoreWordPressBackupStoragePoints, "backup__wordpress__node"),
                (CoreBasecampBackupStoragePoints, "backup__basecamp__node"),
        ):
            stored_backup = model.objects.filter(
                id=stored_backup_id,
                storage__account=account,
                storage__type__code="local",
                status=model.Status.UPLOAD_COMPLETE,
                storage_file_id__isnull=False,
                **{f"{node_lookup}__in": allowed_nodes},
            ).first()
            if stored_backup:
                break

        if not stored_backup:
            raise Http404

        if not stored_backup.direct_download_permitted():
            # The web container must never regain a /backups mount merely to
            # decrypt an object.  A future export workflow can authenticate BSE1
            # in a private source lane and publish a short-lived result; until
            # then, fail closed rather than serving ciphertext with a .zip name.
            return Response(
                {
                    "detail": (
                        "Direct ZIP download is disabled for encrypted backup "
                        "artifacts. Use an authenticated restore or export workflow."
                    ),
                    "artifact_format": "bse1",
                },
                status=status.HTTP_409_CONFLICT,
            )

        local_root = os.path.realpath(settings.LOCAL_STORAGE_ROOT)
        target = os.path.realpath(stored_backup.storage_file_id)
        if target != local_root and not target.startswith(local_root + os.sep):
            raise Http404
        if not os.path.isfile(target):
            raise Http404

        return FileResponse(
            open(target, "rb"),
            as_attachment=True,
            filename=f"{stored_backup.backup.uuid_str}.zip",
        )
