import os

from django.conf import settings
from django.http import FileResponse, Http404
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_datatables.filters import DatatablesFilterBackend

from apps.console.storage.models import CoreStorage
from .filters import CoreStorageLocalFilter
from .permissions import CoreStorageLocalPermissions
from .serializers import CoreStorageReadSerializer, CoreStorageWriteSerializer
from apps._tasks.exceptions import StorageValidationFailed
from ...utils.api_filters import DateRangeFilter
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
        # query &= ~Q(status=CoreStorage.Status.DELETE_REQUESTED)
        queryset = CoreStorage.objects.filter(query)
        return queryset

    def destroy(self, request, *args, **kwargs):
        storage = self.get_object()
        storage.delete_requested()
        return Response(status=status.HTTP_204_NO_CONTENT, data={})

    @action(detail=True, methods=["get"])
    def validate(self, request, pk=None):
        try:
            storage = self.get_object()
            validation = storage.storage_local.validate()
            if validation:
                return Response(
                    {"detail": "Validation passed. Storage is good for backups."},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "detail": "Validation failed. Backups will fail. Check storage details immediately."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            raise StorageValidationFailed(e.__str__())


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

        stored_backup = None
        for model in (
                CoreWebsiteBackupStoragePoints,
                CoreDatabaseBackupStoragePoints,
                CoreWordPressBackupStoragePoints,
                CoreBasecampBackupStoragePoints,
        ):
            stored_backup = model.objects.filter(
                id=stored_backup_id,
                storage__account=account,
                storage__type__code="local",
                status=model.Status.UPLOAD_COMPLETE,
                storage_file_id__isnull=False,
            ).first()
            if stored_backup:
                break

        if not stored_backup:
            raise Http404

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
