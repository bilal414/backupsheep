import uuid

from django.db import IntegrityError, transaction
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.pagination import CursorPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_datatables.filters import DatatablesFilterBackend
from sentry_sdk import capture_exception

from apps.api.v1.cloud.lightsail_bucket_replication.permissions import (
    CoreLightsailBucketReplicationViewPermissions,
)
from apps.api.v1.cloud.lightsail_bucket_replication.serializers import (
    CoreLightsailBucketReplicationObjectSerializer,
    CoreLightsailBucketReplicationReadSerializer,
    CoreLightsailBucketReplicationRunSerializer,
    CoreLightsailBucketReplicationWriteSerializer,
    CoreLightsailBucketRestoreRunSerializer,
)
from apps.api.v1.utils.api_filters import DateRangeFilter
from apps.api.v1.utils.api_serializers import ReadWriteSerializerMixin
from apps.console.backup.replication_models import (
    CoreLightsailBucketReplication,
    CoreLightsailBucketReplicationObject,
    CoreLightsailBucketReplicationRun,
    CoreLightsailBucketRestoreRun,
)
from apps.console.storage.models import CoreStorage


class LightsailObjectProgressPagination(CursorPagination):
    page_size = 100
    page_size_query_param = "page_size"
    max_page_size = 500
    ordering = "id"


class CoreLightsailBucketReplicationView(
    ReadWriteSerializerMixin, viewsets.ModelViewSet
):
    permission_classes = (
        IsAuthenticated,
        CoreLightsailBucketReplicationViewPermissions,
    )
    read_serializer_class = CoreLightsailBucketReplicationReadSerializer
    write_serializer_class = CoreLightsailBucketReplicationWriteSerializer
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    search_fields = (
        "name",
        "source_bucket_name",
        "source_prefix",
        "destination_prefix",
        "status",
    )

    def get_queryset(self):
        member = self.request.user.member
        account = member.get_current_account()
        query = Q(account=account)
        return CoreLightsailBucketReplication.objects.filter(query).select_related(
            "source_connection",
            "destination_storage",
            "last_run",
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.enabled = False
        instance.status = CoreLightsailBucketReplication.Status.PAUSED
        instance.save(update_fields=["enabled", "status", "modified"])
        return Response(status=status.HTTP_204_NO_CONTENT)

    @staticmethod
    def _idempotency_key(request, prefix):
        supplied = request.headers.get("Idempotency-Key") or request.data.get(
            "idempotency_key"
        )
        return str(supplied or f"{prefix}:{uuid.uuid4().hex}")[:255]

    @staticmethod
    def _get_or_create_run(replication, key):
        defaults = {
            "status": CoreLightsailBucketReplicationRun.Status.PENDING,
        }
        try:
            run, _ = CoreLightsailBucketReplicationRun.objects.get_or_create(
                replication=replication,
                idempotency_key=key,
                defaults=defaults,
            )
        except IntegrityError:
            run = CoreLightsailBucketReplicationRun.objects.get(
                replication=replication, idempotency_key=key
            )
        return run

    @action(detail=True, methods=["post"])
    def run(self, request, pk=None):
        replication = self.get_object()
        key = self._idempotency_key(request, "manual")
        with transaction.atomic():
            run = self._get_or_create_run(replication, key)
            if run.status == CoreLightsailBucketReplicationRun.Status.COMPLETE:
                return Response(
                    CoreLightsailBucketReplicationRunSerializer(run).data,
                    status=status.HTTP_200_OK,
                )
            # The idempotency key is also the durable dispatch boundary.  A
            # retried HTTP request must observe the existing Celery id instead of
            # publishing a second task for the same run.
            if run.celery_task_id:
                return Response(
                    CoreLightsailBucketReplicationRunSerializer(run).data,
                    status=status.HTTP_202_ACCEPTED,
                )
            from apps._tasks.integration.lightsail_bucket import (
                start_lightsail_bucket_replication,
            )

            task_id = f"lightsail-bucket-run-{run.id}-{uuid.uuid4().hex}"
            run.celery_task_id = task_id
            run.save(update_fields=["celery_task_id", "modified"])
            transaction.on_commit(
                lambda: start_lightsail_bucket_replication.apply_async(
                    task_id=task_id,
                    kwargs={
                        "replication_id": replication.id,
                        "run_id": run.id,
                        "idempotency_key": key,
                    },
                )
            )
        return Response(
            CoreLightsailBucketReplicationRunSerializer(run).data,
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["get"])
    def runs(self, request, pk=None):
        replication = self.get_object()
        rows = replication.runs.order_by("-created")
        return Response(CoreLightsailBucketReplicationRunSerializer(rows, many=True).data)

    @action(detail=True, methods=["get"], url_path=r"runs/(?P<run_pk>[^/.]+)/objects")
    def objects(self, request, pk=None, run_pk=None):
        replication = self.get_object()
        run = replication.runs.filter(pk=run_pk).first()
        if run is None:
            return Response({"detail": "Replication run not found."}, status=404)
        rows = run.object_states.order_by("key", "source_version_id", "id")
        paginator = LightsailObjectProgressPagination()
        page = paginator.paginate_queryset(rows, request, view=self)
        serializer = CoreLightsailBucketReplicationObjectSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    @action(detail=True, methods=["post"])
    def restore(self, request, pk=None):
        replication = self.get_object()
        source_run_id = request.data.get("source_run_id")
        source_run = None
        if source_run_id is not None:
            source_run = replication.runs.filter(pk=source_run_id).first()
            if source_run is None:
                return Response({"detail": "Source run not found."}, status=404)
        else:
            source_run = replication.last_run
        if source_run is None:
            return Response(
                {"detail": "A completed replication run is required for restore."},
                status=400,
            )
        if source_run.status not in (
            CoreLightsailBucketReplicationRun.Status.COMPLETE,
            CoreLightsailBucketReplicationRun.Status.FAILED,
        ):
            return Response(
                {"detail": "The source run is not ready for restore."}, status=400
            )
        key = self._idempotency_key(request, "restore")
        restore_prefix = str(request.data.get("restore_prefix") or "")
        target_prefix = request.data.get("target_prefix")
        with transaction.atomic():
            normalized_restore_prefix = CoreLightsailBucketReplication.normalize_prefix(
                restore_prefix
            )
            effective_target_prefix = (
                CoreLightsailBucketReplication.normalize_prefix(target_prefix)
                if target_prefix is not None
                else CoreLightsailBucketReplication.normalize_prefix(
                    f"{replication.source_prefix or ''}{normalized_restore_prefix}"
                )
            )
            effective_destination_prefix = (
                CoreLightsailBucketReplication.normalize_prefix(
                    f"{replication.destination_prefix or ''}{normalized_restore_prefix}"
                )
            )
            defaults = {
                "source_run": source_run,
                "restore_prefix": normalized_restore_prefix,
                "target_prefix": effective_target_prefix,
                "destination_prefix": effective_destination_prefix,
                "status": CoreLightsailBucketRestoreRun.Status.PENDING,
            }
            try:
                restore_run, created = CoreLightsailBucketRestoreRun.objects.get_or_create(
                    replication=replication,
                    idempotency_key=key,
                    defaults=defaults,
                )
            except IntegrityError:
                restore_run = CoreLightsailBucketRestoreRun.objects.get(
                    replication=replication, idempotency_key=key
                )
                created = False
            if not created and (
                restore_run.source_run_id != source_run.id
                or restore_run.restore_prefix != normalized_restore_prefix
                or restore_run.target_prefix != effective_target_prefix
                or restore_run.destination_prefix != effective_destination_prefix
            ):
                return Response(
                    {
                        "detail": "This idempotency key belongs to a different restore request."
                    },
                    status=status.HTTP_409_CONFLICT,
                )
            if restore_run.status == CoreLightsailBucketRestoreRun.Status.COMPLETE:
                return Response(
                    CoreLightsailBucketRestoreRunSerializer(restore_run).data,
                    status=status.HTTP_200_OK,
                )
            if restore_run.celery_task_id:
                return Response(
                    CoreLightsailBucketRestoreRunSerializer(restore_run).data,
                    status=status.HTTP_202_ACCEPTED,
                )
            from apps._tasks.integration.lightsail_bucket import (
                restore_lightsail_bucket_replication,
            )

            task_id = f"lightsail-bucket-restore-{restore_run.id}-{uuid.uuid4().hex}"
            restore_run.celery_task_id = task_id
            restore_run.save(update_fields=["celery_task_id", "modified"])
            transaction.on_commit(
                lambda: restore_lightsail_bucket_replication.apply_async(
                    task_id=task_id,
                    kwargs={
                        "replication_id": replication.id,
                        "restore_id": restore_run.id,
                        "source_run_id": getattr(source_run, "id", None),
                        "restore_prefix": normalized_restore_prefix,
                        "target_prefix": effective_target_prefix,
                        "idempotency_key": key,
                    },
                )
            )
        return Response(
            CoreLightsailBucketRestoreRunSerializer(restore_run).data,
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["get"])
    def restores(self, request, pk=None):
        replication = self.get_object()
        rows = replication.restore_runs.order_by("-created")
        return Response(CoreLightsailBucketRestoreRunSerializer(rows, many=True).data)

    @action(detail=True, methods=["post"])
    def validate(self, request, pk=None):
        replication = self.get_object()
        try:
            from apps._tasks.integration.lightsail_bucket import (
                _validate_replication_scope,
                _destination_bucket,
                _failure_for,
                build_destination_client,
                build_source_client,
            )

            _validate_replication_scope(replication)
            source = build_source_client(replication)
            destination = build_destination_client(replication.destination_storage)
            source.head_bucket(Bucket=replication.source_bucket_name)
            destination.head_bucket(
                Bucket=_destination_bucket(replication.destination_storage)
            )
        except Exception as error:
            capture_exception(getattr(error, "__cause__", None) or error)
            failure = _failure_for(error)
            return Response(
                {
                    "valid": False,
                    "detail": failure.message,
                    "error": failure.as_dict(),
                },
                status=400,
            )
        return Response({"valid": True})
