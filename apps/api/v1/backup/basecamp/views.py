import arrow
import boto3
import pytz
from botocore.config import Config
from django.conf import settings
from django.db.models import Q
from django.utils.timezone import get_current_timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response

from apps._tasks.exceptions import (
    SnapshotCreateMissingParams,
    SnapshotCreateError,
    DownloadMissingParams,
    DownloadStoragePointNotFound,
    DownloadStoragePointError,
    StoragePointError,
)
from apps.api.v1.backup.basecamp.filters import CoreBasecampBackupFilter
from apps.api.v1.backup.basecamp.permissions import (
    CoreBasecampBackupViewPermissions,
)
from apps.api.v1.backup.basecamp.serializers import (
    CoreBasecampBackupSerializer,
    CoreBasecampBackupStoragePointsSerializer,
)
from apps.api.v1.utils.api_filters import DateRangeFilter
from apps.api.v1.utils.api_helpers import get_start_end_of_previous_day
from apps.console.backup.models import CoreBasecampBackup
from apps.console.log.models import CoreLog
from apps.console.node.models import CoreNode
from rest_framework import status
from google.cloud import storage as gc_storage
from google.oauth2 import service_account


def _log_activity(request, log_type, data):
    """Write an activity-log row; never let logging break the view."""
    try:
        CoreLog.record(request.user.member.get_current_account(), log_type, data)
    except Exception:
        pass


class CoreBasecampBackupView(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreBasecampBackupViewPermissions)
    serializer_class = CoreBasecampBackupSerializer
    all_fields = [f.name for f in CoreBasecampBackup._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreBasecampBackupFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(basecamp__node__connection__account=member.get_current_account())
        query &= ~Q(basecamp__node__status=CoreNode.Status.DELETE_REQUESTED)
        query &= ~Q(status=CoreBasecampBackup.Status.DELETE_REQUESTED)
        if self.request.query_params.get("node"):
            query &= Q(basecamp__node__id=self.request.query_params.get("node"))
        queryset = CoreBasecampBackup.objects.filter(query)
        return queryset

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.soft_delete()
        return Response(status=status.HTTP_204_NO_CONTENT, data={})

    @action(detail=True, methods=["post"])
    def cancel(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.cancel()
        return Response(status=status.HTTP_202_ACCEPTED, data={})

    @action(detail=True, methods=["post"])
    def retry(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.retry()
        return Response(status=status.HTTP_202_ACCEPTED, data={})

    @action(detail=True)
    def download(self, request, pk=None):
        storage_point_id = self.request.query_params.get("storage_point_id")
        if storage_point_id:
            try:
                backup = self.get_object()
                if backup.stored_basecamp_backups.filter(id=storage_point_id).exists():
                    storage_point = backup.stored_basecamp_backups.get(id=storage_point_id)
                    download_url = storage_point.generate_download_url()
                    _log_activity(
                        request,
                        CoreLog.Type.BACKUP,
                        {
                            "message": f"Download URL generated for backup '{backup.uuid_str}'.",
                            "action": "download",
                            "actor_email": request.user.email,
                            "backup_id": backup.id,
                            "backup_name": backup.name,
                            "node_id": backup.basecamp.node_id,
                            "node_name": backup.basecamp.node.name,
                            "connection_id": backup.basecamp.node.connection_id,
                            "connection_name": backup.basecamp.node.connection.name,
                        },
                    )
                    return Response({"url": download_url, "expire_in": 24 * 3600}, status=status.HTTP_201_CREATED)
                else:
                    raise DownloadStoragePointNotFound()
            except Exception as e:
                raise DownloadStoragePointError(e.__str__())
        else:
            raise DownloadMissingParams()

    @action(detail=True)
    def download_transfer_log(self, request, pk=None):
        backup = self.get_object()
        s3_endpoint = f"https://{settings.AWS_S3_LOGS_ENDPOINT}"

        if "fra.idrivee" in s3_endpoint:
            access_key = settings.IDRIVE_FRA_ACCESS_KEY
            secret_key = settings.IDRIVE_FRA_SECRET_ACCESS_KEY
        else:
            access_key = settings.AWS_S3_ACCESS_KEY
            secret_key = settings.AWS_S3_SECRET_ACCESS_KEY

        s3_client = boto3.client(
            "s3",
            endpoint_url=s3_endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(region_name=settings.AWS_S3_LOGS_REGION, signature_version="v4")
        )
        response = s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": settings.AWS_S3_LOGS_BUCKET,
                "Key": f"{backup.uuid_str}.log",
            },
            ExpiresIn=24 * 3600,
        )
        return Response({"url": response, "expire_in": 24 * 3600}, status=status.HTTP_201_CREATED)

    @action(detail=True)
    def storage_points(self, request, pk=None):
        try:
            backup = self.get_object()
            storage_points = CoreBasecampBackupStoragePointsSerializer(
                backup.stored_basecamp_backups.all(), many=True
            ).data
            return Response(storage_points, status=status.HTTP_200_OK)
        except Exception as e:
            raise StoragePointError(e.__str__())

    @action(detail=False)
    def highcharts(self, request):
        graph = {"categories": [], "series": []}
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)

        start_time = arrow.get(get_start_end_of_previous_day(days=30)["start_time"])
        end_time = arrow.get(get_start_end_of_previous_day(days=0)["start_time"])

        temp_data = []
        for r in arrow.Arrow.span_range("day", start_time.astimezone(timezone), end_time.astimezone(timezone)):
            backup_count = (
                self.get_queryset()
                .filter(
                    created__gte=r[0].datetime,
                    created__lte=r[1].datetime,
                )
                .count()
            )

            temp_data.append(backup_count)

        graph["series"].append(
            {
                "name": "Website",
                "data": temp_data,
                "visible": True,
            }
        )

        # we need labels for the days.
        for r in arrow.Arrow.span_range("day", start_time, end_time):
            graph["categories"].append(r[0].format("MM/DD/YY"))

        return Response(graph)
