import json
from datetime import timedelta

import arrow
import boto3
import pytz
from botocore.config import Config
from celery import current_app
from django.conf import settings
from django.db.models import Q
from django.utils.dateparse import parse_datetime
from django.utils.timezone import get_current_timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework_datatables.filters import DatatablesFilterBackend
from rest_framework.response import Response

from apps.console.api.v1._tasks.exceptions import (
    SnapshotCreateMissingParams,
    SnapshotCreateError,
    DownloadMissingParams,
    DownloadStoragePointNotFound,
    DownloadStoragePointError, StoragePointError, TransferStorageNotFound
)
from apps.console.api.v1.backup.website.filters import CoreWebsiteBackupFilter
from apps.console.api.v1.backup.website.permissions import (
    CoreWebsiteBackupViewPermissions,
)
from apps.console.api.v1.backup.website.serializers import CoreWebsiteBackupSerializer, \
    CoreWebsiteBackupStoragePointsSerializer, CoreWebsiteBackupTransferSerializer
from apps.console.api.v1.utils.api_filters import DateRangeFilter
from apps.console.api.v1.utils.api_helpers import get_start_end_of_previous_day
from apps.console.backup.models import CoreWebsiteBackup
from apps.console.node.models import CoreNode
from rest_framework import status

from apps.console.storage.models import CoreStorage
from apps.utils.api_exceptions import ExceptionDefault
from google.cloud import storage as gc_storage
from google.oauth2 import service_account

class CoreWebsiteBackupView(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated, CoreWebsiteBackupViewPermissions)
    serializer_class = CoreWebsiteBackupSerializer
    all_fields = [f.name for f in CoreWebsiteBackup._meta.get_fields()]
    filter_backends = [
        DjangoFilterBackend,
        DatatablesFilterBackend,
        SearchFilter,
        DateRangeFilter,
    ]
    filterset_class = CoreWebsiteBackupFilter
    search_fields = all_fields

    def get_queryset(self):
        member = self.request.user.member
        query = Q(website__node__connection__account=member.get_current_account())
        query &= ~Q(website__node__status=CoreNode.Status.DELETE_REQUESTED)
        query &= ~Q(status=CoreWebsiteBackup.Status.DELETE_REQUESTED)
        if self.request.query_params.get("node"):
            query &= Q(website__node__id=self.request.query_params.get("node"))
        queryset = CoreWebsiteBackup.objects.filter(query)
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

                if backup.stored_website_backups.filter(
                        id=storage_point_id
                ).exists():
                    storage_point = backup.stored_website_backups.get(
                        id=storage_point_id
                    )

                    # NEW
                    if (
                        storage_point.storage.name == "Storage 01"
                        or storage_point.storage.name == "Storage 02"
                        or storage_point.storage.name == "Storage 03"
                        or storage_point.storage.name == "Storage 04"
                    ) and storage_point.storage.type.code == "bs":
                        member_id = request.user.member.id

                        queue_name = (
                            f"backup_download_request"
                            f"__{backup.node.connection.location.queue}"
                        )

                        current_app.send_task(
                            "backup_download_request",
                            queue=queue_name,
                            kwargs={
                                "storage_point_id": storage_point_id,
                                "backup_type": "website",
                                "member_id": member_id,
                            },
                        )
                        return Response(
                            {"url": "download_requested"},
                            status=status.HTTP_201_CREATED,
                        )
                    else:
                        download_url = storage_point.generate_download_url()
                        return Response({"url": download_url, "expire_in": 24 * 3600}, status=status.HTTP_201_CREATED)
                else:
                    raise DownloadStoragePointNotFound()
            except Exception as e:
                raise DownloadStoragePointError(e.__str__())
        else:
            raise DownloadMissingParams()

    @action(detail=True, methods=["post"])
    def transfer_backup(self, request, pk=None):
        try:
            backup = self.get_object()

            serializer = CoreWebsiteBackupTransferSerializer(
                data=self.request.data, context={"backup": backup}
            )

            if serializer.is_valid():
                storage_point_id = serializer.validated_data.get("storage_point_id")
                storage_ids = serializer.validated_data.get("storage_ids")

                for storage_id in storage_ids:
                    if backup.stored_website_backups.filter(
                            id=storage_point_id
                    ).exists():
                        storage_point = backup.stored_website_backups.get(
                            id=storage_point_id
                        )
                        storage_point.transfer(storage_id=storage_id)
                        # queue_name = (
                        #     f"backup_transfer_request"
                        #     f"__{backup.node.connection.location.queue}"
                        # )
                        #
                        # current_app.send_task(
                        #     "backup_transfer_request",
                        #     queue=queue_name,
                        #     kwargs={
                        #         "storage_point_id": storage_point_id,
                        #         "backup_type": "website",
                        #         "storage_id": storage_id,
                        #     },
                        # )
                        return Response(
                            status=status.HTTP_201_CREATED,
                        )
                    else:
                        return Response(status=status.HTTP_201_CREATED)
            else:
                raise ExceptionDefault(detail=serializer.errors)
        except Exception as e:
            raise TransferStorageNotFound(e.__str__())

    @action(detail=True)
    def download_transfer_log(self, request, pk=None):
        backup = self.get_object()

        # NEW
        date = parse_datetime("2023-01-01 19:0:0.000 -0000")
        date_aws_s3 = parse_datetime("2023-01-28 20:00:0.000 -0000")
        date_google_cloud = parse_datetime("2023-05-02 16:00:0.000 -0000")

        # NEW
        if backup.created > date_google_cloud:
            service_key_json = json.loads(settings.BS_GOOGLE_CLOUD_SERVICE_KEY)
            credentials = service_account.Credentials.from_service_account_info(service_key_json)
            storage_client = gc_storage.Client(credentials=credentials)
            bucket = storage_client.bucket(settings.AWS_S3_LOGS_BUCKET)
            blob = bucket.blob(f"{backup.uuid_str}.log")
            url = blob.generate_signed_url(
                version="v4",
                expiration=timedelta(hours=24),
                method="GET",
            )
            return Response({"url": url, "expire_in": 24 * 3600}, status=status.HTTP_201_CREATED)
        elif backup.created > date_aws_s3:
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
        elif date < backup.created < date_aws_s3:
            s3_client = boto3.client(
                "s3",
                endpoint_url=settings.LOGS_S3_ENDPOINT,
                aws_access_key_id=settings.LOGS_S3_ACCESS_KEY_ID,
                aws_secret_access_key=settings.LOGS_S3_SECRET_ACCESS_KEY,
                config=Config(signature_version='s3v4')
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": settings.LOGS_S3_BUCKET,
                    "Key": f"{backup.uuid_str}.log",
                },
                ExpiresIn=24 * 3600,
            )
            response = response.replace(f"{settings.LOGS_S3_ENDPOINT}/logs", "https://logs.backupsheep.com")
            return Response({"url": response, "expire_in": 24 * 3600}, status=status.HTTP_201_CREATED)
        else:
            s3_client = boto3.client(
                "s3",
                endpoint_url=settings.CEPH_S3_ENDPOINT,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": settings.AWS_LOGS_BUCKET,
                    "Key": f"{backup.uuid_str}.log",
                },
                ExpiresIn=24 * 3600,
            )
            return Response({"url": response, "expire_in": 24 * 3600}, status=status.HTTP_201_CREATED)

    @action(detail=True)
    def download_dir_tree(self, request, pk=None):
        backup = self.get_object()

        # NEW
        date = parse_datetime("2023-01-01 19:0:0.000 -0000")
        date_aws_s3 = parse_datetime("2023-01-28 20:00:0.000 -0000")

        # NEW
        if backup.created > date_aws_s3:
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
                config=Config(region_name=settings.AWS_S3_LOGS_REGION, signature_version="v4"),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": settings.AWS_S3_LOGS_BUCKET,
                    "Key": f"{backup.uuid_str}-dir-tree.log",
                },
                ExpiresIn=24 * 3600,
            )
            return Response({"url": response, "expire_in": 24 * 3600}, status=status.HTTP_201_CREATED)
        elif date < backup.created < date_aws_s3:
            s3_client = boto3.client(
                "s3",
                endpoint_url=settings.LOGS_S3_ENDPOINT,
                aws_access_key_id=settings.LOGS_S3_ACCESS_KEY_ID,
                aws_secret_access_key=settings.LOGS_S3_SECRET_ACCESS_KEY,
                config=Config(signature_version='s3v4')
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": settings.LOGS_S3_BUCKET,
                    "Key": f"{backup.uuid_str}-dir-tree.log",
                },
                ExpiresIn=24 * 3600,
            )
            response = response.replace(f"{settings.LOGS_S3_ENDPOINT}/logs", "https://logs.backupsheep.com")
            return Response({"url": response, "expire_in": 24 * 3600}, status=status.HTTP_201_CREATED)
        else:
            s3_client = boto3.client(
                "s3",
                endpoint_url=settings.CEPH_S3_ENDPOINT,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": settings.AWS_LOGS_BUCKET,
                    "Key": f"{backup.uuid_str}-dir-tree.log",
                },
                ExpiresIn=24 * 3600,
            )
            return Response({"url": response, "expire_in": 24 * 3600}, status=status.HTTP_201_CREATED)

    @action(detail=True)
    def storage_points(self, request, pk=None):
        try:
            backup = self.get_object()
            storage_points = CoreWebsiteBackupStoragePointsSerializer(backup.stored_website_backups.all(), many=True).data
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
            backup_count = self.get_queryset().filter(
                created__gte=r[0].datetime,
                created__lte=r[1].datetime,
            ).count()

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