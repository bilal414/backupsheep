from urllib.parse import urlparse

from rest_framework import serializers

from apps.console.backup.replication_models import (
    CoreLightsailBucketReplication,
    CoreLightsailBucketReplicationObject,
    CoreLightsailBucketReplicationRun,
    CoreLightsailBucketRestoreRun,
)
from apps.console.connection.models import CoreConnection
from apps.console.storage.models import CoreStorage


class CoreLightsailBucketReplicationRunSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source="get_status_display", read_only=True)

    class Meta:
        model = CoreLightsailBucketReplicationRun
        fields = "__all__"
        read_only_fields = (
            "uuid",
            "celery_task_id",
            "status",
            "started_at",
            "completed_at",
            "object_count",
            "completed_count",
            "failed_count",
            "delete_marker_count",
            "bytes_transferred",
            "manifest_key",
            "manifest",
            "error",
        )


class CoreLightsailBucketReplicationObjectSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source="get_status_display", read_only=True)

    class Meta:
        model = CoreLightsailBucketReplicationObject
        fields = "__all__"
        read_only_fields = tuple(
            field.name
            for field in CoreLightsailBucketReplicationObject._meta.fields
            if field.name not in {"id", "created", "modified"}
        )


class CoreLightsailBucketRestoreRunSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source="get_status_display", read_only=True)

    class Meta:
        model = CoreLightsailBucketRestoreRun
        fields = "__all__"
        read_only_fields = (
            "uuid",
            "celery_task_id",
            "status",
            "started_at",
            "completed_at",
            "object_count",
            "completed_count",
            "skipped_count",
            "failed_count",
            "bytes_restored",
            "completed_objects",
            "manifest",
            "lease_owner",
            "lease_token",
            "lease_expires_at",
            "error",
        )


class CoreLightsailBucketReplicationReadSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    last_run_summary = serializers.SerializerMethodField()

    class Meta:
        model = CoreLightsailBucketReplication
        fields = "__all__"
        read_only_fields = ("account", "last_run", "status", "metadata")

    @staticmethod
    def get_last_run_summary(obj):
        run = obj.last_run
        if not run:
            return None
        return CoreLightsailBucketReplicationRunSerializer(run).data


class CoreLightsailBucketReplicationWriteSerializer(serializers.ModelSerializer):
    source_connection = serializers.PrimaryKeyRelatedField(
        queryset=CoreConnection.objects.all()
    )
    destination_storage = serializers.PrimaryKeyRelatedField(
        queryset=CoreStorage.objects.all()
    )

    class Meta:
        model = CoreLightsailBucketReplication
        fields = "__all__"
        read_only_fields = ("account", "uuid", "last_run", "status", "metadata")

    def validate(self, attrs):
        request = self.context.get("request")
        member = getattr(getattr(request, "user", None), "member", None)
        account = member.get_current_account() if member else None
        if account is None:
            raise serializers.ValidationError("An active account is required.")

        connection = attrs.get(
            "source_connection", getattr(self.instance, "source_connection", None)
        )
        storage = attrs.get(
            "destination_storage", getattr(self.instance, "destination_storage", None)
        )
        if connection is None or connection.account_id != account.id:
            raise serializers.ValidationError(
                {"source_connection": "The Lightsail connection is outside the current account."}
            )
        if connection.integration.code != "lightsail":
            raise serializers.ValidationError(
                {"source_connection": "The source connection must be a Lightsail connection."}
            )
        if connection.status != CoreConnection.Status.ACTIVE:
            raise serializers.ValidationError(
                {"source_connection": "The Lightsail connection must be active."}
            )
        try:
            connection.auth_lightsail
        except Exception as error:
            raise serializers.ValidationError(
                {"source_connection": "The Lightsail connection has no credentials configured."}
            ) from error
        if storage is None or storage.account_id != account.id:
            raise serializers.ValidationError(
                {"destination_storage": "The destination storage is outside the current account."}
            )
        if storage.status != CoreStorage.Status.ACTIVE:
            raise serializers.ValidationError(
                {"destination_storage": "The destination storage must be active."}
            )

        bucket = attrs.get(
            "source_bucket_name", getattr(self.instance, "source_bucket_name", "")
        )
        if not bucket or "/" in bucket or len(bucket) > 1024:
            raise serializers.ValidationError(
                {"source_bucket_name": "Enter a valid Lightsail bucket name."}
            )

        endpoint = attrs.get(
            "source_endpoint_url",
            getattr(self.instance, "source_endpoint_url", "") or "",
        )
        if endpoint:
            parsed = urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise serializers.ValidationError(
                    {"source_endpoint_url": "The endpoint must be an HTTP(S) URL or hostname."}
                )
            if parsed.username or parsed.password:
                raise serializers.ValidationError(
                    {"source_endpoint_url": "Credentials must not be embedded in the endpoint URL."}
                )

        interval = attrs.get(
            "interval_minutes", getattr(self.instance, "interval_minutes", 60)
        )
        if interval < 1 or interval > 10080:
            raise serializers.ValidationError(
                {"interval_minutes": "Use an interval between 1 minute and 7 days."}
            )
        lease_seconds = attrs.get(
            "lease_seconds", getattr(self.instance, "lease_seconds", 900)
        )
        if lease_seconds < 60 or lease_seconds > 86400:
            raise serializers.ValidationError(
                {"lease_seconds": "Use a lease between 60 seconds and 24 hours."}
            )
        part_size = attrs.get(
            "part_size_bytes",
            getattr(self.instance, "part_size_bytes", 64 * 1024 * 1024),
        )
        if part_size < 5 * 1024 * 1024 or part_size > 5 * 1024 * 1024 * 1024:
            raise serializers.ValidationError(
                {"part_size_bytes": "Multipart part size must be between 5 MiB and 5 GiB."}
            )

        attrs["source_prefix"] = CoreLightsailBucketReplication.normalize_prefix(
            attrs.get("source_prefix", getattr(self.instance, "source_prefix", ""))
        )
        attrs["destination_prefix"] = CoreLightsailBucketReplication.normalize_prefix(
            attrs.get(
                "destination_prefix", getattr(self.instance, "destination_prefix", "")
            )
        )
        attrs["account"] = account
        return attrs

    def create(self, validated_data):
        return CoreLightsailBucketReplication.objects.create(**validated_data)
