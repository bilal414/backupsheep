import hashlib
import humanfriendly
import json
import re
import pytz
from django.utils.dateparse import parse_datetime
from django.utils.timezone import get_current_timezone
from rest_framework import serializers
from apps.console.account.models import CoreAccount
from apps.api.v1.utils.api_helpers import (
    CurrentAccountDefault,
    CurrentMemberDefault,
)
from apps.console.backup.models import (
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreDatabaseRestore,
)
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreConnectionLocation,
)
from apps.console.node.models import CoreDatabase, CoreNode, CoreSchedule
from apps.console.storage.models import CoreStorage, CoreStorageType
from apps.api.v1.backup.serializers import (
    BackupExecutionStatusListSerializer,
    BackupExecutionStatusMixin,
    CoreBackupScheduleSerializer,
    CoreBackupStorageSerializer,
    SafeProviderMetadataMixin,
    RestoreExecutionStatusMixin,
)


_DATABASE_RESTORE_RESUME_PHASES = frozenset(
    {
        # The materialized-restore wrapper records a terminal ``failed``
        # phase after the database engine has already persisted its durable
        # mapping/checkpoint state.  ``failed`` is safe here only because all
        # of the exact fork, digest, and checkpoint checks below still run.
        "failed",
        "database_importing",
        "database_importing_file",
        "database_replaying",
        "database_adopted",
        "database_complete",
        "database_restore_complete",
    }
)
_DATABASE_RESTORE_RESUME_STATES = frozenset({"importing", "complete"})
_DATABASE_RESTORE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DATABASE_RESTORE_IDENTIFIER_BAD = re.compile(
    r'''[\s;&|`$<>(){}\[\]\\'"!*?~#/]+'''
)
_DATABASE_RESTORE_MANUAL_RESUME_MAX_COUNT = 1000
_DATABASE_RESTORE_MANUAL_RESUME_HISTORY_LIMIT = 10


def _database_restore_identifier(value):
    if not isinstance(value, str) or not value or len(value) > 63:
        return False
    return _DATABASE_RESTORE_IDENTIFIER_BAD.search(value) is None


def _database_restore_source_digest(source, files):
    canonical = json.dumps(
        {source: sorted(files, key=lambda item: item["file"])},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def database_restore_verification_resume_mode(restore):
    """Return the only safe logical-restore resume mode, or an empty string.

    This is deliberately a pure durable-state proof.  It does not inspect a
    provider or database and it never derives safety from an error message.
    The restore engine remains authoritative: it revalidates the archive and
    reconciles the exact target marker before making any target-side decision.
    """
    try:
        if restore.status != CoreDatabaseRestore.Status.FAILED:
            return ""
        if str(restore.execution_phase or "") not in _DATABASE_RESTORE_RESUME_PHASES:
            return ""

        params = restore.params
        metadata = restore.execution_metadata
        if not isinstance(params, dict) or not isinstance(metadata, dict):
            return ""
        if params.get("mode") != "fork" or params.get("mapping_locked") is not True:
            return ""
        if (
            metadata.get("mode") != "fork"
            or metadata.get("mapping_locked") is not True
        ):
            return ""

        backup = restore.backup
        if params.get("source_backup_uuid") != str(backup.uuid):
            return ""

        mapping = params.get("target_mapping")
        durable_mapping = metadata.get("source_to_target")
        if not isinstance(mapping, dict) or not mapping:
            return ""
        if not isinstance(durable_mapping, dict) or durable_mapping != mapping:
            return ""
        if len(set(mapping.values())) != len(mapping):
            return ""
        if any(
            not _database_restore_identifier(source)
            or not _database_restore_identifier(target)
            for source, target in mapping.items()
        ):
            return ""

        raw_digests = metadata.get("source_digests")
        checkpoints = metadata.get("target_checkpoints")
        if not isinstance(raw_digests, dict) or not isinstance(checkpoints, dict):
            return ""
        if set(raw_digests) != set(mapping) or not checkpoints:
            return ""
        if not set(checkpoints).issubset(set(mapping.values())):
            return ""

        valid_checkpoint_count = 0
        for source, raw_files in raw_digests.items():
            if not isinstance(raw_files, list) or not raw_files:
                return ""
            files = []
            file_names = set()
            file_specs = {}
            for item in raw_files:
                if not isinstance(item, dict):
                    return ""
                filename = item.get("file")
                if (
                    not isinstance(filename, str)
                    or not filename
                    or filename in file_names
                    or "/" in filename
                    or "\\" in filename
                ):
                    return ""
                try:
                    byte_count = int(item.get("bytes"))
                except (TypeError, ValueError, OverflowError):
                    return ""
                if byte_count <= 0 or not _DATABASE_RESTORE_SHA256.fullmatch(
                    str(item.get("sha256") or "")
                ):
                    return ""
                files.append(
                    {
                        "file": filename,
                        "bytes": byte_count,
                        "sha256": str(item["sha256"]),
                    }
                )
                file_specs[filename] = files[-1]
                file_names.add(filename)

            expected_digest = _database_restore_source_digest(source, files)
            target = mapping[source]
            checkpoint = checkpoints.get(target)
            if checkpoint is None:
                continue
            if not isinstance(checkpoint, dict):
                return ""
            if (
                checkpoint.get("source") != source
                or checkpoint.get("source_digest") != expected_digest
                or checkpoint.get("status") not in _DATABASE_RESTORE_RESUME_STATES
            ):
                return ""
            checkpoint_files = checkpoint.get("files")
            if not isinstance(checkpoint_files, dict) or set(checkpoint_files) != file_names:
                return ""
            for filename, file_state in checkpoint_files.items():
                if not isinstance(file_state, dict):
                    return ""
                if (
                    filename not in file_specs
                    or file_state.get("sha256") != file_specs[filename]["sha256"]
                    or int(file_state.get("bytes") or 0) != file_specs[filename]["bytes"]
                    or file_state.get("status") not in {"pending", "in_progress", "complete"}
                    or not _DATABASE_RESTORE_SHA256.fullmatch(
                        str(file_state.get("sha256") or "")
                    )
                ):
                    return ""
                try:
                    state_bytes = int(file_state.get("bytes"))
                except (TypeError, ValueError, OverflowError):
                    return ""
                if state_bytes <= 0:
                    return ""
            valid_checkpoint_count += 1

        if valid_checkpoint_count < 1:
            return ""
        return "logical_fork_reconciliation"
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        return ""


class CoreDatabaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoreDatabase
        fields = "__all__"
        datatables_always_serialize = (
            "id",
            "tables",
            "all_tables",
            "databases",
            "all_databases",
            "notes",
        )


class CoreDatabaseBackupStoragePointsSerializer(SafeProviderMetadataMixin, serializers.ModelSerializer):
    storage = CoreBackupStorageSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = CoreDatabaseBackupStoragePoints
        fields = "__all__"

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()


class CoreDatabaseBackupSerializer(BackupExecutionStatusMixin, serializers.ModelSerializer):
    database = CoreDatabaseSerializer(read_only=True)
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    size_display = serializers.SerializerMethodField()
    type_display = serializers.SerializerMethodField()
    schedule = CoreBackupScheduleSerializer()
    stored_backups = CoreDatabaseBackupStoragePointsSerializer(
        source="stored_database_backups", many=True, read_only=True
    )

    class Meta:
        model = CoreDatabaseBackup
        fields = "__all__"
        list_serializer_class = BackupExecutionStatusListSerializer
        datatables_always_serialize = (
            "id",
            "uuid",
            "name",
            "stored_backups",
            "execution_status",
        )

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_created_display(obj):
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)
        date_time = obj.created.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
        return date_time

    @staticmethod
    def get_modified_display(obj):
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)
        date_time = obj.modified.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
        return date_time

    @staticmethod
    def get_size_display(obj):
        return humanfriendly.format_size(obj.size or 0)

    @staticmethod
    def get_type_display(obj):
        return obj.get_type_display()


class CoreDatabaseRestoreSerializer(RestoreExecutionStatusMixin, serializers.ModelSerializer):
    status_display = serializers.SerializerMethodField(read_only=True)
    created_display = serializers.SerializerMethodField()
    modified_display = serializers.SerializerMethodField()
    can_resume_verification = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = CoreDatabaseRestore
        fields = "__all__"
        read_only_fields = (
            "backup",
            "storage_point",
            "status",
            "error",
            "celery_task_id",
            "can_resume_verification",
        )

    @staticmethod
    def get_can_resume_verification(obj):
        return bool(database_restore_verification_resume_mode(obj))

    @staticmethod
    def get_status_display(obj):
        return obj.get_status_display()

    @staticmethod
    def get_created_display(obj):
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)
        date_time = obj.created.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
        return date_time

    @staticmethod
    def get_modified_display(obj):
        timezone = str(get_current_timezone())
        timezone = pytz.timezone(timezone)
        date_time = obj.modified.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
        return date_time
