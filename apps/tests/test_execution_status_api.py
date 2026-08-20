"""Public execution-status serializer contract and redaction tests."""

import json
import uuid
from datetime import timedelta
from importlib import import_module

from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.api.v1.backup.website.serializers import (
    CoreWebsiteBackupSerializer,
    CoreWebsiteRestoreSerializer,
)
from apps.api.v1.backup.serializers import _execution_phase, _safe_provider_status
from apps.console.backup.models import (
    CoreBackupArtifact,
    CoreBackupExecution,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
    CoreWebsiteRestore,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class ExecutionStatusApiTests(BaseTestCase):
    def test_legacy_status_phase_map_overrides_stale_terminal_and_source_phases(self):
        cases = {
            ("complete", "uploading"): "complete",
            ("failed", "restoring"): "failed",
            ("timeout", "polling"): "failed",
            ("cancelled", "capturing"): "cancelled",
            ("partial_some_destinations_failed", "uploading"): "complete",
            ("download_complete", "capturing"): "source_ready",
            ("ready_for_upload", "preparing"): "source_ready",
            ("upload_in_progress", "source_dispatch"): "uploading",
            ("upload_complete", "source_dispatch"): "validating",
            ("upload_validation", "source_dispatch"): "validating",
            ("upload_validation", None): "validating",
            ("in_progress", "download_complete"): "source_ready",
            ("in_progress", "upload_complete"): "validating",
            ("in_progress", "destination_upload_complete"): "validating",
            ("retrying", None): "retrying",
            ("in_progress", "reconciling"): "reconciling",
        }
        for (status, phase), expected in cases.items():
            with self.subTest(status=status, phase=phase):
                self.assertEqual(_execution_phase(status, phase), expected)

    def test_active_database_restore_component_phases_never_report_terminal_complete(self):
        validating_phases = (
            "archive_validated",
            "database_permissions_verified",
            "database_ready",
        )
        restoring_phases = (
            "database_importing",
            "database_importing_file",
            "database_replaying",
            "database_adopted",
            "database_complete",
            "database_restore_complete",
        )

        for phase in validating_phases:
            with self.subTest(status="in_progress", phase=phase):
                self.assertEqual(_execution_phase("in_progress", phase), "validating")
        for phase in restoring_phases:
            with self.subTest(status="in_progress", phase=phase):
                self.assertEqual(_execution_phase("in_progress", phase), "restoring")

        # The parent restore status, not a per-database checkpoint, is the
        # authority for the terminal public phase.
        self.assertEqual(_execution_phase("complete", "database_complete"), "complete")

    def test_active_website_restore_component_completion_stays_restoring(self):
        for phase in (
            "website_transferring",
            "website_staging",
            "website_staged",
            "website_publishing",
            "website_cleanup_pending",
            "website_complete",
        ):
            with self.subTest(status="in_progress", phase=phase):
                self.assertEqual(_execution_phase("in_progress", phase), "restoring")

        self.assertEqual(_execution_phase("complete", "website_complete"), "complete")

    def test_documented_provider_lifecycle_statuses_remain_visible(self):
        self.assertEqual(
            _safe_provider_status("configuring-enhanced-monitoring"),
            "configuring-enhanced-monitoring",
        )
        self.assertEqual(_safe_provider_status("restore-error"), "restore-error")
        self.assertEqual(_safe_provider_status("new"), "new")
        self.assertEqual(_safe_provider_status("archive"), "archive")
        self.assertEqual(_safe_provider_status("in-use"), "in-use")
        self.assertEqual(_safe_provider_status("off"), "off")
        self.assertEqual(_safe_provider_status("terminated"), "terminated")
        self.assertEqual(_safe_provider_status("provider-secret-canary"), "unknown")

    def _backup(self, *, status=None):
        node = factories.make_website_node(self.account, self.member)
        return CoreWebsiteBackup.objects.create(
            website=node.website,
            name="operator-status-backup",
            uuid=f"status-{uuid.uuid4().hex}",
            status=status or UtilBackup.Status.UPLOAD_IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
        )

    @staticmethod
    def _execution(backup, **overrides):
        content_type = ContentType.objects.get_for_model(
            backup, for_concrete_model=False
        )
        values = {
            "backup_content_type": content_type,
            "backup_object_id": backup.pk,
            "phase": "uploading",
            "attempt_count": 3,
            "progress_completed": 4,
            "progress_total": 10,
            "progress_unit": "bytes",
            "provider_status": "in_progress",
            "reconciliation_state": "required",
            "reconciliation_reason": "stale_execution_lease",
            "last_error_code": "PROVIDER_TIMEOUT",
            "next_retry_at": timezone.now() + timedelta(minutes=5),
            "artifact_bytes": 1234,
            "artifact_checksum_algorithm": "sha256",
            "artifact_checksum": "a" * 64,
            "artifact_verified_at": timezone.now(),
            "lease_owner": "worker-secret-canary",
            "lease_token": uuid.uuid4(),
            "lease_expires_at": timezone.now() + timedelta(minutes=2),
            "worker_name": "worker-secret-canary",
            "provider_metadata": {"response_body": "provider-secret-canary"},
            "metadata": {"internal_path": "/srv/secret-canary"},
            "last_error_message": "raw exception secret-canary",
        }
        values.update(overrides)
        return CoreBackupExecution.objects.create(**values)

    def test_website_backup_stage_is_visible_without_exposing_checkpoint_metadata(self):
        backup = self._backup(status=UtilBackup.Status.DOWNLOAD_IN_PROGRESS)
        self._execution(
            backup,
            phase="source_dispatch",
            metadata={
                "public_stage": "website_enumerating",
                "private_checkpoint": "must-not-be-returned",
            },
            progress_completed=20000,
            progress_total=2000000,
            progress_unit="files",
        )

        payload = CoreWebsiteBackupSerializer(backup).data
        status = payload["execution_status"]
        self.assertEqual(status["phase"], "website_enumerating")
        self.assertEqual(status["progress"]["completed"], 20000)
        self.assertEqual(status["progress"]["total"], 2000000)
        self.assertNotIn("private_checkpoint", str(payload))

    def test_in_progress_state_survives_fresh_serializer_instance(self):
        backup = self._backup()
        backup.metadata = {"provider_response": "legacy-provider-secret-canary"}
        backup.save(update_fields=["metadata", "modified"])
        state = self._execution(backup)

        # Fetching a fresh row simulates a process restart: the API must read the
        # database ledger rather than relying on a worker-local object.
        data = CoreWebsiteBackupSerializer(
            CoreWebsiteBackup.objects.get(pk=backup.pk)
        ).data
        status = data["execution_status"]

        self.assertTrue(status["durable"])
        self.assertEqual(status["correlation_id"], str(state.correlation_id))
        self.assertEqual(status["phase"], "uploading")
        self.assertEqual(status["status"], "upload_in_progress")
        self.assertEqual(status["attempts"], 3)
        self.assertEqual(status["progress"], {
            "completed": 4,
            "total": 10,
            "unit": "bytes",
        })
        self.assertEqual(status["artifact"]["bytes"], 1234)
        self.assertEqual(status["artifact"]["checksum_algorithm"], "sha256")
        self.assertEqual(status["reconciliation"], {
            "state": "required",
            "reason": "stale_execution_lease",
        })
        self.assertEqual(status["provider_status"], "in_progress")
        self.assertEqual(status["last_error_code"], "PROVIDER_TIMEOUT")
        self.assertEqual(data["metadata"], {})
        self.assertNotIn("secret-canary", json.dumps(data))
        self.assertNotIn("lease_owner", status)
        self.assertNotIn("lease_token", status)
        self.assertNotIn("lease_expires_at", status)
        self.assertNotIn("worker_name", status)
        self.assertNotIn("provider_metadata", status)
        self.assertNotIn("metadata", status)

        state.provider_status = "provider-secret-canary"
        state.reconciliation_reason = "reconciliation-secret-canary"
        state.save(update_fields=["provider_status", "reconciliation_reason"])
        redacted = CoreWebsiteBackupSerializer(
            CoreWebsiteBackup.objects.get(pk=backup.pk)
        ).data["execution_status"]
        self.assertEqual(redacted["provider_status"], "unknown")
        self.assertIsNone(redacted["reconciliation"]["reason"])
        self.assertNotIn("provider-secret-canary", json.dumps(redacted))
        self.assertNotIn("reconciliation-secret-canary", json.dumps(redacted))

    def test_local_storage_point_state_drives_source_upload_and_retry_phases(self):
        cases = (
            (CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY, "source_ready"),
            (CoreWebsiteBackupStoragePoints.Status.UPLOAD_RETRY, "retrying"),
            (CoreWebsiteBackupStoragePoints.Status.UPLOAD_IN_PROGRESS, "uploading"),
            (CoreWebsiteBackupStoragePoints.Status.UPLOAD_VALIDATION, "validating"),
            (CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE, "validating"),
        )
        for point_status, expected in cases:
            with self.subTest(point_status=point_status):
                backup = self._backup()
                storage = factories.make_storage(
                    self.account,
                    self.member,
                    code="local",
                    bucket=f"phase-{uuid.uuid4().hex[:12]}",
                )
                CoreWebsiteBackupStoragePoints.objects.create(
                    backup=backup,
                    storage=storage,
                    status=point_status,
                )
                self._execution(backup, phase="source_dispatch")

                status = CoreWebsiteBackupSerializer(backup).data["execution_status"]
                self.assertEqual(status["phase"], expected)

    def test_progress_updates_are_visible_and_monotonic(self):
        backup = self._backup()
        state = self._execution(backup)
        first = CoreWebsiteBackupSerializer(backup).data["execution_status"]

        state.progress_completed = 8
        state.progress_total = 12
        state.progress_unit = "files"
        state.save(update_fields=["progress_completed", "progress_total", "progress_unit"])

        second = CoreWebsiteBackupSerializer(
            CoreWebsiteBackup.objects.get(pk=backup.pk)
        ).data["execution_status"]
        self.assertEqual(first["progress"]["completed"], 4)
        self.assertEqual(second["progress"], {
            "completed": 8,
            "total": 12,
            "unit": "files",
        })

    def test_terminal_status_and_correlation_id_are_stable(self):
        backup = self._backup(status=UtilBackup.Status.IN_PROGRESS)
        state = self._execution(
            backup,
            phase="uploading",
            reconciliation_state="resolved",
            reconciliation_reason="provider_reconciled",
            last_error_code="",
            last_error_message="",
            next_retry_at=None,
        )
        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])

        first = CoreWebsiteBackupSerializer(backup).data["execution_status"]
        second = CoreWebsiteBackupSerializer(
            CoreWebsiteBackup.objects.get(pk=backup.pk)
        ).data["execution_status"]
        self.assertEqual(first["correlation_id"], str(state.correlation_id))
        self.assertEqual(second["correlation_id"], first["correlation_id"])
        self.assertEqual(second["phase"], "complete")
        self.assertEqual(second["status"], "complete")
        self.assertIsNone(second["last_error_code"])
        self.assertIsNone(second["next_retry_at"])

    def test_source_artifact_row_is_used_when_execution_rollup_is_empty(self):
        backup = self._backup(status=UtilBackup.Status.COMPLETE)
        content_type = ContentType.objects.get_for_model(
            backup, for_concrete_model=False
        )
        CoreBackupArtifact.objects.create(
            backup_content_type=content_type,
            backup_object_id=backup.pk,
            role=CoreBackupArtifact.Role.SOURCE,
            idempotency_key="source-artifact",
            object_key="archive.zip",
            byte_count=55,
            checksum_algorithm="sha256",
            checksum_value="b" * 64,
            verified_at=timezone.now(),
        )

        status = CoreWebsiteBackupSerializer(backup).data["execution_status"]
        self.assertEqual(status["artifact"]["bytes"], 55)
        self.assertEqual(status["artifact"]["checksum_algorithm"], "sha256")

    def test_backup_list_bulk_loads_execution_rows(self):
        first = self._backup()
        second = self._backup()
        self._execution(first)
        self._execution(second, phase="polling")
        first_storage = factories.make_storage(
            self.account,
            self.member,
            code="local",
            bucket=f"bulk-phase-{uuid.uuid4().hex[:12]}",
        )
        second_storage = factories.make_storage(
            self.account,
            self.member,
            code="local",
            bucket=f"bulk-phase-{uuid.uuid4().hex[:12]}",
        )
        CoreWebsiteBackupStoragePoints.objects.create(
            backup=first,
            storage=first_storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY,
        )
        CoreWebsiteBackupStoragePoints.objects.create(
            backup=second,
            storage=second_storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_RETRY,
        )

        with CaptureQueriesContext(connection) as captured:
            data = CoreWebsiteBackupSerializer(
                CoreWebsiteBackup.objects.filter(pk__in=[first.pk, second.pk]).order_by("pk"),
                many=True,
            ).data

        execution_queries = [
            query for query in captured.captured_queries
            if "core_backup_execution" in query["sql"]
        ]
        artifact_queries = [
            query for query in captured.captured_queries
            if "core_backup_artifact" in query["sql"]
        ]
        point_queries = [
            query for query in captured.captured_queries
            if "core_website_backup_mtm_storage_points" in query["sql"]
        ]
        self.assertEqual(len(execution_queries), 1)
        self.assertEqual(len(artifact_queries), 1)
        self.assertEqual(len(point_queries), 1)
        self.assertEqual(data[0]["execution_status"]["phase"], "source_ready")
        self.assertEqual(data[1]["execution_status"]["phase"], "retrying")

    def test_every_provider_backup_serializer_exposes_the_same_status_field(self):
        serializers = {
            "apps.api.v1.backup.aws": "CoreAWSBackupSerializer",
            "apps.api.v1.backup.aws_rds": "CoreAWSRDSBackupSerializer",
            "apps.api.v1.backup.basecamp": "CoreBasecampBackupSerializer",
            "apps.api.v1.backup.database": "CoreDatabaseBackupSerializer",
            "apps.api.v1.backup.digitalocean": "CoreDigitalOceanBackupSerializer",
            "apps.api.v1.backup.google_cloud": "CoreGoogleCloudBackupSerializer",
            "apps.api.v1.backup.hetzner": "CoreHetznerBackupSerializer",
            "apps.api.v1.backup.lightsail": "CoreLightsailBackupSerializer",
            "apps.api.v1.backup.oracle": "CoreOracleBackupSerializer",
            "apps.api.v1.backup.ovh_ca": "CoreOVHCABackupSerializer",
            "apps.api.v1.backup.ovh_eu": "CoreOVHEUBackupSerializer",
            "apps.api.v1.backup.ovh_us": "CoreOVHUSBackupSerializer",
            "apps.api.v1.backup.upcloud": "CoreUpCloudBackupSerializer",
            "apps.api.v1.backup.vultr": "CoreVultrBackupSerializer",
            "apps.api.v1.backup.vultr_database": "CoreVultrDatabaseBackupSerializer",
            "apps.api.v1.backup.website": "CoreWebsiteBackupSerializer",
            "apps.api.v1.backup.wordpress": "CoreWordPressBackupSerializer",
        }
        for module_name, class_name in serializers.items():
            with self.subTest(serializer=class_name):
                serializer = getattr(import_module(f"{module_name}.serializers"), class_name)()
                self.assertIn("execution_status", serializer.fields)

    def test_restore_status_redacts_coordination_metadata_params_and_errors(self):
        node = factories.make_website_node(self.account, self.member)
        recovery_id = str(uuid.uuid4())
        backup = CoreWebsiteBackup.objects.create(
            website=node.website,
            name="restore-source",
            uuid=f"source-{uuid.uuid4().hex}",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
        )
        restore = CoreWebsiteRestore.objects.create(
            backup=backup,
            name="operator-restore",
            params={
                "delete": True,
                "password": "restore-secret-canary",
                "_bs_provider_status": "creating",
            },
            execution_phase="provider_create_unknown",
            execution_metadata={
                "secret": "execution-secret-canary",
                "internal_path": "/srv/restore-secret-canary",
                "api_request": {
                    "recovery_id": recovery_id,
                    "idempotency_key_sha256": "a" * 64,
                },
            },
            lease_owner="restore-worker-secret-canary",
            lease_token=uuid.uuid4(),
            lease_expires_at=timezone.now() + timedelta(minutes=2),
            heartbeat_at=timezone.now(),
            attempt_count=2,
            progress_completed=2,
            progress_total=5,
            progress_unit="paths",
            last_error_code="PROVIDER_AUTH_FAILED",
            error="Bearer restore-provider-secret-canary",
            status=CoreWebsiteRestore.Status.FAILED,
        )

        data = CoreWebsiteRestoreSerializer(
            CoreWebsiteRestore.objects.get(pk=restore.pk)
        ).data
        status = data["execution_status"]
        self.assertEqual(status["correlation_id"], str(restore.correlation_id))
        self.assertEqual(status["recovery_id"], recovery_id)
        self.assertEqual(status["phase"], "failed")
        self.assertEqual(status["attempts"], 2)
        self.assertEqual(status["progress"], {
            "completed": 2,
            "total": 5,
            "unit": "paths",
        })
        self.assertEqual(data["params"], {"delete": True})
        self.assertEqual(data["error"], UtilBackup.EXECUTION_ERROR_MESSAGES["PROVIDER_AUTH_FAILED"])
        for field in (
            "lease_owner",
            "lease_token",
            "lease_expires_at",
            "heartbeat_at",
            "execution_metadata",
            "worker_name",
            "provider_metadata",
        ):
            self.assertNotIn(field, data)
        self.assertNotIn("secret-canary", json.dumps(data))
