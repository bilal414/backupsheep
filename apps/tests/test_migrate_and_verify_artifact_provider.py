"""Current-state proof for the artifact-provider migration one-shot."""

from types import SimpleNamespace
from unittest import mock

from django.core.management.base import CommandError
from django.core.exceptions import MultipleObjectsReturned
from django.test import SimpleTestCase

from apps.management.commands.migrate_and_verify_artifact_provider import (
    _RETIRED_BACKUP_PROBE_SQL_BY_TABLE,
    _RETIRED_BACKUP_TABLES,
    _artifact_has_durable_shape,
    _backup_preseal_recovery_statuses,
    _backup_output_statuses,
    _destination_matches_source,
    _encryption_ledger_is_complete,
    _execute_retired_backup_probe,
    _recoverable_point_statuses,
    _retained_point_statuses,
    _unledgered_backup_inventory_exists,
    verify_artifact_provider_rows,
)
from apps._tasks.artifact_deletion import (
    DELETION_ORIGIN_KEY,
    build_deletion_origin,
    validate_deletion_origin,
)
from apps.console.backup.models import (
    CoreBackupArtifact,
    CoreBackupEncryptionEnvelope,
    CoreBackupKeyWrap,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
)


class ArtifactProviderCurrentStateProofTests(SimpleTestCase):
    def setUp(self):
        super().setUp()
        self.any_inventory = mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "_any_backup_inventory_exists",
            return_value=False,
        ).start()
        self.unledgered_inventory = mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "_unledgered_backup_inventory_exists",
            return_value=False,
        ).start()
        self.encryption_ledger = mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "_encryption_ledger_is_complete",
            return_value=True,
        ).start()
        self.envelope_objects = mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "CoreBackupEncryptionEnvelope.objects"
        ).start()
        self.envelope_objects.all.return_value.exists.return_value = False
        self.addCleanup(mock.patch.stopall)

    @staticmethod
    def _envelope_query(rows):
        class Query:
            def __init__(self, values):
                self.rows = list(values)

            def select_related(self, *_fields):
                return self

            def prefetch_related(self, *_fields):
                return self

            def iterator(self, **_kwargs):
                return iter(self.rows)

        return Query(rows)

    @staticmethod
    def _valid_envelope_fixture():
        envelope_id = 71
        envelope_uuid = "169fefff-ab41-42f4-a7e5-0639a7876cd2"
        execution = SimpleNamespace(
            backup_content_type_id=12,
            backup_object_id=41,
        )
        wrap = SimpleNamespace(
            pk=83,
            envelope_id=envelope_id,
            provider=CoreBackupKeyWrap.Provider.LOCAL_FILE,
            status=CoreBackupKeyWrap.Status.ACTIVE,
            full_clean=mock.Mock(),
        )
        envelope = SimpleNamespace(
            pk=envelope_id,
            uuid=envelope_uuid,
            format_version=2,
            algorithm="AES-256-GCM-SIV",
            status=CoreBackupEncryptionEnvelope.Status.ACTIVE,
            sealed_at=object(),
            ciphertext_byte_count=128,
            execution=execution,
            _valid_sha256=lambda value: value == "a" * 64,
            full_clean=mock.Mock(),
            get_active_key_wrap=mock.Mock(return_value=wrap),
        )
        source = SimpleNamespace(
            pk=97,
            artifact_format=CoreBackupArtifact.Format.BSE1,
            role=CoreBackupArtifact.Role.SOURCE,
            encryption_envelope=envelope,
            encryption_envelope_id=envelope_id,
            backup_content_type_id=execution.backup_content_type_id,
            backup_object_id=execution.backup_object_id,
            verified_at=object(),
            byte_count=128,
            checksum_algorithm="sha256",
            checksum_value="a" * 64,
            object_key=f"{envelope_uuid}.bse1",
            metadata={"transfer_artifact_name": f"{envelope_uuid}.bse1"},
            storage_id=None,
            validate_encrypted_restore_state=mock.Mock(),
        )
        envelope.artifacts = SimpleNamespace(all=lambda: [source])
        envelope.key_wraps = SimpleNamespace(all=lambda: [wrap])
        return envelope, wrap, source

    def test_complete_encryption_ledger_enumerates_every_envelope_and_wrap(self):
        envelope, wrap, source = self._valid_envelope_fixture()
        self.envelope_objects.all.return_value = self._envelope_query([envelope])
        with mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "CoreBackupKeyWrap.objects"
        ) as wraps:
            wraps.values_list.return_value = [wrap.pk]
            self.assertTrue(_encryption_ledger_is_complete())

        envelope.full_clean.assert_called_once_with()
        wrap.full_clean.assert_called_once_with()
        source.validate_encrypted_restore_state.assert_called_once_with()

    def test_pending_or_unreferenced_envelope_fails_complete_ledger(self):
        envelope, _wrap, _source = self._valid_envelope_fixture()
        envelope.status = CoreBackupEncryptionEnvelope.Status.PENDING
        self.envelope_objects.all.return_value = self._envelope_query([envelope])
        self.assertFalse(_encryption_ledger_is_complete())

        envelope.status = CoreBackupEncryptionEnvelope.Status.ACTIVE
        envelope.artifacts = SimpleNamespace(all=lambda: [])
        self.envelope_objects.all.return_value = self._envelope_query([envelope])
        self.assertFalse(_encryption_ledger_is_complete())

    def test_unpaired_or_pending_wrap_fails_complete_ledger(self):
        self.envelope_objects.all.return_value = self._envelope_query([])
        with mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "CoreBackupKeyWrap.objects"
        ) as wraps:
            wraps.values_list.return_value = [919]
            self.assertFalse(_encryption_ledger_is_complete())

        envelope, wrap, _source = self._valid_envelope_fixture()
        wrap.status = CoreBackupKeyWrap.Status.PENDING
        self.envelope_objects.all.return_value = self._envelope_query([envelope])
        self.assertFalse(_encryption_ledger_is_complete())

        envelope, _wrap, _source = self._valid_envelope_fixture()
        envelope.get_active_key_wrap.side_effect = MultipleObjectsReturned()
        self.envelope_objects.all.return_value = self._envelope_query([envelope])
        self.assertFalse(_encryption_ledger_is_complete())

    def test_exact_retired_tables_use_literal_inventory_probes(self):
        self.assertEqual(
            tuple(_RETIRED_BACKUP_PROBE_SQL_BY_TABLE),
            _RETIRED_BACKUP_TABLES,
        )
        for table_name in _RETIRED_BACKUP_TABLES:
            with self.subTest(table_name=table_name):
                cursor = mock.Mock()
                _execute_retired_backup_probe(cursor, table_name)
                cursor.execute.assert_called_once_with(
                    _RETIRED_BACKUP_PROBE_SQL_BY_TABLE[table_name]
                )

    def test_hostile_or_unknown_retired_table_never_reaches_cursor(self):
        cursor = mock.Mock()

        with self.assertRaisesRegex(CommandError, "unreviewed"):
            _execute_retired_backup_probe(
                cursor,
                "core_wordpress_backup; DELETE FROM core_backup_artifact; --",
            )

        with self.assertRaisesRegex(CommandError, "unreviewed"):
            _execute_retired_backup_probe(cursor, ["core_wordpress_backup"])

        cursor.execute.assert_not_called()

    def test_failed_and_cancelled_attempts_do_not_require_source_artifacts(self):
        output_statuses = _backup_output_statuses(CoreWebsiteBackup)

        self.assertIn(int(CoreWebsiteBackup.Status.COMPLETE), output_statuses)
        self.assertIn(int(CoreWebsiteBackup.Status.PARTIAL), output_statuses)
        self.assertIn(int(CoreWebsiteBackup.Status.UPLOAD_IN_PROGRESS), output_statuses)
        self.assertIn(int(CoreWebsiteBackup.Status.UPLOAD_VALIDATION), output_statuses)
        self.assertIn(int(CoreWebsiteBackup.Status.UPLOAD_COMPLETE), output_statuses)
        self.assertNotIn(int(CoreWebsiteBackup.Status.DOWNLOAD_COMPLETE), output_statuses)
        self.assertNotIn(int(CoreWebsiteBackup.Status.UPLOAD_READY), output_statuses)
        preseal = _backup_preseal_recovery_statuses(CoreWebsiteBackup)
        self.assertIn(int(CoreWebsiteBackup.Status.DOWNLOAD_COMPLETE), preseal)
        self.assertIn(int(CoreWebsiteBackup.Status.UPLOAD_READY), preseal)
        self.assertNotIn(int(CoreWebsiteBackup.Status.FAILED), output_statuses)
        self.assertNotIn(int(CoreWebsiteBackup.Status.CANCELLED), output_statuses)

    def test_unverified_or_wrong_role_artifact_cannot_prove_retained_object(self):
        envelope = SimpleNamespace(
            ciphertext_byte_count=128,
            _valid_sha256=lambda value: value == "a" * 64,
        )
        artifact = SimpleNamespace(
            encryption_envelope=envelope,
            verified_at=None,
            byte_count=128,
            checksum_algorithm="sha256",
            checksum_value="a" * 64,
            object_key="retained.bse1",
            role=CoreBackupArtifact.Role.DESTINATION,
            storage_id=17,
        )
        self.assertFalse(_artifact_has_durable_shape(artifact))
        artifact.verified_at = object()
        artifact.role = CoreBackupArtifact.Role.MANIFEST
        self.assertFalse(_artifact_has_durable_shape(artifact))
        artifact.role = CoreBackupArtifact.Role.DESTINATION
        self.assertTrue(_artifact_has_durable_shape(artifact))

    def test_upload_retry_is_recoverable_without_claiming_destination_commit(self):
        recoverable = _recoverable_point_statuses(CoreWebsiteBackupStoragePoints)
        retained = _retained_point_statuses(CoreWebsiteBackupStoragePoints)

        self.assertIn(
            int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_RETRY),
            recoverable,
        )
        self.assertNotIn(
            int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_RETRY),
            retained,
        )
        self.assertIn(
            int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE),
            retained,
        )
        self.assertNotIn(
            int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY),
            recoverable,
        )

    def test_deletion_origin_distinguishes_committed_and_no_object_points(self):
        point = SimpleNamespace(
            Status=CoreWebsiteBackupStoragePoints.Status,
            metadata={},
        )
        point.metadata[DELETION_ORIGIN_KEY] = build_deletion_origin(
            point,
            int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE),
        )
        self.assertEqual(
            validate_deletion_origin(point),
            (
                "committed-object",
                int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE),
            ),
        )
        point.metadata[DELETION_ORIGIN_KEY].update(
            custody="ambiguous",
            basis="ambiguous-status",
        )
        self.assertIsNone(validate_deletion_origin(point))

        point.metadata = {}
        point.metadata[DELETION_ORIGIN_KEY] = build_deletion_origin(
            point,
            int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY),
        )
        self.assertEqual(
            validate_deletion_origin(point),
            ("no-object", int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY)),
        )
        point.upload_attempt_count = 1
        self.assertIsNone(validate_deletion_origin(point))
        point.upload_attempt_count = 0
        point.metadata = {}
        point.metadata[DELETION_ORIGIN_KEY] = build_deletion_origin(
            point, int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY)
        )
        point.storage_file_id = "unexpected-provider-object"
        self.assertIsNone(validate_deletion_origin(point))
        point.storage_file_id = None
        point.metadata = {}
        point.metadata[DELETION_ORIGIN_KEY] = build_deletion_origin(
            point,
            int(CoreWebsiteBackupStoragePoints.Status.CANCELLED),
        )
        self.assertEqual(
            validate_deletion_origin(point),
            ("no-object", int(CoreWebsiteBackupStoragePoints.Status.CANCELLED)),
        )
        point.upload_attempt_count = 1
        self.assertIsNone(validate_deletion_origin(point))
        point.metadata = {}
        point.metadata[DELETION_ORIGIN_KEY] = build_deletion_origin(
            point,
            int(CoreWebsiteBackupStoragePoints.Status.CANCELLED),
        )
        self.assertEqual(
            validate_deletion_origin(point),
            ("ambiguous", int(CoreWebsiteBackupStoragePoints.Status.CANCELLED)),
        )
        point.metadata = {}
        point.metadata[DELETION_ORIGIN_KEY] = build_deletion_origin(
            point,
            int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_FAILED),
        )
        self.assertEqual(
            validate_deletion_origin(point),
            (
                "ambiguous",
                int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_FAILED),
            ),
        )
        point.metadata[DELETION_ORIGIN_KEY]["custody"] = "committed-object"
        self.assertIsNone(validate_deletion_origin(point))

        for previous_status in (
            999_999,
            int(CoreWebsiteBackupStoragePoints.Status.DELETE_REQUESTED),
            int(CoreWebsiteBackupStoragePoints.Status.DELETE_FAILED),
            int(CoreWebsiteBackupStoragePoints.Status.DELETE_COMPLETED),
        ):
            point.metadata[DELETION_ORIGIN_KEY] = {
                "version": 1,
                "previous_status": previous_status,
                "custody": "ambiguous",
                "basis": "ambiguous-status",
            }
            with self.subTest(previous_status=previous_status):
                self.assertIsNone(validate_deletion_origin(point))

        for field, value in (
            ("version", "1"),
            ("version", True),
            (
                "previous_status",
                str(int(CoreWebsiteBackupStoragePoints.Status.UPLOAD_FAILED)),
            ),
            ("previous_status", True),
        ):
            point.metadata[DELETION_ORIGIN_KEY] = {
                "version": 1,
                "previous_status": int(
                    CoreWebsiteBackupStoragePoints.Status.UPLOAD_FAILED
                ),
                "custody": "ambiguous",
                "basis": "ambiguous-status",
            }
            point.metadata[DELETION_ORIGIN_KEY][field] = value
            with self.subTest(field=field, value=value):
                self.assertIsNone(validate_deletion_origin(point))

    def test_ready_point_on_failed_parent_does_not_require_source(self):
        class Query:
            def __init__(self, rows):
                self.rows = list(rows)

            def select_related(self, *_fields):
                return self

            def iterator(self, **_kwargs):
                return iter(self.rows)

            def order_by(self, *_fields):
                return self

        class Manager:
            def __init__(self, rows):
                self.rows = list(rows)

            def filter(self, **criteria):
                rows = self.rows
                if "status__in" in criteria:
                    accepted = {int(value) for value in criteria["status__in"]}
                    rows = [row for row in rows if int(row.status) in accepted]
                return Query(rows)

        fake_backup_model = SimpleNamespace(
            Status=CoreWebsiteBackup.Status,
            objects=Manager(
                [SimpleNamespace(status=CoreWebsiteBackup.Status.FAILED)]
            ),
        )
        fake_point_model = SimpleNamespace(
            Status=CoreWebsiteBackupStoragePoints.Status,
            objects=Manager(
                [
                    SimpleNamespace(
                        status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY,
                        backup=object(),
                    )
                ]
            ),
        )
        artifact_query = Query([])
        with mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "_BACKUP_FAMILIES",
            ((fake_backup_model, fake_point_model),),
        ), mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "CoreBackupArtifact.objects.filter",
            return_value=artifact_query,
        ), mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "_retired_backup_inventory_exists",
            return_value=False,
        ), mock.patch(
            "apps._tasks.artifact_encryption._load_active_source_state"
        ) as load_source:
            self.assertFalse(_unledgered_backup_inventory_exists())

        load_source.assert_not_called()

    def test_download_complete_without_envelope_allows_source_worker_recovery(self):
        class Query:
            def __init__(self, rows):
                self.rows = list(rows)

            def select_related(self, *_fields):
                return self

            def iterator(self, **_kwargs):
                return iter(self.rows)

            def order_by(self, *_fields):
                return self

        class Manager:
            def __init__(self, rows):
                self.rows = list(rows)

            def filter(self, **criteria):
                rows = self.rows
                if "status__in" in criteria:
                    accepted = {int(value) for value in criteria["status__in"]}
                    rows = [row for row in rows if int(row.status) in accepted]
                return Query(rows)

        backup = SimpleNamespace(status=CoreWebsiteBackup.Status.DOWNLOAD_COMPLETE)
        fake_backup_model = SimpleNamespace(
            Status=CoreWebsiteBackup.Status,
            objects=Manager([backup]),
        )
        fake_point_model = SimpleNamespace(
            Status=CoreWebsiteBackupStoragePoints.Status,
            objects=Manager([]),
        )
        artifact_query = Query([])
        with mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "_BACKUP_FAMILIES",
            ((fake_backup_model, fake_point_model),),
        ), mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "CoreBackupArtifact.objects.filter",
            return_value=artifact_query,
        ), mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "_retired_backup_inventory_exists",
            return_value=False,
        ), mock.patch(
            "apps._tasks.artifact_encryption._load_active_source_state",
            return_value=None,
        ) as load_source:
            self.assertFalse(_unledgered_backup_inventory_exists())

        load_source.assert_called_once_with(backup, allow_absent=True)

    def test_destination_must_match_canonical_source_ciphertext(self):
        source = SimpleNamespace(
            encryption_envelope_id=7,
            byte_count=128,
            checksum_value="a" * 64,
        )
        destination = SimpleNamespace(
            encryption_envelope_id=7,
            byte_count=128,
            checksum_algorithm="sha256",
            checksum_value="a" * 64,
        )

        storage_point = SimpleNamespace(storage_file_id="retained.bse1")
        destination.object_key = "retained.bse1"
        self.assertTrue(
            _destination_matches_source(destination, source, storage_point)
        )
        destination.checksum_value = "b" * 64
        self.assertFalse(
            _destination_matches_source(destination, source, storage_point)
        )
        destination.checksum_value = "a" * 64
        destination.encryption_envelope_id = 8
        self.assertFalse(
            _destination_matches_source(destination, source, storage_point)
        )
        destination.encryption_envelope_id = 7
        destination.object_key = "wrong-object.bse1"
        self.assertFalse(
            _destination_matches_source(destination, source, storage_point)
        )
        destination.object_key = "retained.bse1"
        self.assertFalse(_destination_matches_source(destination, source, None))

    def test_destination_without_exact_provider_readback_fails_sealed_verifier(self):
        from apps._tasks.artifact_encryption import ArtifactPipelineError

        class Query:
            def select_related(self, *_fields):
                return self

            def iterator(self, **_kwargs):
                return iter([destination])

        envelope = SimpleNamespace(
            ciphertext_byte_count=128,
            _valid_sha256=lambda value: value == "a" * 64,
        )
        backup = object()
        destination = SimpleNamespace(
            pk=17,
            backup=backup,
            encryption_envelope=envelope,
            encryption_envelope_id=7,
            verified_at=object(),
            byte_count=128,
            checksum_algorithm="sha256",
            checksum_value="a" * 64,
            object_key="retained.bse1",
            role=CoreBackupArtifact.Role.DESTINATION,
            storage_id=9,
            validate_encrypted_restore_state=mock.Mock(),
        )
        source_artifact = SimpleNamespace(
            encryption_envelope_id=7,
            byte_count=128,
            checksum_value="a" * 64,
        )
        storage_point = SimpleNamespace(storage_file_id="retained.bse1")
        with mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "CoreBackupArtifact.objects.filter",
            return_value=Query(),
        ), mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "_BACKUP_FAMILIES",
            (),
        ), mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "_destination_storage_point",
            return_value=storage_point,
        ), mock.patch(
            "apps.management.commands.migrate_and_verify_artifact_provider."
            "_retired_backup_inventory_exists",
            return_value=False,
        ), mock.patch(
            "apps._tasks.artifact_encryption._load_active_source_state",
            return_value=SimpleNamespace(artifact=source_artifact),
        ), mock.patch(
            "apps._tasks.artifact_encryption."
            "_exact_destination_ciphertext_artifact",
            side_effect=ArtifactPipelineError("provider state missing"),
        ):
            self.assertTrue(_unledgered_backup_inventory_exists())

    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupKeyWrap.objects"
    )
    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupArtifact.objects"
    )
    def test_pending_transition_requires_zero_rows_of_every_status(
        self, artifact_objects, wrap_objects
    ):
        wrap_objects.all.return_value.exists.return_value = True
        artifact_objects.filter.return_value.exists.return_value = False

        with self.assertRaisesRegex(CommandError, "zero data-key wraps"):
            verify_artifact_provider_rows(generation="1-pending-empty")

        wrap_objects.all.return_value.exists.return_value = False
        verify_artifact_provider_rows(generation="1-pending-empty")

        self.envelope_objects.all.return_value.exists.return_value = True
        with self.assertRaisesRegex(CommandError, "zero encryption envelopes"):
            verify_artifact_provider_rows(generation="1-pending-empty")

    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupKeyWrap.objects"
    )
    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupArtifact.objects"
    )
    def test_pending_zero_wraps_still_rejects_one_legacy_artifact(
        self, artifact_objects, wrap_objects
    ):
        wrap_objects.all.return_value.exists.return_value = False
        artifact_objects.filter.return_value.exists.return_value = True

        with self.assertRaisesRegex(CommandError, "zero legacy or unledgered"):
            verify_artifact_provider_rows(generation="1-pending-empty")

    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupKeyWrap.objects"
    )
    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupArtifact.objects"
    )
    def test_pending_empty_rejects_historical_backup_without_artifact_row(
        self, artifact_objects, wrap_objects
    ):
        wrap_objects.all.return_value.exists.return_value = False
        artifact_objects.filter.return_value.exists.return_value = False
        self.any_inventory.return_value = True

        with self.assertRaisesRegex(CommandError, "storage-point"):
            verify_artifact_provider_rows(generation="1-pending-empty")

    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupKeyWrap.objects"
    )
    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupArtifact.objects"
    )
    def test_sealed_generation_rejects_non_local_file_rows(
        self, artifact_objects, wrap_objects
    ):
        wraps = SimpleNamespace()
        wraps.exclude = mock.Mock()
        wraps.exclude.return_value.exists.return_value = True
        wrap_objects.all.return_value = wraps
        artifact_objects.filter.return_value.exists.return_value = False

        with self.assertRaisesRegex(CommandError, "non-local-file"):
            verify_artifact_provider_rows(generation="1")

        wraps.exclude.return_value.exists.return_value = False
        verify_artifact_provider_rows(generation="1")
        wraps.exclude.assert_called_with(provider="local-file")

    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupKeyWrap.objects"
    )
    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupArtifact.objects"
    )
    def test_sealed_generation_rejects_legacy_artifact(
        self, artifact_objects, wrap_objects
    ):
        wraps = SimpleNamespace()
        wraps.exclude = mock.Mock()
        wraps.exclude.return_value.exists.return_value = False
        wrap_objects.all.return_value = wraps
        artifact_objects.filter.return_value.exists.return_value = True

        with self.assertRaisesRegex(CommandError, "legacy plaintext artifact"):
            verify_artifact_provider_rows(generation="1")

    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupKeyWrap.objects"
    )
    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupArtifact.objects"
    )
    def test_sealed_generation_rejects_pending_envelope_or_unledgered_storage_point(
        self, artifact_objects, wrap_objects
    ):
        wraps = SimpleNamespace()
        wraps.exclude = mock.Mock()
        wraps.exclude.return_value.exists.return_value = False
        wrap_objects.all.return_value = wraps
        artifact_objects.filter.return_value.exists.return_value = False
        self.unledgered_inventory.return_value = True

        with self.assertRaisesRegex(CommandError, "without an exact BSE1"):
            verify_artifact_provider_rows(generation="1")

    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupKeyWrap.objects"
    )
    @mock.patch(
        "apps.management.commands.migrate_and_verify_artifact_provider."
        "CoreBackupArtifact.objects"
    )
    def test_sealed_generation_rejects_any_incomplete_encryption_ledger(
        self, artifact_objects, wrap_objects
    ):
        wraps = SimpleNamespace()
        wraps.exclude = mock.Mock()
        wraps.exclude.return_value.exists.return_value = False
        wrap_objects.all.return_value = wraps
        artifact_objects.filter.return_value.exists.return_value = False
        self.encryption_ledger.return_value = False

        with self.assertRaisesRegex(CommandError, "orphan, pending, unpaired"):
            verify_artifact_provider_rows(generation="1")
