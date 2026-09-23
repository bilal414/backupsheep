"""Fail-closed provider-transition tests independent of a live database."""

import importlib
import uuid
from types import SimpleNamespace
from unittest import mock

from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import SimpleTestCase, TransactionTestCase


migration = importlib.import_module(
    "apps._migrations.0049_local_file_artifact_key_provider"
)
bse2_migration = importlib.import_module(
    "apps._migrations.0050_bse2_private_terminal_metadata"
)


class _Query:
    def __init__(self, count=0, exists=False):
        self._count = count
        self._exists = exists

    def count(self):
        return self._count

    def filter(self, **_criteria):
        return self

    def exists(self):
        return self._exists


class ArtifactProviderMigrationTests(SimpleTestCase):
    def setUp(self):
        super().setUp()
        self.backup_inventory = mock.patch.object(
            migration, "legacy_backup_inventory_exists", return_value=False
        ).start()
        self.addCleanup(mock.patch.stopall)

    def _historical_apps(
        self,
        prior_provider_wraps,
        *,
        legacy_artifacts=False,
        encryption_envelopes=0,
    ):
        wraps = SimpleNamespace(
            objects=_Query(
                count=prior_provider_wraps,
                exists=bool(prior_provider_wraps),
            )
        )
        envelopes = SimpleNamespace(
            objects=_Query(exists=bool(encryption_envelopes))
        )
        artifacts = SimpleNamespace(objects=_Query(exists=legacy_artifacts))

        def get_model(_app_label, model_name):
            return {
                "CoreBackupKeyWrap": wraps,
                "CoreBackupEncryptionEnvelope": envelopes,
                "CoreBackupArtifact": artifacts,
            }[model_name]

        return SimpleNamespace(get_model=get_model)

    def test_exact_legacy_tables_use_literal_inventory_probes(self):
        self.assertEqual(
            tuple(migration._LEGACY_BACKUP_PROBE_SQL_BY_TABLE),
            migration.LEGACY_BACKUP_TABLES,
        )
        for table_name in migration.LEGACY_BACKUP_TABLES:
            with self.subTest(table_name=table_name):
                cursor = mock.Mock()
                migration._execute_legacy_backup_probe(cursor, table_name)
                cursor.execute.assert_called_once_with(
                    migration._LEGACY_BACKUP_PROBE_SQL_BY_TABLE[table_name]
                )

    def test_hostile_or_unknown_legacy_table_never_reaches_cursor(self):
        cursor = mock.Mock()

        with self.assertRaisesRegex(RuntimeError, "unreviewed"):
            migration._execute_legacy_backup_probe(
                cursor,
                "core_website_backup; DROP TABLE core_backup_artifact; --",
            )

        with self.assertRaisesRegex(RuntimeError, "unreviewed"):
            migration._execute_legacy_backup_probe(cursor, ["core_website_backup"])

        cursor.execute.assert_not_called()

    def test_prior_local_development_wrap_blocks_local_file_transition(self):
        historical_apps = self._historical_apps(1)

        with self.assertRaisesRegex(RuntimeError, "local-file"):
            migration.require_supported_forward_provider(historical_apps, object())

    def test_non_active_prior_wrap_also_blocks_empty_transition(self):
        historical_apps = self._historical_apps(1)

        with self.assertRaisesRegex(RuntimeError, "zero existing"):
            migration.require_supported_forward_provider(historical_apps, object())

    def test_zero_prior_provider_wraps_allows_empty_transition(self):
        historical_apps = self._historical_apps(0)

        migration.require_supported_forward_provider(historical_apps, object())

    def test_zero_wraps_but_one_legacy_artifact_blocks_transition(self):
        historical_apps = self._historical_apps(0, legacy_artifacts=True)

        with self.assertRaisesRegex(RuntimeError, "zero legacy or unledgered"):
            migration.require_supported_forward_provider(historical_apps, object())

    def test_orphan_envelope_without_wrap_or_artifact_blocks_transition(self):
        historical_apps = self._historical_apps(
            0,
            encryption_envelopes=1,
        )

        with self.assertRaisesRegex(RuntimeError, "BSE v2"):
            bse2_migration.require_empty_forward_encryption_ledger(
                historical_apps,
                object(),
            )

    def test_any_wrap_blocks_bse2_transition_even_without_an_envelope_result(self):
        historical_apps = self._historical_apps(1)

        with self.assertRaisesRegex(RuntimeError, "zero data-key wraps"):
            bse2_migration.require_empty_forward_encryption_ledger(
                historical_apps,
                object(),
            )

    def test_bse2_reverse_refuses_any_envelope_or_wrap(self):
        for wraps, envelopes in ((1, 0), (0, 1), (1, 1)):
            with self.subTest(wraps=wraps, envelopes=envelopes):
                historical_apps = self._historical_apps(
                    wraps,
                    encryption_envelopes=envelopes,
                )
                with self.assertRaisesRegex(RuntimeError, "Cannot reverse"):
                    bse2_migration.require_empty_reverse_encryption_ledger(
                        historical_apps,
                        object(),
                    )

    def test_zero_wraps_and_artifacts_but_historical_backup_blocks_transition(self):
        historical_apps = self._historical_apps(0)
        self.backup_inventory.return_value = True

        with self.assertRaisesRegex(RuntimeError, "storage-point"):
            migration.require_supported_forward_provider(historical_apps, object())


class BSE2MigrationExecutorTests(TransactionTestCase):
    """Exercise the immutable 0049 -> fail-closed 0050 database boundary."""

    migrate_0048 = ("apps", "0048_detach_retired_wordpress_foreign_keys")
    migrate_0049 = ("apps", "0049_local_file_artifact_key_provider")
    migrate_0050 = ("apps", "0050_bse2_private_terminal_metadata")

    def setUp(self):
        super().setUp()
        self._migrate(self.migrate_0049)

    def tearDown(self):
        self._clear_encryption_rows()
        self._migrate(self.migrate_0050)
        super().tearDown()

    @staticmethod
    def _migrate(target):
        executor = MigrationExecutor(connection)
        executor.migrate([target])
        return executor.loader.project_state([target]).apps

    @staticmethod
    def _clear_encryption_rows():
        tables = set(connection.introspection.table_names())
        with connection.cursor() as cursor:
            if "core_backup_key_wrap" in tables:
                cursor.execute("DELETE FROM core_backup_key_wrap")
            if "core_backup_encryption_envelope" in tables:
                cursor.execute("DELETE FROM core_backup_encryption_envelope")

    @staticmethod
    def _create_pending_envelope(historical_apps, *, format_version):
        content_type = historical_apps.get_model("contenttypes", "ContentType")
        execution_model = historical_apps.get_model("apps", "CoreBackupExecution")
        envelope_model = historical_apps.get_model(
            "apps",
            "CoreBackupEncryptionEnvelope",
        )
        owner_type, _created = content_type.objects.get_or_create(
            app_label="apps",
            model="migrationbse2fixture",
        )
        execution = execution_model.objects.create(
            correlation_id=uuid.uuid4(),
            backup_content_type_id=owner_type.pk,
            backup_object_id=uuid.uuid4().int % (2**31),
        )
        return envelope_model.objects.create(
            execution_id=execution.pk,
            format_version=format_version,
            algorithm="AES-256-GCM-SIV",
            context_canonical_json="{}",
            context_sha256="0" * 64,
            header_sha256="1" * 64,
            plaintext_sha256="2" * 64,
            status="pending",
        )

    def test_fresh_0048_path_applies_0049_and_0050(self):
        self._migrate(self.migrate_0048)

        apps_0050 = self._migrate(self.migrate_0050)

        envelope_model = apps_0050.get_model(
            "apps",
            "CoreBackupEncryptionEnvelope",
        )
        self.assertEqual(envelope_model._meta.get_field("format_version").default, 2)

    def test_preapplied_0049_empty_database_migrates_to_0050(self):
        apps_0050 = self._migrate(self.migrate_0050)

        envelope_model = apps_0050.get_model(
            "apps",
            "CoreBackupEncryptionEnvelope",
        )
        self.assertEqual(envelope_model._meta.get_field("format_version").default, 2)

    def test_orphan_v1_envelope_blocks_0050_before_schema_mutation(self):
        apps_0049 = MigrationExecutor(connection).loader.project_state(
            [self.migrate_0049]
        ).apps
        self._create_pending_envelope(apps_0049, format_version=1)

        with self.assertRaisesRegex(RuntimeError, "v1, orphan, pending"):
            self._migrate(self.migrate_0050)

        applied = set(
            MigrationExecutor(connection).loader.applied_migrations
        )
        self.assertNotIn(self.migrate_0050, applied)

    def test_v2_insert_satisfies_new_constraint_and_v1_is_rejected(self):
        apps_0050 = self._migrate(self.migrate_0050)

        envelope = self._create_pending_envelope(
            apps_0050,
            format_version=2,
        )
        self.assertEqual(envelope.format_version, 2)
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._create_pending_envelope(
                apps_0050,
                format_version=1,
            )

    def test_reverse_with_v2_envelope_blocks_before_schema_mutation(self):
        apps_0050 = self._migrate(self.migrate_0050)
        self._create_pending_envelope(apps_0050, format_version=2)

        with self.assertRaisesRegex(RuntimeError, "Cannot reverse"):
            self._migrate(self.migrate_0049)

        applied = set(
            MigrationExecutor(connection).loader.applied_migrations
        )
        self.assertIn(self.migrate_0050, applied)
