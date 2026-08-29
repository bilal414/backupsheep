"""Fail-closed provider-transition tests independent of a live database."""

import importlib
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase


migration = importlib.import_module(
    "apps._migrations.0049_local_file_artifact_key_provider"
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

    def _historical_apps(self, prior_provider_wraps, *, legacy_artifacts=False):
        wraps = SimpleNamespace(objects=_Query(count=prior_provider_wraps))
        artifacts = SimpleNamespace(objects=_Query(exists=legacy_artifacts))

        def get_model(_app_label, model_name):
            return {
                "CoreBackupKeyWrap": wraps,
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

    def test_zero_wraps_and_artifacts_but_historical_backup_blocks_transition(self):
        historical_apps = self._historical_apps(0)
        self.backup_inventory.return_value = True

        with self.assertRaisesRegex(RuntimeError, "storage-point"):
            migration.require_supported_forward_provider(historical_apps, object())
