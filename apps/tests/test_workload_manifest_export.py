"""Durable, provider-neutral workload manifest exporter safety tests."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import uuid
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.contrib.contenttypes.models import ContentType
from django.utils import timezone

from apps._tasks.integration.restore_database import deterministic_target_name
from apps.console.backup.models import (
    CoreBackupArtifact,
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreDatabaseRestore,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
    CoreWebsiteRestore,
)
from apps.console.node.models import CoreDatabase, CoreNode
from apps.console.storage.models import CoreStorage, CoreStorageType
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase
from scripts import workload_manifest_export as exporter
from scripts import upcloud_live_ui_e2e as live_harness


class WorkloadManifestExportTests(BaseTestCase):
    run_id = "bs-e2e-workload-manifest"

    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _storage(self, provider_code, *, account=None, member=None, suffix=""):
        account = account or self.account
        member = member or self.member
        storage_type, _ = CoreStorageType.objects.get_or_create(
            code=provider_code,
            defaults={
                "name": provider_code,
                "is_enabled": True,
                "position": 999,
            },
        )
        return CoreStorage.objects.create(
            account=account,
            type=storage_type,
            name=f"{provider_code}-{suffix or uuid.uuid4().hex[:8]}",
            added_by=member,
            status=CoreStorage.Status.ACTIVE,
        )

    @staticmethod
    def _database_node(account, member, name):
        connection = factories.make_connection(account, member, code="database")
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.DATABASE,
            name=name,
            added_by=member,
        )
        return node

    def _website_metadata(self, backup, target):
        source_digest = "a" * 64
        fingerprint = hashlib.sha256(
            f"{backup.uuid}|{source_digest}".encode("utf-8")
        ).hexdigest()
        file_row = {"path": "index.html", "bytes": 12, "sha256": "b" * 64}
        return {
            "source_manifest": {
                f"directory:{target}": {
                    "path": target,
                    "type": "directory",
                    "source_digest": source_digest,
                    "files": [file_row],
                }
            },
            "source_states": {
                fingerprint: {
                    "path": target,
                    "target_path": target,
                    "type": "directory",
                    "source_digest": source_digest,
                    "status": "complete",
                    "files": {
                        "index.html": {
                            "bytes": 12,
                            "sha256": "b" * 64,
                            "status": "complete",
                        }
                    },
                }
            },
            "completed_sources": [fingerprint],
        }

    def _fixture(self, provider_code, *, account=None, member=None, run_id=None):
        account = account or self.account
        member = member or self.member
        run_id = run_id or self.run_id
        storage = self._storage(
            provider_code,
            account=account,
            member=member,
            suffix=uuid.uuid4().hex[:8],
        )
        target = f"/srv/backupsheep-e2e/{run_id}"

        website_node = factories.make_website_node(
            account, member, all_paths=False
        )
        website = website_node.website
        website.paths = [{"name": target, "path": target, "type": "directory"}]
        website.all_paths = False
        website.save(update_fields=["paths", "all_paths", "modified"])

        database_node = self._database_node(
            account, member, f"database-{provider_code}-{uuid.uuid4().hex[:8]}"
        )
        source_database = (
            "bs_e2e_"
            + hashlib.sha256(f"{run_id}:workloads".encode("utf-8")).hexdigest()[:12]
        )
        database = CoreDatabase.objects.create(
            node=database_node,
            name=source_database,
            databases=[source_database],
            all_databases=False,
        )

        website_uuid = f"bs-{provider_code}-website-{uuid.uuid4().hex[:12]}"
        database_uuid = f"bs-{provider_code}-database-{uuid.uuid4().hex[:12]}"
        website_backup = CoreWebsiteBackup.objects.create(
            website=website,
            uuid=website_uuid,
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
            metadata={},
        )
        database_backup = CoreDatabaseBackup.objects.create(
            database=database,
            uuid=database_uuid,
            status=UtilBackup.Status.COMPLETE,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
            metadata={},
        )

        website_point = CoreWebsiteBackupStoragePoints.objects.create(
            backup=website_backup,
            storage=storage,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id=f"backupsheep-e2e/{run_id}/{website_uuid}.zip",
            metadata={},
        )
        database_point = CoreDatabaseBackupStoragePoints.objects.create(
            backup=database_backup,
            storage=storage,
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE,
            storage_file_id=f"backupsheep-e2e/{run_id}/{database_uuid}.zip",
            metadata={},
        )

        website_restore = CoreWebsiteRestore.objects.create(
            backup=website_backup,
            storage_point=website_point,
            name=f"restore-{website_uuid}",
            params={},
            status=CoreWebsiteRestore.Status.COMPLETE,
            execution_phase="complete",
            execution_metadata=self._website_metadata(website_backup, target),
            progress_completed=1,
            progress_total=1,
            progress_unit="paths",
        )
        database_restore = CoreDatabaseRestore.objects.create(
            backup=database_backup,
            storage_point=database_point,
            name=f"restore-{database_uuid}",
            params={},
            status=CoreDatabaseRestore.Status.COMPLETE,
            execution_phase="complete",
            execution_metadata={},
            progress_completed=1,
            progress_total=1,
            progress_unit="databases",
        )
        source_digest = "c" * 64
        source_target = deterministic_target_name(database_restore, source_database)
        mapping = {source_database: source_target}
        database_restore.params = {
            "mode": "fork",
            "target_mapping": mapping,
            "mapping_locked": True,
            "source_backup_uuid": str(database_backup.uuid),
        }
        database_restore.execution_metadata = {
            "source_to_target": mapping,
            "mapping_locked": True,
            "target_checkpoints": {
                source_target: {
                    "source": source_database,
                    "source_digest": source_digest,
                    "status": "complete",
                }
            },
        }
        database_restore.save(update_fields=["params", "execution_metadata", "modified"])

        for backup, point, kind in (
            (website_backup, website_point, "website"),
            (database_backup, database_point, "database"),
        ):
            checksum = ("d" if kind == "website" else "e") * 64
            object_key = str(point.storage_file_id)
            version_id = f"version-{provider_code}-{kind}-{uuid.uuid4().hex[:8]}"
            point.metadata = {
                "committed": {
                    "object_key": object_key,
                    "version_id": version_id,
                    "sha256": checksum,
                    "size_bytes": 128,
                }
            }
            point.save(update_fields=["metadata", "modified"])
            content_type = ContentType.objects.get_for_model(
                backup, for_concrete_model=False
            )
            CoreBackupArtifact.objects.create(
                backup_content_type=content_type,
                backup_object_id=backup.pk,
                storage=storage,
                role=CoreBackupArtifact.Role.ARCHIVE,
                idempotency_key=f"{provider_code}-{kind}-{uuid.uuid4().hex}",
                object_key=object_key,
                byte_count=128,
                checksum_algorithm="sha256",
                checksum_value=checksum,
                etag=f"etag-{provider_code}-{kind}",
                version_id=version_id,
                verified_at=timezone.now(),
                metadata={},
            )

        return {
            "account_id": account.pk,
            "storage_id": storage.pk,
            "website_backup_id": website_backup.pk,
            "website_restore_id": website_restore.pk,
            "database_backup_id": database_backup.pk,
            "database_restore_id": database_restore.pk,
            "website_point": website_point,
            "database_point": database_point,
            "website_backup": website_backup,
            "website_restore": website_restore,
            "database_backup": database_backup,
            "database_restore": database_restore,
        }

    def _export(self, provider_code, *, fixture=None, output_name=None):
        fixture = fixture or self._fixture(provider_code)
        output = self.root / (output_name or f"generation-{provider_code}-{uuid.uuid4().hex}")
        receipt = exporter.export_workload_manifest(
            output_dir=output,
            account_id=fixture["account_id"],
            run_id=self.run_id,
            storage_id=fixture["storage_id"],
            provider_code=provider_code,
            website_backup_id=fixture["website_backup_id"],
            website_restore_id=fixture["website_restore_id"],
            database_backup_id=fixture["database_backup_id"],
            database_restore_id=fixture["database_restore_id"],
        )
        return fixture, output, receipt

    def test_exact_happy_path_accepts_actual_storage_type_codes(self):
        for provider_code in ("do_spaces", "upcloud", "oracle"):
            with self.subTest(provider_code=provider_code):
                fixture, output, receipt = self._export(provider_code)
                manifest_path = output / exporter.WORKLOAD_MANIFEST_FILENAME
                marker_path = output / exporter.OWNERSHIP_MARKER_FILENAME
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                marker = json.loads(marker_path.read_text(encoding="utf-8"))
                self.assertEqual(set(manifest), exporter.MANIFEST_KEYS)
                self.assertEqual(manifest["run_id"], self.run_id)
                strict_manifest = live_harness._parse_manifest_bytes(
                    manifest_path.read_bytes(), kind="workload"
                )
                self.assertEqual(strict_manifest, manifest)
                verifier = object.__new__(live_harness.UpCloudLiveHarness)
                verifier.config = SimpleNamespace(run_id=self.run_id)
                parsed = verifier._load_workload_manifest(str(output))
                self.assertEqual(parsed["website"]["backup_id"], fixture["website_backup_id"])
                self.assertEqual(
                    parsed["postgresql"]["restore_id"],
                    fixture["database_restore_id"],
                )
                self.assertEqual(
                    manifest["website"]["restore_path"],
                    f"/srv/backupsheep-e2e/{self.run_id}",
                )
                self.assertNotEqual(
                    manifest["postgresql"]["restore_database"],
                    fixture["database_backup"].database.databases[0],
                )
                self.assertEqual(marker["provider_code"], provider_code)
                self.assertEqual(
                    marker["integration_code"],
                    exporter.SUPPORTED_STORAGE_CODES[provider_code],
                )
                self.assertEqual(marker["storage_id"], fixture["storage_id"])
                self.assertEqual(
                    marker["rows"]["website_backup_id"], fixture["website_backup_id"]
                )
                self.assertEqual(
                    marker["rows"]["database_restore_id"],
                    fixture["database_restore_id"],
                )
                website_binding = marker["artifact_bindings"]["website"]
                database_binding = marker["artifact_bindings"]["database"]
                self.assertEqual(
                    website_binding["artifact_id"],
                    marker["rows"]["website_artifact_id"],
                )
                self.assertEqual(
                    database_binding["artifact_id"],
                    marker["rows"]["database_artifact_id"],
                )
                self.assertEqual(website_binding["byte_count"], 128)
                self.assertEqual(database_binding["byte_count"], 128)
                self.assertEqual(website_binding["sha256"], "d" * 64)
                self.assertEqual(database_binding["sha256"], "e" * 64)
                self.assertTrue(
                    website_binding["etag"].startswith(f"etag-{provider_code}-website")
                )
                self.assertTrue(
                    database_binding["etag"].startswith(f"etag-{provider_code}-database")
                )
                self.assertTrue(
                    website_binding["version_id"].startswith(
                        f"version-{provider_code}-website"
                    )
                )
                self.assertTrue(
                    database_binding["version_id"].startswith(
                        f"version-{provider_code}-database"
                    )
                )
                for binding in (website_binding, database_binding):
                    unsigned = dict(binding)
                    binding_digest = unsigned.pop("binding_sha256")
                    self.assertEqual(
                        hashlib.sha256(exporter._json_bytes(unsigned)).hexdigest(),
                        binding_digest,
                    )
                self.assertEqual(
                    marker["manifest"]["filename"],
                    exporter.WORKLOAD_MANIFEST_FILENAME,
                )
                self.assertEqual(
                    marker["manifest"]["sha256"], receipt["manifest"]["sha256"]
                )
                self.assertEqual(
                    marker["manifest"]["byte_count"],
                    manifest_path.stat().st_size,
                )
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(marker_path.stat().st_mode), 0o600)

    def test_digitalocean_integration_name_is_not_accepted_as_storage_type(self):
        fixture = self._fixture("do_spaces")
        with self.assertRaisesRegex(
            exporter.WorkloadManifestExportError, "provider_code"
        ):
            exporter.export_workload_manifest(
                output_dir=self.root / "digitalocean-rejected",
                provider_code="digitalocean",
                **{
                    key: fixture[key]
                    for key in (
                        "account_id",
                        "storage_id",
                        "website_backup_id",
                        "website_restore_id",
                        "database_backup_id",
                        "database_restore_id",
                    )
                },
                run_id=self.run_id,
            )

    def test_cross_account_storage_and_restore_rows_fail_closed(self):
        own = self._fixture("upcloud")
        foreign_account, foreign_member, _user = factories.make_account()
        foreign = self._fixture(
            "upcloud",
            account=foreign_account,
            member=foreign_member,
            run_id=self.run_id,
        )
        with self.assertRaises(exporter.WorkloadManifestExportError):
            exporter.export_workload_manifest(
                output_dir=self.root / "foreign-backup",
                account_id=own["account_id"],
                run_id=self.run_id,
                storage_id=own["storage_id"],
                provider_code="upcloud",
                website_backup_id=foreign["website_backup_id"],
                website_restore_id=foreign["website_restore_id"],
                database_backup_id=own["database_backup_id"],
                database_restore_id=own["database_restore_id"],
            )
        with self.assertRaises(exporter.WorkloadManifestExportError):
            exporter.export_workload_manifest(
                output_dir=self.root / "foreign-storage",
                account_id=own["account_id"],
                run_id=self.run_id,
                storage_id=foreign["storage_id"],
                provider_code="upcloud",
                website_backup_id=own["website_backup_id"],
                website_restore_id=own["website_restore_id"],
                database_backup_id=own["database_backup_id"],
                database_restore_id=own["database_restore_id"],
            )

    def test_cross_storage_point_and_cross_backup_restore_fail_closed(self):
        first = self._fixture("oracle")
        second = self._fixture("oracle")
        with self.assertRaises(exporter.WorkloadManifestExportError):
            exporter.export_workload_manifest(
                output_dir=self.root / "cross-storage-point",
                account_id=first["account_id"],
                run_id=self.run_id,
                storage_id=second["storage_id"],
                provider_code="oracle",
                website_backup_id=first["website_backup_id"],
                website_restore_id=first["website_restore_id"],
                database_backup_id=first["database_backup_id"],
                database_restore_id=first["database_restore_id"],
            )
        with self.assertRaises(exporter.WorkloadManifestExportError):
            exporter.export_workload_manifest(
                output_dir=self.root / "cross-backup-restore",
                account_id=first["account_id"],
                run_id=self.run_id,
                storage_id=first["storage_id"],
                provider_code="oracle",
                website_backup_id=first["website_backup_id"],
                website_restore_id=second["website_restore_id"],
                database_backup_id=first["database_backup_id"],
                database_restore_id=first["database_restore_id"],
            )

    def test_incorrect_database_mapping_and_website_path_fail_closed(self):
        fixture = self._fixture("do_spaces")
        database_restore = fixture["database_restore"]
        database_restore.params["target_mapping"] = {"foreign_source": "foreign_target"}
        database_restore.save(update_fields=["params", "modified"])
        with self.assertRaises(exporter.WorkloadManifestExportError):
            self._export("do_spaces", fixture=fixture, output_name="bad-mapping")

        fixture = self._fixture("upcloud")
        website = fixture["website_backup"].website
        website.paths = [
            {
                "name": f"/srv/backupsheep-e2e/{self.run_id}/../foreign",
                "path": f"/srv/backupsheep-e2e/{self.run_id}/../foreign",
                "type": "directory",
            }
        ]
        website.save(update_fields=["paths", "modified"])
        with self.assertRaises(exporter.WorkloadManifestExportError):
            self._export("upcloud", fixture=fixture, output_name="bad-path")

    def test_missing_completion_or_artifact_evidence_fails_closed(self):
        fixture = self._fixture("oracle")
        fixture["website_point"].status = (
            CoreWebsiteBackupStoragePoints.Status.UPLOAD_IN_PROGRESS
        )
        fixture["website_point"].save(update_fields=["status", "modified"])
        with self.assertRaises(exporter.WorkloadManifestExportError):
            self._export("oracle", fixture=fixture, output_name="in-progress-point")

        fixture = self._fixture("oracle")
        website_content_type = ContentType.objects.get_for_model(
            fixture["website_backup"], for_concrete_model=False
        )
        artifact = CoreBackupArtifact.objects.get(
            backup_content_type=website_content_type,
            backup_object_id=fixture["website_backup_id"],
            storage_id=fixture["storage_id"],
        )
        artifact.verified_at = None
        artifact.save(update_fields=["verified_at", "modified"])
        with self.assertRaises(exporter.WorkloadManifestExportError):
            self._export("oracle", fixture=fixture, output_name="unverified-artifact")

    def test_nested_sensitive_keys_and_manifest_unknown_fields_are_rejected(self):
        fixture = self._fixture("upcloud")
        restore = fixture["database_restore"]
        restore.execution_metadata["nested"] = {
            "level": [{"credentials": {"password": "must-not-be-read"}}]
        }
        restore.save(update_fields=["execution_metadata", "modified"])
        with self.assertRaises(exporter.WorkloadManifestExportError):
            self._export("upcloud", fixture=fixture, output_name="sensitive-json")

        manifest = {
            "schema": 1,
            "run_id": self.run_id,
            "website": {
                "node_id": 1,
                "backup_id": 2,
                "restore_id": 3,
                "restore_path": f"/srv/backupsheep-e2e/{self.run_id}",
            },
            "postgresql": {
                "node_id": 4,
                "backup_id": 5,
                "restore_id": 6,
                "restore_database": "target_db",
            },
            "unexpected": True,
        }
        with self.assertRaises(exporter.WorkloadManifestExportError):
            exporter._validate_manifest(manifest, self.run_id)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaisesRegex(exporter.WorkloadManifestExportError, "duplicate"):
            exporter._strict_json_load('{"nested":{"x":1,"x":2}}')

    def test_output_must_be_new_outside_worktree_with_real_parent(self):
        fixture = self._fixture("do_spaces")
        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaises(exporter.WorkloadManifestExportError):
            self._export("do_spaces", fixture=fixture, output_name="existing")

        symlink = self.root / "destination-link"
        symlink.symlink_to(existing, target_is_directory=True)
        with self.assertRaises(exporter.WorkloadManifestExportError):
            self._export("do_spaces", fixture=fixture, output_name="destination-link")

        parent_link = self.root / "parent-link"
        parent_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(exporter.WorkloadManifestExportError):
            exporter.export_workload_manifest(
                output_dir=parent_link / "new-generation",
                provider_code="do_spaces",
                run_id=self.run_id,
                **{
                    key: fixture[key]
                    for key in (
                        "account_id",
                        "storage_id",
                        "website_backup_id",
                        "website_restore_id",
                        "database_backup_id",
                        "database_restore_id",
                    )
                },
            )

        worktree_child = exporter.ROOT / ".workload-export-test-child"
        with self.assertRaises(exporter.WorkloadManifestExportError):
            self._export(
                "do_spaces",
                fixture=fixture,
                output_name=str(worktree_child),
            )

    def test_racing_destination_is_never_replaced_and_staging_is_cleaned(self):
        fixture = self._fixture("oracle")
        output = self.root / "racing-generation"
        original = exporter._publish_exclusive

        def race(source, destination):
            destination.mkdir(mode=0o755)
            (destination / "racing-owner").write_bytes(b"RACING-OWNER")
            return original(source, destination)

        with mock.patch.object(exporter, "_publish_exclusive", side_effect=race), self.assertRaises(
            exporter.WorkloadManifestExportError
        ):
            self._export("oracle", fixture=fixture, output_name="racing-generation")
        self.assertEqual((output / "racing-owner").read_bytes(), b"RACING-OWNER")
        self.assertEqual(list(self.root.glob(".racing-generation.workload-staging-*")), [])

    def test_atomic_write_failure_leaves_no_partial_generation(self):
        fixture = self._fixture("upcloud")
        original = exporter._write_exclusive_file
        calls = 0

        def fail_on_marker(path, payload):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise exporter.WorkloadManifestExportError("injected atomic failure")
            return original(path, payload)

        with mock.patch.object(
            exporter, "_write_exclusive_file", side_effect=fail_on_marker
        ), self.assertRaisesRegex(
            exporter.WorkloadManifestExportError, "injected atomic failure"
        ):
            self._export("upcloud", fixture=fixture, output_name="atomic-failure")
        self.assertFalse((self.root / "atomic-failure").exists())
        self.assertEqual(list(self.root.glob(".atomic-failure.workload-staging-*")), [])

    def test_cli_prints_only_the_secret_free_receipt(self):
        receipt = {"status": "exported", "provider_code": "do_spaces"}
        output = StringIO()
        args = [
            "--account-id",
            "1",
            "--run-id",
            self.run_id,
            "--storage-id",
            "2",
            "--provider-code",
            "do_spaces",
            "--website-backup-id",
            "3",
            "--website-restore-id",
            "4",
            "--database-backup-id",
            "5",
            "--database-restore-id",
            "6",
            "--output-dir",
            str(self.root / "cli-generation"),
        ]
        with mock.patch.object(
            exporter, "export_workload_manifest", return_value=receipt
        ), redirect_stdout(output):
            self.assertEqual(exporter.main(args), 0)
        self.assertEqual(json.loads(output.getvalue()), receipt)
        self.assertNotIn("password", output.getvalue().casefold())
