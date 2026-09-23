import ast
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]


class LiveE2EScriptSafetyTests(TestCase):
    def _source(self, name):
        return (ROOT / "scripts" / name).read_text(encoding="utf-8")

    def test_aws_harness_has_no_lightsail_client_or_api(self):
        source = self._source("aws_s3_dynamodb_rds_e2e.py")
        tree = ast.parse(source)
        string_values = {
            node.value.lower()
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        self.assertNotIn("lightsail", string_values)
        self.assertNotIn("delete_instance", source)
        self.assertNotIn("delete_disk", source)

    def test_aws_cleanup_is_ledger_gated_and_does_not_bulk_delete_recovery_points(self):
        source = self._source("aws_s3_dynamodb_rds_e2e.py")
        self.assertIn('ledger.entries("recovery_point")', source)
        self.assertIn('ledger.entries("security_group")', source)
        self.assertIn('ledger.entries("s3_bucket")', source)
        self.assertIn('S3_STORAGE = f"{PREFIX}-storage"', source)
        self.assertIn("def cleanup_eligible(kind, identifier):", source)
        self.assertIn("ledger.cleanup_eligible(kind, identifier)", source)
        self.assertIn('cleanup_eligible("recovery_point"', source)
        self.assertIn("RecoveryPointArn=recovery_point_arn", source)
        self.assertNotIn('for point in points:', source)
        self.assertIn('BACKUPSHEEP_E2E_APPLY") == "YES"', source)
        self.assertIn('BACKUPSHEEP_E2E_CLEANUP") == "YES"', source)
        self.assertIn('"total_max_attempts": 1', source)

    def test_aws_vault_preflight_uses_cursor_listing(self):
        source = self._source("aws_s3_dynamodb_rds_e2e.py")
        self.assertIn("def _backup_vault_exists", source)
        self.assertIn("backup_client.list_backup_vaults", source)
        self.assertIn("AWS Backup returned a repeated vault pagination token", source)
        self.assertIn(
            '"backup_vault": _backup_vault_exists(backup_client, BACKUP_VAULT)',
            source,
        )

    def test_aws_long_running_rds_creates_are_ledgered_before_wait(self):
        source = self._source("aws_s3_dynamodb_rds_e2e.py")
        create_at = source.index("rds.create_db_instance(")
        register_at = source.index(
            "_register_rds_instance(ledger, rds, RDS_SOURCE)", create_at
        )
        wait_at = source.index('"source RDS availability"', create_at)
        self.assertLess(create_at, register_at)
        self.assertLess(register_at, wait_at)
        self.assertIn("def _register_rds_snapshot", source)
        self.assertIn('email=f"{PREFIX}-aws@example.invalid"', source)
        self.assertIn("account, user = _recover_local_fixture()", source)

    def test_hetzner_cloud_cleanup_requires_durable_ids(self):
        source = self._source("hetzner_cloud_e2e.py")
        self.assertIn("self._hydrate_created_from_ledger()", source)
        self.assertIn('self.report["mode"] = "cleanup_only"', source)
        self.assertIn('ledger.cleanup_eligible("server", identifier)', source)
        self.assertIn(
            'ledger.cleanup_eligible("snapshot_image", identifier)', source
        )
        self.assertNotIn("adopt_after_partial_create(cleanup_errors)", source)
        self.assertIn("state=\"manual_review\"", source)

    def test_object_storage_attempt_is_never_ownership_proof(self):
        source = self._source("hetzner_object_storage_e2e.py")
        self.assertNotIn("create_attempted", source)
        self.assertIn('ledger.cleanup_eligible("bucket", self.bucket)', source)
        self.assertIn("marker_sha256", source)
        self.assertIn('"total_max_attempts": 1', source)
