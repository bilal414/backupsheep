"""Static safety checks for the disposable native AWS live E2E harness."""

import ast
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from scripts.aws_ec2_ebs_e2e import (
    AmbiguousMutation,
    HarnessError,
    MutationIntentStore,
    _mutation,
    _owned_tags,
    _tags,
)


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "aws_ec2_ebs_e2e.py"


class AWSEC2EBSE2EScriptSafetyTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.source = SCRIPT.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_only_ec2_and_sts_clients_are_constructed(self):
        services = set()
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and function.attr == "client"
                and isinstance(function.value, ast.Name)
                and function.value.id == "boto3"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                services.add(node.args[0].value)
        self.assertEqual(services, {"ec2", "sts"})
        self.assertNotIn("lightsail", self.source.lower())
        self.assertNotIn("delete_instance", self.source)
        self.assertNotIn("delete_disk", self.source)

    def test_writes_require_run_id_apply_and_separate_cleanup_gate(self):
        self.assertIn("require_run_id(os.environ.get(\"BACKUPSHEEP_E2E_RUN_ID\"))", self.source)
        self.assertIn('os.environ.get("BACKUPSHEEP_E2E_APPLY") == "YES"', self.source)
        self.assertIn('os.environ.get("BACKUPSHEEP_E2E_CLEANUP") == "YES"', self.source)
        self.assertIn("if not APPLY:", self.source)
        self.assertIn("if CLEANUP and not APPLY:", self.source)

    def test_boto_timeouts_and_no_blind_mutation_retry_are_present(self):
        self.assertIn('connect_timeout=10', self.source)
        self.assertIn('read_timeout=60', self.source)
        self.assertIn('"total_max_attempts": 1', self.source)
        self.assertIn("class MutationIntentStore", self.source)
        self.assertIn("Persist intent before a mutation and refuse a blind second attempt", self.source)
        self.assertIn("raise AmbiguousMutation", self.source)

    def test_ledger_is_required_before_recording_or_cleanup(self):
        self.assertIn("DurableResourceLedger", self.source)
        self.assertIn("ledger.record(", self.source)
        self.assertIn("ledger.cleanup_eligible(", self.source)
        self.assertIn("ledger.mark_cleanup(", self.source)
        self.assertIn("_entry_matches(resource, entry)", self.source)
        self.assertIn("for entry in ledger.entries(", self.source)

    def test_provider_readback_precedes_each_resource_record(self):
        self.assertIn("resource = readback(resource_id)", self.source)
        self.assertIn("if resource is None:", self.source)
        self.assertIn("_record(", self.source)
        self.assertIn("_describe_image(ec2, ami_id, account_id)", self.source)
        self.assertIn("_describe_snapshot(ec2, snapshot_id, account_id)", self.source)
        self.assertIn("_describe_instance(ec2, restored_instance_id)", self.source)
        self.assertIn("_describe_volume(ec2, restored_volume_id)", self.source)

    def test_fixture_and_native_restore_paths_are_explicit(self):
        for token in (
            "UserData=_fixture_user_data(prefix)",
            "CoreAWSBackup",
            "create_snapshot",
            "restore_snapshot",
            "AMI restore status",
            "EBS restore status",
            "BackupSheepE2E",
            "deregister_image",
            "terminate_instances",
            "delete_snapshot",
            "delete_volume",
        ):
            self.assertIn(token, self.source)
        self.assertIn("restore.save(update_fields=[\"status\", \"modified\"])", self.source)
        self.assertIn("cloud-init fixture did not become ready", self.source)
        self.assertIn('{"available", "in-use"}', self.source)
        self.assertIn("AWS_E2E_EBS_BACKUP_MARKER", self.source)

    def test_fixture_ssh_access_is_run_owned_and_cleanup_is_ledgered(self):
        for token in (
            "AWS_E2E_SSH_PUBLIC_KEY",
            "AWS_E2E_SSH_CIDRS",
            "AWS_E2E_POSTGRES_PASSWORD",
            'kind="key_pair"',
            'ledger.entries("key_pair")',
            "ec2.import_key_pair",
            "ec2.delete_key_pair",
            'email = f"{prefix}-aws-ec2@example.invalid"',
        ):
            self.assertIn(token, self.source)
        self.assertNotIn('"0.0.0.0/0", "Description": "BackupSheep E2E SSH', self.source)

    def test_cleanup_iterates_only_durable_entry_ids(self):
        tree_text = ast.dump(self.tree)
        self.assertIn("entries", tree_text)
        self.assertIn("cleanup_eligible", self.source)
        self.assertIn("resource_id = str(entry.get(\"resource_id\") or \"\")", self.source)
        self.assertNotIn("for resource in _paged(ec2.describe_instances", self.source)

    def test_lost_mutation_response_leaves_intent_and_blocks_second_call(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "aws.json"
            intents = MutationIntentStore(
                ledger_path,
                run_id="bs-e2e-test-1234",
                scope="123456789012:us-east-2",
            )
            provider_call = mock.Mock(side_effect=TimeoutError("response lost"))
            with self.assertRaises(AmbiguousMutation):
                _mutation(
                    intents,
                    "source-instance",
                    "bs-e2e-test-1234:webdb",
                    "run instance",
                    provider_call,
                )
            self.assertEqual(provider_call.call_count, 1)
            with self.assertRaises(HarnessError):
                _mutation(
                    intents,
                    "source-instance",
                    "bs-e2e-test-1234:webdb",
                    "run instance",
                    provider_call,
                )
            self.assertEqual(provider_call.call_count, 1)

    def test_ownership_tag_aliases_are_provider_safe(self):
        tags = _tags(
            "bs-e2e-test-1234",
            "restore-volume",
            Parent="vol-parent",
            Source="snap-source",
            Restore="restore-marker",
        )
        resource = {"Tags": tags}
        self.assertTrue(
            _owned_tags(
                resource,
                "bs-e2e-test-1234",
                "restore-volume",
                marker="restore-marker",
                source_id="snap-source",
                parent="vol-parent",
            )
        )
