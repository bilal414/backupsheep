import json
import os
import tempfile
from unittest import TestCase

from scripts.live_e2e_ledger import (
    DurableResourceLedger,
    LedgerError,
    require_run_id,
)


class DurableResourceLedgerTests(TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = os.path.join(self.temporary.name, "aws.json")

    def _ledger(self, **kwargs):
        return DurableResourceLedger(
            self.path,
            provider=kwargs.get("provider", "aws"),
            run_id=kwargs.get("run_id", "bs-e2e-20260810-deadbeef"),
            scope=kwargs.get("scope", "123456789012:us-east-2"),
        )

    def test_run_id_is_explicit_and_dns_safe(self):
        self.assertEqual(
            require_run_id("bs-e2e-20260810-deadbeef"),
            "bs-e2e-20260810-deadbeef",
        )
        for invalid in (None, "", "AUTO_generated", "../escape", "short"):
            with self.assertRaises(LedgerError):
                require_run_id(invalid)

    def test_record_is_fsynced_with_restrictive_permissions(self):
        ledger = self._ledger()
        ledger.record(
            kind="rds_instance",
            resource_id="db-owned",
            name="db-owned",
            ownership={"BackupSheepE2E": "bs-e2e-20260810-deadbeef"},
            source_witness="source-db",
        )

        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        with open(self.path, encoding="utf-8") as source:
            payload = json.load(source)
        self.assertEqual(payload["resources"][0]["resource_id"], "db-owned")
        self.assertTrue(ledger.cleanup_eligible("rds_instance", "db-owned"))

    def test_generated_name_or_attempt_is_not_cleanup_authority(self):
        ledger = self._ledger()
        self.assertFalse(ledger.cleanup_eligible("s3_bucket", "generated-name"))
        with self.assertRaises(LedgerError):
            ledger.mark_cleanup("s3_bucket", "generated-name", state="deleted")

    def test_existing_ledger_scope_cannot_be_reused(self):
        self._ledger()
        with self.assertRaises(LedgerError):
            self._ledger(scope="999999999999:us-east-2")

    def test_provider_id_cannot_be_rebound_to_another_witness(self):
        ledger = self._ledger()
        ledger.record(
            kind="volume",
            resource_id="vol-1",
            name="owned",
            ownership={"run": "bs-e2e-20260810-deadbeef"},
            source_witness="snapshot-a",
        )
        with self.assertRaises(LedgerError):
            ledger.record(
                kind="volume",
                resource_id="vol-1",
                name="owned",
                ownership={"run": "bs-e2e-20260810-deadbeef"},
                source_witness="snapshot-b",
            )

    def test_cleanup_state_is_durable_and_terminal(self):
        ledger = self._ledger()
        ledger.record(
            kind="server",
            resource_id="42",
            name="owned",
            ownership={"run": "bs-e2e-20260810-deadbeef"},
        )
        ledger.mark_cleanup("server", "42", state="deleted")
        self.assertFalse(ledger.cleanup_eligible("server", "42"))
        self.assertEqual(ledger.get("server", "42")["cleanup_state"], "deleted")
