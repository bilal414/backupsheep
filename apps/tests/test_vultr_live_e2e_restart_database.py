import os
import tempfile

from django.test import TestCase

from scripts.live_e2e_ledger import DurableResourceLedger
from scripts.vultr_live_e2e import LiveVultrHarness, MutationIntentStore


RUN_ID = "bs-e2e-vultr-restart-database"


class VultrLiveE2ERestartDatabaseTests(TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ledger_path = os.path.join(self.temporary.name, "vultr.json")

    def _harness(self):
        harness = LiveVultrHarness.__new__(LiveVultrHarness)
        harness.prefix = RUN_ID
        harness.token = "unit-test-token"
        harness.ledger = DurableResourceLedger(
            self.ledger_path,
            provider="vultr",
            run_id=RUN_ID,
            scope="unit-test-scope",
        )
        harness.intents = MutationIntentStore(
            self.ledger_path,
            run_id=RUN_ID,
            scope="unit-test-scope",
        )
        harness.report = {"ledger": [], "cleanup": {"status": "NOT_RUN", "errors": []}}
        harness.account = None
        harness.member = None
        harness.user = None
        harness.local_ids = {}
        return harness

    def test_setup_local_replaces_only_exact_ledgered_restart_fixture(self):
        first = self._harness()
        first.setup_local()
        old_account_id = first.account.id
        old_user_id = first.user.id
        first.ledger.record(
            kind="instance",
            resource_id="i-owned",
            name=f"{RUN_ID}-source-instance",
            ownership={
                "run_id": RUN_ID,
                "role": "source-instance",
                "request_fingerprint": "a" * 64,
                "label": f"{RUN_ID}-source-instance",
            },
        )

        resumed = self._harness()
        resumed.setup_local()

        self.assertNotEqual(resumed.account.id, old_account_id)
        self.assertNotEqual(resumed.user.id, old_user_id)
        self.assertEqual(
            resumed.report["local_restart_recovery"]["discarded_account_id"],
            old_account_id,
        )
        self.assertEqual(
            resumed.connection.auth_vultr.get_client()["Authorization"],
            "Bearer unit-test-token",
        )
