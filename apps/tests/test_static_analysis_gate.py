import copy
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_static_security", ROOT / "scripts" / "validate_static_security.py"
)
static_security = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = static_security
SPEC.loader.exec_module(static_security)


class StaticAnalysisGateTests(TestCase):
    def setUp(self):
        super().setUp()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        for name in ("apps", "backupsheep", "scripts"):
            (self.root / name).mkdir()
        (self.root / "scripts" / "safe.py").write_text(
            "client.set_missing_host_key_policy(paramiko.RejectPolicy())\n",
            encoding="utf-8",
        )
        self.result = {
            "filename": "apps/example.py",
            "test_id": "B608",
            "issue_severity": "MEDIUM",
            "issue_confidence": "LOW",
            "issue_text": "Possible SQL injection vector.",
            "code": "10 query = 'SELECT ' + fixed_value\n",
        }
        path, test_id, fingerprint = static_security.finding_identity(
            self.result, self.root
        )
        self.policy = {
            "schema": 1,
            "bandit_version": "1.9.4",
            "minimum_severity": "MEDIUM",
            "source_roots": ["apps", "backupsheep", "scripts"],
            "excluded_prefixes": ["apps/tests"],
            "reviews": {"review-1": "Strictly fixed test input."},
            "reviewed_findings": [
                {
                    "path": path,
                    "test_id": test_id,
                    "fingerprint": fingerprint,
                    "review": "review-1",
                }
            ],
        }

    def tearDown(self):
        self.temporary_directory.cleanup()
        super().tearDown()

    def test_exact_reviewed_report_and_reject_policy_pass(self):
        static_security.validate(
            {"errors": [], "results": [self.result]}, self.policy, self.root
        )

    def test_new_changed_and_missing_findings_fail_closed(self):
        changed = copy.deepcopy(self.result)
        changed["code"] = "10 query = 'SELECT ' + request_value\n"
        with self.assertRaisesRegex(
            static_security.StaticSecurityError, "unexpected or changed"
        ):
            static_security.validate(
                {"errors": [], "results": [changed]}, self.policy, self.root
            )
        with self.assertRaisesRegex(
            static_security.StaticSecurityError, "missing or changed"
        ):
            static_security.validate(
                {"errors": [], "results": []}, self.policy, self.root
            )

    def test_conditional_auto_add_policy_is_detected_even_when_bandit_misses_it(self):
        (self.root / "scripts" / "unsafe.py").write_text(
            "client.set_missing_host_key_policy(\n"
            "    paramiko.AutoAddPolicy() if first_connection "
            "else paramiko.RejectPolicy()\n"
            ")\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            static_security.StaticSecurityError, "AutoAddPolicy"
        ):
            static_security.validate(
                {"errors": [], "results": [self.result]}, self.policy, self.root
            )

    def test_policy_fingerprint_is_stable_across_line_number_changes(self):
        moved = copy.deepcopy(self.result)
        moved["code"] = "999 query = 'SELECT ' + fixed_value\n"
        self.assertEqual(
            static_security.finding_identity(self.result, self.root),
            static_security.finding_identity(moved, self.root),
        )

    def test_repository_policy_is_explained_and_pinned(self):
        policy = json.loads(
            (ROOT / "deploy" / "static-analysis-policy.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(policy["bandit_version"], "1.9.4")
        self.assertEqual(policy["minimum_severity"], "MEDIUM")
        self.assertEqual(len(policy["reviewed_findings"]), 61)
        self.assertTrue(
            all(item["review"] in policy["reviews"] for item in policy["reviewed_findings"])
        )
