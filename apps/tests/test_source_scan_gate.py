import ast
import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, defaultTestLoader


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_source_scan", ROOT / "scripts" / "validate_source_scan.py"
)
source_scan = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = source_scan
SPEC.loader.exec_module(source_scan)


class SourceScanGateTests(TestCase):
    # Django's test runner honors class tags directly; unittest ignores them.
    # The Git-free production-image lane excludes this host-tooling tag, while
    # the static-analysis lane runs the class through unittest with real Git.
    tags = {"requires_host_git"}

    def git(self, *arguments, environment=None):
        return subprocess.run(
            ["git", *arguments],
            cwd=self.root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()

    def setUp(self):
        super().setUp()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.target_bytes = {
            "Dockerfile": b"FROM example\nRUN apt-get update\n",
            "Dockerfile.egress": b"FROM example\nUSER 0:0\n",
        }
        for target, payload in self.target_bytes.items():
            (self.root / target).write_bytes(payload)

        self.git("init", "--quiet")
        self.git("config", "user.name", "BackupSheep CI")
        self.git("config", "user.email", "security@example.invalid")
        self.git(
            "remote",
            "add",
            "origin",
            "https://github.com/example/backupsheep.git",
        )
        self.git("add", *sorted(self.target_bytes))
        commit_environment = dict(os.environ)
        commit_environment.update(
            {
                "GIT_AUTHOR_DATE": "2026-08-25T12:00:00+0000",
                "GIT_COMMITTER_DATE": "2026-08-25T12:00:00+0000",
            }
        )
        self.git(
            "commit",
            "--quiet",
            "--message",
            "Source scan fixture",
            environment=commit_environment,
        )
        self.source_revision = self.git("rev-parse", "--verify", "HEAD^{commit}")
        self.git("checkout", "--quiet", "--detach", self.source_revision)
        self.repository_identity = source_scan._trusted_repository_identity_for_checkout(
            self.root, self.source_revision
        )
        self.assertIsNotNone(self.repository_identity)

        self.findings = {
            "Dockerfile": {
                "Type": "Dockerfile Security Check",
                "ID": "DS-0017",
                "Title": "Reviewed update",
                "Severity": "HIGH",
                "Status": "FAIL",
                "CauseMetadata": {"StartLine": 2, "Code": {"Lines": []}},
            },
            "Dockerfile.egress": {
                "Type": "Dockerfile Security Check",
                "ID": "DS-0002",
                "Title": "Reviewed root bootstrap",
                "Severity": "HIGH",
                "Status": "FAIL",
                "CauseMetadata": {"StartLine": 2, "Code": {"Lines": []}},
            },
        }
        self.policy = {
            "schema_version": 1,
            "scanner": copy.deepcopy(source_scan.EXPECTED_SCANNER),
            "reviewed_misconfigurations": [
                {
                    "target": target,
                    "id": finding["ID"],
                    "severity": "HIGH",
                    "status": "FAIL",
                    "target_sha256": hashlib.sha256(
                        self.target_bytes[target]
                    ).hexdigest(),
                    "finding_sha256": source_scan.finding_fingerprint(finding),
                    "reason": "Reviewed and content-pinned test fixture.",
                }
                for target, finding in self.findings.items()
            ],
        }
        self.report = {
            "SchemaVersion": 2,
            "CreatedAt": "2026-08-25T12:34:56.123456Z",
            "ArtifactName": ".",
            "ArtifactType": "repository",
            "ArtifactID": self.repository_identity["artifact_id"],
            "Metadata": copy.deepcopy(self.repository_identity["metadata"]),
            "ReportID": "01234567-89ab-4def-8123-456789abcdef",
            "Trivy": {"Version": "0.74.0"},
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Packages": [{"Name": "Django", "Version": "6.0"}],
                },
                {
                    "Target": "package-lock.json",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Packages": [{"Name": "alpinejs", "Version": "3.15.8"}],
                },
                *[
                    {
                        "Target": target,
                        "Class": "config",
                        "Type": "dockerfile",
                        "MisconfSummary": {"Successes": 19, "Failures": 1},
                        "Misconfigurations": [copy.deepcopy(finding)],
                    }
                    for target, finding in self.findings.items()
                ],
                {
                    "Target": "Dockerfile.postgres",
                    "Class": "config",
                    "Type": "dockerfile",
                    "MisconfSummary": {"Successes": 20, "Failures": 0},
                },
                {
                    "Target": "Dockerfile.rabbitmq",
                    "Class": "config",
                    "Type": "dockerfile",
                    "MisconfSummary": {"Successes": 20, "Failures": 0},
                },
                {
                    "Target": "Dockerfile.rabbitmq-upgrade",
                    "Class": "config",
                    "Type": "dockerfile",
                    "MisconfSummary": {"Successes": 20, "Failures": 0},
                },
                {
                    "Target": "deploy/ci/Dockerfile.postgres-runtime-source",
                    "Class": "config",
                    "Type": "dockerfile",
                    "MisconfSummary": {"Successes": 20, "Failures": 0},
                },
            ],
        }
        self.secret_report = {
            "SchemaVersion": 2,
            "CreatedAt": "2026-08-25T12:35:56.123456Z",
            "ArtifactName": ".",
            "ArtifactType": "repository",
            "ArtifactID": self.repository_identity["artifact_id"],
            "Metadata": copy.deepcopy(self.repository_identity["metadata"]),
            "ReportID": "11234567-89ab-4def-8123-456789abcdef",
            "Trivy": {"Version": "0.74.0"},
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Packages": [{"Name": "Django", "Version": "6.0"}],
                }
            ],
        }
        self.canary_report = {
            "SchemaVersion": 2,
            "CreatedAt": "2026-08-25T12:36:56.123456Z",
            "ArtifactName": ".",
            "ArtifactType": "filesystem",
            "ReportID": "21234567-89ab-4def-8123-456789abcdef",
            "Trivy": {"Version": "0.74.0"},
            "Results": [
                {
                    "Target": target,
                    "Class": "secret",
                    "Secrets": [
                        {
                            "Category": "Twilio",
                            "Code": {"Lines": []},
                            "EndLine": 1,
                            "Match": "private synthetic canary material",
                            "RuleID": "twilio-api-key",
                            "Severity": "MEDIUM",
                            "StartLine": 1,
                            "Title": "Twilio API Key",
                        }
                    ],
                }
                for target in (
                    "canary.md",
                    "canary.lock",
                    "examples/canary.txt",
                    "tests/canary.txt",
                    "vendor/canary.txt",
                )
            ],
        }

    def tearDown(self):
        self.temporary_directory.cleanup()
        super().tearDown()

    def validate(self, report=None, policy=None, secret_report=None, canary_report=None):
        return source_scan.validate_report(
            report if report is not None else self.report,
            secret_report if secret_report is not None else self.secret_report,
            canary_report if canary_report is not None else self.canary_report,
            policy if policy is not None else self.policy,
            self.root,
            self.source_revision,
        )

    def test_exact_content_pinned_report_produces_only_zero_sensitive_evidence(self):
        summary = self.validate()
        self.assertEqual(
            summary["findings"],
            {
                "vulnerabilities": 0,
                "secrets": 0,
                "reviewed_misconfigurations": 2,
                "unreviewed_misconfigurations": 0,
            },
        )
        self.assertEqual(summary["source_revision"], self.source_revision)
        self.assertEqual(summary["inventory"], {"packages": 2})
        self.assertEqual(summary["secret_canaries"]["total"], 5)
        self.assertNotIn("CauseMetadata", json.dumps(summary))

    def test_normal_detached_checkout_and_canary_use_exact_opposite_header_forms(self):
        self.assertTrue((self.root / ".git").is_dir())
        self.assertEqual(self.git("branch", "--show-current"), "")
        self.validate()

        filesystem_main = copy.deepcopy(self.report)
        filesystem_main["ArtifactType"] = "filesystem"
        filesystem_main.pop("ArtifactID")
        filesystem_main.pop("Metadata")
        with self.assertRaises(source_scan.SourceScanError) as raised:
            self.validate(report=filesystem_main)
        self.assertIn("vulnerability/misconfiguration", str(raised.exception))
        self.assertIn("missing_known=ArtifactID,Metadata", str(raised.exception))

        repository_canary = copy.deepcopy(self.canary_report)
        repository_canary["ArtifactType"] = "repository"
        repository_canary["ArtifactID"] = self.repository_identity["artifact_id"]
        repository_canary["Metadata"] = copy.deepcopy(
            self.repository_identity["metadata"]
        )
        with self.assertRaises(source_scan.SourceScanError) as raised:
            self.validate(canary_report=repository_canary)
        self.assertIn("secret canary", str(raised.exception))
        self.assertIn("unexpected_known=ArtifactID,Metadata", str(raised.exception))

    def test_repository_reports_must_share_one_exact_artifact_identity(self):
        changed_secret = copy.deepcopy(self.secret_report)
        changed_url = "https://github.com/example/different.git"
        changed_secret["Metadata"]["RepoURL"] = changed_url
        changed_secret["ArtifactID"] = source_scan._repository_artifact_id(
            changed_url, self.source_revision
        )
        with self.assertRaisesRegex(
            source_scan.SourceScanError, "do not share one exact artifact identity"
        ):
            self.validate(secret_report=changed_secret)

    def test_repository_identity_is_independently_bound_to_checkout_remote(self):
        changed_url = "https://github.com/example/different.git"
        changed_report = copy.deepcopy(self.report)
        changed_secret = copy.deepcopy(self.secret_report)
        for candidate in (changed_report, changed_secret):
            candidate["Metadata"]["RepoURL"] = changed_url
            candidate["ArtifactID"] = source_scan._repository_artifact_id(
                changed_url, self.source_revision
            )
        with self.assertRaisesRegex(
            source_scan.SourceScanError, "does not match the detached checkout"
        ):
            self.validate(report=changed_report, secret_report=changed_secret)

        self.git(
            "remote",
            "set-url",
            "origin",
            "https://github.com/example/reconfigured.git",
        )
        with self.assertRaisesRegex(
            source_scan.SourceScanError, "does not match the detached checkout"
        ):
            self.validate()

    def test_repository_metadata_and_artifact_id_fail_closed(self):
        cases = []

        changed_commit = copy.deepcopy(self.report)
        changed_commit["Metadata"]["Commit"] = "b" * 40
        changed_commit["ArtifactID"] = source_scan._repository_artifact_id(
            changed_commit["Metadata"]["RepoURL"], "b" * 40
        )
        cases.append((changed_commit, "final source revision"))

        invalid_author = copy.deepcopy(self.report)
        invalid_author["Metadata"]["Author"] = "invalid\nauthor <invalid@example.invalid>"
        cases.append((invalid_author, "author repository signature"))

        invalid_committer = copy.deepcopy(self.report)
        invalid_committer["Metadata"]["Committer"] = "invalid committer"
        cases.append((invalid_committer, "committer repository signature"))

        invalid_message = copy.deepcopy(self.report)
        invalid_message["Metadata"]["CommitMsg"] = "invalid\x00message"
        cases.append((invalid_message, "commit message metadata"))

        invalid_url = copy.deepcopy(self.report)
        invalid_url["Metadata"]["RepoURL"] = "http://github.com/example/backupsheep.git"
        cases.append((invalid_url, "repository URL metadata"))

        extra_metadata = copy.deepcopy(self.report)
        extra_metadata["Metadata"]["Branch"] = "develop"
        cases.append((extra_metadata, "metadata shape"))

        missing_metadata = copy.deepcopy(self.report)
        missing_metadata["Metadata"].pop("Committer")
        cases.append((missing_metadata, "metadata shape"))

        invalid_artifact = copy.deepcopy(self.report)
        invalid_artifact["ArtifactID"] = "sha256:" + ("A" * 64)
        cases.append((invalid_artifact, "artifact identity"))

        for candidate, expected_error in cases:
            with self.subTest(expected_error=expected_error), self.assertRaisesRegex(
                source_scan.SourceScanError, expected_error
            ):
                self.validate(report=candidate)

    def test_labeled_schema_diagnostic_never_echoes_unknown_field_names(self):
        malformed = copy.deepcopy(self.report)
        malformed.pop("Trivy")
        private_unknown_key = "private-material-must-not-be-echoed"
        malformed[private_unknown_key] = True
        with self.assertRaises(source_scan.SourceScanError) as raised:
            self.validate(report=malformed)
        diagnostic = str(raised.exception)
        self.assertIn("vulnerability/misconfiguration", diagnostic)
        self.assertIn("missing_known=Trivy", diagnostic)
        self.assertIn("unexpected_unknown_count=1", diagnostic)
        self.assertNotIn(private_unknown_key, diagnostic)

        malformed_secret = copy.deepcopy(self.secret_report)
        malformed_secret.pop("ReportID")
        malformed_secret[private_unknown_key] = True
        with self.assertRaises(source_scan.SourceScanError) as raised:
            self.validate(secret_report=malformed_secret)
        diagnostic = str(raised.exception)
        self.assertIn("all-severity secret", diagnostic)
        self.assertIn("missing_known=ReportID", diagnostic)
        self.assertNotIn(private_unknown_key, diagnostic)

    def test_any_vulnerability_or_secret_fails_without_echoing_secret_material(self):
        vulnerable = copy.deepcopy(self.report)
        vulnerable["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": "CVE-2099-0001", "Severity": "HIGH"}
        ]
        with self.assertRaisesRegex(source_scan.SourceScanError, "1 HIGH/CRITICAL vulnerability"):
            self.validate(vulnerable)

        secret_value = "do-not-print-this-secret-value"
        secret = copy.deepcopy(self.secret_report)
        secret["Results"] = [
            {
                "Target": "private.txt",
                "Class": "secret",
                "Secrets": [
                    {
                        "RuleID": "private-key",
                        "Match": secret_value,
                        "Severity": "LOW",
                    }
                ],
            }
        ]
        with self.assertRaises(source_scan.SourceScanError) as raised:
            self.validate(secret_report=secret)
        self.assertIn("1 all-severity secret", str(raised.exception))
        self.assertNotIn(secret_value, str(raised.exception))
        self.assertNotIn("private-key", str(raised.exception))

    def test_markdown_and_default_skipped_medium_canaries_are_mandatory_and_private(self):
        missing_markdown = copy.deepcopy(self.canary_report)
        missing_markdown["Results"] = missing_markdown["Results"][1:]
        with self.assertRaisesRegex(source_scan.SourceScanError, "canaries were missing"):
            self.validate(canary_report=missing_markdown)

        changed_severity = copy.deepcopy(self.canary_report)
        changed_severity["Results"][0]["Secrets"][0]["Severity"] = "HIGH"
        with self.assertRaises(source_scan.SourceScanError) as raised:
            self.validate(canary_report=changed_severity)
        self.assertIn("canaries were missing", str(raised.exception))
        self.assertNotIn("private synthetic canary material", str(raised.exception))

    def test_extra_missing_changed_and_duplicate_misconfigurations_fail_closed(self):
        cases = []

        extra = copy.deepcopy(self.report)
        extra_finding = copy.deepcopy(self.findings["Dockerfile"])
        extra_finding["ID"] = "DS-9999"
        extra["Results"][2]["Misconfigurations"].append(extra_finding)
        extra["Results"][2]["MisconfSummary"]["Failures"] = 2
        cases.append(extra)

        missing = copy.deepcopy(self.report)
        missing["Results"][2]["Misconfigurations"] = []
        missing["Results"][2]["MisconfSummary"]["Failures"] = 0
        cases.append(missing)

        changed = copy.deepcopy(self.report)
        changed["Results"][2]["Misconfigurations"][0]["Title"] = "Changed scanner evidence"
        cases.append(changed)

        duplicate = copy.deepcopy(self.report)
        duplicate["Results"][2]["Misconfigurations"].append(
            copy.deepcopy(duplicate["Results"][2]["Misconfigurations"][0])
        )
        duplicate["Results"][2]["MisconfSummary"]["Failures"] = 2
        cases.append(duplicate)

        for report in cases:
            with self.subTest(case=cases.index(report)), self.assertRaisesRegex(
                source_scan.SourceScanError, "extra, missing, changed, or duplicated"
            ):
                self.validate(report)

    def test_target_byte_change_and_symlink_fail_closed_before_review_is_used(self):
        (self.root / "Dockerfile").write_bytes(b"FROM changed\n")
        with self.assertRaisesRegex(source_scan.SourceScanError, "source target changed"):
            self.validate()

        (self.root / "Dockerfile").unlink()
        (self.root / "actual-dockerfile").write_bytes(self.target_bytes["Dockerfile"])
        (self.root / "Dockerfile").symlink_to("actual-dockerfile")
        with self.assertRaisesRegex(source_scan.SourceScanError, "regular file"):
            self.validate()

    def test_duplicate_results_and_malformed_scanner_inventory_are_rejected(self):
        duplicate = copy.deepcopy(self.report)
        duplicate["Results"].append(copy.deepcopy(duplicate["Results"][0]))
        with self.assertRaisesRegex(source_scan.SourceScanError, "duplicate result"):
            self.validate(duplicate)

        no_packages = copy.deepcopy(self.report)
        no_packages["Results"][0]["Packages"] = []
        with self.assertRaisesRegex(source_scan.SourceScanError, "package inventory"):
            self.validate(no_packages)

        malformed = copy.deepcopy(self.report)
        malformed["Results"][0]["Unexpected"] = []
        with self.assertRaisesRegex(source_scan.SourceScanError, "malformed"):
            self.validate(malformed)

        missing_clean_dockerfile = copy.deepcopy(self.report)
        missing_clean_dockerfile["Results"] = missing_clean_dockerfile["Results"][:-1]
        with self.assertRaisesRegex(source_scan.SourceScanError, "coverage is missing"):
            self.validate(missing_clean_dockerfile)

        missing_frontend = copy.deepcopy(self.report)
        missing_frontend["Results"] = [
            result
            for result in missing_frontend["Results"]
            if result["Target"] != "package-lock.json"
        ]
        with self.assertRaisesRegex(source_scan.SourceScanError, "coverage is missing"):
            self.validate(missing_frontend)

        missing_secret_inventory = copy.deepcopy(self.secret_report)
        missing_secret_inventory["Results"] = [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Packages": [{"Name": "alpinejs", "Version": "3.15.8"}],
            }
        ]
        with self.assertRaisesRegex(source_scan.SourceScanError, "inventory coverage is missing"):
            self.validate(secret_report=missing_secret_inventory)

    def test_policy_rejects_additional_duplicate_changed_and_unexplained_reviews(self):
        duplicate = copy.deepcopy(self.policy)
        duplicate["reviewed_misconfigurations"][1] = copy.deepcopy(
            duplicate["reviewed_misconfigurations"][0]
        )
        with self.assertRaisesRegex(source_scan.SourceScanError, "duplicate review"):
            self.validate(policy=duplicate)

        extra = copy.deepcopy(self.policy)
        extra["unexpected"] = True
        with self.assertRaisesRegex(source_scan.SourceScanError, "unexpected or missing"):
            self.validate(policy=extra)

        scanner = copy.deepcopy(self.policy)
        scanner["scanner"]["scanners"] = ["vuln", "misconfig"]
        with self.assertRaisesRegex(source_scan.SourceScanError, "scanner contract"):
            self.validate(policy=scanner)

        unexplained = copy.deepcopy(self.policy)
        unexplained["reviewed_misconfigurations"][0]["reason"] = ""
        with self.assertRaisesRegex(source_scan.SourceScanError, "invalid explanation"):
            self.validate(policy=unexplained)

    def test_strict_json_loader_rejects_duplicate_keys_symlinks_and_oversized_files(self):
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"safe":{"value":1,"value":2}}', encoding="utf-8")
        with self.assertRaisesRegex(source_scan.SourceScanError, "duplicate"):
            source_scan.load_json(duplicate, maximum_bytes=1024, label="test report")

        symlink = self.root / "linked.json"
        symlink.symlink_to("duplicate.json")
        with self.assertRaisesRegex(source_scan.SourceScanError, "regular file"):
            source_scan.load_json(symlink, maximum_bytes=1024, label="test report")

        oversized = self.root / "oversized.json"
        with oversized.open("wb") as stream:
            stream.truncate(1025)
        with self.assertRaisesRegex(source_scan.SourceScanError, "size limit"):
            source_scan.load_json(oversized, maximum_bytes=1024, label="test report")

    def test_private_evidence_writer_never_replaces_and_uses_mode_0600(self):
        evidence_directory = self.root / "evidence"
        evidence_directory.mkdir(mode=0o700)
        output = evidence_directory / "summary.json"
        source_scan._write_private_json(output, {"secrets": 0})
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(json.loads(output.read_text()), {"secrets": 0})
        with self.assertRaisesRegex(source_scan.SourceScanError, "Refusing to replace"):
            source_scan._write_private_json(output, {"secrets": 0})

    def test_repository_policy_pins_exact_current_dockerfile_bytes(self):
        policy = json.loads(
            (ROOT / "deploy" / "source-scan-policy.json").read_text(encoding="utf-8")
        )
        reviews = source_scan.validate_policy(policy)
        source_scan.validate_target_hashes(reviews, ROOT)
        self.assertEqual(
            {(review["target"], review["id"]) for review in reviews},
            source_scan.EXPECTED_REVIEWS,
        )

    def test_workflow_uses_pinned_tool_full_checkout_and_zero_sensitive_artifact(self):
        workflow = (
            ROOT / ".github" / "workflows" / "supply-chain-security.yml"
        ).read_text(encoding="utf-8")
        static_job = workflow.split("  static-python-security:\n", 1)[1].split(
            "  application-security-regression:\n", 1
        )[0]
        checkout_step = static_job.split(
            "      - name: Check out exact source\n", 1
        )[1].split("      - name: Set up Python\n", 1)[0]
        self.assertIn("ref: ${{ github.sha }}", checkout_step)
        self.assertEqual(
            workflow.count(
                "uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
            ),
            3,
        )
        self.assertEqual(workflow.count("ref: ${{ github.sha }}"), 3)
        for expected in (
            "deploy/static-analysis-requirements.lock",
            "c7234adc0f4ccc3e17fee62e41971c73bdfdf717623b43faf9bfd0b32bb8d76d",
            "--only-binary=:all:",
            "--require-hashes",
            "scripts/install_release_tools.py",
            "--tool actionlint",
            "--tool trivy",
            "actionlint\" -version",
            "Validate every GitHub Actions workflow",
            "empty-actionlint.yaml",
            "empty-bandit.ini",
            "empty-bandit.yaml",
            "-config-file",
            "suppression canary",
            "--ignore-nosec",
            "B307",
            '--ini "$CI_SOURCE_SCAN_TOOL_DIR/empty-bandit.ini"',
            '-c "$CI_SOURCE_SCAN_TOOL_DIR/empty-bandit.yaml"',
            "-shellcheck=",
            "-pyflakes=",
            "0\\.74\\.0",
            "env -i",
            '--config "$CI_SOURCE_SCAN_TOOL_DIR/empty-trivy.yaml"',
            '--secret-config "$CI_SOURCE_SCAN_TOOL_DIR/strict-trivy-secret.yaml"',
            '--ignorefile "$CI_SOURCE_SCAN_TOOL_DIR/empty-trivy.ignore"',
            "--scanners vuln,misconfig",
            "--scanners secret",
            "--severity HIGH,CRITICAL",
            "--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            "--ignore-unfixed=false",
            "--include-dev-deps",
            "--list-all-pkgs",
            "--exit-code 7",
            "--exit-code 9",
            "scripts/validate_source_scan.py",
            "Exercise source-scan validator contracts",
            "python3 -m unittest apps.tests.test_source_scan_gate -v",
            '--secret-report "$secret_report"',
            '--canary-report "$canary_report"',
            "deploy/source-scan-policy.json",
            'test "$(git rev-parse --verify HEAD)" = "$GITHUB_SHA"',
            'test ! -L "$private_report"',
            "Refusing a pre-existing source-scan tool path.",
            "backupsheep-source-scan-evidence/summary.json",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, static_job)
        for forbidden in ("--skip-dirs", "--skip-files", "--ignore-policy"):
            self.assertNotIn(forbidden, static_job)
        artifact_step = static_job.split(
            "      - name: Retain zero-sensitive final-SHA source-scan evidence", 1
        )[1]
        self.assertNotIn("source-scan-private", artifact_step)
        self.assertNotIn("trivy.json", artifact_step)


class SourceScanInstallerContractTests(TestCase):
    def test_git_repository_contracts_run_only_in_the_git_enabled_static_job(self):
        expected_git_test_names = [
            "test_any_vulnerability_or_secret_fails_without_echoing_secret_material",
            "test_duplicate_results_and_malformed_scanner_inventory_are_rejected",
            "test_exact_content_pinned_report_produces_only_zero_sensitive_evidence",
            "test_extra_missing_changed_and_duplicate_misconfigurations_fail_closed",
            "test_labeled_schema_diagnostic_never_echoes_unknown_field_names",
            "test_markdown_and_default_skipped_medium_canaries_are_mandatory_and_private",
            "test_normal_detached_checkout_and_canary_use_exact_opposite_header_forms",
            "test_policy_rejects_additional_duplicate_changed_and_unexplained_reviews",
            "test_private_evidence_writer_never_replaces_and_uses_mode_0600",
            "test_repository_identity_is_independently_bound_to_checkout_remote",
            "test_repository_metadata_and_artifact_id_fail_closed",
            "test_repository_policy_pins_exact_current_dockerfile_bytes",
            "test_repository_reports_must_share_one_exact_artifact_identity",
            "test_strict_json_loader_rejects_duplicate_keys_symlinks_and_oversized_files",
            "test_target_byte_change_and_symlink_fail_closed_before_review_is_used",
            "test_workflow_uses_pinned_tool_full_checkout_and_zero_sensitive_artifact",
        ]
        self.assertEqual(
            defaultTestLoader.getTestCaseNames(SourceScanGateTests),
            expected_git_test_names,
        )
        self.assertEqual(SourceScanGateTests.tags, {"requires_host_git"})
        self.assertFalse(getattr(SourceScanGateTests, "__unittest_skip__", False))
        for test_name in expected_git_test_names:
            self.assertFalse(
                getattr(
                    getattr(SourceScanGateTests, test_name),
                    "__unittest_skip__",
                    False,
                )
            )

        def contains_host_git_tag(expression):
            return any(
                isinstance(child, ast.Constant)
                and child.value == "requires_host_git"
                for child in ast.walk(expression)
            )

        tagged_test_targets = []
        for path in sorted((ROOT / "apps" / "tests").glob("test_*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in tree.body:
                if not isinstance(node, ast.ClassDef):
                    continue
                class_has_tag = any(
                    contains_host_git_tag(decorator)
                    for decorator in node.decorator_list
                )
                for statement in node.body:
                    if isinstance(statement, ast.Assign) and any(
                        isinstance(target, ast.Name) and target.id == "tags"
                        for target in statement.targets
                    ):
                        class_has_tag = class_has_tag or contains_host_git_tag(
                            statement.value
                        )
                    elif (
                        isinstance(statement, ast.AnnAssign)
                        and isinstance(statement.target, ast.Name)
                        and statement.target.id == "tags"
                        and statement.value is not None
                    ):
                        class_has_tag = class_has_tag or contains_host_git_tag(
                            statement.value
                        )
                    elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if any(
                            contains_host_git_tag(decorator)
                            for decorator in statement.decorator_list
                        ):
                            tagged_test_targets.append(
                                f"{path.relative_to(ROOT).as_posix()}:{node.name}.{statement.name}"
                            )
                if class_has_tag:
                    tagged_test_targets.append(
                        f"{path.relative_to(ROOT).as_posix()}:{node.name}"
                    )
        self.assertEqual(
            tagged_test_targets,
            ["apps/tests/test_source_scan_gate.py:SourceScanGateTests"],
        )

        workflow = (
            ROOT / ".github" / "workflows" / "supply-chain-security.yml"
        ).read_text(encoding="utf-8")
        static_job = workflow.split("  static-python-security:\n", 1)[1].split(
            "  application-security-regression:\n", 1
        )[0]
        regression_job = workflow.split(
            "  application-security-regression:\n", 1
        )[1]
        self.assertIn("Exercise source-scan validator contracts", static_job)
        self.assertIn("command -v git >/dev/null", static_job)
        self.assertIn(
            "python3 -m unittest apps.tests.test_source_scan_gate -v", static_job
        )
        self.assertNotIn("--exclude-tag=requires_host_git", static_job)
        self.assertNotIn("continue-on-error", static_job)
        self.assertIn(
            "Unexpected Git executable in the production application image.",
            regression_job,
        )
        self.assertIn("--exclude-tag=requires_host_git --noinput", regression_job)
        self.assertEqual(regression_job.count("--exclude-tag=requires_host_git"), 1)

    def test_dependency_audit_installer_is_whole_file_and_artifact_hash_locked(self):
        workflow = (
            ROOT / ".github" / "workflows" / "supply-chain-security.yml"
        ).read_text(encoding="utf-8")
        dependency_job = workflow.split(
            "  dependency-and-deployment-checks:\n", 1
        )[1].split("  static-python-security:\n", 1)[0]
        lock_path = ROOT / "deploy" / "dependency-audit-requirements.lock"
        self.assertEqual(
            hashlib.sha256(lock_path.read_bytes()).hexdigest(),
            "123d99c57ebca7ae13478cf0a4dfbb5925fa2ea08769d7aa9117b91393a5d540",
        )
        for expected in (
            "deploy/dependency-audit-requirements.lock",
            "--only-binary=:all:",
            "--require-hashes",
            "--requirement requirements.lock",
            "--disable-pip",
            "--strict",
            "pip-audit 2.10.1",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, dependency_job)
        self.assertNotIn("pip-audit==2.10.1", dependency_job)
        self.assertNotIn("--requirement requirements.txt", dependency_job)
        requirements = [
            line
            for line in lock_path.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        self.assertGreaterEqual(len(requirements), 25)
        self.assertTrue(
            any(line.startswith("pip-audit==2.10.1 ") for line in requirements)
        )
        for requirement in requirements:
            self.assertRegex(
                requirement,
                r"\A[A-Za-z0-9_.-]+==[^ ]+ --hash=sha256:[0-9a-f]{64}\Z",
            )

    def test_installer_hard_codes_non_weakening_secret_config(self):
        installer = (ROOT / "scripts" / "install_release_tools.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '_atomic_write(destination / "empty-actionlint.yaml", b"{}\\n", 0o600)',
            installer,
        )
        self.assertIn(
            '_atomic_write(destination / "empty-bandit.ini", b"[bandit]\\n", 0o600)',
            installer,
        )
        self.assertIn(
            '_atomic_write(destination / "empty-bandit.yaml", b"{}\\n", 0o600)',
            installer,
        )
        self.assertIn(
            'b"  - tests\\n"',
            installer,
        )
        self.assertIn('b"  - examples\\n"', installer)
        self.assertIn('b"  - vendor\\n"', installer)
        self.assertIn('b"  - markdown\\n"', installer)
        self.assertIn('b"skip-patterns: []\\n"', installer)

    def test_source_gate_uses_the_exact_hash_pinned_trivy_asset(self):
        policy = json.loads(
            (ROOT / "deploy" / "release-policy.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            policy["tools"]["trivy"],
            {
                "version": "0.74.0",
                "url": "https://github.com/aquasecurity/trivy/releases/download/"
                "v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz",
                "sha256": "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
                "archive_member": "trivy",
            },
        )
        self.assertEqual(
            policy["tools"]["actionlint"],
            {
                "version": "1.7.12",
                "url": "https://github.com/rhysd/actionlint/releases/download/"
                "v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz",
                "sha256": "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
                "archive_member": "actionlint",
            },
        )
