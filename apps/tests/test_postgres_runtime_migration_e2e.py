"""Static fail-closed contracts for the real PostgreSQL runtime migration gate."""

from pathlib import Path
import subprocess
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "deploy" / "ci" / "run-postgres-runtime-migration-e2e.sh"
SOURCE_IMAGE = ROOT / "deploy" / "ci" / "Dockerfile.postgres-runtime-source"
WORKFLOW = ROOT / ".github" / "workflows" / "supply-chain-security.yml"
GUIDE = ROOT / "docs" / "guides" / "postgres-runtime-migration.md"


class PostgresRuntimeMigrationE2EContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.source_image = SOURCE_IMAGE.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.guide = GUIDE.read_text(encoding="utf-8")

    def test_shell_harness_parses_and_uses_only_the_reviewed_migrator(self):
        result = subprocess.run(
            ["/bin/bash", "-n", str(RUNNER)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            'readonly migrator="${repository_root}/deploy/postgres/migrate-runtime.sh"',
            self.runner,
        )
        self.assertNotIn("source-identity-contract.sh", self.runner)
        self.assertNotIn("AWS_KMS", self.runner)
        self.assertNotIn("aws_kms", self.runner)

    def test_retired_source_fixture_is_exact_digest_uid_and_test_only(self):
        self.assertTrue(
            self.source_image.startswith(
                "# syntax=docker/dockerfile:1.20.0@sha256:"
                "26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d\n"
            )
        )
        self.assertIn(
            "FROM postgres:18.6-trixie@sha256:"
            "06cad38a5d9f5d24b4d83d86def30795d5e4b757fedbf5281172b576dedcd941",
            self.source_image,
        )
        self.assertIn("9c440299ae04a0a79d55b8bf03307036", self.source_image)
        self.assertIn('USER 999:999', self.source_image)
        self.assertIn(
            'runtime-migration-source-fixture="18.6-trixie-glibc-uid999-v1"',
            self.source_image,
        )
        self.assertNotIn("ARG ", self.source_image)
        self.assertNotIn("apt-get", self.source_image)
        self.assertNotIn("COPY ", self.source_image)

    def test_workflow_makes_the_docker_gate_release_blocking_and_bounded(self):
        job = self.workflow.split("  application-security-regression:\n", 1)[1]
        for expected in (
            'TEST_LEGACY_POSTGRES_IMAGE: "backupsheep-ci-postgres-legacy:',
            'TEST_POSTGRES_MIGRATION_PREFIX: "bs-pgm-',
            "--file deploy/ci/Dockerfile.postgres-runtime-source",
            '--tag "$TEST_LEGACY_POSTGRES_IMAGE"',
            "Exercise witnessed PostgreSQL runtime migration and crash recovery",
            "timeout --signal=TERM --kill-after=30s 45m ",
            "deploy/ci/run-postgres-runtime-migration-e2e.sh",
            'owned_image "$TEST_LEGACY_POSTGRES_IMAGE"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, job)
        self.assertNotIn("continue-on-error", job)
        self.assertLess(
            job.index("Exercise witnessed PostgreSQL runtime migration and crash recovery"),
            job.index("Remove exact regression-gate resources"),
        )

    def test_fixture_reconstructs_both_exact_identity_contracts(self):
        for expected in (
            "create_generation2_source()",
            "create_generation3_source()",
            "backupsheep:database-identity-v2:",
            "backupsheep:database-identity-v3:",
            ":retired-v2-runtime",
            "CONNECTION LIMIT 8",
            "CONNECTION LIMIT 128",
            "idle_in_transaction_session_timeout",
            "lock_timeout",
            "statement_timeout",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public",
            "GRANT CONNECT ON DATABASE backupsheep",
            "GRANT USAGE ON SCHEMA public",
            "migrated-debian-generation2-v1",
            "migrated-debian-v1",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.runner)

    def test_schema_data_types_ownership_and_effective_acls_are_proved(self):
        for expected in (
            "CREATE TYPE public.fixture_state AS ENUM",
            "CREATE DOMAIN public.fixture_code",
            "CREATE TYPE public.fixture_pair AS",
            "CREATE TABLE public.migration_fixture",
            "INSERT INTO public.migration_fixture",
            "CREATE FUNCTION public.fixture_label",
            "queued,complete",
            "label:text,amount:integer",
            "pg_catalog.has_database_privilege",
            "pg_catalog.has_schema_privilege",
            "pg_catalog.has_table_privilege",
            "pg_catalog.has_column_privilege",
            "pg_catalog.has_sequence_privilege",
            "pg_catalog.has_function_privilege",
            "pg_catalog.has_type_privilege",
            "0|0|0|0|0|0|0|0|0|0|0",
            "false|false|false|false|false|false|false|false|false|true|true|true",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.runner)

    def test_hostile_role_object_and_acl_have_independent_refusal_runs(self):
        attacks = (
            (
                "CREATE ROLE backupsheep_attacker",
                "generation-3 source identity validation failed",
                "hostile-extra-role",
            ),
            (
                "pg_catalog.lo_create(424242)",
                "large objects outside the automatic migration contract",
                "hostile-large-object",
            ),
            (
                "GRANT SET ON PARAMETER work_mem",
                "non-stock parameter privileges",
                "hostile-parameter-acl",
            ),
        )
        for mutation, message, label in attacks:
            with self.subTest(label=label):
                self.assertIn(mutation, self.runner)
                self.assertIn(message, self.runner)
                self.assertIn(label, self.runner)
        self.assertIn("did not fail closed with status 64", self.runner)
        self.assertIn("reported a false successful migration", self.runner)

    def test_sigkill_boundaries_are_distinct_and_receipt_resume_is_attested(self):
        for failpoint in ("credential", "helper", "receipt"):
            with self.subTest(failpoint=failpoint):
                self.assertIn(f"run_migration {failpoint}", self.runner)
                self.assertIn(f"    {failpoint})", self.runner)
        for expected in (
            'kill -KILL "$BACKUPSHEEP_E2E_MIGRATION_PID"',
            "credential-read-attestation",
            "-postgres-migration-target",
            "finalize-migration",
            ".backupsheep-logical-migration-receipt-v2",
            "source_contract=strict-ten-role-v1",
            "PostgreSQL migration reconciled from its completed receipt:",
            "did not reconcile instead of recopying",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.runner)

    def test_runtime_and_cleanup_never_expand_to_host_or_global_docker_state(self):
        for expected in (
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges:true",
            "--pids-limit 256",
            "com.backupsheep.postgres-runtime-e2e",
            "com.backupsheep.postgres-migration",
            "Refusing to clean an unexpected container",
            "Refusing to clean an unexpected volume",
            "Refusing to remove attached owned volume",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.runner)
        for forbidden in (
            "--privileged",
            "--network host",
            "/var/run/docker.sock",
            "docker system prune",
            "docker volume prune",
            "rm -rf",
            "sudo ",
            "iptables",
            "ufw",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.runner)

    def test_operator_guide_records_real_proof_and_its_boundary(self):
        for expected in (
            "Release-blocking runtime proof",
            "generation-2",
            "generation-3",
            "public enum, domain and composite types",
            "SIGKILLed after credential creation",
            "five-minute Docker-command deadlines",
            "does not replace",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.guide)
