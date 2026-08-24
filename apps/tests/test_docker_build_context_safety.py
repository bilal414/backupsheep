"""Static guards for secrets that must never enter Docker build layers."""

from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]


class DockerBuildContextSafetyTests(TestCase):
    def setUp(self):
        self.rules = [
            line.strip()
            for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def test_context_is_default_deny_with_only_reviewed_runtime_roots(self):
        self.assertEqual(self.rules[0], "**")
        for required in (
            "!Dockerfile",
            "!Dockerfile.postgres",
            "!.dockerignore",
            "!requirements.txt",
            "!requirements.lock",
            "!init.sh",
            "!manage.py",
            "!.env_sample",
            "!apps/",
            "!apps/**",
            "!backupsheep/",
            "!backupsheep/**",
            "!utils/",
            "!utils/**",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.rules)

        for forbidden_allow in (
            "!**",
            "!docs/**",
            "!scripts/**",
            "!.git/**",
            "!install.sh",
        ):
            with self.subTest(forbidden_allow=forbidden_allow):
                self.assertNotIn(forbidden_allow, self.rules)

    def test_tests_caches_and_credential_artifacts_are_reexcluded(self):
        app_allow_index = self.rules.index("!apps/**")
        for excluded in (
            "apps/tests/",
            "apps/**/tests.py",
            "**/__pycache__/",
            "**/*.py[cod]",
            "**/.env",
            "**/.env.*",
            "**/*.env",
            "**/*.pem",
            "**/*.key",
            "**/*.p12",
            "**/*.pfx",
            "**/*.sqlite3",
            "**/*.dump",
            "**/*.sql",
            "**/.aws/",
            "**/.ssh/",
        ):
            with self.subTest(excluded=excluded):
                self.assertIn(excluded, self.rules)
                self.assertGreater(self.rules.index(excluded), app_allow_index)

    def test_dockerfile_does_not_copy_credentials_explicitly(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8").lower()

        self.assertNotIn("copy _docs", dockerfile)
        self.assertNotIn("add _docs", dockerfile)
        self.assertNotIn("copy . /code", dockerfile)
        self.assertNotIn("copy --link . /code", dockerfile)
        self.assertNotIn("copy install.sh", dockerfile)
        self.assertNotIn("copy .env ", dockerfile)
