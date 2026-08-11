"""Static guards for secrets that must never enter Docker build layers."""

from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]


class DockerBuildContextSafetyTests(TestCase):
    def test_local_credential_directory_is_excluded_from_copy_context(self):
        rules = {
            line.strip()
            for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

        self.assertIn("_docs/", rules)
        self.assertIn(".env", rules)
        self.assertIn(".env.*", rules)

    def test_dockerfile_does_not_copy_credentials_explicitly(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8").lower()

        self.assertNotIn("copy _docs", dockerfile)
        self.assertNotIn("add _docs", dockerfile)
