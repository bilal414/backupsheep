"""Deterministic guards for the locally built PostgreSQL runtime image."""

from pathlib import Path
import re
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]


class PostgresImageHardeningContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.dockerfile = (ROOT / "Dockerfile.postgres").read_text(encoding="utf-8")
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    def test_base_and_vendor_entrypoint_are_cryptographically_pinned(self):
        self.assertTrue(
            self.dockerfile.startswith(
                "# syntax=docker/dockerfile:1.20.0@sha256:"
                "26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d\n"
            )
        )
        self.assertIn(
            "FROM postgres:18.6-trixie@sha256:"
            "06cad38a5d9f5d24b4d83d86def30795d5e4b757fedbf5281172b576dedcd941",
            self.dockerfile,
        )
        self.assertIn(
            "printf '%s  %s\\n' "
            "9c440299ae04a0a79d55b8bf03307036d890a40979d2fb698073c9050d4b20a5 "
            "/usr/local/bin/docker-entrypoint.sh",
            self.dockerfile,
        )
        self.assertIn("sha256sum --check --strict", self.dockerfile)
        self.assertNotIn("ARG ", self.dockerfile)

    def test_setpriv_replaces_exactly_the_reviewed_gosu_transition(self):
        self.assertIn(
            "exec setpriv --reuid=postgres --regid=postgres --init-groups -- "
            '"$BASH_SOURCE" "$@"',
            self.dockerfile,
        )
        self.assertIn("rm -f -- /usr/local/bin/gosu", self.dockerfile)
        self.assertIn("! grep -Fq gosu /usr/local/bin/docker-entrypoint.sh", self.dockerfile)
        self.assertIn("! command -v gosu", self.dockerfile)
        self.assertIn("test ! -e /usr/local/bin/gosu", self.dockerfile)
        self.assertTrue(self.dockerfile.rstrip().endswith("USER 999:999"))

    def test_complete_installed_util_linux_family_is_exactly_security_pinned(self):
        self.assertIn('"util-linux=2.41.5-0+deb13u1"', self.dockerfile)
        self.assertIn('"bsdutils=1:2.41.5-0+deb13u1"', self.dockerfile)
        self.assertIn(
            '"login=1:4.16.0-2+really2.41.5-0+deb13u1"',
            self.dockerfile,
        )
        for package in (
            "libblkid1",
            "liblastlog2-2",
            "libmount1",
            "libsmartcols1",
            "libuuid1",
            "mount",
            "util-linux",
        ):
            with self.subTest(package=package):
                self.assertRegex(
                    self.dockerfile,
                    rf"(?:\"{re.escape(package)}=2\.41\.5-0\+deb13u1\"|for package in .*\b{re.escape(package)}\b)",
                )
        self.assertIn("rm -rf /var/lib/apt/lists/*", self.dockerfile)

    def test_compose_builds_the_commit_tagged_database_image_without_pull_fallback(self):
        database = re.search(
            r"^  db:\n(?P<body>.*?)(?=^  rabbitmq:\n)",
            self.compose,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(database)
        block = database.group("body")
        self.assertIn(
            'image: "${BACKUPSHEEP_POSTGRES_IMAGE:-backupsheep-postgres:local}"',
            block,
        )
        self.assertIn("pull_policy: never", block)
        self.assertIn("dockerfile: Dockerfile.postgres", block)
        self.assertIn('user: "999:999"', block)
        self.assertNotIn("cap_add:", block)
        self.assertIn("- pgdata:/var/lib/postgresql", block)
