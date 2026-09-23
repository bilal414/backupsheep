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
            "FROM postgres:18.6-alpine3.24@sha256:"
            "d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2",
            self.dockerfile,
        )
        self.assertIn(
            "printf '%s  %s\\n' "
            "9c440299ae04a0a79d55b8bf03307036d890a40979d2fb698073c9050d4b20a5 "
            "/usr/local/bin/docker-entrypoint.sh",
            self.dockerfile,
        )
        self.assertIn("sha256sum -c -", self.dockerfile)
        self.assertNotIn("ARG ", self.dockerfile)

    def test_su_exec_replaces_exactly_the_reviewed_gosu_transition(self):
        self.assertIn(
            'exec su-exec postgres "$BASH_SOURCE" "$@"',
            self.dockerfile,
        )
        self.assertIn("apk add --no-cache \\", self.dockerfile)
        self.assertIn("'su-exec=0.3-r0'", self.dockerfile)
        self.assertIn("grep -Fxq 'su-exec-0.3-r0'", self.dockerfile)
        self.assertNotIn("apk upgrade", self.dockerfile)
        self.assertIn("rm -f -- /usr/local/bin/gosu", self.dockerfile)
        self.assertIn("! grep -Fq gosu /usr/local/bin/docker-entrypoint.sh", self.dockerfile)
        self.assertIn("! command -v gosu", self.dockerfile)
        self.assertIn("test ! -e /usr/local/bin/gosu", self.dockerfile)
        self.assertIn("USER 70:70", self.dockerfile)

    def test_runtime_embeds_the_generation_witness_gate(self):
        self.assertIn(
            'com.backupsheep.postgres.runtime-generation="18.6-alpine3.24-icu-v1"',
            self.dockerfile,
        )
        self.assertIn(
            'com.backupsheep.postgres.openssl-package-version="3.5.8-r0"',
            self.dockerfile,
        )
        self.assertIn("'libcrypto3=3.5.8-r0'", self.dockerfile)
        self.assertIn("'libssl3=3.5.8-r0'", self.dockerfile)
        self.assertIn("deploy/postgres/entrypoint.sh", self.dockerfile)
        self.assertIn("deploy/postgres/storage-witness.sh", self.dockerfile)
        self.assertIn(
            'ENTRYPOINT ["/usr/local/bin/backupsheep-postgres-entrypoint"]',
            self.dockerfile,
        )

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
        self.assertIn('user: "70:70"', block)
        self.assertNotIn("cap_add:", block)
        self.assertIn(
            "      - type: volume\n"
            "        source: postgres_data_v1\n"
            "        target: /var/lib/postgresql\n"
            "        volume:\n"
            "          nocopy: false\n",
            block,
        )
        self.assertNotIn("source: pgdata", block)
