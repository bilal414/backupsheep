"""Static supply-chain and least-privilege contracts for the application image."""

from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
SLIM_IMAGE = (
    "python:3.14.7-slim-bookworm@sha256:"
    "23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52"
)


class RuntimeImageHardeningTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        cls.runtime = cls.dockerfile.split(" AS runtime\n", 1)[1]

    def test_every_stage_uses_the_same_digest_pinned_slim_base(self):
        self.assertTrue(
            self.dockerfile.startswith(
                "# syntax=docker/dockerfile:1.20.0@sha256:"
                "26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d"
            )
        )
        from_lines = [
            line for line in self.dockerfile.splitlines() if line.startswith("FROM ")
        ]

        self.assertEqual(len(from_lines), 5)
        for line in from_lines:
            with self.subTest(stage=line):
                self.assertTrue(line.startswith(f"FROM {SLIM_IMAGE} AS "))
        self.assertNotIn("python:3.14.7-bookworm@", self.dockerfile)

    def test_python_dependencies_are_built_then_installed_offline(self):
        self.assertIn("AS python-wheels", self.dockerfile)
        self.assertIn("python -m pip wheel", self.dockerfile)
        self.assertIn("--mount=from=python-wheels,source=/wheels", self.runtime)
        self.assertNotIn("COPY --from=python-wheels", self.runtime)
        self.assertIn("--no-index", self.runtime)
        self.assertIn("--find-links=/wheels", self.runtime)
        self.assertIn("python -m pip check", self.runtime)

    def test_database_clients_are_version_pinned_and_authenticated(self):
        expected_packages = (
            '"mariadb-client=1:10.11.18-0+deb12u1"',
            '"postgresql-client-14=14.24-1.pgdg12+2"',
            '"postgresql-client-15=15.19-1.pgdg12+2"',
            '"postgresql-client-16=16.15-1.pgdg12+2"',
            '"postgresql-client-17=17.11-1.pgdg12+2"',
            '"postgresql-client-18=18.6-1.pgdg12+2"',
        )
        for package in expected_packages:
            with self.subTest(package=package):
                self.assertIn(package, self.dockerfile)

        self.assertIn("signed-by=/usr/share/keyrings/pgdg.gpg", self.dockerfile)
        self.assertIn('amd64) lftp_version="4.9.2-2+b1"', self.dockerfile)
        self.assertIn('arm64) lftp_version="4.9.2-2"', self.dockerfile)
        self.assertIn("sha256sum -c -", self.dockerfile)
        self.assertIn("gpg --batch --verify", self.dockerfile)
        self.assertIn('mysql_version="8.4.10"', self.dockerfile)
        self.assertIn("--proto '=https' --tlsv1.2", self.dockerfile)

    def test_final_stage_has_no_build_or_download_tooling(self):
        forbidden = (
            "apt-get",
            "autoconf",
            "automake",
            "build-essential",
            "curl ",
            "g++",
            "gcc",
            "git ",
            "gnupg",
            "libtool",
            "pkg-config",
            "-dev",
            "http://",
            "https://",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, self.runtime.lower())

        self.assertIn("--mount=from=runtime-packages,source=/runtime-debs", self.runtime)
        self.assertNotIn("COPY --from=runtime-packages", self.runtime)
        self.assertIn("dpkg --unpack /runtime-debs/*.deb", self.runtime)
        self.assertIn("dpkg --configure --pending", self.runtime)

    def test_final_stage_probes_required_backup_tools_and_runs_non_root(self):
        required_probes = (
            '"/usr/lib/postgresql/${version}/bin/pg_dump" --version',
            "mariadb-dump --version",
            "/opt/mysql/bin/mysqldump --version",
            "lftp --version",
            "ssh -V",
            "unzip -v",
            "zip -v",
        )
        for probe in required_probes:
            with self.subTest(probe=probe):
                self.assertIn(probe, self.runtime)

        self.assertIn("useradd --uid 10001 --gid 10001", self.runtime)
        self.assertIn("USER 10001:10001", self.runtime)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/init.sh"]', self.runtime)

    def test_restrictive_checkout_modes_cannot_break_non_root_imports(self):
        self.assertIn("find /code -type d -exec chmod 0755 {} +", self.runtime)
        self.assertIn("find /code -type f -exec chmod 0644 {} +", self.runtime)
        self.assertIn("chmod 0755 /code/install.sh", self.runtime)
        self.assertLess(
            self.runtime.index("find /code -type f -exec chmod 0644 {} +"),
            self.runtime.index("USER 10001:10001"),
        )
