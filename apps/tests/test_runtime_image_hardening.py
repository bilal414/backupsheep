"""Static supply-chain and least-privilege contracts for the application image."""

from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
PYTHON_IMAGE = (
    "python:3.14.7-slim-trixie@sha256:"
    "ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4"
)
UBUNTU_IMAGE = (
    "ubuntu:26.04@sha256:"
    "2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b"
)


class RuntimeImageHardeningTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        cls.runtime = cls.dockerfile.split(" AS runtime\n", 1)[1]
        cls.entrypoint = (ROOT / "init.sh").read_text(encoding="utf-8")

    def test_external_python_and_ubuntu_bases_are_digest_pinned(self):
        self.assertTrue(
            self.dockerfile.startswith(
                "# syntax=docker/dockerfile:1.20.0@sha256:"
                "26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d"
            )
        )
        from_lines = [
            line for line in self.dockerfile.splitlines() if line.startswith("FROM ")
        ]

        self.assertEqual(
            from_lines,
            [
                f"FROM {PYTHON_IMAGE} AS python-runtime",
                "FROM python-runtime AS python-wheels",
                "FROM python-runtime AS repository-metadata",
                "FROM python-runtime AS postgres-clients",
                "FROM python-runtime AS mysql-client",
                f"FROM {UBUNTU_IMAGE} AS ubuntu-runtime-base",
                "FROM ubuntu-runtime-base AS ubuntu-runtime-packages",
                "FROM ubuntu-runtime-base AS runtime",
            ],
        )
        self.assertNotIn("python:3.14.7-bookworm@", self.dockerfile)
        self.assertEqual(self.dockerfile.count(PYTHON_IMAGE), 1)
        self.assertEqual(self.dockerfile.count(UBUNTU_IMAGE), 1)
        self.assertIn("COPY --from=python-runtime /usr/local /usr/local", self.runtime)

    def test_python_dependencies_are_built_then_installed_offline(self):
        self.assertIn("AS python-wheels", self.dockerfile)
        self.assertIn("python -m pip --isolated wheel", self.dockerfile)
        self.assertIn("--prefer-binary", self.dockerfile)
        self.assertIn(
            "COPY --link --chmod=0444 requirements.txt requirements.lock /build/",
            self.dockerfile,
        )
        self.assertIn(
            'grep -Fqx "# requirements-sha256: ${requirements_sha256}"',
            self.dockerfile,
        )
        self.assertIn("--requirement=/build/requirements.lock", self.dockerfile)
        self.assertIn("--no-build-isolation", self.dockerfile)
        self.assertIn("--only-binary=:all:", self.dockerfile)
        self.assertIn(
            "--no-binary=crcmod,ibm-cos-sdk,ibm-cos-sdk-core,"
            "ibm-cos-sdk-s3transfer,oss2",
            self.dockerfile,
        )
        self.assertIn("/build/build-tools.lock", self.dockerfile)
        self.assertIn("/wheels/requirements.runtime.lock", self.dockerfile)
        self.assertIn("--mount=from=python-wheels,source=/wheels", self.runtime)
        self.assertNotIn("COPY --from=python-wheels", self.runtime)
        self.assertIn("--no-index", self.runtime)
        self.assertIn("--find-links=/wheels", self.runtime)
        self.assertGreaterEqual(self.dockerfile.count("--require-hashes"), 2)
        self.assertIn("python -m pip --isolated check", self.runtime)
        self.assertIn(
            "/usr/local/lib/python3.14/site-packages/pip-*.dist-info",
            self.runtime,
        )
        self.assertIn("/usr/local/bin/pip3.14", self.runtime)
        for launcher in (
            "cli.exe",
            "cli-32.exe",
            "cli-64.exe",
            "cli-arm64.exe",
            "gui.exe",
            "gui-32.exe",
            "gui-64.exe",
            "gui-arm64.exe",
        ):
            with self.subTest(setuptools_launcher=launcher):
                self.assertIn(launcher, self.runtime)
        self.assertIn(
            "find /usr/local/lib/python3.14/site-packages/setuptools \\",
            self.runtime,
        )
        self.assertIn("-type f -name '*.exe' -print -quit", self.runtime)

    def test_database_clients_are_version_pinned_and_authenticated(self):
        expected_packages = (
            '"mariadb-client-core=1:11.8.6-5ubuntu0.1"',
            '"postgresql-client-14=14.24-1.pgdg13+2"',
            '"postgresql-client-15=15.19-1.pgdg13+2"',
            '"postgresql-client-16=16.15-1.pgdg13+2"',
            '"postgresql-client-17=17.11-1.pgdg13+2"',
            '"postgresql-client-18=18.6-1.pgdg13+2"',
        )
        for package in expected_packages:
            with self.subTest(package=package):
                self.assertIn(package, self.dockerfile)

        security_updates = (
            '"ca-certificates=20260601~26.04.1"',
            '"gzip=1.14-1~exp2ubuntu1.1"',
            '"libmariadb3=1:11.8.6-5ubuntu0.1"',
            '"libncurses6=6.6+20251231-1"',
            '"libpq5=18.6-0ubuntu0.26.04.1"',
            '"libssl3t64=3.5.5-1ubuntu3.4"',
            '"openssh-client=1:10.2p1-2ubuntu3.5"',
            '"openssl=3.5.5-1ubuntu3.4"',
            '"openssl-provider-legacy=3.5.5-1ubuntu3.4"',
            '"tzdata=2026c-0ubuntu0.26.04.1"',
        )
        for package in security_updates:
            with self.subTest(security_update=package):
                self.assertIn(package, self.dockerfile)

        self.assertEqual(self.dockerfile.count("3.5.5-1ubuntu3.3"), 0)
        self.assertEqual(
            self.dockerfile.count("libssl3t64 (= 3.5.5-1ubuntu3.4)"), 3
        )
        self.assertIn(
            "assert_package libssl3t64 3.5.5-1ubuntu3.4", self.dockerfile
        )
        self.assertIn(
            "assert_package openssl 3.5.5-1ubuntu3.4", self.dockerfile
        )
        self.assertIn(
            "assert_package openssl-provider-legacy 3.5.5-1ubuntu3.4",
            self.dockerfile,
        )

        self.assertIn("signed-by=/usr/share/keyrings/pgdg.gpg", self.dockerfile)
        self.assertIn(
            'apt-get download "mariadb-client=1:11.8.6-5ubuntu0.1"',
            self.dockerfile,
        )
        self.assertIn('dpkg-deb --fsys-tarfile "$mariadb_archive"', self.dockerfile)
        self.assertIn("tar -xOf - ./usr/bin/mariadb-dump", self.dockerfile)
        self.assertNotIn(
            'dpkg-deb --extract "$mariadb_archive"', self.dockerfile
        )
        self.assertIn("FROM python-runtime AS postgres-clients", self.dockerfile)
        self.assertIn(
            "--mount=from=postgres-clients,source=/postgres-client-debs,"
            "target=/postgres-client-debs,ro",
            self.runtime,
        )
        self.assertIn(
            "--mount=from=mysql-client,source=/mysql-client-debs,"
            "target=/mysql-client-debs,ro",
            self.runtime,
        )
        self.assertIn("Package: backupsheep-mariadb-dump", self.dockerfile)
        self.assertIn("Source: mariadb (1:11.8.6-5ubuntu0.1)", self.dockerfile)
        self.assertIn("Built-Using: mariadb (= 1:11.8.6-5ubuntu0.1)", self.dockerfile)
        self.assertIn("source_archive_sha256", self.dockerfile)
        self.assertIn('"source_binary_package":"mariadb-client"', self.dockerfile)
        self.assertIn('"source_package":"mariadb"', self.dockerfile)
        self.assertIn("binary_sha256", self.dockerfile)
        self.assertIn("sha256sum -c -", self.dockerfile)
        self.assertIn("gpg --batch --verify", self.dockerfile)
        self.assertIn('mysql_version="8.4.11"', self.dockerfile)
        self.assertIn("--proto '=https' --tlsv1.2", self.dockerfile)
        self.assertIn("Package: backupsheep-oracle-mysql-client", self.dockerfile)
        self.assertIn("Source: mysql-community (8.4.11)", self.dockerfile)
        self.assertIn("Built-Using: mysql-community (= 8.4.11)", self.dockerfile)
        for major, version in (
            ("14", "14.24-1.pgdg13+2"),
            ("15", "15.19-1.pgdg13+2"),
            ("16", "16.15-1.pgdg13+2"),
            ("17", "17.11-1.pgdg13+2"),
            ("18", "18.6-1.pgdg13+2"),
        ):
            with self.subTest(postgresql_major=major):
                self.assertIn(
                    '"Package: backupsheep-postgresql-client-${pg_major}"',
                    self.dockerfile,
                )
                self.assertIn(
                    '"Source: postgresql-${pg_major} (${pg_version})"',
                    self.dockerfile,
                )
                self.assertIn(f'"{major} {version} ', self.dockerfile)

    def test_final_stage_has_no_build_or_download_tooling(self):
        offline_install = self.runtime.split(
            "# Install the authenticated Ubuntu closure", 1
        )[1].split("\n\n# pip is a build/install tool", 1)[0]
        forbidden = (
            "autoconf",
            "automake",
            "build-essential",
            "curl ",
            "g++",
            "gcc",
            "gnupg",
            "libtool",
            "pkg-config",
            "-dev",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, self.runtime.lower())

        self.assertIn(
            "--mount=from=ubuntu-runtime-packages,source=/runtime-debs",
            self.runtime,
        )
        self.assertNotIn("COPY --from=ubuntu-runtime-packages", self.runtime)
        self.assertIn("RUN --network=none", offline_install)
        self.assertIn("dpkg --unpack", offline_install)
        self.assertIn("/runtime-debs/*.deb", offline_install)
        self.assertIn("/postgres-client-debs/*.deb", offline_install)
        self.assertIn("/mysql-client-debs/*.deb", offline_install)
        self.assertIn(
            "DEBIAN_FRONTEND=noninteractive dpkg --configure --pending",
            offline_install,
        )
        self.assertIn(
            "dpkg --purge --force-remove-essential perl-base", offline_install
        )
        self.assertIn("sha256sum -c /runtime-debs/SHA256SUMS", offline_install)
        self.assertNotIn("apt-get update", offline_install)
        self.assertNotIn("http://", offline_install)
        self.assertNotIn("https://", offline_install)

    def test_ubuntu_runtime_removes_pebble_and_preserves_component_provenance(self):
        ubuntu_base = self.dockerfile.split(" AS ubuntu-runtime-base\n", 1)[1].split(
            "\n\n# Resolve and download", 1
        )[0]
        self.assertIn("RUN --network=none", ubuntu_base)
        self.assertIn("rm -f /usr/bin/pebble", ubuntu_base)
        self.assertIn("test ! -e /usr/bin/pebble", ubuntu_base)
        self.assertIn("test ! -e /usr/bin/pebble", self.runtime)
        self.assertIn("test ! -e /usr/bin/perl", self.runtime)
        self.assertIn("dpkg-query -W perl-base", self.runtime)
        self.assertIn("dpkg --audit", self.runtime)
        self.assertIn(
            "assert_package backupsheep-mariadb-dump "
            "11.8.6-5ubuntu0.1+backupsheep1",
            self.runtime,
        )
        self.assertIn(
            "/usr/share/backupsheep/provenance/mariadb-dump.json",
            self.runtime,
        )
        self.assertIn(
            "assert_package backupsheep-oracle-mysql-client "
            "8.4.11+backupsheep1",
            self.runtime,
        )
        self.assertIn(
            "assert_source backupsheep-oracle-mysql-client "
            "mysql-community 8.4.11",
            self.runtime,
        )
        self.assertIn(
            'package="backupsheep-postgresql-client-${pg_major}"', self.runtime
        )
        self.assertIn(
            'assert_package "$package" "${pg_version}+backupsheep1"',
            self.runtime,
        )
        self.assertIn(
            'assert_source "$package" "postgresql-${pg_major}" "$pg_version"',
            self.runtime,
        )
        self.assertIn("source_archive_sha256", self.runtime)
        self.assertIn("source_signature_sha256", self.runtime)
        self.assertIn("payload_sha256", self.runtime)
        self.assertIn(
            'assert_owner "$package" '
            '"/usr/lib/postgresql/${pg_major}/bin/${executable}"',
            self.runtime,
        )
        self.assertIn(
            'assert_owner backupsheep-oracle-mysql-client '
            '"/opt/mysql/bin/${executable}"',
            self.runtime,
        )
        self.assertNotIn("COPY --from=mysql-client /mysql /opt/mysql", self.runtime)
        self.assertNotIn("cp -a /postgresql", self.runtime)
        for digest in (
            # PGDG 14 amd64/arm64 source archives and payload trees.
            "2a17bc01dd3c4345d4ac85b084a11d7fb74265aead805e75cf0a296552f0f42e",
            "4ac24008059ecc1993d9a944648ed36d0730b95d01f6a3522407795b2d00a47f",
            "61983f6ae42ee31c3e3477cfed77d7a42c58956e7abbfeed06e4c6e176042454",
            "65a052e5e9563563d2a502f58066c9bb074e4ef63ef2c321bcfba97ab4a15c0b",
            # Oracle MySQL amd64/arm64 source archives and payload trees.
            "94e204cc94dede3746d2773fa5818f28f555cd8368c75ca0612eac124e6f3e58",
            "04b2f9791d314167a9eb83abcb476f45a7cd9e4aa88fa7a638cba40d1bc2a109",
            "91f3d13d4d651794a4f746d9503605641d129cf700a7abaa6793768851383346",
            "b019990ef3b06aff37c9e7e6c7739cc73fed13de591cacc22f40b010be075a09",
        ):
            with self.subTest(pinned_digest=digest):
                self.assertGreaterEqual(self.dockerfile.count(digest), 2)
        self.assertNotIn('"perl=', self.dockerfile)
        ubuntu_install = self.dockerfile.split("--download-only install", 1)[1].split(
            "; \\\n", 1
        )[0]
        self.assertNotIn('"mariadb-client=', ubuntu_install)

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

        for uid, role in (
            (10001, "backupsheep"),
            (10002, "backupsheep-database"),
            (10003, "backupsheep-files"),
            (10004, "backupsheep-storage"),
            (10005, "backupsheep-logs"),
            (10006, "backupsheep-beat"),
            (10007, "backupsheep-migration"),
            (10008, "backupsheep-cloud"),
        ):
            with self.subTest(role=role):
                self.assertIn(f"useradd --uid {uid} --gid {uid}", self.runtime)
        self.assertIn("--home-dir /run/backupsheep --no-create-home", self.runtime)
        for gid, group in (
            (10989, "backupsheep-db-xfer-w"),
            (10990, "backupsheep-db-xfer-r"),
            (10991, "backupsheep-file-xfer-w"),
            (10992, "backupsheep-file-xfer-r"),
            (10993, "backupsheep-rst-files"),
            (10994, "backupsheep-rst-database"),
            (10995, "backupsheep-rst-writer"),
        ):
            with self.subTest(group=group):
                self.assertIn(f"groupadd --gid {gid} {group}", self.runtime)
        self.assertIn(
            "COPY --link --chown=0:0 --chmod=0555 "
            "deploy/staging/provision-volumes.sh ",
            self.runtime,
        )
        self.assertIn("USER 10001:10001", self.runtime)
        self.assertIn("STOPSIGNAL SIGTERM", self.runtime)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/init.sh"]', self.runtime)

    def test_managed_ssh_lane_keys_are_validated_and_staged_privately(self):
        self.assertIn(
            "managed_key_source='/run/secrets/ssh_managed_database_private_key'",
            self.entrypoint,
        )
        self.assertIn(
            "managed_key_source='/run/secrets/ssh_managed_files_private_key'",
            self.entrypoint,
        )
        self.assertNotIn(
            "managed_key_source='/run/secrets/ssh_managed_private_key'",
            self.entrypoint,
        )
        self.assertIn(
            "managed_key_target='/run/backupsheep/ssh/managed_private_key'",
            self.entrypoint,
        )
        self.assertIn("SSH_MANAGED_DATABASE_PUBLIC_KEY", self.entrypoint)
        self.assertIn("SSH_MANAGED_FILES_PUBLIC_KEY", self.entrypoint)
        self.assertIn(
            "database and files managed SSH identities must be different",
            self.entrypoint,
        )
        self.assertIn('chmod 0600 "$managed_key_target"', self.entrypoint)
        self.assertIn(
            "ssh-keygen -y -P '' -f \"$managed_key_target\"",
            self.entrypoint,
        )

    def test_worker_readiness_cannot_survive_a_container_restart(self):
        stale_removal = self.entrypoint.index(
            "rm -f -- \"$worker_ready_file\""
        )
        preflight = self.entrypoint.index("python /code/manage.py docker_preflight")
        worker_exec = self.entrypoint.index('exec "$@"')
        self.assertLess(stale_removal, preflight)
        self.assertLess(stale_removal, worker_exec)
        self.assertIn(
            "authenticated worker_ready signal recreates this file atomically",
            self.entrypoint,
        )
        self.assertIn(
            "for worker_ready_temporary in /run/backupsheep/.celery-ready.*",
            self.entrypoint,
        )
        self.assertIn(
            'rm -f -- "$worker_ready_temporary"',
            self.entrypoint,
        )

    def test_runtime_copy_is_explicit_and_excludes_operator_tooling(self):
        self.assertNotIn("COPY . /code", self.runtime)
        self.assertNotIn("COPY --link . /code", self.runtime)
        for instruction in (
            "COPY --link --chown=0:0 --chmod=0444 .env_sample manage.py /code/",
            "COPY --link --chown=0:0 apps /code/apps",
            "COPY --link --chown=0:0 backupsheep /code/backupsheep",
            "COPY --link --chown=0:0 utils /code/utils",
        ):
            with self.subTest(instruction=instruction):
                self.assertIn(instruction, self.runtime)
        for excluded in ("install.sh", "docs", "scripts", ".git", "apps/tests"):
            with self.subTest(excluded=excluded):
                self.assertNotIn(f"COPY {excluded}", self.runtime)

    def test_static_assets_are_built_offline_as_non_root(self):
        collect = "python manage.py collectstatic --noinput --clear"
        input_normalization = (
            "\\( -path /code/_storage -o -path /code/static \\) -prune -o"
        )
        self.assertIn("RUN --network=none", self.runtime)
        self.assertIn(
            "--mount=type=tmpfs,target=/code/_storage",
            self.runtime,
        )
        self.assertIn("DJANGO_SERVER=test", self.runtime)
        self.assertIn(collect, self.runtime)
        self.assertIn(input_normalization, self.runtime)
        self.assertIn(
            "install -d -o backupsheep -g backupsheep -m 0700 /code/static",
            self.runtime,
        )
        self.assertLess(
            self.runtime.index(input_normalization),
            self.runtime.index("USER 10001:10001\nRUN --network=none"),
        )
        self.assertLess(
            self.runtime.index("USER 10001:10001\nRUN --network=none"),
            self.runtime.index(collect),
        )
        self.assertNotIn("collectstatic", self.entrypoint)

    def test_application_tree_is_immutable_and_privilege_files_are_cleared(self):
        immutable_file_command = (
            "find /code -xdev -path /code/_storage -prune -o "
            "-type f -exec chmod 0444 {} +"
        )
        self.assertIn(
            "find /code -xdev -path /code/_storage -prune -o "
            "-type d -exec chmod 0555 {} +",
            self.runtime,
        )
        self.assertIn("chown -R 0:0 /code/static", self.runtime)
        self.assertIn(immutable_file_command, self.runtime)
        self.assertIn("find /code -xdev -type l -print -quit", self.runtime)
        self.assertIn("find /code -xdev -type f -links +1", self.runtime)
        self.assertIn("find / -xdev -type f -perm /6000 -exec chmod a-s", self.runtime)
        self.assertLess(
            self.runtime.index(immutable_file_command),
            self.runtime.rindex("USER 10001:10001"),
        )

    def test_runtime_environment_uses_only_volatile_private_state(self):
        for setting in (
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONNOUSERSITE=1",
            "HOME=/run/backupsheep",
            "XDG_CACHE_HOME=/run/backupsheep/cache",
            "XDG_CONFIG_HOME=/run/backupsheep/config",
            "TMPDIR=/tmp",
            "PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
        ):
            with self.subTest(setting=setting):
                self.assertIn(setting, self.runtime)

    def test_entrypoint_fails_closed_and_preserves_argv_and_signals(self):
        self.assertTrue(self.entrypoint.startswith("#!/bin/sh\n"))
        self.assertIn("set -eu", self.entrypoint)
        self.assertIn("umask 077", self.entrypoint)
        self.assertIn("ulimit -c 0", self.entrypoint)
        self.assertIn("expected_uid='10001'", self.entrypoint)
        self.assertIn("expected_gid='10001'", self.entrypoint)
        for role, uid in (
            ("database", 10002),
            ("files", 10003),
            ("storage", 10004),
            ("logs", 10005),
            ("beat", 10006),
            ("migration", 10007),
            ("cloud", 10008),
        ):
            with self.subTest(role=role):
                self.assertRegex(
                    self.entrypoint,
                    rf"{role}\)?(?:\n|.){{0,120}}expected_uid='{uid}'",
                )
        self.assertIn("database_transfer_writer_gid='10989'", self.entrypoint)
        self.assertIn("database_transfer_reader_gid='10990'", self.entrypoint)
        self.assertIn("files_transfer_writer_gid='10991'", self.entrypoint)
        self.assertIn("files_transfer_reader_gid='10992'", self.entrypoint)
        self.assertIn("restore_writer_gid='10995'", self.entrypoint)
        self.assertIn("restore_database_reader_gid='10994'", self.entrypoint)
        self.assertIn("restore_files_reader_gid='10993'", self.entrypoint)
        self.assertNotIn("ssh_trust_gid='10997'", self.entrypoint)
        self.assertNotIn("backupsheep-ssh-trust", self.runtime)
        self.assertIn(
            'verify_owned_directory /var/lib/backupsheep/transfer/database 0 '
            '"$database_transfer_writer_gid" 3771',
            self.entrypoint,
        )
        self.assertIn(
            'verify_owned_directory /var/lib/backupsheep/transfer/files 0 '
            '"$files_transfer_writer_gid" 3771',
            self.entrypoint,
        )
        self.assertIn("reject_dedicated_mount /code/_storage", self.entrypoint)
        self.assertIn(
            "reject_dedicated_mount /var/lib/backupsheep/restore-transfer",
            self.entrypoint,
        )
        self.assertIn("reject_dedicated_mount /backups", self.entrypoint)
        self.assertIn(
            "reject_dedicated_mount /var/lib/backupsheep/ssh-trust",
            self.entrypoint,
        )
        self.assertIn(
            "database_artifact_keyring='/run/secrets/artifact_local_file_database_keyring'",
            self.entrypoint,
        )
        self.assertIn(
            "files_artifact_keyring='/run/secrets/artifact_local_file_files_keyring'",
            self.entrypoint,
        )
        self.assertIn("artifact_keyring_is_read_only_mount()", self.entrypoint)
        self.assertIn('matches == 1 && protected == 1', self.entrypoint)
        self.assertIn("artifact_keyring_metadata_is_safe", self.entrypoint)
        self.assertIn("stat -c '%a:%h'", self.entrypoint)
        self.assertNotIn("stat -c '%u:%g:%a:%h' \"$artifact_keyring\"", self.entrypoint)
        self.assertIn(
            "AWS instance-metadata credentials must be disabled",
            self.entrypoint,
        )
        self.assertIn(
            "AWS SDK endpoint environment overrides must be disabled",
            self.entrypoint,
        )
        self.assertIn(
            "$runtime_role must not mount an artifact keyring",
            self.entrypoint,
        )
        self.assertIn("prepare_private_dir /run/backupsheep", self.entrypoint)
        self.assertIn(
            "for capability_set in CapInh CapPrm CapEff CapBnd CapAmb",
            self.entrypoint,
        )
        self.assertIn("no-new-privileges must be enabled", self.entrypoint)
        self.assertIn("require_mount / any ro", self.entrypoint)
        self.assertIn("require_mount /tmp tmpfs rw noexec nosuid nodev", self.entrypoint)
        self.assertIn("Docker init and a private PID namespace", self.entrypoint)
        self.assertIn("the Docker control socket must not be mounted", self.entrypoint)
        self.assertIn("python /code/manage.py docker_preflight", self.entrypoint)
        self.assertIn(
            "migrate|migrate_and_verify_artifact_provider|docker_preflight",
            self.entrypoint,
        )
        self.assertIn(
            "[ \"$3\" = 'backupsheep.database_identity' ]",
            self.entrypoint,
        )
        self.assertIn('case "$4" in', self.entrypoint)
        self.assertIn("provision|seal", self.entrypoint)
        for variable in (
            "LD_AUDIT",
            "LD_LIBRARY_PATH",
            "LD_PRELOAD",
            "SSLKEYLOGFILE",
        ):
            self.assertIn(variable, self.entrypoint)
        self.assertIn('exec "$@"', self.entrypoint)
        self.assertNotIn('eval "$@"', self.entrypoint)
        self.assertNotIn('exec sh -c "$@"', self.entrypoint)
        self.assertIn("--worker-tmp-dir /run/backupsheep/gunicorn", self.entrypoint)
        self.assertIn("--max-requests 1000", self.entrypoint)
        self.assertIn("--limit-request-fields 100", self.entrypoint)
