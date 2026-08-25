"""Static supply-chain and least-privilege contracts for the application image."""

from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
SLIM_IMAGE = (
    "python:3.14.7-slim-trixie@sha256:"
    "ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4"
)


class RuntimeImageHardeningTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        cls.runtime = cls.dockerfile.split(" AS runtime\n", 1)[1]
        cls.entrypoint = (ROOT / "init.sh").read_text(encoding="utf-8")

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

    def test_database_clients_are_version_pinned_and_authenticated(self):
        expected_packages = (
            '"mariadb-client-core=1:11.8.6-0+deb13u1"',
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
            '"bsdutils=1:2.41.5-0+deb13u1"',
            '"libblkid1=2.41.5-0+deb13u1"',
            '"liblastlog2-2=2.41.5-0+deb13u1"',
            '"libmount1=2.41.5-0+deb13u1"',
            '"libsmartcols1=2.41.5-0+deb13u1"',
            '"libuuid1=2.41.5-0+deb13u1"',
            '"login=1:4.16.0-2+really2.41.5-0+deb13u1"',
            '"mount=2.41.5-0+deb13u1"',
            '"util-linux=2.41.5-0+deb13u1"',
        )
        for package in security_updates:
            with self.subTest(security_update=package):
                self.assertIn(package, self.dockerfile)

        self.assertIn("signed-by=/usr/share/keyrings/pgdg.gpg", self.dockerfile)
        self.assertIn(
            'apt-get download "mariadb-client=1:11.8.6-0+deb13u1"',
            self.dockerfile,
        )
        self.assertIn("/runtime-extras/bin/mariadb-dump", self.dockerfile)
        self.assertIn("/runtime-extras/postgresql/usr/lib/postgresql", self.runtime)
        self.assertIn('amd64) lftp_version="4.9.2-3+b1"', self.dockerfile)
        self.assertIn('arm64) lftp_version="4.9.2-3"', self.dockerfile)
        self.assertIn("sha256sum -c -", self.dockerfile)
        self.assertIn("gpg --batch --verify", self.dockerfile)
        self.assertIn('mysql_version="8.4.11"', self.dockerfile)
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
            "gnupg",
            "libtool",
            "pkg-config",
            "-dev",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, self.runtime.lower())

        self.assertIn("--mount=from=runtime-packages,source=/runtime-debs", self.runtime)
        self.assertNotIn("COPY --from=runtime-packages", self.runtime)
        self.assertIn("/runtime-debs/libblkid1_*.deb", self.runtime)
        self.assertIn(
            "libblkid1 liblastlog2-2 libsmartcols1 libuuid1 libmount1",
            self.runtime,
        )
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
            (10997, "backupsheep-ssh-trust"),
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

    def test_managed_ssh_key_is_validated_and_staged_privately(self):
        self.assertIn(
            "managed_key_source='/run/secrets/ssh_managed_private_key'",
            self.entrypoint,
        )
        self.assertIn(
            "managed_key_target='/run/backupsheep/ssh/managed_private_key'",
            self.entrypoint,
        )
        self.assertIn('chmod 0600 "$managed_key_target"', self.entrypoint)
        self.assertIn(
            "ssh-keygen -y -P '' -f \"$managed_key_target\"",
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
        self.assertIn("ssh_trust_gid='10997'", self.entrypoint)
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
            "database_kms_credentials='/run/secrets/artifact_kms_database_aws_credentials'",
            self.entrypoint,
        )
        self.assertIn(
            "files_kms_credentials='/run/secrets/artifact_kms_files_aws_credentials'",
            self.entrypoint,
        )
        self.assertIn(
            "AWS instance-metadata credentials must be disabled",
            self.entrypoint,
        )
        self.assertIn(
            "AWS SDK endpoint environment overrides must be disabled",
            self.entrypoint,
        )
        self.assertIn(
            "$runtime_role must not mount an artifact-KMS credential secret",
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
            "[ \"$3\" = 'backupsheep.database_identity' ]",
            self.entrypoint,
        )
        self.assertIn("[ \"$4\" = 'provision' ]", self.entrypoint)
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
