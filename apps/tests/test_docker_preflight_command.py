import os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.core.management.base import CommandError
from django.test import SimpleTestCase

from apps.management.commands.docker_preflight import (
    EXPECTED_UID,
    _assert_no_pending_migrations,
    _assert_process_boundary,
    _assert_secure_tmpfs,
    _assert_stock_configuration_sources,
    _proc_status_values,
)


class DockerPreflightCommandTests(SimpleTestCase):
    SAFE_STATUS = """Name:\tpython
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
CapAmb:\t0000000000000000
NoNewPrivs:\t1
Seccomp:\t2
Seccomp_filters:\t1
"""

    def test_proc_status_parser_ignores_unstructured_lines(self):
        self.assertEqual(
            _proc_status_values("Name:\tpython\nmalformed\nNoNewPrivs:\t1\n"),
            {"Name": "python", "NoNewPrivs": "1"},
        )

    def test_expected_boundary_passes(self):
        _assert_process_boundary(
            uid=EXPECTED_UID,
            proc_status=self.SAFE_STATUS,
            root_flags=getattr(os, "ST_RDONLY", 1),
            core_limit=(0, 0),
        )

    def test_root_writable_or_privileged_runtime_fails_closed(self):
        cases = (
            {"uid": 0},
            *(
                {
                    "proc_status": self.SAFE_STATUS.replace(
                        f"{capability_set}:\t0000000000000000",
                        f"{capability_set}:\t1",
                    )
                }
                for capability_set in (
                    "CapInh",
                    "CapPrm",
                    "CapEff",
                    "CapBnd",
                    "CapAmb",
                )
            ),
            {"proc_status": self.SAFE_STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")},
            {"proc_status": self.SAFE_STATUS.replace("Seccomp:\t2", "Seccomp:\t0")},
            {"proc_status": self.SAFE_STATUS.replace("Seccomp_filters:\t1", "Seccomp_filters:\t0")},
            {"root_flags": 0},
            {"core_limit": (0, 1024)},
        )
        defaults = {
            "uid": EXPECTED_UID,
            "proc_status": self.SAFE_STATUS,
            "root_flags": getattr(os, "ST_RDONLY", 1),
            "core_limit": (0, 0),
        }
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(CommandError):
                _assert_process_boundary(**{**defaults, **overrides})

    def test_direct_secret_environment_values_are_not_needed_by_parser(self):
        with mock.patch.dict(os.environ, {"DJANGO_SECRET_KEY": "sensitive"}):
            values = _proc_status_values(self.SAFE_STATUS)
        self.assertNotIn("sensitive", values.values())

    def test_stock_configuration_must_use_fixed_module_and_file_values(self):
        secrets = {
            "DJANGO_SECRET_KEY": "django-file-value",
            "DB_PASSWORD": "database-file-value",
            "RABBITMQ_PASSWORD": "rabbit-file-value",
        }
        runtime_settings = SimpleNamespace(
            SECRET_KEY="django-file-value",
            DATABASES={"default": {"PASSWORD": "database-file-value"}},
            CELERY_BROKER_URL="amqp://user:rabbit-file-value@rabbitmq/backupsheep",
        )
        safe_environment = {
            "DJANGO_SETTINGS_MODULE": "backupsheep.settings",
            "BACKUPSHEEP_SECRETS": "",
        }
        _assert_stock_configuration_sources(
            environment=safe_environment,
            runtime_settings=runtime_settings,
            secret_values=secrets,
        )

        unsafe_cases = (
            ({**safe_environment, "DJANGO_SETTINGS_MODULE": "attacker.settings"}, runtime_settings),
            ({**safe_environment, "BACKUPSHEEP_SECRETS": "{}"}, runtime_settings),
            (
                safe_environment,
                SimpleNamespace(
                    SECRET_KEY="json-secret",
                    DATABASES=runtime_settings.DATABASES,
                    CELERY_BROKER_URL=runtime_settings.CELERY_BROKER_URL,
                ),
            ),
        )
        for environment, candidate_settings in unsafe_cases:
            with self.subTest(environment=environment), self.assertRaises(CommandError):
                _assert_stock_configuration_sources(
                    environment=environment,
                    runtime_settings=candidate_settings,
                    secret_values=secrets,
                )

    def test_tmpfs_mount_requires_noexec_nosuid_and_nodev(self):
        secure = (
            "31 24 0:27 / /tmp rw,nosuid,nodev,noexec,relatime - "
            "tmpfs tmpfs rw,size=262144k,mode=1777\n"
        )
        _assert_secure_tmpfs(Path("/tmp"), secure)

        for unsafe in (
            secure.replace("tmpfs tmpfs", "ext4 /dev/vda1"),
            secure.replace(",noexec", ""),
            secure.replace(" /tmp ", " /different "),
        ):
            with self.subTest(mountinfo=unsafe), self.assertRaises(CommandError):
                _assert_secure_tmpfs(Path("/tmp"), unsafe)

    def test_pending_migrations_fail_closed(self):
        graph = SimpleNamespace(leaf_nodes=lambda: [("apps", "0002")])
        pending = SimpleNamespace(app_label="apps", name="0002_pending")
        executor = SimpleNamespace(
            loader=SimpleNamespace(graph=graph),
            migration_plan=lambda _leaf_nodes: [(pending, False)],
        )
        with self.assertRaisesMessage(CommandError, "apps.0002_pending"):
            _assert_no_pending_migrations(executor)

        executor.migration_plan = lambda _leaf_nodes: []
        _assert_no_pending_migrations(executor)
