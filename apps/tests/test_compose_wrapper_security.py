import json
import hashlib
import os
import signal
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "backupsheep-compose"
INSTALLER = ROOT / "install.sh"
COMPOSE_JSON_PARSER = ROOT / "deploy" / "runtime" / "compose-json.awk"
INSTALLATION_ID = "0123456789abcdef" * 4
OTHER_INSTALLATION_ID = "fedcba9876543210" * 4
SOURCE_COMMIT = "a" * 40
PINNED_RABBIT_IMAGE = f"backupsheep-rabbitmq:{SOURCE_COMMIT}"
PINNED_RABBIT_IMAGE_ID = "sha256:" + ("b" * 64)
PINNED_RABBIT_42_IMAGE = f"backupsheep-rabbitmq-upgrade:{SOURCE_COMMIT}"
PINNED_RABBIT_42_IMAGE_ID = "sha256:" + ("d" * 64)
PINNED_RABBIT_313_IMAGE = f"backupsheep-rabbitmq-legacy-source:{SOURCE_COMMIT}"
PINNED_RABBIT_313_IMAGE_ID = "sha256:" + ("6" * 64)
RABBITMQ_43_FEATURE_FLAGS = (
    "name stability state\n"
    "khepri_db required enabled\n"
    "required_flag required enabled"
)
EGRESS_IMAGE = f"backupsheep-egress:{SOURCE_COMMIT}"
EGRESS_IMAGE_ID = "sha256:" + ("e" * 64)
APP_IMAGE = f"backupsheep:{SOURCE_COMMIT}"
APP_IMAGE_ID = "sha256:" + ("1" * 64)
POSTGRES_IMAGE = f"backupsheep-postgres:{SOURCE_COMMIT}"
POSTGRES_IMAGE_ID = "sha256:" + ("2" * 64)
CONFIG_HASH = "f" * 64
RABBITMQ_42_CONFIG_HASH = "4" * 64
RABBITMQ_43_TRANSITION_CONFIG_HASH = "3" * 64
RABBITMQ_313_CONFIG_HASH = "5" * 64
RABBITMQ_313_RECOVERY_CONFIG_HASH = "7" * 64
RABBITMQ_42_RECOVERY_CONFIG_HASH = "8" * 64
RABBITMQ_43_RECOVERY_CONFIG_HASH = "9" * 64
APP_PAIR_UP = (
    "up",
    "--detach",
    "--no-deps",
    "--force-recreate",
    "app-egress-guard",
    "app",
)

CANONICAL_NETWORKS = (
    "app-database", "app-broker", "migrate-database", "cloud-database",
    "cloud-broker", "database-database", "database-broker", "files-database",
    "files-broker", "storage-database", "storage-broker", "logs-database",
    "logs-broker", "beat-database", "beat-broker", "preflight-database",
    "preflight-broker", "provision-database", "app-egress", "cloud-egress", "database-egress",
    "files-egress", "storage-egress", "logs-egress",
)
CANONICAL_VOLUMES = (
    "postgres_data_v1", "rabbitmq_data", "backup_workdir", "database_workdir",
    "files_workdir", "storage_workdir", "database_ciphertext_transfer",
    "files_ciphertext_transfer", "restore_ciphertext_transfer",
    "staging_layout_witness",
    "backup_storage", "installation_identity", "django_secret_key",
    "db_password", "rabbitmq_password", "onboarding_token",
    "ssh_managed_private_key",
)
CANONICAL_SERVICES = (
    "db", "rabbitmq-volume-init", "rabbitmq", "rabbitmq-provision",
    "staging-provision", "db-provision", "migrate", "preflight",
    "app-egress-guard", "app", "cloud-egress-guard", "worker-cloud",
    "database-egress-guard", "worker-database", "files-egress-guard",
    "worker-files", "storage-egress-guard", "worker-storage",
    "logs-egress-guard", "worker-logs", "beat",
)


class ComposeJsonParserTests(TestCase):
    def run_parser(
        self, payload, *, mode="env", service="app", field="", path=(),
        allow_absent=False,
    ):
        if isinstance(payload, str):
            payload = payload.encode("ascii")
        command = [
            shutil.which("awk") or "/usr/bin/awk",
            "-v",
            f"mode={mode}",
            "-v",
            f"service={service}",
        ]
        if field:
            command.extend(("-v", f"field={field}"))
        if mode in {"path", "count"}:
            command.extend(("-v", f"path_count={len(path)}"))
            for index, component in enumerate(path, start=1):
                command.extend(("-v", f"path{index}={component}"))
        if allow_absent:
            command.extend(("-v", "allow_absent=1"))
        command.extend(("-f", str(COMPOSE_JSON_PARSER)))
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        return subprocess.run(
            command,
            input=payload,
            capture_output=True,
            env=environment,
            check=False,
        )

    def test_length_framed_paths_reject_structural_key_spoofing(self):
        accepted = self.run_parser(
            '{"services":{"app":{"environment":{"SAFE":"ok"},'
            '"command":["good"]}}}'
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(accepted.stdout, b'"SAFE=ok"\n')

        spoofed = (
            '{"services/app":{"environment":{"SAFE":"ok"}}}',
            '{"services/app":{"command":["evil"]}}',
            '{"services":{"app/command":["evil"]},"services/app":{}}',
        )
        for payload in spoofed:
            with self.subTest(payload=payload):
                result = self.run_parser(payload)
                self.assertNotEqual(result.returncode, 0)
                value = self.run_parser(
                    payload, mode="value", service="app", field="command"
                )
                self.assertNotEqual(value.returncode, 0)
        nested = self.run_parser(
            '{"services":{"app":{"environment/SAFE":"ok"}}}'
        )
        self.assertNotEqual(nested.returncode, 0)
        nested_value = self.run_parser(
            '{"services":{"app":{"environment/SAFE":"ok"}}}',
            mode="value",
            service="app",
            field="command",
        )
        self.assertEqual(nested_value.returncode, 0, nested_value.stderr)
        self.assertEqual(nested_value.stdout, b"__BACKUPSHEEP_ABSENT__\n")

    def test_object_keys_and_unicode_scalars_fail_closed(self):
        rejected = (
            '{"services":{"app":{},"app":{}}}',
            '{"serv\\u0069ces":{"app":{"environment":{}}}}',
            '{"services":{"app":{"environment":{"X":"\\uD800"}}}}',
            '{"services":{"app":{"environment":{"X":"\\uDC00"}}}}',
            '{"services":{"app":{"environment":{"X":"\\uD800\\u0041"}}}}',
        )
        for payload in rejected:
            with self.subTest(payload=payload):
                self.assertNotEqual(self.run_parser(payload).returncode, 0)

        valid_pair = self.run_parser(
            '{"services":{"app":{"environment":{"X":"\\uD83D\\uDE00"}}}}'
        )
        self.assertEqual(valid_pair.returncode, 0, valid_pair.stderr)
        self.assertEqual(valid_pair.stdout, b'"X=\\uD83D\\uDE00"\n')
        invalid_utf8 = self.run_parser(
            b'{"services":{"app":{"environment":{"X":"\xc0\xaf"}}}}'
        )
        self.assertNotEqual(invalid_utf8.returncode, 0)

    def test_path_count_and_optional_absence_are_unambiguous(self):
        payload = '[{"a":{"slash/key":["x","y"]},"empty":{}}]'
        root_count = self.run_parser(payload, mode="count", path=())
        self.assertEqual(root_count.returncode, 0, root_count.stderr)
        self.assertEqual(root_count.stdout, b"array|1\n")
        nested_count = self.run_parser(
            payload, mode="count", path=("#0", "a", "slash/key")
        )
        self.assertEqual(nested_count.returncode, 0, nested_count.stderr)
        self.assertEqual(nested_count.stdout, b"array|2\n")
        selected = self.run_parser(
            payload, mode="path", path=("#0", "a", "slash/key", "#1")
        )
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertEqual(selected.stdout, b'"y"\n')

        required_missing = self.run_parser(
            payload, mode="path", path=("#0", "missing")
        )
        self.assertNotEqual(required_missing.returncode, 0)
        optional_missing = self.run_parser(
            payload,
            mode="path",
            path=("#0", "missing"),
            allow_absent=True,
        )
        self.assertEqual(optional_missing.returncode, 0, optional_missing.stderr)
        self.assertEqual(optional_missing.stdout, b"__BACKUPSHEEP_ABSENT__\n")

        wrong_kind = self.run_parser(
            payload, mode="count", path=("#0", "a", "slash/key", "#0")
        )
        self.assertNotEqual(wrong_kind.returncode, 0)


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_PATH = ROOT / "docker-state.json"
EVENT_PATH = ROOT / "docker-events.jsonl"
NETWORKS = __NETWORKS__
VOLUMES = __VOLUMES__
SERVICES = __SERVICES__
INSTALLATION_ID = "0123456789abcdef" * 4
ENVIRONMENT_KEYS = (
    "BACKUPSHEEP_BIND_ADDRESS", "BACKUPSHEEP_IMAGE_MODE", "BACKUPSHEEP_IMAGE",
    "BACKUPSHEEP_POSTGRES_IMAGE", "BACKUPSHEEP_EGRESS_IMAGE",
    "BACKUPSHEEP_RABBITMQ_IMAGE", "BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE",
    "BACKUPSHEEP_RABBITMQ_LEGACY_SOURCE_IMAGE",
    "BACKUPSHEEP_COMPOSE_PROJECT_NAME", "BACKUPSHEEP_INSTALLATION_ID",
    "BACKUPSHEEP_POSTGRES_STORAGE_GENERATION",
    "BACKUPSHEEP_POSTGRES_STORAGE_INTENT", "BACKUPSHEEP_POSTGRES_STORAGE_WITNESS",
    "BACKUPSHEEP_RABBITMQ_SAME_VERSION_RECOVERY",
    "BACKUPSHEEP_RABBITMQ_CLEAN_INSPECT_IMAGE",
    "BACKUPSHEEP_RABBITMQ_CLEAN_INSPECT_USER",
    "BACKUPSHEEP_RABBITMQ_CLEAN_INSPECT_TARGET",
    "COMPOSE_BAKE", "COMPOSE_ENV_FILES",
    "COMPOSE_EXPERIMENTAL", "COMPOSE_FILE", "COMPOSE_MENU", "COMPOSE_PATH_SEPARATOR",
    "COMPOSE_PROFILES", "COMPOSE_PROJECT_NAME", "COMPOSE_REMOVE_ORPHANS",
    "BUILDX_BAKE_FILE", "BUILDKIT_PROGRESS", "DOCKER_BUILDKIT",
    "DOCKER_DEFAULT_PLATFORM", "DOCKER_CONTEXT", "DOCKER_HOST",
    "LC_ALL",
)
SOURCE_COMMIT = "a" * 40
PINNED_RABBIT_IMAGE = f"backupsheep-rabbitmq:{SOURCE_COMMIT}"
PINNED_RABBIT_IMAGE_ID = "sha256:" + ("b" * 64)
PINNED_RABBIT_42_IMAGE = f"backupsheep-rabbitmq-upgrade:{SOURCE_COMMIT}"
PINNED_RABBIT_42_IMAGE_ID = "sha256:" + ("d" * 64)
PINNED_RABBIT_313_IMAGE = f"backupsheep-rabbitmq-legacy-source:{SOURCE_COMMIT}"
PINNED_RABBIT_313_IMAGE_ID = "sha256:" + ("6" * 64)
EGRESS_IMAGE = f"backupsheep-egress:{SOURCE_COMMIT}"
EGRESS_IMAGE_ID = "sha256:" + ("e" * 64)
APP_IMAGE = f"backupsheep:{SOURCE_COMMIT}"
APP_IMAGE_ID = "sha256:" + ("1" * 64)
POSTGRES_IMAGE = f"backupsheep-postgres:{SOURCE_COMMIT}"
POSTGRES_IMAGE_ID = "sha256:" + ("2" * 64)
CONFIG_HASH = "f" * 64
RABBITMQ_42_CONFIG_HASH = "4" * 64
RABBITMQ_43_TRANSITION_CONFIG_HASH = "3" * 64
RABBITMQ_313_CONFIG_HASH = "5" * 64
RABBITMQ_313_RECOVERY_CONFIG_HASH = "7" * 64
RABBITMQ_42_RECOVERY_CONFIG_HASH = "8" * 64
RABBITMQ_43_RECOVERY_CONFIG_HASH = "9" * 64
RABBITMQ_43_FEATURE_FLAGS = (
    "name stability state\n"
    "khepri_db required enabled\n"
    "required_flag required enabled"
)

def load_state():
    if not STATE_PATH.exists():
        return {"containers": {}, "networks": {}, "volumes": {}}
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))

def save_state(state):
    STATE_PATH.write_text(
        json.dumps(state, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )

def emit(value=""):
    if value:
        sys.stdout.write(str(value))
        if not str(value).endswith("\n"):
            sys.stdout.write("\n")

def log_invocation(arguments):
    event = {
        "argv": arguments,
        "env": {key: os.environ.get(key, "<unset>") for key in ENVIRONMENT_KEYS},
    }
    with EVENT_PATH.open("a", encoding="utf-8") as event_file:
        event_file.write(json.dumps(event, sort_keys=True) + "\n")

def option_value(arguments, option):
    for index, argument in enumerate(arguments):
        if argument == option and index + 1 < len(arguments):
            return arguments[index + 1]
        if argument.startswith(option + "="):
            return argument.split("=", 1)[1]
    return None

def compose_subcommand(arguments):
    value_options = {
        "--ansi", "--env-file", "--parallel", "--profile", "--progress",
        "--project-directory", "--project-name", "-f",
    }
    flag_options = {"--all-resources", "--compatibility", "--dry-run"}
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        if argument in value_options:
            index += 2
            continue
        if any(argument.startswith(option + "=") for option in value_options):
            index += 1
            continue
        if argument in flag_options:
            index += 1
            continue
        if argument == "--":
            index += 1
            return arguments[index] if index < len(arguments) else ""
        return argument
    return ""

def canonical_yaml(project, arguments):
    lines = [f"name: {project}", "services:"]
    for service in SERVICES:
        pull_policy = state.get("service_pull_policies", {}).get(service, "never")
        lines.extend(
            (
                f"  {service}:",
                f"    image: {service_image(service)}",
                f"    pull_policy: {pull_policy}",
            )
        )
    lines.append("networks:")
    for network in NETWORKS:
        lines.extend((f"  {network}:", f"    name: {project}_{network}"))
    lines.append("volumes:")
    for volume in VOLUMES:
        lines.extend((f"  {volume}:", f"    name: {project}_{volume}"))
    return "\n".join(lines) + "\n"

def service_image(service):
    if service == "db":
        return POSTGRES_IMAGE
    if service in {"rabbitmq-volume-init", "rabbitmq", "rabbitmq-provision"}:
        return PINNED_RABBIT_IMAGE
    if service.endswith("-egress-guard"):
        return EGRESS_IMAGE
    return APP_IMAGE

def image_id(reference):
    return {
        APP_IMAGE: APP_IMAGE_ID,
        POSTGRES_IMAGE: POSTGRES_IMAGE_ID,
        EGRESS_IMAGE: EGRESS_IMAGE_ID,
        PINNED_RABBIT_IMAGE: PINNED_RABBIT_IMAGE_ID,
        PINNED_RABBIT_42_IMAGE: PINNED_RABBIT_42_IMAGE_ID,
        PINNED_RABBIT_313_IMAGE: PINNED_RABBIT_313_IMAGE_ID,
    }.get(reference, "")

def image_metadata(reference):
    rabbitmq_metadata = {
        PINNED_RABBIT_IMAGE: {
            "config_user": "100:101",
            "labels": {
                "com.backupsheep.rabbitmq.runtime-generation":
                    "4.3.5-alpine3.23-openssl3.5.8-v2",
                "com.backupsheep.rabbitmq.base-index-digest":
                    "sha256:290b4731353a388f75cfdd358f79a3f4925ab3c1e9d23394db635bcb112b3240",
                "com.backupsheep.rabbitmq.openssl-donor-index-digest": "",
                "com.backupsheep.rabbitmq.erlang-donor-index-digest": "",
                "com.backupsheep.rabbitmq.erlang-runtime-version": "",
                "com.backupsheep.rabbitmq.openssl-runtime-version": "3.5.8",
                "com.backupsheep.rabbitmq.openssl-package-version": "3.5.8-r0",
                "com.backupsheep.rabbitmq.gpgv-package-version": "",
                "com.backupsheep.rabbitmq.enabled-plugins": "none",
            },
        },
        PINNED_RABBIT_42_IMAGE: {
            "config_user": "100:101",
            "labels": {
                "com.backupsheep.rabbitmq.runtime-generation":
                    "4.2.9-alpine3.23-openssl3.5.8-v2",
                "com.backupsheep.rabbitmq.base-index-digest":
                    "sha256:b2e69a138ea46106d0336bf8741187cac59031b778517d9ed2c9740f139dfa5a",
                "com.backupsheep.rabbitmq.openssl-donor-index-digest": "",
                "com.backupsheep.rabbitmq.erlang-donor-index-digest": "",
                "com.backupsheep.rabbitmq.erlang-runtime-version": "",
                "com.backupsheep.rabbitmq.openssl-runtime-version": "3.5.8",
                "com.backupsheep.rabbitmq.openssl-package-version": "3.5.8-r0",
                "com.backupsheep.rabbitmq.gpgv-package-version": "",
                "com.backupsheep.rabbitmq.enabled-plugins": "none",
            },
        },
        PINNED_RABBIT_313_IMAGE: {
            "config_user": "999:999",
            "labels": {
                "com.backupsheep.rabbitmq.runtime-generation":
                    "3.13.7-otp26.2.5.21-openssl3.5.8-v3",
                "com.backupsheep.rabbitmq.base-index-digest":
                    "sha256:87178a0ee3e2f52980ba356d38646ed1056705ff2d5ff281f8965456eaa0c1e3",
                "com.backupsheep.rabbitmq.openssl-donor-index-digest":
                    "sha256:f3aa266b9f3ee3d06c6658804aa3b8e4474bfc18880dcc20f469995a728c298b",
                "com.backupsheep.rabbitmq.erlang-donor-index-digest":
                    "sha256:f9007e3e435761bd7f88aafa4bfab20fd4107baa88e3ff45e935ef2aa3e892d5",
                "com.backupsheep.rabbitmq.erlang-runtime-version": "26.2.5.21",
                "com.backupsheep.rabbitmq.openssl-runtime-version": "3.5.8",
                "com.backupsheep.rabbitmq.openssl-package-version":
                    "3.0.13-0ubuntu3.15",
                "com.backupsheep.rabbitmq.gpgv-package-version":
                    "2.4.4-2ubuntu17.4",
                "com.backupsheep.rabbitmq.enabled-plugins": "none",
            },
        },
    }
    return rabbitmq_metadata.get(reference, {})

def compose_healthcheck(service):
    if service == "db":
        return {
            "test": ["CMD-SHELL", "reviewed-db-healthcheck"],
            "interval": "5s", "timeout": "5s", "retries": 10,
        }
    if service == "rabbitmq":
        return {
            "test": [
                "CMD-SHELL",
                'rabbitmq-diagnostics -q -n "${RABBITMQ_NODENAME}" ping',
            ],
            "interval": "5s", "timeout": "5s", "retries": 10,
            "start_period": "30s",
        }
    if service.endswith("-egress-guard"):
        return {
            "test": ["CMD", "/usr/local/bin/backupsheep-egress-healthcheck"],
            "interval": "10s", "timeout": "3s", "retries": 5,
            "start_period": "10s",
        }
    if service in {"app", "worker-cloud", "worker-database", "worker-files", "worker-storage", "worker-logs"}:
        return {
            "test": ["CMD", "/usr/local/bin/backupsheep-egress-workload-healthcheck"],
            "interval": "10s", "timeout": "5s", "retries": 2,
            "start_period": "1m0s",
        }
    return None

APP_RUNTIME_SERVICES = {
    "staging-provision", "db-provision", "migrate", "db-seal", "preflight",
    "app", "worker-cloud", "worker-database", "worker-files", "worker-storage",
    "worker-logs", "beat",
}

def compose_env_value(arguments, key, default):
    env_path = option_value(arguments, "--env-file")
    if not env_path:
        return default
    for line in Path(env_path).read_text(encoding="utf-8").splitlines():
        if not line.startswith(key + "="):
            continue
        value = line.split("=", 1)[1]
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        return value or default
    return default

def normalized_duration(value):
    magnitude, unit = re.fullmatch(r"([1-9][0-9]{0,3})([smh])", value).groups()
    seconds = int(magnitude) * {"s": 1, "m": 60, "h": 3600}[unit]
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h0m0s", seconds
    if seconds % 60 == 0:
        return f"{seconds // 60}m0s", seconds
    return f"{seconds}s", seconds

def service_stop_grace(service, arguments):
    if service == "db":
        return normalized_duration(compose_env_value(arguments, "POSTGRES_STOP_GRACE_PERIOD", "1m"))
    if service == "rabbitmq":
        return normalized_duration(compose_env_value(arguments, "RABBITMQ_STOP_GRACE_PERIOD", "3m"))
    if service in APP_RUNTIME_SERVICES:
        return normalized_duration(compose_env_value(arguments, "BACKUPSHEEP_STOP_GRACE_PERIOD", "5m"))
    return None, None

def canonical_json(project, arguments):
    transition_313 = any(
        "source-3.13.7.compose.yml" in argument for argument in arguments
    )
    transition_42 = any(
        "upgrade-4.2.9.compose.yml" in argument for argument in arguments
    )
    transition_43 = any(
        "transition-4.3.compose.yml" in argument for argument in arguments
    )
    recovery = any(
        "recovery.compose.yml" in argument for argument in arguments
    )
    services = {}
    rabbitmq_node_host = compose_env_value(
        arguments, "BACKUPSHEEP_RABBITMQ_NODE_HOST", "rabbitmq"
    )
    for service in SERVICES:
        model = {
            "image": service_image(service),
            "pull_policy": state.get("service_pull_policies", {}).get(
                service, "never"
            ),
            "environment": {"BACKUPSHEEP_TEST_SERVICE": service},
            "logging": {
                "driver": "json-file",
                "options": {"max-file": "5", "max-size": "10m"},
            },
        }
        healthcheck = compose_healthcheck(service)
        if healthcheck is not None:
            model["healthcheck"] = healthcheck
        if service == "rabbitmq-volume-init":
            model["environment"]["BACKUPSHEEP_RABBITMQ_NODE_HOST"] = rabbitmq_node_host
        elif service == "rabbitmq":
            model["hostname"] = rabbitmq_node_host
            model["environment"].update(
                BACKUPSHEEP_RABBITMQ_NODE_HOST=rabbitmq_node_host,
                RABBITMQ_NODENAME=f"rabbit@{rabbitmq_node_host}",
            )
            if transition_313 or transition_42 or transition_43:
                target = "3.13" if transition_313 else "4.2" if transition_42 else "4.3"
                model["image"] = (
                    PINNED_RABBIT_313_IMAGE if transition_313
                    else PINNED_RABBIT_42_IMAGE if transition_42
                    else PINNED_RABBIT_IMAGE
                )
                if transition_313:
                    model["environment"]["BACKUPSHEEP_RABBITMQ_DATA_GENERATION"] = "unattested"
                model["environment"]["BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET"] = target
                model["entrypoint"] = [
                    "/bin/sh", "/usr/local/bin/backupsheep-rabbitmq-entrypoint",
                    "legacy-source" if transition_313 else "transition",
                ]
            if recovery:
                recovery_version = os.environ.get(
                    "BACKUPSHEEP_RABBITMQ_SAME_VERSION_RECOVERY", ""
                )
                if recovery_version:
                    model["environment"][
                        "BACKUPSHEEP_RABBITMQ_SAME_VERSION_RECOVERY"
                    ] = recovery_version
                model["restart"] = "no"
        elif service == "rabbitmq-provision":
            model["environment"].update(
                BACKUPSHEEP_RABBITMQ_NODE_HOST=rabbitmq_node_host,
                RABBITMQ_NODENAME=f"rabbit@{rabbitmq_node_host}",
            )
        stop_grace, _ = service_stop_grace(service, arguments)
        if stop_grace is not None:
            model["stop_grace_period"] = stop_grace
        services[service] = model
    volumes = {
        volume: {"name": f"{project}_{volume}"}
        for volume in VOLUMES
    }
    if any(
        Path(argument).name == "docker-compose.override.yml"
        for argument in arguments
    ):
        extra_service = state.get("approved_override_extra_service")
        if extra_service:
            services[extra_service] = {
                "image": "attacker/evil:latest",
                "pull_policy": "never",
                "privileged": True,
            }
        mutated_service = state.get("approved_override_mutated_service")
        if mutated_service in services:
            services[mutated_service]["command"] = ["/bin/sh", "-c", "attacker"]
        backup_device = state.get("approved_override_backup_storage_device")
        if backup_device:
            volumes["backup_storage"].update(
                driver="local",
                driver_opts={"type": "none", "o": "bind", "device": backup_device},
            )
    return json.dumps(
        {"name": project, "services": services, "volumes": volumes},
        separators=(",", ":"),
    )

def rabbitmq_config_hash(arguments):
    transition_313 = any(
        "source-3.13.7.compose.yml" in argument for argument in arguments
    )
    transition_42 = any(
        "upgrade-4.2.9.compose.yml" in argument for argument in arguments
    )
    transition_43 = any(
        "transition-4.3.compose.yml" in argument for argument in arguments
    )
    recovery = any(
        "recovery.compose.yml" in argument for argument in arguments
    )
    if recovery and transition_313:
        return RABBITMQ_313_RECOVERY_CONFIG_HASH
    if recovery and transition_42:
        return RABBITMQ_42_RECOVERY_CONFIG_HASH
    if recovery and transition_43:
        return RABBITMQ_43_RECOVERY_CONFIG_HASH
    if transition_313:
        return RABBITMQ_313_CONFIG_HASH
    if transition_42:
        return RABBITMQ_42_CONFIG_HASH
    if transition_43:
        return RABBITMQ_43_TRANSITION_CONFIG_HASH
    return CONFIG_HASH

def docker_healthcheck(service):
    healthcheck = compose_healthcheck(service)
    if healthcheck is None:
        return None
    durations = {
        "3s": 3_000_000_000,
        "5s": 5_000_000_000,
        "10s": 10_000_000_000,
        "30s": 30_000_000_000,
        "1m0s": 60_000_000_000,
    }
    return {
        "Test": healthcheck["test"],
        "Interval": durations[healthcheck["interval"]],
        "Timeout": durations[healthcheck["timeout"]],
        "Retries": healthcheck["retries"],
        "StartPeriod": durations.get(healthcheck.get("start_period", "0s"), 0),
        "StartInterval": 0,
    }

def matching_resources(resources, arguments):
    resource_filter = option_value(arguments, "--filter")
    if not resource_filter:
        return list(resources.items())
    if resource_filter.startswith("volume="):
        volume_name = resource_filter[len("volume="):]
        return [
            (resource_id, resource)
            for resource_id, resource in resources.items()
            if volume_name in resource.get("volumes", ())
        ]
    if resource_filter.startswith("name="):
        name_pattern = resource_filter[len("name="):]
        try:
            return [
                (resource_id, resource)
                for resource_id, resource in resources.items()
                if re.search(name_pattern, "/" + resource.get("name", ""))
            ]
        except re.error:
            return []
    if not resource_filter.startswith("label="):
        return []
    expression = resource_filter[len("label="):]
    if "=" not in expression:
        return []
    label, value = expression.split("=", 1)
    return [
        (resource_id, resource)
        for resource_id, resource in resources.items()
        if resource.get("labels", {}).get(label, "") == value
    ]

def find_resource(resources, identifier):
    if identifier in resources:
        return resources[identifier]
    for resource in resources.values():
        if resource.get("name") == identifier:
            return resource
    raise KeyError(identifier)

def inspect_value(resource, template):
    if template == '{{.Config.User}}|{{index .Config.Labels "com.backupsheep.rabbitmq.runtime-generation"}}|{{index .Config.Labels "com.backupsheep.rabbitmq.base-index-digest"}}|{{index .Config.Labels "com.backupsheep.rabbitmq.openssl-donor-index-digest"}}|{{index .Config.Labels "com.backupsheep.rabbitmq.erlang-donor-index-digest"}}|{{index .Config.Labels "com.backupsheep.rabbitmq.erlang-runtime-version"}}|{{index .Config.Labels "com.backupsheep.rabbitmq.openssl-runtime-version"}}|{{index .Config.Labels "com.backupsheep.rabbitmq.openssl-package-version"}}|{{index .Config.Labels "com.backupsheep.rabbitmq.gpgv-package-version"}}|{{index .Config.Labels "com.backupsheep.rabbitmq.enabled-plugins"}}':
        labels = resource.get("labels", {})
        return "|".join((
            resource.get("config_user", ""),
            labels.get("com.backupsheep.rabbitmq.runtime-generation", ""),
            labels.get("com.backupsheep.rabbitmq.base-index-digest", ""),
            labels.get("com.backupsheep.rabbitmq.openssl-donor-index-digest", ""),
            labels.get("com.backupsheep.rabbitmq.erlang-donor-index-digest", ""),
            labels.get("com.backupsheep.rabbitmq.erlang-runtime-version", ""),
            labels.get("com.backupsheep.rabbitmq.openssl-runtime-version", ""),
            labels.get("com.backupsheep.rabbitmq.openssl-package-version", ""),
            labels.get("com.backupsheep.rabbitmq.gpgv-package-version", ""),
            labels.get("com.backupsheep.rabbitmq.enabled-plugins", ""),
        ))
    label_match = re.search(r'index [^\"]*Labels[^\"]*\"([^\"]+)\"', template)
    if label_match:
        value = resource.get("labels", {}).get(label_match.group(1), "")
        marker = "__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__"
        if marker in template:
            return f"{len(value.encode('utf-8'))}:{value}{marker}"
        return value
    if template == "{{.Name}}":
        return resource.get("name", "")
    if template == "{{.Id}}":
        return resource.get("id", "a" * 64)
    if template == "{{.State.Status}}":
        return resource.get("state", "")
    if template == "{{if .State.Health}}{{.State.Health.Status}}{{end}}":
        return resource.get("health", "")
    if template == "{{.Config.Image}}":
        return resource.get("config_image", "")
    if template == "{{.Image}}":
        return resource.get("image_id", "")
    if template == "{{.Config.Hostname}}":
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        default = "rabbitmq" if service == "rabbitmq" else resource.get("id", "a" * 64)[:12]
        return resource.get("config_hostname", default)
    if template == "{{.Config.Domainname}}":
        return resource.get("config_domainname", "")
    if template == "{{.Config.WorkingDir}}":
        if resource.get("is_image"):
            default = "/code" if resource.get("id") == APP_IMAGE_ID else ""
        else:
            service = resource.get("labels", {}).get("com.docker.compose.service", "")
            default = "/code" if service in APP_RUNTIME_SERVICES else ""
        return resource.get("config_working_dir", default)
    if template == "{{.Config.StopSignal}}":
        if resource.get("is_image"):
            default = "SIGTERM" if resource.get("id") == APP_IMAGE_ID else ""
        else:
            service = resource.get("labels", {}).get("com.docker.compose.service", "")
            default = "SIGTERM" if service in APP_RUNTIME_SERVICES else ""
        return resource.get("config_stop_signal", default)
    if template == "{{json .Config.StopTimeout}}":
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        defaults = {"db": 60, "rabbitmq": 180}
        default = 300 if service in APP_RUNTIME_SERVICES else defaults.get(service)
        return json.dumps(resource.get("config_stop_timeout", default), separators=(",", ":"))
    if template == "{{.Config.Tty}}|{{.Config.OpenStdin}}|{{.Config.StdinOnce}}|{{.Config.AttachStdin}}|{{.Config.AttachStdout}}|{{.Config.AttachStderr}}":
        return resource.get("console_policy", "false|false|false|false|true|true")
    if template == "{{json .Config.Shell}}":
        return json.dumps(resource.get("config_shell"), separators=(",", ":"))
    if template == "{{json .Config.Env}}":
        if resource.get("is_image"):
            default = ["PATH=/usr/bin"]
        else:
            service = resource.get("labels", {}).get("com.docker.compose.service", "")
            default = ["PATH=/usr/bin", f"BACKUPSHEEP_TEST_SERVICE={service}"]
            if service in {"rabbitmq-volume-init", "rabbitmq", "rabbitmq-provision"}:
                default.append("BACKUPSHEEP_RABBITMQ_NODE_HOST=rabbitmq")
            if service in {"rabbitmq", "rabbitmq-provision"}:
                default.append("RABBITMQ_NODENAME=rabbit@rabbitmq")
        return json.dumps(resource.get("config_env", default), separators=(",", ":"))
    if template == "{{json .Config.Entrypoint}}":
        return json.dumps(resource.get("config_entrypoint"), separators=(",", ":"))
    if template == "{{json .Config.Cmd}}":
        return json.dumps(resource.get("config_cmd"), separators=(",", ":"))
    if template == '{{.Config.User}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.AutoRemove}}':
        return resource.get(
            "transition_helper_contract",
            '100:101|["/bin/sh"]|["-ceu","/usr/local/bin/backupsheep-rabbitmq-volume-init finalize-transition >/dev/null && /usr/local/bin/backupsheep-rabbitmq-volume-init verify >/dev/null"]|none|true|true',
        )
    if template == '{{.Config.User}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.AutoRemove}}|{{.HostConfig.RestartPolicy.Name}}|{{.HostConfig.Privileged}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}':
        return resource.get("clean_inspector_contract", "")
    if template == '{{range .Config.Env}}{{println .}}{{end}}':
        return "\n".join(resource.get("config_env", ()))
    if template == "{{.Path}}":
        configured = resource.get("config_entrypoint") or resource.get("config_cmd") or []
        return resource.get("path", configured[0] if configured else "")
    if template == "{{json .Config.Healthcheck}}":
        if resource.get("is_image"):
            default = None
        else:
            service = resource.get("labels", {}).get("com.docker.compose.service", "")
            default = docker_healthcheck(service)
        return json.dumps(resource.get("config_healthcheck", default), separators=(",", ":"))
    if template == "{{json .Config.Healthcheck.Test}}":
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        healthcheck = resource.get("config_healthcheck", docker_healthcheck(service)) or {}
        return json.dumps(healthcheck.get("Test"), separators=(",", ":"))
    if template in {
        "{{.Config.Healthcheck.Interval}}", "{{.Config.Healthcheck.Timeout}}",
        "{{.Config.Healthcheck.Retries}}", "{{.Config.Healthcheck.StartPeriod}}",
        "{{.Config.Healthcheck.StartInterval}}",
    }:
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        source = compose_healthcheck(service) or {}
        defaults = {
            "{{.Config.Healthcheck.Interval}}": source.get("interval", "0s"),
            "{{.Config.Healthcheck.Timeout}}": source.get("timeout", "0s"),
            "{{.Config.Healthcheck.Retries}}": source.get("retries", 0),
            "{{.Config.Healthcheck.StartPeriod}}": source.get("start_period", "0s"),
            "{{.Config.Healthcheck.StartInterval}}": source.get("start_interval", "0s"),
        }
        override_key = {
            "{{.Config.Healthcheck.Interval}}": "health_interval",
            "{{.Config.Healthcheck.Timeout}}": "health_timeout",
            "{{.Config.Healthcheck.Retries}}": "health_retries",
            "{{.Config.Healthcheck.StartPeriod}}": "health_start_period",
            "{{.Config.Healthcheck.StartInterval}}": "health_start_interval",
        }[template]
        return resource.get(override_key, defaults[template])
    if template == '{{.HostConfig.LogConfig.Type}}|{{len .HostConfig.LogConfig.Config}}|{{index .HostConfig.LogConfig.Config "max-size"}}|{{index .HostConfig.LogConfig.Config "max-file"}}':
        return resource.get("log_config", "json-file|2|10m|5")
    if template == "{{.HostConfig.RestartPolicy.Name}}":
        return resource.get("restart_policy", "")
    if template == '{{range .HostConfig.CapDrop}}{{println .}}{{end}}':
        return resource.get("cap_drop", "ALL")
    if template == '{{range .HostConfig.SecurityOpt}}{{println .}}{{end}}':
        return resource.get("security_opt", "no-new-privileges:true")
    if template == '{{range .HostConfig.CapAdd}}{{println .}}{{end}}':
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        if service.endswith("-egress-guard"):
            default = "CHOWN\nNET_ADMIN\nSETGID\nSETPCAP\nSETUID"
        elif service == "staging-provision":
            default = "CHOWN\nDAC_OVERRIDE\nFOWNER\nFSETID"
        else:
            default = ""
        return resource.get("cap_add", default)
    if template == '{{range $name, $settings := .NetworkSettings.Networks}}{{println $name}}{{end}}':
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        networks = {
            "db": ("app-database", "beat-database", "cloud-database", "database-database", "files-database", "logs-database", "migrate-database", "preflight-database", "provision-database", "storage-database"),
            "rabbitmq-volume-init": ("none",),
            "rabbitmq": ("app-broker", "beat-broker", "cloud-broker", "database-broker", "files-broker", "logs-broker", "preflight-broker", "provision-broker", "storage-broker"),
            "rabbitmq-provision": ("provision-broker",),
            "staging-provision": ("none",),
            "db-provision": ("provision-database",),
            "migrate": ("migrate-database",),
            "db-seal": ("provision-database",),
            "preflight": ("preflight-broker", "preflight-database"),
            "app-egress-guard": ("app-broker", "app-database", "app-egress"),
            "cloud-egress-guard": ("cloud-broker", "cloud-database", "cloud-egress"),
            "database-egress-guard": ("database-broker", "database-database", "database-egress"),
            "files-egress-guard": ("files-broker", "files-database", "files-egress"),
            "storage-egress-guard": ("storage-broker", "storage-database", "storage-egress"),
            "logs-egress-guard": ("logs-broker", "logs-database", "logs-egress"),
            "beat": ("beat-broker", "beat-database"),
        }
        default = "\n".join(sorted(f"backupsheep_{name}" for name in networks.get(service, ())))
        return resource.get("attached_networks", default)
    if template == '{{range $path, $options := .HostConfig.Tmpfs}}{{printf "%s|%s\\n" $path $options}}{{end}}':
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        tmpfs = {
            "db": (
                "/tmp|rw,noexec,nosuid,nodev,size=128m,mode=1777",
                "/var/run/postgresql|rw,noexec,nosuid,nodev,size=16m,mode=3775,uid=70,gid=70",
            ),
            "rabbitmq-volume-init": ("/tmp|rw,noexec,nosuid,nodev,size=8m,mode=1777",),
            "rabbitmq": (
                "/tmp|rw,noexec,nosuid,nodev,size=128m,mode=1777",
                "/var/log/rabbitmq|rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=100,gid=101",
                "/run/backupsheep-rabbitmq|rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=100,gid=101",
            ),
            "rabbitmq-provision": ("/tmp|rw,noexec,nosuid,nodev,size=32m,mode=1777",),
            "staging-provision": ("/tmp|rw,noexec,nosuid,nodev,size=16m,mode=1777",),
        }
        app_uids = {
            "app": 10001, "worker-cloud": 10008, "worker-database": 10002,
            "worker-files": 10003, "worker-storage": 10004,
            "worker-logs": 10005, "beat": 10006, "db-provision": 10007,
            "migrate": 10007, "db-seal": 10007, "preflight": 10007,
        }
        if service.endswith("-egress-guard"):
            values = ("/run/backupsheep-egress|rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=0,gid=0",)
        elif service in app_uids:
            uid = app_uids[service]
            values = (
                "/tmp|rw,noexec,nosuid,nodev,size=256m,mode=1777",
                f"/run/backupsheep|rw,noexec,nosuid,nodev,size=16m,mode=0700,uid={uid},gid={uid}",
            )
        else:
            values = tmpfs.get(service, ())
        return resource.get("tmpfs_policy", "\n".join(sorted(values)))
    if template == '{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.HostConfig.MemoryReservation}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.MemorySwappiness}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.ShmSize}}|{{json .HostConfig.Init}}|{{.HostConfig.OomKillDisable}}|{{.HostConfig.OomScoreAdj}}|{{len .HostConfig.Ulimits}}':
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        resources = {
            "db": (256, 2147483648, 2000000000, 268435456, "false", 2),
            "rabbitmq-volume-init": (32, 67108864, 250000000, 67108864, "false", 2),
            "rabbitmq": (512, 1073741824, 1000000000, 67108864, "false", 2),
            "rabbitmq-provision": (128, 268435456, 500000000, 67108864, "false", 2),
            "staging-provision": (64, 134217728, 250000000, 67108864, "true", 2),
            "db-provision": (512, 536870912, 500000000, 67108864, "true", 2),
            "migrate": (512, 2147483648, 2000000000, 67108864, "true", 2),
            "db-seal": (512, 1073741824, 1000000000, 67108864, "true", 2),
            "preflight": (512, 1073741824, 1000000000, 67108864, "true", 2),
            "app": (512, 2147483648, 2000000000, 67108864, "true", 2),
            "worker-cloud": (512, 1073741824, 2000000000, 67108864, "true", 2),
            "worker-database": (512, 2147483648, 2000000000, 67108864, "true", 2),
            "worker-files": (512, 2147483648, 2000000000, 67108864, "true", 2),
            "worker-storage": (512, 2147483648, 2000000000, 67108864, "true", 2),
            "worker-logs": (512, 536870912, 1000000000, 67108864, "true", 2),
            "beat": (512, 536870912, 500000000, 67108864, "true", 2),
        }
        if service.endswith("-egress-guard"):
            values = (32, 67108864, 250000000, 67108864, "false", 2)
        else:
            values = resources.get(service, (0, 0, 0, 0, "false", 0))
        pids, memory, cpus, shm, init, ulimit_count = values
        default = "|".join(
            str(value)
            for value in (
                pids, memory, 0, memory, 0, cpus, shm, init, "false", 0,
                ulimit_count,
            )
        )
        return resource.get("resource_policy", default)
    if template == '{{.HostConfig.CgroupParent}}|{{.HostConfig.CpuShares}}|{{.HostConfig.CpuPeriod}}|{{.HostConfig.CpuQuota}}|{{.HostConfig.CpuRealtimePeriod}}|{{.HostConfig.CpuRealtimeRuntime}}|{{.HostConfig.CpusetCpus}}|{{.HostConfig.CpusetMems}}|{{.HostConfig.BlkioWeight}}|{{len .HostConfig.BlkioWeightDevice}}|{{len .HostConfig.BlkioDeviceReadBps}}|{{len .HostConfig.BlkioDeviceWriteBps}}|{{len .HostConfig.BlkioDeviceReadIOps}}|{{len .HostConfig.BlkioDeviceWriteIOps}}|{{len .HostConfig.StorageOpt}}|{{.HostConfig.CPUCount}}|{{.HostConfig.CPUPercent}}|{{.HostConfig.IOMaximumIOps}}|{{.HostConfig.IOMaximumBandwidth}}':
        return resource.get(
            "resource_zero_policy", "|0|0|0|0|0|||0|0|0|0|0|0|0|0|0|0|0"
        )
    if template == '{{range .HostConfig.Ulimits}}{{println .Name "|" .Soft "|" .Hard}}{{end}}':
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        if service.endswith("-egress-guard"):
            nofile = 128
        elif service.startswith("rabbitmq") or service == "db":
            nofile = 65536
        else:
            nofile = 4096
        return resource.get("ulimits", f"core | 0 | 0\nnofile | {nofile} | {nofile}")
    if template == '{{len .HostConfig.DeviceRequests}}|{{len .HostConfig.DeviceCgroupRules}}|{{.HostConfig.UsernsMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.Runtime}}|{{len .HostConfig.Sysctls}}|{{len .HostConfig.DNS}}|{{len .HostConfig.DNSOptions}}|{{len .HostConfig.DNSSearch}}|{{len .HostConfig.ExtraHosts}}|{{len .HostConfig.VolumesFrom}}|{{len .HostConfig.Links}}|{{.HostConfig.PublishAllPorts}}|{{.HostConfig.AutoRemove}}|{{.HostConfig.Cgroup}}|{{.HostConfig.ContainerIDFile}}|{{.HostConfig.VolumeDriver}}|{{json .HostConfig.ConsoleSize}}|{{len .HostConfig.Annotations}}|{{.HostConfig.Isolation}}|{{.HostConfig.KernelMemory}}|{{.HostConfig.KernelMemoryTCP}}|{{.HostConfig.RestartPolicy.MaximumRetryCount}}':
        return resource.get(
            "host_boundary", "0|0|||runc|0|0|0|0|0|0|0|false|false||||[0,0]|0||0|0|0"
        )
    if template == '{{range .HostConfig.GroupAdd}}{{println .}}{{end}}':
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        groups = {
            "worker-database": "10989\n10990\n10994",
            "worker-files": "10991\n10992\n10993",
            "worker-storage": "10990\n10992\n10993\n10994\n10995",
        }
        return resource.get("group_add", groups.get(service, ""))
    if template == '{{range .HostConfig.ReadonlyPaths}}{{println .}}{{end}}':
        return resource.get(
            "readonly_paths",
            "/proc/bus\n/proc/fs\n/proc/irq\n/proc/sys\n/proc/sysrq-trigger",
        )
    if template == '{{range .HostConfig.MaskedPaths}}{{println .}}{{end}}':
        return resource.get(
            "masked_paths",
            "/proc/acpi\n/proc/asound\n/proc/interrupts\n/proc/kcore\n/proc/keys\n"
            "/proc/latency_stats\n/proc/sched_debug\n/proc/scsi\n/proc/timer_list\n"
            "/proc/timer_stats\n/sys/devices/virtual/powercap\n/sys/firmware",
        )
    if template == '{{range .Mounts}}{{printf "%s|%s|%s|%s|%t|%s|%s\\n" .Type .Name .Source .Destination .RW .Propagation .Mode}}{{end}}':
        if "mounts" in resource:
            return resource["mounts"]
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        lines = []
        def add(kind, source, target, writable):
            if kind == "bind":
                name, runtime_source = "", str(source)
                propagation, mode = "rprivate", "ro"
            elif kind == "volume":
                name = str(source)
                runtime_source = f"/var/lib/docker/volumes/{name}/_data"
                propagation, mode = "", ""
            else:
                name, runtime_source = "", ""
                propagation, mode = "", ""
            lines.append(
                f"{kind}|{name}|{runtime_source}|{target}|{'true' if writable else 'false'}|{propagation}|{mode}"
            )
        secret_sets = {
            "db": ("db_bootstrap_password",),
            "rabbitmq": ("rabbitmq_bootstrap_password",),
            "rabbitmq-provision": tuple(f"rabbitmq_{role}_password" for role in (
                "bootstrap", "app", "preflight", "beat", "cloud", "database", "files", "storage", "logs"
            )),
            "db-provision": tuple(f"db_{role}_password" for role in (
                "bootstrap", "migrator", "app", "preflight", "beat", "cloud", "database", "files", "storage", "logs"
            )),
            "migrate": ("django_secret_key", "db_migrator_password", "rabbitmq_preflight_password"),
            "db-seal": tuple(f"db_{role}_password" for role in (
                "bootstrap", "migrator", "app", "preflight", "beat", "cloud", "database", "files", "storage", "logs"
            )),
            "preflight": ("django_secret_key", "db_preflight_password", "rabbitmq_preflight_password", "celery_trusted_public_keys"),
            "app": ("django_secret_key", "db_app_password", "rabbitmq_app_password", "celery_signing_app_private_key", "celery_trusted_public_keys", "onboarding_token"),
            "worker-cloud": ("django_secret_key", "db_cloud_password", "rabbitmq_cloud_password", "celery_signing_cloud_private_key", "celery_trusted_public_keys"),
            "worker-database": ("django_secret_key", "db_database_password", "rabbitmq_database_password", "celery_signing_database_private_key", "celery_trusted_public_keys", "ssh_managed_database_private_key", "artifact_local_file_database_keyring"),
            "worker-files": ("django_secret_key", "db_files_password", "rabbitmq_files_password", "celery_signing_files_private_key", "celery_trusted_public_keys", "ssh_managed_files_private_key", "artifact_local_file_files_keyring"),
            "worker-storage": ("django_secret_key", "db_storage_password", "rabbitmq_storage_password", "celery_signing_storage_private_key", "celery_trusted_public_keys"),
            "worker-logs": ("django_secret_key", "db_logs_password", "rabbitmq_logs_password", "celery_signing_logs_private_key", "celery_trusted_public_keys"),
            "beat": ("django_secret_key", "db_beat_password", "rabbitmq_beat_password", "celery_signing_beat_private_key", "celery_trusted_public_keys"),
        }
        for secret in secret_sets.get(service, ()):
            add("bind", ROOT / ".secrets" / secret, f"/run/secrets/{secret}", False)
        tracked = {
            "rabbitmq-volume-init": (("deploy/rabbitmq/volume-init.sh", "/usr/local/bin/backupsheep-rabbitmq-volume-init"),),
            "rabbitmq": (
                ("deploy/rabbitmq/90-backupsheep.conf", "/etc/rabbitmq/conf.d/90-backupsheep.conf"),
                ("deploy/rabbitmq/entrypoint.sh", "/usr/local/bin/backupsheep-rabbitmq-entrypoint"),
                ("deploy/rabbitmq/volume-init.sh", "/usr/local/bin/backupsheep-rabbitmq-volume-init"),
            ),
            "rabbitmq-provision": (("deploy/rabbitmq/provision.sh", "/usr/local/bin/backupsheep-rabbitmq-provision"),),
        }
        for source, target in tracked.get(service, ()):
            add("bind", ROOT / source, target, False)
        volumes = {
            "db": (("postgres_data_v1", "/var/lib/postgresql", True),),
            "rabbitmq-volume-init": (("rabbitmq_data", "/var/lib/rabbitmq", True),),
            "rabbitmq": (("rabbitmq_data", "/var/lib/rabbitmq", True),),
            "rabbitmq-provision": (("rabbitmq_data", "/var/lib/rabbitmq", False),),
            "staging-provision": (
                ("database_workdir", "/volumes/database", True), ("files_workdir", "/volumes/files", True),
                ("storage_workdir", "/volumes/storage", True), ("database_ciphertext_transfer", "/volumes/database-transfer", True),
                ("files_ciphertext_transfer", "/volumes/files-transfer", True), ("restore_ciphertext_transfer", "/volumes/restore-transfer", True),
                ("backup_storage", "/volumes/backup-storage", True), ("backup_workdir", "/volumes/legacy", True),
                ("staging_layout_witness", "/volumes/witness", True),
            ),
            "app": (("installation_identity", "/run/backupsheep-installation", False),),
            "worker-database": (("database_workdir", "/code/_storage", True), ("database_ciphertext_transfer", "/var/lib/backupsheep/transfer/database", True), ("restore_ciphertext_transfer", "/var/lib/backupsheep/restore-transfer", False)),
            "worker-files": (("files_workdir", "/code/_storage", True), ("files_ciphertext_transfer", "/var/lib/backupsheep/transfer/files", True), ("restore_ciphertext_transfer", "/var/lib/backupsheep/restore-transfer", False)),
            "worker-storage": (("storage_workdir", "/code/_storage", True), ("database_ciphertext_transfer", "/var/lib/backupsheep/transfer/database", False), ("files_ciphertext_transfer", "/var/lib/backupsheep/transfer/files", False), ("restore_ciphertext_transfer", "/var/lib/backupsheep/restore-transfer", True), ("backup_storage", "/backups", True)),
        }
        for source, target, writable in volumes.get(service, ()):
            add("volume", f"backupsheep_{source}", target, writable)
        tmpfs_targets = {
            "db": ("/tmp", "/var/run/postgresql"),
            "rabbitmq-volume-init": ("/tmp",), "rabbitmq": ("/tmp", "/var/log/rabbitmq", "/run/backupsheep-rabbitmq"),
            "rabbitmq-provision": ("/tmp",), "staging-provision": ("/tmp",),
        }
        if service.endswith("-egress-guard"):
            targets = ("/run/backupsheep-egress",)
        else:
            targets = tmpfs_targets.get(service, ("/tmp", "/run/backupsheep") if service not in ("",) else ())
        for target in targets:
            add("tmpfs", "", target, True)
        return "\n".join(lines)
    if template == '{{range .Mounts}}{{printf "%s|%s|%s|%s|%t\\n" .Type .Name .Source .Destination .RW}}{{end}}':
        return resource.get("transition_helper_mounts", "")
    if template == '{{range .HostConfig.Binds}}{{println .}}{{end}}':
        runtime_mounts = inspect_value(
            resource,
            '{{range .Mounts}}{{printf "%s|%s|%s|%s|%t|%s|%s\\n" .Type .Name .Source .Destination .RW .Propagation .Mode}}{{end}}',
        )
        records = []
        for line in runtime_mounts.splitlines():
            kind, _name, source, target, writable, _propagation, _mode = line.split("|")
            if kind == "bind":
                records.append(
                    f"{source}:{target}:{'rw' if writable == 'true' else 'ro'}"
                )
        return resource.get("host_binds", "\n".join(records))
    if template == '{{range .HostConfig.Mounts}}{{printf "%s|%s|%s|%t|" .Type .Source .Target .ReadOnly}}{{if .VolumeOptions}}{{printf "true|%t|%s|%d|" .VolumeOptions.NoCopy .VolumeOptions.Subpath (len .VolumeOptions.Labels)}}{{if .VolumeOptions.DriverConfig}}true{{else}}false{{end}}{{else}}false|false||-1|false{{end}}{{printf "|"}}{{if .BindOptions}}true{{else}}false{{end}}{{printf "|"}}{{if .TmpfsOptions}}true{{else}}false{{end}}{{printf "|"}}{{if .ClusterOptions}}true{{else}}false{{end}}{{printf "|"}}{{if .ImageOptions}}true{{else}}false{{end}}{{println}}{{end}}':
        if "host_mounts" in resource:
            return resource["host_mounts"]
        runtime_mounts = inspect_value(
            resource,
            '{{range .Mounts}}{{printf "%s|%s|%s|%s|%t|%s|%s\\n" .Type .Name .Source .Destination .RW .Propagation .Mode}}{{end}}',
        )
        records = []
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        for line in runtime_mounts.splitlines():
            kind, name, _source, target, writable, _propagation, _mode = line.split("|")
            if kind == "volume":
                no_copy = not (
                    (service == "db" and target == "/var/lib/postgresql")
                    or (
                        service in {"rabbitmq-volume-init", "rabbitmq"}
                        and target == "/var/lib/rabbitmq"
                    )
                )
                records.append(
                    f"volume|{name}|{target}|{'false' if writable == 'true' else 'true'}|"
                    f"true|{str(no_copy).lower()}||0|false|false|false|false|false"
                )
        return "\n".join(records)
    if template == '{{with index .HostConfig.PortBindings "8000/tcp"}}{{len .}}|{{range .}}{{.HostIp}}|{{.HostPort}}{{end}}{{else}}0||{{end}}':
        return resource.get("port_binding", "1|127.0.0.1|8000")
    if template == '{{.Config.User}}|{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.CgroupnsMode}}|{{len .HostConfig.Devices}}|{{len .HostConfig.PortBindings}}|{{.HostConfig.RestartPolicy.Name}}|{{.HostConfig.NetworkMode}}':
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        users = {
            "db": "70:70", "rabbitmq-volume-init": "100:101",
            "rabbitmq": "100:101", "rabbitmq-provision": "100:101",
            "staging-provision": "0:0", "db-provision": "10007:10007",
            "migrate": "10007:10007", "db-seal": "10007:10007",
            "preflight": "10007:10007", "app-egress-guard": "0:0",
            "cloud-egress-guard": "0:0", "database-egress-guard": "0:0",
            "files-egress-guard": "0:0", "storage-egress-guard": "0:0",
            "logs-egress-guard": "0:0", "app": "10001:10001",
            "worker-cloud": "10008:10008", "worker-database": "10002:10002",
            "worker-files": "10003:10003", "worker-storage": "10004:10004",
            "worker-logs": "10005:10005", "beat": "10006:10006",
        }
        long_lived = {
            "db", "rabbitmq", "app", "worker-cloud", "worker-database",
            "worker-files", "worker-storage", "worker-logs", "beat",
        }
        networks = {
            "db": "backupsheep_app-database",
            "rabbitmq-volume-init": "none",
            "rabbitmq": "backupsheep_app-broker",
            "rabbitmq-provision": "backupsheep_provision-broker",
            "staging-provision": "none",
            "db-provision": "backupsheep_provision-database",
            "migrate": "backupsheep_migrate-database",
            "db-seal": "backupsheep_provision-database",
            "preflight": "backupsheep_preflight-database",
            "app-egress-guard": "backupsheep_app-database",
            "cloud-egress-guard": "backupsheep_cloud-database",
            "database-egress-guard": "backupsheep_database-database",
            "files-egress-guard": "backupsheep_files-database",
            "storage-egress-guard": "backupsheep_storage-database",
            "logs-egress-guard": "backupsheep_logs-database",
            "app": "container:backupsheep-app-egress-guard-1",
            "worker-cloud": "container:backupsheep-cloud-egress-guard-1",
            "worker-database": "container:backupsheep-database-egress-guard-1",
            "worker-files": "container:backupsheep-files-egress-guard-1",
            "worker-storage": "container:backupsheep-storage-egress-guard-1",
            "worker-logs": "container:backupsheep-logs-egress-guard-1",
            "beat": "backupsheep_beat-database",
        }
        port_count = 1 if service == "app-egress-guard" else 0
        default = (
            f"{users.get(service, '')}|false|true||private|private|0|{port_count}|"
            f"{'unless-stopped' if service in long_lived else 'no'}|{networks.get(service, '')}"
        )
        return resource.get("runtime_policy", default)
    if template == '{{.Driver}}|{{.Internal}}|{{.Attachable}}|{{.Ingress}}|{{len .Options}}|{{index .Options "com.docker.network.bridge.enable_icc"}}|{{.IPAM.Driver}}|{{len .IPAM.Options}}':
        logical = resource.get("labels", {}).get("com.docker.compose.network", "")
        is_egress = logical in {
            "app-egress", "cloud-egress", "database-egress", "files-egress",
            "storage-egress", "logs-egress",
        }
        return resource.get(
            "runtime_policy",
            f"bridge|{'false' if is_egress else 'true'}|false|false|{'1|false' if is_egress else '0|'}|default|0",
        )
    if template == '{{len .IPAM.Config}}|{{range .IPAM.Config}}{{.Subnet}}|{{.IPRange}}|{{.Gateway}}|{{len .AuxiliaryAddresses}}{{end}}':
        return resource.get("ipam_policy", "1|172.30.0.0/16||172.30.0.1|0")
    if template == '{{range $id, $endpoint := .Containers}}{{printf "%s|%s|%s|%s|%s|%s\\n" $id $endpoint.Name $endpoint.EndpointID $endpoint.MacAddress $endpoint.IPv4Address $endpoint.IPv6Address}}{{end}}':
        return resource.get("network_endpoints", "")
    if template.startswith('{{with index .NetworkSettings.Networks "') and '{{.NetworkID}}|{{.EndpointID}}|' in template:
        if '"none"' in template and '{{len .Aliases}}' in template:
            lifecycle = resource.get("state") or "created"
            if lifecycle == "running":
                return resource.get(
                    "none_network_state", f"{'9' * 64}|{'8' * 64}|||0||0|0|0"
                )
            if lifecycle == "exited":
                return resource.get(
                    "none_network_state", f"{'9' * 64}||||0||0|0|0"
                )
            return resource.get("none_network_state", "||||0||0|0|0")
        return resource.get(
            "network_endpoint_state",
            f"{'a' * 64}|{'b' * 64}|172.30.0.1|172.30.0.2|16|02:42:ac:1e:00:02|0",
        )
    if template == '{{.State.Status}}|{{.State.Running}}|{{.State.Pid}}|{{.State.ExitCode}}':
        lifecycle = resource.get("state") or "created"
        if lifecycle == "running":
            return resource.get("lifecycle_policy", "running|true|1234|0")
        if lifecycle == "exited":
            return resource.get("lifecycle_policy", "exited|false|0|0")
        return resource.get("lifecycle_policy", "created|false|0|0")
    if template.startswith('{{with index .NetworkSettings.Networks "') and '{{range .Aliases}}' in template:
        service = resource.get("labels", {}).get("com.docker.compose.service", "")
        return resource.get("network_aliases", f"{resource.get('name', '')}\n{service}")
    if template == "{{.Driver}}|{{len .Options}}|{{.Scope}}|{{.Mountpoint}}":
        name = resource.get("name", "")
        return resource.get(
            "runtime_policy", f"local|0|local|/var/lib/docker/volumes/{name}/_data"
        )
    if template == "{{json .Options}}":
        return json.dumps(resource.get("volume_options", {}), separators=(",", ":"))
    if template == "{{.Driver}}|{{.Scope}}|{{.Mountpoint}}":
        name = resource.get("name", "")
        return resource.get(
            "source_binding_policy",
            f"local|local|/var/lib/docker/volumes/{name}/_data",
        )
    return ""

def handle_compose(arguments, state):
    command = compose_subcommand(arguments)
    project = option_value(arguments, "--project-name") or "backupsheep"
    rabbitmq_node_host = compose_env_value(
        arguments, "BACKUPSHEEP_RABBITMQ_NODE_HOST", "rabbitmq"
    )
    command_index = arguments.index(command) if command in arguments else -1
    command_arguments = arguments[command_index + 1:] if command_index >= 0 else []
    if command == state.get("blocked_compose_command") and "--dry-run" not in arguments:
        wait_path = Path(state["compose_wait_path"])
        entered_path = Path(state["compose_entered_path"])
        pid_path_value = state.get("compose_pid_path")
        entered_path.write_text("entered\n", encoding="utf-8")
        if pid_path_value:
            Path(pid_path_value).write_text(f"{os.getpid()}\n", encoding="utf-8")
        while wait_path.exists():
            time.sleep(0.01)
    if command == "config":
        if "--quiet" in command_arguments:
            return
        if "--hash" in command_arguments:
            hash_index = command_arguments.index("--hash")
            requested = command_arguments[hash_index + 1]
            config_hash = (
                rabbitmq_config_hash(arguments)
                if requested == "rabbitmq"
                else CONFIG_HASH
            )
            emit(f"{requested} {config_hash}")
            return
        if "--services" in command_arguments:
            services = list(SERVICES)
            if any("upgrade-4.2.9.compose.yml" in argument for argument in arguments):
                services.append("rabbitmq-uid-transition")
            emit("\n".join(services))
            return
        if "--images" in command_arguments:
            images_index = command_arguments.index("--images")
            requested_services = command_arguments[images_index + 1:]
            if len(requested_services) == 1:
                requested = requested_services[0]
                if requested.endswith("-egress-guard"):
                    emit(state.get("egress_image", EGRESS_IMAGE))
                elif requested in {"rabbitmq-volume-init", "rabbitmq", "rabbitmq-provision"}:
                    compose_file_count = sum(
                        1 for argument in arguments if argument == "-f"
                    )
                    if any("source-3.13.7.compose.yml" in argument for argument in arguments):
                        emit(PINNED_RABBIT_313_IMAGE)
                    elif any("upgrade-4.2.9.compose.yml" in argument for argument in arguments):
                        emit(PINNED_RABBIT_42_IMAGE)
                    elif compose_file_count == 1:
                        emit(PINNED_RABBIT_IMAGE)
                    else:
                        emit(state.get("combined_rabbitmq_image", PINNED_RABBIT_IMAGE))
                else:
                    emit(service_image(requested))
                return
            emit("\n".join(sorted(set(service_image(service) for service in SERVICES))))
            return
        if option_value(command_arguments, "--format") == "json" or "--format=json" in command_arguments:
            emit(canonical_json(project, arguments))
            return
        emit(canonical_yaml(project, arguments))
        return
    if command == "run":
        if "rabbitmq-clean-inspector" in command_arguments:
            if not any(
                "clean-inspector.compose.yml" in argument
                for argument in arguments
            ):
                sys.exit(1)
            sys.exit(state.get("rabbitmq_clean_inspector_exit_code", 0))
        if "rabbitmq-volume-init" in command_arguments:
            if any("backupsheep-rabbitmq-volume-init resume" in argument for argument in command_arguments):
                sys.exit(state.get("rabbitmq_witness_resume_exit_code", 1))
            return
        if "rabbitmq-uid-transition" in command_arguments:
            sys.exit(state.get("rabbitmq_uid_transition_exit_code", 0))
    if command in {"stop", "rm"} and "rabbitmq" in command_arguments:
        for resource_id, resource in list(state["containers"].items()):
            if resource.get("labels", {}).get("com.docker.compose.service") != "rabbitmq":
                continue
            if command == "stop":
                resource["state"] = "exited"
                resource["health"] = ""
            else:
                del state["containers"][resource_id]
        save_state(state)
        return
    if command == "up":
        selected_rabbit = "rabbitmq" in command_arguments
        transition_313 = any(
            "source-3.13.7.compose.yml" in argument for argument in arguments
        )
        transition_42 = any(
            "upgrade-4.2.9.compose.yml" in argument for argument in arguments
        )
        transition_43 = any(
            "transition-4.3.compose.yml" in argument for argument in arguments
        )
        recovery = any(
            "recovery.compose.yml" in argument for argument in arguments
        )
        canonical_recreate = (
            selected_rabbit
            and "--force-recreate" in command_arguments
            and not transition_313
            and not transition_42
            and not transition_43
            and not recovery
        )
        if recovery:
            exit_code = state.get("rabbitmq_recovery_compose_up_exit_code", 0)
        elif canonical_recreate:
            exit_code = state.get("canonical_compose_up_exit_code", 0)
        else:
            exit_code = state.get("compose_up_exit_code", 0)
        if exit_code:
            sys.exit(exit_code)
        if recovery:
            transition_key = "rabbitmq_recovery_compose_up_transition_result"
        elif canonical_recreate:
            transition_key = "canonical_compose_up_transition_result"
        else:
            transition_key = "compose_up_transition_result"
        transition = state.pop(transition_key, None)
        if selected_rabbit and (transition is not None or transition_313 or transition_42 or transition_43 or canonical_recreate):
            transition = transition or {}
            rabbit = next(
                (
                    resource
                    for resource in state["containers"].values()
                    if resource.get("labels", {}).get("com.docker.compose.service") == "rabbitmq"
                ),
                None,
            )
            if rabbit is None:
                rabbit = {
                    "name": f"{project}-rabbitmq-1",
                    "labels": {
                        "com.docker.compose.project": project,
                        "com.docker.compose.project.working_dir": str(ROOT.resolve()),
                        "com.docker.compose.service": "rabbitmq",
                    },
                }
                state["containers"]["rabbit-container"] = rabbit
            compose_files = [
                arguments[index + 1]
                for index, argument in enumerate(arguments[:-1])
                if argument == "-f"
            ]
            rabbit["labels"]["com.docker.compose.project.config_files"] = ",".join(compose_files)
            rabbit["labels"]["com.docker.compose.config-hash"] = transition.get(
                "config_hash",
                rabbitmq_config_hash(arguments),
            )
            rabbit["labels"]["com.backupsheep.installation-id"] = transition.get(
                "installation_id",
                INSTALLATION_ID,
            )
            rabbit["state"] = transition.get("state", "running")
            rabbit["health"] = transition.get("health", "healthy")
            rabbit["config_image"] = transition.get(
                "config_image",
                PINNED_RABBIT_313_IMAGE if transition_313
                else PINNED_RABBIT_42_IMAGE if transition_42
                else PINNED_RABBIT_IMAGE,
            )
            rabbit["image_id"] = transition.get(
                "image_id",
                PINNED_RABBIT_313_IMAGE_ID if transition_313
                else PINNED_RABBIT_42_IMAGE_ID if transition_42
                else PINNED_RABBIT_IMAGE_ID,
            )
            rabbit["config_hostname"] = transition.get(
                "config_hostname", rabbitmq_node_host
            )
            target = "3.13" if transition_313 else "4.2" if transition_42 else "4.3" if transition_43 else ""
            recovery_version = os.environ.get(
                "BACKUPSHEEP_RABBITMQ_SAME_VERSION_RECOVERY", ""
            )
            rabbit["config_env"] = transition.get(
                "config_env",
                ["PATH=/usr/bin", "BACKUPSHEEP_TEST_SERVICE=rabbitmq"]
                + [
                    f"BACKUPSHEEP_RABBITMQ_NODE_HOST={rabbitmq_node_host}",
                    f"RABBITMQ_NODENAME=rabbit@{rabbitmq_node_host}",
                ]
                + (["BACKUPSHEEP_RABBITMQ_DATA_GENERATION=unattested"] if transition_313 else [])
                + ([f"BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET={target}"] if target else []),
            )
            if recovery and recovery_version and not any(
                record.startswith("BACKUPSHEEP_RABBITMQ_SAME_VERSION_RECOVERY=")
                for record in rabbit["config_env"]
            ):
                rabbit["config_env"].append(
                    f"BACKUPSHEEP_RABBITMQ_SAME_VERSION_RECOVERY={recovery_version}"
                )
            rabbit["config_entrypoint"] = transition.get(
                "config_entrypoint",
                (
                    [
                        "/bin/sh",
                        "/usr/local/bin/backupsheep-rabbitmq-entrypoint",
                        "legacy-source" if transition_313 else "transition",
                    ]
                    if target else None
                ),
            )
            rabbit.pop("path", None)
            rabbit["volumes"] = [f"{project}_rabbitmq_data"]
            if transition_313:
                data_mountpoint = f"/var/lib/docker/volumes/{project}_rabbitmq_data/_data"
                rabbit.update({
                    "runtime_policy": "999:999|false|true||private|private|0|0|no|none",
                    "attached_networks": "none",
                    "restart_policy": "no",
                    "tmpfs_policy": (
                        "/run/backupsheep-rabbitmq|rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=999,gid=999\n"
                        "/tmp|rw,noexec,nosuid,nodev,size=128m,mode=1777\n"
                        "/var/log/rabbitmq|rw,noexec,nosuid,nodev,size=64m,mode=0750,uid=999,gid=999"
                    ),
                    "mounts": "\n".join((
                        f"bind||{ROOT / 'deploy/rabbitmq/90-legacy-source.conf'}|/etc/rabbitmq/conf.d/90-backupsheep.conf|false|rprivate|ro",
                        f"bind||{ROOT / 'deploy/rabbitmq/entrypoint.sh'}|/usr/local/bin/backupsheep-rabbitmq-entrypoint|false|rprivate|ro",
                        f"bind||{ROOT / 'deploy/rabbitmq/volume-init.sh'}|/usr/local/bin/backupsheep-rabbitmq-volume-init|false|rprivate|ro",
                        f"volume|{project}_rabbitmq_data|{data_mountpoint}|/var/lib/rabbitmq|true||",
                        "tmpfs|||/tmp|true||",
                        "tmpfs|||/var/log/rabbitmq|true||",
                        "tmpfs|||/run/backupsheep-rabbitmq|true||",
                    )),
                    "host_mounts": (
                        f"volume|{project}_rabbitmq_data|/var/lib/rabbitmq|false|"
                        "true|true||0|false|false|false|false|false"
                    ),
                })
            elif recovery:
                for key in (
                    "attached_networks", "tmpfs_policy", "mounts",
                    "host_mounts", "host_binds",
                ):
                    rabbit.pop(key, None)
                rabbit["runtime_policy"] = (
                    "100:101|false|true||private|private|0|0|no|"
                    f"{project}_app-broker"
                )
                rabbit["restart_policy"] = "no"
            else:
                for key in (
                    "runtime_policy", "attached_networks", "restart_policy",
                    "tmpfs_policy", "mounts", "host_mounts", "host_binds",
                ):
                    rabbit.pop(key, None)
            state["rabbitmq_server_version"] = transition.get(
                "server_version",
                "3.13.7" if transition_313 else "4.2.9" if transition_42 else "4.3.5",
            )
            state["rabbitmq_node"] = transition.get(
                "rabbitmq_node", f"rabbit@{rabbitmq_node_host}"
            )
            default_feature_flags = (
                "name stability state\n"
                "khepri_db experimental disabled\n"
                "stream_queue stable enabled"
            ) if transition_313 else RABBITMQ_43_FEATURE_FLAGS
            if recovery:
                default_feature_flags = state.get(
                    "rabbitmq_feature_flags", default_feature_flags
                )
            state["rabbitmq_feature_flags"] = transition.get(
                "feature_flags", default_feature_flags
            )
            save_state(state)

def handle_collection(kind, arguments, state):
    resources = state[kind]
    operation = arguments[1] if len(arguments) > 1 else ""
    if operation == "ls":
        matches = matching_resources(resources, arguments)
        if "--quiet" in arguments:
            emit("\n".join(resource_id for resource_id, _ in matches))
        elif option_value(arguments, "--format") == "{{.Name}}":
            emit("\n".join(resource.get("name", "") for _, resource in matches))
        return
    if operation == "inspect":
        template = option_value(arguments, "--format") or ""
        identifier = arguments[-1]
        try:
            if kind == "networks" and identifier == "none":
                resource = {"name": "none", "id": "9" * 64}
            else:
                resource = find_resource(resources, identifier)
            emit(inspect_value(resource, template))
        except KeyError:
            sys.exit(1)
        return
    if kind == "volumes" and operation == "create":
        labels = {}
        name = arguments[-1]
        index = 2
        while index < len(arguments) - 1:
            if arguments[index] == "--label" and index + 1 < len(arguments):
                key, value = arguments[index + 1].split("=", 1)
                labels[key] = value
                index += 2
                continue
            index += 1
        resources[name] = {"labels": labels, "name": name}
        save_state(state)
        emit(name)

def handle_raw_docker(arguments, state):
    if not arguments:
        return
    if arguments[0] == "version":
        if option_value(arguments, "--format") != "{{.Server.Os}}|{{.Server.Arch}}":
            sys.exit(1)
        emit(state.get("docker_server_platform", "linux|amd64"))
        return
    if arguments[0:2] == ["context", "show"]:
        emit(state.get("docker_context", os.environ.get("DOCKER_CONTEXT", "default")))
        return
    if arguments[0:2] == ["context", "inspect"]:
        emit(state.get("docker_endpoint", "unix:///var/run/docker.sock"))
        return
    if arguments[0] == "ps":
        matches = matching_resources(state["containers"], arguments)
        if "--all" not in arguments and "-a" not in arguments:
            matches = [
                (resource_id, resource)
                for resource_id, resource in matches
                if resource.get("state") == "running"
            ]
        emit("\n".join(resource_id for resource_id, _ in matches))
        return
    if arguments[0] == "network":
        handle_collection("networks", arguments, state)
        return
    if arguments[0] == "volume":
        handle_collection("volumes", arguments, state)
        return
    if arguments[0:2] == ["container", "rm"]:
        identifier = arguments[-1]
        for resource_id, resource in list(state["containers"].items()):
            if resource_id == identifier or resource.get("name") == identifier:
                del state["containers"][resource_id]
                save_state(state)
                emit(resource_id)
                return
        sys.exit(1)
    if arguments[0] == "inspect":
        template = option_value(arguments, "--format") or ""
        identifier = arguments[-1]
        try:
            emit(inspect_value(find_resource(state["containers"], identifier), template))
        except KeyError:
            sys.exit(1)
        return
    if arguments[0:2] == ["image", "inspect"]:
        template = option_value(arguments, "--format") or ""
        identifier = arguments[-1]
        if identifier in state.get("missing_image_refs", []):
            sys.exit(1)
        expected_id = image_id(identifier)
        if identifier.startswith("sha256:"):
            expected_id = identifier if identifier in {
                APP_IMAGE_ID, POSTGRES_IMAGE_ID, EGRESS_IMAGE_ID,
                PINNED_RABBIT_IMAGE_ID, PINNED_RABBIT_42_IMAGE_ID,
                PINNED_RABBIT_313_IMAGE_ID,
            } else ""
        if not expected_id:
            sys.exit(1)
        overrides = {
            PINNED_RABBIT_42_IMAGE_ID: state.get("pinned_rabbitmq_42_image_id", PINNED_RABBIT_42_IMAGE_ID),
            PINNED_RABBIT_IMAGE_ID: state.get("pinned_rabbitmq_image_id", PINNED_RABBIT_IMAGE_ID),
            EGRESS_IMAGE_ID: state.get("egress_image_id", EGRESS_IMAGE_ID),
        }
        effective_id = overrides.get(expected_id, expected_id)
        image = {"is_image": True, "id": effective_id}
        reference = next(
            (
                candidate
                for candidate in (
                    APP_IMAGE, POSTGRES_IMAGE, EGRESS_IMAGE,
                    PINNED_RABBIT_IMAGE, PINNED_RABBIT_42_IMAGE,
                    PINNED_RABBIT_313_IMAGE,
                )
                if image_id(candidate) == expected_id
            ),
            identifier,
        )
        image.update(image_metadata(reference))
        if template == "{{.Id}}":
            emit(effective_id)
        else:
            emit(inspect_value(image, template))
        return
    if arguments[0] == "exec":
        if "/usr/local/bin/backupsheep-egress-healthcheck" in arguments:
            sys.exit(state.get("guard_healthcheck_exit_code", 0))
        elif "/usr/local/bin/backupsheep-rabbitmq-volume-init" in arguments:
            action = arguments[-1]
            sys.exit(state.get(f"rabbitmq_volume_{action}_exit_code", 0))
        elif "server_version" in arguments:
            emit(state.get("rabbitmq_server_version", "4.3.5"))
        elif "enable_feature_flag" in arguments and arguments[-1] == "all":
            exit_code = state.get("rabbitmq_enable_feature_flag_exit_code", 0)
            if exit_code:
                sys.exit(exit_code)
            state["rabbitmq_feature_flags"] = RABBITMQ_43_FEATURE_FLAGS
            save_state(state)
        elif "list_feature_flags" in arguments:
            emit(
                state.get(
                    "rabbitmq_feature_flags",
                    RABBITMQ_43_FEATURE_FLAGS,
                )
            )
        elif "eval" in arguments and "node()." in arguments:
            emit(state.get("rabbitmq_node", "rabbit@rabbitmq"))
        elif "list_vhosts" in arguments:
            emit(state.get("rabbitmq_vhosts", "/"))
        elif "list_users" in arguments:
            emit(state.get("rabbitmq_users", "guest\t[administrator]"))
        elif "list_queues" in arguments:
            emit(state.get("rabbitmq_queues", ""))
    elif arguments[0] == "run":
        if option_value(arguments, "--pull") != "never" or not any(
            reference in arguments
            for reference in (
                PINNED_RABBIT_IMAGE,
                PINNED_RABBIT_42_IMAGE,
                PINNED_RABBIT_313_IMAGE,
            )
        ):
            sys.exit(1)
        sys.exit(state.get("raw_docker_run_exit_code", 0))

arguments = sys.argv[1:]
log_invocation(arguments)
state = load_state()
if arguments and arguments[0] == "compose":
    handle_compose(arguments, state)
else:
    handle_raw_docker(arguments, state)
'''


class SecureComposeWrapperTests(TestCase):
    maxDiff = None

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="backupsheep-compose-wrapper-"
        )
        self.root = Path(self.temporary_directory.name)
        self.wrapper = self.root / "backupsheep-compose"
        shutil.copyfile(WRAPPER, self.wrapper)
        self.wrapper.chmod(0o700)
        self.base_file = self.root / "docker-compose.yml"
        self.base_file.write_text(
            'name: "${BACKUPSHEEP_COMPOSE_PROJECT_NAME:?required}"\n'
            f"services:\n  app:\n    image: {APP_IMAGE}\n",
            encoding="utf-8",
        )
        self.base_file.chmod(0o600)
        for name in (
            "Dockerfile.rabbitmq",
            "Dockerfile.rabbitmq-upgrade",
            "Dockerfile.rabbitmq-legacy-source",
        ):
            fixture = self.root / name
            fixture.write_text("reviewed fixture\n", encoding="utf-8")
            fixture.chmod(0o600)
        rabbit_dir = self.root / "deploy" / "rabbitmq"
        rabbit_dir.mkdir(parents=True, mode=0o700)
        for name in (
            "volume-init.sh", "entrypoint.sh", "provision.sh",
            "90-backupsheep.conf", "90-legacy-source.conf", "uid-transition.sh",
        ):
            fixture = rabbit_dir / name
            fixture.write_text("reviewed fixture\n", encoding="utf-8")
            fixture.chmod(0o600)
        for name in (
            "transition-4.3.compose.yml", "source-3.13.7.compose.yml",
            "recovery.compose.yml", "clean-inspector.compose.yml",
        ):
            fixture = rabbit_dir / name
            fixture.write_text("services: {}\n", encoding="utf-8")
            fixture.chmod(0o600)
        runtime_dir = self.root / "deploy" / "runtime"
        runtime_dir.mkdir(mode=0o700)
        shutil.copyfile(COMPOSE_JSON_PARSER, runtime_dir / "compose-json.awk")
        (runtime_dir / "compose-json.awk").chmod(0o600)
        secrets_dir = self.root / ".secrets"
        secrets_dir.mkdir(mode=0o700)
        secret_names = {
            "django_secret_key", "celery_trusted_public_keys", "onboarding_token",
            "ssh_managed_database_private_key", "ssh_managed_files_private_key",
            "artifact_local_file_database_keyring", "artifact_local_file_files_keyring",
        }
        secret_names.update(
            f"db_{role}_password" for role in (
                "bootstrap", "migrator", "app", "preflight", "beat", "cloud",
                "database", "files", "storage", "logs",
            )
        )
        secret_names.update(
            f"rabbitmq_{role}_password" for role in (
                "bootstrap", "app", "preflight", "beat", "cloud", "database",
                "files", "storage", "logs",
            )
        )
        secret_names.update(
            f"celery_signing_{role}_private_key" for role in (
                "app", "beat", "cloud", "database", "files", "storage", "logs",
            )
        )
        for name in secret_names:
            fixture = secrets_dir / name
            fixture.write_text("fixture\n", encoding="utf-8")
            fixture.chmod(0o600)
        self.env_file = self.root / ".env"
        self.write_env()
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir(mode=0o700)
        self.event_log = self.root / "docker-events.jsonl"
        self.state_path = self.root / "docker-state.json"
        self.set_state()
        fake_docker = self.fake_bin / "docker"
        fake_source = FAKE_DOCKER.replace(
            "__NETWORKS__", repr(CANONICAL_NETWORKS)
        ).replace("__VOLUMES__", repr(CANONICAL_VOLUMES)).replace(
            "__SERVICES__", repr(CANONICAL_SERVICES)
        )
        fake_docker.write_text(fake_source, encoding="utf-8")
        fake_docker.chmod(0o700)

    def tearDown(self):
        lock_dir = Path(f"{self.root.resolve()}.backupsheep-mutation-lock")
        if lock_dir.exists():
            shutil.rmtree(lock_dir)
        self.temporary_directory.cleanup()

    def write_env(
        self,
        *,
        project_name="backupsheep",
        installation_value=f"'{INSTALLATION_ID}'",
        generation_value="'4.3'",
        egress_generation_value="'2'",
        database_value="'backupsheep'",
        postgres_storage_generation="18-alpine-icu-v1-pending-fresh",
        postgres_storage_intent="new-empty-v1",
        rabbitmq_node_host="rabbitmq",
        image_mode="local-build",
        additional_lines=(),
    ):
        lines = [
            f"BACKUPSHEEP_COMPOSE_PROJECT_NAME='{project_name}'",
            "BACKUPSHEEP_BIND_ADDRESS='127.0.0.1'",
            f"BACKUPSHEEP_IMAGE_MODE='{image_mode}'",
            f"BACKUPSHEEP_IMAGE='{APP_IMAGE}'",
            f"BACKUPSHEEP_POSTGRES_IMAGE='{POSTGRES_IMAGE}'",
            f"BACKUPSHEEP_EGRESS_IMAGE='{EGRESS_IMAGE}'",
            f"BACKUPSHEEP_RABBITMQ_IMAGE='{PINNED_RABBIT_IMAGE}'",
            f"BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE='{PINNED_RABBIT_42_IMAGE}'",
            f"BACKUPSHEEP_RABBITMQ_LEGACY_SOURCE_IMAGE='{PINNED_RABBIT_313_IMAGE}'",
        ]
        if database_value is not None:
            lines.append(f"DB_NAME={database_value}")
        if installation_value is not None:
            lines.append(f"BACKUPSHEEP_INSTALLATION_ID={installation_value}")
        witness_installation = (installation_value or "").strip("'\"")
        if len(witness_installation) == 64 and all(
            character in "0123456789abcdef" for character in witness_installation
        ):
            witness_material = (
                "BackupSheep/postgres-storage/v1|"
                f"{witness_installation}|{project_name}|postgres_data_v1|"
                f"18-alpine-icu-v1|icu=und|{postgres_storage_intent}"
            )
            postgres_storage_witness = hashlib.sha256(
                witness_material.encode("utf-8")
            ).hexdigest()
        else:
            postgres_storage_witness = "0" * 64
        lines.extend(
            (
                f"BACKUPSHEEP_POSTGRES_STORAGE_GENERATION='{postgres_storage_generation}'",
                f"BACKUPSHEEP_POSTGRES_STORAGE_INTENT='{postgres_storage_intent}'",
                f"BACKUPSHEEP_POSTGRES_STORAGE_WITNESS='{postgres_storage_witness}'",
            )
        )
        if egress_generation_value is not None:
            lines.append(
                f"BACKUPSHEEP_EGRESS_POLICY_GENERATION={egress_generation_value}"
            )
        if generation_value is not None:
            lines.append(f"BACKUPSHEEP_RABBITMQ_DATA_GENERATION={generation_value}")
        if rabbitmq_node_host is not None:
            lines.append(f"BACKUPSHEEP_RABBITMQ_NODE_HOST='{rabbitmq_node_host}'")
        lines.extend(additional_lines)
        self.env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.env_file.chmod(0o600)

    def set_state(self, *, containers=None, networks=None, volumes=None, **extra):
        container_state = containers or {}
        volume_state = dict(volumes or {})
        service_volumes = {
            "db": ("postgres_data_v1",),
            "rabbitmq-volume-init": ("rabbitmq_data",),
            "rabbitmq": ("rabbitmq_data",),
            "rabbitmq-provision": ("rabbitmq_data",),
            "staging-provision": (
                "database_workdir", "files_workdir", "storage_workdir",
                "database_ciphertext_transfer", "files_ciphertext_transfer",
                "restore_ciphertext_transfer", "backup_storage", "backup_workdir",
                "staging_layout_witness",
            ),
            "app": ("installation_identity",),
            "worker-database": (
                "database_workdir", "database_ciphertext_transfer",
                "restore_ciphertext_transfer",
            ),
            "worker-files": (
                "files_workdir", "files_ciphertext_transfer",
                "restore_ciphertext_transfer",
            ),
            "worker-storage": (
                "storage_workdir", "database_ciphertext_transfer",
                "files_ciphertext_transfer", "restore_ciphertext_transfer",
                "backup_storage",
            ),
        }
        existing_names = {resource.get("name") for resource in volume_state.values()}
        for container in container_state.values():
            service = container.get("labels", {}).get("com.docker.compose.service", "")
            for logical in service_volumes.get(service, ()):
                physical = f"backupsheep_{logical}"
                if physical in existing_names:
                    continue
                key = f"auto-{logical}"
                volume_state[key] = self.owned_volume(logical)
                existing_names.add(physical)
        state = {
            "containers": container_state,
            "networks": networks or {},
            "volumes": volume_state,
        }
        state.update(extra)
        self.state_path.write_text(
            json.dumps(state, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )

    def state(self):
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def clear_events(self):
        self.event_log.unlink(missing_ok=True)

    def events(self):
        if not self.event_log.exists():
            return []
        return [
            json.loads(line)
            for line in self.event_log.read_text(encoding="utf-8").splitlines()
        ]

    @staticmethod
    def event_subcommand(event):
        arguments = event["argv"]
        if not arguments or arguments[0] != "compose":
            return ""
        commands = {
            "build", "config", "create", "down", "exec", "restart", "rm",
            "run", "start", "up",
        }
        return next((argument for argument in arguments if argument in commands), "")

    def compose_events(self, command=None):
        events = [event for event in self.events() if event["argv"][:1] == ["compose"]]
        if command is not None:
            events = [event for event in events if self.event_subcommand(event) == command]
        return events

    def raw_events(self, *prefix):
        return [
            event for event in self.events()
            if event["argv"][: len(prefix)] == list(prefix)
        ]

    def test_wrapper_accepts_only_exact_linux_amd64_docker_server(self):
        for platform, accepted in (
            ("linux|amd64", True),
            ("linux|arm64", False),
            ("linux|386", False),
            ("darwin|amd64", False),
            ("linux|x86_64", False),
            ("linux|amd64\nlinux|arm64", False),
            ("", False),
        ):
            with self.subTest(platform=repr(platform)):
                self.set_state(docker_server_platform=platform)
                self.clear_events()
                result = self.run_wrapper("config", "--quiet")
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertEqual(len(self.raw_events("version")), 1)
                if accepted:
                    self.assertTrue(self.compose_events("config"))
                else:
                    self.assertIn(
                        "supports only a linux/amd64 Docker server", result.stderr
                    )
                    self.assertEqual(self.compose_events(), [])
                    self.assertFalse(
                        Path(f"{self.root.resolve()}.backupsheep-mutation-lock").exists()
                    )

    def run_wrapper(self, *arguments, check=False, extra_environment=None):
        environment = self.wrapper_environment(extra_environment)
        return subprocess.run(
            [str(self.wrapper), *arguments], cwd=self.root, env=environment,
            check=check, capture_output=True, text=True,
        )

    def rootful_docker_environment(self):
        allowed = {Path("/var/run/docker.sock"), Path("/run/docker.sock")}
        for socket_path in allowed:
            try:
                metadata = socket_path.lstat()
                resolved = socket_path.parent.resolve(strict=True) / socket_path.name
            except OSError:
                continue
            if (
                stat.S_ISSOCK(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and metadata.st_uid == 0
                and resolved in allowed
            ):
                return {
                    "DOCKER_CONTEXT": "",
                    "DOCKER_HOST": f"unix://{socket_path}",
                }
        self.skipTest("a real canonical root-owned Docker socket is unavailable")

    def wrapper_environment(self, extra_environment=None):
        environment = os.environ.copy()
        environment["PATH"] = f"{self.fake_bin}{os.pathsep}{environment['PATH']}"
        environment.update(
            BACKUPSHEEP_BIND_ADDRESS="0.0.0.0",
            BACKUPSHEEP_IMAGE_MODE="signed-release",
            BACKUPSHEEP_IMAGE="attacker/image:latest",
            BACKUPSHEEP_POSTGRES_IMAGE="attacker/postgres:latest",
            BACKUPSHEEP_EGRESS_IMAGE="attacker/egress:latest",
            BACKUPSHEEP_RABBITMQ_IMAGE="attacker/rabbitmq:latest",
            BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE="attacker/rabbitmq-upgrade:latest",
            BACKUPSHEEP_RABBITMQ_LEGACY_SOURCE_IMAGE="attacker/rabbitmq-legacy:latest",
            BACKUPSHEEP_COMPOSE_PROJECT_NAME="ambient-attacker",
            BACKUPSHEEP_INSTALLATION_ID=OTHER_INSTALLATION_ID,
            COMPOSE_BAKE="true",
            COMPOSE_ENV_FILES="/tmp/attacker.env",
            COMPOSE_EXPERIMENTAL="true",
            COMPOSE_FILE="/tmp/attacker.yml",
            COMPOSE_PATH_SEPARATOR="!",
            COMPOSE_PROFILES="operations",
            COMPOSE_PROJECT_NAME="foreign",
            COMPOSE_REMOVE_ORPHANS="1",
            BUILDX_BAKE_FILE="/tmp/attacker.hcl",
            BUILDKIT_PROGRESS="plain",
            DOCKER_BUILDKIT="0",
            DOCKER_DEFAULT_PLATFORM="linux/arm64",
            DOCKER_CONTEXT="reviewed-context",
            DOCKER_HOST="ssh://reviewed-daemon",
        )
        if extra_environment:
            environment.update(extra_environment)
        return environment

    def assert_refused(self, arguments, message, *, extra_environment=None):
        result = self.run_wrapper(
            *arguments, extra_environment=extra_environment
        )
        self.assertNotEqual(result.returncode, 0, arguments)
        self.assertIn(message, result.stderr, arguments)
        return result

    def test_root_override_requires_euid_zero_and_wrapper_ownership_guards(self):
        source = self.wrapper.read_text(encoding="utf-8")
        self.assertTrue(source.startswith("#!/bin/bash\n"))
        self.assertLess(
            source.index('if [[ "${1-}" == "--allow-root-install" ]]'),
            source.index('script_path="${BASH_SOURCE[0]}"'),
        )
        self.assertIn(
            'root_install_mode_allowed "$EUID" "$allow_root_install"', source
        )
        self.assertIn(
            'validate_private_file "$script_path" "backupsheep-compose wrapper"',
            source,
        )
        self.assertIn(
            'validate_private_directory "$installation_parent"', source
        )
        self.assertIn("validate_privileged_runtime_environment", source)
        self.assertIn(
            "for variable in HOME DOCKER_CONFIG DOCKER_CERT_PATH", source
        )
        self.assertIn('"$(file_uid "$path")" == "$EUID"', source)
        self.assertNotIn("SUDO_USER", source)
        self.assertNotIn("SUDO_UID", source)

        self.run_wrapper("config", "--quiet", check=True)
        refused = self.run_wrapper(
            "--allow-root-install", "config", "--quiet"
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(
            "valid only when the effective invoking UID is 0", refused.stderr
        )

        self.wrapper.chmod(0o720)
        writable = self.run_wrapper("config", "--quiet")
        self.assertNotEqual(writable.returncode, 0)
        self.assertIn(
            "backupsheep-compose wrapper must not be writable by group",
            writable.stderr,
        )
        self.wrapper.chmod(0o700)

        hardlink = self.root / "backupsheep-compose-hardlink"
        os.link(self.wrapper, hardlink)
        linked = self.run_wrapper("config", "--quiet")
        self.assertNotEqual(linked.returncode, 0)
        self.assertIn(
            "backupsheep-compose wrapper must not be hard-linked", linked.stderr
        )
        hardlink.unlink()

        self.root.chmod(0o720)
        unsafe_directory = self.run_wrapper("config", "--quiet")
        self.assertNotEqual(unsafe_directory.returncode, 0)
        self.assertIn(
            "installation path ancestor is attacker-writable",
            unsafe_directory.stderr,
        )
        self.root.chmod(0o700)
        self.run_wrapper("config", "--quiet", check=True)

    @staticmethod
    def labels(resource_type, logical_name, installation_id=INSTALLATION_ID):
        labels = {
            "com.docker.compose.project": "backupsheep",
            f"com.docker.compose.{resource_type}": logical_name,
        }
        if installation_id is not None:
            labels["com.backupsheep.installation-id"] = installation_id
        return labels

    def sentinel(self, installation_id=INSTALLATION_ID):
        return {
            "labels": self.labels("volume", "installation_identity", installation_id),
            "name": "backupsheep_installation_identity",
        }

    def owned_volume(self, logical_name, installation_id=INSTALLATION_ID):
        return {
            "labels": self.labels("volume", logical_name, installation_id),
            "name": f"backupsheep_{logical_name}",
        }

    def owned_container(self, service, installation_id=INSTALLATION_ID, **state):
        labels = {
            "com.docker.compose.project": "backupsheep",
            "com.docker.compose.project.working_dir": str(self.root.resolve()),
            "com.docker.compose.project.config_files": str(self.base_file.resolve()),
            "com.docker.compose.service": service,
            "com.docker.compose.config-hash": CONFIG_HASH,
        }
        if installation_id is not None:
            labels["com.backupsheep.installation-id"] = installation_id
        if service == "db":
            default_image, default_id = POSTGRES_IMAGE, POSTGRES_IMAGE_ID
        elif service in {"rabbitmq-volume-init", "rabbitmq", "rabbitmq-provision"}:
            default_image, default_id = PINNED_RABBIT_IMAGE, PINNED_RABBIT_IMAGE_ID
        elif service.endswith("-egress-guard"):
            default_image, default_id = EGRESS_IMAGE, EGRESS_IMAGE_ID
        else:
            default_image, default_id = APP_IMAGE, APP_IMAGE_ID
        defaults = {"config_image": default_image, "image_id": default_id}
        defaults.update(state)
        return {
            "labels": labels,
            "name": f"backupsheep-{service}-1",
            **defaults,
        }

    def owned_guard(self, service, installation_id=INSTALLATION_ID, **state):
        defaults = {
            "state": "running",
            "health": "healthy",
            "config_image": EGRESS_IMAGE,
            "image_id": EGRESS_IMAGE_ID,
            "restart_policy": "no",
        }
        defaults.update(state)
        return self.owned_container(
            service,
            installation_id=installation_id,
            **defaults,
        )

    def owned_oneoff(self, service, installation_id=INSTALLATION_ID, **state):
        resource = self.owned_container(
            service,
            installation_id=installation_id,
            **state,
        )
        resource["labels"]["com.docker.compose.oneoff"] = "True"
        return resource

    def rabbit_overlay(self):
        rabbit = self.root / "deploy" / "rabbitmq" / "upgrade-4.2.9.compose.yml"
        rabbit.parent.mkdir(parents=True, exist_ok=True)
        rabbit.write_text("services: {}\n", encoding="utf-8")
        rabbit.chmod(0o600)
        return rabbit

    def rabbit_source_overlay(self):
        return self.root / "deploy" / "rabbitmq" / "source-3.13.7.compose.yml"

    def prepare_legacy_rabbit_source(self, *, installation_id=INSTALLATION_ID):
        self.write_env(generation_value="''")
        self.set_state(
            volumes={
                "sentinel": self.sentinel(installation_id),
                "rabbit-data": self.owned_volume(
                    "rabbitmq_data", installation_id=installation_id
                ),
            }
        )
        result = self.run_wrapper(
            "--prepare-rabbitmq-3.13-source",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )
        self.clear_events()
        return result

    def rabbit_transition_state(
        self,
        *,
        config_files,
        server_version,
        feature_flags=None,
        installation_id=INSTALLATION_ID,
        compose_up_transition_result=None,
        compose_up_exit_code=0,
        container_image_ref=None,
        container_image_id=None,
        combined_rabbitmq_image=PINNED_RABBIT_IMAGE,
        container_state="running",
        container_health="healthy",
        container_config_hash=None,
        container_config_env=None,
        container_config_entrypoint=None,
        attest_exact_source=True,
    ):
        transition_42 = "upgrade-4.2.9.compose.yml" in config_files
        transition_43 = "transition-4.3.compose.yml" in config_files
        if container_config_hash is None:
            container_config_hash = (
                RABBITMQ_42_CONFIG_HASH if transition_42
                else RABBITMQ_43_TRANSITION_CONFIG_HASH if transition_43
                else CONFIG_HASH
            )
        transition_target = "4.2" if transition_42 else "4.3" if transition_43 else ""
        if container_config_env is None:
            container_config_env = [
                "PATH=/usr/bin",
                "BACKUPSHEEP_TEST_SERVICE=rabbitmq",
                "BACKUPSHEEP_RABBITMQ_NODE_HOST=rabbitmq",
                "RABBITMQ_NODENAME=rabbit@rabbitmq",
            ]
            if transition_target:
                container_config_env.append(
                    f"BACKUPSHEEP_RABBITMQ_TRANSITION_TARGET={transition_target}"
                )
        if container_config_entrypoint is None and transition_target:
            container_config_entrypoint = [
                "/bin/sh", "/usr/local/bin/backupsheep-rabbitmq-entrypoint",
                "transition",
            ]
        rabbit_labels = {
            "com.docker.compose.project": "backupsheep",
            "com.docker.compose.project.working_dir": str(self.root.resolve()),
            "com.docker.compose.project.config_files": config_files,
            "com.docker.compose.service": "rabbitmq",
            "com.docker.compose.config-hash": container_config_hash,
        }
        if installation_id is not None:
            rabbit_labels["com.backupsheep.installation-id"] = installation_id
        if feature_flags is None:
            if server_version.startswith("3.13."):
                feature_flags = (
                    "name stability state\n"
                    "khepri_db experimental disabled\n"
                    "stream_queue stable enabled"
                )
            else:
                feature_flags = RABBITMQ_43_FEATURE_FLAGS
        if container_image_ref is None:
            container_image_ref = (
                PINNED_RABBIT_42_IMAGE if transition_42
                else PINNED_RABBIT_IMAGE if transition_43 or not server_version.startswith("3.13.")
                else "rabbitmq:legacy-source"
            )
        if container_image_id is None:
            container_image_id = (
                PINNED_RABBIT_42_IMAGE_ID if transition_42
                else PINNED_RABBIT_IMAGE_ID if transition_43 or not server_version.startswith("3.13.")
                else "sha256:" + ("f" * 64)
            )
        self.set_state(
            containers={
                "rabbit-container": {
                    "health": container_health,
                    "config_image": container_image_ref,
                    "config_env": container_config_env,
                    "config_entrypoint": container_config_entrypoint,
                    "image_id": container_image_id,
                    "labels": rabbit_labels,
                    "name": "backupsheep-rabbitmq-1",
                    "state": container_state,
                }
            },
            volumes={
                "sentinel": self.sentinel(),
                "rabbit-data": self.owned_volume("rabbitmq_data"),
            },
            rabbitmq_feature_flags=feature_flags,
            rabbitmq_server_version=server_version,
            compose_up_transition_result=compose_up_transition_result,
            compose_up_exit_code=compose_up_exit_code,
            combined_rabbitmq_image=combined_rabbitmq_image,
        )
        if transition_42 and attest_exact_source:
            source_binding = hashlib.sha256(
                (
                    "BackupSheep/rabbitmq-source/v1|"
                    f"{installation_id or ''}|backupsheep|{server_version}|"
                    f"{config_files}|{container_config_hash}|"
                    f"{container_image_ref}|{container_image_id}"
                ).encode("ascii")
            ).hexdigest()
            self.write_rabbit_transition_ledger(
                phase="attested",
                source_class="4.2.9",
                target="4.2",
                source_binding=source_binding,
            )

    def env_value(self, key):
        for line in self.env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1]
        return None

    def write_rabbit_transition_ledger(
        self,
        *,
        phase,
        source_class,
        target,
        source_binding="9" * 64,
        config_hash=None,
        image_ref=None,
        image_id=None,
        final_newline=True,
    ):
        target_version = {
            "3.13": "3.13.7", "4.2": "4.2.9", "4.3": "4.3.5"
        }[target]
        if config_hash is None:
            config_hash = (
                RABBITMQ_313_CONFIG_HASH if target == "3.13"
                else RABBITMQ_42_CONFIG_HASH if target == "4.2"
                else RABBITMQ_43_TRANSITION_CONFIG_HASH
            )
        if image_ref is None:
            image_ref = (
                PINNED_RABBIT_313_IMAGE if target == "3.13"
                else PINNED_RABBIT_42_IMAGE if target == "4.2"
                else PINNED_RABBIT_IMAGE
            )
        if image_id is None:
            image_id = (
                PINNED_RABBIT_313_IMAGE_ID if target == "3.13"
                else PINNED_RABBIT_42_IMAGE_ID if target == "4.2"
                else PINNED_RABBIT_IMAGE_ID
            )
        content = "\n".join(
            (
                "version=1",
                f"installation_id={INSTALLATION_ID}",
                "project_name=backupsheep",
                f"phase={phase}",
                f"source_class={source_class}",
                f"source_binding={source_binding}",
                f"target_version={target_version}",
                f"target_config_hash={config_hash}",
                f"target_image_ref={image_ref}",
                f"target_image_id={image_id}",
            )
        )
        if final_newline:
            content += "\n"
        path = self.root / ".backupsheep-rabbitmq-transition-state"
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_ambient_model_build_profile_and_identity_controls_are_removed(self):
        result = self.run_wrapper("config", "--services", check=True)
        self.assertEqual(result.stdout.splitlines(), list(CANONICAL_SERVICES))
        compose_events = self.compose_events()
        self.assertEqual(len(compose_events), 3)
        stripped = {
            "BACKUPSHEEP_BIND_ADDRESS", "BACKUPSHEEP_IMAGE_MODE",
            "BACKUPSHEEP_IMAGE", "BACKUPSHEEP_POSTGRES_IMAGE",
            "BACKUPSHEEP_EGRESS_IMAGE", "BACKUPSHEEP_RABBITMQ_IMAGE",
            "BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE",
            "BACKUPSHEEP_RABBITMQ_LEGACY_SOURCE_IMAGE",
            "BACKUPSHEEP_COMPOSE_PROJECT_NAME", "BACKUPSHEEP_INSTALLATION_ID",
            "COMPOSE_ENV_FILES", "COMPOSE_FILE",
            "COMPOSE_PATH_SEPARATOR", "COMPOSE_PROFILES", "COMPOSE_PROJECT_NAME",
            "BUILDX_BAKE_FILE", "BUILDKIT_PROGRESS", "DOCKER_BUILDKIT",
            "DOCKER_DEFAULT_PLATFORM",
        }
        for event in compose_events:
            for key in stripped:
                self.assertEqual(event["env"][key], "<unset>", key)
            self.assertEqual(event["env"]["COMPOSE_BAKE"], "false")
            self.assertEqual(event["env"]["COMPOSE_EXPERIMENTAL"], "false")
            self.assertEqual(event["env"]["COMPOSE_REMOVE_ORPHANS"], "0")
            self.assertEqual(event["env"]["DOCKER_CONTEXT"], "reviewed-context")
            self.assertEqual(event["env"]["DOCKER_HOST"], "ssh://reviewed-daemon")
            self.assertEqual(event["env"]["LC_ALL"], "C")
            arguments = event["argv"]
            self.assertEqual(arguments[arguments.index("--project-name") + 1], "backupsheep")
            self.assertEqual(arguments[arguments.index("--env-file") + 1], str(self.env_file.resolve()))
            self.assertNotIn("foreign", arguments)
            if "operations" in arguments:
                profile_index = arguments.index("--profile")
                self.assertEqual(
                    arguments[profile_index : profile_index + 3],
                    ["--profile", "operations", "config"],
                )
            self.assertNotIn("/tmp/attacker.yml", arguments)

    def test_overlays_require_explicit_approval_and_have_canonical_order(self):
        override = self.root / "docker-compose.override.yml"
        override.write_text("services: {}\n", encoding="utf-8")
        override.chmod(0o600)
        rabbit = self.root / "deploy" / "rabbitmq" / "upgrade-4.2.9.compose.yml"
        rabbit.parent.mkdir(parents=True, exist_ok=True)
        rabbit.write_text("services: {}\n", encoding="utf-8")
        rabbit.chmod(0o600)
        self.assert_refused(("config", "--quiet"), "review it and pass --approved-compose-file")
        self.clear_events()
        self.run_wrapper(
            "--approved-compose-file", str(rabbit),
            "--approved-compose-file", str(override),
            "config", "--quiet", check=True,
        )
        expected_files = [str(self.base_file.resolve()), str(override.resolve()), str(rabbit.resolve())]
        saw_active_model = False
        for event in self.compose_events():
            arguments = event["argv"]
            actual_files = [
                arguments[index + 1] for index, argument in enumerate(arguments)
                if argument == "-f"
            ]
            self.assertIn(
                actual_files,
                (
                    [str(self.base_file.resolve())],
                    [str(self.base_file.resolve()), str(override.resolve())],
                    expected_files,
                ),
            )
            saw_active_model = saw_active_model or actual_files == expected_files
        self.assertTrue(saw_active_model)
        duplicate = self.run_wrapper(
            "--approved-compose-file", str(override),
            "--approved-compose-file", str(override), "config",
        )
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("supplied more than once", duplicate.stderr)

    def test_unapproved_or_unsafe_overlay_is_refused(self):
        unknown = self.root / "attacker.compose.yml"
        unknown.write_text("services: {}\n", encoding="utf-8")
        unknown.chmod(0o600)
        self.assert_refused(
            ("--approved-compose-file", str(unknown), "config"),
            "only the exact deployment override",
        )
        override = self.root / "docker-compose.override.yml"
        override.write_text("services: {}\n", encoding="utf-8")
        override.chmod(0o622)
        self.assert_refused(
            ("--approved-compose-file", str(override), "config"),
            "must not be writable by group",
        )

    def test_approved_override_cannot_change_services_or_pull_policy(self):
        override = self.root / "docker-compose.override.yml"
        override.write_text("services: {}\n", encoding="utf-8")
        override.chmod(0o600)
        approved = ("--approved-compose-file", str(override))

        self.set_state(approved_override_extra_service="evil")
        self.assert_refused(
            (*approved, "config", "--quiet"),
            "changed reviewed Compose key services",
        )

        self.set_state(approved_override_mutated_service="app")
        self.assert_refused(
            (*approved, "config", "--quiet"),
            "changed reviewed Compose key services",
        )

        self.set_state(service_pull_policies={"app": "always"})
        self.assert_refused(
            (*approved, "config", "--quiet"),
            "must retain pull_policy: never",
        )

    def test_approved_backup_storage_bind_is_exactly_attested(self):
        local_docker = self.rootful_docker_environment()
        device_path = self.root / "approved-backup-storage"
        device_path.mkdir(mode=0o700)
        device = str(device_path.resolve(strict=True))
        override = self.root / "docker-compose.override.yml"
        override.write_text(
            "volumes:\n"
            "  backup_storage:\n"
            "    driver: local\n"
            "    driver_opts:\n"
            "      type: none\n"
            "      o: bind\n"
            f"      device: {device}\n",
            encoding="utf-8",
        )
        override.chmod(0o600)
        backup_storage = self.owned_volume("backup_storage")
        backup_storage.update(
            runtime_policy=(
                "local|3|local|/var/lib/docker/volumes/"
                "backupsheep_backup_storage/_data"
            ),
            volume_options={"type": "none", "o": "bind", "device": device},
        )
        self.set_state(
            volumes={
                "sentinel": self.sentinel(),
                "backup-storage": backup_storage,
            },
            approved_override_backup_storage_device=device,
        )
        approved = ("--approved-compose-file", str(override))
        self.run_wrapper(
            *approved, "ps", "--all", check=True,
            extra_environment=local_docker,
        )

        backup_storage["volume_options"]["device"] = "/mnt/other"
        self.set_state(
            volumes={
                "sentinel": self.sentinel(),
                "backup-storage": backup_storage,
            },
            approved_override_backup_storage_device=device,
        )
        self.assert_refused(
            (*approved, "ps", "--all"),
            "options differ from the exact reviewed bind target",
            extra_environment=local_docker,
        )

        self.set_state(approved_override_backup_storage_device="/")
        self.assert_refused(
            (*approved, "config", "--quiet"),
            "cannot be the host root",
            extra_environment=local_docker,
        )

        self.set_state(approved_override_backup_storage_device=device)
        self.assert_refused(
            (*approved, "config", "--quiet"),
            "requires the canonical local rootful Docker socket",
            extra_environment={
                "DOCKER_CONTEXT": "",
                "DOCKER_HOST": "ssh://reviewed-daemon",
            },
        )

        self.set_state(
            approved_override_backup_storage_device=device,
            docker_context="remote-review",
            docker_endpoint="ssh://backup-host",
        )
        self.assert_refused(
            (*approved, "config", "--quiet"),
            "requires the canonical local rootful Docker socket",
            extra_environment={
                "DOCKER_CONTEXT": "remote-review",
                "DOCKER_HOST": "",
            },
        )

        self.set_state(
            approved_override_backup_storage_device=device,
            docker_context="forwarded-review",
            docker_endpoint="unix:///tmp/remote-docker.sock",
        )
        self.assert_refused(
            (*approved, "config", "--quiet"),
            "requires the canonical local rootful Docker socket",
            extra_environment={
                "DOCKER_CONTEXT": "forwarded-review",
                "DOCKER_HOST": "",
            },
        )

    def test_approved_backup_storage_remote_endpoint_rejection_is_platform_independent(self):
        # Keep this endpoint-focused fixture outside host-control roots even
        # when the test runner's executable TMPDIR is intentionally under
        # /run. Endpoint rejection occurs before local directory inspection.
        device = "/tmp/backupsheep-remote-endpoint-fixture"
        override = self.root / "docker-compose.override.yml"
        override.write_text(
            "volumes:\n"
            "  backup_storage:\n"
            "    driver: local\n"
            "    driver_opts:\n"
            "      type: none\n"
            "      o: bind\n"
            f"      device: {device}\n",
            encoding="utf-8",
        )
        override.chmod(0o600)
        approved = ("--approved-compose-file", str(override))
        cases = (
            (
                {"DOCKER_CONTEXT": "", "DOCKER_HOST": "ssh://remote"},
                {},
            ),
            (
                {"DOCKER_CONTEXT": "forwarded", "DOCKER_HOST": ""},
                {
                    "docker_context": "forwarded",
                    "docker_endpoint": "unix:///tmp/remote-docker.sock",
                },
            ),
        )
        for environment, state in cases:
            with self.subTest(environment=environment):
                self.set_state(
                    approved_override_backup_storage_device=device,
                    **state,
                )
                self.assert_refused(
                    (*approved, "config", "--quiet"),
                    "requires the canonical local rootful Docker socket",
                    extra_environment=environment,
                )

    def test_approved_backup_storage_rejects_symlinks_and_inode_replacement(self):
        local_docker = self.rootful_docker_environment()
        real_device = self.root / "real-backup-storage"
        real_device.mkdir(mode=0o700)
        linked_device = self.root / "linked-backup-storage"
        linked_device.symlink_to(real_device, target_is_directory=True)
        override = self.root / "docker-compose.override.yml"
        override.write_text(
            "volumes:\n"
            "  backup_storage:\n"
            "    driver: local\n"
            "    driver_opts:\n"
            "      type: none\n"
            "      o: bind\n"
            f"      device: {linked_device}\n",
            encoding="utf-8",
        )
        override.chmod(0o600)
        approved = ("--approved-compose-file", str(override))
        self.set_state(
            approved_override_backup_storage_device=str(linked_device)
        )
        self.assert_refused(
            (*approved, "config", "--quiet"),
            "must already be a real directory",
            extra_environment=local_docker,
        )

        linked_device.unlink()
        real_parent = self.root / "real-storage-parent"
        nested_device = real_parent / "nested"
        nested_device.mkdir(parents=True, mode=0o700)
        linked_parent = self.root / "linked-storage-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        symlink_component_device = linked_parent / "nested"
        self.set_state(
            approved_override_backup_storage_device=str(symlink_component_device)
        )
        self.assert_refused(
            (*approved, "config", "--quiet"),
            "canonical and contain no symlink component",
            extra_environment=local_docker,
        )
        linked_parent.unlink()

        device = str(real_device.resolve(strict=True))
        override.write_text(
            "volumes:\n"
            "  backup_storage:\n"
            "    driver: local\n"
            "    driver_opts:\n"
            "      type: none\n"
            "      o: bind\n"
            f"      device: {device}\n",
            encoding="utf-8",
        )
        override.chmod(0o600)
        self.set_state(approved_override_backup_storage_device=device)
        self.run_wrapper(
            *approved, "build", "app", check=True,
            extra_environment=local_docker,
        )
        ledger = self.root / ".backupsheep-backup-storage-identity"
        self.assertTrue(ledger.is_file())
        self.assertIn("version=2\n", ledger.read_text(encoding="utf-8"))
        self.assertIn(f"device={device}\n", ledger.read_text(encoding="utf-8"))
        self.assertRegex(
            ledger.read_text(encoding="utf-8"),
            r"ancestor_sha256=[0-9a-f]{64}\n?$",
        )

        replaced = self.root / "replaced-backup-storage"
        real_device.rename(replaced)
        real_device.mkdir(mode=0o700)
        self.assert_refused(
            (*approved, "config", "--quiet"),
            "differs from its installation ledger",
            extra_environment=local_docker,
        )

    def test_approved_backup_storage_rejects_attacker_writable_ancestor(self):
        local_docker = self.rootful_docker_environment()
        with tempfile.TemporaryDirectory(
            prefix="backupsheep-unsafe-storage-",
            dir=self.root.parent,
        ) as unsafe_parent_raw:
            unsafe_parent = Path(unsafe_parent_raw)
            unsafe_parent.chmod(0o777)
            device_path = unsafe_parent / "backup-storage"
            device_path.mkdir(mode=0o700)
            device = str(device_path.resolve(strict=True))
            override = self.root / "docker-compose.override.yml"
            override.write_text(
                "volumes:\n"
                "  backup_storage:\n"
                "    driver: local\n"
                "    driver_opts:\n"
                "      type: none\n"
                "      o: bind\n"
                f"      device: {device}\n",
                encoding="utf-8",
            )
            override.chmod(0o600)
            self.set_state(approved_override_backup_storage_device=device)
            self.assert_refused(
                ("--approved-compose-file", str(override), "config", "--quiet"),
                "attacker-writable without a root-owned sticky boundary",
                extra_environment=local_docker,
            )

    def test_backup_storage_target_allows_only_safe_install_or_service_ownership(self):
        source = self.wrapper.read_text(encoding="utf-8")

        self.assertIn(
            "10#$target_owner == 0 || 10#$target_owner == EUID",
            source,
        )
        self.assertIn("10#$target_owner == 10004", source)
        self.assertIn("(8#$target_mode & 8#022) == 0", source)
        self.assertIn(
            '"$(dirname -- "$reviewed_backup_storage_device")")"',
            source,
        )

    def test_caller_cannot_replace_model_project_environment_or_orphan_policy(self):
        attacks = (
            ("-f", "/tmp/attacker.yml", "up"), ("-f=/tmp/attacker.yml", "up"),
            ("-f/tmp/attacker.yml", "up"), ("--file", "/tmp/attacker.yml", "up"),
            ("--file=/tmp/attacker.yml", "up"), ("-pforeign", "up"),
            ("--project-name", "foreign", "up"), ("--project-directory=/tmp", "up"),
            ("--env-file", "/tmp/attacker.env", "up"), ("up", "--remove-orphans"),
            ("up", "--remove-orphans=false"), ("up", "--dry-run=false"),
            ("--all-resources", "up"), ("--all-resources=true", "up"),
            ("--compatibility", "up"), ("--compatibility=true", "up"),
        )
        for arguments in attacks:
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "may not override")

    def test_config_is_strictly_read_only_and_cannot_write_or_resolve_registry_digests(self):
        for arguments in (
            ("config", "--lock-image-digests"),
            ("config", "--lock-image-digests=lock.yml"),
            ("config", "--resolve-image-digests"),
            ("config", "--resolve-image-digests=true"),
            ("config", "--output", "rendered.yml"),
            ("config", "--output=rendered.yml"),
            ("config", "-o", "rendered.yml"),
            ("config", "-orendered.yml"),
            ("config", "unexpected-positional"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "unsupported config option")

        for arguments in (
            ("config", "--quiet"),
            ("config", "--services"),
            ("config", "--format", "json"),
            ("config", "--format=yaml"),
            ("config", "--no-interpolate", "--images"),
        ):
            with self.subTest(arguments=arguments):
                self.run_wrapper(*arguments, check=True)

    def test_volume_deletion_boolean_cluster_rm_and_rmi_forms_fail_closed(self):
        self.set_state(volumes={"sentinel": self.sentinel()})
        deletion_forms = (
            ("down", "--volumes"), ("down", "--volumes=true"),
            ("down", "--volumes=false"), ("down", "-v"),
            ("down", "-v=true"), ("down", "-tv"),
        )
        for arguments in deletion_forms:
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "--allow-data-deletion")
        for arguments in (("rm", "--volumes"), ("rm", "-v"), ("rm", "-sv")):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "not supported")
        for arguments in (
            ("down", "--rmi", "all"), ("down", "--rmi=local"), ("rm", "--rmi=all"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "cannot remove shared reviewed image")
        accepted = self.run_wrapper("--allow-data-deletion", "down", "--volumes", check=True)
        self.assertEqual(accepted.returncode, 0)

    def test_volume_deletion_is_refused_with_an_overlay(self):
        self.set_state(volumes={"sentinel": self.sentinel()})
        override = self.root / "docker-compose.override.yml"
        override.write_text("services: {}\n", encoding="utf-8")
        override.chmod(0o600)
        self.assert_refused(
            ("--approved-compose-file", str(override), "--allow-data-deletion", "down", "--volumes"),
            "while an approved Compose overlay is active",
        )

    def test_compose_and_build_controls_inside_env_file_are_rejected(self):
        forbidden = (
            "COMPOSE_FILE", "COMPOSE_PROFILES", "COMPOSE_BAKE", "COMPOSE_PROJECT_NAME",
            "BUILDX_BAKE_FILE", "BUILDX_EXPERIMENTAL", "BUILDKIT_PROGRESS",
            "DOCKER_BUILDKIT", "DOCKER_DEFAULT_PLATFORM", "DOCKER_HOST",
            "DOCKER_CONTEXT", "BACKUPSHEEP_SECRETS",
        )
        for key in forbidden:
            with self.subTest(key=key):
                self.write_env(additional_lines=(f"{key}='attacker'",))
                self.assert_refused(("config", "--quiet"), "forbidden Docker/Compose")

    def test_model_shaping_environment_values_have_strict_resource_grammars(self):
        invalid = (
            ("BACKUPSHEEP_TMPFS_SIZE", "256m,exec,suid,dev", "integer size"),
            ("POSTGRES_TMPFS_SIZE", "128m,exec", "integer size"),
            ("RABBITMQ_TMPFS_SIZE", "0m", "integer size"),
            ("BACKUPSHEEP_PIDS_LIMIT", "0", "reviewed resource range"),
            ("POSTGRES_PIDS_LIMIT", "512.0", "canonical decimal integer"),
            ("APP_CPU_LIMIT", "64.001", "canonical CPU value"),
            ("WORKER_CLOUD_CPU_LIMIT", "nan", "canonical CPU value"),
            ("APP_MEMORY_LIMIT", "99999999g", "reviewed resource range"),
            ("BACKUPSHEEP_STOP_GRACE_PERIOD", "5m,exec", "canonical nonzero duration"),
            ("BACKUPSHEEP_BIND_PORT", "8000/tcp", "canonical decimal integer"),
            ("DOCKER_LOG_MAX_FILE", "21", "reviewed resource range"),
        )
        for key, value, message in invalid:
            with self.subTest(key=key, value=value):
                self.write_env(additional_lines=(f"{key}='{value}'",))
                self.clear_events()
                self.assert_refused(("config", "--quiet"), message)
                self.assertEqual(self.events(), [])

        self.write_env(
            additional_lines=(
                "BACKUPSHEEP_TMPFS_SIZE='256m'",
                "POSTGRES_TMPFS_SIZE='128M'",
                "RABBITMQ_TMPFS_SIZE='131072k'",
                "APP_CPU_LIMIT='2.000'",
                "APP_MEMORY_LIMIT='2048m'",
                "BACKUPSHEEP_STOP_GRACE_PERIOD='300s'",
            )
        )
        self.run_wrapper("config", "--quiet", check=True)

    def test_database_name_uses_the_stock_non_system_identifier_contract(self):
        for value in (
            None,
            "",
            "postgres",
            "template0",
            "template1",
            "Tenant",
            "tenant-name",
            "ténant",
            "1tenant",
            " tenant",
            "tenant ",
            "a" * 64,
        ):
            with self.subTest(value=value):
                database_value = None if value is None else f"'{value}'"
                self.write_env(database_value=database_value)
                self.clear_events()
                self.assert_refused(
                    ("config", "--quiet"),
                    "DB_NAME must be a non-system lowercase PostgreSQL database identifier",
                )
                self.assertEqual(self.events(), [])

        for value in ("backupsheep", "_backupsheep", "tenant_1", "a" * 63):
            with self.subTest(value=value):
                self.write_env(database_value=f"'{value}'")
                self.run_wrapper("config", "--quiet", check=True)

    def test_nul_bytes_in_env_are_rejected_before_parsing_or_docker(self):
        original = self.env_file.read_bytes()
        expected = b"BACKUPSHEEP_COMPOSE_PROJECT_NAME='backupsheep'"
        for replacement in (
            b"BACKUPSHEEP_COMPOSE_PROJECT_NAME=backupsheep\x00evil",
            b"BACKUPSHEEP_COMPOSE_PROJECT_NAME=\x00backupsheep",
        ):
            with self.subTest(replacement=replacement):
                self.env_file.write_bytes(original.replace(expected, replacement, 1))
                self.env_file.chmod(0o600)
                self.clear_events()
                self.assert_refused(("up",), "NUL byte")
                self.assertEqual(self.events(), [])

    def test_installation_id_must_be_exact_lowercase_hex(self):
        invalid_values = (
            None, "''", "'0'", f"'{INSTALLATION_ID[:-1]}'",
            f"'{INSTALLATION_ID}0'", f"'{INSTALLATION_ID.upper()}'",
            "'" + ("g" * 64) + "'", "'$(id)'",
        )
        for value in invalid_values:
            with self.subTest(value=value):
                self.write_env(installation_value=value)
                self.assert_refused(
                    ("config", "--quiet"),
                    "one stable 64-character lowercase hexadecimal value",
                )
                self.assertEqual(self.events(), [])
        self.write_env(installation_value=f'"{INSTALLATION_ID}"')
        self.run_wrapper("up", "--detach", check=True)
        sentinel = self.state()["volumes"]["backupsheep_installation_identity"]
        self.assertEqual(sentinel["labels"]["com.backupsheep.installation-id"], INSTALLATION_ID)

    def test_hostile_locale_cannot_broaden_ascii_identity_grammars(self):
        self.write_env(installation_value=f"'{INSTALLATION_ID.upper()}'")
        result = self.run_wrapper(
            "up",
            extra_environment={"LC_ALL": "en_US.US-ASCII"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("lowercase hexadecimal", result.stderr)
        self.assertEqual(self.events(), [])

        self.write_env(project_name="BackupSheep")
        result = self.run_wrapper(
            "up",
            extra_environment={"LC_ALL": "en_US.US-ASCII"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("lowercase project name", result.stderr)
        self.assertEqual(self.events(), [])

    def test_project_name_accepts_the_same_safe_quoting_as_the_installer(self):
        for value in ("backupsheep", "'backupsheep'", '"backupsheep"'):
            with self.subTest(value=value):
                self.write_env()
                contents = self.env_file.read_text(encoding="utf-8")
                contents = contents.replace(
                    "BACKUPSHEEP_COMPOSE_PROJECT_NAME='backupsheep'",
                    f"BACKUPSHEEP_COMPOSE_PROJECT_NAME={value}",
                    1,
                )
                self.env_file.write_text(contents, encoding="utf-8")
                self.env_file.chmod(0o600)
                self.set_state()
                self.clear_events()
                self.run_wrapper("up", "--detach", check=True)
                self.assertIn(
                    "backupsheep_installation_identity", self.state()["volumes"]
                )

    def test_project_name_boundary_matrix_fails_closed(self):
        safe_names = ("a", "0", "a_b-c", "a" * 63)
        for project_name in safe_names:
            with self.subTest(project_name=project_name):
                self.write_env(project_name=project_name)
                self.set_state()
                self.clear_events()
                self.run_wrapper("up", "--detach", check=True)
                sentinel_name = f"{project_name}_installation_identity"
                self.assertEqual(
                    self.state()["volumes"][sentinel_name]["labels"][
                        "com.docker.compose.project"
                    ],
                    project_name,
                )

        invalid_names = (
            "", "A", "-project", "_project", "a" * 64, "project.name",
            "project/name", "project name", "--version", "project\nname",
            "backupsheepé",
        )
        for project_name in invalid_names:
            with self.subTest(project_name=project_name):
                self.write_env(project_name=project_name)
                self.set_state()
                self.clear_events()
                result = self.run_wrapper("up", "--detach")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.events(), [])

    def test_hostile_sentinel_project_labels_never_reach_compose_mutation(self):
        hostile_labels = (
            "--version", "BackupSheep", "backupsheep\nforeign",
            "backupsheep\n", "backupsheep\x00", "backupsheepé",
            "backupsheep__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__",
        )
        for project_label in hostile_labels:
            with self.subTest(project_label=repr(project_label)):
                sentinel = self.sentinel()
                sentinel["labels"]["com.docker.compose.project"] = project_label
                self.set_state(volumes={"sentinel": sentinel})
                self.clear_events()
                result = self.run_wrapper("up")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.raw_events("volume", "create"), [])
                self.assertEqual(self.compose_events("up"), [])

    def test_exact_name_resource_project_control_bytes_are_refused(self):
        for project_label in ("backupsheep\n", "backupsheep\x00"):
            for resource_kind in ("network", "volume"):
                with self.subTest(
                    project_label=repr(project_label), resource_kind=resource_kind
                ):
                    sentinel = self.sentinel()
                    if resource_kind == "network":
                        resource = {
                            "labels": {
                                "com.docker.compose.project": project_label,
                                "com.docker.compose.network": "app-database",
                            },
                            "name": "backupsheep_app-database",
                        }
                        self.set_state(
                            networks={"hostile": resource},
                            volumes={"sentinel": sentinel},
                        )
                    else:
                        resource = self.owned_volume("postgres_data_v1")
                        resource["labels"]["com.docker.compose.project"] = project_label
                        self.set_state(
                            volumes={"sentinel": sentinel, "hostile": resource}
                        )
                    self.clear_events()
                    result = self.run_wrapper("up")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.raw_events("volume", "create"), [])
                    self.assertEqual(self.compose_events("up"), [])

    def test_option_shaped_logical_labels_cannot_bypass_membership_checks(self):
        hostile_resources = {
            "container": {
                "containers": {
                    "hostile": self.owned_container("--version"),
                },
                "volumes": {"sentinel": self.sentinel()},
            },
            "network": {
                "networks": {
                    "hostile": {
                        "labels": {
                            "com.docker.compose.project": "backupsheep",
                            "com.docker.compose.network": "--version",
                            "com.backupsheep.installation-id": INSTALLATION_ID,
                        },
                        "name": "backupsheep_--version",
                    }
                },
                "volumes": {"sentinel": self.sentinel()},
            },
            "volume": {
                "volumes": {
                    "sentinel": self.sentinel(),
                    "hostile": {
                        "labels": self.labels("volume", "--version"),
                        "name": "backupsheep_--version",
                    },
                }
            },
        }
        for resource_kind, state in hostile_resources.items():
            with self.subTest(resource_kind=resource_kind):
                self.set_state(**state)
                self.clear_events()
                result = self.run_wrapper("up")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unexpected", result.stderr)
                self.assertEqual(self.raw_events("volume", "create"), [])
                self.assertEqual(self.compose_events("up"), [])

    def test_egress_policy_generation_two_is_required_before_any_compose_call(self):
        for value in (None, "''", "'1'", "'3'", "'public'", "'2 '"):
            with self.subTest(value=value):
                self.write_env(egress_generation_value=value)
                self.clear_events()
                self.assert_refused(
                    ("config", "--quiet"),
                    "reviewed fail-closed value 2",
                )
                self.assertEqual(self.events(), [])

    def test_fresh_mutation_creates_a_labeled_identity_sentinel(self):
        self.run_wrapper("up", "--detach", check=True)
        self.assertEqual(
            self.state()["volumes"],
            {"backupsheep_installation_identity": self.sentinel()},
        )
        create_events = self.raw_events("volume", "create")
        self.assertEqual(len(create_events), 1)
        arguments = create_events[0]["argv"]
        self.assertIn(f"com.backupsheep.installation-id={INSTALLATION_ID}", arguments)
        self.assertEqual(arguments[-1], "backupsheep_installation_identity")

    def test_dry_run_before_or_after_subcommand_never_creates_sentinel(self):
        for arguments in (("--dry-run", "up"), ("up", "--dry-run")):
            with self.subTest(arguments=arguments):
                self.set_state()
                self.clear_events()
                self.run_wrapper(*arguments, check=True)
                self.assertEqual(self.state()["volumes"], {})
                self.assertEqual(self.raw_events("volume", "create"), [])

    def test_profile_value_cannot_masquerade_as_structural_dry_run(self):
        self.write_env(generation_value="''")
        self.set_state()
        self.assert_refused(
            ("--profile", "--dry-run", "up"),
            "only reviewed Compose profile is operations",
        )
        self.assertEqual(self.state()["volumes"], {})
        self.assertEqual(self.raw_events("volume", "create"), [])

        self.clear_events()
        self.run_wrapper("--profile", "operations", "up", check=True)
        self.assertIn("backupsheep_installation_identity", self.state()["volumes"])
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "'4.3'"
        )

    def test_exact_name_unlabeled_network_or_volume_collision_is_refused(self):
        collisions = (
            ("networks", {"foreign": {"labels": {}, "name": "backupsheep_app-database"}},
             "Docker network backupsheep_app-database collides"),
            ("volumes", {"foreign": {"labels": {}, "name": "backupsheep_pgdata"}},
             "Docker volume backupsheep_pgdata collides"),
        )
        for collection, resources, message in collisions:
            with self.subTest(collection=collection):
                self.set_state(**{collection: resources})
                self.assert_refused(("up",), message)
                self.assertNotIn("backupsheep_installation_identity", self.state()["volumes"])

    def test_labeled_network_and_volume_collisions_require_exact_runtime_policy(self):
        network = {
            "labels": self.labels("network", "app-database"),
            "name": "backupsheep_app-database",
            "runtime_policy": "bridge|false|true|false|0||default|0",
        }
        self.set_state(
            networks={"network": network},
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(("up",), "unsafe driver, namespace, attachment, option, or IPAM")

        network["runtime_policy"] = "bridge|true|false|false|0||default|0"
        network["ipam_policy"] = "1|172.30.0.0/16|172.30.1.0/24|172.30.0.1|1"
        self.set_state(
            networks={"network": network},
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(("up",), "unsafe or ambiguous IPAM allocation")

        sentinel = self.sentinel()
        sentinel["runtime_policy"] = "local|3|local|/"
        self.set_state(volumes={"sentinel": sentinel})
        self.assert_refused(("up",), "unsafe driver, bind option, scope, or mountpoint")

    def test_owned_network_rejects_a_foreign_attached_endpoint(self):
        endpoint_id = "9" * 64
        network = {
            "labels": self.labels("network", "app-database"),
            "name": "backupsheep_app-database",
            "id": "a" * 64,
            "network_endpoints": (
                f"{endpoint_id}|foreign-endpoint|{'b' * 64}|02:42:ac:1e:00:02|"
                "172.30.0.2/16|"
            ),
        }
        foreign = {
            "name": "foreign-endpoint",
            "labels": {
                "com.docker.compose.project": "foreign",
                "com.docker.compose.service": "app",
                "com.docker.compose.project.working_dir": str(self.root.resolve()),
                "com.backupsheep.installation-id": INSTALLATION_ID,
            },
        }
        self.set_state(
            containers={endpoint_id: foreign},
            networks={"network": network},
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(("up",), "foreign or wrong-installation endpoint")

    def test_owned_network_rejects_a_missing_expected_endpoint(self):
        network = {
            "labels": self.labels("network", "app-database"),
            "name": "backupsheep_app-database",
            "id": "a" * 64,
            "network_endpoints": "",
        }
        guard = self.owned_guard("app-egress-guard")
        guard["id"] = "9" * 64
        self.set_state(
            containers={"guard": guard},
            networks={"network": network},
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "complete endpoint set differs from the reviewed existing-container topology",
        )

    def test_container_reads_and_mutations_require_exact_runtime_and_config_hash(self):
        guard = self.owned_guard("app-egress-guard")
        guard["runtime_policy"] = "0:0|true|false|host|host|host|1|1|always|host"
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "unsafe user, privilege, namespace, device, port, rootfs, or restart runtime",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["cap_add"] = "CHOWN\nNET_ADMIN\nSYS_ADMIN"
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "capability or no-new-privileges policy drifted",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["labels"]["com.docker.compose.config-hash"] = "0" * 64
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "not created from the exact reviewed rendered configuration",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["attached_networks"] = (
            "backupsheep_app-broker\nbackupsheep_app-database\n"
            "backupsheep_app-egress\nforeign_admin"
        )
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "extra, missing, or foreign network attachment",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["resource_policy"] = "32|67108864|250000000|67108864|false|1"
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "drifted PID, memory, swap, CPU, OOM, shared-memory, init, or ulimit controls",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["resource_policy"] = (
            "32|67108864|0|67108864|0|250000000|67108864|false|false|0|3"
        )
        guard["ulimits"] = "core | 0 | 0\nnofile | 128 | 128\nnproc | 256 | 256"
        self.set_state(
            containers={"guard": guard},
            volumes={"sentinel": self.sentinel()},
        )
        self.run_wrapper("logs", "app-egress-guard", check=True)

        guard = self.owned_guard("app-egress-guard")
        guard["resource_policy"] = (
            "32|67108864|0|67108864|0|250000000|67108864|false|false|0|3"
        )
        guard["ulimits"] = "core | 0 | 0\nnofile | 128 | 128\nrtprio | 99 | 99"
        self.set_state(
            containers={"guard": guard},
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "unsafe daemon-default ulimits",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["resource_policy"] = (
            "32|67108864|0|134217728|0|250000000|67108864|false|false|0|2"
        )
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "drifted PID, memory, swap, CPU, OOM, shared-memory, init, or ulimit controls",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["resource_zero_policy"] = "host.slice|1024|100000|50000|0|0|||500|1|0|0|0|0|1|0|0|0|0"
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "unreviewed cgroup parent, CPU, block-I/O, storage, or Windows resource control",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["host_boundary"] = "1|0|host|host|kata|1|1|1|1|1|1|1|true|true"
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "unreviewed device, user/UTS namespace, runtime, sysctl, DNS, host, link, volume-from, or publication",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["group_add"] = "0"
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "supplementary group boundary drifted",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["mounts"] = "bind||/|/host|true|rprivate|ro"
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "unreviewed or writable host bind mount",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["tmpfs_policy"] = (
            "/run/backupsheep-egress|rw,exec,suid,dev,size=1m,mode=0777,uid=0,gid=0"
        )
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "tmpfs targets or security options drifted",
        )

        guard = self.owned_guard("app-egress-guard")
        app = self.owned_container("app", state="running")
        app["host_mounts"] = (
            "volume|backupsheep_installation_identity|"
            "/run/backupsheep-installation|true|true|false||0|false|false|false|false"
        )
        self.set_state(
            containers={"guard": guard, "app": app},
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(
            ("logs", "app"),
            "unsafe mount-create volume, NoCopy, subpath, label, driver, bind, tmpfs, cluster, or image options",
        )

        app["host_mounts"] = (
            "volume|backupsheep_installation_identity|"
            "/run/backupsheep-installation|true|true|true||1|true|false|false|false"
        )
        self.set_state(
            containers={"guard": guard, "app": app},
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(
            ("logs", "app"),
            "unsafe mount-create volume, NoCopy, subpath, label, driver, bind, tmpfs, cluster, or image options",
        )

        guard = self.owned_guard("app-egress-guard")
        guard["port_binding"] = "1|0.0.0.0|8000"
        self.set_state(containers={"guard": guard})
        self.assert_refused(
            ("logs", "app-egress-guard"),
            "exact reviewed loopback publication",
        )

    def test_core_and_guard_services_have_exact_singleton_cardinality(self):
        for service, factory in (
            ("db", self.owned_container),
            ("app-egress-guard", self.owned_guard),
            ("beat", self.owned_container),
        ):
            with self.subTest(service=service):
                self.set_state(
                    containers={
                        "first": factory(service),
                        "second": factory(service),
                    },
                    volumes={"sentinel": self.sentinel()},
                )
                self.assert_refused(
                    ("logs", service),
                    f"Compose service {service} exceeds its exact reviewed container cardinality",
                )

    def test_runtime_config_cannot_hide_behind_copied_compose_labels(self):
        attacks = (
            (
                {"config_env": [
                    "PATH=/usr/bin",
                    "BACKUPSHEEP_TEST_SERVICE=app-egress-guard",
                    "LD_PRELOAD=/evil.so",
                ]},
                "configured environment differs",
            ),
            (
                {"config_env": [
                    "PATH=/usr/bin",
                    "BACKUPSHEEP_TEST_SERVICE=app-egress-guard",
                    "PATH=/attacker",
                ]},
                "duplicate keys",
            ),
            ({"config_cmd": ["/bin/sh", "-c", "malicious"]}, "configured command differs"),
            ({"config_entrypoint": ["/bin/sh"]}, "configured entrypoint differs"),
            (
                {"config_healthcheck": {
                    "Test": ["CMD-SHELL", "exit 0"],
                    "Interval": 10_000_000_000,
                    "Timeout": 3_000_000_000,
                    "Retries": 5,
                    "StartPeriod": 10_000_000_000,
                    "StartInterval": 0,
                }},
                "healthcheck command differs",
            ),
            ({"log_config": "syslog|1|||"}, "logging driver or rotation policy differs"),
            ({"config_working_dir": "/code/_storage"}, "working directory differs"),
            ({"config_stop_signal": "SIGKILL"}, "stop signal differs"),
            ({"config_stop_timeout": 1}, "stop timeout differs"),
            ({"config_shell": ["/bin/true", "-c"]}, "command shell differs"),
            ({"console_policy": "false|false|false|false|false|true"}, "disables audited output"),
            ({"console_policy": "true|false|false|false|true|true"}, "unreviewed console mode"),
            ({"image_id": "sha256:" + ("9" * 64)}, "exact reviewed local image reference and ID"),
        )
        for state, message in attacks:
            with self.subTest(state=state):
                self.set_state(
                    containers={
                        "guard": self.owned_guard("app-egress-guard", **state)
                    },
                    volumes={"sentinel": self.sentinel()},
                )
                self.assert_refused(("logs", "app-egress-guard"), message)

        rabbit = self.owned_container("rabbitmq", state="running")
        rabbit["config_hostname"] = "attacker-node"
        self.set_state(
            containers={"rabbit": rabbit},
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(
            ("logs", "rabbitmq"),
            "hostname differs from the exact reviewed identity",
        )

    def test_nondefault_reviewed_stop_grace_period_is_bound_to_runtime_seconds(self):
        self.write_env(
            additional_lines=(
                "BACKUPSHEEP_STOP_GRACE_PERIOD='7s'",
                "POSTGRES_STOP_GRACE_PERIOD='2m'",
                "RABBITMQ_STOP_GRACE_PERIOD='1h'",
            )
        )
        for service, expected in (("app", 7), ("db", 120), ("rabbitmq", 3600)):
            with self.subTest(service=service):
                container = self.owned_container(service, state="running")
                container["config_stop_timeout"] = expected
                containers = {service: container}
                if service == "app":
                    container["network_mode"] = "container:guard"
                    containers["guard"] = self.owned_guard("app-egress-guard")
                self.set_state(
                    containers=containers,
                    volumes={"sentinel": self.sentinel()},
                )
                self.run_wrapper("logs", service, check=True)

    def test_stranded_non_egress_oneoff_is_rejected_before_project_access(self):
        self.set_state(
            containers={"oneoff": self.owned_oneoff("migrate", state="exited")},
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(
            ("logs", "migrate"),
            "stranded one-off container for migrate",
        )

    def test_service_cannot_substitute_another_roles_secret_with_same_mount_count(self):
        guard = self.owned_guard("app-egress-guard")
        app = self.owned_container("app", state="running")
        secret_names = (
            "django_secret_key", "db_bootstrap_password", "rabbitmq_app_password",
            "celery_signing_app_private_key", "celery_trusted_public_keys",
            "onboarding_token",
        )
        mounts = [
            f"bind||{self.root.resolve() / '.secrets' / name}|/run/secrets/{name}|false|rprivate|ro"
            for name in secret_names
        ]
        mounts.extend(
            (
                "volume|backupsheep_installation_identity|/var/lib/docker/volumes/backupsheep_installation_identity/_data|/run/backupsheep-installation|false||",
                "tmpfs|||/tmp|true||",
                "tmpfs|||/run/backupsheep|true||",
            )
        )
        app["mounts"] = "\n".join(mounts)
        self.set_state(
            containers={"guard": guard, "app": app},
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(
            ("logs", "app"),
            "does not mount its exact reviewed secret set",
        )

    def test_existing_resources_require_one_matching_identity_sentinel(self):
        self.set_state(volumes={"sentinel": self.sentinel(OTHER_INSTALLATION_ID)})
        self.assert_refused(
            ("up",), "ownership sentinel belongs to a different BackupSheep installation"
        )
        self.set_state(
            volumes={"database": self.owned_volume("postgres_data_v1")}
        )
        self.assert_refused(
            ("up",),
            "existing Compose resources require exactly one matching installation-identity sentinel",
        )

    def test_exact_owned_retired_ssh_trust_volume_is_detached_rollback_evidence(self):
        self.set_state(
            volumes={
                "sentinel": self.sentinel(),
                "retired-trust": self.owned_volume("ssh_trust", installation_id=None),
            }
        )
        self.run_wrapper(*APP_PAIR_UP, check=True)
        attachment_checks = [
            event
            for event in self.raw_events("ps")
            if "volume=backupsheep_ssh_trust" in event["argv"]
        ]
        self.assertEqual(len(attachment_checks), 2)
        self.assertTrue(all("--all" in event["argv"] for event in attachment_checks))

        self.set_state(
            volumes={
                "sentinel": self.sentinel(),
                "retired-trust": self.owned_volume("ssh_trust", OTHER_INSTALLATION_ID),
            }
        )
        self.assert_refused(
            APP_PAIR_UP,
            "ssh_trust belongs to a different BackupSheep installation",
        )

        self.set_state(
            volumes={
                "retired-trust": self.owned_volume("ssh_trust", installation_id=None),
            }
        )
        self.assert_refused(
            APP_PAIR_UP,
            "exactly one matching installation-identity sentinel",
        )
        self.assertNotIn("backupsheep_installation_identity", self.state()["volumes"])

        self.set_state(
            volumes={
                "foreign": {
                    "labels": {},
                    "name": "backupsheep_ssh_trust",
                },
            }
        )
        self.assert_refused(
            APP_PAIR_UP,
            "collides with the retired BackupSheep trust volume",
        )

        for state in ("running", "exited"):
            with self.subTest(attached_container_state=state):
                self.set_state(
                    containers={
                        "foreign-container": {
                            "labels": {},
                            "name": "foreign-container",
                            "state": state,
                            "volumes": ["backupsheep_ssh_trust"],
                        },
                    },
                    volumes={
                        "sentinel": self.sentinel(),
                        "retired-trust": self.owned_volume(
                            "ssh_trust", installation_id=None
                        ),
                    },
                )
                self.assert_refused(
                    APP_PAIR_UP,
                    "still has attached containers",
                )

    def test_exact_owned_retired_pgdata_is_detached_rollback_evidence(self):
        for storage_intent in (
            "migrated-debian-v1",
            "migrated-debian-generation2-v1",
        ):
            with self.subTest(storage_intent=storage_intent):
                self.write_env(
                    postgres_storage_generation="18-alpine-icu-v1",
                    postgres_storage_intent=storage_intent,
                )
                self.set_state(
                    volumes={
                        "sentinel": self.sentinel(),
                        "database": self.owned_volume("postgres_data_v1"),
                        "retired-pgdata": self.owned_volume(
                            "pgdata", installation_id=None
                        ),
                    }
                )
                self.event_log.unlink(missing_ok=True)
                self.run_wrapper(*APP_PAIR_UP, check=True)
                attachment_checks = [
                    event
                    for event in self.raw_events("ps")
                    if "volume=backupsheep_pgdata" in event["argv"]
                ]
                self.assertEqual(len(attachment_checks), 2)
                self.assertTrue(
                    all("--all" in event["argv"] for event in attachment_checks)
                )

    def test_verified_sentinel_allows_only_exact_path_blank_identity_legacy_containers(self):
        legacy_app = self.owned_container("app", installation_id=None)
        self.set_state(
            containers={
                "legacy-app": legacy_app,
                "owned-guard": self.owned_guard("app-egress-guard"),
            },
            volumes={"sentinel": self.sentinel()},
        )
        self.run_wrapper(*APP_PAIR_UP, check=True)

        for drift, expected_message in (
            ("working_dir", "different installation path"),
            ("config_files", "different model"),
            ("service", "unexpected service container"),
        ):
            with self.subTest(drift=drift):
                labels = dict(legacy_app["labels"])
                if drift == "working_dir":
                    labels["com.docker.compose.project.working_dir"] = "/srv/foreign"
                elif drift == "config_files":
                    labels["com.docker.compose.project.config_files"] = "/srv/foreign.yml"
                else:
                    labels["com.docker.compose.service"] = "foreign"
                self.set_state(
                    containers={"legacy-app": {**legacy_app, "labels": labels}},
                    volumes={"sentinel": self.sentinel()},
                )
                self.assert_refused(
                    APP_PAIR_UP, expected_message
                )

        self.set_state(
            containers={
                "legacy-app": legacy_app,
                "owned-guard": self.owned_guard("app-egress-guard"),
            },
            volumes={"sentinel": self.sentinel(OTHER_INSTALLATION_ID)},
        )
        self.assert_refused(
            APP_PAIR_UP,
            "ownership sentinel belongs to a different BackupSheep installation",
        )

    def test_blank_identity_legacy_rabbit_requires_exact_source_adoption(self):
        self.write_env(generation_value="''")
        overlay = self.rabbit_overlay()
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="3.13.7",
            installation_id=None,
        )
        self.assert_refused(
            (
                "--approved-compose-file", str(overlay),
                "--allow-rabbitmq-generation-transition=4.2",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "outside the exact 3.13 adoption or 4.2 target history",
        )

        self.prepare_legacy_rabbit_source()
        ledger = (self.root / ".backupsheep-rabbitmq-transition-state").read_text(
            encoding="utf-8"
        )
        self.assertIn("phase=attested\n", ledger)
        self.assertIn("source_class=3.13.7\n", ledger)

    def test_legacy_rabbit_volume_blocks_broad_up_and_option_value_decoys(self):
        self.write_env(generation_value="''")
        self.set_state(
            volumes={
                "sentinel": self.sentinel(),
                "rabbit-data": self.owned_volume("rabbitmq_data"),
            }
        )
        commands = (
            ("up",),
            ("up", "--attach", "db"),
            ("up", "--exit-code-from", "migrate"),
        )
        for arguments in commands:
            with self.subTest(arguments=arguments):
                self.assert_refused(
                    arguments, "existing RabbitMQ volume has no proven 4.3 generation"
                )

    def test_no_deps_one_off_worker_avoids_broker_but_dependency_run_is_gated(self):
        self.write_env(generation_value="''")
        self.set_state(
            containers={
                "guard": self.owned_guard("storage-egress-guard"),
            },
            volumes={
                "sentinel": self.sentinel(),
                "rabbit-data": self.owned_volume("rabbitmq_data"),
            }
        )
        self.run_wrapper(
            "run", "--rm", "--no-deps", "worker-storage", "sh", "-ceu", "true",
            check=True,
        )
        self.assertTrue(self.compose_events("run"))
        self.clear_events()
        self.assert_refused(
            ("run", "--rm", "worker-storage", "sh", "-ceu", "true"),
            "must include --no-deps",
        )

    def test_fresh_broad_up_records_generation_but_paired_no_deps_app_does_not(self):
        self.write_env(generation_value="''")
        self.set_state()
        self.run_wrapper("up", check=True)
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "'4.3'"
        )
        self.assertEqual(
            sum(
                line.startswith("BACKUPSHEEP_RABBITMQ_DATA_GENERATION=")
                for line in self.env_file.read_text(encoding="utf-8").splitlines()
            ),
            1,
        )

        self.write_env(generation_value="''")
        self.set_state()
        self.clear_events()
        self.run_wrapper(*APP_PAIR_UP, check=True)
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "''"
        )
        self.assertIn(
            "backupsheep_installation_identity", self.state()["volumes"]
        )

    def test_rabbit_transition_flag_has_exact_scope_and_overlay_pairing(self):
        rabbit = self.rabbit_overlay()
        self.assert_refused(
            ("--allow-rabbitmq-generation-transition=4.1", "up"),
            "transition target must be exactly 4.2 or 4.3",
        )
        self.assert_refused(
            (
                "--allow-rabbitmq-generation-transition=4.2",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "4.2 transition requires the exact reviewed RabbitMQ overlay",
        )
        self.assert_refused(
            (
                "--approved-compose-file", str(rabbit),
                "--allow-rabbitmq-generation-transition=4.3",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "4.3 transition must use the pinned base model",
        )
        self.assert_refused(
            (
                "--approved-compose-file", str(rabbit),
                "--allow-rabbitmq-generation-transition=4.2",
                "up", "--no-deps", "--detach", "rabbitmq",
            ),
            "transition flag is scoped to",
        )
        self.assert_refused(
            ("--approved-compose-file", str(rabbit), "up", "--detach"),
            "compatibility overlay may mutate only through",
        )

    def test_signed_release_refuses_every_rabbitmq_generation_transition_before_docker(self):
        self.write_env(
            generation_value="''",
            image_mode="signed-release",
        )
        for target in ("4.2", "4.3"):
            with self.subTest(target=target):
                self.clear_events()
                refused = self.run_wrapper(
                    f"--allow-rabbitmq-generation-transition={target}",
                    "up", "--detach", "--no-deps", "rabbitmq",
                )
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn("signed-release mode is fresh-only", refused.stderr)
                self.assertEqual(self.events(), [])
        self.clear_events()
        refused = self.run_wrapper(
            "--prepare-rabbitmq-3.13-source",
            "up", "--detach", "--no-deps", "rabbitmq",
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("signed-release mode is fresh-only", refused.stderr)
        self.assertEqual(self.events(), [])

    def test_preexisting_local_rabbit_image_without_ledger_is_sanitized_rebuilt(self):
        self.write_env(generation_value="''")
        self.set_state(
            volumes={
                "sentinel": self.sentinel(),
                "rabbit-data": self.owned_volume("rabbitmq_data"),
            }
        )

        self.run_wrapper(
            "--prepare-rabbitmq-3.13-source",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )

        build_events = self.compose_events("build")
        self.assertEqual(len(build_events), 1)
        build_arguments = build_events[0]["argv"]
        self.assertEqual(
            build_arguments[-4:],
            ["build", "--pull", "--no-cache", "rabbitmq"],
        )
        self.assertEqual(
            [
                build_arguments[index + 1]
                for index, argument in enumerate(build_arguments)
                if argument == "-f"
            ],
            [str(self.base_file.resolve()), str(self.rabbit_source_overlay().resolve())],
        )
        for key in (
            "BACKUPSHEEP_IMAGE_MODE",
            "BACKUPSHEEP_RABBITMQ_IMAGE",
            "BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE",
            "BACKUPSHEEP_RABBITMQ_LEGACY_SOURCE_IMAGE",
            "COMPOSE_FILE",
            "COMPOSE_PROFILES",
        ):
            self.assertEqual(build_events[0]["env"][key], "<unset>", key)

    def test_valid_42_transition_uses_base_then_rabbit_model_history(self):
        rabbit = self.rabbit_overlay()
        self.prepare_legacy_rabbit_source()
        self.run_wrapper(
            "--approved-compose-file", str(rabbit),
            "--allow-rabbitmq-generation-transition=4.2",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )
        build_events = self.compose_events("build")
        self.assertEqual(len(build_events), 1)
        self.assertEqual(
            build_events[0]["argv"][-4:],
            ["build", "--pull", "--no-cache", "rabbitmq"],
        )
        self.assertEqual(
            [
                build_events[0]["argv"][index + 1]
                for index, argument in enumerate(build_events[0]["argv"])
                if argument == "-f"
            ],
            [str(self.base_file.resolve()), str(rabbit.resolve())],
        )
        target_up = self.compose_events("up")
        self.assertEqual(len(target_up), 1)
        self.assertEqual(
            [
                target_up[0]["argv"][index + 1]
                for index, argument in enumerate(target_up[0]["argv"])
                if argument == "-f"
            ],
            [str(self.base_file.resolve()), str(rabbit.resolve())],
        )
        uid_runs = [
            event for event in self.compose_events("run")
            if "rabbitmq-uid-transition" in event["argv"]
        ]
        self.assertEqual(len(uid_runs), 1)
        diagnostic = [
            event for event in self.raw_events("exec")
            if "server_version" in event["argv"]
        ]
        self.assertEqual(len(diagnostic), 2)
        for event in diagnostic:
            self.assertEqual(event["argv"][1:3], ["--user", "rabbitmq"])

    def test_exact_healthy_42_target_skips_recreation_but_completes_postflight(self):
        rabbit = self.rabbit_overlay()
        target_history = f"{self.base_file.resolve()},{rabbit.resolve()}"
        arguments = (
            "--approved-compose-file", str(rabbit),
            "--allow-rabbitmq-generation-transition=4.2",
            "up", "--detach", "--no-deps", "rabbitmq",
        )
        for phase in ("target-ready", "attested"):
            with self.subTest(phase=phase):
                self.write_env(generation_value="''")
                self.rabbit_transition_state(
                    config_files=target_history,
                    server_version="4.2.9",
                )
                if phase == "target-ready":
                    self.write_rabbit_transition_ledger(
                        phase="target-ready",
                        source_class="3.13.7",
                        target="4.2",
                    )
                self.clear_events()

                self.run_wrapper(*arguments, check=True)

                self.assertEqual(self.compose_events("build"), [])
                self.assertEqual(self.compose_events("up"), [])
                self.assertEqual(
                    [
                        event for event in self.compose_events("run")
                        if "rabbitmq-uid-transition" in event["argv"]
                    ],
                    [],
                )
                diagnostics = [
                    event for event in self.raw_events("exec")
                    if "server_version" in event["argv"]
                ]
                self.assertEqual(len(diagnostics), 2)
                ledger = (
                    self.root / ".backupsheep-rabbitmq-transition-state"
                ).read_text(encoding="utf-8")
                self.assertIn("phase=attested\n", ledger)
                self.assertIn("source_class=4.2.9\n", ledger)

    def test_matching_transition_ledger_requires_the_exact_local_image_id(self):
        rabbit = self.rabbit_overlay()
        target_history = f"{self.base_file.resolve()},{rabbit.resolve()}"
        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=target_history,
            server_version="4.2.9",
        )
        self.write_rabbit_transition_ledger(
            phase="attested",
            source_class="4.2.9",
            target="4.2",
            image_id="sha256:" + ("0" * 64),
        )
        self.clear_events()

        self.assert_refused(
            (
                "--approved-compose-file", str(rabbit),
                "--allow-rabbitmq-generation-transition=4.2",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "protected RabbitMQ transition image ID changed",
        )
        self.assertEqual(self.compose_events("build"), [])
        self.assertEqual(self.compose_events("up"), [])

    def test_nonhealthy_or_absent_exact_42_target_is_force_recreated(self):
        rabbit = self.rabbit_overlay()
        target_history = f"{self.base_file.resolve()},{rabbit.resolve()}"
        arguments = (
            "--approved-compose-file", str(rabbit),
            "--allow-rabbitmq-generation-transition=4.2",
            "up", "--detach", "--no-deps", "rabbitmq",
        )
        scenarios = (
            ("created", "created", ""),
            ("exited", "exited", ""),
            ("unhealthy", "running", "unhealthy"),
            ("absent", None, None),
        )
        for scenario, container_state, container_health in scenarios:
            with self.subTest(scenario=scenario):
                self.write_env(generation_value="''")
                if scenario == "absent":
                    self.set_state(
                        volumes={
                            "sentinel": self.sentinel(),
                            "rabbit-data": self.owned_volume("rabbitmq_data"),
                        }
                    )
                    self.write_rabbit_transition_ledger(
                        phase="attested",
                        source_class="4.2.9",
                        target="4.2",
                    )
                else:
                    self.rabbit_transition_state(
                        config_files=target_history,
                        server_version="4.2.9",
                        container_state=container_state,
                        container_health=container_health,
                    )
                self.clear_events()

                self.run_wrapper(*arguments, check=True)

                up_events = self.compose_events("up")
                self.assertEqual(len(up_events), 2)
                self.assertIn("--force-recreate", up_events[-1]["argv"])

    def test_each_rabbit_hop_refuses_a_disabled_non_khepri_stable_flag(self):
        rabbit = self.rabbit_overlay()
        cases = (
            (
                (
                    "--approved-compose-file", str(rabbit),
                    "--allow-rabbitmq-generation-transition=4.2",
                    "up", "--detach", "--no-deps", "rabbitmq",
                ),
                str(self.base_file.resolve()),
                "3.13.7",
                "experimental disabled",
            ),
            (
                (
                    "--allow-rabbitmq-generation-transition=4.3",
                    "up", "--detach", "--no-deps", "rabbitmq",
                ),
                f"{self.base_file.resolve()},{rabbit.resolve()}",
                "4.2.9",
                "stable enabled",
            ),
        )
        for arguments, config_files, version, khepri_columns in cases:
            with self.subTest(version=version):
                if version == "3.13.7":
                    self.prepare_legacy_rabbit_source()
                    state = self.state()
                    state["rabbitmq_feature_flags"] = (
                        "name stability state\n"
                        f"khepri_db {khepri_columns}\n"
                        "stream_queue stable disabled"
                    )
                    self.state_path.write_text(json.dumps(state), encoding="utf-8")
                else:
                    self.write_env(generation_value="''")
                    self.rabbit_transition_state(
                        config_files=config_files,
                        server_version=version,
                        feature_flags=(
                            "name stability state\n"
                            f"khepri_db {khepri_columns}\n"
                            "stream_queue stable disabled"
                        ),
                    )
                self.clear_events()
                self.assert_refused(
                    arguments, "stable/required flag is not enabled"
                )
                self.assertEqual(self.compose_events("up"), [])

    def test_313_with_experimental_khepri_enabled_requires_blue_green(self):
        rabbit = self.rabbit_overlay()
        self.prepare_legacy_rabbit_source()
        state = self.state()
        state["rabbitmq_feature_flags"] = (
            "name stability state\n"
            "khepri_db experimental enabled\n"
            "stream_queue stable enabled"
        )
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        self.assert_refused(
            (
                "--approved-compose-file", str(rabbit),
                "--allow-rabbitmq-generation-transition=4.2",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "blue-green migration",
        )
        self.assertEqual(self.compose_events("up"), [])

    def test_valid_43_transition_accepts_rabbit_history_and_parses_khepri_list(self):
        rabbit = self.rabbit_overlay()
        self.write_env(generation_value="''")
        rabbit_history = f"{self.base_file.resolve()},{rabbit.resolve()}"
        self.rabbit_transition_state(
            config_files=rabbit_history,
            server_version="4.2.9",
            feature_flags=(
                "name stability state\n"
                "classic_mirrored_queue_version stable enabled\n"
                "khepri_db stable enabled\n"
                "stream_queue stable enabled"
            ),
            compose_up_transition_result={
                "installation_id": INSTALLATION_ID,
                "server_version": "4.3.5",
                "feature_flags": (
                    "name stability state\n"
                    "khepri_db required enabled\n"
                    "new_in_43 stable disabled\n"
                    "required_flag required enabled"
                ),
            },
        )
        self.run_wrapper(
            "--allow-rabbitmq-generation-transition=4.3",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )
        up_events = self.compose_events("up")
        self.assertEqual(len(up_events), 2)
        transition_files = [
            up_events[0]["argv"][index + 1]
            for index, argument in enumerate(up_events[0]["argv"])
            if argument == "-f"
        ]
        self.assertEqual(
            transition_files,
            [
                str(self.base_file.resolve()),
                str((self.root / "deploy/rabbitmq/transition-4.3.compose.yml").resolve()),
            ],
        )
        canonical_files = [
            up_events[1]["argv"][index + 1]
            for index, argument in enumerate(up_events[1]["argv"])
            if argument == "-f"
        ]
        self.assertEqual(canonical_files, [str(self.base_file.resolve())])
        self.assertIn("--force-recreate", up_events[1]["argv"])
        feature_query = [
            event for event in self.raw_events("exec")
            if "list_feature_flags" in event["argv"]
        ]
        self.assertEqual(len(feature_query), 3)
        witness_commands = [
            event["argv"][-1]
            for event in self.raw_events("exec")
            if "/usr/local/bin/backupsheep-rabbitmq-volume-init" in event["argv"]
        ]
        self.assertEqual(
            witness_commands, ["finalize-transition", "verify", "verify"]
        )
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "'4.3'"
        )

    def test_exact_healthy_prepared_43_target_skips_only_transition_recreation(self):
        transition = self.root / "deploy/rabbitmq/transition-4.3.compose.yml"
        transition_history = f"{self.base_file.resolve()},{transition.resolve()}"
        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=transition_history,
            server_version="4.3.5",
            feature_flags=RABBITMQ_43_FEATURE_FLAGS,
        )
        self.write_rabbit_transition_ledger(
            phase="target-ready",
            source_class="4.2.9",
            target="4.3",
        )
        self.clear_events()

        self.run_wrapper(
            "--allow-rabbitmq-generation-transition=4.3",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )

        up_events = self.compose_events("up")
        self.assertEqual(len(up_events), 1)
        compose_files = [
            up_events[0]["argv"][index + 1]
            for index, argument in enumerate(up_events[0]["argv"])
            if argument == "-f"
        ]
        self.assertEqual(compose_files, [str(self.base_file.resolve())])
        self.assertIn("--force-recreate", up_events[0]["argv"])
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "'4.3'"
        )
        self.assertFalse(
            (self.root / ".backupsheep-rabbitmq-transition-state").exists()
        )

    def test_attested_canonical_43_pre_env_crash_replays_full_transition(self):
        transition = self.root / "deploy/rabbitmq/transition-4.3.compose.yml"
        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="4.3.5",
            feature_flags=RABBITMQ_43_FEATURE_FLAGS,
        )
        self.write_rabbit_transition_ledger(
            phase="attested",
            source_class="4.3.5",
            target="4.3",
        )
        self.clear_events()

        self.run_wrapper(
            "--allow-rabbitmq-generation-transition=4.3",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )

        up_events = self.compose_events("up")
        self.assertEqual(len(up_events), 2)
        transition_files = [
            up_events[0]["argv"][index + 1]
            for index, argument in enumerate(up_events[0]["argv"])
            if argument == "-f"
        ]
        self.assertEqual(
            transition_files,
            [str(self.base_file.resolve()), str(transition.resolve())],
        )
        canonical_files = [
            up_events[1]["argv"][index + 1]
            for index, argument in enumerate(up_events[1]["argv"])
            if argument == "-f"
        ]
        self.assertEqual(canonical_files, [str(self.base_file.resolve())])
        witness_commands = [
            event["argv"][-1]
            for event in self.raw_events("exec")
            if "/usr/local/bin/backupsheep-rabbitmq-volume-init" in event["argv"]
        ]
        self.assertEqual(
            witness_commands,
            ["verify", "finalize-transition", "verify", "verify"],
        )
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "'4.3'"
        )
        self.assertFalse(
            (self.root / ".backupsheep-rabbitmq-transition-state").exists()
        )

    def test_43_transition_failure_or_unverified_result_keeps_generation_blank(self):
        rabbit = self.rabbit_overlay()
        rabbit_history = f"{self.base_file.resolve()},{rabbit.resolve()}"
        scenarios = (
            (
                "compose-failure",
                {"compose_up_exit_code": 81},
                "",
            ),
            (
                "wrong-post-version",
                {
                    "compose_up_transition_result": {
                        "installation_id": INSTALLATION_ID,
                        "server_version": "4.2.9",
                    }
                },
                "not the pinned 4.3.5 target during the RabbitMQ 4.3 transition attestation",
            ),
            (
                "wrong-post-identity",
                {
                    "compose_up_transition_result": {
                        "installation_id": OTHER_INSTALLATION_ID,
                        "server_version": "4.3.5",
                    }
                },
                "different BackupSheep installation identity",
            ),
            (
                "ambiguous-post-khepri",
                {
                    "compose_up_transition_result": {
                        "installation_id": INSTALLATION_ID,
                        "server_version": "4.3.5",
                        "feature_flags": (
                            "khepri_db stable enabled\nkhepri_db stable enabled"
                        ),
                    }
                },
                "feature flags are ambiguous",
            ),
            (
                "wrong-post-image",
                {
                    "compose_up_transition_result": {
                        "installation_id": INSTALLATION_ID,
                        "server_version": "4.3.5",
                        "image_id": "sha256:" + ("d" * 64),
                    }
                },
                "not bound to the exact reviewed local image reference and ID",
            ),
        )
        for scenario, transition_options, expected_message in scenarios:
            with self.subTest(scenario=scenario):
                self.write_env(generation_value="''")
                self.rabbit_transition_state(
                    config_files=rabbit_history,
                    server_version="4.2.9",
                    **transition_options,
                )
                result = self.run_wrapper(
                    "--allow-rabbitmq-generation-transition=4.3",
                    "up", "--detach", "--no-deps", "rabbitmq",
                )
                self.assertNotEqual(result.returncode, 0)
                if expected_message:
                    self.assertIn(expected_message, result.stderr)
                self.assertEqual(
                    self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "''"
                )

    def test_43_target_and_canonical_gates_require_a_required_feature_row(self):
        rabbit = self.rabbit_overlay()
        rabbit_history = f"{self.base_file.resolve()},{rabbit.resolve()}"
        no_required_rows = "name stability state\nkhepri_db stable enabled"
        for failure_phase in ("target", "canonical"):
            with self.subTest(failure_phase=failure_phase):
                self.write_env(generation_value="''")
                self.rabbit_transition_state(
                    config_files=rabbit_history,
                    server_version="4.2.9",
                    feature_flags=(
                        "name stability state\n"
                        "khepri_db required enabled\n"
                        "stream_queue stable enabled"
                    ),
                    compose_up_transition_result=(
                        {"feature_flags": no_required_rows}
                        if failure_phase == "target"
                        else None
                    ),
                )
                if failure_phase == "canonical":
                    state = self.state()
                    state["canonical_compose_up_transition_result"] = {
                        "feature_flags": no_required_rows
                    }
                    self.state_path.write_text(json.dumps(state), encoding="utf-8")
                self.clear_events()
                self.assert_refused(
                    (
                        "--allow-rabbitmq-generation-transition=4.3",
                        "up", "--detach", "--no-deps", "rabbitmq",
                    ),
                    "stable/required flag is not enabled",
                )
                self.assertEqual(
                    self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "''"
                )

    def test_43_volume_witness_alone_never_authorizes_transition_recovery(self):
        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="4.3.5",
            feature_flags=RABBITMQ_43_FEATURE_FLAGS,
        )
        state = self.state()
        state["containers"]["rabbit-container"]["state"] = "exited"
        state["containers"]["rabbit-container"]["health"] = ""
        # Even a broker-volume witness that the networkless helper can resume is
        # not transition authority. Only protected host state may bridge a crash.
        state["rabbitmq_witness_resume_exit_code"] = 0
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        self.assert_refused(
            (
                "--allow-rabbitmq-generation-transition=4.3",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "exact interrupted RabbitMQ target lacks matching protected durable transition state",
        )
        self.assertEqual(self.compose_events("up"), [])
        self.assertEqual(self.compose_events("run"), [])
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "''"
        )

    def test_prepared_43_host_state_recovers_a_stopped_source_and_commits(self):
        self.write_env(generation_value="''")
        rabbit = self.rabbit_overlay()
        self.rabbit_transition_state(
            config_files=f"{self.base_file.resolve()},{rabbit.resolve()}",
            server_version="4.2.9",
            feature_flags=RABBITMQ_43_FEATURE_FLAGS,
            container_state="exited",
            container_health="",
        )
        prior_ledger = dict(
            line.split("=", 1)
            for line in (
                self.root / ".backupsheep-rabbitmq-transition-state"
            ).read_text(encoding="utf-8").splitlines()
        )
        self.write_rabbit_transition_ledger(
            phase="prepared",
            source_class="4.2.9",
            target="4.3",
            source_binding=prior_ledger["source_binding"],
        )
        self.run_wrapper(
            "--allow-rabbitmq-generation-transition=4.3",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )
        self.assertEqual(len(self.compose_events("up")), 3)
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "'4.3'"
        )
        self.assertFalse(
            (self.root / ".backupsheep-rabbitmq-transition-state").exists()
        )

    def test_attested_43_host_state_repairs_witness_before_absent_target_recreate(self):
        self.write_env(generation_value="''")
        self.rabbit_overlay()
        self.set_state(
            volumes={
                "sentinel": self.sentinel(),
                "rabbit-data": self.owned_volume("rabbitmq_data"),
            }
        )
        self.write_rabbit_transition_ledger(
            phase="attested", source_class="4.3.5", target="4.3"
        )
        self.run_wrapper(
            "--allow-rabbitmq-generation-transition=4.3",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )
        witness_repairs = [
            event for event in self.compose_events("run")
            if any("finalize-transition" in argument for argument in event["argv"])
        ]
        self.assertEqual(len(witness_repairs), 1)
        self.assertEqual(len(self.compose_events("up")), 3)
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "'4.3'"
        )

    def test_attested_43_reconciles_only_the_exact_stranded_witness_oneoff(self):
        self.write_env(generation_value="''")
        self.rabbit_overlay()
        helper_id = "7" * 64
        helper_name = "backupsheep-rabbitmq-transition-witness"
        self.set_state(
            containers={
                helper_id: {
                    "id": helper_id,
                    "name": helper_name,
                    "state": "exited",
                    "health": "",
                    "config_image": PINNED_RABBIT_IMAGE,
                    "image_id": PINNED_RABBIT_IMAGE_ID,
                    "labels": {
                        "com.docker.compose.project": "backupsheep",
                        "com.docker.compose.project.working_dir": str(self.root.resolve()),
                        "com.docker.compose.project.config_files": str(self.base_file.resolve()),
                        "com.docker.compose.service": "rabbitmq-volume-init",
                        "com.docker.compose.oneoff": "True",
                        "com.backupsheep.installation-id": INSTALLATION_ID,
                    },
                    "transition_helper_mounts": (
                        f"bind||{self.root.resolve()}/deploy/rabbitmq/volume-init.sh|"
                        "/usr/local/bin/backupsheep-rabbitmq-volume-init|false\n"
                        "volume|backupsheep_rabbitmq_data|"
                        "/var/lib/docker/volumes/backupsheep_rabbitmq_data/_data|"
                        "/var/lib/rabbitmq|true"
                    ),
                }
            },
            volumes={
                "sentinel": self.sentinel(),
                "rabbit-data": self.owned_volume("rabbitmq_data"),
            },
        )
        self.write_rabbit_transition_ledger(
            phase="attested", source_class="4.3.5", target="4.3"
        )
        self.run_wrapper(
            "--allow-rabbitmq-generation-transition=4.3",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )
        removals = [
            event for event in self.raw_events("container")
            if event["argv"][1:3] == ["rm", "--force"]
        ]
        self.assertEqual(len(removals), 1)
        self.assertEqual(removals[0]["argv"][-1], helper_id)

        # A near-match is never deleted before normal ownership rejects it.
        self.write_env(generation_value="''")
        self.set_state(
            containers={
                helper_id: {
                    "id": helper_id,
                    "name": helper_name,
                    "state": "exited",
                    "config_image": PINNED_RABBIT_IMAGE,
                    "image_id": PINNED_RABBIT_IMAGE_ID,
                    "labels": {
                        "com.docker.compose.project": "backupsheep",
                        "com.docker.compose.project.working_dir": str(self.root.resolve()),
                        "com.docker.compose.project.config_files": str(self.base_file.resolve()),
                        "com.docker.compose.service": "rabbitmq-volume-init",
                        "com.docker.compose.oneoff": "True",
                        "com.backupsheep.installation-id": INSTALLATION_ID,
                    },
                    "transition_helper_contract": "drifted",
                    "transition_helper_mounts": "",
                }
            },
            volumes={
                "sentinel": self.sentinel(),
                "rabbit-data": self.owned_volume("rabbitmq_data"),
            },
        )
        self.write_rabbit_transition_ledger(
            phase="attested", source_class="4.3.5", target="4.3"
        )
        self.clear_events()
        self.assert_refused(
            (
                "--allow-rabbitmq-generation-transition=4.3",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "command or isolation policy drifted",
        )
        self.assertEqual(
            [event for event in self.raw_events("container") if "rm" in event["argv"]],
            [],
        )

    def test_attested_42_without_container_must_recover_42_before_43(self):
        self.write_env(generation_value="''")
        rabbit = self.rabbit_overlay()
        self.set_state(
            volumes={
                "sentinel": self.sentinel(),
                "rabbit-data": self.owned_volume("rabbitmq_data"),
            }
        )
        self.write_rabbit_transition_ledger(
            phase="attested", source_class="4.2.9", target="4.2"
        )
        self.assert_refused(
            (
                "--allow-rabbitmq-generation-transition=4.3",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "must first be recreated with the reviewed 4.2 command",
        )
        self.assertEqual(self.compose_events("up"), [])

        self.clear_events()
        self.run_wrapper(
            "--approved-compose-file", str(rabbit),
            "--allow-rabbitmq-generation-transition=4.2",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )
        self.assertEqual(len(self.compose_events("up")), 2)
        ledger = (self.root / ".backupsheep-rabbitmq-transition-state").read_text(
            encoding="utf-8"
        )
        self.assertIn("phase=attested\n", ledger)
        self.assertIn("target_version=4.2.9\n", ledger)

    def test_43_transition_never_commits_env_before_witness_and_canonical_recreation(self):
        rabbit = self.rabbit_overlay()
        rabbit_history = f"{self.base_file.resolve()},{rabbit.resolve()}"
        for failure_key, expected_message in (
            (
                "rabbitmq_volume_finalize-transition_exit_code",
                "could not durably finalize the attested RabbitMQ 4.3 volume witness",
            ),
            (
                "canonical_compose_up_exit_code",
                "",
            ),
        ):
            with self.subTest(failure_key=failure_key):
                self.write_env(generation_value="''")
                self.rabbit_transition_state(
                    config_files=rabbit_history,
                    server_version="4.2.9",
                    feature_flags="name stability state\nkhepri_db stable enabled",
                )
                state = self.state()
                state[failure_key] = 83
                self.state_path.write_text(json.dumps(state), encoding="utf-8")
                self.clear_events()
                result = self.run_wrapper(
                    "--allow-rabbitmq-generation-transition=4.3",
                    "up", "--detach", "--no-deps", "rabbitmq",
                )
                self.assertNotEqual(result.returncode, 0)
                if expected_message:
                    self.assertIn(expected_message, result.stderr)
                self.assertEqual(
                    self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "''"
                )

    def test_exact_435_reconciliation_records_witness_but_newer_43_is_not_downgraded(self):
        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="4.3.5",
            feature_flags=RABBITMQ_43_FEATURE_FLAGS,
        )
        self.run_wrapper(
            "--allow-rabbitmq-generation-transition=4.3",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "'4.3'"
        )

        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="4.3.6",
            feature_flags=RABBITMQ_43_FEATURE_FLAGS,
        )
        self.clear_events()
        self.assert_refused(
            (
                "--allow-rabbitmq-generation-transition=4.3",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "does not report the pinned 4.3.5 server version",
        )
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "''"
        )

    def test_43_reconciliation_rejects_default_override_rabbit_image_substitution(self):
        override = self.root / "docker-compose.override.yml"
        override.write_text(
            "services:\n  rabbitmq:\n    image: attacker/rabbitmq:4.3.5\n",
            encoding="utf-8",
        )
        override.chmod(0o600)
        self.write_env(generation_value="''")
        config_history = f"{self.base_file.resolve()},{override.resolve()}"
        self.rabbit_transition_state(
            config_files=config_history,
            server_version="4.3.5",
            feature_flags="name stability state\nkhepri_db stable enabled",
            combined_rabbitmq_image=(
                "attacker/rabbitmq:4.3.5@sha256:" + ("e" * 64)
            ),
        )
        self.assert_refused(
            (
                "--approved-compose-file", str(override),
                "--allow-rabbitmq-generation-transition=4.3",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "combined RabbitMQ service must resolve to exactly one reviewed image",
        )
        self.assertEqual(self.compose_events("up"), [])
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "''"
        )

    def test_43_hop_attests_exact_isolated_429_overlay_image(self):
        rabbit = self.rabbit_overlay()
        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=f"{self.base_file.resolve()},{rabbit.resolve()}",
            server_version="4.2.9",
            feature_flags="name stability state\nkhepri_db stable enabled",
            container_image_id="sha256:" + ("9" * 64),
        )
        self.assert_refused(
            (
                "--allow-rabbitmq-generation-transition=4.3",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "not bound to the exact reviewed local image reference and ID",
        )
        self.assertEqual(self.compose_events("up"), [])
        self.assertEqual(self.compose_events("up"), [])

        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="4.3.5",
            feature_flags=RABBITMQ_43_FEATURE_FLAGS,
            container_image_id="sha256:" + ("d" * 64),
        )
        self.clear_events()
        self.assert_refused(
            (
                "--allow-rabbitmq-generation-transition=4.3",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "not bound to the exact reviewed local image reference and ID",
        )
        self.assertEqual(self.compose_events("up"), [])
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "''"
        )

    def test_43_transition_rejects_wrong_source_or_ambiguous_khepri_record(self):
        rabbit = self.rabbit_overlay()
        rabbit_history = f"{self.base_file.resolve()},{rabbit.resolve()}"
        scenarios = (
            (
                "4.1.9",
                "khepri_db stable enabled",
                "requires the exact attested healthy RabbitMQ 4.2.9 source",
            ),
            (
                "4.3.6",
                "khepri_db stable enabled",
                "requires the exact attested healthy RabbitMQ 4.2.9 source",
            ),
            (
                "4.2.9",
                "khepri_db stable enabled\nkhepri_db stable enabled",
                "feature flags are ambiguous",
            ),
            (
                "4.2.9",
                "khepri_db stable disabled",
                "stable/required flag is not enabled",
            ),
        )
        for server_version, feature_flags, message in scenarios:
            with self.subTest(server_version=server_version, feature_flags=feature_flags):
                self.write_env(generation_value="''")
                self.rabbit_transition_state(
                    config_files=rabbit_history,
                    server_version=server_version,
                    feature_flags=feature_flags,
                )
                self.assert_refused(
                    (
                        "--allow-rabbitmq-generation-transition=4.3",
                        "up", "--detach", "--no-deps", "rabbitmq",
                    ),
                    message,
                )

    def test_start_restart_and_unpause_cannot_resume_pre_hardening_containers(self):
        self.write_env(generation_value="''")
        self.set_state(
            volumes={
                "sentinel": self.sentinel(),
                "rabbit-data": self.owned_volume("rabbitmq_data"),
            }
        )
        for arguments in (
            ("start", "app"),
            ("restart", "--no-deps", "app"),
            ("unpause", "app"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "can resume a pre-hardening container")
        self.assertEqual(self.compose_events("start"), [])
        self.assertEqual(self.compose_events("restart"), [])
        self.assertEqual(self.compose_events("unpause"), [])

    def test_mutations_are_serialized_while_read_only_commands_remain_concurrent(self):
        wait_path = self.root / "hold-compose-up"
        entered_path = self.root / "compose-up-entered"
        wait_path.write_text("hold\n", encoding="utf-8")
        self.set_state(
            blocked_compose_command="up",
            compose_wait_path=str(wait_path),
            compose_entered_path=str(entered_path),
        )
        first = subprocess.Popen(
            [str(self.wrapper), "up", "--detach"],
            cwd=self.root,
            env=self.wrapper_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 10
            while not entered_path.exists() and time.monotonic() < deadline:
                if first.poll() is not None:
                    stdout, stderr = first.communicate()
                    self.fail(
                        f"first mutating wrapper exited before its hold point: "
                        f"{first.returncode}\n{stdout}\n{stderr}"
                    )
                time.sleep(0.02)
            self.assertTrue(entered_path.exists(), "first wrapper never reached Compose up")

            lock_dir = Path(f"{self.root.resolve()}.backupsheep-mutation-lock")
            self.assertTrue(lock_dir.is_dir())
            refused = self.run_wrapper("up", "--detach")
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("installer/wrapper mutation is active", refused.stderr)

            # Observability and a structural dry-run do not contend with the writer.
            self.run_wrapper("config", "--quiet", check=True)
            self.run_wrapper("--dry-run", "up", "--detach", check=True)
        finally:
            wait_path.unlink(missing_ok=True)
            if first.poll() is None:
                first.wait(timeout=10)
        stdout, stderr = first.communicate()
        self.assertEqual(first.returncode, 0, f"{stdout}\n{stderr}")
        self.assertFalse(
            Path(f"{self.root.resolve()}.backupsheep-mutation-lock").exists()
        )

    def test_direct_signals_terminate_compose_group_and_release_exact_lock(self):
        lock_dir = Path(f"{self.root.resolve()}.backupsheep-mutation-lock")
        for signal_number, expected in (
            (signal.SIGHUP, 129),
            (signal.SIGINT, 130),
            (signal.SIGTERM, 143),
        ):
            with self.subTest(signal=signal_number):
                wait_path = self.root / f"hold-compose-{signal_number}"
                entered_path = self.root / f"compose-entered-{signal_number}"
                pid_path = self.root / f"compose-pid-{signal_number}"
                wait_path.write_text("hold\n", encoding="utf-8")
                self.set_state(
                    blocked_compose_command="up",
                    compose_wait_path=str(wait_path),
                    compose_entered_path=str(entered_path),
                    compose_pid_path=str(pid_path),
                )
                process = subprocess.Popen(
                    [str(self.wrapper), "up", "--detach"],
                    cwd=self.root,
                    env=self.wrapper_environment(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                deadline = time.monotonic() + 10
                while (not entered_path.exists() or not pid_path.exists()) and time.monotonic() < deadline:
                    if process.poll() is not None:
                        stdout, stderr = process.communicate()
                        self.fail(f"wrapper exited before signal: {process.returncode}\n{stdout}\n{stderr}")
                    time.sleep(0.02)
                self.assertTrue(lock_dir.is_dir())
                child_pid = int(pid_path.read_text(encoding="utf-8").strip())
                process.send_signal(signal_number)
                stdout, stderr = process.communicate(timeout=12)
                self.assertEqual(process.returncode, expected, f"{stdout}\n{stderr}")
                self.assertFalse(lock_dir.exists())
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
                wait_path.unlink(missing_ok=True)

    def test_installer_lock_excludes_wrapper_mutation_but_not_observation(self):
        wait_path = self.root / "hold-installer-lock"
        entered_path = self.root / "installer-lock-entered"
        wait_path.write_text("hold\n", encoding="utf-8")
        holder_script = r'''
source "$1"
INSTALL_DIR="$2"
acquire_installation_mutation_lock
: > "$3"
while [[ -e "$4" ]]; do
    sleep 0.02
done
release_mutation_lock
'''
        holder = subprocess.Popen(
            [
                "bash",
                "-c",
                holder_script,
                "installer-lock-holder",
                str(INSTALLER),
                str(self.root.resolve()),
                str(entered_path),
                str(wait_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 10
            while not entered_path.exists() and time.monotonic() < deadline:
                if holder.poll() is not None:
                    stdout, stderr = holder.communicate()
                    self.fail(
                        "installer lock holder exited before its hold point: "
                        f"{holder.returncode}\n{stdout}\n{stderr}"
                    )
                time.sleep(0.02)
            self.assertTrue(entered_path.exists(), "installer never acquired its lock")

            refused = self.run_wrapper("up", "--detach")
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("installer/wrapper mutation is active", refused.stderr)
            self.run_wrapper("config", "--quiet", check=True)
        finally:
            wait_path.unlink(missing_ok=True)
            if holder.poll() is None:
                holder.wait(timeout=10)
        stdout, stderr = holder.communicate()
        self.assertEqual(holder.returncode, 0, f"{stdout}\n{stderr}")
        self.assertFalse(
            Path(f"{self.root.resolve()}.backupsheep-mutation-lock").exists()
        )

    def test_direct_installer_child_inherits_exact_lock_without_releasing_it(self):
        lock_dir = Path(f"{self.root.resolve()}.backupsheep-mutation-lock")
        script = r'''
source "$1"
INSTALL_DIR="$2"
acquire_installation_mutation_lock
"$3" --inherit-installer-lock up --detach
[[ -d "$MUTATION_LOCK_DIR" && "$(<"$MUTATION_LOCK_OWNER_FILE")" == "$MUTATION_LOCK_TOKEN" ]]
release_mutation_lock
'''
        result = subprocess.run(
            [
                "bash",
                "-c",
                script,
                "installer-inherited-lock",
                str(INSTALLER),
                str(self.root.resolve()),
                str(self.wrapper),
            ],
            cwd=self.root,
            env=self.wrapper_environment(),
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertFalse(lock_dir.exists())
        self.assertEqual(len(self.compose_events("up")), 1)

    def test_installer_volume_reconcile_is_locked_and_uses_exact_named_oneoff(self):
        refused = self.run_wrapper("--installer-reconcile-rabbitmq-volume")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("restricted to the locked installer child", refused.stderr)

        override = self.root / "docker-compose.override.yml"
        override.write_text("services: {}\n", encoding="utf-8")
        override.chmod(0o600)
        self.set_state(
            volumes={
                "rabbit": self.owned_volume("rabbitmq_data"),
                "sentinel": self.owned_volume("installation_identity"),
            }
        )
        lock_dir = Path(f"{self.root.resolve()}.backupsheep-mutation-lock")
        script = r'''
source "$1"
INSTALL_DIR="$2"
acquire_installation_mutation_lock
"$3" --inherit-installer-lock --installer-reconcile-rabbitmq-volume \
  --approved-compose-file "$4"
[[ -d "$MUTATION_LOCK_DIR" && "$(<"$MUTATION_LOCK_OWNER_FILE")" == "$MUTATION_LOCK_TOKEN" ]]
release_mutation_lock
'''
        result = subprocess.run(
            [
                "bash",
                "-c",
                script,
                "installer-rabbitmq-volume-reconcile",
                str(INSTALLER),
                str(self.root.resolve()),
                str(self.wrapper),
                str(override),
            ],
            cwd=self.root,
            env=self.wrapper_environment(),
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertFalse(lock_dir.exists())
        run_events = self.compose_events("run")
        self.assertEqual(len(run_events), 1)
        argv = run_events[0]["argv"]
        self.assertIn("--rm", argv)
        self.assertIn("--no-deps", argv)
        self.assertIn("--name", argv)
        self.assertIn("backupsheep-rabbitmq-transition-witness", argv)
        self.assertEqual(argv[-1], "rabbitmq-volume-init")

    def test_inherited_installer_lock_rejects_wrong_parent_and_extra_entries(self):
        lock_dir = Path(f"{self.root.resolve()}.backupsheep-mutation-lock")
        lock_dir.mkdir(mode=0o700)
        owner = lock_dir / "owner"
        owner.write_text(
            f"version=1;tool=install.sh;pid={os.getpid() + 1000};uid={os.geteuid()}\n",
            encoding="utf-8",
        )
        owner.chmod(0o600)
        wrong_parent = self.run_wrapper(
            "--inherit-installer-lock", "up", "--detach"
        )
        self.assertNotEqual(wrong_parent.returncode, 0)
        self.assertIn("does not name this direct child", wrong_parent.stderr)
        self.assertTrue(lock_dir.is_dir())

        owner.write_text(
            f"version=1;tool=install.sh;pid={os.getpid()};uid={os.geteuid()}\n",
            encoding="utf-8",
        )
        owner.chmod(0o600)
        extra = lock_dir / "unexpected"
        extra.write_text("x\n", encoding="utf-8")
        extra.chmod(0o600)
        unexpected = self.run_wrapper(
            "--inherit-installer-lock", "config", "--quiet"
        )
        self.assertNotEqual(unexpected.returncode, 0)
        self.assertIn("unexpected entry", unexpected.stderr)
        self.assertTrue(lock_dir.is_dir())

    def test_interrupted_inherited_child_never_releases_parent_installer_lock(self):
        lock_dir = Path(f"{self.root.resolve()}.backupsheep-mutation-lock")
        wait_path = self.root / "hold-inherited-compose"
        entered_path = self.root / "inherited-compose-entered"
        child_pid_path = self.root / "inherited-wrapper-pid"
        lock_survived_path = self.root / "inherited-lock-survived"
        wait_path.write_text("hold\n", encoding="utf-8")
        self.set_state(
            blocked_compose_command="up",
            compose_wait_path=str(wait_path),
            compose_entered_path=str(entered_path),
        )
        script = r'''
source "$1"
INSTALL_DIR="$2"
acquire_installation_mutation_lock
set +e
set -m
"$3" --inherit-installer-lock up --detach &
child=$!
set +m
printf '%s\n' "$child" > "$4"
wait "$child"
status=$?
if [[ -d "$MUTATION_LOCK_DIR" && "$(<"$MUTATION_LOCK_OWNER_FILE")" == "$MUTATION_LOCK_TOKEN" ]]; then
    : > "$5"
fi
release_mutation_lock
exit "$status"
'''
        holder = subprocess.Popen(
            [
                "bash",
                "-c",
                script,
                "installer-inherited-signal",
                str(INSTALLER),
                str(self.root.resolve()),
                str(self.wrapper),
                str(child_pid_path),
                str(lock_survived_path),
            ],
            cwd=self.root,
            env=self.wrapper_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 10
        while (
            not entered_path.exists() or not child_pid_path.exists()
        ) and time.monotonic() < deadline:
            if holder.poll() is not None:
                stdout, stderr = holder.communicate()
                self.fail(
                    f"installer holder exited before inherited child signal: "
                    f"{holder.returncode}\n{stdout}\n{stderr}"
                )
            time.sleep(0.02)
        self.assertTrue(lock_dir.is_dir())
        child_pid = int(child_pid_path.read_text(encoding="utf-8").strip())
        os.killpg(child_pid, signal.SIGTERM)
        try:
            stdout, stderr = holder.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(child_pid, signal.SIGKILL)
            holder.kill()
            stdout, stderr = holder.communicate(timeout=5)
            self.fail(f"inherited child did not terminate\n{stdout}\n{stderr}")
        self.assertEqual(holder.returncode, 143, f"{stdout}\n{stderr}")
        self.assertTrue(lock_survived_path.exists())
        self.assertFalse(lock_dir.exists())
        wait_path.unlink(missing_ok=True)

    def test_inherited_installer_lock_flag_order_and_duplication_fail_closed(self):
        for arguments in (
            ("config", "--inherit-installer-lock", "--quiet"),
            (
                "--inherit-installer-lock",
                "--inherit-installer-lock",
                "config",
                "--quiet",
            ),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_wrapper(*arguments)
                self.assertNotEqual(result.returncode, 0)

    def test_stale_or_malformed_mutation_lock_fails_closed_without_reaping(self):
        lock_dir = Path(f"{self.root.resolve()}.backupsheep-mutation-lock")
        lock_dir.mkdir(mode=0o700)
        owner = lock_dir / "owner"
        owner.write_text(
            "version=1;tool=backupsheep-compose;pid=999999;uid=0\n",
            encoding="utf-8",
        )
        owner.chmod(0o600)

        self.run_wrapper("config", "--quiet", check=True)
        result = self.run_wrapper("up", "--detach")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale fail-closed lock remains", result.stderr)
        self.assertTrue(lock_dir.is_dir())
        self.assertEqual(
            owner.read_text(encoding="utf-8"),
            "version=1;tool=backupsheep-compose;pid=999999;uid=0\n",
        )

    def test_wrapper_sets_private_umask_before_any_lock_or_file_work(self):
        source = self.wrapper.read_text(encoding="utf-8")
        self.assertLess(source.index("umask 077"), source.index("mutation_lock_dir="))

    def test_egress_lifecycle_requires_exact_force_recreated_pairs(self):
        for arguments, message in (
            (("up", "--detach", "--no-deps", "app"), "only with its paired guard"),
            (
                ("up", "--detach", "--no-deps", "app-egress-guard"),
                "only with its paired workload",
            ),
            (
                ("up", "--detach", "app-egress-guard", "app"),
                "requires both --force-recreate and --no-deps",
            ),
            (("attach", "app-egress-guard"), "signal proxying"),
            (("exec", "app-egress-guard", "kill", "1"), "exec is forbidden"),
            (("stop", "app-egress-guard"), "may not target an egress guard"),
            (("kill", "cloud-egress-guard"), "may not target an egress guard"),
            (("rm", "files-egress-guard"), "may not target an egress guard"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, message)

        self.set_state()
        self.clear_events()
        self.run_wrapper(*APP_PAIR_UP, check=True)
        pair_up = self.compose_events("up")[-1]["argv"]
        self.assertIn("--force-recreate", pair_up)
        self.assertIn("--no-deps", pair_up)
        self.assertIn("app-egress-guard", pair_up)
        self.assertIn("app", pair_up)

        self.set_state(
            containers={
                "guard": self.owned_container("app-egress-guard"),
                "app": self.owned_container("app"),
            },
            volumes={"sentinel": self.sentinel()},
        )
        self.assert_refused(
            ("up", "--detach"),
            "broad up cannot change an existing egress lifecycle",
        )

    def test_no_recreate_and_run_workdir_value_decoys_are_refused(self):
        for arguments in (
            ("up", "--no-recreate", "app"),
            ("up", "--no-recreate=true", "app"),
            ("create", "--no-recreate", "app"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "non-recreation")

        self.write_env(generation_value="''")
        self.set_state(
            volumes={
                "sentinel": self.sentinel(),
                "rabbit-data": self.owned_volume("rabbitmq_data"),
            }
        )
        for arguments in (
            ("run", "--rm", "--workdir", "--no-deps", "app", "true"),
            ("run", "--rm", "--workdir=--no-deps", "app", "true"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "must include --no-deps")

    def test_run_rejects_runtime_bypass_flags_including_boolean_forms(self):
        attacks = (
            ("run", "--rm", "--no-deps", "--privileged", "app", "id"),
            ("run", "--rm", "--no-deps", "--privileged=true", "app", "id"),
            ("run", "--rm", "--no-deps", "--privileged=false", "app", "id"),
            ("run", "--rm", "--no-deps", "--detach", "app", "id"),
            ("run", "--rm", "--no-deps", "--detach=true", "app", "id"),
            ("run", "--rm", "--no-deps", "-d", "app", "id"),
            ("run", "--rm", "--no-deps", "--service-ports=true", "app", "id"),
            ("run", "--rm", "--no-deps", "--use-aliases=true", "app", "id"),
            ("run", "--rm", "--no-deps", "--publish=127.0.0.1:9000:9000", "app", "id"),
            ("run", "--rm", "--no-deps", "--env-from-file=/tmp/attacker.env", "app", "id"),
            ("run", "--rm", "--no-deps", "--label=owned=false", "app", "id"),
            ("run", "--rm", "--no-deps", "--name=trusted", "app", "id"),
        )
        for arguments in attacks:
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "run cannot add privilege")
        for arguments in (
            ("run", "--rm", "--no-deps", "--user=0:0", "app", "id"),
            ("run", "--rm", "--no-deps", "--env=DJANGO_SERVER=test", "app", "id"),
            ("run", "--rm", "--no-deps", "--entrypoint=python", "app", "id"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "requires --allow-reviewed-runtime-overrides")

    def test_run_denies_stateful_services_and_post_service_flags_are_command(self):
        for service in ("db", "rabbitmq", "beat"):
            with self.subTest(service=service):
                self.assert_refused(
                    ("run", "--rm", service, "id"),
                    "restricted to non-root BackupSheep application-image services",
                )
        self.set_state(
            containers={"guard": self.owned_guard("app-egress-guard")},
            volumes={"sentinel": self.sentinel()},
        )
        self.clear_events()
        self.run_wrapper(
            "run", "--rm", "--no-deps", "app", "--privileged=true", check=True
        )
        final_run = self.compose_events("run")[-1]["argv"]
        run_index = final_run.index("run")
        self.assertEqual(
            final_run[run_index:],
            [
                "run", "--pull", "never", "--rm", "--no-deps", "app",
                "--privileged=true",
            ],
        )

    def test_egress_backed_run_attests_one_current_live_guard(self):
        exact = ("run", "--rm", "--no-deps", "app", "true")
        scenarios = (
            ("missing", {}, {}, "exactly one existing app-egress-guard"),
            (
                "duplicate",
                {
                    "guard-1": self.owned_guard("app-egress-guard"),
                    "guard-2": self.owned_guard("app-egress-guard"),
                },
                {},
                "exceeds its exact reviewed container cardinality",
            ),
            (
                "stopped",
                {"guard": self.owned_guard("app-egress-guard", state="exited")},
                {},
                "must already be running and healthy",
            ),
            (
                "unhealthy",
                {"guard": self.owned_guard("app-egress-guard", health="unhealthy")},
                {},
                "must already be running and healthy",
            ),
            (
                "restartable",
                {
                    "guard": self.owned_guard(
                        "app-egress-guard", restart_policy="unless-stopped"
                    )
                },
                {},
                "required no-restart lifecycle",
            ),
            (
                "wrong-ref",
                {
                    "guard": self.owned_guard(
                        "app-egress-guard", config_image="attacker/egress:latest"
                    )
                },
                {},
                "not bound to the exact reviewed local image reference and ID",
            ),
            (
                "wrong-id",
                {
                    "guard": self.owned_guard(
                        "app-egress-guard", image_id="sha256:" + ("f" * 64)
                    )
                },
                {},
                "not bound to the exact reviewed local image reference and ID",
            ),
            (
                "stale-lease",
                {"guard": self.owned_guard("app-egress-guard")},
                {"guard_healthcheck_exit_code": 1},
                "failed its fresh kernel-lease healthcheck",
            ),
        )
        for scenario, containers, extra, message in scenarios:
            with self.subTest(scenario=scenario):
                self.set_state(
                    containers=containers,
                    volumes={"sentinel": self.sentinel()},
                    **extra,
                )
                self.clear_events()
                self.assert_refused(exact, message)
                self.assertEqual(self.compose_events("run"), [])

        self.set_state(
            containers={"guard": self.owned_guard("app-egress-guard")},
            volumes={"sentinel": self.sentinel()},
        )
        self.clear_events()
        self.run_wrapper(*exact, check=True)
        self.assertTrue(self.compose_events("run"))
        healthchecks = [
            event
            for event in self.raw_events("exec")
            if "/usr/local/bin/backupsheep-egress-healthcheck" in event["argv"]
        ]
        self.assertEqual(len(healthchecks), 1)

    def test_stranded_egress_oneoff_blocks_run_pair_recreation_and_down(self):
        for oneoff_state in ("running", "exited"):
            with self.subTest(oneoff_state=oneoff_state):
                containers = {
                    "guard": self.owned_guard("app-egress-guard"),
                    "app": self.owned_container("app"),
                    "oneoff": self.owned_oneoff("app", state=oneoff_state),
                }
                self.set_state(
                    containers=containers,
                    volumes={"sentinel": self.sentinel()},
                )
                for arguments in (
                    ("run", "--rm", "--no-deps", "app", "true"),
                    APP_PAIR_UP,
                    ("down",),
                ):
                    with self.subTest(arguments=arguments):
                        self.clear_events()
                        self.assert_refused(
                            arguments,
                            "egress-backed Compose one-off for app still exists",
                        )
                        self.assertEqual(self.compose_events("run"), [])
                        self.assertEqual(self.compose_events("up"), [])
                        self.assertEqual(self.compose_events("down"), [])

    def test_legacy_ssh_trust_host_mount_is_always_rejected(self):
        migration_directory = self.root / ".backupsheep-ssh-migration.test"
        migration_directory.mkdir(mode=0o700)
        known_hosts = migration_directory / "known_hosts"
        known_hosts.write_text("host ssh-ed25519 AAAATEST\n", encoding="utf-8")
        known_hosts.chmod(0o444)
        mount = f"{known_hosts.resolve()}:/migration/known_hosts:ro"
        exact = (
            "--allow-reviewed-runtime-overrides",
            "run", "--rm", "--no-deps",
            "--volume", mount,
            "--entrypoint", "/bin/sh",
            "app", "-ceu", "true",
        )
        self.assert_refused(
            exact,
            "host volume overrides are not supported",
        )
        self.assertFalse(self.compose_events("run"))

    def test_former_root_ownership_recipe_is_always_rejected(self):
        exact = (
            "--allow-reviewed-runtime-overrides", "--profile", "operations",
            "run", "--rm", "--no-deps", "--user", "0:0",
            "--cap-add", "CHOWN", "--cap-add", "FOWNER",
            "--cap-add", "DAC_OVERRIDE", "--entrypoint", "sh",
            "worker-storage", "-ceu", "true",
        )
        self.set_state(
            containers={"guard": self.owned_guard("storage-egress-guard")},
            volumes={"sentinel": self.sentinel()},
        )
        attacks = (
            exact,
            tuple(argument for argument in exact if argument != "--rm"),
            tuple(argument for argument in exact if argument != "--no-deps"),
            (
                "--allow-reviewed-runtime-overrides", "run", "--rm", "--no-deps",
                "--cap-add", "CHOWN", "worker-storage", "true",
            ),
            (
                "--allow-reviewed-runtime-overrides", "run", "--rm", "--no-deps",
                "--entrypoint", "sh", "worker-storage", "-ceu", "true",
            ),
        )
        for arguments in attacks:
            with self.subTest(arguments=arguments):
                result = self.run_wrapper(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.compose_events("run"))

    def test_exact_offline_test_runtime_recipes_are_accepted_and_scoped(self):
        default_entrypoint = (
            "--allow-reviewed-runtime-overrides",
            "run", "--rm", "--no-deps", "-e", "DJANGO_SERVER=test",
            "app", "python", "manage.py", "test", "apps.tests",
        )
        python_entrypoint = (
            "--allow-reviewed-runtime-overrides", "--profile", "operations",
            "run", "--rm", "--no-deps", "-e", "DJANGO_SERVER=test",
            "--entrypoint", "python", "worker-cloud",
            "manage.py", "test", "apps.tests",
        )
        for arguments in (default_entrypoint, python_entrypoint):
            with self.subTest(arguments=arguments):
                guard_service = (
                    "app-egress-guard"
                    if arguments == default_entrypoint
                    else "cloud-egress-guard"
                )
                self.set_state(
                    containers={"guard": self.owned_guard(guard_service)},
                    volumes={"sentinel": self.sentinel()},
                )
                self.clear_events()
                self.run_wrapper(*arguments, check=True)
                self.assertTrue(self.compose_events("run"))

        incomplete = (
            tuple(argument for argument in default_entrypoint if argument != "--rm"),
            tuple(argument for argument in default_entrypoint if argument != "--no-deps"),
            default_entrypoint[:-3] + ("shell",),
            python_entrypoint[:-3] + ("manage.py", "shell"),
        )
        for arguments in incomplete:
            with self.subTest(arguments=arguments):
                result = self.run_wrapper(*arguments)
                self.assertNotEqual(result.returncode, 0)

    def test_exec_rejects_privilege_user_and_environment_bypass_flags(self):
        attacks = (
            ("exec", "--privileged", "app", "id"),
            ("exec", "--privileged=true", "app", "id"),
            ("exec", "--privileged=false", "app", "id"),
            ("exec", "--user=0:0", "app", "id"),
            ("exec", "-u0:0", "app", "id"),
            ("exec", "--env=X=Y", "app", "id"),
            ("exec", "-eX=Y", "app", "id"),
        )
        for arguments in attacks:
            with self.subTest(arguments=arguments):
                self.assert_refused(
                    arguments, "exec cannot override privilege, user, or environment"
                )
        for arguments in (
            ("exec", "--detach", "app", "sleep", "30"),
            ("exec", "--detach=true", "app", "sleep", "30"),
            ("exec", "-d", "app", "sleep", "30"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "detached exec is refused")

    def test_wait_down_project_is_always_refused(self):
        for arguments in (("wait", "--down-project"), ("wait", "--down-project=true")):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "run a separately validated down command")

    def test_stateful_exec_forces_vendor_server_uids(self):
        for service, expected_user in (("db", "70:70"), ("rabbitmq", "rabbitmq")):
            with self.subTest(service=service):
                self.set_state()
                self.clear_events()
                self.run_wrapper("exec", service, "id", check=True)
                final_exec = self.compose_events("exec")[-1]["argv"]
                exec_index = final_exec.index("exec")
                self.assertEqual(
                    final_exec[exec_index : exec_index + 4],
                    ["exec", "--user", expected_user, service],
                )

    def test_pull_and_build_argument_overrides_are_refused(self):
        for arguments in (("pull",), ("push",), ("publish",), ("commit", "app", "snapshot")):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "outside the reviewed local-image deployment workflow")
        for arguments in (
            ("build", "--build-arg", "TOKEN=secret", "app"),
            ("build", "--build-arg=TOKEN=secret", "app"),
            ("build", "--builder=attacker", "app"),
            ("build", "--ssh=default", "app"), ("build", "--push", "app"),
            ("build", "--no-cache=false", "app"),
            ("build", "unknown-service"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "build options are fixed by the wrapper" if arguments[1].startswith("-") else "unknown or unreviewed Compose build service")
        for arguments in (
            ("up", "--pull=always"), ("up", "--pull=false"),
            ("up", "--pull", "missing"), ("up", "--build"),
            ("create", "--renew-anon-volumes"), ("run", "--watch", "app", "id"),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_wrapper(*arguments)
                self.assertNotEqual(result.returncode, 0)
        self.set_state()
        self.clear_events()
        self.run_wrapper("build", "app", check=True)
        build_event = self.compose_events("build")[-1]["argv"]
        build_index = build_event.index("build")
        self.assertEqual(
            build_event[build_index : build_index + 4],
            ["build", "--pull", "--no-cache", "app"],
        )
        self.assertEqual(build_event.count("-f"), 1)
        self.assertTrue(build_event[build_event.index("-f") + 1].endswith("docker-compose.yml"))
        self.set_state()
        self.clear_events()
        self.run_wrapper("up", "--pull=never", check=True)
        up_event = self.compose_events("up")[-1]["argv"]
        self.assertIn("--no-build", up_event)
        self.assertIn("--pull=never", up_event)

    def test_run_refuses_missing_local_image_without_implicit_build(self):
        self.set_state(missing_image_refs=[APP_IMAGE])
        result = self.assert_refused(
            ("run", "--rm", "--no-deps", "app", "true"),
            "local image is absent",
        )
        self.assertNotIn(APP_IMAGE, result.stdout)
        self.assertEqual(self.compose_events("build"), [])
        self.assertEqual(self.compose_events("run"), [])

    def test_compose_menu_is_disabled_and_cannot_trigger_sync_or_exec(self):
        for arguments in (("up", "--menu"), ("up", "--menu=true")):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "Compose menu is refused")
        self.clear_events()
        self.run_wrapper("config", "--quiet", check=True)
        compose_event = self.compose_events("config")[-1]
        self.assertEqual(compose_event["env"]["COMPOSE_MENU"], "false")
        source = self.wrapper.read_text(encoding="utf-8")
        self.assertIn('"COMPOSE_MENU=false"', source)

    def test_scale_is_worker_only_bounded_and_not_a_direct_command(self):
        rejected = (
            (("up", "--scale", "worker-cloud=0"), "only worker-cloud"),
            (("up", "--scale=worker-cloud=33"), "bounded to 32"),
            (("up", "--scale=worker-cloud=100"), "only worker-cloud"),
            (("up", "--scale=app=1"), "only worker-cloud"),
            (("up", "--scale=db=1"), "only worker-cloud"),
            (("up", "--scale=rabbitmq=1"), "only worker-cloud"),
            (("up", "--scale=beat=2"), "only worker-cloud"),
            (("up", "--scale=migrate=2"), "only worker-cloud"),
            (("up", "--scale=worker-unknown=2"), "only worker-cloud"),
        )
        for arguments, message in rejected:
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, message)
        self.assert_refused(("scale", "worker-cloud=2"), "use up --scale")
        self.set_state()
        self.clear_events()
        self.run_wrapper(
            "up",
            "--no-deps",
            "--force-recreate",
            "--scale",
            "worker-cloud=1",
            "--scale=worker-storage=32",
            "cloud-egress-guard",
            "worker-cloud",
            "storage-egress-guard",
            "worker-storage",
            check=True,
        )
        final_up = self.compose_events("up")[-1]["argv"]
        self.assertIn("worker-cloud=1", final_up)
        self.assertIn("--scale=worker-storage=32", final_up)

    def test_cp_is_denied(self):
        self.assert_refused(
            ("cp", "app:/etc/passwd", "/tmp/passwd"),
            "outside the reviewed local-image deployment workflow",
        )


class DockerRuntimeContractTests(TestCase):
    """Empirically pin security-relevant Engine inspect semantics on CI Linux."""

    def test_network_none_and_tmpfs_inspect_contract_on_real_engine(self):
        docker = shutil.which("docker")
        if not docker or os.environ.get("DOCKER_HOST"):
            self.skipTest("a local default Docker Engine is required")
        context = subprocess.run(
            [docker, "context", "show"], check=False, capture_output=True, text=True,
        )
        if context.returncode or context.stdout.strip() != "default":
            self.skipTest("refusing to create fixtures outside the local default Docker context")
        info = subprocess.run(
            [docker, "info", "--format", "{{.OSType}}"],
            check=False, capture_output=True, text=True,
        )
        if info.returncode or info.stdout.strip() != "linux":
            self.skipTest("a reachable local Linux Docker Engine is required")

        suffix = f"{os.getpid()}-{time.time_ns()}"
        image = f"backupsheep-runtime-contract:{suffix}"
        container = f"backupsheep-runtime-contract-{suffix}"
        volume = f"backupsheep-runtime-contract-{suffix}"
        compose_project = f"bscontract{os.getpid()}"
        with tempfile.TemporaryDirectory(prefix="backupsheep-runtime-contract-") as temporary:
            root = Path(temporary)
            rootfs = root / "rootfs"
            (rootfs / "bin").mkdir(parents=True)
            marker = rootfs / "marker"
            archive = root / "rootfs.tar"
            marker.write_text("runtime contract\n", encoding="utf-8")
            source = root / "runtime-contract.c"
            source.write_text("int main(void) { return 0; }\n", encoding="ascii")
            compiler = shutil.which("cc")
            if not compiler:
                self.skipTest("a C compiler is required for the scratch runtime fixture")
            compiled = subprocess.run(
                [compiler, "-static", "-s", "-o", str(rootfs / "bin" / "runtime-contract"), str(source)],
                check=False, capture_output=True, text=True,
            )
            if compiled.returncode:
                self.skipTest("a static C toolchain is required for the scratch runtime fixture")
            with tarfile.open(archive, "w") as output:
                for entry in sorted(rootfs.rglob("*")):
                    output.add(entry, arcname=str(entry.relative_to(rootfs)))
            imported = subprocess.run(
                [docker, "import", str(archive), image],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)
            try:
                created_volume = subprocess.run(
                    [docker, "volume", "create", volume],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(created_volume.returncode, 0, created_volume.stderr)
                created = subprocess.run(
                    [
                        docker, "create", "--name", container, "--network", "none",
                        "--stop-timeout", "7",
                        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777",
                        "--mount", f"type=volume,src={volume},dst=/data,volume-nocopy",
                        image, "/bin/runtime-contract",
                    ],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(created.returncode, 0, created.stderr)
                inspected = subprocess.run(
                    [docker, "inspect", container],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(inspected.returncode, 0, inspected.stderr)
                document = json.loads(inspected.stdout)[0]
                self.assertEqual(document["HostConfig"]["NetworkMode"], "none")
                self.assertEqual(set(document["NetworkSettings"]["Networks"]), {"none"})
                none_endpoint = document["NetworkSettings"]["Networks"]["none"]
                self.assertEqual(none_endpoint.get("NetworkID", ""), "")
                self.assertEqual(none_endpoint.get("EndpointID", ""), "")
                self.assertEqual(none_endpoint.get("Gateway", ""), "")
                self.assertEqual(none_endpoint.get("IPAddress", ""), "")
                self.assertEqual(none_endpoint.get("IPPrefixLen", 0), 0)
                self.assertEqual(none_endpoint.get("MacAddress", ""), "")
                self.assertFalse(none_endpoint.get("Aliases"))
                self.assertFalse(none_endpoint.get("Links"))
                self.assertFalse(none_endpoint.get("DriverOpts"))
                self.assertEqual(
                    document["HostConfig"]["Tmpfs"],
                    {"/tmp": "rw,noexec,nosuid,nodev,size=8m,mode=1777"},
                )
                self.assertEqual(document["Config"]["Hostname"], document["Id"][:12])
                self.assertEqual(document["Config"]["StopTimeout"], 7)
                self.assertFalse(document["Config"]["Tty"])
                self.assertFalse(document["Config"]["OpenStdin"])
                self.assertFalse(document["Config"]["StdinOnce"])
                self.assertFalse(document["Config"]["AttachStdin"])
                self.assertTrue(document["Config"]["AttachStdout"])
                self.assertTrue(document["Config"]["AttachStderr"])
                volume_inspect = subprocess.run(
                    [docker, "volume", "inspect", volume],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(volume_inspect.returncode, 0, volume_inspect.stderr)
                mountpoint = json.loads(volume_inspect.stdout)[0]["Mountpoint"]
                runtime_mount = next(
                    mount for mount in document["Mounts"] if mount["Destination"] == "/data"
                )
                self.assertEqual(runtime_mount["Type"], "volume")
                self.assertEqual(runtime_mount["Name"], volume)
                self.assertEqual(runtime_mount["Source"], mountpoint)
                self.assertEqual(runtime_mount["Mode"], "")
                create_mount = next(
                    mount for mount in document["HostConfig"]["Mounts"]
                    if mount["Target"] == "/data"
                )
                self.assertEqual(create_mount["Type"], "volume")
                self.assertEqual(create_mount["Source"], volume)
                self.assertTrue(create_mount["VolumeOptions"]["NoCopy"])
                self.assertFalse(create_mount["VolumeOptions"].get("Subpath"))
                self.assertFalse(create_mount["VolumeOptions"].get("Labels"))
                self.assertIsNone(create_mount["VolumeOptions"].get("DriverConfig"))
                self.assertIsNone(create_mount.get("BindOptions"))
                self.assertIsNone(create_mount.get("TmpfsOptions"))
                self.assertIsNone(create_mount.get("ClusterOptions"))
                self.assertIsNone(create_mount.get("ImageOptions"))

                started = subprocess.run(
                    [docker, "start", "--attach", container],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(started.returncode, 0, started.stderr)
                exited_document = json.loads(
                    subprocess.check_output([docker, "inspect", container], text=True)
                )[0]
                none_id = subprocess.check_output(
                    [docker, "network", "inspect", "--format", "{{.Id}}", "none"],
                    text=True,
                ).strip()
                exited_endpoint = exited_document["NetworkSettings"]["Networks"]["none"]
                self.assertEqual(exited_document["State"]["Status"], "exited")
                self.assertEqual(exited_endpoint.get("NetworkID"), none_id)
                self.assertEqual(exited_endpoint.get("EndpointID", ""), "")

                compose_file = root / "compose.yml"
                compose_file.write_text(
                    "services:\n"
                    "  isolated:\n"
                    f"    image: {image}\n"
                    "    pull_policy: never\n"
                    "    network_mode: none\n"
                    "    command: [/bin/runtime-contract]\n"
                    "    volumes:\n"
                    f"      - type: volume\n        source: data\n        target: /data\n        volume:\n          nocopy: true\n"
                    "volumes:\n"
                    f"  data:\n    external: true\n    name: {volume}\n",
                    encoding="utf-8",
                )
                composed = subprocess.run(
                    [docker, "compose", "--project-name", compose_project, "-f", str(compose_file), "create"],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(composed.returncode, 0, composed.stderr)
                compose_container = f"{compose_project}-isolated-1"
                compose_document = json.loads(
                    subprocess.check_output([docker, "inspect", compose_container], text=True)
                )[0]
                self.assertEqual(compose_document["HostConfig"]["NetworkMode"], "none")
                self.assertEqual(set(compose_document["NetworkSettings"]["Networks"]), {"none"})
                compose_mount = next(
                    mount for mount in compose_document["Mounts"] if mount["Destination"] == "/data"
                )
                self.assertEqual(compose_mount["Mode"], "")
                # Use Engine start for the exact Compose-created container;
                # Compose has no portable attach flag for its start command.
                compose_started = subprocess.run(
                    [docker, "start", "--attach", compose_container],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(compose_started.returncode, 0, compose_started.stderr)
                compose_exited = json.loads(
                    subprocess.check_output([docker, "inspect", compose_container], text=True)
                )[0]
                self.assertEqual(compose_exited["State"]["Status"], "exited")
                self.assertEqual(
                    compose_exited["NetworkSettings"]["Networks"]["none"].get("NetworkID"),
                    none_id,
                )
            finally:
                subprocess.run(
                    [docker, "compose", "--project-name", compose_project, "-f", str(root / "compose.yml"), "down"],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    [docker, "rm", "--force", container],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    [docker, "image", "rm", image],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    [docker, "volume", "rm", volume],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )


if __name__ == "__main__":
    import unittest
    unittest.main()
