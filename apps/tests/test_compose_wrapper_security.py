import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "backupsheep-compose"
INSTALLATION_ID = "0123456789abcdef" * 4
OTHER_INSTALLATION_ID = "fedcba9876543210" * 4
PINNED_RABBIT_IMAGE = "rabbitmq:4.3.5-management@sha256:" + ("a" * 64)
PINNED_RABBIT_IMAGE_ID = "sha256:" + ("b" * 64)
PINNED_RABBIT_42_IMAGE = "rabbitmq:4.2.9-management@sha256:" + ("c" * 64)
PINNED_RABBIT_42_IMAGE_ID = "sha256:" + ("d" * 64)

CANONICAL_NETWORKS = (
    "app-database", "app-broker", "migrate-database", "cloud-database",
    "cloud-broker", "database-database", "database-broker", "files-database",
    "files-broker", "storage-database", "storage-broker", "logs-database",
    "logs-broker", "beat-database", "beat-broker", "preflight-database",
    "preflight-broker", "provision-database", "app-egress", "cloud-egress", "database-egress",
    "files-egress", "storage-egress", "logs-egress",
)
CANONICAL_VOLUMES = (
    "pgdata", "rabbitmq_data", "backup_workdir", "ssh_trust",
    "backup_storage", "installation_identity", "django_secret_key",
    "db_password", "rabbitmq_password", "onboarding_token",
    "ssh_managed_private_key",
)
CANONICAL_SERVICES = (
    "db", "rabbitmq", "db-provision", "migrate", "preflight", "app", "worker-cloud",
    "worker-database", "worker-files", "worker-storage", "worker-logs", "beat",
)


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_PATH = ROOT / "docker-state.json"
EVENT_PATH = ROOT / "docker-events.jsonl"
NETWORKS = __NETWORKS__
VOLUMES = __VOLUMES__
SERVICES = __SERVICES__
ENVIRONMENT_KEYS = (
    "BACKUPSHEEP_BIND_ADDRESS", "BACKUPSHEEP_IMAGE", "BACKUPSHEEP_POSTGRES_IMAGE",
    "BACKUPSHEEP_INSTALLATION_ID", "COMPOSE_BAKE", "COMPOSE_ENV_FILES",
    "COMPOSE_EXPERIMENTAL", "COMPOSE_FILE", "COMPOSE_PATH_SEPARATOR",
    "COMPOSE_PROFILES", "COMPOSE_PROJECT_NAME", "COMPOSE_REMOVE_ORPHANS",
    "BUILDX_BAKE_FILE", "BUILDKIT_PROGRESS", "DOCKER_BUILDKIT",
    "DOCKER_DEFAULT_PLATFORM", "DOCKER_CONTEXT", "DOCKER_HOST",
)
PINNED_RABBIT_IMAGE = "rabbitmq:4.3.5-management@sha256:" + ("a" * 64)
PINNED_RABBIT_IMAGE_ID = "sha256:" + ("b" * 64)
PINNED_RABBIT_42_IMAGE = "rabbitmq:4.2.9-management@sha256:" + ("c" * 64)
PINNED_RABBIT_42_IMAGE_ID = "sha256:" + ("d" * 64)

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

def canonical_yaml(project):
    lines = [f"name: {project}", "services:"]
    for service in SERVICES:
        lines.extend((f"  {service}:", "    image: backupsheep:test"))
    lines.append("networks:")
    for network in NETWORKS:
        lines.extend((f"  {network}:", f"    name: {project}_{network}"))
    lines.append("volumes:")
    for volume in VOLUMES:
        lines.extend((f"  {volume}:", f"    name: {project}_{volume}"))
    return "\n".join(lines) + "\n"

def matching_resources(resources, arguments):
    label_filter = option_value(arguments, "--filter")
    if not label_filter or not label_filter.startswith("label="):
        return list(resources.items())
    expression = label_filter[len("label="):]
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
    label_match = re.search(r'index [^\"]*\"([^\"]+)\"', template)
    if label_match:
        return resource.get("labels", {}).get(label_match.group(1), "")
    if template == "{{.Name}}":
        return resource.get("name", "")
    if template == "{{.State.Status}}":
        return resource.get("state", "")
    if template == "{{if .State.Health}}{{.State.Health.Status}}{{end}}":
        return resource.get("health", "")
    if template == "{{.Config.Image}}":
        return resource.get("config_image", "")
    if template == "{{.Image}}":
        return resource.get("image_id", "")
    return ""

def handle_compose(arguments, state):
    command = compose_subcommand(arguments)
    project = option_value(arguments, "--project-name") or "backupsheep"
    command_index = arguments.index(command) if command in arguments else -1
    command_arguments = arguments[command_index + 1:] if command_index >= 0 else []
    if command == "config":
        if "--quiet" in command_arguments:
            return
        if "--services" in command_arguments:
            emit("\n".join(SERVICES))
            return
        if "--images" in command_arguments:
            compose_file_count = sum(
                1 for argument in arguments if argument == "-f"
            )
            if any("upgrade-4.2.9.compose.yml" in argument for argument in arguments):
                emit(PINNED_RABBIT_42_IMAGE)
            elif compose_file_count > 1:
                emit(state.get("combined_rabbitmq_image", PINNED_RABBIT_IMAGE))
            else:
                emit(PINNED_RABBIT_IMAGE)
            return
        emit(canonical_yaml(project))
        return
    if command == "up":
        exit_code = state.get("compose_up_exit_code", 0)
        if exit_code:
            sys.exit(exit_code)
        transition = state.pop("compose_up_transition_result", None)
        if transition:
            rabbit = next(
                resource
                for resource in state["containers"].values()
                if resource.get("labels", {}).get("com.docker.compose.service") == "rabbitmq"
            )
            compose_files = [
                arguments[index + 1]
                for index, argument in enumerate(arguments[:-1])
                if argument == "-f"
            ]
            rabbit["labels"]["com.docker.compose.project.config_files"] = ",".join(compose_files)
            rabbit["labels"]["com.backupsheep.installation-id"] = transition[
                "installation_id"
            ]
            rabbit["state"] = transition.get("state", "running")
            rabbit["health"] = transition.get("health", "healthy")
            rabbit["config_image"] = transition.get(
                "config_image", PINNED_RABBIT_IMAGE
            )
            rabbit["image_id"] = transition.get(
                "image_id", PINNED_RABBIT_IMAGE_ID
            )
            state["rabbitmq_server_version"] = transition.get(
                "server_version", "4.3.5"
            )
            state["rabbitmq_feature_flags"] = transition.get(
                "feature_flags", "name stability state\nkhepri_db stable enabled"
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
            emit(inspect_value(find_resource(resources, identifier), template))
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
    if arguments[0] == "ps":
        matches = matching_resources(state["containers"], arguments)
        emit("\n".join(resource_id for resource_id, _ in matches))
        return
    if arguments[0] == "network":
        handle_collection("networks", arguments, state)
        return
    if arguments[0] == "volume":
        handle_collection("volumes", arguments, state)
        return
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
        if template == "{{.Id}}" and identifier in (
            PINNED_RABBIT_IMAGE, PINNED_RABBIT_42_IMAGE
        ):
            if identifier == PINNED_RABBIT_42_IMAGE:
                emit(state.get("pinned_rabbitmq_42_image_id", PINNED_RABBIT_42_IMAGE_ID))
            else:
                emit(state.get("pinned_rabbitmq_image_id", PINNED_RABBIT_IMAGE_ID))
            return
        sys.exit(1)
    if arguments[0] == "exec":
        if "server_version" in arguments:
            emit(state.get("rabbitmq_server_version", "4.3.5"))
        elif "list_feature_flags" in arguments:
            emit(
                state.get(
                    "rabbitmq_feature_flags",
                    "name stability state\nkhepri_db stable enabled",
                )
            )

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
            "services:\n  app:\n    image: backupsheep:test\n",
            encoding="utf-8",
        )
        self.base_file.chmod(0o600)
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
        self.temporary_directory.cleanup()

    def write_env(
        self,
        *,
        installation_value=f"'{INSTALLATION_ID}'",
        generation_value="'4.3'",
        additional_lines=(),
    ):
        lines = [
            "BACKUPSHEEP_COMPOSE_PROJECT_NAME='backupsheep'",
            "BACKUPSHEEP_BIND_ADDRESS='127.0.0.1'",
        ]
        if installation_value is not None:
            lines.append(f"BACKUPSHEEP_INSTALLATION_ID={installation_value}")
        if generation_value is not None:
            lines.append(f"BACKUPSHEEP_RABBITMQ_DATA_GENERATION={generation_value}")
        lines.extend(additional_lines)
        self.env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.env_file.chmod(0o600)

    def set_state(self, *, containers=None, networks=None, volumes=None, **extra):
        state = {
            "containers": containers or {},
            "networks": networks or {},
            "volumes": volumes or {},
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

    def run_wrapper(self, *arguments, check=False, extra_environment=None):
        environment = os.environ.copy()
        environment["PATH"] = f"{self.fake_bin}{os.pathsep}{environment['PATH']}"
        environment.update(
            BACKUPSHEEP_BIND_ADDRESS="0.0.0.0",
            BACKUPSHEEP_IMAGE="attacker/image:latest",
            BACKUPSHEEP_POSTGRES_IMAGE="attacker/postgres:latest",
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
        return subprocess.run(
            [str(self.wrapper), *arguments], cwd=self.root, env=environment,
            check=check, capture_output=True, text=True,
        )

    def assert_refused(self, arguments, message):
        result = self.run_wrapper(*arguments)
        self.assertNotEqual(result.returncode, 0, arguments)
        self.assertIn(message, result.stderr, arguments)
        return result

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
        }
        if installation_id is not None:
            labels["com.backupsheep.installation-id"] = installation_id
        return {
            "labels": labels,
            "name": f"backupsheep-{service}-1",
            **state,
        }

    def rabbit_overlay(self):
        rabbit = self.root / "deploy" / "rabbitmq" / "upgrade-4.2.9.compose.yml"
        rabbit.parent.mkdir(parents=True, exist_ok=True)
        rabbit.write_text("services: {}\n", encoding="utf-8")
        rabbit.chmod(0o600)
        return rabbit

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
    ):
        rabbit_labels = {
            "com.docker.compose.project": "backupsheep",
            "com.docker.compose.project.working_dir": str(self.root.resolve()),
            "com.docker.compose.project.config_files": config_files,
            "com.docker.compose.service": "rabbitmq",
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
                feature_flags = "name stability state\nkhepri_db stable enabled"
        if container_image_ref is None:
            container_image_ref = (
                PINNED_RABBIT_IMAGE
                if server_version == "4.3.5"
                else (
                    PINNED_RABBIT_42_IMAGE
                    if server_version == "4.2.9"
                    else "rabbitmq:legacy-source"
                )
            )
        if container_image_id is None:
            container_image_id = (
                PINNED_RABBIT_IMAGE_ID
                if server_version == "4.3.5"
                else (
                    PINNED_RABBIT_42_IMAGE_ID
                    if server_version == "4.2.9"
                    else "sha256:" + ("f" * 64)
                )
            )
        self.set_state(
            containers={
                "rabbit-container": {
                    "health": "healthy",
                    "config_image": container_image_ref,
                    "image_id": container_image_id,
                    "labels": rabbit_labels,
                    "name": "backupsheep-rabbitmq-1",
                    "state": "running",
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

    def env_value(self, key):
        for line in self.env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1]
        return None

    def test_ambient_model_build_profile_and_identity_controls_are_removed(self):
        result = self.run_wrapper("config", "--services", check=True)
        self.assertEqual(result.stdout.splitlines(), list(CANONICAL_SERVICES))
        compose_events = self.compose_events()
        self.assertEqual(len(compose_events), 2)
        stripped = {
            "BACKUPSHEEP_BIND_ADDRESS", "BACKUPSHEEP_IMAGE", "BACKUPSHEEP_POSTGRES_IMAGE",
            "BACKUPSHEEP_INSTALLATION_ID", "COMPOSE_ENV_FILES", "COMPOSE_FILE",
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
            arguments = event["argv"]
            self.assertEqual(arguments[arguments.index("--project-name") + 1], "backupsheep")
            self.assertEqual(arguments[arguments.index("--env-file") + 1], str(self.env_file.resolve()))
            self.assertNotIn("foreign", arguments)
            self.assertNotIn("operations", arguments)
            self.assertNotIn("/tmp/attacker.yml", arguments)

    def test_overlays_require_explicit_approval_and_have_canonical_order(self):
        override = self.root / "docker-compose.override.yml"
        override.write_text("services: {}\n", encoding="utf-8")
        override.chmod(0o600)
        rabbit = self.root / "deploy" / "rabbitmq" / "upgrade-4.2.9.compose.yml"
        rabbit.parent.mkdir(parents=True)
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
        for event in self.compose_events():
            arguments = event["argv"]
            actual_files = [
                arguments[index + 1] for index, argument in enumerate(arguments)
                if argument == "-f"
            ]
            self.assertEqual(actual_files, expected_files)
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

    def test_existing_resources_require_one_matching_identity_sentinel(self):
        self.set_state(volumes={"sentinel": self.sentinel(OTHER_INSTALLATION_ID)})
        self.assert_refused(
            ("up",), "ownership sentinel belongs to a different BackupSheep installation"
        )
        self.set_state(volumes={"pgdata": self.owned_volume("pgdata")})
        self.assert_refused(
            ("up",),
            "existing Compose resources require exactly one matching installation-identity sentinel",
        )

    def test_verified_sentinel_allows_only_exact_path_blank_identity_legacy_containers(self):
        legacy_app = self.owned_container("app", installation_id=None)
        self.set_state(
            containers={"legacy-app": legacy_app},
            volumes={"sentinel": self.sentinel()},
        )
        self.run_wrapper("up", "--detach", "--no-deps", "app", check=True)

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
                    ("up", "--detach", "--no-deps", "app"), expected_message
                )

        self.set_state(
            containers={"legacy-app": legacy_app},
            volumes={"sentinel": self.sentinel(OTHER_INSTALLATION_ID)},
        )
        self.assert_refused(
            ("up", "--detach", "--no-deps", "app"),
            "ownership sentinel belongs to a different BackupSheep installation",
        )

    def test_verified_sentinel_unblocks_blank_identity_legacy_rabbit_transition(self):
        self.write_env(generation_value="''")
        overlay = self.rabbit_overlay()
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="3.13.7",
            installation_id=None,
        )
        self.run_wrapper(
            "--approved-compose-file", str(overlay),
            "--allow-rabbitmq-generation-transition=4.2",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )

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
            "existing RabbitMQ volume has no proven 4.3 generation",
        )

    def test_fresh_broad_up_records_generation_but_no_deps_app_does_not(self):
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
        self.run_wrapper("up", "--no-deps", "app", check=True)
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

    def test_valid_42_transition_uses_base_then_rabbit_model_history(self):
        rabbit = self.rabbit_overlay()
        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="3.13.7",
        )
        self.run_wrapper(
            "--approved-compose-file", str(rabbit),
            "--allow-rabbitmq-generation-transition=4.2",
            "up", "--detach", "--no-deps", "rabbitmq",
            check=True,
        )
        expected_files = [str(self.base_file.resolve()), str(rabbit.resolve())]
        for event in self.compose_events():
            arguments = event["argv"]
            actual_files = [
                arguments[index + 1]
                for index, argument in enumerate(arguments)
                if argument == "-f"
            ]
            self.assertEqual(actual_files, expected_files)
        diagnostic = [
            event for event in self.raw_events("exec")
            if "server_version" in event["argv"]
        ]
        self.assertEqual(len(diagnostic), 1)
        self.assertEqual(diagnostic[0]["argv"][1:3], ["--user", "rabbitmq"])

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
        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="3.13.7",
            feature_flags=(
                "name stability state\n"
                "khepri_db experimental enabled\n"
                "stream_queue stable enabled"
            ),
        )
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
                    "khepri_db stable enabled\n"
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
        for event in self.compose_events("up"):
            arguments = event["argv"]
            actual_files = [
                arguments[index + 1]
                for index, argument in enumerate(arguments)
                if argument == "-f"
            ]
            self.assertEqual(actual_files, [str(self.base_file.resolve())])
        feature_query = [
            event for event in self.raw_events("exec")
            if "list_feature_flags" in event["argv"]
        ]
        self.assertEqual(len(feature_query), 2)
        self.assertEqual(
            self.env_value("BACKUPSHEEP_RABBITMQ_DATA_GENERATION"), "'4.3'"
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
                "post-transition broker is not the pinned RabbitMQ 4.3.5 target",
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
                "not running the exact digest-pinned reviewed image",
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

    def test_exact_435_reconciliation_records_witness_but_newer_43_is_not_downgraded(self):
        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="4.3.5",
            feature_flags="name stability state\nkhepri_db stable enabled",
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
            feature_flags="name stability state\nkhepri_db stable enabled",
        )
        self.clear_events()
        self.assert_refused(
            (
                "--allow-rabbitmq-generation-transition=4.3",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "exact 4.3.5 reconciliation result",
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
            "override changed the base model's pinned RabbitMQ image",
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
            "not running the exact digest-pinned reviewed image",
        )
        self.assertEqual(self.compose_events("up"), [])
        self.assertEqual(self.compose_events("up"), [])

        self.write_env(generation_value="''")
        self.rabbit_transition_state(
            config_files=str(self.base_file.resolve()),
            server_version="4.3.5",
            feature_flags="name stability state\nkhepri_db stable enabled",
            container_image_id="sha256:" + ("d" * 64),
        )
        self.clear_events()
        self.assert_refused(
            (
                "--allow-rabbitmq-generation-transition=4.3",
                "up", "--detach", "--no-deps", "rabbitmq",
            ),
            "not running the exact digest-pinned reviewed image",
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
                "requires the exact healthy RabbitMQ 4.2.9 source",
            ),
            (
                "4.3.6",
                "khepri_db stable enabled",
                "exact 4.3.5 reconciliation result",
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
            ("run", "--workdir", "--no-deps", "app", "true"),
            ("run", "--workdir=--no-deps", "app", "true"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "working-directory override")

    def test_run_rejects_runtime_bypass_flags_including_boolean_forms(self):
        attacks = (
            ("run", "--privileged", "app", "id"),
            ("run", "--privileged=true", "app", "id"),
            ("run", "--privileged=false", "app", "id"),
            ("run", "--detach", "app", "id"),
            ("run", "--detach=true", "app", "id"),
            ("run", "-d", "app", "id"),
            ("run", "--service-ports=true", "app", "id"),
            ("run", "--use-aliases=true", "app", "id"),
            ("run", "--publish=127.0.0.1:9000:9000", "app", "id"),
            ("run", "--env-from-file=/tmp/attacker.env", "app", "id"),
            ("run", "--label=owned=false", "app", "id"),
            ("run", "--name=trusted", "app", "id"),
        )
        for arguments in attacks:
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "run cannot add privilege")
        for arguments in (
            ("run", "--user=0:0", "app", "id"),
            ("run", "--env=DJANGO_SERVER=test", "app", "id"),
            ("run", "--entrypoint=python", "app", "id"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "requires --allow-reviewed-runtime-overrides")

    def test_run_denies_stateful_services_and_post_service_flags_are_command(self):
        for service in ("db", "rabbitmq", "beat"):
            with self.subTest(service=service):
                self.assert_refused(
                    ("run", service, "id"),
                    "restricted to non-root BackupSheep application-image services",
                )
        self.set_state()
        self.clear_events()
        self.run_wrapper("run", "app", "--privileged=true", check=True)
        final_run = self.compose_events("run")[-1]["argv"]
        run_index = final_run.index("run")
        self.assertEqual(final_run[run_index:], ["run", "app", "--privileged=true"])

    def test_exact_ssh_trust_runtime_recipe_is_accepted_and_incomplete_forms_fail(self):
        migration_directory = self.root / ".backupsheep-ssh-migration.test"
        migration_directory.mkdir(mode=0o700)
        known_hosts = migration_directory / "known_hosts"
        known_hosts.write_text("host ssh-ed25519 AAAATEST\n", encoding="utf-8")
        known_hosts.chmod(0o444)
        mount = f"{known_hosts.resolve()}:/migration/known_hosts:ro"
        exact = (
            "--allow-reviewed-runtime-overrides",
            "run", "--rm", "--no-deps",
            "--entrypoint", "/bin/sh",
            "--volume", mount,
            "app", "-ceu", "true",
        )
        self.run_wrapper(*exact, check=True)
        self.assertTrue(self.compose_events("run"))

        incomplete = (
            (
                "--allow-reviewed-runtime-overrides", "run", "--no-deps",
                "--entrypoint", "/bin/sh", "--volume", mount,
                "app", "-ceu", "true",
            ),
            (
                "--allow-reviewed-runtime-overrides", "run", "--rm",
                "--entrypoint", "/bin/sh", "--volume", mount,
                "app", "-ceu", "true",
            ),
            (
                "--allow-reviewed-runtime-overrides", "run", "--rm", "--no-deps",
                "--entrypoint", "/bin/sh", "--volume", mount,
                "app", "-c", "true",
            ),
        )
        for arguments in incomplete:
            with self.subTest(arguments=arguments):
                result = self.run_wrapper(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("host-file override is restricted", result.stderr)

        migration_directory.chmod(0o755)
        self.assert_refused(exact, "migration directory must be private")

    def test_exact_root_ownership_recipe_is_accepted_and_incomplete_forms_fail(self):
        exact = (
            "--allow-reviewed-runtime-overrides", "--profile", "operations",
            "run", "--rm", "--no-deps", "--user", "0:0",
            "--cap-add", "CHOWN", "--cap-add", "FOWNER",
            "--cap-add", "DAC_OVERRIDE", "--entrypoint", "sh",
            "worker-storage", "-ceu", "true",
        )
        self.run_wrapper(*exact, check=True)
        self.assertTrue(self.compose_events("run"))

        incomplete = (
            tuple(argument for argument in exact if argument != "--rm"),
            tuple(argument for argument in exact if argument != "--no-deps"),
            (
                "--allow-reviewed-runtime-overrides", "--profile", "operations",
                "run", "--rm", "--no-deps", "--user", "0:0",
                "--cap-add", "CHOWN", "--cap-add", "FOWNER",
                "--entrypoint", "sh", "worker-storage", "-ceu", "true",
            ),
            exact[:-2] + ("-c", "true"),
        )
        for arguments in incomplete:
            with self.subTest(arguments=arguments):
                result = self.run_wrapper(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("exact worker-storage ownership migration", result.stderr)

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
                self.set_state()
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

    def test_stateful_exec_forces_vendor_server_uids(self):
        for service, expected_user in (("db", "999:999"), ("rabbitmq", "rabbitmq")):
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
        ):
            with self.subTest(arguments=arguments):
                self.assert_refused(arguments, "outside the exact reviewed build")
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
        self.assertTrue(self.compose_events("build"))
        self.set_state()
        self.clear_events()
        self.run_wrapper("up", "--pull=never", check=True)
        self.assertTrue(self.compose_events("up"))

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
            "up", "--scale", "worker-cloud=1", "--scale=worker-storage=32", check=True,
        )
        final_up = self.compose_events("up")[-1]["argv"]
        self.assertIn("worker-cloud=1", final_up)
        self.assertIn("--scale=worker-storage=32", final_up)

    def test_cp_is_denied(self):
        self.assert_refused(
            ("cp", "app:/etc/passwd", "/tmp/passwd"),
            "outside the reviewed local-image deployment workflow",
        )


if __name__ == "__main__":
    import unittest
    unittest.main()
