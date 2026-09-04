"""Fail closed unless the stock Docker security boundary is actually active."""

from __future__ import annotations

import errno
import hashlib
import hmac
import importlib
import os
import resource
import stat
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from kombu import Connection

from backupsheep.celery_security import (
    CONSUMER_QUEUES,
    LANES,
    _load_private_key,
    _load_public_keys,
    _security_configuration,
)
from backupsheep.celery_task_manifest import (
    TaskManifestError,
    validate_configured_routes,
    validate_registered_tasks,
)
from backupsheep.database_identity import (
    ProvisioningError,
    assert_database_lane_contract,
)
from backupsheep.database_lane_policy import LANES as DATABASE_LANES
from backupsheep.artifact_crypto import artifact_provider_policy_witness


EXPECTED_UID = 10001
EXPECTED_UID_BY_ROLE = {
    "web": 10001,
    "database": 10002,
    "files": 10003,
    "storage": 10004,
    "logs": 10005,
    "beat": 10006,
    "migration": 10007,
    "cloud": 10008,
}
REQUIRED_SECRET_FILE_ENV = {
    "DJANGO_SECRET_KEY": "/run/secrets/django_secret_key",
}
CELERY_PUBLIC_KEYS_FILE = "/run/secrets/celery_trusted_public_keys"
FORBIDDEN_CREDENTIAL_URL_ENV = ("DATABASE_URL", "CELERY_BROKER_URL")


def _assert_stock_configuration_sources(*, environment, runtime_settings, secret_values):
    errors = []
    if environment.get("DJANGO_SETTINGS_MODULE") != "backupsheep.settings":
        errors.append("DJANGO_SETTINGS_MODULE does not select backupsheep.settings")
    if environment.get("BACKUPSHEEP_SECRETS"):
        errors.append("BACKUPSHEEP_SECRETS replaces the reviewed stock configuration")
    if environment.get("BACKUPSHEEP_EGRESS_POLICY_GENERATION") != "2":
        errors.append("fail-closed egress policy generation 2 is not active")

    expected_django = secret_values.get("DJANGO_SECRET_KEY", "")
    expected_database = secret_values.get("DB_PASSWORD", "")
    expected_rabbitmq = secret_values.get("RABBITMQ_PASSWORD", "")
    actual_database = runtime_settings.DATABASES.get("default", {}).get("PASSWORD", "")
    try:
        actual_rabbitmq = unquote(
            urlsplit(runtime_settings.CELERY_BROKER_URL).password or ""
        )
    except (TypeError, ValueError):
        actual_rabbitmq = ""

    for label, expected, actual in (
        ("Django", expected_django, runtime_settings.SECRET_KEY),
        ("database", expected_database, actual_database),
        ("RabbitMQ", expected_rabbitmq, actual_rabbitmq),
    ):
        if not expected or not hmac.compare_digest(str(expected), str(actual)):
            errors.append(f"{label} setting was not resolved from its stock secret file")
    if errors:
        raise CommandError("Docker security preflight failed: " + "; ".join(errors))


def _rabbitmq_secret_path(environment):
    lane = str(environment.get("BACKUPSHEEP_CELERY_LANE") or "")
    if lane not in (*LANES, "preflight"):
        raise CommandError("Docker security preflight failed: Celery lane is invalid")
    return f"/run/secrets/rabbitmq_{lane}_password"


def _required_secret_file_env(environment):
    return {
        **REQUIRED_SECRET_FILE_ENV,
        "DB_PASSWORD": _database_secret_path(environment),
        "RABBITMQ_PASSWORD": _rabbitmq_secret_path(environment),
    }


def _database_secret_path(environment):
    lane = str(environment.get("BACKUPSHEEP_DATABASE_LANE") or "")
    if lane not in DATABASE_LANES:
        raise CommandError(
            "Docker security preflight failed: database lane is invalid"
        )
    return f"/run/secrets/db_{lane}_password"


def _read_stock_secret_values(required_secret_files):
    values = {}
    for setting_name, expected_path in required_secret_files.items():
        try:
            values[setting_name] = Path(expected_path).read_text(encoding="utf-8").rstrip("\n")
        except OSError as error:
            raise CommandError(
                "Docker security preflight failed: could not read a required stock secret file"
            ) from error
    return values


def _assert_celery_identity(environment):
    lane = str(environment.get("BACKUPSHEEP_CELERY_LANE") or "")
    if str(environment.get("BACKUPSHEEP_CELERY_SECURITY_REQUIRED") or "").lower() != "true":
        raise CommandError(
            "Docker security preflight failed: authenticated Celery is not required"
        )
    expected_user = f"backupsheep_{lane}"
    if environment.get("RABBITMQ_USER") != expected_user:
        raise CommandError(
            "Docker security preflight failed: RabbitMQ identity does not match its Celery lane"
        )
    if environment.get("CELERY_TRUSTED_PUBLIC_KEYS_FILE") != CELERY_PUBLIC_KEYS_FILE:
        raise CommandError(
            "Docker security preflight failed: Celery public-key registry path drifted"
        )
    publishing = lane in LANES
    expected_private = (
        f"/run/secrets/celery_signing_{lane}_private_key" if publishing else ""
    )
    if str(environment.get("CELERY_SIGNING_PRIVATE_KEY_FILE") or "") != expected_private:
        raise CommandError(
            "Docker security preflight failed: Celery signing-key path drifted"
        )
    try:
        config = _security_configuration(publishing=publishing)
        public_keys = _load_public_keys(
            config.public_keys_file, config.installation_id
        )
        if publishing:
            probe = b"backupsheep-celery-identity-v2"
            public_keys[lane].verify(
                _load_private_key(config.private_key_file).sign(probe), probe
            )
        elif lane not in CONSUMER_QUEUES and lane != "preflight":
            raise ValueError("invalid non-publishing lane")
    except Exception as error:
        raise CommandError(
            "Docker security preflight failed: Celery signing material is invalid"
        ) from error


def _assert_celery_task_manifest(runtime_settings):
    """Import every reviewed task and reject registry/route drift before service start."""

    from backupsheep.celery import app

    try:
        validate_configured_routes(runtime_settings.CELERY_TASK_ROUTES)
        for module_name in runtime_settings.CELERY_IMPORTS:
            importlib.import_module(module_name)
        app.finalize()
        validate_registered_tasks(app.tasks)
    except (ImportError, TaskManifestError) as error:
        raise CommandError(
            "Docker security preflight failed: Celery task manifest drifted"
        ) from error


def _proc_status_values(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key] = value.strip()
    return values


def _assert_process_boundary(
    *, uid: int, proc_status: str, root_flags: int, core_limit, expected_uid=EXPECTED_UID
):
    errors = []
    status_values = _proc_status_values(proc_status)
    if uid != expected_uid:
        errors.append(f"runtime UID must be {expected_uid}, observed {uid}")
    for capability_set in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        try:
            capabilities = int(status_values.get(capability_set, "invalid"), 16)
        except ValueError:
            capabilities = -1
        if capabilities != 0:
            errors.append(f"{capability_set} Linux capabilities are not empty")
    if status_values.get("NoNewPrivs") != "1":
        errors.append("no-new-privileges is not active")
    if status_values.get("Seccomp") != "2":
        errors.append("seccomp filtering is not active")
    try:
        seccomp_filters = int(status_values.get("Seccomp_filters", "0"))
    except ValueError:
        seccomp_filters = 0
    if seccomp_filters < 1:
        errors.append("no seccomp filter is installed")
    if not root_flags & getattr(os, "ST_RDONLY", 1):
        errors.append("container root filesystem is writable")
    if tuple(core_limit) != (0, 0):
        errors.append("core dumps are not disabled")
    if errors:
        raise CommandError("Docker security preflight failed: " + "; ".join(errors))


def _assert_read_only_path(path: Path):
    probe = path / f".backupsheep-preflight-{os.getpid()}"
    try:
        descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        if error.errno in {errno.EROFS, errno.EACCES, errno.EPERM}:
            return
        raise CommandError(
            f"Docker security preflight could not verify read-only path {path}: {error}"
        ) from error
    else:
        os.close(descriptor)
        try:
            probe.unlink()
        finally:
            raise CommandError(
                f"Docker security preflight failed: {path} is unexpectedly writable"
            )


def _decode_mountinfo_path(raw_path: str) -> str:
    for escaped, value in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        raw_path = raw_path.replace(escaped, value)
    return raw_path


def _assert_secure_tmpfs(path: Path, mountinfo: str):
    expected = str(path)
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        if not separator:
            continue
        fields = before.split()
        filesystem = after.split()
        if len(fields) < 6 or len(filesystem) < 3:
            continue
        if _decode_mountinfo_path(fields[4]) != expected:
            continue
        mount_options = set(fields[5].split(","))
        super_options = set(filesystem[2].split(","))
        if filesystem[0] != "tmpfs":
            raise CommandError(f"Required runtime path {path} is not a tmpfs mount")
        required_options = {"rw", "noexec", "nosuid", "nodev"}
        missing = required_options - (mount_options | super_options)
        if missing:
            raise CommandError(
                f"Required tmpfs path {path} is missing mount protections: "
                + ", ".join(sorted(missing))
            )
        return
    raise CommandError(f"Required runtime path {path} is not a distinct mount")


def _assert_private_writable_tmpfs(
    path: Path, mountinfo: str, *, expected_uid=EXPECTED_UID
):
    try:
        metadata = path.stat()
    except OSError as error:
        raise CommandError(f"Required tmpfs path {path} is unavailable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise CommandError(f"Required tmpfs path {path} is not a directory")
    if path == Path("/run/backupsheep") and metadata.st_uid != expected_uid:
        raise CommandError(
            f"Required tmpfs path {path} must be owned by UID {expected_uid}"
        )
    if path == Path("/run/backupsheep") and stat.S_IMODE(metadata.st_mode) != 0o700:
        raise CommandError("/run/backupsheep must have mode 0700")
    if path == Path("/tmp") and stat.S_IMODE(metadata.st_mode) != 0o1777:
        raise CommandError("/tmp must have mode 01777")
    _assert_secure_tmpfs(path, mountinfo)
    try:
        with tempfile.NamedTemporaryFile(prefix="preflight-", dir=path) as temporary:
            if stat.S_IMODE(os.fstat(temporary.fileno()).st_mode) & 0o077:
                raise CommandError(f"Temporary file under {path} was not private")
    except OSError as error:
        raise CommandError(f"Required tmpfs path {path} is not writable: {error}") from error


def _assert_no_pending_migrations(executor: MigrationExecutor):
    plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
    if not plan:
        return
    pending = ", ".join(
        f"{migration.app_label}.{migration.name}"
        for migration, _backwards in plan[:10]
    )
    if len(plan) > 10:
        pending += f", and {len(plan) - 10} more"
    raise CommandError(
        "Docker deployment preflight failed: unapplied database migrations: "
        + pending
    )


def _assert_runtime_database_identity(*, cursor, environment, runtime_settings):
    """Prove the active login and the complete generation-3 ACL/RLS boundary."""

    configured_user = str(
        runtime_settings.DATABASES.get("default", {}).get("USER", "") or ""
    )
    try:
        assert_database_lane_contract(
            cursor,
            environment=environment,
            configured_user=configured_user,
        )
    except ProvisioningError as error:
        raise CommandError(f"Docker security preflight failed: {error}") from error


def _assert_managed_ssh_identity(*, environment, runtime_settings):
    """Prove split public identity and least-privilege private-key custody."""

    from apps.console.connection.managed_ssh import (
        ManagedSSHOperationError,
        managed_public_key_fingerprint,
        managed_public_key_for_lane,
    )
    from apps.console.connection.ssh import _load_private_key

    role = str(environment.get("BACKUPSHEEP_RUNTIME_ROLE") or "")
    errors = []
    if runtime_settings.SSH_MANAGED_LANE_ISOLATION_REQUIRED is not True:
        errors.append("managed SSH lane isolation is not required")
    if str(runtime_settings.SSH_MANAGED_PUBLIC_KEY or ""):
        errors.append("the legacy shared managed SSH public key is configured")

    public_keys = {}
    try:
        for lane in ("database", "files"):
            value = managed_public_key_for_lane(lane)
            public_keys[lane] = value
            if value:
                managed_public_key_fingerprint(value)
    except ManagedSSHOperationError:
        errors.append("managed SSH lane public keys are invalid")
    enabled = bool(public_keys.get("database") and public_keys.get("files"))

    runtime_path = str(runtime_settings.SSH_MANAGED_PRIVATE_KEY_PATH or "")
    lane_sources = {
        "database": Path("/run/secrets/ssh_managed_database_private_key"),
        "files": Path("/run/secrets/ssh_managed_files_private_key"),
    }
    if role in lane_sources:
        own_source = lane_sources[role]
        other_source = lane_sources["files" if role == "database" else "database"]
        if own_source.is_symlink() or not own_source.is_file():
            errors.append("the lane managed SSH private-key secret is unavailable")
        if other_source.exists() or other_source.is_symlink():
            errors.append("the opposite managed SSH private-key secret is mounted")
        if enabled:
            expected_path = "/run/backupsheep/ssh/managed_private_key"
            if runtime_path != expected_path:
                errors.append("the managed SSH private key is not staged in private tmpfs")
            else:
                key_path = Path(runtime_path)
                try:
                    metadata = key_path.lstat()
                    if key_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                        raise ValueError("not a regular file")
                    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
                        raise ValueError("unsafe ownership or mode")
                    if metadata.st_size < 1 or metadata.st_size > 64 * 1024:
                        raise ValueError("unsafe size")
                    private_key = _load_private_key(runtime_path, managed=True)
                    private_fingerprint = hashlib.sha256(
                        private_key.asbytes()
                    ).hexdigest()
                    public_fingerprint = managed_public_key_fingerprint(
                        public_keys[role]
                    )
                    if not hmac.compare_digest(
                        private_fingerprint, public_fingerprint
                    ):
                        raise ValueError("public/private mismatch")
                except Exception:
                    errors.append(
                        "the staged managed SSH private key is invalid or mismatched"
                    )
        elif runtime_path or Path(
            "/run/backupsheep/ssh/managed_private_key"
        ).exists():
            errors.append("a managed SSH private key exists while the feature is disabled")
    else:
        if runtime_path:
            errors.append("this runtime role can access a managed SSH private-key path")
        if any(path.exists() or path.is_symlink() for path in lane_sources.values()):
            errors.append("this runtime role mounts a managed SSH private-key secret")

    if errors:
        raise CommandError("Docker security preflight failed: " + "; ".join(errors))


def _assert_artifact_encryption_boundary(*, environment, runtime_settings):
    """Prove the hardened stack cannot transfer or restore plaintext artifacts."""

    errors = []
    if runtime_settings.BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE != "bse1":
        errors.append("artifact encryption mode is not BSE1")
    if runtime_settings.BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE is not True:
        errors.append("enterprise artifact policy is not active")
    if runtime_settings.BACKUPSHEEP_ARTIFACT_KEY_PROVIDER != "local-file":
        errors.append("artifact key custody is not the production local-file provider")
    provider_generation = str(
        getattr(
            runtime_settings,
            "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION",
            "",
        )
    )
    provider_witness = str(
        getattr(runtime_settings, "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS", "")
    )
    installation_id = str(
        getattr(runtime_settings, "BACKUPSHEEP_INSTALLATION_ID", "")
    )
    expected_provider_witness = artifact_provider_policy_witness(
        installation_id,
        "1",
    )
    if provider_generation != "1" or not hmac.compare_digest(
        provider_witness,
        expected_provider_witness,
    ):
        errors.append("artifact key-provider generation is not sealed to this installation")
    if runtime_settings.BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE is not False:
        errors.append("legacy plaintext restore is enabled")
    if environment.get("BACKUPSHEEP_PLAINTEXT_ROOT", "/code/_storage") != "/code/_storage":
        errors.append("the private artifact root is not the stock container path")
    if (
        environment.get(
            "BACKUPSHEEP_CIPHERTEXT_TRANSFER_ROOT",
            "/var/lib/backupsheep/transfer",
        )
        != "/var/lib/backupsheep/transfer"
    ):
        errors.append("the ciphertext transfer root is not the stock container path")
    runtime_role = str(environment.get("BACKUPSHEEP_RUNTIME_ROLE") or "")
    configured_keyring = str(
        getattr(
            runtime_settings,
            "BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH",
            "",
        )
    )
    lane_keyrings = {
        lane: Path(f"/run/secrets/artifact_local_file_{lane}_keyring")
        for lane in ("database", "files")
    }
    if runtime_role in lane_keyrings:
        expected_keyring = lane_keyrings[runtime_role]
        opposite_lane = "files" if runtime_role == "database" else "database"
        opposite_keyring = lane_keyrings[opposite_lane]
        if configured_keyring != str(expected_keyring):
            errors.append("the source role does not use its exact lane artifact keyring path")
        if not expected_keyring.exists() or expected_keyring.is_symlink():
            errors.append("the source role artifact keyring mount is absent or unsafe")
        if opposite_keyring.exists() or opposite_keyring.is_symlink():
            errors.append("the source role mounted the opposite artifact keyring")
    else:
        if configured_keyring:
            errors.append("the non-source preflight role received an artifact keyring path")
        for keyring_path in lane_keyrings.values():
            if keyring_path.exists() or keyring_path.is_symlink():
                errors.append("the non-source preflight role mounted an artifact keyring")
    if errors:
        raise CommandError(
            "Docker security preflight failed: " + "; ".join(errors)
        )


def _assert_artifact_keyring_database_state(*, cursor, environment, runtime_settings):
    """Prove the source lane retains every database-referenced wrapping key."""

    runtime_role = str(environment.get("BACKUPSHEEP_RUNTIME_ROLE") or "")
    if runtime_role not in {"database", "files"}:
        return

    from backupsheep.artifact_crypto.providers import LocalFileKeyProvider

    provider = None
    try:
        provider = LocalFileKeyProvider(
            runtime_settings.BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH,
            lane=runtime_role,
            installation_id=runtime_settings.BACKUPSHEEP_INSTALLATION_ID,
        )
        retained_key_ids = set(provider.key_ids)
        # Row-level security limits this query to the authenticated source lane.
        # Retired generations are intentionally excluded; active, pending and
        # manual-review wraps must all remain recoverable before new work starts.
        cursor.execute(
            """
            SELECT DISTINCT wrapping_key_id
            FROM core_backup_key_wrap
            WHERE provider = %s AND status <> %s
            """,
            ["local-file", "retired"],
        )
        referenced_key_ids = {
            str(row[0]) for row in cursor.fetchall() if row and row[0]
        }
        if not referenced_key_ids.issubset(retained_key_ids):
            raise CommandError(
                "Docker security preflight failed: the source artifact keyring "
                "is missing a non-retired database-referenced key"
            )
    except CommandError:
        raise
    except Exception as error:
        raise CommandError(
            "Docker security preflight failed: artifact keyring/database "
            "consistency could not be verified"
        ) from error
    finally:
        if provider is not None:
            provider.destroy()


class Command(BaseCommand):
    help = "Validate the stock Docker runtime boundary, database, and broker without consuming work."

    def handle(self, *args, **options):
        runtime_role = str(os.environ.get("BACKUPSHEEP_RUNTIME_ROLE") or "")
        try:
            expected_uid = EXPECTED_UID_BY_ROLE[runtime_role]
        except KeyError as error:
            raise CommandError(
                "Docker security preflight failed: runtime role is invalid"
            ) from error
        try:
            proc_status = Path("/proc/self/status").read_text(encoding="utf-8")
            mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
            root_flags = os.statvfs("/").f_flag
        except OSError as error:
            raise CommandError(f"Cannot inspect the Docker runtime boundary: {error}") from error

        _assert_process_boundary(
            uid=os.getuid(),
            proc_status=proc_status,
            root_flags=root_flags,
            core_limit=resource.getrlimit(resource.RLIMIT_CORE),
            expected_uid=expected_uid,
        )
        _assert_read_only_path(Path("/code"))
        _assert_read_only_path(Path("/etc"))
        _assert_private_writable_tmpfs(
            Path("/tmp"), mountinfo, expected_uid=expected_uid
        )
        _assert_private_writable_tmpfs(
            Path("/run/backupsheep"), mountinfo, expected_uid=expected_uid
        )

        required_secret_files = _required_secret_file_env(os.environ)
        for setting_name, expected_path in required_secret_files.items():
            if os.environ.get(setting_name):
                raise CommandError(
                    f"Docker security preflight failed: {setting_name} is exposed "
                    "as a direct environment variable"
                )
            if os.environ.get(f"{setting_name}_FILE") != expected_path:
                raise CommandError(
                    f"Docker security preflight failed: {setting_name}_FILE does not "
                    "use the stock /run/secrets target"
                )
        for setting_name in FORBIDDEN_CREDENTIAL_URL_ENV:
            if os.environ.get(setting_name):
                raise CommandError(
                    f"Docker security preflight failed: {setting_name} exposes a "
                    "credential URL and overrides the stock file-backed settings"
                )
        _assert_stock_configuration_sources(
            environment=os.environ,
            runtime_settings=settings,
            secret_values=_read_stock_secret_values(required_secret_files),
        )
        _assert_celery_identity(os.environ)
        _assert_celery_task_manifest(settings)
        _assert_managed_ssh_identity(
            environment=os.environ,
            runtime_settings=settings,
        )
        _assert_artifact_encryption_boundary(
            environment=os.environ,
            runtime_settings=settings,
        )

        static_root = Path(settings.STATIC_ROOT)
        if not static_root.is_dir() or not any(static_root.iterdir()):
            raise CommandError(
                "Docker security preflight failed: immutable collected static assets "
                "are missing from the image"
            )

        call_command("check", deploy=True, fail_level="ERROR", verbosity=0)
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                if cursor.fetchone() != (1,):
                    raise CommandError("Database authentication probe returned bad data")
                _assert_runtime_database_identity(
                    cursor=cursor,
                    environment=os.environ,
                    runtime_settings=settings,
                )
                _assert_artifact_keyring_database_state(
                    cursor=cursor,
                    environment=os.environ,
                    runtime_settings=settings,
                )
            _assert_no_pending_migrations(MigrationExecutor(connection))
        except CommandError:
            raise
        except Exception as error:
            raise CommandError("Database authentication probe failed") from error

        try:
            broker = Connection(settings.CELERY_BROKER_URL, connect_timeout=10)
            broker.ensure_connection(max_retries=0)
            broker.release()
        except Exception as error:
            raise CommandError("RabbitMQ authentication probe failed") from error

        self.stdout.write(
            self.style.SUCCESS(
                "Docker security preflight passed: immutable non-root runtime, "
                "file-backed secrets, lane-scoped BSE1 artifact custody, "
                "least-privilege database identity, applied migrations, database, "
                "and broker verified."
            )
        )
