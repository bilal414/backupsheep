"""Fail closed unless the stock Docker security boundary is actually active."""

from __future__ import annotations

import errno
import hmac
import os
import re
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


EXPECTED_UID = 10001
REQUIRED_SECRET_FILE_ENV = {
    "DJANGO_SECRET_KEY": "/run/secrets/django_secret_key",
    "DB_PASSWORD": "/run/secrets/db_password",
    "RABBITMQ_PASSWORD": "/run/secrets/rabbitmq_password",
}
FORBIDDEN_CREDENTIAL_URL_ENV = ("DATABASE_URL", "CELERY_BROKER_URL")
INSTALLATION_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _assert_stock_configuration_sources(*, environment, runtime_settings, secret_values):
    errors = []
    if environment.get("DJANGO_SETTINGS_MODULE") != "backupsheep.settings":
        errors.append("DJANGO_SETTINGS_MODULE does not select backupsheep.settings")
    if environment.get("BACKUPSHEEP_SECRETS"):
        errors.append("BACKUPSHEEP_SECRETS replaces the reviewed stock configuration")

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


def _read_stock_secret_values():
    values = {}
    for setting_name, expected_path in REQUIRED_SECRET_FILE_ENV.items():
        try:
            values[setting_name] = Path(expected_path).read_text(encoding="utf-8").rstrip("\n")
        except OSError as error:
            raise CommandError(
                "Docker security preflight failed: could not read a required stock secret file"
            ) from error
    return values


def _proc_status_values(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key] = value.strip()
    return values


def _assert_process_boundary(*, uid: int, proc_status: str, root_flags: int, core_limit):
    errors = []
    status_values = _proc_status_values(proc_status)
    if uid != EXPECTED_UID:
        errors.append(f"runtime UID must be {EXPECTED_UID}, observed {uid}")
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


def _assert_private_writable_tmpfs(path: Path, mountinfo: str):
    try:
        metadata = path.stat()
    except OSError as error:
        raise CommandError(f"Required tmpfs path {path} is unavailable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise CommandError(f"Required tmpfs path {path} is not a directory")
    if path == Path("/run/backupsheep") and metadata.st_uid != EXPECTED_UID:
        raise CommandError(
            f"Required tmpfs path {path} must be owned by UID {EXPECTED_UID}"
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
    """Prove the active Django login is the marked, non-owner runtime role."""

    errors = []
    generation = str(environment.get("BACKUPSHEEP_DATABASE_IDENTITY_GENERATION") or "")
    installation_id = str(environment.get("BACKUPSHEEP_INSTALLATION_ID") or "")
    bootstrap_user = str(environment.get("DB_BOOTSTRAP_USER") or "")
    migrator_user = str(environment.get("DB_MIGRATOR_USER") or "")
    runtime_user = str(environment.get("DB_USER") or "")
    configured_user = str(
        runtime_settings.DATABASES.get("default", {}).get("USER", "") or ""
    )
    if generation != "2":
        errors.append("database identity generation is not 2")
    if not INSTALLATION_ID_PATTERN.fullmatch(installation_id):
        errors.append("installation identity is malformed")
    if not runtime_user or configured_user != runtime_user:
        errors.append("Django is not configured for the stock runtime database role")
    if len({bootstrap_user, migrator_user, runtime_user}) != 3 or not all(
        (bootstrap_user, migrator_user, runtime_user)
    ):
        errors.append("database bootstrap, migrator, and runtime roles are not distinct")

    cursor.execute(
        """
        SELECT current_user,
               role.rolsuper, role.rolcreatedb, role.rolcreaterole,
               role.rolreplication, role.rolbypassrls, role.rolcanlogin,
               COALESCE(pg_catalog.shobj_description(role.oid, 'pg_authid'), ''),
               pg_catalog.pg_get_userbyid(database.datdba),
               pg_catalog.pg_get_userbyid(namespace.nspowner),
               pg_catalog.has_database_privilege(
                   current_user, current_database(), 'CREATE'
               ),
               pg_catalog.has_database_privilege(
                   current_user, current_database(), 'TEMPORARY'
               ),
               pg_catalog.has_schema_privilege(current_user, 'public', 'CREATE')
          FROM pg_catalog.pg_roles role
          JOIN pg_catalog.pg_database database
            ON database.datname = current_database()
          JOIN pg_catalog.pg_namespace namespace
            ON namespace.nspname = 'public'
         WHERE role.rolname = current_user
        """
    )
    record = cursor.fetchone()
    if record is None:
        errors.append("the active database login is absent from pg_roles")
    else:
        (
            active_user,
            superuser,
            create_database,
            create_role,
            replication,
            bypass_rls,
            can_login,
            marker,
            database_owner,
            schema_owner,
            database_create,
            database_temporary,
            schema_create,
        ) = record
        if active_user != runtime_user:
            errors.append("the active database login is not DB_USER")
        if superuser or create_database or create_role or replication or bypass_rls:
            errors.append("the runtime database role has elevated role attributes")
        if not can_login:
            errors.append("the runtime database role cannot log in")
        expected_marker = (
            f"backupsheep:database-identity-v2:{installation_id}:runtime"
        )
        if marker != expected_marker:
            errors.append("the runtime database role marker does not match this installation")
        if database_owner != migrator_user or schema_owner != migrator_user:
            errors.append("the migrator does not own the database and public schema")
        if database_create or database_temporary or schema_create:
            errors.append("the runtime database role retains DDL or temporary-object privilege")

    cursor.execute(
        """
        SELECT 'member of ' || parent.rolname
          FROM pg_catalog.pg_auth_members membership
          JOIN pg_catalog.pg_roles member ON member.oid = membership.member
          JOIN pg_catalog.pg_roles parent ON parent.oid = membership.roleid
         WHERE member.rolname = current_user
        UNION ALL
        SELECT 'granted to ' || member.rolname
          FROM pg_catalog.pg_auth_members membership
          JOIN pg_catalog.pg_roles member ON member.oid = membership.member
          JOIN pg_catalog.pg_roles parent ON parent.oid = membership.roleid
         WHERE parent.rolname = current_user
         ORDER BY 1
        """
    )
    memberships = [row[0] for row in cursor.fetchall()]
    if memberships:
        errors.append("the runtime database role has role memberships")

    if errors:
        raise CommandError(
            "Docker security preflight failed: " + "; ".join(errors)
        )


class Command(BaseCommand):
    help = "Validate the stock Docker runtime boundary, database, and broker without consuming work."

    def handle(self, *args, **options):
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
        )
        _assert_read_only_path(Path("/code"))
        _assert_read_only_path(Path("/etc"))
        _assert_private_writable_tmpfs(Path("/tmp"), mountinfo)
        _assert_private_writable_tmpfs(Path("/run/backupsheep"), mountinfo)

        for setting_name, expected_path in REQUIRED_SECRET_FILE_ENV.items():
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
            secret_values=_read_stock_secret_values(),
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
                "file-backed secrets, least-privilege database identity, applied "
                "migrations, database, and broker verified."
            )
        )
