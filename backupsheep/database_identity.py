"""Provision the stock Docker PostgreSQL identities without exposing passwords.

The bundled PostgreSQL image must bootstrap a fresh cluster with a superuser.  That
credential is deliberately confined to the database container and two one-shot
provisioner phases.  Django migrations use a separate object-owning login and every
long-lived application lane uses its own non-owner login and password.

This module is executed as ``python -m backupsheep.database_identity provision``
inside the immutable application image.  It is intentionally independent of Django
settings: loading Django with the bootstrap credential would make an accidental
management command a privileged database client.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

import psycopg2
from psycopg2 import sql

from backupsheep.database_lane_policy import (
    EXPECTED_TABLES,
    EXPECTED_ROUTINE_ATTRIBUTES,
    EXPECTED_ROUTINES,
    EXPECTED_MANAGED_SSH_FOREIGN_KEYS,
    EXPECTED_TRIGGERS,
    LANE_COLUMN_SELECT_POLICY,
    LANE_COLUMN_UPDATE_POLICY,
    LANE_TABLE_POLICY,
    LANES,
    REPLAY_TABLE,
    ROW_SECURITY_TABLES,
    ROUTINE_EXECUTE_POLICY,
    TABLE_PRIVILEGES,
    row_policy_definitions,
)


IDENTITY_GENERATION = "3"
SECRET_ROOT = Path("/run/secrets")
MAX_SECRET_BYTES = 4096
ROLE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
INSTALLATION_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
LANE_ENVIRONMENT = MappingProxyType(
    {
        "app": ("DB_APP_USER", "DB_APP_PASSWORD_FILE"),
        "preflight": ("DB_PREFLIGHT_USER", "DB_PREFLIGHT_PASSWORD_FILE"),
        "beat": ("DB_BEAT_USER", "DB_BEAT_PASSWORD_FILE"),
        "cloud": ("DB_CLOUD_USER", "DB_CLOUD_PASSWORD_FILE"),
        "database": ("DB_DATABASE_USER", "DB_DATABASE_PASSWORD_FILE"),
        "files": ("DB_FILES_USER", "DB_FILES_PASSWORD_FILE"),
        "storage": ("DB_STORAGE_USER", "DB_STORAGE_PASSWORD_FILE"),
        "logs": ("DB_LOGS_USER", "DB_LOGS_PASSWORD_FILE"),
    }
)


class ProvisioningError(RuntimeError):
    """A fail-closed database identity contract violation."""


def _policy_witness(
    *,
    installation_id: str,
    table: str,
    lane: str,
    command: str,
    source_predicate: str,
    catalog_using: str | None,
    catalog_check: str | None,
) -> str:
    """Bind a policy comment to both reviewed source and catalog expressions.

    PostgreSQL rewrites policy expressions with casts and parentheses.  Recording
    both hashes lets an unprivileged preflight validate drift without needing CREATE
    privilege to ask PostgreSQL to parse a second copy of the source expression.
    """

    source_digest = hashlib.sha256(
        (command + "\0" + source_predicate).encode("utf-8")
    ).hexdigest()
    catalog_digest = hashlib.sha256(
        ((catalog_using or "") + "\0" + (catalog_check or "")).encode("utf-8")
    ).hexdigest()
    return (
        "backupsheep:database-identity-v3:"
        f"{installation_id}:rls:{table}:{lane}:{command.lower()}"
        + f":source={source_digest}:catalog={catalog_digest}"
    )


def _required_environment(environment: dict[str, str], name: str) -> str:
    value = str(environment.get(name) or "").strip()
    if not value:
        raise ProvisioningError(f"{name} is required")
    return value


def _role_name(environment: dict[str, str], name: str) -> str:
    value = _required_environment(environment, name)
    if not ROLE_PATTERN.fullmatch(value):
        raise ProvisioningError(
            f"{name} must be a lowercase PostgreSQL role identifier"
        )
    return value


def _read_secret(path_value: str, label: str, *, root: Path = SECRET_ROOT) -> str:
    """Read one direct, regular, immutable-style Compose secret file."""

    try:
        resolved_root = root.resolve(strict=True)
        path = Path(path_value)
        if not path.is_absolute():
            raise ProvisioningError(f"{label} secret path must be absolute")
        unresolved = path.lstat()
        if stat.S_ISLNK(unresolved.st_mode):
            raise ProvisioningError(f"{label} secret must not be a symbolic link")
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(resolved_root)
    except ProvisioningError:
        raise
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as error:
        raise ProvisioningError(
            f"{label} secret must be an existing file directly below {root}"
        ) from error
    if len(relative.parts) != 1:
        raise ProvisioningError(f"{label} secret must be directly below {root}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise ProvisioningError(f"{label} secret could not be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ProvisioningError(
                f"{label} secret must be one regular, non-hard-linked file"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ProvisioningError(f"{label} secret must not be group/world writable")
        if metadata.st_size <= 0 or metadata.st_size > MAX_SECRET_BYTES:
            raise ProvisioningError(f"{label} secret has an invalid size")
        payload = os.read(descriptor, MAX_SECRET_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_SECRET_BYTES:
        raise ProvisioningError(f"{label} secret is too large")
    if b"\x00" in payload or b"\r" in payload:
        raise ProvisioningError(f"{label} secret must contain exactly one line")
    if payload.endswith(b"\n"):
        payload = payload[:-1]
    if not payload or b"\n" in payload:
        raise ProvisioningError(f"{label} secret must contain exactly one line")
    try:
        value = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProvisioningError(f"{label} secret is not UTF-8") from error
    if len(value) < 24:
        raise ProvisioningError(f"{label} secret is shorter than 24 characters")
    return value


@dataclass(frozen=True)
class IdentityConfiguration:
    installation_id: str
    database: str
    host: str
    port: int
    bootstrap_user: str
    migrator_user: str
    bootstrap_password: str
    migrator_password: str
    lane_users: Mapping[str, str]
    lane_passwords: Mapping[str, str]

    @classmethod
    def from_environment(
        cls,
        environment: dict[str, str] | None = None,
        *,
        secret_root: Path = SECRET_ROOT,
    ) -> "IdentityConfiguration":
        values = dict(os.environ if environment is None else environment)
        generation = _required_environment(
            values, "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION"
        )
        if generation != IDENTITY_GENERATION:
            raise ProvisioningError(
                "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION must be 3"
            )
        installation_id = _required_environment(values, "BACKUPSHEEP_INSTALLATION_ID")
        if not INSTALLATION_ID_PATTERN.fullmatch(installation_id):
            raise ProvisioningError(
                "BACKUPSHEEP_INSTALLATION_ID must be 64 lowercase hexadecimal characters"
            )
        database = _required_environment(values, "DB_NAME")
        if "\x00" in database or len(database) > 63:
            raise ProvisioningError("DB_NAME is not a valid PostgreSQL identifier")
        host = _required_environment(values, "DB_HOST")
        if host != "db":
            raise ProvisioningError("DB_HOST must be the stock internal service name db")
        try:
            port = int(_required_environment(values, "DB_PORT"))
        except ValueError as error:
            raise ProvisioningError("DB_PORT must be an integer") from error
        if not 1 <= port <= 65535:
            raise ProvisioningError("DB_PORT must be between 1 and 65535")
        if port != 5432:
            raise ProvisioningError("DB_PORT must be 5432 for the stock database")

        bootstrap_user = _role_name(values, "DB_BOOTSTRAP_USER")
        migrator_user = _role_name(values, "DB_MIGRATOR_USER")
        lane_users = {
            lane: _role_name(values, variable)
            for lane, (variable, _secret_variable) in LANE_ENVIRONMENT.items()
        }
        all_users = {bootstrap_user, migrator_user, *lane_users.values()}
        if len(all_users) != 2 + len(LANES):
            raise ProvisioningError(
                "bootstrap, migrator, and every lane database role must be distinct"
            )

        def secret(variable: str, label: str) -> str:
            path = _required_environment(values, variable)
            return _read_secret(path, label, root=secret_root)

        bootstrap_password = secret(
            "DB_BOOTSTRAP_PASSWORD_FILE", "database bootstrap"
        )
        migrator_password = secret(
            "DB_MIGRATOR_PASSWORD_FILE", "database migrator"
        )
        lane_passwords = {
            lane: secret(secret_variable, f"database {lane}")
            for lane, (_user_variable, secret_variable) in LANE_ENVIRONMENT.items()
        }
        all_passwords = {
            bootstrap_password,
            migrator_password,
            *lane_passwords.values(),
        }
        if len(all_passwords) != 2 + len(LANES):
            raise ProvisioningError(
                "bootstrap, migrator, and every lane database credential must be distinct"
            )

        return cls(
            installation_id=installation_id,
            database=database,
            host=host,
            port=port,
            bootstrap_user=bootstrap_user,
            migrator_user=migrator_user,
            bootstrap_password=bootstrap_password,
            migrator_password=migrator_password,
            lane_users=MappingProxyType(lane_users),
            lane_passwords=MappingProxyType(lane_passwords),
        )

    def marker(self, role_kind: str) -> str:
        return (
            "backupsheep:database-identity-v3:"
            f"{self.installation_id}:{role_kind}"
        )

    def legacy_marker(self, role_kind: str) -> str:
        return (
            "backupsheep:database-identity-v2:"
            f"{self.installation_id}:{role_kind}"
        )


def _role_record(cursor, role_name: str):
    cursor.execute(
        """
        SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication,
               rolbypassrls, rolcanlogin,
               COALESCE(shobj_description(oid, 'pg_authid'), '')
          FROM pg_catalog.pg_roles
         WHERE rolname = %s
        """,
        (role_name,),
    )
    return cursor.fetchone()


def _assert_no_memberships(cursor, role_name: str) -> None:
    cursor.execute(
        """
        SELECT 'member of ' || parent.rolname
          FROM pg_catalog.pg_auth_members membership
          JOIN pg_catalog.pg_roles member ON member.oid = membership.member
          JOIN pg_catalog.pg_roles parent ON parent.oid = membership.roleid
         WHERE member.rolname = %s
        UNION ALL
        SELECT 'granted to ' || member.rolname
          FROM pg_catalog.pg_auth_members membership
          JOIN pg_catalog.pg_roles member ON member.oid = membership.member
          JOIN pg_catalog.pg_roles parent ON parent.oid = membership.roleid
         WHERE parent.rolname = %s
         ORDER BY 1
        """,
        (role_name, role_name),
    )
    memberships = [row[0] for row in cursor.fetchall()]
    if memberships:
        raise ProvisioningError(
            f"database role {role_name} has unexpected memberships: "
            + ", ".join(memberships)
        )


def _ensure_application_role(
    cursor,
    *,
    role_name: str,
    password: str,
    marker: str,
    allowed_existing_markers: frozenset[str] = frozenset(),
) -> None:
    record = _role_record(cursor, role_name)
    if record is None:
        cursor.execute(
            sql.SQL(
                "CREATE ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD %s"
            ).format(sql.Identifier(role_name)),
            (password,),
        )
    else:
        (
            _name,
            superuser,
            createdb,
            createrole,
            replication,
            bypassrls,
            login,
            comment,
        ) = record
        if comment != marker and comment not in allowed_existing_markers:
            raise ProvisioningError(
                f"database role {role_name} already exists without this installation's marker"
            )
        if superuser or createdb or createrole or replication or bypassrls or not login:
            raise ProvisioningError(
                f"database role {role_name} has unsafe attributes"
            )
        _assert_no_memberships(cursor, role_name)
        cursor.execute(
            sql.SQL(
                "ALTER ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD %s"
            ).format(sql.Identifier(role_name)),
            (password,),
        )
    cursor.execute(
        sql.SQL("COMMENT ON ROLE {} IS %s").format(sql.Identifier(role_name)),
        (marker,),
    )


def _assert_bootstrap_role(cursor, config: IdentityConfiguration) -> None:
    cursor.execute("SELECT current_user")
    if cursor.fetchone()[0] != config.bootstrap_user:
        raise ProvisioningError("database connection did not use DB_BOOTSTRAP_USER")
    record = _role_record(cursor, config.bootstrap_user)
    if record is None or not record[1] or not record[6]:
        raise ProvisioningError(
            "database bootstrap role must be a login superuser"
        )
    existing_comment = record[7]
    marker = config.marker("bootstrap")
    if existing_comment and existing_comment not in {
        marker,
        config.legacy_marker("bootstrap"),
    }:
        raise ProvisioningError(
            "database bootstrap role is marked for a different installation"
        )
    cursor.execute(
        sql.SQL("COMMENT ON ROLE {} IS %s").format(
            sql.Identifier(config.bootstrap_user)
        ),
        (marker,),
    )


def _reject_inventory(cursor, query: str, category: str) -> None:
    """Reject stock-Docker database objects outside the reviewed migration set."""

    cursor.execute(query)
    objects = [str(row[0]) for row in cursor.fetchall()]
    if objects:
        raise ProvisioningError(
            f"database contains unsupported {category}: " + ", ".join(objects[:10])
        )


def _assert_supported_database_shape(
    cursor, config: IdentityConfiguration
) -> None:
    """Bound automatic ownership migration to objects the provisioner understands.

    PostgreSQL's bootstrap superuser is a pinned role.  Ownership dependencies for
    objects it creates are therefore not guaranteed to appear in ``pg_shdepend``.
    Explicit catalog inventories are required; otherwise an empty custom schema or
    a user-defined type could silently retain the superuser as owner.
    """

    _reject_inventory(
        cursor,
        """
        SELECT namespace.nspname
          FROM pg_catalog.pg_namespace namespace
         WHERE namespace.nspname <> 'public'
           AND namespace.nspname <> 'information_schema'
           AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
         ORDER BY namespace.nspname
        """,
        "schemas outside public",
    )
    _reject_inventory(
        cursor,
        """
        SELECT extension.extname
          FROM pg_catalog.pg_extension extension
         WHERE extension.extname <> 'plpgsql'
         ORDER BY extension.extname
        """,
        "extensions",
    )
    _reject_inventory(
        cursor,
        """
        SELECT relation.relname || ' (' || relation.relkind::text || ')'
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace namespace
            ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relkind NOT IN ('r', 'p', 'S', 'v', 'm', 'f', 'i', 'I')
         ORDER BY relation.relname
        """,
        "relation kinds",
    )
    _reject_inventory(
        cursor,
        """
        SELECT database_type.typname
          FROM pg_catalog.pg_type database_type
          JOIN pg_catalog.pg_namespace namespace
            ON namespace.oid = database_type.typnamespace
          LEFT JOIN pg_catalog.pg_type element_type
            ON element_type.oid = database_type.typelem
          LEFT JOIN pg_catalog.pg_class element_relation
            ON element_relation.oid = element_type.typrelid
         WHERE namespace.nspname = 'public'
           AND database_type.typrelid = 0
           AND NOT (
               database_type.typelem <> 0
               AND element_relation.relkind IN ('r', 'p', 'v', 'm', 'f')
           )
         ORDER BY database_type.typname
        """,
        "standalone types",
    )
    _reject_inventory(
        cursor,
        """
        SELECT inventory.kind || ' ' || inventory.name
          FROM (
                SELECT 'collation' AS kind, coll.collname AS name
                  FROM pg_catalog.pg_collation coll
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = coll.collnamespace
                 WHERE namespace.nspname = 'public'
                UNION ALL
                SELECT 'conversion', conv.conname
                  FROM pg_catalog.pg_conversion conv
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = conv.connamespace
                 WHERE namespace.nspname = 'public'
                UNION ALL
                SELECT 'operator', opr.oprname
                  FROM pg_catalog.pg_operator opr
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = opr.oprnamespace
                 WHERE namespace.nspname = 'public'
                UNION ALL
                SELECT 'operator class', opc.opcname
                  FROM pg_catalog.pg_opclass opc
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = opc.opcnamespace
                 WHERE namespace.nspname = 'public'
                UNION ALL
                SELECT 'operator family', opf.opfname
                  FROM pg_catalog.pg_opfamily opf
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = opf.opfnamespace
                 WHERE namespace.nspname = 'public'
                UNION ALL
                SELECT 'statistics', stat.stxname
                  FROM pg_catalog.pg_statistic_ext stat
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = stat.stxnamespace
                 WHERE namespace.nspname = 'public'
                UNION ALL
                SELECT 'text search configuration', cfg.cfgname
                  FROM pg_catalog.pg_ts_config cfg
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = cfg.cfgnamespace
                 WHERE namespace.nspname = 'public'
                UNION ALL
                SELECT 'text search dictionary', dict.dictname
                  FROM pg_catalog.pg_ts_dict dict
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = dict.dictnamespace
                 WHERE namespace.nspname = 'public'
                UNION ALL
                SELECT 'text search parser', prs.prsname
                  FROM pg_catalog.pg_ts_parser prs
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = prs.prsnamespace
                 WHERE namespace.nspname = 'public'
                UNION ALL
                SELECT 'text search template', tmpl.tmplname
                  FROM pg_catalog.pg_ts_template tmpl
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = tmpl.tmplnamespace
                 WHERE namespace.nspname = 'public'
               ) inventory
         ORDER BY inventory.kind, inventory.name
        """,
        "user-defined catalog objects",
    )
    _reject_inventory(
        cursor,
        """
        SELECT inventory.kind || ' ' || inventory.name
          FROM (
                SELECT 'event trigger' AS kind, evt.evtname AS name
                  FROM pg_catalog.pg_event_trigger evt
                UNION ALL
                SELECT 'foreign-data wrapper', fdw.fdwname
                  FROM pg_catalog.pg_foreign_data_wrapper fdw
                UNION ALL
                SELECT 'foreign server', srv.srvname
                  FROM pg_catalog.pg_foreign_server srv
                UNION ALL
                SELECT 'large object', lom.oid::text
                  FROM pg_catalog.pg_largeobject_metadata lom
                UNION ALL
                SELECT 'publication', pub.pubname
                  FROM pg_catalog.pg_publication pub
                UNION ALL
                SELECT 'subscription', sub.subname
                  FROM pg_catalog.pg_subscription sub
                 WHERE sub.subdbid = (
                           SELECT database.oid
                             FROM pg_catalog.pg_database database
                            WHERE database.datname = current_database()
                       )
               ) inventory
         ORDER BY inventory.kind, inventory.name
        """,
        "cluster object classes",
    )
    _reject_inventory(
        cursor,
        """
        SELECT lang.lanname
          FROM pg_catalog.pg_language lang
         WHERE lang.lanname NOT IN ('internal', 'c', 'sql', 'plpgsql')
         ORDER BY lang.lanname
        """,
        "procedural languages",
    )
    cursor.execute(
        """
        SELECT role.rolname || ':' ||
               COALESCE(namespace.nspname, '<global>') || ':' ||
               defaults.defaclobjtype::text
          FROM pg_catalog.pg_default_acl defaults
          JOIN pg_catalog.pg_roles role ON role.oid = defaults.defaclrole
          LEFT JOIN pg_catalog.pg_namespace namespace
            ON namespace.oid = defaults.defaclnamespace
         WHERE role.rolname <> %s
         ORDER BY role.rolname, namespace.nspname, defaults.defaclobjtype
        """,
        (config.migrator_user,),
    )
    unexpected_defaults = [str(row[0]) for row in cursor.fetchall()]
    if unexpected_defaults:
        raise ProvisioningError(
            "database contains unsupported default privileges: "
            + ", ".join(unexpected_defaults[:10])
        )


def _transfer_public_ownership(cursor, config: IdentityConfiguration) -> None:
    cursor.execute(
        """
        SELECT owner.rolname
          FROM pg_catalog.pg_database database
          JOIN pg_catalog.pg_roles owner ON owner.oid = database.datdba
         WHERE database.datname = current_database()
        """
    )
    database_owner = cursor.fetchone()[0]
    if database_owner not in {config.bootstrap_user, config.migrator_user}:
        raise ProvisioningError(
            f"database is owned by unexpected role {database_owner}"
        )

    cursor.execute(
        """
        SELECT owner.rolname
          FROM pg_catalog.pg_namespace namespace
          JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
         WHERE namespace.nspname = 'public'
        """
    )
    public_schema_owner = cursor.fetchone()[0]
    if public_schema_owner not in {
        config.bootstrap_user,
        config.migrator_user,
        "pg_database_owner",
    }:
        raise ProvisioningError(
            f"public schema is owned by unexpected role {public_schema_owner}"
        )

    cursor.execute(
        """
        SELECT namespace.nspname, relation.relname, relation.relkind, owner.rolname
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
          JOIN pg_catalog.pg_roles owner ON owner.oid = relation.relowner
         WHERE namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND namespace.nspname <> 'information_schema'
           AND relation.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
         ORDER BY namespace.nspname, relation.relname
        """
    )
    relations = cursor.fetchall()
    unexpected = [
        f"{schema}.{name}"
        for schema, name, _kind, owner in relations
        if schema != "public"
        or owner not in {config.bootstrap_user, config.migrator_user}
    ]
    if unexpected:
        raise ProvisioningError(
            "database contains relations outside the reviewed ownership boundary: "
            + ", ".join(unexpected[:10])
        )

    commands = {
        "r": "ALTER TABLE {}.{} OWNER TO {}",
        "p": "ALTER TABLE {}.{} OWNER TO {}",
        "S": "ALTER SEQUENCE {}.{} OWNER TO {}",
        "v": "ALTER VIEW {}.{} OWNER TO {}",
        "m": "ALTER MATERIALIZED VIEW {}.{} OWNER TO {}",
        "f": "ALTER FOREIGN TABLE {}.{} OWNER TO {}",
    }
    # A sequence can be OWNED BY a table column and PostgreSQL requires both objects
    # to have the same owner. Transfer tables/views first and sequences last so an
    # otherwise valid legacy schema cannot fail according to lexical object order.
    relation_order = {"r": 0, "p": 0, "v": 0, "m": 0, "f": 0, "S": 1}
    for schema, name, kind, owner in sorted(
        relations, key=lambda row: (relation_order[row[2]], row[0], row[1])
    ):
        if owner == config.migrator_user:
            continue
        cursor.execute(
            sql.SQL(commands[kind]).format(
                sql.Identifier(schema),
                sql.Identifier(name),
                sql.Identifier(config.migrator_user),
            )
        )

    cursor.execute(
        """
        SELECT namespace.nspname, procedure.proname, procedure.prokind,
               pg_catalog.pg_get_function_identity_arguments(procedure.oid),
               owner.rolname
          FROM pg_catalog.pg_proc procedure
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
          JOIN pg_catalog.pg_roles owner ON owner.oid = procedure.proowner
         WHERE namespace.nspname = 'public'
         ORDER BY procedure.oid
        """
    )
    procedures = cursor.fetchall()
    unexpected_procedures = [
        f"{schema}.{name}"
        for schema, name, _kind, _arguments, owner in procedures
        if owner not in {config.bootstrap_user, config.migrator_user}
    ]
    if unexpected_procedures:
        raise ProvisioningError(
            "database contains routines outside the reviewed ownership boundary: "
            + ", ".join(unexpected_procedures[:10])
        )
    routine_commands = {
        "f": "ALTER FUNCTION {}.{}({}) OWNER TO {}",
        "p": "ALTER PROCEDURE {}.{}({}) OWNER TO {}",
        "a": "ALTER AGGREGATE {}.{}({}) OWNER TO {}",
        "w": "ALTER FUNCTION {}.{}({}) OWNER TO {}",
    }
    for schema, name, kind, arguments, owner in procedures:
        if owner == config.migrator_user:
            continue
        # Identity arguments are generated by PostgreSQL from catalog data. They are
        # deliberately composed as SQL because quoting them as one identifier would
        # change the function signature.
        cursor.execute(
            sql.SQL(routine_commands[kind]).format(
                sql.Identifier(schema),
                sql.Identifier(name),
                sql.SQL(arguments),
                sql.Identifier(config.migrator_user),
            )
        )

    cursor.execute(
        sql.SQL("ALTER DATABASE {} OWNER TO {}").format(
            sql.Identifier(config.database),
            sql.Identifier(config.migrator_user),
        )
    )
    cursor.execute(
        sql.SQL("ALTER SCHEMA public OWNER TO {}").format(
            sql.Identifier(config.migrator_user)
        )
    )

    # PostgreSQL ownership spans more catalog types than Django normally creates
    # (for example enums, domains, collations and text-search objects). Do not leave
    # one of those silently owned by the bootstrap superuser. A legacy installation
    # with such an object must use a reviewed manual migration and then retry.
    cursor.execute(
        """
        SELECT dependency.classid::pg_catalog.regclass::text, dependency.objid
          FROM pg_catalog.pg_shdepend dependency
          JOIN pg_catalog.pg_roles owner ON owner.oid = dependency.refobjid
         WHERE dependency.dbid = (
                   SELECT oid
                     FROM pg_catalog.pg_database
                    WHERE datname = current_database()
               )
           AND dependency.refclassid = 'pg_catalog.pg_authid'::pg_catalog.regclass
           AND dependency.deptype = 'o'
           AND owner.rolname = %s
         ORDER BY dependency.classid::pg_catalog.regclass::text, dependency.objid
         LIMIT 10
        """,
        (config.bootstrap_user,),
    )
    remaining_ownership = cursor.fetchall()
    if remaining_ownership:
        descriptions = [f"{catalog} oid {oid}" for catalog, oid in remaining_ownership]
        raise ProvisioningError(
            "database contains unsupported objects still owned by the bootstrap role: "
            + ", ".join(descriptions)
        )


def _legacy_runtime_roles(cursor, config: IdentityConfiguration) -> tuple[str, ...]:
    """Return this installation's generation-2 runtime role, if one exists."""

    cursor.execute(
        """
        SELECT role.rolname
          FROM pg_catalog.pg_roles role
         WHERE pg_catalog.shobj_description(role.oid, 'pg_authid') = %s
         ORDER BY role.rolname
        """,
        (config.legacy_marker("runtime"),),
    )
    roles = tuple(str(row[0]) for row in cursor.fetchall())
    if len(roles) > 1:
        raise ProvisioningError(
            "multiple generation-2 runtime roles claim this installation"
        )
    protected = {
        config.bootstrap_user,
        config.migrator_user,
        *config.lane_users.values(),
    }
    if any(role in protected for role in roles):
        raise ProvisioningError(
            "the generation-2 runtime role collides with a generation-3 role"
        )
    return roles


def _configure_role_defaults(cursor, role_name: str, *, connection_limit: int) -> None:
    role = sql.Identifier(role_name)
    cursor.execute(sql.SQL("ALTER ROLE {} RESET ALL").format(role))
    cursor.execute(
        sql.SQL("ALTER ROLE {} CONNECTION LIMIT {}").format(
            role, sql.Literal(connection_limit)
        )
    )
    # ``search_path`` is a PostgreSQL identifier list, not one string-valued GUC.
    # Quoting ``public, pg_catalog`` as a literal would select a single nonexistent
    # schema and make the one-shot migrator fail before creating django_migrations.
    cursor.execute(
        sql.SQL("ALTER ROLE {} SET search_path TO public, pg_catalog").format(role)
    )
    settings = {
        "statement_timeout": "1h",
        "lock_timeout": "30s",
        "idle_in_transaction_session_timeout": "5min",
    }
    for name, value in settings.items():
        cursor.execute(
            sql.SQL("ALTER ROLE {} SET {} TO {}").format(
                role, sql.Identifier(name), sql.Literal(value)
            )
        )


def _revoke_default_privileges(
    cursor,
    config: IdentityConfiguration,
    grantees: tuple[str, ...],
) -> None:
    migrator = sql.Identifier(config.migrator_user)
    object_types = ("TABLES", "SEQUENCES", "FUNCTIONS", "TYPES")
    for object_type in object_types:
        cursor.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                "REVOKE ALL ON {} FROM PUBLIC"
            ).format(migrator, sql.SQL(object_type))
        )
        for grantee in grantees:
            cursor.execute(
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                    "REVOKE ALL ON {} FROM {}"
                ).format(
                    migrator,
                    sql.SQL(object_type),
                    sql.Identifier(grantee),
                )
            )


def _prepare_privilege_boundary(
    cursor,
    config: IdentityConfiguration,
    legacy_roles: tuple[str, ...],
) -> None:
    """Revoke every runtime grant before the one-shot migrator runs."""

    database = sql.Identifier(config.database)
    migrator = sql.Identifier(config.migrator_user)
    runtime_roles = tuple(config.lane_users.values()) + legacy_roles

    cursor.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(database))
    cursor.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    cursor.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
    cursor.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC")
    cursor.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC")
    cursor.execute("REVOKE ALL ON ALL ROUTINES IN SCHEMA public FROM PUBLIC")

    for role_name in runtime_roles:
        role = sql.Identifier(role_name)
        cursor.execute(
            sql.SQL("REVOKE ALL ON DATABASE {} FROM {}").format(database, role)
        )
        cursor.execute(sql.SQL("REVOKE ALL ON SCHEMA public FROM {}").format(role))
        cursor.execute(
            sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(role)
        )
        cursor.execute(
            sql.SQL("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {}").format(
                role
            )
        )
        cursor.execute(
            sql.SQL("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM {}").format(
                role
            )
        )
        cursor.execute(
            sql.SQL("REVOKE ALL ON ALL ROUTINES IN SCHEMA public FROM {}").format(
                role
            )
        )

    _revoke_default_privileges(cursor, config, runtime_roles)
    cursor.execute(
        sql.SQL("GRANT CONNECT, TEMPORARY, CREATE ON DATABASE {} TO {}").format(
            database, migrator
        )
    )
    cursor.execute(
        sql.SQL("GRANT USAGE, CREATE ON SCHEMA public TO {}").format(migrator)
    )
    _configure_role_defaults(cursor, config.migrator_user, connection_limit=8)

    for lane, role_name in config.lane_users.items():
        role = sql.Identifier(role_name)
        cursor.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(database, role))
        cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(role))
        _configure_role_defaults(
            cursor,
            role_name,
            connection_limit=8 if lane in {"preflight", "beat"} else 128,
        )

    for legacy_role in legacy_roles:
        _assert_no_memberships(cursor, legacy_role)
        cursor.execute(
            sql.SQL("ALTER ROLE {} NOLOGIN PASSWORD NULL").format(
                sql.Identifier(legacy_role)
            )
        )
        cursor.execute(
            sql.SQL("ALTER ROLE {} RESET ALL").format(sql.Identifier(legacy_role))
        )
        cursor.execute(
            sql.SQL("COMMENT ON ROLE {} IS %s").format(sql.Identifier(legacy_role)),
            (config.marker("retired-v2-runtime"),),
        )
        # Existing sessions retain authentication after NOLOGIN.  Terminate only this
        # exact marked legacy role while operations are stopped by the installer.
        cursor.execute(
            """
            SELECT pg_catalog.pg_terminate_backend(activity.pid)
              FROM pg_catalog.pg_stat_activity activity
             WHERE activity.usename = %s
               AND activity.pid <> pg_catalog.pg_backend_pid()
            """,
            (legacy_role,),
        )


def _assert_exact_schema_inventory(cursor) -> dict[str, str]:
    cursor.execute(
        """
        SELECT relation.relname, relation.relkind
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace namespace
            ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
         ORDER BY relation.relname
        """
    )
    relations = {str(name): str(kind) for name, kind in cursor.fetchall()}
    actual_tables = {
        name for name, kind in relations.items() if kind in {"r", "p"}
    }
    missing = sorted(EXPECTED_TABLES - actual_tables)
    unexpected = sorted(actual_tables - EXPECTED_TABLES)
    unsupported = sorted(
        f"{name} ({kind})"
        for name, kind in relations.items()
        if kind not in {"r", "p"}
    )
    if missing or unexpected or unsupported:
        details = []
        if missing:
            details.append("missing tables: " + ", ".join(missing[:10]))
        if unexpected:
            details.append("unexpected tables: " + ", ".join(unexpected[:10]))
        if unsupported:
            details.append("unsupported relations: " + ", ".join(unsupported[:10]))
        raise ProvisioningError(
            "database schema does not match the reviewed lane policy ("
            + "; ".join(details)
            + ")"
        )
    cursor.execute(
        """
        SELECT procedure.proname,
               pg_catalog.pg_get_function_identity_arguments(procedure.oid),
               pg_catalog.pg_get_function_result(procedure.oid),
               language.lanname,
               procedure.prokind,
               procedure.prosecdef,
               procedure.proleakproof,
               procedure.provolatile,
               procedure.proparallel,
               procedure.proconfig
          FROM pg_catalog.pg_proc procedure
          JOIN pg_catalog.pg_namespace namespace
            ON namespace.oid = procedure.pronamespace
          JOIN pg_catalog.pg_language language
            ON language.oid = procedure.prolang
         WHERE namespace.nspname = 'public'
         ORDER BY procedure.proname,
                  pg_catalog.pg_get_function_identity_arguments(procedure.oid)
        """
    )
    routines = cursor.fetchall()
    actual_routines = {
        (str(name), str(arguments), str(result))
        for name,
        arguments,
        result,
        _language,
        _kind,
        _security_definer,
        _leakproof,
        _volatility,
        _parallel,
        _config in routines
    }
    expected_routines = {
        (name, arguments, result)
        for name, (arguments, result) in EXPECTED_ROUTINES.items()
    }
    unsafe_routines = [
        str(name)
        for name,
        _arguments,
        _result,
        language,
        kind,
        security_definer,
        leakproof,
        volatility,
        parallel,
        config in routines
        if (
            str(language),
            str(kind),
            bool(security_definer),
            bool(leakproof),
            str(volatility),
            str(parallel),
            tuple(config or ()),
        )
        != EXPECTED_ROUTINE_ATTRIBUTES.get(str(name))
    ]
    if actual_routines != expected_routines or unsafe_routines:
        missing = sorted(expected_routines - actual_routines)
        unexpected = sorted(actual_routines - expected_routines)
        details = []
        if missing:
            details.append("missing " + ", ".join(name for name, _args, _result in missing))
        if unexpected:
            details.append(
                "unexpected " + ", ".join(name for name, _args, _result in unexpected)
            )
        if unsafe_routines:
            details.append("unsafe attributes " + ", ".join(unsafe_routines))
        raise ProvisioningError(
            "public-schema routines do not match the reviewed lane policy: "
            + "; ".join(details)
        )

    cursor.execute(
        """
        SELECT relation.relname, trigger.tgname
          FROM pg_catalog.pg_trigger trigger
          JOIN pg_catalog.pg_class relation ON relation.oid = trigger.tgrelid
          JOIN pg_catalog.pg_namespace namespace
            ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND NOT trigger.tgisinternal
         ORDER BY relation.relname, trigger.tgname
        """
    )
    actual_triggers = {
        (str(table_name), str(trigger_name))
        for table_name, trigger_name in cursor.fetchall()
    }
    if actual_triggers != EXPECTED_TRIGGERS:
        missing = sorted(EXPECTED_TRIGGERS - actual_triggers)
        unexpected = sorted(actual_triggers - EXPECTED_TRIGGERS)
        details = []
        if missing:
            details.append(
                "missing " + ", ".join(f"{table}.{name}" for table, name in missing)
            )
        if unexpected:
            details.append(
                "unexpected "
                + ", ".join(f"{table}.{name}" for table, name in unexpected)
            )
        raise ProvisioningError(
            "public-schema triggers do not match the reviewed lane policy: "
            + "; ".join(details)
        )

    cursor.execute(
        """
        SELECT source.relname, source_attribute.attname,
               target.relname, target_attribute.attname,
               foreign_key.confdeltype, foreign_key.condeferrable,
               foreign_key.condeferred
          FROM pg_catalog.pg_constraint foreign_key
          JOIN pg_catalog.pg_class source ON source.oid = foreign_key.conrelid
          JOIN pg_catalog.pg_namespace source_namespace
            ON source_namespace.oid = source.relnamespace
          JOIN pg_catalog.pg_class target ON target.oid = foreign_key.confrelid
          JOIN pg_catalog.pg_namespace target_namespace
            ON target_namespace.oid = target.relnamespace
          CROSS JOIN LATERAL unnest(foreign_key.conkey, foreign_key.confkey)
            WITH ORDINALITY AS key_pair(source_attnum, target_attnum, position)
          JOIN pg_catalog.pg_attribute source_attribute
            ON source_attribute.attrelid = source.oid
           AND source_attribute.attnum = key_pair.source_attnum
          JOIN pg_catalog.pg_attribute target_attribute
            ON target_attribute.attrelid = target.oid
           AND target_attribute.attnum = key_pair.target_attnum
         WHERE foreign_key.contype = 'f'
           AND source_namespace.nspname = 'public'
           AND target_namespace.nspname = 'public'
           AND source.relname IN (
               'core_managed_ssh_operation',
               'core_ssh_host_key_approval',
               'core_ssh_host_key_approval_event'
           )
         ORDER BY source.relname, source_attribute.attname, key_pair.position
        """
    )
    actual_managed_ssh_foreign_keys = {
        (
            str(source_table),
            str(source_column),
            str(target_table),
            str(target_column),
            str(delete_action),
            bool(deferrable),
            bool(deferred),
        )
        for (
            source_table,
            source_column,
            target_table,
            target_column,
            delete_action,
            deferrable,
            deferred,
        ) in cursor.fetchall()
    }
    if actual_managed_ssh_foreign_keys != EXPECTED_MANAGED_SSH_FOREIGN_KEYS:
        raise ProvisioningError(
            "managed SSH FK cascades/audit independence drifted from policy"
        )
    return relations


def _sequence_owners(cursor) -> dict[str, str]:
    cursor.execute(
        """
        SELECT sequence.relname, owned_table.relname
          FROM pg_catalog.pg_class sequence
          JOIN pg_catalog.pg_namespace namespace
            ON namespace.oid = sequence.relnamespace
          LEFT JOIN pg_catalog.pg_depend dependency
            ON dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
           AND dependency.objid = sequence.oid
           AND dependency.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
           AND dependency.deptype IN ('a', 'i')
          LEFT JOIN pg_catalog.pg_class owned_table
            ON owned_table.oid = dependency.refobjid
         WHERE namespace.nspname = 'public'
           AND sequence.relkind = 'S'
         ORDER BY sequence.relname
        """
    )
    owners: dict[str, str] = {}
    for sequence_name, table_name in cursor.fetchall():
        sequence_name = str(sequence_name)
        if not table_name or sequence_name in owners:
            raise ProvisioningError(
                f"sequence {sequence_name} is not owned by exactly one reviewed table"
            )
        table_name = str(table_name)
        if table_name not in EXPECTED_TABLES:
            raise ProvisioningError(
                f"sequence {sequence_name} belongs to an unreviewed table"
            )
        owners[sequence_name] = table_name
    return owners


def _assert_public_object_ownership(cursor, migrator_user: str) -> None:
    """Require every reviewed public object to remain migrator-owned."""

    cursor.execute(
        """
        SELECT inventory.kind || ' ' || inventory.name
          FROM (
                SELECT 'relation' AS kind, relation.relname AS name,
                       owner.rolname AS owner
                  FROM pg_catalog.pg_class relation
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = relation.relnamespace
                  JOIN pg_catalog.pg_roles owner ON owner.oid = relation.relowner
                 WHERE namespace.nspname = 'public'
                   AND relation.relkind IN ('r', 'p', 'S')
                UNION ALL
                SELECT 'routine', procedure.proname, owner.rolname
                  FROM pg_catalog.pg_proc procedure
                  JOIN pg_catalog.pg_namespace namespace
                    ON namespace.oid = procedure.pronamespace
                  JOIN pg_catalog.pg_roles owner ON owner.oid = procedure.proowner
                 WHERE namespace.nspname = 'public'
               ) inventory
         WHERE inventory.owner <> %s
         ORDER BY inventory.kind, inventory.name
        """,
        (migrator_user,),
    )
    unexpected = [str(row[0]) for row in cursor.fetchall()]
    if unexpected:
        raise ProvisioningError(
            "public-schema object ownership drifted from the migrator: "
            + ", ".join(unexpected[:10])
        )


def _apply_row_policies(cursor, config: IdentityConfiguration) -> None:
    definitions = row_policy_definitions()
    expected_names = {(table, policy_name) for table, _lane, _command, _predicate, policy_name in definitions}
    cursor.execute(
        """
        SELECT policy.tablename, policy.policyname
          FROM pg_catalog.pg_policies policy
         WHERE policy.schemaname = 'public'
         ORDER BY policy.tablename, policy.policyname
        """
    )
    existing = {(str(table), str(name)) for table, name in cursor.fetchall()}
    unexpected = sorted(existing - expected_names)
    if unexpected:
        raise ProvisioningError(
            "database contains unreviewed row-security policies: "
            + ", ".join(f"{table}.{name}" for table, name in unexpected[:10])
        )

    for table in sorted(EXPECTED_TABLES):
        identifier = sql.Identifier("public", table)
        if table in ROW_SECURITY_TABLES:
            cursor.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(identifier))
            cursor.execute(sql.SQL("ALTER TABLE {} NO FORCE ROW LEVEL SECURITY").format(identifier))
        else:
            cursor.execute(sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY").format(identifier))
            cursor.execute(sql.SQL("ALTER TABLE {} NO FORCE ROW LEVEL SECURITY").format(identifier))

    for table, lane, command, predicate, policy_name in definitions:
        cursor.execute(
            sql.SQL("DROP POLICY IF EXISTS {} ON {}").format(
                sql.Identifier(policy_name), sql.Identifier("public", table)
            )
        )
        if command in {"ALL", "UPDATE"}:
            cursor.execute(
                sql.SQL(
                    "CREATE POLICY {} ON {} FOR {} TO {} USING ({}) WITH CHECK ({})"
                ).format(
                    sql.Identifier(policy_name),
                    sql.Identifier("public", table),
                    sql.SQL(command),
                    sql.Identifier(config.lane_users[lane]),
                    sql.SQL(predicate),
                    sql.SQL(predicate),
                )
            )
        elif command == "INSERT":
            cursor.execute(
                sql.SQL("CREATE POLICY {} ON {} FOR INSERT TO {} WITH CHECK ({})").format(
                    sql.Identifier(policy_name),
                    sql.Identifier("public", table),
                    sql.Identifier(config.lane_users[lane]),
                    sql.SQL(predicate),
                )
            )
        else:
            cursor.execute(
                sql.SQL("CREATE POLICY {} ON {} FOR {} TO {} USING ({})").format(
                    sql.Identifier(policy_name),
                    sql.Identifier("public", table),
                    sql.SQL(command),
                    sql.Identifier(config.lane_users[lane]),
                    sql.SQL(predicate),
                )
            )
        cursor.execute(
            """
            SELECT pg_catalog.pg_get_expr(policy.polqual, policy.polrelid),
                   pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid)
              FROM pg_catalog.pg_policy policy
              JOIN pg_catalog.pg_class relation ON relation.oid = policy.polrelid
              JOIN pg_catalog.pg_namespace namespace
                ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname = 'public'
               AND relation.relname = %s
               AND policy.polname = %s
            """,
            (table, policy_name),
        )
        catalog_using, catalog_check = cursor.fetchone()
        cursor.execute(
            sql.SQL("COMMENT ON POLICY {} ON {} IS %s").format(
                sql.Identifier(policy_name), sql.Identifier("public", table)
            ),
            (
                _policy_witness(
                    installation_id=config.installation_id,
                    table=table,
                    lane=lane,
                    command=command,
                    source_predicate=predicate,
                    catalog_using=(
                        str(catalog_using) if catalog_using is not None else None
                    ),
                    catalog_check=(
                        str(catalog_check) if catalog_check is not None else None
                    ),
                ),
            ),
        )


def _seal_lane_grants(cursor, config: IdentityConfiguration) -> None:
    """Apply exact post-migration grants and row policies."""

    _assert_exact_schema_inventory(cursor)
    _assert_public_object_ownership(cursor, config.migrator_user)
    sequence_owners = _sequence_owners(cursor)
    for lane, role_name in config.lane_users.items():
        role = sql.Identifier(role_name)
        for table, privileges in LANE_TABLE_POLICY[lane].items():
            cursor.execute(
                sql.SQL("GRANT {} ON TABLE {} TO {}").format(
                    sql.SQL(", ").join(sql.SQL(value) for value in sorted(privileges)),
                    sql.Identifier("public", table),
                    role,
                )
            )
        for sequence_name, table_name in sequence_owners.items():
            if "INSERT" not in LANE_TABLE_POLICY[lane].get(table_name, ()):
                continue
            cursor.execute(
                sql.SQL("GRANT USAGE, SELECT ON SEQUENCE {} TO {}").format(
                    sql.Identifier("public", sequence_name), role
                )
            )
        for table, columns in LANE_COLUMN_SELECT_POLICY.get(lane, {}).items():
            cursor.execute(
                sql.SQL("GRANT SELECT ({}) ON TABLE {} TO {}").format(
                    sql.SQL(", ").join(
                        sql.Identifier(column) for column in sorted(columns)
                    ),
                    sql.Identifier("public", table),
                    role,
                )
            )
        for table, columns in LANE_COLUMN_UPDATE_POLICY.get(lane, {}).items():
            cursor.execute(
                sql.SQL("GRANT UPDATE ({}) ON TABLE {} TO {}").format(
                    sql.SQL(", ").join(
                        sql.Identifier(column) for column in sorted(columns)
                    ),
                    sql.Identifier("public", table),
                    role,
                )
            )
        for routine_name in ROUTINE_EXECUTE_POLICY.get(lane, ()):
            arguments, _result = EXPECTED_ROUTINES[routine_name]
            cursor.execute(
                sql.SQL("GRANT EXECUTE ON FUNCTION {}.{}({}) TO {}").format(
                    sql.Identifier("public"),
                    sql.Identifier(routine_name),
                    sql.SQL(arguments),
                    role,
                )
            )
    _apply_row_policies(cursor, config)


def _transaction_cursor(connection):
    """Return the shared advisory-lock cursor context for either phase."""

    return connection.cursor()


def provision_database_identities(connection, config: IdentityConfiguration) -> None:
    """Prepare generation-3 identities before migrations in one transaction."""

    with connection:
        with _transaction_cursor(connection) as cursor:
            cursor.execute("SET LOCAL statement_timeout = '5min'")
            cursor.execute("SET LOCAL lock_timeout = '30s'")
            cursor.execute("SET LOCAL search_path = pg_catalog")
            cursor.execute(
                "SELECT pg_catalog.pg_advisory_xact_lock(%s)",
                (0x4253504749445633,),
            )
            _assert_bootstrap_role(cursor, config)
            _assert_supported_database_shape(cursor, config)
            _ensure_application_role(
                cursor,
                role_name=config.migrator_user,
                password=config.migrator_password,
                marker=config.marker("migrator"),
                allowed_existing_markers=frozenset(
                    {config.legacy_marker("migrator")}
                ),
            )
            for lane in LANES:
                _ensure_application_role(
                    cursor,
                    role_name=config.lane_users[lane],
                    password=config.lane_passwords[lane],
                    marker=config.marker(lane),
                )
            _transfer_public_ownership(cursor, config)
            legacy_roles = _legacy_runtime_roles(cursor, config)
            _prepare_privilege_boundary(cursor, config, legacy_roles)


def seal_database_identities(connection, config: IdentityConfiguration) -> None:
    """Seal exact generation-3 grants after migrations in one transaction."""

    with connection:
        with _transaction_cursor(connection) as cursor:
            cursor.execute("SET LOCAL statement_timeout = '5min'")
            cursor.execute("SET LOCAL lock_timeout = '30s'")
            cursor.execute("SET LOCAL search_path = pg_catalog")
            cursor.execute(
                "SELECT pg_catalog.pg_advisory_xact_lock(%s)",
                (0x4253504749445633,),
            )
            _assert_bootstrap_role(cursor, config)
            _assert_supported_database_shape(cursor, config)
            _transfer_public_ownership(cursor, config)
            legacy_roles = _legacy_runtime_roles(cursor, config)
            _prepare_privilege_boundary(cursor, config, legacy_roles)
            _seal_lane_grants(cursor, config)


def _runtime_identity_configuration(
    environment: Mapping[str, str],
) -> tuple[str, str, str, dict[str, str]]:
    """Parse the non-secret identity contract visible to every stock container."""

    values = dict(environment)
    generation = _required_environment(
        values, "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION"
    )
    if generation != IDENTITY_GENERATION:
        raise ProvisioningError(
            "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION must be 3"
        )
    installation_id = _required_environment(values, "BACKUPSHEEP_INSTALLATION_ID")
    if not INSTALLATION_ID_PATTERN.fullmatch(installation_id):
        raise ProvisioningError(
            "BACKUPSHEEP_INSTALLATION_ID must be 64 lowercase hexadecimal characters"
        )
    lane = _required_environment(values, "BACKUPSHEEP_DATABASE_LANE")
    if lane not in LANES:
        raise ProvisioningError("BACKUPSHEEP_DATABASE_LANE is not a reviewed lane")
    bootstrap_user = _role_name(values, "DB_BOOTSTRAP_USER")
    migrator_user = _role_name(values, "DB_MIGRATOR_USER")
    lane_users = {
        lane_name: _role_name(values, user_variable)
        for lane_name, (user_variable, _secret_variable) in LANE_ENVIRONMENT.items()
    }
    if len({bootstrap_user, migrator_user, *lane_users.values()}) != 2 + len(LANES):
        raise ProvisioningError(
            "bootstrap, migrator, and every lane database role must be distinct"
        )
    return installation_id, lane, migrator_user, {
        "bootstrap": bootstrap_user,
        "migrator": migrator_user,
        **lane_users,
    }


def _acl_rows(cursor, query: str, parameters: tuple = ()) -> set[tuple[str, ...]]:
    cursor.execute(query, parameters)
    return {tuple(str(value) for value in row) for row in cursor.fetchall()}


def assert_database_lane_contract(
    cursor,
    *,
    environment: Mapping[str, str],
    configured_user: str,
) -> str:
    """Validate the complete sealed generation-3 ACL/RLS contract read-only.

    The preflight lane has no table access beyond ``django_migrations``. PostgreSQL
    catalogs are sufficient to witness every role, object grant, default privilege,
    and row policy without giving that lane an ownership or DDL capability.
    """

    installation_id, lane, migrator_user, roles_by_kind = (
        _runtime_identity_configuration(environment)
    )
    lane_users = {lane_name: roles_by_kind[lane_name] for lane_name in LANES}
    active_user = lane_users[lane]
    if not configured_user or configured_user != active_user:
        raise ProvisioningError(
            "Django is not configured for its declared database lane role"
        )

    _assert_exact_schema_inventory(cursor)
    _assert_public_object_ownership(cursor, migrator_user)

    all_role_names = tuple(roles_by_kind.values())
    cursor.execute(
        """
        SELECT role.rolname, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
               role.rolreplication, role.rolbypassrls, role.rolcanlogin,
               role.rolconnlimit, role.rolconfig,
               COALESCE(pg_catalog.shobj_description(role.oid, 'pg_authid'), '')
          FROM pg_catalog.pg_roles role
         WHERE role.rolname = ANY(%s)
         ORDER BY role.rolname
        """,
        (list(all_role_names),),
    )
    role_records = {str(row[0]): row[1:] for row in cursor.fetchall()}
    missing_roles = sorted(set(all_role_names) - set(role_records))
    if missing_roles:
        raise ProvisioningError(
            "database identity roles are missing: " + ", ".join(missing_roles)
        )

    expected_role_defaults = {
        "search_path=public, pg_catalog",
        "statement_timeout=1h",
        "lock_timeout=30s",
        "idle_in_transaction_session_timeout=5min",
    }
    for kind, role_name in roles_by_kind.items():
        (
            superuser,
            createdb,
            createrole,
            replication,
            bypassrls,
            can_login,
            connection_limit,
            role_config,
            marker,
        ) = role_records[role_name]
        expected_marker = (
            f"backupsheep:database-identity-v3:{installation_id}:{kind}"
        )
        if marker != expected_marker:
            raise ProvisioningError(
                f"database role {role_name} marker does not match this installation"
            )
        if kind == "bootstrap":
            if not superuser or not can_login:
                raise ProvisioningError(
                    "database bootstrap role is not the expected login superuser"
                )
            continue
        if superuser or createdb or createrole or replication or bypassrls or not can_login:
            raise ProvisioningError(
                f"database role {role_name} has unsafe attributes"
            )
        expected_limit = 8 if kind in {"migrator", "preflight", "beat"} else 128
        if int(connection_limit) != expected_limit:
            raise ProvisioningError(
                f"database role {role_name} connection limit drifted"
            )
        if set(role_config or ()) != expected_role_defaults:
            raise ProvisioningError(
                f"database role {role_name} session defaults drifted"
            )

    cursor.execute(
        """
        SELECT member.rolname, parent.rolname
          FROM pg_catalog.pg_auth_members membership
          JOIN pg_catalog.pg_roles member ON member.oid = membership.member
          JOIN pg_catalog.pg_roles parent ON parent.oid = membership.roleid
         WHERE member.rolname = ANY(%s) OR parent.rolname = ANY(%s)
         ORDER BY member.rolname, parent.rolname
        """,
        (list(all_role_names), list(all_role_names)),
    )
    memberships = cursor.fetchall()
    if memberships:
        raise ProvisioningError("database identity roles have unexpected memberships")

    cursor.execute(
        """
        SELECT current_user,
               pg_catalog.pg_get_userbyid(database.datdba),
               pg_catalog.pg_get_userbyid(namespace.nspowner),
               pg_catalog.has_database_privilege(current_user, current_database(), 'CONNECT'),
               pg_catalog.has_database_privilege(current_user, current_database(), 'CREATE'),
               pg_catalog.has_database_privilege(current_user, current_database(), 'TEMPORARY'),
               pg_catalog.has_schema_privilege(current_user, 'public', 'USAGE'),
               pg_catalog.has_schema_privilege(current_user, 'public', 'CREATE')
          FROM pg_catalog.pg_database database
          JOIN pg_catalog.pg_namespace namespace ON namespace.nspname = 'public'
         WHERE database.datname = current_database()
        """
    )
    (
        observed_user,
        database_owner,
        schema_owner,
        can_connect,
        can_create_database_object,
        can_create_temporary,
        can_use_schema,
        can_create_schema_object,
    ) = cursor.fetchone()
    if observed_user != active_user:
        raise ProvisioningError("active database login does not match its declared lane")
    if database_owner != migrator_user or schema_owner != migrator_user:
        raise ProvisioningError("database or public schema is not owned by the migrator")
    if (
        not can_connect
        or not can_use_schema
        or can_create_database_object
        or can_create_temporary
        or can_create_schema_object
    ):
        raise ProvisioningError(
            "active database lane has missing runtime access or forbidden DDL/TEMP access"
        )

    expected_table_acl = {
        (table, lane_users[lane_name], privilege, "False")
        for lane_name, policy in LANE_TABLE_POLICY.items()
        for table, privileges in policy.items()
        for privilege in privileges
    }
    actual_table_acl = _acl_rows(
        cursor,
        """
        SELECT relation.relname,
               CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END,
               acl.privilege_type, acl.is_grantable
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) acl
          LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
         WHERE namespace.nspname = 'public'
           AND relation.relkind IN ('r', 'p')
         ORDER BY relation.relname, 2, acl.privilege_type
        """,
    )
    actual_table_acl = {
        row for row in actual_table_acl if row[1] != migrator_user
    }
    if actual_table_acl != expected_table_acl:
        raise ProvisioningError("database table privileges drifted from the lane policy")

    expected_column_acl = {
        (table, column, lane_users[lane_name], privilege, "False")
        for privilege, column_policy in (
            ("SELECT", LANE_COLUMN_SELECT_POLICY),
            ("UPDATE", LANE_COLUMN_UPDATE_POLICY),
        )
        for lane_name, tables in column_policy.items()
        for table, columns in tables.items()
        for column in columns
    }
    actual_column_acl = _acl_rows(
        cursor,
        """
        SELECT relation.relname, attribute.attname,
               CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END,
               acl.privilege_type, acl.is_grantable
          FROM pg_catalog.pg_attribute attribute
          JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) acl
          LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
         WHERE namespace.nspname = 'public'
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
         ORDER BY relation.relname, attribute.attname, 3, acl.privilege_type
        """,
    )
    actual_column_acl = {
        row for row in actual_column_acl if row[2] != migrator_user
    }
    if actual_column_acl != expected_column_acl:
        raise ProvisioningError("database column privileges drifted from the lane policy")

    cursor.execute(
        """
        SELECT sequence.relname, owned_table.relname
          FROM pg_catalog.pg_class sequence
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = sequence.relnamespace
          JOIN pg_catalog.pg_depend dependency
            ON dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
           AND dependency.objid = sequence.oid
           AND dependency.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
           AND dependency.deptype IN ('a', 'i')
          JOIN pg_catalog.pg_class owned_table ON owned_table.oid = dependency.refobjid
         WHERE namespace.nspname = 'public' AND sequence.relkind = 'S'
         ORDER BY sequence.relname
        """
    )
    sequence_owners = {
        str(sequence_name): str(table_name)
        for sequence_name, table_name in cursor.fetchall()
    }
    expected_sequence_acl = {
        (sequence_name, lane_users[lane_name], privilege, "False")
        for sequence_name, table_name in sequence_owners.items()
        for lane_name, policy in LANE_TABLE_POLICY.items()
        if "INSERT" in policy.get(table_name, ())
        for privilege in ("SELECT", "USAGE")
    }
    actual_sequence_acl = _acl_rows(
        cursor,
        """
        SELECT relation.relname,
               CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END,
               acl.privilege_type, acl.is_grantable
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) acl
          LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
         WHERE namespace.nspname = 'public' AND relation.relkind = 'S'
         ORDER BY relation.relname, 2, acl.privilege_type
        """,
    )
    actual_sequence_acl = {
        row for row in actual_sequence_acl if row[1] != migrator_user
    }
    if actual_sequence_acl != expected_sequence_acl:
        raise ProvisioningError("database sequence privileges drifted from the lane policy")

    expected_routine_acl = {
        (routine_name, arguments, lane_users[lane_name], "EXECUTE", "False")
        for lane_name, routines in ROUTINE_EXECUTE_POLICY.items()
        for routine_name in routines
        for arguments, _result in (EXPECTED_ROUTINES[routine_name],)
    }
    actual_routine_acl = _acl_rows(
        cursor,
        """
        SELECT procedure.proname,
               pg_catalog.pg_get_function_identity_arguments(procedure.oid),
               CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END,
               acl.privilege_type, acl.is_grantable
          FROM pg_catalog.pg_proc procedure
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(procedure.proacl) acl
          LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
         WHERE namespace.nspname = 'public'
         ORDER BY procedure.proname, 2, 3, acl.privilege_type
        """,
    )
    actual_routine_acl = {
        row for row in actual_routine_acl if row[2] != migrator_user
    }
    if actual_routine_acl != expected_routine_acl:
        raise ProvisioningError("database routine privileges drifted from the lane policy")

    expected_database_acl = {
        (role_name, "CONNECT", "False") for role_name in lane_users.values()
    }
    actual_database_acl = _acl_rows(
        cursor,
        """
        SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END,
               acl.privilege_type, acl.is_grantable
          FROM pg_catalog.pg_database database
          CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) acl
          LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
         WHERE database.datname = current_database()
         ORDER BY 1, acl.privilege_type
        """,
    )
    actual_database_acl = {
        row for row in actual_database_acl if row[0] != migrator_user
    }
    if actual_database_acl != expected_database_acl:
        raise ProvisioningError("database-level privileges drifted from the lane policy")

    expected_schema_acl = {
        (role_name, "USAGE", "False") for role_name in lane_users.values()
    }
    actual_schema_acl = _acl_rows(
        cursor,
        """
        SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END,
               acl.privilege_type, acl.is_grantable
          FROM pg_catalog.pg_namespace namespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) acl
          LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
         WHERE namespace.nspname = 'public'
         ORDER BY 1, acl.privilege_type
        """,
    )
    actual_schema_acl = {
        row for row in actual_schema_acl if row[0] != migrator_user
    }
    if actual_schema_acl != expected_schema_acl:
        raise ProvisioningError("schema privileges drifted from the lane policy")

    default_acl = _acl_rows(
        cursor,
        """
        SELECT owner.rolname,
               COALESCE(namespace.nspname, '<global>'),
               defaults.defaclobjtype,
               CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END,
               acl.privilege_type, acl.is_grantable
          FROM pg_catalog.pg_default_acl defaults
          JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
          LEFT JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
          LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
         ORDER BY owner.rolname, 2, defaults.defaclobjtype, 4, acl.privilege_type
        """,
    )
    unexpected_default_acl = {
        row for row in default_acl if row[3] != migrator_user
    }
    if unexpected_default_acl:
        raise ProvisioningError("database default privileges grant unreviewed access")

    cursor.execute(
        """
        SELECT relation.relname, relation.relrowsecurity, relation.relforcerowsecurity
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p')
         ORDER BY relation.relname
        """
    )
    rls_state = {
        str(table): (bool(enabled), bool(forced))
        for table, enabled, forced in cursor.fetchall()
    }
    expected_rls_state = {
        table: (table in ROW_SECURITY_TABLES, False) for table in EXPECTED_TABLES
    }
    if rls_state != expected_rls_state:
        raise ProvisioningError("database row-security enablement drifted")

    # ``pg_get_expr`` qualification depends on the session search path. Sealing
    # deparses under pg_catalog; temporarily use the same path, then restore it so
    # Django's following migration check can still resolve public tables.
    cursor.execute("SELECT pg_catalog.current_setting('search_path')")
    previous_search_path = str(cursor.fetchone()[0])
    cursor.execute(
        "SELECT pg_catalog.set_config('search_path', 'pg_catalog', false)"
    )
    cursor.execute(
        """
        SELECT relation.relname, policy.polname, policy.polpermissive, policy.polcmd,
               ARRAY(
                   SELECT pg_catalog.pg_get_userbyid(role_oid)
                     FROM unnest(policy.polroles) role_oid
                    ORDER BY 1
               ),
               pg_catalog.pg_get_expr(policy.polqual, policy.polrelid),
               pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid),
               COALESCE(pg_catalog.obj_description(policy.oid, 'pg_policy'), '')
          FROM pg_catalog.pg_policy policy
          JOIN pg_catalog.pg_class relation ON relation.oid = policy.polrelid
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
         ORDER BY relation.relname, policy.polname
        """
    )
    policy_records = cursor.fetchall()
    cursor.execute(
        "SELECT pg_catalog.set_config('search_path', %s, false)",
        (previous_search_path,),
    )
    definitions = row_policy_definitions()
    expected_policies = {
        (table, policy_name): (lane_name, command, predicate)
        for table, lane_name, command, predicate, policy_name in definitions
    }
    expected_policy_keys = set(expected_policies)
    actual_policy_keys = {
        (str(table), str(policy_name))
        for table, policy_name, *_remaining in policy_records
    }
    if actual_policy_keys != expected_policy_keys:
        raise ProvisioningError("database row-security policy inventory drifted")
    for (
        table,
        policy_name,
        permissive,
        command,
        policy_roles,
        catalog_using,
        catalog_check,
        marker,
    ) in policy_records:
        table = str(table)
        policy_name = str(policy_name)
        lane_name, expected_command, predicate = expected_policies[
            (table, policy_name)
        ]
        expected_marker = _policy_witness(
            installation_id=installation_id,
            table=table,
            lane=lane_name,
            command=expected_command,
            source_predicate=predicate,
            catalog_using=(
                str(catalog_using) if catalog_using is not None else None
            ),
            catalog_check=(
                str(catalog_check) if catalog_check is not None else None
            ),
        )
        drift = []
        if not permissive:
            drift.append("restrictive")
        catalog_commands = {
            "ALL": "*",
            "SELECT": "r",
            "INSERT": "a",
            "UPDATE": "w",
            "DELETE": "d",
        }
        if command != catalog_commands[expected_command]:
            drift.append("command")
        if list(policy_roles) != [lane_users[lane_name]]:
            drift.append("roles")
        if expected_command in {"ALL", "UPDATE"} and catalog_using != catalog_check:
            drift.append("check-expression")
        if expected_command in {"SELECT", "DELETE"} and catalog_check is not None:
            drift.append("unexpected-check-expression")
        if expected_command == "INSERT" and (
            catalog_using is not None or catalog_check is None
        ):
            drift.append("insert-expression")
        if marker != expected_marker:
            drift.append("witness")
        if drift:
            raise ProvisioningError(
                f"database row-security policy {table}.{policy_name} drifted: "
                + ", ".join(drift)
            )

    return lane


def _connect(config: IdentityConfiguration):
    # libpq accepts dozens of PG* environment variables, including PGHOSTADDR and
    # PGSERVICEFILE, that can redirect or weaken a connection even when the ordinary
    # host fragments look safe. This is a single-threaded one-shot; remove every
    # libpq environment default around the call and supply the reviewed parameters.
    inherited_libpq = {
        name: value for name, value in os.environ.items() if name.startswith("PG")
    }
    for name in inherited_libpq:
        os.environ.pop(name, None)
    try:
        return psycopg2.connect(
            dbname=config.database,
            user=config.bootstrap_user,
            password=config.bootstrap_password,
            host="db",
            port=5432,
            connect_timeout=10,
            application_name="backupsheep-database-identity-provisioner",
            options="-c client_min_messages=warning",
            sslmode="disable",
            target_session_attrs="read-write",
        )
    finally:
        os.environ.update(inherited_libpq)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments not in (["provision"], ["seal"]):
        print(
            "Usage: python -m backupsheep.database_identity {provision|seal}",
            file=sys.stderr,
        )
        return 2
    try:
        config = IdentityConfiguration.from_environment()
        connection = _connect(config)
        try:
            if arguments == ["provision"]:
                provision_database_identities(connection, config)
            else:
                seal_database_identities(connection, config)
        finally:
            connection.close()
        if arguments == ["seal"]:
            # The catalog witness proves exact grants; direct rollback-only logins
            # prove that PostgreSQL enforces them for every real lane credential.
            # Keep this after the sealing transaction so a failed probe prevents
            # installer promotion without undoing the safer revoked boundary.
            from backupsheep.database_lane_probe import LaneProbeError, run_probe

            try:
                run_probe(config)
            except (LaneProbeError, psycopg2.Error, RuntimeError, ValueError) as error:
                raise ProvisioningError(
                    "database lane adversarial probe rejected the sealed policy"
                ) from error
    except (ProvisioningError, psycopg2.Error) as error:
        # Never include connection DSNs, diagnostics, or exception reprs here: a
        # driver error can contain a credential-bearing connection parameter.
        print(
            "BackupSheep database identity provisioning failed closed: "
            + (
                str(error)
                if isinstance(error, ProvisioningError)
                else "database rejected the provisioning transaction"
            ),
            file=sys.stderr,
        )
        return 1
    print(
        "BackupSheep database identity generation 3 "
        + ("is prepared" if arguments == ["provision"] else "is sealed")
        + ": bootstrap, migrator, and every long-lived lane are separated."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
