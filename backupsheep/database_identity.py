"""Provision the stock Docker PostgreSQL identities without exposing passwords.

The bundled PostgreSQL image must bootstrap a fresh cluster with a superuser.  That
credential is deliberately confined to the database container and this one-shot
provisioner.  Django migrations use a separate object-owning login and every
long-lived application process uses a non-owner runtime login.

This module is executed as ``python -m backupsheep.database_identity provision``
inside the immutable application image.  It is intentionally independent of Django
settings: loading Django with the bootstrap credential would make an accidental
management command a privileged database client.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import psycopg2
from psycopg2 import sql


IDENTITY_GENERATION = "2"
SECRET_ROOT = Path("/run/secrets")
MAX_SECRET_BYTES = 4096
ROLE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
INSTALLATION_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class ProvisioningError(RuntimeError):
    """A fail-closed database identity contract violation."""


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
    runtime_user: str
    bootstrap_password: str
    migrator_password: str
    runtime_password: str

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
                "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION must be 2"
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
        runtime_user = _role_name(values, "DB_USER")
        if len({bootstrap_user, migrator_user, runtime_user}) != 3:
            raise ProvisioningError(
                "bootstrap, migrator, and runtime database roles must be distinct"
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
        runtime_password = secret("DB_PASSWORD_FILE", "database runtime")
        if len({bootstrap_password, migrator_password, runtime_password}) != 3:
            raise ProvisioningError(
                "bootstrap, migrator, and runtime database credentials must be distinct"
            )

        return cls(
            installation_id=installation_id,
            database=database,
            host=host,
            port=port,
            bootstrap_user=bootstrap_user,
            migrator_user=migrator_user,
            runtime_user=runtime_user,
            bootstrap_password=bootstrap_password,
            migrator_password=migrator_password,
            runtime_password=runtime_password,
        )

    def marker(self, role_kind: str) -> str:
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
        if comment != marker:
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
    if existing_comment and existing_comment != marker:
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


def _apply_grants(cursor, config: IdentityConfiguration) -> None:
    database = sql.Identifier(config.database)
    migrator = sql.Identifier(config.migrator_user)
    runtime = sql.Identifier(config.runtime_user)

    cursor.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(database))
    cursor.execute(
        sql.SQL("GRANT CONNECT, TEMPORARY, CREATE ON DATABASE {} TO {}").format(
            database, migrator
        )
    )
    cursor.execute(
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(database, runtime)
    )
    cursor.execute(
        sql.SQL("REVOKE CREATE, TEMPORARY ON DATABASE {} FROM {}").format(
            database, runtime
        )
    )
    cursor.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    cursor.execute(
        sql.SQL("GRANT USAGE, CREATE ON SCHEMA public TO {}").format(migrator)
    )
    cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(runtime))
    cursor.execute(
        sql.SQL("REVOKE CREATE ON SCHEMA public FROM {}").format(runtime)
    )

    cursor.execute(
        "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC"
    )
    cursor.execute(
        sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(runtime)
    )
    cursor.execute(
        sql.SQL(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}"
        ).format(runtime)
    )
    cursor.execute(
        "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC"
    )
    cursor.execute(
        sql.SQL("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {}").format(
            runtime
        )
    )
    cursor.execute(
        sql.SQL(
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}"
        ).format(runtime)
    )
    cursor.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC")
    cursor.execute(
        sql.SQL("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {}").format(
            runtime
        )
    )
    cursor.execute(
        sql.SQL(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
            "REVOKE ALL ON TABLES FROM PUBLIC"
        ).format(migrator)
    )
    cursor.execute(
        sql.SQL(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}"
        ).format(migrator, runtime)
    )
    cursor.execute(
        sql.SQL(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
            "REVOKE ALL ON SEQUENCES FROM PUBLIC"
        ).format(migrator)
    )
    cursor.execute(
        sql.SQL(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
            "GRANT USAGE, SELECT ON SEQUENCES TO {}"
        ).format(migrator, runtime)
    )
    cursor.execute(
        sql.SQL(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
            "REVOKE ALL ON FUNCTIONS FROM PUBLIC"
        ).format(migrator)
    )
    cursor.execute(
        sql.SQL(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
            "GRANT EXECUTE ON FUNCTIONS TO {}"
        ).format(migrator, runtime)
    )
    cursor.execute(
        sql.SQL("ALTER ROLE {} SET search_path TO public, pg_catalog").format(
            migrator
        )
    )
    cursor.execute(
        sql.SQL("ALTER ROLE {} SET search_path TO public, pg_catalog").format(runtime)
    )


def provision_database_identities(connection, config: IdentityConfiguration) -> None:
    """Apply the v2 identity split in one fail-closed PostgreSQL transaction."""

    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SET LOCAL statement_timeout = '5min'")
            cursor.execute("SET LOCAL lock_timeout = '30s'")
            cursor.execute("SET LOCAL search_path = pg_catalog")
            cursor.execute("SELECT pg_catalog.pg_advisory_xact_lock(%s)", (0x4253504749445632,))
            _assert_bootstrap_role(cursor, config)
            _assert_supported_database_shape(cursor, config)
            _ensure_application_role(
                cursor,
                role_name=config.migrator_user,
                password=config.migrator_password,
                marker=config.marker("migrator"),
            )
            _ensure_application_role(
                cursor,
                role_name=config.runtime_user,
                password=config.runtime_password,
                marker=config.marker("runtime"),
            )
            _transfer_public_ownership(cursor, config)
            _apply_grants(cursor, config)


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
    if arguments != ["provision"]:
        print(
            "Usage: python -m backupsheep.database_identity provision",
            file=sys.stderr,
        )
        return 2
    try:
        config = IdentityConfiguration.from_environment()
        connection = _connect(config)
        try:
            provision_database_identities(connection, config)
        finally:
            connection.close()
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
        "BackupSheep database identity generation 2 is provisioned: "
        "bootstrap, migrator, and runtime roles are separated."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
