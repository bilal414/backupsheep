"""Detach preserved WordPress history from active application tables.

The WordPress models were removed from Django state in 0047 while their tables
were deliberately retained.  PostgreSQL will not truncate or delete an active
parent while an invisible retained table still references it, even when the
foreign key's logical ``on_delete`` action used to be CASCADE or SET_NULL.

Drop only the four retired-to-active foreign keys.  The archived tables,
columns, rows, identifier values, and the two foreign keys that keep the
retired WordPress subgraph internally coherent all remain in place.
"""

from django.db import migrations


RETIRED_TABLES = frozenset(
    {
        "core_auth_wordpress",
        "core_wordpress",
        "core_wordpress_backup",
        "core_wordpress_backup_mtm_storage_points",
    }
)

# Fingerprints contain every security-relevant PostgreSQL FK property:
# name, child table/columns, parent table/columns, update action, delete action,
# match type, deferrability, initial deferral, and validation state.
EXTERNAL_FOREIGN_KEYS = (
    (
        "core_auth_wordpress_connection_id_5607ad50_fk_core_conn",
        "core_auth_wordpress",
        ("connection_id",),
        "core_connection",
        ("id",),
        "a",
        "a",
        "s",
        True,
        True,
        True,
    ),
    (
        "core_wordpress_node_id_00009feb_fk_core_node_id",
        "core_wordpress",
        ("node_id",),
        "core_node",
        ("id",),
        "a",
        "a",
        "s",
        True,
        True,
        True,
    ),
    (
        "core_wordpress_backup_schedule_id_133c67ca_fk_core_schedule_id",
        "core_wordpress_backup",
        ("schedule_id",),
        "core_schedule",
        ("id",),
        "a",
        "a",
        "s",
        True,
        True,
        True,
    ),
    (
        "core_wordpress_backu_storage_id_2b592e02_fk_core_stor",
        "core_wordpress_backup_mtm_storage_points",
        ("storage_id",),
        "core_storage",
        ("id",),
        "a",
        "a",
        "s",
        True,
        True,
        True,
    ),
)

INTERNAL_FOREIGN_KEYS = (
    (
        "core_wordpress_backu_wordpress_id_8119660f_fk_core_word",
        "core_wordpress_backup",
        ("wordpress_id",),
        "core_wordpress",
        ("id",),
        "a",
        "a",
        "s",
        True,
        True,
        True,
    ),
    (
        "core_wordpress_backu_backup_id_ff22242a_fk_core_word",
        "core_wordpress_backup_mtm_storage_points",
        ("backup_id",),
        "core_wordpress_backup",
        ("id",),
        "a",
        "a",
        "s",
        True,
        True,
        True,
    ),
)

ACTIVE_PARENT_TABLES = frozenset(
    fingerprint[3] for fingerprint in EXTERNAL_FOREIGN_KEYS
)
REQUIRED_TABLES = RETIRED_TABLES | ACTIVE_PARENT_TABLES


def _require_postgresql(connection):
    if connection.vendor != "postgresql":
        raise RuntimeError(
            "Retired WordPress foreign-key detachment requires PostgreSQL."
        )


def _require_tables(connection):
    with connection.cursor() as cursor:
        present = set(connection.introspection.table_names(cursor))
    missing = sorted(REQUIRED_TABLES - present)
    if missing:
        raise RuntimeError(
            "Retired WordPress foreign-key topology is incomplete; missing tables: "
            + ", ".join(missing)
        )


def _lock_topology(schema_editor):
    quote = schema_editor.quote_name
    table_list = ", ".join(quote(table) for table in sorted(REQUIRED_TABLES))
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            f"LOCK TABLE {table_list} IN SHARE ROW EXCLUSIVE MODE"
        )


def foreign_key_inventory(connection):
    """Return exact FK fingerprints for every constraint touching retired tables."""

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT constraint_record.conname,
                   child.relname,
                   ARRAY(
                       SELECT child_attribute.attname
                         FROM unnest(constraint_record.conkey)
                              WITH ORDINALITY AS child_key(attnum, position)
                         JOIN pg_catalog.pg_attribute AS child_attribute
                           ON child_attribute.attrelid = constraint_record.conrelid
                          AND child_attribute.attnum = child_key.attnum
                        ORDER BY child_key.position
                   ),
                   parent.relname,
                   ARRAY(
                       SELECT parent_attribute.attname
                         FROM unnest(constraint_record.confkey)
                              WITH ORDINALITY AS parent_key(attnum, position)
                         JOIN pg_catalog.pg_attribute AS parent_attribute
                           ON parent_attribute.attrelid = constraint_record.confrelid
                          AND parent_attribute.attnum = parent_key.attnum
                        ORDER BY parent_key.position
                   ),
                   constraint_record.confupdtype,
                   constraint_record.confdeltype,
                   constraint_record.confmatchtype,
                   constraint_record.condeferrable,
                   constraint_record.condeferred,
                   constraint_record.convalidated
              FROM pg_catalog.pg_constraint AS constraint_record
              JOIN pg_catalog.pg_class AS child
                ON child.oid = constraint_record.conrelid
              JOIN pg_catalog.pg_namespace AS child_namespace
                ON child_namespace.oid = child.relnamespace
              JOIN pg_catalog.pg_class AS parent
                ON parent.oid = constraint_record.confrelid
              JOIN pg_catalog.pg_namespace AS parent_namespace
                ON parent_namespace.oid = parent.relnamespace
             WHERE constraint_record.contype = 'f'
               AND child_namespace.nspname = current_schema()
               AND parent_namespace.nspname = current_schema()
               AND (child.relname = ANY(%s) OR parent.relname = ANY(%s))
             ORDER BY child.relname, constraint_record.conname
            """,
            (sorted(RETIRED_TABLES), sorted(RETIRED_TABLES)),
        )
        return tuple(
            (
                name,
                child_table,
                tuple(child_columns),
                parent_table,
                tuple(parent_columns),
                update_action,
                delete_action,
                match_type,
                deferrable,
                initially_deferred,
                validated,
            )
            for (
                name,
                child_table,
                child_columns,
                parent_table,
                parent_columns,
                update_action,
                delete_action,
                match_type,
                deferrable,
                initially_deferred,
                validated,
            ) in cursor.fetchall()
        )


def _require_exact_topology(connection, expected, *, phase):
    actual = foreign_key_inventory(connection)
    if len(actual) != len(expected) or set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        raise RuntimeError(
            f"Retired WordPress foreign-key topology drifted during {phase}; "
            f"missing={missing!r}, unexpected={unexpected!r}."
        )


def detach_retired_wordpress_foreign_keys(apps, schema_editor):
    del apps
    connection = schema_editor.connection
    _require_postgresql(connection)
    _require_tables(connection)
    _lock_topology(schema_editor)
    expected_before = INTERNAL_FOREIGN_KEYS + EXTERNAL_FOREIGN_KEYS
    _require_exact_topology(connection, expected_before, phase="forward audit")

    quote = schema_editor.quote_name
    with connection.cursor() as cursor:
        for constraint_name, child_table, *_remaining in EXTERNAL_FOREIGN_KEYS:
            cursor.execute(
                f"ALTER TABLE {quote(child_table)} "
                f"DROP CONSTRAINT {quote(constraint_name)}"
            )

    _require_exact_topology(
        connection,
        INTERNAL_FOREIGN_KEYS,
        phase="forward verification",
    )


def _require_no_orphans(schema_editor):
    quote = schema_editor.quote_name
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        for fingerprint in EXTERNAL_FOREIGN_KEYS:
            (
                _constraint_name,
                child_table,
                child_columns,
                parent_table,
                parent_columns,
                *_properties,
            ) = fingerprint
            child_column = child_columns[0]
            parent_column = parent_columns[0]
            cursor.execute(
                f"SELECT 1 FROM {quote(child_table)} AS retired_child "
                f"LEFT JOIN {quote(parent_table)} AS active_parent "
                f"ON active_parent.{quote(parent_column)} = "
                f"retired_child.{quote(child_column)} "
                f"WHERE retired_child.{quote(child_column)} IS NOT NULL "
                f"AND active_parent.{quote(parent_column)} IS NULL LIMIT 1"
            )
            if cursor.fetchone() is not None:
                raise RuntimeError(
                    "Cannot restore retired WordPress foreign keys: archived "
                    f"{child_table}.{child_column} identifiers are orphaned."
                )


def restore_retired_wordpress_foreign_keys(apps, schema_editor):
    del apps
    connection = schema_editor.connection
    _require_postgresql(connection)
    _require_tables(connection)
    _lock_topology(schema_editor)
    _require_exact_topology(
        connection,
        INTERNAL_FOREIGN_KEYS,
        phase="reverse audit",
    )
    _require_no_orphans(schema_editor)

    quote = schema_editor.quote_name
    with connection.cursor() as cursor:
        for fingerprint in EXTERNAL_FOREIGN_KEYS:
            (
                constraint_name,
                child_table,
                child_columns,
                parent_table,
                parent_columns,
                *_properties,
            ) = fingerprint
            cursor.execute(
                f"ALTER TABLE {quote(child_table)} "
                f"ADD CONSTRAINT {quote(constraint_name)} "
                f"FOREIGN KEY ({quote(child_columns[0])}) "
                f"REFERENCES {quote(parent_table)} ({quote(parent_columns[0])}) "
                "DEFERRABLE INITIALLY DEFERRED"
            )

    _require_exact_topology(
        connection,
        INTERNAL_FOREIGN_KEYS + EXTERNAL_FOREIGN_KEYS,
        phase="reverse verification",
    )


class Migration(migrations.Migration):
    dependencies = [("apps", "0047_retire_wordpress_integration")]

    operations = [
        migrations.RunPython(
            detach_retired_wordpress_foreign_keys,
            restore_retired_wordpress_foreign_keys,
        ),
    ]
