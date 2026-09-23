"""Shared MySQL/MariaDB database-level schema metadata helpers."""

import re


DATABASE_DEFAULTS_QUERY = (
    "SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME "
    "FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = DATABASE();"
)

SYSTEM_DATABASES = frozenset(
    {
        "information_schema",
        "mysql",
        "performance_schema",
        "sys",
    }
)

_SCHEMA_TOKEN = re.compile(r"^[A-Za-z0-9_]+$")


def parse_database_defaults(output):
    """Return validated database defaults from a two-column client result."""
    rows = [line for line in str(output or "").splitlines() if line.strip()]
    if len(rows) != 1:
        raise ValueError("database defaults query returned an unexpected row count")
    fields = rows[0].split("\t")
    if len(fields) != 2 or not all(_SCHEMA_TOKEN.fullmatch(value) for value in fields):
        raise ValueError("database defaults query returned malformed values")
    return {"character_set": fields[0], "collation": fields[1]}


def is_schema_token(value):
    return isinstance(value, str) and bool(_SCHEMA_TOKEN.fullmatch(value))


def database_defaults_preamble(defaults):
    """Return a database-local SQL preamble bound into the dump digest.

    Restore clients select the owned target database before reading a dump, so
    an unqualified ``ALTER DATABASE`` applies the source defaults to that target
    without embedding or replaying the source database name.
    """
    if not isinstance(defaults, dict):
        raise ValueError("database defaults are malformed")
    character_set = defaults.get("character_set")
    collation = defaults.get("collation")
    if not is_schema_token(character_set) or not is_schema_token(collation):
        raise ValueError("database defaults are malformed")
    return (
        f"ALTER DATABASE CHARACTER SET {character_set} COLLATE {collation};\n"
    ).encode("ascii")
