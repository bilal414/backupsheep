"""Emit the exact transactional Django migration graph for release signing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Iterable
from typing import Any


MIGRATION_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}\.[0-9][A-Za-z0-9_]{0,127}$")
MAX_MIGRATIONS = 4096


def migration_digest(names: list[str], *, leaves: bool = False) -> str:
    domain = (
        "BACKUPSHEEP-DJANGO-MIGRATION-LEAVES-V1"
        if leaves
        else "BACKUPSHEEP-DJANGO-MIGRATION-SET-V1"
    )
    payload = (domain + "\n" + "\n".join(names) + "\n").encode("ascii")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def build_contract(
    disk_migrations: dict[tuple[str, str], Any],
    graph_nodes: Iterable[tuple[str, str]],
    leaf_nodes: Iterable[tuple[str, str]],
) -> dict[str, Any]:
    disk_keys = set(disk_migrations)
    nodes = set(graph_nodes)
    if not disk_keys or len(disk_keys) > MAX_MIGRATIONS or nodes != disk_keys:
        raise ValueError("the loaded migration graph is incomplete or exceeds its bound")
    migrations = sorted(f"{app}.{name}" for app, name in disk_keys)
    leaves = sorted(f"{app}.{name}" for app, name in set(leaf_nodes))
    if not leaves or not set(leaves).issubset(migrations):
        raise ValueError("migration graph leaves are incomplete")
    if len(migrations) != len(set(migrations)) or len(leaves) != len(set(leaves)):
        raise ValueError("migration graph contains duplicate canonical names")
    if any(MIGRATION_RE.fullmatch(name) is None for name in (*migrations, *leaves)):
        raise ValueError("migration graph contains a noncanonical name")
    for key, migration in disk_migrations.items():
        if getattr(migration, "replaces", None):
            raise ValueError(f"replacement migration requires explicit release review: {key}")
        if getattr(migration, "atomic", True) is not True:
            raise ValueError(f"nontransactional migration is not release-safe: {key}")
    return {
        "schema_version": 1,
        "all_migrations_atomic": True,
        "migrations": migrations,
        "migration_set_sha256": migration_digest(migrations),
        "leaves": leaves,
        "leaf_set_sha256": migration_digest(leaves, leaves=True),
    }


def main() -> int:
    # The release image is the reviewed dependency boundary.  This minimal
    # settings module avoids application startup hooks and never opens a DB or
    # network connection while the migration files are imported.
    os.environ.clear()
    os.environ.update(
        {
            "DJANGO_SETTINGS_MODULE": "backupsheep.release_migration_settings",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    try:
        import django
        from django.db.migrations.loader import MigrationLoader

        django.setup()
        loader = MigrationLoader(None, ignore_no_migrations=True)
        contract = build_contract(
            loader.disk_migrations,
            loader.graph.nodes,
            loader.graph.leaf_nodes(),
        )
    except Exception as exc:  # pragma: no cover - exercised in the release image.
        print(f"release migration contract failed: {exc}", file=sys.stderr)
        return 1
    json.dump(contract, sys.stdout, ensure_ascii=True, sort_keys=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
