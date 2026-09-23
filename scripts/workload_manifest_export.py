"""Export a secret-free workload restore manifest from durable ORM rows.

The resulting ``upcloud-workload-manifest.json`` deliberately keeps the schema
accepted by ``scripts/upcloud_live_ui_e2e.py verify-workloads``.  Storage
identity is recorded in a separate ownership marker because the verifier's
manifest schema is intentionally strict and provider-neutral.

This module does not construct provider clients, inspect provider credentials,
or decrypt storage/connection fields.  It reads only the explicitly named
BackupSheep rows and publishes a new, exclusive generation outside the
checkout.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKLOAD_MANIFEST_FILENAME = "upcloud-workload-manifest.json"
OWNERSHIP_MARKER_FILENAME = ".workload-manifest-ownership.json"
WORKLOAD_SCHEMA = 1
ATOMIC_PUBLISH_UNAVAILABLE = (
    "Exclusive atomic directory publication is unavailable."
)

SUPPORTED_STORAGE_CODES = {
    "do_spaces": "digitalocean",
    "upcloud": "upcloud",
    "oracle": "oracle",
}

SAFE_RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{6,61}[a-z0-9])$")
SAFE_BACKUP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")
SAFE_DATABASE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

MANIFEST_KEYS = frozenset({"schema", "run_id", "website", "postgresql"})
WEBSITE_KEYS = frozenset({"node_id", "backup_id", "restore_id", "restore_path"})
DATABASE_KEYS = frozenset(
    {"node_id", "backup_id", "restore_id", "restore_database"}
)

SENSITIVE_KEY_PARTS = frozenset(
    {
        "access_key",
        "api_key",
        "api_token",
        "authorization",
        "bearer",
        "credential",
        "private_key",
        "password",
        "passphrase",
        "secret",
        "secret_key",
        "session_token",
        "token",
    }
)


class WorkloadManifestExportError(RuntimeError):
    """A safe, operator-facing export refusal with no provider payload."""


def _positive(value, label: str) -> int:
    if isinstance(value, bool):
        raise WorkloadManifestExportError(f"{label} must be a positive integer.")
    if isinstance(value, float):
        raise WorkloadManifestExportError(f"{label} must be a positive integer.")
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        raise WorkloadManifestExportError(
            f"{label} must be a positive integer."
        ) from None
    if result < 1:
        raise WorkloadManifestExportError(f"{label} must be a positive integer.")
    return result


def _safe_run_id(value) -> str:
    value = str(value or "").strip()
    if not SAFE_RUN_ID.fullmatch(value):
        raise WorkloadManifestExportError("run_id is malformed.")
    return value


def _storage_code(value) -> str:
    value = str(value or "").strip()
    # This is intentionally exact.  ``digitalocean`` is the integration code,
    # not a CoreStorageType code, and must never be silently aliased here.
    if value not in SUPPORTED_STORAGE_CODES:
        raise WorkloadManifestExportError(
            "provider_code must be one of do_spaces, upcloud, or oracle."
        )
    return value


def _safe_backup_id(value, label: str) -> str:
    value = str(value or "").strip()
    if (
        not SAFE_BACKUP_ID.fullmatch(value)
        or value in {".", ".."}
        or ".." in value
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise WorkloadManifestExportError(f"{label} is unsafe.")
    return value


def _safe_database(value, label: str) -> str:
    value = str(value or "")
    if not SAFE_DATABASE.fullmatch(value):
        raise WorkloadManifestExportError(f"{label} is malformed.")
    return value


def _strict_object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WorkloadManifestExportError("A JSON object contains a duplicate key.")
        result[key] = value
    return result


def _strict_json_load(value):
    """Decode JSON with duplicate-key rejection for callers that read JSON."""

    try:
        return json.loads(value, object_pairs_hook=_strict_object_pairs)
    except WorkloadManifestExportError:
        raise
    except (TypeError, ValueError):
        raise WorkloadManifestExportError("JSON input is malformed.") from None


def _sensitive_key(key) -> bool:
    normalized = str(key).casefold().replace("-", "_")
    compact = normalized.replace("_", "")
    if normalized in SENSITIVE_KEY_PARTS or compact in {
        part.replace("_", "") for part in SENSITIVE_KEY_PARTS
    }:
        return True
    return any(
        normalized.endswith(f"_{part}") or normalized.startswith(f"{part}_")
        for part in SENSITIVE_KEY_PARTS
    )


def _assert_secret_free(value, label: str) -> None:
    """Reject secret-shaped ORM JSON before it can influence an output."""

    if isinstance(value, dict):
        for key, child in value.items():
            if _sensitive_key(key):
                raise WorkloadManifestExportError(
                    f"{label} contains a sensitive field name."
                )
            _assert_secret_free(child, label)
    elif isinstance(value, list):
        for child in value:
            _assert_secret_free(child, label)


def _exact_row(model, row_id, label: str, *, select_related=()):
    queryset = model.objects.filter(pk=_positive(row_id, label))
    if select_related:
        queryset = queryset.select_related(*select_related)
    rows = list(queryset.order_by("pk")[:2])
    if len(rows) != 1:
        raise WorkloadManifestExportError(f"{label} is missing or ambiguous.")
    return rows[0]


def _node_account_id(node, label: str) -> int:
    try:
        account_id = int(node.connection.account_id)
    except (AttributeError, TypeError, ValueError):
        raise WorkloadManifestExportError(
            f"{label} has no exact account binding."
        ) from None
    if account_id < 1:
        raise WorkloadManifestExportError(f"{label} has no exact account binding.")
    return account_id


def _require_status(row, expected: int, label: str) -> None:
    try:
        status = int(row.status)
    except (AttributeError, TypeError, ValueError):
        raise WorkloadManifestExportError(f"{label} has no durable status.") from None
    if status != expected:
        raise WorkloadManifestExportError(f"{label} is not complete.")


def _safe_object_key(value, backup, label: str) -> str:
    object_key = str(value or "")
    backup_id = _safe_backup_id(
        getattr(backup, "uuid_str", None), f"{label} backup identifier"
    )
    if (
        not object_key
        or object_key.startswith("/")
        or "\\" in object_key
        or any(ord(character) < 32 or ord(character) == 127 for character in object_key)
        or any(part in {"", ".", ".."} for part in object_key.split("/"))
        or not object_key.endswith(f"{backup_id}.zip")
    ):
        raise WorkloadManifestExportError(f"{label} object key is unsafe or unbound.")
    return object_key


def _durable_targets(website_restore, website_backup, database_restore, database_backup, run_id):
    """Run the existing strict, pure target validators without provider I/O."""

    try:
        from scripts.upcloud_manifest_export import (
            _durable_database_restore_target,
            _durable_website_restore_target,
        )

        website_target = _durable_website_restore_target(
            website_restore,
            backup=website_backup,
            run_id=run_id,
        )
        database_target = _durable_database_restore_target(
            database_restore,
            backup=database_backup,
        )
    except WorkloadManifestExportError:
        raise
    except Exception as error:
        # The helper's normal failure is already safe; this wrapper prevents ORM
        # or implementation details from becoming a CLI/provider disclosure.
        if error.__class__.__name__ == "UpCloudManifestExportError":
            raise WorkloadManifestExportError(str(error)) from None
        raise WorkloadManifestExportError(
            "Durable workload restore evidence could not be validated."
        ) from None

    base = f"/srv/backupsheep-e2e/{run_id}"
    if not (website_target == base or website_target.startswith(base + "/")):
        raise WorkloadManifestExportError(
            "Website restore target escaped the owned run root."
        )
    return website_target, database_target


def _verified_artifact(backup, storage_point, storage_id: int, label: str) -> dict:
    """Reuse the strict artifact identity check used by the UpCloud exporter."""

    try:
        from scripts.upcloud_manifest_export import _artifact_for

        artifact = _artifact_for(
            backup,
            storage_id=storage_id,
            storage_point=storage_point,
            label=label,
        )
    except WorkloadManifestExportError:
        raise
    except Exception as error:
        if error.__class__.__name__ == "UpCloudManifestExportError":
            raise WorkloadManifestExportError(str(error)) from None
        raise WorkloadManifestExportError(
            f"{label} artifact evidence could not be validated."
        ) from None

    _safe_object_key(artifact.get("object_key"), backup, label)
    return artifact


def _artifact_binding(artifact: dict) -> dict:
    """Return only non-secret artifact identity covered by a binding digest."""

    identity = {
        "artifact_id": int(artifact["artifact_id"]),
        "byte_count": int(artifact["byte_count"]),
        "sha256": str(artifact["sha256"]).casefold(),
        "etag": str(artifact["etag"]),
        "version_id": str(artifact["version_id"]),
    }
    identity["binding_sha256"] = hashlib.sha256(
        _json_bytes(identity)
    ).hexdigest()
    return identity


def _load_scope(
    *,
    account_id: int,
    run_id: str,
    storage_id: int,
    provider_code: str,
    website_backup_id: int,
    website_restore_id: int,
    database_backup_id: int,
    database_restore_id: int,
):
    from apps.console.backup.models import (
        CoreDatabaseBackup,
        CoreDatabaseRestore,
        CoreWebsiteBackup,
        CoreWebsiteRestore,
    )
    from apps.console.storage.models import CoreStorage

    storage = _exact_row(
        CoreStorage,
        storage_id,
        "storage_id",
        select_related=("type", "account"),
    )
    if int(storage.account_id) != account_id:
        raise WorkloadManifestExportError("Storage is cross-account.")
    if str(storage.type.code) != provider_code:
        raise WorkloadManifestExportError("Storage provider code does not match.")
    if int(storage.status) != int(CoreStorage.Status.ACTIVE):
        raise WorkloadManifestExportError("Storage is not active.")

    website_backup = _exact_row(
        CoreWebsiteBackup,
        website_backup_id,
        "website_backup_id",
        select_related=("website__node__connection",),
    )
    website_restore = _exact_row(
        CoreWebsiteRestore,
        website_restore_id,
        "website_restore_id",
        select_related=("backup__website__node__connection", "storage_point__storage__type"),
    )
    database_backup = _exact_row(
        CoreDatabaseBackup,
        database_backup_id,
        "database_backup_id",
        select_related=("database__node__connection",),
    )
    database_restore = _exact_row(
        CoreDatabaseRestore,
        database_restore_id,
        "database_restore_id",
        select_related=("backup__database__node__connection", "storage_point__storage__type"),
    )

    _require_status(website_backup, 3, "Website backup")
    _require_status(website_restore, 3, "Website restore")
    _require_status(database_backup, 3, "Database backup")
    _require_status(database_restore, 3, "Database restore")

    website_node = website_backup.website.node
    database_node = database_backup.database.node
    if int(website_node.type) != 3 or int(database_node.type) != 4:
        raise WorkloadManifestExportError("Workload node types are inconsistent.")
    if _node_account_id(website_node, "Website workload") != account_id:
        raise WorkloadManifestExportError("Website workload is cross-account.")
    if _node_account_id(database_node, "Database workload") != account_id:
        raise WorkloadManifestExportError("Database workload is cross-account.")

    website_storage_point = website_restore.storage_point
    database_storage_point = database_restore.storage_point
    if website_storage_point is None or database_storage_point is None:
        raise WorkloadManifestExportError("A restore has no exact storage point.")
    for point, backup, label in (
        (website_storage_point, website_backup, "Website storage point"),
        (database_storage_point, database_backup, "Database storage point"),
    ):
        _require_status(point, 3, label)
        if (
            int(point.storage_id) != storage_id
            or int(point.backup_id) != int(backup.pk)
            or int(point.storage.account_id) != account_id
            or str(point.storage.type.code) != provider_code
        ):
            raise WorkloadManifestExportError(
                f"{label} is cross-account, cross-storage, or cross-backup."
            )

    if int(website_restore.backup_id) != int(website_backup.pk):
        raise WorkloadManifestExportError("Website restore is cross-backup.")
    if int(database_restore.backup_id) != int(database_backup.pk):
        raise WorkloadManifestExportError("Database restore is cross-backup.")

    # Read and inspect only durable JSON fields that participate in the proof.
    # Storage credential rows are intentionally never traversed.
    for row, label in (
        (website_backup, "Website backup"),
        (website_restore, "Website restore"),
        (database_backup, "Database backup"),
        (database_restore, "Database restore"),
        (website_storage_point, "Website storage point"),
        (database_storage_point, "Database storage point"),
    ):
        for field in ("metadata", "execution_metadata", "params"):
            if hasattr(row, field):
                _assert_secret_free(getattr(row, field), label)

    website_target, database_target = _durable_targets(
        website_restore,
        website_backup,
        database_restore,
        database_backup,
        run_id,
    )
    website_artifact = _verified_artifact(
        website_backup,
        website_storage_point,
        storage_id,
        "website",
    )
    database_artifact = _verified_artifact(
        database_backup,
        database_storage_point,
        storage_id,
        "database",
    )
    for artifact, label in (
        (website_artifact, "Website artifact"),
        (database_artifact, "Database artifact"),
    ):
        _assert_secret_free(artifact, label)

    rows = {
        "website_node_id": int(website_backup.website.node_id),
        "website_backup_id": int(website_backup.pk),
        "website_restore_id": int(website_restore.pk),
        "database_node_id": int(database_backup.database.node_id),
        "database_backup_id": int(database_backup.pk),
        "database_restore_id": int(database_restore.pk),
        "website_storage_point_id": int(website_storage_point.pk),
        "database_storage_point_id": int(database_storage_point.pk),
        "website_artifact_id": int(website_artifact["artifact_id"]),
        "database_artifact_id": int(database_artifact["artifact_id"]),
    }
    return {
        "storage": storage,
        "website_backup": website_backup,
        "website_restore": website_restore,
        "database_backup": database_backup,
        "database_restore": database_restore,
        "website_target": website_target,
        "database_target": database_target,
        "website_artifact": website_artifact,
        "database_artifact": database_artifact,
        "rows": rows,
    }


def _build_workload_manifest_with_proof(
    *,
    account_id,
    run_id,
    storage_id,
    provider_code,
    website_backup_id,
    website_restore_id,
    database_backup_id,
    database_restore_id,
) -> tuple[dict, dict]:
    """Return ``(manifest, proof)`` from exact durable row IDs.

    ``proof`` is internal/export-only data used to build the ownership marker;
    it is never written into the verifier-consumed manifest.
    """

    account_id = _positive(account_id, "account_id")
    storage_id = _positive(storage_id, "storage_id")
    run_id = _safe_run_id(run_id)
    provider_code = _storage_code(provider_code)
    scope = _load_scope(
        account_id=account_id,
        run_id=run_id,
        storage_id=storage_id,
        provider_code=provider_code,
        website_backup_id=_positive(website_backup_id, "website_backup_id"),
        website_restore_id=_positive(website_restore_id, "website_restore_id"),
        database_backup_id=_positive(database_backup_id, "database_backup_id"),
        database_restore_id=_positive(database_restore_id, "database_restore_id"),
    )
    website_backup = scope["website_backup"]
    website_restore = scope["website_restore"]
    database_backup = scope["database_backup"]
    database_restore = scope["database_restore"]
    manifest = {
        "schema": WORKLOAD_SCHEMA,
        "run_id": run_id,
        "website": {
            "node_id": int(website_backup.website.node_id),
            "backup_id": int(website_backup.pk),
            "restore_id": int(website_restore.pk),
            "restore_path": scope["website_target"],
        },
        "postgresql": {
            "node_id": int(database_backup.database.node_id),
            "backup_id": int(database_backup.pk),
            "restore_id": int(database_restore.pk),
            "restore_database": scope["database_target"],
        },
    }
    _validate_manifest(manifest, run_id)
    proof = {
        "account_id": account_id,
        "provider_code": provider_code,
        "integration_code": SUPPORTED_STORAGE_CODES[provider_code],
        "storage_id": storage_id,
        "rows": scope["rows"],
        "website_restore_correlation_id": str(website_restore.correlation_id),
        "database_restore_correlation_id": str(database_restore.correlation_id),
        "website_restore_path": scope["website_target"],
        "database_restore_database": scope["database_target"],
        "website_artifact": scope["website_artifact"],
        "database_artifact": scope["database_artifact"],
    }
    _assert_secret_free(proof, "Export proof")
    return manifest, proof


def build_workload_manifest(
    *,
    account_id,
    run_id,
    storage_id,
    provider_code,
    website_backup_id,
    website_restore_id,
    database_backup_id,
    database_restore_id,
) -> dict:
    """Build only the strict verifier payload from durable ORM rows."""

    manifest, _proof = _build_workload_manifest_with_proof(
        account_id=account_id,
        run_id=run_id,
        storage_id=storage_id,
        provider_code=provider_code,
        website_backup_id=website_backup_id,
        website_restore_id=website_restore_id,
        database_backup_id=database_backup_id,
        database_restore_id=database_restore_id,
    )
    return manifest


collect_workload_manifest = build_workload_manifest


def _validate_manifest(manifest: dict, run_id: str) -> None:
    if set(manifest) != MANIFEST_KEYS:
        raise WorkloadManifestExportError("Workload manifest fields are malformed.")
    if type(manifest.get("schema")) is not int or manifest["schema"] != WORKLOAD_SCHEMA:
        raise WorkloadManifestExportError("Workload manifest schema is malformed.")
    if manifest.get("run_id") != run_id:
        raise WorkloadManifestExportError("Workload manifest run scope is malformed.")
    website = manifest.get("website")
    database = manifest.get("postgresql")
    if not isinstance(website, dict) or set(website) != WEBSITE_KEYS:
        raise WorkloadManifestExportError("Website workload manifest fields are malformed.")
    if not isinstance(database, dict) or set(database) != DATABASE_KEYS:
        raise WorkloadManifestExportError("Database workload manifest fields are malformed.")
    for row, label in ((website, "website"), (database, "postgresql")):
        for field in ("node_id", "backup_id", "restore_id"):
            _positive(row.get(field), f"{label}.{field}")
    if not isinstance(website["restore_path"], str) or not website["restore_path"].startswith(
        "/srv/backupsheep-e2e/"
    ):
        raise WorkloadManifestExportError("Website restore path is malformed.")
    _safe_database(database["restore_database"], "postgresql.restore_database")
    _assert_secret_free(manifest, "Workload manifest")


def _json_bytes(payload: dict) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        # Round-trip through the duplicate-key rejecting decoder.  This keeps
        # the output contract explicit even though the source is a Python dict.
        decoded = _strict_json_load(encoded)
    except WorkloadManifestExportError:
        raise
    except (TypeError, ValueError, UnicodeError):
        raise WorkloadManifestExportError("Manifest JSON is not serializable.") from None
    if decoded != payload:
        raise WorkloadManifestExportError("Manifest JSON changed during validation.")
    return encoded


def _write_exclusive_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise WorkloadManifestExportError("Manifest generation file already exists.") from None
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_exclusive(source: Path, destination: Path) -> None:
    """Atomically publish a directory without replacing a racing destination."""

    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform.startswith("linux"):
        renameat2 = getattr(library, "renameat2", None)
        if renameat2 is None:
            raise WorkloadManifestExportError(ATOMIC_PUBLISH_UNAVAILABLE)
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(-100, source_bytes, -100, destination_bytes, 1)
    elif sys.platform == "darwin":
        renamex_np = getattr(library, "renamex_np", None)
        if renamex_np is None:
            raise WorkloadManifestExportError(ATOMIC_PUBLISH_UNAVAILABLE)
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = renamex_np(source_bytes, destination_bytes, 0x00000004)
    else:
        raise WorkloadManifestExportError(ATOMIC_PUBLISH_UNAVAILABLE)
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise WorkloadManifestExportError(
            "Manifest generation destination already exists."
        )
    raise WorkloadManifestExportError(
        "Manifest generation could not be published atomically."
    )


def _safe_generation_destination(value) -> Path:
    requested = Path(value).expanduser()
    if not requested.is_absolute():
        raise WorkloadManifestExportError("Manifest output must be an absolute path.")
    if requested.name in {"", ".", ".."}:
        raise WorkloadManifestExportError(
            "Manifest output must name a new generation directory."
        )
    if requested.exists() or requested.is_symlink():
        raise WorkloadManifestExportError(
            "Manifest generation destination already exists."
        )
    parent = requested.parent
    if not parent.is_dir() or parent.is_symlink():
        raise WorkloadManifestExportError(
            "Manifest generation parent must be an existing real directory."
        )
    absolute_parent = os.path.abspath(os.fspath(parent))
    real_parent = os.path.realpath(absolute_parent)
    if real_parent != absolute_parent:
        raise WorkloadManifestExportError(
            "Manifest generation parent must not traverse a symlink."
        )
    parent = Path(real_parent)
    destination = parent / requested.name
    if destination.exists() or destination.is_symlink():
        raise WorkloadManifestExportError(
            "Manifest generation destination already exists."
        )
    if "_docs" in destination.parts:
        raise WorkloadManifestExportError("Manifest output must not be inside _docs.")
    try:
        destination.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise WorkloadManifestExportError("Manifest output must be outside the worktree.")
    return destination


def export_workload_manifest(
    *,
    output_dir,
    account_id,
    run_id,
    storage_id,
    provider_code,
    website_backup_id,
    website_restore_id,
    database_backup_id,
    database_restore_id,
) -> dict:
    """Publish one new generation and return a secret-free JSON receipt."""

    destination = _safe_generation_destination(output_dir)
    manifest, proof = _build_workload_manifest_with_proof(
        account_id=account_id,
        run_id=run_id,
        storage_id=storage_id,
        provider_code=provider_code,
        website_backup_id=website_backup_id,
        website_restore_id=website_restore_id,
        database_backup_id=database_backup_id,
        database_restore_id=database_restore_id,
    )
    manifest_bytes = _json_bytes(manifest)
    marker = {
        "schema": WORKLOAD_SCHEMA,
        "kind": "workload_restore_manifest_ownership",
        "run_id": manifest["run_id"],
        "provider_code": proof["provider_code"],
        "integration_code": proof["integration_code"],
        "storage_id": proof["storage_id"],
        "rows": proof["rows"],
        "website_restore_correlation_id": proof["website_restore_correlation_id"],
        "database_restore_correlation_id": proof["database_restore_correlation_id"],
        "website_restore_path": proof["website_restore_path"],
        "database_restore_database": proof["database_restore_database"],
        "artifact_bindings": {
            "website": _artifact_binding(proof["website_artifact"]),
            "database": _artifact_binding(proof["database_artifact"]),
        },
        "manifest": {
            "filename": WORKLOAD_MANIFEST_FILENAME,
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "byte_count": len(manifest_bytes),
        },
    }
    _assert_secret_free(marker, "Ownership marker")
    marker_bytes = _json_bytes(marker)

    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.workload-staging-",
            dir=destination.parent,
        )
    )
    os.chmod(staging, 0o700)
    published = False
    try:
        _write_exclusive_file(
            staging / WORKLOAD_MANIFEST_FILENAME,
            manifest_bytes,
        )
        _write_exclusive_file(
            staging / OWNERSHIP_MARKER_FILENAME,
            marker_bytes,
        )
        _fsync_directory(staging)
        _publish_exclusive(staging, destination)
        published = True
        _fsync_directory(destination.parent)
    finally:
        if not published and staging.exists():
            shutil.rmtree(staging)

    marker_sha256 = hashlib.sha256(marker_bytes).hexdigest()
    return {
        "status": "exported",
        "run_id": manifest["run_id"],
        "provider_code": proof["provider_code"],
        "integration_code": proof["integration_code"],
        "storage_id": proof["storage_id"],
        "generation_dir": str(destination),
        "manifest": {
            "path": str(destination / WORKLOAD_MANIFEST_FILENAME),
            "filename": WORKLOAD_MANIFEST_FILENAME,
            "sha256": marker["manifest"]["sha256"],
            "byte_count": marker["manifest"]["byte_count"],
        },
        "ownership_marker": {
            "path": str(destination / OWNERSHIP_MARKER_FILENAME),
            "filename": OWNERSHIP_MARKER_FILENAME,
            "sha256": marker_sha256,
            "byte_count": len(marker_bytes),
        },
        "rows": proof["rows"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Export one secret-free provider-neutral workload restore manifest "
            "from durable BackupSheep rows."
        )
    )
    parser.add_argument("--account-id", type=int, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--storage-id", type=int, required=True)
    parser.add_argument(
        "--provider-code",
        "--storage-provider-code",
        "--storage-type-code",
        dest="provider_code",
        required=True,
        help="Exact CoreStorageType code: do_spaces, upcloud, or oracle.",
    )
    parser.add_argument("--website-backup-id", type=int, required=True)
    parser.add_argument("--website-restore-id", type=int, required=True)
    parser.add_argument("--database-backup-id", type=int, required=True)
    parser.add_argument("--database-restore-id", type=int, required=True)
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv=None, *, environment=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backupsheep.settings")
        import django

        django.setup()
        receipt = export_workload_manifest(
            output_dir=args.output_dir,
            account_id=args.account_id,
            run_id=args.run_id,
            storage_id=args.storage_id,
            provider_code=args.provider_code,
            website_backup_id=args.website_backup_id,
            website_restore_id=args.website_restore_id,
            database_backup_id=args.database_backup_id,
            database_restore_id=args.database_restore_id,
        )
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except WorkloadManifestExportError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except Exception:
        # Do not expose ORM/provider configuration or exception payloads through
        # a command intended to be safe around credential-bearing containers.
        print("ERROR: Workload manifest export stopped safely.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
