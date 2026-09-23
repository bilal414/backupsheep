"""Secret-free UpCloud E2E manifest export from explicit durable row IDs.

This module never creates a provider client and never decrypts an integration.
It reads only BackupSheep ORM rows, rejects ambiguity, and atomically publishes
one exclusive, ownership-marked generation containing three mode-0600 JSON
files outside the repository checkout.
"""

from __future__ import annotations

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
SAFE_RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{6,61}[a-z0-9])$")
SAFE_BACKUP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
POSTGRES_IDENTIFIER_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
GENERATION_MARKER = ".upcloud-manifest-generation.json"
MANIFEST_FILENAMES = {
    "compute": "upcloud-compute-manifest.json",
    "workload": "upcloud-workload-manifest.json",
    "object": "upcloud-object-manifest.json",
}


class UpCloudManifestExportError(RuntimeError):
    pass


def _positive(value, label):
    if isinstance(value, bool):
        raise UpCloudManifestExportError(f"{label} must be a positive row ID.")
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise UpCloudManifestExportError(f"{label} must be a positive row ID.") from None
    if value < 1:
        raise UpCloudManifestExportError(f"{label} must be a positive row ID.")
    return value


def _safe_backup_id(value):
    value = str(value or "").strip()
    if (
        not SAFE_BACKUP_ID.fullmatch(value)
        or value in {".", ".."}
        or ".." in value
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise UpCloudManifestExportError(
            "A durable backup object identifier is unsafe."
        )
    return value


def _exact_row(model, row_id, label, *, select_related=()):
    queryset = model.objects.filter(pk=_positive(row_id, label))
    if select_related:
        queryset = queryset.select_related(*select_related)
    rows = list(queryset[:2])
    if len(rows) != 1:
        raise UpCloudManifestExportError(f"{label} is missing or ambiguous.")
    return rows[0]


def _node_account_id(node):
    try:
        return int(node.connection.account_id)
    except (AttributeError, TypeError, ValueError):
        raise UpCloudManifestExportError("A durable node has no exact account binding.") from None


def _require_complete(row, label):
    if int(getattr(row, "status", -1)) != 3:
        raise UpCloudManifestExportError(f"{label} is not complete.")


def _safe_owned_website_path(value, run_id):
    value = str(value or "")
    base = f"/srv/backupsheep-e2e/{run_id}"
    if (
        value != value.strip()
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or not (value == base or value.startswith(base + "/"))
    ):
        raise UpCloudManifestExportError("Website restore target escaped its owned run root.")
    parts = value.split("/")
    if parts[0] or any(part in {"", ".", ".."} for part in parts[1:]):
        raise UpCloudManifestExportError("Website restore target path is ambiguous.")
    return value


def _durable_website_restore_target(restore, *, backup, run_id):
    """Return one completed in-place target proven by immutable row evidence."""

    _positive(getattr(restore, "pk", None), "website_restore_id")
    website = backup.website
    configured = website.paths if isinstance(website.paths, list) else []
    if bool(website.all_paths) or len(configured) != 1 or not isinstance(configured[0], dict):
        raise UpCloudManifestExportError("Website restore path configuration is ambiguous.")
    configured_row = configured[0]
    if set(configured_row) not in ({"path", "type"}, {"name", "path", "type"}):
        raise UpCloudManifestExportError("Website restore path configuration is malformed.")
    target = _safe_owned_website_path(configured_row.get("path"), run_id)
    if (
        configured_row.get("type") != "directory"
        or ("name" in configured_row and configured_row.get("name") != target)
    ):
        raise UpCloudManifestExportError("Website restore path configuration changed.")

    metadata = restore.execution_metadata
    if not isinstance(metadata, dict):
        raise UpCloudManifestExportError("Website restore execution evidence is missing.")
    manifest = metadata.get("source_manifest")
    states = metadata.get("source_states")
    completed = metadata.get("completed_sources")
    if (
        not isinstance(manifest, dict)
        or len(manifest) != 1
        or not isinstance(states, dict)
        or len(states) != 1
    ):
        raise UpCloudManifestExportError("Website restore source evidence is ambiguous.")
    source_key, source = next(iter(manifest.items()))
    fingerprint, state = next(iter(states.items()))
    if not isinstance(source, dict) or not isinstance(state, dict):
        raise UpCloudManifestExportError("Website restore source evidence is malformed.")
    source_digest = str(source.get("source_digest") or "").casefold()
    expected_fingerprint = hashlib.sha256(
        f"{backup.uuid}|{source_digest}".encode("utf-8")
    ).hexdigest()
    if any(
        (
            source_key != f"directory:{target}",
            set(source) != {"path", "type", "source_digest", "files"},
            source.get("path") != target,
            source.get("type") != "directory",
            not SHA256_RE.fullmatch(source_digest),
            fingerprint != expected_fingerprint,
            completed != [fingerprint],
            state.get("path") != target,
            state.get("target_path") != target,
            state.get("type") != "directory",
            state.get("source_digest") != source_digest,
            state.get("status") != "complete",
        )
    ):
        raise UpCloudManifestExportError("Website restore source evidence conflicts.")

    manifest_files = source.get("files")
    state_files = state.get("files")
    if not isinstance(manifest_files, list) or not manifest_files or not isinstance(state_files, dict):
        raise UpCloudManifestExportError("Website restore file evidence is incomplete.")
    expected_files = {}
    for row in manifest_files:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise UpCloudManifestExportError("Website restore file evidence is malformed.")
        path = str(row.get("path") or "")
        sha256 = str(row.get("sha256") or "").casefold()
        try:
            byte_count = int(row.get("bytes"))
        except (TypeError, ValueError):
            raise UpCloudManifestExportError("Website restore file evidence is malformed.") from None
        if (
            not path
            or path in expected_files
            or path.startswith("/")
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or not SHA256_RE.fullmatch(sha256)
            or byte_count < 0
        ):
            raise UpCloudManifestExportError("Website restore file evidence is malformed.")
        expected_files[path] = {"bytes": byte_count, "sha256": sha256, "status": "complete"}
    if state_files != expected_files:
        raise UpCloudManifestExportError("Website restore file evidence conflicts.")

    if any(
        (
            str(restore.execution_phase) != "complete",
            int(restore.progress_completed or 0) != 1,
            int(restore.progress_total or 0) != 1,
            str(restore.progress_unit or "") != "paths",
        )
    ):
        raise UpCloudManifestExportError("Website restore completion evidence is incomplete.")
    return target


def _durable_database_restore_target(restore, *, backup):
    """Return one fork target bound to source, backup, checkpoint, and restore row."""

    _positive(getattr(restore, "pk", None), "database_restore_id")
    configured = backup.database.databases
    if (
        bool(backup.database.all_databases)
        or not isinstance(configured, list)
        or len(configured) != 1
    ):
        raise UpCloudManifestExportError("Database restore source configuration is ambiguous.")
    source = str(configured[0] or "")
    params = restore.params if isinstance(restore.params, dict) else {}
    mapping = params.get("target_mapping")
    if not isinstance(mapping, dict) or len(mapping) != 1:
        raise UpCloudManifestExportError("Database restore target evidence is missing or ambiguous.")
    mapped_source, target = next(iter(mapping.items()))
    target = str(target or "")
    if any(
        (
            mapped_source != source,
            not POSTGRES_IDENTIFIER_RE.fullmatch(source),
            not POSTGRES_IDENTIFIER_RE.fullmatch(target),
            target == source,
            params.get("mode") != "fork",
            params.get("mapping_locked") is not True,
            str(params.get("source_backup_uuid") or "") != str(backup.uuid),
        )
    ):
        raise UpCloudManifestExportError("Database restore target evidence conflicts.")
    correlation = str(restore.correlation_id).replace("-", "")
    source_slug = re.sub(r"[^a-zA-Z0-9]+", "_", source).strip("_").lower()[:22]
    source_digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    expected_target = f"bs_restore_{correlation[:12]}_{source_slug or 'database'}_{source_digest}"[:63]
    if not re.fullmatch(r"[0-9a-f]{32}", correlation) or target != expected_target:
        raise UpCloudManifestExportError("Database restore target is not bound to its restore row.")
    metadata = restore.execution_metadata if isinstance(restore.execution_metadata, dict) else {}
    checkpoints = metadata.get("target_checkpoints")
    checkpoint = checkpoints.get(target) if isinstance(checkpoints, dict) else None
    if any(
        (
            metadata.get("source_to_target") != mapping,
            metadata.get("mapping_locked") is not True,
            not isinstance(checkpoints, dict),
            len(checkpoints or {}) != 1,
            not isinstance(checkpoint, dict),
            (checkpoint or {}).get("source") != source,
            (checkpoint or {}).get("status") != "complete",
            not SHA256_RE.fullmatch(str((checkpoint or {}).get("source_digest") or "")),
            str(restore.execution_phase) != "complete",
            int(restore.progress_completed or 0) != 1,
            int(restore.progress_total or 0) != 1,
            str(restore.progress_unit or "") != "databases",
        )
    ):
        raise UpCloudManifestExportError("Database restore completion evidence conflicts.")
    return target


def _artifact_for(backup, *, storage_id, storage_point, label):
    artifacts = list(
        backup.artifact_records.filter(
            storage_id=storage_id,
            role__in=("archive", "destination"),
            verified_at__isnull=False,
        ).order_by("pk")[:3]
    )
    if len(artifacts) != 1:
        raise UpCloudManifestExportError(
            f"{label} has missing or duplicate verified artifact evidence."
        )
    artifact = artifacts[0]
    object_key = str(artifact.object_key or "")
    backup_uuid = _safe_backup_id(backup.uuid_str)
    checksum = str(artifact.checksum_value or "").casefold()
    etag = str(artifact.etag or "").strip('"')
    version_id = str(artifact.version_id or "")
    if any(
        (
            str(artifact.checksum_algorithm or "").casefold() != "sha256",
            not SHA256_RE.fullmatch(checksum),
            int(artifact.byte_count) < 1,
            not etag,
            not version_id,
            version_id == "null",
            str(storage_point.storage_file_id or "") != object_key,
            not object_key.endswith(f"{backup_uuid}.zip"),
        )
    ):
        raise UpCloudManifestExportError(f"{label} artifact evidence is incomplete.")
    try:
        committed = storage_point.committed_integrity_identity()
        committed_version = storage_point.committed_version_id()
    except Exception:
        raise UpCloudManifestExportError(
            f"{label} has conflicting committed artifact evidence."
        ) from None
    if committed != {"size_bytes": int(artifact.byte_count), "sha256": checksum}:
        raise UpCloudManifestExportError(f"{label} integrity evidence conflicts.")
    if committed_version != version_id:
        raise UpCloudManifestExportError(f"{label} version evidence conflicts.")
    return {
        "kind": label,
        "backup_id": int(backup.pk),
        "backup_uuid": backup_uuid,
        "storage_point_id": int(storage_point.pk),
        "storage_id": int(storage_id),
        "artifact_id": int(artifact.pk),
        "artifact_status": "verified",
        "object_key": object_key,
        "sha256": checksum,
        "byte_count": int(artifact.byte_count),
        "etag": etag,
        "version_id": version_id,
    }


def _upcloud_source_id(restore, label):
    try:
        integration = restore.node.upcloud
        value = str(integration.unique_id or "")
    except (AttributeError, TypeError):
        value = ""
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        value,
    ):
        raise UpCloudManifestExportError(f"{label} has no exact UpCloud source ID.")
    return value


def collect_upcloud_manifest_payloads(
    *,
    run_id,
    account_id,
    storage_id,
    website_backup_id,
    website_restore_id,
    database_backup_id,
    database_restore_id,
    volume_restore_id,
    server_restore_id,
):
    """Build all manifests from explicit ORM row IDs without credential access."""

    run_id = str(run_id or "").strip()
    if not SAFE_RUN_ID.fullmatch(run_id):
        raise UpCloudManifestExportError("run_id is malformed.")
    account_id = _positive(account_id, "account_id")
    storage_id = _positive(storage_id, "storage_id")

    from apps.console.backup.models import (
        CoreCloudRestore,
        CoreDatabaseBackup,
        CoreDatabaseRestore,
        CoreWebsiteBackup,
        CoreWebsiteRestore,
    )
    from apps.console.storage.models import CoreStorage

    storage = _exact_row(
        CoreStorage, storage_id, "storage_id", select_related=("type", "account")
    )
    if storage.account_id != account_id or storage.type.code != "upcloud":
        raise UpCloudManifestExportError("The storage row is cross-account or not UpCloud.")

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
        select_related=("backup__website__node__connection", "storage_point__storage"),
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
        select_related=("backup__database__node__connection", "storage_point__storage"),
    )
    volume_restore = _exact_row(
        CoreCloudRestore,
        volume_restore_id,
        "volume_restore_id",
        select_related=("node__connection",),
    )
    server_restore = _exact_row(
        CoreCloudRestore,
        server_restore_id,
        "server_restore_id",
        select_related=("node__connection",),
    )

    rows = (
        (website_backup, website_backup.website.node, "website backup"),
        (website_restore, website_restore.backup.website.node, "website restore"),
        (database_backup, database_backup.database.node, "database backup"),
        (database_restore, database_restore.backup.database.node, "database restore"),
        (volume_restore, volume_restore.node, "volume restore"),
        (server_restore, server_restore.node, "server restore"),
    )
    for row, node, label in rows:
        _require_complete(row, label)
        if _node_account_id(node) != account_id:
            raise UpCloudManifestExportError(f"{label} is cross-account.")

    if (
        website_restore.backup_id != website_backup.pk
        or database_restore.backup_id != database_backup.pk
        or website_restore.storage_point is None
        or database_restore.storage_point is None
        or website_restore.storage_point.storage_id != storage_id
        or database_restore.storage_point.storage_id != storage_id
        or website_restore.storage_point.backup_id != website_backup.pk
        or database_restore.storage_point.backup_id != database_backup.pk
    ):
        raise UpCloudManifestExportError("A workload restore is cross-backup or cross-storage.")
    if (
        int(website_restore.storage_point.status) != 3
        or int(database_restore.storage_point.status) != 3
    ):
        raise UpCloudManifestExportError("A workload storage point is not upload-complete.")

    website_object = _artifact_for(
        website_backup,
        storage_id=storage_id,
        storage_point=website_restore.storage_point,
        label="website",
    )
    database_object = _artifact_for(
        database_backup,
        storage_id=storage_id,
        storage_point=database_restore.storage_point,
        label="database",
    )
    prefix = f"backupsheep-e2e/{run_id}/"
    for row in (website_object, database_object):
        if row["object_key"] != f"{prefix}{row['backup_uuid']}.zip":
            raise UpCloudManifestExportError("An object key escaped the exact UpCloud run prefix.")

    volume_backup = volume_restore.backup
    server_backup = server_restore.backup
    _require_complete(volume_backup, "volume backup")
    _require_complete(server_backup, "server backup")
    if volume_restore.node_id == server_restore.node_id:
        raise UpCloudManifestExportError("Volume and server restores reuse one node.")
    if int(volume_restore.node.type) != 2 or int(server_restore.node.type) != 1:
        raise UpCloudManifestExportError("Cloud restore node types are inconsistent.")
    volume_identity = dict((volume_restore.params or {}).get("_bs_upcloud_restore") or {})
    server_identity = dict((server_restore.params or {}).get("_bs_upcloud_restore") or {})
    required_server = (
        "storage_marker",
        "server_marker",
        "hostname",
        "candidate_storage_id",
    )
    if any(not server_identity.get(key) for key in required_server):
        raise UpCloudManifestExportError("Server restore evidence is incomplete.")
    restore_storage_id = str(
        server_identity.get("candidate_storage_id")
        or server_identity.get("restore_storage_id")
        or ""
    )
    restore_server_id = str(server_restore.resource_id or "")
    volume_restore_id_value = str(volume_restore.resource_id or "")
    for value, label in (
        (str(volume_backup.unique_id or ""), "volume backup provider ID"),
        (volume_restore_id_value, "volume restore provider ID"),
        (str(server_backup.unique_id or ""), "server backup provider ID"),
        (restore_storage_id, "server restore storage ID"),
        (restore_server_id, "server restore server ID"),
    ):
        if not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            value,
        ):
            raise UpCloudManifestExportError(f"{label} is missing or malformed.")

    expected_restore_path = _durable_website_restore_target(
        website_restore,
        backup=website_backup,
        run_id=run_id,
    )
    restore_database = _durable_database_restore_target(
        database_restore,
        backup=database_backup,
    )

    return {
        "compute": {
            "schema": 1,
            "run_id": run_id,
            "volume": {
                "node_id": int(volume_restore.node_id),
                "backup_id": int(volume_backup.pk),
                "restore_id": int(volume_restore.pk),
                "source_resource_id": _upcloud_source_id(volume_restore, "volume restore"),
                "backup_resource_id": str(volume_backup.unique_id),
                "backup_marker": str(volume_backup.uuid_str),
                "restore_resource_id": volume_restore_id_value,
                "restore_marker": str(volume_restore.restore_marker),
            },
            "server": {
                "node_id": int(server_restore.node_id),
                "backup_id": int(server_backup.pk),
                "restore_id": int(server_restore.pk),
                "source_resource_id": _upcloud_source_id(server_restore, "server restore"),
                "backup_resource_id": str(server_backup.unique_id),
                "backup_marker": str(server_backup.uuid_str),
                "restore_storage_id": restore_storage_id,
                "restore_storage_marker": str(server_identity["storage_marker"]),
                "restore_server_id": restore_server_id,
                "restore_server_marker": str(server_identity["server_marker"]),
                "restore_hostname": str(server_identity["hostname"]),
            },
        },
        "workload": {
            "schema": 1,
            "run_id": run_id,
            "website": {
                "node_id": int(website_backup.website.node_id),
                "backup_id": int(website_backup.pk),
                "restore_id": int(website_restore.pk),
                "restore_path": expected_restore_path,
            },
            "postgresql": {
                "node_id": int(database_backup.database.node_id),
                "backup_id": int(database_backup.pk),
                "restore_id": int(database_restore.pk),
                "restore_database": restore_database,
            },
        },
        "object": {
            "schema": 1,
            "run_id": run_id,
            "objects": [website_object, database_object],
        },
    }


def _json_bytes(payload: dict) -> bytes:
    try:
        return (
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise UpCloudManifestExportError(
            "A manifest generation payload is not serializable."
        ) from error


def _artifact_binding(row: dict) -> dict:
    """Return the exact non-secret artifact identity covered by a digest."""

    if not isinstance(row, dict):
        raise UpCloudManifestExportError("An artifact row is malformed.")
    try:
        artifact_id = int(row["artifact_id"])
        byte_count = int(row["byte_count"])
    except (KeyError, TypeError, ValueError):
        raise UpCloudManifestExportError("An artifact row identity is malformed.") from None
    checksum = str(row.get("sha256") or "").casefold()
    etag = str(row.get("etag") or "")
    version_id = str(row.get("version_id") or "")
    if (
        artifact_id < 1
        or byte_count < 1
        or not SHA256_RE.fullmatch(checksum)
        or not etag
        or not version_id
        or version_id == "null"
    ):
        raise UpCloudManifestExportError("An artifact row identity is incomplete.")
    identity = {
        "artifact_id": artifact_id,
        "byte_count": byte_count,
        "sha256": checksum,
        "etag": etag,
        "version_id": version_id,
    }
    return {
        **identity,
        "binding_sha256": hashlib.sha256(_json_bytes(identity)).hexdigest(),
    }


def _generation_rows(payloads: dict) -> tuple[int, dict, dict]:
    """Derive the marker's storage, row, and artifact bindings from payloads."""

    compute = payloads.get("compute") if isinstance(payloads, dict) else None
    workload = payloads.get("workload") if isinstance(payloads, dict) else None
    object_manifest = payloads.get("object") if isinstance(payloads, dict) else None
    if not all(isinstance(value, dict) for value in (compute, workload, object_manifest)):
        raise UpCloudManifestExportError("A complete UpCloud manifest set is required.")
    volume = compute.get("volume")
    server = compute.get("server")
    website = workload.get("website")
    database = workload.get("postgresql")
    objects = object_manifest.get("objects")
    if (
        not all(isinstance(value, dict) for value in (volume, server, website, database))
        or not isinstance(objects, list)
        or len(objects) != 2
        or any(not isinstance(row, dict) for row in objects)
    ):
        raise UpCloudManifestExportError("Manifest row bindings are incomplete.")
    object_by_kind = {str(row.get("kind") or ""): row for row in objects}
    if set(object_by_kind) != {"website", "database"}:
        raise UpCloudManifestExportError("Manifest artifact kinds are ambiguous.")
    website_object = object_by_kind["website"]
    database_object = object_by_kind["database"]
    storage_ids = {
        _positive(website_object.get("storage_id"), "website storage_id"),
        _positive(database_object.get("storage_id"), "database storage_id"),
    }
    if len(storage_ids) != 1:
        raise UpCloudManifestExportError("Manifest storage bindings are inconsistent.")
    rows = {
        "volume_node_id": _positive(volume.get("node_id"), "volume node_id"),
        "volume_backup_id": _positive(volume.get("backup_id"), "volume backup_id"),
        "volume_restore_id": _positive(volume.get("restore_id"), "volume restore_id"),
        "server_node_id": _positive(server.get("node_id"), "server node_id"),
        "server_backup_id": _positive(server.get("backup_id"), "server backup_id"),
        "server_restore_id": _positive(server.get("restore_id"), "server restore_id"),
        "website_node_id": _positive(website.get("node_id"), "website node_id"),
        "website_backup_id": _positive(website.get("backup_id"), "website backup_id"),
        "website_restore_id": _positive(website.get("restore_id"), "website restore_id"),
        "database_node_id": _positive(database.get("node_id"), "database node_id"),
        "database_backup_id": _positive(database.get("backup_id"), "database backup_id"),
        "database_restore_id": _positive(database.get("restore_id"), "database restore_id"),
        "website_storage_point_id": _positive(
            website_object.get("storage_point_id"), "website storage_point_id"
        ),
        "database_storage_point_id": _positive(
            database_object.get("storage_point_id"), "database storage_point_id"
        ),
        "website_artifact_id": _positive(
            website_object.get("artifact_id"), "website artifact_id"
        ),
        "database_artifact_id": _positive(
            database_object.get("artifact_id"), "database artifact_id"
        ),
    }
    bindings = {
        "website": _artifact_binding(website_object),
        "database": _artifact_binding(database_object),
    }
    return next(iter(storage_ids)), rows, bindings


def _write_exclusive_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise UpCloudManifestExportError(
            "A manifest generation file already exists."
        ) from None
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            descriptor = -1
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_exclusive(source: Path, destination: Path) -> None:
    """Atomically publish a directory without replacing any destination."""

    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    result = -1
    if sys.platform.startswith("linux"):
        renameat2 = getattr(library, "renameat2", None)
        if renameat2 is None:
            raise UpCloudManifestExportError(
                "Exclusive atomic directory publication is unavailable."
            )
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,
            source_bytes,
            -100,
            destination_bytes,
            1,
        )
    elif sys.platform == "darwin":
        renamex_np = getattr(library, "renamex_np", None)
        if renamex_np is None:
            raise UpCloudManifestExportError(
                "Exclusive atomic directory publication is unavailable."
            )
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = renamex_np(source_bytes, destination_bytes, 0x00000004)
    else:
        raise UpCloudManifestExportError(
            "Exclusive atomic directory publication is unavailable."
        )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise UpCloudManifestExportError(
            "Manifest generation destination already exists."
        )
    raise UpCloudManifestExportError(
        "The manifest generation could not be published atomically."
    )


def _safe_generation_destination(value) -> Path:
    requested = Path(value).expanduser()
    if requested.name in {"", ".", ".."}:
        raise UpCloudManifestExportError(
            "Manifest output must name a new generation directory."
        )
    if requested.exists() or requested.is_symlink():
        raise UpCloudManifestExportError(
            "Manifest generation destination already exists."
        )
    parent = requested.parent
    if parent.is_symlink() or not parent.is_dir():
        raise UpCloudManifestExportError(
            "Manifest generation parent must be an existing real directory."
        )
    try:
        parent = parent.resolve(strict=True)
    except OSError as error:
        raise UpCloudManifestExportError(
            "Manifest generation parent is unavailable."
        ) from error
    destination = parent / requested.name
    if "_docs" in destination.parts:
        raise UpCloudManifestExportError("Manifest output must not be inside _docs.")
    try:
        destination.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise UpCloudManifestExportError(
            "Manifest output must be outside the worktree."
        )
    if destination.exists() or destination.is_symlink():
        raise UpCloudManifestExportError(
            "Manifest generation destination already exists."
        )
    return destination


def export_upcloud_manifests(*, output_dir, **row_ids):
    destination = _safe_generation_destination(output_dir)
    payloads = collect_upcloud_manifest_payloads(**row_ids)
    if set(payloads) != set(MANIFEST_FILENAMES):
        raise UpCloudManifestExportError(
            "A generation requires exactly compute, workload, and object manifests."
        )
    run_id = str(row_ids.get("run_id") or "")
    if not SAFE_RUN_ID.fullmatch(run_id):
        raise UpCloudManifestExportError("The manifest generation run ID is unsafe.")

    serialized = {}
    for kind in MANIFEST_FILENAMES:
        payload = payloads[kind]
        if (
            not isinstance(payload, dict)
            or type(payload.get("schema")) is not int
            or payload.get("schema") != 1
            or payload.get("run_id") != run_id
        ):
            raise UpCloudManifestExportError(
                "A manifest payload is outside the requested generation."
            )
        serialized[kind] = _json_bytes(payload)
    marker = {
        "schema": 1,
        "kind": "upcloud_manifest_generation_ownership",
        "provider": "upcloud",
        "integration_code": "upcloud",
        "run_id": run_id,
        "disposition": "EXCLUSIVE_COMPLETE_GENERATION",
        "manifests": {
            kind: {
                "filename": MANIFEST_FILENAMES[kind],
                "sha256": hashlib.sha256(serialized[kind]).hexdigest(),
                "byte_count": len(serialized[kind]),
            }
            for kind in MANIFEST_FILENAMES
        },
    }
    storage_id, rows, artifact_bindings = _generation_rows(payloads)
    marker["storage_id"] = storage_id
    marker["rows"] = rows
    marker["artifact_bindings"] = artifact_bindings
    marker_bytes = _json_bytes(marker)

    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.upcloud-staging-",
            dir=destination.parent,
        )
    )
    os.chmod(staging, 0o700)
    published = False
    try:
        for kind, filename in MANIFEST_FILENAMES.items():
            _write_exclusive_file(staging / filename, serialized[kind])
        _write_exclusive_file(staging / GENERATION_MARKER, marker_bytes)
        _fsync_directory(staging)
        _rename_directory_exclusive(staging, destination)
        published = True
        _fsync_directory(destination.parent)
    finally:
        if not published and staging.exists():
            shutil.rmtree(staging)

    paths = {
        kind: str(destination / filename)
        for kind, filename in MANIFEST_FILENAMES.items()
    }
    return {
        "status": "exported",
        "generation_dir": str(destination),
        "generation_marker": str(destination / GENERATION_MARKER),
        "files": paths,
    }
