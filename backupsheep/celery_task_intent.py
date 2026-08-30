"""Resolve signed Celery messages to durable, task-specific intent records.

The signature proves which runtime lane published a message.  It does not prove that
the lane was entitled to create a new backup, restore, or deletion.  These resolvers
bind high-impact messages to pre-existing database rows or to bounded state sweeps;
the returned identity is signed by the publisher and recomputed by the consumer.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Callable


class TaskIntentError(RuntimeError):
    """A task message has no matching durable business intent."""


def notification_fanout_task_id(log_id: int, data: Mapping[str, Any]) -> str:
    """Derive the stable message id without placing notification data on RabbitMQ."""

    try:
        encoded = json.dumps(
            dict(data), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise TaskIntentError("notification request is not canonical JSON") from error
    digest = hashlib.sha256(encoded).hexdigest()
    return uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"backupsheep:notification-fanout:{int(log_id)}:{digest}",
    ).hex


def _arguments(args: Any, kwargs: Any) -> tuple[list[Any], dict[str, Any]]:
    if not isinstance(args, (list, tuple)) or not isinstance(kwargs, Mapping):
        raise TaskIntentError("task arguments are malformed")
    return list(args), dict(kwargs)


def _argument(
    args: Sequence[Any], kwargs: Mapping[str, Any], index: int, name: str
) -> Any:
    positional = args[index] if len(args) > index else None
    keyword = kwargs.get(name)
    if positional is not None and keyword is not None and positional != keyword:
        raise TaskIntentError(f"task argument {name} is ambiguous")
    return keyword if keyword is not None else positional


def _positive_id(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise TaskIntentError(f"{label} is invalid")
    try:
        canonical = int(value)
    except (TypeError, ValueError) as error:
        raise TaskIntentError(f"{label} is invalid") from error
    if canonical <= 0 or str(canonical) != str(value):
        raise TaskIntentError(f"{label} is invalid")
    return canonical


def _empty_sweep(
    task_name: str,
    _task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    if args or kwargs:
        raise TaskIntentError(f"state sweep {task_name} does not accept arguments")
    return {"kind": "bounded-state-sweep", "task": task_name}


def _backup_message_payload(
    args: Sequence[Any], kwargs: Mapping[str, Any]
) -> dict[str, Any]:
    names = ("node_id", "schedule_id", "storage_ids", "notes", "resume")
    if len(args) > len(names) or set(kwargs) - set(names):
        raise TaskIntentError("backup task arguments exceed the durable request")
    node_id = _positive_id(_argument(args, kwargs, 0, "node_id"), "backup node id")
    schedule_value = _argument(args, kwargs, 1, "schedule_id")
    schedule_id = (
        _positive_id(schedule_value, "backup schedule id")
        if schedule_value is not None
        else None
    )
    storage_value = _argument(args, kwargs, 2, "storage_ids")
    if storage_value is None:
        storage_ids = []
    elif isinstance(storage_value, (list, tuple)) and not isinstance(
        storage_value, (str, bytes)
    ):
        storage_ids = [
            _positive_id(value, "backup storage id") for value in storage_value
        ]
    else:
        raise TaskIntentError("backup storage ids are malformed")
    if storage_ids != sorted(set(storage_ids)):
        raise TaskIntentError("backup storage ids are not canonical")
    notes = _argument(args, kwargs, 3, "notes")
    if notes is not None and (
        not isinstance(notes, str) or len(notes) > 10_000
    ):
        raise TaskIntentError("backup notes are malformed")
    resume = _argument(args, kwargs, 4, "resume")
    if not isinstance(resume, bool):
        raise TaskIntentError("backup resume flag is malformed")
    return {
        "node_id": node_id,
        "schedule_id": schedule_id,
        "storage_ids": storage_ids,
        "notes": notes,
        "resume": resume,
    }


def _json_digest(value: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(
            dict(value), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise TaskIntentError("durable intent is not canonical JSON") from error
    return hashlib.sha256(encoded).hexdigest()


def _backup_request(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    from apps.console.backup.models import CoreBackupRequest

    message_payload = _backup_message_payload(args, kwargs)
    node_id = message_payload["node_id"]
    request = CoreBackupRequest.objects.filter(
        task_id=task_id,
        task_name=task_name,
        node_id=node_id,
        status__in=(
            CoreBackupRequest.Status.PENDING,
            CoreBackupRequest.Status.DISPATCHED,
            CoreBackupRequest.Status.CLAIMED,
        ),
    ).first()
    if request is not None:
        durable_payload = dict(request.payload or {})
        if durable_payload != message_payload:
            raise TaskIntentError("backup message differs from its durable request")
        return {
            "kind": "backup-request",
            "id": request.pk,
            "correlation_id": str(request.correlation_id),
            "task_id": request.task_id,
            "task": request.task_name,
            "node_id": request.node_id,
            "payload_sha256": _json_digest(durable_payload),
        }

    # Generation-2 upgrades can have an active pre-outbox backup. Its immutable
    # Celery id and concrete backup row are the recovery intent.
    from apps._tasks.helper.tasks import (
        _backup_recovery_kwargs,
        _recovery_backup_models,
    )

    cloud_models, local_models = _recovery_backup_models()
    for model in cloud_models + local_models:
        backup = model.objects.filter(celery_task_id=task_id).first()
        if backup is None or backup.node_id != node_id:
            continue
        if backup.node.backup_task_name() != task_name:
            continue
        durable_payload = _backup_message_payload(
            (), _backup_recovery_kwargs(backup, backup.node)
        )
        if durable_payload != message_payload:
            raise TaskIntentError("backup recovery message differs from its durable row")
        return {
            "kind": "existing-backup",
            "model": backup._meta.label_lower,
            "id": backup.pk,
            "task_id": task_id,
            "node_id": node_id,
            "payload_sha256": _json_digest(durable_payload),
        }
    raise TaskIntentError("backup task has no durable request or recovery row")


def _scheduled_backup(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    from apps.console.node.models import CoreSchedule

    schedule_id = _positive_id(
        _argument(args, kwargs, 0, "schedule_id"), "schedule id"
    )
    schedule = CoreSchedule.objects.filter(pk=schedule_id).first()
    if schedule is None:
        raise TaskIntentError("scheduled backup has no durable schedule")
    return {
        "kind": "scheduled-backup",
        "task": task_name,
        "task_id": task_id,
        "schedule_id": schedule.pk,
        "node_id": schedule.node_id,
    }


def _restore_row(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    publisher: str,
    *,
    model_name: str,
) -> dict[str, Any]:
    from apps.console.backup import models as backup_models

    model = getattr(backup_models, model_name)
    if model_name in {"CoreWebsiteRestore", "CoreDatabaseRestore"}:
        restore_id = _positive_id(
            _argument(args, kwargs, 2, "restore_id"), "restore id"
        )
        node_id = _positive_id(_argument(args, kwargs, 0, "node_id"), "node id")
        backup_id = _positive_id(
            _argument(args, kwargs, 1, "backup_id"), "backup id"
        )
        restore = model.objects.select_related("backup__node").filter(
            pk=restore_id,
            backup_id=backup_id,
            backup__node_id=node_id,
        ).first()
    elif model_name == "CoreCloudRestore":
        restore_id = _positive_id(
            _argument(args, kwargs, 1 if task_name == "poll_cloud_restore" else 2, "restore_id"),
            "restore id",
        )
        node_id = _positive_id(_argument(args, kwargs, 0, "node_id"), "node id")
        restore = model.objects.filter(pk=restore_id, node_id=node_id).first()
        if restore is not None and task_name == "restore_cloud_backup":
            backup_id = _positive_id(
                _argument(args, kwargs, 1, "backup_id"), "backup id"
            )
            if restore.backup_id != backup_id:
                restore = None
    else:
        restore_id = _positive_id(
            _argument(args, kwargs, 0, "restore_id"), "restore id"
        )
        restore = model.objects.filter(pk=restore_id).first()

    if restore is None:
        raise TaskIntentError("restore task does not match a durable restore row")
    terminal = {
        restore.Status.COMPLETE,
        restore.Status.FAILED,
        getattr(restore.Status, "CANCELLED", object()),
    }
    if restore.status in terminal:
        raise TaskIntentError("restore intent is already terminal")
    stored_task_id = str(restore.celery_task_id or "")
    metadata = (
        dict(restore.execution_metadata or {})
        if isinstance(restore.execution_metadata, dict)
        else {}
    )
    manual_task_id = str(metadata.get("manual_resume_task_id") or "")
    if publisher == "app" and task_id not in {stored_task_id, manual_task_id}:
        raise TaskIntentError("application restore task id is not durably reserved")
    return {
        "kind": "restore",
        "model": restore._meta.label_lower,
        "id": restore.pk,
        "correlation_id": str(restore.correlation_id),
        "authorized_task_id": task_id,
    }


def _website_restore(*values) -> dict[str, Any]:
    return _restore_row(*values, model_name="CoreWebsiteRestore")


def _database_restore(*values) -> dict[str, Any]:
    return _restore_row(*values, model_name="CoreDatabaseRestore")


def _cloud_restore(*values) -> dict[str, Any]:
    return _restore_row(*values, model_name="CoreCloudRestore")


def _vultr_database_restore(*values) -> dict[str, Any]:
    return _restore_row(*values, model_name="CoreVultrDatabaseRestore")


def _cloud_backup(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    if task_name == "poll_vultr_database_backup":
        from apps.console.backup.models import CoreVultrDatabaseBackup

        backup_id = _positive_id(
            _argument(args, kwargs, 0, "backup_id"), "backup id"
        )
        backup = CoreVultrDatabaseBackup.objects.filter(pk=backup_id).first()
    else:
        from apps.console.node.models import CoreNode

        node_id = _positive_id(_argument(args, kwargs, 0, "node_id"), "node id")
        backup_id = _positive_id(
            _argument(args, kwargs, 1, "backup_id"), "backup id"
        )
        node = CoreNode.objects.filter(pk=node_id).first()
        try:
            backup = node.get_cloud_backup(backup_id) if node is not None else None
        except Exception as error:
            raise TaskIntentError("cloud backup identity is invalid") from error
    if backup is None:
        raise TaskIntentError("cloud poll has no durable backup")
    return {
        "kind": "cloud-backup",
        "model": backup._meta.label_lower,
        "id": backup.pk,
        "reserved_task_id": str(backup.celery_task_id or ""),
        "message_task_id": task_id,
    }


def _local_backup(task_name: str, args: Sequence[Any], kwargs: Mapping[str, Any]):
    from apps._tasks.integration.storage.tasks import _BACKUP_MODELS
    from apps.console.node.models import CoreNode

    node_id = _positive_id(_argument(args, kwargs, 0, "node_id"), "node id")
    backup_id = _positive_id(_argument(args, kwargs, 1, "backup_id"), "backup id")
    node = CoreNode.objects.filter(pk=node_id).first()
    if node is None:
        raise TaskIntentError(f"{task_name} has no durable node")
    model_key = node._local_backup_model_key()
    model = _BACKUP_MODELS.get(model_key)
    backup = (
        model.objects.filter(pk=backup_id, node_id=node_id).first()
        if model is not None
        else None
    )
    if backup is None:
        raise TaskIntentError(f"{task_name} does not resolve one local backup")
    source_lane = "database" if model_key == "database" else "files"
    return node, backup, model_key, source_lane


def _backup_destination(
    _task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    publisher: str,
) -> dict[str, Any]:
    """Bind storage validation to one immutable local-backup request phase."""

    from apps._tasks.integration.storage.tasks import _BACKUP_MODELS
    from apps.console.utils.models import UtilBackup

    model_key = str(_argument(args, kwargs, 0, "model_key") or "")
    backup_id = _positive_id(
        _argument(args, kwargs, 1, "backup_id"), "backup id"
    )
    if len(args) > 2 or set(kwargs) - {"model_key", "backup_id"}:
        raise TaskIntentError(
            "destination validation accepts only a model key and backup id"
        )
    expected_source_lane = {
        "database": "database",
        "website": "files",
        "basecamp": "files",
    }.get(model_key)
    if expected_source_lane is None:
        raise TaskIntentError("destination validation has an invalid source model")
    if publisher not in {expected_source_lane, "storage"}:
        raise TaskIntentError(
            "destination validation publisher does not own the source model"
        )
    model = _BACKUP_MODELS.get(model_key)
    backup = (
        model.objects.select_related("node").filter(pk=backup_id).first()
        if model is not None
        else None
    )
    if backup is None or backup.status not in UtilBackup.ACTIVE_STATUSES:
        raise TaskIntentError(
            "destination validation has no active durable backup"
        )
    source_task_id = str(backup.celery_task_id or "")
    if not source_task_id:
        raise TaskIntentError("destination validation has no source task id")
    phase_task_id = backup.node.local_destination_preparation_task_id(backup)
    if task_id != phase_task_id:
        raise TaskIntentError("destination validation task id is not reserved")
    return {
        "kind": "local-backup-destination",
        "model_key": model_key,
        "backup_model": backup._meta.label_lower,
        "backup_id": backup.pk,
        "node_id": backup.node_id,
        "source_task_id": source_task_id,
        "request_digest": backup.node._destination_request_digest(backup),
        "phase_task_id": phase_task_id,
    }


def _storage_upload(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    publisher: str,
) -> dict[str, Any]:
    node, backup, model_key, source_lane = _local_backup(task_name, args, kwargs)
    if publisher not in {source_lane, "storage"}:
        raise TaskIntentError("storage upload publisher does not own the source model")
    stored_id = _positive_id(
        _argument(args, kwargs, 2, "stored_backup_id"), "storage point id"
    )
    relations = (
        "stored_website_backups",
        "stored_database_backups",
        "stored_basecamp_backups",
    )
    points = []
    for relation in relations:
        manager = getattr(backup, relation, None)
        if manager is not None:
            point = manager.filter(pk=stored_id).first()
            if point is not None:
                points.append(point)
    if len(points) != 1:
        raise TaskIntentError("storage upload has no durable destination point")
    if points[0].pk not in node.authorized_local_destination_point_ids(backup):
        raise TaskIntentError("storage upload lacks a storage-owned authorization")
    return {
        "kind": "storage-upload",
        "model_key": model_key,
        "backup_model": backup._meta.label_lower,
        "backup_id": backup.pk,
        "point_model": points[0]._meta.label_lower,
        "point_id": points[0].pk,
        "node_id": node.pk,
        "task_id": task_id,
    }


def _backup_finalize(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    publisher: str,
) -> dict[str, Any]:
    node, backup, model_key, source_lane = _local_backup(task_name, args, kwargs)
    if publisher not in {source_lane, "storage"}:
        raise TaskIntentError("backup finalizer publisher does not own the source model")
    return {
        "kind": "backup-finalize",
        "model_key": model_key,
        "model": backup._meta.label_lower,
        "id": backup.pk,
        "node_id": node.pk,
        "task_id": task_id,
    }


def _backup_delete(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    from apps.console.utils.models import UtilBackup

    if task_name == "reconcile_oracle_backup_deletion":
        from apps.console.backup.models import CoreOracleBackup

        backup_id = _positive_id(
            _argument(args, kwargs, 0, "backup_id"), "backup id"
        )
        model_key = "oracle"
        backup = CoreOracleBackup.objects.filter(pk=backup_id).first()
    else:
        from apps._tasks.integration.storage.tasks import _BACKUP_MODELS

        model_key = str(_argument(args, kwargs, 0, "model_key") or "")
        backup_id = _positive_id(
            _argument(args, kwargs, 1, "backup_id"), "backup id"
        )
        model = _BACKUP_MODELS.get(model_key)
        backup = model.objects.filter(pk=backup_id).first() if model else None
    if backup is None or backup.status not in {
        UtilBackup.Status.DELETE_REQUESTED,
        UtilBackup.Status.DELETE_IN_PROGRESS,
    }:
        raise TaskIntentError("backup deletion lacks a requested durable row")
    return {
        "kind": "backup-delete",
        "model_key": model_key,
        "model": backup._meta.label_lower,
        "id": backup.pk,
        "task_id": task_id,
    }


def _storage_delete(
    _task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    from apps.console.storage.models import CoreStorage

    storage_id = _positive_id(
        _argument(args, kwargs, 0, "storage_id"), "storage id"
    )
    storage = CoreStorage.objects.filter(
        pk=storage_id, status=CoreStorage.Status.DELETE_REQUESTED
    ).first()
    if storage is None:
        raise TaskIntentError("storage deletion lacks a requested durable row")
    return {"kind": "storage-delete", "id": storage.pk, "task_id": task_id}


def _node_delete(
    _task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    from apps.console.node.models import CoreNode

    node_id = _positive_id(_argument(args, kwargs, 0, "node_id"), "node id")
    node = CoreNode.objects.filter(
        pk=node_id,
        status=CoreNode.Status.DELETE_REQUESTED,
        flag_delete_node=True,
    ).first()
    if node is None:
        raise TaskIntentError("node deletion lacks a requested durable row")
    return {"kind": "node-delete", "id": node.pk, "task_id": task_id}


def _node_cache_cleanup(
    _task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    from apps.console.node.models import CoreNode

    node_id = _positive_id(_argument(args, kwargs, 0, "node_id"), "node id")
    node = CoreNode.objects.filter(
        pk=node_id,
        type=CoreNode.Type.WEBSITE,
    ).first()
    if node is None:
        raise TaskIntentError("cache cleanup has no durable website-node scope")
    return {
        "kind": "node-cache-cleanup",
        "id": node.pk,
        "node_uuid": node.uuid_str,
        "task_id": task_id,
    }


def _storage_configuration(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    if task_name == "storage_aws_s3_sync_lifecycle":
        from apps.console.storage.models import CoreStorageAWSS3

        value = _argument(args, kwargs, 0, "storage_aws_s3_id")
        row = CoreStorageAWSS3.objects.filter(
            pk=_positive_id(value, "S3 storage id")
        ).first()
    else:
        from apps.console.storage.models import CoreStorage

        value = _argument(args, kwargs, 0, "storage_id")
        row = CoreStorage.objects.filter(
            pk=_positive_id(value, "storage id")
        ).first()
    if row is None:
        raise TaskIntentError("storage task has no durable configuration")
    return {
        "kind": "storage-configuration",
        "model": row._meta.label_lower,
        "id": row.pk,
        "task_id": task_id,
    }


def _source_ciphertext_cleanup(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    from apps._tasks.integration.storage.tasks import _BACKUP_MODELS

    if task_name == "cleanup_database_ciphertext_fence":
        model_key = "database"
        backup_value = _argument(args, kwargs, 0, "backup_id")
    else:
        model_key = str(_argument(args, kwargs, 0, "model_key") or "")
        backup_value = _argument(args, kwargs, 1, "backup_id")
        if model_key not in {"website", "basecamp"}:
            raise TaskIntentError("files cleanup has the wrong source model")
    backup_id = _positive_id(backup_value, "backup id")
    model = _BACKUP_MODELS.get(model_key)
    backup = model.objects.filter(pk=backup_id).first() if model else None
    if backup is None:
        raise TaskIntentError("ciphertext cleanup has no durable backup")
    return {
        "kind": "source-ciphertext-cleanup",
        "model": backup._meta.label_lower,
        "id": backup.pk,
        "backup_uuid": backup.uuid_str,
        "task_id": task_id,
    }


def _restore_ciphertext(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    publisher: str,
) -> dict[str, Any]:
    from apps._tasks.artifact_encryption import local_restore_phase_task_id
    from apps._tasks.integration.storage.tasks import _LOCAL_RESTORE_MODELS

    model_key = str(_argument(args, kwargs, 0, "model_key") or "")
    restore_id = _positive_id(
        _argument(args, kwargs, 1, "restore_id"), "restore id"
    )
    if len(args) > 2 or set(kwargs) - {"model_key", "restore_id"}:
        raise TaskIntentError(
            "restore ciphertext task accepts only its model key and restore id"
        )
    expected_source_lane = {"database": "database", "website": "files"}.get(
        model_key
    )
    if expected_source_lane is None or publisher not in {
        expected_source_lane,
        "storage",
    }:
        raise TaskIntentError(
            "restore ciphertext publisher does not own the source model"
        )
    model = _LOCAL_RESTORE_MODELS.get(model_key)
    restore = model.objects.filter(pk=restore_id).first() if model else None
    if restore is None or restore.storage_point_id is None:
        raise TaskIntentError("ciphertext handoff has no durable restore")
    try:
        phase = {
            "stage_local_restore_ciphertext": "stage",
            "cleanup_local_restore_ciphertext": "cleanup",
        }[task_name]
    except KeyError as error:  # pragma: no cover - manifest/resolver invariant
        raise TaskIntentError("restore ciphertext task is not reviewed") from error
    terminal = restore.status in {restore.Status.COMPLETE, restore.Status.FAILED}
    handoff = (
        dict(restore.execution_metadata or {}).get(
            "local_restore_ciphertext_handoff"
        )
        or {}
    )
    if phase == "stage" and terminal:
        raise TaskIntentError("terminal restore cannot stage ciphertext")
    if phase == "cleanup" and (
        not terminal
        or not isinstance(handoff, Mapping)
        or handoff.get("status")
        not in {"ready", "authenticated", "cleanup_complete"}
    ):
        raise TaskIntentError("restore ciphertext cleanup lacks a terminal witness")
    phase_task_id = local_restore_phase_task_id(restore, phase)
    if task_id != phase_task_id:
        raise TaskIntentError("restore ciphertext task id is not reserved")
    return {
        "kind": "restore-ciphertext",
        "phase": phase,
        "model": restore._meta.label_lower,
        "id": restore.pk,
        "correlation_id": str(restore.correlation_id),
        "backup_id": restore.backup_id,
        "storage_point_id": restore.storage_point_id,
        "restore_task_id": str(restore.celery_task_id or ""),
        "phase_task_id": phase_task_id,
    }


_LOCAL_ARTIFACT_PATTERN = re.compile(
    r"(?:restore_)?(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}"
    r"-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?:_[0-9a-f]{16})?\Z",
    re.IGNORECASE,
)


def _local_artifact_cleanup(
    _task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    publisher: str,
) -> dict[str, Any]:
    from apps._tasks.integration.storage.tasks import _BACKUP_MODELS

    raw_identity = str(_argument(args, kwargs, 0, "backup_uuid") or "")
    path_type = str(_argument(args, kwargs, 1, "path_type") or "")
    match = _LOCAL_ARTIFACT_PATTERN.fullmatch(raw_identity)
    if match is None or path_type not in {"dir", "zip", "both", "restore"}:
        raise TaskIntentError("local cleanup identity is malformed")
    backup_uuid = uuid.UUID(match.group("uuid"))
    matches = [
        row
        for model in _BACKUP_MODELS.values()
        if (row := model.objects.filter(uuid=backup_uuid).first()) is not None
    ]
    if len(matches) != 1:
        raise TaskIntentError("local cleanup has no unique durable backup")
    backup = matches[0]
    model_key = backup.node._local_backup_model_key()
    source_lane = "database" if model_key == "database" else "files"
    if model_key not in _BACKUP_MODELS or publisher not in {source_lane, "storage"}:
        raise TaskIntentError("local cleanup publisher does not own the source model")
    return {
        "kind": "local-artifact-cleanup",
        "model_key": model_key,
        "model": backup._meta.label_lower,
        "id": backup.pk,
        "backup_uuid": str(backup_uuid),
        "work_identity": raw_identity,
        "path_type": path_type,
        "task_id": task_id,
    }


def _multipart_cleanup(
    _task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    from apps._tasks.integration.storage.tasks import (
        _STORAGE_POINT_MODELS,
        has_owned_multipart_cleanup_candidate,
    )

    model_key = str(_argument(args, kwargs, 0, "model_key") or "")
    point_id = _positive_id(_argument(args, kwargs, 1, "point_id"), "point id")
    model = _STORAGE_POINT_MODELS.get(model_key)
    point = model.objects.filter(pk=point_id).first() if model else None
    if point is None or not has_owned_multipart_cleanup_candidate(point):
        raise TaskIntentError("multipart cleanup lacks a durable creation proof")
    return {
        "kind": "multipart-cleanup",
        "model": point._meta.label_lower,
        "id": point.pk,
        "task_id": task_id,
    }


def _lightsail_replication(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    publisher: str,
) -> dict[str, Any]:
    from apps.console.backup.replication_models import (
        CoreLightsailBucketReplication,
        CoreLightsailBucketReplicationRun,
    )

    replication_id = _positive_id(
        _argument(args, kwargs, 0, "replication_id"), "replication id"
    )
    replication = CoreLightsailBucketReplication.objects.filter(
        pk=replication_id
    ).first()
    if replication is None:
        raise TaskIntentError("bucket task has no durable replication")
    run_value = _argument(args, kwargs, 1, "run_id")
    run = None
    if run_value is not None:
        run = CoreLightsailBucketReplicationRun.objects.filter(
            pk=_positive_id(run_value, "replication run id"),
            replication_id=replication_id,
        ).first()
        if run is None:
            raise TaskIntentError("bucket task has no durable replication run")
        if publisher == "app" and str(run.celery_task_id or "") != task_id:
            raise TaskIntentError("bucket replication task id is not reserved")
    return {
        "kind": "lightsail-replication",
        "replication_id": replication.pk,
        "run_id": run.pk if run else None,
        "reserved_task_id": str(run.celery_task_id or "") if run else "",
    }


def _lightsail_restore(
    _task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    publisher: str,
) -> dict[str, Any]:
    from apps.console.backup.replication_models import CoreLightsailBucketRestoreRun

    replication_id = _positive_id(
        _argument(args, kwargs, 0, "replication_id"), "replication id"
    )
    restore_id = _positive_id(
        _argument(args, kwargs, 1, "restore_id"), "restore run id"
    )
    restore = CoreLightsailBucketRestoreRun.objects.filter(
        pk=restore_id, replication_id=replication_id
    ).first()
    if restore is None or restore.status in {
        restore.Status.COMPLETE,
        restore.Status.FAILED,
        restore.Status.CANCELLED,
    }:
        raise TaskIntentError("bucket restore has no active durable run")
    if publisher == "app" and str(restore.celery_task_id or "") != task_id:
        raise TaskIntentError("bucket restore task id is not reserved")
    return {
        "kind": "lightsail-restore",
        "id": restore.pk,
        "replication_id": restore.replication_id,
        "reserved_task_id": str(restore.celery_task_id or ""),
    }


def _managed_ssh_operation(
    task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    """Bind a managed-key network operation to its immutable database request."""

    from django.utils import timezone

    from apps.console.connection.managed_ssh import (
        ManagedSSHOperationError,
        operation_intent_material,
        validate_operation_intent,
    )
    from apps.console.connection.models import CoreConnection, CoreManagedSSHOperation

    expected = {
        "validate_managed_ssh_database_connection": ("database", "validate"),
        "validate_managed_ssh_files_connection": ("files", "validate"),
        "discover_managed_ssh_database_objects": ("database", "discover"),
        "discover_managed_ssh_files_objects": ("files", "discover"),
        "update_managed_ssh_database_metadata": ("database", "update_metadata"),
    }
    try:
        expected_lane, expected_operation = expected[task_name]
    except KeyError as error:  # pragma: no cover - manifest/resolver invariant
        raise TaskIntentError("managed SSH task is not reviewed") from error
    operation_id = _positive_id(
        _argument(args, kwargs, 0, "operation_id"), "managed SSH operation id"
    )
    if len(args) > 1 or set(kwargs) - {"operation_id"}:
        raise TaskIntentError("managed SSH task accepts only its durable operation id")
    operation = (
        CoreManagedSSHOperation.objects.select_related("connection__integration")
        .filter(pk=operation_id)
        .first()
    )
    if operation is None:
        raise TaskIntentError("managed SSH operation does not exist")
    if (
        str(operation.celery_task_id) != task_id
        or operation.status
        not in {
            CoreManagedSSHOperation.Status.PENDING,
            CoreManagedSSHOperation.Status.RUNNING,
        }
        or operation.expires_at <= timezone.now()
    ):
        raise TaskIntentError("managed SSH operation identity, state, or expiry drifted")
    expected_connection_status = (
        CoreConnection.Status.PENDING
        if expected_operation == "validate"
        else CoreConnection.Status.ACTIVE
    )
    if operation.connection.status != expected_connection_status:
        raise TaskIntentError("managed SSH connection is not in the required state")
    try:
        validate_operation_intent(
            operation,
            expected_lane=expected_lane,
            expected_operation=expected_operation,
        )
    except ManagedSSHOperationError as error:
        raise TaskIntentError(f"managed SSH durable intent is invalid: {error}") from error
    return {
        "kind": "managed-ssh-operation",
        "task": task_name,
        **operation_intent_material(operation),
    }

def _log_record(
    _task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    from apps.console.log.models import CoreLog

    if len(args) > 1 or set(kwargs) - {"log_reference"}:
        raise TaskIntentError("notification fanout accepts only its durable log id")
    log_id = _positive_id(
        _argument(args, kwargs, 0, "log_reference"), "log id"
    )
    log = CoreLog.objects.filter(pk=log_id).first()
    data = dict(log.data or {}) if log is not None and isinstance(log.data, dict) else {}
    if (
        log is None
        or data.get("sender_name") != "BackupSheep - Notification Bot"
        or data.get("notification_fanout_status") != "pending"
    ):
        raise TaskIntentError("log delivery has no durable log row")
    request = data.get("notification_request")
    if request is not None:
        reviewed = {
            "storage_validation_failed": "fail",
            "unable_to_start_backup": "fail",
            "error_during_backup": "fail",
            "unable_to_upload_backup": "fail",
            "backup_is_complete": "success",
            "restore_started": "fail",
            "restore_completed": "success",
            "restore_failed": "fail",
        }
        if (
            not isinstance(request, Mapping)
            or set(request) != {"version", "event", "template"}
            or request.get("version") != 1
            or reviewed.get(request.get("template")) != request.get("event")
        ):
            raise TaskIntentError("log delivery email request is not reviewed")
    expected_task_id = notification_fanout_task_id(log_id, data)
    if task_id != expected_task_id:
        raise TaskIntentError("notification fanout task id is not reserved")
    return {
        "kind": "notification-fanout",
        "id": log_id,
        "task_id": task_id,
    }


def _restricted_log_record_publication(
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    """Authorize source publication with only the granted CoreLog.id column.

    The deterministic task id commits to the full immutable request. The logs
    consumer recomputes that id from the row before task code runs; source lanes
    therefore never need SELECT on account_id or the JSON payload.
    """

    from apps.console.log.models import CoreLog

    if len(args) > 1 or set(kwargs) - {"log_reference"}:
        raise TaskIntentError("notification fanout accepts only its durable log id")
    log_id = _positive_id(
        _argument(args, kwargs, 0, "log_reference"), "log id"
    )
    try:
        canonical_task_id = uuid.UUID(str(task_id)).hex
    except (AttributeError, TypeError, ValueError) as error:
        raise TaskIntentError("notification fanout task id is malformed") from error
    if canonical_task_id != task_id or not CoreLog.objects.only("pk").filter(
        pk=log_id
    ).exists():
        raise TaskIntentError("notification fanout lacks a committed log row")
    return {
        "kind": "notification-fanout",
        "id": log_id,
        "task_id": task_id,
    }


def _notification_delivery(
    _task_name: str,
    task_id: str,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    _publisher: str,
) -> dict[str, Any]:
    from apps.console.notification.models import CoreNotificationDelivery

    if len(args) > 1 or set(kwargs) - {"delivery_id", "delivery_reference"}:
        raise TaskIntentError(
            "notification delivery accepts only its durable delivery id"
        )
    delivery_id = _positive_id(
        _argument(
            args,
            kwargs,
            0,
            "delivery_reference"
            if "delivery_reference" in kwargs
            else "delivery_id",
        ),
        "notification delivery id",
    )
    delivery = CoreNotificationDelivery.objects.select_related("log").filter(
        pk=delivery_id
    ).first()
    if delivery is None:
        raise TaskIntentError("notification task has no durable delivery")
    log_data = dict(delivery.log.data or {}) if isinstance(delivery.log.data, dict) else {}
    encoded = json.dumps(
        log_data, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "kind": "notification-delivery",
        "id": delivery_id,
        "log_id": delivery.log_id,
        "channel_type": delivery.channel_type,
        "channel_id": delivery.channel_id,
        "request_sha256": hashlib.sha256(encoded).hexdigest(),
        "task_id": task_id,
    }


INTENT_RESOLVERS: dict[str, Callable[..., dict[str, Any]]] = {
    "backup_request": _backup_request,
    "backup_destination": _backup_destination,
    "scheduled_backup": _scheduled_backup,
    "website_restore": _website_restore,
    "database_restore": _database_restore,
    "cloud_restore": _cloud_restore,
    "vultr_database_restore": _vultr_database_restore,
    "cloud_backup": _cloud_backup,
    "storage_upload": _storage_upload,
    "backup_finalize": _backup_finalize,
    "backup_delete": _backup_delete,
    "storage_delete": _storage_delete,
    "node_delete": _node_delete,
    "node_cache_cleanup": _node_cache_cleanup,
    "storage_configuration": _storage_configuration,
    "source_ciphertext_cleanup": _source_ciphertext_cleanup,
    "restore_ciphertext": _restore_ciphertext,
    "local_artifact_cleanup": _local_artifact_cleanup,
    "multipart_cleanup": _multipart_cleanup,
    "lightsail_replication": _lightsail_replication,
    "lightsail_restore": _lightsail_restore,
    "managed_ssh_operation": _managed_ssh_operation,
    "log_record": _log_record,
    "notification_delivery": _notification_delivery,
    "retention_sweep": _empty_sweep,
    "state_sweep": _empty_sweep,
}


def resolve_task_intent(
    *,
    task_name: str,
    task_id: str,
    args: Any,
    kwargs: Any,
    publisher: str,
    intent: str,
    phase: str = "consume",
) -> dict[str, Any]:
    positional, keyword = _arguments(args, kwargs)
    if phase not in {"publish", "consume"}:
        raise TaskIntentError("task intent resolution phase is invalid")
    if intent == "log_record" and phase == "publish" and publisher != "logs":
        return _restricted_log_record_publication(
            task_id, positional, keyword
        )
    try:
        resolver = INTENT_RESOLVERS[intent]
    except KeyError as error:
        raise TaskIntentError(f"task {task_name} has an unknown intent policy") from error
    return resolver(task_name, task_id, positional, keyword, publisher)
