"""Durable HTTP request boundary for Vultr managed-database restores."""

from __future__ import annotations

import hashlib
import hmac
import json
from functools import partial

from django.db import IntegrityError, transaction

from apps.console.backup.models import CoreVultrDatabaseRestore


class VultrDatabaseRestoreRequestConflict(Exception):
    """The caller reused an idempotency key for a different restore body."""


def _legacy_request_fingerprint(restore):
    payload = {
        "node_id": restore.backup.vultr_database.node_id,
        "backup_id": restore.backup_id,
        "name": restore.name,
        "params": restore.params or {},
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def create_or_replay_vultr_database_restore(
    *,
    node,
    backup,
    name,
    params,
    correlation_id,
    request_fingerprint,
    request_metadata,
):
    """Create one durable restore row and dispatch one stable Celery task.

    The database uniqueness constraint arbitrates concurrent HTTP deliveries.
    The task identifier is persisted in the same transaction as the request,
    so a broker acknowledgement loss is recovered by the periodic restore
    sweep without accepting another provider fork request.
    """

    from apps._tasks.integration.vultr_database import restore_vultr_database

    created = False
    dispatch_required = False
    with transaction.atomic():
        restore = (
            CoreVultrDatabaseRestore.objects.select_for_update()
            .select_related("backup__vultr_database__node")
            .filter(correlation_id=correlation_id)
            .first()
        )
        if restore is None:
            try:
                with transaction.atomic():
                    restore = CoreVultrDatabaseRestore.objects.create(
                        backup=backup,
                        correlation_id=correlation_id,
                        name=name,
                        params=params,
                        execution_metadata=request_metadata,
                    )
                created = True
            except IntegrityError:
                restore = (
                    CoreVultrDatabaseRestore.objects.select_for_update()
                    .select_related("backup__vultr_database__node")
                    .get(correlation_id=correlation_id)
                )

        stored_metadata = dict(restore.execution_metadata or {})
        stored_request = dict(stored_metadata.get("api_request") or {})
        stored_fingerprint = stored_request.get("fingerprint")
        if not created and not stored_fingerprint:
            stored_fingerprint = _legacy_request_fingerprint(restore)
        if (
            restore.backup_id != backup.id
            or restore.backup.vultr_database.node_id != node.id
            or not hmac.compare_digest(
                str(stored_fingerprint or ""), request_fingerprint
            )
        ):
            raise VultrDatabaseRestoreRequestConflict

        task_id = restore.celery_task_id or (
            f"vultr-db-restore-{restore.id}-{correlation_id.hex}"
        )
        if not restore.celery_task_id:
            restore.celery_task_id = task_id
            restore.save(update_fields=["celery_task_id", "modified"])
            dispatch_required = True
        if created or dispatch_required:
            transaction.on_commit(
                partial(
                    restore_vultr_database.apply_async,
                    task_id=task_id,
                    args=[restore.id],
                )
            )
    return restore, created
