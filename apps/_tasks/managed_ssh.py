"""Lane-specific execution for installation-managed SSH-key operations."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta

from celery import current_app
from django.conf import settings
from django.db import connection as database_connection, models, transaction
from django.utils import timezone

from apps.console.connection.managed_ssh import (
    ManagedSSHOperationError,
    acquire_managed_ssh_mutation_lock,
    dispatch_managed_ssh_operation,
    validate_operation_intent,
)
from apps.console.connection.reliability import classify_connection_error


def _canonical_json(value) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _digest(value) -> str:
    if not isinstance(value, str):
        value = _canonical_json(value)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bounded_integer(name, default, minimum, maximum):
    try:
        value = int(getattr(settings, name, default))
    except (TypeError, ValueError):
        value = default
    return min(max(value, minimum), maximum)


def _lease_seconds() -> int:
    return int(settings.MANAGED_SSH_OPERATION_LEASE_SECONDS)


def _bounded_result(payload) -> tuple[dict, str]:
    if not isinstance(payload, dict):
        raise ManagedSSHOperationError(
            "The managed SSH worker returned an invalid result."
        )
    encoded = _canonical_json(payload).encode("utf-8")
    maximum = _bounded_integer(
        "MANAGED_SSH_RESULT_MAX_BYTES",
        1024 * 1024,
        16 * 1024,
        4 * 1024 * 1024,
    )
    if len(encoded) > maximum:
        raise ManagedSSHOperationError(
            "The managed SSH result exceeded the safe response limit."
        )
    canonical_payload = json.loads(encoded)
    return canonical_payload, hashlib.sha256(encoded).hexdigest()


def _safe_failure(error, *, stage) -> dict:
    return classify_connection_error(error, stage=stage).as_dict()


def _operation_identity(operation_id):
    from apps.console.connection.models import CoreManagedSSHOperation

    return (
        CoreManagedSSHOperation.objects.filter(pk=operation_id)
        .values(
            "pk",
            "account_id",
            "connection_id",
            "host_key_approval_pk_snapshot",
        )
        .first()
    )


def _locked_context(operation_id, *, require_approval=True):
    """Lock account -> connection -> auth -> approval -> operation in one order."""

    from apps.console.account.models import CoreAccount
    from apps.console.connection.models import (
        CoreAuthDatabase,
        CoreAuthWebsite,
        CoreConnection,
        CoreManagedSSHOperation,
        CoreSSHHostKeyApproval,
    )

    acquire_managed_ssh_mutation_lock()

    identity = _operation_identity(operation_id)
    if identity is None:
        return None
    account = CoreAccount.objects.select_for_update().get(pk=identity["account_id"])
    connection = (
        CoreConnection.objects.select_for_update()
        .select_related("integration", "account")
        .get(pk=identity["connection_id"], account=account)
    )
    if connection.integration.code == "database":
        auth = CoreAuthDatabase.objects.select_for_update().get(
            connection=connection
        )
        connection._state.fields_cache["auth_database"] = auth
    elif connection.integration.code == "website":
        auth = CoreAuthWebsite.objects.select_for_update().get(connection=connection)
        connection._state.fields_cache["auth_website"] = auth
    else:
        raise ManagedSSHOperationError("The managed SSH source lane changed.")

    approval = (
        CoreSSHHostKeyApproval.objects.select_for_update()
        .filter(pk=identity["host_key_approval_pk_snapshot"], account=account)
        .first()
    )
    if require_approval and approval is None:
        raise ManagedSSHOperationError(
            "The managed SSH host-key approval was revoked."
        )
    operation = CoreManagedSSHOperation.objects.select_for_update().get(
        pk=operation_id,
        account=account,
        connection=connection,
    )
    operation._state.fields_cache["connection"] = connection
    auth._state.fields_cache["connection"] = connection
    return operation, connection, auth, approval


def _set_connection_validation_status_locked(operation, connection, status):
    from apps.console.connection.models import CoreManagedSSHOperation

    if operation.operation != CoreManagedSSHOperation.Operation.VALIDATE:
        return
    latest = (
        CoreManagedSSHOperation.objects.filter(
            connection=connection,
            operation=CoreManagedSSHOperation.Operation.VALIDATE,
        )
        .order_by("-created", "-pk")
        .only("pk", "connection_generation")
        .first()
    )
    if (
        latest is None
        or latest.pk != operation.pk
        or operation.connection_generation != connection.managed_ssh_generation
    ):
        return
    connection.status = status
    connection.save(update_fields=("status", "modified"))


def _terminal_failure_locked(operation, connection, error_payload, *, status="failed"):
    from apps.console.connection.models import CoreConnection

    completed_at = timezone.now()
    operation.status = status
    operation.lease_token = None
    operation.lease_expires_at = None
    operation.completed_at = completed_at
    operation.result_payload = {}
    operation.result_digest = ""
    operation.error_payload = error_payload
    operation.execution_witness_digest = _digest(
        {
            "intent_digest": operation.intent_digest,
            "status": status,
            "error": error_payload,
            "completed_at": completed_at.isoformat(),
        }
    )
    operation.save(
        update_fields=(
            "status",
            "lease_token",
            "lease_expires_at",
            "completed_at",
            "result_payload",
            "result_digest",
            "error_payload",
            "execution_witness_digest",
            "modified",
        )
    )
    _set_connection_validation_status_locked(
        operation, connection, CoreConnection.Status.SUSPENDED
    )


def _finalize_unclaimed_failure(operation_id, error, *, stage):
    from apps.console.connection.models import CoreManagedSSHOperation

    with transaction.atomic():
        context = _locked_context(operation_id, require_approval=False)
        if context is None:
            return
        operation, connection, _auth, _approval = context
        if operation.status not in (
            CoreManagedSSHOperation.Status.PENDING,
            CoreManagedSSHOperation.Status.RUNNING,
        ):
            return
        if (
            operation.status == CoreManagedSSHOperation.Status.RUNNING
            and operation.lease_expires_at
            and operation.lease_expires_at > timezone.now()
        ):
            return
        _terminal_failure_locked(
            operation,
            connection,
            _safe_failure(error, stage=stage),
        )


def _claim(operation_id: int, *, expected_lane: str, expected_operation: str):
    from apps.console.connection.models import CoreConnection, CoreManagedSSHOperation

    try:
        with transaction.atomic():
            context = _locked_context(operation_id)
            if context is None:
                return None
            operation, connection, _auth, _approval = context
            if operation.status in (
                CoreManagedSSHOperation.Status.COMPLETE,
                CoreManagedSSHOperation.Status.FAILED,
                CoreManagedSSHOperation.Status.EXPIRED,
            ):
                return None
            now = timezone.now()
            if operation.expires_at <= now:
                _terminal_failure_locked(
                    operation,
                    connection,
                    {
                        "code": "OPERATION_EXPIRED",
                        "detail": "The managed SSH request expired before execution.",
                        "stage": "worker_queue",
                        "retryable": True,
                        "remediation": "Retry the connection operation.",
                    },
                    status=CoreManagedSSHOperation.Status.EXPIRED,
                )
                return None
            if (
                operation.status == CoreManagedSSHOperation.Status.RUNNING
                and operation.lease_expires_at is not None
                and operation.lease_expires_at > now
            ):
                return None
            validate_operation_intent(
                operation,
                expected_lane=expected_lane,
                expected_operation=expected_operation,
            )
            if operation.operation == CoreManagedSSHOperation.Operation.VALIDATE:
                if connection.status != CoreConnection.Status.PENDING:
                    raise ManagedSSHOperationError(
                        "The connection is not awaiting managed SSH validation."
                    )
            elif connection.status != CoreConnection.Status.ACTIVE:
                raise ManagedSSHOperationError(
                    "The connection is not active for this managed SSH operation."
                )

            lease_token = uuid.uuid4()
            operation.status = CoreManagedSSHOperation.Status.RUNNING
            operation.lease_token = lease_token
            operation.lease_expires_at = now + timedelta(seconds=_lease_seconds())
            operation.attempts += 1
            if operation.claimed_at is None:
                operation.claimed_at = now
            operation.result_payload = {}
            operation.result_digest = ""
            operation.error_payload = {}
            operation.save(
                update_fields=(
                    "status",
                    "lease_token",
                    "lease_expires_at",
                    "attempts",
                    "claimed_at",
                    "result_payload",
                    "result_digest",
                    "error_payload",
                    "modified",
                )
            )
            return operation.pk, lease_token
    except Exception as error:
        _finalize_unclaimed_failure(
            operation_id, error, stage="managed_ssh_intent"
        )
        return None


def _assert_connection_state(operation, connection):
    from apps.console.connection.models import CoreConnection, CoreManagedSSHOperation

    if operation.operation == CoreManagedSSHOperation.Operation.VALIDATE:
        if connection.status != CoreConnection.Status.PENDING:
            raise ManagedSSHOperationError(
                "The connection is not awaiting managed SSH validation."
            )
    elif connection.status != CoreConnection.Status.ACTIVE:
        raise ManagedSSHOperationError(
            "The connection is not active for this managed SSH operation."
        )


def _snapshot_execution(operation_id, lease_token, *, expected_lane, operation_name):
    """Linearize authorization, then release every database lock before I/O."""

    from apps.console.connection.models import CoreManagedSSHOperation

    with transaction.atomic():
        context = _locked_context(operation_id)
        if context is None:
            return None
        operation, connection, auth, _approval = context
        if (
            operation.status != CoreManagedSSHOperation.Status.RUNNING
            or operation.lease_token != lease_token
        ):
            return None
        if (
            operation.lease_expires_at is None
            or operation.lease_expires_at <= timezone.now()
        ):
            _terminal_failure_locked(
                operation,
                connection,
                {
                    "code": "OPERATION_LEASE_EXPIRED",
                    "detail": "The managed SSH execution lease expired.",
                    "stage": "worker_execution",
                    "retryable": True,
                    "remediation": "Retry the connection operation.",
                },
                status=CoreManagedSSHOperation.Status.EXPIRED,
            )
            return None
        validate_operation_intent(
            operation,
            expected_lane=expected_lane,
            expected_operation=operation_name,
        )
        _assert_connection_state(operation, connection)
        auth._managed_ssh_host_key_witness = {
            "approval_id": operation.host_key_approval_pk_snapshot,
            "generation": operation.host_key_approval_generation,
            "fingerprint": operation.host_key_fingerprint,
            "negotiated_host_key_algorithm": (
                operation.host_key_negotiated_algorithm
            ),
        }
        auth._ssh_trust_lock_held = True
        auth._managed_ssh_public_key_fingerprint_witness = (
            operation.managed_public_key_fingerprint
        )
        return operation, auth


def _execute_snapshot(operation, auth, *, expected_lane, operation_name):
    if expected_lane == "database":
        if operation_name == "validate":
            auth.check_connection(check_errors=True)
            return {"valid": True}, None
        if operation_name == "discover":
            return {"eligible_objects": auth.get_eligible_objects()}, None
        if operation_name == "update_metadata":
            return None, auth.find_db_type_and_version()
        raise ManagedSSHOperationError("The managed SSH database task is invalid.")
    if expected_lane == "files":
        if operation_name == "validate":
            auth.check_connection(check_errors=True)
            return {"valid": True}, None
        if operation_name == "discover":
            requested_path = operation.requested_path or None
            path_tree = [
                {"name": "Root", "path": "/"},
                {"name": "User Home", "path": "."},
            ]
            if requested_path and requested_path != "/":
                for number, item in enumerate(requested_path.split("/")):
                    path_item = "/".join(
                        requested_path.split("/")[: number + 1]
                    )
                    if path_item not in {entry["path"] for entry in path_tree}:
                        path_tree.append({"name": item, "path": path_item})
            return {
                "eligible_objects": auth.get_eligible_objects(
                    path=requested_path
                ),
                "path_tree": path_tree,
            }, None
        raise ManagedSSHOperationError("The managed SSH files task is invalid.")
    raise ManagedSSHOperationError("The managed SSH source lane is invalid.")


def _apply_database_metadata_locked(auth, discovered_slug):
    if discovered_slug:
        for available_version in auth.DatabaseVersion.values:
            if available_version in discovered_slug:
                auth.version = available_version
                break
        for available_type, label in auth.DatabaseType.choices:
            if label.lower() in discovered_slug:
                auth.type = available_type
                break
        auth.save(update_fields=("type", "version", "modified"))
    return {"type": auth.get_type_display(), "version": auth.get_version_display()}


def _stage(operation_name):
    return (
        "object_discovery"
        if operation_name == "discover"
        else "metadata_discovery"
        if operation_name == "update_metadata"
        else "validation"
    )


def _execute_and_finalize(operation_id, lease_token, *, expected_lane, operation_name):
    from apps.console.connection.models import CoreConnection, CoreManagedSSHOperation

    try:
        snapshot = _snapshot_execution(
            operation_id,
            lease_token,
            expected_lane=expected_lane,
            operation_name=operation_name,
        )
        if snapshot is None:
            return
        snapshotted_operation, snapshotted_auth = snapshot
        payload, discovered_metadata = _execute_snapshot(
            snapshotted_operation,
            snapshotted_auth,
            expected_lane=expected_lane,
            operation_name=operation_name,
        )
        if payload is not None:
            payload, result_digest = _bounded_result(payload)

        with transaction.atomic():
            context = _locked_context(operation_id)
            if context is None:
                return
            operation, connection, auth, _approval = context
            if (
                operation.status != CoreManagedSSHOperation.Status.RUNNING
                or operation.lease_token != lease_token
            ):
                return
            if (
                operation.lease_expires_at is None
                or operation.lease_expires_at <= timezone.now()
            ):
                _terminal_failure_locked(
                    operation,
                    connection,
                    {
                        "code": "OPERATION_LEASE_EXPIRED",
                        "detail": "The managed SSH execution lease expired.",
                        "stage": "worker_execution",
                        "retryable": True,
                        "remediation": "Retry the connection operation.",
                    },
                    status=CoreManagedSSHOperation.Status.EXPIRED,
                )
                return
            validate_operation_intent(
                operation,
                expected_lane=expected_lane,
                expected_operation=operation_name,
            )
            _assert_connection_state(operation, connection)

            completed_at = timezone.now()
            if operation.expires_at <= completed_at:
                _terminal_failure_locked(
                    operation,
                    connection,
                    {
                        "code": "OPERATION_EXPIRED",
                        "detail": "The managed SSH request expired during execution.",
                        "stage": "worker_execution",
                        "retryable": True,
                        "remediation": "Retry the connection operation.",
                    },
                    status=CoreManagedSSHOperation.Status.EXPIRED,
                )
                return
            if operation_name == "update_metadata":
                payload = {
                    "database": _apply_database_metadata_locked(
                        auth, discovered_metadata
                    )
                }
                payload, result_digest = _bounded_result(payload)
            operation.status = CoreManagedSSHOperation.Status.COMPLETE
            operation.lease_token = None
            operation.lease_expires_at = None
            operation.completed_at = completed_at
            operation.result_payload = payload
            operation.result_digest = result_digest
            operation.error_payload = {}
            operation.execution_witness_digest = _digest(
                {
                    "intent_digest": operation.intent_digest,
                    "result_digest": result_digest,
                    "status": "complete",
                    "completed_at": completed_at.isoformat(),
                }
            )
            operation.save(
                update_fields=(
                    "status",
                    "lease_token",
                    "lease_expires_at",
                    "completed_at",
                    "result_payload",
                    "result_digest",
                    "error_payload",
                    "execution_witness_digest",
                    "modified",
                )
            )
            _set_connection_validation_status_locked(
                operation, connection, CoreConnection.Status.ACTIVE
            )
    except Exception as error:
        _finalize_running_failure(
            operation_id,
            lease_token,
            error,
            stage=_stage(operation_name),
        )


def _finalize_running_failure(operation_id, lease_token, error, *, stage):
    from apps.console.connection.models import CoreManagedSSHOperation

    with transaction.atomic():
        context = _locked_context(operation_id, require_approval=False)
        if context is None:
            return
        operation, connection, _auth, _approval = context
        if (
            operation.status != CoreManagedSSHOperation.Status.RUNNING
            or operation.lease_token != lease_token
        ):
            return
        _terminal_failure_locked(
            operation,
            connection,
            _safe_failure(error, stage=stage),
        )


def _run(operation_id: int, *, expected_lane: str, expected_operation: str):
    claim = _claim(
        operation_id,
        expected_lane=expected_lane,
        expected_operation=expected_operation,
    )
    if claim is None:
        return
    claimed_operation_id, lease_token = claim
    _execute_and_finalize(
        claimed_operation_id,
        lease_token,
        expected_lane=expected_lane,
        operation_name=expected_operation,
    )


def _maintain_lane(source_lane):
    from apps.console.connection.models import CoreManagedSSHOperation

    now = timezone.now()
    batch_size = _bounded_integer("MANAGED_SSH_MAINTENANCE_BATCH_SIZE", 100, 1, 500)
    due_ids = list(
        CoreManagedSSHOperation.objects.filter(
            source_lane=source_lane,
            status__in=(
                CoreManagedSSHOperation.Status.PENDING,
                CoreManagedSSHOperation.Status.RUNNING,
            ),
        )
        .filter(
            models.Q(expires_at__lte=now)
            | models.Q(status=CoreManagedSSHOperation.Status.PENDING)
            | models.Q(lease_expires_at__lte=now)
        )
        .order_by("created", "pk")
        .values_list("pk", flat=True)[:batch_size]
    )
    for operation_id in due_ids:
        dispatch_managed_ssh_operation(operation_id)

    retention_days = _bounded_integer(
        "MANAGED_SSH_OPERATION_RETENTION_DAYS", 30, 7, 365
    )
    # Workers have no table DELETE. The SECURITY DEFINER routine authenticates
    # the session role's installation marker, derives its lane, clamps both
    # inputs again, and preserves the current-generation validation proof.
    with database_connection.cursor() as cursor:
        cursor.execute(
            "SELECT public.backupsheep_delete_managed_ssh_operation_retention(%s, %s)",
            (retention_days, batch_size),
        )
        cursor.fetchone()


@current_app.task(
    name="validate_managed_ssh_database_connection",
    bind=True,
    ignore_result=True,
    soft_time_limit=settings.MANAGED_SSH_TASK_SOFT_TIME_LIMIT_SECONDS,
    time_limit=settings.MANAGED_SSH_TASK_TIME_LIMIT_SECONDS,
)
def validate_managed_ssh_database_connection(self, operation_id):
    return _run(operation_id, expected_lane="database", expected_operation="validate")


@current_app.task(
    name="validate_managed_ssh_files_connection",
    bind=True,
    ignore_result=True,
    soft_time_limit=settings.MANAGED_SSH_TASK_SOFT_TIME_LIMIT_SECONDS,
    time_limit=settings.MANAGED_SSH_TASK_TIME_LIMIT_SECONDS,
)
def validate_managed_ssh_files_connection(self, operation_id):
    return _run(operation_id, expected_lane="files", expected_operation="validate")


@current_app.task(
    name="discover_managed_ssh_database_objects",
    bind=True,
    ignore_result=True,
    soft_time_limit=settings.MANAGED_SSH_TASK_SOFT_TIME_LIMIT_SECONDS,
    time_limit=settings.MANAGED_SSH_TASK_TIME_LIMIT_SECONDS,
)
def discover_managed_ssh_database_objects(self, operation_id):
    return _run(operation_id, expected_lane="database", expected_operation="discover")


@current_app.task(
    name="discover_managed_ssh_files_objects",
    bind=True,
    ignore_result=True,
    soft_time_limit=settings.MANAGED_SSH_TASK_SOFT_TIME_LIMIT_SECONDS,
    time_limit=settings.MANAGED_SSH_TASK_TIME_LIMIT_SECONDS,
)
def discover_managed_ssh_files_objects(self, operation_id):
    return _run(operation_id, expected_lane="files", expected_operation="discover")


@current_app.task(
    name="update_managed_ssh_database_metadata",
    bind=True,
    ignore_result=True,
    soft_time_limit=settings.MANAGED_SSH_TASK_SOFT_TIME_LIMIT_SECONDS,
    time_limit=settings.MANAGED_SSH_TASK_TIME_LIMIT_SECONDS,
)
def update_managed_ssh_database_metadata(self, operation_id):
    return _run(
        operation_id,
        expected_lane="database",
        expected_operation="update_metadata",
    )


@current_app.task(
    name="maintain_managed_ssh_database_operations", bind=True, ignore_result=True
)
def maintain_managed_ssh_database_operations(self):
    return _maintain_lane("database")


@current_app.task(
    name="maintain_managed_ssh_files_operations", bind=True, ignore_result=True
)
def maintain_managed_ssh_files_operations(self):
    return _maintain_lane("files")
