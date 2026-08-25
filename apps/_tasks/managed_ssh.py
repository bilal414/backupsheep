"""Lane-specific execution for installation-managed SSH-key operations."""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from datetime import timedelta

from celery import current_app
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.console.connection.managed_ssh import (
    ManagedSSHOperationError,
    connection_config_material,
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


def _lease_seconds() -> int:
    try:
        value = int(getattr(settings, "MANAGED_SSH_OPERATION_LEASE_SECONDS", 180))
    except (TypeError, ValueError):
        value = 180
    return min(max(value, 30), 600)


def _bounded_result(payload) -> tuple[dict, str]:
    if not isinstance(payload, dict):
        raise ManagedSSHOperationError(
            "The managed SSH worker returned an invalid result."
        )
    encoded = _canonical_json(payload).encode("utf-8")
    try:
        maximum = int(getattr(settings, "MANAGED_SSH_RESULT_MAX_BYTES", 1024 * 1024))
    except (TypeError, ValueError):
        maximum = 1024 * 1024
    maximum = min(max(maximum, 16 * 1024), 4 * 1024 * 1024)
    if len(encoded) > maximum:
        raise ManagedSSHOperationError(
            "The managed SSH result exceeded the safe response limit."
        )
    # Decode the canonical form so no custom mapping/list subclass or non-JSON
    # object reaches the durable result column.
    canonical_payload = json.loads(encoded)
    return canonical_payload, hashlib.sha256(encoded).hexdigest()


def _safe_failure(error, *, stage) -> dict:
    failure = classify_connection_error(error, stage=stage)
    return failure.as_dict()


def _set_connection_validation_status(operation, status):
    from apps.console.connection.models import CoreConnection

    if operation.operation != "validate":
        return
    operation.connection.status = status
    operation.connection.save(update_fields=("status",))


def _terminal_failure_locked(operation, error_payload, *, status="failed"):
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
    _set_connection_validation_status(operation, CoreConnection.Status.SUSPENDED)


def _claim(operation_id: int, *, expected_lane: str, expected_operation: str):
    from apps.console.connection.models import CoreManagedSSHOperation

    with transaction.atomic():
        operation = (
            CoreManagedSSHOperation.objects.select_for_update()
            .select_related("connection__integration")
            .get(pk=operation_id)
        )
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
        try:
            validate_operation_intent(
                operation,
                expected_lane=expected_lane,
                expected_operation=expected_operation,
            )
            if operation.operation == "validate":
                from apps.console.connection.models import CoreConnection

                if operation.connection.status != CoreConnection.Status.PENDING:
                    raise ManagedSSHOperationError(
                        "The connection is not awaiting managed SSH validation."
                    )
            else:
                from apps.console.connection.models import CoreConnection

                if operation.connection.status != CoreConnection.Status.ACTIVE:
                    raise ManagedSSHOperationError(
                        "The connection is not active for this managed SSH operation."
                    )
        except Exception as error:
            _terminal_failure_locked(
                operation,
                _safe_failure(error, stage="managed_ssh_intent"),
            )
            return None

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


def _execute_operation(operation_id: int, operation_name: str):
    from apps.console.connection.models import CoreManagedSSHOperation

    operation = CoreManagedSSHOperation.objects.select_related(
        "connection__integration"
    ).get(pk=operation_id)
    connection = operation.connection
    before_material = connection_config_material(connection)
    if operation.source_lane == "database":
        auth = connection.auth_database
        if operation_name == "validate":
            auth.check_connection(check_errors=True)
            return {"valid": True}, before_material
        if operation_name == "discover":
            return {"eligible_objects": auth.get_eligible_objects()}, before_material
        if operation_name == "update_metadata":
            result = auth.update_db_type_and_version()
            return {"database": result}, before_material
    elif operation.source_lane == "files":
        auth = connection.auth_website
        if operation_name == "validate":
            auth.check_connection(check_errors=True)
            return {"valid": True}, before_material
        if operation_name == "discover":
            return {
                "eligible_objects": auth.get_eligible_objects(
                    path=operation.requested_path
                )
            }, before_material
    raise ManagedSSHOperationError(
        "The managed SSH task does not match its operation row."
    )


def _validate_post_execution(operation, before_material):
    operation.connection.refresh_from_db()
    if operation.source_lane == "database":
        operation.connection.auth_database.refresh_from_db()
    else:
        operation.connection.auth_website.refresh_from_db()
    if operation.operation != "update_metadata":
        validate_operation_intent(
            operation,
            expected_lane=operation.source_lane,
            expected_operation=operation.operation,
        )
        return

    # Metadata discovery is allowed to update exactly database type/version. Every
    # other connection field remains bound to the pre-execution intent digest.
    after_material = connection_config_material(operation.connection)
    expected = copy.deepcopy(before_material)
    expected["auth"]["type"] = after_material["auth"]["type"]
    expected["auth"]["version"] = after_material["auth"]["version"]
    if after_material != expected:
        raise ManagedSSHOperationError(
            "The database connection changed during metadata discovery."
        )


def _finalize_success(operation_id: int, lease_token, payload, before_material):
    from apps.console.connection.models import CoreConnection, CoreManagedSSHOperation

    payload, result_digest = _bounded_result(payload)
    with transaction.atomic():
        operation = (
            CoreManagedSSHOperation.objects.select_for_update()
            .select_related("connection__integration")
            .get(pk=operation_id)
        )
        if (
            operation.status != CoreManagedSSHOperation.Status.RUNNING
            or operation.lease_token != lease_token
        ):
            return
        try:
            _validate_post_execution(operation, before_material)
        except Exception as error:
            _terminal_failure_locked(
                operation,
                _safe_failure(error, stage="managed_ssh_postcondition"),
            )
            return
        completed_at = timezone.now()
        if operation.expires_at <= completed_at:
            _terminal_failure_locked(
                operation,
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
        _set_connection_validation_status(operation, CoreConnection.Status.ACTIVE)


def _finalize_failure(operation_id: int, lease_token, error, *, stage):
    from apps.console.connection.models import CoreManagedSSHOperation

    with transaction.atomic():
        operation = (
            CoreManagedSSHOperation.objects.select_for_update()
            .select_related("connection__integration")
            .get(pk=operation_id)
        )
        if (
            operation.status != CoreManagedSSHOperation.Status.RUNNING
            or operation.lease_token != lease_token
        ):
            return
        _terminal_failure_locked(operation, _safe_failure(error, stage=stage))


def _run(operation_id: int, *, expected_lane: str, expected_operation: str):
    claim = _claim(
        operation_id,
        expected_lane=expected_lane,
        expected_operation=expected_operation,
    )
    if claim is None:
        return
    operation_id, lease_token = claim
    try:
        payload, before_material = _execute_operation(operation_id, expected_operation)
    except Exception as error:
        _finalize_failure(
            operation_id,
            lease_token,
            error,
            stage=(
                "object_discovery"
                if expected_operation == "discover"
                else "metadata_discovery"
                if expected_operation == "update_metadata"
                else "validation"
            ),
        )
        return
    _finalize_success(operation_id, lease_token, payload, before_material)


@current_app.task(
    name="validate_managed_ssh_database_connection", bind=True, ignore_result=True
)
def validate_managed_ssh_database_connection(self, operation_id):
    return _run(
        operation_id,
        expected_lane="database",
        expected_operation="validate",
    )


@current_app.task(
    name="validate_managed_ssh_files_connection", bind=True, ignore_result=True
)
def validate_managed_ssh_files_connection(self, operation_id):
    return _run(
        operation_id,
        expected_lane="files",
        expected_operation="validate",
    )


@current_app.task(
    name="discover_managed_ssh_database_objects", bind=True, ignore_result=True
)
def discover_managed_ssh_database_objects(self, operation_id):
    return _run(
        operation_id,
        expected_lane="database",
        expected_operation="discover",
    )


@current_app.task(
    name="discover_managed_ssh_files_objects", bind=True, ignore_result=True
)
def discover_managed_ssh_files_objects(self, operation_id):
    return _run(
        operation_id,
        expected_lane="files",
        expected_operation="discover",
    )


@current_app.task(
    name="update_managed_ssh_database_metadata", bind=True, ignore_result=True
)
def update_managed_ssh_database_metadata(self, operation_id):
    return _run(
        operation_id,
        expected_lane="database",
        expected_operation="update_metadata",
    )
