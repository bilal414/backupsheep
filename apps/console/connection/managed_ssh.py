"""Durable broker boundary for the installation-managed SSH private key.

Only database and files workers mount the private key.  The web role authorizes an
opaque operation row, publishes its reserved Celery task id, and reads the durable
result.  Every consumer recomputes the public-key, connection, and intent digests
before opening a network connection.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import posixpath
import re
import secrets
import time
import uuid
from datetime import timedelta

from celery import current_app
from django.conf import settings
from django.db import transaction
from django.utils import timezone


_KEY_TYPE_RE = re.compile(r"^[A-Za-z0-9@._+-]{1,128}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_BY_INTEGRATION = {"database": "database", "website": "files"}
_TASK_BY_INTENT = {
    ("database", "validate"): "validate_managed_ssh_database_connection",
    ("files", "validate"): "validate_managed_ssh_files_connection",
    ("database", "discover"): "discover_managed_ssh_database_objects",
    ("files", "discover"): "discover_managed_ssh_files_objects",
    ("database", "update_metadata"): "update_managed_ssh_database_metadata",
}


class ManagedSSHOperationError(RuntimeError):
    """A managed-key operation did not satisfy its durable intent contract."""


def _canonical_json(value) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _sha256(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def managed_public_key_fingerprint(public_key: str | None = None) -> str:
    """Hash the canonical OpenSSH wire blob, never its comment or formatting."""

    public_key = (
        str(public_key)
        if public_key is not None
        else str(getattr(settings, "SSH_MANAGED_PUBLIC_KEY", ""))
    ).strip()
    if not public_key or "\n" in public_key or "\r" in public_key:
        raise ManagedSSHOperationError(
            "The managed SSH public key is missing or malformed."
        )
    fields = public_key.split()
    if len(fields) not in (2, 3) or not _KEY_TYPE_RE.fullmatch(fields[0]):
        raise ManagedSSHOperationError("The managed SSH public key is malformed.")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ManagedSSHOperationError(
            "The managed SSH public key is malformed."
        ) from error
    if len(blob) < 8 or len(blob) > 16 * 1024:
        raise ManagedSSHOperationError("The managed SSH public key is malformed.")
    key_type_size = int.from_bytes(blob[:4], "big")
    if key_type_size < 1 or key_type_size > 128 or 4 + key_type_size > len(blob):
        raise ManagedSSHOperationError("The managed SSH public key is malformed.")
    try:
        embedded_key_type = blob[4 : 4 + key_type_size].decode("ascii")
    except UnicodeDecodeError as error:
        raise ManagedSSHOperationError(
            "The managed SSH public key is malformed."
        ) from error
    if embedded_key_type != fields[0]:
        raise ManagedSSHOperationError(
            "The managed SSH public key type does not match its wire key."
        )
    return _sha256(blob)


def normalize_requested_path(value) -> str:
    """Return one bounded POSIX path representation for signed discovery intent."""

    if value is None or str(value) == "":
        return "."
    raw = str(value)
    if len(raw.encode("utf-8")) > 2048 or any(
        ord(character) < 32 or ord(character) == 127 for character in raw
    ):
        raise ManagedSSHOperationError("The requested remote path is invalid.")
    normalized = posixpath.normpath(raw)
    # POSIX preserves exactly two leading slashes with implementation-defined
    # meaning. SFTP has no need for that ambiguity, so canonicalize it to one.
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    if len(normalized.encode("utf-8")) > 2048:
        raise ManagedSSHOperationError("The requested remote path is too long.")
    return normalized


def _secret_digest(value) -> str:
    if value is None:
        return _sha256(b"<none>")
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytearray):
        value = bytes(value)
    if not isinstance(value, bytes):
        value = str(value).encode("utf-8")
    return _sha256(value)


def _connection_material(connection) -> dict:
    integration = str(connection.integration.code)
    common = {
        "account_id": connection.account_id,
        "connection_id": connection.pk,
        "integration": integration,
        "location_id": connection.location_id,
    }
    if integration == "website":
        auth = connection.auth_website
        common["auth"] = {
            "host": auth.host,
            "port": auth.port,
            "protocol": auth.protocol,
            "username": _secret_digest(auth.username),
            "password": _secret_digest(auth.password),
            "private_key": _secret_digest(auth.private_key),
            "use_public_key": bool(auth.use_public_key),
            "use_private_key": bool(auth.use_private_key),
            "ftps_use_explicit_ssl": bool(auth.ftps_use_explicit_ssl),
            "verify_ssl": auth.verify_ssl is not False,
            "allow_legacy_rsa": bool(auth.flag_use_sha1_key_verification),
        }
    elif integration == "database":
        auth = connection.auth_database
        common["auth"] = {
            "host": auth.host,
            "port": auth.port,
            "database_name": auth.database_name,
            "all_databases": bool(auth.all_databases),
            "username": _secret_digest(auth.username),
            "password": _secret_digest(auth.password),
            "type": auth.type,
            "version": auth.version,
            "include_stored_procedure": bool(auth.include_stored_procedure),
            "use_ssl": bool(auth.use_ssl),
            "ssh_host": auth.ssh_host,
            "ssh_port": auth.ssh_port,
            "ssh_username": _secret_digest(auth.ssh_username),
            "ssh_password": _secret_digest(auth.ssh_password),
            "private_key": _secret_digest(auth.private_key),
            "use_public_key": bool(auth.use_public_key),
            "use_private_key": bool(auth.use_private_key),
            "allow_legacy_rsa": bool(auth.flag_use_sha1_key_verification),
        }
    else:
        raise ManagedSSHOperationError(
            "The connection type cannot use the managed SSH key."
        )
    return common


def connection_config_digest(connection) -> str:
    return _sha256(_canonical_json(_connection_material(connection)))


def connection_config_material(connection) -> dict:
    """Expose a detached canonical snapshot for controlled metadata mutation checks."""

    return json.loads(_canonical_json(_connection_material(connection)))


def source_lane_for_connection(connection) -> str:
    source_lane = _SOURCE_BY_INTEGRATION.get(str(connection.integration.code))
    if source_lane is None:
        raise ManagedSSHOperationError(
            "The connection type cannot use the managed SSH key."
        )
    return source_lane


def connection_uses_managed_key(connection) -> bool:
    integration = str(connection.integration.code)
    if integration == "database":
        return bool(connection.auth_database.use_public_key)
    if integration == "website":
        return bool(connection.auth_website.use_public_key)
    return False


def task_name_for_operation(source_lane: str, operation: str) -> str:
    try:
        return _TASK_BY_INTENT[(source_lane, operation)]
    except KeyError as error:
        raise ManagedSSHOperationError(
            "The managed SSH operation is not supported for this source lane."
        ) from error


def _intent_material(
    *,
    operation_uuid,
    connection_id,
    account_id,
    source_lane,
    operation,
    requested_path,
    public_key_fingerprint,
    config_digest,
    celery_task_id,
    idempotency_key,
    expires_at,
) -> dict:
    return {
        "schema": "backupsheep-managed-ssh-operation-v1",
        "uuid": str(operation_uuid),
        "connection_id": int(connection_id),
        "account_id": int(account_id),
        "source_lane": str(source_lane),
        "operation": str(operation),
        "requested_path": str(requested_path),
        "managed_public_key_fingerprint": str(public_key_fingerprint),
        "connection_config_digest": str(config_digest),
        "celery_task_id": str(celery_task_id),
        "idempotency_key": str(idempotency_key),
        "expires_at": expires_at.isoformat(),
    }


def operation_intent_material(operation) -> dict:
    return _intent_material(
        operation_uuid=operation.uuid,
        connection_id=operation.connection_id,
        account_id=operation.account_id,
        source_lane=operation.source_lane,
        operation=operation.operation,
        requested_path=operation.requested_path,
        public_key_fingerprint=operation.managed_public_key_fingerprint,
        config_digest=operation.connection_config_digest,
        celery_task_id=operation.celery_task_id,
        idempotency_key=operation.idempotency_key,
        expires_at=operation.expires_at,
    )


def operation_intent_digest(operation) -> str:
    return _sha256(_canonical_json(operation_intent_material(operation)))


def validate_operation_intent(operation, *, expected_lane=None, expected_operation=None):
    """Recompute every immutable witness before publish or execution."""

    if expected_lane is not None and operation.source_lane != expected_lane:
        raise ManagedSSHOperationError("The managed SSH source lane changed.")
    if expected_operation is not None and operation.operation != expected_operation:
        raise ManagedSSHOperationError("The managed SSH operation changed.")
    if operation.account_id != operation.connection.account_id:
        raise ManagedSSHOperationError("The managed SSH account binding changed.")
    if source_lane_for_connection(operation.connection) != operation.source_lane:
        raise ManagedSSHOperationError("The managed SSH connection lane changed.")
    if not connection_uses_managed_key(operation.connection):
        raise ManagedSSHOperationError(
            "The connection no longer uses the managed SSH key."
        )
    if managed_public_key_fingerprint() != operation.managed_public_key_fingerprint:
        raise ManagedSSHOperationError("The managed SSH public key changed.")
    if connection_config_digest(operation.connection) != operation.connection_config_digest:
        raise ManagedSSHOperationError("The managed SSH connection changed.")
    if operation_intent_digest(operation) != operation.intent_digest:
        raise ManagedSSHOperationError("The managed SSH intent digest changed.")
    if not _DIGEST_RE.fullmatch(operation.idempotency_key):
        raise ManagedSSHOperationError("The managed SSH idempotency key is invalid.")
    task_name_for_operation(operation.source_lane, operation.operation)


def _operation_ttl_seconds() -> int:
    try:
        value = int(getattr(settings, "MANAGED_SSH_OPERATION_TTL_SECONDS", 300))
    except (TypeError, ValueError):
        value = 300
    return min(max(value, 30), 900)


def create_managed_ssh_operation(connection, operation: str, *, requested_path=""):
    """Persist one immutable request and publish only after its DB commit."""

    from apps.console.connection.models import CoreConnection, CoreManagedSSHOperation

    if not transaction.get_connection().in_atomic_block:
        with transaction.atomic():
            return create_managed_ssh_operation(
                connection,
                operation,
                requested_path=requested_path,
            )

    connection = (
        CoreConnection.objects.select_for_update()
        .select_related("integration")
        .get(pk=connection.pk)
    )
    # Fetch the one-to-one auth row after the connection lock. This also makes the
    # config digest cover the exact row that will be used by the worker.
    if connection.integration.code == "database":
        connection.auth_database
    elif connection.integration.code == "website":
        connection.auth_website

    source_lane = source_lane_for_connection(connection)
    operation = str(operation)
    task_name_for_operation(source_lane, operation)
    if not connection_uses_managed_key(connection):
        raise ManagedSSHOperationError(
            "This connection does not use the managed SSH key."
        )
    path = normalize_requested_path(requested_path) if operation == "discover" else ""
    if operation == "validate":
        if connection.status != CoreConnection.Status.PENDING:
            connection.status = CoreConnection.Status.PENDING
            connection.save(update_fields=("status",))
    elif connection.status != CoreConnection.Status.ACTIVE:
        raise ManagedSSHOperationError(
            "The managed SSH connection must be active before this operation."
        )

    fingerprint = managed_public_key_fingerprint()
    config_digest = connection_config_digest(connection)
    now = timezone.now()
    existing = (
        CoreManagedSSHOperation.objects.filter(
            connection=connection,
            source_lane=source_lane,
            operation=operation,
            requested_path=path,
            managed_public_key_fingerprint=fingerprint,
            connection_config_digest=config_digest,
            status__in=(
                CoreManagedSSHOperation.Status.PENDING,
                CoreManagedSSHOperation.Status.RUNNING,
            ),
            expires_at__gt=now,
        )
        .order_by("-created")
        .first()
    )
    if existing is not None:
        transaction.on_commit(lambda pk=existing.pk: dispatch_managed_ssh_operation(pk))
        return existing

    operation_uuid = uuid.uuid4()
    celery_task_id = uuid.uuid4()
    idempotency_key = _sha256(secrets.token_bytes(32))
    expires_at = now + timedelta(seconds=_operation_ttl_seconds())
    material = _intent_material(
        operation_uuid=operation_uuid,
        connection_id=connection.pk,
        account_id=connection.account_id,
        source_lane=source_lane,
        operation=operation,
        requested_path=path,
        public_key_fingerprint=fingerprint,
        config_digest=config_digest,
        celery_task_id=celery_task_id,
        idempotency_key=idempotency_key,
        expires_at=expires_at,
    )
    durable_operation = CoreManagedSSHOperation.objects.create(
        uuid=operation_uuid,
        connection=connection,
        account_id=connection.account_id,
        source_lane=source_lane,
        operation=operation,
        requested_path=path,
        managed_public_key_fingerprint=fingerprint,
        connection_config_digest=config_digest,
        celery_task_id=celery_task_id,
        idempotency_key=idempotency_key,
        intent_digest=_sha256(_canonical_json(material)),
        expires_at=expires_at,
    )
    transaction.on_commit(
        lambda pk=durable_operation.pk: dispatch_managed_ssh_operation(pk)
    )
    return durable_operation


def dispatch_managed_ssh_operation(operation_id: int) -> None:
    """Publish a reserved operation without inventing a replacement task id."""

    from apps.console.connection.models import CoreManagedSSHOperation

    operation = CoreManagedSSHOperation.objects.select_related(
        "connection__integration"
    ).get(pk=operation_id)
    if operation.status not in (
        CoreManagedSSHOperation.Status.PENDING,
        CoreManagedSSHOperation.Status.RUNNING,
    ):
        return
    validate_operation_intent(operation)
    remaining = int((operation.expires_at - timezone.now()).total_seconds())
    if remaining <= 0:
        return
    current_app.send_task(
        task_name_for_operation(operation.source_lane, operation.operation),
        args=(operation.pk,),
        task_id=str(operation.celery_task_id),
        expires=remaining,
    )


def wait_for_managed_ssh_operation(operation, timeout_seconds=None):
    """Poll only the durable row; never trust a transient Celery result payload."""

    from apps.console.connection.models import CoreManagedSSHOperation

    if timeout_seconds is None:
        try:
            timeout_seconds = float(
                getattr(settings, "MANAGED_SSH_OPERATION_WAIT_SECONDS", 30)
            )
        except (TypeError, ValueError):
            timeout_seconds = 30.0
    timeout_seconds = min(max(float(timeout_seconds), 0.0), 60.0)
    deadline = time.monotonic() + timeout_seconds
    terminal = {
        CoreManagedSSHOperation.Status.COMPLETE,
        CoreManagedSSHOperation.Status.FAILED,
        CoreManagedSSHOperation.Status.EXPIRED,
    }
    while True:
        operation.refresh_from_db()
        if operation.status in terminal or time.monotonic() >= deadline:
            return operation
        time.sleep(0.1)
