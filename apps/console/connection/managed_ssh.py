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
import uuid
from datetime import timedelta

from celery import current_app
from django.conf import settings
from django.db import connection as database_connection, transaction
from django.utils.crypto import salted_hmac
from django.utils import timezone

from .ssh import STRICT_HOST_KEY_ALGORITHMS, normalize_ssh_host
from .reliability import SSHHostKeyApprovalRequiredError


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
_PUBLIC_KEY_SETTING_BY_LANE = {
    "database": "SSH_MANAGED_DATABASE_PUBLIC_KEY",
    "files": "SSH_MANAGED_FILES_PUBLIC_KEY",
}
MANAGED_SSH_MUTATION_ADVISORY_LOCK = 3141592653589793


class ManagedSSHOperationError(RuntimeError):
    """A managed-key operation did not satisfy its durable intent contract."""


def acquire_managed_ssh_mutation_lock() -> None:
    """Take the installation-wide fence before any related row lock.

    The second-account database trigger must fence every installation-managed
    authentication row atomically. Every application path that can create an
    account, change managed authentication, or create managed work therefore
    uses one order: advisory fence, account, membership, connection/auth,
    approval, operation. Database triggers reject lock-order violations rather
    than waiting in a cycle.
    """

    if not transaction.get_connection().in_atomic_block:
        raise ManagedSSHOperationError(
            "The managed SSH mutation fence requires an atomic transaction."
        )
    with database_connection.cursor() as cursor:
        cursor.execute(
            "SELECT pg_catalog.pg_advisory_xact_lock(%s)",
            (MANAGED_SSH_MUTATION_ADVISORY_LOCK,),
        )


def assert_managed_ssh_single_account(account_id) -> int:
    """Bind the installation-managed identity to one security tenant.

    A lane key is shared by every worker replica in this installation. It must
    therefore never be offered to two independent accounts: either could target
    a host on which the other installed that same public key. Multi-account
    installations must use customer-supplied private keys until per-account
    managed identities are implemented.
    """

    try:
        expected_account_id = int(account_id)
    except (TypeError, ValueError) as error:
        raise ManagedSSHOperationError(
            "A valid account is required for managed SSH authentication."
        ) from error
    with database_connection.cursor() as cursor:
        cursor.execute(
            "SELECT public.backupsheep_managed_ssh_single_account(%s)",
            (expected_account_id,),
        )
        allowed = bool(cursor.fetchone()[0])
    if not allowed:
        raise ManagedSSHOperationError(
            "Installation-managed SSH authentication is available only for a "
            "single-account installation. Multi-account installations must use "
            "a customer-supplied private key."
        )
    return expected_account_id


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


def _read_ssh_wire_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise ManagedSSHOperationError("The managed SSH public key is malformed.")
    size = int.from_bytes(blob[offset : offset + 4], "big")
    offset += 4
    if size < 1 or size > 16 * 1024 or offset + size > len(blob):
        raise ManagedSSHOperationError("The managed SSH public key is malformed.")
    return blob[offset : offset + size], offset + size


def _validate_managed_public_key_strength(key_type: str, blob: bytes) -> None:
    embedded_type, offset = _read_ssh_wire_string(blob, 0)
    if embedded_type.decode("ascii", errors="strict") != key_type:
        raise ManagedSSHOperationError(
            "The managed SSH public key type does not match its wire key."
        )
    if key_type == "ssh-ed25519":
        public_bytes, offset = _read_ssh_wire_string(blob, offset)
        if len(public_bytes) != 32 or offset != len(blob):
            raise ManagedSSHOperationError("The managed Ed25519 key is malformed.")
        return
    raise ManagedSSHOperationError(
        "Installation-managed SSH identities must use Ed25519."
    )


def managed_public_key_for_lane(source_lane: str) -> str:
    try:
        setting_name = _PUBLIC_KEY_SETTING_BY_LANE[str(source_lane)]
    except KeyError as error:
        raise ManagedSSHOperationError("The managed SSH source lane is invalid.") from error
    public_key = str(getattr(settings, setting_name, "") or "").strip()
    lane_isolation_required = bool(
        getattr(settings, "SSH_MANAGED_LANE_ISOLATION_REQUIRED", False)
    )
    if not public_key and not lane_isolation_required:
        public_key = str(getattr(settings, "SSH_MANAGED_PUBLIC_KEY", "") or "").strip()
    if lane_isolation_required:
        other_lane = "files" if source_lane == "database" else "database"
        other_setting = _PUBLIC_KEY_SETTING_BY_LANE[other_lane]
        other_key = str(getattr(settings, other_setting, "") or "").strip()
        if bool(public_key) != bool(other_key):
            raise ManagedSSHOperationError(
                "Both managed SSH lane identities must be configured together."
            )
        if public_key and (
            managed_public_key_fingerprint(public_key)
            == managed_public_key_fingerprint(other_key)
        ):
            raise ManagedSSHOperationError(
                "Database and files managed SSH identities must be different."
            )
    return public_key


def managed_public_key_fingerprint(
    public_key: str | None = None, *, source_lane: str | None = None
) -> str:
    """Hash the canonical OpenSSH wire blob, never its comment or formatting."""

    if public_key is None:
        if source_lane is None:
            public_key = str(getattr(settings, "SSH_MANAGED_PUBLIC_KEY", "") or "")
        else:
            public_key = managed_public_key_for_lane(source_lane)
    public_key = str(public_key).strip()
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
    try:
        _validate_managed_public_key_strength(fields[0], blob)
    except UnicodeError as error:
        raise ManagedSSHOperationError(
            "The managed SSH public key is malformed."
        ) from error
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
        tagged_value = b"\x00"
    else:
        if isinstance(value, memoryview):
            value = value.tobytes()
        if isinstance(value, bytearray):
            value = bytes(value)
        if not isinstance(value, bytes):
            value = str(value).encode("utf-8")
        tagged_value = b"\x01" + value
    # This is a change witness, never a password verifier. A plain digest would
    # still let a database-only attacker dictionary-guess low-entropy provider
    # credentials offline. Derive a domain-separated HMAC from the file-backed
    # Django secret so PostgreSQL alone cannot test guesses.
    return salted_hmac(
        "backupsheep.managed-ssh.connection-secret.v1",
        tagged_value,
        secret=settings.SECRET_KEY,
        algorithm="sha256",
    ).hexdigest()


def _connection_material(connection) -> dict:
    integration = str(connection.integration.code)
    common = {
        "account_id": connection.account_id,
        "connection_id": connection.pk,
        "integration": integration,
    }
    if integration == "website":
        auth = connection.auth_website
        common["auth"] = {
            "host": (
                normalize_ssh_host(auth.host)
                if auth.protocol == auth.Protocol.SFTP
                else str(auth.host)
            ),
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
        uses_ssh = bool(auth.use_public_key or auth.use_private_key)
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
            "ssh_host": normalize_ssh_host(auth.ssh_host) if uses_ssh else None,
            "ssh_port": auth.ssh_port if uses_ssh else None,
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


def _active_request_membership(account_id, requested_by_member_id):
    """Lock and return the member/account authorization witness."""

    from apps.console.member.models import CoreMember, CoreMemberAccount

    member = (
        CoreMember.objects.select_for_update()
        .select_related("user")
        .get(pk=requested_by_member_id)
    )
    membership = (
        CoreMemberAccount.objects.select_for_update()
        .filter(
            member=member,
            account_id=account_id,
            status=CoreMemberAccount.Status.ACTIVE,
        )
        .first()
    )
    if membership is None:
        raise ManagedSSHOperationError(
            "The requesting member is not active in this account."
        )
    return member, membership


def _active_request_permission(
    account_id, requested_by_member_id, codename="integration_changes"
):
    """Lock and recheck the complete tenant permission witness."""

    from django.contrib.auth.models import Group, Permission

    from apps.console.account.models import CoreAccountGroup

    member, membership = _active_request_membership(
        account_id, requested_by_member_id
    )
    if membership.primary:
        return member, membership
    permission = Permission.objects.filter(
        content_type__app_label=CoreAccountGroup._meta.app_label,
        content_type__model=CoreAccountGroup._meta.model_name,
        codename=codename,
    ).first()
    if permission is None:
        raise ManagedSSHOperationError(
            "The required integration permission is unavailable."
        )
    candidate_group_ids = list(
        CoreAccountGroup.objects.filter(
            account_id=account_id,
            group__user=member.user,
            group__permissions=permission,
        )
        .order_by("group_id")
        .values_list("group_id", flat=True)
        .distinct()
    )
    if not candidate_group_ids:
        raise ManagedSSHOperationError(
            "Integration-change permission is required."
        )
    locked_enrollments = list(
        CoreAccountGroup.objects.select_for_update()
        .filter(account_id=account_id, group_id__in=candidate_group_ids)
        .order_by("group_id", "pk")
    )
    locked_group_ids = {enrollment.group_id for enrollment in locked_enrollments}
    user_group_through = member.user.groups.through
    permission_group_through = Group.permissions.through
    locked_user_groups = {
        row.group_id
        for row in user_group_through.objects.select_for_update()
        .filter(user_id=member.user_id, group_id__in=locked_group_ids)
        .order_by("group_id")
    }
    locked_permission_groups = {
        row.group_id
        for row in permission_group_through.objects.select_for_update()
        .filter(permission_id=permission.pk, group_id__in=locked_group_ids)
        .order_by("group_id")
    }
    if not (locked_group_ids & locked_user_groups & locked_permission_groups):
        raise ManagedSSHOperationError(
            "Integration-change permission is required."
        )
    return member, membership


def validate_direct_connection_and_activate(connection, *, requested_by_member):
    """Validate a non-managed connection with no database lock held over I/O."""

    from apps.console.account.models import CoreAccount
    from apps.console.connection.models import (
        CoreConnection,
        CoreSSHHostKeyApproval,
    )

    try:
        member_id = int(getattr(requested_by_member, "pk", requested_by_member))
    except (TypeError, ValueError) as error:
        raise ManagedSSHOperationError(
            "A valid requesting member is required for connection validation."
        ) from error

    approval_witness = None
    with transaction.atomic():
        account = CoreAccount.objects.select_for_update().get(pk=connection.account_id)
        _active_request_permission(account.pk, member_id)
        locked_connection = (
            CoreConnection.objects.select_for_update()
            .select_related("integration")
            .get(pk=connection.pk, account=account)
        )
        if locked_connection.integration.code == "database":
            auth = locked_connection.auth_database.__class__.objects.select_for_update().get(
                connection=locked_connection
            )
            locked_connection._state.fields_cache["auth_database"] = auth
            uses_ssh = bool(auth.use_private_key)
            host, port = auth.ssh_host, auth.ssh_port
        elif locked_connection.integration.code == "website":
            auth = locked_connection.auth_website.__class__.objects.select_for_update().get(
                connection=locked_connection
            )
            locked_connection._state.fields_cache["auth_website"] = auth
            uses_ssh = auth.protocol == auth.Protocol.SFTP
            host, port = auth.host, auth.port
        else:
            raise ManagedSSHOperationError(
                "This connection type does not support direct SSH validation."
            )

        if bool(auth.use_public_key):
            raise ManagedSSHOperationError(
                "Managed SSH connections require a durable worker validation."
            )

        if uses_ssh:
            approval = CoreSSHHostKeyApproval.objects.select_for_update().get(
                account=account,
                normalized_host=normalize_ssh_host(host),
                port=port,
            )
            auth._managed_ssh_host_key_witness = {
                "approval_id": approval.pk,
                "generation": approval.generation,
                "fingerprint": approval.fingerprint,
                "negotiated_host_key_algorithm": (
                    approval.negotiated_host_key_algorithm
                ),
            }
            auth._ssh_trust_lock_held = True
            approval_witness = (
                approval.pk,
                approval.generation,
                approval.fingerprint,
                approval.negotiated_host_key_algorithm,
            )

        auth._state.fields_cache["connection"] = locked_connection
        config_digest = connection_config_digest(locked_connection)
        connection_generation = locked_connection.managed_ssh_generation

    # The endpoint is attacker-controlled. Execute against the detached immutable
    # model/config/trust snapshot after every transaction and row lock is released.
    if locked_connection.integration.code == "database":
        auth.check_connection(check_errors=True)
    else:
        if auth.validate() is not True:
            raise ManagedSSHOperationError("Connection validation failed.")

    # Re-authorize and compare every mutable witness before projecting ACTIVE.
    with transaction.atomic():
        account = CoreAccount.objects.select_for_update().get(pk=connection.account_id)
        _active_request_permission(account.pk, member_id)
        current_connection = (
            CoreConnection.objects.select_for_update()
            .select_related("integration")
            .get(pk=connection.pk, account=account)
        )
        if current_connection.integration.code == "database":
            current_auth = current_connection.auth_database.__class__.objects.select_for_update().get(
                connection=current_connection
            )
            current_connection._state.fields_cache["auth_database"] = current_auth
            current_host, current_port = current_auth.ssh_host, current_auth.ssh_port
        else:
            current_auth = current_connection.auth_website.__class__.objects.select_for_update().get(
                connection=current_connection
            )
            current_connection._state.fields_cache["auth_website"] = current_auth
            current_host, current_port = current_auth.host, current_auth.port
        if bool(current_auth.use_public_key):
            raise ManagedSSHOperationError(
                "The connection changed to a managed SSH identity."
            )
        if (
            current_connection.managed_ssh_generation != connection_generation
            or connection_config_digest(current_connection) != config_digest
        ):
            raise ManagedSSHOperationError(
                "The connection changed during validation; retry it."
            )
        if approval_witness is not None:
            current_approval = CoreSSHHostKeyApproval.objects.select_for_update().get(
                account=account,
                normalized_host=normalize_ssh_host(current_host),
                port=current_port,
            )
            current_witness = (
                current_approval.pk,
                current_approval.generation,
                current_approval.fingerprint,
                current_approval.negotiated_host_key_algorithm,
            )
            if current_witness != approval_witness:
                raise ManagedSSHOperationError(
                    "The SSH host-key approval changed during validation; retry it."
                )
        current_connection.status = CoreConnection.Status.ACTIVE
        current_connection.save(update_fields=("status", "modified"))
        return current_connection


def assert_managed_connection_policy(connection) -> None:
    """Reject compatibility switches that weaken the stock managed identity."""

    integration = str(connection.integration.code)
    if integration == "database":
        auth = connection.auth_database
    elif integration == "website":
        auth = connection.auth_website
    else:
        raise ManagedSSHOperationError(
            "The connection type cannot use the managed SSH key."
        )
    if bool(auth.flag_use_sha1_key_verification):
        raise ManagedSSHOperationError(
            "Legacy RSA/SHA-1 authentication is not permitted for managed SSH keys."
        )


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
    connection_generation,
    host_key_approval_pk_snapshot,
    host_key_approval_generation,
    host_key_fingerprint,
    host_key_negotiated_algorithm,
    requested_by_member_pk_snapshot,
    requested_by_user_pk_snapshot,
    request_actor_kind,
    request_source,
    celery_task_id,
    idempotency_key,
    expires_at,
) -> dict:
    return {
        "schema": "backupsheep-managed-ssh-operation-v2",
        "uuid": str(operation_uuid),
        "connection_id": int(connection_id),
        "account_id": int(account_id),
        "source_lane": str(source_lane),
        "operation": str(operation),
        "requested_path": str(requested_path),
        "managed_public_key_fingerprint": str(public_key_fingerprint),
        "connection_config_digest": str(config_digest),
        "connection_generation": int(connection_generation),
        "host_key_approval_pk_snapshot": int(host_key_approval_pk_snapshot),
        "host_key_approval_generation": int(host_key_approval_generation),
        "host_key_fingerprint": str(host_key_fingerprint),
        "host_key_negotiated_algorithm": str(host_key_negotiated_algorithm),
        "requested_by_member_pk_snapshot": int(requested_by_member_pk_snapshot),
        "requested_by_user_pk_snapshot": int(requested_by_user_pk_snapshot),
        "request_actor_kind": str(request_actor_kind),
        "request_source": str(request_source),
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
        connection_generation=operation.connection_generation,
        host_key_approval_pk_snapshot=operation.host_key_approval_pk_snapshot,
        host_key_approval_generation=operation.host_key_approval_generation,
        host_key_fingerprint=operation.host_key_fingerprint,
        host_key_negotiated_algorithm=operation.host_key_negotiated_algorithm,
        requested_by_member_pk_snapshot=operation.requested_by_member_pk_snapshot,
        requested_by_user_pk_snapshot=operation.requested_by_user_pk_snapshot,
        request_actor_kind=operation.request_actor_kind,
        request_source=operation.request_source,
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
    assert_managed_ssh_single_account(operation.account_id)
    if source_lane_for_connection(operation.connection) != operation.source_lane:
        raise ManagedSSHOperationError("The managed SSH connection lane changed.")
    if not connection_uses_managed_key(operation.connection):
        raise ManagedSSHOperationError(
            "The connection no longer uses the managed SSH key."
        )
    assert_managed_connection_policy(operation.connection)
    if operation.connection_generation != operation.connection.managed_ssh_generation:
        raise ManagedSSHOperationError("The managed SSH connection generation changed.")
    from apps.console.connection.models import CoreSSHHostKeyApproval

    try:
        approval = CoreSSHHostKeyApproval.objects.get(
            pk=operation.host_key_approval_pk_snapshot
        )
    except CoreSSHHostKeyApproval.DoesNotExist as error:
        raise ManagedSSHOperationError(
            "The managed SSH host-key approval was revoked."
        ) from error
    if (
        approval.account_id != operation.account_id
        or approval.generation != operation.host_key_approval_generation
        or approval.fingerprint != operation.host_key_fingerprint
        or approval.negotiated_host_key_algorithm
        != operation.host_key_negotiated_algorithm
    ):
        raise ManagedSSHOperationError("The managed SSH host-key approval changed.")
    if (
        managed_public_key_fingerprint(source_lane=operation.source_lane)
        != operation.managed_public_key_fingerprint
    ):
        raise ManagedSSHOperationError("The managed SSH public key changed.")
    if connection_config_digest(operation.connection) != operation.connection_config_digest:
        raise ManagedSSHOperationError("The managed SSH connection changed.")
    if operation_intent_digest(operation) != operation.intent_digest:
        raise ManagedSSHOperationError("The managed SSH intent digest changed.")
    if not _DIGEST_RE.fullmatch(operation.idempotency_key):
        raise ManagedSSHOperationError("The managed SSH idempotency key is invalid.")
    task_name_for_operation(operation.source_lane, operation.operation)


def _operation_ttl_seconds() -> int:
    return int(settings.MANAGED_SSH_OPERATION_TTL_SECONDS)


def _publish_retry_delay_seconds(publish_attempts: int) -> int:
    base = _bounded_setting("MANAGED_SSH_REPUBLISH_BASE_SECONDS", 10, 5, 60)
    maximum = _bounded_setting("MANAGED_SSH_REPUBLISH_MAX_SECONDS", 60, base, 300)
    exponent = min(max(int(publish_attempts) - 1, 0), 8)
    return min(base * (2**exponent), maximum)


def _bounded_setting(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(getattr(settings, name, default))
    except (TypeError, ValueError):
        value = default
    return min(max(value, minimum), maximum)


def _expire_durable_operation_locked(operation, now) -> None:
    from apps.console.connection.models import CoreConnection, CoreManagedSSHOperation

    error_payload = {
        "code": "OPERATION_EXPIRED",
        "detail": "The managed SSH request expired before execution.",
        "stage": "worker_queue",
        "retryable": True,
        "remediation": "Retry the connection operation.",
    }
    operation.status = CoreManagedSSHOperation.Status.EXPIRED
    operation.lease_token = None
    operation.lease_expires_at = None
    operation.completed_at = now
    operation.result_payload = {}
    operation.result_digest = ""
    operation.error_payload = error_payload
    operation.execution_witness_digest = _sha256(
        _canonical_json(
            {
                "intent_digest": operation.intent_digest,
                "status": "expired",
                "error": error_payload,
                "completed_at": now.isoformat(),
            }
        )
    )
    operation.publish_error_code = "OPERATION_EXPIRED"
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
            "publish_error_code",
            "modified",
        )
    )
    if operation.operation == CoreManagedSSHOperation.Operation.VALIDATE:
        latest = (
            CoreManagedSSHOperation.objects.filter(
                connection_id=operation.connection_id,
                operation=CoreManagedSSHOperation.Operation.VALIDATE,
            )
            .order_by("-created", "-pk")
            .only("pk", "connection_generation")
            .first()
        )
        if (
            latest is not None
            and latest.pk == operation.pk
            and latest.connection_generation
            == operation.connection.managed_ssh_generation
        ):
            CoreConnection.objects.filter(pk=operation.connection_id).update(
                status=CoreConnection.Status.SUSPENDED,
                modified=now,
            )


def _dispatch_after_commit(operation_id: int) -> None:
    # Publication is a wake-up hint for the durable row. Never turn a committed
    # API mutation into a 500 merely because RabbitMQ was transiently unavailable.
    try:
        dispatch_managed_ssh_operation(operation_id)
    except Exception:
        return


def create_managed_ssh_operation(
    connection,
    operation: str,
    *,
    requested_path="",
    requested_by_member,
    request_source="api",
):
    """Persist one immutable request and publish only after its DB commit."""

    from apps.console.connection.models import (
        CoreConnection,
        CoreManagedSSHOperation,
        CoreSSHHostKeyApproval,
    )

    if not transaction.get_connection().in_atomic_block:
        with transaction.atomic():
            return create_managed_ssh_operation(
                connection,
                operation,
                requested_path=requested_path,
                requested_by_member=requested_by_member,
                request_source=request_source,
            )

    # This must precede every account/member/connection row lock. The SQL
    # guards use a non-blocking assertion of the same fence so a future caller
    # that violates the global order fails with a retryable serialization error
    # instead of forming a database deadlock.
    acquire_managed_ssh_mutation_lock()

    try:
        requested_by_member_id = int(getattr(requested_by_member, "pk", requested_by_member))
    except (TypeError, ValueError) as error:
        raise ManagedSSHOperationError(
            "A valid requesting member is required for managed SSH operations."
        ) from error
    if requested_by_member_id < 1 or request_source != "api":
        raise ManagedSSHOperationError(
            "The managed SSH request audit identity is invalid."
        )

    # Every user-authorized managed trust mutation uses account -> membership ->
    # connection -> auth -> approval -> operation ordering.
    from apps.console.account.models import CoreAccount

    expected_account_id = connection.account_id
    CoreAccount.objects.select_for_update().only("pk").get(pk=expected_account_id)
    assert_managed_ssh_single_account(expected_account_id)
    requesting_member, _membership = _active_request_permission(
        expected_account_id, requested_by_member_id
    )
    connection = (
        CoreConnection.objects.select_for_update()
        .select_related("integration")
        .get(pk=connection.pk)
    )
    if connection.account_id != expected_account_id:
        raise ManagedSSHOperationError("The managed SSH account binding changed.")
    # Fetch the one-to-one auth row after the connection lock. This also makes the
    # config digest cover the exact row that will be used by the worker.
    if connection.integration.code == "database":
        auth = connection.auth_database.__class__.objects.select_for_update().get(
            connection_id=connection.pk
        )
        connection._state.fields_cache["auth_database"] = auth
    elif connection.integration.code == "website":
        auth = connection.auth_website.__class__.objects.select_for_update().get(
            connection_id=connection.pk
        )
        connection._state.fields_cache["auth_website"] = auth

    source_lane = source_lane_for_connection(connection)
    operation = str(operation)
    task_name_for_operation(source_lane, operation)
    if not connection_uses_managed_key(connection):
        raise ManagedSSHOperationError(
            "This connection does not use the managed SSH key."
        )
    assert_managed_connection_policy(connection)
    path = normalize_requested_path(requested_path) if operation == "discover" else ""
    if operation == "validate":
        if connection.status != CoreConnection.Status.PENDING:
            connection.status = CoreConnection.Status.PENDING
            connection.save(update_fields=("status",))
    elif connection.status != CoreConnection.Status.ACTIVE:
        raise ManagedSSHOperationError(
            "The managed SSH connection must be active before this operation."
        )

    fingerprint = managed_public_key_fingerprint(source_lane=source_lane)
    config_digest = connection_config_digest(connection)
    if source_lane == "database":
        approval_host, approval_port = auth.ssh_host, auth.ssh_port
    else:
        approval_host, approval_port = auth.host, auth.port
    normalized_approval_host = normalize_ssh_host(approval_host)
    approvals = list(
        CoreSSHHostKeyApproval.objects.select_for_update().filter(
            account_id=connection.account_id,
            normalized_host=normalized_approval_host,
            port=approval_port,
        )
    )
    algorithm_rank = {
        algorithm: index for index, algorithm in enumerate(STRICT_HOST_KEY_ALGORITHMS)
    }
    approvals.sort(
        key=lambda candidate: algorithm_rank.get(
            candidate.negotiated_host_key_algorithm,
            len(algorithm_rank),
        )
    )
    if not approvals or approvals[0].negotiated_host_key_algorithm not in algorithm_rank:
        raise SSHHostKeyApprovalRequiredError()
    host_key_approval = approvals[0]
    now = timezone.now()
    existing = (
        CoreManagedSSHOperation.objects.filter(
            connection=connection,
            source_lane=source_lane,
            operation=operation,
            requested_path=path,
            managed_public_key_fingerprint=fingerprint,
            connection_config_digest=config_digest,
            connection_generation=connection.managed_ssh_generation,
            host_key_approval_pk_snapshot=host_key_approval.pk,
            host_key_approval_generation=host_key_approval.generation,
            host_key_fingerprint=host_key_approval.fingerprint,
            host_key_negotiated_algorithm=host_key_approval.negotiated_host_key_algorithm,
            requested_by_member_pk_snapshot=requesting_member.pk,
            requested_by_user_pk_snapshot=requesting_member.user_id,
            request_actor_kind="member",
            request_source=request_source,
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
        transaction.on_commit(lambda pk=existing.pk: _dispatch_after_commit(pk))
        return existing


    active_statuses = (
        CoreManagedSSHOperation.Status.PENDING,
        CoreManagedSSHOperation.Status.RUNNING,
    )
    per_connection_limit = _bounded_setting(
        "MANAGED_SSH_ACTIVE_PER_CONNECTION", 4, 1, 16
    )
    per_account_limit = _bounded_setting("MANAGED_SSH_ACTIVE_PER_ACCOUNT", 20, 1, 100)
    active = CoreManagedSSHOperation.objects.filter(
        status__in=active_statuses,
        expires_at__gt=now,
    )
    if active.filter(connection=connection).count() >= per_connection_limit:
        raise ManagedSSHOperationError(
            "Too many managed SSH operations are active for this connection."
        )
    if active.filter(account_id=connection.account_id).count() >= per_account_limit:
        raise ManagedSSHOperationError(
            "Too many managed SSH operations are active for this account."
        )

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
        connection_generation=connection.managed_ssh_generation,
        host_key_approval_pk_snapshot=host_key_approval.pk,
        host_key_approval_generation=host_key_approval.generation,
        host_key_fingerprint=host_key_approval.fingerprint,
        host_key_negotiated_algorithm=host_key_approval.negotiated_host_key_algorithm,
        requested_by_member_pk_snapshot=requesting_member.pk,
        requested_by_user_pk_snapshot=requesting_member.user_id,
        request_actor_kind="member",
        request_source=request_source,
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
        connection_generation=connection.managed_ssh_generation,
        host_key_approval_pk_snapshot=host_key_approval.pk,
        host_key_approval_generation=host_key_approval.generation,
        host_key_fingerprint=host_key_approval.fingerprint,
        host_key_negotiated_algorithm=host_key_approval.negotiated_host_key_algorithm,
        requested_by_member_pk_snapshot=requesting_member.pk,
        requested_by_user_pk_snapshot=requesting_member.user_id,
        request_actor_kind="member",
        request_source=request_source,
        celery_task_id=celery_task_id,
        idempotency_key=idempotency_key,
        intent_digest=_sha256(_canonical_json(material)),
        expires_at=expires_at,
    )
    transaction.on_commit(
        lambda pk=durable_operation.pk: _dispatch_after_commit(pk)
    )
    return durable_operation


def _locked_dispatch_operation(operation_id: int):
    """Lock one durable request in the global managed-SSH lock order."""

    from apps.console.account.models import CoreAccount
    from apps.console.connection.models import (
        CoreAuthDatabase,
        CoreAuthWebsite,
        CoreConnection,
        CoreManagedSSHOperation,
        CoreSSHHostKeyApproval,
    )

    acquire_managed_ssh_mutation_lock()

    identity = (
        CoreManagedSSHOperation.objects.filter(pk=operation_id)
        .values(
            "account_id",
            "connection_id",
            "host_key_approval_pk_snapshot",
        )
        .first()
    )
    if identity is None:
        raise CoreManagedSSHOperation.DoesNotExist
    account = CoreAccount.objects.select_for_update().only("pk").get(
        pk=identity["account_id"]
    )
    connection = (
        CoreConnection.objects.select_for_update()
        .select_related("account", "integration")
        .get(pk=identity["connection_id"], account=account)
    )
    if connection.integration.code == "database":
        auth = CoreAuthDatabase.objects.select_for_update().get(
            connection=connection
        )
        connection._state.fields_cache["auth_database"] = auth
    elif connection.integration.code == "website":
        auth = CoreAuthWebsite.objects.select_for_update().get(
            connection=connection
        )
        connection._state.fields_cache["auth_website"] = auth
    else:
        raise ManagedSSHOperationError("The managed SSH source lane changed.")
    # Lock the approval before the operation even when it has been revoked. The
    # later intent check supplies the typed failure; the ordering prevents a
    # dispatch/rotation deadlock.
    CoreSSHHostKeyApproval.objects.select_for_update().filter(
        pk=identity["host_key_approval_pk_snapshot"],
        account=account,
    ).first()
    operation = (
        CoreManagedSSHOperation.objects.select_for_update()
        .get(
            pk=operation_id,
            account=account,
            connection=connection,
            host_key_approval_pk_snapshot=identity[
                "host_key_approval_pk_snapshot"
            ],
        )
    )
    operation._state.fields_cache["connection"] = connection
    return operation


def _record_publish_error(operation_id: int, code: str, *, attempted_at=None) -> None:
    from apps.console.connection.models import CoreManagedSSHOperation

    try:
        with transaction.atomic():
            operation = _locked_dispatch_operation(operation_id)
            if operation.status not in (
                CoreManagedSSHOperation.Status.PENDING,
                CoreManagedSSHOperation.Status.RUNNING,
            ):
                return
            if attempted_at is not None and operation.last_publish_attempt_at != attempted_at:
                return
            if operation.published_at is not None:
                return
            operation.publish_error_code = code
            operation.save(update_fields=("publish_error_code", "modified"))
    except (CoreManagedSSHOperation.DoesNotExist, ManagedSSHOperationError):
        return


def dispatch_managed_ssh_operation(operation_id: int) -> bool:
    """Idempotently wake one durable operation without inventing a task id."""

    from apps.console.connection.models import CoreManagedSSHOperation

    attempted_at = None
    try:
        with transaction.atomic():
            operation = _locked_dispatch_operation(operation_id)
            now = timezone.now()
            if operation.status == CoreManagedSSHOperation.Status.RUNNING:
                if operation.lease_expires_at and operation.lease_expires_at > now:
                    return False
            elif operation.status != CoreManagedSSHOperation.Status.PENDING:
                return False
            if operation.expires_at <= now:
                _expire_durable_operation_locked(operation, now)
                return False
            if operation.last_publish_attempt_at is not None:
                retry_after = operation.last_publish_attempt_at + timedelta(
                    seconds=_publish_retry_delay_seconds(operation.publish_attempts)
                )
                if retry_after > now:
                    return False
            operation.publish_attempts += 1
            operation.last_publish_attempt_at = now
            attempted_at = now
            operation.publish_error_code = ""
            operation.save(
                update_fields=(
                    "publish_attempts",
                    "last_publish_attempt_at",
                    "publish_error_code",
                    "modified",
                )
            )
            validate_operation_intent(operation)
            remaining = int((operation.expires_at - now).total_seconds())
            task_name = task_name_for_operation(
                operation.source_lane, operation.operation
            )
            task_id = str(operation.celery_task_id)
            operation_pk = operation.pk
    except CoreManagedSSHOperation.DoesNotExist:
        return False
    except Exception:
        _record_publish_error(operation_id, "INTENT_REJECTED")
        return False

    try:
        current_app.send_task(
            task_name,
            args=(operation_pk,),
            task_id=task_id,
            expires=remaining,
        )
    except Exception:
        _record_publish_error(
            operation_id,
            "BROKER_UNAVAILABLE",
            attempted_at=attempted_at,
        )
        return False

    published_at = timezone.now()
    try:
        with transaction.atomic():
            operation = _locked_dispatch_operation(operation_id)
            if operation.last_publish_attempt_at != attempted_at:
                return True
            update_fields = ["publish_error_code", "modified"]
            operation.publish_error_code = ""
            if operation.published_at is None:
                operation.published_at = published_at
                update_fields.append("published_at")
            operation.save(update_fields=tuple(update_fields))
    except (CoreManagedSSHOperation.DoesNotExist, ManagedSSHOperationError):
        return True
    return True
