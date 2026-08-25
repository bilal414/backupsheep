"""Crash-safe SSH host-key preview and approval workflow.

The API intentionally separates key discovery from authenticated SSH use. A
preview token identifies the exact account, user, endpoint, algorithm, and
fingerprint that the user reviewed. Approval re-fetches the key and atomically
updates the tenant-scoped database ledger; workers materialize exact ephemeral
OpenSSH trust files only for the lifetime of a transfer.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from django.db import connection as db_connection, transaction
from rest_framework import status

from apps.console.connection import ssh
from apps.console.log.models import CoreLog


logger = logging.getLogger(__name__)

TOKEN_SALT = "backupsheep.ssh-host-key-approval.v2"
DEFAULT_TOKEN_MAX_AGE = 10 * 60
class SSHHostKeyFlowError(Exception):
    """A client-safe, typed error for the host-key approval endpoints."""

    def __init__(self, code: str, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status_code = status_code

@dataclass(frozen=True)
class ScannedHostKey:
    host: str
    port: int
    key_type: str
    negotiated_host_key_algorithm: str
    bits: int
    fingerprint: str
    key: object


def _token_max_age() -> int:
    value = getattr(settings, "SSH_HOST_KEY_APPROVAL_TOKEN_MAX_AGE", DEFAULT_TOKEN_MAX_AGE)
    try:
        return max(1, min(int(value), 24 * 60 * 60))
    except (TypeError, ValueError):
        return DEFAULT_TOKEN_MAX_AGE


def _validate_endpoint(host, port):
    if not isinstance(host, str):
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH host is required.")
    try:
        host = ssh.normalize_ssh_host(host)
    except (TypeError, ValueError):
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH host is required.")
    if isinstance(port, bool):
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH port is required.")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH port is required.")
    if not 1 <= port <= 65535:
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH port is required.")
    return host, port


def _request_payload(payload):
    if not hasattr(payload, "get"):
        raise SSHHostKeyFlowError("invalid_request", "A JSON object is required.")
    return payload


def _fingerprint(key) -> str:
    try:
        digest = hashlib.sha256(key.asbytes()).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    except Exception:
        raise SSHHostKeyFlowError(
            "ssh_handshake_failed", "SSH handshake did not provide a usable host key.", 502
        )


def scan_remote_host_key(host: str, port: int) -> ScannedHostKey:
    try:
        scan = ssh.scan_host_key(host, port)
        key = scan.key
        key_type = scan.wire_key_type
        if not isinstance(key_type, str) or not key_type:
            raise ValueError("missing key type")
        return ScannedHostKey(
            host=host,
            port=port,
            key_type=key_type,
            negotiated_host_key_algorithm=scan.negotiated_host_key_algorithm,
            bits=scan.bits,
            fingerprint=_fingerprint(key),
            key=key,
        )
    except SSHHostKeyFlowError:
        raise
    except ssh.SSHHostKeyScanError as error:
        raise SSHHostKeyFlowError(error.code, error.detail, error.status_code)
    except Exception:
        logger.warning("SSH host-key scan failed")
        raise SSHHostKeyFlowError(
            "ssh_scan_failed", "Unable to read the SSH host key.", status.HTTP_502_BAD_GATEWAY
        )


def _scan_for_approval(host: str, port: int) -> ScannedHostKey:
    """Keep even unexpected scanner adapters inside the safe error contract."""

    try:
        return scan_remote_host_key(host, port)
    except SSHHostKeyFlowError:
        raise
    except Exception:
        logger.warning("SSH host-key scan adapter failed")
        raise SSHHostKeyFlowError(
            "ssh_scan_failed", "Unable to read the SSH host key.", status.HTTP_502_BAD_GATEWAY
        )


def _token_signer() -> signing.TimestampSigner:
    return signing.TimestampSigner(salt=TOKEN_SALT)


def _approval_witness(approval) -> str:
    material = None
    if approval is not None:
        material = {
            "id": approval.pk,
            "generation": approval.generation,
            "fingerprint": approval.fingerprint,
            "negotiated_host_key_algorithm": approval.negotiated_host_key_algorithm,
            "wire_key_type": approval.wire_key_type,
        }
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _database_host_key_state(account, scanned):
    from apps.console.connection.models import CoreSSHHostKeyApproval

    approval = CoreSSHHostKeyApproval.objects.filter(
        account=account,
        normalized_host=scanned.host,
        port=scanned.port,
    ).first()
    if approval is None:
        return "unknown", False, None
    approved = (
        approval.wire_key_type == scanned.key_type
        and approval.fingerprint == scanned.fingerprint
        and approval.negotiated_host_key_algorithm
        == scanned.negotiated_host_key_algorithm
        and approval.bits == scanned.bits
    )
    return ("already_approved", False, approval) if approved else (
        "changed",
        True,
        approval,
    )


def _make_approval_token(request, account, scanned: ScannedHostKey, approval) -> str:
    payload = {
        "version": 2,
        "account_id": str(account.pk),
        "user_id": str(request.user.pk),
        "host": scanned.host,
        "port": scanned.port,
        "key_type": scanned.key_type,
        "negotiated_host_key_algorithm": scanned.negotiated_host_key_algorithm,
        "bits": scanned.bits,
        "fingerprint": scanned.fingerprint,
        "local_approval_witness": _approval_witness(approval),
    }
    return _token_signer().sign_object(payload)


def _current_account(request):
    try:
        account = request.user.member.get_current_account()
    except Exception:
        account = None
    if account is None or account.pk is None:
        raise SSHHostKeyFlowError(
            "account_unavailable",
            "A current BackupSheep account is required.",
            status.HTTP_403_FORBIDDEN,
        )
    return account


@contextlib.contextmanager
def _account_scan_slot(account):
    """Permit one bounded SSH handshake per account without cross-tenant blocking."""

    key = f"security:ssh-host-key-scan:account:{int(account.pk)}"
    token = os.urandom(16).hex()
    if not cache.add(key, token, timeout=60):
        raise SSHHostKeyFlowError(
            "scan_busy",
            "Another SSH host-key scan is already running for this account.",
            status.HTTP_429_TOO_MANY_REQUESTS,
        )
    try:
        yield
    finally:
        if cache.get(key) == token:
            cache.delete(key)


def preview_host_key(request, payload):
    payload = _request_payload(payload)
    account = _current_account(request)
    host, port = _validate_endpoint(payload.get("host"), payload.get("port"))
    # Network I/O is deliberately outside every database/file lock. A slow or
    # malicious endpoint cannot serialize trust changes for another tenant.
    with _account_scan_slot(account):
        scanned = _scan_for_approval(host, port)
    state, replace_required, approval = _database_host_key_state(account, scanned)
    return {
        "host": scanned.host,
        "port": scanned.port,
        "key_type": scanned.key_type,
        "negotiated_host_key_algorithm": scanned.negotiated_host_key_algorithm,
        "bits": scanned.bits,
        "fingerprint": scanned.fingerprint,
        "status": state,
        "approval_token": _make_approval_token(
            request, account, scanned, approval
        ),
        "replace_required": replace_required,
    }


def _unsign_approval_token(request, account, token):
    if not isinstance(token, str) or not token:
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    try:
        payload = _token_signer().unsign_object(token, max_age=_token_max_age())
    except signing.SignatureExpired:
        raise SSHHostKeyFlowError("approval_expired", "The approval token has expired.")
    except signing.BadSignature:
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    if not isinstance(payload, dict):
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    required = (
        "version",
        "account_id",
        "user_id",
        "host",
        "port",
        "key_type",
        "negotiated_host_key_algorithm",
        "bits",
        "fingerprint",
        "local_approval_witness",
    )
    if any(field not in payload for field in required):
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    if payload.get("version") != 2:
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    if not hmac.compare_digest(str(payload["account_id"]), str(account.pk)):
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is not valid for this account.")
    if not hmac.compare_digest(str(payload["user_id"]), str(request.user.pk)):
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is not valid for this user.")
    try:
        host, port = _validate_endpoint(payload["host"], payload["port"])
    except SSHHostKeyFlowError:
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    if (
        not isinstance(payload["key_type"], str)
        or not isinstance(payload["negotiated_host_key_algorithm"], str)
        or isinstance(payload["bits"], bool)
        or not isinstance(payload["bits"], int)
        or not isinstance(payload["fingerprint"], str)
        or not isinstance(payload["local_approval_witness"], str)
    ):
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    payload["host"] = host
    payload["port"] = port
    return payload


def _requested_fingerprint(payload):
    fingerprint = payload.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint or len(fingerprint) > 128:
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH fingerprint is required.")
    return fingerprint


def approve_host_key(request, payload):
    payload = _request_payload(payload)
    account = _current_account(request)
    approval = _unsign_approval_token(request, account, payload.get("approval_token"))
    requested_fingerprint = _requested_fingerprint(payload)
    if not hmac.compare_digest(requested_fingerprint, str(approval["fingerprint"])):
        raise SSHHostKeyFlowError(
            "approval_invalid", "The fingerprint does not match the approval token."
        )
    replacement = payload.get("replace", False)
    if not isinstance(replacement, bool):
        raise SSHHostKeyFlowError("invalid_request", "The replace flag must be boolean.")

    with _account_scan_slot(account):
        scanned = _scan_for_approval(approval["host"], approval["port"])
    if (
        scanned.key_type != approval["key_type"]
        or scanned.negotiated_host_key_algorithm
        != approval["negotiated_host_key_algorithm"]
        or scanned.bits != approval["bits"]
        or not hmac.compare_digest(
            scanned.fingerprint, str(approval["fingerprint"])
        )
    ):
        raise SSHHostKeyFlowError(
            "host_key_changed",
            "The SSH host key changed after preview; preview it again.",
            status.HTTP_409_CONFLICT,
        )

    from apps.console.account.models import CoreAccount
    from apps.console.connection.models import CoreConnection, CoreSSHHostKeyApproval
    from apps.console.connection.managed_ssh import (
        ManagedSSHOperationError,
        _active_request_permission,
        acquire_managed_ssh_mutation_lock,
    )

    with transaction.atomic():
        acquire_managed_ssh_mutation_lock()
        locked_account = CoreAccount.objects.select_for_update().get(pk=account.pk)
        try:
            _active_request_permission(
                locked_account.pk,
                request.user.member.pk,
                "integration_changes",
            )
        except ManagedSSHOperationError:
            raise SSHHostKeyFlowError(
                "permission_denied",
                "Integration-change permission is required.",
                status.HTTP_403_FORBIDDEN,
            ) from None
        # Match the same account -> connection -> approval lock order used by
        # managed operation creation. Lock every account connection in PK order:
        # legacy mixed host spellings must not create a trigger lock inversion.
        list(
            CoreConnection.objects.select_for_update()
            .filter(account=locked_account)
            .order_by("pk")
            .values_list("pk", flat=True)
        )
        current = (
            CoreSSHHostKeyApproval.objects.select_for_update()
            .filter(
                account=locked_account,
                normalized_host=scanned.host,
                port=scanned.port,
            )
            .first()
        )
        if not hmac.compare_digest(
            _approval_witness(current), str(approval["local_approval_witness"])
        ):
            raise SSHHostKeyFlowError(
                "approval_conflict",
                "The local SSH approval changed; preview it again.",
                status.HTTP_409_CONFLICT,
            )
        state, replace_required, _unused = _database_host_key_state(
            locked_account, scanned
        )
        if state == "changed" and replace_required and not replacement:
            raise SSHHostKeyFlowError(
                "host_key_changed",
                "The approved SSH host key changed; explicit replacement is required.",
                status.HTTP_409_CONFLICT,
            )
        if current is None:
            current = CoreSSHHostKeyApproval.objects.create(
                account=locked_account,
                normalized_host=scanned.host,
                port=scanned.port,
                wire_key_type=scanned.key_type,
                public_key_base64=scanned.key.get_base64(),
                fingerprint=scanned.fingerprint,
                negotiated_host_key_algorithm=scanned.negotiated_host_key_algorithm,
                bits=scanned.bits,
                approved_by_member_pk_snapshot=request.user.member.pk,
                approved_by_user_pk_snapshot=request.user.pk,
            )
        elif state != "already_approved":
            current.wire_key_type = scanned.key_type
            current.public_key_base64 = scanned.key.get_base64()
            current.fingerprint = scanned.fingerprint
            current.negotiated_host_key_algorithm = (
                scanned.negotiated_host_key_algorithm
            )
            current.bits = scanned.bits
            current.approved_by_member_pk_snapshot = request.user.member.pk
            current.approved_by_user_pk_snapshot = request.user.pk
            current.save(
                update_fields=(
                    "wire_key_type",
                    "public_key_base64",
                    "fingerprint",
                    "negotiated_host_key_algorithm",
                    "bits",
                    "approved_by_member_pk_snapshot",
                    "approved_by_user_pk_snapshot",
                    "modified",
                )
            )
        current.refresh_from_db()

    CoreLog.record(
        account,
        CoreLog.Type.CONNECTION,
        {
            "message": f"SSH host key approved for {scanned.host}:{scanned.port}.",
            "action": "ssh_host_key_approve",
            "actor_email": request.user.email,
            "host": scanned.host,
            "port": scanned.port,
            "key_type": scanned.key_type,
            "negotiated_host_key_algorithm": scanned.negotiated_host_key_algorithm,
            "bits": scanned.bits,
            "approval_generation": current.generation,
            "fingerprint": scanned.fingerprint,
            "replace": replacement,
            "status": state,
        },
    )
    return {
        "detail": "SSH host key approved.",
        "status": "already_approved" if state == "already_approved" else "approved",
        "host": scanned.host,
        "port": scanned.port,
        "key_type": scanned.key_type,
        "negotiated_host_key_algorithm": scanned.negotiated_host_key_algorithm,
        "bits": scanned.bits,
        "approval_generation": current.generation,
        "fingerprint": scanned.fingerprint,
    }


def revoke_host_key(request, payload):
    """Revoke one account-scoped endpoint without requiring a live server scan."""

    payload = _request_payload(payload)
    account = _current_account(request)
    host, port = _validate_endpoint(payload.get("host"), payload.get("port"))

    from apps.console.account.models import CoreAccount
    from apps.console.connection.models import CoreConnection, CoreSSHHostKeyApproval
    from apps.console.connection.managed_ssh import (
        ManagedSSHOperationError,
        _active_request_permission,
        acquire_managed_ssh_mutation_lock,
    )

    revoked = None
    with transaction.atomic():
        acquire_managed_ssh_mutation_lock()
        locked_account = CoreAccount.objects.select_for_update().get(pk=account.pk)
        try:
            _active_request_permission(
                locked_account.pk,
                request.user.member.pk,
                "integration_changes",
            )
        except ManagedSSHOperationError:
            raise SSHHostKeyFlowError(
                "permission_denied",
                "Integration-change permission is required.",
                status.HTTP_403_FORBIDDEN,
            ) from None
        list(
            CoreConnection.objects.select_for_update()
            .filter(account=locked_account)
            .order_by("pk")
            .values_list("pk", flat=True)
        )
        approval = (
            CoreSSHHostKeyApproval.objects.select_for_update()
            .filter(
                account=locked_account,
                normalized_host=host,
                port=port,
            )
            .first()
        )
        if approval is not None:
            revoked = {
                "generation": approval.generation,
                "fingerprint": approval.fingerprint,
                "key_type": approval.wire_key_type,
            }
            with db_connection.cursor() as cursor:
                cursor.execute(
                    "SELECT public.backupsheep_revoke_ssh_host_key_approval("
                    "%s, %s)",
                    (
                        approval.pk,
                        locked_account.pk,
                    ),
                )
                deleted = cursor.fetchone()
            if deleted != (True,):
                raise SSHHostKeyFlowError(
                    "approval_changed",
                    "SSH host-key approval changed while it was being revoked.",
                    status.HTTP_409_CONFLICT,
                )

    if revoked is None:
        return {
            "detail": "SSH host key was already revoked for this account.",
            "status": "already_revoked",
            "host": host,
            "port": port,
        }

    CoreLog.record(
        account,
        CoreLog.Type.CONNECTION,
        {
            "message": f"SSH host key revoked for {host}:{port}.",
            "action": "ssh_host_key_revoke",
            "actor_email": request.user.email,
            "host": host,
            "port": port,
            "key_type": revoked["key_type"],
            "approval_generation": revoked["generation"],
            "fingerprint": revoked["fingerprint"],
        },
    )
    return {
        "detail": "SSH host key revoked. Matching connections are pending review.",
        "status": "revoked",
        "host": host,
        "port": port,
        "approval_generation": revoked["generation"] + 1,
        "fingerprint": revoked["fingerprint"],
    }
