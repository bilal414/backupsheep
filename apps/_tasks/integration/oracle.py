"""Crash-safe Oracle Cloud volume backup integration.

The task entry point remains intentionally small.  Provider mutation, adoption,
pagination, and error classification live in :class:`OracleVolumeAdapter` so
they can be exercised without a Celery worker or live tenancy.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import uuid
from dataclasses import dataclass
from email.utils import parsedate_to_datetime

from celery import current_app
from celery.exceptions import MaxRetriesExceededError, SoftTimeLimitExceeded
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps._tasks.exceptions import (
    ConnectionValidationFailedError,
    NodeBackupFailedError,
)
from apps.console.account.models import CoreAccount
from apps.console.connection.models import CoreConnection, _oci_client_kwargs
from apps.console.node.models import CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup


ORACLE_PROVIDER = "oracle"
ORACLE_BACKUP_TAG = "BACKUPSHEEP__UUID"
ORACLE_SOURCE_TAG = "BACKUPSHEEP__SOURCE"
ORACLE_KIND_TAG = "BACKUPSHEEP__KIND"
ORACLE_REQUEST_TAG = "BACKUPSHEEP__REQUEST"
ORACLE_RESTORE_TAG = "BACKUPSHEEP_RESTORE"
ORACLE_RESTORE_SOURCE_TAG = "BACKUPSHEEP_RESTORE_SOURCE"
ORACLE_RESTORE_ORIGIN_TAG = "BACKUPSHEEP_RESTORE_ORIGIN"
ORACLE_DELETE_STATE_KEY = "oracle_delete"

ORACLE_DELETE_INITIAL_STATUSES = frozenset(
    {
        UtilBackup.Status.DELETE_REQUESTED,
        UtilBackup.Status.COMPLETE,
        UtilBackup.Status.PARTIAL,
        UtilBackup.Status.FAILED,
        UtilBackup.Status.MAX_RETRY_FAILED,
        UtilBackup.Status.DELETE_FAILED,
        UtilBackup.Status.DELETE_FAILED_NOT_FOUND,
        UtilBackup.Status.DELETE_MAX_RETRY_FAILED,
        UtilBackup.Status.CANCELLED,
        UtilBackup.Status.TIMEOUT,
    }
)

DEFAULT_ORACLE_PAGE_LIMIT = 100
DEFAULT_ORACLE_MAX_PAGES = 100
DEFAULT_ORACLE_MAX_ITEMS = 10_000
DEFAULT_ORACLE_MAX_COMPARTMENTS = 1_000
DEFAULT_ORACLE_RETRY_TOKEN_REPLAY_SECONDS = 20 * 60 * 60
MAX_ORACLE_RETRY_TOKEN_LENGTH = 64
_OCI_OCID = re.compile(r"ocid1\.[a-z0-9-]+\.[A-Za-z0-9._:-]{1,1000}\Z")
_OCI_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")

_TERMINAL_BACKUP_STATES = {"FAULTY", "TERMINATED", "TERMINATING"}
_AVAILABLE_BACKUP_STATE = "AVAILABLE"
_AUTH_CODES = {
    "authfailed",
    "invalidauthenticationinfo",
    "invalidcredentials",
    "notauthenticated",
    "notauthorized",
    "notauthorizedornotfound",
    "signaturenotvalid",
}
_NOT_FOUND_CODES = {"notfound", "notauthorizedornotfound"}
_RATE_LIMIT_CODES = {"toomanyrequests", "throttled", "throttling"}
_QUOTA_CODES = {
    "limitexceeded",
    "quotaexceeded",
    "resourcelimitexceeded",
}
_TRANSIENT_CODES = {
    "externalserverinvalidresponse",
    "externalservertimeout",
    "externalserverunreachable",
    "internalerror",
    "requesttimeout",
    "serviceunavailable",
}


class OracleProviderError(RuntimeError):
    """A secret-free provider error consumed by shared retry orchestration."""

    SAFE_MESSAGES = {
        "PROVIDER_AUTH_FAILED": (
            "Oracle Cloud rejected the configured credentials or permissions."
        ),
        "PROVIDER_NOT_FOUND": "Oracle Cloud could not find the requested resource.",
        "PROVIDER_NOT_FOUND_OR_UNAUTHORIZED": (
            "Oracle Cloud concealed whether the resource is absent or unauthorized; "
            "manual review is required."
        ),
        "QUOTA_EXCEEDED": "The Oracle Cloud resource quota was exceeded.",
        "PROVIDER_RATE_LIMIT": (
            "Oracle Cloud rate-limited the request; BackupSheep will retry."
        ),
        "PROVIDER_TIMEOUT": (
            "The Oracle Cloud request timed out; its outcome will be reconciled."
        ),
        "PROVIDER_TRANSIENT_OUTAGE": (
            "Oracle Cloud is temporarily unavailable; BackupSheep will retry."
        ),
        "PROVIDER_DUPLICATE_MATCH": (
            "Multiple Oracle Cloud resources matched this backup; manual review is required."
        ),
        "PROVIDER_OWNERSHIP_MISMATCH": (
            "Oracle Cloud resource ownership verification failed."
        ),
        "PROVIDER_RECONCILIATION_REQUIRED": (
            "The Oracle Cloud operation could not be reconciled automatically."
        ),
        "PROVIDER_CREATE_OUTCOME_UNKNOWN": (
            "Oracle Cloud accepted the request status without a verifiable resource; "
            "BackupSheep will reconcile before retrying."
        ),
        "PROVIDER_MALFORMED_RESPONSE": (
            "Oracle Cloud returned an invalid response; manual review is required."
        ),
        "PROVIDER_UNSUPPORTED_RESOURCE": (
            "This Oracle Cloud resource type is not supported for native backup."
        ),
        "PROVIDER_REQUEST_FAILED": "Oracle Cloud rejected the provider request.",
        "PROVIDER_FAILED": "Oracle Cloud reported a terminal provider failure.",
    }

    def __init__(
        self,
        code,
        *,
        retryable=False,
        unknown_outcome=False,
        http_status=None,
        retry_after=None,
    ):
        self.code = str(code or "PROVIDER_FAILED")[:64]
        self.error_code = self.code
        self.retryable = bool(retryable)
        self.unknown_outcome = bool(unknown_outcome)
        self.http_status = _safe_int(http_status)
        self.retry_after = _bounded_retry_after(retry_after)
        super().__init__(
            self.SAFE_MESSAGES.get(self.code, self.SAFE_MESSAGES["PROVIDER_FAILED"])
        )


@dataclass(frozen=True)
class OracleBackupWitness:
    marker: str
    source_id: str
    volume_type: str
    compartment_id: str
    request_token: str

    def as_dict(self):
        return {
            "provider": ORACLE_PROVIDER,
            "marker": self.marker,
            "source_id": self.source_id,
            "volume_type": self.volume_type,
            "compartment_id": self.compartment_id,
            "request_token": self.request_token,
        }


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _bounded_positive_setting(name, default, maximum):
    value = _safe_int(getattr(settings, name, default))
    if value is None or value <= 0:
        value = default
    return min(value, maximum)


def _bounded_retry_after(value, default=60):
    seconds = _safe_int(value)
    if seconds is None or seconds <= 0:
        seconds = default
    return min(seconds, 86_400)


def _header_value(headers, name):
    if not isinstance(headers, dict):
        return None
    expected = str(name).casefold()
    for key, value in headers.items():
        if str(key).casefold() == expected:
            return value
    return None


def _retry_after_from_headers(headers):
    value = _header_value(headers, "retry-after")
    if value in (None, ""):
        return 60
    seconds = _safe_int(value)
    if seconds is not None:
        return _bounded_retry_after(seconds)
    try:
        parsed = parsedate_to_datetime(str(value))
        if timezone.is_naive(parsed):
            parsed = timezone.make_aware(parsed, dt.timezone.utc)
        return _bounded_retry_after((parsed - timezone.now()).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return 60


def _provider_code(error):
    value = str(getattr(error, "code", "") or "").strip().casefold()
    return value if re.fullmatch(r"[a-z0-9_.:-]{1,64}", value) else ""


def classify_oracle_error(error, *, mutation=False):
    """Map OCI/transport failures to stable categories without retaining text."""

    if isinstance(error, OracleProviderError):
        return error

    status = _safe_int(
        getattr(error, "status", None) or getattr(error, "status_code", None)
    )
    code = _provider_code(error)
    headers = getattr(error, "headers", None) or {}
    retry_after = _retry_after_from_headers(headers)
    name = error.__class__.__name__.casefold()

    # OCI deliberately uses NotAuthorizedOrNotFound when revealing existence
    # would leak information.  Treating it as an ordinary 404 could make a
    # poller or delete reconciler declare success without ownership evidence.
    if code == "notauthorizedornotfound":
        return OracleProviderError(
            "PROVIDER_NOT_FOUND_OR_UNAUTHORIZED", http_status=status
        )
    if status in {401, 403} or code in _AUTH_CODES:
        return OracleProviderError("PROVIDER_AUTH_FAILED", http_status=status)
    if status == 404 or code in _NOT_FOUND_CODES:
        return OracleProviderError("PROVIDER_NOT_FOUND", http_status=status)
    if code in _QUOTA_CODES:
        return OracleProviderError("QUOTA_EXCEEDED", http_status=status)
    if status == 429 or code in _RATE_LIMIT_CODES:
        return OracleProviderError(
            "PROVIDER_RATE_LIMIT",
            retryable=True,
            unknown_outcome=mutation,
            http_status=status,
            retry_after=retry_after,
        )
    if status in {408, 504} or "timeout" in name:
        return OracleProviderError(
            "PROVIDER_TIMEOUT",
            retryable=True,
            unknown_outcome=mutation,
            http_status=status,
            retry_after=retry_after,
        )
    if (
        status in {425, 500, 502, 503}
        or status is not None
        and status >= 500
        or code in _TRANSIENT_CODES
        or any(token in name for token in ("connection", "requestexception", "serviceunavailable"))
    ):
        return OracleProviderError(
            "PROVIDER_TRANSIENT_OUTAGE",
            retryable=True,
            unknown_outcome=mutation,
            http_status=status,
            retry_after=retry_after,
        )
    if status is not None and status >= 400:
        return OracleProviderError("PROVIDER_REQUEST_FAILED", http_status=status)
    if isinstance(error, (ValueError, KeyError, TypeError)):
        return OracleProviderError(
            "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=mutation
        )
    return OracleProviderError(
        "PROVIDER_FAILED", unknown_outcome=mutation
    )


def oracle_retry_token(marker):
    """Return a stable OCI retry token without leaking caller-provided text."""

    digest = hashlib.sha256(str(marker).encode("utf-8")).hexdigest()
    return f"bs-{digest[: MAX_ORACLE_RETRY_TOKEN_LENGTH - 3]}"


def _require_oci_ocid(value, resource_type):
    value = str(value or "").strip()
    if (
        not _OCI_OCID.fullmatch(value)
        or not value.startswith(f"ocid1.{resource_type}.")
    ):
        raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
    return value


def _retry_token_replay_seconds():
    # OCI retry tokens are documented as finite-lived. Stop comfortably before
    # the provider's 24-hour boundary; after that, a replay can become a second
    # mutation and therefore requires manual reconciliation.
    return _bounded_positive_setting(
        "ORACLE_RETRY_TOKEN_REPLAY_SECONDS",
        DEFAULT_ORACLE_RETRY_TOKEN_REPLAY_SECONDS,
        23 * 60 * 60,
    )


def _parse_provider_timestamp(value):
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as error:
        raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE") from error
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, dt.timezone.utc)
    return parsed


def _create_intent_metadata(backup, witness):
    state = backup.get_execution_state(create=False)
    existing = dict(state.provider_metadata or {}) if state else {}
    expected_witness = witness.as_dict()
    current_witness = existing.get("witness")
    if current_witness is not None and current_witness != expected_witness:
        raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
    started_value = existing.get("mutation_started_at")
    if existing.get("create_attempted") and not started_value:
        raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
    started = (
        _parse_provider_timestamp(started_value)
        if started_value
        else timezone.now()
    )
    deadline = started + dt.timedelta(seconds=_retry_token_replay_seconds())
    if existing.get("create_attempted") and timezone.now() >= deadline:
        raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
    return {
        "provider": ORACLE_PROVIDER,
        "witness": expected_witness,
        "create_attempted": True,
        "outcome_unknown": True,
        "mutation_started_at": started.isoformat(),
        "retry_token_replay_deadline_at": deadline.isoformat(),
    }


def _oracle_delete_state(backup, witness, resource_id):
    """Read and validate the durable delete checkpoint for one OCI resource."""

    execution = backup.get_execution_state(create=False)
    metadata = dict(execution.provider_metadata or {}) if execution else {}
    raw = metadata.get(ORACLE_DELETE_STATE_KEY)
    if raw in (None, {}):
        return {}, metadata
    if not isinstance(raw, dict):
        raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")

    expected = {
        "resource_id": str(resource_id),
        "marker": witness.marker,
        "source_id": witness.source_id,
        "compartment_id": witness.compartment_id,
        "request_token": witness.request_token,
    }
    for key, value in expected.items():
        stored = raw.get(key)
        if stored not in (None, "") and str(stored) != str(value):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
    return dict(raw), metadata


def _persist_oracle_delete_state(backup, state, witness, resource_id):
    """Persist a delete intent/outcome before the next provider boundary."""

    checkpoint = dict(state)
    checkpoint.update(
        {
            "schema": 1,
            "resource_id": str(resource_id),
            "marker": witness.marker,
            "source_id": witness.source_id,
            "compartment_id": witness.compartment_id,
            "request_token": witness.request_token,
        }
    )
    fence = {}
    lease_owner = getattr(backup, "_required_backup_lease_owner", "")
    lease_token = getattr(backup, "_required_backup_lease_token", "")
    if lease_owner and lease_token:
        fence = {
            "lease_owner": lease_owner,
            "lease_token": lease_token,
            "require_live": True,
        }
    recorded = backup.record_provider_reference(
        resource_id=str(resource_id),
        idempotency_key=witness.request_token,
        provider_status=str(checkpoint.get("phase") or "delete_reconciling"),
        metadata={
            "provider": ORACLE_PROVIDER,
            "ownership_verified": bool(checkpoint.get("ownership_verified")),
            ORACLE_DELETE_STATE_KEY: checkpoint,
        },
        **fence,
    )
    if recorded is None:
        raise OracleProviderError("WORKER_LEASE_LOST")
    return checkpoint


def _begin_oracle_delete(backup, state, witness, resource_id):
    """Atomically elect the one worker allowed to issue the first DELETE.

    The provider request is deliberately made after this checkpoint commits. A
    second API/task delivery that races the first one observes ``delete_started``
    under the row lock and remains a read-only reconciler instead of replaying
    the provider mutation.
    """

    backup.ensure_execution_fence()
    with transaction.atomic():
        locked = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        execution = locked.get_execution_state(create=False)
        if execution is None:
            raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
        metadata = dict(execution.provider_metadata or {})
        current = metadata.get(ORACLE_DELETE_STATE_KEY)
        if current not in (None, {}) and not isinstance(current, dict):
            raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
        current = dict(current or {})
        expected = {
            "resource_id": str(resource_id),
            "marker": witness.marker,
            "source_id": witness.source_id,
            "compartment_id": witness.compartment_id,
            "request_token": witness.request_token,
        }
        for key, value in expected.items():
            stored = current.get(key)
            if stored not in (None, "") and str(stored) != str(value):
                raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        if current.get("delete_started") and not current.get("absence_verified"):
            return current, False

        checkpoint = dict(state)
        checkpoint.update(
            {
                "schema": 1,
                **expected,
                "phase": "delete_requested",
                "delete_started": True,
                "delete_completed": False,
                "absence_verified": False,
                "ownership_verified": True,
                "requested_at": timezone.now().isoformat(),
                # This is a durable election witness, not a provider credential.
                # It remains after a crash so a later worker never guesses whether
                # the first DELETE reached OCI.
                "delete_claim_id": uuid.uuid4().hex,
            }
        )
        metadata.update(
            {
                "provider": ORACLE_PROVIDER,
                "ownership_verified": True,
                ORACLE_DELETE_STATE_KEY: checkpoint,
            }
        )
        execution.provider_resource_id = str(resource_id)
        execution.provider_idempotency_key = witness.request_token
        execution.provider_status = "delete_requested"
        execution.provider_metadata = metadata
        execution.save()
        return checkpoint, True


def claim_oracle_delete_reconciliation(
    backup, lease_owner, lease_seconds, *, allow_initial=False
):
    """Claim one Oracle delete row before any provider read or write.

    Reconciliation workers claim only DELETE_IN_PROGRESS rows. API/node cleanup
    may opt into the initial terminal/delete-request statuses so the first
    provider read is fenced by the same durable lease.
    """

    owner = str(lease_owner or "").strip()
    if not owner:
        raise ValueError("lease_owner is required")
    lease_seconds = max(30, min(int(lease_seconds), 3600))
    now = timezone.now()
    with transaction.atomic():
        fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        eligible_statuses = {UtilBackup.Status.DELETE_IN_PROGRESS}
        if allow_initial:
            eligible_statuses.update(ORACLE_DELETE_INITIAL_STATUSES)
        if fresh.status not in eligible_statuses:
            return None
        state = fresh.get_execution_state(create=True)
        if state.lease_is_active(now):
            return None
        if state.next_retry_at and state.next_retry_at > now:
            return None
        if state.lease_owner or state.lease_token or state.lease_expires_at:
            history = list(
                (state.reconciliation_metadata or {}).get(
                    "stale_oracle_delete_leases", []
                )
            )
            history.append(
                {
                    "detected_at": now.isoformat(),
                    "previous_owner": state.lease_owner,
                    "previous_token": str(state.lease_token or ""),
                    "previous_expires_at": (
                        state.lease_expires_at.isoformat()
                        if state.lease_expires_at
                        else None
                    ),
                }
            )
            reconciliation_metadata = dict(state.reconciliation_metadata or {})
            reconciliation_metadata["stale_oracle_delete_leases"] = history[-20:]
            state.reconciliation_metadata = reconciliation_metadata
            if (
                state.reconciliation_state
                != state.ReconciliationState.MANUAL_REVIEW
            ):
                state.reconciliation_state = state.ReconciliationState.REQUIRED
            state.reconciliation_reason = "stale_oracle_delete_lease"
        state.lease_owner = owner[:255]
        state.phase = "oracle_delete_reconcile"
        state.lease_token = uuid.uuid4()
        state.lease_expires_at = now + dt.timedelta(seconds=lease_seconds)
        state.heartbeat_at = now
        state.claim_count += 1
        state.started_at = state.started_at or now
        state.finished_at = None
        state.next_retry_at = None
        state.save()
        if fresh.status != UtilBackup.Status.DELETE_IN_PROGRESS:
            fresh.status = UtilBackup.Status.DELETE_IN_PROGRESS
            fresh.save(update_fields=["status", "modified"])
        fresh.bind_execution_fence(owner, str(state.lease_token))
        return fresh, str(state.lease_token)


def release_oracle_delete_reconciliation(
    backup, lease_owner, lease_token, *, retry_seconds=120
):
    """Release a delete lease and durably schedule the next reconciliation."""

    retry_seconds = max(0, min(int(retry_seconds), 3600))
    now = timezone.now()
    with transaction.atomic():
        fresh = backup.__class__.objects.select_for_update().get(pk=backup.pk)
        state = fresh.get_execution_state(create=False)
        if state is None or not state.lease_matches(
            lease_owner, lease_token, phase="oracle_delete_reconcile", require_live=False
        ):
            return None
        terminal = fresh.status != UtilBackup.Status.DELETE_IN_PROGRESS
        state.lease_owner = ""
        state.lease_token = None
        state.lease_expires_at = None
        if terminal:
            state.phase = (
                "complete"
                if fresh.status == UtilBackup.Status.DELETE_COMPLETED
                else "failed"
            )
            state.finished_at = now
            state.next_retry_at = None
            if state.reconciliation_state in {
                state.ReconciliationState.REQUIRED,
                state.ReconciliationState.IN_PROGRESS,
            }:
                state.reconciliation_state = state.ReconciliationState.RESOLVED
                state.reconciliation_reason = "oracle_delete_terminal"
        else:
            state.phase = "oracle_delete_wait"
            state.finished_at = None
            state.next_retry_at = now + dt.timedelta(seconds=retry_seconds)
        state.save()
        return fresh


def _oracle_delete_absence(backup, state, witness, resource_id):
    """Commit provider absence before allowing the public row to complete."""

    state = dict(state)
    state.update(
        {
            "phase": "absence_verified",
            "delete_started": True,
            "delete_completed": True,
            "absence_verified": True,
            "absence_verified_at": timezone.now().isoformat(),
            "ownership_verified": True,
        }
    )
    _persist_oracle_delete_state(backup, state, witness, resource_id)
    return "already_absent"


def _oracle_delete_accepted(backup, state, witness, resource_id):
    """Persist acceptance while keeping deletion visibly in progress."""

    state = dict(state)
    state.update(
        {
            "phase": "delete_accepted",
            "delete_started": True,
            "delete_completed": False,
            "absence_verified": False,
            "ownership_verified": True,
            "accepted_at": timezone.now().isoformat(),
        }
    )
    _persist_oracle_delete_state(backup, state, witness, resource_id)
    return UtilBackup.Status.IN_PROGRESS


def _oracle_delete_rejected(backup, state, witness, resource_id, error):
    """Clear only a definitively rejected request so a later retry is safe."""

    state = dict(state)
    state.update(
        {
            "phase": "delete_rejected",
            "delete_started": False,
            "delete_completed": False,
            "last_error_code": str(getattr(error, "code", "PROVIDER_FAILED")),
        }
    )
    _persist_oracle_delete_state(backup, state, witness, resource_id)


def _resource_dict(resource):
    if isinstance(resource, dict):
        return dict(resource)
    fields = (
        "id",
        "display_name",
        "lifecycle_state",
        "freeform_tags",
        "compartment_id",
        "boot_volume_id",
        "volume_id",
        "source_boot_volume_backup_id",
        "source_volume_backup_id",
        "size_in_gbs",
        "size_in_gigabytes",
        "size_in_mbs",
        "availability_domain",
        "image_id",
        "shape",
        "source_details",
        "time_created",
    )
    result = {field: getattr(resource, field, None) for field in fields}
    source_details = result.get("source_details")
    if source_details is not None and not isinstance(source_details, dict):
        result["source_details"] = {
            field: getattr(source_details, field, None)
            for field in (
                "id",
                "image_id",
                "boot_volume_backup_id",
                "volume_backup_id",
                "source_type",
            )
            if getattr(source_details, field, None) is not None
        }
    return result


def _response_data(response):
    if isinstance(response, dict):
        data = response.get("data")
    else:
        data = getattr(response, "data", None)
    return data


def _response_status(response):
    if isinstance(response, dict):
        return _safe_int(response.get("status"))
    return _safe_int(getattr(response, "status", None))


def _next_page(response):
    if isinstance(response, dict):
        value = response.get("opc-next-page") or response.get("opc_next_page")
        if value is None:
            value = _header_value(response.get("headers") or {}, "opc-next-page")
        return value
    value = getattr(response, "opc_next_page", None)
    if value is None:
        value = _header_value(getattr(response, "headers", None) or {}, "opc-next-page")
    return value


def _validate_success_response(response, *, accepted=(200,), mutation=False):
    status = _response_status(response)
    if status not in set(accepted):
        synthetic = type(
            "OracleResponseError",
            (),
            {"status": status, "code": "", "headers": getattr(response, "headers", {})},
        )()
        raise classify_oracle_error(synthetic, mutation=mutation)
    return response


def iter_oracle_pages(method, *, max_pages=None, max_items=None, **kwargs):
    """Yield a complete, bounded OCI cursor inventory.

    A repeated/missing cursor or malformed page fails closed.  Returning a partial
    inventory could make a recovery worker emit a duplicate provider mutation.
    """

    max_pages = max_pages or _bounded_positive_setting(
        "ORACLE_MAX_PAGES", DEFAULT_ORACLE_MAX_PAGES, 1_000
    )
    max_items = max_items or _bounded_positive_setting(
        "ORACLE_MAX_ITEMS", DEFAULT_ORACLE_MAX_ITEMS, 100_000
    )
    limit = _bounded_positive_setting(
        "ORACLE_PAGE_LIMIT", DEFAULT_ORACLE_PAGE_LIMIT, 1_000
    )
    page = None
    seen = set()
    yielded = 0

    for _page_number in range(max_pages):
        request = dict(kwargs)
        request["limit"] = min(limit, max_items - yielded)
        if request["limit"] <= 0:
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
        if page:
            request["page"] = page
        response = _validate_success_response(method(**request), accepted=(200,))
        data = _response_data(response)
        if not isinstance(data, (list, tuple)):
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
        for item in data:
            yielded += 1
            if yielded > max_items:
                raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
            yield item

        cursor = _next_page(response)
        if cursor in (None, ""):
            return
        cursor = str(cursor).strip()
        if not cursor or cursor in seen:
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
        seen.add(cursor)
        page = cursor

    raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")


class OracleVolumeAdapter:
    """Exact, bounded OCI block/boot-volume backup operations."""

    def __init__(self, node_or_integration, *, client=None):
        if hasattr(node_or_integration, "node"):
            self.integration = node_or_integration
            self.node = node_or_integration.node
        else:
            self.node = node_or_integration
            self.integration = node_or_integration.oracle
        self.volume_type = str(
            (self.integration.metadata or {}).get("_bs_vol_type") or ""
        ).casefold()
        if self.volume_type not in {"boot", "block"}:
            raise OracleProviderError("PROVIDER_UNSUPPORTED_RESOURCE")
        if self.node.type != CoreNode.Type.VOLUME:
            raise OracleProviderError("PROVIDER_UNSUPPORTED_RESOURCE")
        self.source_id = _require_oci_ocid(
            self.integration.unique_id,
            "bootvolume" if self.volume_type == "boot" else "volume",
        )
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import oci

            config = self.node.connection.auth_oracle.get_verified_client()
            self._client = oci.core.BlockstorageClient(
                config, **_oci_client_kwargs()
            )
        return self._client

    def _get_source(self):
        method = (
            self.client.get_boot_volume
            if self.volume_type == "boot"
            else self.client.get_volume
        )
        parameter = (
            {"boot_volume_id": self.source_id}
            if self.volume_type == "boot"
            else {"volume_id": self.source_id}
        )
        try:
            response = _validate_success_response(method(**parameter), accepted=(200,))
        except Exception as error:
            raise classify_oracle_error(error) from error
        source = _resource_dict(_response_data(response))
        if (
            str(source.get("id") or "") != self.source_id
            or not str(source.get("compartment_id") or "").strip()
        ):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        return source

    def validate_source(self):
        source = self._get_source()
        state = str(source.get("lifecycle_state") or "").upper()
        if state != "AVAILABLE":
            raise OracleProviderError("PROVIDER_FAILED")
        return source

    def witness(self, backup, source=None):
        source = source or self._get_source()
        marker = str(backup.uuid_str or "").strip()
        if not marker:
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
        return OracleBackupWitness(
            marker=marker,
            source_id=self.source_id,
            volume_type=self.volume_type,
            compartment_id=str(source.get("compartment_id") or ""),
            request_token=oracle_retry_token(marker),
        )

    @staticmethod
    def _tags(resource):
        tags = resource.get("freeform_tags")
        if not isinstance(tags, dict):
            return {}
        return {str(key): str(value) for key, value in tags.items()}

    def _owns_backup(self, resource, witness, *, resource_id=None):
        resource = _resource_dict(resource)
        tags = self._tags(resource)
        source_field = "boot_volume_id" if self.volume_type == "boot" else "volume_id"
        source = resource.get(source_field)
        return bool(
            resource.get("id")
            and (not resource_id or str(resource.get("id")) == str(resource_id))
            and str(resource.get("display_name") or "") == witness.marker
            and tags.get(ORACLE_BACKUP_TAG) == witness.marker
            and tags.get(ORACLE_SOURCE_TAG) == witness.source_id
            and tags.get(ORACLE_KIND_TAG) == witness.volume_type
            and tags.get(ORACLE_REQUEST_TAG) == witness.request_token
            and str(source or "") == witness.source_id
            and str(resource.get("compartment_id") or "") == witness.compartment_id
        )

    def _list_method(self):
        return (
            self.client.list_boot_volume_backups
            if self.volume_type == "boot"
            else self.client.list_volume_backups
        )

    def find_owned_backup(self, witness):
        request = {
            "compartment_id": witness.compartment_id,
            "display_name": witness.marker,
        }
        request[
            "boot_volume_id" if self.volume_type == "boot" else "volume_id"
        ] = witness.source_id
        try:
            resources = [
                _resource_dict(item)
                for item in iter_oracle_pages(self._list_method(), **request)
            ]
        except Exception as error:
            raise classify_oracle_error(error) from error
        exact = [item for item in resources if self._owns_backup(item, witness)]
        if len(exact) > 1:
            raise OracleProviderError("PROVIDER_DUPLICATE_MATCH")
        foreign = [
            item
            for item in resources
            if str(item.get("display_name") or "") == witness.marker
            and item not in exact
        ]
        if foreign:
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        return exact[0] if exact else None

    @staticmethod
    def _provider_metadata(resource, witness, *, adopted):
        resource = _resource_dict(resource)
        return {
            "provider": ORACLE_PROVIDER,
            "witness": witness.as_dict(),
            "resource": {
                key: resource.get(key)
                for key in (
                    "id",
                    "display_name",
                    "lifecycle_state",
                    "compartment_id",
                    "boot_volume_id",
                    "volume_id",
                    "size_in_gbs",
                )
                if resource.get(key) is not None
            },
            "adopted": bool(adopted),
            "outcome_unknown": False,
            "ownership_verified": True,
        }

    def _record_intent(self, backup, witness):
        state = backup.record_provider_reference(
            idempotency_key=witness.request_token,
            provider_status="create_intent",
            metadata=_create_intent_metadata(backup, witness),
        )
        if state is None:
            raise OracleProviderError("WORKER_LEASE_LOST")

    def _record_backup(self, backup, resource, witness, *, adopted):
        resource = _resource_dict(resource)
        resource_id = str(resource.get("id") or "").strip()
        if not resource_id or not self._owns_backup(
            resource, witness, resource_id=resource_id
        ):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        backup.ensure_execution_fence()
        backup.unique_id = resource_id
        backup.size_gigabytes = resource.get("size_in_gbs") or resource.get(
            "size_in_gigabytes"
        )
        backup.set_provider_metadata(
            self._provider_metadata(resource, witness, adopted=adopted)
        )
        backup.save(update_fields=["unique_id", "size_gigabytes", "metadata", "modified"])
        state = backup.record_provider_reference(
            resource_id=resource_id,
            idempotency_key=witness.request_token,
            provider_status=str(resource.get("lifecycle_state") or "accepted"),
            metadata=self._provider_metadata(resource, witness, adopted=adopted),
        )
        if state is None:
            raise OracleProviderError("WORKER_LEASE_LOST")
        try:
            from apps.console.backup.models import CoreBackupExecution

            backup.set_reconciliation_state(
                reconciliation_state=CoreBackupExecution.ReconciliationState.RESOLVED,
                reason="oracle_backup_adopted" if adopted else "oracle_backup_created",
                metadata={"provider": ORACLE_PROVIDER, "resource_id": resource_id},
            )
        except ImportError:
            pass
        return resource_id

    def _create_details(self, witness):
        import oci

        tags = {
            ORACLE_BACKUP_TAG: witness.marker,
            ORACLE_SOURCE_TAG: witness.source_id,
            ORACLE_KIND_TAG: witness.volume_type,
            ORACLE_REQUEST_TAG: witness.request_token,
        }
        if self.volume_type == "boot":
            return oci.core.models.CreateBootVolumeBackupDetails(
                boot_volume_id=witness.source_id,
                display_name=witness.marker,
                freeform_tags=tags,
                type=oci.core.models.CreateBootVolumeBackupDetails.TYPE_FULL,
            )
        return oci.core.models.CreateVolumeBackupDetails(
            volume_id=witness.source_id,
            display_name=witness.marker,
            freeform_tags=tags,
            type=oci.core.models.CreateVolumeBackupDetails.TYPE_FULL,
        )

    def create_or_adopt_backup(self, backup):
        source = self._get_source()
        if str(source.get("lifecycle_state") or "").upper() != "AVAILABLE":
            raise OracleProviderError("PROVIDER_FAILED")
        witness = self.witness(backup, source)
        existing = self.find_owned_backup(witness)
        if existing:
            return self._record_backup(backup, existing, witness, adopted=True)

        self._record_intent(backup, witness)
        backup.ensure_execution_fence()
        method = (
            self.client.create_boot_volume_backup
            if self.volume_type == "boot"
            else self.client.create_volume_backup
        )
        try:
            response = _validate_success_response(
                method(
                    create_boot_volume_backup_details=self._create_details(witness),
                    opc_retry_token=witness.request_token,
                )
                if self.volume_type == "boot"
                else method(
                    create_volume_backup_details=self._create_details(witness),
                    opc_retry_token=witness.request_token,
                ),
                accepted=(200, 202),
                mutation=True,
            )
        except Exception as error:
            classified = classify_oracle_error(error, mutation=True)
            # OCI guarantees the same opc-retry-token identifies one mutation for
            # its validity window. A lost response is still reconciled by tags and
            # source before the token is ever replayed.
            if classified.unknown_outcome or classified.retryable:
                try:
                    candidate = self.find_owned_backup(witness)
                except OracleProviderError as reconciliation_error:
                    if reconciliation_error.code in {
                        "PROVIDER_DUPLICATE_MATCH",
                        "PROVIDER_OWNERSHIP_MISMATCH",
                    }:
                        raise
                    candidate = None
                if candidate:
                    return self._record_backup(
                        backup, candidate, witness, adopted=True
                    )
                backup.record_execution_error(
                    code=classified.code,
                    retry_at=timezone.now()
                    + dt.timedelta(seconds=classified.retry_after),
                    retryable=True,
                    reconciliation_reason="oracle_backup_create_outcome_unknown",
                    reconciliation_metadata={
                        "provider": ORACLE_PROVIDER,
                        "request_token": witness.request_token,
                    },
                )
            raise classified from error

        resource = _resource_dict(_response_data(response))
        if not self._owns_backup(resource, witness):
            candidate = self.find_owned_backup(witness)
            if candidate:
                return self._record_backup(backup, candidate, witness, adopted=True)
            raise OracleProviderError(
                "PROVIDER_CREATE_OUTCOME_UNKNOWN",
                retryable=True,
                unknown_outcome=True,
            )
        from apps._tasks.integration.oracle_acceptance import (
            maybe_fault_after_accepted_backup,
        )

        maybe_fault_after_accepted_backup(
            backup,
            resource_type=(
                "boot_volume" if self.volume_type == "boot" else "volume"
            ),
            request_token=witness.request_token,
            provider_resource_id=str(resource.get("id") or ""),
            request_metadata=self._provider_metadata(
                resource, witness, adopted=False
            ),
        )
        return self._record_backup(backup, resource, witness, adopted=False)

    def poll_backup(self, backup):
        """Perform one exact, categorized provider observation."""

        from apps.console.backup.models import (
            _provider_failed,
            _provider_in_progress,
            _record_provider_outcome,
        )

        state = backup.get_execution_state(create=False)
        provider_metadata = dict(state.provider_metadata or {}) if state else {}
        raw_witness = provider_metadata.get("witness")
        if not isinstance(raw_witness, dict):
            raw_witness = (backup.metadata or {}).get("witness")
        if not isinstance(raw_witness, dict):
            return _provider_failed(
                backup,
                provider=ORACLE_PROVIDER,
                state="missing_witness",
                code="PROVIDER_RECONCILIATION_REQUIRED",
            )
        if (
            not state
            or str(state.provider_resource_id or "")
            != str(backup.unique_id or "")
            or str(state.provider_idempotency_key or "")
            != str(raw_witness.get("request_token") or "")
        ):
            return _provider_failed(
                backup,
                provider=ORACLE_PROVIDER,
                state="durable_pointer_mismatch",
                code="PROVIDER_RECONCILIATION_REQUIRED",
            )
        try:
            witness = OracleBackupWitness(
                marker=str(raw_witness["marker"]),
                source_id=str(raw_witness["source_id"]),
                volume_type=str(raw_witness["volume_type"]),
                compartment_id=str(raw_witness["compartment_id"]),
                request_token=str(raw_witness["request_token"]),
            )
        except (KeyError, TypeError, ValueError):
            return _provider_failed(
                backup,
                provider=ORACLE_PROVIDER,
                state="malformed_witness",
                code="PROVIDER_MALFORMED_RESPONSE",
            )
        if witness.source_id != self.source_id or witness.volume_type != self.volume_type:
            return _provider_failed(
                backup,
                provider=ORACLE_PROVIDER,
                state="ownership_mismatch",
                code="PROVIDER_OWNERSHIP_MISMATCH",
            )

        method = (
            self.client.get_boot_volume_backup
            if self.volume_type == "boot"
            else self.client.get_volume_backup
        )
        parameter = (
            {"boot_volume_backup_id": backup.unique_id}
            if self.volume_type == "boot"
            else {"volume_backup_id": backup.unique_id}
        )
        try:
            response = _validate_success_response(method(**parameter), accepted=(200,))
            resource = _resource_dict(_response_data(response))
        except Exception as error:
            classified = classify_oracle_error(error)
            backup.record_execution_error(
                code=classified.code,
                retry_at=(
                    timezone.now() + dt.timedelta(seconds=classified.retry_after)
                    if classified.retryable
                    else None
                ),
                retryable=classified.retryable,
            )
            return (
                UtilBackup.Status.IN_PROGRESS
                if classified.retryable
                else UtilBackup.Status.FAILED
            )
        if not self._owns_backup(resource, witness, resource_id=backup.unique_id):
            return _provider_failed(
                backup,
                provider=ORACLE_PROVIDER,
                state="ownership_mismatch",
                code="PROVIDER_OWNERSHIP_MISMATCH",
            )
        lifecycle = str(resource.get("lifecycle_state") or "").upper()
        if lifecycle == _AVAILABLE_BACKUP_STATE:
            backup.size_gigabytes = resource.get("size_in_gbs")
            backup.set_provider_metadata(
                self._provider_metadata(resource, witness, adopted=True)
            )
            backup.save(update_fields=["size_gigabytes", "metadata", "modified"])
            _record_provider_outcome(
                backup,
                provider=ORACLE_PROVIDER,
                category="complete",
                provider_status=lifecycle,
                resource_id=backup.unique_id,
            )
            return UtilBackup.Status.COMPLETE
        if lifecycle in _TERMINAL_BACKUP_STATES:
            return _provider_failed(
                backup, provider=ORACLE_PROVIDER, state=lifecycle
            )
        if not lifecycle:
            return _provider_failed(
                backup,
                provider=ORACLE_PROVIDER,
                state="missing_lifecycle",
                code="PROVIDER_MALFORMED_RESPONSE",
            )
        return _provider_in_progress(
            backup,
            provider=ORACLE_PROVIDER,
            state=lifecycle,
            resource_id=backup.unique_id,
        )

    def delete_backup(self, backup):
        """Reconcile OCI deletion until the provider proves resource absence.

        OCI accepts backup deletion asynchronously.  The delete intent is
        checkpointed before the first DELETE call, so a lost response or worker
        crash can poll the exact resource without issuing a second mutation.
        """

        backup.ensure_execution_fence()
        execution = backup.get_execution_state(create=False)
        provider_metadata = dict(execution.provider_metadata or {}) if execution else {}
        raw_witness = provider_metadata.get("witness")
        if not isinstance(raw_witness, dict):
            raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
        if (
            not execution
            or str(execution.provider_resource_id or "")
            != str(backup.unique_id or "")
            or str(execution.provider_idempotency_key or "")
            != str(raw_witness.get("request_token") or "")
        ):
            raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
        try:
            witness = OracleBackupWitness(
                marker=str(raw_witness["marker"]),
                source_id=str(raw_witness["source_id"]),
                volume_type=str(raw_witness["volume_type"]),
                compartment_id=str(raw_witness["compartment_id"]),
                request_token=str(raw_witness["request_token"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE") from error
        delete_state, provider_metadata = _oracle_delete_state(
            backup, witness, backup.unique_id
        )
        if delete_state.get("absence_verified"):
            return "already_absent"
        method = (
            self.client.get_boot_volume_backup
            if self.volume_type == "boot"
            else self.client.get_volume_backup
        )
        parameter = (
            {"boot_volume_backup_id": backup.unique_id}
            if self.volume_type == "boot"
            else {"volume_backup_id": backup.unique_id}
        )
        try:
            response = _validate_success_response(method(**parameter), accepted=(200,))
        except Exception as error:
            classified = classify_oracle_error(error)
            if classified.code == "PROVIDER_NOT_FOUND" and (
                delete_state.get("ownership_verified")
                or provider_metadata.get("ownership_verified")
            ):
                return _oracle_delete_absence(
                    backup, delete_state, witness, backup.unique_id
                )
            raise classified from error
        resource = _resource_dict(_response_data(response))
        if not self._owns_backup(resource, witness, resource_id=backup.unique_id):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")

        if delete_state.get("delete_started"):
            delete_state.update(
                {
                    "phase": "delete_reconciling",
                    "last_observed_at": timezone.now().isoformat(),
                    "ownership_verified": True,
                }
            )
            _persist_oracle_delete_state(
                backup, delete_state, witness, backup.unique_id
            )
            return UtilBackup.Status.IN_PROGRESS

        backup.ensure_execution_fence()
        # This checkpoint intentionally precedes the provider mutation.  If the
        # worker dies before or during DELETE, the next worker polls and never
        # blindly replays the non-idempotent provider request.  The row lock also
        # elects one concurrent API/task caller as the only DELETE issuer.
        delete_state, claimed = _begin_oracle_delete(
            backup, delete_state, witness, backup.unique_id
        )
        if not claimed:
            return UtilBackup.Status.IN_PROGRESS
        delete = (
            self.client.delete_boot_volume_backup
            if self.volume_type == "boot"
            else self.client.delete_volume_backup
        )
        try:
            response = delete(**parameter)
            _validate_success_response(response, accepted=(200, 202, 204), mutation=True)
        except Exception as error:
            classified = classify_oracle_error(error, mutation=True)
            if classified.code == "PROVIDER_NOT_FOUND":
                return _oracle_delete_absence(
                    backup, delete_state, witness, backup.unique_id
                )
            if not classified.retryable and not classified.unknown_outcome:
                _oracle_delete_rejected(
                    backup, delete_state, witness, backup.unique_id, classified
                )
            raise classified from error
        return _oracle_delete_accepted(
            backup, delete_state, witness, backup.unique_id
        )


@dataclass(frozen=True)
class OracleComputeWitness:
    marker: str
    source_id: str
    compartment_id: str
    request_token: str

    def as_dict(self):
        return {
            "provider": ORACLE_PROVIDER,
            "marker": self.marker,
            "source_id": self.source_id,
            "resource_type": "compute_image",
            "compartment_id": self.compartment_id,
            "request_token": self.request_token,
        }


class OracleComputeAdapter:
    """Exact OCI custom-image backup support for compute instances.

    The current shared model does not route Oracle compute nodes here yet.  This
    provider-only implementation is ready for that small shared wiring change.
    """

    def __init__(self, node_or_integration, *, client=None):
        if hasattr(node_or_integration, "node"):
            self.integration = node_or_integration
            self.node = node_or_integration.node
        else:
            self.node = node_or_integration
            self.integration = node_or_integration.oracle
        if self.node.type != CoreNode.Type.CLOUD:
            raise OracleProviderError("PROVIDER_UNSUPPORTED_RESOURCE")
        self.source_id = _require_oci_ocid(self.integration.unique_id, "instance")
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import oci

            self._client = oci.core.ComputeClient(
                self.node.connection.auth_oracle.get_verified_client(),
                **_oci_client_kwargs(),
            )
        return self._client

    def _get_source(self):
        try:
            response = _validate_success_response(
                self.client.get_instance(instance_id=self.source_id),
                accepted=(200,),
            )
        except Exception as error:
            raise classify_oracle_error(error) from error
        source = _resource_dict(_response_data(response))
        if (
            str(source.get("id") or "") != self.source_id
            or not str(source.get("compartment_id") or "").strip()
        ):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        if str(source.get("lifecycle_state") or "").upper() not in {
            "RUNNING",
            "STOPPED",
        }:
            raise OracleProviderError("PROVIDER_FAILED")
        return source

    def witness(self, backup, source=None):
        source = source or self._get_source()
        marker = str(backup.uuid_str or "").strip()
        if not marker:
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
        return OracleComputeWitness(
            marker=marker,
            source_id=self.source_id,
            compartment_id=str(source.get("compartment_id") or ""),
            request_token=oracle_retry_token(marker),
        )

    @staticmethod
    def _tags(resource):
        tags = resource.get("freeform_tags")
        return (
            {str(key): str(value) for key, value in tags.items()}
            if isinstance(tags, dict)
            else {}
        )

    def _owns_image(self, resource, witness, *, resource_id=None):
        resource = _resource_dict(resource)
        tags = self._tags(resource)
        return bool(
            resource.get("id")
            and (not resource_id or str(resource["id"]) == str(resource_id))
            and str(resource.get("display_name") or "") == witness.marker
            and str(resource.get("compartment_id") or "")
            == witness.compartment_id
            and tags.get(ORACLE_BACKUP_TAG) == witness.marker
            and tags.get(ORACLE_SOURCE_TAG) == witness.source_id
            and tags.get(ORACLE_KIND_TAG) == "compute_image"
            and tags.get(ORACLE_REQUEST_TAG) == witness.request_token
        )

    def find_owned_image(self, witness):
        try:
            images = [
                _resource_dict(item)
                for item in iter_oracle_pages(
                    self.client.list_images,
                    compartment_id=witness.compartment_id,
                    display_name=witness.marker,
                )
            ]
        except Exception as error:
            raise classify_oracle_error(error) from error
        exact = [item for item in images if self._owns_image(item, witness)]
        if len(exact) > 1:
            raise OracleProviderError("PROVIDER_DUPLICATE_MATCH")
        if any(item not in exact for item in images):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        return exact[0] if exact else None

    @staticmethod
    def _metadata(resource, witness, *, adopted):
        resource = _resource_dict(resource)
        return {
            "provider": ORACLE_PROVIDER,
            "witness": witness.as_dict(),
            "resource": {
                key: resource.get(key)
                for key in (
                    "id",
                    "display_name",
                    "lifecycle_state",
                    "compartment_id",
                    "size_in_mbs",
                )
                if resource.get(key) is not None
            },
            "adopted": bool(adopted),
            "outcome_unknown": False,
            "ownership_verified": True,
        }

    def _record(self, backup, resource, witness, *, adopted):
        resource = _resource_dict(resource)
        if not self._owns_image(resource, witness):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        backup.ensure_execution_fence()
        backup.unique_id = str(resource["id"])
        size_mbs = resource.get("size_in_mbs")
        backup.size_gigabytes = (
            float(size_mbs) / 1024 if size_mbs not in (None, "") else None
        )
        backup.set_provider_metadata(self._metadata(resource, witness, adopted=adopted))
        backup.save(update_fields=["unique_id", "size_gigabytes", "metadata", "modified"])
        state = backup.record_provider_reference(
            resource_id=backup.unique_id,
            idempotency_key=witness.request_token,
            provider_status=str(resource.get("lifecycle_state") or "accepted"),
            metadata=self._metadata(resource, witness, adopted=adopted),
        )
        if state is None:
            raise OracleProviderError("WORKER_LEASE_LOST")
        try:
            from apps.console.backup.models import CoreBackupExecution

            backup.set_reconciliation_state(
                reconciliation_state=CoreBackupExecution.ReconciliationState.RESOLVED,
                reason="oracle_image_adopted" if adopted else "oracle_image_created",
                metadata={
                    "provider": ORACLE_PROVIDER,
                    "resource_id": backup.unique_id,
                },
            )
        except ImportError:
            pass
        return backup.unique_id

    def create_or_adopt_backup(self, backup):
        import oci

        witness = self.witness(backup)
        existing = self.find_owned_image(witness)
        if existing:
            return self._record(backup, existing, witness, adopted=True)
        state = backup.record_provider_reference(
            idempotency_key=witness.request_token,
            provider_status="create_intent",
            metadata=_create_intent_metadata(backup, witness),
        )
        if state is None:
            raise OracleProviderError("WORKER_LEASE_LOST")
        details = oci.core.models.CreateImageDetails(
            compartment_id=witness.compartment_id,
            instance_id=witness.source_id,
            display_name=witness.marker,
            freeform_tags={
                ORACLE_BACKUP_TAG: witness.marker,
                ORACLE_SOURCE_TAG: witness.source_id,
                ORACLE_KIND_TAG: "compute_image",
                ORACLE_REQUEST_TAG: witness.request_token,
            },
        )
        backup.ensure_execution_fence()
        try:
            response = _validate_success_response(
                self.client.create_image(
                    create_image_details=details,
                    opc_retry_token=witness.request_token,
                ),
                accepted=(200, 202),
                mutation=True,
            )
        except Exception as error:
            classified = classify_oracle_error(error, mutation=True)
            if classified.unknown_outcome or classified.retryable:
                candidate = self.find_owned_image(witness)
                if candidate:
                    return self._record(backup, candidate, witness, adopted=True)
            raise classified from error
        resource = _resource_dict(_response_data(response))
        if not self._owns_image(resource, witness):
            candidate = self.find_owned_image(witness)
            if candidate:
                return self._record(backup, candidate, witness, adopted=True)
            raise OracleProviderError(
                "PROVIDER_CREATE_OUTCOME_UNKNOWN",
                retryable=True,
                unknown_outcome=True,
            )
        from apps._tasks.integration.oracle_acceptance import (
            maybe_fault_after_accepted_backup,
        )

        maybe_fault_after_accepted_backup(
            backup,
            resource_type="compute_image",
            request_token=witness.request_token,
            provider_resource_id=str(resource.get("id") or ""),
            request_metadata=self._metadata(resource, witness, adopted=False),
        )
        return self._record(backup, resource, witness, adopted=False)

    def poll_backup(self, backup):
        from apps.console.backup.models import (
            _provider_failed,
            _provider_in_progress,
            _record_provider_outcome,
        )

        state = backup.get_execution_state(create=False)
        raw = dict(state.provider_metadata or {}).get("witness") if state else None
        if not isinstance(raw, dict):
            return _provider_failed(
                backup,
                provider=ORACLE_PROVIDER,
                state="missing_witness",
                code="PROVIDER_RECONCILIATION_REQUIRED",
            )
        if (
            not state
            or str(state.provider_resource_id or "")
            != str(backup.unique_id or "")
            or str(state.provider_idempotency_key or "")
            != str(raw.get("request_token") or "")
        ):
            return _provider_failed(
                backup,
                provider=ORACLE_PROVIDER,
                state="durable_pointer_mismatch",
                code="PROVIDER_RECONCILIATION_REQUIRED",
            )
        try:
            witness = OracleComputeWitness(
                marker=str(raw["marker"]),
                source_id=str(raw["source_id"]),
                compartment_id=str(raw["compartment_id"]),
                request_token=str(raw["request_token"]),
            )
            response = _validate_success_response(
                self.client.get_image(image_id=backup.unique_id), accepted=(200,)
            )
            image = _resource_dict(_response_data(response))
        except Exception as error:
            classified = classify_oracle_error(error)
            backup.record_execution_error(
                code=classified.code,
                retry_at=(
                    timezone.now() + dt.timedelta(seconds=classified.retry_after)
                    if classified.retryable
                    else None
                ),
                retryable=classified.retryable,
            )
            return (
                UtilBackup.Status.IN_PROGRESS
                if classified.retryable
                else UtilBackup.Status.FAILED
            )
        if not self._owns_image(image, witness, resource_id=backup.unique_id):
            return _provider_failed(
                backup,
                provider=ORACLE_PROVIDER,
                state="ownership_mismatch",
                code="PROVIDER_OWNERSHIP_MISMATCH",
            )
        lifecycle = str(image.get("lifecycle_state") or "").upper()
        if lifecycle == "AVAILABLE":
            _record_provider_outcome(
                backup,
                provider=ORACLE_PROVIDER,
                category="complete",
                provider_status=lifecycle,
                resource_id=backup.unique_id,
            )
            return UtilBackup.Status.COMPLETE
        if lifecycle in {"DISABLED", "DELETED"}:
            return _provider_failed(
                backup, provider=ORACLE_PROVIDER, state=lifecycle
            )
        if not lifecycle:
            return _provider_failed(
                backup,
                provider=ORACLE_PROVIDER,
                state="missing_lifecycle",
                code="PROVIDER_MALFORMED_RESPONSE",
            )
        return _provider_in_progress(
            backup,
            provider=ORACLE_PROVIDER,
            state=lifecycle,
            resource_id=backup.unique_id,
        )

    def delete_backup(self, backup):
        """Reconcile OCI image deletion until the provider proves absence."""

        backup.ensure_execution_fence()
        execution = backup.get_execution_state(create=False)
        provider_metadata = dict(execution.provider_metadata or {}) if execution else {}
        raw = provider_metadata.get("witness")
        if not isinstance(raw, dict):
            raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
        if (
            not execution
            or str(execution.provider_resource_id or "")
            != str(backup.unique_id or "")
            or str(execution.provider_idempotency_key or "")
            != str(raw.get("request_token") or "")
        ):
            raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
        try:
            witness = OracleComputeWitness(
                marker=str(raw["marker"]),
                source_id=str(raw["source_id"]),
                compartment_id=str(raw["compartment_id"]),
                request_token=str(raw["request_token"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE") from error
        delete_state, provider_metadata = _oracle_delete_state(
            backup, witness, backup.unique_id
        )
        if delete_state.get("absence_verified"):
            return "already_absent"
        try:
            response = _validate_success_response(
                self.client.get_image(image_id=backup.unique_id), accepted=(200,)
            )
        except Exception as error:
            classified = classify_oracle_error(error)
            if classified.code == "PROVIDER_NOT_FOUND" and (
                delete_state.get("ownership_verified")
                or provider_metadata.get("ownership_verified")
            ):
                return _oracle_delete_absence(
                    backup, delete_state, witness, backup.unique_id
                )
            raise classified from error
        image = _resource_dict(_response_data(response))
        if not self._owns_image(image, witness, resource_id=backup.unique_id):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")

        if delete_state.get("delete_started"):
            delete_state.update(
                {
                    "phase": "delete_reconciling",
                    "last_observed_at": timezone.now().isoformat(),
                    "ownership_verified": True,
                }
            )
            _persist_oracle_delete_state(
                backup, delete_state, witness, backup.unique_id
            )
            return UtilBackup.Status.IN_PROGRESS

        backup.ensure_execution_fence()
        delete_state, claimed = _begin_oracle_delete(
            backup, delete_state, witness, backup.unique_id
        )
        if not claimed:
            return UtilBackup.Status.IN_PROGRESS
        try:
            response = self.client.delete_image(image_id=backup.unique_id)
            _validate_success_response(response, accepted=(200, 202, 204), mutation=True)
        except Exception as error:
            classified = classify_oracle_error(error, mutation=True)
            if classified.code == "PROVIDER_NOT_FOUND":
                return _oracle_delete_absence(
                    backup, delete_state, witness, backup.unique_id
                )
            if not classified.retryable and not classified.unknown_outcome:
                _oracle_delete_rejected(
                    backup, delete_state, witness, backup.unique_id, classified
                )
            raise classified from error
        return _oracle_delete_accepted(
            backup, delete_state, witness, backup.unique_id
        )


def oracle_backup_adapter(node_or_integration, *, client=None):
    node = (
        node_or_integration.node
        if hasattr(node_or_integration, "node")
        else node_or_integration
    )
    if node.type == CoreNode.Type.CLOUD:
        return OracleComputeAdapter(node_or_integration, client=client)
    return OracleVolumeAdapter(node_or_integration, client=client)


def _oracle_clients(auth, *, identity=None, compute=None, block=None):
    import oci

    config = auth.get_verified_client()
    return (
        identity
        or oci.identity.IdentityClient(config, **_oci_client_kwargs()),
        compute or oci.core.ComputeClient(config, **_oci_client_kwargs()),
        block or oci.core.BlockstorageClient(config, **_oci_client_kwargs()),
    )


def _active_compartment_ids(auth, identity_client):
    """Return the tenancy root plus every accessible active child exactly once."""

    ids = [str(auth.tenancy)]
    maximum = _bounded_positive_setting(
        "ORACLE_MAX_COMPARTMENTS", DEFAULT_ORACLE_MAX_COMPARTMENTS, 10_000
    )
    try:
        compartments = iter_oracle_pages(
            identity_client.list_compartments,
            compartment_id=str(auth.tenancy),
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE",
        )
        for raw in compartments:
            compartment = _resource_dict(raw)
            compartment_id = str(compartment.get("id") or "").strip()
            lifecycle = str(compartment.get("lifecycle_state") or "").upper()
            if compartment_id and lifecycle == "ACTIVE" and compartment_id not in ids:
                if len(ids) >= maximum:
                    raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
                ids.append(compartment_id)
    except Exception as error:
        raise classify_oracle_error(error) from error
    return ids


def _oracle_discovery_item(resource, object_type, *, volume_type=None):
    resource = _resource_dict(resource)
    resource_id = str(resource.get("id") or "").strip()
    compartment_id = str(resource.get("compartment_id") or "").strip()
    availability_domain = str(resource.get("availability_domain") or "").strip()
    lifecycle = str(resource.get("lifecycle_state") or "").upper()
    if not resource_id or not compartment_id or not availability_domain or not lifecycle:
        raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
    if lifecycle in {"TERMINATED", "TERMINATING"}:
        return None
    payload = {
        "id": resource_id,
        "_bs_unique_id": resource_id,
        "_bs_name": str(resource.get("display_name") or resource_id),
        "_bs_region": availability_domain,
        "_bs_size": None,
        "_bs_resource_type": object_type,
        "_bs_compartment_id": compartment_id,
        "_bs_availability_domain": availability_domain,
        "_bs_lifecycle_state": lifecycle,
    }
    if object_type == "cloud":
        payload["_bs_shape"] = resource.get("shape")
    else:
        if volume_type not in {"boot", "block"}:
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
        payload["_bs_size"] = resource.get("size_in_gbs")
        payload["_bs_vol_type"] = volume_type
    return payload


def discover_oracle_objects(
    auth,
    object_type,
    *,
    identity_client=None,
    compute_client=None,
    block_storage_client=None,
):
    """Discover OCI compute instances or volumes with bounded cursor scans."""

    object_type = str(object_type or "cloud").casefold()
    if object_type not in {"cloud", "volume"}:
        raise OracleProviderError("PROVIDER_UNSUPPORTED_RESOURCE")
    identity_client, compute_client, block_storage_client = _oracle_clients(
        auth,
        identity=identity_client,
        compute=compute_client,
        block=block_storage_client,
    )
    compartment_ids = _active_compartment_ids(auth, identity_client)
    discovered = {}
    observed = 0
    maximum = _bounded_positive_setting(
        "ORACLE_MAX_ITEMS", DEFAULT_ORACLE_MAX_ITEMS, 100_000
    )
    try:
        for compartment_id in compartment_ids:
            if object_type == "cloud":
                for raw in iter_oracle_pages(
                    compute_client.list_instances,
                    compartment_id=compartment_id,
                ):
                    observed += 1
                    if observed > maximum:
                        raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
                    item = _oracle_discovery_item(raw, "cloud")
                    if item is None:
                        continue
                    if item["_bs_compartment_id"] != compartment_id:
                        raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
                    if item["id"] in discovered:
                        raise OracleProviderError("PROVIDER_DUPLICATE_MATCH")
                    discovered[item["id"]] = item
                continue

            for volume_type, method in (
                ("boot", block_storage_client.list_boot_volumes),
                ("block", block_storage_client.list_volumes),
            ):
                for raw in iter_oracle_pages(method, compartment_id=compartment_id):
                    observed += 1
                    if observed > maximum:
                        raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
                    item = _oracle_discovery_item(
                        raw, "volume", volume_type=volume_type
                    )
                    if item is None:
                        continue
                    if item["_bs_compartment_id"] != compartment_id:
                        raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
                    if item["id"] in discovered:
                        raise OracleProviderError("PROVIDER_DUPLICATE_MATCH")
                    discovered[item["id"]] = item
    except Exception as error:
        raise classify_oracle_error(error) from error
    return list(discovered.values())


def discover_exact_oracle_object(auth, object_type, resource_id, **clients):
    """Return one provider-authoritative UI linking payload by immutable OCID."""

    resource_id = str(resource_id or "").strip()
    if not resource_id:
        raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
    object_type = str(object_type or "").casefold()
    try:
        if object_type == "cloud" and resource_id.startswith("ocid1.instance."):
            client = clients.get("compute_client")
            if client is None:
                import oci

                client = oci.core.ComputeClient(
                    auth.get_verified_client(), **_oci_client_kwargs()
                )
            response = _validate_success_response(
                client.get_instance(instance_id=resource_id), accepted=(200,)
            )
            item = _oracle_discovery_item(_response_data(response), "cloud")
        elif object_type == "volume" and resource_id.startswith("ocid1.bootvolume."):
            client = clients.get("block_storage_client")
            if client is None:
                import oci

                client = oci.core.BlockstorageClient(
                    auth.get_verified_client(), **_oci_client_kwargs()
                )
            response = _validate_success_response(
                client.get_boot_volume(boot_volume_id=resource_id), accepted=(200,)
            )
            item = _oracle_discovery_item(
                _response_data(response), "volume", volume_type="boot"
            )
        elif object_type == "volume" and resource_id.startswith("ocid1.volume."):
            client = clients.get("block_storage_client")
            if client is None:
                import oci

                client = oci.core.BlockstorageClient(
                    auth.get_verified_client(), **_oci_client_kwargs()
                )
            response = _validate_success_response(
                client.get_volume(volume_id=resource_id), accepted=(200,)
            )
            item = _oracle_discovery_item(
                _response_data(response), "volume", volume_type="block"
            )
        else:
            raise OracleProviderError("PROVIDER_UNSUPPORTED_RESOURCE")
    except Exception as error:
        raise classify_oracle_error(error) from error
    if item is None:
        raise OracleProviderError("PROVIDER_NOT_FOUND")
    if item["_bs_unique_id"] != resource_id:
        raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
    try:
        identity_client = clients.get("identity_client")
        if identity_client is None:
            import oci

            identity_client = oci.identity.IdentityClient(
                auth.get_verified_client(), **_oci_client_kwargs()
            )
        allowed_compartments = set(_active_compartment_ids(auth, identity_client))
    except Exception as error:
        raise classify_oracle_error(error) from error
    if item["_bs_compartment_id"] not in allowed_compartments:
        raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
    return item


@dataclass(frozen=True)
class OracleRestoreWitness:
    marker: str
    source_backup_id: str
    source_id: str
    target_type: str
    target_name: str
    compartment_id: str
    availability_domain: str
    request_token: str

    def as_dict(self):
        return {
            "provider": ORACLE_PROVIDER,
            "marker": self.marker,
            "source_backup_id": self.source_backup_id,
            "source_id": self.source_id,
            "target_type": self.target_type,
            "target_name": self.target_name,
            "compartment_id": self.compartment_id,
            "availability_domain": self.availability_domain,
            "request_token": self.request_token,
        }


class OracleRestoreAdapter:
    """Crash-safe Oracle compute/volume fork restore implementation.

    This adapter is deliberately provider-only.  ``CoreOracle.restore_snapshot``
    and ``CoreOracle.check_restore`` still need to delegate to it from the shared
    model before production traffic uses these methods.
    """

    def __init__(
        self,
        node_or_integration,
        *,
        compute_client=None,
        block_storage_client=None,
    ):
        if hasattr(node_or_integration, "node"):
            self.integration = node_or_integration
            self.node = node_or_integration.node
        else:
            self.node = node_or_integration
            self.integration = node_or_integration.oracle
        self._compute_client = compute_client
        self._block_storage_client = block_storage_client
        if self.node.type == CoreNode.Type.CLOUD:
            self.target_type = "instance"
        elif self.node.type == CoreNode.Type.VOLUME:
            volume_type = str(
                (self.integration.metadata or {}).get("_bs_vol_type") or ""
            ).casefold()
            if volume_type not in {"boot", "block"}:
                raise OracleProviderError("PROVIDER_UNSUPPORTED_RESOURCE")
            self.target_type = "boot_volume" if volume_type == "boot" else "volume"
        else:
            raise OracleProviderError("PROVIDER_UNSUPPORTED_RESOURCE")
        self.source_id = _require_oci_ocid(
            self.integration.unique_id,
            "instance"
            if self.target_type == "instance"
            else "bootvolume"
            if self.target_type == "boot_volume"
            else "volume",
        )

    @property
    def compute_client(self):
        if self._compute_client is None:
            import oci

            self._compute_client = oci.core.ComputeClient(
                self.node.connection.auth_oracle.get_verified_client(),
                **_oci_client_kwargs(),
            )
        return self._compute_client

    @property
    def block_storage_client(self):
        if self._block_storage_client is None:
            import oci

            self._block_storage_client = oci.core.BlockstorageClient(
                self.node.connection.auth_oracle.get_verified_client(),
                **_oci_client_kwargs(),
            )
        return self._block_storage_client

    def _source_backup(self, backup):
        """Read and verify the immutable provider backup before restore."""

        execution = backup.get_execution_state(create=False)
        metadata = dict(execution.provider_metadata or {}) if execution else {}
        raw_witness = metadata.get("witness")
        if not isinstance(raw_witness, dict):
            raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
        if (
            not execution
            or str(execution.provider_resource_id or "")
            != str(backup.unique_id or "")
            or str(execution.provider_idempotency_key or "")
            != str(raw_witness.get("request_token") or "")
        ):
            raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
        if self.target_type == "instance":
            _require_oci_ocid(backup.unique_id, "image")
            if (
                str(raw_witness.get("resource_type") or "") != "compute_image"
                or str(raw_witness.get("source_id") or "") != self.source_id
            ):
                raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
            try:
                response = _validate_success_response(
                    self.compute_client.get_image(image_id=backup.unique_id),
                    accepted=(200,),
                )
            except Exception as error:
                raise classify_oracle_error(error) from error
            resource = _resource_dict(_response_data(response))
            witness = OracleComputeWitness(
                marker=str(raw_witness.get("marker") or ""),
                source_id=str(raw_witness.get("source_id") or ""),
                compartment_id=str(raw_witness.get("compartment_id") or ""),
                request_token=str(raw_witness.get("request_token") or ""),
            )
            if not OracleComputeAdapter(
                self.integration, client=self.compute_client
            )._owns_image(resource, witness, resource_id=backup.unique_id):
                raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
            if str(resource.get("lifecycle_state") or "").upper() != "AVAILABLE":
                raise OracleProviderError("PROVIDER_FAILED")
            return resource, raw_witness

        volume_type = "boot" if self.target_type == "boot_volume" else "block"
        _require_oci_ocid(
            backup.unique_id,
            "bootvolumebackup" if volume_type == "boot" else "volumebackup",
        )
        if (
            str(raw_witness.get("volume_type") or "") != volume_type
            or str(raw_witness.get("source_id") or "") != self.source_id
        ):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        method = (
            self.block_storage_client.get_boot_volume_backup
            if volume_type == "boot"
            else self.block_storage_client.get_volume_backup
        )
        parameter = (
            {"boot_volume_backup_id": backup.unique_id}
            if volume_type == "boot"
            else {"volume_backup_id": backup.unique_id}
        )
        try:
            response = _validate_success_response(method(**parameter), accepted=(200,))
        except Exception as error:
            raise classify_oracle_error(error) from error
        resource = _resource_dict(_response_data(response))
        witness = OracleBackupWitness(
            marker=str(raw_witness.get("marker") or ""),
            source_id=str(raw_witness.get("source_id") or ""),
            volume_type=str(raw_witness.get("volume_type") or ""),
            compartment_id=str(raw_witness.get("compartment_id") or ""),
            request_token=str(raw_witness.get("request_token") or ""),
        )
        if not OracleVolumeAdapter(
            self.integration, client=self.block_storage_client
        )._owns_backup(resource, witness, resource_id=backup.unique_id):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        if str(resource.get("lifecycle_state") or "").upper() != "AVAILABLE":
            raise OracleProviderError("PROVIDER_FAILED")
        return resource, raw_witness

    @staticmethod
    def _target_tags(witness):
        return {
            ORACLE_RESTORE_TAG: witness.marker,
            ORACLE_RESTORE_SOURCE_TAG: witness.source_backup_id,
            ORACLE_RESTORE_ORIGIN_TAG: witness.source_id,
            ORACLE_KIND_TAG: witness.target_type,
            ORACLE_REQUEST_TAG: witness.request_token,
        }

    @classmethod
    def _owns_target(cls, resource, witness, *, resource_id=None):
        resource = _resource_dict(resource)
        tags = resource.get("freeform_tags")
        tags = (
            {str(key): str(value) for key, value in tags.items()}
            if isinstance(tags, dict)
            else {}
        )
        source_details = resource.get("source_details")
        source_details = source_details if isinstance(source_details, dict) else {}
        # Instances are restored from an image, but restored boot/block volumes
        # can also expose the *original* image_id alongside source_details for
        # the exact volume backup.  Binding a volume restore to that image would
        # reject a correctly created target (or, worse, prove the wrong source).
        # Select the provider source according to the target type.
        if witness.target_type == "instance":
            provider_source = resource.get("image_id") or source_details.get(
                "image_id"
            )
        else:
            source_keys = (
                ("boot_volume_backup_id", "id")
                if witness.target_type == "boot_volume"
                else ("volume_backup_id", "id")
            )
            provider_source = next(
                (
                    source_details.get(key)
                    for key in source_keys
                    if source_details.get(key)
                ),
                None,
            )
        return bool(
            resource.get("id")
            and (not resource_id or str(resource["id"]) == str(resource_id))
            and str(resource.get("display_name") or "") == witness.target_name
            and str(resource.get("compartment_id") or "")
            == witness.compartment_id
            and (
                not witness.availability_domain
                or str(resource.get("availability_domain") or "")
                == witness.availability_domain
            )
            and tags.get(ORACLE_RESTORE_TAG) == witness.marker
            and tags.get(ORACLE_RESTORE_SOURCE_TAG) == witness.source_backup_id
            and tags.get(ORACLE_RESTORE_ORIGIN_TAG) == witness.source_id
            and tags.get(ORACLE_KIND_TAG) == witness.target_type
            and tags.get(ORACLE_REQUEST_TAG) == witness.request_token
            and str(provider_source or "") == witness.source_backup_id
        )

    def _witness(self, backup, restore, source_backup):
        from apps.console.node.models import _prepare_cloud_restore, _restore_params

        marker, params = _prepare_cloud_restore(
            restore,
            provider=ORACLE_PROVIDER,
            source_id=backup.unique_id,
            target_kind=self.target_type,
            target_name=restore.name,
        )
        compartment_id = str(
            params.get("compartment_id")
            or source_backup.get("compartment_id")
            or ""
        ).strip()
        source_compartment_id = _require_oci_ocid(
            source_backup.get("compartment_id"), "compartment"
        )
        if compartment_id != source_compartment_id:
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        availability_domain = str(params.get("availability_domain") or "").strip()
        if not compartment_id:
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
        if self.target_type in {"boot_volume", "volume", "instance"} and not availability_domain:
            source_metadata = self.integration.metadata or {}
            availability_domain = str(
                source_metadata.get("_bs_availability_domain")
                or source_metadata.get("availability_domain")
                or ""
            ).strip()
        if not availability_domain:
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
        request_token = oracle_retry_token(
            f"restore:{getattr(restore, 'correlation_id', None) or restore.pk}"
        )
        witness = OracleRestoreWitness(
            marker=marker,
            source_backup_id=str(backup.unique_id),
            source_id=self.source_id,
            target_type=self.target_type,
            target_name=str(restore.name),
            compartment_id=compartment_id,
            availability_domain=availability_domain,
            request_token=request_token,
        )
        params = _restore_params(restore)
        existing = params.get("_bs_oracle_restore")
        if existing is not None and existing != witness.as_dict():
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        params["_bs_oracle_restore"] = witness.as_dict()
        restore.params = params
        restore.save(update_fields=["params", "modified"])
        return witness

    @staticmethod
    def _witness_from_restore(restore):
        params = restore.params if isinstance(restore.params, dict) else {}
        raw = params.get("_bs_oracle_restore")
        if not isinstance(raw, dict):
            raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
        try:
            return OracleRestoreWitness(
                marker=str(raw["marker"]),
                source_backup_id=str(raw["source_backup_id"]),
                source_id=str(raw["source_id"]),
                target_type=str(raw["target_type"]),
                target_name=str(raw["target_name"]),
                compartment_id=str(raw["compartment_id"]),
                availability_domain=str(raw["availability_domain"]),
                request_token=str(raw["request_token"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE") from error

    def find_owned_target(self, witness):
        if witness.target_type == "instance":
            method = self.compute_client.list_instances
            request = {
                "compartment_id": witness.compartment_id,
                "display_name": witness.target_name,
            }
        elif witness.target_type == "boot_volume":
            method = self.block_storage_client.list_boot_volumes
            # OCI does not support display_name on list_boot_volumes.  Scan the
            # bounded compartment/AD inventory and filter locally.
            request = {
                "compartment_id": witness.compartment_id,
                "availability_domain": witness.availability_domain,
            }
        else:
            method = self.block_storage_client.list_volumes
            request = {
                "compartment_id": witness.compartment_id,
                "availability_domain": witness.availability_domain,
                "display_name": witness.target_name,
            }
        try:
            resources = [
                _resource_dict(item) for item in iter_oracle_pages(method, **request)
            ]
        except Exception as error:
            raise classify_oracle_error(error) from error
        named = [
            item
            for item in resources
            if str(item.get("display_name") or "") == witness.target_name
        ]
        exact = [item for item in named if self._owns_target(item, witness)]
        if len(exact) > 1:
            raise OracleProviderError("PROVIDER_DUPLICATE_MATCH")
        if any(item not in exact for item in named):
            raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        return exact[0] if exact else None

    def _create(self, witness, restore):
        import oci

        tags = self._target_tags(witness)
        if witness.target_type == "instance":
            params = restore.params or {}
            shape = str(params.get("shape") or "").strip()
            subnet_id = _require_oci_ocid(params.get("subnet_id"), "subnet")
            if not _OCI_SHAPE.fullmatch(shape):
                raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
            assign_public_ip = params.get("assign_public_ip", False)
            if not isinstance(assign_public_ip, bool):
                raise OracleProviderError("PROVIDER_MALFORMED_RESPONSE")
            details = oci.core.models.LaunchInstanceDetails(
                compartment_id=witness.compartment_id,
                availability_domain=witness.availability_domain,
                display_name=witness.target_name,
                shape=shape,
                freeform_tags=tags,
                create_vnic_details=oci.core.models.CreateVnicDetails(
                    assign_public_ip=assign_public_ip,
                    display_name=f"{witness.target_name}-vnic"[:255],
                    freeform_tags=tags,
                    subnet_id=subnet_id,
                ),
                source_details=oci.core.models.InstanceSourceViaImageDetails(
                    image_id=witness.source_backup_id
                ),
            )
            return self.compute_client.launch_instance(
                launch_instance_details=details,
                opc_retry_token=witness.request_token,
            )
        if witness.target_type == "boot_volume":
            details = oci.core.models.CreateBootVolumeDetails(
                compartment_id=witness.compartment_id,
                availability_domain=witness.availability_domain,
                display_name=witness.target_name,
                freeform_tags=tags,
                source_details=oci.core.models.BootVolumeSourceFromBootVolumeBackupDetails(
                    id=witness.source_backup_id
                ),
            )
            return self.block_storage_client.create_boot_volume(
                create_boot_volume_details=details,
                opc_retry_token=witness.request_token,
            )
        details = oci.core.models.CreateVolumeDetails(
            compartment_id=witness.compartment_id,
            availability_domain=witness.availability_domain,
            display_name=witness.target_name,
            freeform_tags=tags,
            source_details=oci.core.models.VolumeSourceFromVolumeBackupDetails(
                id=witness.source_backup_id
            ),
        )
        return self.block_storage_client.create_volume(
            create_volume_details=details,
            opc_retry_token=witness.request_token,
        )

    @staticmethod
    def _record_retryable_preflight(restore, error):
        """Persist a retryable read failure without claiming a create was sent."""

        from apps.console.node.models import _restore_status

        params = dict(restore.params or {})
        params["_bs_create_outcome_unknown"] = False
        params["_bs_last_error_code"] = error.code
        params["_bs_last_error_category"] = "retryable_preflight"
        restore.params = params
        restore.status = _restore_status("IN_PROGRESS")
        restore.operation_phase = restore.OperationPhase.RECONCILING
        restore.last_error_code = error.code
        restore.error = str(error)
        restore.next_retry_at = timezone.now() + dt.timedelta(
            seconds=error.retry_after
        )
        restore.save(
            update_fields=[
                "params",
                "status",
                "operation_phase",
                "last_error_code",
                "error",
                "next_retry_at",
                "modified",
            ]
        )
        return _restore_status("IN_PROGRESS")

    def restore_snapshot(self, backup, restore):
        from apps.console.node.models import (
            _restore_adopt,
            _restore_begin_mutation,
            _restore_observe_zero_match,
            _restore_resolve_reconciliation,
            _restore_safe_failure,
            _restore_status,
            _restore_unknown,
        )

        mutation_started = bool(
            isinstance(restore.params, dict)
            and restore.params.get("_bs_mutation_started_at")
        )
        try:
            source_backup, _source_witness = self._source_backup(backup)
            witness = self._witness(backup, restore, source_backup)
            if restore.resource_id:
                return _restore_status("IN_PROGRESS")
            candidate = self.find_owned_target(witness)
            if candidate:
                _restore_adopt(
                    restore,
                    candidate.get("id"),
                    provider_status=candidate.get("lifecycle_state"),
                    params_update={"_bs_oracle_restore": witness.as_dict()},
                )
                _restore_resolve_reconciliation(restore)
                return _restore_status("IN_PROGRESS")
            if _restore_unknown(restore):
                params = restore.params if isinstance(restore.params, dict) else {}
                started_value = params.get("_bs_mutation_started_at")
                if not started_value:
                    raise OracleProviderError("PROVIDER_RECONCILIATION_REQUIRED")
                started = _parse_provider_timestamp(started_value)
                replay_deadline = started + dt.timedelta(
                    seconds=_retry_token_replay_seconds()
                )
                if timezone.now() >= replay_deadline:
                    return _restore_observe_zero_match(restore)
            else:
                _restore_begin_mutation(restore)
                mutation_started = True
            restore.assert_live_execution_fence()
            response = _validate_success_response(
                self._create(witness, restore),
                accepted=(200, 202),
                mutation=True,
            )
            resource = _resource_dict(_response_data(response))
            if not self._owns_target(resource, witness):
                raise OracleProviderError(
                    "PROVIDER_MALFORMED_RESPONSE", unknown_outcome=True
                )
            from apps._tasks.integration.oracle_acceptance import (
                maybe_fault_after_accepted_restore,
            )

            maybe_fault_after_accepted_restore(
                restore,
                marker=witness.marker,
                resource_type=witness.target_type,
                request_token=witness.request_token,
                provider_resource_id=str(resource.get("id") or ""),
                request_metadata={
                    "provider": ORACLE_PROVIDER,
                    "witness": witness.as_dict(),
                    "resource": {
                        key: resource.get(key)
                        for key in (
                            "id",
                            "display_name",
                            "lifecycle_state",
                            "compartment_id",
                            "availability_domain",
                        )
                        if resource.get(key) is not None
                    },
                },
            )
            _restore_adopt(
                restore,
                resource.get("id"),
                provider_status=resource.get("lifecycle_state"),
                params_update={"_bs_oracle_restore": witness.as_dict()},
            )
            _restore_resolve_reconciliation(restore)
            return _restore_status("IN_PROGRESS")
        except OracleProviderError as error:
            if error.retryable or error.unknown_outcome:
                if not mutation_started and not error.unknown_outcome:
                    return self._record_retryable_preflight(restore, error)
                from apps.console.node.models import _restore_unknown_outcome

                _restore_unknown_outcome(restore, code=error.code)
                return _restore_status("IN_PROGRESS")
            manual = error.code in {
                "PROVIDER_DUPLICATE_MATCH",
                "PROVIDER_MALFORMED_RESPONSE",
                "PROVIDER_OWNERSHIP_MISMATCH",
                "PROVIDER_RECONCILIATION_REQUIRED",
            }
            return _restore_safe_failure(restore, error.code, manual_review=manual)
        except Exception as error:
            classified = classify_oracle_error(error, mutation=mutation_started)
            if classified.retryable or classified.unknown_outcome:
                if not mutation_started and not classified.unknown_outcome:
                    return self._record_retryable_preflight(restore, classified)
                from apps.console.node.models import _restore_unknown_outcome

                _restore_unknown_outcome(restore, code=classified.code)
                return _restore_status("IN_PROGRESS")
            return _restore_safe_failure(
                restore, classified.code, manual_review=False
            )

    def check_restore(self, restore):
        from apps.console.node.models import (
            _restore_observe_zero_match,
            _restore_record_provider_status,
            _restore_safe_failure,
            _restore_status,
        )

        try:
            witness = self._witness_from_restore(restore)
            if witness.target_type != self.target_type:
                raise OracleProviderError("PROVIDER_OWNERSHIP_MISMATCH")
            if witness.target_type == "instance":
                response = self.compute_client.get_instance(
                    instance_id=restore.resource_id
                )
            elif witness.target_type == "boot_volume":
                response = self.block_storage_client.get_boot_volume(
                    boot_volume_id=restore.resource_id
                )
            else:
                response = self.block_storage_client.get_volume(
                    volume_id=restore.resource_id
                )
            _validate_success_response(response, accepted=(200,))
            resource = _resource_dict(_response_data(response))
        except Exception as error:
            classified = classify_oracle_error(error)
            if classified.code == "PROVIDER_NOT_FOUND":
                return _restore_observe_zero_match(
                    restore,
                    provider_error_code="PROVIDER_NOT_FOUND",
                    observation_kind="missing_target",
                )
            if classified.retryable:
                params = dict(restore.params or {})
                params["_bs_last_error_code"] = classified.code
                params["_bs_last_error_category"] = "retryable"
                restore.params = params
                restore.last_error_code = classified.code
                restore.error = str(classified)
                restore.next_retry_at = timezone.now() + dt.timedelta(
                    seconds=classified.retry_after
                )
                restore.save(
                    update_fields=[
                        "params",
                        "last_error_code",
                        "error",
                        "next_retry_at",
                        "modified",
                    ]
                )
                return _restore_status("IN_PROGRESS")
            return _restore_safe_failure(
                restore,
                classified.code,
                manual_review=classified.code
                in {
                    "PROVIDER_DUPLICATE_MATCH",
                    "PROVIDER_MALFORMED_RESPONSE",
                    "PROVIDER_OWNERSHIP_MISMATCH",
                    "PROVIDER_RECONCILIATION_REQUIRED",
                },
            )
        if not self._owns_target(resource, witness, resource_id=restore.resource_id):
            return _restore_safe_failure(
                restore, "PROVIDER_OWNERSHIP_MISMATCH", manual_review=True
            )
        lifecycle = str(resource.get("lifecycle_state") or "").upper()
        _restore_record_provider_status(restore, lifecycle)
        complete_states = (
            {"RUNNING", "STOPPED"}
            if witness.target_type == "instance"
            else {"AVAILABLE"}
        )
        failed_states = (
            {"TERMINATED", "TERMINATING"}
            if witness.target_type == "instance"
            else {"FAULTY", "TERMINATED", "TERMINATING"}
        )
        if lifecycle in complete_states:
            return _restore_status("COMPLETE")
        if lifecycle in failed_states:
            return _restore_safe_failure(restore, "PROVIDER_FAILED")
        if not lifecycle:
            return _restore_safe_failure(
                restore, "PROVIDER_MALFORMED_RESPONSE", manual_review=True
            )
        return _restore_status("IN_PROGRESS")


def create_or_adopt_oracle_backup(node_or_integration, backup, *, client=None):
    """Compatibility callback used by the Oracle Celery task and tests."""

    return oracle_backup_adapter(
        node_or_integration, client=client
    ).create_or_adopt_backup(backup)


@current_app.task(
    name="backup_oracle",
    track_started=True,
    bind=True,
    default_retry_delay=900,
    max_retries=4,
    soft_time_limit=(24 * 3600),
)
def backup_oracle(
    self,
    node_id=None,
    schedule_id=None,
    storage_ids=None,
    notes=None,
    resume=False,
):
    attempt_no = self.request.retries + 1
    schedule_check = None
    if schedule_id:
        backup_type = UtilBackup.Type.SCHEDULED
        if resume or CoreSchedule.objects.filter(
            id=schedule_id, status=CoreSchedule.Status.ACTIVE
        ).exists():
            schedule_check = True
    else:
        backup_type = UtilBackup.Type.ON_DEMAND
        schedule_check = True

    query = Q(id=node_id)
    query &= ~Q(status=CoreNode.Status.DELETE_REQUESTED)
    query &= ~Q(status=CoreNode.Status.PAUSED)
    query &= ~Q(connection__status=CoreConnection.Status.DELETE_REQUESTED)
    query &= ~Q(connection__status=CoreConnection.Status.PAUSED)
    query &= ~Q(connection__account__status=CoreAccount.Status.DELETE_REQUESTED)

    if not CoreNode.objects.filter(query).exists() or not schedule_check:
        return
    node = CoreNode.objects.get(id=node_id)
    try:
        try:
            node.connection.validate()
            adapter = oracle_backup_adapter(node)
            if isinstance(adapter, OracleVolumeAdapter):
                adapter.validate_source()
            else:
                adapter._get_source()
        except Exception:
            # The fenced provider create remains authoritative; validation is a
            # best-effort UX check and cannot create a duplicate operation.
            pass

        backup = node.backup_initiate(
            self.request.id,
            backup_type,
            attempt_no,
            schedule_id,
            storage_ids,
            notes,
        )
        if backup is None:
            return

        if not backup.unique_id:
            from apps._tasks.helper.tasks import run_provider_create

            if run_provider_create(
                backup,
                self.request.id,
                lambda claimed: create_or_adopt_oracle_backup(node, claimed),
            ) is None:
                return

        from apps._tasks.helper.tasks import poll_cloud_backup

        poll_cloud_backup.apply_async(args=[node.id, backup.id], countdown=60)
    except ConnectionValidationFailedError as error:
        node.notify_backup_fail(error, backup_type)
        node.backup_retrying_reset(self.request.id)
        raise self.retry()
    except SoftTimeLimitExceeded as error:
        node.notify_backup_fail(error, backup_type)
        node.backup_timeout_reset(self.request.id)
    except OracleProviderError as error:
        # run_provider_create normally consumes typed provider outcomes. This is
        # the narrow fallback for failures before a backup row can be fenced.
        node.notify_backup_fail(error, backup_type)
        node.backup_retrying_reset(self.request.id)
        if error.retryable:
            raise self.retry(countdown=error.retry_after)
        raise
    except Exception as error:
        safe_error = NodeBackupFailedError(
            node,
            "oracle-provider",
            attempt_no,
            backup_type,
            message="The Oracle Cloud backup request could not be completed.",
        )
        try:
            node.notify_backup_fail(safe_error, backup_type)
            node.backup_retrying_reset(self.request.id)
            raise self.retry() from error
        except MaxRetriesExceededError:
            node.backup_max_retries_reached(self.request.id)
