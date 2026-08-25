"""Transactional outbox for backup requests.

The database row is committed before broker publication.  Publication may be
repeated with the same Celery task id because the worker's row lock, execution
ledger, and provider reconciliation are the idempotency boundary.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta

from celery import current_app
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from sentry_sdk import capture_exception
from backupsheep.source_recovery_policy import (
    RECOVERY_INCOMPLETE_SOURCE_FAMILIES,
    SOURCE_RECOVERY_UNAVAILABLE_MESSAGE,
    source_backup_creation_available,
    require_source_backup_creation,
)


_SAFE_BROKER_ERROR = (
    "The backup request is safely queued and will be dispatched automatically "
    "when the worker broker is available."
)
_SAFE_BROKER_FAILURE = (
    "The backup request could not be published yet and will be retried "
    "automatically."
)
_SAFE_INELIGIBLE_REQUEST = (
    "The backup request was cancelled because its node, connection, or account "
    "is paused, disabled, or being deleted."
)
_DEFINITE_NEGATIVE_PUBLISH_ERRORS = {
    "attributeerror",
    "decodeerror",
    "encodeerror",
    "invalidtaskerror",
    "keyerror",
    "notbounderror",
    "serializernotinstalled",
    "serializationerror",
    "typeerror",
    "valueerror",
}


def _backup_request_ineligible_q():
    """Return the shared query for requests no provider task can start.

    Provider task entry points historically return early for these states.  Keeping
    the same decision at the outbox boundary prevents a durable DISPATCHED row from
    being republished forever after an operator pauses or removes its source.
    """
    from apps.console.account.models import CoreAccount
    from apps.console.connection.models import CoreConnection
    from apps.console.node.models import CoreNode

    ineligible = (
        Q(
            node__status__in=(
                CoreNode.Status.PAUSED,
                CoreNode.Status.PAUSED_MAX_RETRIES,
                CoreNode.Status.DELETE_REQUESTED,
                CoreNode.Status.DELETE_COMPLETED,
            )
        )
        | Q(
            node__connection__status__in=(
                CoreConnection.Status.PAUSED,
                CoreConnection.Status.DELETE_REQUESTED,
            )
        )
        | Q(
            node__connection__account__status__in=(
                CoreAccount.Status.DISABLED,
                CoreAccount.Status.DELETE_REQUESTED,
            )
        )
    )
    unavailable_families = [
        code
        for code in RECOVERY_INCOMPLETE_SOURCE_FAMILIES
        if not source_backup_creation_available(code)
    ]
    if unavailable_families:
        ineligible |= Q(
            node__connection__integration__code__in=unavailable_families
        )
    return ineligible


def _backup_request_ineligible_reason(node):
    """Return a stable internal reason when a request can no longer be run."""
    from apps.console.account.models import CoreAccount
    from apps.console.connection.models import CoreConnection
    from apps.console.node.models import CoreNode

    if node.status in {
        CoreNode.Status.PAUSED,
        CoreNode.Status.PAUSED_MAX_RETRIES,
        CoreNode.Status.DELETE_REQUESTED,
        CoreNode.Status.DELETE_COMPLETED,
    }:
        return "node_ineligible"
    connection = node.connection
    if connection.status in {
        CoreConnection.Status.PAUSED,
        CoreConnection.Status.DELETE_REQUESTED,
    }:
        return "connection_ineligible"
    if connection.account.status in {
        CoreAccount.Status.DISABLED,
        CoreAccount.Status.DELETE_REQUESTED,
    }:
        return "account_ineligible"
    if not source_backup_creation_available(connection.integration.code):
        return "source_recovery_unavailable"
    return None


def _bounded_exponential_delay(base_seconds, attempt, maximum_seconds):
    """Return a bounded, deterministic delay for one outbox attempt.

    The outbox is swept more frequently than many broker outages last.  A
    deterministic backoff is preferable here to random jitter: the database
    row is the coordination point, and the lease already elects one publisher
    when several beat workers run at once.
    """
    try:
        base = max(1, int(base_seconds))
    except (TypeError, ValueError):
        base = 60
    try:
        maximum = max(base, int(maximum_seconds))
    except (TypeError, ValueError):
        maximum = base
    try:
        exponent = max(0, min(int(attempt) - 1, 30))
    except (TypeError, ValueError):
        exponent = 0
    return min(maximum, base * (1 << exponent))


def _failed_publish_delay(attempt):
    return _bounded_exponential_delay(
        getattr(settings, "BACKUP_REQUEST_RETRY_SECONDS", 60),
        attempt,
        getattr(settings, "BACKUP_REQUEST_RETRY_MAX_SECONDS", 15 * 60),
    )


def _claim_timeout(attempt):
    return _bounded_exponential_delay(
        getattr(settings, "BACKUP_REQUEST_CLAIM_TIMEOUT_SECONDS", 5 * 60),
        attempt,
        getattr(settings, "BACKUP_REQUEST_CLAIM_TIMEOUT_MAX_SECONDS", 60 * 60),
    )


def _is_ambiguous_publish_error(error):
    """Whether the broker may have accepted a publish before the error.

    A transport timeout/connection failure is not a negative acknowledgement.
    Retrying it on the short failed-publish interval can create a second
    delivery while the first message is already queued.  Keep this classifier
    deliberately conservative: only explicit serialization/argument failures
    are definite negatives, while transport-layer and unknown failures use the
    longer claim timeout.
    """
    current = error
    seen = set()
    definite_negative = False
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        error_name = current.__class__.__name__.lower()
        module_name = current.__class__.__module__.lower()
        if isinstance(current, (ConnectionError, TimeoutError, OSError)):
            return True
        if error_name in {
            "operationalerror",
            "connectionclosederror",
            "connectionerror",
            "connectionreseterror",
            "brokenpipeerror",
            "channelclosederror",
            "sockettimeout",
            "timeouterror",
        } and any(
            namespace in module_name for namespace in ("kombu", "amqp", "celery")
        ):
            return True
        if module_name.startswith(("kombu.", "amqp.")):
            if error_name not in _DEFINITE_NEGATIVE_PUBLISH_ERRORS:
                return True
        if error_name in _DEFINITE_NEGATIVE_PUBLISH_ERRORS:
            definite_negative = True
        current = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )
    # An unrecognized exception is not proof that RabbitMQ rejected the
    # message. Keep the row conservative unless the exception is explicitly a
    # pre-publish validation/serialization failure.
    return not definite_negative


def _opaque_request_key(node_id, trigger, idempotency_key):
    material = f"backup-request:{int(node_id)}:{trigger}:{idempotency_key}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _normalized_storage_ids(values):
    result = set()
    for value in values or ():
        try:
            identifier = int(value)
        except (TypeError, ValueError):
            continue
        if identifier > 0:
            result.add(identifier)
    return sorted(result)


def create_backup_request(
    *,
    node,
    schedule=None,
    storage_ids=None,
    notes=None,
    requested_by=None,
    trigger="on_demand",
    idempotency_key=None,
):
    """Commit one durable request and best-effort publish it.

    ``idempotency_key`` is hashed before storage so arbitrary client headers never
    become identifiers or log material.  An existing key returns the original row.
    """
    from apps.console.backup.models import CoreBackupRequest

    require_source_backup_creation(node.connection.integration.code)
    idempotency_key = str(idempotency_key or uuid.uuid4())
    request_key = _opaque_request_key(node.pk, trigger, idempotency_key)
    task_id = uuid.uuid5(uuid.NAMESPACE_URL, request_key).hex
    payload = {
        "node_id": int(node.pk),
        "schedule_id": int(schedule.pk) if schedule is not None else None,
        "storage_ids": _normalized_storage_ids(storage_ids),
        "notes": str(notes)[:10000] if notes is not None else None,
        # Once accepted into the outbox, a scheduled delivery remains recoverable
        # even if the schedule is subsequently paused or edited.
        "resume": True,
    }
    with transaction.atomic():
        request, created = CoreBackupRequest.objects.get_or_create(
            request_key=request_key,
            defaults={
                "task_id": task_id,
                "task_name": node.backup_task_name(),
                "node": node,
                "schedule": schedule,
                "requested_by": requested_by,
                "trigger": trigger,
                "payload": payload,
                "next_dispatch_at": timezone.now(),
            },
        )
        if not created and request.node_id != node.pk:
            raise ValueError("Backup request identity is already in use.")

    # A failed/ambiguous publish is intentionally not raised to the caller: the
    # committed outbox row is the acceptance contract and the recovery sweep owns
    # subsequent delivery.
    try:
        # Only the process that created the row gets an immediate publish.  A
        # replay of the same idempotency key must observe the durable schedule;
        # forcing it would manufacture duplicate deliveries on every UI retry.
        publish_backup_request(request.pk, force=created)
    except Exception as error:  # pragma: no cover - defensive broker client boundary
        capture_exception(error)
    request.refresh_from_db()
    return request


def _persist_confirmed_dispatch(
    request_id, owner, token, published_at, claim_timeout
):
    """Finalize a publish without crossing the worker's fencing boundary."""
    from apps.console.backup.models import CoreBackupRequest

    # The worker can claim the request before this update runs. Matching the
    # dispatch token prevents a late publisher from regressing CLAIMED to
    # DISPATCHED. A zero-row update is still a successful broker publication;
    # the worker owns the durable outcome in that race.
    return CoreBackupRequest.objects.filter(
        pk=request_id,
        dispatch_lease_owner=owner,
        dispatch_lease_token=token,
        status__in=(
            CoreBackupRequest.Status.PENDING,
            CoreBackupRequest.Status.DISPATCHED,
        ),
    ).update(
        status=CoreBackupRequest.Status.DISPATCHED,
        dispatch_lease_owner="",
        dispatch_lease_token=None,
        dispatch_lease_expires_at=None,
        next_dispatch_at=published_at + timedelta(seconds=claim_timeout),
        published_at=published_at,
        last_error_code="",
        last_error_message="",
        modified=published_at,
    )


def publish_backup_request(request_id, *, force=False):
    """Claim one dispatch lease, publish with confirms, and persist the outcome.

    ``PENDING`` rows use the short failed-publish backoff.  A confirmed (or
    transport-ambiguous) ``DISPATCHED`` row uses the longer claim timeout: the
    worker may simply be queued, or the broker may have accepted a publish
    whose confirmation was lost.  Both cases must be given time to claim the
    stable task id before another delivery is attempted.
    """
    from apps.console.backup.models import CoreBackupRequest

    now = timezone.now()
    lease_seconds = max(
        15, int(getattr(settings, "BACKUP_REQUEST_DISPATCH_LEASE_SECONDS", 60))
    )
    owner = f"dispatcher:{uuid.uuid4().hex}"
    token = uuid.uuid4()

    with transaction.atomic():
        request = (
            CoreBackupRequest.objects.select_for_update()
            .select_related(
                "node__connection__account",
                "node__connection__integration",
            )
            .get(pk=request_id)
        )
        if request.status not in {
            CoreBackupRequest.Status.PENDING,
            CoreBackupRequest.Status.DISPATCHED,
        }:
            return False
        if (
            request.dispatch_lease_token
            and request.dispatch_lease_expires_at
            and request.dispatch_lease_expires_at > now
        ):
            return False
        ineligible_reason = _backup_request_ineligible_reason(request.node)
        if ineligible_reason:
            # Keep a previously confirmed ``published_at`` as evidence of the
            # broker hand-off, but make the row terminal and remove it from all
            # future recovery sweeps. The queued task, if any, will hit the same
            # source-state guard and return without creating a backup.
            request.status = CoreBackupRequest.Status.CANCELLED
            request.dispatch_lease_owner = ""
            request.dispatch_lease_token = None
            request.dispatch_lease_expires_at = None
            request.next_dispatch_at = None
            request.last_error_code = (
                "SOURCE_RECOVERY_UNAVAILABLE"
                if ineligible_reason == "source_recovery_unavailable"
                else "REQUEST_INELIGIBLE"
            )
            request.last_error_message = (
                SOURCE_RECOVERY_UNAVAILABLE_MESSAGE
                if request.last_error_code == "SOURCE_RECOVERY_UNAVAILABLE"
                else _SAFE_INELIGIBLE_REQUEST
            )
            request.modified = now
            request.save(
                update_fields=[
                    "status",
                    "dispatch_lease_owner",
                    "dispatch_lease_token",
                    "dispatch_lease_expires_at",
                    "next_dispatch_at",
                    "last_error_code",
                    "last_error_message",
                    "modified",
                ]
            )
            return False
        # ``force`` is intentionally only an initial PENDING publish escape
        # hatch.  It must never bypass a confirmed/ambiguous claim timeout.
        if request.status == CoreBackupRequest.Status.DISPATCHED:
            if request.next_dispatch_at and request.next_dispatch_at > now:
                return False
        elif not force and request.next_dispatch_at and request.next_dispatch_at > now:
            return False

        request.dispatch_lease_owner = owner
        request.dispatch_lease_token = token
        request.dispatch_lease_expires_at = now + timedelta(seconds=lease_seconds)
        request.dispatch_attempt_count += 1
        attempt = request.dispatch_attempt_count
        claim_timeout = _claim_timeout(attempt)
        # Commit the conservative outcome before contacting RabbitMQ. If this
        # process dies after broker acceptance (or before it calls the broker),
        # recovery sees DISPATCHED plus the claim timeout instead of treating the
        # row as a short-delay failed publish.
        request.status = CoreBackupRequest.Status.DISPATCHED
        request.next_dispatch_at = now + timedelta(seconds=claim_timeout)
        request.last_error_code = "BROKER_PUBLISH_AMBIGUOUS"
        request.last_error_message = _SAFE_BROKER_ERROR
        request.save(
            update_fields=[
                "status",
                "dispatch_lease_owner",
                "dispatch_lease_token",
                "dispatch_lease_expires_at",
                "next_dispatch_at",
                "dispatch_attempt_count",
                "last_error_code",
                "last_error_message",
                "modified",
            ]
        )
        task_name = request.task_name
        task_id = request.task_id
        payload = dict(request.payload or {})

    try:
        current_app.send_task(
            task_name,
            task_id=task_id,
            kwargs=payload,
            delivery_mode=2,
            mandatory=True,
            retry=True,
            retry_policy={
                "max_retries": 3,
                "interval_start": 0,
                "interval_step": 1,
                "interval_max": 3,
            },
        )
    except Exception as error:
        capture_exception(error)
        ambiguous = _is_ambiguous_publish_error(error)
        failed_at = timezone.now()
        request_status = (
            CoreBackupRequest.Status.DISPATCHED
            if ambiguous
            else CoreBackupRequest.Status.PENDING
        )
        delay = (
            _claim_timeout(attempt)
            if ambiguous
            else _failed_publish_delay(attempt)
        )
        CoreBackupRequest.objects.filter(
            pk=request_id,
            dispatch_lease_owner=owner,
            dispatch_lease_token=token,
        ).update(
            status=request_status,
            dispatch_lease_owner="",
            dispatch_lease_token=None,
            dispatch_lease_expires_at=None,
            next_dispatch_at=failed_at + timedelta(seconds=delay),
            last_error_code=(
                "BROKER_PUBLISH_AMBIGUOUS"
                if ambiguous
                else "BROKER_PUBLISH_FAILED"
            ),
            last_error_message=(
                _SAFE_BROKER_ERROR if ambiguous else _SAFE_BROKER_FAILURE
            ),
            modified=failed_at,
        )
        return False

    published_at = timezone.now()
    _persist_confirmed_dispatch(
        request_id, owner, token, published_at, claim_timeout
    )
    return True


def backup_request_status(request):
    """Return a public-safe status envelope for API/UI polling."""
    backup = request.backup
    backup_status = None
    backup_status_display = None
    if backup is not None:
        backup_status = getattr(backup, "status", None)
        try:
            backup_status_display = backup.get_status_display()
        except (AttributeError, TypeError, ValueError):
            backup_status_display = None
    return {
        "request_id": str(request.correlation_id),
        "status": request.status,
        "status_display": request.get_status_display(),
        "backup_id": request.backup_object_id,
        "backup_status": backup_status,
        "backup_status_display": backup_status_display,
        "dispatch_attempts": request.dispatch_attempt_count,
        "error_code": request.last_error_code or None,
        "message": request.last_error_message or None,
        "created": request.created,
        "modified": request.modified,
    }
