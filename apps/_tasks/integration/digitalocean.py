import datetime
import hashlib
import json

from celery import current_app
from celery.exceptions import MaxRetriesExceededError
from django.conf import settings
from django.db.models import Q
from sentry_sdk import capture_exception

from apps.console.account.models import CoreAccount
from apps._tasks.exceptions import (
    NodeNotReadyForBackupError,
    ConnectionNotReadyForBackupError,
    ConnectionValidationFailedError,
    NodeBackupFailedError,
    NodeValidationFailedError,
)
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreSchedule
from apps.console.utils.models import UtilBackup
from celery.exceptions import SoftTimeLimitExceeded
from apps.api.v1.connection.digitalocean.client import (
    DigitalOceanAPIError,
    find_exact_snapshot,
)


DIGITALOCEAN_REQUEST_METADATA_KEY = "_digitalocean_request"
DIGITALOCEAN_REQUEST_SCHEMA = 1


def _digitalocean_request_identity(backup):
    """Return the immutable, non-secret identity of one snapshot request."""

    node = backup.digitalocean.node
    if node.type == CoreNode.Type.CLOUD:
        resource_type = "droplet"
    elif node.type == CoreNode.Type.VOLUME:
        resource_type = "volume"
    else:
        raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
    source_id = backup.digitalocean.unique_id
    marker = backup.uuid_str
    if source_id in (None, "") or marker in (None, ""):
        raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
    identity = {
        "schema": DIGITALOCEAN_REQUEST_SCHEMA,
        "account_id": str(node.connection.account_id),
        "connection_id": str(node.connection_id),
        "node_id": str(node.pk),
        "source_id": str(source_id),
        "resource_type": resource_type,
        "marker": str(marker),
    }
    canonical = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    identity["request_fingerprint"] = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()
    return identity


def _persist_digitalocean_request(backup, identity, *, phase=None, updates=None):
    """Persist a stable request witness through the active create fence."""

    metadata = dict(backup.metadata or {})
    current = metadata.get(DIGITALOCEAN_REQUEST_METADATA_KEY)
    if current is not None and not isinstance(current, dict):
        raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
    current = dict(current or {})
    immutable = (
        "schema",
        "account_id",
        "connection_id",
        "node_id",
        "source_id",
        "resource_type",
        "marker",
        "request_fingerprint",
    )
    if current and any(current.get(key) != identity.get(key) for key in immutable):
        raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
    request = dict(current or identity)
    if phase:
        request["phase"] = str(phase)
    if updates:
        request.update(dict(updates))
    metadata[DIGITALOCEAN_REQUEST_METADATA_KEY] = request
    backup.metadata = metadata
    backup.save(update_fields=["metadata", "modified"])
    return request


def _digitalocean_create_callback(node, task_id):
    """Wrap the legacy adapter with fencing and deterministic reconciliation."""

    def create(claimed):
        metadata = dict(claimed.metadata or {})
        control = metadata.get("_backup_control") or {}
        lease_token = control.get("create_lease_token")
        if not lease_token:
            error = DigitalOceanAPIError("PROVIDER_RECONCILIATION_REQUIRED")
            error.unknown_outcome = True
            raise error

        claimed.bind_execution_fence(task_id, lease_token)
        try:
            claimed.ensure_execution_fence()
            identity = _digitalocean_request_identity(claimed)
            previous = metadata.get(DIGITALOCEAN_REQUEST_METADATA_KEY)
            is_recovery = isinstance(previous, dict)
            request = _persist_digitalocean_request(
                claimed,
                identity,
                phase="reconciling" if is_recovery else "prepared",
            )
            state = claimed.record_provider_reference(
                idempotency_key=identity["marker"],
                metadata={
                    "provider": "digitalocean",
                    "request_fingerprint": identity["request_fingerprint"],
                    "resource_type": identity["resource_type"],
                    "source_id": identity["source_id"],
                },
                lease_owner=task_id,
                lease_token=lease_token,
            )
            if state is None:
                raise DigitalOceanAPIError("PROVIDER_RECONCILIATION_REQUIRED")
            provider_metadata = dict(state.provider_metadata or {})
            state_operation_id = str(state.provider_operation_id or "")
            state_resource_id = str(state.provider_resource_id or "")
            if (
                claimed.action_id not in (None, "")
                and state_operation_id
                and str(claimed.action_id) != state_operation_id
            ) or (
                claimed.unique_id not in (None, "")
                and state_resource_id
                and str(claimed.unique_id) != state_resource_id
            ):
                raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
            if state_operation_id or state_resource_id:
                if (
                    str(state.provider_idempotency_key or "")
                    != identity["marker"]
                    or str(provider_metadata.get("provider") or "")
                    != "digitalocean"
                    or str(provider_metadata.get("source_id") or "")
                    != identity["source_id"]
                    or str(provider_metadata.get("resource_type") or "")
                    != identity["resource_type"]
                    or str(provider_metadata.get("request_fingerprint") or "")
                    != identity["request_fingerprint"]
                    or (
                        state_operation_id
                        and identity["resource_type"] != "droplet"
                    )
                ):
                    raise DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
                # The execution pointer is written before the legacy backup-row
                # pointer. A worker may die between those writes; adopt only this
                # already-validated durable pointer and never call the provider
                # create endpoint again.
                update_fields = ["metadata", "modified"]
                if state_operation_id and not claimed.action_id:
                    claimed.action_id = state_operation_id
                    update_fields.append("action_id")
                if state_resource_id and not claimed.unique_id:
                    claimed.unique_id = state_resource_id
                    update_fields.append("unique_id")
                _persist_digitalocean_request(
                    claimed,
                    identity,
                    phase="accepted",
                    updates={
                        "provider_action_id": state_operation_id,
                        "provider_snapshot_id": state_resource_id,
                    },
                )
                claimed.save(update_fields=list(dict.fromkeys(update_fields)))
                return

            mutation_uncertain = bool(
                provider_metadata.get("create_attempted")
                or provider_metadata.get("outcome_unknown")
            )
            reconciliation_state = str(
                getattr(state, "reconciliation_state", "") or ""
            )
            if reconciliation_state == "manual_review" and not mutation_uncertain:
                raise DigitalOceanAPIError("PROVIDER_RECONCILIATION_REQUIRED")
            # A durable request envelope that survived the previous callback is
            # itself the conservative no-replay fence. Definitive preflight
            # failures remove that envelope before returning, while a worker
            # crash or escaped lost response leaves it present. The model-level
            # create flags provide the same fence when provider acceptance was
            # observed deeper in the adapter.
            is_recovery = bool(is_recovery or mutation_uncertain)
            if is_recovery and request.get("phase") != "reconciling":
                request = _persist_digitalocean_request(
                    claimed,
                    identity,
                    phase="reconciling",
                )

            # If a worker previously entered this adapter without persisting a
            # provider pointer, never issue a second create blindly.  Reconcile
            # the complete snapshot inventory by marker + source + type first.
            if is_recovery and not claimed.action_id and not claimed.unique_id:
                claimed.ensure_execution_fence()
                snapshot = find_exact_snapshot(
                    headers=node.connection.auth_digitalocean.get_verified_client(),
                    marker=identity["marker"],
                    source_id=identity["source_id"],
                    resource_type=identity["resource_type"],
                )
                if snapshot:
                    claimed.unique_id = str(snapshot["id"])
                    claimed.size_gigabytes = snapshot.get(
                        "min_disk_size", snapshot.get("size_gigabytes")
                    )
                    _persist_digitalocean_request(
                        claimed,
                        identity,
                        phase="adopted",
                        updates={"provider_snapshot_id": claimed.unique_id},
                    )
                    claimed.save(
                        update_fields=[
                            "unique_id",
                            "size_gigabytes",
                            "metadata",
                            "modified",
                        ]
                    )
                    claimed.record_provider_reference(
                        resource_id=claimed.unique_id,
                        idempotency_key=identity["marker"],
                        provider_status=str(
                            snapshot.get("state") or snapshot.get("status") or "visible"
                        ),
                        lease_owner=task_id,
                        lease_token=lease_token,
                    )
                    return

                observations = int(request.get("zero_match_observations") or 0) + 1
                _persist_digitalocean_request(
                    claimed,
                    identity,
                    phase="reconciling",
                    updates={"zero_match_observations": observations},
                )
                try:
                    max_observations = int(
                        getattr(
                            settings,
                            "DIGITALOCEAN_CREATE_RECONCILIATION_OBSERVATIONS",
                            4,
                        )
                    )
                except (TypeError, ValueError):
                    max_observations = 4
                max_observations = min(max(max_observations, 2), 100)
                if observations >= max_observations:
                    raise DigitalOceanAPIError(
                        "PROVIDER_RECONCILIATION_REQUIRED"
                    )
                error = DigitalOceanAPIError(
                    "PROVIDER_TRANSIENT_OUTAGE",
                    retryable=True,
                    unknown_outcome=True,
                )
                raise error

            _persist_digitalocean_request(
                claimed,
                identity,
                phase="mutation_boundary",
            )
            claimed.ensure_execution_fence()
            result = node.digitalocean.create_snapshot(claimed)
            claimed.refresh_from_db()
            claimed.bind_execution_fence(task_id, lease_token)
            _persist_digitalocean_request(
                claimed,
                identity,
                phase="accepted",
                updates={
                    "provider_action_id": str(claimed.action_id or ""),
                    "provider_snapshot_id": str(claimed.unique_id or ""),
                },
            )
            return result
        finally:
            claimed.unbind_execution_fence()

    return create


@current_app.task(
    name="backup_digitalocean",
    track_started=True,
    bind=True,
    default_retry_delay=900,
    max_retries=4,
    # retry_backoff=True,
    # retry_backoff_max=900,
    # retry_jitter=False,
    soft_time_limit=(24 * 3600),
)
def backup_digitalocean(
    self,
    node_id=None,
    schedule_id=None,
    storage_ids=None,
    notes=None,
    resume=False,
):
    attempt_no = self.request.retries + 1

    schedule_check = None

    # treat this as scheduled backup
    if schedule_id:
        backup_type = UtilBackup.Type.SCHEDULED
        if resume or CoreSchedule.objects.filter(id=schedule_id, status=CoreSchedule.Status.ACTIVE).exists():
            schedule_check = True
    # treat this as on-demand backup
    else:
        backup_type = UtilBackup.Type.ON_DEMAND
        schedule_check = True

    query = Q(id=node_id)
    query &= ~Q(status=CoreNode.Status.DELETE_REQUESTED)
    query &= ~Q(status=CoreNode.Status.PAUSED)
    query &= ~Q(connection__status=CoreConnection.Status.DELETE_REQUESTED)
    query &= ~Q(connection__status=CoreConnection.Status.PAUSED)
    query &= ~Q(connection__account__status=CoreAccount.Status.DELETE_REQUESTED)

    if CoreNode.objects.filter(query).exists() and schedule_check:
        node = CoreNode.objects.get(id=node_id)

        try:

            """
            Best-effort pre-checks (these may refresh auth tokens). A transient
            validation failure must NOT fail the backup -- the snapshot call itself is
            the real test, so we proceed regardless.
            """
            try:
                node.connection.validate()
                node.validate()
            except Exception:
                pass

            """
            Initialize the backup
            """
            backup = node.backup_initiate(
                self.request.id,
                backup_type,
                attempt_no,
                schedule_id,
                storage_ids,
                notes,
            )

            # None means another backup for this node is already in flight under a
            # different task -- exit gracefully so no duplicate snapshot is created.
            if backup is None:
                return

            """
            Generate snapshot. Only create if there's no existing action_id/unique_id,
            which means a snapshot for this backup is already running.
            """
            if node.type == CoreNode.Type.CLOUD:
                if not backup.action_id and not backup.unique_id:
                    from apps._tasks.helper.tasks import run_provider_create

                    if run_provider_create(
                        backup,
                        self.request.id,
                        _digitalocean_create_callback(node, self.request.id),
                    ) is None:
                        return
            elif node.type == CoreNode.Type.VOLUME:
                if not backup.unique_id:
                    from apps._tasks.helper.tasks import run_provider_create

                    if run_provider_create(
                        backup,
                        self.request.id,
                        _digitalocean_create_callback(node, self.request.id),
                    ) is None:
                        return

            """
            Hand off to async polling instead of blocking the worker. poll_cloud_backup
            waits for the snapshot to finish, finalizes it (retention + success notify),
            and tolerates flaky status calls without failing the backup.
            """
            from apps._tasks.helper.tasks import poll_cloud_backup
            poll_cloud_backup.apply_async(args=[node.id, backup.id], countdown=60)
        except (
            NodeNotReadyForBackupError,
            ConnectionNotReadyForBackupError,
            ConnectionValidationFailedError,
        ) as error:
            node.notify_backup_fail(error, backup_type)
            node.backup_retrying_reset(self.request.id)
            raise self.retry()
        except SoftTimeLimitExceeded as error:
            node.notify_backup_fail(error, backup_type)
            node.backup_timeout_reset(self.request.id)
        except Exception as error:
            try:
                """
                Reset node for retry
                """
                node.notify_backup_fail(error, backup_type)
                node.backup_retrying_reset(self.request.id)
                raise self.retry()
            except MaxRetriesExceededError:
                """
                Reset node for max retries
                """
                node.backup_max_retries_reached(self.request.id)
