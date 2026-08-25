"""Reviewed production Celery routes, publishers, and durable-intent classes.

This module is deliberately independent of Django models and settings so it can be
loaded by the installer, CI, publishers, and workers without creating import cycles.
There is no wildcard/default policy: adding a task decorator is a release-blocking
change until the task is reviewed and added here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


DEFAULT_TASK_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
QUEUES = frozenset(("default", "cloud", "database", "files", "storage", "logs"))
LANES = frozenset(("app", "beat", "cloud", "database", "files", "storage", "logs"))
QUEUE_CONSUMERS = {
    "default": "cloud",
    "cloud": "cloud",
    "database": "database",
    "files": "files",
    "storage": "storage",
    "logs": "logs",
}


class TaskManifestError(RuntimeError):
    """The registered task set or configured routes drifted from review."""


@dataclass(frozen=True, slots=True)
class TaskPolicy:
    queue: str
    publishers: frozenset[str]
    intent: str
    max_age_seconds: int = DEFAULT_TASK_MAX_AGE_SECONDS

    @property
    def target(self) -> str:
        return QUEUE_CONSUMERS[self.queue]


def _policy(queue: str, publishers: tuple[str, ...], intent: str) -> TaskPolicy:
    return TaskPolicy(queue=queue, publishers=frozenset(publishers), intent=intent)


# Each entry is a complete publisher/task/target decision. Publishers always include
# the consumer lane only where task retry or an in-lane durable handoff needs it.
TASK_POLICIES: dict[str, TaskPolicy] = {
    # Database source lane.
    "backup_database": _policy(
        "database",
        ("app", "cloud", "database", "storage"),
        "backup_request",
    ),
    "restore_database_backup": _policy(
        "database", ("app", "cloud", "database"), "database_restore"
    ),
    "cleanup_database_ciphertext_fence": _policy(
        "database", ("storage", "database"), "source_ciphertext_cleanup"
    ),
    "validate_managed_ssh_database_connection": _policy(
        "database", ("app", "database"), "managed_ssh_operation"
    ),
    "discover_managed_ssh_database_objects": _policy(
        "database", ("app", "database"), "managed_ssh_operation"
    ),
    "update_managed_ssh_database_metadata": _policy(
        "database", ("app", "database"), "managed_ssh_operation"
    ),
    "maintain_managed_ssh_database_operations": _policy(
        "database", ("beat", "database"), "state_sweep"
    ),
    # Files source lane.
    "backup_website": _policy(
        "files", ("app", "cloud", "files", "storage"), "backup_request"
    ),
    "backup_wordpress": _policy(
        "files", ("app", "cloud", "files", "storage"), "backup_request"
    ),
    "backup_basecamp": _policy(
        "files", ("app", "cloud", "files", "storage"), "backup_request"
    ),
    "restore_website_backup": _policy(
        "files", ("app", "cloud", "files"), "website_restore"
    ),
    "cleanup_files_ciphertext_fence": _policy(
        "files", ("storage", "files"), "source_ciphertext_cleanup"
    ),
    "validate_managed_ssh_files_connection": _policy(
        "files", ("app", "files"), "managed_ssh_operation"
    ),
    "discover_managed_ssh_files_objects": _policy(
        "files", ("app", "files"), "managed_ssh_operation"
    ),
    "maintain_managed_ssh_files_operations": _policy(
        "files", ("beat", "files"), "state_sweep"
    ),
    # Storage/artifact lane.
    "storage_upload": _policy(
        "storage", ("database", "files", "storage"), "storage_upload"
    ),
    "prepare_local_backup_destinations": _policy(
        "storage", ("database", "files", "storage"), "backup_destination"
    ),
    "resume_pending_backup_destination_validations": _policy(
        "storage", ("beat", "storage"), "state_sweep"
    ),
    "finalize_backup": _policy(
        "storage", ("database", "files", "storage"), "backup_finalize"
    ),
    "delete_from_disk": _policy(
        "storage", ("database", "files", "storage"), "local_artifact_cleanup"
    ),
    "stage_local_restore_ciphertext": _policy(
        "storage", ("database", "files", "storage"), "restore_ciphertext"
    ),
    "cleanup_local_restore_ciphertext": _policy(
        "storage", ("database", "files", "storage"), "restore_ciphertext"
    ),
    "reset_incremental_cache": _policy(
        "files", ("app", "files"), "node_cache_cleanup"
    ),
    "delete_old_logs": _policy(
        "files", ("beat", "files"), "retention_sweep"
    ),
    "delete_old_database_logs": _policy(
        "database", ("beat", "database"), "retention_sweep"
    ),
    "delete_old_storage_logs": _policy(
        "storage", ("beat", "storage"), "retention_sweep"
    ),
    "validate_local_storage": _policy(
        "storage", ("app", "storage"), "storage_configuration"
    ),
    "validate_pending_local_storages": _policy(
        "storage", ("beat", "storage"), "state_sweep"
    ),
    "delete_backup_requested": _policy(
        "storage", ("app", "storage"), "backup_delete"
    ),
    "delete_storage_requested": _policy(
        "storage", ("app", "storage"), "storage_delete"
    ),
    "resume_requested_storage_deletions": _policy(
        "storage", ("beat", "storage"), "state_sweep"
    ),
    "storage_aws_s3_sync_lifecycle": _policy(
        "storage", ("app", "storage"), "storage_configuration"
    ),
    "retry_protected_storage_deletes": _policy(
        "storage", ("beat", "storage"), "state_sweep"
    ),
    "storage_cleanup_owned_multipart": _policy(
        "storage", ("storage",), "multipart_cleanup"
    ),
    "storage_sweep_owned_multipart_cleanup": _policy(
        "storage", ("beat", "storage"), "state_sweep"
    ),
    # Cloud-provider and control lanes.
    "sync_lightsail_bucket_replications": _policy(
        "cloud", ("beat", "cloud"), "state_sweep"
    ),
    "resume_lightsail_bucket_replications": _policy(
        "cloud", ("beat", "cloud"), "state_sweep"
    ),
    "resume_lightsail_bucket_restores": _policy(
        "cloud", ("beat", "cloud"), "state_sweep"
    ),
    "start_lightsail_bucket_replication": _policy(
        "cloud", ("app", "cloud"), "lightsail_replication"
    ),
    "replicate_lightsail_bucket": _policy(
        "cloud", ("cloud",), "lightsail_replication"
    ),
    "recover_stale_lightsail_bucket_leases": _policy(
        "cloud", ("cloud",), "lightsail_replication"
    ),
    "finalize_lightsail_bucket_replication": _policy(
        "cloud", ("cloud",), "lightsail_replication"
    ),
    "restore_lightsail_bucket_prefix": _policy(
        "cloud", ("app", "cloud"), "lightsail_restore"
    ),
    "restore_lightsail_bucket_replication": _policy(
        "cloud", ("app", "cloud"), "lightsail_restore"
    ),
    "backup_digitalocean": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_hetzner": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_vultr": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_vultr_database": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_aws": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_aws_rds": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_lightsail": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_google_cloud": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_oracle": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_upcloud": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_ovh_ca": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_ovh_eu": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "backup_ovh_us": _policy(
        "cloud", ("app", "cloud"), "backup_request"
    ),
    "poll_cloud_backup": _policy("cloud", ("cloud",), "cloud_backup"),
    "restore_cloud_backup": _policy(
        "cloud", ("app", "cloud"), "cloud_restore"
    ),
    "poll_cloud_restore": _policy("cloud", ("cloud",), "cloud_restore"),
    "poll_vultr_database_backup": _policy(
        "cloud", ("cloud",), "cloud_backup"
    ),
    "restore_vultr_database": _policy(
        "cloud", ("app", "cloud"), "vultr_database_restore"
    ),
    "poll_vultr_database_restore": _policy(
        "cloud", ("cloud",), "vultr_database_restore"
    ),
    "reconcile_oracle_backup_deletion": _policy(
        "cloud", ("cloud",), "backup_delete"
    ),
    "reconcile_oracle_backup_deletions": _policy(
        "cloud", ("beat", "cloud"), "state_sweep"
    ),
    "run_scheduled_backup": _policy(
        "default", ("beat", "cloud"), "scheduled_backup"
    ),
    "resume_pending_backup_requests": _policy(
        "default", ("beat", "cloud"), "state_sweep"
    ),
    "resume_in_progress_backups": _policy(
        "default", ("beat", "cloud"), "state_sweep"
    ),
    "resume_in_progress_database_backups": _policy(
        "database", ("beat", "database"), "state_sweep"
    ),
    "resume_in_progress_files_backups": _policy(
        "files", ("beat", "files"), "state_sweep"
    ),
    "resume_in_progress_restores": _policy(
        "default", ("beat", "cloud"), "state_sweep"
    ),
    "resume_in_progress_database_restores": _policy(
        "database", ("beat", "database"), "state_sweep"
    ),
    "resume_in_progress_files_restores": _policy(
        "files", ("beat", "files"), "state_sweep"
    ),
    "node_delete_requested": _policy(
        "default", ("app", "cloud"), "node_delete"
    ),
    "delete_cloud_node_requested": _policy(
        "cloud", ("app", "cloud"), "node_delete"
    ),
    "delete_local_node_requested": _policy(
        "storage", ("app", "storage"), "node_delete"
    ),
    "resume_requested_node_deletions": _policy(
        "default", ("beat", "cloud"), "state_sweep"
    ),
    "resume_requested_local_node_deletions": _policy(
        "storage", ("beat", "storage"), "state_sweep"
    ),
    # Logs and notifications. Each task is explicit even when several lanes can
    # legitimately create an opaque log/email record during their own work.
    "send_log_to_db": _policy(
        "logs",
        ("app", "cloud", "database", "files", "storage", "logs"),
        "log_record",
    ),
    "deliver_log_notification": _policy(
        "logs", ("logs",), "notification_delivery"
    ),
    "recover_notification_fanouts": _policy(
        "logs", ("beat", "logs"), "state_sweep"
    ),
    "recover_notification_deliveries": _policy(
        "logs", ("beat", "logs"), "state_sweep"
    ),
    "delete_old_db_logs": _policy(
        "logs", ("beat", "logs"), "retention_sweep"
    ),
    "cleanup_celery_task_replays": _policy(
        "logs", ("beat", "logs"), "retention_sweep"
    ),
}


# These tasks mutate provider/source/storage state or erase local/durable records.
# CI asserts that none can regress to message-only authorization.
RISKY_TASKS = frozenset(
    name
    for name in TASK_POLICIES
    if any(
        token in name
        for token in (
            "backup_",
            "restore",
            "delete",
            "cleanup",
            "finalize",
            "reset_incremental",
            "lifecycle",
            "replicate",
        )
    )
)


CELERY_FRAMEWORK_TASKS = frozenset(
    (
        "celery.accumulate",
        "celery.backend_cleanup",
        "celery.chain",
        "celery.chord",
        "celery.chord_unlock",
        "celery.chunks",
        "celery.group",
        "celery.map",
        "celery.starmap",
    )
)


def task_policy(task_name: str) -> TaskPolicy:
    try:
        return TASK_POLICIES[task_name]
    except KeyError as error:
        raise TaskManifestError(
            f"task {task_name!r} is absent from the reviewed manifest"
        ) from error


def celery_routes() -> dict[str, dict[str, str]]:
    """Return a fresh Celery route mapping with no implicit/default entries."""

    return {name: {"queue": policy.queue} for name, policy in TASK_POLICIES.items()}


def validate_configured_routes(routes: Mapping[str, object]) -> None:
    expected = celery_routes()
    actual = {name: dict(route) for name, route in routes.items()}
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        changed = sorted(
            name
            for name in set(actual) & set(expected)
            if actual[name] != expected[name]
        )
        raise TaskManifestError(
            "Celery route manifest drift: "
            f"missing={missing}, unexpected={unexpected}, changed={changed}"
        )


def validate_registered_tasks(
    registry: Mapping[str, object], *, required_base: type | None = None
) -> None:
    actual = set(registry)
    expected = set(TASK_POLICIES) | set(CELERY_FRAMEWORK_TASKS)
    if actual != expected:
        raise TaskManifestError(
            "Celery task registry drift: "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
        )
    if required_base is not None:
        unguarded = sorted(
            name for name, task in registry.items() if not isinstance(task, required_base)
        )
        if unguarded:
            raise TaskManifestError(
                f"Celery tasks bypass authenticated base: {unguarded}"
            )


def validate_manifest() -> None:
    for name, policy in TASK_POLICIES.items():
        if not name or "*" in name:
            raise TaskManifestError("task names must be explicit")
        if policy.queue not in QUEUES:
            raise TaskManifestError(f"task {name} has an invalid queue")
        if not policy.publishers or not policy.publishers <= LANES:
            raise TaskManifestError(f"task {name} has invalid publishers")
        if policy.target not in policy.publishers:
            raise TaskManifestError(
                f"task {name} cannot publish a signed retry from its consumer lane"
            )
        if policy.max_age_seconds <= 0 or policy.max_age_seconds > DEFAULT_TASK_MAX_AGE_SECONDS:
            raise TaskManifestError(f"task {name} has an invalid maximum age")
        if policy.intent in {"", "message"}:
            raise TaskManifestError(f"task {name} lacks reviewed durable intent")


validate_manifest()
