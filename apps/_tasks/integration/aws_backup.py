"""Small, idempotent wrappers around the AWS Backup control plane.

The cloud integrations keep the durable provider identifiers on their existing
backup/restore rows.  This module deliberately contains no Celery or model
state: it only translates BackupSheep's resource names into AWS Backup API
requests and returns the provider response for the caller to persist.
"""

import hashlib


AWS_BACKUP_RESOURCE_TYPES = frozenset(("s3", "dynamodb"))
AWS_BACKUP_API_RESOURCE_TYPES = {
    "s3": "S3",
    "dynamodb": "DynamoDB",
}


def idempotency_token(kind, value):
    """Return a stable token within AWS Backup's 50-character limit."""

    # AWS Backup documents a maximum of 50 characters for IdempotencyToken.
    # Keep enough digest material to avoid practical collisions while staying
    # below the provider limit for every resource name.
    return hashlib.sha256(f"backupsheep:{kind}:{value}".encode("utf-8")).hexdigest()[:48]


def _partition(auth):
    """Read the AWS partition from STS instead of assuming commercial AWS."""

    identity = auth.get_client("sts").get_caller_identity()
    arn = str(identity.get("Arn") or "arn:aws:iam::000000000000:root")
    parts = arn.split(":")
    return parts[1] if len(parts) > 1 else "aws"


def default_role_arn(auth):
    """Return the ARN of AWS's documented default Backup service role."""

    account_id = auth.get_client("sts").get_caller_identity()["Account"]
    return (
        f"arn:{_partition(auth)}:iam::{account_id}:role/"
        "service-role/AWSBackupDefaultServiceRole"
    )


def backup_role_arn(auth):
    """Use an explicitly configured role, otherwise the AWS default role."""

    configured = str(getattr(auth, "backup_role_arn", "") or "").strip()
    return configured or default_role_arn(auth)


def resource_arn(auth, resource_type, resource_id):
    """Build the ARN accepted by ``StartBackupJob`` for a supported resource."""

    if resource_type == "s3":
        return f"arn:{_partition(auth)}:s3:::{resource_id}"
    if resource_type == "dynamodb":
        account_id = auth.get_client("sts").get_caller_identity()["Account"]
        return (
            f"arn:{_partition(auth)}:dynamodb:{auth.region.code}:"
            f"{account_id}:table/{resource_id}"
        )
    raise ValueError(f"Unsupported AWS Backup resource type: {resource_type}")


def start_backup_job(
    auth,
    resource_type,
    resource_id,
    vault_name,
    token,
    recovery_point_tags=None,
):
    """Start an on-demand job with a stable idempotency token."""

    if resource_type not in AWS_BACKUP_RESOURCE_TYPES:
        raise ValueError(f"Unsupported AWS Backup resource type: {resource_type}")

    return auth.get_client("backup").start_backup_job(
        BackupVaultName=vault_name or "Default",
        ResourceArn=resource_arn(auth, resource_type, resource_id),
        IamRoleArn=backup_role_arn(auth),
        IdempotencyToken=token,
        RecoveryPointTags=recovery_point_tags or {},
    )


def describe_backup_job(auth, job_id):
    return auth.get_client("backup").describe_backup_job(BackupJobId=job_id)


def start_restore_job(
    auth,
    resource_type,
    recovery_point_arn,
    metadata,
    token,
):
    """Start a restore with stable provider-side deduplication."""

    if resource_type not in AWS_BACKUP_RESOURCE_TYPES:
        raise ValueError(f"Unsupported AWS Backup resource type: {resource_type}")

    return auth.get_client("backup").start_restore_job(
        RecoveryPointArn=recovery_point_arn,
        IamRoleArn=backup_role_arn(auth),
        Metadata=metadata,
        ResourceType=AWS_BACKUP_API_RESOURCE_TYPES[resource_type],
        IdempotencyToken=token,
    )


def describe_restore_job(auth, job_id):
    return auth.get_client("backup").describe_restore_job(RestoreJobId=job_id)
