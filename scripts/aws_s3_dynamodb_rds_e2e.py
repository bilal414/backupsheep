"""Disposable AWS end-to-end test for the AWS S3/DynamoDB/RDS integrations.

The script creates one explicitly prefixed fixture set, exercises backup and
restore status through the BackupSheep models, verifies the restored data, and
can remove only resources whose exact IDs and ownership proofs were fsynced to
the run ledger. It is intended
to run inside the app image with AWS credentials supplied through the process
environment; it never reads credentials from the repository.

It never creates a Lightsail client and never mutates or deletes Lightsail.
Mutation and cleanup are separate explicit opt-ins.

Example:

    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
      AWS_E2E_RDS_CIDRS=198.51.100.7/32,2001:db8::7/128 \
      BACKUPSHEEP_E2E_RUN_ID=bs-e2e-20260810-5b4a6b63 \
      BACKUPSHEEP_E2E_LEDGER_PATH=/code/_storage/e2e-ledgers/aws.json \
      BACKUPSHEEP_E2E_APPLY=YES BACKUPSHEEP_E2E_CLEANUP=YES \
      python scripts/aws_s3_dynamodb_rds_e2e.py

To continue the exact run after a worker/process crash, set
``BACKUPSHEEP_E2E_MODE=RESUME`` and provide the original RDS password through
``AWS_E2E_RDS_PASSWORD``. RESUME is guarded and never recreates a backup or
restore job.
"""

import fcntl
import ipaddress
import json
import os
import re
import secrets
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import boto3
import django
import psycopg2
from botocore.exceptions import BotoCoreError, ClientError
from botocore.config import Config


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backupsheep.settings")
django.setup()

from apps.api.v1.utils.api_helpers import bs_encrypt  # noqa: E402
from apps.console.backup.models import (  # noqa: E402
    CoreAWSBackup,
    CoreAWSRDSBackup,
    CoreCloudRestore,
)
from apps.console.connection.models import (  # noqa: E402
    CoreAuthAWS,
    CoreAuthAWSRDS,
    CoreAWSRegion,
)
from apps.console.node.models import CoreAWS, CoreAWSRDS, CoreNode  # noqa: E402
from apps.console.utils.models import UtilBackup  # noqa: E402
from apps.tests import factories  # noqa: E402
from apps._tasks.integration.aws_backup import idempotency_token  # noqa: E402
from scripts.live_e2e_ledger import (  # noqa: E402
    DurableResourceLedger,
    LedgerError,
    bounded_error,
    provider_error_class,
    require_run_id,
)


REGION = os.environ.get("AWS_E2E_REGION", "us-east-2")
POLL_SECONDS = max(int(os.environ.get("AWS_E2E_POLL_SECONDS", "20")), 5)
TIMEOUT_SECONDS = max(int(os.environ.get("AWS_E2E_TIMEOUT_SECONDS", "3600")), 300)
TAG_POLL_SECONDS = max(int(os.environ.get("AWS_E2E_TAG_POLL_SECONDS", "5")), 1)
_RUN_ID = os.environ.get("BACKUPSHEEP_E2E_RUN_ID")
PREFIX = require_run_id(_RUN_ID) if _RUN_ID else ""
APPLY = os.environ.get("BACKUPSHEEP_E2E_APPLY") == "YES"
CLEANUP = os.environ.get("BACKUPSHEEP_E2E_CLEANUP") == "YES"
RESUME = os.environ.get("BACKUPSHEEP_E2E_MODE", "").strip().upper() == "RESUME"
BOTO_CONFIG = Config(
    connect_timeout=10,
    read_timeout=60,
    retries={"total_max_attempts": 1, "mode": "standard"},
)
S3_SOURCE = f"{PREFIX}-source"
S3_RESTORE = f"{PREFIX}-restore"
S3_STORAGE = f"{PREFIX}-storage"
DDB_SOURCE = f"{PREFIX}-ddb"
DDB_RESTORE = f"{PREFIX}-ddb-restore"
RDS_SOURCE = f"{PREFIX}-rds"
RDS_RESTORE = f"{PREFIX}-rds-restore"
RDS_SUBNET_GROUP = f"{PREFIX}-subnet"
RDS_SECURITY_GROUP = f"{PREFIX}-sg"
BACKUP_VAULT = PREFIX
ROLE_NAME = f"{PREFIX}-role"
OBJECT_KEY = "fixture/marker.txt"
MARKER = f"{PREFIX}:backup-restore-marker"
OWNERSHIP_TAG = "BackupSheepE2E"
MAX_PROVIDER_PAGES = 1000
MAX_PROVIDER_ITEMS = 10000


class RestoreRecoveryError(RuntimeError):
    """A restore reconciliation invariant failed closed."""

    def __init__(self, code, message=None):
        self.code = str(code)
        super().__init__(message or self.code)


class HarnessError(RuntimeError):
    """A live harness safety invariant failed closed."""


def _preflight_local_safety_gates():
    """Reject unsafe mutation modes before constructing any AWS client."""
    if CLEANUP and not APPLY:
        raise HarnessError(
            "Cleanup is a provider write and requires both "
            "BACKUPSHEEP_E2E_APPLY=YES and BACKUPSHEEP_E2E_CLEANUP=YES."
        )
    if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get(
        "AWS_SECRET_ACCESS_KEY"
    ):
        raise HarnessError(
            "AWS credentials must be supplied explicitly through the process environment."
        )


_ALLOWED_AWS_CLIENT_SERVICES = frozenset(
    {"backup", "dynamodb", "ec2", "iam", "rds", "s3", "sts"}
)


@contextmanager
def _aws_client_guard():
    """Allow only the AWS services this runner is explicitly designed to use."""
    original_client = boto3.client

    def guarded_client(service_name, *args, **kwargs):
        normalized = str(service_name or "").strip().lower()
        if normalized not in _ALLOWED_AWS_CLIENT_SERVICES:
            raise HarnessError("The AWS E2E runner attempted an unsupported client.")
        return original_client(service_name, *args, **kwargs)

    boto3.client = guarded_client
    try:
        yield
    finally:
        boto3.client = original_client


def _normalize_cidr_values(values, label, *, required):
    """Return canonical, non-world-open IPv4/IPv6 CIDRs."""
    if isinstance(values, str):
        values = values.split(",")
    cleaned = [str(value).strip() for value in values or []]
    if required and not cleaned:
        raise HarnessError(f"{label} is required and must contain explicit CIDRs.")
    if any(not value or "/" not in value for value in cleaned):
        raise HarnessError(f"{label} contains an invalid CIDR.")

    networks = set()
    for value in cleaned:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise HarnessError(f"{label} contains an invalid CIDR: {value}") from error
        if network.prefixlen == 0:
            raise HarnessError(f"{label} must not contain a world-open CIDR.")
        networks.add(network)
    return tuple(
        str(network)
        for network in sorted(
            networks,
            key=lambda item: (
                item.version,
                int(item.network_address),
                item.prefixlen,
            ),
        )
    )


def _validated_cidrs(raw_value, env_name):
    """Validate an explicit comma-separated CIDR environment setting."""
    return _normalize_cidr_values(str(raw_value or ""), env_name, required=True)


def _security_group_permission(from_port, to_port, cidrs, description):
    """Build an AWS security-group rule without permitting world-open access."""
    normalized = _normalize_cidr_values(cidrs, "AWS security-group ingress", required=True)
    permission = {
        "IpProtocol": "tcp",
        "FromPort": int(from_port),
        "ToPort": int(to_port),
    }
    ipv4 = [
        {"CidrIp": value, "Description": description}
        for value in normalized
        if ipaddress.ip_network(value).version == 4
    ]
    ipv6 = [
        {"CidrIpv6": value, "Description": description}
        for value in normalized
        if ipaddress.ip_network(value).version == 6
    ]
    if ipv4:
        permission["IpRanges"] = ipv4
    if ipv6:
        permission["Ipv6Ranges"] = ipv6
    return permission


class _ResumeComplete(Exception):
    """Internal control flow marker so the shared cleanup/final report still runs."""


class RestoreIntentStore:
    """Atomic, locked, fsynced intent state for AWS Backup restore requests.

    The intent is written before the provider mutation.  Immutable identity fields
    cannot be changed later; only the provider outcome and finalization state may
    advance.  This is deliberately local to this harness so its recovery contract
    cannot depend on private implementation details of another live E2E script.
    """

    _REQUIRED = frozenset(
        {
            "marker",
            "resource_type",
            "source_recovery_point_arn",
            "target_name",
            "target_arn",
            "restore_id",
            "restore_token",
        }
    )
    _IMMUTABLE = frozenset(
        {
            "marker",
            "resource_type",
            "source_recovery_point_arn",
            "target_name",
            "target_arn",
            "restore_id",
            "restore_correlation_id",
            "restore_token",
        }
    )

    def __init__(self, path, *, run_id, scope):
        if not path:
            raise LedgerError("A ledger path is required for restore intents.")
        self.path = Path(path).expanduser().resolve().with_name(
            Path(path).name + ".restore-intents.json"
        )
        self.run_id = require_run_id(run_id)
        self.scope = str(scope)
        if not self.scope:
            raise LedgerError("An AWS account and region scope are required.")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        with self._locked():
            if self.path.exists():
                self._validate(self._read_unlocked())
            else:
                self._write_unlocked(
                    {
                        "schema": 1,
                        "run_id": self.run_id,
                        "scope": self.scope,
                        "pending": {},
                    }
                )

    def _locked(self):
        store = self

        class Lock:
            def __enter__(self):
                self.handle = open(store.lock_path, "a+", encoding="utf-8")
                os.chmod(store.lock_path, 0o600)
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
                return self.handle

            def __exit__(self, exc_type, exc, tb):
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
                self.handle.close()

        return Lock()

    def _read_unlocked(self):
        try:
            with open(self.path, encoding="utf-8") as source:
                return json.load(source)
        except (OSError, ValueError) as error:
            raise LedgerError("The AWS restore intent state could not be read.") from error

    def _validate(self, payload):
        if not isinstance(payload, dict) or payload.get("schema") != 1:
            raise LedgerError("The AWS restore intent state is malformed.")
        if payload.get("run_id") != self.run_id or payload.get("scope") != self.scope:
            raise LedgerError("The AWS restore intent state scope does not match.")
        pending = payload.get("pending")
        if not isinstance(pending, dict):
            raise LedgerError("The AWS restore intent pending map is malformed.")
        if any(not isinstance(key, str) or not isinstance(value, dict) for key, value in pending.items()):
            raise LedgerError("The AWS restore intent contains a malformed entry.")
        if any(not self._REQUIRED.issubset(value) for value in pending.values()):
            raise LedgerError("The AWS restore intent is missing an immutable witness.")
        return payload

    def _write_unlocked(self, payload):
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(payload, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def get(self, key):
        with self._locked():
            payload = self._validate(self._read_unlocked())
            value = payload["pending"].get(str(key))
            return dict(value) if isinstance(value, dict) else None

    def put(self, key, value):
        if not isinstance(value, dict) or not self._REQUIRED.issubset(value):
            raise LedgerError("A restore intent is missing its immutable witness.")
        key = str(key)
        with self._locked():
            payload = self._validate(self._read_unlocked())
            current = payload["pending"].get(key)
            if current is not None:
                if any(current.get(field) != value.get(field) for field in self._IMMUTABLE):
                    raise LedgerError("A restore intent already exists with another witness.")
                merged = dict(current)
                # Reopening an intent during RESUME must preserve an accepted or
                # unknown provider outcome. Resetting mutation_state to prepared
                # would make a retry eligible to issue a duplicate request.
                for field, candidate in value.items():
                    if field in self._IMMUTABLE or field not in merged:
                        merged[field] = candidate
                value = merged
            payload["pending"][key] = dict(value)
            self._write_unlocked(payload)
        return dict(value)

    def update(self, key, **updates):
        key = str(key)
        with self._locked():
            payload = self._validate(self._read_unlocked())
            current = payload["pending"].get(key)
            if not isinstance(current, dict):
                raise LedgerError("Cannot update an unknown restore intent.")
            if any(field in self._IMMUTABLE for field in updates):
                raise LedgerError("Immutable restore intent fields cannot be updated.")
            current = dict(current)
            current.update(updates)
            payload["pending"][key] = current
            self._write_unlocked(payload)
        return current

    def clear(self, key):
        with self._locked():
            payload = self._validate(self._read_unlocked())
            payload["pending"].pop(str(key), None)
            self._write_unlocked(payload)

    def pending(self):
        with self._locked():
            payload = self._validate(self._read_unlocked())
            return {key: dict(value) for key, value in payload["pending"].items()}


def _not_found(error):
    return isinstance(error, ClientError) and error.response.get("Error", {}).get(
        "Code"
    ) in {
        "NoSuchBucket",
        "NoSuchKey",
        "ResourceNotFoundException",
        "DBInstanceNotFound",
        "DBSnapshotNotFoundFault",
        "DBSnapshotNotFound",
        "DBSubnetGroupNotFoundFault",
        "InvalidGroup.NotFound",
        "NoSuchEntity",
        "ResourceNotFoundException",
        "404",
        "NotFound",
    }


def _sleep():
    time.sleep(POLL_SECONDS)


def _wait(label, callback, complete, failed=None, timeout=TIMEOUT_SECONDS):
    started = time.monotonic()
    history = []
    while True:
        value = callback()
        history.append(str(value))
        if value in complete:
            return value, history
        if failed and value in failed:
            raise RuntimeError(f"{label} failed with state {value}")
        if time.monotonic() - started > timeout:
            raise TimeoutError(f"Timed out waiting for {label}; states={history[-8:]}")
        _sleep()


def _delete_versioned_bucket(s3, bucket):
    try:
        key_marker = None
        version_id_marker = None
        seen_markers = set()
        pages = 0
        item_count = 0
        while True:
            pages += 1
            if pages > MAX_PROVIDER_PAGES:
                raise HarnessError("S3 version pagination exceeded the bounded page limit.")
            params = {"Bucket": bucket, "MaxKeys": 1000}
            if key_marker is not None:
                params["KeyMarker"] = key_marker
            if version_id_marker is not None:
                params["VersionIdMarker"] = version_id_marker
            response = s3.list_object_versions(**params)
            entries = []
            entries.extend(
                {"Key": row["Key"], "VersionId": row["VersionId"]}
                for row in response.get("Versions") or []
            )
            entries.extend(
                {"Key": row["Key"], "VersionId": row["VersionId"]}
                for row in response.get("DeleteMarkers") or []
            )
            item_count += len(entries)
            if item_count > MAX_PROVIDER_ITEMS:
                raise HarnessError("S3 version pagination exceeded the bounded item limit.")
            if not entries:
                if response.get("IsTruncated"):
                    raise HarnessError(
                        "S3 returned a truncated version page without objects."
                    )
                break
            for offset in range(0, len(entries), 1000):
                s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": entries[offset : offset + 1000], "Quiet": True},
                )
            if not response.get("IsTruncated"):
                break
            next_marker = (
                response.get("NextKeyMarker"),
                response.get("NextVersionIdMarker"),
            )
            if not next_marker[0] or next_marker in seen_markers:
                raise HarnessError("S3 returned missing or repeated version pagination markers.")
            seen_markers.add(next_marker)
            key_marker, version_id_marker = next_marker
        s3.delete_bucket(Bucket=bucket)
    except Exception as error:
        if not _not_found(error):
            raise


def _delete_table(dynamodb, name):
    try:
        dynamodb.delete_table(TableName=name)

        def table_status():
            try:
                return dynamodb.describe_table(TableName=name)["Table"]["TableStatus"]
            except ClientError as error:
                if _not_found(error):
                    return "deleted"
                raise

        _wait(
            f"DynamoDB table {name} deletion",
            table_status,
            {"deleted"},
        )
    except ClientError as error:
        if not _not_found(error):
            raise


def _delete_rds_instance(rds, identifier):
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=identifier,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )

        def instance_status():
            try:
                return rds.describe_db_instances(
                    DBInstanceIdentifier=identifier
                )["DBInstances"][0]["DBInstanceStatus"]
            except ClientError as error:
                if _not_found(error):
                    return "deleted"
                raise

        _wait(
            f"RDS instance {identifier} deletion",
            instance_status,
            {"deleted"},
        )
    except ClientError as error:
        if not _not_found(error):
            raise


def _delete_rds_snapshot(rds, identifier):
    """Delete one exact snapshot and return only after AWS proves absence."""
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=identifier)

        def snapshot_status():
            try:
                snapshots = rds.describe_db_snapshots(
                    DBSnapshotIdentifier=identifier
                ).get("DBSnapshots") or []
            except ClientError as error:
                if _not_found(error):
                    return "deleted"
                raise
            if len(snapshots) != 1:
                raise HarnessError(
                    "AWS returned an ambiguous exact RDS snapshot read-back."
                )
            return str(snapshots[0].get("Status") or "visible")

        _wait(
            f"RDS snapshot {identifier} deletion",
            snapshot_status,
            {"deleted"},
        )
    except ClientError as error:
        if not _not_found(error):
            raise


def _delete_recovery_point(backup_client, vault_name, recovery_point_arn):
    """Delete one exact recovery point and wait for ResourceNotFound."""
    try:
        backup_client.delete_recovery_point(
            BackupVaultName=vault_name,
            RecoveryPointArn=recovery_point_arn,
        )

        def recovery_point_status():
            try:
                response = backup_client.describe_recovery_point(
                    BackupVaultName=vault_name,
                    RecoveryPointArn=recovery_point_arn,
                )
            except ClientError as error:
                if _not_found(error):
                    return "deleted"
                raise
            return str(response.get("Status") or "visible")

        _wait(
            f"AWS Backup recovery point {recovery_point_arn} deletion",
            recovery_point_status,
            {"deleted"},
        )
    except ClientError as error:
        if not _not_found(error):
            raise


def _connect_rds(rds, identifier, password):
    description = rds.describe_db_instances(DBInstanceIdentifier=identifier)[
        "DBInstances"
    ][0]
    endpoint = description.get("Endpoint") or {}
    return psycopg2.connect(
        host=endpoint["Address"],
        port=endpoint.get("Port", 5432),
        user="bsadmin",
        password=password,
        dbname="postgres",
        sslmode="require",
        connect_timeout=15,
    )


def _rds_marker(rds, identifier, password):
    connection = _connect_rds(rds, identifier, password)
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS backupsheep_e2e_marker "
                    "(id integer primary key, value text not null)"
                )
                cursor.execute(
                    "INSERT INTO backupsheep_e2e_marker (id, value) VALUES (1, %s) "
                    "ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value",
                    (MARKER,),
                )
    finally:
        connection.close()


def _assert_rds_marker(rds, identifier, password):
    connection = _connect_rds(rds, identifier, password)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT value FROM backupsheep_e2e_marker WHERE id = 1")
            value = cursor.fetchone()[0]
            if value != MARKER:
                raise AssertionError(f"RDS marker mismatch: {value!r}")
    finally:
        connection.close()


def _wait_backup(backup, label):
    state, history = _wait(
        label,
        backup.poll_status,
        {UtilBackup.Status.COMPLETE},
        {UtilBackup.Status.FAILED, UtilBackup.Status.TIMEOUT},
    )
    return {"state": backup.get_status_display(), "history": history[-8:]}


def _wait_restore(node_object, restore, label):
    state, history = _wait(
        label,
        restore.poll_status,
        {CoreCloudRestore.Status.COMPLETE},
        {CoreCloudRestore.Status.FAILED},
    )
    restore.status = state
    restore.save(update_fields=["status", "modified"])
    return {"state": restore.get_status_display(), "history": history[-8:]}


def _tag_map(rows):
    return {str(row.get("Key")): str(row.get("Value")) for row in rows or []}


def _exact_exists(callback):
    try:
        callback()
        return True
    except ClientError as error:
        if _not_found(error):
            return False
        raise


def _s3_bucket_exists(s3, name):
    try:
        s3.head_bucket(Bucket=name)
        return True
    except ClientError as error:
        status = int(
            ((error.response or {}).get("ResponseMetadata") or {}).get(
                "HTTPStatusCode", 0
            )
            or 0
        )
        if status == 404:
            return False
        # 301/403 still prove that the globally unique bucket name is occupied.
        if status in {301, 403}:
            return True
        raise


def _backup_vault_exists(backup_client, name):
    """Use cursor pagination because Backup masks an absent vault as HTTP 403."""
    next_token = None
    seen_tokens = set()
    pages = 0
    item_count = 0
    while True:
        pages += 1
        if pages > MAX_PROVIDER_PAGES:
            raise RuntimeError("AWS Backup vault pagination exceeded the bounded page limit")
        params = {"MaxResults": 100}
        if next_token:
            params["NextToken"] = next_token
        response = backup_client.list_backup_vaults(**params)
        page = response.get("BackupVaultList") or []
        if not isinstance(page, list):
            raise RuntimeError("AWS Backup returned a malformed vault page")
        item_count += len(page)
        if item_count > MAX_PROVIDER_ITEMS:
            raise RuntimeError("AWS Backup vault pagination exceeded the bounded item limit")
        if any(
            str(vault.get("BackupVaultName") or "") == name
            for vault in page
        ):
            return True
        next_token = response.get("NextToken")
        if not next_token:
            if len(page) >= params["MaxResults"]:
                raise RuntimeError("AWS Backup returned a full vault page without a cursor")
            return False
        if not isinstance(next_token, str) or next_token in seen_tokens:
            raise RuntimeError("AWS Backup returned a repeated vault pagination token")
        seen_tokens.add(next_token)


def _provider_error_code(error):
    """Classify provider failures without treating them as IN_PROGRESS."""
    if isinstance(error, RestoreRecoveryError):
        return error.code
    if isinstance(error, ClientError):
        error_data = error.response.get("Error") or {}
        provider_code = str(error_data.get("Code") or "").lower()
        status_code = int(
            ((error.response or {}).get("ResponseMetadata") or {}).get(
                "HTTPStatusCode", 0
            )
            or 0
        )
        if _not_found(error) or status_code == 404:
            return "PROVIDER_NOT_FOUND"
        if provider_code in {
            "throttling",
            "throttlingexception",
            "toomanyrequestsexception",
            "limitexceededexception",
            "requestlimitexceeded",
        } or status_code == 429:
            return "PROVIDER_RATE_LIMIT"
        if provider_code in {"requesttimeout", "requesttimeoutexception"}:
            return "PROVIDER_TIMEOUT"
        if provider_code in {
            "serviceunavailable",
            "serviceunavailableexception",
            "internalfailure",
            "internalservererror",
        } or status_code >= 500:
            return "PROVIDER_TRANSIENT_OUTAGE"
        return "PROVIDER_FAILED"
    if isinstance(error, TimeoutError):
        return "PROVIDER_TIMEOUT"
    if isinstance(error, OSError):
        return "PROVIDER_TRANSIENT_OUTAGE"
    if isinstance(error, BotoCoreError):
        if "timeout" in type(error).__name__.lower():
            return "PROVIDER_TIMEOUT"
        return "PROVIDER_TRANSIENT_OUTAGE"
    return provider_error_class(error)


def _safe_error(error):
    return f"{_provider_error_code(error)}: {bounded_error(error)}"


def _restore_target_arn(resource_type, target_name, account_id):
    if resource_type == "s3":
        return f"arn:aws:s3:::{target_name}"
    if resource_type == "dynamodb":
        return f"arn:aws:dynamodb:{REGION}:{account_id}:table/{target_name}"
    raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")


def _restore_intent_key(resource_type, restore):
    return f"{resource_type}:{restore.pk}"


def _prepare_restore_intent(
    intent_store,
    restore,
    *,
    resource_type,
    source_recovery_point_arn,
    target_name,
    account_id,
):
    """Persist the immutable restore witness before calling AWS Backup."""
    resource_type = str(resource_type)
    target_name = str(target_name or "").strip()
    source_recovery_point_arn = str(source_recovery_point_arn or "").strip()
    if resource_type not in {"s3", "dynamodb"} or not target_name or not source_recovery_point_arn:
        raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
    marker = f"backupsheep-restore-{restore.id}"[:128]
    token = idempotency_token("restore", restore.id)
    target_arn = _restore_target_arn(resource_type, target_name, account_id)
    intent = {
        "marker": marker,
        "resource_type": resource_type,
        "source_recovery_point_arn": source_recovery_point_arn,
        "target_name": target_name,
        "target_arn": target_arn,
        "restore_id": str(restore.id),
        "restore_correlation_id": str(getattr(restore, "correlation_id", "") or ""),
        "restore_token": token,
        "mutation_state": "prepared",
    }
    key = _restore_intent_key(resource_type, restore)
    try:
        intent_store.put(key, intent)
    except LedgerError as error:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH", str(error)) from error

    params = dict(restore.params) if isinstance(restore.params, dict) else {}
    existing_token = str(params.get("_aws_backup_restore_token") or "")
    if existing_token and existing_token != token:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    existing_marker = str(getattr(restore, "restore_marker", "") or "")
    if existing_marker and existing_marker != marker:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    params["_aws_backup_restore_token"] = token
    params["_bs_restore_intent"] = {
        "run_id": PREFIX,
        "resource_type": resource_type,
        "restore_id": str(restore.id),
        "restore_correlation_id": intent["restore_correlation_id"],
        "source_recovery_point_arn": source_recovery_point_arn,
        "target_name": target_name,
        "target_arn": target_arn,
        "marker": marker,
        "restore_token": token,
    }
    restore.restore_marker = marker
    restore.params = params
    restore.save(update_fields=["restore_marker", "params", "modified"])
    return key, intent


def _assert_restore_intent_row(restore, intent):
    """Verify that a local restore row still represents the intent on disk."""
    if str(restore.id) != str(intent.get("restore_id")):
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    correlation_id = str(getattr(restore, "correlation_id", "") or "")
    if correlation_id != str(intent.get("restore_correlation_id") or ""):
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    params = restore.params if isinstance(restore.params, dict) else {}
    if str(params.get("_aws_backup_restore_token") or "") != str(
        intent.get("restore_token") or ""
    ):
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if str(getattr(restore, "restore_marker", "") or "") != str(
        intent.get("marker") or ""
    ):
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if restore.provider_job_id and intent.get("provider_job_id"):
        if str(restore.provider_job_id) != str(intent["provider_job_id"]):
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if restore.resource_id and str(restore.resource_id) != str(intent.get("target_name")):
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")


def _restore_job_metadata_target(job, intent):
    metadata = job.get("RestoreMetadata")
    if metadata is None:
        metadata = job.get("Metadata")
    if metadata is None:
        return None
    if not isinstance(metadata, dict):
        raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
    resource_type = str(intent.get("resource_type") or "")
    key = "DestinationBucketName" if resource_type == "s3" else "TargetTableName"
    target = metadata.get(key)
    if target is None:
        return None
    return str(target)


def _validate_restore_job(job, intent, *, require_target=False):
    if not isinstance(job, dict):
        raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
    job_id = str(job.get("RestoreJobId") or "").strip()
    source = str(job.get("RecoveryPointArn") or "").strip()
    resource_type = str(job.get("ResourceType") or "").strip().lower()
    if not job_id or not source or not resource_type or "Status" not in job:
        raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
    expected_type = str(intent.get("resource_type") or "").lower()
    if source != str(intent.get("source_recovery_point_arn") or ""):
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if resource_type != expected_type:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    created_arn = str(job.get("CreatedResourceArn") or "").strip()
    target_metadata = _restore_job_metadata_target(job, intent)
    target_name = str(intent.get("target_name") or "")
    if created_arn and created_arn != str(intent.get("target_arn") or ""):
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if target_metadata and target_metadata != target_name:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    marker = None
    metadata = job.get("RestoreMetadata") or job.get("Metadata")
    if isinstance(metadata, dict) and metadata.get("BackupSheepRestoreMarker") is not None:
        marker = str(metadata.get("BackupSheepRestoreMarker"))
        if marker != str(intent.get("marker") or ""):
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if require_target and not created_arn and target_metadata != target_name:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    return job


def _describe_restore_job_exact(backup_client, intent, job_id, *, require_target=False):
    try:
        job = backup_client.describe_restore_job(RestoreJobId=str(job_id))
    except Exception as error:
        raise RestoreRecoveryError(_provider_error_code(error)) from error
    _validate_restore_job(job, intent, require_target=require_target)
    if str(job.get("RestoreJobId") or "") != str(job_id):
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    return job


def _list_restore_jobs_exact(backup_client, intent):
    """Find one exact restore job using AWS Backup's cursor contract."""
    source_arn = str(intent.get("source_recovery_point_arn") or "")
    arn_parts = source_arn.split(":")
    account_id = arn_parts[4] if len(arn_parts) >= 6 else ""
    expected_type = str(intent.get("resource_type") or "").lower()
    api_resource_type = {"s3": "S3", "dynamodb": "DynamoDB"}.get(
        expected_type
    )
    if not re.fullmatch(r"[0-9]{12}", account_id) or not api_resource_type:
        raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
    matches = []
    next_token = None
    seen_tokens = set()
    item_count = 0
    for _ in range(MAX_PROVIDER_PAGES):
        request = {
            # ListRestoreJobs does not accept RecoveryPointArn. Narrow with its
            # real account/resource-type filters, then match source and target
            # identity locally across every cursor page.
            "ByAccountId": account_id,
            "ByResourceType": api_resource_type,
            "MaxResults": 100,
        }
        if next_token:
            request["NextToken"] = next_token
        try:
            response = backup_client.list_restore_jobs(**request)
        except Exception as error:
            raise RestoreRecoveryError(_provider_error_code(error)) from error
        if not isinstance(response, dict) or "RestoreJobs" not in response:
            raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
        page = response["RestoreJobs"]
        if not isinstance(page, list):
            raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
        item_count += len(page)
        if item_count > MAX_PROVIDER_ITEMS:
            raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
        for job in page:
            if not isinstance(job, dict):
                raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
            # Account/resource filters intentionally include unrelated jobs.
            # Ignore them; validate complete ownership only after an exact
            # recovery-point match identifies a possible candidate.
            if (
                str(job.get("RecoveryPointArn") or "") != source_arn
                or str(job.get("ResourceType") or "").lower()
                != expected_type
            ):
                continue
            _validate_restore_job(job, intent, require_target=False)
            created_arn = str(job.get("CreatedResourceArn") or "")
            target_metadata = _restore_job_metadata_target(job, intent)
            if created_arn == str(intent["target_arn"]) or target_metadata == str(
                intent["target_name"]
            ):
                matches.append(job)
        next_value = response.get("NextToken")
        if next_value in (None, ""):
            break
        if not isinstance(next_value, str) or next_value in seen_tokens or next_value == next_token:
            raise RestoreRecoveryError("PROVIDER_REPEATED_CURSOR")
        seen_tokens.add(next_value)
        next_token = next_value
    else:
        raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
    if len(matches) > 1:
        raise RestoreRecoveryError("PROVIDER_DUPLICATE_MATCH")
    if not matches:
        return None
    return _describe_restore_job_exact(
        backup_client,
        intent,
        matches[0]["RestoreJobId"],
        require_target=True,
    )


def _adopt_restore_job(restore, intent_store, intent_key, intent, job):
    _validate_restore_job(job, intent, require_target=True)
    job_id = str(job["RestoreJobId"])
    _assert_restore_intent_row(restore, intent)
    params = dict(restore.params) if isinstance(restore.params, dict) else {}
    params["_bs_create_outcome_unknown"] = False
    params["_bs_restore_job_witness"] = {
        "restore_job_id": job_id,
        "source_recovery_point_arn": intent["source_recovery_point_arn"],
        "target_arn": intent["target_arn"],
        "target_name": intent["target_name"],
        "restore_token": intent["restore_token"],
    }
    restore.provider_job_id = job_id
    restore.resource_id = intent["target_name"]
    restore.params = params
    restore.status = CoreCloudRestore.Status.IN_PROGRESS
    restore.operation_phase = "polling"
    restore.error = ""
    restore.save(
        update_fields=[
            "provider_job_id",
            "resource_id",
            "params",
            "status",
            "operation_phase",
            "error",
            "modified",
        ]
    )
    intent_store.update(
        intent_key,
        provider_job_id=job_id,
        provider_status=str(job.get("Status") or "")[:64],
        mutation_state="accepted",
    )
    return job


def _start_or_reconcile_restore(
    node_object,
    backup_client,
    restore,
    intent_store,
    intent_key,
    *,
    start_callback,
):
    """Start once, or adopt the exact already-accepted AWS Backup job."""
    intent = intent_store.get(intent_key)
    if not intent:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    restore.refresh_from_db()
    _assert_restore_intent_row(restore, intent)
    if restore.provider_job_id:
        job = _describe_restore_job_exact(
            backup_client, intent, restore.provider_job_id, require_target=False
        )
        intent_store.update(
            intent_key,
            provider_job_id=str(restore.provider_job_id),
            provider_status=str(job.get("Status") or "")[:64],
            mutation_state="accepted",
        )
        return job

    existing = _list_restore_jobs_exact(backup_client, intent)
    if existing is not None:
        return _adopt_restore_job(restore, intent_store, intent_key, intent, existing)

    if str(intent.get("mutation_state") or "prepared") != "prepared":
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    # This fsynced transition is the process-crash fence. A retry seeing it must
    # reconcile the provider and may not call start_restore_job again.
    intent = intent_store.update(intent_key, mutation_state="request_started")
    try:
        start_callback()
    except BaseException as error:
        code = _provider_error_code(error)
        intent_store.update(
            intent_key,
            mutation_state="outcome_unknown",
            last_error_code=code,
        )
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise RestoreRecoveryError(code) from error

    restore.refresh_from_db()
    _assert_restore_intent_row(restore, intent)
    if restore.provider_job_id:
        job = _describe_restore_job_exact(
            backup_client, intent, restore.provider_job_id, require_target=False
        )
        intent_store.update(
            intent_key,
            provider_job_id=str(restore.provider_job_id),
            provider_status=str(job.get("Status") or "")[:64],
            mutation_state="accepted",
        )
        return job
    # The provider may have accepted the request while the application process
    # died before saving provider_job_id. Only the exact target/source witness may
    # be adopted; zero matches is an unknown outcome, never permission to retry.
    existing = _list_restore_jobs_exact(backup_client, intent)
    if existing is None:
        intent_store.update(
            intent_key,
            mutation_state="outcome_unknown",
            last_error_code="PROVIDER_RECONCILIATION_REQUIRED",
        )
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    return _adopt_restore_job(restore, intent_store, intent_key, intent, existing)


def _verify_completed_restore_job(backup_client, intent, job_id):
    job = _describe_restore_job_exact(
        backup_client, intent, job_id, require_target=True
    )
    status = str(job.get("Status") or "").upper()
    if status == "COMPLETED":
        created_arn = str(job.get("CreatedResourceArn") or "")
        if created_arn != str(intent["target_arn"]):
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
        return job
    if status in {"PENDING", "RUNNING", "PARTIAL"}:
        raise RestoreRecoveryError("IN_PROGRESS")
    if status in {"FAILED", "ABORTED", "EXPIRED"}:
        raise RestoreRecoveryError("PROVIDER_FAILED")
    raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")


def _ddb_ownership_observation(dynamodb, name, expected_arn):
    try:
        response = dynamodb.describe_table(TableName=name)
    except ClientError as error:
        if _not_found(error):
            return {"state": "absent"}
        raise RestoreRecoveryError(_provider_error_code(error)) from error
    except Exception as error:
        raise RestoreRecoveryError(_provider_error_code(error)) from error
    if not isinstance(response, dict) or not isinstance(response.get("Table"), dict):
        raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
    table = response["Table"]
    if table.get("TableName") != name or str(table.get("TableArn") or "") != str(expected_arn):
        return {"state": "mismatch", "table": table}
    if str(table.get("TableStatus") or "") != "ACTIVE":
        return {"state": "in_progress", "table": table}
    try:
        tags_response = dynamodb.list_tags_of_resource(ResourceArn=expected_arn)
    except ClientError as error:
        if _not_found(error):
            return {"state": "not_yet_visible", "table": table}
        raise RestoreRecoveryError(_provider_error_code(error)) from error
    except Exception as error:
        raise RestoreRecoveryError(_provider_error_code(error)) from error
    if not isinstance(tags_response, dict) or not isinstance(tags_response.get("Tags"), list):
        raise RestoreRecoveryError("PROVIDER_MALFORMED_RESPONSE")
    tags = _tag_map(tags_response["Tags"])
    if tags.get(OWNERSHIP_TAG) == PREFIX:
        return {"state": "owned", "table": table}
    if OWNERSHIP_TAG in tags:
        return {"state": "mismatch", "table": table}
    return {"state": "missing", "table": table}


def _wait_ddb_tag_readback(
    dynamodb,
    name,
    expected_arn,
    *,
    timeout=120,
    sleep_callback=None,
):
    """Boundedly distinguish delayed tag visibility, absence, and mismatch."""
    started = time.monotonic()
    last_state = "not_yet_visible"
    while True:
        observation = _ddb_ownership_observation(dynamodb, name, expected_arn)
        state = observation["state"]
        last_state = state
        if state == "owned":
            return observation["table"]
        if state == "mismatch":
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
        if time.monotonic() - started >= timeout:
            if state == "absent":
                raise RestoreRecoveryError("PROVIDER_NOT_FOUND")
            if state == "in_progress":
                raise RestoreRecoveryError("IN_PROGRESS")
            raise RestoreRecoveryError("PROVIDER_TAG_NOT_YET_VISIBLE")
        if sleep_callback:
            sleep_callback()
        else:
            time.sleep(TAG_POLL_SECONDS)


def _restore_provenance(intent, job):
    return json.dumps(
        {
            "restore_job_id": str(job.get("RestoreJobId") or ""),
            "source_recovery_point_arn": intent["source_recovery_point_arn"],
            "target_arn": intent["target_arn"],
            "target_name": intent["target_name"],
            "restore_id": intent["restore_id"],
            "restore_correlation_id": intent.get("restore_correlation_id", ""),
            "restore_token": intent["restore_token"],
        },
        sort_keys=True,
    )


def _record_or_verify_restore_ledger(
    ledger,
    kind,
    resource_id,
    *,
    name,
    intent,
    job,
):
    """Idempotently accept only an exact prior restore ledger witness.

    The interrupted live run recorded one DynamoDB restore manually before this
    harness gained structured JSON provenance. Preserve that append-only record
    only when every immutable provider identifier matches the completed job.
    """
    expected_json = _restore_provenance(intent, job)
    expected_legacy = (
        f"{intent['source_recovery_point_arn']}"
        f"|restore-job:{job['RestoreJobId']}"
        f"|created-resource:{intent['target_arn']}"
    )
    existing = [
        entry
        for entry in ledger.entries(kind)
        if str(entry.get("resource_id") or "") == str(resource_id)
    ]
    if len(existing) > 1:
        raise RestoreRecoveryError("PROVIDER_DUPLICATE_MATCH")
    if existing:
        entry = existing[0]
        ownership = entry.get("ownership") or {}
        source_witness = str(entry.get("source_witness") or "")
        provider_arn = str(ownership.get("provider_arn") or "")
        provenance_matches = (
            source_witness == expected_json
            and provider_arn == str(intent.get("target_arn") or "")
        ) or (
            source_witness == expected_legacy
            and provider_arn in {"", str(intent.get("target_arn") or "")}
        )
        if (
            str(entry.get("name") or "") != str(name)
            or ownership.get("tag_key") != OWNERSHIP_TAG
            or ownership.get("tag_value") != PREFIX
            or not provenance_matches
        ):
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
        return entry
    _ledger_record(
        ledger,
        kind,
        resource_id,
        name=name,
        source=expected_json,
        immutable_id=intent["target_arn"],
    )
    return None


def _finalize_ddb_restore(
    dynamodb,
    backup_client,
    restore,
    intent_store,
    intent_key,
    ledger,
    *,
    marker,
):
    intent = intent_store.get(intent_key)
    if not intent:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    restore.refresh_from_db()
    _assert_restore_intent_row(restore, intent)
    if not restore.provider_job_id:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    job = _verify_completed_restore_job(
        backup_client, intent, restore.provider_job_id
    )
    try:
        item = dynamodb.get_item(
            TableName=intent["target_name"],
            Key={"id": {"S": "fixture"}},
        ).get("Item") or {}
    except Exception as error:
        raise RestoreRecoveryError(_provider_error_code(error)) from error
    if item.get("marker", {}).get("S") != marker:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    observation = _ddb_ownership_observation(
        dynamodb, intent["target_name"], intent["target_arn"]
    )
    if observation["state"] == "mismatch":
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if observation["state"] != "owned":
        # A missing tag is safe to add only after the exact table ARN was read.
        try:
            dynamodb.tag_resource(
                ResourceArn=intent["target_arn"],
                Tags=[{"Key": OWNERSHIP_TAG, "Value": PREFIX}],
            )
        except Exception as error:
            raise RestoreRecoveryError(_provider_error_code(error)) from error
    _wait_ddb_tag_readback(
        dynamodb,
        intent["target_name"],
        intent["target_arn"],
    )
    _record_or_verify_restore_ledger(
        ledger,
        "dynamodb_table",
        intent["target_name"],
        name=intent["target_name"],
        intent=intent,
        job=job,
    )
    # The ledger write is itself atomic/fsynced. Only after it succeeds may the
    # pre-mutation intent be removed.
    intent_store.update(intent_key, mutation_state="ledgered")
    intent_store.clear(intent_key)
    return job


def _finalize_s3_restore(
    s3,
    backup_client,
    restore,
    intent_store,
    intent_key,
    ledger,
    *,
    marker,
):
    intent = intent_store.get(intent_key)
    if not intent:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    restore.refresh_from_db()
    _assert_restore_intent_row(restore, intent)
    if not restore.provider_job_id:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    job = _verify_completed_restore_job(
        backup_client, intent, restore.provider_job_id
    )
    try:
        restored = s3.get_object(
            Bucket=intent["target_name"], Key=OBJECT_KEY
        )["Body"].read().decode()
    except Exception as error:
        raise RestoreRecoveryError(_provider_error_code(error)) from error
    if restored != marker:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    _record_or_verify_restore_ledger(
        ledger,
        "restore_provenance",
        f"{intent['resource_type']}:{intent['restore_id']}",
        name=intent["target_name"],
        intent=intent,
        job=job,
    )
    intent_store.update(intent_key, mutation_state="ledgered")
    intent_store.clear(intent_key)
    return job


def _exact_preflight(s3, dynamodb, rds, ec2, backup_client, iam):
    """Refuse every exact target collision before the first mutation."""
    collisions = {
        "s3_source": _s3_bucket_exists(s3, S3_SOURCE),
        "s3_restore": _s3_bucket_exists(s3, S3_RESTORE),
        "s3_storage": _s3_bucket_exists(s3, S3_STORAGE),
        "ddb_source": _exact_exists(
            lambda: dynamodb.describe_table(TableName=DDB_SOURCE)
        ),
        "ddb_restore": _exact_exists(
            lambda: dynamodb.describe_table(TableName=DDB_RESTORE)
        ),
        "rds_source": _exact_exists(
            lambda: rds.describe_db_instances(DBInstanceIdentifier=RDS_SOURCE)
        ),
        "rds_restore": _exact_exists(
            lambda: rds.describe_db_instances(DBInstanceIdentifier=RDS_RESTORE)
        ),
        "rds_snapshot": _exact_exists(
            lambda: rds.describe_db_snapshots(
                DBSnapshotIdentifier=f"{PREFIX}-rds-snapshot"
            )
        ),
        "rds_subnet_group": _exact_exists(
            lambda: rds.describe_db_subnet_groups(
                DBSubnetGroupName=RDS_SUBNET_GROUP
            )
        ),
        "backup_vault": _backup_vault_exists(backup_client, BACKUP_VAULT),
        "iam_role": _exact_exists(lambda: iam.get_role(RoleName=ROLE_NAME)),
        "security_group": bool(
            ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [RDS_SECURITY_GROUP]}]
            ).get("SecurityGroups")
        ),
    }
    if any(collisions.values()):
        occupied = sorted(key for key, value in collisions.items() if value)
        raise RuntimeError(
            "The explicit live-test target already exists: " + ", ".join(occupied)
        )
    return collisions


def _s3_owned(s3, bucket):
    try:
        tags = s3.get_bucket_tagging(Bucket=bucket).get("TagSet") or []
    except ClientError:
        return False
    return _tag_map(tags).get(OWNERSHIP_TAG) == PREFIX


def _ddb_description_owned(dynamodb, name, *, expected_arn=None):
    try:
        table = dynamodb.describe_table(TableName=name)["Table"]
        tags = dynamodb.list_tags_of_resource(
            ResourceArn=table["TableArn"]
        ).get("Tags") or []
    except ClientError as error:
        if _not_found(error):
            return None
        raise
    except (KeyError, TypeError) as error:
        raise HarnessError(
            "AWS returned a malformed exact DynamoDB ownership read-back."
        ) from error
    if expected_arn is not None and str(table.get("TableArn") or "") != str(expected_arn):
        return False
    return table if _tag_map(tags).get(OWNERSHIP_TAG) == PREFIX else False


def _rds_description_owned(rds, identifier, *, snapshot=False, expected_arn=None):
    try:
        if snapshot:
            resource = rds.describe_db_snapshots(
                DBSnapshotIdentifier=identifier
            )["DBSnapshots"][0]
            arn = resource["DBSnapshotArn"]
        else:
            resource = rds.describe_db_instances(
                DBInstanceIdentifier=identifier
            )["DBInstances"][0]
            arn = resource["DBInstanceArn"]
        tags = rds.list_tags_for_resource(ResourceName=arn).get("TagList") or []
    except ClientError as error:
        if _not_found(error):
            return None
        raise
    if expected_arn is not None and str(arn) != str(expected_arn):
        return False
    return resource if _tag_map(tags).get(OWNERSHIP_TAG) == PREFIX else False


def _ec2_security_group_owned(ec2, identifier):
    try:
        groups = ec2.describe_security_groups(GroupIds=[identifier]).get(
            "SecurityGroups", []
        )
    except ClientError as error:
        if _not_found(error):
            return None
        raise
    if len(groups) != 1:
        return False
    return groups[0] if _tag_map(groups[0].get("Tags")).get(OWNERSHIP_TAG) == PREFIX else False


def _ledger_record(
    ledger, kind, resource_id, *, name=None, source="", immutable_id=None
):
    ownership = {"tag_key": OWNERSHIP_TAG, "tag_value": PREFIX}
    if immutable_id:
        ownership["provider_arn"] = str(immutable_id)
    ledger.record(
        kind=kind,
        resource_id=resource_id,
        name=name or resource_id,
        ownership=ownership,
        source_witness=source,
    )


def _register_rds_instance(ledger, rds, identifier, *, source=""):
    """Persist an accepted RDS create as soon as exact tags are readable."""
    started = time.monotonic()
    while True:
        owned = _rds_description_owned(rds, identifier)
        if owned is False:
            raise RuntimeError(f"AWS RDS ownership mismatch for {identifier}.")
        if owned is not None:
            _ledger_record(
                ledger,
                "rds_instance",
                identifier,
                name=identifier,
                source=source,
                immutable_id=owned.get("DBInstanceArn"),
            )
            return owned
        if time.monotonic() - started > 120:
            raise RuntimeError(
                f"AWS accepted RDS instance {identifier}, but exact ownership "
                "could not be read back; manual reconciliation is required."
            )
        _sleep()


def _register_rds_snapshot(ledger, rds, identifier, *, source):
    """Tag and ledger an accepted manual snapshot before its long availability wait."""
    started = time.monotonic()
    while True:
        try:
            rows = rds.describe_db_snapshots(
                DBSnapshotIdentifier=identifier
            ).get("DBSnapshots") or []
        except ClientError as error:
            if not _not_found(error):
                raise
            rows = []
        if len(rows) > 1:
            raise RuntimeError(f"AWS returned duplicate RDS snapshots for {identifier}.")
        if rows:
            snapshot = rows[0]
            arn = str(snapshot.get("DBSnapshotArn") or "")
            expected_prefix = f"arn:aws:rds:{REGION}:"
            if (
                snapshot.get("DBSnapshotIdentifier") != identifier
                or str(snapshot.get("DBInstanceIdentifier") or "") != str(source)
                or snapshot.get("SnapshotType") != "manual"
                or not arn.startswith(expected_prefix)
            ):
                raise RuntimeError("AWS RDS snapshot source ownership read-back failed.")
            rds.add_tags_to_resource(
                ResourceName=arn,
                Tags=[{"Key": OWNERSHIP_TAG, "Value": PREFIX}],
            )
            if not _rds_description_owned(rds, identifier, snapshot=True):
                raise RuntimeError("AWS RDS snapshot tag read-back failed.")
            _ledger_record(
                ledger,
                "rds_snapshot",
                identifier,
                name=identifier,
                source=source,
                immutable_id=arn,
            )
            return snapshot
        if time.monotonic() - started > 120:
            raise RuntimeError(
                f"AWS accepted RDS snapshot {identifier}, but it could not be "
                "read back; manual reconciliation is required."
            )
        _sleep()


def _recover_local_fixture():
    """Recover only the exact provider-specific local account after a restart."""
    from django.contrib.auth import get_user_model

    email = f"{PREFIX}-aws@example.invalid"
    users = list(get_user_model().objects.filter(username=email, email=email)[:2])
    if not users:
        return None, None
    if len(users) != 1:
        raise RuntimeError("Multiple exact AWS E2E users were found.")
    user = users[0]
    try:
        member = user.member
    except Exception as error:
        raise RuntimeError("The exact AWS E2E user has no member graph.") from error
    memberships = list(member.memberships.select_related("account")[:2])
    if len(memberships) != 1:
        raise RuntimeError(
            "The exact AWS E2E user does not own exactly one account."
        )
    account = memberships[0].account
    expected_names = {
        f"{PREFIX}-aws-connection",
        f"{PREFIX}-rds-connection",
    }
    if account.connections.exclude(name__in=expected_names).exists():
        raise RuntimeError("The exact AWS E2E account contains an unrelated connection.")
    return account, user


def _exact_one(queryset, label):
    rows = list(queryset[:2])
    if len(rows) != 1:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED", f"Expected exactly one {label}.")
    return rows[0]


def _resume_provider_preflight(s3, dynamodb, rds):
    """Prove the existing run-owned provider graph before RESUME mutations."""
    for bucket in (S3_SOURCE, S3_RESTORE, S3_STORAGE):
        if not _s3_bucket_exists(s3, bucket):
            raise RestoreRecoveryError("PROVIDER_NOT_FOUND")
        if not _s3_owned(s3, bucket):
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    source_table = _ddb_description_owned(
        dynamodb, DDB_SOURCE
    )
    if source_table is None:
        raise RestoreRecoveryError("PROVIDER_NOT_FOUND")
    if source_table is False:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    source_rds = _rds_description_owned(rds, RDS_SOURCE)
    if source_rds is None:
        raise RestoreRecoveryError("PROVIDER_NOT_FOUND")
    if source_rds is False:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")


def _resume_local_graph(account, user, *, rds_password):
    """Adopt the exact failed-run graph, creating only a missing local RDS tail."""
    member = getattr(user, "member", None)
    if member is None:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    aws_connection = _exact_one(
        account.connections.filter(name=f"{PREFIX}-aws-connection"),
        "AWS connection",
    )
    s3_node = _exact_one(aws_connection.nodes.filter(name=S3_SOURCE), "S3 node")
    ddb_node = _exact_one(aws_connection.nodes.filter(name=DDB_SOURCE), "DynamoDB node")
    if s3_node.type != CoreNode.Type.CLOUD or ddb_node.type != CoreNode.Type.CLOUD:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if s3_node.aws.resource_type != CoreAWS.ResourceType.S3:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if ddb_node.aws.resource_type != CoreAWS.ResourceType.DYNAMODB:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if s3_node.aws.unique_id != S3_SOURCE or ddb_node.aws.unique_id != DDB_SOURCE:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    ddb_backup = _exact_one(
        CoreAWSBackup.objects.filter(
            aws=ddb_node.aws, uuid=f"{PREFIX}-ddb-backup"
        ),
        "DynamoDB backup",
    )
    ddb_restore = _exact_one(
        CoreCloudRestore.objects.filter(node=ddb_node, name=DDB_RESTORE),
        "DynamoDB restore",
    )
    if ddb_restore.backup_id != ddb_backup.id:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")

    rds_connection_rows = list(
        account.connections.filter(name=f"{PREFIX}-rds-connection")[:2]
    )
    if len(rds_connection_rows) > 1:
        raise RestoreRecoveryError("PROVIDER_DUPLICATE_MATCH")
    if rds_connection_rows:
        rds_connection = rds_connection_rows[0]
        if rds_connection.integration.code != "aws_rds":
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
        rds_node = _exact_one(rds_connection.nodes.filter(name=RDS_SOURCE), "RDS node")
        if rds_node.type != CoreNode.Type.CLOUD:
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
        rds_aws = rds_node.aws_rds
        if rds_aws.unique_id != RDS_SOURCE:
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    else:
        if not rds_password:
            raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
        key = account.get_encryption_key()
        rds_connection = factories.make_connection(
            account,
            member,
            code="aws_rds",
            name=f"{PREFIX}-rds-connection",
        )
        CoreAuthAWSRDS.objects.create(
            connection=rds_connection,
            region=CoreAWSRegion.objects.get(code=REGION),
            access_key=bs_encrypt(os.environ["AWS_ACCESS_KEY_ID"], key),
            secret_key=bs_encrypt(os.environ["AWS_SECRET_ACCESS_KEY"], key),
        )
        rds_node = CoreNode.objects.create(
            connection=rds_connection,
            type=CoreNode.Type.CLOUD,
            name=RDS_SOURCE,
            added_by=member,
        )
        rds_aws = CoreAWSRDS.objects.create(
            node=rds_node,
            name=RDS_SOURCE,
            unique_id=RDS_SOURCE,
        )
    rds_backup_rows = list(
        CoreAWSRDSBackup.objects.filter(
            aws_rds=rds_aws, uuid=f"{PREFIX}-rds-snapshot"
        )[:2]
    )
    if len(rds_backup_rows) > 1:
        raise RestoreRecoveryError("PROVIDER_DUPLICATE_MATCH")
    if rds_backup_rows:
        rds_backup = rds_backup_rows[0]
    else:
        rds_backup = CoreAWSRDSBackup.objects.create(
            aws_rds=rds_aws,
            uuid=f"{PREFIX}-rds-snapshot",
            unique_id=f"{PREFIX}-rds-snapshot",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
    rds_restore_rows = list(
        CoreCloudRestore.objects.filter(node=rds_node, name=RDS_RESTORE)[:2]
    )
    if len(rds_restore_rows) > 1:
        raise RestoreRecoveryError("PROVIDER_DUPLICATE_MATCH")
    if rds_restore_rows:
        rds_restore = rds_restore_rows[0]
        if rds_restore.backup_id != rds_backup.id:
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    else:
        rds_restore = CoreCloudRestore.objects.create(
            node=rds_node,
            backup_id=rds_backup.id,
            name=RDS_RESTORE,
            params={
                "db_instance_class": os.environ.get("AWS_E2E_RDS_CLASS", "db.t3.micro"),
                "db_subnet_group_name": RDS_SUBNET_GROUP,
                "publicly_accessible": True,
                "vpc_security_group_ids": [
                    # The provider-side security group is resolved from the ledger
                    # by the caller before this graph is used for a restore.
                ],
            },
        )
    return {
        "account": account,
        "user": user,
        "aws_connection": aws_connection,
        "s3_node": s3_node,
        "ddb_node": ddb_node,
        "ddb_backup": ddb_backup,
        "ddb_restore": ddb_restore,
        "rds_connection": rds_connection,
        "rds_node": rds_node,
        "rds_aws": rds_aws,
        "rds_backup": rds_backup,
        "rds_restore": rds_restore,
    }


def _resume_rds_continuation(rds, graph, ledger, *, security_group_id, rds_password, report):
    """Continue the RDS half without duplicating an accepted snapshot/restore."""
    rds_backup = graph["rds_backup"]
    snapshot_identifier = f"{PREFIX}-rds-snapshot"
    snapshot_rows = []
    try:
        snapshot_rows = rds.describe_db_snapshots(
            DBSnapshotIdentifier=snapshot_identifier
        ).get("DBSnapshots") or []
    except ClientError as error:
        if not _not_found(error):
            raise RestoreRecoveryError(_provider_error_code(error)) from error
    if len(snapshot_rows) > 1:
        raise RestoreRecoveryError("PROVIDER_DUPLICATE_MATCH")
    if not snapshot_rows:
        graph["rds_node"].aws_rds.create_snapshot(rds_backup)
        rds_backup.refresh_from_db()
    else:
        snapshot = snapshot_rows[0]
        if (
            snapshot.get("DBSnapshotIdentifier") != snapshot_identifier
            or snapshot.get("DBInstanceIdentifier") != RDS_SOURCE
            or snapshot.get("SnapshotType") != "manual"
        ):
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
        rds_backup.unique_id = snapshot_identifier
        rds_backup.save(update_fields=["unique_id", "modified"])
    snapshot_identifier = str(rds_backup.unique_id or snapshot_identifier)
    _register_rds_snapshot(
        ledger,
        rds,
        snapshot_identifier,
        source=RDS_SOURCE,
    )
    report["tests"]["RDS native snapshot resume"] = _wait_backup(
        rds_backup, "RDS native snapshot resume"
    )

    rds_restore = graph["rds_restore"]
    if not rds_restore.params:
        rds_restore.params = {
            "db_instance_class": os.environ.get("AWS_E2E_RDS_CLASS", "db.t3.micro"),
            "db_subnet_group_name": RDS_SUBNET_GROUP,
            "publicly_accessible": True,
            "vpc_security_group_ids": [security_group_id],
        }
        rds_restore.save(update_fields=["params", "modified"])
    else:
        params = dict(rds_restore.params)
        groups = params.get("vpc_security_group_ids") or []
        if groups and groups != [security_group_id]:
            raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
        params["vpc_security_group_ids"] = [security_group_id]
        rds_restore.params = params
        rds_restore.save(update_fields=["params", "modified"])
    rds_restore.refresh_from_db()
    if not rds_restore.resource_id:
        # The application restore adapter owns deterministic reconciliation. It
        # verifies the BackupSheepRestore/BackupSheepSource tags before adopting
        # an exact-name instance whose create response was lost; the harness must
        # never bypass that ownership proof by setting resource_id itself.
        graph["rds_node"].aws_rds.restore_snapshot(rds_backup, rds_restore)
    rds_restore.refresh_from_db()
    if rds_restore.resource_id and rds_restore.resource_id != RDS_RESTORE:
        raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
    if not rds_restore.resource_id:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")

    started = time.monotonic()
    restoring_instance = None
    while True:
        try:
            rows = rds.describe_db_instances(
                DBInstanceIdentifier=RDS_RESTORE
            ).get("DBInstances") or []
        except ClientError as error:
            if _not_found(error):
                rows = []
            else:
                raise RestoreRecoveryError(_provider_error_code(error)) from error
        if len(rows) > 1:
            raise RestoreRecoveryError("PROVIDER_DUPLICATE_MATCH")
        if rows:
            instance = rows[0]
            if instance.get("DBInstanceIdentifier") != RDS_RESTORE:
                raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
            provider_tags = _tag_map(
                rds.list_tags_for_resource(
                    ResourceName=instance["DBInstanceArn"]
                ).get("TagList")
                or []
            )
            if (
                provider_tags.get("BackupSheepRestore")
                != str(rds_restore.restore_marker)
                or provider_tags.get("BackupSheepSource") != snapshot_identifier
            ):
                raise RestoreRecoveryError("PROVIDER_OWNERSHIP_MISMATCH")
            rds.add_tags_to_resource(
                ResourceName=instance["DBInstanceArn"],
                Tags=[{"Key": OWNERSHIP_TAG, "Value": PREFIX}],
            )
            _register_rds_instance(
                ledger,
                rds,
                RDS_RESTORE,
                source=snapshot_identifier,
            )
            restoring_instance = instance
            break
        if time.monotonic() - started > 120:
            raise RestoreRecoveryError("PROVIDER_NOT_FOUND")
        _sleep()

    status = str((restoring_instance or {}).get("DBInstanceStatus") or "")
    if status != "available":
        _wait(
            "restored RDS availability",
            lambda: rds.describe_db_instances(
                DBInstanceIdentifier=RDS_RESTORE
            )["DBInstances"][0]["DBInstanceStatus"],
            {"available"},
            {
                "failed",
                "incompatible-restore",
                "incompatible-network",
                "incompatible-parameters",
            },
            timeout=TIMEOUT_SECONDS,
        )
    if not rds_password:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    _assert_rds_marker(rds, RDS_RESTORE, rds_password)
    rds_restore.status = CoreCloudRestore.Status.COMPLETE
    rds_restore.save(update_fields=["status", "modified"])
    report["tests"]["RDS restore and data verification resume"] = {"status": "PASS"}


def _resume_existing_run(
    s3,
    dynamodb,
    rds,
    backup_client,
    ledger,
    intent_store,
    report,
    *,
    rds_password,
):
    """Resume only the exact failed run; no source/restore backup is recreated."""
    if not APPLY:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED", "RESUME requires APPLY=YES.")
    if not rds_password:
        raise RestoreRecoveryError(
            "PROVIDER_RECONCILIATION_REQUIRED",
            "RESUME requires AWS_E2E_RDS_PASSWORD for the final data verification.",
        )
    account, user = _recover_local_fixture()
    if account is None or user is None:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    _resume_provider_preflight(s3, dynamodb, rds)
    graph = _resume_local_graph(account, user, rds_password=rds_password)
    ddb_backup = graph["ddb_backup"]
    ddb_restore = graph["ddb_restore"]
    ddb_state = dict((ddb_backup.metadata or {}).get("_aws_backup") or {})
    ddb_recovery_point = str(ddb_state.get("recovery_point_arn") or "")
    if not ddb_recovery_point:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    matching_points = [
        entry
        for entry in ledger.entries("recovery_point")
        if str(entry.get("resource_id") or "") == ddb_recovery_point
        and str(entry.get("source_witness") or "") == DDB_SOURCE
    ]
    if len(matching_points) != 1:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    ddb_intent_key, _ = _prepare_restore_intent(
        intent_store,
        ddb_restore,
        resource_type="dynamodb",
        source_recovery_point_arn=ddb_recovery_point,
        target_name=DDB_RESTORE,
        account_id=str(report["account"]),
    )
    _start_or_reconcile_restore(
        graph["ddb_node"].aws,
        backup_client,
        ddb_restore,
        intent_store,
        ddb_intent_key,
        start_callback=lambda: graph["ddb_node"].aws.restore_snapshot(
            ddb_backup, ddb_restore
        ),
    )
    report["tests"]["DynamoDB restore resume adoption"] = {"status": "PASS"}
    _wait_restore(
        graph["ddb_node"].aws,
        ddb_restore,
        "DynamoDB restore resume job",
    )
    _finalize_ddb_restore(
        dynamodb,
        backup_client,
        ddb_restore,
        intent_store,
        ddb_intent_key,
        ledger,
        marker=MARKER,
    )
    report["tests"]["DynamoDB restore resume finalization"] = {"status": "PASS"}
    security_entries = ledger.entries("security_group")
    exact_security = [
        entry
        for entry in security_entries
        if str(entry.get("name") or "") == RDS_SECURITY_GROUP
    ]
    if len(exact_security) != 1:
        raise RestoreRecoveryError("PROVIDER_RECONCILIATION_REQUIRED")
    _resume_rds_continuation(
        rds,
        graph,
        ledger,
        security_group_id=str(exact_security[0]["resource_id"]),
        rds_password=rds_password,
        report=report,
    )
    report["mode"] = "resume"
    report["status"] = "PASS"


def _reconcile_pending_restore_intents(
    s3, dynamodb, backup_client, intent_store, ledger
):
    """Prove every pending restore intent before any provider cleanup write."""
    unresolved = []
    for key, intent in intent_store.pending().items():
        restore_id = str(intent.get("restore_id") or "")
        restore_rows = list(CoreCloudRestore.objects.filter(pk=restore_id)[:2])
        if len(restore_rows) != 1:
            unresolved.append(
                f"{key}: exact local restore row is missing or duplicated"
            )
            continue
        restore = restore_rows[0]
        try:
            _assert_restore_intent_row(restore, intent)
            job = _list_restore_jobs_exact(
                backup_client, intent
            )
        except Exception as error:
            unresolved.append(f"{key}: {_safe_error(error)}")
            continue
        if job is not None:
            unresolved.append(
                f"{key}: exact provider restore job remains; cleanup is blocked"
            )
            continue
        state = str(intent.get("mutation_state") or "prepared")
        if state == "prepared":
            # A complete provider read found no exact source/target job. This is
            # the only state in which an intent may be removed without adoption.
            intent_store.clear(key)
            continue
        if state == "ledgered":
            resource_type = str(intent.get("resource_type") or "")
            target_name = str(intent.get("target_name") or "")
            if resource_type == "dynamodb":
                entry = ledger.get("dynamodb_table", target_name)
                expected_arn = str(
                    (entry or {}).get("ownership", {}).get("provider_arn") or ""
                )
                observed = (
                    _ddb_description_owned(
                        dynamodb, target_name, expected_arn=expected_arn
                    )
                    if expected_arn
                    else False
                )
                if observed is False or observed is None:
                    unresolved.append(
                        f"{key}: immutable DynamoDB restore identity could not be proven"
                    )
                    continue
            elif resource_type == "s3":
                if not _s3_bucket_exists(s3, target_name) or not _s3_owned(
                    s3, target_name
                ):
                    unresolved.append(
                        f"{key}: exact S3 restore bucket identity could not be proven"
                    )
                    continue
            else:
                unresolved.append(f"{key}: unsupported restore intent type")
                continue
            intent_store.clear(key)
            continue
        unresolved.append(
            f"{key}: accepted or ambiguous restore outcome needs provider reconciliation"
        )
    return unresolved


def main():
    report = {"prefix": PREFIX, "region": REGION, "tests": {}, "cleanup": []}
    try:
        _preflight_local_safety_gates()
    except HarnessError as error:
        report["status"] = "FAIL"
        report["error"] = _safe_error(error)
        report["cleanup"] = {
            "status": "REFUSED" if CLEANUP else "NOT_REQUESTED",
            "errors": [_safe_error(error)] if CLEANUP else [],
        }
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 1
    ledger = None
    intent_store = None
    created = {
        "role": False,
        "vault": False,
        "source_bucket": False,
        "restore_bucket": False,
        "ddb_source": False,
        "ddb_restore": False,
        "rds_source": False,
        "rds_restore": False,
        "subnet_group": False,
        "security_group": False,
        "account": False,
    }
    account = None
    user = None
    role_arn = None
    vault = None
    subnet_ids = []
    security_group_id = None
    rds_password = (
        os.environ.get("AWS_E2E_RDS_PASSWORD", "")
        if RESUME
        else secrets.token_urlsafe(24)
    )
    rds_snapshot_identifier = f"{PREFIX}-rds-snapshot"
    with _aws_client_guard():
        rds = boto3.client("rds", region_name=REGION, config=BOTO_CONFIG)
        ec2 = boto3.client("ec2", region_name=REGION, config=BOTO_CONFIG)
        s3 = boto3.client("s3", region_name=REGION, config=BOTO_CONFIG)
        dynamodb = boto3.client("dynamodb", region_name=REGION, config=BOTO_CONFIG)
        backup_client = boto3.client("backup", region_name=REGION, config=BOTO_CONFIG)
        iam = boto3.client("iam", region_name=REGION, config=BOTO_CONFIG)
    client_guard = _aws_client_guard()
    client_guard.__enter__()

    try:
        with _aws_client_guard():
            identity = boto3.client(
                "sts", region_name=REGION, config=BOTO_CONFIG
            ).get_caller_identity()
        report["account"] = identity.get("Account")
        report["caller"] = str(identity.get("Arn", "")).split("/")[-1]
        ledger = DurableResourceLedger(
            os.environ.get("BACKUPSHEEP_E2E_LEDGER_PATH"),
            provider="aws",
            run_id=PREFIX,
            scope=f"{report['account']}:{REGION}",
        )
        intent_store = RestoreIntentStore(
            os.environ.get("BACKUPSHEEP_E2E_LEDGER_PATH"),
            run_id=PREFIX,
            scope=f"{report['account']}:{REGION}",
        )

        if RESUME:
            report["mode"] = "resume"
            report["exact_preflight"] = {"mode": "resume", "status": "GUARDED"}
            _resume_existing_run(
                s3,
                dynamodb,
                rds,
                backup_client,
                ledger,
                intent_store,
                report,
                rds_password=rds_password,
            )
            raise _ResumeComplete()

        report["exact_preflight"] = _exact_preflight(
            s3, dynamodb, rds, ec2, backup_client, iam
        )
        report["baseline_collisions"] = report["exact_preflight"]

        if not APPLY:
            report["status"] = "PREFLIGHT_PASS"
            report["mode"] = "read_only"
            return 0

        # Validate the runner allowlist after all read-only collision checks but
        # before the first provider write. Resume and cleanup reconciliation do
        # not create ingress, so an obsolete runner address must not strand
        # already-owned resources.
        rds_cidrs = _validated_cidrs(
            os.environ.get("AWS_E2E_RDS_CIDRS"), "AWS_E2E_RDS_CIDRS"
        )

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "backup.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role = iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f"Disposable BackupSheep AWS Backup E2E role {PREFIX}",
            Tags=[{"Key": "BackupSheepE2E", "Value": PREFIX}],
        )
        created["role"] = True
        role_arn = role["Role"]["Arn"]
        observed_role = iam.get_role(RoleName=ROLE_NAME)["Role"]
        role_tags = iam.list_role_tags(RoleName=ROLE_NAME).get("Tags") or []
        if (
            observed_role.get("Arn") != role_arn
            or _tag_map(role_tags).get(OWNERSHIP_TAG) != PREFIX
        ):
            raise RuntimeError("AWS IAM role ownership read-back failed.")
        _ledger_record(ledger, "iam_role", role_arn, name=ROLE_NAME)
        policy_arns = [
            "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
            "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
            "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup",
            "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore",
        ]
        for policy_arn in policy_arns:
            iam.attach_role_policy(RoleName=ROLE_NAME, PolicyArn=policy_arn)
        # IAM role propagation is eventually consistent; wait before AWS Backup
        # assumes it. This is not a fixed provider-job wait.
        time.sleep(15)

        backup_client.create_backup_vault(
            BackupVaultName=BACKUP_VAULT,
            BackupVaultTags={"BackupSheepE2E": PREFIX},
        )
        created["vault"] = True
        vault_description = backup_client.describe_backup_vault(
            BackupVaultName=BACKUP_VAULT
        )
        vault_arn = vault_description.get("BackupVaultArn")
        vault_tags = backup_client.list_tags(ResourceArn=vault_arn).get("Tags") or {}
        if not vault_arn or str(vault_tags.get(OWNERSHIP_TAG) or "") != PREFIX:
            raise RuntimeError("AWS Backup vault ownership read-back failed.")
        _ledger_record(ledger, "backup_vault", vault_arn, name=BACKUP_VAULT)

        create_bucket_args = {"Bucket": S3_SOURCE}
        if REGION != "us-east-1":
            create_bucket_args["CreateBucketConfiguration"] = {"LocationConstraint": REGION}
        s3.create_bucket(**create_bucket_args)
        created["source_bucket"] = True
        s3.put_bucket_tagging(
            Bucket=S3_SOURCE,
            Tagging={"TagSet": [{"Key": OWNERSHIP_TAG, "Value": PREFIX}]},
        )
        if not _s3_owned(s3, S3_SOURCE):
            raise RuntimeError("AWS source bucket ownership read-back failed.")
        _ledger_record(ledger, "s3_bucket", S3_SOURCE)
        s3.put_bucket_versioning(
            Bucket=S3_SOURCE,
            VersioningConfiguration={"Status": "Enabled"},
        )
        s3.put_object(
            Bucket=S3_SOURCE,
            Key=OBJECT_KEY,
            Body=MARKER.encode(),
            Metadata={"backupsheep-e2e": PREFIX},
        )

        create_restore_bucket_args = {"Bucket": S3_RESTORE}
        if REGION != "us-east-1":
            create_restore_bucket_args["CreateBucketConfiguration"] = {"LocationConstraint": REGION}
        s3.create_bucket(**create_restore_bucket_args)
        created["restore_bucket"] = True
        s3.put_bucket_tagging(
            Bucket=S3_RESTORE,
            Tagging={"TagSet": [{"Key": OWNERSHIP_TAG, "Value": PREFIX}]},
        )
        if not _s3_owned(s3, S3_RESTORE):
            raise RuntimeError("AWS restore bucket ownership read-back failed.")
        _ledger_record(ledger, "s3_bucket", S3_RESTORE)
        s3.put_bucket_versioning(
            Bucket=S3_RESTORE,
            VersioningConfiguration={"Status": "Enabled"},
        )

        create_storage_bucket_args = {"Bucket": S3_STORAGE}
        if REGION != "us-east-1":
            create_storage_bucket_args["CreateBucketConfiguration"] = {
                "LocationConstraint": REGION
            }
        s3.create_bucket(**create_storage_bucket_args)
        s3.put_bucket_tagging(
            Bucket=S3_STORAGE,
            Tagging={"TagSet": [{"Key": OWNERSHIP_TAG, "Value": PREFIX}]},
        )
        if not _s3_owned(s3, S3_STORAGE):
            raise RuntimeError("AWS UI storage bucket ownership read-back failed.")
        _ledger_record(ledger, "s3_bucket", S3_STORAGE)
        s3.put_bucket_versioning(
            Bucket=S3_STORAGE,
            VersioningConfiguration={"Status": "Enabled"},
        )

        dynamodb.create_table(
            TableName=DDB_SOURCE,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            Tags=[{"Key": "BackupSheepE2E", "Value": PREFIX}],
        )
        created["ddb_source"] = True
        dynamodb.get_waiter("table_exists").wait(
            TableName=DDB_SOURCE,
            WaiterConfig={
                "Delay": min(POLL_SECONDS, 30),
                "MaxAttempts": max(1, int(TIMEOUT_SECONDS / min(POLL_SECONDS, 30))),
            },
        )
        ddb_source_table = _ddb_description_owned(dynamodb, DDB_SOURCE)
        if not ddb_source_table:
            raise RuntimeError("AWS DynamoDB source ownership read-back failed.")
        _ledger_record(
            ledger,
            "dynamodb_table",
            DDB_SOURCE,
            immutable_id=ddb_source_table["TableArn"],
        )
        dynamodb.put_item(
            TableName=DDB_SOURCE,
            Item={"id": {"S": "fixture"}, "marker": {"S": MARKER}},
        )

        default_vpcs = ec2.describe_vpcs(
            Filters=[{"Name": "is-default", "Values": ["true"]}]
        ).get("Vpcs", [])
        if not default_vpcs:
            raise RuntimeError("No default VPC is available for the disposable RDS test.")
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "default-for-az", "Values": ["true"]},
            ]
        ).get("Subnets", [])
        by_az = {}
        for subnet in subnets:
            by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
        subnet_ids = list(by_az.values())[:2]
        if len(subnet_ids) < 2:
            raise RuntimeError("At least two default subnets are required for RDS.")

        security_group_id = ec2.create_security_group(
            GroupName=RDS_SECURITY_GROUP,
            Description=f"Disposable BackupSheep E2E security group {PREFIX}",
            VpcId=vpc_id,
            TagSpecifications=[
                {
                    "ResourceType": "security-group",
                    "Tags": [{"Key": "BackupSheepE2E", "Value": PREFIX}],
                }
            ],
        )["GroupId"]
        created["security_group"] = True
        if not _ec2_security_group_owned(ec2, security_group_id):
            raise RuntimeError("AWS security group ownership read-back failed.")
        _ledger_record(
            ledger,
            "security_group",
            security_group_id,
            name=RDS_SECURITY_GROUP,
            source=vpc_id,
        )
        ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                _security_group_permission(
                    5432,
                    5432,
                    rds_cidrs,
                    "BackupSheep E2E RDS runner",
                )
            ],
        )

        rds.create_db_subnet_group(
            DBSubnetGroupName=RDS_SUBNET_GROUP,
            DBSubnetGroupDescription=f"Disposable BackupSheep E2E subnet group {PREFIX}",
            SubnetIds=subnet_ids,
            Tags=[{"Key": "BackupSheepE2E", "Value": PREFIX}],
        )
        created["subnet_group"] = True
        subnet_group = rds.describe_db_subnet_groups(
            DBSubnetGroupName=RDS_SUBNET_GROUP
        )["DBSubnetGroups"][0]
        subnet_group_arn = subnet_group["DBSubnetGroupArn"]
        subnet_tags = rds.list_tags_for_resource(
            ResourceName=subnet_group_arn
        ).get("TagList") or []
        if _tag_map(subnet_tags).get(OWNERSHIP_TAG) != PREFIX:
            raise RuntimeError("AWS RDS subnet group ownership read-back failed.")
        _ledger_record(
            ledger,
            "rds_subnet_group",
            subnet_group_arn,
            name=RDS_SUBNET_GROUP,
            source=",".join(sorted(subnet_ids)),
        )
        rds.create_db_instance(
            DBInstanceIdentifier=RDS_SOURCE,
            DBInstanceClass=os.environ.get("AWS_E2E_RDS_CLASS", "db.t3.micro"),
            Engine="postgres",
            AllocatedStorage=20,
            MasterUsername="bsadmin",
            MasterUserPassword=rds_password,
            DBSubnetGroupName=RDS_SUBNET_GROUP,
            VpcSecurityGroupIds=[security_group_id],
            BackupRetentionPeriod=1,
            PubliclyAccessible=True,
            StorageType="gp3",
            CopyTagsToSnapshot=True,
            DeletionProtection=False,
            Tags=[{"Key": "BackupSheepE2E", "Value": PREFIX}],
        )
        created["rds_source"] = True
        _register_rds_instance(ledger, rds, RDS_SOURCE)
        _wait(
            "source RDS availability",
            lambda: rds.describe_db_instances(DBInstanceIdentifier=RDS_SOURCE)[
                "DBInstances"
            ][0]["DBInstanceStatus"],
            {"available"},
            {"failed", "incompatible-restore", "incompatible-network"},
        )
        if not _rds_description_owned(rds, RDS_SOURCE):
            raise RuntimeError("AWS RDS source ownership read-back failed.")
        _rds_marker(rds, RDS_SOURCE, rds_password)

        # Create the BackupSheep-side source graph only for the resources above.
        account, member, user = factories.make_account(
            email=f"{PREFIX}-aws@example.invalid"
        )
        created["account"] = True
        key = account.get_encryption_key()
        aws_connection = factories.make_connection(
            account,
            member,
            code="aws",
            name=f"{PREFIX}-aws-connection",
        )
        aws_auth = CoreAuthAWS.objects.create(
            connection=aws_connection,
            region=CoreAWSRegion.objects.get(code=REGION),
            access_key=bs_encrypt(os.environ["AWS_ACCESS_KEY_ID"], key),
            secret_key=bs_encrypt(os.environ["AWS_SECRET_ACCESS_KEY"], key),
            backup_vault_name=BACKUP_VAULT,
            backup_role_arn=role_arn,
        )
        s3_node = CoreNode.objects.create(
            connection=aws_connection,
            type=CoreNode.Type.CLOUD,
            name=S3_SOURCE,
            added_by=member,
        )
        s3_aws = CoreAWS.objects.create(
            node=s3_node,
            name=S3_SOURCE,
            unique_id=S3_SOURCE,
            resource_type=CoreAWS.ResourceType.S3,
        )
        ddb_node = CoreNode.objects.create(
            connection=aws_connection,
            type=CoreNode.Type.CLOUD,
            name=DDB_SOURCE,
            added_by=member,
        )
        ddb_aws = CoreAWS.objects.create(
            node=ddb_node,
            name=DDB_SOURCE,
            unique_id=DDB_SOURCE,
            resource_type=CoreAWS.ResourceType.DYNAMODB,
        )

        s3_backup = CoreAWSBackup.objects.create(
            aws=s3_aws,
            uuid=f"{PREFIX}-s3-backup",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        s3_node.aws.create_snapshot(s3_backup)
        first_s3_job = s3_backup.unique_id
        # The application-level duplicate guard sees the persisted provider
        # reference and must not issue another create call.
        from apps._tasks.helper.tasks import run_provider_create  # noqa: E402

        run_provider_create(s3_backup, f"{PREFIX}-s3-duplicate", s3_node.aws.create_snapshot)
        if s3_backup.unique_id != first_s3_job:
            raise AssertionError("Duplicate S3 create changed the provider job id")
        report["tests"]["S3 backup duplicate guard"] = {"status": "PASS", "job_id": first_s3_job}
        report["tests"]["S3 backup"] = _wait_backup(s3_backup, "S3 AWS Backup job")
        s3_backup.refresh_from_db()
        s3_backup_state = dict((s3_backup.metadata or {}).get("_aws_backup") or {})
        s3_recovery_point = str(s3_backup_state.get("recovery_point_arn") or "")
        if not s3_recovery_point:
            raise RuntimeError("AWS S3 backup completed without a recovery point ARN.")
        _ledger_record(
            ledger,
            "recovery_point",
            s3_recovery_point,
            name=BACKUP_VAULT,
            source=S3_SOURCE,
        )

        s3_restore = CoreCloudRestore.objects.create(
            node=s3_node,
            backup_id=s3_backup.id,
            name=f"{PREFIX}-s3-restore",
            params={
                "destination_bucket_name": S3_RESTORE,
                "RestoreLatestVersionsUpTo": "all",
            },
        )
        s3_intent_key, _ = _prepare_restore_intent(
            intent_store,
            s3_restore,
            resource_type="s3",
            source_recovery_point_arn=s3_recovery_point,
            target_name=S3_RESTORE,
            account_id=str(report["account"]),
        )
        _start_or_reconcile_restore(
            s3_node.aws,
            backup_client,
            s3_restore,
            intent_store,
            s3_intent_key,
            start_callback=lambda: s3_node.aws.restore_snapshot(
                s3_backup, s3_restore
            ),
        )
        report["tests"]["S3 restore"] = _wait_restore(s3_node.aws, s3_restore, "S3 restore job")
        _finalize_s3_restore(
            s3,
            backup_client,
            s3_restore,
            intent_store,
            s3_intent_key,
            ledger,
            marker=MARKER,
        )
        report["tests"]["S3 restore data verification"] = {"status": "PASS", "key": OBJECT_KEY}

        ddb_backup = CoreAWSBackup.objects.create(
            aws=ddb_aws,
            uuid=f"{PREFIX}-ddb-backup",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        ddb_node.aws.create_snapshot(ddb_backup)
        report["tests"]["DynamoDB backup"] = _wait_backup(ddb_backup, "DynamoDB AWS Backup job")
        ddb_backup.refresh_from_db()
        ddb_backup_state = dict((ddb_backup.metadata or {}).get("_aws_backup") or {})
        ddb_recovery_point = str(ddb_backup_state.get("recovery_point_arn") or "")
        if not ddb_recovery_point:
            raise RuntimeError("AWS DynamoDB backup completed without a recovery point ARN.")
        _ledger_record(
            ledger,
            "recovery_point",
            ddb_recovery_point,
            name=BACKUP_VAULT,
            source=DDB_SOURCE,
        )
        ddb_restore = CoreCloudRestore.objects.create(
            node=ddb_node,
            backup_id=ddb_backup.id,
            name=DDB_RESTORE,
            params={"target_table_name": DDB_RESTORE},
        )
        ddb_intent_key, _ = _prepare_restore_intent(
            intent_store,
            ddb_restore,
            resource_type="dynamodb",
            source_recovery_point_arn=ddb_recovery_point,
            target_name=DDB_RESTORE,
            account_id=str(report["account"]),
        )
        _start_or_reconcile_restore(
            ddb_node.aws,
            backup_client,
            ddb_restore,
            intent_store,
            ddb_intent_key,
            start_callback=lambda: ddb_node.aws.restore_snapshot(
                ddb_backup, ddb_restore
            ),
        )
        report["tests"]["DynamoDB restore"] = _wait_restore(
            ddb_node.aws, ddb_restore, "DynamoDB restore job"
        )
        _finalize_ddb_restore(
            dynamodb,
            backup_client,
            ddb_restore,
            intent_store,
            ddb_intent_key,
            ledger,
            marker=MARKER,
        )
        created["ddb_restore"] = True
        report["tests"]["DynamoDB restore data verification"] = {"status": "PASS"}

        rds_connection = factories.make_connection(
            account,
            member,
            code="aws_rds",
            name=f"{PREFIX}-rds-connection",
        )
        rds_auth = CoreAuthAWSRDS.objects.create(
            connection=rds_connection,
            region=CoreAWSRegion.objects.get(code=REGION),
            access_key=bs_encrypt(os.environ["AWS_ACCESS_KEY_ID"], key),
            secret_key=bs_encrypt(os.environ["AWS_SECRET_ACCESS_KEY"], key),
        )
        rds_node = CoreNode.objects.create(
            connection=rds_connection,
            type=CoreNode.Type.CLOUD,
            name=RDS_SOURCE,
            added_by=member,
        )
        rds_aws = CoreAWSRDS.objects.create(
            node=rds_node,
            name=RDS_SOURCE,
            unique_id=RDS_SOURCE,
        )
        rds_backup = CoreAWSRDSBackup.objects.create(
            aws_rds=rds_aws,
            uuid=rds_snapshot_identifier,
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        rds_node.aws_rds.create_snapshot(rds_backup)
        snapshot_identifier = str(rds_backup.unique_id or rds_snapshot_identifier)
        _register_rds_snapshot(
            ledger,
            rds,
            snapshot_identifier,
            source=RDS_SOURCE,
        )
        report["tests"]["RDS native snapshot"] = _wait_backup(
            rds_backup, "RDS native snapshot"
        )
        rds_backup.refresh_from_db()
        snapshot_identifier = str(rds_backup.unique_id or rds_snapshot_identifier)
        snapshot = rds.describe_db_snapshots(
            DBSnapshotIdentifier=snapshot_identifier
        )["DBSnapshots"][0]
        rds.add_tags_to_resource(
            ResourceName=snapshot["DBSnapshotArn"],
            Tags=[{"Key": OWNERSHIP_TAG, "Value": PREFIX}],
        )
        if not _rds_description_owned(rds, snapshot_identifier, snapshot=True):
            raise RuntimeError("AWS RDS snapshot ownership read-back failed.")
        _ledger_record(
            ledger,
            "rds_snapshot",
            snapshot_identifier,
            source=RDS_SOURCE,
            immutable_id=snapshot["DBSnapshotArn"],
        )
        rds_restore = CoreCloudRestore.objects.create(
            node=rds_node,
            backup_id=rds_backup.id,
            name=RDS_RESTORE,
            params={
                "db_instance_class": os.environ.get("AWS_E2E_RDS_CLASS", "db.t3.micro"),
                "db_subnet_group_name": RDS_SUBNET_GROUP,
                "publicly_accessible": True,
                "vpc_security_group_ids": [security_group_id],
            },
        )
        rds_node.aws_rds.restore_snapshot(rds_backup, rds_restore)
        created["rds_restore"] = True
        started = time.monotonic()
        while True:
            try:
                restoring = rds.describe_db_instances(
                    DBInstanceIdentifier=RDS_RESTORE
                )["DBInstances"][0]
            except ClientError as error:
                if not _not_found(error):
                    raise
                restoring = None
            if restoring is not None:
                restoring_arn = restoring["DBInstanceArn"]
                if (
                    restoring.get("DBInstanceIdentifier") != RDS_RESTORE
                    or str(restoring.get("DBSnapshotIdentifier") or "")
                    != snapshot_identifier
                ):
                    raise RuntimeError("AWS RDS restore source ownership read-back failed.")
                rds.add_tags_to_resource(
                    ResourceName=restoring_arn,
                    Tags=[{"Key": OWNERSHIP_TAG, "Value": PREFIX}],
                )
                _register_rds_instance(
                    ledger,
                    rds,
                    RDS_RESTORE,
                    source=snapshot_identifier,
                )
                break
            if time.monotonic() - started > 120:
                raise RuntimeError(
                    "AWS accepted the RDS restore, but the exact target could not "
                    "be read back; manual reconciliation is required."
                )
            _sleep()
        _wait(
            "restored RDS availability",
            lambda: rds.describe_db_instances(DBInstanceIdentifier=RDS_RESTORE)[
                "DBInstances"
            ][0]["DBInstanceStatus"],
            {"available"},
            {"failed", "incompatible-restore", "incompatible-network", "incompatible-parameters"},
        )
        restored_rds = rds.describe_db_instances(
            DBInstanceIdentifier=RDS_RESTORE
        )["DBInstances"][0]
        rds.add_tags_to_resource(
            ResourceName=restored_rds["DBInstanceArn"],
            Tags=[{"Key": OWNERSHIP_TAG, "Value": PREFIX}],
        )
        if not _rds_description_owned(rds, RDS_RESTORE):
            raise RuntimeError("AWS RDS restore ownership read-back failed.")
        _assert_rds_marker(rds, RDS_RESTORE, rds_password)
        rds_restore.status = CoreCloudRestore.Status.COMPLETE
        rds_restore.save(update_fields=["status", "modified"])
        report["tests"]["RDS restore and data verification"] = {"status": "PASS"}
        report["status"] = "PASS"
    except _ResumeComplete:
        pass
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = _safe_error(error)
    finally:
        cleanup_errors = []
        if not CLEANUP:
            report["cleanup"] = {"status": "NOT_REQUESTED", "errors": []}
        elif ledger is None:
            report["cleanup"] = {
                "status": "MANUAL_REVIEW",
                "errors": ["Cleanup refused because the durable AWS ledger is unavailable."],
            }
        else:
            try:
                pending_errors = _reconcile_pending_restore_intents(
                    s3, dynamodb, backup_client, intent_store, ledger
                )
            except Exception as error:
                pending_errors = [f"restore intent reconciliation: {_safe_error(error)}"]
            if pending_errors:
                report["status"] = "MANUAL_REVIEW"
                report["cleanup"] = {
                    "status": "MANUAL_REVIEW",
                    "errors": pending_errors,
                }
                cleanup_errors.extend(pending_errors)

            def cleanup_eligible(kind, identifier):
                """Refuse every destructive cleanup after ambiguous reconciliation."""
                return not pending_errors and ledger.cleanup_eligible(kind, identifier)

            def refuse(kind, identifier, reason):
                reason = bounded_error(reason)
                cleanup_errors.append(f"{kind} {identifier}: {reason}")
                try:
                    ledger.mark_cleanup(
                        kind, identifier, state="manual_review", error=reason
                    )
                except LedgerError:
                    pass

            # New/forked RDS instances first. Exact account/region tags and the
            # durable ID are both required; a generated name has no authority.
            for identifier in (RDS_RESTORE, RDS_SOURCE):
                if not cleanup_eligible("rds_instance", identifier):
                    continue
                try:
                    entry = ledger.get("rds_instance", identifier) or {}
                    expected_arn = str(
                        (entry.get("ownership") or {}).get("provider_arn") or ""
                    )
                    if not expected_arn:
                        refuse("rds_instance", identifier, "missing immutable provider ARN")
                        continue
                    owned = _rds_description_owned(
                        rds, identifier, expected_arn=expected_arn
                    )
                    if owned is None:
                        ledger.mark_cleanup("rds_instance", identifier, state="absent")
                    elif owned is False:
                        refuse("rds_instance", identifier, "ownership tag mismatch")
                    else:
                        _delete_rds_instance(rds, identifier)
                        ledger.mark_cleanup("rds_instance", identifier, state="absent")
                except Exception as error:
                    refuse("rds_instance", identifier, f"ambiguous cleanup outcome: {error}")

            for entry in ledger.entries("rds_snapshot"):
                identifier = str(entry["resource_id"])
                if not cleanup_eligible("rds_snapshot", identifier):
                    continue
                try:
                    expected_arn = str(
                        (entry.get("ownership") or {}).get("provider_arn") or ""
                    )
                    if not expected_arn:
                        refuse("rds_snapshot", identifier, "missing immutable provider ARN")
                        continue
                    owned = _rds_description_owned(
                        rds,
                        identifier,
                        snapshot=True,
                        expected_arn=expected_arn,
                    )
                    if owned is None:
                        ledger.mark_cleanup("rds_snapshot", identifier, state="absent")
                    elif owned is False or str(owned.get("DBInstanceIdentifier")) != str(
                        entry.get("source_witness")
                    ):
                        refuse("rds_snapshot", identifier, "ownership/source mismatch")
                    else:
                        _delete_rds_snapshot(rds, identifier)
                        ledger.mark_cleanup("rds_snapshot", identifier, state="absent")
                except Exception as error:
                    refuse("rds_snapshot", identifier, f"ambiguous cleanup outcome: {error}")

            for table in (DDB_RESTORE, DDB_SOURCE):
                if not cleanup_eligible("dynamodb_table", table):
                    continue
                try:
                    entry = ledger.get("dynamodb_table", table) or {}
                    expected_arn = str(
                        (entry.get("ownership") or {}).get("provider_arn") or ""
                    )
                    if not expected_arn:
                        refuse("dynamodb_table", table, "missing immutable provider ARN")
                        continue
                    owned = _ddb_description_owned(
                        dynamodb, table, expected_arn=expected_arn
                    )
                    if owned is None:
                        ledger.mark_cleanup("dynamodb_table", table, state="absent")
                    elif owned is False:
                        refuse("dynamodb_table", table, "ownership tag mismatch")
                    else:
                        _delete_table(dynamodb, table)
                        ledger.mark_cleanup("dynamodb_table", table, state="absent")
                except Exception as error:
                    refuse("dynamodb_table", table, f"ambiguous cleanup outcome: {error}")

            allowed_buckets = {S3_RESTORE, S3_SOURCE, S3_STORAGE}
            for bucket_entry in ledger.entries("s3_bucket"):
                bucket = str(bucket_entry.get("resource_id") or "")
                if not cleanup_eligible("s3_bucket", bucket):
                    continue
                if (
                    bucket not in allowed_buckets
                    or str(bucket_entry.get("name") or "") != bucket
                ):
                    refuse("s3_bucket", bucket, "unexpected ledger bucket name")
                    continue
                try:
                    if not _s3_bucket_exists(s3, bucket):
                        ledger.mark_cleanup("s3_bucket", bucket, state="absent")
                    elif not _s3_owned(s3, bucket):
                        refuse("s3_bucket", bucket, "ownership tag mismatch")
                    else:
                        _delete_versioned_bucket(s3, bucket)
                        ledger.mark_cleanup("s3_bucket", bucket, state="absent")
                except Exception as error:
                    refuse("s3_bucket", bucket, f"ambiguous cleanup outcome: {error}")

            # Delete only the exact recovery point ARNs recorded after completed
            # BackupSheep jobs. Never enumerate a vault and delete arbitrary rows.
            for entry in ledger.entries("recovery_point"):
                recovery_point_arn = str(entry["resource_id"])
                if not cleanup_eligible("recovery_point", recovery_point_arn):
                    continue
                source = str(entry.get("source_witness") or "")
                expected_source_arn = (
                    f"arn:aws:s3:::{source}"
                    if source == S3_SOURCE
                    else f"arn:aws:dynamodb:{REGION}:{report.get('account')}:table/{source}"
                )
                try:
                    description = backup_client.describe_recovery_point(
                        BackupVaultName=BACKUP_VAULT,
                        RecoveryPointArn=recovery_point_arn,
                    )
                    if (
                        str(description.get("RecoveryPointArn") or "")
                        != recovery_point_arn
                        or str(description.get("ResourceArn") or "")
                        != expected_source_arn
                    ):
                        refuse(
                            "recovery_point",
                            recovery_point_arn,
                            "source ownership mismatch",
                        )
                        continue
                    _delete_recovery_point(
                        backup_client,
                        BACKUP_VAULT,
                        recovery_point_arn,
                    )
                    ledger.mark_cleanup(
                        "recovery_point", recovery_point_arn, state="absent"
                    )
                except ClientError as error:
                    if _not_found(error):
                        ledger.mark_cleanup(
                            "recovery_point", recovery_point_arn, state="absent"
                        )
                    else:
                        refuse(
                            "recovery_point",
                            recovery_point_arn,
                            f"ambiguous cleanup outcome: {error}",
                        )
                except Exception as error:
                    refuse(
                        "recovery_point",
                        recovery_point_arn,
                        f"ambiguous cleanup outcome: {error}",
                    )

            vault_entries = ledger.entries("backup_vault")
            if vault_entries:
                vault_entry = vault_entries[0]
                vault_resource_id = str(vault_entry["resource_id"])
                if cleanup_eligible("backup_vault", vault_resource_id):
                    try:
                        description = backup_client.describe_backup_vault(
                            BackupVaultName=BACKUP_VAULT
                        )
                        tags = backup_client.list_tags(
                            ResourceArn=description["BackupVaultArn"]
                        ).get("Tags") or {}
                        remaining = backup_client.list_recovery_points_by_backup_vault(
                            BackupVaultName=BACKUP_VAULT, MaxResults=1
                        ).get("RecoveryPoints") or []
                        if (
                            description.get("BackupVaultArn") != vault_resource_id
                            or str(tags.get(OWNERSHIP_TAG) or "") != PREFIX
                            or remaining
                        ):
                            refuse(
                                "backup_vault",
                                vault_resource_id,
                                "ownership mismatch or unrecorded recovery points remain",
                            )
                        else:
                            backup_client.delete_backup_vault(
                                BackupVaultName=BACKUP_VAULT
                            )
                            ledger.mark_cleanup(
                                "backup_vault", vault_resource_id, state="deleted"
                            )
                    except ClientError as error:
                        if _not_found(error):
                            ledger.mark_cleanup(
                                "backup_vault", vault_resource_id, state="absent"
                            )
                        else:
                            refuse(
                                "backup_vault",
                                vault_resource_id,
                                f"ambiguous cleanup outcome: {error}",
                            )
                    except Exception as error:
                        refuse(
                            "backup_vault",
                            vault_resource_id,
                            f"ambiguous cleanup outcome: {error}",
                        )

            for security_group_entry in ledger.entries("security_group"):
                security_group_resource_id = str(
                    security_group_entry["resource_id"]
                )
                if not cleanup_eligible(
                    "security_group", security_group_resource_id
                ):
                    continue
                try:
                    owned = _ec2_security_group_owned(
                        ec2, security_group_resource_id
                    )
                    if owned is None:
                        ledger.mark_cleanup(
                            "security_group",
                            security_group_resource_id,
                            state="absent",
                        )
                    elif (
                        owned is False
                        or owned.get("GroupName")
                        != security_group_entry.get("name")
                        or str(owned.get("VpcId") or "")
                        != str(security_group_entry.get("source_witness") or "")
                    ):
                        refuse(
                            "security_group",
                            security_group_resource_id,
                            "ownership/name/VPC mismatch",
                        )
                    else:
                        ec2.delete_security_group(
                            GroupId=security_group_resource_id
                        )
                        started = time.monotonic()
                        while _ec2_security_group_owned(
                            ec2, security_group_resource_id
                        ) is not None:
                            if time.monotonic() - started > 120:
                                raise RuntimeError(
                                    "security group remained after delete"
                                )
                            _sleep()
                        ledger.mark_cleanup(
                            "security_group",
                            security_group_resource_id,
                            state="deleted",
                        )
                except Exception as error:
                    refuse(
                        "security_group",
                        security_group_resource_id,
                        f"ambiguous cleanup outcome: {error}",
                    )

            subnet_entries = ledger.entries("rds_subnet_group")
            if subnet_entries:
                subnet_entry = subnet_entries[0]
                subnet_resource_id = str(subnet_entry["resource_id"])
                if cleanup_eligible("rds_subnet_group", subnet_resource_id):
                    try:
                        group = rds.describe_db_subnet_groups(
                            DBSubnetGroupName=RDS_SUBNET_GROUP
                        )["DBSubnetGroups"][0]
                        tags = rds.list_tags_for_resource(
                            ResourceName=group["DBSubnetGroupArn"]
                        ).get("TagList") or []
                        if (
                            group["DBSubnetGroupArn"] != subnet_resource_id
                            or _tag_map(tags).get(OWNERSHIP_TAG) != PREFIX
                        ):
                            refuse(
                                "rds_subnet_group",
                                subnet_resource_id,
                                "ownership mismatch",
                            )
                        else:
                            rds.delete_db_subnet_group(
                                DBSubnetGroupName=RDS_SUBNET_GROUP
                            )
                            ledger.mark_cleanup(
                                "rds_subnet_group", subnet_resource_id, state="deleted"
                            )
                    except ClientError as error:
                        if _not_found(error):
                            ledger.mark_cleanup(
                                "rds_subnet_group", subnet_resource_id, state="absent"
                            )
                        else:
                            refuse(
                                "rds_subnet_group",
                                subnet_resource_id,
                                f"ambiguous cleanup outcome: {error}",
                            )
                    except Exception as error:
                        refuse(
                            "rds_subnet_group",
                            subnet_resource_id,
                            f"ambiguous cleanup outcome: {error}",
                        )

            role_entries = ledger.entries("iam_role")
            if role_entries:
                role_entry = role_entries[0]
                role_resource_id = str(role_entry["resource_id"])
                if cleanup_eligible("iam_role", role_resource_id):
                    try:
                        observed = iam.get_role(RoleName=ROLE_NAME)["Role"]
                        tags = iam.list_role_tags(RoleName=ROLE_NAME).get("Tags") or []
                        if (
                            observed.get("Arn") != role_resource_id
                            or _tag_map(tags).get(OWNERSHIP_TAG) != PREFIX
                        ):
                            refuse("iam_role", role_resource_id, "ownership mismatch")
                        else:
                            for policy_arn in (
                                "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
                                "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
                                "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup",
                                "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore",
                            ):
                                iam.detach_role_policy(
                                    RoleName=ROLE_NAME, PolicyArn=policy_arn
                                )
                            iam.delete_role(RoleName=ROLE_NAME)
                            ledger.mark_cleanup(
                                "iam_role", role_resource_id, state="deleted"
                            )
                    except ClientError as error:
                        if _not_found(error):
                            ledger.mark_cleanup(
                                "iam_role", role_resource_id, state="absent"
                            )
                        else:
                            refuse(
                                "iam_role",
                                role_resource_id,
                                f"ambiguous cleanup outcome: {error}",
                            )
                    except Exception as error:
                        refuse(
                            "iam_role",
                            role_resource_id,
                            f"ambiguous cleanup outcome: {error}",
                        )

            if account is None and not cleanup_errors:
                try:
                    account, user = _recover_local_fixture()
                except Exception as error:
                    cleanup_errors.append(
                        f"recover BackupSheep test account: {_safe_error(error)}"
                    )
            if account is not None and not cleanup_errors:
                try:
                    account.delete()
                except Exception as error:
                    cleanup_errors.append(
                        f"BackupSheep test account: {_safe_error(error)}"
                    )
            if user is not None and not cleanup_errors:
                try:
                    user.delete()
                except Exception as error:
                    cleanup_errors.append(
                        f"BackupSheep test user: {_safe_error(error)}"
                    )
            report["cleanup"] = {
                "status": "PASS" if not cleanup_errors else "MANUAL_REVIEW",
                "errors": cleanup_errors,
            }
        client_guard.__exit__(None, None, None)
        print(json.dumps(report, indent=2, sort_keys=True, default=str))

    cleanup_ok = report["cleanup"]["status"] in {"PASS", "NOT_REQUESTED"}
    return 0 if report.get("status") == "PASS" and cleanup_ok else 1


if __name__ == "__main__":
    required = (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "BACKUPSHEEP_E2E_RUN_ID",
        "BACKUPSHEEP_E2E_LEDGER_PATH",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "error": "Missing required environment variables: "
                    + ", ".join(missing),
                },
                indent=2,
            )
        )
        sys.exit(1)
    sys.exit(main())
