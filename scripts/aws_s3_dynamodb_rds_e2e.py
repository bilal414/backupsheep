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
      BACKUPSHEEP_E2E_RUN_ID=bs-e2e-20260810-5b4a6b63 \
      BACKUPSHEEP_E2E_LEDGER_PATH=/code/_storage/e2e-ledgers/aws.json \
      BACKUPSHEEP_E2E_APPLY=YES BACKUPSHEEP_E2E_CLEANUP=YES \
      python scripts/aws_s3_dynamodb_rds_e2e.py
"""

import ipaddress
import json
import os
import secrets
import sys
import time
import traceback
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import boto3
import django
import psycopg2
from botocore.exceptions import ClientError
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
from scripts.live_e2e_ledger import (  # noqa: E402
    DurableResourceLedger,
    LedgerError,
    require_run_id,
)


REGION = os.environ.get("AWS_E2E_REGION", "us-east-2")
POLL_SECONDS = max(int(os.environ.get("AWS_E2E_POLL_SECONDS", "20")), 5)
TIMEOUT_SECONDS = max(int(os.environ.get("AWS_E2E_TIMEOUT_SECONDS", "3600")), 300)
_RUN_ID = os.environ.get("BACKUPSHEEP_E2E_RUN_ID")
PREFIX = require_run_id(_RUN_ID) if _RUN_ID else ""
APPLY = os.environ.get("BACKUPSHEEP_E2E_APPLY") == "YES"
CLEANUP = os.environ.get("BACKUPSHEEP_E2E_CLEANUP") == "YES"
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
        while True:
            response = s3.list_object_versions(Bucket=bucket)
            entries = []
            entries.extend(
                {"Key": row["Key"], "VersionId": row["VersionId"]}
                for row in response.get("Versions") or []
            )
            entries.extend(
                {"Key": row["Key"], "VersionId": row["VersionId"]}
                for row in response.get("DeleteMarkers") or []
            )
            if not entries:
                break
            for offset in range(0, len(entries), 1000):
                s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": entries[offset : offset + 1000], "Quiet": True},
                )
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
    while True:
        params = {"MaxResults": 100}
        if next_token:
            params["NextToken"] = next_token
        response = backup_client.list_backup_vaults(**params)
        if any(
            str(vault.get("BackupVaultName") or "") == name
            for vault in (response.get("BackupVaultList") or [])
        ):
            return True
        next_token = response.get("NextToken")
        if not next_token:
            return False
        if next_token in seen_tokens:
            raise RuntimeError("AWS Backup returned a repeated vault pagination token")
        seen_tokens.add(next_token)


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


def _ddb_description_owned(dynamodb, name):
    try:
        table = dynamodb.describe_table(TableName=name)["Table"]
        tags = dynamodb.list_tags_of_resource(
            ResourceArn=table["TableArn"]
        ).get("Tags") or []
    except (ClientError, KeyError):
        return None
    return table if _tag_map(tags).get(OWNERSHIP_TAG) == PREFIX else False


def _rds_description_owned(rds, identifier, *, snapshot=False):
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


def _ledger_record(ledger, kind, resource_id, *, name=None, source=""):
    ledger.record(
        kind=kind,
        resource_id=resource_id,
        name=name or resource_id,
        ownership={"tag_key": OWNERSHIP_TAG, "tag_value": PREFIX},
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


def main():
    report = {"prefix": PREFIX, "region": REGION, "tests": {}, "cleanup": []}
    ledger = None
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
    rds_password = secrets.token_urlsafe(24)
    rds_snapshot_identifier = f"{PREFIX}-rds-snapshot"
    rds = boto3.client("rds", region_name=REGION, config=BOTO_CONFIG)
    ec2 = boto3.client("ec2", region_name=REGION, config=BOTO_CONFIG)
    s3 = boto3.client("s3", region_name=REGION, config=BOTO_CONFIG)
    dynamodb = boto3.client("dynamodb", region_name=REGION, config=BOTO_CONFIG)
    backup_client = boto3.client("backup", region_name=REGION, config=BOTO_CONFIG)
    iam = boto3.client("iam", region_name=REGION, config=BOTO_CONFIG)

    try:
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

        report["exact_preflight"] = _exact_preflight(
            s3, dynamodb, rds, ec2, backup_client, iam
        )
        report["baseline_collisions"] = report["exact_preflight"]

        if not APPLY:
            report["status"] = "PREFLIGHT_PASS"
            report["mode"] = "read_only"
            return 0

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
        dynamodb.get_waiter("table_exists").wait(TableName=DDB_SOURCE)
        if not _ddb_description_owned(dynamodb, DDB_SOURCE):
            raise RuntimeError("AWS DynamoDB source ownership read-back failed.")
        _ledger_record(ledger, "dynamodb_table", DDB_SOURCE)
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

        public_ip = ipaddress.ip_address(
            urllib.request.urlopen("https://checkip.amazonaws.com", timeout=15)
            .read()
            .decode()
            .strip()
        )
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
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpRanges": [{"CidrIp": f"{public_ip}/32", "Description": "BackupSheep E2E runner"}],
                }
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
        s3_node.aws.restore_snapshot(s3_backup, s3_restore)
        report["tests"]["S3 restore"] = _wait_restore(s3_node.aws, s3_restore, "S3 restore job")
        restored = s3.get_object(Bucket=S3_RESTORE, Key=OBJECT_KEY)["Body"].read().decode()
        if restored != MARKER:
            raise AssertionError(f"S3 restore marker mismatch: {restored!r}")
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
        ddb_node.aws.restore_snapshot(ddb_backup, ddb_restore)
        report["tests"]["DynamoDB restore"] = _wait_restore(
            ddb_node.aws, ddb_restore, "DynamoDB restore job"
        )
        item = dynamodb.get_item(
            TableName=DDB_RESTORE,
            Key={"id": {"S": "fixture"}},
        ).get("Item") or {}
        if item.get("marker", {}).get("S") != MARKER:
            raise AssertionError(f"DynamoDB restore marker mismatch: {item!r}")
        restored_table = dynamodb.describe_table(TableName=DDB_RESTORE)["Table"]
        dynamodb.tag_resource(
            ResourceArn=restored_table["TableArn"],
            Tags=[{"Key": OWNERSHIP_TAG, "Value": PREFIX}],
        )
        if not _ddb_description_owned(dynamodb, DDB_RESTORE):
            raise RuntimeError("AWS DynamoDB restore ownership read-back failed.")
        _ledger_record(
            ledger,
            "dynamodb_table",
            DDB_RESTORE,
            source=ddb_recovery_point,
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
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = str(error)
        traceback.print_exc()
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
            def refuse(kind, identifier, reason):
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
                if not ledger.cleanup_eligible("rds_instance", identifier):
                    continue
                try:
                    owned = _rds_description_owned(rds, identifier)
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
                if not ledger.cleanup_eligible("rds_snapshot", identifier):
                    continue
                try:
                    owned = _rds_description_owned(rds, identifier, snapshot=True)
                    if owned is None:
                        ledger.mark_cleanup("rds_snapshot", identifier, state="absent")
                    elif owned is False or str(owned.get("DBInstanceIdentifier")) != str(
                        entry.get("source_witness")
                    ):
                        refuse("rds_snapshot", identifier, "ownership/source mismatch")
                    else:
                        rds.delete_db_snapshot(DBSnapshotIdentifier=identifier)
                        ledger.mark_cleanup("rds_snapshot", identifier, state="deleted")
                except Exception as error:
                    refuse("rds_snapshot", identifier, f"ambiguous cleanup outcome: {error}")

            for table in (DDB_RESTORE, DDB_SOURCE):
                if not ledger.cleanup_eligible("dynamodb_table", table):
                    continue
                try:
                    owned = _ddb_description_owned(dynamodb, table)
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
                if not ledger.cleanup_eligible("s3_bucket", bucket):
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
                if not ledger.cleanup_eligible("recovery_point", recovery_point_arn):
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
                    backup_client.delete_recovery_point(
                        BackupVaultName=BACKUP_VAULT,
                        RecoveryPointArn=recovery_point_arn,
                    )
                    ledger.mark_cleanup(
                        "recovery_point", recovery_point_arn, state="deleted"
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
                if ledger.cleanup_eligible("backup_vault", vault_resource_id):
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
                if not ledger.cleanup_eligible(
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
                if ledger.cleanup_eligible("rds_subnet_group", subnet_resource_id):
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
                if ledger.cleanup_eligible("iam_role", role_resource_id):
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
                    cleanup_errors.append(f"recover BackupSheep test account: {error}")
            if account is not None and not cleanup_errors:
                try:
                    account.delete()
                except Exception as error:
                    cleanup_errors.append(f"BackupSheep test account: {error}")
            if user is not None and not cleanup_errors:
                try:
                    user.delete()
                except Exception as error:
                    cleanup_errors.append(f"BackupSheep test user: {error}")
            report["cleanup"] = {
                "status": "PASS" if not cleanup_errors else "MANUAL_REVIEW",
                "errors": cleanup_errors,
            }
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
