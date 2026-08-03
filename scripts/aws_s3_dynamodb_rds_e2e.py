"""Disposable AWS end-to-end test for the AWS S3/DynamoDB/RDS integrations.

The script creates one uniquely prefixed fixture set, exercises backup and
restore status through the BackupSheep models, verifies the restored data, and
removes only the resources whose names carry this run's prefix.  It is intended
to run inside the app image with AWS credentials supplied through the process
environment; it never reads credentials from the repository.

Example:

    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
      python scripts/aws_s3_dynamodb_rds_e2e.py
"""

import datetime as dt
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


REGION = os.environ.get("AWS_E2E_REGION", "us-east-1")
POLL_SECONDS = max(int(os.environ.get("AWS_E2E_POLL_SECONDS", "20")), 5)
TIMEOUT_SECONDS = max(int(os.environ.get("AWS_E2E_TIMEOUT_SECONDS", "3600")), 300)


def _unique_prefix():
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%y%m%d%H%M%S")
    return f"bs-codex-{stamp}-{secrets.token_hex(3)}"


PREFIX = _unique_prefix()
S3_SOURCE = f"{PREFIX}-source"
S3_RESTORE = f"{PREFIX}-restore"
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


def main():
    report = {"prefix": PREFIX, "region": REGION, "tests": {}, "cleanup": []}
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
    role_arn = None
    vault = None
    subnet_ids = []
    security_group_id = None
    rds_password = secrets.token_urlsafe(24)
    rds_snapshot_identifier = f"{PREFIX}-rds-snapshot"
    rds = boto3.client("rds", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    dynamodb = boto3.client("dynamodb", region_name=REGION)
    backup_client = boto3.client("backup", region_name=REGION)
    iam = boto3.client("iam", region_name=REGION)

    try:
        identity = boto3.client("sts", region_name=REGION).get_caller_identity()
        report["account"] = identity.get("Account")
        report["caller"] = str(identity.get("Arn", "")).split("/")[-1]

        # Read-only collision check. The random prefix must not exist before we
        # create anything, and every cleanup target below is guarded by this prefix.
        existing = {
            "s3": [
                b["Name"]
                for b in s3.list_buckets().get("Buckets", [])
                if b.get("Name", "").startswith(PREFIX)
            ],
            "dynamodb": [
                n for n in dynamodb.list_tables().get("TableNames", []) if n.startswith(PREFIX)
            ],
            "rds": [
                d["DBInstanceIdentifier"]
                for d in rds.describe_db_instances().get("DBInstances", [])
                if d.get("DBInstanceIdentifier", "").startswith(PREFIX)
            ],
            "vaults": [
                v["BackupVaultName"]
                for v in backup_client.list_backup_vaults().get("BackupVaultList", [])
                if v.get("BackupVaultName", "").startswith(PREFIX)
            ],
        }
        report["baseline_collisions"] = existing
        if any(existing.values()):
            raise RuntimeError(f"Unique test prefix is already in use: {existing}")

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

        create_bucket_args = {"Bucket": S3_SOURCE}
        if REGION != "us-east-1":
            create_bucket_args["CreateBucketConfiguration"] = {"LocationConstraint": REGION}
        s3.create_bucket(**create_bucket_args)
        created["source_bucket"] = True
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
        s3.put_bucket_versioning(
            Bucket=S3_RESTORE,
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
        _wait(
            "source RDS availability",
            lambda: rds.describe_db_instances(DBInstanceIdentifier=RDS_SOURCE)[
                "DBInstances"
            ][0]["DBInstanceStatus"],
            {"available"},
            {"failed", "incompatible-restore", "incompatible-network"},
        )
        _rds_marker(rds, RDS_SOURCE, rds_password)

        # Create the BackupSheep-side source graph only for the resources above.
        account, member, _ = factories.make_account(
            email=f"{PREFIX}@example.invalid"
        )
        created["account"] = True
        key = account.get_encryption_key()
        aws_connection = factories.make_connection(account, member, code="aws")
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
        created["ddb_restore"] = True
        report["tests"]["DynamoDB restore data verification"] = {"status": "PASS"}

        rds_connection = factories.make_connection(account, member, code="aws_rds")
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
        report["tests"]["RDS native snapshot"] = _wait_backup(
            rds_backup, "RDS native snapshot"
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
        _wait(
            "restored RDS availability",
            lambda: rds.describe_db_instances(DBInstanceIdentifier=RDS_RESTORE)[
                "DBInstances"
            ][0]["DBInstanceStatus"],
            {"available"},
            {"failed", "incompatible-restore", "incompatible-network", "incompatible-parameters"},
        )
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
        # Cleanup is deliberately exact-name and prefix-scoped. Never enumerate
        # and delete an existing user resource outside this run's names.
        cleanup_errors = []
        for identifier in (RDS_RESTORE, RDS_SOURCE):
            if identifier.startswith(PREFIX):
                try:
                    _delete_rds_instance(rds, identifier)
                except Exception as error:
                    cleanup_errors.append(f"RDS {identifier}: {error}")
        try:
            if rds_snapshot_identifier.startswith(PREFIX):
                rds.delete_db_snapshot(DBSnapshotIdentifier=rds_snapshot_identifier)
        except Exception as error:
            if not _not_found(error):
                cleanup_errors.append(f"RDS snapshot: {error}")
        for table in (DDB_RESTORE, DDB_SOURCE):
            if table.startswith(PREFIX):
                try:
                    _delete_table(dynamodb, table)
                except Exception as error:
                    cleanup_errors.append(f"DynamoDB {table}: {error}")
        for bucket in (S3_RESTORE, S3_SOURCE):
            if bucket.startswith(PREFIX):
                try:
                    _delete_versioned_bucket(s3, bucket)
                except Exception as error:
                    cleanup_errors.append(f"S3 {bucket}: {error}")
        if created["vault"]:
            try:
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline:
                    points = backup_client.list_recovery_points_by_backup_vault(
                        BackupVaultName=BACKUP_VAULT
                    ).get("RecoveryPoints", [])
                    if not points:
                        break
                    for point in points:
                        backup_client.delete_recovery_point(
                            BackupVaultName=BACKUP_VAULT,
                            RecoveryPointArn=point["RecoveryPointArn"],
                        )
                    time.sleep(POLL_SECONDS)
                backup_client.delete_backup_vault(BackupVaultName=BACKUP_VAULT)
            except Exception as error:
                cleanup_errors.append(f"AWS Backup vault: {error}")
        if created["security_group"] and security_group_id:
            try:
                ec2.delete_security_group(GroupId=security_group_id)
            except Exception as error:
                if not _not_found(error):
                    cleanup_errors.append(f"security group: {error}")
        if created["subnet_group"]:
            try:
                rds.delete_db_subnet_group(DBSubnetGroupName=RDS_SUBNET_GROUP)
            except Exception as error:
                if not _not_found(error):
                    cleanup_errors.append(f"RDS subnet group: {error}")
        if created["role"]:
            for policy_arn in (
                "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
                "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
                "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup",
                "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore",
            ):
                try:
                    iam.detach_role_policy(RoleName=ROLE_NAME, PolicyArn=policy_arn)
                except Exception as error:
                    if not _not_found(error):
                        cleanup_errors.append(f"detach {policy_arn}: {error}")
            try:
                iam.delete_role(RoleName=ROLE_NAME)
            except Exception as error:
                if not _not_found(error):
                    cleanup_errors.append(f"IAM role: {error}")
        if created["account"] and account is not None:
            try:
                account.delete()
            except Exception as error:
                cleanup_errors.append(f"BackupSheep test account: {error}")
        report["cleanup"] = {"status": "PASS" if not cleanup_errors else "FAIL", "errors": cleanup_errors}
        print(json.dumps(report, indent=2, sort_keys=True, default=str))

    return 0 if report.get("status") == "PASS" and not report["cleanup"]["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
