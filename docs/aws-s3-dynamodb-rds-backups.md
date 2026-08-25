# AWS S3, DynamoDB, and RDS backups

The `aws` cloud source supports Amazon S3 buckets and DynamoDB tables in addition
to EC2 instances and EBS volumes. S3 and DynamoDB use AWS Backup's asynchronous
backup and restore APIs. The separate `aws_rds` source continues to use native RDS
DB snapshots because that path preserves the existing RDS-specific restore options.

## Configuration

In the AWS connection form, configure:

* **Region** — the region containing the resources.
* **Backup vault** — an existing AWS Backup vault; `Default` is used when omitted.
* **Backup IAM role ARN** — optional. If omitted, BackupSheep uses
  `AWSBackupDefaultServiceRole` in the connection's AWS account.

The role supplied to AWS Backup must trust `backup.amazonaws.com` and have the
provider-managed permissions required for the resource types in use. For S3 and
DynamoDB, the AWS managed backup and restore policies are the reference baseline:

* `AWSBackupServiceRolePolicyForBackup`
* `AWSBackupServiceRolePolicyForRestores`
* `AWSBackupServiceRolePolicyForS3Backup` (S3)
* `AWSBackupServiceRolePolicyForS3Restore` (S3 restore)

AWS Backup resource-type opt-in must also be enabled in the target region. The
connection validation and discovery calls are read-only; selecting a resource does
not create a provider backup.

## Resource requirements

* S3 discovery is region-scoped. Buckets in `us-east-1` are reported by AWS as a
  null bucket location and are normalized to `us-east-1`.
* S3 source buckets must have versioning enabled. The restore destination must also
  be an existing versioned bucket selected explicitly by `destination_bucket_name`.
  Restore never silently overwrites the source bucket. ACL restoration is disabled
  by default so modern `BucketOwnerEnforced` destinations work; set `RestoreACLs`
  to true only when the destination supports ACLs.
* DynamoDB discovery is paginated and only tables in the configured region are
  offered. A DynamoDB restore creates a new table; provide `target_table_name` (or
  use the restore name) and do not reuse the source table name.
* RDS restore uses the existing native RDS snapshot flow. Use a new DB instance
  identifier and provide the required subnet group, security groups, and class for
  the target account/VPC.

## Durable job and restore behavior

AWS Backup returns a `BackupJobId` immediately. BackupSheep stores it on the backup
row, together with the vault, resource ARN, resource type, and recovery-point data.
Status polling calls `DescribeBackupJob` and records the provider response. A worker
crash or server restart therefore resumes polling the same AWS job instead of
starting a second backup. The AWS idempotency token is deterministic for the backup
identity as an additional provider-side duplicate guard.

Restore rows persist the AWS `RestoreJobId`, recovery point ARN, and restore
parameters. Redelivered restore tasks poll the existing job; they do not call
`StartRestoreJob` again. Completed restores are verified by checking that the S3
destination exists or the DynamoDB target reaches `ACTIVE`. Failed provider states
are retained as failed with the provider message.

Native RDS snapshots use a deterministic snapshot identifier, persist the
provider status payload in JSON-safe form, and are polled until `available`.
RDS restores persist the target instance identifier and are checked through the
same asynchronous restore-status task, so a worker restart resumes status checks
against the existing target rather than issuing another restore request.

Deleting an AWS cloud backup deletes only the recorded recovery point from the
configured vault. It does not delete the source bucket, source table, source RDS
instance, or any resource not owned by that BackupSheep backup row.

## Verification

Focused local coverage, after creating the manual Compose configuration and protected
`.secrets` files from the installation guide:

```bash
./backupsheep-compose build db app app-egress-guard
./backupsheep-compose --allow-reviewed-runtime-overrides run --rm --no-deps \
  -e DJANGO_SERVER=test app \
  python manage.py test apps.tests.test_aws_backup_resources
```

The disposable live harness is:

```text
scripts/aws_s3_dynamodb_rds_e2e.py
```

It creates a unique, prefix-scoped S3 source/destination pair, DynamoDB source and
restore table, Backup vault, IAM role, RDS source/restore instances, subnet group,
and security group. It first checks that the generated prefix is unused, then tests
the following cases:

| Case | Assertion |
| --- | --- |
| Account and collision guard | STS identity succeeds; no pre-existing test-prefix resource exists |
| S3 discovery | Source bucket is discovered only in the configured region |
| DynamoDB discovery | Table discovery and table-size normalization work |
| S3 backup | AWS Backup accepts the source and the persisted job reaches completion |
| S3 duplicate delivery | Re-running provider creation preserves the original BackupJobId |
| S3 restore | Restore job completes into the explicitly supplied versioned destination and the marker object matches |
| DynamoDB backup | AWS Backup job completes and a recovery point is recorded |
| DynamoDB restore | A new table reaches `ACTIVE` and the marker item matches |
| RDS snapshot | Native RDS snapshot reaches `available` |
| RDS restore | A new RDS instance reaches `available` and the PostgreSQL marker matches |
| Exact cleanup | Only resources created by the run are removed; final prefix inventory is empty |

The harness reads credentials from environment variables, uses no existing resource
as a test target, and performs exact-name cleanup in `finally`. Run it only with a
test account/region where temporary RDS and AWS Backup charges are acceptable.

Recorded live verification on 2026-08-03 used the disposable prefix
`bs-codex-260803104128-33d293` in `us-east-1`. All S3, DynamoDB, and native RDS
backup/restore assertions passed, including S3 marker-object verification,
DynamoDB marker-item verification, PostgreSQL marker verification, and the S3
duplicate-create guard. AWS and local cleanup both completed with no errors; a
final exact-prefix inventory was empty and the generated local test user was
removed.

References: [AWS Backup S3 backups](https://docs.aws.amazon.com/aws-backup/latest/devguide/s3-backups.html),
[restoring S3](https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-s3.html),
[restoring DynamoDB](https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-dynamodb.html),
[StartBackupJob](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_StartBackupJob.html),
[StartRestoreJob](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_StartRestoreJob.html),
and [restoring RDS](https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-rds.html).
