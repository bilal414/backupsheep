# AWS Lightsail live backup test report

> Historical evidence only — do not rerun this report. AWS Lightsail is outside
> the current mutation and cleanup scope and must remain untouched, even when
> credentials for other AWS services are available.

Date: 2026-08-02<br>
Region: `us-east-1` / `us-east-1a`<br>
Scope: the AWS account represented by the locally supplied admin key, using only
resources whose names began with `backupsheep-aws-e2e-20260802-a1c4534d`.

No access key, secret, private key, database password, or decrypted credential is
included in this report.

## Safety baseline

The initial read-only inventory found zero Lightsail instances, disks, instance
snapshots, disk snapshots, relational databases, or database snapshots in the test
region, and zero S3 buckets in the account. The test created a dedicated Lightsail
key pair, source instance, S3 bucket, PostgreSQL fixture, and temporary restore
instance. A temporary 8-GB disk was also created while exercising the volume branch.

The final provider inventory found no resources under the test prefix. The temporary
BackupSheep account, connection records, nodes, storage record, backup rows, and
restore rows were also gone after the disposable harness teardown. Existing AWS
resources were not selected or modified.

## Test matrix

| ID | Test | Result | Evidence |
| --- | --- | --- | --- |
| AWS-01 | Parse the local key file, call STS identity, select `us-east-1`, and inventory existing resources | PASS | Identity and zero-resource baseline recorded before provisioning |
| AWS-02 | Create/use/delete an isolated Lightsail key pair | PASS | Replacement key authenticated to the source instance; exact key was removed during cleanup |
| AWS-03 | Create S3 bucket, verify ownership/access, run BackupSheep S3 validation, and clean up | PASS | `head_bucket` and the storage put/get/delete probe succeeded; bucket was empty at final inventory |
| AWS-04 | Validate Lightsail credentials and enumerate eligible instances | PASS | Connection validation and eligible-object lookup succeeded |
| AWS-05 | SFTP file backup to the AWS S3 storage backend | PASS | Archive contained `backup-fixture/fixture.txt` and `backup-fixture/subdir/nested.txt`; fixture marker was verified inside the downloaded S3 zip |
| AWS-06 | Restore the file archive after mutating both files | PASS | Restore completed and both original fixture markers were read back over SSH |
| AWS-07 | PostgreSQL backup over SSH to the AWS S3 storage backend | PASS | Archive contained `bs_aws_e2e.sql`; the database fixture marker was verified inside the downloaded S3 zip |
| AWS-08 | Restore PostgreSQL after mutating the fixture row | PASS | Restore completed and the original database marker was read back over SSH |
| AWS-09 | Lightsail instance snapshot with duplicate deliveries | PASS | Same-ID and different-ID duplicate deliveries exited while the first snapshot was in flight; exactly one provider snapshot/BackupSheep cloud-backup row remained |
| AWS-10 | Restore the Lightsail instance snapshot to a new instance | PASS after fix | The first attempt exposed Lightsail's regional `availabilityZone=all` response. The adapter now falls back to the source instance AZ; the rerun created a running instance and SSH-verified both file and database fixtures |
| AWS-11 | Volume restore AZ fallback | PASS in unit coverage; live provider cleanup completed | Mocked Lightsail disk restore coverage verifies `all` falls back to the source disk AZ. The temporary live disk was removed before final inventory |
| AWS-12 | Final cleanup and resource-drift check | PASS | Exact-prefix Lightsail/S3 inventory and local ORM inventory were empty |
| AWS-13 | Worker crash/restart during an in-progress Lightsail snapshot | PASS | After AWS accepted a second isolated snapshot, the cloud worker was stopped and recreated. The persisted row resumed from its provider reference and reached `Complete`; AWS contained one snapshot for that backup name |
| AWS-14 | Full regression after the live run | PASS | Focused duplicate/recovery suite: 102/102. Full Django suite: 341/341 |

## Changes made

* `CoreLightsail.restore_snapshot()` now treats Lightsail's regional `all`/`global`
  marker as non-concrete and obtains a valid AZ from the source instance or disk.
* Cloud restore rows now enter `In-Progress` before the provider request, so API
  consumers can distinguish an accepted restore from a queued one.
* The async poll lease now records the next poll ETA. A scheduled successor can claim
  the poll after that ETA while a healthy poll still owns the safety lease. This
  prevents a five-minute lease from suppressing the next two-minute poll forever.
* Regression coverage was added for the poll-lease handoff. The duplicate-backup
  suite also covers active-state blocking, same-task retry reuse, provider-create
  leases, storage-phase recovery, and concurrent initiation.

## Harness observations

AWS Lightsail's boto3 response fields are named `privateKeyBase64` and
`publicKeyBase64`, but the live response was already PEM/OpenSSH text. The test
harness wrote those values as returned rather than decoding them. The initial
throwaway malformed key was deleted before any source instance or bucket was
created.

The restored instance was verified with a disposable SSH client using a host key
captured for that exact new test endpoint. BackupSheep's production SFTP path remained
strict and used reviewed known-host entries for the source and restore endpoints.

The live crash test intentionally stopped only the disposable cloud worker after the
provider reference had been persisted. RabbitMQ/DB state and the original backup row
were left intact; the restarted worker consumed the queued poll without a second
provider create call.

The live S3 file/database tests used one test bucket and four objects from the run's
isolated BackupSheep account. The file and database restore tasks fetched those exact
objects, restored the original fixture hashes after mutation, and the bucket was then
emptied and deleted.

## Official API references

* [Lightsail CreateKeyPair](https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_CreateKeyPair.html)
* [Boto3 Lightsail `create_key_pair`](https://docs.aws.amazon.com/boto3/latest/reference/services/lightsail/client/create_key_pair.html)
* [Lightsail CLI guide](https://docs.aws.amazon.com/lightsail/latest/userguide/getstarted-awscli.html)
* [Lightsail snapshots](https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-snapshots-in-amazon-lightsail.html)
* [Create an instance from a Lightsail snapshot](https://docs.aws.amazon.com/lightsail/latest/userguide/lightsail-how-to-create-instance-from-snapshot.html)
* [Amazon S3 CreateBucket API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html)
* [Amazon S3 DeleteObject API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html)
