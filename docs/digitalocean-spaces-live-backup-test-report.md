# DigitalOcean Spaces live backup and restore validation

> Historical evidence only — do not rerun this report as a playbook. A new live
> test requires separately confirmed current login information, explicit team
> scope, a unique ownership marker, and a fresh durable resource ledger.

**Date:** 2026-08-02
**Scope:** DigitalOcean Spaces storage integration, SFTP file backup, PostgreSQL backup, restore, duplicate Celery delivery, and cleanup
**Result:** PASS after the Spaces validation probe fix

## Safety scope

- Authentication used only the token in `_docs/digitalocean.txt`. The token, temporary Spaces secret, and temporary private key were not recorded in source control or this report.
- The DigitalOcean team inventory was checked explicitly through the Teams API. All resources created by this run were scoped to the `Personal` team and used the unique tag `backupsheep-spaces-e2e-20260802` where tagging was available.
- Existing DigitalOcean Spaces keys were read only. A dedicated temporary full-access Spaces key was created for this run and deleted during teardown.
- An unrelated service occupied port `8000`; disposable BackupSheep containers used port `8001`. Existing `cloudmoo` containers and BackupSheep base services were not changed.
- The temporary bucket, Droplet, SSH key, BackupSheep account records, credentials, shared-volume artifacts, and known-host entry were removed after testing.

## Test resources

| Resource | Value |
| --- | --- |
| Spaces bucket | `backupsheep-spaces-e2e-20260802-1785672308` in `nyc3` |
| Temporary source Droplet | `backupsheep-spaces-e2e-20260802-source`, ID `589403321` |
| Temporary source SSH key | DigitalOcean key ID `58168668` |
| SFTP fixture | `/home/bsbackup/backup-fixture/fixture.txt` and `subdir/nested.txt` |
| PostgreSQL fixture | Database `spaces_e2e_source`, table `public.backup_fixture` |
| BackupSheep file backup | ID `29`, task ID `spaces-e2e-file-20260802` |
| BackupSheep database backup | ID `20`, task ID `spaces-e2e-database-20260802` |
| Restore records | File restore ID `5`; database restore ID `7` |

## Live test matrix

| ID | Test | Procedure and evidence | Result |
| --- | --- | --- | --- |
| SP-01 | Personal-team scope | Queried DigitalOcean teams and used the `Personal` team for the isolated run. | **PASS** — no resources outside the test scope were modified. |
| SP-02 | Spaces credential and bucket lifecycle | Created a dedicated Spaces key, created the `nyc3` bucket through the S3-compatible integration, and validated the configured storage connection. | **PASS** — storage validation returned `True`; the temporary key was later deleted. |
| SP-03 | Concurrent Spaces validation | Ran four real concurrent `CoreStorageDoSpaces.validate()` probes against the live bucket. | **PASS** — all four returned `True` and no probe collided. |
| SP-04 | Duplicate SFTP file backup | Dispatched the same `backup_website` task ID twice for the SFTP source. | **PASS** — one backup row reached `Complete`, size `1,077` bytes; one `Upload Complete` storage point and one Spaces object were created. The archive contained both fixture files. |
| SP-05 | SFTP file restore | Mutated the remote fixture, restored BackupSheep file backup ID `29`, then read both files over SSH. | **PASS** — restore ID `5` reached `Complete`; both original fixture values were restored. |
| SP-06 | Duplicate PostgreSQL backup | Dispatched the same `backup_database` task ID twice for the temporary PostgreSQL source. | **PASS** — one backup row reached `Complete`, size `1,092` bytes; one `Upload Complete` storage point and one Spaces object were created. The archive contained `spaces_e2e_source.sql` and the expected table/payload. |
| SP-07 | PostgreSQL backup permission precondition | The first dump correctly exposed that the temporary fixture table was owned by `postgres`, not the dump role. The ownership and schema grant were corrected only on the temporary database, and the same task ID was redelivered. | **PASS after fixture correction** — the final backup completed without changing application permission behavior. |
| SP-08 | PostgreSQL restore | Mutated the temporary database payload, restored BackupSheep database backup ID `20`, and queried the table over SSH. | **PASS** — restore ID `7` reached `Complete`; the original payload was present. |
| SP-09 | Backup deletion and object cleanup | Soft-deleted both BackupSheep backup records and inspected the bucket directly before bucket deletion. | **PASS** — both records and storage points reached `Delete Completed`; direct object listing returned zero objects. |
| SP-10 | Full teardown | Deleted the bucket, temporary Spaces key, source Droplet, source SSH key, BackupSheep test records, local credential artifacts, and shared test artifacts. | **PASS** — final inventory reported zero tagged Droplets, zero temporary Spaces keys, zero temporary SSH keys, zero disposable containers, and zero matching BackupSheep accounts/users/nodes/storages. |

## Findings and code change

DigitalOcean Spaces validation generated probe names from `int(time.time())`. Concurrent validation calls in the duplicate-backup path could therefore share a key: one call could delete the other call's object and report a false validation failure.

The Spaces probe now uses `uuid.uuid4().hex`, and regression coverage verifies that consecutive validation calls use distinct keys. The live four-way concurrent validation also passed after rebuilding the application image.

## Backup and restore evidence

- File object: `backupsheep-spaces-e2e-20260802/bs-spaces-e2e-files-on-de-n49-b29.zip`
- Database object: `backupsheep-spaces-e2e-20260802/bs-spaces-e2e-database-on-n50-b20.zip`
- Duplicate delivery produced one durable BackupSheep record and one provider object for each backup type.
- File restore verified `fixture.txt` and `subdir/nested.txt` over SSH.
- Database restore verified the fixture row through `psql` over SSH.
- Both provider objects were removed by the BackupSheep delete flow before the bucket was deleted.

## Automated verification

The repository image was rebuilt from the checked-out source. The `.env` file was not modified; disposable containers used `DJANGO_SERVER=dev` explicitly.

```text
Focused storage/restore suite: 103 tests, 19.598s, OK
Complete repository suite:    338 tests, 55.931s, OK
```

## API references

The live checks used the documented DigitalOcean Teams, Spaces, Spaces Keys, S3-compatible, Droplet, and account SSH-key APIs. References: [Spaces create](https://docs.digitalocean.com/products/spaces/how-to/create/), [Spaces API](https://docs.digitalocean.com/reference/api/spaces/), [Spaces Keys API](https://docs.digitalocean.com/reference/api/reference/spaces-keys/), and [Personal access tokens](https://docs.digitalocean.com/reference/api/create-personal-access-token/).

## Boundaries

This run validated the live DigitalOcean Spaces storage path, SFTP file backup and restore, PostgreSQL backup and restore, duplicate delivery, deletion, and cleanup. The restore tests restored into isolated temporary targets on the temporary source Droplet; no existing customer resource was used. A physical host reboot was not performed in this run, but the durable task/backup behavior and worker restart path were covered by the earlier DigitalOcean live report in [`digitalocean-live-backup-test-report.md`](digitalocean-live-backup-test-report.md).
