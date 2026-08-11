# DigitalOcean live backup validation

> Historical evidence only — do not rerun this report as a playbook. A new live
> test requires separately confirmed current login information, explicit team
> scope, a unique ownership marker, and a fresh durable resource ledger.

**Date:** 2026-08-01
**Scope:** DigitalOcean provider backups and the BackupSheep resumable/idempotent backup path
**Result:** PASS after the fixes listed below

## Safety scope

- Authentication used only the token in `_docs/digitalocean.txt`; the token and temporary private key were not recorded in source control or this report.
- The token was initially verified against the DigitalOcean `Personal` team. The initial inventory contained zero Droplets, volumes, and snapshots. The one pre-existing SSH key was read only and was never modified.
- Every live test resource created by this run used the unique tag `backupsheep-e2e-20260801` and was deleted during cleanup.
- The local web service used port `8001` because an unrelated `cloudmoo` container occupied port `8000`. That container and its resources were not changed.

## Test resources

| Resource | Value |
| --- | --- |
| Droplet | `backupsheep-e2e-20260801-server`, ID `589276938`, Ubuntu 24.04, `s-1vcpu-2gb`, `nyc1` |
| Volume | `backupsheep-e2e-20260801-volume`, ID `3c6f4936-8de9-11f1-b2b3-8a6f1f710ee0`, 1 GiB ext4 |
| Temporary SSH key | DigitalOcean key ID `58157516` |
| Test fixtures | `/home/bsbackup/backup-fixture/fixture.txt`; PostgreSQL database `bsbackupdb`, table `backup_fixture` |

The Droplet ran PostgreSQL 16 and was used for both the SFTP file test and the SSH-tunneled PostgreSQL dump test. The fixture payload was `digitalocean-live-e2e`.

## Live test matrix

| ID | Test | Procedure and evidence | Result |
| --- | --- | --- | --- |
| DO-01 | API authentication and Personal-team scope | Read-only account and resource inventory using the supplied token. | **PASS** — token valid; Personal team selected; initial Droplet, volume, and snapshot inventories were empty. |
| DO-02 | DigitalOcean connection checks | Created BackupSheep DigitalOcean server and volume connections and checked them through the cloud worker. | **PASS** — both connection checks completed successfully. |
| DO-03 | Droplet backup with duplicate delivery | Dispatched the same Celery task ID twice for the Droplet. | **PASS** — one BackupSheep backup row, one provider snapshot (`239393038`), one persisted action (`3324549127`), final status `Complete`. |
| DO-04 | Volume backup with an empty snapshot catalog | Repeated the duplicate-delivery test against the attached volume. DigitalOcean returned `"snapshots": null` for an empty catalog. | **PASS after fix** — the first run exposed a `NoneType` iteration bug; after the null-safe fix, one BackupSheep row and one volume snapshot (`5d059b80-8deb-11f1-9fbe-5a54d836f93a`) completed successfully. |
| DO-05 | In-progress status visibility | Started a second Droplet backup and queried `GET /api/v1/backups/digitalocean/?node=45` before the provider action completed. | **PASS** — API returned `status_display: In-Progress` with action `3324567978`; the same row later became `Complete` with snapshot `239393285`. |
| DO-06 | SFTP file backup with duplicate delivery | Backed up the fixture directory over SFTP while delivering the same task twice. | **PASS after fixes** — one backup row, one `Upload Complete` storage point, 4,505-byte archive, nine files. The archive contained `backup-fixture/fixture.txt` and `.bashrc`. |
| DO-07 | PostgreSQL dump with duplicate delivery | Ran the SSH-tunneled PostgreSQL backup twice with the same task ID. | **PASS** — one backup row, one `Upload Complete` storage point, 1,070-byte archive. The SQL archive contained `backup_fixture` and the expected `digitalocean-live-e2e` payload. |
| DO-08 | Worker crash/restart resume | Interrupted the file-backup worker while the SFTP operation was in progress, restarted the worker, and allowed the queued task to be redelivered. | **PASS** — the durable backup UUID was reused, the operation resumed to `Complete`, and no duplicate backup row or provider artifact was created. This is a worker/container restart simulation; no host reboot was performed. |
| DO-09 | Snapshot deletion | Deleted all three test snapshots through BackupSheep and checked provider state directly. | **PASS** — all three BackupSheep rows reached `Delete Completed`; direct DigitalOcean inventory found zero matching Droplet or volume snapshots. |
| DO-10 | Full resource cleanup | Detached and deleted the volume, deleted the Droplet and temporary SSH key, and removed the local test account, storage path, and known-host entry. | **PASS** — volume detach completed; Droplet, volume, and key deletion returned HTTP 204; final inventory was zero for tagged Droplets, matching volumes, matching snapshots, and the temporary key. |

## Findings and changes

1. DigitalOcean can return `snapshots: null` instead of `snapshots: []` for an empty snapshot catalog. Creation, polling, and deletion now treat both forms as an empty page.
2. Local storage validation used a second-resolution timestamp for its probe filename. Concurrent duplicate Celery deliveries could delete each other’s probe and report a false storage failure. Probe names now use UUIDs.
3. The SFTP `lftp` command received a relative private-key path. The path is now absolute so the system SSH process resolves the same key regardless of its working directory.
4. Paramiko could truncate an unencrypted Ed25519 key while attempting an unnecessary serialization. Unencrypted keys are now preserved byte-for-byte; passphrase conversion is staged to a temporary file and validated before replacing the original.
5. Regression coverage was added for null DigitalOcean snapshot lists, concurrent local-storage validation, absolute SFTP key paths, and unencrypted Ed25519 key preservation.

## Automated verification

The current image was rebuilt from the checked-out source. The repository `.env` was not modified; because it contains a production-mode guard with a development placeholder secret, disposable local containers were started with a one-command `DJANGO_SERVER=dev` override.

The focused regression command completed successfully:

```text
docker compose run --rm --no-deps -e DJANGO_SERVER=dev --entrypoint python worker-cloud manage.py test \
  apps.tests.test_backup_engine.ProviderPollStatusResilienceTests \
  apps.tests.test_backup_engine.DigitalOceanSnapshotCreateTests \
  apps.tests.test_backup_engine.WebsiteMirrorOptsTests \
  apps.tests.test_backup_engine.NormalizeSshKeyTests \
  apps.tests.test_storage.LocalStorageModelTests --verbosity=1

Found 16 test(s)
Ran 16 tests in 2.184s
OK
```

## Boundaries

- The live run validated provider snapshot creation, persisted action/status tracking, duplicate delivery behavior, SFTP file backup, PostgreSQL dump backup, deletion, and cleanup.
- The restart test terminated and restarted a worker container while retaining the durable database and broker. A physical host reboot and a restore-from-snapshot drill were not performed in this run.
- The DigitalOcean API behavior was checked against the official API reference and the live Personal-team account: [API reference](https://docs.digitalocean.com/reference/api/reference/), [API overview](https://docs.digitalocean.com/reference/api/), and [Personal access tokens](https://docs.digitalocean.com/reference/api/create-personal-access-token/).
