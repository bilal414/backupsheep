# BackupSheep UpCloud, Oracle Cloud, and DigitalOcean live E2E wrap-up — 2026-08-12

> **Superseded:** Continue from
> `provider-live-e2e-final-handoff-20260813.md`. That document records the
> completed UpCloud row-26 SIGKILL recovery, power-safe public-network restore,
> final live evidence, and current DigitalOcean/Oracle artifact gaps.

This file is historical evidence for the provider work stopped on 2026-08-12;
it is not the current status or resume authority. The final handoff is
authoritative and supersedes this file wherever they disagree. This file also
supersedes the status sections in `provider-live-e2e-resume-handoff-20260812.md`
and `upcloud-enterprise-reliability-20260812.md` for this historical checkpoint.
It intentionally contains no API tokens, object-storage secrets, database
passwords, private keys, browser cookies, or decrypted application credentials.

## Safety rules for the next session

1. Work on `develop`; verify local, `origin/develop`, and the demo checkout before
   changing anything.
2. Never touch AWS Lightsail.
3. For DigitalOcean, remain in Personal team UUID
   `0ba41777-3fbc-4093-9193-0f2709d2948a`.
4. Provider resources may be changed or deleted only after a fresh read proves
   the exact account/team/tenancy, immutable ID, generated run name, marker or
   labels, region/zone/compartment, source relationship, and request witness.
5. A ledger entry is not deletion authority. Zero matches, duplicate matches,
   missing ownership fields, a partial inventory, or provider read failure must
   stop mutation.
6. Preserve `/opt/backupsheep/docker-compose.override.yml`. Its expected SHA-256
   is `90c8c98923b97e32a077f27ddefe5e8e7236a9249d91a24e8e9c4b32f94a1462`.
7. Never print `_docs`, runtime secret files, environment variables, decrypted
   integration values, SSH private keys, or provider response bodies.

## Repository and deployment checkpoint

- Local repository: `/Users/bilal/Projects/BackupSheep/backupsheep`
- Branch: `develop`
- Remote: `origin/develop`
- Demo host: `64.177.125.68`
- Demo checkout: `/opt/backupsheep`
- Public URL: `https://demo.backupsheep.com`
- Base commit before the final wrap-up commit: `c12f2cd13abad147ee2b3a58556e007d71a6583f`
- Historical code/deployment provenance is recorded by the commit containing
  this file. For current authoritative provenance, use the final handoff and
  require the demo checkout to equal `origin/develop` before continuing.

Preserved pre-deployment database snapshots created during the final fixes:

| Candidate | Snapshot | Bytes | Mode | SHA-256 |
| --- | --- | ---: | ---: | --- |
| `bcf5fbd` | `/var/backups/backupsheep/predeploy-bcf5fbd-20260812T233744Z.sql.gz` | 241755 | 0600 | `a414d07cbb0ada1f407827b961184316b44f34f724bac2cebd174d269869fd66` |
| `ec3802f` | `/var/backups/backupsheep/predeploy-ec3802f-20260812T234028Z.sql.gz` | 241746 | 0600 | `b67094e8c1085e60dee793b29bdfcad05c00d9427e56fc2c5dbe680a34591c22` |
| `c12f2cd` | `/var/backups/backupsheep/predeploy-c12f2cd-20260812T234655Z.sql.gz` | 242085 | 0600 | `bbd8208a10052aff07b351cd81b9c9c65d95588ea9d7083ce4fa7cb0286b9500` |
| `3e07a08` | `/var/backups/backupsheep/predeploy-3e07a08-20260813T000144Z.sql.gz` | 243531 | 0600 | `13286e9785e1bb24509b82315565e6f3b2bfb8d0e0cc611446bdd266e74264cc` |

All four passed `gzip -t`. Earlier snapshots are listed in the superseded
handoff and remain available.

### Final demo deployment receipt

The code-bearing wrap-up commit `3e07a08b1a8f2ba9465d1a72c64ca225ca676035`
was pushed to `origin/develop`, fast-forwarded on the demo, rebuilt, migrated,
and verified before this historical receipt was recorded. Current deployment
provenance is governed by the final handoff.

Verified after deployment:

- migration container exit code `0`;
- app container healthy and `python manage.py check` reported no issues;
- `worker-cloud` restored to one running worker, alongside beat, database,
  files, logs, and storage workers;
- previously queued `cloud` and `default` broker messages drained to zero;
- zero in-progress cloud, website, database, or Vultr managed-database restores;
- cloud restore row `26` remained failed with no resource/job pointer and
  `verification_resume_mode=provider_retry`;
- signed-in UI showed `Retry same restore` for row `26`; it was not clicked;
- `https://demo.backupsheep.com/healthz/` returned HTTP 200 over the configured
  IPv6 address.

## What was implemented

The provider reliability work is represented by these commits, in order:

- `ef5743c` — initial multi-cloud integrations and live harnesses.
- `1b0630f` — persisted provider idempotency witnesses.
- `9f1723c` — bound Oracle boot restores to their exact source backup.
- `2ed59bb` — hardened provider restore reconciliation.
- `28ee48d` — hardened UpCloud firewall and provider restore evidence.
- `9ab26d3` — hardened multi-cloud live backup reconciliation and manifests.
- `b9a6ed2` — fixed the UpCloud clone adoption contract.
- `9935ac1` — allowed strictly proven pointerless UpCloud reconciliation.
- `2ba469d` — fixed PostgreSQL marker verification to use pure SQL instead of
  unsupported psql meta-commands in `--command` mode.
- `02e21d8` — added a hash-only, exact-row UpCloud post-acceptance hard-kill hold.
- `1d1d19d` — hardened pointerless UpCloud server adoption and immutable source,
  configuration, firewall, storage, marker, and state-machine proofs.
- `bcf5fbd` — added bounded, tenant-scoped, same-row logical database restore
  verification resume with transaction locking and broker-loss recovery.
- `ec3802f` — exposed failed logical restores in UI history so an older failed
  row can actually be resumed.
- `c12f2cd` — fixed the UpCloud restored-server create request: top-level
  `boot_order=disk`, exact attached boot storage/address, and no readback-only
  `boot_disk` request field.
- The final wrap-up commit adds a narrowly fenced `provider_retry` mode for an
  UpCloud server request that was definitively rejected. It reuses the same
  restore row only when the full immutable server witness and a complete
  zero-match provider scan are durable. Ambiguous/lost responses remain
  reconciliation-only.

The common reliability contract now includes:

- durable database records as the source of truth instead of Celery result state;
- deterministic request/restore markers and provider request fingerprints;
- renewable leases and mutation-boundary worker fencing;
- unique full-inventory adoption before retrying provider mutations;
- distinct provider failure, not-found, authentication, rate-limit, timeout,
  conflict, quota, transient-outage, malformed, and manual-review outcomes;
- bounded HTTP timeouts;
- same-row UI status and operator resume/retry controls;
- object metadata for SHA-256, byte count, ETag, version ID, bucket, key, and
  ownership marker;
- exact provider ownership verification before poll or delete;
- test hooks for accepted-but-not-persisted provider responses and hard worker
  termination.

## Automated verification

The final working tree passed:

- 66/66 database restore manual-resume and hardening tests;
- 12/12 focused database manual-resume tests after the history visibility fix;
- 24/24 UpCloud server firewall/crash tests after the create payload fix;
- 51/51 cloud manual-resume, UpCloud server, and native restore UI tests after
  adding definite-rejection same-row retry;
- 1,564/1,564 tests in the complete `apps.tests` Docker suite after all final
  code changes (`196.788s`, `OK`);
- Python compilation and `git diff --check`.

A later pre-review receipt recorded 1,570/1,570 tests in the complete
`apps.tests` Docker suite. GPT-5.6 Sol Max subsequently found blockers, and
GPT-5.6 Luna Max implemented the accepted fixes. The authoritative handoff
records the later final result: 70/70 focused tests and 1,583/1,583 complete
`apps.tests` tests passed after those fixes.

The full-suite output included intentional negative-path logging for lost broker
acknowledgements, duplicate suppression, and provider-cleanup refusal. The run
still completed with exit code 0 and `OK`; those messages are expected test
evidence, not live provider failures.

## Demo application state at wrap-up

The production database read immediately before wrap-up contained no pending or
in-progress website, database, native cloud, or Vultr managed-database restore
row. Historical failed/manual-review rows remain intentionally visible; they are
not active jobs.

Successful current rows include:

| Provider/workload | Backup/restore row | Provider target or result |
| --- | --- | --- |
| DigitalOcean Droplet | cloud restore `17` | Droplet `591950219`, complete |
| DigitalOcean Volume | cloud restore `24` | Volume `5e6e20a0-9695-11f1-9250-ea23293535eb`, complete |
| Oracle Compute | cloud restore `19` | exact instance OCID persisted, complete |
| Oracle block volume | cloud restore `21` | exact volume OCID persisted, complete |
| Oracle boot volume crash adoption | cloud restore `23` | exact boot-volume OCID persisted, complete |
| UpCloud Volume | cloud restore `25` | storage `014913a9-3217-4f09-b541-1f5ba2173c96`, complete |
| UpCloud PostgreSQL | database restore `16` | same fork target adopted, complete |
| UpCloud website | website restore `9` | source tree restored exactly, complete |

Historical terminal rows `18`, `20`, and `22` represent earlier contract failures
superseded by successful rows `24`, `23`, and related fixes. Database restore rows
`11` and `12` are historical rejected attempts; rows `13` through `16` are
complete. No action is required merely because the historical failures remain.

## UpCloud live E2E

### Exact run scope

- Run ID: `bs-e2e-upcloud-20260812-74c9f2a1`
- Ledger:
  `/Users/bilal/.backupsheep-e2e/upcloud/bs-e2e-upcloud-20260812-74c9f2a1/ledger.json`
- Runtime directory:
  `/Users/bilal/.backupsheep-e2e/upcloud/bs-e2e-upcloud-20260812-74c9f2a1/`
- Account: `bilal414`
- UI connection `19`; website node `27`; PostgreSQL node `28`; server node `29`;
  volume node `30`; storage destination `6`.
- Source server `00e6027e-d4e5-4779-bc3f-18080a4ee0d3`, public IPv4
  `152.44.38.25`.
- Source boot storage `01e47e4e-c6de-4870-b3e2-1347f011c2bb`.
- Source data volume `01279e53-5678-40e8-9210-dce5a0559e9e`.
- Managed Object Storage service `12a6acc5-091e-4bbe-ac96-ace1be725864`.
- Bucket `bs-bs-e2e-upcloud-20260812-74c9f2a1-objects-c25b6ce19f`.
- Prefix `backupsheep-e2e/bs-e2e-upcloud-20260812-74c9f2a1/`.
- Bucket versioning was enabled and read back as `Enabled` before the newest
  website/database uploads.

### Native backup and restore evidence

- Server backup row `4` completed with provider backup
  `01e3e859-77b4-4502-96f2-87ced534783a`, marker
  `bs-bs-bs-e2e-upcloud-202608-n29-b4`, size 10 GB.
- Volume restore row `25` completed with exact normal storage
  `014913a9-3217-4f09-b541-1f5ba2173c96`, marker
  `backupsheep-upcloud-25-e48aa9f7326ecf2c5aaf0a0c`, zone `us-chi1`,
  size 10 GB, tier `standard`, encryption `yes`, and provider `origin=null`.
  One signed-in UI resume adopted that one target; no duplicate target exists.

### Website and PostgreSQL evidence

Website backup row `11`, storage-point row `11`:

- UUID `bs-upcloud-website-fixture-n27-b11`;
- object key
  `backupsheep-e2e/bs-e2e-upcloud-20260812-74c9f2a1/bs-upcloud-website-fixture-n27-b11.zip`;
- 69,165 bytes;
- SHA-256 `b314a0a5904870745888360bab2b2c65a9fb4519e7dcb02b2dfb231983ce1e19`;
- ETag `3ee4294c9255347ad26dcebc26631774`;
- version ID `1786575272066`.

Website restore row `9` completed after overwrite/delete/extra-file mutation.
Readback showed the exact original four-file set and hashes and no extra file.

PostgreSQL backup row `10`, storage-point row `12`:

- UUID `bs-upcloud-postgresql-fixtu-n28-b10`;
- object key
  `backupsheep-e2e/bs-e2e-upcloud-20260812-74c9f2a1/bs-upcloud-postgresql-fixtu-n28-b10.zip`;
- 5,129 bytes;
- SHA-256 `b2a91db4540e66cca7db61d28723eb9ca0b9a05a28f6efc0fe31d72ae0aaa8bd`;
- ETag `2ea8fb94f064c943c0c0689f81e2fb96`;
- version ID `1786575287925`.

Restore row `16` originally reached the correct fork but was falsely marked
failed because psql meta-commands were sent through `--command`. After `2ba469d`,
the signed-in UI exposed the same failed row. Clicking `Resume verification`
on the deployed `ec3802f` path reused row `16`, adopted the existing marker, and
completed with its original mapping:

- source `bs_e2e_50d32a3bb404`;
- target `bs_restore_45c7b8c781e6_bs_e2e_50d32a3bb404_b51c2326c3b4`;
- `manual_resume_count=1`;
- checkpoint status `complete`, `adopted=true`;
- progress `1/1 databases`.

Expected workload evidence is 120 customer rows, 480 event rows, total 600,
canonical data SHA-256
`f8621cd4a65a00c394f8ead3e427e16859248450bc7cc23ebf529764c5934cb7`,
and schema SHA-256
`4768a03a122f1e6f2fe7b2dd8a609174e0c9ccaa5391012d8472c4484b76df87`.

### UpCloud server restore row 26 — exact stopping point

Do not create a replacement restore row. Row `26` is the durable continuation
boundary.

- Backup row `4`; node `29`; status `FAILED`; operation/execution phase `failed`.
- Error code `PROVIDER_REQUEST_FAILED`; the provider definitively rejected the
  old create request, so `_bs_create_outcome_unknown=false`.
- Server marker
  `backupsheep-upcloud-server-26-c8d13216324ea7ca399d0f80`.
- Storage marker
  `backupsheep-upcloud-storage-26-c8d13216324ea7ca399d0f80`.
- Exact cloned boot storage `010656e3-1b94-444b-a600-393b2750cbbf`.
- Fresh provider read at wrap-up: HTTP 200, `online`, `normal`, `us-chi1`,
  10 GB, `standard`, encrypted `yes`, `origin=null`, exact title above.
- Fresh complete server inventory: one account server total, one page, scan
  complete, and **zero** matches for the row-26 server marker.
- No `resource_id`, `provider_job_id`, or candidate server ID is persisted.

The highest-confidence rejection cause was the old request sending
`boot_disk=1` on an `action=attach` storage device. The live setup harness had
already recorded that UpCloud rejects that input despite exposing `boot_disk`
on readback. `c12f2cd` removes it and sets `boot_order=disk`. The final wrap-up
change makes the row eligible for `Retry same restore` only with the exact
durable proof and complete zero-match scan above. The worker still performs a
fresh source read, target-storage ownership read, and complete server inventory
before POST.

### How to resume row 26 normally

1. Verify the final demo SHA, healthy app, normal `worker-cloud`, exact row-26
   database state, zero provider marker matches, and the exact online storage
   fields above.
2. Sign in and open `https://demo.backupsheep.com/console/nodes/29/`.
3. Open the completed server backup's Restore modal. The historical row should
   show `Retry same restore`, not `Restore another copy`.
4. Click once. Confirm the response tracks restore ID `26`, increments its
   bounded manual-resume sequence, and does not insert another restore row.
5. Observe one provider server marker only. Wait for exact firewall replacement,
   its 120-second stabilization window, public IPv4 assignment, and terminal
   completion.

### How to run the remaining real SIGKILL acceptance test

Do this instead of the normal resume flow if crash acceptance is still required:

1. Scale `worker-cloud` to zero and verify no cloud worker container exists.
2. Click `Retry same restore` once in the UI; this durably transitions row `26`
   and queues the same-row poll while no ordinary cloud worker can consume it.
3. Run a one-off cloud task with these exact non-secret gates:

   ```text
   BACKUPSHEEP_UPCLOUD_FAULT_MODE=restore-server-post-accept-pre-persist
   BACKUPSHEEP_UPCLOUD_FAULT_RESTORE_ID=26
   BACKUPSHEEP_UPCLOUD_FAULT_RESTORE_MARKER=backupsheep-upcloud-server-26-c8d13216324ea7ca399d0f80
   BACKUPSHEEP_UPCLOUD_FAULT_ACTION=hold
   BACKUPSHEEP_UPCLOUD_FAULT_HOLD_SECONDS=300
   ```

4. The one-off task must use `poll_cloud_restore.apply(args=[29,26], ...)`, not
   create a new restore. Wait until the hash-only `acceptance_fault` witness is
   durable, then send real SIGKILL to that one-off container.
5. Confirm row `26` remains queryable in progress with a stale lease, exactly
   one server marker exists, and no provider pointer was persisted.
6. Restore the normal cloud worker. Duplicate queued deliveries must be fenced.
   After lease expiry, the same row must adopt exactly one server, restore the
   exact firewall chain, wait the stabilization interval, assign the witnessed
   public family, and complete.

Do not run the test if the fresh preflight finds a marker match before the
controlled create, more than one marker match, changed target storage, or any
ownership ambiguity.

## DigitalOcean live E2E

- Run `bs-e2e-do-20260812-c91a7e52`.
- Ledger
  `/Users/bilal/.backupsheep-e2e/digitalocean/bs-e2e-do-20260812-c91a7e52/ledger.json`.
- UI connection `15`, Droplet node `22`, volume node `23`, Spaces storage `5`.
- Source Droplet `591905892`; source volume
  `4a300611-966c-11f1-8ac3-5a82d57d1373`; firewall
  `cd108ca8-949c-4a6f-9689-dc9e6a57c4ca`.
- Bucket
  `bs-e2e-bs-e2e-do-20260812-c91a7e52-fc4b8129a3a5ec908bde`, region `nyc3`,
  versioning enabled.
- Droplet backup row `1` -> snapshot `240881466`; restore row `17` -> Droplet
  `591950219`, complete.
- Volume backup row `2` -> snapshot
  `6fa34c67-9685-11f1-9250-ea23293535eb`; restore row `24` -> volume
  `5e6e20a0-9695-11f1-9250-ea23293535eb`, complete.
- Website restore row `6` and database restore row `13` completed from Spaces.
- Spaces website storage-point row `8`: 69,165 bytes, SHA-256
  `50b7af806f49fffdd9fa6d98d39c490b5bcce363e3b065926e6803be1a9f5f1b`,
  ETag `51c300543d61b435b97d2af108bb97d6`, non-empty version ID.
- Spaces database storage-point row `9`: 5,103 bytes, SHA-256
  `f67fe72bcd104c5e10d5bf63e5e5835f9ee80e11f2df9fc21923d4011c3a94d0`,
  ETag `62070413ef36bb5f6fc699f1f51e2a69`, non-empty version ID.

Remaining DigitalOcean work:

1. Normalize the existing UI object manifest before running the hardened object
   verifier. It currently lacks top-level `schema`, `run_id`, and `prefix`, an
   exact `backup_id` on each object, and the durable
   `spaces_bucket.ownership.prefix` witness in the ledger. Do not weaken the
   verifier to accept the older shape.
2. Run fresh provider-read-only native backup and volume-restore verification.
   The volume target is known, but its exact target witness is not durably
   recorded in the old ledger, so supply and re-prove that witness explicitly.
3. The DigitalOcean harness has no `verify-workloads` command. Website/database
   restore payload verification must use the documented SSH/UI evidence path;
   do not invent a command-line phase.
4. Droplet restore verification is not read-only because it can attach a
   firewall and probe the target. Treat it as a provider mutation and require
   the full apply gates and exact ownership proof.
5. The old ledger predates newer creation fingerprints, so cleanup must fail
   closed; do not use it alone as deletion authority. Rotate the exposed PAT
   immediately after the last required DigitalOcean call.

## Oracle Cloud live E2E

- Run `bs-e2e-oracle-20260812-a7c42f91`.
- UI connection `16`; compute node `24`; boot-volume node `25`; block-volume node
  `26`; Object Storage destination `7`.
- Native backup rows `4`, `5`, and `6` completed.
- Compute restore row `19`, block-volume restore row `21`, and boot-volume
  restore row `23` completed.
- Row `23` used a real SIGKILL after provider acceptance and before pointer
  persistence; the same row adopted exactly one target after restart.
- Website restore row `8` and database restore row `15` completed from Oracle
  Object Storage.
- Bucket `bs-e2e-oracle-20260812-a7c42f91-objects`.
- Oracle website storage-point row `10`: 69,165 bytes, SHA-256
  `50b7af806f49fffdd9fa6d98d39c490b5bcce363e3b065926e6803be1a9f5f1b`,
  ETag `51c300543d61b435b97d2af108bb97d6`, version ID
  `ac6538da-c4d7-4e4f-87a0-2327c0465be1`.
- Oracle database storage-point row `11`: 5,103 bytes, SHA-256
  `f67fe72bcd104c5e10d5bf63e5e5835f9ee80e11f2df9fc21923d4011c3a94d0`,
  ETag `62070413ef36bb5f6fc699f1f51e2a69`, version ID
  `0763de95-389f-4fb9-810f-8c7776563be7`.

Remaining Oracle work:

1. Build the missing secret-free `ui-manifest.json` from durable demo rows and
   provider reads. It must bind the exact run, compartment, source IDs, backup
   IDs, restore IDs/names/markers/request tokens, and website/database object
   key, version, ETag, SHA-256, and byte count.
2. The only currently inert harness phase is `--phase plan`. The existing
   `--phase verify --ui-manifest ...` path is **not read-only**: it requires the
   explicit apply gate and may attach the restored block volume and launch a
   boot-verifier instance. Do not describe or run it as a read-only audit.
3. Once the manifest is complete, execute the gated verification against only
   the exact-owned run, then perform a fresh before/after inventory and
   exact-owned cleanup audit. Retain the existing OCI CLI profile; do not print
   its key or configuration.

## Credential incident and required rotation

During this long live session, tool output exposed these credentials:

- DigitalOcean PAT;
- UpCloud API token;
- UpCloud fixture root SSH private key.

Their values are not repeated here. After the final provider calls, revoke or
rotate both API tokens and destroy the exact-owned UpCloud fixture server or
rotate its root SSH key. Review access to retained terminal/transcript output.
Oracle private-key contents and object-storage secrets were not printed.

## Remaining acceptance gates

The code and live evidence are substantial, but enterprise acceptance is not yet
claimed. Remaining work is:

1. Complete UpCloud row `26` through either the normal same-row retry or the real
   SIGKILL acceptance sequence above; prove exactly one target and exact firewall,
   network, storage, and payload readback.
2. Run `verify-compute`, `verify-workloads`, and object verification for UpCloud,
   DigitalOcean, and Oracle with current hardened manifests.
3. Perform fresh before/after provider inventories and exact-owned cleanup. Stop
   wherever old ledgers lack current ownership fingerprints; never infer cleanup
   authority.
4. Rotate exposed credentials and remove or re-key the UpCloud fixture host.
5. At this historical checkpoint, obtain the requested GPT-5.6 Sol Max final
   review after live gates are complete, then apply accepted feedback with
   GPT-5.6 Luna Max and rerun all tests. The review has since found blockers and
   the accepted fixes have been implemented; use the final handoff for the
   current post-fix gates.
6. Rerun final focused and full Docker suites after any review fixes.
7. Confirm zero active/stranded work, all intended cleanup, exact deployed SHA,
   migration success, healthy containers, and public HTTPS health.

## Secret-safe resume checklist

```sh
cd /Users/bilal/Projects/BackupSheep/backupsheep
git status --short --branch
git fetch origin develop
git rev-list --left-right --count develop...origin/develop
git log -1 --oneline
git diff --check
```

```sh
ssh -o BatchMode=yes root@64.177.125.68 \
  'cd /opt/backupsheep && git rev-parse HEAD && git status --short --branch && sha256sum docker-compose.override.yml'
```

```sh
curl -fsS --max-time 20 -o /dev/null \
  -w '%{http_code} %{url_effective}\n' \
  https://demo.backupsheep.com/healthz/
```

Before any provider mutation, repeat the exact account/team check, full bounded
inventory, marker count, source and target ownership read, and durable-row read.
Do not continue from memory alone.
