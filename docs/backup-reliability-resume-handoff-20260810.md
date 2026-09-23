# Backup reliability and live E2E resume handoff — 2026-08-10

This document is the operational resume point for the BackupSheep enterprise
backup hardening and live provider validation work. It intentionally contains no
credentials, passwords, private keys, session cookies, or unredacted provider
tokens.

> **Superseded stop point:** the authoritative final checkpoint is now
> `docs/backup-reliability-final-wrap-up-20260810.md`, at implementation commit
> `e43ef8e9c77019db919720a49e693583eda9c0dc`. The sections below preserve the
> earlier plan and evidence chronology; do not use their older pending lists as
> the current resume order.

## Historical stop point (superseded)

- Working branch: `develop`.
- Integrated implementation checkpoint: `4be0ce809681fb6770af33fea14a10949d3b26d8`.
- That checkpoint is pushed to `origin/develop` and deployed at
  `https://demo.backupsheep.com/`.
- The demo remote checkout was clean except for its intentional, untracked
  `docker-compose.override.yml`; that file was preserved.
- The deployment migration container exited `0`.
- `python manage.py check` reported no issues on the deployed application.
- Internal and public `/healthz/` probes returned HTTP 200.
- The deployed image was checked and did not contain `/code/_docs`, `/code/.env`,
  or `/code/.git`.
- A signed-in Chrome UI smoke test loaded the post-deployment dashboard. It
  showed 19 protected sources, 4 active schedules, and 0 open exceptions.
- A database query immediately before wrap-up found no active AWS, RDS,
  website, or database backups; no active cloud, website, or database restores;
  and no pending/dispatched backup requests.
- No new live provider request was started after the user requested this
  wrap-up.

The implementation is substantially hardened and the automated suite is green,
but this is not an enterprise acceptance certificate. The newest RDS and
database convergence paths still need the fresh live UI crash tests described
below, followed by exact owned-resource cleanup and the requested final
independent review.

## Non-negotiable safety boundaries

1. Run live tests only for services whose supplied login information
   authenticates successfully at an exact provider identity/account endpoint.
2. Current live scope is BackupSheep demo, AWS, and Hetzner only.
3. The currently supplied Vultr token returned HTTP 401 at
   `GET https://api.vultr.com/v2/account`. Do not make another Vultr live call,
   list resources, create resources, or clean resources until a valid token is
   supplied. The Vultr results in the historical report are not a fresh test of
   this implementation.
4. No DigitalOcean or other provider login was authenticated in this pass. Do
   not test those services.
5. Never mutate or delete AWS Lightsail resources. Do not even instantiate a
   Lightsail client in a mutation or cleanup harness.
6. For AWS and Hetzner, mutate or delete only an exact resource whose account or
   project, region, immutable provider ID, run tag or label, and source witness
   all match the durable ledger. A generated name alone is never deletion
   authority.
7. If an accepted provider request has zero or multiple ownership matches, stop
   in manual-reconciliation state. Do not issue another create and do not guess
   a deletion target.
8. Preserve `/opt/backupsheep/docker-compose.override.yml` on the demo host.
9. Do not print or paste values from `_docs/`. Credentials were exposed in
   terminal/tool output during this run and should be rotated after validation.
10. `_docs/` is gitignored and Docker-ignored. Keep it that way.

Credential files known to exist locally, without recording their values:

- `_docs/aws.txt`
- `_docs/hetzner.txt` (the filename is intentionally misspelled)
- `_docs/vultr.txt`
- `_docs/demo.txt`
- `_docs/s3_bucket.txt`
- `_docs/bilal-macbook_accessKeys.csv`

These files were set to mode `0600`. Authentication status, not file presence,
controls whether a provider can be tested.

## Implemented code

### Generic execution and restore reconciliation

- Durable backup executions use renewable fenced leases, stable correlation
  IDs, progress, provider operation/resource IDs, retry timing, and explicit
  reconciliation state.
- Public restore errors now distinguish provider not-found, authentication,
  rate limits, timeout, transient outage, terminal provider failure, ownership
  mismatch, and manual reconciliation. Provider errors are not reported as
  generic `IN_PROGRESS`.
- Ambiguous restore marker/checkpoint/collision/ownership states map to terminal
  `RESTORE_RECONCILIATION_REQUIRED` instead of issuing another provider request.
- Restore mutation boundaries re-read the current lease owner, token, and
  expiry. Stale workers are fenced out before destructive or externally visible
  work.

Primary files:

- `apps/_tasks/integration/restore.py`
- `apps/api/v1/backup/serializers.py`
- `apps/console/backup/models.py`
- `apps/tests/test_restore_execution_lease.py`

### Website and database backups/restores

- Paramiko SFTP operations use bounded connection and operation timeouts.
- Remote temporary names are correlation/fence scoped and parsed strictly.
- Cleanup verifies the final scoped inventory is empty; malformed or duplicate
  matches stop for manual review.
- PostgreSQL restores replay through a transaction and durable per-file
  checkpoints. A worker crash during import resumes on the same logical row and
  cannot leave a partially committed target dataset.
- Exact-owned MySQL/MariaDB fork restores converge after a partial import by
  re-reading the restore marker and live execution fence immediately before
  dropping, recreating, and replaying the target database.
- MySQL/MariaDB in-place restore remains fail-closed/manual because destructive
  convergence cannot be proved safe there.
- Marker changes, stale fences, malformed checkpoints, and cleanup failures all
  fail closed.

Primary files:

- `apps/_tasks/integration/restore_database.py`
- `apps/tests/test_database_restore_hardening.py`

### AWS RDS snapshot and restore

- RDS backup execution persists a versioned provisional/committed witness.
- `CreateDBSnapshot` receives request-bound ownership tags before the request is
  sent.
- Adoption validates exact snapshot identifier, snapshot create time, original
  snapshot time, source DB resource ID/ARN, region/account, source configuration,
  and ownership tags.
- A short exclusive fenced create lease prevents duplicate snapshot requests,
  including when duplicate deliveries have missing or identical Celery IDs.
- `DBSnapshotAlreadyExists` is reconciled rather than treated as permission to
  create another snapshot.
- Zero-match, temporary 404, and temporarily missing tag states have bounded
  observation windows and remain distinct from terminal not-found.
- Lost restore responses can adopt a temporarily invisible exact-owned target.
- Restore defaults carry the durable source subnet group, VPC security groups,
  class, public accessibility, storage type, IOPS, and throughput instead of
  silently using AWS defaults.
- Cursor-based `Marker` pagination has finite page and item bounds.
- Delete flows verify ownership before every poll/delete, do not re-delete while
  AWS reports `deleting`, persist a fenced delete-response witness, and report
  success only after exact provider absence is observed.
- Crash-before-request and lost-response redispatch are bounded.

Primary files:

- `apps/console/backup/models.py`
- `apps/console/node/models.py`
- `apps/tests/test_aws_rds_reliability.py`
- `apps/tests/test_aws_backup_resources.py`

Relevant provider documentation:

- <https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBSnapshot.html>
- <https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBSnapshots.html>
- <https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromDBSnapshot.html>
- <https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_RestoreFromSnapshot.html>

### Live-provider harness safety

- AWS and Hetzner harnesses now persist mutation intent before provider calls,
  retain immutable IDs, use strict client/endpoint allowlists, require explicit
  CIDRs, reject unowned cleanup, paginate with hard bounds, and treat uncertain
  readback as manual review rather than absence.
- AWS service allowlists explicitly exclude Lightsail.
- EC2 reservation ownership, DynamoDB read outages, RDS snapshot asynchronous
  deletion, AWS Backup recovery-point deletion, Hetzner Object Storage pending
  intents, and Hetzner aggregate fixture deletion were hardened.
- Vultr's offline harness now uses cursor pagination, durable request/upload
  intents, request fingerprints, lost-upload adoption, rate-limit `Retry-After`
  parsing, error redaction, exact run IDs, ambiguous-create preservation, and
  verified-absence cleanup. It was not freshly run live because authentication
  failed.

Primary files:

- `scripts/live_e2e_ledger.py`
- `scripts/aws_ec2_ebs_e2e.py`
- `scripts/aws_s3_dynamodb_rds_e2e.py`
- `scripts/hetzner_cloud_e2e.py`
- `scripts/hetzner_object_storage_e2e.py`
- `scripts/hetzner_web_database_fixture_e2e.py`
- `scripts/vultr_live_e2e.py`
- `apps/tests/test_aws_e2e_network_safety.py`
- `apps/tests/test_hetzner_e2e_endpoint_safety.py`
- `apps/tests/test_vultr_live_e2e_ledger_safety.py`

### Docker credential boundary

- `_docs/` was added to `.dockerignore` because the Dockerfile uses
  `COPY . /code/`.
- Static regression tests ensure `_docs/`, `.env`, and `.env.*` remain excluded
  and that the Dockerfile does not explicitly copy the credential directory.
- Both the local rebuilt image and the deployed rebuilt image were inspected and
  proved not to contain `/code/_docs`, `/code/.env`, or `/code/.git`.

Primary files:

- `.dockerignore`
- `apps/tests/test_docker_build_context_safety.py`

## Automated verification already completed

All listed runs were Docker-backed and made no live provider calls unless they
are explicitly listed under live evidence.

| Verification | Result |
| --- | --- |
| RDS reliability focused set | 46/46 passed |
| AWS/RDS/restore-lease combined set | 81/81 passed |
| Database restore hardening | 49/49 passed |
| Focused AWS provider modules | 82/82 passed |
| Integrated reliability selection | 520/520 passed |
| Full Django test suite | 1,128/1,128 passed in 137.254 seconds |
| Changed Python files | `python3 -m py_compile` passed |
| Django system check | No issues |
| Migration drift | `makemigrations --check --dry-run`: no changes |
| Patch hygiene | `git diff --check` passed |
| Docker image credential paths | Absent locally and on demo |

The full suite prints expected fail-closed JSON for tests that deliberately
attempt cleanup without both opt-in flags. Those messages are passing safety
tests, not provider cleanup failures.

## Live evidence already completed

The full evidence and hashes are in `docs/live-e2e-20260810.md`. The minimum
resume-critical facts are repeated here.

### Website restore

- Restore row `5` recovered after a hard file-worker crash on the same logical
  row/task with no duplicate restore.
- Artifact: 100,681,610 bytes.
- Artifact SHA-256:
  `975330a1c64b3e3b3cc25eed66b94cfb0590a3c3b8dbb4a7c3e4fbc5741ad030`.
- File checks and the 96 MiB payload checksum matched, the stale file was absent,
  and no current staging directory remained.

### PostgreSQL restore

- Node `21`, backup `5`, restore row `7`.
- Stable task ID: `b7a2028e-798b-4ffa-a00c-ec7592c51bad`.
- Worker was killed during `database_importing`.
- The same row/task completed on attempt `2`.
- Target database:
  `bs_restore_0c6125c198c1_bs_postgres_e41af5f75324`.
- Source/target data and marker matched. A fresh run on the newest checkpoint is
  still required to prove the final scoped-temp cleanup and checkpoint changes.

### AWS EC2/EBS/S3/DynamoDB

- EC2 source `i-0fc13e2a765f8a713` restored to
  `i-07bfcc4da9c671648`; guest fingerprint and data matched.
- EBS snapshot `snap-078baa6fb054c1a86` restored to
  `vol-00671eafd76f818b8`; the 16 MiB payload SHA-256 matched.
- S3 source bucket `bs-e2e-20260810-aws-8c6d2a91-source` restored to
  `bs-e2e-20260810-aws-8c6d2a91-ui-restore`; byte count, SHA-256,
  ETag, source version ID, and target version ID were persisted and matched.
- DynamoDB source `bs-e2e-20260810-aws-8c6d2a91-ddb` restored to
  `bs-bs-e2e-20260810-aws-8c6d-dynamodb-tab-aws8c6dn14b3`; schema,
  item count, marker item, and canonical digest matched.

### AWS RDS

- Source instance: `bs-e2e-20260810-aws-8c6d2a91-rds`.
- Source DB resource ID:
  `db-7Q6WUZG6K47IHPH4ICMXOWTTEY`.
- Original UI restore target:
  `bs-bs-e2e-20260810-aws-8c6d-rds-database-aws8c6dn15b1`.
- Original target DB resource ID:
  `db-KGLYH7L66O7HJAXTKM74P3ERO4`.
- UI restore row `1` completed and database marker data matched.
- Known finding: this old restore used AWS's default subnet group because the old
  application did not persist/forward the source network configuration. The
  exact owned target was remediated to the exact owned source security group;
  no default security group was changed. The new code addresses this, but the
  fresh live proof is still pending.

### Hetzner

- Native source server `161180865`.
- Snapshot `418592977`.
- Restored server `161234276`.
- Website/database fixture server `161187384`.
- Fixture SSH key `116869582`.
- Object Storage bucket `bs-e2e-20260810-5b4a6b63` with exact ownership marker.
- Native snapshot/restore ownership and control-plane state were verified.
- No guest SSH/data claim was made for restored server `161234276` because a
  confirmed guest login was not available for it.

### Historical Vultr evidence only

- The last authenticated run was
  `bs-vultr-e2e-20260804133752-91b44d`.
- Its compute, block, Object Storage, automatic-backup monitoring, and managed
  database backup/fork restore tests passed and its exact run-owned resources
  were cleaned.
- It does not validate the current code. Do not rerun it with the current 401
  token.

## Exact retained resource ledger

These resources were intentionally retained for reruns and final cleanup. Before
changing any one of them, re-read provider state and independently prove its
exact account/project, region, immutable ID, ownership marker, and source
witness. This table is a starting inventory, not deletion authority.

| Provider | Resource | Exact ID/name | State at last proof |
| --- | --- | --- | --- |
| AWS | EC2 source | `i-0fc13e2a765f8a713` | Retained |
| AWS | EC2 backup AMI | `ami-0ae65ee0f29828de5` | Retained |
| AWS | EC2 restore | `i-07bfcc4da9c671648` | Retained |
| AWS | EBS snapshot | `snap-078baa6fb054c1a86` | Retained |
| AWS | EBS restored volume | `vol-00671eafd76f818b8` | Retained |
| AWS | S3 source bucket | `bs-e2e-20260810-aws-8c6d2a91-source` | Retained |
| AWS | S3 restore bucket | `bs-e2e-20260810-aws-8c6d2a91-ui-restore` | Retained |
| AWS | DynamoDB source | `bs-e2e-20260810-aws-8c6d2a91-ddb` | Retained |
| AWS | DynamoDB restore | `bs-bs-e2e-20260810-aws-8c6d-dynamodb-tab-aws8c6dn14b3` | Retained |
| AWS | RDS source | `bs-e2e-20260810-aws-8c6d2a91-rds` | Available at last proof |
| AWS | RDS original restore | `bs-bs-e2e-20260810-aws-8c6d-rds-database-aws8c6dn15b1` | Available at last proof |
| AWS | RDS manual snapshot | Expected exact run identifier `bs-e2e-20260810-aws-8c6d2a91-rds-snapshot`; re-read exact ARN/tags/time before use | Available at last proof |
| Hetzner | Native source server | `161180865` | Running at last proof |
| Hetzner | Native snapshot | `418592977` | Available at last proof |
| Hetzner | Native restore server | `161234276` | Running at last proof |
| Hetzner | Website/database fixture | `161187384` | Retained |
| Hetzner | Fixture SSH key | `116869582` | Retained |
| Hetzner Object Storage | Test bucket | `bs-e2e-20260810-5b4a6b63` | Retained |

BackupSheep UI fixture nodes at wrap-up:

| Node | Integration | Name |
| --- | --- | --- |
| `13` | AWS EC2 | `bs-e2e-20260810-aws-8c6d2a91-source` |
| `15` | AWS RDS | `bs-e2e-20260810-aws-8c6d2a91-rds` |
| `19` | Website | `Hetzner Website Files 2026-08-10` |
| `20` | MariaDB | `Hetzner MariaDB Fixture 2026-08-10` |
| `21` | PostgreSQL | `Hetzner PostgreSQL Fixture 2026-08-10` |

## Remaining acceptance work, in order

### 1. Re-establish the safe baseline

- Check out `develop`, fetch `origin/develop`, and confirm no divergence or
  unrelated local edits.
- Confirm the demo remote HEAD equals `origin/develop`, while preserving the
  untracked Compose override.
- Re-run public health, migration exit, Django system check, and signed-in UI
  smoke.
- Authenticate AWS with STS and Hetzner with the exact Cloud API account/project
  endpoint without printing credentials. If either fails, remove that provider
  from live scope immediately.
- Query exact run-owned inventories before mutation. Do not use a name-only or
  prefix-only cleanup decision.
- Confirm zero active BackupSheep backup/restore rows and zero pending or
  dispatched backup requests before starting each crash test.

### 2. Fresh AWS RDS UI snapshot and crash-safe restore

Use node `15` through the signed-in UI.

1. Click **Create Snapshot** once.
2. Record the new BackupSheep backup row, stable Celery task ID, execution
   correlation ID, attempt/delivery counts, phase, provider operation/resource
   ID, and complete v3 provisional/committed witness.
3. Verify the exact provider snapshot has one ownership match and that its ARN,
   account, region, source ARN/resource ID, request tag, source tag, snapshot
   create time, original snapshot time, and source configuration match the
   durable witness.
4. Trigger restore through the UI using source-derived defaults.
5. Kill only the exact `worker-cloud` container after AWS has accepted the
   request and while the target is creating/polling. Record the container ID and
   restore phase before the kill.
6. Let Compose restart the worker or restart only that service. Verify takeover
   uses the same restore row and task identity, increments the attempt, adopts
   exactly one provider target, and never sends a second restore request.
7. Verify the restored DB class, subnet group, VPC security groups, public
   accessibility, storage type, IOPS, throughput, source snapshot, ownership
   tags, and restore marker all match the committed witness.
8. Connect to the exact owned target and compare the source/target marker and
   data digest.
9. Exercise visible status/activity transitions and verify 404, rate-limit,
   timeout, transient outage, and terminal failure remain distinct in stored and
   public state. Lost-response injection remains automated evidence unless a
   safe live fault proxy is deliberately introduced.
10. Do not delete the RDS source until all source identity and immutable witness
    checks pass. If testing source-loss fallback, delete only that exact owned
    source, use `SkipFinalSnapshot`, and then prove restore from the committed
    snapshot witness. This is optional unless retained as a release criterion.

### 3. Fresh PostgreSQL and MariaDB UI crash tests

PostgreSQL node `21`, backup `5`:

1. Start a new UI restore to a new exact-owned fork target.
2. Record row/task/correlation/fence and scoped remote names.
3. Kill only `worker-database` during `database_importing`.
4. Verify the same row/task resumes, attempt count increases, checkpoints are
   adopted, the import converges, source/target data and marker match, and the
   final scoped remote temporary inventory is empty.

MariaDB node `20`:

1. Take or select a verified complete backup and start a fork restore through
   the UI.
2. Kill `worker-database` after partial import, never during an unproved in-place
   target.
3. Verify the exact-owned target marker and live fence are re-read immediately
   before drop/recreate.
4. Verify the same restore row/task converges after replay, data checksums match,
   and no scoped remote files remain.
5. Confirm an in-place retry still stops for manual review instead of dropping a
   database whose ownership is not exact.

### 4. Fresh Hetzner control-plane/UI rerun

- Use only authenticated Hetzner Cloud/Object Storage endpoints and the exact
  retained fixture resources above, or create a new uniquely labeled run with a
  new durable ledger.
- Re-run native snapshot and fork restore through the UI, kill the exact cloud
  worker after provider acceptance, and verify same-row adoption with one exact
  provider match.
- Re-run website/database storage uploads and restores only against the exact
  owned Object Storage bucket and fixture server.
- Persist and read back checksum, bytes, ETag, and version ID or an explicit
  provider-unavailable value.
- Do not claim restored guest integrity without confirmed guest login.

### 5. Exact cleanup and drift audit

- Re-read every item in the retained ledger.
- For each deletion, require the durable ledger witness plus exact provider
  ownership and source correlation immediately before the call.
- Wait for provider-confirmed absence; a timeout, 404 ambiguity, API outage, or
  failed read is not proof of absence.
- Remove BackupSheep fixture rows only after their external resource graph is
  reconciled.
- Prove zero exact run-owned AWS and Hetzner resources remain, or list each
  intentionally retained item with reason.
- Prove no AWS Lightsail API call or mutation occurred.
- Prove the application has zero active backup/restore jobs and no pending
  outbox requests after cleanup.

### 6. Requested independent review and feedback pass

This required sequence is not complete:

1. Delegate a read-only enterprise review of the final integrated code and live
   evidence to **GPT-5.6 Sol Max**.
2. Give Sol the safety boundaries, this handoff, the full diff since `8bbb3ef`,
   the live evidence report, and all exact test results.
3. Classify findings by backup correctness risk: duplicate creation, data loss,
   ownership bypass, stale-worker mutation, false success/absence, integrity
   omission, or observability gap.
4. Delegate actionable fixes to **GPT-5.6 Luna Max** with disjoint write scopes.
5. Review the patches locally; do not accept generated changes without tests.
6. Re-run focused suites, the integrated 520-test selection, the full suite,
   static checks, Docker build-context proof, and fresh live checks affected by
   a fix.

### 7. Final ship sequence

- Update `docs/live-e2e-20260810.md` and this handoff with final evidence and
  cleanup state.
- Run `git diff --check`, changed-file Python compilation, Django check,
  migration drift check, focused tests, and the full suite.
- Scan staged filenames/content for credentials without printing matches.
- Commit intentionally on `develop`, push to `origin/develop`, and confirm local
  and remote ancestry.
- On the demo host, follow the current [exact-commit upgrade and rollback
  runbook](guides/upgrades.md). Do not use direct Compose or a broad `up` once any
  guard/workload pair exists: the verified wrapper requires a reviewed whole-stack
  `down`, then exact paired recreation so an old workload cannot remain attached to a
  replaced guard namespace.

- Verify exact deployed commit, migration exit `0`, healthy service state,
  internal/public health HTTP 200, deployed image credential-path absence,
  signed-in dashboard/activity UI, and zero-active-job invariant.

## Useful read-only resume commands

These commands intentionally avoid credential output.

```sh
git status --short --branch
git fetch origin develop
git rev-list --left-right --count develop...origin/develop
git diff --check
```

```sh
ssh -o BatchMode=yes root@64.177.125.68 \
  'cd /opt/backupsheep && git rev-parse HEAD && git status --short --branch'
```

```sh
curl -fsS --max-time 20 -o /dev/null \
  -w '%{http_code} %{url_effective}\n' \
  https://demo.backupsheep.com/healthz/
```

```sh
ssh -o BatchMode=yes root@64.177.125.68 \
  'cd /opt/backupsheep && \
   docker compose -f docker-compose.yml -f docker-compose.override.yml \
   exec -T app python manage.py check'
```

For local one-off Django checks, the repository's local `.env` still contains a
production-placeholder signing key. Use a test-only override and `--no-deps` so
the check does not race the Compose `migrate` service:

```sh
docker compose run --rm --no-deps \
  -e DJANGO_SERVER=local \
  -e DJANGO_SECRET_KEY=local-static-verification-key-only \
  app python manage.py check
```

Do not use shell commands that print `_docs/`, `env`, Compose environment, or
decrypted integration fields.

## Final acceptance criteria

Do not call this enterprise-ready until all of the following are true:

- Newest RDS and PostgreSQL/MariaDB UI crash tests pass on the deployed commit.
- Accepted-but-unpersisted provider requests are adopted without duplicates.
- Provider ownership is verified before every poll and delete.
- Provider 404, failure, rate limit, timeout, and transient outage are visibly
  distinct from in-progress.
- Object uploads persist and verify byte count, checksum, ETag, and version ID or
  explicit provider unavailability.
- All exact run-owned resources are cleaned or intentionally documented, with
  provider-confirmed absence and no Lightsail mutation.
- Sol Max review is complete and all accepted findings are fixed by Luna Max.
- Focused, integrated, and full suites are green after those fixes.
- Final code is committed, pushed, deployed, healthy, and the application shows
  no active or stranded backup/restore work.
