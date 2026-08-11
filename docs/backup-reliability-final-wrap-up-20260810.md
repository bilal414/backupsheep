# BackupSheep backup reliability final wrap-up — 2026-08-10

This is the authoritative resume document for the enterprise backup-hardening
work completed in the 2026-08-10 session. It supersedes the older stop points in
`docs/backup-reliability-resume-handoff-20260810.md` and
`docs/live-e2e-20260810.md`; those files remain useful as the detailed historical
test narrative.

This document intentionally contains no passwords, private keys, access keys,
session cookies, or provider tokens. A resource name in this document is an
inventory hint, never sufficient deletion authority.

## Authoritative stop point

- Working branch: `develop`.
- Final implementation commit: `e43ef8e9c77019db919720a49e693583eda9c0dc`.
- Commit title: `Address enterprise restore review findings`.
- The implementation commit is pushed to `origin/develop`.
- The commit containing this document is a documentation-only descendant of the
  implementation commit. Resolve it with
  `git log -1 --format=%H -- docs/backup-reliability-final-wrap-up-20260810.md`;
  the final `origin/develop` and demo heads should equal that descendant.
- It is deployed at `https://demo.backupsheep.com/` from
  `/opt/backupsheep` on `64.177.125.68`.
- The demo checkout was on `develop` at the exact implementation commit when
  verified. Its only non-repository item was the intentional untracked
  `docker-compose.override.yml`; it was preserved.
- The migration container exited `0`, `python manage.py check` reported no
  issues, the application container became healthy, and public `/healthz/`
  returned HTTP 200.
- The deployed image was verified not to contain `/code/_docs`, `/code/.env`,
  or `/code/.git`.
- A signed-in browser check opened AWS RDS node `15`, opened the newest native
  restore modal, and showed `Complete`, `Provider: available`, the exact target
  identifier, and no stale failure alert.
- A final dynamic database query found no active backup rows across any concrete
  backup model, no active cloud/website/database/Vultr-database restore rows,
  no active backup execution leases, no active restore leases, no required or
  running backup reconciliation rows, and no pending or dispatched backup
  requests.
- No new provider resource was created or deleted during wrap-up. The only live
  data repair removed two stale presentation keys from already-complete RDS
  restore row `8`, after exact row, task, correlation, fingerprint, marker,
  target, status, and immutable AWS DB resource-ID assertions passed.

The code is committed, pushed, deployed, and healthy. This is still not a blanket
enterprise acceptance certificate: the final-code Hetzner native crash test,
live validation of the newest AWS Backup S3/DynamoDB lost-response changes,
owned-resource cleanup/drift audit, and credential rotation remain open.

## Non-negotiable safety boundaries

1. Never change or delete AWS Lightsail resources. Do not add Lightsail to a
   cleanup harness or instantiate it as part of a broad AWS deletion pass.
2. Test only a provider for which login was successfully verified at its exact
   identity/account endpoint during that pass.
3. For AWS and Hetzner, mutate or delete only a resource whose exact account or
   project, region, immutable provider ID, run marker, ownership tags or labels,
   and source witness all match the durable run ledger immediately before the
   call.
4. A generated name or run prefix alone is never create-adoption or deletion
   authority.
5. Zero matches after an uncertain provider mutation means bounded read-only
   reconciliation. Multiple matches, malformed identity, or exhausted
   visibility bounds mean manual review. Never issue a blind second create.
6. Preserve `/opt/backupsheep/docker-compose.override.yml` on the demo host.
7. Do not print, copy into documentation, commit, or place in a Docker build any
   values from `_docs/`, `.env`, decrypted connection fields, or browser storage.
8. Before each new crash test, prove zero active BackupSheep work and record the
   exact provider and application baseline. Kill only the worker/container that
   owns the exact test task.

## What was implemented

### Durable execution, duplicate prevention, and resumption

- Backup requests are committed to a durable outbox before Celery publication.
  Republished deliveries reuse the stable task identity and converge on one
  logical backup row.
- Backups and restores use renewable fenced leases with owner, token, expiry,
  heartbeat, attempt count, progress, correlation ID, retry timing, and explicit
  reconciliation state.
- A stale worker must re-read and prove its live fence immediately before a
  provider mutation or destructive restore step. A takeover prevents the stale
  worker from committing afterward.
- Provider operation IDs, resource IDs, idempotency keys, request fingerprints,
  ownership markers, source witnesses, and reconciliation observations are
  persisted outside Celery result state.
- Terminal backup finalization also terminalizes the execution ledger, clears
  poll fences, and resolves stale recovery-required state.
- Public execution status exposes queued, running, adopting, retrying, manual
  review, failed, and complete states with safe error codes and correlation
  details.

### Generic cloud restore safety

- Provider 404, authentication failure, rate limit, timeout, transient outage,
  terminal failure, malformed response, ownership mismatch, duplicate match,
  and reconciliation-required outcomes are distinct.
- A healthy later poll clears stale public error rollups. An error written by the
  current reconciliation observation remains visible and retains its
  `RECONCILING` or retry phase.
- Manual `Resume verification` is allowed only for a failed manual-review row
  with an existing provider pointer. It performs read-only polling, never a new
  create, has a bounded resume count, and keeps the original root task identity.
- A lost broker acknowledgement after manual resume returns the exact durable
  row even if the poll raced to `COMPLETE` or `FAILED` before the HTTP handler
  recovered.
- The browser tracks the exact restore row ID after creation. Name matching is
  allowed only for the initial lost-response recovery and only when exactly one
  row matches, so duplicate display names cannot switch the visible restore.

### AWS Backup S3 and DynamoDB restore reliability

- `ListRestoreJobs` now uses only current SDK/API filters:
  `ByAccountId`, `ByResourceType`, `MaxResults`, and `NextToken`. The unsupported
  `RecoveryPointArn` request filter was removed.
- Every listed or described job must match exact restore-job ID when known,
  recovery-point ARN, account ID, resource type, and created target ARN when AWS
  exposes it.
- `StartRestoreJob` metadata and a deterministic idempotency token are durable
  before the request. A lost response is recovered by replaying the exact same
  request/token; AWS documents this as a successful no-op after acceptance.
- The AWS job pointer and target pointer are persisted in the same database
  write. A crash cannot leave `resource_id` durable while losing
  `provider_job_id`.
- `PENDING` and `RUNNING` are the only accepted transitional restore-job states.
  `FAILED` and `ABORTED` are provider failures even when no target ARN exists.
  A completed job must have the exact target ARN and a readable exact target.
  Backup-only states such as `PARTIAL` or `EXPIRED` fail closed as malformed in
  the restore path.
- S3 destination safety witnesses survive request-identity persistence. The
  destination must be the selected non-source bucket, versioning must be
  enabled, and bounded object/version/delete-marker/multipart scans must prove
  it empty before restore.
- DynamoDB completion requires the exact table ARN, `ACTIVE` table state, and
  exact ownership/tag verification.

### AWS EC2/EBS, DigitalOcean, Hetzner, and RDS

- AWS EC2/EBS lost-create recovery searches by the exact BackupSheep ownership
  tag and exact source relationship. Zero matches remain in a bounded visibility
  window; duplicate or foreign matches fail closed.
- DigitalOcean restore inventory, source reads, create calls, and polling now
  use bounded request timeouts. Tagged zero-match recovery is bounded and never
  creates again while the outcome is unknown.
- Hetzner restore recovery uses its exact provider-side restore label and source
  image relationship. Zero matches are bounded; duplicate pages/matches and
  ownership inconsistencies fail closed.
- RDS backup and restore use durable versioned source/target witnesses, exact
  account/region/resource identity, provider ownership tags, cursor-based
  `Marker` pagination with hard bounds, fenced create/delete leases, bounded
  target/tag visibility, and source-derived network/storage defaults.
- Current documented RDS lifecycle states are classified as success,
  transitional, or terminal failure. The legitimate
  `configuring-enhanced-monitoring` transition no longer becomes a malformed
  response/manual-review state.

### Website, database, and storage integrity

- Website and database tasks use stable execution rows, scoped remote temporary
  names, bounded SSH/SFTP operations, integrity checks, and takeover-safe
  cleanup.
- PostgreSQL fork restores replay inside a transaction and use a durable marker
  so a killed import can safely retry without partial committed data.
- MySQL/MariaDB fork restores re-read exact target ownership and the live fence
  immediately before drop/recreate/replay. Unproved in-place destructive retry
  remains fail closed/manual review.
- Upload evidence persists byte count, checksum algorithm/value, ETag, version
  ID or explicit provider unavailability, object key, multipart ID when used,
  and verification time. Local artifacts and remote read-back are validated
  before a backup is finalized.

## Independent review and feedback cycle

The requested final sequence was completed:

1. GPT-5.6 Sol Max performed a read-only enterprise review of the integrated
   code and evidence.
2. Eight findings were accepted: invalid AWS Backup restore-job filtering;
   substring/insufficient AWS job ownership and false-success risk; immediate
   zero-match manual review for AWS EC2/EBS, DigitalOcean, and Hetzner; missing
   DigitalOcean restore timeouts; stale healthy status errors; manual-resume
   broker-ack race; same-name UI row switching; and notification exception
   variable shadowing.
3. Disjoint GPT-5.6 Luna Max agents implemented provider, generic restore/UI,
   and notification fixes.
4. Main-agent review then added current AWS restore lifecycle enforcement,
   active-reconciliation error preservation, S3 preflight witness preservation,
   and atomic AWS target/job-pointer persistence.
5. All generated changes were reviewed locally and passed the final test gates
   below before commit or deployment.

## Final automated verification

All tests were Docker-backed and used mocked provider boundaries unless a case
is explicitly listed in the live evidence section.

| Gate | Final result |
| --- | --- |
| Sol/Luna-focused reliability selection | `169/169` passed in `27.721s` after correcting the regressions the gate exposed |
| Final AWS Backup S3 restore module | `19/19` passed in `3.658s` |
| Full Django suite on the committed source tree | `1,157/1,157` passed in `154.459s` |
| Django system check | No issues |
| Migration drift | `makemigrations --check --dry-run`: no changes |
| Python compilation | All changed Python files compiled |
| Patch hygiene | `git diff --check` passed |
| Staged credential-pattern scan | Zero matches in staged production source |
| Local Docker build | Passed |
| Deployed Docker credential boundary | `/code/_docs`, `/code/.env`, and `/code/.git` absent |

The full suite deliberately prints fail-closed output for cleanup attempts that
lack both destructive opt-in flags and for injected provider/broker failures.
Those messages are passing safety assertions, not live cleanup failures.

## Final operational state

The post-deployment read-only query returned:

```json
{
  "active_backup_execution_leases": 0,
  "active_backups": {},
  "active_restore_leases": 0,
  "active_restores": {},
  "backup_reconciliation_required_or_running": 0,
  "pending_or_dispatched_backup_requests": 0
}
```

Two historical execution rows had previously retained `required` reconciliation
after their backing rows were already complete: execution `3` for database
backup `4`, and execution `13` for Vultr backup `11`. Each was repaired with the
normal guarded `finalize_execution(terminal_phase="complete")` path. Their final
phase is complete and reconciliation is resolved; no active lease was present.

## Final live UI and crash-recovery evidence

### AWS RDS backup row 3

- BackupSheep node: `15`.
- Source identifier: `bs-e2e-20260810-aws-8c6d2a91-rds`.
- Source immutable DB resource ID:
  `db-7Q6WUZG6K47IHPH4ICMXOWTTEY`.
- Backup row: `3`.
- Provider snapshot identifier:
  `bs-bs-e2e-20260810-aws-8c6d-n15-b3`.
- Stable task ID: `ec647a6f3ce2591e90f7ed7f8a783ebf`.
- Correlation ID: `a1d71460-e0bd-4e24-abd7-023b0cdd4049`.
- Ownership marker:
  `bs-rds-f56b417fd2c5e9e88698920a7c812cebaa71f962820b61857b8c13e6aea24858`.
- The exact cloud worker was killed after AWS accepted the snapshot request.
  Recovery adopted the same snapshot with one exact match and no duplicate
  provider operation. The snapshot reached `available`.

### AWS RDS restore row 8

- Source snapshot:
  `bs-bs-e2e-20260810-aws-8c6d-n15-b3`.
- Restore row: `8`.
- Root task ID:
  `cloud-restore-8-5eb4ecfe2df25dcca4e75e06bf144f1d`.
- Correlation ID: `5eb4ecfe-2df2-5dcc-a4e7-5e06bf144f1d`.
- Restore marker: `backupsheep-restore-8`.
- Request fingerprint:
  `2aac5ea573f352cdd4632f34150ddbd9b8c093531857afcca9779a3265e88477`.
- Target identifier:
  `bs-bs-e2e-20260810-aws-8c6d-rds-database-aws8c6dn15b3`.
- Target immutable DB resource ID:
  `db-CELMLVJGGGWXM6TNJVEMSWTNOQ`.
- The exact cloud worker was killed after AWS accepted the restore. Recovery
  retained the same row, root task, marker, fingerprint, correlation, and target.
- AWS transitioned through `configuring-enhanced-monitoring`; this live state
  exposed and verified the lifecycle-policy fix.
- Exact provider read-back found one owned target. Tags were exactly
  `BackupSheepRestore=backupsheep-restore-8` and
  `BackupSheepSource=bs-bs-e2e-20260810-aws-8c6d-n15-b3`.
- Provider identity was read back in AWS account `810832359046`, region
  `us-east-2`; exact owned target match count was `1`.
- Source and target matched for class `db.t3.micro`, subnet group, security
  group, public accessibility, `gp3`, IOPS `3000`, throughput `125`, and
  allocated storage `20 GB`.
- Manual `Resume verification` performed a read-only poll on the same target and
  completed the row. Final attempt count was `4`; manual-resume count was `1`.
- The signed-in modal was rechecked after the final deployment and exact stale
  rollup repair. It displayed `Complete`, provider `available`, and no old alert.
- The first repair transaction deliberately refused a mismatched assumption
  that `resource_id` held AWS's immutable `DbiResourceId`; it rolled back without
  changing the row. The successful repair asserted the adapter's actual target
  identifier pointer plus `_bs_rds_target_identity.target_dbi_resource_id`
  before removing only `_bs_last_error_code` and
  `_bs_last_error_category`.
- Source and target each contained one exact
  `backupsheep_e2e_marker` row with value
  `bs-e2e-20260810-aws-8c6d2a91:backup-restore-marker`.
- To perform the data comparison, only these exact owned source and target
  master passwords were rotated to an ephemeral generated value. That value was
  not printed or persisted. Future database login requires another controlled
  password rotation after re-verifying exact ownership.
- No new AWS resource or network rule was created for the data check; an
  existing exact test `/32` rule was reused.

### PostgreSQL backup row 7 and restore row 9

- Backup UUID: `bs-hetzner-postgresql-fixtu-n21-b7`.
- Backup task: `308c3f21c7b05598b717be857f1853b9`.
- Artifact: `1,516` bytes.
- SHA-256:
  `05be27af1a97bc6f766faeb09fd322e279e85929226a46b97dc7967d5f997b45`.
- Object key:
  `ui-e2e/hetzner-postgresql-fixtu-n21/bs-hetzner-postgresql-fixtu-n21-b7.zip`.
- ETag: `"387d62685aae716e9f282f747e4d6d2c"`.
- Version ID: explicitly unavailable/null from this storage provider.
- Restore row: `9`.
- Root task: `a93d2b35-ccac-41f6-b766-cc2f650b7749`.
- Correlation ID: `6cf3c99d-6ecd-40e5-b273-fb0ff7082b77`.
- Exact fork target:
  `bs_restore_6cf3c99d6ecd_bs_postgres_e41af5f75324`.
- The exact database worker was killed during import. Attempt `2` adopted the
  same target and transactionally replayed exactly once.
- Source and target each had `20` customers, `0` orders, and dataset marker
  `mutated-before-ui-restore`. The durable restore marker/digest was complete.
- Exact correlation-scoped remote temporary residue count after completion: `0`.

### MariaDB backup row 8 and restore row 10

- Backup UUID: `bs-hetzner-mariadb-fixture-n20-b8`.
- Backup task: `53865f2e95ee53bdac9b5e8de59d71f5`.
- Artifact: `1,564` bytes.
- SHA-256:
  `b00f188ec63bf0bb05b127c8b9d6de76a2c2b5f201ebaf3ea1c644fe3db6961c`.
- Object key:
  `ui-e2e/hetzner-mariadb-fixture-n20/bs-hetzner-mariadb-fixture-n20-b8.zip`.
- ETag: `"c099057c8eba2f06b8b9ef8155ece18f"`.
- Version ID: explicitly unavailable/null from this storage provider.
- Restore row: `10`.
- Root task: `c98b5a16-a9d2-4055-a6f2-7e05577cf8fb`.
- Correlation ID: `4bac2a87-2d40-4c5b-8314-f2baf304c891`.
- Exact fork target:
  `bs_restore_4bac2a872d40_bs_mariadb_f350dcb0700e`.
- The exact database worker was killed during import. Attempt `2` adopted the
  exact owned target and did not replay an already-complete import.
- Source and target each had `20` customers and `0` orders. The marker was
  complete and exact remote residue count was `0`.

### Final read-only Hetzner state

- Token authentication succeeded during the live pass.
- Native source server `161180865` was running (`cx23`, `fsn1`) with the exact
  run label.
- Snapshot `418592977` was `available`, created from source `161180865`, with
  exact account, connection, source, and backup labels.
- Restore server `161234276` was running with
  `backupsheep.restore=6` and `backupsheep.source=418592977`.
- Website/database fixture server `161187384` and fixture SSH key `116869582`
  retained exact fixture-run labels.
- A new final-code Hetzner provider-acceptance/worker-kill test was not run. Do
  not represent this control-plane read-back as that missing test.

## Exact retained resource ledger

All entries are intentionally retained and may be billable. Re-read every entry
before any action. Do not use this table by itself as deletion authority.

Run identities that scope the retained graph:

- Main run: `bs-e2e-20260810-5b4a6b63`.
- AWS S3/DynamoDB/RDS child run: `bs-e2e-20260810-aws-8c6d2a91`.
- AWS EC2/EBS child run: `bs-e2e-20260810-ec2-93ae5f16`.
- Hetzner fixture child run: `bs-e2e-20260810-hzfix-2f7c91ab`.
- Historical, not current, Vultr run:
  `bs-vultr-e2e-20260804133752-91b44d`.

| Provider | Resource | Exact identifier | Last verified state / note |
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
| AWS | RDS source | `bs-e2e-20260810-aws-8c6d2a91-rds` / `db-7Q6WUZG6K47IHPH4ICMXOWTTEY` | Available at last proof |
| AWS | RDS older restore | `bs-bs-e2e-20260810-aws-8c6d-rds-database-aws8c6dn15b1` / `db-KGLYH7L66O7HJAXTKM74P3ERO4` | Available at last proof |
| AWS | RDS newest snapshot | `bs-bs-e2e-20260810-aws-8c6d-n15-b3` | Available; exact ownership marker recorded above |
| AWS | RDS newest restore | `bs-bs-e2e-20260810-aws-8c6d-rds-database-aws8c6dn15b3` / `db-CELMLVJGGGWXM6TNJVEMSWTNOQ` | Available; complete row `8` |
| Hetzner | Native source server | `161180865` | Running at last proof |
| Hetzner | Native snapshot | `418592977` | Available at last proof |
| Hetzner | Native restore server | `161234276` | Running at last proof |
| Hetzner | Website/database fixture | `161187384` | Running at last proof |
| Hetzner | Fixture SSH key | `116869582` | Retained |
| Hetzner Object Storage | Test bucket | `bs-e2e-20260810-5b4a6b63` | Exact ownership marker; retained |
| Fixture server | PostgreSQL fork | `bs_restore_6cf3c99d6ecd_bs_postgres_e41af5f75324` | Complete test target |
| Fixture server | MariaDB fork | `bs_restore_4bac2a872d40_bs_mariadb_f350dcb0700e` | Complete test target |

Relevant BackupSheep fixture nodes:

| Node | Integration | Name |
| --- | --- | --- |
| `13` | AWS EC2 | `bs-e2e-20260810-aws-8c6d2a91-source` |
| `15` | AWS RDS | `bs-e2e-20260810-aws-8c6d2a91-rds` |
| `19` | Website | `Hetzner Website Files 2026-08-10` |
| `20` | MariaDB | `Hetzner MariaDB Fixture 2026-08-10` |
| `21` | PostgreSQL | `Hetzner PostgreSQL Fixture 2026-08-10` |

## Credential and provider availability state

- Local credential files remain gitignored and Docker-ignored. Their values are
  intentionally omitted here.
- AWS and Hetzner authenticated during the completed live pass.
- The supplied Vultr token returned HTTP 401 at the exact account endpoint in
  the current pass. Do not list, create, mutate, or clean Vultr resources until
  a replacement token is supplied and account identity is re-established.
- No DigitalOcean login was authenticated in the final pass. Its new restore
  behavior is automated-test evidence only.
- Do not test any other provider/service without confirmed login information.
- Credentials used during the broader session appeared in user messages or tool
  output. Rotate AWS, Hetzner, demo, storage, old Vultr, DigitalOcean, and any
  other supplied long-lived credential before treating the environment as
  production-like.

## Remaining work, in exact priority order

### 1. Re-establish the deployment and zero-work baseline

1. Fetch `origin/develop` and confirm the local checkout has no unrelated
   changes or divergence.
2. Confirm the demo checkout uses the intended `develop` head and still has only
   the intentional untracked Compose override.
3. Confirm migration exit `0`, app health `healthy`, public `/healthz/` 200,
   Django check success, and image credential-path absence.
4. Run the dynamic zero-active query before any provider mutation.
5. Authenticate only the provider needed for the next case at its exact identity
   endpoint without printing credentials.

### 2. Fresh final-code Hetzner native snapshot/restore crash test

1. Use a new unique run ID and durable ledger, or re-use a retained fixture only
   after exact project, immutable ID, run/source labels, and current state proof.
2. Start a native snapshot through the BackupSheep UI.
3. Kill only the exact cloud worker after Hetzner accepts the request and before
   the provider ID is committed.
4. Verify the same backup row/task adopts one exact snapshot; zero matches remain
   bounded, and multiple/foreign matches stop.
5. Start fork restore through the UI and repeat the worker-kill/adoption proof.
6. Verify exact source image, restore label, source label, provider state,
   duplicate-match count `1`, UI progress, and final zero-active state.
7. Do not claim guest data integrity unless confirmed guest login exists.

### 3. Live-test the final AWS Backup S3/DynamoDB changes

The older code had successful live S3/DynamoDB backup/restore evidence. The
final Sol/Luna AWS restore-job changes are automated-test verified but not live
fault-injected.

1. Create only new uniquely tagged source and target resources, or prove exact
   ownership of retained fixtures before reuse.
2. Exercise `StartRestoreJob` lost-response recovery with the same durable
   idempotency token and metadata.
3. Prove exact account, type, recovery-point ARN, job ID, target ARN, and target
   ownership; record one exact match and no second restore job.
4. Verify failed/aborted, 404, rate-limit, timeout, transient outage, transitional
   missing target ARN, and completed exact target behavior without exposing
   provider response details publicly.
5. Recheck S3 empty/versioned destination witnesses and DynamoDB active/tag/data
   integrity.

### 4. Validate bounded zero-match paths where credentials exist

- Safely live-observe the final bounded no-match behavior for AWS EC2/EBS and
  Hetzner using only a deliberate fault boundary or test-owned delayed
  visibility scenario.
- DigitalOcean remains offline-test only until login is available.
- Never turn a zero-match experiment into permission for another create.

### 5. Exact owned-resource cleanup and drift audit

1. Re-read every retained item and build the full dependency graph.
2. Before each delete, prove exact provider account/project, region, immutable
   ID, run tag/label, source witness, and BackupSheep row correlation.
3. Delete only those exact IDs in dependency-safe order.
4. Poll to provider-confirmed absence. An API error, timeout, outage, or
   ambiguous 404 is not absence proof.
5. Delete fixture databases/rows only after external resources and active work
   are reconciled.
6. Record every intentionally retained item and why it remains billable.
7. Prove no AWS Lightsail call or mutation occurred.

### 6. Rotate credentials and revalidate least privilege

- Rotate every long-lived credential supplied or exposed during the session.
- Replace full-admin credentials with least-privilege provider roles/policies.
- Reconnect BackupSheep using the rotated values without placing them in Git,
  docs, Docker layers, shell history output, or test fixtures.
- The disposable RDS source/target login requires a new exact-owned password
  rotation if another data-level check is needed.

### 7. Final acceptance decision

After the remaining live tests, cleanup, and rotation:

- rerun changed-file compilation, Django check, migration drift, focused tests,
  and the full Docker suite;
- repeat signed-in UI status/activity checks and the zero-active invariant;
- update this document and the live report with exact evidence;
- commit, push, deploy the exact final head, and verify deployment provenance.

## Safe resume commands

These commands are intentionally read-only and do not print credentials.

```sh
git status --short --branch
git fetch origin develop
git rev-list --left-right --count develop...origin/develop
git log -1 --oneline develop
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
   docker inspect -f "{{.State.Health.Status}}" backupsheep-app-1 && \
   docker compose -f docker-compose.yml -f docker-compose.override.yml \
   exec -T app python manage.py check'
```

Do not run commands that print `_docs/`, `.env`, Compose environment, decrypted
connection fields, database passwords, browser cookies, or provider response
bodies.

## Current acceptance matrix

| Criterion | State at stop |
| --- | --- |
| Durable crash recovery and duplicate suppression | Automated and live evidence passed for RDS, PostgreSQL, and MariaDB |
| In-progress visibility and safe error classification | Passed automated gates and final RDS UI verification |
| Final independent Sol review and Luna implementation | Complete |
| Final full suite | `1,157/1,157` passed |
| Code committed, pushed, deployed, and healthy | Complete at implementation commit `e43ef8e9c77019db919720a49e693583eda9c0dc` |
| Fresh final-code Hetzner native crash test | Pending |
| Live final-code AWS Backup S3/DynamoDB lost-response test | Pending |
| Fresh Vultr test | Blocked by current HTTP 401 credential |
| DigitalOcean final live test | Not run; no authenticated login in final pass |
| Exact retained-resource cleanup/drift audit | Pending |
| Credential rotation/least-privilege revalidation | Pending |

## Provider references used for the final review

- AWS Backup `ListRestoreJobs`:
  <https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_ListRestoreJobs.html>
- AWS Backup `StartRestoreJob`:
  <https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_StartRestoreJob.html>
- AWS Backup `DescribeRestoreJob`:
  <https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_DescribeRestoreJob.html>
- Amazon RDS DB instance status reference:
  <https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/accessing-monitoring.html>
