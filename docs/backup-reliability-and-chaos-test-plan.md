# Backup reliability architecture and acceptance plan

BackupSheep treats the database as the source of truth for orchestration and the
provider as the source of truth for remote side effects. Celery is a delivery
mechanism only. A message ID, worker process, result backend entry, or in-memory
object is never sufficient evidence that a backup was or was not created.

This document defines the invariants that every backup and restore integration must
meet and the tests required before a release can be described as crash-resilient.

## Non-negotiable invariants

1. One logical request has one durable request identity and one stable Celery task
   ID, even when an API request, schedule trigger, broker publish, or worker delivery
   is repeated.
2. A worker must hold a renewable database lease before it performs work. The lease
   includes a random fencing token so an expired worker cannot commit after a
   replacement takes over.
3. A provider mutation is preceded by an immutable witness containing the provider,
   source resource, resource type, account/project/region scope, and deterministic
   BackupSheep marker.
4. If a provider may have accepted a mutation but the response or database commit is
   lost, recovery inventories every provider page and adopts exactly one matching
   resource. It never issues another mutation until reconciliation proves zero
   matches. Multiple matches stop in manual review.
5. Provider ownership is fail-closed. Missing source, account, project, region, type,
   marker, or version evidence is not treated as a match.
6. `404`, authentication failure, authorization failure, throttling, provider outage,
   timeout, malformed response, explicit provider failure, and a healthy in-progress
   state are distinct durable outcomes.
7. A local source archive is usable only after ZIP CRC validation, exact byte count,
   SHA-256, a durable artifact row, and an fsynced commit marker agree.
8. Every destination has exactly one logical upload row. Resumable provider session
   IDs, part ledgers/cursors, object key, byte count, SHA-256, ETag, and version ID are
   checkpointed before the parent can become complete.
9. Restore validates the exact committed object/version and archive safety before it
   modifies a target. Provider-native restore defaults to a new resource or fork.
10. Deletion mutates only an exactly owned resource/version. A `404` is idempotent
    success only after prior durable ownership proof and a persisted delete-started
    checkpoint.
11. Recovery sweeps are safe to run concurrently. They are bounded, cursor-aware,
    lease-protected, and keep the original logical request identity.
12. Operator APIs and UI show durable phase, progress, retry timing, reconciliation
    state, safe error code/message, and correlation ID without exposing credentials,
    provider bodies, worker identities, local paths, or lease tokens.

## Durable lifecycle

```text
accepted request
  -> durable outbox
  -> claimed source execution
  -> provider witness or local artifact build
  -> provider reconciliation / artifact verification
  -> provider polling or destination uploads
  -> integrity verification
  -> complete | partial | failed | manual review
  -> ownership-verified restore/deletion
```

An interruption may leave a row in any non-terminal phase. RabbitMQ redelivery is the
fast path; the periodic database sweep is the independent fallback. Neither path is
allowed to infer that a remote mutation failed merely because its response is absent.

## Failure classification contract

| Outcome | Durable behavior | Automatic mutation allowed? |
| --- | --- | --- |
| Healthy provider work | Keep `IN_PROGRESS`; poll after the configured interval | No new create |
| Rate limited | Record rate-limit code and bounded `Retry-After` | Retry same operation after deadline |
| Timeout/lost response after mutation | Mark reconciliation required and retain witness | Reconcile first; create only after zero exact matches |
| Transient provider outage | Record transient code and bounded backoff | Retry read; reconcile before any create |
| Authentication/authorization failure | Terminal actionable failure | No |
| Proven provider `404` while polling | Terminal not-found failure | No |
| Proven provider `404` after delete-started | Deletion complete | No second delete |
| Unproven provider `404` during deletion | Manual failure/review | No |
| Ownership mismatch or missing evidence | Terminal/manual review | No |
| Multiple exact reconciliation matches | Manual review | No |
| Malformed provider response | Failure or reconciliation required | No blind mutation |
| Worker lease lost | Stale worker is fenced; replacement owns progress | Stale worker: no |

## Automated acceptance matrix

These tests run against Dockerized PostgreSQL, RabbitMQ, web, Beat, and workers.
Provider calls may be deterministic fakes unless a row explicitly requires a live
provider.

| ID | Scenario | Required assertion |
| --- | --- | --- |
| DUR-01 | Submit the same API idempotency key concurrently | One outbox row, task ID, backup row, and source action |
| DUR-02 | Distinct manual requests overlap on one node | Node lock permits one active backup; the other links safely without a provider create |
| DUR-03 | Two Beat instances fire one schedule occurrence | One occurrence identity and one outbox request |
| DUR-04 | Beat dies after outbox commit but before broker confirmation | Recovery publishes the same task ID |
| DUR-05 | Broker accepts a message but confirmation is lost | Conservative claim timeout; no short-delay duplicate publish |
| DUR-06 | RabbitMQ is unavailable when a request is accepted | Request remains queryable and publishes after broker recovery |
| DUR-07 | RabbitMQ restarts with queued work | Durable queue/message survives, or database sweep republishes the same request |
| DUR-08 | Source worker is killed mid-file transfer | Partial workspace is rejected/cleared and the same backup row resumes |
| DUR-09 | Source worker is killed mid-database dump | Truncated dump is never committed; same backup row resumes |
| DUR-10 | Worker dies after archive fsync but before upload dispatch | CRC/SHA/manifest adoption; no second source snapshot |
| DUR-11 | Source archive is truncated or changed after commit | Upload refuses it with an integrity error |
| DUR-12 | Two source workers race after lease expiry | Old fence cannot commit or publish storage work |
| DUR-13 | Storage worker dies during multipart upload | Persisted upload ID/parts resume; no second object identity |
| DUR-14 | Object upload succeeds but response is lost | Exact key/metadata/size/checksum adoption; no second upload |
| DUR-15 | Provider returns two exact object matches | Stop in reconciliation/manual review |
| DUR-16 | One of several destinations fails validation | Remaining destinations run and parent becomes `PARTIAL`, never false `COMPLETE` |
| DUR-17 | No requested destination validates | Source dump is not started |
| DUR-18 | Required air-gapped destination fails | Source dump is not started and policy failure is durable |
| DUR-19 | Early or duplicate finalizer runs while upload is active | Parent stays non-terminal and finalizer retries |
| DUR-20 | Finalizer is redelivered after terminal commit | Status and retention remain idempotent |
| DUR-21 | Restore worker dies during download | Same restore row/lease resumes exact object/version |
| DUR-22 | Restore archive has traversal, duplicate paths, symlink, special file, bomb ratio, or CRC failure | No target mutation |
| DUR-23 | Provider accepts native restore but response is lost | Exact restore marker is adopted; no second target |
| DUR-24 | Native managed-database restore is requested without destructive confirmation | Fork/new cluster is used by default |
| DUR-25 | Delete response is lost after provider acceptance | Prior ownership/delete checkpoint converts exact absence to success |
| DUR-26 | Delete sees an unproven `404` or ownership mismatch | No success claim and no further mutation |
| DUR-27 | Provider inventory spans multiple pages | Cursor traverses all pages and persists page progress |
| DUR-28 | Provider returns 401/403, 404, 429, 5xx, timeout, malformed, failed, and active states | Each maps to its distinct durable code/state |
| DUR-29 | Process restarts while an operation is active | Status API reconstructs phase/progress from PostgreSQL only |
| DUR-30 | Status payload contains secret canaries in internal fields | API/UI output contains none of them |
| DUR-31 | Historical duplicate destination rows exist during deployment | Cleanup migration merges progress; later constraint permits one row only |
| DUR-32 | Migration process is interrupted between cleanup and constraint creation | Rerun resumes from the recorded atomic migration boundary |

## UI acceptance matrix

All scenarios use the same public UI and API routes as an ordinary account member.

| ID | Scenario | Required assertion |
| --- | --- | --- |
| UI-01 | Configure a website source and S3-compatible destination | Validation result is actionable and secrets are never echoed |
| UI-02 | Configure MySQL, MariaDB, and PostgreSQL nodes | Correct engine/options are retained after reload |
| UI-03 | Start an on-demand file backup | One run appears immediately with durable correlation/status |
| UI-04 | Double-click or repeat the start request | One logical request/provider side effect |
| UI-05 | Observe provider polling, throttling, and recovery | UI distinguishes waiting, retrying, and reconciling |
| UI-06 | Observe multipart upload progress | Progress survives page refresh and worker restart |
| UI-07 | Restore files after source mutation | Restored hashes equal the original fixture hashes |
| UI-08 | Restore each database after row mutation | Restored schema/row counts and fixture hashes equal originals |
| UI-09 | Attempt destructive/in-place managed restore without confirmation | UI/API rejects it and offers fork/new-resource mode |
| UI-10 | View a failed/manual-review run | Safe remediation and correlation ID are available; no raw provider error |

## Live Vultr acceptance matrix

Every live run uses a unique prefix and an explicit resource ledger. Baseline provider
inventory is read-only. Cleanup may target only IDs created by that run and only after
the ID plus marker/tag/source ownership proof match. Existing resources are never
changed, rebooted, snapshotted, attached, detached, or deleted.

| ID | Scenario | Required assertion |
| --- | --- | --- |
| VUL-LIVE-01 | Create isolated compute source and take server snapshot through UI | One owned snapshot and one completed BackupSheep run |
| VUL-LIVE-02 | Kill cloud worker after provider acceptance before local ID commit | Recovery adopts exactly one snapshot |
| VUL-LIVE-03 | Create isolated block volume, snapshot, and restore | Restored volume identity/source/size are exact |
| VUL-LIVE-04 | Create isolated Object Storage/bucket and upload file backup | SHA-256, bytes, ETag, key, and version ID (when supplied) agree |
| VUL-LIVE-05 | Kill storage worker during multipart upload | Upload resumes/adopts without a duplicate object |
| VUL-LIVE-06 | Create website fixtures on an isolated server, mutate, and restore | All fixture hashes return to baseline |
| VUL-LIVE-07 | Create MySQL fixture, mutate, and restore | Schema, row count, and fixture digest return to baseline |
| VUL-LIVE-08 | Create MariaDB fixture, mutate, and restore | Schema, row count, and fixture digest return to baseline |
| VUL-LIVE-09 | Create PostgreSQL fixture, mutate, and restore | Schema, row count, and fixture digest return to baseline |
| VUL-LIVE-10 | Create managed database backup and fork restore | New owned cluster is created; source is unchanged |
| VUL-LIVE-11 | Reboot BackupSheep host with active jobs | Database state resumes and provider inventory shows no duplicate action |
| VUL-LIVE-12 | Restart RabbitMQ with accepted/queued jobs | Stable request IDs resume after broker recovery |
| VUL-LIVE-13 | Provider rate limit/transient fault injection where safely possible | Backoff/status are visible and no blind create occurs |
| VUL-LIVE-14 | Restore from exact storage version after a newer key version exists | Selected committed version is restored |
| VUL-LIVE-15 | Final ownership-scoped cleanup and drift inventory | No run-owned resources remain; baseline resources are unchanged |

## Live AWS acceptance matrix

Every AWS mutation uses a unique run prefix plus `backupsheep:test-run` and
`backupsheep:managed-by=codex-e2e` tags where the service supports tags. Before any
cleanup, the resource ID, account ID, region, tags, and creation ledger must all
match. Untagged or pre-existing resources are never changed, rebooted, snapshotted,
attached, restored, or deleted.

| ID | Scenario | Required assertion |
| --- | --- | --- |
| AWS-LIVE-01 | Confirm caller account and capture read-only regional baseline | Account/region are recorded without credentials and no baseline resource changes |
| AWS-LIVE-02 | Create isolated EC2 source and take AMI backup through UI | One owned AMI and its owned snapshots; one completed BackupSheep run |
| AWS-LIVE-03 | Lose the EC2 create response before persistence | Exact tag/source/account/region reconciliation adopts one AMI; no duplicate |
| AWS-LIVE-04 | Create isolated EBS data volume, snapshot, and restore | Restored volume source, size, type, encryption scope, and fixture digest agree |
| AWS-LIVE-05 | Create isolated RDS source, native snapshot, and new-instance restore | Restored DB is a new owned instance; source remains unchanged |
| AWS-LIVE-06 | Lose the RDS snapshot or restore response | Exact ARN/tag/source reconciliation adopts one resource; multiple matches fail closed |
| AWS-LIVE-07 | Create isolated S3 versioned bucket and upload file/database backups | SHA-256, bytes, ETag, key, and version ID agree with the durable artifact ledger |
| AWS-LIVE-08 | Interrupt multipart upload and restart workers | Persisted upload ID/parts resume or exact object is adopted; no duplicate key/version |
| AWS-LIVE-09 | Create isolated DynamoDB table, export/backup, mutate, and restore to new table | Item count and deterministic fixture digest return to baseline; source remains unchanged |
| AWS-LIVE-10 | Restart BackupSheep workers, broker, and host during separate AWS jobs | Durable status resumes and provider inventory contains one logical side effect per request |
| AWS-LIVE-11 | Exercise UI double-submit and page refresh during AWS backup/restore | One durable request; progress/retry/reconciliation survive refresh |
| AWS-LIVE-12 | Ownership-scoped cleanup and final drift inventory | Only ledger-owned IDs are removed and baseline IDs/tags remain unchanged |

## Live Hetzner acceptance matrix

Every Hetzner mutation uses a unique run prefix and labels
`backupsheep-test-run=<run>` and `managed-by=codex-e2e`. Cleanup is permitted only
when project identity, provider ID, label set, source witness, and the local creation
ledger all agree. Existing servers, volumes, snapshots, images, networks, firewalls,
SSH keys, and load balancers are read-only.

| ID | Scenario | Required assertion |
| --- | --- | --- |
| HET-LIVE-01 | Confirm project identity and capture read-only baseline | Project scope is recorded without credentials and baseline resources are unchanged |
| HET-LIVE-02 | Create isolated server and snapshot it through UI | One owned snapshot with exact source/project/labels and one completed run |
| HET-LIVE-03 | Lose snapshot response before resource ID persistence | Full pagination adopts exactly one matching image; no second create |
| HET-LIVE-04 | Create an isolated volume and attempt to configure native volume backup | UI/API clearly report that Hetzner has no native volume-snapshot workflow; no image, clone, detach, or delete mutation is issued |
| HET-LIVE-05 | Provision website fixtures on the isolated server, mutate, and restore | Restored SHA-256 manifest exactly matches the pre-backup fixture manifest |
| HET-LIVE-06 | Provision MySQL, MariaDB, and PostgreSQL fixtures, mutate, and restore | Schema, row counts, and deterministic fixture digests return to baseline for each engine |
| HET-LIVE-07 | Restart workers/broker during Hetzner create and polling phases | Same request resumes; one provider resource exists and UI shows durable recovery state |
| HET-LIVE-08 | Exercise UI double-submit, rate/transient fault handling, and manual review | No blind create; UI distinguishes retry, reconciliation, terminal failure, and manual review |
| HET-LIVE-09 | Ownership-scoped cleanup and final drift inventory | Only ledger-owned IDs are removed and all baseline IDs/labels remain unchanged |

## Evidence required for each live run

- UTC start/end time and unique run prefix.
- Account/team/project identity confirmation without recording credentials.
- Read-only baseline counts and collision check.
- Resource ledger: service, role, provider ID, marker/tag, source ID, and cleanup
  eligibility.
- BackupSheep request, backup/restore, execution, artifact, and destination row IDs.
- Worker/broker interruption timestamps and pre/post durable phases.
- Provider inventory proving one exact create/restore action.
- Archive/object SHA-256 and bytes; file hashes or database fixture digest before
  mutation, after mutation, and after restore.
- UI screenshots or browser assertions for configuration, running/recovery, and
  terminal states.
- Cleanup results and final provider drift check.

## Release gate

The feature is not accepted merely because migrations apply, code compiles, unit tests
pass, or one normal-path live backup succeeds. Release requires:

1. clean migration rehearsal from the previous release and a fresh database;
2. the full Docker test suite;
3. process-level source/upload/restore worker crash tests;
4. RabbitMQ outage/restart tests;
5. UI-driven file and database backup/restore tests;
6. live Vultr, AWS, and Hetzner tests using only run-owned resources;
7. an independent security/reliability review; and
8. a documented cleanup and drift-free provider inventory for every provider.
