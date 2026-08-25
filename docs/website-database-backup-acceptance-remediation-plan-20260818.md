# Website and database backup acceptance remediation plan — 2026-08-18

This document is the implementation and acceptance handoff for defects found in:

- `docs/website-database-backup-acceptance-20260815.md`
- `docs/large-backup-acceptance-20260816.md`

It records what passed, what failed, what remains unverified, the relevant current
implementation paths, and an ordered plan to close the gaps one at a time.

This is not a release certificate. Both source reports concluded **Partial Pass**.
A successful backup or uploaded artifact is not recovery proof; a scenario is fully
accepted only after an isolated restore and exact content/object verification.
As of the 2026-08-23 closure, every remediation exit gate defined in this document is
Pass on the recorded deployed revision; that statement does not extend to unadvertised
future sizes, engines, or provider scenarios.

## Document status and scope

- Review date: 2026-08-18.
- Repository: `/Users/bilal/Projects/BackupSheep/backupsheep`.
- Branch observed during review: `develop`, aligned with `origin/develop`.
- Review method: read both acceptance reports and inspect the relevant current code
  and automated-test coverage.
- The original planning pass changed no application code, configuration,
  infrastructure, provider resource, or live BackupSheep object.
- No automated or live acceptance test was rerun during the original planning pass.
- Pre-existing local changes to `.gitignore`, `README.md`, `SECURITY.md`, and
  `docs/backup-reliability-resume-handoff-20260810.md` were left untouched.
- Exact causes are labelled **confirmed**, **strongly indicated**, or **unproven**.
  UI-only evidence does not justify inventing a backend cause.

## Active remediation session constraints and tracker

Last updated: 2026-08-23 CDT / 2026-08-23 UTC.

This document is the sole source of scope and the only remediation-plan document to
update during the current work session. On 2026-08-18 the user explicitly authorized
deployment of this plan's code changes to `demo.backupsheep.com` and creation of
isolated test resources in the Vultr account. The active boundaries are:

- Work only on remediation slices and acceptance gates defined in this document.
- Deployment and remote Docker workloads are allowed on `demo.backupsheep.com` after
  exact revision/provenance checks, an active-job safety check, and a recoverable
  pre-deployment database snapshot.
- Use the Vultr account for isolated website and database source nodes. Every created
  resource must have a unique run ID, an ownership label where the provider supports
  one, an exact inventory, and a recorded ongoing-cost/cleanup state.
- The demo host's `/mnt/blockstorage` volume may be attached to demo-side Docker
  workloads for large fixtures and artifacts when a scale gate requires it.
- Do not run local Docker on this MacBook. Do not create or download large backup
  files on this MacBook; large data generation, backup, restore, and verification must
  stay on the demo/Vultr side.
- Preserve unrelated local changes and the demo host's untracked `_docs/` and
  `docker-compose.override.yml`. Do not print secrets, credential files, provider
  response bodies, or the contents of `_docs/`.
- Do not edit the separate backup-reliability handoff as part of this program.
- The user has now authorized demo-server cleanup and exact run-owned test-resource
  cleanup. Fresh ownership/inventory reads are still required before provider deletion;
  record retained resources and costs when cleanup is deferred.
- Do not mark a slice complete merely because code was edited, deployed, or unit tests
  pass. The slice-specific restore and exact-content acceptance gates still control.

| Slice | Status | Current evidence / next gate |
| --- | --- | --- |
| 0 — Regression fixtures | **Pass — deterministic fixtures or bounded live-only protocols now cover every original failure and every declared scale/fault gate** | Run `bs-remed-20260818-0d08dcf` retains PostgreSQL 16, MariaDB 11.8, MySQL 8.4, SFTP/FTP/FTPS, ASCII/Unicode/path-control, engine-client, object-family, crash-boundary, 1M/5M, 1/5/10/25 GB database, 10/25/50/100 GB website, and two-million-file witnesses. All eight database families ran through the signed-in UI for all three engines with isolated exact restore verification. The required database crash/foreign-target gates, website matrix, multipart resume/orphan gates, and terminal diagnostic/UI controls have recorded outcomes. Live-only cases have bounded run IDs, ownership records, and cleanup evidence rather than hidden dependencies on unrelated acceptance resources. |
| 1 — PostgreSQL self-restore | **Pass — current/historical, direct/SSH, all eight UI families, 1/5/10/25 GB, crash recovery, and collision/tamper gates are complete** | Current direct backup `56`/restore `37`, historical direct backup `58`/restore `40`, current SSH backup `63`/restore `45`, SSH 1M restores `48`, `51`, and `53`, eight-family restore `64`, 1 GB restore `65`, and 5 GB restore `66` passed strict exact verification. The later large gates are now closed by PostgreSQL 10M-row backup `99`/controlled-crash restore `93` and 25M-row backup `100`/restore `90`; both completed through the signed-in UI with exact data/schema/marker evidence and natural same-row recovery. Restores `60`/`61` preserve markerless and forged targets. |
| 2 — MariaDB self-restore | **Pass for the stated MariaDB exit gate — direct/SSH, all eight UI fixture families, 5 GB, client rejection, explicit import-error recovery, three SSH crash boundaries, terminal UI, and collision/tamper safety** | Direct backup `57`/restore `39` and SSH backup `60`/restore `42` passed with the exact sandbox header and engine-matched clients. Backup `67` passed 100,000-row post-client/lost-response and pre-client recovery as restores `54`/`55`; backup `66`/restore `56` passed post-marker/pre-final-status adoption without re-import. Restore `62` passed controlled import-error/manual-resume recovery. Restores `58`/`59` preserved markerless/forged targets. Connection/node `72`/`99`, generation backups `72`/`73`, and same-row restore `67` pass all eight MariaDB families. Backup `74`/restore `68` passed the 5,000,000-row/5.86 GB source gate with exact aggregate, sampled, schema, marker, scheduler, cleanup, full ordered digest, and signed-in Complete/1-of-1 modal evidence. Cross-engine fault coverage and any later advertised sizes remain tracked separately in Slices 3 and 10. |
| 3 — MySQL/MariaDB crash convergence | **Pass for the required MySQL 1M/5M, foreign-target, and full eight-family gates; additional cross-engine repetition is optional expansion** | MySQL restores `74`–`77` cover committed-row, pre-client, post-client/pre-checkpoint, and post-marker/pre-final-status loss on the same 1M artifact. Each stayed on one logical row, used natural stale-lease takeover, reached exact data/schema/marker/UI completion, and left zero targeted restore-work residue; post-marker restore `77` additionally proves one import invocation and marker adoption. Restores `78`/`79` failed closed and preserved markerless/forged foreign targets byte-for-byte. Backup `81`/restore `82` pass all eight fixture families and database-default fidelity on deployed revision `ee8ec34`. Backup `88`, clean restore `83`, and controlled-kill restore `84` close the 5M repetition with exact full ordered-row/schema/marker proof and one natural attempt-2 takeover. Earlier restore `44` proves committed-row recovery at 100k. MariaDB restores `54`–`56` cover its three boundaries; restore `68` survived broker redelivery at 5M; restores `58`/`59` preserve markerless/mismatched targets. |
| 4, 6–7 — Website archive/scale work | **Pass — scalable archive contract, complete W1–W9 UI fixture matrix, live case-fold/Unicode-normalization rejection, plain FTP and explicit FTPS legal-component fuzz, 300-level real-SFTP path, 10/25/50/100 GB restore proof, and two-million-file backup/restore/interruption are complete** | Revisions through `81ea8a2` provide bounded enumeration/writing/verification, capacity preflight, a durable mirror checkpoint, disk-spooled restore identity, renewable local-storage verification/copy leases, safe long-task completion, and fail-closed C0-control handling. Backup `50`/restore `25` pass the combined W1/W2/W3/W4/W5/W6b/W7/W9 signed-in matrix; W6 and W8 pass independently. Backup `44`/restore `22` and interrupted backup `49` pass the two-million-file gates. Backup `42`/restore `27` passes the 107,421,554,763-byte archive and 107,421,554,467-byte restored-member gate. Case-folding backup `52` plus deployed restore `29` prove terminal `RESTORE_TARGET_NAME_COLLISION`; FTP/FTPS backups `57`/`58` and restores `34`/`35` pass the legal-component matrix; backup `56` and restore `33` prove C0-control rejection. Claimed-size website backups `59`–`61` and signed-in restores `36`–`38` now pass 10, 25, and 50 GiB with exact hashes, CRCs, target manifests, one logical row each, drained queues, zero scoped residue, and zero restart/OOM. Slices 4 and 6–8 are **Pass**. |
| 5 — Unicode filename round-trip | **Pass for new and retained historical small-artifact restore gates, broader destination/path-component fuzz, and the completed claimed-size website matrix** | Backup `38` reproduced the missing ZIP UTF-8 flag. Commit `cf9e97b1` preserves the existing ZIP payload while marking valid UTF-8 names; backup `39` and restore `18` round-tripped the exact Unicode manifest. Revisions `6f49977`, `6e0eafd`, `129e386`, and `320d5d3` repair only the downloaded working copy and keep Python validation/collision state bounded; they are deployed. Signed-in restore `20` of retained historical backup `38` completed at 1/1 and reproduced the exact 15-entry source manifest, SHA-256 `2eb24411702c799d58eeeb19f6297d55ddd0352ed3ab5ffa5c24aef4b73276d9`, with no mojibake or duplicate names. Backups `57`/`58` and restores `34`/`35` additionally preserve case-distinct, NFC/NFD-distinct, multilingual, quoted, spaced, hidden, empty-directory, zero-byte, long-component, and shell-metacharacter names over FTP and FTPS. High-cardinality and claimed-size scale pass under Slice 4. |
| 8 — 100 GB multipart upload/resume | **Pass — live upload/resume, orphan cleanup, bounded archive wait, Vultr ETag transition, and full website restore are complete** | Revision `926ae46` and backup `42` prove one 107,421,554,763-byte object, 7,881-part same-upload-ID hard-kill resume, archive SHA-256 `71ec61b44453a81201295bcb2f480c74b653f18333319821857cab74ba0775d1`, and zero unfinished multipart uploads. Restore `24` remains the pre-fix fail-closed ETag control. Exact `bf10816` passed 22/22 focused plus 1,919/1,919 full tests, was deployed after a verified database snapshot, and restore `27` completed once through the signed-in UI. The retained archive CRC passes; its 107,421,554,467-byte member and destination both hash to `9b2b8afb1f2d9eb176e291b8ecf0e045c591c229a5203d9fbcfed10347af1229`. UI, queues, active/reserved inventory, residue, provider object, and container health all pass. |
| 9 — Owned orphan multipart cleanup | **Pass — committed, service-scoped deployed, automated, and live Vultr gates complete** | Deployed revision `a351ce2` persists exact creation/abort witnesses, never replays an unknown or definitively rejected abort, retains bounded blocked-inventory observations, reuses a cleanup-purpose fenced lease without changing terminal customer state, and adds immediate plus bounded stale cleanup dispatch. Local and isolated-demo no-database suites pass 70/70; ten focused real-model task/lease/sweep/routing tests and the corrected 131-test broader storage regression set pass. Live points `47`–`50` prove exact-owned abort, completion-ambiguous no-abort, foreign/multiple no-abort, and malformed-inventory no-abort. The isolated Vultr canary prefix finishes with zero objects and zero multipart uploads. |
| 10 — Database restore performance | **Pass — declared 1M/5M performance, compatibility, bounded-memory, MySQL 10/25 GB, and PostgreSQL 10/25 GB gates are complete** | Revisions `8f2198b` and `9454507` persist bounded extended-insert/row-by-row contracts. The controlled MySQL 5M current median is 249.94 seconds versus 16,956.91 seconds for the exact historical format, a 67.84x improvement with identical ordered evidence and zero OOM events. MySQL backups/restores `95`/`86` and `97`/`88` close 10/25 GB, including a 25 GB same-row crash takeover. PostgreSQL backup `99`/restore `93` closes the 10M-row controlled-crash gate; backup `100`/restore `90` closes the 25M-row gate. Exact content, schema, markers, UI terminal state, queues, worker health, and scoped cleanup pass. |
| 11 — Database object/event fidelity | **Pass, with restore preflight hardened after a live MySQL privilege finding** | New MySQL and MariaDB full-object artifacts restored PK/FK/index/view/trigger/procedure/function/event definitions exactly without changing either server's scheduler state. PostgreSQL objects passed independently in the 1M fixture. A real restricted MySQL account fails validation safely as `DATABASE_EVENT_PRIVILEGE_REQUIRED`. Persistent TLS restore `71` exposed MySQL binary-log error 1419 after mutation when a trigger/function archive lacked `SUPER`; deployed revision `fecf40a` now recognizes escaped database wildcard grants and rejects this binlog combination before target creation unless `SUPER` or safe server settings are present. |
| 12 — Database selection validation | **Pass — HTTP no-mutation, signed-in empty-selection Save gating, existing-node valid-save semantics, rendered server-field errors with selection preservation, and explicit cross-account execution rejection pass** | Remote Django tests passed, and an authenticated invalid PATCH returned field-specific HTTP 400 without changing database source `41`. On existing all-database node `104`, removing all eight selections disabled Modify Node; reload restored all eight and source `54` was unchanged. A signed-in note-only save and revert preserved every selection/mode and returned the exact original record. On isolated exact image `3d40faf`, a primary user from account `1` received scoped HTTP 404s when reading or requesting a backup of account `2` node `1` and when requesting restore of its backup `1`; request/restore counts and the database queue remained zero and the foreign backup was unchanged. A real Chromium edit of owned source `2` then forced the otherwise-valid outgoing request to carry an empty table selection: the server returned the exact `all_tables` HTTP 400 field error, the page retained its name and enabled all-tables state, and the durable record plus backup/restore side-effect counts remained unchanged. |
| 13 — Diagnostics and transfer logs | **Pass — bounded attempt history, public-safe stage codes, operator-only correlation, retry survival, and live redaction gates are complete** | Commit `5b4775e` persists at most 20 allowlisted attempt records with timestamps, stage, code, retry decision, and correlation ID; raw exceptions go only to correlation-tagged Sentry events. Signed-in cases cover unsafe source backup `64`, collision restore `39`, archive-retry backup `65`, storage-stall/resume backup `69`, worker-loss restore `41`, and redaction-canary backup `70`. Commit `8dba19b` prevents recovered Complete rows from presenting historical errors as current while retaining their attempt history. The dead Log File action remains removed. |
| 14 — Phase labels and storage counters | **Pass — prior phase/action/refresh/timezone/counter gates plus terminal static size/file refresh are browser-proven** | Revisions `ab2efce`, `7bc0aef`, and `59d15bc` keep the parent source-ready until a fenced storage claim, resolve local active phases from durable destination rows, and update terminal row actions from the same polling state. Signed-in backups `92`/`93`, exact-image backup `3`, demo backups `94`/`63`, restore `24`, and block-backed storage `10` retain their passed gates. On one unchanged signed-in node `109` page, backup `63` advanced from Files `0` through active/source-ready/uploading states to Complete with Size `1.37 GB`, Files `103,573`, terminal actions, and refreshed node totals without a page reload. Its exact artifact/ledger/queue/worker checks also pass. |
| 15 — MySQL TLS | **Pass for the stated persistent validation/backup/restore and negative-classification gate** | Revisions `a5b3d69` and `6cbc93d` make new MySQL 8.4 connections default to TLS, select the submitted version's client bundle during first validation, map the explicit switch to `REQUIRED`/`DISABLED` without plaintext fallback, distinguish MySQL 1045 `REQUIRE SSL` from a wrong password with one bounded TLS hint probe, keep MariaDB's vendor-specific option format, and preserve TCP/auth/TLS error contracts. Persistent connection `73`/auth `52` stores `use_ssl=true`; node `102` backup `75` completed over `TLS_AES_128_GCM_SHA256`; restore `71` completed at attempt 2/1-of-1 after the exact fixture account received the separately required restore privileges. Source/fork row and normalized schema digests match exactly. Revision `fecf40a` closes the two preflight defects exposed by the first restore attempts without weakening TLS. |
| 16 — Capacity and long-task broker contract | **Pass — declared capacity contract and current exact-image release gate are complete** | Revisions `2bda859` and `f4cf2d0` provide the live-proven 25-hour broker timeout and stable RabbitMQ identity. Request `155` plus backups `92`/`93` prove durable excess-work queueing and exact-once drain. Current exact revision `8dba19b` passes 24/24 focused, 105/105 adjacent, and 1,953/1,953 repository tests; the full log hashes to `eb712e08dc991a936069b500ac772781ce9a5091729edde4afb5e7ce1c1c3863`. Image `sha256:17bc006e472c9bc399582b5e2f48b325e4495717270d16993bf2666f1dbf856c` is deployed to the app plus default/files/storage/database workers after predeploy snapshot SHA-256 `b303f5ef01a8b2e0d642d48d19a4db4e4babb95a0be342131c4d80a4903a30d4`. Django checks/migration drift pass, the app is healthy, scoped queues are empty, and six workers are online/idle. Earlier 25/50/100 GB capacity and bounded-memory gates remain passed. |

The original `ACC-RST-PG-001` failure is now remediated for current and historical
direct artifacts, current SSH artifacts, the eight-family UI matrix, and the
1/5/10/25 GB product gates described below. PostgreSQL Slice 1 is Pass.

### Original source-only verification record

- `python3 -m py_compile` passed for all 17 changed Python implementation/test/settings
  files, including the new database-selection regression module.
- `git diff --check` passed, and the designated remediation document has no trailing
  whitespace.
- A source-only arithmetic check for the reported 107,421,554,763-byte S3 object
  produced a 13,631,488-byte part size and 7,881 total parts under the new default
  geometry.
- No Django test case, template render, database query, database client, Docker
  command, remote request, deployment, or resource mutation was run. Every authored
  test and all runtime/acceptance gates remain unexecuted.
- The repository's pre-existing `.gitignore` rule `/docs/` ignores this document, so
  its local updates do not appear in normal `git status`; `.gitignore` was not changed
  by this remediation work.

The bullets above preserve the original pre-authorization checkpoint. They are
superseded for current status by the live execution record below.

### Live remediation execution record — 2026-08-18 through 2026-08-20 UTC

#### Safety, provenance, and deployment

- Demo checkout: `/opt/backupsheep`, branch `develop`, is aligned with
  `origin/develop` at `79dc391e7860a4e4e2313b915f9d0f3de49ffe3c`; only the
  pre-existing untracked `_docs/` and `docker-compose.override.yml` remain. The app
  uses exact demo image
  `sha256:0f5d79efc4e83dcce33454fd45dd10d51daaea1c38a06527fab119d1aea2870f`
  (1,257,386,607 bytes) with the same full revision label. The database worker and
  run-scoped 100 GB files/storage/default recovery workers use exact `ac13059` demo
  image `sha256:231a9c9b4c438983374bf8c10f2fae99b8874a97e8ed4e98cb7c33fbd097cf6b`
  (1,257,386,414 bytes); `79dc391` changes only the browser template and its test.
  The app is healthy, Django system and migration checks pass, and public HTTP takes
  the expected HTTPS redirect. Normal shared files/storage workers remain stopped;
  the unrelated older cloud worker continues only the cloud queue while the exact
  recovery worker exclusively consumes default. The prior `cecdac0` remediation
  workers are retained stopped as rollback witnesses. Every affected active container
  reports zero restarts/OOM. The run-scoped files/storage workers bind work storage to
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/website-100gb-restore-work/worker-shared`.
- Pre-deployment PostgreSQL custom-format snapshots are retained on block storage and
  validate with `pg_restore --list`. The latest is
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/deployments/ac13059cf00ce46b/database-predeploy.dump`,
  1,095,964 bytes, mode `0600`, SHA-256
  `3e71dabf838083ab94aa898aef6cc5dfe8a8acd8b6184c20feefb285092e3247`.
- Revisions `8d2d669`, `a1bef25`, `bab0630`, `b336c4c`, `677aef9`, `61d9fad`,
  `cecdac0`, `ac13059`, and `79dc391` were committed,
  pushed, built as exact labelled images, checked with Django system/migration gates,
  and deployed in order. `a1bef25` removes five native-restore null dereferences and
  is browser-proven for partial/complete/empty restore state. `bab0630` permits only
  Vultr multipart zero-length HEAD metadata while preserving exact GET byte/SHA
  enforcement. `b336c4c` detects authenticated `VULTR_ARCHIVE` rehydration and avoids
  futile GET calls; `677aef9` exposes the corresponding safe public API/browser
  guidance. `61d9fad` fences orderly retry reservations from the periodic recovery
  sweep, acknowledges redundant lease-busy deliveries, and gives the archive-only
  wait four days of retry budget at the current interval. The exact image passes
  167/167 focused restore/integrity tests and the complete 1,909/1,909 suite in
  440.521 seconds, with zero isolated PostgreSQL/RabbitMQ restart or OOM. `cecdac0`
  adds a post-archive, pre-staging SFTP destination-name fidelity gate and a regression
  proving it never runs while archive fetch is unavailable. Its exact isolated image
  `sha256:e1954f744d874cace0d37e93d0658ce119ef587a4799fa240e1ef15851122beb`
  (1,260,825,132 bytes) passes 20/20 focused, 170/170 adjacent, and 1,912/1,912
  complete tests in 441.297 seconds. `ac13059` routes restore-created and next-retry
  timestamps through one browser-local formatter with a legacy fallback. `79dc391`
  restarts polling when a refreshed modal finds an existing nonterminal restore. Its
  isolated exact image
  `sha256:22286f6416cf358b9da7cbcdda77c2dd6d24a0d43c20a2872192fb779daff6aa`
  (1,260,825,588 bytes) passes 122/122 affected UI/restore tests and the complete
  1,914/1,914 suite in 447.733 seconds before the exact app-only deployment above.
- Live 100 GB restore `23` is retained as the exact pre-`bab0630` failing control:
  `RESTORE_INTEGRITY_FAILED`, zero progress, zero target files, and no destination
  mutation after Vultr returned `Content-Length: 0` for the otherwise exact committed
  7,881-part object. Signed-in restore `24`, correlation
  `effe21d5-cd55-400b-a565-a9a658f3ac13`, was created with delete-extras disabled.
  It has remained one durable row while the provider reports storage class
  `VULTR_ARCHIVE` and `ongoing-request="true"`; every admitted attempt releases its
  renewable lease, leaves zero target files/archive partials, and persists the exact
  `RESTORE_ARCHIVE_NOT_READY` retry state. Before `61d9fad`, the files queue grew from
  two to twelve scheduled deliveries and the `47→49` boundary admitted two sequential
  attempts. Deployment requeued those twelve; the new worker acknowledged eleven as
  redundant and retained one orderly retry. Subsequent `49→50→51→52` boundaries each
  admitted exactly one attempt, three periodic recovery sweeps left
  `recovery_dispatch_count=11`, and the files queue remained zero ready/one scheduled.
  The `cecdac0` handoff observed attempts `80→83` only because the normal 09:43,
  09:45, and 09:47 UTC intervals crossed the deployment window; the next interval
  advanced exactly once to `84` at 09:49 UTC, retained `recovery_dispatch_count=11`,
  and left zero ready/one scheduled files delivery plus zero target probe/stage residue.
  The exact `ac13059` worker handoff similarly advanced attempt `106` once at the
  10:34 UTC boundary, requeued its one countdown delivery to the new worker, and
  retained one consumer/one scheduled delivery. Attempts through `118` continued once
  per two-minute interval; `recovery_dispatch_count` remains `11`, target residue is
  zero, and the app-only `79dc391` deployment did not touch that worker. The signed-in
  modal renders Scheduled retry/Retrying, the scheduled next-retry value, and
  “The storage provider is restoring this archive; the restore will resume
  automatically when it is ready.” After refresh on `79dc391`, the same modal rendered
  creation at Aug 20, 2026, 1:29 AM and next retry at 5:58 AM in the browser timezone;
  live polling advanced only the next-retry value to 6:00 AM without another refresh.
  Fresh post-deployment browser logs contain zero new warnings/errors.
- A separate exact-owned Vultr regression host now isolates build and automated-test
  load from the demo benchmark: instance
  `22e5c4bc-ca0a-46b5-8ea5-6eb16f617ee5`, label
  `bs-remed-20260818-0d08dcf-ci-20260820`, ownership tag
  `bs-remed-20260818-0d08dcf`, New Jersey, Ubuntu 24.04 LTS, public IPv4
  `108.61.142.2`, 2 vCPUs, 4,003,916 KiB host memory, and 100 GB NVMe. Automatic
  backups and DDoS protection are disabled; the verified rate is `$0.033/hour`
  (`$24/month` if retained). It uses the reviewed `Bilal-Macbook-Pro` SSH key and
  has no BackupSheep application endpoint exposed. Its Docker-only PostgreSQL test
  project is `bs330d`; no local MacBook Docker or large local artifact was used.
- Exact commit `d242178dbd447b4af3d9dd447123aca3f25599fc` built on that host as image
  `sha256:b0abbfba343a82780f17653da768bd58b9562ae830c32b0a8b07e1dd9384a913`
  (1,260,812,064 bytes). The retry-notification module passes 12/12 from the exact
  image. The complete current suite then passes 1,895/1,895 in 488.894 seconds
  against isolated PostgreSQL 18, with no host OOM evidence and 76,165,066,752 bytes
  free after the run. This closed the then-current exact-image automated-suite gate,
  not the live retry/partial transition or demo deployment.
- Exact commit `3d40faf9242fc9967d11d421eafa953fba70bc3b` was then exported from Git
  without a local archive and built on the isolated host as image
  `sha256:28b2aedffbfeb46e0652e92c211381fdebc2d7c5909ad984cc58dc59e598b0cd`
  (1,260,813,854 bytes). The focused broker/capacity plus retry-notification gate
  passes 23/23. The complete repository suite passes 1,896/1,896 in 478.193 seconds
  (507 seconds wall time) against isolated PostgreSQL 18, with no kernel OOM evidence;
  67,208,527,872 bytes remained free afterward. This remains the proven capacity
  ancestor's exact-image automated-suite gate.
- Exact commit `8d2d669456c857c1e80106f3fcc2463655f807ec` was exported from the clean
  Git tree and built only on the isolated host as image
  `sha256:e5a9666d2a5b98a84409eb9a281018bc196ae0e8ae0af3c82e160ffc0672aad4`
  (1,260,814,347 bytes). The focused local-backup finalization and public-state gate
  passes 57/57. Its exact live two-destination backup `3` also passes the scheduled
  retry, terminal partial, safe error, terminal-action, exact-byte, one-successful-
  upload, and zero-final-storage-queue gates described in Slice 14. The complete
  exact-image suite passes 1,896/1,896 in 437.445 seconds (465.73 seconds wall;
  28,672 KiB supervising-client maximum RSS) against isolated PostgreSQL 18. The
  host recorded no kernel OOM evidence and retained 63,573,880,832 bytes free. This
  revision was subsequently deployed after the controlled 5M historical-format
  comparison passed; its live demo outcome is recorded above and in Slice 14.
- The isolated full stack exposed only loopback port `127.0.0.1:18000`; PostgreSQL,
  RabbitMQ, and every worker remained private. All five workers answered ping with the
  shipped concurrency/prefetch values: cloud `4/1`, database `1/1`, files `1/1`,
  storage `2/1`, and logs `2/1`. Idle stack memory proved that 4 GB is a deliberately
  tight starter profile, so the declared minimum also requires 8 GB of SSD-backed swap
  and SSD/NVMe work storage.
- Capacity phase A ran a real 1,000,000-row PostgreSQL export, a 100,000-file
  collect/archive, and two simultaneous 1,073,741,824-byte storage copies. The database
  export took 3.054 seconds, website lane 35.203 seconds, and storage lanes 5.564/5.559
  seconds. The 298,779,556-byte dump, 101,001-entry/26,697,102-byte ZIP, and both storage
  copies verified; the copies share exact SHA-256
  `49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14`.
  All 106 health and 106 signed-in console probes returned HTTP 200. Health p95 was
  0.0081 seconds and console p95 was 0.7106 seconds. The host read 1,758,711,808 bytes,
  wrote 3,722,088,448 bytes, reached an eight-process run queue and 1,763,020 KiB swap,
  and recorded no OOM or worker restart.
- After an exact service restart reset the probe processes and swap baseline, capacity
  phase B restored phase A's dump while repeating the same website and two-storage
  lanes. Restore took 13.571 seconds, website 46.914 seconds, and storage 9.998/10.000
  seconds. The target has exactly 1,000,000 distinct IDs, min/max 1/1,000,000,
  256,000,000 payload bytes, and source-equal primary/expression indexes. Both storage
  hashes and the 101,001-entry website ZIP verify. All 258 health and 258 signed-in
  console probes returned HTTP 200; p95 values were 0.0112 and 0.2671 seconds. The host
  read 2,927,828,992 bytes, wrote 5,052,964,864 bytes, reached a nine-process run queue
  and 969,364 KiB sampled swap, and recorded no OOM/restart. Every queue finished empty.
- No website/database backup or restore row was active before the `f4adce3`
  affected-service replacement. The sole cloud-queue work was one unacknowledged,
  scheduled Oracle deletion reconciliation; its exact task identity and broker
  redelivery survival are recorded below.
- No website/database restore row or database-worker task was active before the
  `6555d57` replacement, and no website/database restore row was active before the
  app-only `cb7fbc8` replacement.
- Before the app-only `f9669c5` replacement, every website/database backup and restore
  row was terminal. A scheduled `resume_in_progress_backups` maintenance task was
  allowed to finish; all five workers then reported empty active and reserved
  inventories before the app container was replaced.
- Before the `0220727` app/database-worker replacement, every website/database backup
  and restore row was terminal, the database worker reported empty active/reserved
  inventories, and the `database` queue reported zero ready/unacknowledged messages.
  The unrelated scheduled cloud reconciliation remained isolated on the cloud queue.
- Recoverable root-owned mode-0600 PostgreSQL snapshots were taken before each live
  deployment boundary:
  - `/var/backups/backupsheep/predeploy-0d08dcf-20260818T121015Z.sql.gz`,
    SHA-256 `a4ba7e918cc85152f9c1a7d2c0303b316b747e8522f7aea4dedaaf50f24aa3e8`;
  - `/var/backups/backupsheep/predeploy-214dba7-20260818T125100Z.sql.gz`,
    SHA-256 `9ddd620c1c2a312b07f0964586ac2f2dfc387f3cc03edced53956c727b391dad`;
  - `/var/backups/backupsheep/predeploy-cf9e97b-20260818T130456Z.sql.gz`,
    SHA-256 `3717bfb03cf9ab321b83b69fdd923a21c403e7dd98b7e5a35fed2008ae8f35ac`;
  - `/var/backups/backupsheep/predeploy-49d36b8-20260818T172931Z.sql.gz`,
    347,368 bytes, SHA-256
    `abab0e8d22ab82fcb9bd80d248a619710a608f542e42aef43497cc5394fa7428`;
  - `/var/backups/backupsheep/predeploy-4ef78f0-20260818T181216Z.sql.gz`,
    351,468 bytes, SHA-256
    `d744cee643901cd328e84dd4683b904316c3328dceda3b3a7cfcf88a33108942`;
  - `/var/backups/backupsheep/predeploy-71c8aed-20260818T193820Z.sql.gz`,
    371,893 bytes, SHA-256
    `a9a86733ac05e7bc8b614da6df095064b303c52a7189e80c46a56cca1832cd67`;
  - `/var/backups/backupsheep/predeploy-698f655-20260818T201022Z.sql.gz`,
    376,294 bytes, SHA-256
    `8a111b9c70a3b9d7ec3f31de1daab6b81c004c1fad03c16b212da6331dd8c91f`;
  - `/var/backups/backupsheep/predeploy-1139b51-20260818T202032Z.sql.gz`,
    376,741 bytes, SHA-256
    `9cdd1f7251472a4bd8057d67741ae3edb8815e94f30ef7907eb4600d2842f3bc`;
  - `/var/backups/backupsheep/predeploy-bc35401-20260818T202844Z.sql.gz`,
    376,867 bytes, SHA-256
    `0c85a6eb0503adef4a9c0c897e7322f281dea40f4ce3948b77fee4fd02760f76`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-f4adce3-20260818T2138Z.dump`, 964,598-byte custom-format snapshot,
    SHA-256
    `8f06a74a7a25431c8c8e405db6fd36dead3a35dec5f2802c2662c3e10b87e493`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-6555d57-20260818T2242Z.dump`, 967,266-byte custom-format snapshot,
    SHA-256
    `3e11946f177de065c73c315a960551c31e677d41e9fa422fbefec9c6ab60b7ae`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-cb7fbc8-20260818T2312Z.dump`, 970,757-byte custom-format snapshot,
    SHA-256
    `eb2a7455c8552ed831fe62d8933d4352ad0974f4502e9063d50e9e958ee30ef5`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-f9669c5-20260819T000216Z.dump`, 978,138-byte custom-format snapshot,
    SHA-256
    `4b9720308c18d47d0a898aba6e420d582238511f49421016258f9d37def14666`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-0220727-20260819T025907Z.dump`, 993,103-byte custom-format snapshot,
    SHA-256
    `864a0491f4cf5a0b43c71120a984ba35f53ad9ac3c43bcff14eecdc8db558f88`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-8f2198b-20260819T074012Z.dump`, 995,879-byte custom-format snapshot,
    SHA-256
    `1fb4a7c04c1591c6ca719483d59e44701fc560c35ee3419e3e4211375319d3c6`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-5f3678b-20260819T083452Z.dump`, 1,001,432-byte custom-format
    snapshot, SHA-256
    `f0c6db948fb85729e9ee058e604f4b9ea42c8068cb39774ca93c01218ddf423a`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-fecf40a-20260819T091327Z.dump`, 1,011,236-byte custom-format
    snapshot, SHA-256
    `8213b40e0fc7b861f9632d0c6fd5d0413b7bb07fa94885bd23c3936ab497031a`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-d547501-20260819T101147Z.dump`, mode `0600`, 5,087,284 bytes,
    SHA-256
    `e382a8f95849b7f1383c12c33e02a27f5be832e1800646f5007b869e14e56eb2`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-e360056-20260819T123137Z.dump`, mode `0600`, 5,229,171 bytes,
    SHA-256
    `0d5b85a58ba459e4f939272745fe1a844acfb21396d357aa05e4a27cab476f31`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-ca06dfa-20260819T124752Z.dump`, mode `0600`, 5,250,415 bytes,
    SHA-256
    `fb0c3d32014bc8a9b2d94c859b3538331335e501730d7a5daf36257278c3ec83`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-80827f5-20260819T131601Z.dump`, mode `0600`, 1,035,481 bytes,
    SHA-256
    `8b21bf32b0b3f2a538c3a03f319fd6e84f754a5a6e0a61b7df9588090014acb9`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-e122271-20260819T132356Z.dump`, mode `0600`, 1,036,777 bytes,
    SHA-256
    `c3db3f8e22be0c0f689188de523a1acb319bfd29f03f9d51ee1ff4c3cde5aefb`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-ee8ec34-20260819T133525Z.dump`, mode `0600`, 1,039,046 bytes,
    SHA-256
    `b882cded058c406b84ed5f79fe59f5b4605f985f71ea4bc8021950bfd46be004`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-b4cb5c5-20260819T183849Z.dump`, mode `0600`, 1,058,846 bytes,
    SHA-256
    `f9164c293f126852f0b28c9544a23ffc99431c64180b678b47da7bb43fecd1c3`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `demo-pre-9454507-20260819T2344Z.dump`, mode `0600`, 1,073,891 bytes,
    SHA-256
    `6bfd501bd41a6ce6b5c11e7c8c0f26c8f646764a462b708c5592ac3ae6dfe053`;
  - `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
    `deploy-6829331/demo-pre-6829331-20260820T0112Z.dump`, mode `0600`,
    1,078,723 bytes, SHA-256
    `f29caf54fb8710427bf9a26e3f1485a5739d1ef3e68160dfdc6cb8fb34e73a1a`.
- Scoped commits pushed to `origin/develop`:
  - `0d08dcfd138412ae4593fe0198c977f642a574b8` — original database, S3,
    selection, diagnostics, phase, and counter slices;
  - `214dba7576db316e281849fe9a0b64eb29c30b43` — bounded MariaDB/MySQL
    vendor transaction-wrapper validation;
  - `cf9e97b1cb54c21a669fe130cf1050501db2b188` — UTF-8 website ZIP-name
    flag correction;
  - `49d36b85b22da4798190b2480f1252383ef328f1` — bounded compatibility for
    historical PostgreSQL `--clean` dumps;
  - `4ef78f0a7d5976d2f6d1c4188b6b50e93f35309d` — engine-specific query/dump
    client capability validation for MySQL and MariaDB;
  - `71c8aedc5d0225f436edb747bb51fc3fbeb1227c` — MySQL/MariaDB scheduled-event
    export and safe event-privilege backup classification;
  - `698f655c1f5f3d1879faf570b6f30b32c77485c9` — proactive direct/SSH/all-database
    event-read privilege validation;
  - `1139b5135b300f92f36992afd03f563eaed11cfa` — preserve typed database
    validation failures at the database API boundary;
  - `bc3540159fe024f32145d5b5971fb8ac69cf96a2` — stop safe public connection-error
    extraction before it descends into a raw wrapped client error;
  - `f4adce30246898de036df33ea110f0e21cf6833f` — bind a recovery dispatch
    reservation to its exact deterministic task and consume that reservation
    atomically when the recovery lease is claimed;
  - `6555d57d48eba994b096ab2494ff9597d6128862` — classify an existing
    markerless MySQL/MariaDB fork as a name collision after a read-only marker-table
    metadata check, while preserving genuine client/query failures;
  - `cb7fbc8da83913714356485e97d0632f747b6063` — render phase/progress,
    allowlisted error guidance, and expandable correlation/error-code diagnostics on
    historical restore rows;
  - `f9669c5d9eb8b1d2f28ee820a6d264e4153383a9` — map durable database/website
    component checkpoints to active validating/restoring phases so a component-level
    `complete` token cannot terminate client polling before the parent restore is
    terminal;
  - `0220727a5a517434c85830254e0e35b48b50afab` — detect explicit MySQL/MariaDB
    `DEFINER` clauses during archive validation and require the correct global,
    vendor/version-specific definer capability before the first target mutation;
  - `2bda859aa920916825252151a9be24bde46e77a4` through
    `e4205be` — 25-hour RabbitMQ acknowledgement timeout, bounded historical UTF-8
    repair, MySQL TLS validation, source/archive policy, streaming ZIP validation and
    collision state, the 2.1M restore ceiling, and one verified writer enumeration;
  - `926ae46` — bounded multipart state/bodies, exact final inventory, progress
    checkpoints, no-progress recovery, and per-mutation upload fencing;
  - `8f2198bcf5d1646ab7fefa56326cabf48a1f539a` — extended inserts plus an exact
    persisted dump contract for new normal MySQL/MariaDB artifacts;
  - `f4cf2d06c1fc1ef8a01e7fe13a295b3371c9268a` — stable RabbitMQ node hostname so
    the persistent volume reopens the same durable broker state after recreation;
  - `5f3678b379da94a6e00357a1295ee3fd8b4c0fcf` — retry a deep website mirror
    serially after the known `lftp` parallel-mirror path assertion, while retaining
    the original failure in the run log;
  - `fecf40a5765218dfd21597ff4bf8099ba4b3c147` — recognize MySQL's displayed
    escaping for literal wildcard-scope underscores and preflight trigger/function
    binary-log requirements before any restore-target mutation;
  - `d547501a181de36905dffeb5b36ab13937737281` — persist a non-secret exact
    prior-fence work suffix during stale restore takeover and clean only the prior and
    current local restore generations, including their local credential files;
  - `e36005611a0d44fa04a005652a3722c3d8cb1a06` — validate MySQL
    all-database connections with the selected client and full-object privilege
    policy while excluding system schemas;
  - `389101595aefb0135550eb8b16724bf1f7b0d99e` — back up direct
    multi-database selections as one authenticated SQL member per selected database;
  - `ca06dfad3b8432d7a00afaad89bb83fe52edb432` — make redelivery of an
    already-terminal backup a durable no-op instead of re-exporting its source;
  - `80827f5bd935248bc0dec1d6b9f2ab31fe9b8128` — record authenticated
    MySQL/MariaDB database character-set and collation defaults in dump contract v2
    and bind a database-default preamble to every selected SQL member;
  - `e122271b2f9f08f674764ca3f0da13dc9d138d7c` — flush each schema-default
    preamble before the dump subprocess writes, preserving its required first-line
    ordering on the real file descriptor;
  - `ee8ec3487f129b474b3cec72da467a5370162e2a` — permit only the exact
    first-line schema-default preamble authenticated by contract-v2 metadata during
    MySQL/MariaDB restore; historical, moved, mismatched, and injected
    `ALTER DATABASE` statements remain rejected;
  - `b4cb5c505c424fc03170961d45c304285d401c8e` through
    `e9c842f65b9a64053953b7e59271338a913a2866` — bounded high-cardinality website
    writing/checkpoint reuse, bounded CRC verification and files-worker capacity,
    disk-spooled restore identity, and long-restore lease-safe completion;
  - `a351ce2df3598276d8ca52faeb67ab1389b173fb` — exact-owned multipart cleanup
    witnesses, fenced cleanup dispatch, and fail-closed provider inventory handling;
  - `9454507f82156273868a9d185e69603381be4380` — preserve intentional MySQL/MariaDB
    row-by-row output while restoring `--quick` streaming after `--skip-opt`;
  - `ab2efce31bccf439407cd16033f43a99337c551b` — retain the verified source-ready
    parent state until a fenced storage worker actually claims a destination;
  - `7bc0aef1b07c821e7960c603c9eaddc22534ba5c` — derive queued, retrying,
    uploading, and validating public phases from durable local storage-point rows
    with one bulk query rather than stale source-worker phase text;
  - `6829331ab02508c5bf94d05b6059acc033f47eaf` — correct the focused phase
    regression harness without changing runtime behavior;
  - `59d15bc9b454395b05bc44dad67635e2c7988f06` — bind the complete/cancel row
    actions to the same polled execution component as the phase label;
  - `cbb467091816dce7e031c79fb2bed69dcfa14d9a` — update the native-restore UI
    contract test for the polled terminal-action guard;
  - `330d4423f3e41e005c0a2765d29683d0da877eea` — keep retryable storage failures
    schedulable when the failure-notification path receives the classified error;
  - `d242178dbd447b4af3d9dd447123aca3f25599fc` — isolate the legacy safe-message
    regression from email/broker delivery so the test proves only that a string is
    never passed to Sentry;
  - `3d40faf9242fc9967d11d421eafa953fba70bc3b` — publish the measured minimum-host
    worker/prefetch/latency contract and regression-lock its queue limits to the
    shipped Compose and sample-environment defaults;
  - `8d2d669456c857c1e80106f3fcc2463655f807ec` — replace stale transient retry
    guidance with terminal `STORAGE_RETRIES_EXHAUSTED` when a local destination's
    retry budget is exhausted, while retaining a safe browser-visible next action.
- The former service-scoped deployment left `app` and `worker-database` on revision
  `0220727` in exact image
  `sha256:e273143d64837974b728428637846700282bab3c0a5e7d9f4efc183b3e804551`.
  `worker-cloud` remains on the already deployed `f4adce3` image; files, storage, log,
  and Beat services were left untouched. Both replaced containers resolve to the exact
  candidate image and the checkout remains clean except for `_docs/` and
  `docker-compose.override.yml`.
  The preceding `f4adce3` deployment advanced `app`, `worker-database`, and
  `worker-cloud` together to image
  `sha256:c84dd1e0d4d730e2a6260f8f6b7eea2a759e1d90d59f06e945f633ccb93eefb0`.
  The cloud worker was required because it executes `resume_in_progress_restores`;
  files, storage, and log workers were not replaced. The pre-existing unacknowledged
  Oracle reconciliation delivery `140daf8e-d7d8-4c6f-8ca8-a2b9eb9b7187` survived
  the graceful cloud-worker replacement with the same task ID and was observed as a
  broker-redelivered scheduled task on the new worker.
- The full-service baseline deployment ran revision `f4cf2d0` and exact image
  `sha256:37a0066e3a8b2ba177e9a93777be49098fb96a395ee51fd78d8adb09b63ec746`
  on the app, all five workers, and Beat. The app and RabbitMQ are healthy, all five
  workers answer ping, local/public `/healthz/` return `ok`, Django checks pass, and
  migrations report no work. The combined changed-area image gate passes 429/429;
  seven focused broker tests separately pass the stable-hostname/timeout contract.
- Revision `5f3678b` was subsequently deployed to the full application service set;
  its focused deep-mirror module passed 23/23 and the complete website archive/
  restore group passed 214/214 before the signed-in 300-level SFTP gate succeeded.
- The preceding targeted deployment ran revision `fecf40a` and exact image
  `sha256:89dcd7e9777b384d7197b0a5ff6a768954621d655e31d6601548793ed51fa03d`
  on `app` and `worker-database`. The database restore change does not execute in
  Beat or the cloud/files/logs/storage workers, so those containers were deliberately
  not recreated while an unrelated cloud delivery remained unacknowledged. Their
  pre-deployment IDs stayed unchanged; only app `394823ad...` became `40479ee2...`
  and database worker `995b85dd...` became `704be1f2...`. The app is healthy, the
  new database worker and all four untouched workers answer Celery ping, Django and
  migration checks pass, local HTTP redirects as configured, public HTTPS responds,
  and the database queue is `0/0` with one consumer. The override SHA-256 remained
  unchanged. A deployed live preflight through persistent auth `52` returned
  `create=true`, `drop=true` for the standard escaped run wildcard and left probe
  schema `bs_restore_probe_0d08dcf` absent (`count=0`).
- The cleanup-focused targeted deployment ran revision
  `d547501a181de36905dffeb5b36ab13937737281` and exact labeled image
  `sha256:32212732850792afe80a5fd11a81b0ffac18f66e47b7dacdbff87e681238b2f3`
  on `app`, `worker-database`, `worker-files`, and `worker-storage`, the four services
  that execute or expose local database/website restore cleanup. App
  `40479ee2...` became `d579cbab...`, database worker `704be1f2...` became
  `a73d56cb...`, files worker `b40b0d58...` became `551a9fe9...`, and storage worker
  `8de51a33...` became `e0ff0c81...`. Beat `50a63c29...`, cloud worker
  `149ace15...`, log worker `b1cefa1e...`, PostgreSQL `e09222c5...`, and RabbitMQ
  `9924bfe5...` were not recreated; the unrelated cloud delivery remained isolated.
  The app is healthy, all five workers answer ping, Django check and migration check
  pass, local `/` redirects `301` to HTTPS, public HTTPS redirects `302` to login,
  and the database/files/storage queues are each `0/0` with one consumer after the
  live gate. The checkout has no tracked changes and preserves `_docs/` plus the
  unchanged Compose override.
- The preceding MySQL targeted deployment ran revision
  `9454507f82156273868a9d185e69603381be4380` and exact labeled image
  `sha256:977e6aabe07567b648a708a1372c6f5f59031bb178051ad3633f5ea6b8d4afb7`
  on `app` and `worker-database`. The pre-deployment inventory proved no active or
  reserved database task and a drained database queue. Only those two affected
  services were recreated; files remains on `e9c842f`, storage and Beat on
  `a351ce2`, and unrelated cloud/log workers were not touched. The app is healthy,
  public `/healthz/` returns `ok`, all five workers answer ping, the database worker
  now runs the declared concurrency/prefetch `1`/`1`, Django checks pass, migration
  drift is empty, and checkout/`origin/develop`/image labels identify the same full
  revision. The exact built image repeated the 123/123 database-engine regression
  gate before deployment. No local Docker workload was used.
- The subsequent phase/action deployment advances the demo checkout to
  `cbb467091816dce7e031c79fb2bed69dcfa14d9a`. The source/storage handoff services
  (`worker-database`, `worker-files`, and `worker-storage`) run exact image
  `sha256:29c1ad2f47fcd7349905b2692e0a6e95f5a37f1e64a4b2f5f0259eab1d1ed17c`
  built from `6829331`; the app runs exact image
  `sha256:889259a271d1a70ff27749712f4bf4caa09ff37728b312afef7cdf2158f3f3ee`
  built from `cbb4670`. The later two commits change only the template and tests, so
  no worker was needlessly recreated for that app-only boundary. Preflight reported
  zero active website/database backups or restores and drained database/files/storage
  queues. Focused phase tests passed 5/5, adjacent recovery/finalization tests 67/67,
  the exact `6829331` image repeated 67/67, the row-action/restore UI set passed
  55/55, and the exact final image passed 110/110. Django checks and migration drift
  are clean, the app is healthy, all five workers answer ping, and the affected
  queues drained after each live gate. No local Docker workload was used.
- Public and local health endpoints returned `ok`; the app, PostgreSQL, and RabbitMQ
  containers were healthy, all five workers answered Celery ping, and zero tasks were
  active immediately after deployment verification. `manage.py check`, migration
  drift, and migration-plan checks passed.
- The same health check was repeated after restore `62` completed: local and public
  `/healthz/` returned `ok`, all five workers answered ping, and every worker reported
  empty active and reserved task inventories.
- The same checks were repeated after deployed eight-family restore `64`: local and
  public `/healthz/` returned `ok`; the app, PostgreSQL, and RabbitMQ were healthy;
  all five workers answered ping; and every active/reserved inventory was empty.
- After `0220727`, the app container was healthy, public routing responded, the new
  database worker answered Celery ping, and the database queue was `0/0`. After
  restore `67` completed, all website/database rows were terminal and the database
  queue/worker were empty again.

#### Explicit stop checkpoint — 2026-08-20 UTC

- The user stopped active remediation after the case-folding fixture was prepared.
  From that instruction onward, no application code, host-key record, product backup
  or restore, provider object, Docker workload, or cleanup action was created,
  changed, approved, or deployed. This documentation update is the only continuation.
- Local `develop`, `origin/develop`, and the demo checkout are aligned at
  `79dc391e7860a4e4e2313b915f9d0f3de49ffe3c`. The final two pushed commits are
  `ac13059cf00ce46b0fea106c02f6e4e0965d1c33`, which puts restore creation and retry
  timestamps through one browser-local timezone formatter, and
  `79dc391e7860a4e4e2313b915f9d0f3de49ffe3c`, which resumes five-second polling when
  a refreshed modal opens an already-active restore. The exact `ac13059` CI image
  passed 121/121 affected and 1,913/1,913 complete tests in 431.625 seconds; the exact
  `79dc391` CI image passed 122/122 affected and 1,914/1,914 complete tests in
  447.733 seconds. The demo
  app runs exact `79dc391`; database plus run-scoped files/storage/default workers
  remain on functionally compatible exact `ac13059` because the later commit changes
  only the template and its regression test. The local worktree still contains only
  the unrelated tracked modifications in `.gitignore`, `README.md`, `SECURITY.md`,
  and `docs/backup-reliability-resume-handoff-20260810.md`; this sole plan remains
  ignored by the repository's existing `/docs/` rule.
- During the `ac13059` handoff, the first replacement default recovery container was
  launched with an incorrectly ordered command and exited with code `2` before it
  consumed any task. It was removed and recreated with the correct Celery entrypoint.
  The active exact workers at the stop boundary are
  `backupsheep-worker-database-1`, `bs-remed-100gb-worker-files-ac13059`,
  `bs-remed-100gb-worker-storage-ac13059`, and
  `bs-remed-worker-default-ac13059`; prior `cecdac0` remediation workers remain
  stopped as rollback witnesses. Restore `24` crossed attempt `106` exactly once
  during that handoff, and its single scheduled files delivery transferred to the
  replacement worker without amplification.
- The latest recorded pre-stop 100 GB witness is `2026-08-20T10:59:37Z`: restore
  `24` was one durable row at attempt `118`, phase `retrying`, status `2`, next retry
  `2026-08-20 11:00:54.446479+00:00`, `recovery_dispatch_count=11`, and no lease.
  Files had zero ready/one scheduled delivery with one consumer; storage, default,
  and database each had zero ready/zero scheduled with one consumer. Destination
  residue was zero. The exact provider object still reported `ContentLength=0`, the
  expected ETag and metadata SHA-256, storage class `VULTR_ARCHIVE`,
  `ongoing-request="true"`, and zero unfinished exact multipart uploads. Automatic
  retries may advance the attempt counter after this timestamp; the terminal
  107,421,554,467-byte member hash/CRC/residue proof remains open and must not be
  inferred from the retained wait state.
- The next Slice 4 fixture is retained, not accepted. Its exact filesystem, container,
  product identifiers, blocked validation state, and no-mutation resume procedure are
  recorded in Slice 4 and the retained-resource inventory below. No cleanup was
  performed when work stopped.

#### Resume checkpoint — 2026-08-22 UTC

- Fresh read-only state found restore `24` terminal at attempt `165`, status `Failed`,
  phase `failed`, `RESTORE_INTEGRITY_FAILED`, no lease/retry, and unchanged
  `recovery_dispatch_count=11`. The files/storage/default/database queues were empty;
  the exact SFTP target contained zero files/directories, and correlation-scoped
  probe/stage/partial residue was zero. The signed-in modal shows two historical
  terminal failures, including the Aug. 20, 2026, 1:29 AM row, with only the safe
  “The restore failed an integrity check” message and Technical details affordance.
- Vultr now reports the exact object readable: `ContentLength=107421554763`, storage
  class `VULTR_ARCHIVE`, `ongoing-request="false"`, rehydration expiry Thu,
  27 Aug 2026 12:33:52 GMT, matching BackupSheep SHA/byte metadata, and zero exact
  unfinished multipart uploads. A one-byte remote-only range GET returned ZIP byte
  `0x50`, content range `0-0/107421554763`, and the same current ETag as HEAD. The
  only observed provider-identity difference is the transport ETag, from committed
  `"f85bcf1d85f95ec5b2047c0b45e530fa-7881"` to
  `"c10e7b037337edd450ec3c1a8c2c53cf-1025"`; the unversioned durable artifact ledger,
  exact key, expected bytes, and SHA metadata remain unchanged; the post-rehydration
  full content stream is not yet verified.
- Commit `bf108161dd9cc35234c25dd6595ddd21bfd9fa26` (`Handle Vultr archive ETag
  transitions`) was created and pushed
  on `develop`. It leaves the committed ETag immutable, permits a changed ETag only
  for an explicitly transitioning multipart Vultr archive, pins the first live ETag
  across GET and final HEAD, and retains full streamed byte-count/SHA verification
  before publication. The failing regression reproduced `PROVIDER_VERSION_DRIFT`
  before the change; afterward 22/22 S3-compatible integrity tests and 112/112 broader
  no-database restore/storage tests pass without local Docker or large local data.
- Exact-image/database/full-suite verification and deployment are intentionally
  pending. The demo host was not used for build/test load while an unrelated CloudMoo
  worker consumed about 5.1 GiB of its 7.24 GiB memory, swap was effectively 100%
  occupied, and load ranged above 10. The retained isolated CI host is available, but
  private source transfer/pull is paused until the user explicitly confirms that exact
  destination is trusted for this repository. No demo checkout, image, service, row,
  provider object, or test fixture changed during these blocked release checks.
- The case-folding fixture remains exactly at its prior checkpoint: connection/auth/
  node/website `81`/`12`/`110`/`27`, zero approved host keys, zero backups, and zero
  restores. Its independently read ED25519 fingerprint is
  `SHA256:QahlGELbQL9L26z5WO4KfkMfR3RP6NCqYeGJ/Hu/+J8`; approval and product execution
  have not started.

#### Continuation execution — 2026-08-22 UTC

- The unrelated CloudMoo application stack was the confirmed source of demo memory,
  swap, and load pressure. Its exact web/worker/beat/database/RabbitMQ containers were
  stopped, not deleted; its database and broker volumes were preserved. Demo memory
  available rose to more than 6 GiB initially and load converged. No BackupSheep test
  row, provider object, or source fixture was changed by that cleanup.
- Exact commit `bf108161dd9cc35234c25dd6595ddd21bfd9fa26` built on the demo as image
  `sha256:dfa4f69800dc2dfa069149e6f058a7028970b0996d66e25157dd1e45964c3a80`
  (1,257,387,296 bytes) with the matching full OCI revision. The image contains no
  `.env`, `.git`, or `_docs`. Twenty-two focused S3/Vultr integrity tests pass, and
  the complete exact-image suite passes 1,919/1,919 in 370.610 seconds against
  disposable PostgreSQL/RabbitMQ with no OOM. Django system/migration checks pass.
- The predeployment custom PostgreSQL dump is retained at
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/deployments/`
  `bf108161dd9cc35234c25dd6595ddd21bfd9fa26/`
  `database-predeploy-20260822T161207Z.dump`, 1,109,344 bytes, mode `0600`, SHA-256
  `e8e18bb8013d742bc97233b815277b8375eb4f97aa0f11ed5670e042b9c744fe`;
  `pg_restore --list` passes. With every website/database row terminal, all affected
  queues drained, and no leases/pending requests, the exact app, database, files, and
  default services were deployed. Public/internal health, checks, six-worker ping,
  restart/OOM, and queue gates pass. The compatible run-scoped storage worker remains
  on exact `ac13059`.
- Signed-in restore `26`, correlation
  `32649cf5-403f-4dac-a446-44c3a3bb9253`, proved that `bf10816` accepted the changed
  1,025-part live Vultr ETag, streamed the complete 107,421,554,763-byte archive, and
  reached extraction. It then failed safely before target writes because node `101`
  had later been changed from the backup's root/all-paths layout to an explicit deep
  path. Backup `42` durably stores `all_paths=true`, while the restore engine read the
  mutable current website selection. The target remained empty. This is a distinct
  historical path-snapshot defect, not an ETag regression.
- The disposable SFTP account home was moved to the exact block-backed target and the
  node was changed through the signed-in Modify flow to directory `.`; UI validation
  passed. Before the retry, a retained hard link to restore `26`'s downloaded archive
  was independently verified entirely on demo block storage: exact size
  107,421,554,763, archive SHA-256
  `71ec61b44453a81201295bcb2f480c74b653f18333319821857cab74ba0775d1`,
  CRC exit `0`, and exact 107,421,554,467-byte member SHA-256
  `9b2b8afb1f2d9eb176e291b8ecf0e045c591c229a5203d9fbcfed10347af1229`.
- Through the signed-in node `101` UI, restore `27`, correlation
  `380477ec-05d4-410b-8e58-a151fb1954b4`, was created from backup `42`/point `44`
  with `delete=false`. It remained one durable row and attempt, rendered Validating
  while fetching/extracting/indexing, changed to Restoring at 0/1 only after the
  durable `archive_validated` checkpoint, and rendered Complete at 1/1 only after the
  final checkpoint. The target contains one file and one root directory only. The
  file is exactly 107,421,554,467 bytes and its independently read destination SHA-256
  is the same `9b2b8afb…47af1229` value above.
- Restore `27` left no correlation-scoped worker work, provider partial, target probe,
  hidden stage, or retry. Files/storage/default/database queues are `0/0`; all six
  workers answer ping with empty active/reserved inventories. The app, files,
  storage, default, database, and SFTP containers remain running with zero restart/OOM.
  Fresh Vultr HEAD reports 107,421,554,763 bytes, live ETag
  `"c10e7b037337edd450ec3c1a8c2c53cf-1025"`, `VULTR_ARCHIVE`,
  `ongoing-request="false"`, exact BackupSheep byte/SHA/backup metadata, and zero
  unfinished exact-key multipart uploads. This closes the full 100 GB website restore
  gate and Slice 8.
- A focused local-only regression now freezes website `all_paths`/`paths`/`excludes`
  on a newly created backup row and makes restore prefer an available backup snapshot
  over later mutable node-path settings, while retaining the legacy fallback for old
  rows with no snapshot. Two tests reproduce restore `26`'s root-to-explicit mismatch
  and prove same-task retries do not overwrite the frozen selection. Python
  compilation and whitespace checks pass. These changes are intentionally uncommitted,
  untested in Django, and undeployed while the completed live gate is being recorded.
- Work then resumed under renewed authorization. The independently read ED25519
  fingerprint for `bs-remed-casefold-sftp-20260820:22`,
  `SHA256:QahlGELbQL9L26z5WO4KfkMfR3RP6NCqYeGJ/Hu/+J8`, exactly matched the signed-in
  preview, including key type `ssh-ed25519`. The host key was explicitly approved in
  the UI and connection `81` subsequently rendered “Validation passed. Integration is
  good for backups.” No key was accepted implicitly.
- The first tiny signed-in request created backup `51`, task
  `32a5f963d72959afb5711885f5424c55`, and exposed a demo-worker topology defect rather
  than a product retry defect: the temporary block-backed files worker used a private
  `/code/_storage` bind while the app persisted the approved key in the normal
  `backup_workdir` volume. It therefore could not read the UI-approved trust record.
  Backup `51` was cancelled through the signed-in UI. The disposable worker was
  replaced with one that, at that historical revision, kept its block-backed work path
  but mounted the then-current legacy trust volume read-only at `/ssh-trust`; app and
  worker then shared exact known-hosts
  SHA-256 `6df2e0c6c2ca1e1a4b2082940b1400fa7717ac829b3c9168e04d14614d6d26eb`.
- A second signed-in request created backup `52`/point `54`, UUID
  `bs-bs-remed-20260818-0d08dc-n110-b52`. It completed once at 1,197/1,197 bytes with
  three files. The committed local ZIP is 1,197 bytes, CRC-clean, and has SHA-256
  `c06d07006bb28c4320e1b845f2940d581f6b2f11597f6c35f3aedbf77f32d83b`; source and
  destination artifact ledgers agree. Its exact member hashes are
  `f17cf8db09aa7c93a12e038636eb1649be2ee3885ee84e1b8dafea0e6762e2c7` for
  `foreign-sentinel.txt`,
  `1be8165d849e8d54a1a4d12a3b0691107a14c7b26c592ea3996f51dd6ed82667` for
  `index.html`, and
  `49a790e35ac6610984bf247ac581ddde3e36942cbecddd293224b8aae0f611e7` for
  `nested/keep.txt`.
- Signed-in restore `28`, correlation `e4fa69ed-20e7-438c-b12b-6a904dc0faa9`, reached
  the intended destination-fidelity boundary in one attempt with `delete=false`. Its
  secured log said `RESTORE_TARGET_NAME_COLLISION; no target data was published`, but
  the generic task/API mapper rendered `RESTORE_SOURCE_UNAVAILABLE`. The fail-closed
  engine behavior and unchanged target passed; the public classification did not.
- Commit `7657d2777cded5bb276fb37971beab38fcce223e` (`Freeze website backup paths and
  preserve collision errors`) freezes `all_paths`, `paths`, and `excludes` only when a
  new website backup row is created; backup transport, incremental cache identity,
  and restore source layout use that frozen path selection. Historical rows whose two
  path snapshot fields are both null retain their previous fallback to the current
  node. The same commit explicitly maps and allowlists
  `RESTORE_TARGET_NAME_COLLISION` with path-free actionable guidance. Six new focused
  regressions pass, the affected batch passes 324/324, Django checks report no issues
  or migrations, and the exact revision passes repository-wide discovery
  1,925/1,925 in 419.018 seconds with exit `0`, zero OOM, and zero restart. The earlier
  1,915-test result was the narrower `apps.tests` label and is not used as the complete
  release count.
- Before deployment, a verified custom-format PostgreSQL snapshot was written at mode
  `0600` to
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/deployments/`
  `7657d2777cded5bb276fb37971beab38fcce223e/predeploy-backupsheep.dump`. It is
  1,118,934 bytes, has SHA-256
  `18667e952dbe832d198a6c4b3d1500ddf0a637644e41d21038e189fb3d4fc5a8`, and its
  1,432-line `pg_restore --list` verification passes. Exact image
  `sha256:e3587e93ef6b1b2c289d8be78ef095488d143f789e83656a06f879c7e1803c88`
  carries the matching OCI revision and is deployed to app/database/default/files.
  The files worker retains its block-backed work directory plus read-only shared trust
  mount. All six expected workers answer, app health/check/migration gates pass,
  relevant queues are empty, and affected containers report zero restart/OOM.
- Deployed signed-in restore `29`, correlation
  `49dcaa3f-c114-4593-a5e0-7541cb517e72`, completed the live negative gate in one
  attempt with `delete=false`: the UI visibly renders Terminal failure / Failed and
  exact `RESTORE_TARGET_NAME_COLLISION`; the durable safe message states that no
  website data was uploaded or published. The three source hashes above are unchanged.
  No correlation-scoped local ZIP/tree/key, remote probe, hidden stage, partial path,
  lease, retry, or duplicate restore row remains, and files/default/storage/database
  queues are all `0/0`. This closes the retained live case-folding/normalization gate;
  the later plain-FTP/explicit-FTPS and legal path-component closure is recorded under
  Slice 4. The 10/25/50 GB website matrix was still open at this checkpoint and is
  closed by backups `59`–`61`/restores `36`–`38` above.

#### Active scale acceptance extension — 2026-08-19

- A new exact-owned 250 GB Vultr block volume named
  `bs-remed-20260818-0d08dcf-scale-250gb` was created in Chicago and attached only
  to fixture instance `7f52de9f-9238-45d4-bd1f-b66792288c83`. Its provider ID is
  `1be82b17-1e9f-4af3-b1fe-d29ee8579574`, device serial
  `ord-1be82b171e9f4a`, and ext4 UUID
  `2accb9ec-84df-4e0e-9d54-1b013a77e73c`. It is mounted persistently at
  `/mnt/bs-remed-scale-0d08dcf`, provides about 246 GB usable space and 16,384,000
  inodes, costs $25/month, and is retained. It must not be detached or deleted
  without fresh exact ownership reads and explicit cleanup authorization.
- The two-million-file source exists only on that remote volume under
  `bs-remed-20260818-0d08dcf/website-2m/source`. It contains exactly 2,000,000
  34-byte files in 2,000 directories, 68,000,000 payload bytes, and logical
  manifest SHA-256
  `9369b102a7b6cc7803d44c6d5e9e3ba301a6436e600373f75fb9574621bf4d46`.
  Generation took 158.108 seconds with 203,376 KiB peak RSS; the independent
  stratified witness SHA-256 is
  `a7af3d24a71ef18af99a748ff26cd474482332033df20d568312a58d07b56ea0`.
  Signed-in node `106` started backup `43` to storage `10` at
  2026-08-19 15:32:27 UTC. The mirror and old writer enumeration reached all source
  files, but the historical `mkdir_p` placeholder contaminated the manifest with
  `backupsheep.txt`, producing 2,000,001 rather than 2,000,000 entries. The exact
  180,000,016-byte manifest has SHA-256
  `45477822fd418b0b65e44a4b8e9d0fb9928e9b442d13d49260b85d7719c1e3c4`.
  Info-ZIP then reached about 1,195,872 KiB anonymous RSS and the kernel killed its
  process at 16:35:23 UTC under global memory pressure, so no archive was committed.
  The old retry cleanup deleted the completed mirror and left the public row at a
  generic source-export failure. Its exact task was revoked/cancelled before the
  900-second retry, and the log, manifest, count/hash, and kernel evidence were
  retained under demo block storage at
  `website-2m/failed-old-writer-20260819/`. This is a useful confirmed failure, not a
  pass: the bounded writer must be deployed before another full mirror is attempted.
- A dedicated MySQL 8.4.11 container named
  `bs-remed-mysql84-scale-0d08dcf` now serves exact source database
  `bs_remed_mysql_lg5_0d08dcf` from the new volume. It contains 5,000,000 rows and
  distinct IDs, min/max `0`/`4,999,999`, ID sum `12,499,997,500,000`, and
  5,185,000,000 payload bytes. The ten boundary samples, view, fixture metadata,
  object inventory, `log_bin=OFF`, and source marker passed; creation plus exact
  verification took 505 seconds. BackupSheep connection `78`, node `107`, and
  database `56` reach it only through exact tunnel container
  `bs-remed-mysql84-scale-tunnel`.
- Signed-in MySQL 5M backup `88`, point `92`, UUID
  `bs-bs-remed-20260818-0d08dc-n107-b88`, completed once to storage `10`.
  Its 263,656,096-byte source and destination artifact identity is SHA-256
  `a00cce0225717a0d138d9f7deace79b8de7a30f1c23c37516c139ef4b2993d79`;
  the persisted writer contract is `--single-transaction
  --column-statistics=0 --set-gtid-purged=OFF --no-tablespaces
  --max_allowed_packet=512M --extended-insert`. Signed-in clean restore `83`,
  correlation `bf8a463a-f22f-4381-a242-1c0b7cc78fe0`, started at 16:02 UTC to
  exact fork `bs_restore_bf8a463af22f_bs_remed_mysql_lg5_0d0_8e635348dafc` and
  completed once on attempt 1. Source and fork match at 5,000,000 rows/distinct IDs,
  min/max `0`/`4,999,999`, ID sum `12,499,997,500,000`, 5,185,000,000 payload bytes,
  metadata SHA-256 `d577657088ffe3d575e01f3405e441da4daef18b7c0013648b03df1432972004`,
  sample SHA-256 `7088d1115fd87b1924bc8fcf7529cd9065bd72c7dc50e1d1992b66d49a047a4d`,
  view SHA-256 `20de8a88254b8fa3d195e0653e3a815b90556238c23386e6f7172cac966729f5`,
  normalized DDL SHA-256
  `912deaffafb4b1de3fbdbd76b4fab106af816e011667283aaa1ce802d4502131`,
  and full ordered-row SHA-256
  `fcefb7f1baddda52c94c47ccaa702b377240f71f4f5acc6d47dd1d77b4b54c9a`.
  Its exact marker is complete. Fault restore `84`, correlation
  `bee81612-858e-4587-93a7-3ffd1545b9b0`, was then the sole active database job.
  At 16:35:41 UTC the database worker was hard-killed with the exact target client
  attached; non-blocking engine statistics showed about 336,544 rows before the
  kill, and an exact post-kill read proved 1,898,218 committed rows behind an
  `importing` marker while the durable row remained attempt 1 at 0/1. The same
  `ee8ec34` worker revision was restarted, broker redelivery stayed fenced until
  lease expiry, and natural takeover completed the same logical restore on attempt 2
  at 1/1. Source and fork match on the same exact aggregate, metadata, sample, view,
  normalized DDL, and full ordered-row SHA-256 values recorded above. The sole marker
  is `complete` and exactly binds correlation
  `bee81612-858e-4587-93a7-3ffd1545b9b0`, backup UUID, source, and target. The
  signed-in modal shows restore `84` as Complete at 1/1 beside clean restore `83`;
  no correlation-scoped restore work or target client remains. Exact evidence is
  retained at `mysql-5m/restore84-verification.txt`. This closes the required MySQL
  5M committed-row kill/recovery repetition.
- The controlled same-host MySQL 1M import comparison is now materially complete.
  The retained historical row-by-row artifact imported once in 3,795.03 seconds;
  the current extended-insert artifact imported three times in 49.80, 51.41, and
  52.86 seconds (51.41-second median). Every import produced the same exact digest
  `65e6f39c2cd6d22ce8edfc878007abe86f6eefb47a8a9053214369bc3a1bcc0e`.
  The median improvement is 73.82x (98.65% less elapsed time). Historical client
  RSS was about 1.117 GB versus 12.2–12.3 MiB for current imports, while the product
  worker stayed about 153–168 MiB instead of 1.23–1.24 GB. At this checkpoint only
  the controlled 1M comparison was closed; the later controlled 5M comparison is
  closed by the subsequent 16,956.91-second historical run and 249.94-second current
  median recorded below, while advertised 10/25 GB gates remain open.
- The live Vultr 100 GB gate uses bucket
  `bs-remed-0d08dcf-100gb-20260819`, prefix
  `bs-remed-20260818-0d08dcf/100gb`, backup `42`, point `44`, and an exact
  107,421,554,763-byte valid sparse Zip64 source retained on demo block storage.
  Geometry is 13,631,488 bytes per part and 7,881 parts. Only
  `worker-storage` was hard-killed at 2026-08-19 15:08:37 UTC after durable part
  1,008. Fresh provider inventory showed part 1,020 under the same upload ID,
  proving twelve remotely accepted parts beyond the local checkpoint. Attempt 2
  took over naturally after lease expiry, adopted those parts, and retained upload
  ID `2~vYLRU9GNWpRw64BSw1UczC5YjwYUdxH`. It completed at 7,881/7,881 parts on
  attempt 2. Durable state and provider HEAD agree on exact size 107,421,554,763 and
  source SHA-256
  `71ec61b44453a81201295bcb2f480c74b653f18333319821857cab74ba0775d1`;
  provider metadata binds backup `42`, byte count, SHA-256, and multipart operation
  marker. Exact-prefix inventory contains one object, ETag
  `f85bcf1d85f95ec5b2047c0b45e530fa-7881`, and zero unfinished multipart uploads.
  A full streamed provider read then returned exactly 107,421,554,763 bytes with
  SHA-256 `71ec61b44453a81201295bcb2f480c74b653f18333319821857cab74ba0775d1`,
  matching the independently hashed block-storage source. Local hashing took 237.703
  seconds and the provider stream took 540.409 seconds. The exact temporary Docker
  bind target was unmounted and its zero-byte underlying placeholder removed after
  proof; the block-storage source and provider object remain retained. This closes
  Slice 8's live upload/interruption/resume/object-integrity gate. A full website
  restore of this scale remains a separate final-matrix gate.
- Pushed and affected-service-deployed revision `b4cb5c5` adds byte/inode preflight, a fenced mirror
  identity checkpoint, archive-only retry after exact workspace revalidation,
  unique staged-file cleanup, and allowlisted file-count/stage UI progress. Nine
  focused tests passed in an isolated remote test database and isolated `_storage`;
  the broader affected batch passed 67/67, and both disposable databases were
  destroyed. The live OOM adds a confirmed missing requirement: current candidate
  work now replaces Info-ZIP for verified website member lists with a Python writer
  that keeps only one member in memory and disk-spools central-directory records,
  emits Zip64 end records, writes UTF-8 flags directly, mixes stored small files with
  streamed deflate for larger files, and binds count/member-list/source-byte identity
  before atomic publication. It also removes the non-source placeholder and exact
  `.files` cleanup leak. Its small archive module passes 12 tests locally, including
  semantic and atomic-failure coverage. A predeployment review then found that a
  truly empty website's valid zero-member ZIP is reported as a warning exit by
  Info-ZIP; the candidate now validates that structure directly and restores it as an
  empty directory without invoking the warning-only extractor path. The expanded
  archive module passes 13 tests locally. On Linux, the empty-site backup/restore
  batch passes 27/27 and the broader affected archive/restore/execution/API batch
  passes 183/183 in isolated disposable databases; both databases and their test
  databases were destroyed. The measured high-cardinality writer gate below passed
  before deployment; the full product backup/restore and controlled interruption
  remain open.
- The same read-only candidate source then passed the complete `apps.tests` suite:
  1,849/1,849 in 1,039.854 seconds with `APP_DOMAIN=test.example`, an isolated base
  database, its automatically created test database, and isolated `_storage`.
  An initial full run had 1,848 passes and one invite-URL assertion because the
  production Compose environment injected `demo.backupsheep.com`; that exact test
  passed after switching only to the reserved test host, and the full suite was then
  repeated cleanly. `manage.py check` reports no issues and migration drift reports
  no changes. All three disposable base/test database pairs from the 27-, 183-, and
  1,849-test gates were destroyed. Revision `b4cb5c5` contains only the fourteen
  remediation source/test files and is pushed to `origin/develop`; unrelated local
  documentation edits remain outside that commit.
- The final high-cardinality writer gate passed on the remote 250 GB fixture volume.
  It enumerated exactly 2,000,000 files plus 2,000 directories and 68,000,000
  logical source bytes in 346.462 seconds, then wrote, fsynced, structurally
  validated, CRC-tested, atomically published, revalidated, and independently
  recounted one 328,212,098-byte ZIP in 5,281.770 writer seconds. The final archive
  SHA-256 is
  `51bdd2343403f35279a2ede24753f6f02e25b1d2560e3937c504231f076320c6`;
  its exact 2,002,000-member list is 38,014,000 bytes with SHA-256
  `c4cd5387986d454ebdbe1ba8568c273b697464e4c06bc746a0032d6eec909d5a`.
  The writer crossed 201 live-fence checks, used 221,388 KiB maximum resident
  memory, performed zero swaps, and completed the complete harness in 1:34:29 with
  exit status `0`. This closes the bounded-writer resource/correctness gate and
  contrasts with the old writer's roughly 1,195,872 KiB OOM. It does not yet close
  the signed-in product backup/restore or controlled interruption gates.
- Immediately before deploying `b4cb5c5`, Beat was stopped and every
  website/database backup, restore, storage-point, and durable-request inventory was
  empty; the files/database/storage queues were each `0` ready / `0`
  unacknowledged. All five workers reported empty active and reserved inventories.
  The one previously documented cloud reconciliation delivery remained isolated on
  the cloud queue, so its older cloud worker and the unrelated logs worker were not
  replaced. The exact image
  `sha256:e392d781f5d2f6172385eb8d87fcde46437d886884016e912288d95b90b8c15e`
  contains no `_docs`, `.env`, or `.git`; image-level Django checks and migration
  drift checks passed. The migration container exited `0` with no migrations. App,
  worker-files, worker-database, worker-storage, and Beat all run the image with OCI
  revision `b4cb5c505c424fc03170961d45c304285d401c8e`; internal health is `ok`,
  public HTTPS health returned `200`, Django reports no issues, and all five workers
  answer ping. The signed-in node `106` UI loaded successfully after deployment.
- Signed-in backup request `151` created website backup `44`, UUID
  `bs-bs-remed-20260818-0d08dc-n106-b44`, with exactly one accepted destination,
  storage `10`. The request is durably `claimed` once and execution correlation
  `ae6d8e60-f75d-4f7b-8693-8e150295a300` started once. The customer UI truthfully
  exposed **Website Mirroring**, **Website Enumerating**, and 2,000,000/2,000,000
  file progress before archive creation. Three files-worker children were then
  kernel-OOM-killed by the historical Python `ZipFile.testzip()` source verifier at
  1,848,072, 1,523,324, and 1,574,044 KiB RSS; the already committed archive and
  durable mirror checkpoint remained recoverable.
- Pushed revision `6c66aa3` uses bounded `unzip -tqq` CRC verification, caps that
  verifier to 12 hours, runs the files worker at concurrency/prefetch `1`/`1`, and
  bounds app request concurrency. Its complete `apps.tests` candidate passed
  1,878/1,878, with focused final-candidate checks repeated after the declaration and
  batching-only follow-up. Only `app` and `worker-files` were replaced. The recovered
  same backup `44` then completed and uploaded once: source and storage point `46`
  identify the exact mode-0600 block-storage artifact
  `bs-bs-remed-20260818-0d08dc-n106-b44.zip`, 612,497,006 bytes, SHA-256
  `7abc4c03ca25616065b7e1248a7d77c2bd206a0259024dd9516deaa2c84e30f7`,
  2,002,005 ZIP entries, clean CRCs, and one upload attempt. No post-fix OOM occurred.
- Pre-restore inspection found that the old website restore still materialized and
  persisted every extracted member in one Python list/dictionary. Pushed revision
  `d4c1b33` replaces that path with a private disk-spooled SQLite manifest and
  deterministic aggregate v2 identity, retaining detailed per-file state only below
  the bounded 1,000-file default. Large manifests now persist only algorithm,
  SHA-256, file/directory/member counts, and logical bytes; a second scan proves the
  extracted tree unchanged before remote staging. Its exact candidate passed 54/54
  final focused, 157/157 broader, and the preceding behaviorally identical full
  1,878-test suite; system and migration checks were clean and all disposable
  databases were destroyed. A 100,100-member measurement repeated the same digest in
  3.369/3.629 seconds at about 187 MiB process RSS with no inline file state or index
  residue. Only `app` and `worker-files` were replaced on exact image
  `sha256:c47cafecff272d5c52fbe19a0f73e44e8479be7c285972a8051946ea8d050e7a`.
- Through the signed-in UI, restore `22`, correlation
  `a15b4fff-b02a-4128-8eac-22444e4a61e0`, restored backup `44` from point `46`
  with delete mode disabled. The UI moved from Queued/Pending through active
  Validating and Restoring to Complete at 1/1 only after publication and cleanup.
  The first and second bounded source scans both produced 2,000,000 files, 2,000
  directories, 2,002,000 source members, 68,000,000 bytes, manifest SHA-256
  `bbd589716d4961afaf66236ab5ae95c526a30bcc6bfcb28a7e6e965a832d7f2c`,
  and source digest
  `8f17d08a9394e9e0f6a14781b9fd98e0c7b204711c030c92ade2f35c75535004`.
  Durable metadata stayed at 1,994 bytes and contains no inline file map. The exact
  restored target and reversibly retained pre-restore baseline each pass 2,000
  directory/2,000,000 file topology and the same 4,100-sample witness SHA-256
  `a7af3d24a71ef18af99a748ff26cd474482332033df20d568312a58d07b56ea0`;
  the restored logical byte sum is 68,000,000. Restore-scoped local and remote stage/
  previous-target residue is zero, the files queue is `0/0`, and the new worker's
  cgroup reports a 1,408,442,368-byte peak with zero OOM/OOM-kill events.
- That 40-minute restore exposed a separate terminal-boundary defect: the final
  unrestricted model save overwrote the background thread's current heartbeat and
  lease expiry with the task's initial in-memory values. The data and UI were already
  safely Complete, but Celery emitted one 30-second terminal no-op redelivery and the
  completion-notification outbox marker was skipped. New regression
  `test_long_restore_completion_does_not_rewind_renewed_lease` fails against deployed
  `d4c1b33` with the heartbeat rewound by one hour and passes after the outcome save
  is limited to its owned fields. Pushed revision `e9c842f` passes that regression,
  156/156 restore/lease/notification tests, Django checks, and migration drift. Its
  pre-deployment database dump is
  `demo-pre-e9c842f-20260819T2210Z.dump`, 1,068,450 bytes, mode `0600`, SHA-256
  `d0c81d851332e97904124d5bbf2eefc410836404ca19819d997143c7e6e77c69`.
  Only `app` and `worker-files` were recreated on exact image
  `sha256:7d1389f80d0aa526d52ab62ffb522812e0ca2c02d9d90e9bcf74e0c7ec76c3ef`;
  public health is `ok`, all five workers answer ping, and the files queue is `0/0`.
- Signed-in request `152` created controlled backup `49`, UUID
  `bs-bs-remed-20260818-0d08dc-n106-b49`, to storage `10` only, with execution
  correlation `12dd33d0-d084-4bf7-9c3e-a528985e7786` and task
  `696fcaa972b8578793aedafa3d8d4dde`. Before interruption, its durable checkpoint
  bound exactly 2,000,000 files, 2,005 directories, 68,000,000 logical bytes,
  178,154,219 path bytes, manifest SHA-256
  `95b7b2cd006d529fb2c7725a0a1f506612eb117cc8a2d57ef811f5c547500499`,
  members SHA-256
  `a2e9fda0153eb6401bb66e696adb3703dd2891b30785c08018d50da1c12428de`, and
  tree SHA-256
  `330360588b44f3edd5eb876585cf99b3834ca3d09ad5f4e0f0bf05dcb5cff400`.
  Only the exact files-worker child was hard-killed at `2026-08-19T23:12:09Z`
  while private inode `6874851` was growing. Broker redelivery of the same task was
  fenced by the live lease; after natural expiry, attempt 2/claim 5 reused the
  checkpoint. Its log contains one source `Path:` and one
  `Verified mirror checkpoint; retrying archive without another source transfer.`
  witness, proving no second `lftp` mirror. The old private partial is absent; new
  inode `6853567` was atomically renamed to the final artifact, and no private partial
  remains.
- Backup `49` finished as one logical row on attempt 2, claim 5, delivery 3, with
  resolved reconciliation and one upload attempt. Source and destination are both
  mode `0600`, 612,497,006 bytes, SHA-256
  `3bb9cc5b8e933e3204c99fe89ae53bf02890b22495f1e0b52d0bb6fe7fc35036`.
  Independent verification found clean CRCs and exactly 2,002,005 entries. A bounded
  one-pass verifier matched 4,100 files/139,400 payload bytes with concatenated
  payload SHA-256
  `4683c3bc78cffde6f5d00ed634b8819e94ebc160b95c43ba3144443baca204c9`
  against source logical manifest
  `9369b102a7b6cc7803d44c6d5e9e3ba301a6436e600373f75fb9574621bf4d46`;
  it used 27,612 KiB peak RSS. The mode-0600 sample manifest is retained under the
  run evidence directory with SHA-256
  `46ffd3e34c5ca3d8c89b9f2240ac7b2a86376e5915c781f4fceb4c3da60905e`.
  The signed-in UI shows Complete, Phase Complete, resolved recovery, exact byte
  progress, and 2,000,000 files. This closes Slice 7's controlled interruption,
  checkpoint-reuse, no-retransfer, atomic-publication, upload, and final-artifact
  exit gates.

#### Claimed-size website closure and local-storage lease deployment — 2026-08-22 UTC

- The retained 25 GiB upload was the exact failing control for a long local-storage
  boundary. Backup `60`/point `62`, UUID
  `bs-bs-remed-20260818-0d08dc-n117-b60`, completed source work but its first three
  storage deliveries lost their 15-minute lease during CRC/source-hash/copy work.
  Two confirmed defects combined: local validation/copy had no same-thread lease
  pulse, and a later fenced full-model save could overwrite a freshly renewed lease
  deadline with the model instance's older value.
- Commit `7f3269a96e51e72a8b0bc9f26d7c340cd6adefb1` pulses the fenced
  storage lease within long local CRC, source-hash, copy, and destination-hash loops
  and preserves lease-loss exceptions. Commit
  `81ea8a25ad1078e993893d0ab8e194c99dc21e88` re-reads the current fenced lease
  row under lock before a model save and preserves its renewed owner/token/expiry/
  heartbeat fields. The final candidate passes 19/19 focused lease/local-storage
  tests, 94/94 adjacent storage/restore tests, and 1,930/1,930 repository tests in
  476.825 seconds; Django system and migration-drift checks pass.
- The verified predeployment dump is retained at
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/deployments/`
  `81ea8a25ad1078e993893d0ab8e194c99dc21e88/predeploy-backupsheep.dump`,
  1,149,241 bytes, mode `0600`, SHA-256
  `f667e34c7167df89892d6c668847bc4f16c9770268f90e5925dfebeb656e390b`;
  its 1,432-entry `pg_restore --list` check passes. Exact image
  `sha256:2970f18b951b33fa238ced36acf3755118c17feea91124e084251910cc80c8d4`
  carries the matching full OCI revision and is deployed only to the app and the
  run-scoped storage worker. The prior storage worker is retained stopped as
  `bs-remed-100gb-worker-storage-pre81ea8a2`; database/default/files services were
  not restarted for this deployment.
- The deployed worker naturally adopted retained backup `60` as storage attempt 4 on
  the same logical row. Its 26,843,545,600 raw bytes and 25 files produced one
  26,851,743,727-byte destination with SHA-256
  `0c0a002948fb31f4458a3e0375fa98aa95b5470828ef8662fc515879d42419b0`.
  Source/destination artifact ledgers agree, independent destination hashing and
  `unzip -tqq` pass, and no duplicate backup was created. Signed-in restore `37`,
  correlation `e7456936-3751-45fa-9934-0deaf3fb188a`, completed once at 1/1.
  Its target contains exactly 25 one-GiB files, 26,843,545,600 bytes; every file has
  SHA-256 `1804b99041527da2425e1f9901f212e36d3e84cc4cd99c33b30662a5ddeb220f`.
  Remote stage/previous residue and large local restore work are zero.
- Signed-in node `116` created backup `59`/point `61`, UUID
  `bs-bs-remed-20260818-0d08dc-n116-b59`, for the separate 10 GiB gate. Its ten
  one-GiB source files total 10,737,418,240 bytes. One 10,740,698,272-byte artifact
  with SHA-256
  `2b2e134434ce0e73d3e256ea0c25897b09f68d12a7f62ac3da8b185288c76541`
  is source/destination-identical and CRC-clean. Signed-in restore `36`, correlation
  `0c9ee6e8-5ea6-49a2-9189-0732dca91698`, completed once at 1/1 and reproduced the
  exact ten-file/10,737,418,240-byte target; every file has the same exact
  `1804b990…b220f` SHA-256 witness. Scoped stage/work residue is zero.
- Signed-in node `118` created backup `61`/point `63`, UUID
  `bs-bs-remed-20260818-0d08dc-n118-b61`, for the separate 50 GiB gate. Its 50
  one-GiB files total 53,687,091,200 bytes. Storage attempt 1 produced one
  53,703,486,152-byte artifact with source/destination SHA-256
  `c028b457c9cef01f0e5286f5494510d9dc98e1f3777bf94d6bb492422d784ae5`;
  independent destination hashing and `unzip -tqq` pass while the lease renews across
  validation and block-storage copy. Signed-in restore `38`, correlation
  `0d4c4251-133b-4c96-a1a2-3829a3954e0e`, completed once at 1/1 with `delete=false`.
  During private SFTP staging the live target remained empty; atomic publication then
  produced exactly 50 one-GiB files/53,687,091,200 bytes, each with exact SHA-256
  `1804b990…b220f`, and zero hidden stage/previous residue. The original fixtures for
  all three sizes were restored after verification.
- Fresh durable reads show backup `61`, point `63`, and restore `38` terminal at
  `Complete`, with one storage attempt, one restore attempt, cleared leases/errors,
  progress 1/1 paths, and two artifact records. No `n118-b61` work item remains;
  files/storage/database/default queues are `0/0`. The app, files worker, and storage
  worker are running with zero restart/OOM. `/mnt/blockstorage` has
  633,865,711,616 bytes free. These results close every claimed 10/25/50 GiB website
  backup/restore gate and Slice 4.
- One presentation-only issue remains under Slice 14: at backup `61`'s live terminal
  transition, progress and actions updated but the static Size/Files cells briefly
  remained blank/`0`; a normal page reload immediately rendered `53.7 GB`/`50`.
  Durable counters were already exact. The acceptance gate is a terminal poll that
  refreshes those static cells without requiring reload.

#### Current diagnostic, UI-refresh, and large-database continuation — 2026-08-23 UTC

- Commit `d5c06a9410e3e177291a3711dd4fec1c77a9dac2` adds bounded live backup
  metrics to the execution-status contract, refreshes terminal Size/Files/node
  counters in the existing page state, and improves public-safe database restore
  diagnostics. Its exact candidate passed repository discovery 1,926/1,926 in
  388.189 seconds. A live MySQL restore then exposed that client error line numbers
  can identify the start of a multi-line statement rather than the line containing
  its `DEFINER` clause. Commit
  `561c1703bc33463f37f93e0df0db5155e30855f7` conservatively tracks statement-start
  witnesses so that only the proven statement receives the existing public
  classification. It passed 81/81 focused restore-hardening tests and the corrected
  full suite 1,928/1,928 in 379.182 seconds. The first full-suite invocation had one
  environment-only invite assertion because it inherited the live `APP_DOMAIN`;
  the exact test passed in isolation with the normal test domain, and the corrected
  complete invocation is the release count.
- Before deploying `561c170`, a mode-`0600` PostgreSQL snapshot was retained under
  the run's block-storage predeploy directory at 522,081 bytes and SHA-256
  `c86ea26670cb1838c64f04993c29831ae94dca35a090eb43e4d7261e08ae10da`.
  Demo `/opt/backupsheep` and `origin/develop` are aligned at `561c170`; exact image
  `sha256:b8896cfba733ac60dbb67c5925575ff0441598c11f701912d95eb269bd735ee9`
  runs the app and dedicated database worker. Django checks, migration drift,
  internal/public health, and the affected queue/worker gates passed.
- The live classifier control uses MySQL backup `96`/point `101`, UUID
  `bs-bs-remed-20260818-0d08dc-n120-b96`, and restore `87`, correlation
  `5e9cde65-d303-4379-8203-e22728dd1ea8`. On the pre-fix image, attempt 1 stopped
  safely as generic `RESTORE_TARGET_REJECTED`; the target had only the exact
  importing marker and the source was unchanged. Deployed `561c170` made attempt 2
  fail safely as `DATABASE_RESTORE_SYSTEM_DEFINER_REQUIRED` with actionable
  SYSTEM_USER guidance even though MySQL reported line 69 and the `DEFINER` text was
  on line 70. After granting that privilege only to the disposable fixture account,
  the signed-in `Resume verification` action completed the same restore row on
  attempt 3 at 1/1. Source and fork each have the exact row/view/object inventory,
  the view retains `root@localhost` plus `SQL SECURITY DEFINER`, and the sole marker
  matches correlation, backup UUID, source, target, digest, and `complete` state.
- The retained MySQL 10 GB gate uses connection/node `84`/`119`, backup `95`/point
  `100`, and restore `86`. Its SQL entry is 10,859,246,782 bytes; the ZIP is
  526,481,463 bytes with SHA-256
  `b9b072239f61927550aa29172e96bcf9c7cb40bc3c848b1be1021c2cf64b3ff9`.
  The signed-in safe-fork restore completed after the exact disposable account
  received its missing preflight privileges. Source and target match at 10,000,000
  rows, normalized schema/default/view/marker evidence, and full ordered digest
  `c4f1912f72be5988d15334bdd98e819e31085bc0b6609a4b8b2f156a034cffdc`;
  targeted residue is zero. This closes the separate MySQL 10 GB support gate.
- Signed-in website node `109` then closed Slice 14's remaining no-reload display
  gate with backup `63`, UUID
  `bs-bs-remed-20260818-0d08dc-n109-b63`. On one unchanged browser page, its live row
  changed from Files `0` to `103,573`, advanced through Website Archiving and Source
  archive ready, then rendered Complete with Size `1.37 GB`, Files `103,573`,
  Download/Restore/Delete present, and Cancel absent. The node summary changed on
  that same page from one backup/1.37 GB/Aug. 20 to two backups/2.73 GB/Aug. 23.
  The destination is mode `0600`, 1,365,639,963 bytes, SHA-256
  `da71a6927c3ab33f121912262ff9a5796abd3f8d7fb530b9ee287fcf8a9bc021`,
  and CRC-clean; source/destination ledgers agree, upload attempt count is one,
  relevant queues drained, and affected workers have zero restart/OOM.
- The exact-owned MySQL 25 GB source `bs_remed_mysql_lg25_0d08dcf` contains
  25,000,000 distinct IDs `0` through `24,999,999`, ID sum
  `312,499,987,500,000`, 25,925,000,000 payload bytes, and one source tag. The first
  evidence-only ordered verifier omitted MySQL client `--quick` and its client was
  cgroup-OOM-killed before emitting a row hash; the server stayed running and the
  product backup had not started. The corrected streaming verifier used under 10 MiB
  client RSS and ended `RESULT=PASS` with metadata SHA-256
  `8f533eefd47c11b7420d35fadf1e2dc2a90e6b385e30fef65408d807d638be00`,
  view SHA-256
  `2c396b0175d2511b8885da8aaf53a8db19d15c6aeab944d517d5adfd4dbb3e55`,
  and full ordered-row SHA-256
  `829e8972e8e2637f658a2c01fa2813e996bd0492ad5c28e5efa35b78e8a6776b`.
- Through signed-in node `121`, request `175` created one backup `97`/point `102`,
  UUID `bs-bs-remed-20260818-0d08dc-n121-b97`. The dump client stayed near 12 MiB
  and the database worker below 500 MiB. The row truthfully advanced from active to
  Source archive ready, Uploading, and Complete. Its mode-`0600` destination is
  1,319,587,231 bytes at source/destination SHA-256
  `b62282d5037c382521edf9d300c73775e9db1b87eb504f37bc48a2f665bf814f`,
  passes CRC, and contains only `backupsheep.txt` plus the 27,414,785,434-byte SQL
  member; that SQL member's independently streamed SHA-256 is
  `42dc8dac88d89d54098c26d37a67afe21ce8f502141ea32b8d19885483d079f4`.
  One storage attempt completed and both queues drained.
- Signed-in safe-fork restore `88`, correlation
  `722fa3ed-d8c2-45fd-a3f4-63345ca3224a`, targets
  `bs_restore_722fa3edd8c2_bs_remed_mysql_lg25_0d_1796e479afe1`. Attempt 1 reached
  durable `database_importing_file`, UI Restoring 0/1, and an exact importing marker.
  A deliberate exit-137 stop of only the run-owned database worker released the real
  client and proved exactly 2,749,618 committed/distinct rows, IDs `0` through
  `2,749,617`, ID sum `3,780,198,198,153`, and 2,851,353,866 payload bytes. The same
  restore row stayed active; its one delivery requeued with zero consumers while the
  live lease expired. Starting the same worker after expiry produced attempt 2 with
  exactly one stale takeover and prior work suffix `72b087fc8d845da9`. The
  replacement revalidated the full artifact before mutation, then proved the fork
  contained only the exact importing marker before starting its second real client.
  Attempt 2 completed on that same restore row; the signed-in modal showed Complete,
  phase Complete, and 1/1. The durable row is status `3`, phase `complete`, attempt
  count `2`, with lease/retry/error fields cleared and exactly one stale takeover
  whose previous phase/expiry/work suffix match the recorded interruption.
- Remote verification then matched source and target exactly at 25,000,000 rows and
  distinct IDs, IDs `0` through `24,999,999`, ID sum `312,499,987,500,000`,
  25,925,000,000 payload bytes, one source tag, metadata, boundary samples, summary
  view, normalized DDL, and full ordered-row SHA-256
  `829e8972e8e2637f658a2c01fa2813e996bd0492ad5c28e5efa35b78e8a6776b`.
  The first marker assertion used the wrong evidence-column name `backup_id` after all
  content checks passed; a corrected `backup_uuid` assertion then proved one version-1
  primary marker with the exact correlation, backup UUID, source, target, source
  digest `922a8f449be2c60cb543782abcf658663f3566e4a1532f5690d9a9cb21cb7985`,
  and state `complete`. The final evidence file is mode-local to the Vultr block
  volume with SHA-256
  `2430bdf1bba75799cc0a18047273a543889d324e9084192f2a4f65d495e8e5ff`.
  The database queue drained to zero ready/unacknowledged, its consumer stayed
  healthy with zero worker restart/OOM, and exact old/new correlation work-suffix
  residue is zero. This closes the MySQL 25 GB backup, strict UI restore,
  crash-takeover, exact-content, and cleanup gate.

#### Final PostgreSQL, diagnostics, and release closure — 2026-08-23 UTC

- Signed-in PostgreSQL backup `100`/restore `90` closed the 25M-row/25 GB-class gate.
  The 148,620,669-byte destination ZIP matches its source ledger at SHA-256
  `4626f366e04ad7bdc767d2b06ca5f58f33134b5d814219600f7b57dd2791e816`;
  the 26,163,891,715-byte SQL member hashes to
  `84773f3e099e97dd789da53abd6a620627a92143d04a6c0b45edeefd33565b1f`.
  The exact target has 25,000,000 distinct rows, IDs 0–24,999,999, ID sum
  312,499,987,500,000, 25,925,000,000 payload bytes, source-equal schema, exact
  completion marker, and full ordered SHA-256
  `c0bf5c145aec013a2649242d56d3176384faf7d60e0da1817b83610b4bc49cec`.
- Signed-in PostgreSQL backup `99`/restore `93` separately closed the 10M-row crash
  gate. Attempt 1 was killed at the real import boundary; transaction rollback kept
  the public table absent and marker importing. One natural stale-lease takeover
  completed attempt 2 on the same row. The UI reached Complete/1-of-1 only after
  exact source/fork aggregate, schema, marker, sample, and full ordered verification.
  Namespaced local and remote correlation residue is zero.
- Revision `be41098` closes the combined PostgreSQL stale-work cleanup exposed during
  the 25M control and passed 138/138 focused plus 1,941/1,941 repository tests. The
  subsequent 10M kill/replay is its live acceptance repetition.
- Revision `5b4775e` then added bounded public attempt history, public-safe stage/code
  guidance, and operator-only correlated diagnostics. Live signed-in cases `64`,
  `39`, `65`, `69`, `41`, and `70` cover unsafe source, collision, archive retry,
  storage stall, worker loss, and secret-canary redaction. Restore `41` reproduces the
  full 103,573-file website baseline after exact natural takeover.
- Revision `8dba19b` corrects completed-state error rollups without erasing attempt
  history. It was pushed, built, and deployed to the app and scoped default/files/
  storage/database workers. Signed-in backups `65` and `69` now show Complete with no
  current error while retaining their historical codes in Technical details.
- The exact release passed Django checks, migration drift, 24/24 focused, 105/105
  adjacent, and 1,953/1,953 full tests. The final full-suite log SHA-256 is
  `eb712e08dc991a936069b500ac772781ce9a5091729edde4afb5e7ce1c1c3863`.
  All isolated suite resources and exact transient Slice 13 fixtures were cleaned;
  production queues remained empty except the pre-existing cloud reconciliation
  delivery, which was deliberately left untouched.

#### Remote automated verification

- The first deployed candidate passed 43/43 database-focused tests.
- A 58-test API/UI/storage batch initially produced 56 passes and two HTTP 301
  failures because the one-off test container inherited production HTTPS redirect
  settings. With `DJANGO_SERVER=local` and `DJANGO_HTTPS=false`, both affected tests
  passed and the full batch repeated at 58/58.
- The MariaDB validator follow-up passed 60/60 restore hardening and vendor-client
  tests. The exact live 3,695-byte MariaDB 11.8 artifact also passed fork validation,
  while the same transaction boundary remained rejected for in-place mode.
- The UTF-8 archive follow-up passed 21/21 archive, finalization, extraction, and
  website-restore tests on demo-side Linux. This includes preserving distinct NFC and
  NFD filenames. The same small unit module passed locally with that one test skipped
  because the Mac filesystem normalizes the two names; no local Docker or large local
  artifact was used.
- Candidate `manage.py check`, migration drift check, and migration plan check were
  clean; no schema migration was required.
- The bounded PostgreSQL historical-clean compatibility candidate and deployed image
  passed 102/102 focused restore, hardening, crash-safety, and lease tests. A real
  historical product artifact then restored strictly with exact rows and objects.
- Engine-client work first passed 24/24 focused tests. The final isolated batch passed
  305/305 connection, serializer, backup-engine, restore-hardening, crash-safety,
  lease, and restore tests in 217.470 seconds. An earlier 15-test serializer run was
  redirected only because it inherited production HTTPS; all 15 passed with the
  isolated test settings.
- Scheduled-event export first passed 7/7 focused regressions and 119/119 affected
  backup/UI/error tests. Its exact candidate passed 354/354 broader database tests in
  255.697 seconds.
- Proactive event-read privilege validation passed 22/22 focused tests and 156/156
  affected connection/API/database tests. Its exact candidate passed 360/360 broader
  database tests in 256.685 seconds.
- The two API-boundary corrections passed 33/33 focused connection/API tests on the
  final candidate. `manage.py check`, migration drift, and the migration plan remained
  clean; no schema migration was required.
- On the final `bc354015` image, 58/58 isolated PostgreSQL/database-restore hardening,
  logical crash-safety, and durable restore-lease tests passed in 37.855 seconds. The
  test database was isolated as `backupsheep_slice1_fault_20260818`; the live demo
  database was not used by this automated batch.
- The final image also passed 17/17 focused connection-error and database-client
  capability tests in 0.045 seconds for the MariaDB missing-client gate.
- The recovery-reservation regression first failed as expected on the deployed
  `bc354015` implementation: the exact recovery delivery raised `RestoreLeaseBusy`
  on the sweep's own future `next_retry_at`. After the bounded fix, all three new
  reservation/ordinary-delivery/later-backoff contracts passed, followed by 20/20
  durable restore-lease tests.
- The mounted candidate passed 89/89 database-restore hardening, transactional
  crash-safety, and restore-lease tests in 67.319 seconds. Exact built image
  `sha256:c84dd1e0d4d730e2a6260f8f6b7eea2a759e1d90d59f06e945f633ccb93eefb0`
  repeated the same 89/89 suite in 74.329 seconds. All runs used isolated remote
  test databases; no local Docker or live demo application database was used for
  their test data.
- `manage.py check`, migration drift, and the fully applied migration plan were clean
  for the exact candidate. The recovery fix stores its task/timestamp binding in the
  existing execution metadata and requires no schema migration.
- The markerless-collision regression failed first on the deployed `f4adce3` code
  with the raw `NodeBackupFailedError` raised by the missing marker table. The bounded
  implementation then passed the exact focused regression, followed by 90/90 mounted
  database-hardening/crash/lease tests in 71.000 seconds. Exact built image
  `sha256:3b7603d2d0e9f31fca257fd12a5398306b5c785d947120c4e6306b9a10fb0b33`
  repeated 90/90 in 63.966 seconds. `manage.py check`, migration drift, and the fully
  applied migration plan were clean in an isolated remote database; both exact-name
  disposable check databases were removed.
- The historical-restore diagnostics contract failed first against deployed
  `6555d57`: the recent-row summary was hidden and no per-row correlation/error-code
  affordance existed. The bounded template fix passed 7/7 focused UI tests, 31/31
  execution-status/modal/manual-resume tests, and a mounted 215/215 restore/API/UI/
  hardening/crash/lease batch in 153.263 seconds. Exact image
  `sha256:f1fc0bd63bc244c2cb44dc692ce9f7b89fb9a73dae5223e31c6b5ce3b3c3d79b`
  passed the 31/31 release-focused batch in 19.846 seconds. `manage.py check`,
  migration drift, and the applied migration plan were clean; the exact disposable
  check database was removed.
- The multi-database polling regression then failed as expected against deployed
  `cb7fbc8`: six active durable phase cases were misclassified, including
  `database_complete` and `database_restore_complete` as public `complete`. The
  mounted `f9669c5` candidate passed all 11 execution-status API tests. Exact deployed
  image `sha256:abfba7a7e6f5bc364f697e898e7ea7f1825cedab50aa1e1204e730170fdc5951`
  then passed 21/21 execution-status API, dashboard UI, and logical-restore modal tests
  in an isolated demo-side database. `manage.py check`, migration drift, and the live
  phase contract were clean; both exact disposable test databases were removed.
- The MariaDB matrix first exposed a late object-family failure on restore `67` after
  five targets had completed: its dump preserved explicit `root@localhost` definers,
  while the dedicated restricted fixture account had CREATE/DROP/object privileges but
  not MariaDB `SET USER`. A minimal run-owned diagnostic target reproduced exact server
  error 1227. This classified both a fixture permission omission and a product defect:
  fork preflight checked CREATE/DROP but did not detect a required definer capability
  before mutation.
- The `0220727` candidate passed the six new archive/grant regressions and all 68/68
  database-restore hardening tests in an isolated demo-side database. `python`
  compilation, `git diff --check`, `manage.py check`, migration drift, and the fully
  applied migration plan were clean; both disposable test databases were removed.
  MySQL 8.0 accepts `SET_USER_ID`/legacy `SUPER`, MySQL 8.4 requires
  `SET_ANY_DEFINER` plus `ALLOW_NONEXISTENT_DEFINER`, and MariaDB requires `SET USER`
  or its legacy `SUPER` equivalent. Ordinary row data containing the text `DEFINER=`
  does not trigger the archive requirement.
- The deep-mirror fallback candidate passed 23/23 focused website tests and the exact
  deployed implementation passed 214/214 archive, writer, extraction, restore, task,
  and UI regressions before product backup `41` and restore `21` closed W6.
- The MySQL restore-preflight candidate passed 73/73 focused hardening tests in
  54.326 seconds and 93/93 hardening, manual-resume, and logical crash-safety tests in
  75.758 seconds. The two isolated candidate database/test-database pairs were
  destroyed; a fresh count found zero remaining candidate databases. The mounted
  live probe recognized the exact escaped `bs\_restore\_%` scope and left its probe
  schema absent. After deployment, the same product-authenticated no-mutation probe
  again returned CREATE/DROP coverage with schema count zero.
- The stale local-work regression was captured before implementation against the
  deployed `fecf40a` image: the takeover record lacked `previous_work_suffix` and
  `delete_from_disk(..., "restore")` left the exact fenced directory, ZIP, manifest,
  MySQL defaults file, and website private-key path in place (one expected error and
  one expected failure across two tests). Revision `d547501` then passed the four
  exact database/website takeover-cleanup regressions, 55/55 focused restore/lease/
  cleanup tests, 116/116 database hardening/manual-resume/crash/lease tests, and the
  complete 215/215 `test_backup_engine` plus `test_restore` modules. The exact labeled
  image repeated the four new regressions at 4/4. Every isolated test database was
  destroyed; Python compilation and `git diff --check` passed, and no migration was
  required.
- The MySQL all-database/direct-export/terminal-redelivery sequence was exercised by
  the signed-in node `104` product path. Cancelled backup `77` retained the original
  `source_export_failed` witness from the unsupported one-command direct exporter;
  the bounded multi-database exporter and terminal redelivery no-op then produced
  generation backups `78`/`79` without replaying any terminal backup.
- The schema-default candidate passed 20 focused direct/SSH MySQL/MariaDB tests, all
  115 backup-engine tests, and two malformed/injection security regressions. Live
  MySQL 8.4 and MariaDB 11.8 probes confirmed the unqualified database-default
  statement works; both exact-owned probe schemas were removed. The file-descriptor
  ordering correction then passed all 117 backup-engine tests.
- The authenticated restore-preamble candidate passed all 76 restore-hardening tests
  and all 114 restore plus logical crash-safety tests. It accepts only the exact
  first line bound to contract-v2 engine/database/default metadata for fork or
  explicit in-place mode; missing metadata, historical contract-v1 artifacts, moved
  or mismatched preambles, later `ALTER DATABASE` statements, and injection remain
  blocked before target mutation. No schema migration was required.

#### Isolated Vultr and BackupSheep inventory

- Run ID: `bs-remed-20260818-0d08dcf`.
- Vultr SSH key `f95297d8-3113-409a-b181-f19bc3c53fbe`; firewall group
  `24834436-6346-4036-ba38-a251bae1eacc`; rules `1`, `2`, and `3` allow only
  demo IPv4 `64.177.125.68/32` to SSH, MySQL-family, and PostgreSQL ports.
- Vultr instance `7f52de9f-9238-45d4-bd1f-b66792288c83`, label
  `bs-remed-20260818-0d08dcf-webdb`, IP `64.177.8.4`, `ord`,
  `vc2-2c-4gb`, Ubuntu 24.04, backups disabled, and exact run tag/firewall/key
  ownership. The durable ledger has six exact resource rows and zero pending mutation
  intents.
- The instance runs remote-only Docker fixtures `bs-remed-pg16`
  (`postgres:16-bookworm`), `bs-remed-maria118` (`mariadb:11.8`), and
  `bs-remed-mysql84` (`mysql:8.4`) with run labels/volumes, plus an isolated SFTP tree
  at `/srv/bs-remed-website/source`. A separate run-owned deep-tree source is retained
  at `/srv/bs-remed-website/deep300-0d08dcf`; it has 301 directories including its
  root, one leaf, and a 2,999-byte relative directory path. The MySQL fixture is
  reached from the demo Docker
  network through exact-run-labelled container `bs-remed-mysql84-tunnel`, which uses
  strict SSH host-key verification; no provider firewall rule was broadened. Its
  mode-0600 environment file is retained under
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/` and was never
  printed. No fixture or backup data was downloaded to the MacBook.
- The owned VM now has PostgreSQL client `16.15` from PostgreSQL's official PGDG
  Noble repository. Ubuntu's initial `16.14` client was correctly rejected as older
  than the fixture server's `16.15`; after the client-only upgrade, product SSH
  validation passed. No PostgreSQL server/container setting or data was changed by
  that package installation.
- BackupSheep account `1` test objects: local storage `9`/local row `1`, website
  connection/node/source `60`/`89`/`23`, PostgreSQL `61`/`90`/`41`, MariaDB
  `62`/`91`/`42`, MariaDB SSH `63`/`42`/`92`/`43`, MySQL
  `66`/`45`/`93`/`44`, PostgreSQL SSH `67`/`46`/`94`/`45`, and PostgreSQL SSH 1M
  crash connection/auth/node/source `68`/`47`/`95`/`46`. The exact-owned source
  database is `bs_remed_pg_crash_0d08dcf`. The local destination path is
  `/backups/bs-remed-20260818-0d08dcf`; these small gates did not require the large
  block-storage mount.
- PostgreSQL all-database connection/auth/node/source `71`/`50`/`96`/`47` selects
  exactly eight run-scoped databases: `pg_tiny`, `bs_remed_pg_crash_0d08dcf`, and
  `bs_remed_pg_matrix_{medium,manytables,blobs,unicode,objects,mutable}_0d08dcf`.
  Node `96` is named `bs-remed-20260818-0d08dcf PostgreSQL 8-family matrix`; it has
  no schedule. The six new sources contain related medium tables, 450 tables across
  three schemas, exact binary/text payloads, Unicode rows, advanced PostgreSQL
  objects, and a mutable generation fixture; all were generated on the owned Vultr
  host.
- Node `96` has generation-1 backup `68`/point `72`, UUID
  `bs-bs-remed-20260818-0d08dc-n96-b68`, 56,309,918 bytes, artifact SHA-256
  `d63db5c8afe01fcc33f08d778f0d1ab1f533f87137e5bbd83ea2a9813bc6bf5d`;
  and generation-2 backup `69`/point `73`, UUID
  `bs-bs-remed-20260818-0d08dc-n96-b69`, 56,310,353 bytes, artifact SHA-256
  `ae36b1485296d161219fb63a045bbf8ccb00a77b141c7459812200d378c89dfe`.
  Backup `69` contains exactly eight SQL entries plus `backupsheep.txt`, passes ZIP
  CRC, and captures the mutable source after ten updates, five deletes, and twenty
  inserts. Exact-owned restores `63` and `64`, correlations
  `7d0188a1-c6e5-4aee-8977-bf3695885b37` and
  `28e82507-35b9-4a22-a8dd-7fa324300215`, and all sixteen deterministic fork
  databases are retained as the pre-fix and deployed-fix matrix witnesses.
- Demo block storage is bind-mounted read/write into the existing backup-storage
  volume only at `/backups/bs-remed-large-0d08dcf`; its source is
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/large-local-storage`.
  `findmnt` resolves the bind to `/dev/vdb1` and the volume had 930 GB free after the
  1 GB gate. Existing destination paths were not changed. Signed-in storage `10` /
  local row `2`, named `bs-remed-20260818-0d08dcf-large-block`, uses relative path
  `bs-remed-large-0d08dcf`, has `no_delete=true`, and passed UI validation.
- PostgreSQL source `48` / node `97`, named
  `bs-remed-20260818-0d08dcf PostgreSQL 1GB`, reuses connection/auth `71`/`50`,
  selects only `bs_remed_pg_lg1_0d08dcf`, and has no schedule. The source contains
  exactly 1,000,000 deterministic 1,037-byte payload rows; its measured database and
  relation sizes before backup were 1,200,864,279 and 1,193,099,264 bytes.
  Signed-in backup `70`/point `74`, UUID
  `bs-bs-remed-20260818-0d08dc-n97-b70`, completed to storage `10` at 801,978,786
  bytes. Its mode-0600 block-storage ZIP has SHA-256
  `1de06b43a0385dcaaa5fba893a62f9a1f907e36650524ce3ab7804650e19b9d0`,
  passes CRC, and contains only the 1,057,890,529-byte SQL entry and
  `backupsheep.txt`.
- Exact-owned restore `65`, correlation
  `5371f447-5dc3-41b7-b7f4-771dc6fe97ea`, targets
  `bs_restore_5371f4475dc3_bs_remed_pg_lg1_0d08dc_344980b83ff8`. It completed as
  attempt 1 with one complete file/target checkpoint, no error, retry, or live lease.
  The target fork, source, archive, product rows, and block-storage artifact are
  retained as the 1 GB witness.
- PostgreSQL source `49` / node `98`, named
  `bs-remed-20260818-0d08dcf PostgreSQL 5GB`, also reuses connection/auth `71`/`50`,
  selects only `bs_remed_pg_lg5_0d08dcf`, and has no schedule. The source contains
  exactly 5,000,000 deterministic 1,037-byte payload rows; its measured database and
  relation sizes before backup were 5,973,023,767 and 5,965,258,752 bytes.
  Signed-in backup `71`/point `75`, UUID
  `bs-bs-remed-20260818-0d08dc-n98-b71`, completed to storage `10` at 4,010,171,167
  bytes in one upload attempt. Its mode-0600 block-storage ZIP has SHA-256
  `0341551cdaed77c3555bcc950dffcc74efd3fdd87f4ebbfaf4d308cc948d192b`,
  passes CRC, and contains only the 5,293,890,529-byte SQL entry and
  `backupsheep.txt`.
- Exact-owned restore `66`, correlation
  `60bbe408-4020-49c6-9b54-156f9739a98b`, targets
  `bs_restore_60bbe4084020_bs_remed_pg_lg5_0d08dc_b028b5c2055a`. It completed as
  attempt 1 with one complete file/target checkpoint, no error, retry, or live lease.
  The target fork, source, archive, product rows, and block-storage artifact are
  retained as the 5 GB witness.
- MariaDB multi-database connection/auth `72` uses a dedicated exact-owned SSH user,
  key, and MariaDB account on the existing run-scoped Vultr fixture. Its node/source
  `99` selects only `bs_remed_maria_matrix_{tiny,medium,large,manytables,blobs,unicode,objects,mutable}_0d08dcf`
  and has no schedule; the pre-existing connection `63` and its source remain
  unchanged. The eight source families cover three-row/view, related-table/FK,
  1,000,000-row, 400-table, 8 MiB binary/2 MiB text, byte-exact Unicode, full
  object/event/sequence, and mutable-generation cases. MariaDB's global event
  scheduler remained `OFF` during setup and generation changes.
- Node `99` has generation-1 backup `72`/point `76`, UUID
  `bs-bs-remed-20260818-0d08dc-n99-b72`, 43,030,979 bytes, artifact SHA-256
  `5fe5580b555bd1b38881ac6fb8b5ef5b3132890262a0aa059f10f9eef115c978`;
  and generation-2 backup `73`/point `77`, UUID
  `bs-bs-remed-20260818-0d08dc-n99-b73`, 43,031,121 bytes, artifact SHA-256
  `c863e4a81ee163fe263677bf083c3df0f134137487e440de19d26a0af441247f`.
  Each completed in one attempt to local storage `9`, is mode `0600`, passes ZIP
  CRC, and contains exactly eight SQL files plus `backupsheep.txt`. Between the two
  archives only the mutable family changed: generation 2 has 115 distinct rows,
  85 generation-1 rows, 30 generation-2 rows, no rows 91–95, twenty rows 101–120,
  ten exact updates, and ordered-row SHA-256
  `54f56289c0b6dfcb96036b4f0988373ab8cc5c16cd658f860282d90d1c8f15ba`.
- Signed-in generation-2 restore `67`, correlation
  `34c52a31-7c9f-4991-8524-00d5ed1d0a09`, locked an immutable eight-source target
  mapping and exact per-file digests. Attempt 1 rendered Validating 0/8, Restoring
  1/8 and 3/8, then failed safely at 5/8 while importing the object family. The first
  five targets/files were exact and complete; the object target retained only its
  exact importing marker plus the pre-error partial inventory, and tiny/Unicode had
  not started. The 108,891,075-byte one-million-row SQL file sustained about 306
  single-row inserts/second and made the attempt exceed RabbitMQ's 30-minute consumer
  acknowledgement timeout; the redelivered delivery was a durable no-op after the
  failed row. This broker timeout is recorded as a separate Slice 10/16 observation,
  not hidden as a restore pass.
- Commit `0220727` was deployed, and `SET USER` was then granted only to exact-owned
  disposable account `bs_matrix_0d08dcf`; the global scheduler remained `OFF`. The
  signed-in `Resume verification` action retained restore `67`, recorded one
  `logical_fork_reconciliation` resume and task `database-restore-resume-67-1`, and
  rendered Recovering/reconciling at 5/8. Attempt 2 re-read and adopted the five exact
  complete markers without importing them, rechecked ownership and rebuilt only the
  partial object target, then created tiny and Unicode. It completed in 21.557 seconds
  at 8/8 with eight complete file/target checkpoints, no error, retry, or live lease.
- Source and fork verification matches for every family: tiny/medium/large/many-table/
  blob/Unicode/object/mutable normalized data and schema SHA-256 values are identical;
  the large family has 1,000,000 exact rows; blobs retain exact 8 MiB/2 MiB hashes;
  the object family has the required PK/FK/index/view/trigger/function/procedure/event/
  sequence inventory; and mutable generation 2 has the exact 115-row delta and
  `54f56289c0b6dfcb96036b4f0988373ab8cc5c16cd658f860282d90d1c8f15ba` row hash.
  All eight sole marker rows match correlation, backup UUID, source, target, digest,
  version, and `complete` state. Scheduler is `OFF`, remote restore-temp and local
  preflight-credential residue are zero, and the signed-in modal exposes Complete only
  at 8/8.
- MariaDB 5 GB source `51` / node `100`, named
  `bs-remed-20260818-0d08dcf MariaDB 5GB`, reuses connection/auth `72` and selects
  only `bs_remed_maria_lg5_0d08dcf`; it has no schedule. The source was generated
  entirely on the owned Vultr host and contains exactly 5,000,000 distinct IDs,
  min/max `0`/`4,999,999`, ID sum `12,499,997,500,000`, and exact 1,037-byte
  incompressible payloads. The measured InnoDB table is 5,858,394,112 bytes. Its
  full canonical row-stream SHA-256 is
  `99281fb30c37db403aa55ac7f871f28a37aa876f4f5ed88275db4c8d3bcddf10` and
  normalized schema SHA-256 is
  `c4fb6718ec3b1b4dcfca6fff75fbe1c23d8a3c857e70c326c9e9fb16c82081c8`.
- Signed-in backup `74` / point `78`, UUID
  `bs-bs-remed-20260818-0d08dc-n100-b74`, completed in one attempt to storage `10`.
  Its mode-0600 block-storage ZIP is 3,962,075,387 bytes with SHA-256
  `90f3d91d2740e87a1b2dad42bff90b0ebbfcc5c8f66423177c7128262cbe63b4`.
  Independent `unzip -t` passed; the archive contains exactly the
  5,378,891,089-byte `bs_remed_maria_lg5_0d08dcf.sql` entry and 190-byte
  `backupsheep.txt`. Source and destination artifact ledgers have the same byte
  count/checksum and verified timestamps; the backup has no live lease or error.
- Signed-in safe-fork restore `68`, correlation
  `a305b6bb-a4fb-4408-ad34-d7a6013af357`, started at
  `2026-08-19T03:38:39Z` with immutable target
  `bs_restore_a305b6bba4fb_bs_remed_maria_lg5_0d0_959807f8e2f2`. Source
  validation recorded the exact 5,378,891,089-byte SQL entry with SHA-256
  `ad2f334af5b0dcd5e1179ed3ec4e8f195125c75ea1276fdd3a79610284207b76`
  and source digest
  `6b9f4a5b56de5a04c2d7d5e94e9730b4b659c9febe3212e8cde250e0f634de29`.
  It completed at `2026-08-19T07:33:12Z` on the same logical row and attempt 1,
  progress 1/1, with no error, retry, or remaining lease. Source and fork each have
  exactly 5,000,000 distinct keys, min/max `0`/`4,999,999`, key sum
  `12,499,997,500,000`, and exactly 5,185,000,000 payload bytes at 1,037 bytes per
  row. All seven deterministic MD5/SHA-256 samples match. An ordered full-coverage
  digest of every key plus every payload SHA-256 is identical on both sides at
  `a30683ea08b932e9e1bf9ba8985a477b4afbec980374679b9e84cf65201bd7c0`.
  Exact `SHOW CREATE TABLE` text is equal with SHA-256
  `0bc89d389e203fb031889c4d928a75090033fbeec4f7f6f674a4fb5c69efc929`;
  this is an additional comparison beside the previously recorded normalized source
  schema digest. The sole marker exactly matches correlation, backup UUID, source,
  target, source digest, and `complete` state. Scheduler remains `OFF`, remote restore
  residue is zero, and the database queue is `0/0` with one consumer. The signed-in
  terminal modal was subsequently observed at Complete, phase Complete, progress 1/1;
  no active or reserved database task remained.
- At `2026-08-19T04:08:39Z`, exactly 1,800 seconds after task receipt, RabbitMQ
  enforced its configured `consumer_timeout=1800000`: delivery tag `7` raised
  `PRECONDITION_FAILED` and stopped the database worker's consumer. The fenced task
  child and its one remote MariaDB client remained alive, continued the same target
  import, and kept renewing restore `68`'s lease; no second restore row or attempt was
  created. The same broker delivery became ready while the database queue had zero
  consumers (`ready=1`, `unacknowledged=0`, `consumers=0`). At final import commit,
  the task durably completed row `68`, released its lease, and the database worker
  re-established a consumer. The queued original delivery then drained as a terminal
  no-op: restore count remained one, attempt count remained one, and the database
  queue converged to `0/0/1` without a second provider mutation.
- Revision `2bda859aa920916825252151a9be24bde46e77a4` mounts
  `deploy/rabbitmq/90-backupsheep.conf` read-only and raises RabbitMQ's
  acknowledgement timeout to 90,000,000 ms (25 hours), two hours beyond the
  application's longest 23-hour external-command budget. Six focused broker-setting
  tests pass in the remote application image; Docker Compose resolves the exact
  read-only mount; and an isolated, resource-limited RabbitMQ 3.13 runtime returned
  `{ok,90000000}` from its live `consumer_timeout` query. It is now deployed and the
  live broker returns `{ok,90000000}` before and after controlled recreation. This
  timeout change addressed the reproduced premature acknowledgement failure only. At
  that checkpoint the capacity, queue-latency, queued-state, and concurrency-policy
  gates remained open; the later request `155`, backups `92`/`93`, and 2026-08-20
  minimum-host capacity record below supersede that checkpoint and close Slice 16.
- The first broker recreation exposed an independent Compose durability defect: the
  named `backupsheep_rabbitmq_data` volume was preserved, but RabbitMQ used the new
  container ID as its node hostname and opened a new empty Mnesia directory. The
  stopped 1.1 MiB volume was preserved at
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
  `rabbitmq-volume-pre-recovery-20260819T075443Z.tgz`, mode `0600`, 55,251 bytes,
  SHA-256 `dc072aa714856dcd0d09a2183aed96c5caee03c760916915494ac9b27b7aee85`.
  Starting a temporary broker under the exact prior node identity recovered the six
  durable queues and the one pending cloud reconciliation delivery. Its corresponding
  PostgreSQL row (`CoreOracleBackup` `8`) remained `Delete In-Progress`, due, and
  lease-free, so the new stable broker could safely rely on the existing bounded
  recovery sweep rather than replaying an unknown provider write.
- Revision `f4cf2d06c1fc1ef8a01e7fe13a295b3371c9268a` fixes the broker hostname to the
  stable, resolvable Compose service name `rabbitmq` and adds a source-level regression
  assertion. Seven focused broker tests pass. The exact image
  `sha256:37a0066e3a8b2ba177e9a93777be49098fb96a395ee51fd78d8adb09b63ec746`
  also passes the combined 429/429 deployment regression batch, Django checks, and
  migration-drift checks. It is deployed across app, all five workers, and Beat; the
  broker runs as `rabbit@rabbitmq` on the original named volume. A recovered durable
  cloud delivery remained exactly one (`0 ready / 1 unacknowledged`) across a second
  controlled broker recreation, all five workers reconnected, and local/public health
  both returned `ok`.
- Backup `64` now also has exact-owned restores `51`, `52`, and `53`. Restore `51` is
  the pre-client kill/replay gate; restore `52` is a clean non-fault baseline from the
  first lost-response instrumentation attempt; restore `53` is the committed-marker
  lost-response/adoption gate. Their deterministic fork databases are retained with
  the rest of the run-scoped evidence.
- PostgreSQL SSH backup `63` now also has terminal test restores `60` and `61`.
  Restore `60`, correlation `2a030bab-439c-4b41-a525-081950731f1f`, targets retained
  markerless database `bs_restore_2a030bab439c_pg_tiny_2208b78613f0`. Restore `61`,
  correlation `fb9c1512-8652-456e-bfa5-5317da02d0fd`, targets retained forged-marker
  database `bs_restore_fb9c15128652_pg_tiny_2208b78613f0`. These are run-scoped
  foreign collision fixtures rather than BackupSheep-owned restore targets; no
  cleanup, adoption, or target mutation was attempted.
- MariaDB SSH backup `67` (`bs-bs-remed-20260818-0d08dc-n92-b67`), point `71`,
  4,717,147-byte ZIP with SHA-256
  `c633173200c12b14da85b500e8834bdc05f5c09bef5f356bef42dc0ca3899a49`,
  has exact-owned restores `54` and `55`. Their correlations are
  `272fd21e-3189-4435-8322-b88b0ed3bccb` and
  `889f6d7f-bc66-4516-a05c-0d57dd52b24f`; their deterministic fork databases and the
  retained `maria_tiny.bs_remed_crash_probe` 100,000-row source remain evidence for
  the post-client/lost-response and pre-client recovery boundaries.
- MariaDB SSH object/event backup `66` now also has exact-owned restore `56`,
  correlation `fb292c7c-61ef-43ad-8934-e900093d95d0`, target
  `bs_restore_fb292c7c61ef_maria_tiny_4ffef62a1a97`. It is retained as the
  post-marker/pre-final-status adoption witness alongside baseline restore `50` from
  the same immutable artifact.
- Backup `66` also has terminal test restores `57`, `58`, and `59`. Restore `57`
  reproduced the old generic markerless-client classification against retained
  foreign target `bs_restore_23ce01f7a1ed_maria_tiny_4ffef62a1a97`. Restore `58`,
  correlation `a15f0f59-4efa-49f3-aa6a-79291ec560db`, proves the deployed classifier
  against retained foreign target
  `bs_restore_a15f0f594efa_maria_tiny_4ffef62a1a97`. Restore `59`, correlation
  `33d61d71-4f58-42e9-ada0-e70756a60bd9`, proves a structurally valid but
  mismatched marker fails closed in retained target
  `bs_restore_33d61d714f58_maria_tiny_4ffef62a1a97`. These run-scoped collision
  fixtures are intentionally not BackupSheep-owned restore targets and are retained;
  no cleanup or adoption was attempted.
- Backup `66` also has exact-owned restore `62`, correlation
  `cabaec95-94f8-4bd0-84a4-a460645541ae`, target
  `bs_restore_cabaec9594f8_maria_tiny_4ffef62a1a97`. This is the controlled
  import-error/manual-resume witness. It remains one logical row with one recorded
  manual resume, attempt count 2, an exact complete target checkpoint, and no active
  lease, retry, or error. The deterministic fork is retained with the other
  run-scoped product evidence.
- The event-fidelity additions are disabled exact-owned events named
  `bs_remed_20260818_0d08dcf_event` in `mysql_tiny` and `maria_tiny`, plus the MariaDB
  PK/FK/index/view/trigger/procedure/function fixture. MySQL restricted validation
  connection/auth `69`/`48` uses exact-owned user `bs_event_limited_0d08dcf`, which
  has object-read grants and deliberately has no global or database `EVENT` grant.
  Its generated credential remains only in mode-0600 demo-side file
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/mysql_event_limited.pass`;
  it was never printed or downloaded.
- MariaDB missing-client validation connection/auth `70`/`49` uses exact-owned SSH
  user `bsnodb_0d08dcf`. That user's run-scoped login shell exposes an empty client
  path while preserving key authentication, SFTP, and the existing database tunnel.
  No node or backup is attached to connection `70`.
- The SSH host key was approved through BackupSheep's preview/approval flow only after
  matching independently recorded Ed25519 fingerprint
  `SHA256:fOqPRunwMb1PO80U4tbWIm87IjId/9LFpHiZ5OncrZE`.
- Historical website backup `38` now has signed-in restore `20`, correlation
  `e4915cd0-4cb6-4b9f-9c53-f3c1d0582747`. Its first post-deployment attempt was
  restore `19`; that row failed safely because the test fixture's bind-mounted target
  could not be renamed, not because the compatibility reader rejected the archive.
  The fixture was then isolated without deleting the original, and restore `20`
  completed. Both original and restored 15-entry trees are retained.
- Deep-tree node `101`, backup `41`, point `43`, and restore `21` are retained with
  their exact-owned source and restored trees. The pre-fix assertion witness is
  cancelled backup `40`; it cannot replay. The compact product artifact is 970,666
  bytes and the original source was moved aside recoverably before restore.
- Persistent MySQL TLS connection/auth `73`/`52` and node `102` use the exact-owned
  `REQUIRE SSL` fixture account and select `mysql_tiny` with stored procedures/events
  intentionally disabled. Backup `75`, point `79`, restores `69`–`71`, the completed
  restore `71` fork, and two failed exact-owned diagnostic forks are retained. The
  fixture account's temporary broad unescaped wildcard grant was revoked; its final
  database scope is the exact escaped run wildcard plus the global privileges needed
  for the selected object's definers and MySQL binary-log policy. The protected
  credential remains remote, mode 0600, and was never printed or downloaded.
- MySQL 1M connection/auth/node/source `75`/`54`/`103`/`53`, named
  `bs-remed-20260818-0d08dcf MySQL 1M crash`, uses TLS, selects only
  `bs_remed_mysql_lg1_0d08dcf`, excludes stored procedures by policy, and has no
  schedule. The source was generated entirely on the owned Vultr fixture and contains
  exactly 1,000,000 rows/distinct IDs, min/max `0`/`999,999`, ID sum
  `499,999,500,000`, and 1,037,000,000 payload bytes. Its InnoDB table is
  1,172,307,968 bytes. The full ordered `id` plus payload-SHA-256 stream is 71,888,890
  bytes with SHA-256
  `e8c356259d8934f396b32fd895502d4d9e3b72c3fcd95a6e7ad5d55f947e1cb9`.
- Signed-in backup `76`/point `80`, UUID
  `bs-bs-remed-20260818-0d08dc-n103-b76`, completed in one attempt to storage `10`.
  Its mode-0600 block-storage ZIP is 53,396,706 bytes with SHA-256
  `ff76262838b444bb34e5fba775f188f0cfeba4e34654ddaaa643b2cfbda5a6e6`; CRC passes.
  The 1,084,928,638-byte SQL entry has SHA-256
  `6d9c2dd148f9b5d79fc2c7ba0e402a32ccd7458aa4f1a9782031f4ee91e0f551`.
  The persisted writer contract is `--single-transaction --column-statistics=0
  --set-gtid-purged=OFF --no-tablespaces --max_allowed_packet=512M
  --extended-insert`.
- Normal signed-in restore `72`, correlation
  `58fabd32-6d72-4d20-8b33-0c7a498e24ee`, completed once to exact-owned target
  `bs_restore_58fabd326d72_bs_remed_mysql_lg1_0d0_c5648735361b` and is retained as
  the baseline. Fault restore `73`, correlation
  `6c24805c-b315-47ae-96ac-d06ca061098f`, was hard-killed with 211,012 committed rows
  visible and later completed once as attempt 2 with exact data/schema/marker/UI
  evidence. That first live repetition exposed one remaining local-cleanup defect:
  its crashed fence generation `00f4fbcb85ea7de6` retained an extracted tree, ZIP,
  and MySQL defaults file even though the successful generation cleaned itself.
- After deploying `d547501`, signed-in fault restore `74`, correlation
  `61d32739-c989-4ad8-9369-13f5a4074406`, reused immutable backup `76` and target
  `bs_restore_61d32739c989_bs_remed_mysql_lg1_0d0_c5648735361b`. Only
  `worker-database` was hard-killed during `database_importing_file`, with 962,152
  committed rows and an exact `importing` marker visible. The durable row stayed
  attempt 1/0-of-1 until natural lease expiry, then recorded one stale takeover with
  prior work suffix `b6ff864dc68c758f`, rebuilt only its exact-owned fork as attempt
  2, and completed at 1/1. Source and fork match exactly on count/distinct/min/max/sum/
  payload bytes, view output, fixture metadata hash, normalized column/index/table
  hashes, and the full ordered digest above. The exact marker is `complete`; the two
  queued generation-cleanup tasks succeeded; targeted restore residue is zero; and
  only the retained logs and phase lock remain. Performance Schema statement-history
  instrumentation was returned to `NO` after the gate.
- MySQL all-database connection/auth/node/source `77`/`56`/`104`/`54`, named
  `bs-remed-20260818-0d08dcf MySQL 8-family matrix`, selects exactly the run-scoped
  `tiny`, `medium`, `large`, `manytables`, `blobs`, `unicode`, `objects`, and
  `mutable` databases. The MySQL server is `8.4.11` with scheduler `ON`. The fixture
  includes three tiny rows; the related medium cardinalities
  `1000/9999/10000/5000/1000/4000/4000/1000` with zero orphans; exactly 1,000,000
  large rows; 400 tables; exact 8 MiB binary and 2 MiB text values; eight byte-exact
  Unicode rows; PK/FK/index/view/trigger/procedure/function/disabled-event objects;
  and a mutable generation-2 set with 115 rows after ten updates, five deletes, and
  twenty inserts.
- Cancelled signed-in backup `77`/point `81` is retained as the original direct
  multi-database `source_export_failed` witness. Contract-v1 generation backups
  `78`/point `82` and `79`/point `83` completed at 41,799,257 and 41,799,392 bytes
  with artifact SHA-256
  `f7fd8044bd8244ddfacea0e16a19897d3801fb8a040b68065709080a6b8ab36f` and
  `d419740521df892d293d0c8d9ec5991dc71e37bb07abf8cfd3eb0588f0da223e`.
  Each is CRC-clean and contains exactly eight SQL members plus `backupsheep.txt`.
  Restore `80`, correlation `0bbcb251-36c9-4c3d-9d0f-82c7fd0f454f`, completed all
  eight targets with exact data/objects, but live verification exposed that their
  database defaults had drifted from source `utf8mb4_unicode_ci` to server default
  `utf8mb4_0900_ai_ci`. That result is retained as a negative schema-fidelity witness,
  not counted as final acceptance.
- Contract-v2 backup `80`/point `84` proved that all eight authenticated defaults were
  recorded, but live archive inspection found its preamble at the end of each SQL
  member because the Python stream buffer had not been flushed before the child dump
  subprocess wrote. Its CRC-clean 41,799,618-byte artifact, SHA-256
  `e4bb4e577134b53dcb9821f91c9d3ce7845d8a5b3b2041c3e848c1ae0c39dba9`, is
  retained as the exact buffering witness and is not the accepted matrix artifact.
- After the flush fix, contract-v2 backup `81`/point `85`, UUID
  `bs-bs-remed-20260818-0d08dc-n104-b81`, completed at 41,799,525 bytes. Its
  mode-0600, CRC-clean artifact has SHA-256
  `513c13126a00490ff15de8e98c2348c8f1849154c0d8f759438fdfcd2fdd4f48`;
  source and destination metadata agree, and every SQL member begins exactly with
  `ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`. First restore
  `81`, correlation `ff9e11ee-5cfe-41a8-a7eb-4fb72cec7529`, failed safely during
  validation at 0/8 because the prior restore allowlist rejected every
  `ALTER DATABASE`; it returned the public integrity error, retained its locked
  target mapping, and changed no target.
- On deployed `ee8ec34`, signed-in restore `82`, correlation
  `cdc668aa-0c88-428d-a69a-2a0b399ca859`, completed once from Validating 0/8 through
  Restoring 0/8, 1/8, 2/8, and 7/8 to Complete 8/8. All eight fork databases now have
  source-equal `utf8mb4`/`utf8mb4_unicode_ci` defaults and exact counts, aggregates,
  binary/text hashes, Unicode rows, tables, indexes, constraints, views, routines,
  trigger, disabled event, mutable delta, and complete markers. An independent
  source/fork verifier normalizes only MySQL's redundant rendering of
  `CHARACTER SET <same-token> COLLATE` in `SHOW CREATE`; the complete eight-family
  evidence is then byte-for-byte equal with SHA-256
  `062aa0bb7874ca5c50cf126fe6e29b13b899ca797061b48eceec27757a297eaf`.
- The restore-preflight source/test overlay is retained under
  `candidates/mysql-restore-preflight-20260819/`. It contains no backup payload or
  credential. Both isolated candidate database pairs and the scratch trigger probe
  schema were removed after exact ownership checks.

#### Product backup/restore evidence

| Gate | Backup / restore evidence | Exact verification | Result |
| --- | --- | --- | --- |
| PostgreSQL 16 current artifact | Backup `56`, point `60`, ZIP SHA-256 `22696645571e3deae13a7edc33d397bf7d4c8c5c7ec427383cccac8a471b035d`; restore `37` to `bs_restore_7f3d0fbdcaa1_pg_tiny_2208b78613f0` | Persisted options are `-w --clean --if-exists`; SQL contains `DROP TABLE/VIEW IF EXISTS`; source and fork each have 3 rows and 3 view rows with digest `9d4aeae23ac956affa844bf3a2880c0124b184bab0b1087dd660ef400525b36d` | **Pass for this new direct-mode tiny artifact** |
| PostgreSQL 16 historical `--clean` artifact | Backup `58`; restore `40` through the deployed product path | The bounded preflight accepted only recognized database-local cleanup statements, added compatibility only for the new exact-owned fork, retained `ON_ERROR_STOP` and a single transaction, and produced exact rows and required objects | **Pass for this historical direct-mode tiny artifact** |
| PostgreSQL 16 current SSH artifact | Backup `63`, point `67`, ZIP SHA-256 `fb3dc2c67a391aa153279388e5e1de7d78884461f5783df517067ebeea317ac9`; restore `45` to `bs_restore_3fb55bd50988_pg_tiny_2208b78613f0` | ZIP CRC passes; persisted options are `-w --clean --if-exists` and the dump contains both recognized `DROP ... IF EXISTS` statements. Source/fork each have 3 rows, 3 distinct IDs, and 3 view rows with canonical digest `89c2744833ef4351242249e928f0732a793b3c9324b563c4a9b069c3d1b1f40a`. Relation/index/constraint inventories match and the sole marker row is exact | **Pass for this SSH-mode tiny artifact** |
| PostgreSQL markerless collision | Backup `63`; restore `60`, correlation `2a030bab-439c-4b41-a525-081950731f1f`, target `bs_restore_2a030bab439c_pg_tiny_2208b78613f0` | The deployed restore returned public `RESTORE_RECONCILIATION_REQUIRED`, terminal `failed`, `can_resume_verification=false`, with no target checkpoint. Before and after, the target contained only `public.foreign_sentinel`; witness `bs-remed-pg-markerless-collision-0d08dcf` retained SHA-256 `e7929de4a84a5dc1b5730af96642ffd4f7a1d9c64ea303c16dfcceea57ba5117`. No create, drop, marker claim, or import occurred | **Pass for deployed PostgreSQL markerless collision behavior** |
| PostgreSQL forged-marker collision | Backup `63`; restore `61`, correlation `fb9c1512-8652-456e-bfa5-5317da02d0fd`, target `bs_restore_fb9c15128652_pg_tiny_2208b78613f0` | A run-scoped target was precreated with `public.foreign_sentinel` and a structurally valid `__backupsheep_restore.marker` row whose correlation was deliberately `00000000-0000-4000-8000-000000000061`. The deployed restore returned public `RESTORE_RECONCILIATION_REQUIRED`, terminal `failed`, `can_resume_verification=false`, with no target checkpoint. Sentinel SHA-256 `3341023c9ad46ca8539983e53e2beb5e7bdcfbc3ea2ce6cf1b6025c1dd101bb5`, marker SHA-256 `e895cad424ec873a65574145f2fc19e66466c7acbd04f78e30bf4f1de99948ff`, and the exact two-table inventory were unchanged | **Pass for PostgreSQL forged-marker fail-closed/no-mutation behavior** |
| PostgreSQL 16 SSH 1M worker kill | Backup `64`, point `68`, 45,123,255-byte ZIP, SHA-256 `b9aee5d2cb619b9e543b215cc59d28900faafdec042f9c91c3061320083444dc`; clean baseline restores `46`/`47`; fault restore `48`, correlation `48917237-ff4d-4182-95be-9641afdfc584`, target `bs_restore_48917237ff4d_bs_remed_pg_crash_0d08_bd2d3e7b9ffc` | Worker was killed two seconds after `database_importing` on attempt 1. The exact marker remained `importing` and `public.crash_probe` was not visible, proving the interrupted transaction exposed no partial table. One stale-lease takeover replayed the transaction as attempt 2. Source/fork each have 1,000,000 rows and distinct IDs, min/max 1/1,000,000, sum IDs 500,000,500,000, hash sum `2004767769598567751901`, full-coverage 256-bucket digest `4143b55792a19ae2fb3ee71b97b80e9417b3224b9626aef146d4282d1032054e`, matching sampled digest, Unicode/binary rows, view/audit, seven constraints, seven indexes, two sequences, functions, trigger, and exact `complete` marker | **Pass for PostgreSQL 1M mid-import kill/replay; the normal UI-matrix gate passed in restore `64`, and later 10/25 GB-class gates pass in restores `93`/`90`** |
| PostgreSQL 16 SSH 1M pre-client kill | Restore `51`, correlation `0391d618-3865-40b0-9bf2-6cae6e9a5518`, target `bs_restore_0391d6183865_bs_remed_pg_crash_0d08_bd2d3e7b9ffc` | The worker was killed after the durable `database_importing`/file `in_progress` checkpoint while no `psql --single-transaction` process existed. The marker was `importing` and `crash_probe` was absent. One natural stale-lease takeover replayed attempt 2 and completed. Source/fork match at 1,000,000 count/distinct, min/max 1/1,000,000, ID sum 500,000,500,000, hash sum `8571929584914099601309`, and full-coverage 256-bucket digest `327633680958e6a32d6a3fa5bca1a149`. Small-data digest `461d1a83e26be32fbe12f3525a0af7b7`, 25-object digest `77c7da8ae44c45798553ff30db1f9524`, and two-sequence digest `e9d828ea8a07e37b784df60c35eb8fb8` also match; remote temp count is zero | **Pass for the PostgreSQL pre-client kill/replay boundary** |
| PostgreSQL 16 SSH 1M committed-marker lost response | Restore `53`, correlation `465e91c7-e4ef-4473-b865-30ccce6c7709`, target `bs_restore_465e91c7e4ef_bs_remed_pg_crash_0d08_bd2d3e7b9ffc` | A run-scoped client shim held the successful response only after real `psql` returned zero. At kill time the database marker was `complete`, while the durable row still showed attempt 1, `database_importing`, 0/1 and two remote temp files. One natural takeover completed attempt 2 with checkpoint `adopted=true` and no transaction replay. All 1M, small-data, object, and sequence digests match the source values in the preceding row; the exact marker is complete and remote temp count is zero. The temporary shim/trigger were removed and `/usr/bin/psql 16.15` is again authoritative | **Pass for post-commit lost response and exact marker adoption without re-import** |
| PostgreSQL 16 eight-family UI matrix and component-phase polling | Generation-1 backup `68`/point `72`; mutable generation-2 backup `69`/point `73`; pre-fix restore `63`; deployed `f9669c5` restore `64`, correlation `28e82507-35b9-4a22-a8dd-7fa324300215` | Both artifacts completed through the signed-in UI; backup `69` passes CRC and contains exactly eight SQL files plus its metadata entry. Pre-fix restore `63` exposed `Complete · 5/8` while its worker was still running, although its durable row later correctly reached 8/8. After the public-phase fix, the signed-in modal for restore `64` remained Actively running at Validating 0/8 and Restoring 0/8, 1/8, 3/8, and 7/8, then changed to Complete only at 8/8. The row is attempt 1 with eight complete target/file checkpoints, no lease/retry/error, source-equal normalized data and schema hashes for all eight families, and eight exact complete markers bound to this correlation and backup `69`. Fixture temp residue is zero | **Pass for PostgreSQL tiny/medium/1M/many-table/blob/Unicode/object/mutable UI restore and deployed terminal polling; scale evidence continues in the following rows** |
| PostgreSQL 16 1 GB signed-in backup/restore | Source/node `48`/`97`; backup `70`/point `74`, UUID `bs-bs-remed-20260818-0d08dc-n97-b70`; restore `65`, correlation `5371f447-5dc3-41b7-b7f4-771dc6fe97ea` | The 1.20 GB source database produced an 801,978,786-byte mode-0600 block-storage ZIP with SHA-256 `1de06b43a0385dcaaa5fba893a62f9a1f907e36650524ce3ab7804650e19b9d0`; CRC passes and the ZIP has exactly one 1,057,890,529-byte SQL entry plus metadata. The signed-in restore modal progressed through active validation/restoration and rendered Complete only at 1/1. Source/fork each contain 1,000,000 distinct IDs, min/max 0/999,999, sum 499,999,500,000, and exact 1,037-byte payloads. Their full-coverage 256-bucket digest is `e65fa0caee60a5bd6e56ea170298221e5e6c27cd5f3f63f4f734149b92594fa3`; all seven sampled payload hashes and normalized schema SHA-256 `c7da4dd2c41f71cc4c20bb55974ce6840156b87a1e88c341ad54097e788b3e20` match. The sole marker is exact/complete and fixture/demo targeted temp residue is zero | **Pass for the PostgreSQL 1 GB product gate** |
| PostgreSQL 16 5 GB signed-in backup/restore | Source/node `49`/`98`; backup `71`/point `75`, UUID `bs-bs-remed-20260818-0d08dc-n98-b71`; restore `66`, correlation `60bbe408-4020-49c6-9b54-156f9739a98b` | The 5.973 GB source database produced a 4,010,171,167-byte mode-0600 block-storage ZIP with SHA-256 `0341551cdaed77c3555bcc950dffcc74efd3fdd87f4ebbfaf4d308cc948d192b`; CRC passes and the ZIP has exactly one 5,293,890,529-byte SQL entry plus metadata. Before commit, durable phase/file/target states were `database_importing`/`in_progress`/`importing`, marker state was `importing`, the UI remained Actively running at 0/1, and `public.big` was invisible. The signed-in modal rendered Complete only after atomic commit at 1/1. Source/fork each contain 5,000,000 distinct IDs, min/max 0/4,999,999, sum 12,499,997,500,000, and exact 1,037-byte payloads. Their full-coverage 256-bucket digest is `93c588095a48c259c3a1284911ee95a55923eb19d2cbc0a3e51712fcb40d906b`; all seven sampled payload hashes and normalized schema SHA-256 `c7da4dd2c41f71cc4c20bb55974ce6840156b87a1e88c341ad54097e788b3e20` match. The sole marker is exact/complete and fixture/demo payload residue is zero | **Pass for the PostgreSQL 5 GB product gate; separate 10/25 GB-class claims pass in restores `93`/`90`** |
| MariaDB 11.8 current artifact | Backup `57`, point `61`, ZIP SHA-256 `2fa4a533b0f1f39f45c09f07f1c7d1db42a64ee1446fbd15a373f365b9845ee7`; first restore `38` failed pre-mutation; restore `39` completed to `bs_restore_0caba3f13390_maria_tiny_4ffef62a1a97` | Exact sandbox header preserved. Failure `38` exposed the legitimate vendor `AUTOCOMMIT off → COMMIT → AUTOCOMMIT restore` wrapper; the failed target was absent. After the bounded fix, source and fork each have 3 rows and 3 view rows with digest `58748a0e5153098a88ab8e49972eeea4ef39fbbadd39a6614da72f300a17b5ea` | **Pass for this new direct-mode tiny artifact** |
| MariaDB 11.8 SSH artifact after capability deployment | Backup `60`, point `64`, ZIP SHA-256 `399473b982bb4958cea49a117e26559feda712bcccb83a635ca17308c7eb889a`; restore `42` to `bs_restore_cd6bbf729e70_maria_tiny_4ffef62a1a97` | Dump has the exact sandbox header and identifies MariaDB dump 10.19/10.11.14. Source/fork have 3 exact rows and 3 view rows with canonical digest `94c914e5e4c03b95fc03b2d67fdd8375eae8f3b80e44eb082a9cc5b0eac0`; completion marker is exact | **Pass for this SSH-mode tiny artifact** |
| MariaDB 11.8 full objects and event | Backup request `99eaa5b1-7b5e-4b53-92bd-1dbdf8e3d28b`, backup `66` (`bs-bs-remed-20260818-0d08dc-n92-b66`), point `70`, 2,698-byte ZIP, SHA-256 `83a8ecbb06bcbcd5432402f15a21cb46051763bab37dc3e36d875c45e897a933`; restore `50`, correlation `c97673a4-54f6-409b-8d44-1badec152d9e`, target `bs_restore_c97673a454f6_maria_tiny_4ffef62a1a97` | CRC passes. Source/fork data digest is `88150bca8e19a927d57ec1ed973b7ca776fe4ce784da4e8b7cb98f73b01f1572`; canonical object digest is `8c101bf3d66121c9ae5d95f182f81d1a1c51d30a2a3ba172a6a96dccfc607678`. The fork has PK/FK, three non-primary indexes, two views, one trigger, function, procedure, exact disabled event, and exact completion marker. The global scheduler remained `OFF` | **Pass for the MariaDB Slice 11 object/event gate** |
| MariaDB 11.8 SSH post-client/lost-response kill | Backup `67`, point `71`; restore `54`, correlation `272fd21e-3189-4435-8322-b88b0ed3bccb`, target `bs_restore_272fd21e3189_maria_tiny_4ffef62a1a97` | The worker was killed while the real SSH `mariadb` import was active. The client survived the SSH-channel loss and committed 100,000 rows, but the exact marker and durable file checkpoint remained `importing`/`in_progress`; two namespaced temp files remained. The old scheduler needed five dispatch attempts before a timing gap allowed attempt 2 to claim. The deterministic fork-recovery path re-read the exact importing marker, reset the generation, dropped only the owned fork, and replayed into a fresh target. Final source/fork stats are 100,000 rows/distinct IDs, min/max 1/100,000 and sum 5,000,050,000; ordered-row digest `7e3e1329c8d4cdb0015c53840477c244ba3c6ba6c1a02b5e92545d5d87d3dc8c`, small-data digest `b7400d7ebc5f6fd8522f1dfb3cc41a6364fe3581f3adf8600c5502724b8201e6`, and normalized object digest `d99705e679c11c0a3a8d6c247462b246807f3669c4554dddb0a78afc9f1f39da` match. Marker is exact/complete, scheduler is `OFF`, and temp count is zero | **Pass for MariaDB 100k post-client/lost-response rebuild; exposed recovery-reservation starvation fixed below** |
| MariaDB 11.8 SSH pre-client kill and reservation consumption | Restore `55`, correlation `889f6d7f-bc66-4516-a05c-0d57dd52b24f`, target `bs_restore_889f6d7fbc66_maria_tiny_4ffef62a1a97`; deployed revision `f4adce3` | A target-scoped pass-through shim held only this restore after the durable file checkpoint and before `/usr/bin/mariadb`; the real-client count and source-table count were both zero, with only the exact importing marker present. The sole active task was hard-killed at `2026-08-18T21:57:22Z` (container exit 137). Its exact broker delivery was revoked without termination to isolate the durable sweep. The normal sweep reserved recovery at `22:00:32.001894Z`; `recover-restore-CoreDatabaseRestore-55` consumed the matching reservation at `22:00:32.126274Z`, recorded one stale takeover/dispatch, cleared `next_retry_at` and the reservation marker, and completed attempt 2 at `22:05:56.798847Z`. Final stats and row/small digests equal restore `54`; source/target normalized DDL digest is `4c4d2c5b3b3a55b0ad57ea251a6058caa363ba94e7302e2295381e921566dc29`. Marker is exact/complete, scheduler is `OFF`, temp count is zero, and the shim/flags/transfer files were removed with `/usr/bin/mariadb 10.11.14` authoritative again | **Pass for MariaDB 100k pre-client replay and the deployed recovery-reservation fix** |
| MariaDB 11.8 SSH post-marker/pre-final-status kill | Backup `66`, restore `56`, correlation `fb292c7c-61ef-43ad-8934-e900093d95d0`, target `bs_restore_fb292c7c61ef_maria_tiny_4ffef62a1a97` | A target-scoped wrapper delegated the exact completion-marker update to `/usr/bin/mariadb`, observed exit zero, then held only its successful response. At the kill boundary the marker was exact/`complete`, all three `restore_probe` rows were present, and zero real clients remained, while the durable row was attempt 1 at `database_importing`, file `complete`, target `importing`, and progress 0/1. The sole database task was hard-killed at `2026-08-18T22:17:01Z` (exit 137). Natural redelivery claimed one stale lease at `22:19:52.346869Z`, set the existing target checkpoint to `complete` with `adopted=true`, and completed at `22:19:55.817764Z` without another import. Counts are `restore_probe=3`, parent/child/audit `2/2/2`; normalized data and DDL exactly match retained restore `50` from the same backup with SHA-256 `12a8c7fec6e9f208211d60af108bb9e3ff010c2a033c797cd81f8787684a1b74` and `7e7390785cd6f80130cfc05dcb2eed334e6df1c4094f9a2af7409b502879b663`. Marker is exact/complete, scheduler is `OFF`, temp count is zero, and all instrumentation was removed | **Pass for MariaDB post-marker adoption without re-import** |
| MariaDB 11.8 SSH explicit import error and signed-in UI resume | Backup `66`; restore `62`, correlation `cabaec95-94f8-4bd0-84a4-a460645541ae`, target `bs_restore_cabaec9594f8_maria_tiny_4ffef62a1a97` | A target-specific wrapper returned exit 86 only for the non-query import command before invoking the real client. Attempt 1 failed at `database_importing_file` with file `maria_tiny.sql` `in_progress`, target `importing`, progress 0/1, and only the exact importing marker present. The public row exposed safe `RESTORE_TARGET_REJECTED` guidance, exact technical details, and `can_resume_verification=true`; no raw client output appeared. After the wrapper was retired and `/usr/bin/mariadb 10.11.14` was authoritative, the signed-in modal's `Resume verification` action dispatched `database-restore-resume-62-1` at `2026-08-18T23:25:59.539778Z`. The same row completed as attempt 2 at `23:26:04.310262Z`, with progress 1/1, cleared lease/error/retry, `can_resume_verification=false`, file SHA-256 `890c174b1888e4618399f6ac15ee52159dd43c07450130e858e78c7d84954994`, and exact complete marker SHA-256 `f262e688242ddb78dd1a4da6eb15ac50b916513df4de57c90568180d88714209`. Source, retained baseline restore `50`, and restore `62` share normalized data SHA-256 `774aab1cafd40ff835d46cba58f0694d1a7e0133783b0062e1fc8ce3c9857c37` and normalized DDL SHA-256 `9647a65c416dc7d422fb598e2b0c9462dc9b714fbddd11bb1adda5617b8235a1`; counts are `restore_probe=3`, parent/child/audit `2/2/2`, with two views, one trigger, function, procedure, three non-primary indexes, one FK, and the exact disabled event. Global scheduler is `OFF`, product temp residue is zero, and active instrumentation is zero | **Pass for bounded explicit import failure, customer-visible manual resume, and exact recovery** |
| MariaDB 11.8 eight-family UI matrix, definer preflight, and same-row recovery | Generation-1 backup `72`/point `76`; mutable generation-2 backup `73`/point `77`, UUID `bs-bs-remed-20260818-0d08dc-n99-b73`; restore `67`, correlation `34c52a31-7c9f-4991-8524-00d5ed1d0a09`; deployed revision `0220727` | Both mode-0600 artifacts pass CRC and contain exactly eight SQL files plus metadata. Attempt 1 advanced through active 0/8, 1/8, and 3/8 before the object dump's explicit `root@localhost` definers exposed missing MariaDB `SET USER` at 5/8. Five exact complete targets were retained; the object target was partial and tiny/Unicode unstarted. The bounded fix detects definers during archive validation and checks vendor/version-specific global capability before a first mutation. After granting only `SET USER` to the exact disposable fixture account, signed-in resume retained the same row, rendered Recovering/reconciling at 5/8, adopted the five complete targets, rebuilt only the exact-owned partial object target, and completed attempt 2 in 21.557 seconds at 8/8. Every family has source-equal normalized data/schema hashes; large has exactly 1,000,000 rows; 8 MiB/2 MiB payload hashes match; Unicode is byte-exact; objects include PK/FK/index/view/trigger/function/procedure/event/sequence; mutable generation 2 has the exact 115-row delta/hash. Eight sole markers exactly match correlation/backup/source/target/digest and `complete`; scheduler stayed `OFF`; remote temp and local preflight-credential residue are zero | **Pass for all eight MariaDB fixture families, bounded definer preflight, resumable reconciliation, and terminal 8/8 UI; the separate 5 GB gate passes in backup `74`/restore `68` below** |
| MariaDB 11.8 signed-in 5 GB backup/restore | Source/node `51`/`100`; backup `74`/point `78`, UUID `bs-bs-remed-20260818-0d08dc-n100-b74`; restore `68`, correlation `a305b6bb-a4fb-4408-ad34-d7a6013af357`, target `bs_restore_a305b6bba4fb_bs_remed_maria_lg5_0d0_959807f8e2f2` | The 5,858,394,112-byte table produced a 3,962,075,387-byte mode-0600 ZIP with SHA-256 `90f3d91d2740e87a1b2dad42bff90b0ebbfcc5c8f66423177c7128262cbe63b4`; CRC passes and its SQL is 5,378,891,089 bytes with SHA-256 `ad2f334af5b0dcd5e1179ed3ec4e8f195125c75ea1276fdd3a79610284207b76`. Restore `68` completed once at attempt 1 and signed-in 1/1. Source/fork each have 5,000,000 distinct keys, identical sums and payload bytes, matching samples, full ordered digest `a30683ea08b932e9e1bf9ba8985a477b4afbec980374679b9e84cf65201bd7c0`, equal DDL SHA-256 `0bc89d389e203fb031889c4d928a75090033fbeec4f7f6f674a4fb5c69efc929`, exact complete marker, scheduler `OFF`, and zero restore residue | **Pass for the MariaDB 5 GB product and terminal-UI gate** |
| MariaDB markerless collision classification | Backup `66`; pre-fix restore `57`, correlation `23ce01f7-a1ed-4dfa-b92e-38b9dd6a9d27`; deployed-fix restore `58`, correlation `a15f0f59-4efa-49f3-aa6a-79291ec560db`, target `bs_restore_a15f0f594efa_maria_tiny_4ffef62a1a97` | Restore `57` preserved its markerless target but exposed the old generic `RESTORE_TARGET_REJECTED` classification. After deploying `6555d57`, restore `58` returned public `RESTORE_RECONCILIATION_REQUIRED`, terminal `failed`, `can_resume_verification=false`, with no target checkpoint. Before and after, the target contained only `foreign_sentinel`; witness `bs-remed-markerless-classified-0d08dcf` retained SHA-256 `237a05bc9cc61e1e8dd6d83562574c92ac8a060acd2f2f75ce7b25936927f3a4`. No create, drop, marker claim, or import occurred | **Pass for deployed markerless collision fail-closed behavior** |
| MariaDB forged-marker collision | Backup `66`; restore `59`, correlation `33d61d71-4f58-42e9-ada0-e70756a60bd9`, target `bs_restore_33d61d714f58_maria_tiny_4ffef62a1a97` | A run-scoped target was precreated with `foreign_sentinel` and a structurally valid marker whose correlation was deliberately `00000000-0000-4000-8000-000000000059`. The deployed restore returned public `RESTORE_RECONCILIATION_REQUIRED`, terminal `failed`, `can_resume_verification=false`, with no target checkpoint. Sentinel SHA-256 `744112802e39cc25748197f1f0903b893d8fc0fda1bae0f30ff08ba802db1abe`, marker-row SHA-256 `0432ac2337bf1739ec0a9458a20963564590f026b0ebe718fb53749c3f8a319b`, and the exact two-table inventory were unchanged after failure | **Pass for forged-marker fail-closed/no-mutation behavior** |
| MariaDB 11.8 SSH client entirely missing | Connection/auth `70`/`49`; exact-owned SSH user `bsnodb_0d08dcf` can authenticate and use SFTP/tunnelling but resolves neither `mariadb` nor `mariadb-dump` | Live authenticated validation returns HTTP 400 with `DATABASE_CLIENT_UNSUPPORTED`, stage `worker_preflight`, `retryable=false`, and explicit MariaDB/mariadb-dump installation/revalidate guidance. No node or backup was created and both capability/restore temp-file counts are zero | **Pass for the Slice 2 missing-client validation/UX contract** |
| MySQL 8.4 eight-family signed-in UI matrix and schema-default fidelity | Connection/auth/node/source `77`/`56`/`104`/`54`; cancelled failure witness backup `77`; generation backups `78`/`79`; accepted contract-v2 backup `81`/point `85`, UUID `bs-bs-remed-20260818-0d08dc-n104-b81`; negative restores `80`/`81`; accepted restore `82`, correlation `cdc668aa-0c88-428d-a69a-2a0b399ca859`; deployed `ee8ec34` | Backup `77` reproduced the direct multi-database exporter failure. Restore `80` proved exact data but exposed database-default drift. Backup `80` proved the first schema-default preamble was reordered by buffering. Backup `81` is CRC-clean, mode 0600, 41,799,525 bytes, SHA-256 `513c13126a00490ff15de8e98c2348c8f1849154c0d8f759438fdfcd2fdd4f48`, contains exactly eight SQL files plus metadata, records all eight source defaults in contract v2, and begins every SQL member with its authenticated default statement. Restore `81` then failed safely at validation 0/8 with no mutation under the old allowlist. After the bounded authenticated-preamble fix, signed-in restore `82` stayed active through 0/8, 1/8, 2/8, and 7/8 and completed once at 8/8. Tiny/medium/1M/many-table/blob/Unicode/object/mutable targets match exact counts, relationships/orphans, sums, full row/blob/text/Unicode hashes, 400-table inventory, objects/event state, 115-row generation-2 delta, database defaults, and markers. Source and target independent normalized evidence are byte-identical at SHA-256 `062aa0bb7874ca5c50cf126fe6e29b13b899ca797061b48eceec27757a297eaf`; normalization removes only MySQL's redundant `CHARACTER SET <same-token> COLLATE` rendering | **Pass for all eight MySQL fixture families, schema-default fidelity, authenticated restore preamble, and terminal 8/8 UI; controlled 1M/5M performance and 10/25 GB gates also pass separately** |
| MySQL 8.4 direct tiny/object artifact | Backup `61`, point `65`, ZIP SHA-256 `a469c7e9352c2424332313a3f8dc46148334b965550dfde11c235cd0dd32ec1d`; restore `43` to `bs_restore_f71d8f99ab96_mysql_tiny_25c8ea257848` | Exact 3-row Unicode/binary content and view match; marker is exact; one view, one trigger, two routines, one FK, one secondary index, and three audit rows are present | **Pass for this earlier direct tiny/object fixture; event coverage is superseded by backup `65`/restore `49` below** |
| MySQL 8.4 full objects and event | Backup request `258cef15-1b44-43d3-82a9-35d8bcffe7a3`, backup `65` (`bs-bs-remed-20260818-0d08dc-n93-b65`), point `69`, 4,779,025-byte ZIP, SHA-256 `0947e7bff417c009484f11d3b058bd696cca52c36bf2625811ba67ddd27fb06c`; restore `49`, correlation `13193e2b-0c30-4ea3-a82e-c12f51d87aa6`, target `bs_restore_13193e2b0c30_mysql_tiny_25c8ea257848` | CRC passes and the 24,000,461-byte SQL contains the exact event. Source/fork data digest is `d0b0d9cfb578e2f6ee6b5f924822a28c7e29af1b5dd5105a4ac5b0e4ef69196a`; canonical object digest is `c7883dfe00b589fd4ee8faf5a593f1b2c1a8a410a8780322c77e9a51d0352a1c`. The fork has exact 100,000-row count/distinct/min/max, PK/FK, two secondary indexes, view, trigger, function, procedure, disabled event, and completion marker. The global scheduler remained `ON` | **Pass for the MySQL Slice 11 object/event gate; coarse restore progress remains a Slice 10 issue** |
| MySQL 8.4 committed-row worker kill | Backup `62`, point `66`, 4,778,741-byte artifact, ZIP SHA-256 `61b3e15f9243d8ff36256b5aa06349f0e8e45110d99084f848f67eb63ed67f89`; restore `44`, correlation `5d26accf-bf49-44ee-bb40-df22d43c01e9` | The worker was killed in `database_importing_file` with 87,981 rows visible. The expired lease was taken over once and the same logical restore completed as attempt 2. Source/fork each have 100,000 rows, 100,000 distinct IDs, min/max 1/100,000, and ordered digest `e709980cbd9f12cb4cfad98d0fa7ab1f96236b3afde84aa76dd7a1ce1d892fed`. Tiny rows/view/audit and FK/index/routine/trigger definitions also match; the sole marker row exactly records state `complete` | **Pass for this one MySQL crash boundary** |
| MySQL 8.4 required 1M committed-row worker kill and local cleanup | Connection/auth/node/source `75`/`54`/`103`/`53`; backup `76`/point `80`, UUID `bs-bs-remed-20260818-0d08dc-n103-b76`; normal restore `72`; pre-fix cleanup witness restore `73`; deployed-fix restore `74`, correlation `61d32739-c989-4ad8-9369-13f5a4074406`; revision `d547501` | The CRC-clean 53,396,706-byte artifact has SHA-256 `ff76262838b444bb34e5fba775f188f0cfeba4e34654ddaaa643b2cfbda5a6e6`; its 1,084,928,638-byte SQL has SHA-256 `6d9c2dd148f9b5d79fc2c7ba0e402a32ccd7458aa4f1a9782031f4ee91e0f551`. Restore `74` was hard-killed at attempt 1 with 962,152 committed rows, file/target `in_progress`/`importing`, and an exact importing marker. The same row waited for natural lease expiry, recorded one stale takeover plus prior work suffix, rebuilt only its exact-owned fork, and completed attempt 2 at 1/1. Source and fork each have 1,000,000 distinct IDs, min/max 0/999,999, sum 499,999,500,000, 1,037,000,000 payload bytes, matching view/metadata and normalized column/index/table hashes, and identical 71,888,890-byte ordered stream SHA-256 `e8c356259d8934f396b32fd895502d4d9e3b72c3fcd95a6e7ad5d55f947e1cb9`. Marker identity/state is exact; both fence generations cleaned through the storage queue; targeted residue is zero; and the signed-in modal stayed active during recovery and became Complete only at 1/1 | **Pass for the required MySQL 1M committed-row repetition, exact recovery, terminal UI, and deployed stale-generation cleanup. The remaining 1M boundaries pass in restores `75`–`77`; the required 5M repetition separately passes in restores `83`/`84`** |
| MySQL 8.4 1M pre-client worker kill | Backup `76`/point `80`; restore `75`, correlation `62c23ed7-afd5-4be1-90a1-3273b6b7ca93`, target `bs_restore_62c23ed7afd5_bs_remed_mysql_lg1_0d0_c5648735361b`; deployed revision `d547501` | A target-scoped one-shot wrapper held only this restore after the durable `database_importing_file` checkpoint and before the real MySQL client. At the boundary the exact marker was `importing`, the target contained only the marker table, `crash_probe` was absent, real-client count was zero, and the UI showed Restoring 0/1. The worker was hard-killed at `2026-08-19T11:32:39Z`; natural expiry produced attempt 2 with prior suffix `4cf2c7dc3d1d67cb`, which rebuilt the exact-owned fork and completed 1/1. Source/fork each have 1,000,000 rows/distinct IDs, min/max 0/999,999, sum 499,999,500,000, and 1,037,000,000 payload bytes. Their full 1,044,888,890-byte ordered raw-row stream has SHA-256 `e5e16d71f8e68d8faad689c645061c4bc8f3a191140b4b167ba1d716df5f8851`; normalized columns/indexes/tables/views have matching SHA-256 `d513a9ddc456f7920b6f19bd8d96b5504b02a02bc825b5ae561a5c348f136bd0`, `09fef69dabdc9089ea627e4616b2feb4b5f8f4299fd56103ed66a7cbceede392`, `e777b23ebe89ec6e863fc8e858fc8587ff05cea9274fafb43f50f2402dcb129b`, and `5bf6daa0abf6a767748f96c17f97c5d1ee4560c4a129cd90b99300786ae893d6`. Marker identity/state is exact, UI reached Complete 1/1, and only the retained log remains | **Pass for the required MySQL pre-client kill/replay boundary** |
| MySQL 8.4 1M post-client/pre-checkpoint worker kill | Backup `76`/point `80`; restore `76`, correlation `353c4f91-ebd6-4f55-924b-45922177d784`, target `bs_restore_353c4f91ebd6_bs_remed_mysql_lg1_0d0_c5648735361b`; deployed revision `d547501` | The one-shot wrapper delegated the complete 1M import to the real client, observed exit zero, and held the successful response before the file checkpoint. At the boundary all 1,000,000 rows were committed with exact aggregate values, the marker and durable target remained `importing`, the file remained `in_progress`, no real client remained, and the UI stayed at Restoring 0/1. The worker was hard-killed at `2026-08-19T11:55:32Z`; attempt 2 recorded prior suffix `d62e994c93c4e36d`, rejected the ambiguous importing generation, rebuilt only the exact-owned fork, and completed. Source/fork match on the same full ordered-row, column, index, table, and view hashes recorded for restore `75`; the exact marker is complete, the UI reached Complete 1/1, and targeted residue is zero | **Pass for lost client success before durable checkpoint, safe rebuild, and duplicate-free convergence** |
| MySQL 8.4 1M post-marker/pre-final-status worker kill | Backup `76`/point `80`; restore `77`, correlation `0bb2767a-a0dd-42fa-b08a-b90efd53e981`, target `bs_restore_0bb2767aa0dd_bs_remed_mysql_lg1_0d0_c5648735361b`; deployed revision `d547501` | The exact marker update returned zero and a one-shot wrapper held that successful response before the final target/status checkpoint. At the boundary all 1M rows and the marker were complete, the durable target was still `importing` with its file complete at 0/1, the UI remained active, and an independent target-import audit counted exactly one invocation. The worker was hard-killed at `2026-08-19T12:05:09Z`; natural attempt 2 recorded prior suffix `99a96a2ff8553380`, validated the artifact, adopted the exact marker with `adopted=true`, and completed without entering another file-import phase. The import count remained one; source/fork match on the full ordered-row and four normalized schema/view hashes above; the UI reached Complete 1/1 and targeted residue is zero | **Pass for exact-marker adoption after lost completion response, with no re-import** |
| MySQL 8.4 required 5M committed-row worker kill | Connection/node/source `78`/`107`/`56`; backup `88`/point `92`, UUID `bs-bs-remed-20260818-0d08dc-n107-b88`; clean restore `83`; fault restore `84`, correlation `bee81612-858e-4587-93a7-3ffd1545b9b0`, target `bs_restore_bee81612858e_bs_remed_mysql_lg5_0d0_8e635348dafc`; deployed revision `ee8ec34` | The 263,656,096-byte extended-insert artifact has SHA-256 `a00cce0225717a0d138d9f7deace79b8de7a30f1c23c37516c139ef4b2993d79`. Clean restore `83` completed once. Restore `84` was hard-killed at `2026-08-19T16:35:41Z`; an exact post-kill read proved 1,898,218 committed rows behind an `importing` marker while the durable row remained attempt 1 at 0/1. Natural lease takeover completed the same row on attempt 2. Source and fork each have 5,000,000 distinct IDs, min/max 0/4,999,999, sum 12,499,997,500,000, 5,185,000,000 payload bytes, matching metadata/sample/view/DDL hashes, and identical full ordered-row SHA-256 `fcefb7f1baddda52c94c47ccaa702b377240f71f4f5acc6d47dd1d77b4b54c9a`. The marker identity/state is exact, the signed-in recent-restores modal shows Complete 1/1, and correlation-scoped work residue is zero | **Pass for the required MySQL 5M fault repetition and clean baseline** |
| MySQL 8.4 intentional 5M row-by-row writer | Connection/node/source `78`/`108`/`57`; backup `90`/point `94`, UUID `bs-bs-remed-20260818-0d08dc-n108-b90`; deployed revision `9454507` | The pre-fix `--skip-opt` run buffered toward 1,847,884 KiB and was OOM-killed. The deployed rerun persisted `--skip-opt --quick`, streamed 5,598,892,551 SQL bytes with 12,276 KiB maximum dump-client RSS and zero cgroup OOM events, then committed one 264,535,256-byte CRC-clean artifact. Source/destination SHA-256 is `ecd191cfda06639690b8c9eaceda27ef6c7a8b9e0fa584989c07d91fb7e73e7d`; the destination is mode `0600`, exactly one upload completed, no SQL/defaults/partial archive remains in work storage, and the signed-in UI shows Complete with exact byte progress. The same-host historical import took 16,956.91 seconds; current-format runs took 239.20/249.94/255.83 seconds, with identical exact evidence and zero benchmark OOM | **Pass for bounded row-by-row generation, one verified upload, and the controlled 5M import comparison (67.84x/98.53% median improvement)** |
| MySQL markerless collision classification | Backup `76`; restore `78`, correlation `74f89f00-ec12-455e-8248-79c0b35477e1`, target `bs_restore_74f89f00ec12_bs_remed_mysql_lg1_0d0_c5648735361b` | The target was precreated while the database worker was stopped with only `foreign_sentinel` and run witness `bs-remed-mysql-markerless-0d08dcf-r78`. Before/after canonical evidence SHA-256 is identically `05bbb3c5c774dd887e29d66d6dd5d07d8e17152a5bcdb581c0d9f0f96894ba36`. Restore `78` failed on attempt 1 before any target checkpoint/import with public `RESTORE_RECONCILIATION_REQUIRED`; the UI showed Manual review required, Failed, 0/1. The database, sole table, sentinel key, and payload were unchanged | **Pass for MySQL markerless collision fail-closed/no-drop behavior** |
| MySQL forged-marker collision | Backup `76`; restore `79`, correlation `d8edbd1f-6b92-4e3e-8450-743db32acf7c`, target `bs_restore_d8edbd1f6b92_bs_remed_mysql_lg1_0d0_c5648735361b` | The target was precreated with `foreign_sentinel` plus a structurally valid marker whose correlation was deliberately `00000000-0000-4000-8000-000000000079` and whose digest was deliberately foreign. Exact two-table, sentinel, and marker evidence has identical before/after SHA-256 `90129aa95b2438d43964ac7d812f8452cf6cc47713593aee90c92bc542e8e858`. Restore `79` failed on attempt 1 before any target checkpoint/import with public `RESTORE_RECONCILIATION_REQUIRED`; the UI showed Manual review required, Failed, 0/1. No table, row, marker field, or payload changed | **Pass for MySQL forged-marker fail-closed/no-drop behavior** |
| MySQL 8.4 persistent TLS backup/restore and restore preflight | Connection/auth `73`/`52`, node `102`; backup `75`/point `79`, UUID `bs-bs-remed-20260818-0d08dc-n102-b75`; completed restore `71`, correlation `b9195849-0378-4d5d-93a3-f0a9e38c102b`, target `bs_restore_b91958490378_mysql_tiny_25c8ea257848`; deployed revision `fecf40a` | The product's stored credentials negotiate `TLS_AES_128_GCM_SHA256`. Backup `75` completed first attempt to a CRC-clean 4,727,322-byte ZIP, SHA-256 `8c8af78531d1f41688018b21a968b54bbe3e5038874d7b30e6d701953d2eddf7`, containing 20,597,328-byte SQL. Restore `69` failed before mutation because the old parser misread MySQL's displayed escaping for `bs\_restore\_%`. A temporary diagnostic grant allowed restore `70` to expose MySQL error 1419 after target creation: `log_bin=1`, `log_bin_trust_function_creators=0`, trigger/function archive, and no `SUPER`. After the exact account received required privileges, signed-in resume kept restore `71` as one row, rebuilt only its exact-owned fork, and completed attempt 2 at 1/1. Source/fork data digest `0f018f9e06d7694bc094698724571895a9e9bc9e11f927aed8f3cc8b1841d78b` and normalized schema digest `dc99017f02cf600e75d73a13031df526c7de8ad56d7c5334930be712e2b5f0c1` match; counts, view, trigger, and exact completion marker match. Routines/events are absent by the node's explicit `include_stored_procedure=false` policy, not restore loss. Deployed `fecf40a` now accepts the escaped scope and, when needed, reads only the two non-secret binlog settings and fails before target creation | **Pass for persistent MySQL TLS validation/backup/restore and deployed no-mutation preflight; the full MySQL eight-family matrix separately passes in backup `81`/restore `82`** |
| MySQL event-read privilege validation | Connection/auth `69`/`48`, full-object policy, exact-owned restricted user with zero `EVENT` privilege | Live authenticated validation returns HTTP 400 with code `DATABASE_EVENT_PRIVILEGE_REQUIRED`, stage `authorization`, `retryable=false`, and exact grant/revalidate remediation. No raw client message or credential appears in the response | **Pass for the Slice 11 privilege/error-contract gate** |
| Website ASCII/mixed tree | Backup `37`, point `39`, ZIP SHA-256 `5f0b57141377771f791e99b5e752865fdde3df8780770e92e88709713cc43bdd`; restore `17` with `delete=true` | After overwrite, deletion, and extra-file mutation, manifest returned exactly to `734cab760336c35d23abd010377ed4ea12644065518b60da29b4e9dc86654023`; the extra file and all staging/previous-target paths were absent | **Pass for this small product-path gate** |
| Website Unicode reproduction | Backup `38`, point `40`, ZIP SHA-256 `6b6416f42047330de1e0c00dcfc131ebc5dc7da7762cf5fce82e0a46f7f6fedc` | All nine non-ASCII entries had bit 11 clear and decoded as CP437 mojibake even though the raw filename bytes were valid UTF-8 | **Fail reproduced; cause confirmed** |
| Website Unicode corrected writer | Backup `39`, point `41`, ZIP SHA-256 `8715d3c3ca9b24fa6323592040ddcceec5bc296c90c9575fc9f90747ac7e73f0`; restore `18` with `delete=true` | All non-ASCII entries carry the UTF-8 flag and CRC passes. Accented Latin NFC/NFD, Arabic, CJK, Cyrillic, emoji, quotes, spaces, hidden file, zero-byte file, empty directory, and nested mixed names restored to exact 15-entry manifest `3ba55b6127c753b58dd04b87ec44fcd33c147d142c5c12aec9e2e6399567360f`, with no mojibake or extra names | **Pass for newly produced small archives** |
| Website historical unflagged UTF-8 reader | Retained backup `38`; signed-in restore `20`, correlation `e4915cd0-4cb6-4b9f-9c53-f3c1d0582747` | The deployed reader repaired only its downloaded working copy. Restore completed at attempt 1/1-of-1; source and destination each have the same 15 entries and canonical manifest SHA-256 `2eb24411702c799d58eeeb19f6297d55ddd0352ed3ab5ffa5c24aef4b73276d9`, including Arabic, CJK, Cyrillic, emoji, NFC/NFD, quotes/spaces, hidden/zero-byte files, and empty directory. The committed provider artifact was not rewritten | **Pass for historical small-artifact compatibility and signed-in UI** |
| Website W6 real-SFTP 300-level tree | Node `101`; cancelled pre-fix backup `40`; deployed-fix backup `41`, point `43`, UUID `bs-bs-remed-20260818-0d08dc-n101-b41`; restore `21`, correlation `cb7067e4-c3ba-48d4-aed3-06af7954b6b8` | The source has 301 directories including root, one file, a 2,999-byte relative directory path, and 3,008-byte leaf path. Backup `41` recorded the parallel `lftp` assertion then bounded serial fallback, completed on attempt 1, and produced a CRC-clean 970,666-byte ZIP with SHA-256 `01223b8637d430b3c607d5e7b19118b32fcfd55f8561e7e16eb1566c391d9913`. Signed-in restore `21` completed 1/1; source and restored trees each have 301 directories/one file and canonical manifest SHA-256 `f12ad78bcb8eb00df9ac512ad2c5e76a62d8cda9a9aeefb3cc2b44a72fcdf398` | **Pass for W6 product backup, restore, exact content, and terminal UI** |
| Website combined W1/W2/W3/W4/W5/W6b/W7/W9 signed-in matrix | Connection/node `80`/`109`; backup `50`/point `52`, 1,365,639,963-byte ZIP, SHA-256 `07b1266857f7d745b834a9c26aead674c07a60f1c0843ce052ab230d26a2eb34`; restore `25`, correlation `3cf8205d-2be9-4b78-ac0b-eff5f03ebd5e` | The exact source contains 103,573 files, 473 directories, and 1,339,687,255 logical bytes: W1 3 files; W2 146; W3 four 64 MiB files; W4 1,000 one-MiB files; W5 102,400 files; W6b 40 levels; W7 ten zero-byte files/eight empty directories plus sentinel; W9 eight metadata/hidden files. Backup completed once with matching source/destination artifact ledgers and CRC-clean 104,048-entry ZIP. Before restore the source was moved aside and two extras were planted. Restore used a disk-spooled manifest and private atomic stage, kept the live target at only the two extras until swap, then completed once at 1/1. Restored file, directory, and entry manifests match the source at SHA-256 `d5361ebb5aabb3c2760c2decaeb2c120ad790ff4d5c52fdbd5b2a2784272d907`; extras/stages are zero and browser warnings/errors are zero | **Pass for every remaining W1–W9 signed-in fixture gate; W6 and W8 retain their independent witnesses** |
| Website case-folding and Unicode-normalizing destination | Connection/auth/node/website `81`/`12`/`110`/`27`; cancelled trust-mount control backup `51`; complete backup `52`/point `54`, UUID `bs-bs-remed-20260818-0d08dc-n110-b52`; pre-fix restore `28`; deployed restore `29`, correlation `49dcaa3f-c114-4593-a5e0-7541cb517e72`; exact deployed `7657d27` | The signed-in host-key preview exactly matched the independently read ED25519 fingerprint before explicit approval. Backup `52` is a CRC-clean 1,197-byte three-file ZIP with SHA-256 `c06d07006bb28c4320e1b845f2940d581f6b2f11597f6c35f3aedbf77f32d83b`. Restore `28` proved the engine stopped before publication but exposed the generic-code defect. After `7657d27` passed 1,925/1,925 repository-wide tests and was deployed, signed-in restore `29` failed once with `delete=false`, Terminal failure / Failed, and exact public `RESTORE_TARGET_NAME_COLLISION`. Source/sentinel hashes remained `f17cf8db09aa7c93a12e038636eb1649be2ee3885ee84e1b8dafea0e6762e2c7`, `1be8165d849e8d54a1a4d12a3b0691107a14c7b26c592ea3996f51dd6ed82667`, and `49a790e35ac6610984bf247ac581ddde3e36942cbecddd293224b8aae0f611e7`; no local work, remote probe/stage/partial, retry, lease, or duplicate row remains | **Pass for live case-distinct and NFC/NFD collision rejection before target publication** |
| Website FTP/FTPS C0-control rejection | Plain-FTP node `113`, retained backup `55`, pre-fix restore `32`, deployed restore `33`; rejection node `114`, backup `56`; exact deployed `8f8a479` | Backup `55` retained a tabbed name exactly, but pre-fix restore `32` silently stripped the tab while reporting Complete. Deployed restore `33` now fails once as `RESTORE_INTEGRITY_FAILED` before mutation and preserves the sole foreign target hash. Backup `56` fails once at zero files/bytes; the Activity UI shows exact `SOURCE_SPECIAL_FILE_UNSUPPORTED`, and no archive/artifact/upload is published. The fixture containing tab and `U+001F` remains unchanged and all targeted residue/retry/lease checks are zero | **Pass for live compatibility-reader and source-publication rejection of non-portable C0 controls** |
| Website broader plain-FTP/explicit-FTPS legal path matrix | Connections/nodes `82`/`113` and `83`/`115`; backups/points `57`/`59` and `58`/`60`; restores `34`/`35`, correlations `03f81b82-5db8-4edc-9cea-1b938eef25cb` and `11b134ac-3e17-49ab-a064-52d36e7113de` | Each source has 28 files, 12 directories, 259 bytes, and exact canonical manifest `d6b4cbf723034d2f75bb008fcc30ae1e72463df02fbeee036ac5428a90845c4b` across spaces, dash/dots, quotes/metacharacters, long component, hidden/zero/empty entries, case and NFC/NFD distinctions, and multilingual names. Both CRC-clean archives reproduce that manifest. Both signed-in delete-extras restores complete once at 1/1, reproduce the exact manifest, remove the planted foreign file, and leave zero retry/lease/error or probe/stage/partial residue | **Pass for broader legal path-component backup/restore over plain FTP and explicit FTPS** |
| Website two-million-file clean and interrupted paths | Node `106`; backup `44`/point `46`; restore `22`; controlled backup `49`/point `51`, UUID `bs-bs-remed-20260818-0d08dc-n106-b49` | Backup `44`/restore `22` prove one 612,497,006-byte, 2,002,005-entry artifact restores exactly 2,000,000 files, 2,000 source directories, 68,000,000 logical bytes, and the source 4,100-file witness. Backup `49` was hard-killed during private archive growth, naturally took over the same row, reused its exact mirror checkpoint without another source transfer, removed the old partial, atomically published a new artifact, and uploaded once. Its source/destination SHA-256 is `3bb9cc5b8e933e3204c99fe89ae53bf02890b22495f1e0b52d0bb6fe7fc35036`; CRC, entry count, bounded sample, residue, and signed-in Complete/Resolved recovery gates pass | **Pass for Slice 7 clean backup/restore and controlled interruption** |
| Website 100 GB full restore | Backup `42`/point `44`; pre-fix controls restores `23`/`24`; setup-mismatch control restore `26`; accepted restore `27`, correlation `380477ec-05d4-410b-8e58-a151fb1954b4`; connection `79`; exact deployed `bf10816` | Exact `bf10816` passes 22/22 focused and 1,919/1,919 complete tests and is deployed after a verified database snapshot. Restore `26` proved full ETag-compatible download/extraction but exposed the separately documented mutable-path mismatch before target writes. After the fixture was corrected through the signed-in Modify/validate flow, restore `27` completed once with `delete=false`. The UI progressed Validating → Restoring 0/1 → Complete 1/1. Archive SHA is `71ec61b44453a81201295bcb2f480c74b653f18333319821857cab74ba0775d1`; CRC passes; the 107,421,554,467-byte member and sole target file both hash to `9b2b8afb1f2d9eb176e291b8ecf0e045c591c229a5203d9fbcfed10347af1229`. Provider HEAD/metadata, zero unfinished uploads, one row/attempt, drained queue/active/reserved inventory, zero work/probe/stage residue, and zero restart/OOM all pass | **Pass for full 100 GB signed-in restore and exact terminal evidence** |
| Database empty-selection rejection | Authenticated PATCH of source `41`; real Chromium edit of isolated exact-image source `2` with a controlled outbound-request mutation | Both requests returned HTTP 400 with the exact `all_tables` field error. The Chromium page remained on the edit route with `scope-owned-db`, `Backup All Tables=true`, and Modify enabled; its durable selection and node name remained unchanged | **Pass for HTTP no-mutation and rendered browser-error preservation** |
| Database cross-account execution rejection | Isolated exact image `3d40faf`; signed-in account `1`; foreign account/node/storage/backup `2`/`1`/`1`/`1` | CSRF-correct node read, backup request, and restore request each returned scoped HTTP 404. Backup-request/restore counts remained `0/0`, the database queue remained `0/0`, and the foreign backup status/modified timestamp were unchanged | **Pass for explicit account-scoped no-mutation execution** |
| Storage counters and phases | Local storage `9`, block-backed local storage `10`; database restores `37`–`82`; website restores `17`–`21`; queued/source-ready backups `91`–`93`; exact-image retry/partial backup `3` | A fresh completed-point aggregation reports storage `9` website `4` across two sources/980,981 bytes and database `24` across ten sources/444,201,165 bytes, total 445,182,146 bytes. The three new 4,727,334-byte database destinations account exactly for the increase. Storage `10` remains independently reconciled at database `4`/four sources/8,827,622,046 bytes. Category bytes, counts, and source counts derive only from upload-complete rows. The prior restore matrix remains passed; backups `92`/`93` add live source-ready and polled terminal-action proof, and exact-image backup `3` adds scheduled-retry and terminal-partial proof | **Pass for current local destinations and observed queued/source-ready/retrying/partial/matrix/scale/TLS/crash-recovery phases** |
| Durable queue, source-ready, and terminal row actions | Request `155`; backups/points `91`/`95`, `92`/`96`, and `93`/`97` on node `102` and local storage `9` | With database and storage consumers stopped, request `155` persisted once as dispatched, the database queue held one ready delivery, and no concrete backup existed; the signed-in UI confirmed the request was durably queued. Pre-fix backup `91` then exposed the verified source artifact/ready point as generic In Progress, establishing the failure. After deployment, backup `92` stayed `Download Complete` with point ready and zero upload attempts while the signed-in row showed Source archive ready at 4,727,334/4,727,334 bytes. Backup `93` repeated the state with Cancel visible; after storage resumed, the same DOM row changed to Complete with Download/Restore/Delete and no Cancel. Each backup completed one upload; source/destination SHA-256 values match respectively at `147de41bb27cd68ce68cdbd59a5a242b69d037eba9e98d3fcbbc680120479d50`, `4bf72f7a076e52c9b8b58c9db698a80eeb2ce244296bb8f00660c1a2d9870084`, and `9930d67f333875436b3b85ecbae6818d33cf34d8fce4d82b4dba0d861c82ea8f` | **Pass for durable queued acceptance, source-ready visibility, exact one-upload completion, and non-contradictory terminal actions** |
| Scheduled retry to terminal partial | Isolated exact image `8d2d669`; node `2`; backup `3`; points `3`/`4`; local storages `4`/`5` | A real task and Chromium row changed from Source archive ready to Scheduled retry/Retrying with its real next-retry time, safe guidance, and Cancel. After revoking only that exact scheduled test delivery, a controlled Celery retry header of `96` exercised the max-retry boundary without a 24-hour wait. Point `3` completed one exact 187-byte upload; point `4` became terminal `UPLOAD_FAILED` on attempt 2 with `STORAGE_RETRIES_EXHAUSTED`. The normal finalizer made the same parent Partial/Complete with summary configured 2, accepted 2, uploaded 1, failed 1 and no next retry. The browser showed exact 187/187-byte progress, safe exhausted-retry guidance, Download/Restore/Delete, and no Cancel; the final storage queue was exactly empty after purging the one revoked test delivery | **Pass for exact scheduled-retry visibility, terminal partial finalization, safe guidance, and terminal actions** |
| Historical restore browser diagnostics | Signed-in node `94`, backup `63`, restores `60`/`61`; deployed app `cb7fbc8` | The restore modal visibly renders `Manual review required`, `Phase: Failed`, `Progress: 0 / 1 databases`, and the allowlisted reconciliation guidance for both rows. Expanding each row's `Technical details` shows its exact correlation (`2a030bab-439c-4b41-a525-081950731f1f` or `fb9c1512-8652-456e-bfa5-5317da02d0fd`) and `RESTORE_RECONCILIATION_REQUIRED`. The Restore action remains disabled until explicit acknowledgement, and neither failed row offers verification resume | **Pass for terminal historical-row browser presentation** |

#### Retained resources, cost, and cleanup state

- The Vultr instance, SSH key, firewall group/rules, three fixture
  containers/volumes, both exact-owned SFTP sources including
  `/srv/bs-remed-website/deep300-0d08dcf`, exact-owned PostgreSQL 1M source database,
  demo-side MySQL
  tunnel, two disabled event fixtures, the MariaDB object/100,000-row crash fixture,
  backup `67` and restore `54`/`55` forks, restore `62`'s exact-owned completed fork,
  PostgreSQL eight-family source set, node `96`, backups `68`/`69`, restores `63`/`64`,
  and their exact-owned forks,
  MariaDB eight-family sources, node `99`, backups `72`/`73`, restore `67`, its eight
  exact-owned forks, and the exact diagnostic definer target,
  restricted MySQL validation user/connection,
  MariaDB no-client SSH user/shell/connection, the mode-0600 `f4adce3`, `6555d57`,
  `cb7fbc8`, `f9669c5`, `0220727`, `5f3678b`, `fecf40a`, `d547501`, `e360056`,
  `ca06dfa`, `80827f5`, `e122271`, and `ee8ec34` demo
  snapshots, five
  retained markerless/forged-marker collision databases, MariaDB 5 GB node `100`/
  backup `74`/restore `68`, historical website restore `20`, deep-tree node `101`/
  backup `41`/restore `21`, persistent MySQL TLS connection `73`/node `102`/backup
  `75`/restore `71`, and their exact-owned verification targets,
  protected credential/environment files, product connections/nodes/storage,
  successful restore forks, and acceptance artifacts are intentionally retained for
  subsequent slices. Only exact temporary test shims, flags, SQL verification files,
  and fixture-host transfer copies were removed from active paths; the small
  demo-side setup/source overlays were moved recoverably to mode-0700 directory
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
  `retired-transfer-files-cb7fbc8/`. Restore `62`'s three demo-side instrumentation
  files are likewise inactive in mode-0700 directory
  `retired-import-error-restore62-cb7fbc8/`; the fixture-side wrapper, hit witness,
  transfer copy, and verification files are inactive in mode-0700 directory
  `/root/bs-remed-retired-instrumentation/`. No retained provider/product evidence
  was deleted.
- The small multipart candidate overlay and its automated-test sources are retained at
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
  `candidates/multipart-bounded-20260819/`. It contains no provider object or large
  generated archive. All nine isolated candidate-test databases were dropped after
  their respective runs.
- The small database dump-format candidate overlay is retained at the same run root
  under `candidates/database-extended-insert-20260819/`. It contains source/test
  overlays only, not a database dump. Both successful candidate-run databases and the
  earlier import-preflight run database were dropped.
- The small stale-restore-cleanup test overlay is retained under
  `candidate-stale-restore-cleanup/`; it contains only two regression-test source
  files and no payload or credential. All disposable databases from its red/green,
  focused, hardening, and full-module runs were destroyed. The mode-0600 predeploy
  snapshot `demo-pre-d547501-20260819T101147Z.dump` is retained on block storage.
- MySQL 1M source `bs_remed_mysql_lg1_0d08dcf`, connection/auth/node/source
  `75`/`54`/`103`/`53`, backup `76`/point `80`, normal restore `72`, pre-fix cleanup
  witness restore `73`, deployed-fix restore `74`, boundary restores `75`–`77`,
  foreign-target restores `78`/`79`, their five exact-owned or deliberately foreign
  targets, and the prior exact-owned forks are retained. The 53,396,706-byte
  mode-0600 block-storage artifact reuses the existing
  user volume and no new provider storage resource was created. After exact path and
  run ownership were rechecked, cleanup task
  `d4535ec7-2673-413a-8c83-ee13efdb42e8` removed only restore `73`'s stale fenced
  directory/ZIP/defaults file. Restore `74` then caused its own prior and current
  fenced generations to be removed automatically by cleanup tasks
  `0f31497a-5f2d-4638-b61a-25b4266c29cc` and
  `b3c05efb-9c9c-412a-853b-946442f38d08`. The retained product logs and phase lock
  remain; targeted payload/credential residue is zero.
- Restores `75`–`77` each caused their prior and current fence-scoped work generations
  to be removed through the normal storage queue; only the shared retained restore log
  remains. Their small mode-0600 one-shot boundary witnesses and verifier sources are
  retained under the run root on demo block storage. After restore `77`, the temporary
  MySQL wrapper was removed by recreating only `worker-database` from exact image
  `sha256:32212732850792afe80a5fd11a81b0ffac18f66e47b7dacdbff87e681238b2f3`
  at revision `d547501`; `/opt/mysql/bin/mysql` again has its original SHA-256
  `d14e4d70a0ab8fd9aeaf95ecd2213e7994ae1eeca6041022c77b50a8e659dbc0`, and
  no wrapper, real-client alias, mode, audit, event, or ready file remains in the
  active container. Restores `78`/`79` deliberately retain their tiny foreign targets
  as no-drop evidence. All five targets live on the already-retained MySQL fixture;
  no Vultr instance, volume, firewall, or storage destination was added.
- MySQL eight-family connection/auth/node/source `77`/`56`/`104`/`54`, all eight
  source databases, cancelled backup `77`, complete backups `78`–`81`/points
  `82`–`85`, negative restores `80`/`81`, accepted restore `82`, and the exact-owned
  restore targets are retained. The four completed artifacts total 167,197,792 bytes
  on existing storage `9`; no provider storage or Vultr resource was added. The
  accepted source verifier is inactive as mode 0700
  `/root/bs-remed-mysql-matrix-verify-v2.sh`; its demo-side copy is mode 0600 under
  the run root. The small schema-default and authenticated-preamble source/test
  overlays are retained under `candidates/mysql-schema-defaults-20260819/` and
  `candidates/mysql-schema-restore-preamble-20260819/`. Scratch probe schemas were
  removed. The matrix targets remain available for the controlled performance and
  later scale work; the fixture VM currently has limited free root-disk capacity, so
  a 5M/larger fixture must pass a fresh capacity/ownership preflight before creation.
- Restore `64`'s read-only matrix verifier is inactive in mode-0700 directories
  `retired-pg-matrix-restore64-f9669c5/` on demo block storage and
  `/root/bs-remed-retired-instrumentation/pg-matrix-restore64-f9669c5/` on the fixture
  host. The fixture has zero correlation-scoped restore temp files; the demo work
  volume retains only the expected zero-byte phase lock and two small product logs
  for backup `69`, not an archive or extracted restore payload.
- Restore `65`'s 1 GB setup/verifier files are inactive in mode-0700 directories
  `retired-pg-lg1-restore65-f9669c5/` on demo block storage and
  `/root/bs-remed-retired-instrumentation/pg-lg1-restore65-f9669c5/` on the fixture
  host. No correlation/source-named product temp file remains on either host. The
  retained block-storage backup artifact occupies about 765 MiB; this reuses the
  user's existing volume and creates no additional provider storage resource.
- Restore `66`'s 5 GB setup/verifier files and generation log are inactive in
  mode-0700 directories `retired-pg-lg5-restore66-f9669c5/` on demo block storage
  and `/root/bs-remed-retired-instrumentation/pg-lg5-restore66-f9669c5/` on the
  fixture host. No correlation/source-named product temp file remains on the fixture;
  the demo work volume retains only the expected zero-byte phase lock and two small
  product logs for backup/restore `71`/`66`. The two mode-0600 block artifacts total
  4,812,149,953 bytes and reuse the user's existing volume; no provider storage
  resource was created.
- Restore `67`'s verifier remains staged on the fixture with SHA-256
  `2ef02597b0c9f6c1bed787bfb6dedf103877883839d45347cd242d43ba394297` for the
  next evidence review. The exposed first-generation matrix SSH key was revoked and
  is recoverably quarantined; only its rotated replacement remains authorized. The
  fixture retains zero `.backupsheep_restore_*` files for the dedicated matrix user,
  and the demo work volume retains only expected product logs/phase lock rather than
  an extracted restore payload or credential file. No retained target or artifact was
  deleted.
- The MariaDB 5 GB source/fork and its 3,962,075,387-byte block-storage artifact are
  retained. The historical Unicode source and restore trees, deep-tree source/original
  and restore trees, and MySQL TLS source/completed fork are also retained. Their
  large content never crossed onto the MacBook. Restore `70`'s failed diagnostic
  target and restore `71`'s earlier exact-owned generation remain evidence for the
  preflight defect and safe same-row recovery; they must not be dropped without a
  fresh marker/ownership read and explicit cleanup authorization.
- The active Slice 4 case-folding fixture is retained at
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/website-casefold-20260820/`.
  It consists of the sparse 64 MiB ext4 image mounted through `/dev/loop0`, the
  run-labelled container `bs-remed-casefold-sftp-20260820`, and product
  connection/auth/node/website `81`/`12`/`110`/`27`. The capability check and three
  tiny source files occupy only existing demo block storage; no Vultr instance,
  provider volume, object, multipart upload, or storage destination was created for
  this fixture. Its independently verified host key is approved. Cancelled control
  backup `51`, complete backup `52`/point `54`, pre-fix restore `28`, and passing
  deployed collision restore `29` are retained as product evidence. Restore `29`
  has one attempt, exact public `RESTORE_TARGET_NAME_COLLISION`, unchanged source
  hashes, and zero probe/stage/work residue. The container and loop mount remain
  active, so they reuse already-running demo compute for retained evidence or until
  cleanup. Cleanup is now authorized by the user for the demo, but must
  still recheck the exact run labels, product references, mount, and loop identity
  before removing any recorded object; do not apply a broad orphan or path cleanup.
- The retained small FTP/FTPS fixture is rooted at
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/website-protocol-20260822/`.
  Run-labelled container `bs-remed-ftp-ftps-20260822` is on
  `backupsheep_default`, publishes no host port, and serves only the run-owned
  `source-ftp` and `source-ftps` trees plus their moved-aside pre-restore witnesses.
  Product connections/auth/nodes are `82`/`13`/`111` and `83`/`14`/`112`; backups
  `53`/`54`, points `55`/`56`, and restores `30`/`31` are retained as exact evidence.
  Path-fuzz nodes `113`/`115`, unsafe-control node `114`, backups `55`–`58`, points
  `57`–`60`, and restores `32`–`35` are also retained. Moved-aside trees preserve the
  pre-fix tab-stripping control, the failed historical-restore target, both accepted
  source manifests, and the post-restore outputs. The legal active targets each occupy
  only 259 bytes; the control fixture is 35 bytes. No large local data is involved.
  The self-signed test certificate expires after seven days; no credential is recorded
  in this document. The fixture uses negligible existing demo block storage and no new
  Vultr instance, provider volume, object-storage bucket, or published network port.
- Final Slice 13 cleanup removed only exact run-owned transient resources: the
  1,073,741,824-byte `slice13-storage-stall-1g.bin`, the isolated two-file C0 canary
  directory, stopped custom storage-stall worker, disposable state-fix worktree, and
  its patch-identical stash. The active plain-FTP source returned to exactly three
  files/71 bytes. The final suite's disposable container/database/RabbitMQ user/vhost
  and failed test-broker image tag were also removed. Acceptance backups, manifests,
  restore evidence, active normal workers, and unrelated demo resources were retained.
- Estimated Vultr compute cost is approximately USD 0.03/hour (about USD 20/month if
  left continuously running); treat this as an estimate until reconciled with the
  account invoice. Billing continues while the instance is retained.
- Cleanup is currently authorized, but must still rehydrate the exact local ledger,
  perform fresh provider ownership reads, confirm zero pending intents, and delete
  only the recorded IDs.

#### Current acceptance state after the 2026-08-23 closure

- No release-blocking exit gate defined by Slices 0–16 remains open. Database,
  website, multipart, diagnostics, UI-state, capacity, deployment, and current
  full-suite gates all have recorded signed-in/live or exact automated evidence.
- Deliberately repeating every MySQL boundary on MariaDB and vice versa is optional
  expansion beyond the stated Slice 3 exit gate, not a failed supported scenario.
  Likewise, database sizes beyond the explicitly accepted MySQL 25 GB, PostgreSQL
  25 GB-class, and MariaDB 5 GB limits require a new acceptance claim before they can
  be advertised.
- The exact run-owned Vultr fixture VM and 250 GB block volume remain retained for
  evidence at the previously recorded estimated cost. The VM still identifies itself
  as `bs-remed-20260818-0d08dcf-webdb` and exposes the 268,435,456,000-byte block
  device. Provider deletion was not attempted because no current Vultr API credential
  was available in the demo application inventory; this is a cost/cleanup residual,
  not a product acceptance failure.

#### Historical gates-open checkpoint — superseded by the closure above

- PostgreSQL 1/5 GB restore gates are now closed with full-coverage digests and exact
  schemas. Later claimed 10/25 GB gates remain open. The focused
  automated tamper/marker/checksum/lease suite is green; current/historical direct,
  current SSH, all-eight-family signed-in UI, 1M mid-import, 1M pre-client, 1M
  committed-marker lost-response, markerless collision, forged-marker, and
  component-phase polling product gates are now closed.
- MariaDB's all-eight-family and 5 GB signed-in backup/restore gates are now closed,
  including the final 1/1 terminal modal. Broader UI lease-loss coverage and later
  cross-engine fault cases remain. The
  small direct/SSH self-restore, wrong-vendor/entirely-missing-client validation,
  100,000-row post-client/lost-response rebuild, 100,000-row pre-client replay, and
  post-marker adoption, explicit import-error/manual-browser-resume, markerless
  collision, and forged-marker gates are now closed.
- Automatic compatibility for already stored unflagged UTF-8 ZIPs such as backup `38`,
  the real-SFTP 300-level gate, and the full W1–W9 signed-in fixture matrix are closed.
  Backup `50`/restore `25` close W1/W2/W3/W4/W5/W6b/W7/W9 with exact manifests; W6
  and W8 retain their independent exact witnesses. Backup `52`/restore `29` close the
  live destination case-folding and NFC/NFD-normalization collision gate with exact
  public failure, unchanged hashes, one attempt, and zero residue on the retained
  ext4 `+F` fixture. Backups `53`/`54` and restores `30`/`31` close the small plain-FTP
  and explicit-FTPS gates with exact delete-extras round trips. Deployed `8f8a479`,
  backup `56`, and restore `33` close the non-portable C0-control source/reader gates;
  backups `57`/`58` and restores `34`/`35` close the broader legal-component matrix
  over both protocols with one exact manifest. Backups `59`–`61` and signed-in
  restores `36`–`38` close the claimed 10/25/50 GB website matrix with exact
  artifact/target hashes and zero residue. The 100 GB gate is closed by backup
  `42`/restore `27`. The
  bounded writer/mirror resource
  measurements, progress/checkpoint evidence, and full two-million-file clean plus
  interrupted backup/restore gates are closed.
- The required MySQL 1,000,000-row committed-row, pre-client,
  post-client/pre-checkpoint, and post-marker/pre-final-status kill/recovery gates are
  now closed with signed-in active-to-terminal UI, exact full-row/schema/marker proof,
  one-row natural takeover, and zero targeted local-work residue. MySQL markerless and
  forged-target no-drop safety are also closed. The full MySQL eight-family signed-in
  backup/restore matrix is closed by backup `81`/restore `82`, including exact
  database defaults and source-equal normalized evidence. Backup `88`, clean restore
  `83`, and controlled-kill restore `84` also close the required 5,000,000-row
  repetition with exact full ordered-row, schema, marker, terminal-UI, and residue
  proof. Deliberately repeated MySQL/MariaDB cross-engine cases and later advertised
  database sizes remain open. The live S3 100 GB upload/resume, full-byte object,
  full signed-in website restore, and exact-owned orphan cleanup gates are closed.
  The controlled historical/current
  MySQL 5M comparison is closed by the 16,956.91-second exact historical run and the
  249.94-second current median. The exact-image retry/partial browser transition is
  closed by backup `3`; only later claimed database sizes remain open. Exact
  `bf10816` passes its 1,919-test release gate and closes the 100 GB customer-path
  restore on restore `27`. Exact successor `7657d27` passes repository-wide discovery
  1,925/1,925, is deployed, and closes the public collision-code gate on restore `29`.
  Slice 11's
  dedicated cross-engine object/event gate is closed, but
  this does not replace the still-open MySQL/MariaDB large/fault matrix. Slice 15's
  persistent MySQL TLS gate is closed, including the deployed no-mutation restore
  preflight.
- Slice 14 retains one newly observed browser gap: terminal polling updated backup
  `61`'s progress/actions but not its static Size/Files cells until page reload. Slice
  13 still lacks stage-specific attempt history and secured operator diagnostics
  beyond the public safe-error contract.

## Executive conclusion

The reports demonstrated strong backup creation coverage and originally identified
six primary defect families blocking full acceptance:

1. PostgreSQL backups cannot be restored by BackupSheep's own restore path.
2. MariaDB backups cannot be restored by BackupSheep's own restore path.
3. Non-ASCII website filenames do not round-trip safely.
4. A 300-level website tree cannot be backed up.
5. A 2,000,000-file website cannot produce a usable archive.
6. A roughly 100 GB website archive cannot complete its S3 upload.

The list above is the original report finding set. Current/historical PostgreSQL
self-restore, MariaDB self-restore through 5 GB, new/historical Unicode names, and the
real-SFTP 300-level tree now have product restore and exact-content evidence. The
100 GB multipart upload/resume/object-integrity failure is now closed by live backup
`42`, and its full signed-in restore is closed by restore `27`. The two-million-file
clean restore and controlled interruption gates are closed by backup `44`/restore `22`
and backup `49`. The live case-folding/normalization target is closed fail-safe by
backup `52`/restore `29`. Backups `57`/`58` and restores `34`/`35` close bounded legal
path-component fuzz over FTP/FTPS, while backup `56` and restore `33` close the
non-portable C0-control boundary. Website 10/25/50 GB is now closed by backups
`59`–`61`/restores `36`–`38`. PostgreSQL/MySQL 10/25 GB, stage-specific secured
diagnostics, and the terminal static Size/Files refresh defect are also closed by the
2026-08-23 evidence above. Deliberately repeating every cross-engine fault boundary
remains an optional expansion rather than a stated release gate. The
reports also identify a potentially corrupting MySQL/MariaDB crash-resume path,
slow row-by-row restores, originally missing MySQL/MariaDB event export, weak
node-selection validation,
orphaned multipart uploads, and several diagnostic/status/counting defects.
The deployed Slice 3 work now closes all four required MySQL 1M crash boundaries,
stale local-work cleanup, markerless/forged-target no-drop safety, and the required
MySQL 5M committed-row repetition. Deliberately repeated cross-engine gates remain
open.

Fix correctness and recoverability before performance or display polish. Each work
slice below has its own automated and acceptance exit gate; do not combine unrelated
fixes into one broad change.

## What the reports proved works

### Website and database report — 2026-08-15

- All 24 database backup-creation scenarios completed and their artifacts existed in
  S3: MySQL, MariaDB, and PostgreSQL across tiny, medium, 1,000,000-row, many-table,
  blob, Unicode, object, and mutable-data fixtures.
- MySQL restore passed all eight fixture families, subject to the missing `EVENT`
  object noted below.
- ASCII website restores passed for W1, W2, W4, W7, and W9.
- The W7 restore proved that zero-byte files, empty directories, and the
  delete-extras option worked together.
- The W9 restore preserved hidden files including dotfiles.
- Scheduling fired on time and could be paused.
- Wrong-password, unreachable-host, and SFTP authentication failures produced useful
  connection-level validation errors.
- SSH host-key approval displayed the expected fingerprint.

### Large-scale report — 2026-08-16 to 2026-08-17

- All nine database backup-creation scenarios completed under heavy concurrency:
  MySQL at 1/5/10/25 GB, PostgreSQL at 1/5/10/25 GB, and MariaDB at 5 GB.
- Website backup creation completed at 10, 25, and 50 GB.
- MySQL 1 GB and 5 GB safe-fork restores reached exact final row counts and matching
  payload hashes.
- A 10 GB website restore returned all 10,240 files with sampled hashes matching the
  source.
- Fourteen backup requests were accepted close together, the UI remained available,
  and queued work continued after one worker process was killed by the host.

These passes should be preserved as regression coverage; they do not need to be
reimplemented while fixing unrelated failures.

## Unsuccessful acceptance results

### Primary failures and partials

This table preserves the outcomes at the time of the two source reports. Use the
active tracker and live evidence table above for current remediation status; do not
rewrite historical failures as if they had originally passed.

| ID | Scenario | Result | Evidence summary |
| --- | --- | --- | --- |
| ACC-RST-PG-001 | PostgreSQL restore | **Fail** | Tiny, objects, many-tables, and mutable restores failed twice each. Fork databases were created but remained empty apart from the BackupSheep marker. The same artifacts loaded with a tolerant independent client. |
| ACC-RST-MARIA-002 | MariaDB restore | **Fail** | Tiny, objects, and mutable restores failed twice each. The artifact loaded with a matching MariaDB client, indicating a restore-client/path incompatibility rather than a corrupt backup. |
| ACC-WEB-UTF8-003 | Website special filenames | **Partial** | File contents remained byte-identical, but non-ASCII names restored as mojibake duplicates. |
| ACC-WEB-DEEP-004 | Website tree at 300 levels | **Fail** | Backup failed twice with `SOURCE_EXPORT_FAILED`; the 40-level boundary probe completed. |
| ACC-S3-100GB-005 | Website archive around 100 GB | **Fail** | The archive was built and checksummed, but S3 multipart upload stopped at exactly 1,000 parts / 8,388,608,000 bytes on the initial attempt and retry. No final object was produced. |
| ACC-WEB-2M-006 | Website with 2,000,000 files | **Fail** | Mirror enumerated all files, then export/archive failed or remained in re-archiving for more than 12 hours without producing an artifact. |

### Blocked restores caused by failed backups

| Scenario | Result | Blocking condition |
| --- | --- | --- |
| Website 100 GB restore | **Blocked** | No committed storage artifact exists because upload never completed. |
| Website 2,000,000-file restore | **Blocked** | No committed archive exists because export never completed. |

### Additional defects and risks observed during acceptance

| ID | Severity from reports | Finding |
| --- | --- | --- |
| ACC-RST-MYSQL-007 | Medium, but data-safety sensitive | A worker kill during MySQL restore led to replayed inserts before the fork eventually converged to exact final data. Tables without suitable keys could be corrupted. |
| ACC-DB-PERF-008 | Medium/performance | MySQL/MariaDB dumps use `--skip-extended-insert`; 1,000,000 rows took about 35 minutes under light load and 5,000,000 rows took about eight hours under load. |
| ACC-DB-EVENT-009 | Low/object fidelity | The MySQL `EVENT` fixture did not appear in the restored fork. |
| ACC-DB-SELECT-010 | Medium/usability and correctness | Database-node creation defaulted to no tables selected and allowed save; the first run then failed opaquely. |
| ACC-OBS-DIAG-011 | Medium | `SOURCE_EXPORT_FAILED` did not identify mirror, path, archive, validation, disk, or timeout stage, and retry history was not visible. |
| ACC-OBS-LOG-012 | Low | The failed-run Log File button called an endpoint that intentionally returns HTTP 404 in self-hosted builds. |
| ACC-UI-PHASE-013 | Low | Terminal failures could retain `Phase: In Progress`; `Download Complete` could be read as whole-run completion while upload was still active. |
| ACC-UI-STORAGE-014 | Low | Website/database storage category counters displayed zero while the total stored byte count was correct. |
| ACC-S3-ORPHAN-015 | Low/cost and hygiene | A failed or stalled multipart upload left about 8.39 GB of incomplete parts in S3. |
| ACC-DB-TLS-016 | Environment/usability | A first connection for a fresh MySQL 8.4 account could fail with `TLS_REQUIRED`, while a retry succeeded. |
| ACC-CAPACITY-017 | Operational warning | Fourteen parallel jobs drove a 2-vCPU host to very high load and one worker OOM kill. Work continued, so this was not a queue-loss failure, but concurrency needs an explicit capacity policy. |

## Incomplete or unverified coverage

Do not silently convert these entries to Pass. They require a real restore or an
explicit product decision of Not Supported.

### From the 2026-08-15 report

- W3 (four 64 MB files): backup verified, product restore not rerun.
- W5 (102,400 files): archive entries and sampled hashes verified, but no full UI
  restore was run.
- W6b (40-level tree): backup-only boundary probe; no restore.
- Four PostgreSQL fixture families were not restored after the engine-level restore
  failure was established.
- Five MariaDB fixture families were not restored after the engine-level restore
  failure was established.

### From the 2026-08-16 report

- MySQL 10 GB and 25 GB restores were not run.
- PostgreSQL 1/5/10/25 GB restores were not run.
- MariaDB 5 GB restore was not run.
- Website 25 GB and 50 GB restores were not run.
- Website 100 GB and 2,000,000-file restores were blocked by backup failures.

## Current implementation trace and cause confidence

### ACC-RST-PG-001 — PostgreSQL restore

**Confidence: cause confirmed; current and historical direct-mode tiny integration
proofs pass, with broader gates still open.**

Relevant code:

- `apps/_tasks/integration/backup/postgresql.py`
- `apps/_tasks/integration/restore_database.py`
- `apps/tests/test_restore.py`
- `apps/tests/test_database_restore_hardening.py`

Current behavior:

- The acceptance revision defaulted backup options to `-w --clean`.
- Deployed code defaults future backups to
  `-w --clean --if-exists` and persists that exact value on the backup row.
- Restore imports the dump using `psql --single-transaction
  --set=ON_ERROR_STOP=1`.
- An unconditional cleanup statement from `pg_dump --clean` can fail against a
  fresh fork where the object does not yet exist. Strict import then aborts the
  entire transaction.
- The bounded compatibility path accepts only recognized historical cleanup
  statements for a new exact-owned fork, and current/historical product restores
  `37`/`40` passed against PostgreSQL 16 with exact verification.

Do not solve this by globally disabling `ON_ERROR_STOP`; doing so could hide genuine
restore corruption.

### ACC-RST-MARIA-002 — MariaDB restore

**Confidence: cause confirmed; deployed direct/SSH, all-eight-family, 5 GB, and
pre/post-client 100,000-row MariaDB 11.8 proofs pass. Remaining cross-engine fault/UI
gates are tracked separately.**

Relevant code:

- `apps/_tasks/integration/restore_database.py`
- `apps/console/connection/models.py`
- `Dockerfile`
- `apps/tests/test_restore.py`
- `apps/tests/test_database_restore_hardening.py`

Current deployed behavior:

- MySQL and MariaDB still share `_restore_mysql_family`, but query, marker,
  permission, direct import, and SSH import commands now select `mysql` or `mariadb`
  from the authenticated engine type through one centralized selector.
- Focused and broad tests assert direct/SSH vendor selection, capability failure,
  protected credential files, and exact sandbox-header handling without changing dump
  bytes.
- Real MariaDB 11.8 direct restore `39` and SSH restore `42` passed with exact rows,
  view, header, and completion marker. Arbitrary dump lines or comments are not
  stripped.
- SSH restores `54` and `55` passed exact 100,000-row post-client/lost-response and
  pre-client recovery. Revision `f4adce3` additionally prevents the durable recovery
  task from rejecting its own sweep reservation while preserving normal backoff
  fencing for every nonmatching delivery.
- Matrix backups `72`/`73` and same-row restore `67` pass all eight MariaDB families.
  Revision `0220727` additionally fails explicit-definer archives at permission
  preflight before a first target mutation unless the authenticated MariaDB account
  has global `SET USER`/legacy `SUPER`; it preserves the original definer semantics
  rather than rewriting the dump.
- Backup `74`/restore `68` passes the signed-in 5 GB gate with exact full-row,
  payload, schema, marker, scheduler, cleanup, and terminal 1/1 evidence.

### ACC-WEB-UTF8-003, ACC-WEB-DEEP-004, ACC-WEB-2M-006 — website archives

**Confidence: Unicode and deep-tree causes confirmed and their product gates pass;
the exact two-million-file production failure remains unproven.**

Relevant code:

- `apps/_tasks/integration/backup/_archive.py`
- `apps/_tasks/integration/backup/website.py`
- `apps/_tasks/integration/restore_website.py`
- `apps/_tasks/integration/backup/errors.py`
- `apps/tests/test_backup_engine.py`
- `apps/tests/test_restore.py`

Current deployed behavior:

- New archives keep ZIP/Zip64, preserve explicit empty-directory entries, apply the
  strict UTF-8 flag to valid non-ASCII names, reject unsafe/special paths, and validate
  CRC/path/type/expansion limits before publication or destination mutation.
- The writer consumes the already verified manifest once and suppresses unbounded
  per-file `zip` output. Python validation streams central entries and spools
  duplicate/ancestor collision state to SQLite rather than retaining all names.
- The historical reader repairs only its private downloaded working copy. Backup `38`
  restored exactly as signed-in restore `20`; the committed artifact was unchanged.
- W6 failure was reproduced in `lftp`'s parallel mirror at the 3,008-byte leaf path.
  Revision `5f3678b` records that assertion and makes one clean serial mirror retry.
  Backup `41`/restore `21` then passed the exact 300-level product gate.

At this cause-analysis checkpoint, the actual SFTP mirror, writer RSS/time, full
extraction, product restore, progress, and interruption behavior at two million files
remained open. Slice 7 later closes that gate with backup `44`/restore `22` and
interrupted backup `49`; the W6 result alone was not used as evidence.

### ACC-S3-100GB-005 and ACC-S3-ORPHAN-015 — S3 multipart

**Confidence: fixed-size design limitation confirmed; exact 1,000-part stall mechanism
remains unproven.**

Relevant code:

- `apps/_tasks/integration/storage/s3_verified.py`
- `apps/_tasks/integration/storage/aws_s3.py`
- `apps/_tasks/integration/storage/tasks.py`
- `backupsheep/settings.py`
- `apps/tests/test_s3_verified.py`
- `apps/tests/test_s3_compatible_storage_adapters.py`

Current behavior:

- The acceptance revision used a fixed 8 MiB part size. The deployed Slice 8
  implementation computes aligned geometry from exact object size, configured minimum,
  bounded inventory limit, and a default target of 8,000 parts before create.
- The selected part size is persisted in multipart state and reused rather than
  recalculated after settings changes; legacy in-flight uploads recover and validate
  their prior geometry before another part write.
- The reported 107,421,554,763-byte archive would require about 12,806 parts at that
  old size, while the repository bounds multipart reconciliation at 10,000 parts.
- `_list_parts` now validates bounded pages, ordered unique part numbers, ETags,
  sizes, and advancing cursors. A focused mocked test covers a 1,001-part inventory.
- The uploader persists an ever-growing completed-parts list after each part, causing
  increasingly expensive database JSON writes.
- The report observed the exact 1,000-part API boundary, but UI-only evidence cannot
  prove whether pagination, lease/progress persistence, worker state, or another
  boundary caused the actual stop.

### ACC-RST-MYSQL-007, ACC-DB-PERF-008, ACC-DB-EVENT-009

**Confidence: confirmed behavior; object/event fidelity, four MariaDB fault
boundaries, the earlier MySQL 100k committed-row kill, and the required MySQL 1M
committed-row repetition pass. Remaining MySQL and cross-engine boundaries still
require proof.**

Relevant code:

- `apps/_tasks/integration/backup/mysql.py`
- `apps/_tasks/integration/backup/mariadb.py`
- `apps/_tasks/integration/restore_database.py`
- `apps/tests/test_backup_engine.py`
- `apps/tests/test_database_restore_hardening.py`

Current deployed behavior:

- New normal MySQL and MariaDB artifacts use extended inserts and persist their exact
  dump contract; historical row-by-row artifacts remain restorable.
- Full-object policy includes routines, triggers, and events, with proactive EVENT and
  definer privilege checks. Exact MySQL/MariaDB object/event restores passed without
  changing either server's scheduler state.
- Fork convergence drops and recreates only an exact-owned partially imported
  target, while in-place ambiguity fails closed. Restore `44` proved this behavior at
  one live boundary: after a hard kill with 87,981 visible rows, one stale-lease
  takeover rebuilt the fork and produced exactly 100,000 distinct rows and a matching
  full ordered digest. MariaDB restores `54`, `55`, `56`, and `68` cover pre-client,
  post-client/lost-response, post-marker adoption, and a 5M-row broker redelivery.
- Backup `76`/restore `74` repeats MySQL's committed-row boundary at the required
  1,000,000 rows through the signed-in product path. A kill with 962,152 visible rows
  produced one stale takeover and an exact attempt-2 fork; full ordered data, schema,
  view, marker, and terminal UI evidence match. Revision `d547501` also closes the
  stale fence-generation local-work leak exposed by the first 1M repetition.
- Revision `fecf40a` also preflights MySQL trigger/function binary-log requirements
  before target creation. Backup `88` and restores `83`/`84` additionally close the
  required MySQL 5M clean/fault repetition. Deliberately repeated cross-engine
  boundaries remain open.

### ACC-DB-SELECT-010 — empty database selection

**Confidence: confirmed.**

Relevant code:

- `apps/api/v1/database/serializers.py`
- `apps/console/_templates/console/setup/_setup_database_node.html`

Current behavior:

- New single-database UI state defaults to all tables; all-database connections
  default to all databases. Save remains disabled until the connection-appropriate
  selection is non-empty.
- The serializer now validates the effective create or partial-update state, rejects
  empty, mixed, contradictory, malformed, and wrong-connection-mode selections, and
  retains the nested serializer's existing account authorization check.
- Focused serializer regressions passed in the isolated remote test settings, and an
  authenticated invalid PATCH returned field-specific HTTP 400 without changing the
  persisted source. Slice 12's later signed-in empty-selection and field-error tests
  close Browser Save-gating.

### ACC-OBS-LOG-012, ACC-UI-PHASE-013, ACC-UI-STORAGE-014

**Confidence: confirmed.**

Relevant code:

- `apps/api/v1/backup/database/views.py`
- `apps/api/v1/backup/website/views.py`
- `apps/api/v1/backup/serializers.py`
- `apps/console/_templates/console/node/detail.html`
- `apps/console/setup/views.py`
- `apps/console/_templates/console/setup/_setup_and_list_storage.html`
- `apps/console/storage/models.py`

Current behavior:

- Transfer-log endpoints remain unavailable in self-hosted mode; the local UI no
  longer offers the dead action and instead directs the user to bounded technical
  details and the correlation ID.
- Public phase serialization now uses an explicit legacy-status map. Terminal parent
  status and source-ready parent status override stale active phases, and the UI
  renders `DOWNLOAD_COMPLETE` as `Source archive ready` without stopping polling.
- The cost summary now returns website/database/SaaS category usage from completed,
  account-scoped storage points with one grouped query per backup family. The setup
  view maps that common contract to the existing category columns, including both
  WordPress and Basecamp in SaaS, without cross-join multiplication.

## Non-negotiable implementation invariants

Every slice must preserve these rules:

1. Celery delivery is not durable operation state. PostgreSQL rows and exact provider
   readback establish recovery.
2. A retry must reuse the same logical backup/restore and provider operation identity.
3. A stale worker cannot commit after losing its lease/fence.
4. A MySQL/MariaDB fork may be dropped only after exact ownership-marker and current
   lease proof. An ambiguous or explicit in-place target is never auto-dropped.
5. PostgreSQL strict error handling remains enabled for real restore errors.
6. A multipart retry never creates a second upload until exact reconciliation proves
   that doing so is safe.
7. An incomplete multipart upload is aborted only after exact bucket, key, upload ID,
   ownership marker, and terminal-safety proof.
8. An archive is uploadable only after atomic publication, CRC validation, exact byte
   count, SHA-256, and the durable source-artifact record agree.
9. Public diagnostics expose allowlisted codes and remediation, not raw client stderr,
   provider bodies, credentials, local paths, or lease tokens.
10. A scenario does not Pass until a restore into an isolated target proves exact
    content and required objects.

## Ordered implementation plan

### Slice 0 — Reproduce and freeze regression fixtures

Status: **Pass. Every original failure has a deterministic fixture or an explicitly
bounded live-only protocol, and all declared database/website scale and crash fixtures
have recorded signed-in outcomes plus independent verification.**

Objective: turn each report failure into a deterministic, secret-free test before
changing behavior.

Required work:

1. Add real Docker integration fixtures for PostgreSQL 16, MariaDB 11.8, and MySQL
   8.4 using the same dump/import paths as workers.
2. Preserve representative report artifacts or regenerate deterministic equivalents:
   PostgreSQL `--clean`, the exact MariaDB sandbox header, Unicode names, deep paths,
   and multipart inventories spanning more than 1,000 parts.
3. Add stage-level internal metrics for mirror, manifest, archive, validation, upload,
   and restore import. Keep public messages allowlisted.
4. Record baseline runtime, peak RSS, disk/inode use, file count, part count, and
   database row/object checks.

Exit gate:

- Each primary failure is reproduced locally or is explicitly labelled live-only with
  a bounded live test protocol.
- No test depends on the existing acceptance resources or credentials.
- No production/demo mutation is required.

### Slice 1 — Fix PostgreSQL self-restore

Status: **Pass for current direct/SSH and historical direct-mode artifacts, all eight
signed-in UI fixture families, the 1/5/10/25 GB product gates, PostgreSQL crash/
reconciliation boundaries, terminal UI, and foreign-target safety.**

Objective: every BackupSheep-generated PostgreSQL backup must restore strictly into a
new isolated fork.

Required work:

1. Change future default dumps to include `--clean --if-exists` and persist the exact
   normalized options on the backup row.
2. Define a compatibility path for historical `--clean` dumps. It must be restricted
   to recognized `pg_dump` cleanup statements for a newly created exact-owned fork.
3. Keep `--single-transaction` and `ON_ERROR_STOP=1` for the actual import.
4. Reject malformed or unrecognized compatibility input before target mutation.
5. Preserve the ownership marker and include its completion update in the same
   transaction as the data import.
6. Retain current fail-closed behavior for unsafe in-place dumps.

Local implementation record — 2026-08-18:

- Required work item 1 is implemented in
  `apps/_tasks/integration/backup/postgresql.py`: the default is now
  `-w --clean --if-exists`, and the exact option string continues to be persisted on
  the backup row before export.
- Direct and SSH regression assertions in `apps/tests/test_backup_engine.py` now
  require both cleanup flags and the persisted default option value.
- Python AST parsing passed for both changed files, and `git diff --check` passed.
- At the original source-only checkpoint, no Django test command, database client,
  database server, Docker command, UI test, remote request, deployment, or resource
  mutation had been run.
- Required work items 2–6 and all automated and acceptance exit gates remain open.
  In particular, no historical-dump compatibility transform has been added without
  the real `pg_dump`/`psql` integration fixture needed to prove it safe.

Live update — 2026-08-18:

- The current-artifact automated gate now passes through the deployed product path:
  backup `56` persisted `-w --clean --if-exists`, its SQL contains cleanup statements
  with `IF EXISTS`, and restore `37` completed into the deterministic isolated fork.
- Source/fork verification is exact for the current tiny fixture: both contain three
  rows and three rows through the required view, and both canonical row streams hash
  to `9d4aeae23ac956affa844bf3a2880c0124b184bab0b1087dd660ef400525b36d`.
- Commit `49d36b85b22da4798190b2480f1252383ef328f1` adds a bounded historical
  compatibility preflight. It recognizes only `pg_dump` cleanup statements for
  database-local object classes, refuses cluster-scoped or malformed input before
  mutation, and keeps the real import strict and transactional. The deployed
  candidate passed 102/102 focused tests.
- Historical backup `58` and restore `40` then passed the product path against the
  real PostgreSQL 16 fixture with exact rows and required objects. This closes the
  current and historical direct-artifact bullets. At that checkpoint the broader
  fault matrix, UI fixture families, and large restores remained open; the later
  updates below close the small UI matrix but not the large restores.
- PostgreSQL SSH connection/auth/node/source `67`/`46`/`94`/`45` was created under
  the same run ID. Validation first failed safely because the SSH host had no client,
  then correctly rejected Ubuntu client `16.14` as older than server `16.15`. A
  client-only upgrade from the official PGDG Noble repository installed
  `psql`/`pg_dump 16.15`; validation then passed.
- Current SSH backup `63`/point `67` and restore `45` passed with clean ZIP CRC,
  persisted `-w --clean --if-exists`, exact 3-row/3-view digest
  `89c2744833ef4351242249e928f0732a793b3c9324b563c4a9b069c3d1b1f40a`,
  matching relation/index/constraint inventories, and an exact completion marker.
  No server/container configuration or data was changed to obtain the client match.
- Exact-owned PostgreSQL database `bs_remed_pg_crash_0d08dcf` and product
  connection/auth/node/source `68`/`47`/`95`/`46` contain a 1,000,000-row crash table
  plus Unicode/binary rows, view/audit, FK/indexes, functions, trigger, and sequences.
  Data generation occurred entirely on Vultr. Backup `64`/point `68` produced a clean
  45,123,255-byte ZIP with SHA-256
  `b9aee5d2cb619b9e543b215cc59d28900faafdec042f9c91c3061320083444dc`.
  Two fast restores (`46`/`47`) completed before fault monitors could fire and are
  retained as non-fault baselines.
- Restore `48` reached `database_importing` on attempt 1 and only
  `worker-database` was hard-killed two seconds later. The durable marker stayed
  `importing`, its file checkpoint stayed `in_progress`, and the source table was not
  visible in the target, proving the failed transaction had not published partial
  data. The lease expired naturally; one stale-lease takeover recorded
  `transaction_replay_count=1` and completed as attempt 2 without a manual row edit or
  replacement restore request.
- Final source/fork verification is exact across 1,000,000 rows and distinct IDs,
  min/max 1/1,000,000, ID sum 500,000,500,000, hash sum
  `2004767769598567751901`, 256 full-coverage ordered bucket digests (combined
  SHA-256 `4143b55792a19ae2fb3ee71b97b80e9417b3224b9626aef146d4282d1032054e`),
  seven sampled rows, all small data and object families in this fixture, and the
  exact completion marker. This closes the PostgreSQL 1M import-kill/replay gate, but
  at that checkpoint did not close the browser, matrix, or scale gates. The later
  eight-family run below closes the browser/matrix portion only.
- The test source initially set an explicit option already containing `-w`, so backup
  `64` persisted the harmless duplicate `-w -w --clean --if-exists`. The source
  configuration was reset to `None` after the test so future backups exercise the
  canonical default. Backup `63` already proves that exact default as
  `-w --clean --if-exists`; no application-code defect was inferred from the fixture
  misconfiguration.
- The final deployed image passed 58/58 focused database-restore hardening,
  transactional crash-safety, and durable-lease tests. These cover exact marker
  ownership/mismatch, source-checksum change, foreign marker and collision refusal,
  stale-worker fencing, atomic PostgreSQL replay/adoption, and bounded remote-temp
  cleanup. No new application change was needed for the following two live gates.
- Restore `51` was killed after the durable importing/file checkpoint but before any
  import client existed. The target had only the exact `importing` marker and no
  `crash_probe` table. After natural lease expiry, the same row was claimed as attempt
  2, recorded `transaction_replay_count=1`, and completed. Its full 1M, small-table,
  object, sequence, and marker verification matches the source, and no remote temp
  artifact remains.
- Restore `52` completed as a normal one-attempt baseline because the first test-only
  trigger was outside the fixture SSH user's accessible home. This was an
  instrumentation miss, not a product failure; no worker kill occurred for that row.
- Restore `53` used a temporary run-scoped `/usr/local/bin/psql` pass-through shim on
  the exact-owned fixture host. The shim delegated to `/usr/bin/psql 16.15` and held
  only the successful response after a restore import returned zero. At the kill
  boundary PostgreSQL's marker was already `complete`, but the durable row remained
  attempt 1/`database_importing`/0-of-1 and two namespaced remote temp files remained.
  The next natural lease takeover adopted the exact marker as attempt 2 with
  `adopted=true`, did not record a transaction replay, and completed without a second
  import. All exact data/object/sequence digests match and temp count returned to zero.
- The temporary shim, hold/ready files, and transfer copies were removed after the
  gate. `/usr/local/bin/psql` is absent, `command -v psql` again resolves to
  `/usr/bin/psql`, and the fixture reports PostgreSQL client 16.15. The database worker
  was recreated from the already-built `bc354015` image after each deliberate kill;
  no new image or code deployment occurred.
- Deployed revision `6555d57` was then exercised against two run-scoped foreign
  PostgreSQL targets using backup `63`. Markerless restore `60` and forged-marker
  restore `61` both stopped before checkpoint/import with public
  `RESTORE_RECONCILIATION_REQUIRED` and `can_resume_verification=false`. Their exact
  sentinel/marker hashes and table inventories remained unchanged, as recorded in
  the product evidence table. No target was dropped, adopted, or imported.
- Six additional run-scoped PostgreSQL sources were created entirely on the Vultr
  fixture host and combined with `pg_tiny` and the existing 1M source. The resulting
  eight families cover medium related tables, 450 tables across three schemas,
  binary/text payloads up to 8 MiB, byte-distinct Unicode, advanced objects, and a
  mutable generation. Signed-in node `96` selected exactly those eight databases.
- Generation-1 backup `68` completed at 56,309,918 bytes. The mutable source was then
  changed from generation 1 to generation 2 by updating IDs 1–10, deleting 91–95,
  and inserting 101–120; its final 115-row state has 85 generation-1 rows, 30
  generation-2 rows, zero deleted rows, all ten exact updates, and all twenty exact
  inserts. Generation-2 backup `69` completed at 56,310,353 bytes and its CRC-valid
  ZIP has exactly eight SQL files plus `backupsheep.txt`.
- Pre-fix restore `63` discovered a public-status defect without a restore-engine or
  data-integrity failure: while the parent row was still `in_progress`, a completed
  per-database checkpoint set durable phase `database_complete`. Substring phase
  classification exposed that component token as public `complete`, so the signed-in
  modal stopped polling at Complete/5-of-8 even though the worker continued to 8/8.
  Closing and reopening the modal later showed the correct durable Complete/8-of-8.
- Commit `f9669c5d9eb8b1d2f28ee820a6d264e4153383a9` gives every granular database
  and website restore checkpoint an explicit active public alias. Active
  `database_complete`/`database_restore_complete` now remain `restoring`; only the
  terminal parent status can produce public `complete`. The regression first failed
  six cases against deployed `cb7fbc8`, then passed 11/11 candidate API tests and
  21/21 exact-image API/UI/modal tests after the app-only deployment.
- Signed-in deployed restore `64`, correlation
  `28e82507-35b9-4a22-a8dd-7fa324300215`, visibly progressed through Validating 0/8
  and Restoring 0/8, 1/8, 3/8, and 7/8; it changed to Complete only at 8/8. Its one
  durable attempt has eight complete target checkpoints and eight complete file
  checkpoints, no live lease, retry, or error, and no fixture-side temp residue.
- A dedicated signed-in 1 GB gate then used source database
  `bs_remed_pg_lg1_0d08dcf`, whose 1,000,000 deterministic rows each contain a
  1,037-byte payload. Its measured source database size was 1,200,864,279 bytes.
  Backup `70`/point `74` completed to the demo block-storage destination as an
  801,978,786-byte CRC-valid ZIP with SHA-256
  `1de06b43a0385dcaaa5fba893a62f9a1f907e36650524ce3ab7804650e19b9d0`.
- Signed-in restore `65`, correlation
  `5371f447-5dc3-41b7-b7f4-771dc6fe97ea`, visibly remained active during validation
  and restoration and rendered Complete at 1/1 only after the durable parent became
  terminal. It completed in one attempt with exact source/file/target checkpoints,
  no retry/error/lease, and a completion marker bound to backup `70` and the exact
  source/target names.
- Remote source/fork verification covered every row through a 256-bucket digest.
  Both sides have 1,000,000 distinct IDs, min/max 0/999,999, sum
  499,999,500,000, 1,037-byte minimum/maximum payloads, and full-coverage SHA-256
  `e65fa0caee60a5bd6e56ea170298221e5e6c27cd5f3f63f4f734149b92594fa3`.
  All seven sampled row hashes match, as does the normalized schema SHA-256
  `c7da4dd2c41f71cc4c20bb55974ce6840156b87a1e88c341ad54097e788b3e20`.
  No large byte crossed the MacBook, targeted temp residue is zero, all containers
  are healthy, and every Celery active/reserved inventory was empty after the gate.
- The next signed-in gate used `bs_remed_pg_lg5_0d08dcf`, with 5,000,000
  deterministic 1,037-byte rows and measured source database/relation sizes of
  5,973,023,767/5,965,258,752 bytes. Backup `71`/point `75` completed through the
  product to block storage at 4,010,171,167 bytes in one upload attempt. Independent
  SHA-256 `0341551cdaed77c3555bcc950dffcc74efd3fdd87f4ebbfaf4d308cc948d192b`
  and CRC checks pass; the archive contains only the exact 5,293,890,529-byte SQL
  entry and metadata.
- Signed-in restore `66`, correlation
  `60bbe408-4020-49c6-9b54-156f9739a98b`, remained Actively running at 0/1 during
  validation and import. At the live transaction boundary, durable phase/file/target
  states were `database_importing`/`in_progress`/`importing`, the exact marker was
  `importing`, and `public.big` was invisible. The same attempt then committed and
  the UI changed to Complete/1-of-1 only after the parent/checkpoints were terminal.
- Source and fork each have 5,000,000 distinct IDs, min/max 0/4,999,999, sum
  12,499,997,500,000, and fixed 1,037-byte payloads. Their every-row 256-bucket
  SHA-256 is
  `93c588095a48c259c3a1284911ee95a55923eb19d2cbc0a3e51712fcb40d906b`;
  all seven fixed row hashes and normalized schema SHA-256
  `c7da4dd2c41f71cc4c20bb55974ce6840156b87a1e88c341ad54097e788b3e20`
  match. Its sole marker is exact/complete. No large byte crossed the MacBook; payload
  temp residue is zero; public/container health is `ok`; and every worker's active
  and reserved inventories were empty after the gate.

Restore `64` source/target equality was recomputed remotely from normalized PostgreSQL
16 dumps. Normalization removed only PostgreSQL 16's per-run `\restrict` tokens and
the BackupSheep ownership-marker schema; dump bytes never crossed the MacBook. Each
hash below is identical for the named source and its deterministic restore `64` fork:

| PostgreSQL family | Normalized data SHA-256 | Normalized schema SHA-256 |
| --- | --- | --- |
| Tiny | `87fa7ab65067edac75f19500d03e14197a83da14903326aff48af1dd47dc27d6` | `2f57664fdb7194ed357b8117d74fab4ad176bd17d124ccbd0fff6e5c6f17ea65` |
| Medium related tables | `5a00705ef853ab2fdefeb67f8e19ecad239274b8e54e77c74bd7214e883bbb10` | `4c03c64a135a0363ec045188a16eb290a5b72465ceecf70409bcd4f64d872fd2` |
| 1,000,000 rows | `80f609482cd551f08c24074fc40a2d3681dcda1f33bf71f43a5f99fa9b409718` | `30ecf69cdd0cd100dc5486ece52ee4c01d8e8f17960864dc3a6e4e07b2487cd1` |
| Many tables/schemas | `f41c461fbaa3ce645065d9a743f87ed5437f356e6dfbb2ad29dd42abbbdab4a5` | `8e3a549f9159bb8cb81e1c7aa9c1a5dd177724c23e89e57c4103ffc5da137439` |
| Blobs/text | `fd2d625103bb20ec329d6eff73065cb50e512896936f862ff7a3953cf3db7945` | `6c1d4a1af53e54d44cf403d29462595052c8eba32b735cc92f4611eac6ef7c9d` |
| Unicode | `bfb7088ee1ee80e52450ef4b868a13b7f9101034149cd3bca5eb28dbcd42d0b7` | `96ba2fee36c349855673e238a606ff98a34fb7b0a5c6ca464c0876cd3030eda9` |
| Advanced objects | `6a8bd517be48a07b7345ad5f023344549425683900c625ad60f6a39264bb5268` | `6a5a171f9641306802771ffa09c10bab90b36a22830ecf62fcd3ebba824d2d7b` |
| Mutable generation 2 | `68eb10c1fedaf8c192be8f59ff0e77f94b8a3d71f907655db24e1ef743ad7302` | `250f8bb343108dcab3d80130f7c8d2e0c1beaf23623c36b48002cc34d8cb80b8` |

The exact metric gates agree with those whole-dump hashes: the 1M family has
1,000,000 distinct IDs with min/max 1/1,000,000 and sum 500,000,500,000; the
many-table family has three schemas, 450 tables, and 450 rows; the blob family retains
the exact 8 MiB binary and 2 MiB text values; Unicode has eight byte-exact rows; the
object family retains two schemas, three tables, one view, three sequences, two
functions, one procedure, one trigger, one FK, and its expected data/audit rows; and
the mutable fork has the exact generation-2 counts described above. Every target's
sole marker is `complete` and binds its exact source, target, correlation, backup UUID,
and source digest.

Automated exit gate:

- A real current `pg_dump --clean --if-exists` artifact restores through the product
  path.
- A real historical `--clean` artifact restores through the bounded compatibility
  path.
- An unrelated SQL error still aborts the transaction and leaves no partial dataset.
- A worker kill mid-import replays the same transaction and converges once. This now
  passes for the deployed SSH 1M fixture (`64`/`48`).
- Marker collision, marker tampering, source checksum change, and lease loss stop
  without a destructive retry.

The focused automated batches and live restores above now satisfy the transaction/
fence, foreign/tampered-target, eight-family UI, exact-data, component-phase polling,
and 1/5/10/25 GB portions of this gate. Slice 1 is Pass.

Acceptance exit gate:

- **Passed:** all eight PostgreSQL families ran through the signed-in UI; exact rows,
  schemas, views, triggers, functions/procedures, sequences, indexes, FKs, blobs,
  Unicode bytes, and mutable generation-2 semantics match their isolated forks.
- **Passed:** UI polling remained active through the last component checkpoint and
  stopped only after the parent restore became terminal at 8/8.
- **Passed:** the dedicated 1 GB source exceeded 1.20 GB on PostgreSQL storage and
  restored through the signed-in product path from a CRC-valid 801,978,786-byte
  block-storage artifact, with full-coverage row and schema equality.
- **Passed:** the dedicated 5 GB source measured 5.973 GB and restored through the
  signed-in product path from a CRC-valid 4,010,171,167-byte block-storage artifact,
  with atomic visibility, full-coverage row equality, and exact schema/marker proof.
- **Passed:** signed-in PostgreSQL 10M-row backup `99` and restore `93`, correlation
  `f75458a2-c4a5-4889-a35a-f49dad03e9ad`, close the 10 GB-class gate. A deliberate
  database-worker exit `137` during attempt 1 left only the importing marker and no
  public table. Natural stale-lease takeover completed the same restore row on
  attempt 2; the UI moved from Restoring 0/1 to Complete 1/1. Source and fork match
  at exact aggregate/schema/marker boundaries and full ordered digest `93716a…`.
  Verification evidence SHA-256 begins `671ea86…`; the final namespaced-cleanup
  witness is SHA-256
  `5f3f45f597a8eef3435dad29186af1094d07ddac3f7515256acc2888c31442dd`.
- **Passed:** signed-in PostgreSQL 25M-row backup `100`/restore `90`, correlation
  `a81d628c-0bb6-4d04-9d79-011d6a398236`, close the 25 GB-class gate. The
  148,620,669-byte ZIP is source/destination identical at SHA-256
  `4626f366e04ad7bdc767d2b06ca5f58f33134b5d814219600f7b57dd2791e816`;
  its 26,163,891,715-byte SQL member hashes to
  `84773f3e099e97dd789da53abd6a620627a92143d04a6c0b45edeefd33565b1f`.
  The target reached exact aggregate/schema/marker and ordered-digest
  `c0bf5c145aec013a2649242d56d3176384faf7d60e0da1817b83610b4bc49cec`
  equality, with signed-in terminal completion. The retained exact verification
  evidence SHA-256 is
  `ee4f3f6e4c449fb4aa8d7a01191ee7bbeca5da8dd25b93e468c2992d0cfdeb1c`.
- **Passed:** combined PostgreSQL cleanup/recovery revision `be41098` passed 138/138
  focused tests in 40.359 seconds and 1,941/1,941 repository tests in 380.445 seconds.
  The evidence logs hash respectively to
  `7c33a1722e097dbf69d84b213e3c4f15e9729c9f55e684882a038ec29396c3eb`
  and `6df93d29b2c2cd6064fe491835965cb18e539965c0228cc23c5f7bcbdd6d8dad`.

Rollback:

- Revert the PostgreSQL-specific dump/compatibility slice only. Do not weaken the
  generic restore fence or transaction contract.

### Slice 2 — Fix MariaDB self-restore

Status: **Pass for the stated MariaDB exit gate: direct and SSH MariaDB 11.8
artifacts, all eight signed-in fixture families, real client rejection, explicit
import-error/manual-resume recovery, pre/post-client 100,000-row recovery, live
collision/tamper safety, and the 5 GB product restore all pass.**

Objective: select a MariaDB-compatible client and restore current vendor dumps without
weakening MySQL behavior.

Required work:

1. Centralize engine-aware client selection for direct queries, imports, permission
   probes, marker checks, and SSH commands.
2. Use `mariadb` for MariaDB and the version-matched MySQL client for MySQL.
3. Add worker-start or connection-validation capability checks that fail clearly if
   the required client is missing or too old for the dump contract.
4. Test the exact sandbox header as bytes. Never remove arbitrary first lines or
   comments from a dump.
5. Keep credentials in 0600 option files and preserve current redaction.

Local implementation record — 2026-08-18:

- `CoreAuthDatabase.mysql_family_client_binary()` now centralizes MySQL-family
  vendor selection. Connection checks/object discovery and restore query/import paths
  use `mysql` for MySQL and `mariadb` for MariaDB in direct and SSH modes.
- The restore path still uses the existing protected option files and does not modify
  dump contents. A regression passes the exact
  `/*M!999999\- enable the sandbox mode */` header to the import subprocess as bytes.
- Focused mocked assertions cover direct and SSH query selection, direct MariaDB
  import selection, and unchanged MySQL selection.
- At the original source-only checkpoint, required work item 3 and every
  automated/acceptance exit gate needing installed clients or a real MariaDB server
  remained open; no Django or real-client test had been run.

Live update — 2026-08-18:

- The deployed database-worker image contains `/usr/bin/mariadb` 12.3.2 and the
  separate version-matched `/opt/mysql/bin/mysql` 8.4.10. The 60-test hardening batch
  passed on the demo-side image.
- Real backup `57` preserved the exact MariaDB 11.8 sandbox header. Restore `38`
  failed before target mutation because the integrity validator rejected MariaDB's
  legitimate `AUTOCOMMIT off → COMMIT → AUTOCOMMIT restore` dump wrapper. Exact
  provider read-back proved that failed target was absent.
- Commit `214dba7576db316e281849fe9a0b64eb29c30b43` permits only that complete
  vendor wrapper, only for isolated MySQL/MariaDB forks. Unpaired/malformed wrappers,
  PostgreSQL boundaries, and in-place boundaries remain rejected.
- Restore `39` then completed. Source/fork verification found three exact rows and
  three view rows on each side with digest
  `58748a0e5153098a88ab8e49972eeea4ef39fbbadd39a6614da72f300a17b5ea`.
- Commit `4ef78f0a7d5976d2f6d1c4188b6b50e93f35309d` adds engine-specific
  query/dump-client capability checks for direct and SSH operation, version/vendor
  validation, an exact MariaDB sandbox-header feature probe, protected option files,
  and stable redacted `DATABASE_CLIENT_UNSUPPORTED` failures. The final isolated
  connection/backup/restore batch passed 305/305.
- MariaDB SSH backup `60` and restore `42` passed using `mariadb-dump`/`mariadb`, with
  exact rows, view, artifact header, and completion marker. Direct and SSH small
  current-artifact bullets are now proven. Import/kill/marker/lease faults, full UI
  fixture families, and 5 GB remain open;
  Slice 2 is not Done.
- A no-write live validation reused the owned MariaDB SSH credentials under a
  deliberately incorrect MySQL 8.4 engine contract. The remote MariaDB compatibility
  binaries were rejected before any backup/target mutation with safe code
  `DATABASE_CLIENT_UNSUPPORTED`, stage `worker_preflight`, `retryable=false`, and
  actionable client-install guidance. No invalid connection was persisted. This
  closes the wrong-vendor live case.
- Exact-owned SSH user `bsnodb_0d08dcf` and connection/auth `70`/`49` provide the
  entirely-missing-binary case without changing the normal fixture user's client
  path. The account authenticates with the existing run key, SFTP succeeds, and the
  database tunnel remains available, but its run-scoped shell resolves neither
  `mariadb` nor `mariadb-dump`.
- Authenticated validation of connection `70` returns HTTP 400 with
  `DATABASE_CLIENT_UNSUPPORTED`, stage `worker_preflight`, `retryable=false`, and
  explicit MariaDB/mariadb-dump installation guidance. It created no node/backup and
  removed the temporary remote credential file. The final image also passed 17/17
  focused classifier/capability tests. This closes the entirely-missing-client
  validation and public UX gate; the dedicated user/shell/connection are retained for
  later reruns, while only their temporary transfer copies were removed.
- Backup `67` is a clean 4,717,147-byte SSH MariaDB artifact containing the full
  object/event fixture plus 100,000 deterministic crash rows. Restore `54` was killed
  while its real remote client was active and later rebuilt the exact owned fork as
  attempt 2 after the remote client had completed without returning to the worker.
  Restore `55` was killed at the opposite boundary: the file checkpoint and importing
  marker were durable, but no real MariaDB client or source table existed.
- Both backup-`67` fault restores converge to the exact row, small-data, object/DDL, marker, and
  scheduler evidence recorded in the product table. Each has one logical restore row,
  one stale-lease takeover, attempt count 2, one current complete target, and zero
  remote temp artifacts. Temporary client instrumentation was target-scoped and is
  removed; the fixture again resolves `/usr/bin/mariadb 10.11.14`.
- Restore `54` also exposed a generic recovery-dispatch starvation defect: the sweep
  stored a two-minute dispatch reservation in `next_retry_at`, while the dispatched
  recovery task treated that same future value as a backoff. Repeated sweeps could
  renew the reservation before a recovery retry found a timing gap. Commit `f4adce3`
  binds the reservation timestamp in execution metadata and allows only the exact
  deterministic recovery task to consume it atomically; ordinary delivery IDs and
  later true backoffs remain blocked.
- The deployed fix passed its red/green and 89-test ladders, then restore `55` proved
  it live: the sweep-to-claim interval was 124 ms, the reservation key disappeared in
  the claiming transaction, and `recovery_claimed_task_id` records the exact recovery
  delivery. No manual restore-row edit or replacement restore request was used.
- Small object/event backup `66`/restore `56` closes the post-marker/pre-final-status
  boundary. The worker was killed after the real marker update returned zero but
  before `_checkpoint(... database_complete ...)`; durable state remained importing
  while the database marker was complete. One natural stale takeover set
  `adopted=true` and completed in about three seconds without another import. Its
  normalized data/DDL streams exactly match retained restore `50` from the same
  artifact, scheduler state stayed `OFF`, and temp residue is zero.
- Restore `57` reproduced a classification defect without mutating its markerless
  canary target: the missing marker-table query surfaced as generic
  `RESTORE_TARGET_REJECTED` before the intended name-collision branch. Commit
  `6555d57` adds only a read-only `information_schema.TABLES` fallback; a real marker
  query failure is re-raised when the marker table exists.
- On exact deployed image
  `sha256:3b7603d2d0e9f31fca257fd12a5398306b5c785d947120c4e6306b9a10fb0b33`,
  restore `58` returned public `RESTORE_RECONCILIATION_REQUIRED` for a markerless
  target and restore `59` returned the same code for a deliberately mismatched marker.
  Neither row is verification-resumable, neither gained a target checkpoint, and the
  sentinel/marker hashes and table inventories recorded above were unchanged. The
  foreign databases remain retained; no drop, import, or marker claim occurred.
- Restore `62` closes the explicit import-error gate without a code change. A
  target-scoped fixture wrapper returned exit 86 only for this restore's non-query
  MariaDB import. Attempt 1 stopped at the durable file/target importing checkpoint;
  the target contained only its exact importing marker, the global scheduler stayed
  `OFF`, and the public response remained redacted. The signed-in restore modal
  visibly showed terminal failure, phase Failed, progress 0/1, the exact correlation
  and `RESTORE_TARGET_REJECTED`, and one enabled `Resume verification` action.
- After removing the wrapper from the executable path, that UI action recorded one
  bounded `logical_fork_reconciliation` manual resume and dispatched deterministic
  task `database-restore-resume-62-1`. The same logical row completed as attempt 2 at
  1/1 with no live lease, retry, error, resumable action, product temp file, or active
  test shim. Source, retained baseline restore `50`, and restore `62` have identical
  normalized data/DDL hashes; all expected rows, views, trigger, routines, indexes,
  FK, disabled event, and exact completion marker are present. The small
  instrumentation files are retained only in the locked quarantine locations
  recorded above.
- Generation backups `72`/`73` and restore `67` close the full-fixture signed-in UI
  gate. Attempt 1 exposed a new late-failure boundary: the object dump contained
  explicit `root@localhost` definers, but the deliberately restricted matrix account
  lacked MariaDB `SET USER`. Five targets were already complete when object import
  failed. The UI correctly showed Terminal failure at 5/8 and one bounded resume
  action, but CREATE/DROP-only preflight had not prevented partial target mutation.
- Commit `0220727` scans each already-validated MySQL/MariaDB dump for real SQL
  `DEFINER=` metadata while excluding INSERT/REPLACE row text, carries that immutable
  requirement into fork permission preflight, and requires MariaDB `SET USER`, MySQL
  8.0 `SET_USER_ID`, or MySQL 8.4's `SET_ANY_DEFINER` plus
  `ALLOW_NONEXISTENT_DEFINER` before mutation. The denial is terminal, redacted,
  actionable `DATABASE_RESTORE_PERMISSION_DENIED`; it never rewrites a definer or
  silently changes object security semantics. Six new regressions and all 68 restore
  hardening tests passed on the exact deployed image.
- After only the run-owned fixture account received `SET USER`, signed-in resume kept
  restore `67` as one logical row/one manual-resume history entry. Attempt 2 adopted
  the first five complete targets, dropped/rebuilt only the exact-owned partial object
  target, then imported tiny/Unicode and completed at 8/8. Full normalized data/schema
  streams match for all eight source/fork pairs, including exact million-row,
  blob/text, Unicode, object/event/sequence, and generation-2 mutable evidence. Eight
  markers are exact/complete, the scheduler stayed `OFF`, and remote restore-temp and
  local preflight-credential residue are zero.
- The first attempt also established a performance baseline: the legacy
  `--skip-extended-insert` 1,000,000-row file sustained roughly 306 insert statements
  per second and made the database task exceed RabbitMQ's 1,800-second consumer
  acknowledgement timeout. The same delivery was redelivered after failure but became
  a durable no-op. This does not invalidate the exact restore result, but it leaves the
  Slice 10 performance and Slice 16 long-task/broker contract open.
- Signed-in backup `74` and restore `68` close the Slice 2 scale gate. The
  5,858,394,112-byte source table restored once at attempt 1 after the original broker
  delivery exceeded 30 minutes; the redelivery drained as a terminal no-op. Exact
  5,000,000-row count/distinct/range/sum, all payload bytes, seven samples, full
  ordered digest, DDL, marker, scheduler state, residue, and final Complete/1-of-1 UI
  evidence match. Later sizes remain unclaimed unless separately accepted.

Automated exit gate:

- A real MariaDB 11.8 dump containing the sandbox header restores through direct mode.
- The same contract is exercised for SSH mode.
- MySQL fixtures still select `/opt/mysql/bin/mysql` where available.
- Wrong engine/client and missing-client failures are safe and actionable; pre-client
  and post-client/lost-response kills converge through the exact fork contract.
- Explicit import failure now converges through the same logical row after a bounded
  customer-visible manual resume. Remaining cross-engine boundaries and lease-loss
  presentation still require live acceptance evidence. Markerless and forged-marker
  collision behavior is live-proven for MariaDB.

Acceptance exit gate:

- **Passed:** rerun all eight MariaDB fixture families through the signed-in UI.
- **Passed:** verify exact rows, binary/text/Unicode payloads, all required database
  objects, immutable mapping/digests, exact markers, scheduler state, and temp cleanup.
- **Passed:** restore the 5 GB MariaDB fixture through the signed-in product path and
  prove exact data/schema/marker/UI completion.

### Slice 3 — Prove duplicate-free MySQL/MariaDB crash convergence

Status: **Pass for the required MySQL scope. All four required MySQL 1M crash boundaries, visible same-row
UI recovery, local stale-generation cleanup, markerless/forged-target no-drop gates,
the full MySQL eight-family UI matrix, and the required 5M committed-row fault
repetition pass; MariaDB pre-client,
post-client/lost-response, post-marker worker-kill, 5M broker redelivery, and
foreign-target fixtures also pass. Deliberately repeated cross-engine cases remain
open.**

Objective: an interrupted fork import must never replay into a partially imported
target.

Required work:

1. Persist a restore-generation/reset witness before any owned-target drop.
2. Re-read the live restore lease and exact target marker immediately before drop.
3. Drop only the exact-owned fork; recreate it; recreate the marker; prove the target
   contains no source tables/rows; then begin import.
4. On lost client response, reconcile marker state before any replay.
5. Keep interrupted in-place imports in manual review.
6. Reset public progress when a fork generation is intentionally rebuilt so the UI
   never implies that old and new rows are cumulative progress.
7. Preserve the prior fence generation's non-secret work suffix during takeover, then
   remove only that restore row's prior and current local work/credential files.

Automated exit gate:

- Hard-kill tests at: before client start, after first committed rows, after client
  success but before checkpoint save, and after marker completion but before final
  status save.
- Every fork recovery has one logical restore row, one current generation, exact final
  row count, exact distinct-key count, matching hashes, and no duplicate data.
- A foreign or markerless target is never dropped.

Acceptance exit gate:

- **Passed:** repeat the 1,000,000-row restore with a forced worker kill.
- **Passed for all four 1M boundaries:** observe durable recovery in the UI and verify
  the target during and after pre-client, committed-row, post-client/pre-checkpoint,
  and post-marker/pre-final-status kills, including zero local work residue.
- **Passed:** markerless and forged-marker MySQL/MariaDB fork targets fail closed and
  remain byte-for-byte unchanged.
- **Pending:** repeat at 5,000,000 rows after the performance slice is complete.

Live update — 2026-08-18 through 2026-08-19:

- A dedicated MySQL 8.4 fixture and product connection first passed a normal tiny
  backup/restore (`61`/`43`) with exact data, view, trigger, two routines, FK, index,
  audit rows, and marker. This proved the deployed MySQL client path before faulting
  it. That artifact predates event export; the later `65`/`49` object/event pair closes
  the separate Slice 11 gate.
- Backup `62` contains the same object fixture plus 100,000 `crash_probe` rows. During
  restore `44`, the database worker was hard-killed in `database_importing_file` with
  87,981 partial rows visible. The surviving durable row remained In-Progress until
  its lease expired; a normal redelivery claimed it once as attempt 2. No manual
  restore-state edit or replacement restore request was made.
- The resumed worker rebuilt the exact-owned fork and completed. There is one logical
  restore row, one recorded stale-lease takeover, an exact `complete` marker, exactly
  100,000 rows and 100,000 distinct IDs (min/max 1/100,000), and matching ordered-row
  SHA-256
  `e709980cbd9f12cb4cfad98d0fa7ab1f96236b3afde84aa76dd7a1ce1d892fed`.
  The source/fork tiny rows, view, audit rows, FK, indexes, routines, and trigger also
  match exactly.
- At that checkpoint this closed only the after-first-committed-rows behavior for the
  100,000-row MySQL fixture. The later 1M product gate below supersedes its row-count
  and UI limitations; other boundaries and 5M remain open.
- Run-owned MySQL 8.4 source `bs_remed_mysql_lg1_0d08dcf` contains exactly 1,000,000
  distinct IDs, min/max `0`/`999,999`, sum `499,999,500,000`, and 1,037,000,000
  payload bytes. Signed-in backup `76`/point `80` completed in one upload attempt;
  normal restore `72` completed once and establishes the unfaulted baseline.
- Fault restore `73` was hard-killed after 211,012 committed rows and recovered on the
  same logical row as attempt 2 with exact data/schema/marker/UI proof. It also exposed
  a distinct crash-cleanup defect: the dead attempt's fence-scoped extracted tree,
  ZIP, and defaults file remained because the successful attempt cleaned only its own
  suffix. This prevented the 1M gate from being called clean despite correct data.
- Revision `d547501` records the exact prior fence-derived work suffix in the bounded
  stale-takeover history and teaches the existing storage cleanup task to remove an
  exact restore generation's directory, ZIP/manifest, MySQL defaults file, and website
  private-key file. Database and website restore finalizers enqueue cleanup for every
  recorded stale generation plus their current generation; invalid or unrelated
  suffixes are ignored, paths remain confined to `_storage`, and logs are retained.
- The pre-fix regressions failed with one error and one assertion failure; the final
  candidate passed 4/4 new tests, 55/55 focused tests, 116/116 hardening/manual-resume/
  crash/lease tests, 215/215 full affected modules, and 4/4 on the labeled image.
  Revision `d547501` is deployed to app/database/files/storage services.
- Deployed restore `74` was hard-killed at `database_importing_file` with 962,152
  committed rows, its file/target checkpoints `in_progress`/`importing`, and its exact
  marker still `importing`. The sole row remained attempt 1/0-of-1 while redeliveries
  waited for the live dead-worker lease. Natural expiry produced exactly one takeover,
  persisted prior suffix `b6ff864dc68c758f`, and rebuilt only the exact-owned target
  as attempt 2; no row edit or replacement restore request occurred.
- Restore `74` completed at 1/1 and the signed-in modal stayed active during attempt-2
  validation/replay before showing Complete. Source and fork match on all 1,000,000
  rows/distinct IDs, min/max/sum/payload bytes, view, fixture metadata, normalized
  column/index/table hashes, and full ordered-stream SHA-256
  `e8c356259d8934f396b32fd895502d4d9e3b72c3fcd95a6e7ad5d55f947e1cb9`.
  The marker is exact and `complete`; both generation cleanup tasks succeeded; only
  retained logs/phase lock remain; and targeted restore residue is zero.
- MySQL restore `75` closes the 1M pre-client boundary. A target-scoped one-shot
  wrapper held after the durable file checkpoint and before the real client; the
  exact marker was importing, only the marker table existed, and real-client/source-
  table counts were zero. The `11:32:39Z` hard kill produced one natural takeover,
  prior suffix `4cf2c7dc3d1d67cb`, safe fork rebuild, exact 1M data/schema/marker proof,
  Complete 1/1 UI, and zero targeted residue.
- MySQL restore `76` closes the 1M post-client/pre-checkpoint boundary. The real client
  returned zero after committing all 1M rows, while the marker and durable target/file
  remained importing/in-progress at UI 0/1. The `11:55:32Z` hard kill produced one
  natural takeover with prior suffix `d62e994c93c4e36d`; attempt 2 rejected the
  ambiguous generation, rebuilt only the exact-owned fork, and completed with the
  same full-row and normalized schema/view hashes as restore `75`.
- MySQL restore `77` closes the 1M post-marker/pre-final-status boundary. At the
  `12:05:09Z` hard kill, all rows and the exact marker were complete while the durable
  target remained importing with its file complete at 0/1. One natural takeover with
  prior suffix `99a96a2ff8553380` set `adopted=true`; an independent wrapper audit
  stayed at exactly one import invocation, proving no replay. Full data/schema hashes,
  marker, terminal UI, and cleanup all pass.
- Across restores `75`–`77`, source and fork each have 1,000,000 rows/distinct IDs,
  min/max 0/999,999, sum 499,999,500,000, and 1,037,000,000 payload bytes. Their full
  1,044,888,890-byte ordered raw-row stream SHA-256 is
  `e5e16d71f8e68d8faad689c645061c4bc8f3a191140b4b167ba1d716df5f8851`;
  normalized column/index/table/view hashes also match exactly. Every marker is bound
  to its correlation, backup, source, target, and immutable source digest.
- MySQL restores `78` and `79` close markerless and forged-marker no-drop safety.
  Both failed on attempt 1 before a target checkpoint/import with public
  `RESTORE_RECONCILIATION_REQUIRED` and Manual review required/Failed/0-of-1 UI.
  Markerless evidence SHA-256 stayed
  `05bbb3c5c774dd887e29d66d6dd5d07d8e17152a5bcdb581c0d9f0f96894ba36`;
  forged two-table/sentinel/marker evidence stayed
  `90129aa95b2438d43964ac7d812f8452cf6cc47713593aee90c92bc542e8e858`.
  No foreign table, row, marker field, or payload changed.
- MariaDB backup `67`/restore `54` closes the engine's post-client/lost-response
  boundary. At worker death the remote import was still active; it later left 100,000
  committed rows behind an importing marker and durable in-progress checkpoint.
  Attempt 2 could not adopt that ambiguous generation, so it re-read ownership,
  reset the checkpoint, dropped only the exact fork, recreated its marker, and
  replayed to exact final data and objects.
- MariaDB restore `55` closes the pre-client boundary. A target-scoped shim proved
  zero real clients and zero source tables after the durable checkpoint; exit-137
  worker loss left the exact importing marker intact. The deployed recovery sweep
  claimed once as attempt 2 and replayed cleanly. Full-row, small-data, and DDL
  digests match; both retained MariaDB targets have exact complete markers, disabled
  events/global scheduler `OFF`, and zero restore-temp residue.
- MariaDB backup `66`/restore `56` closes the post-marker/pre-final-status boundary.
  At worker death the database marker and all data were complete while the durable
  target remained importing at 0/1. One stale takeover recorded `adopted=true` and
  completed without re-import; normalized data/DDL match baseline restore `50`
  exactly and no temporary artifact remains.
- MariaDB restores `58` and `59` close the foreign/markerless and forged-marker
  no-drop gates. Both stopped before checkpoint/import, returned the public manual
  reconciliation code, and preserved exact before/after sentinel and marker evidence.
- MariaDB restore `62` separately closes bounded explicit import-error recovery and
  its customer-visible manual-resume observation. These MariaDB gates do not
  substitute for remaining cross-engine fault coverage or the required MySQL
  5,000,000-row repetition. The separate MySQL fixture UI matrix is now closed by
  backup `81`/restore `82`.

### Slice 4 — Establish a scalable website archive contract

Status: **Pass. The bounded ZIP contract, complete W1–W9 signed-in fixture
matrix, real-SFTP 300-level tree, measured two-million-member writer, full
two-million-file product backup/restore, same-row controlled interruption, live
case-folding/NFC-NFD collision rejection, and the plain-FTP/explicit-FTPS legal
path-component matrix pass. C0 controls fail closed on both source and compatibility
restore paths. Backups `59`–`61`/restores `36`–`38` pass the claimed 10/25/50 GB
website matrix, and the 100 GB full restore passes.**

Objective: create one archive implementation that preserves website semantics and is
safe for Unicode, empty directories, deep trees, and millions of files.

Format contract decision — 2026-08-19:

- New website artifacts remain ZIP, require Zip64 support, permit stored or deflated
  regular-file payloads, and do not permit encrypted entries. Every non-ASCII member
  name is strict UTF-8 with general-purpose bit 11 set in both the local and central
  headers. The whole committed artifact has a SHA-256 identity and every file retains
  its ZIP CRC.
- Member names are relative POSIX paths with `/` separators. Absolute paths, drive or
  UNC prefixes, backslashes, every C0 control character (`U+0000`–`U+001F`),
  empty/`.`/`..` path components,
  traversal, and local/central filename disagreement are invalid. Directory entries
  end in `/`.
- Source Unicode code points are preserved exactly. BackupSheep does not NFC/NFD
  normalize, case-fold, or silently rename names: composed/decomposed and
  case-distinct paths may coexist when the source and destination support them.
  Duplicate detection applies after separator and lexical path normalization while
  retaining exact Unicode/case distinctions. If the destination cannot represent
  that exact set, restore fails before destination mutation rather than merging it.
- Hidden files, zero-byte files, and empty directories are required semantics.
  Symlinks, sockets, devices, FIFOs, and other special files are rejected before
  publication and remain rejected by the compatibility reader; they are neither
  dereferenced nor silently omitted. The public failure is terminal and actionable.
- A file's mirrored modification time is recorded where the source protocol exposes
  it, preferably with an extended UTC timestamp and otherwise at ZIP's two-second
  granularity. It is best-effort destination metadata, not artifact identity. Owner,
  group, ACL, xattr, and executable-mode preservation are not claimed until separately
  specified and acceptance-tested.
- Publication uses a unique same-filesystem partial path, validates structure, member
  names/types, CRCs, configured expansion/member limits, and the execution fence,
  fsyncs the artifact, atomically renames it, fsyncs the parent, and only then exposes
  it for upload. Restore performs the corresponding checks in a private staging tree
  before any destination write.
- The scale implementation must keep resident memory bounded independently of total
  member count. Central-directory state and normalized-name collision state may spool
  to disk; no Python list/dict/set of all two million members is acceptable. Progress
  is monotonic in files and bytes and persisted in bounded batches, never one database
  write per file.

Current implementation boundary: the streaming parser, external CRC tester, bounded
Python writer, SQLite restore preflight, product extraction, durable checkpoint
reuse, and atomic publication have measured evidence at two million files. Backup
`50`/restore `25` additionally prove all remaining W1–W9 semantics through one
signed-in product run with an exact 103,573-file manifest and atomic delete-extras
restore. Backup `52`/restore `29` additionally prove live fail-closed behavior on a
destination that collapses both case-distinct and NFC/NFD-distinct names. Backups
`53`/`54` and restores `30`/`31` additionally prove plain FTP and explicit FTPS through
the signed-in product path. Backups `57`/`58` and restores `34`/`35` extend that proof
to the broader legal path-component matrix, while backup `56` and restore `33` prove
fail-closed C0-control handling. Backups `59`–`61` and restores `36`–`38` add exact
10/25/50 GiB artifact and restored-target proof, closing the last Slice 4 gap.

Implementation update — 2026-08-19:

- Revision `cecdac0` adds a restore-owned destination fidelity probe for SFTP
  restores. After the provider object is available and the private archive tree has
  passed structural/name/CRC validation, but before any website staging or publish,
  the worker writes four tiny case- and NFC/NFD-distinct names beneath an exact
  correlation/source-derived hidden path. It requires all four exact basenames in a
  bounded listing, renames only a restore-owned child, and cleans only the exact probe
  paths. A missing name fails terminally as `RESTORE_TARGET_NAME_COLLISION` with safe
  guidance and no website publication. Permission probing remains before archive
  fetch; a dedicated ordering regression proves the new fidelity probe is not invoked
  while an archive provider reports the object unavailable, preventing repeated target
  mutations during the live 100 GB rehydration wait. The exact isolated image passes
  20/20 focused, 170/170 adjacent restore/archive/lease, and 1,912/1,912 complete tests
  in 441.297 seconds. The exact revision is deployed and its active archive-wait row
  retains one retry per interval with zero probe/stage residue. This is implementation
  and non-colliding-target evidence only: a live case-folding/normalizing destination,
  FTP/FTPS behavior, and broader component/path-normalization fuzz still control the
  remaining Slice 4 destination gate at this historical checkpoint.
- A live collision-prone destination was prepared immediately before the stop
  instruction, but its product gate was not run. The retained root is
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/website-casefold-20260820/`.
  Its 67,108,864-byte sparse `casefold.ext4` image is mounted from `/dev/loop0` at
  `mnt/`; `mnt/casefold` is ext4 with the case-insensitive `+F` flag. A capability
  check attempted four exact basenames. The case-distinct pair collapsed to only
  `Case-sensitive-name.bin` (5 bytes), and the NFC/NFD pair collapsed to only
  `café-normalization-name.bin` (3 bytes), proving this destination exhibits both
  failure modes needed by the live product test.
- Run-owned SFTP container `bs-remed-casefold-sftp-20260820` uses exact image
  `backupsheep:79dc391e7860a4e4`, network `backupsheep_default`, no published port,
  labels `backupsheep.remediation.run=bs-remed-20260818-0d08dcf` and
  `backupsheep.remediation.purpose=website-casefold-sftp`, and bind-mounts the
  case-folding directory at `/srv/bs-remed-casefold`. It runs as `bscasefold`,
  UID/GID `22002`, using the exact run-owned public key already retained for the
  isolated 100 GB fixture. At the stop read it was running with zero restarts/OOM.
  Its tiny source contains `index.html` (16 bytes),
  `foreign-sentinel.txt` (43 bytes), and `nested/keep.txt` (12 bytes).
- Product connection/auth/node/website `81`/`12`/`110`/`27` point only to
  `/srv/bs-remed-casefold/source` with `all_paths=false`; connection and node remain
  at status `1`. Creation committed
  before post-transaction connection validation returned the safe strict-host-key
  error, “The SSH host key has not been reviewed for this destination.” At that historical
  revision, the legacy shared known-hosts file contained zero approved entries for
  `bs-remed-casefold-sftp-20260820`. No host-key preview or approval was performed;
  the source has exactly zero product backups and zero restores. Consequently there
  is no live `RESTORE_TARGET_NAME_COLLISION` result and this does not close Slice 4.
- On resume, reuse this fixture rather than creating another one. First independently
  verify the displayed host-key fingerprint out of band, then use the signed-in
  preview and explicit approval flow and validate connection `81`. Create a tiny
  backup on a small exact-owned destination, hash the source sentinel and manifest,
  and request the restore through the signed-in UI. The exit gate is one terminal
  `RESTORE_TARGET_NAME_COLLISION` row before staging/publication, unchanged sentinel
  and source manifest, zero probe/stage residue, no retry loop, and no duplicate
  restore row. Do not perform any of those actions without renewed active-work
  authorization.
- Live closure update — 2026-08-22: the signed-in host-key preview exactly matched the
  independently read ED25519 fingerprint and was explicitly approved. Backup `52` is
  a CRC-clean 1,197-byte three-file product archive. Pre-fix restore `28` reached the
  collision boundary but exposed generic public error mapping. Exact deployed commit
  `7657d27` then preserved `RESTORE_TARGET_NAME_COLLISION`, and signed-in restore `29`,
  correlation `49dcaa3f-c114-4593-a5e0-7541cb517e72`, failed terminally in one attempt
  before publication with `delete=false`. The target's three exact hashes are
  unchanged; local work, remote probe/stage/partial, lease, retry, and duplicate-row
  counts are zero. This closes the live case-folding/NFC-NFD destination gate without
  making a claim about the later protocol runs or broader component coverage.
- FTP/FTPS closure update — 2026-08-22: one run-owned `pyftpdlib` fixture serves a
  tiny three-file tree over plain FTP and explicit FTPS from demo block storage. The
  FTPS connection stores `ftps_use_explicit_ssl=true` and `verify_ssl=false` for its
  seven-day self-signed test certificate. Connections/auth/nodes `82`/`13`/`111` and
  `83`/`14`/`112` were created and validated through the signed-in website-integration
  UI; both remained Active. No backup or restore endpoint was called directly.
- Signed-in plain-FTP backup `53`, point `55`, UUID
  `bs-bs-remed-20260818-0d08dc-n111-b53`, completed once with three files and a
  CRC-clean 777-byte ZIP. Its artifact SHA-256 is
  `04c26ae7c35f54adb74b7798656a9ba62ae2d72783298781d4bbefa0834e0a29`.
  After the source tree was moved aside and replaced by one foreign file, signed-in
  delete-extras restore `30`, correlation
  `8e7fef1b-0153-4278-bf38-c175683e8c26`, completed in one attempt at 1/1. The
  foreign file is absent and the restored hashes are exactly
  `f17cf8db09aa7c93a12e038636eb1649be2ee3885ee84e1b8dafea0e6762e2c7`,
  `1be8165d849e8d54a1a4d12a3b0691107a14c7b26c592ea3996f51dd6ed82667`, and
  `49a790e35ac6610984bf247ac581ddde3e36942cbecddd293224b8aae0f611e7`.
- Signed-in explicit-FTPS backup `54`, point `56`, UUID
  `bs-bs-remed-20260818-0d08dc-n112-b54`, completed once with three files and a
  CRC-clean 787-byte ZIP. Its artifact SHA-256 is
  `4c60e87d346946787140a87eccab4b0b15197ea962894193e94453e192d04192`.
  The equivalent foreign-file mutation followed by signed-in delete-extras restore
  `31`, correlation `1e6724d2-5ad2-429f-a8bf-29b53573e60a`, completed in one attempt
  at 1/1 and reproduced the same three payload hashes. Both restores have empty
  lease/error/retry state, zero remote stage/partial residue, and exact three-file
  source counts. The fixture and affected app/files/default/database services report
  zero restart/OOM. Relevant files/default/storage/database queues are drained; the
  pre-existing unrelated cloud delivery remains one unacknowledged message. This
  closes the small plain-FTP and explicit-FTPS functional gates without claiming the
  broader path-component fuzz gate.
- Path-fuzz failing control — 2026-08-22: the first broader plain-FTP source contained
  29 regular files, 12 non-root directories, and 263 bytes across leading/trailing and
  repeated spaces, leading dash, dots, quotes, shell metacharacters, brackets/braces,
  percent/hash/plus, hidden and zero-byte entries, empty directories, a 240-byte
  component, case-distinct and NFC/NFD-distinct pairs, Arabic/CJK/Cyrillic/emoji, and
  one tab-containing basename. Its canonical manifest was
  `b0eedf6be9069f2a2a11c9251c7d4eac3c2b653707def007a298122490cb57da`.
  Signed-in backup `55`, point `57`, UUID
  `bs-bs-remed-20260818-0d08dc-n113-b55`, completed as a CRC-clean 7,547-byte ZIP,
  SHA-256 `2ef4bea8c43d5e1a4138411b7984a16431d1607e7931d91ed2817faca99f09b3`,
  with the same manifest. Pre-fix signed-in delete-extras restore `32`, correlation
  `f4cb6418-1af6-4773-a885-4a45c54ae666`, then incorrectly rendered Complete even
  though FTP had silently changed only `tab\tname.txt` to `tabname.txt`; counts and
  bytes remained `29/12/263`, but the restored manifest became
  `55a5992a34e22fd15321b6ae6d48727afd5d9eaa46a73ed14185b99ab48660ee`.
  This is the retained live failing control for the portable-name boundary.
- Revision `8f8a4796daf65ac563e32cf4ba18e933fb7fae46` rejects every C0 control before
  website archive publication and rejects the same set in compatibility restore
  members before destination mutation. The two fail-first regressions reproduced the
  old behavior; the implementation then passed 2/2 focused, 33/33 affected, and the
  complete 1,926/1,926 suite in 383.107 seconds. It was pushed and deployed as exact
  image `sha256:32afe78b16a9b22caef207dffa302454bd2a610bd844432c848ec526547fce45`
  after mode-0600 PostgreSQL snapshot
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/deployments/8f8a4796daf65ac563e32cf4ba18e933fb7fae46/predeploy-backupsheep.dump`,
  SHA-256 `6b9d464d822df159cfea88e3041775c7130fe428387ac4fdeb0e9432f9a9bb1c`.
  The app and exact files/default/database workers report the deployed revision, zero
  restart/OOM, healthy web status, clean Django checks/migration state, six responsive
  workers on their expected queues, and empty active/reserved/durable work.
- Historical-archive post-deploy restore `33`, correlation
  `4954e57a-d0a2-4c4f-97b3-69cecb52c8a2`, was requested through the signed-in UI
  from backup `55` with `delete=true`. The modal rendered Terminal failure / Failed
  with the integrity guidance. The durable row is one attempt with exact
  `RESTORE_INTEGRITY_FAILED`, no retry or remaining lease. The destination remained
  exactly one zero-byte `foreign-only-control.txt`, SHA-256
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
  and no probe/stage/partial residue exists.
- Source-side control node `114` was created through the signed-in plain-FTP flow and
  points only to a three-file fixture containing one safe name, one tabbed name, and
  one `U+001F` name. Signed-in backup `56`, UUID
  `bs-bs-remed-20260818-0d08dc-n114-b56`, failed terminally on attempt 1 at zero
  files/bytes. The Activity UI visibly shows exact
  `SOURCE_SPECIAL_FILE_UNSUPPORTED` and remove-or-exclude guidance without the source
  path. No archive/artifact record or upload attempt was published; request point `58`
  remains only a non-uploaded intent row, and the source is unchanged.
- After removing the deliberately unsupported tab member, the legal matrix contained
  exactly 28 regular files, 12 non-root directories, and 259 bytes with canonical
  manifest `d6b4cbf723034d2f75bb008fcc30ae1e72463df02fbeee036ac5428a90845c4b`.
  Signed-in plain-FTP backup `57`/point `59` produced a CRC-clean 7,397-byte artifact,
  SHA-256 `3c1133ba74bf25ca02f51f2eba04fbf57117dbdf45a22001f0dadbc06e76eebf`;
  signed-in explicit-FTPS backup `58`/point `60` produced a CRC-clean 7,479-byte
  artifact, SHA-256
  `9def263233a66a8c9fba5a57e23d39679828bce62262cefb2755338638b3810b`.
  Both archives reproduce the exact source manifest. Delete-extras restores `34` and
  `35`, correlations `03f81b82-5db8-4edc-9cea-1b938eef25cb` and
  `11b134ac-3e17-49ab-a064-52d36e7113de`, completed through the signed-in UI on one
  attempt at 1/1. Both targets reproduce the exact `28/12/259` manifest, delete the
  planted foreign file, leave no retry/lease/error, and leave zero probe/stage/partial
  residue. This closes the broader legal path-component and portable-control gates for
  both FTP modes; the then-open claimed 10/25/50 GB website matrix is now closed by
  backups `59`–`61`/restores `36`–`38`.
- Revision `f19bd55` changes the manifest pass into a deterministic per-directory
  ordered scan using `lstat`. It accepts only real directories and regular files;
  file/directory symlinks, FIFOs and other special types, a symlink/non-directory
  source root, backslashes, and all C0 controls are rejected before `zip` is invoked.
  The private exception may retain the relative path for diagnostics, while the
  persisted/public error remains path-free `SOURCE_SPECIAL_FILE_UNSUPPORTED` with
  explicit remove-or-exclude remediation.
- The manifest is written to a unique mode-private partial file, flushed and fsynced,
  and atomically renamed only after a complete scan. A policy error publishes neither
  manifest nor ZIP. The task now preserves the structured non-retryable failure
  through `NodeBackupFailedError`, the notification allowlist, and terminal backup
  state, and does not schedule four identical retries.
- The exact combined candidate passed all 101 `test_backup_engine` tests; 65 focused
  archive/error/website-task/execution-state/restore-extraction tests; and all seven
  finalizer tests including file symlink, directory symlink, FIFO, invalid line-name,
  deterministic manifest, full cleanup, and incremental-cache retention. The files
  were mounted read-only over the deployed image and every disposable test database
  was destroyed. This is pre-deployment evidence only.
- Revision `6e0eafd` replaces `ZipFile.infolist()` in UTF-8 header repair with a
  one-entry-at-a-time parser for standard and Zip64 end records, Zip64 local-header
  offsets, optional central signatures, archive comments, and strict local/central
  filename agreement. It patches only the two UTF-8 flag fields and holds at most one
  central record's bounded filename/extra data. Synthetic Zip64 end-record and
  per-entry-offset regressions pass, including a guard that fails if `ZipFile` is
  instantiated by the repair path. The exact candidate passed 103/103 archive and
  restore tests followed by 13/13 focused archive/extraction tests. Revision
  `c40d37d` separately updates two stale SSH MySQL assertions from opportunistic
  `PREFERRED` to the already-committed `REQUIRED` TLS contract. None of these
  revisions had been deployed at this historical checkpoint while restore `68`
  remained active; their later deployment and terminal evidence are recorded above.
- Revision `129e386` reuses the streaming standard/Zip64 reader for archive metadata,
  validates every local/central header pair, finds required database dump suffixes
  without `namelist()`, and sends CRC verification to quiet Info-ZIP testing without
  retaining per-member Python objects or command output. Revision `320d5d3` replaces
  restore's `infolist()` and Python collision `set` with a mode-private disposable
  SQLite `WITHOUT ROWID` index on the destination filesystem, committed in bounded
  batches. It rejects lexical ambiguity, duplicate paths, file/descendant conflicts
  in either order, special/encrypted/unsupported members, configured member/expansion
  limits, and insufficient disk before a quiet `-UU` extraction into the private
  staging tree. Temporary index and partial trees are removed on every tested failure.
  The exact candidate passes 10 archive tests, 21 combined archive/extraction tests,
  102/102 backup-engine tests, 101/101 full restore tests, and a final 13/13 semantic
  extraction run covering CRC failure, hidden/zero-byte/empty-directory semantics,
  case-distinct paths, and composed/decomposed Unicode names. This remains
  pre-deployment evidence and does not substitute for measured high-cardinality RSS.
- A run-owned block-storage fixture now covers 10,000, 100,000, 1,000,000, and
  2,000,000 empty regular-file members at
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/fixtures/archive-scale-20260819`.
  The artifacts are respectively 1,300,022; 13,000,098; 130,000,098; and
  260,000,098 bytes with SHA-256 `81f1d8a087bc470b2d0035b40b04827162b12f1aa07fa78ff8c45a0613215c73`,
  `48ae512f7d153e157589bd3b00325d4fbab53ea79d5f48054cc3f0f9645951c2`,
  `24e412ec03a716f9918a173c358bfa34bedab113df739957fe3eda0f97d0741c`,
  and `684aede362d3e109e566bf19308c899716744600c4855ac887bd0dad9998ede4`.
  The one-entry-at-a-time validator plus Info-ZIP CRC test took 0.223/1.838/19.057/
  35.007 seconds with Python and child peak RSS between 22,388 and 22,536 KiB.
  The SQLite restore preflight took 0.516/4.518/43.379/74.667 seconds with peak
  Django-process RSS between 186,152 and 186,872 KiB; every disposable index was
  removed. Full private-staging extraction of 10,000 and 100,000 members took 0.567
  and 10.588 seconds at 186,540/186,620 KiB and produced exact 10,000/100,000 file
  counts. Those exact run-owned extracted trees were then removed, freeing 110,000
  inodes; the four compact ZIP fixtures are retained for repeatability.
- Revision `c1a202b` raises the sample/configured default and defensive restore
  fallback from 1,000,000 to 2,100,000 members, enough for the reported 2,000,000
  files plus 1,000 directories while retaining a hard safety ceiling. A candidate
  process with no environment override resolves the exact value `2100000`. The
  metadata/preflight evidence is not a substitute for the required real mirror,
  product upload, full extraction, exact hash verification, or interruption rerun.
- Revision `e4205be` removes two writer-scale hazards. Info-ZIP now runs quiet with
  stdout discarded and stderr disk-spooled to a bounded diagnostic tail, so two
  million per-file `adding:` lines cannot accumulate in worker memory. The source
  policy scan writes a second private, fsynced file/directory stream during the same
  deterministic walk; `zip -@` consumes that exact stream, including explicit empty
  directories, instead of running a second recursive directory enumeration. The
  public `.files` manifest remains file-only and unchanged. Timeout kills the child,
  removes staged output/member state, and now classifies as `BACKUP_TIMEOUT` rather
  than opaque export failure. The full backup-engine module passes 103/103, a focused
  archive/finalizer/error set passes 28/28, and the final 9/9 finalizer run preserves
  empty directories plus exact Unicode, spaces, single quotes, and double quotes with
  no private member-list residue. Actual two-million-file writer timing/RSS is still
  required before this sub-gate can pass.
- The `e4205be` writer was then measured against real run-owned block-storage trees
  containing 10,000 and 100,000 extracted empty files. Its full write, UTF-8 repair,
  CRC validation, and metadata reread completed in 0.930 and 10.091 seconds. Python
  peak RSS stayed 22,860/22,796 KiB; child peak RSS was 22,860 KiB at 10,000 and
  55,028 KiB at 100,000, so the external writer—not Python—still has a measurable
  entry-count slope that must be checked at two million. The exact outputs contain
  10,000/100,000 entries, are 1,820,022/18,200,098 bytes, and have SHA-256
  `85bbfdbb8e6bc3d75af786730b33d4834488188371ba4f50daf80b6f5e4e83c0` and
  `4d91a08013418f3b06a29c22d093e9b5f0ff7c670050d9cdcee6b212340ce95f`.
  The exact 100,000-file source tree was removed after verification to free its
  inodes; compact source/output ZIPs and member lists remain under the recorded
  archive-scale fixture directory.

Required work:

1. Define the format contract before implementation:
   UTF-8 filenames, Zip64, hidden files, zero-byte files, empty directories, timestamp
   behavior, path normalization, symlink policy, duplicate-name policy, CRC, and
   atomic publication.
2. Select or build a bounded-memory archive writer. A naive Python `ZipFile` walk is
   not acceptable until its two-million-entry memory use is measured.
3. Stream or spool central-directory state rather than retaining unbounded per-entry
   Python objects.
4. Avoid traversing the same tree independently for manifest and archive when a
   single verified enumeration can feed both.
5. Emit monotonic file/byte progress in bounded batches, not one database write per
   file.
6. Preserve current source-artifact fsync, checksum, CRC, and fence semantics.

Automated exit gate:

- W1 through W9 all pass signed-in product backup/restore gates; W6 and W8 also retain
  independent deep-tree and current/historical Unicode witnesses.
- Unsafe paths, duplicate normalized names, symlinks/special files according to the
  chosen policy, archive bombs, and CRC failures remain rejected before restore writes.
- Peak memory stays within an explicit bound as entry count increases.

Rollback:

- Keep the old archive implementation behind an internal compatibility reader only if
  needed for existing objects. Do not route new backups back to a writer known to
  corrupt non-ASCII names.

### Slice 5 — Close Unicode filename round-trip

Dependency: Slice 4.

Status: **Pass for newly produced and retained historical small archives. Remaining
destination-collision fuzzing and high-cardinality work stays open under Slice 4.**

Required work:

1. Ensure non-ASCII archive entries carry the correct UTF-8 representation/flag.
2. Define normalization behavior without silently renaming distinct source files.
3. Detect collisions where two archive names normalize to the same restore path.
4. Preserve exact original name bytes/Unicode code points where the source protocol
   exposes them reliably.

Exit gate:

- Backup and UI restore exact names and bytes for accented Latin, Arabic, CJK,
  Cyrillic, emoji, composed/decomposed forms, quotes, spaces, hidden files, and nested
  combinations.
- Restoring onto an existing site does not create mojibake duplicates.

Live update — 2026-08-18:

- Backup `38` reproduced the report exactly: Info-ZIP wrote valid raw UTF-8 filename
  bytes while leaving general-purpose bit 11 clear, so Python/standard ZIP readers
  decoded the names as CP437 mojibake.
- Commit `cf9e97b1cb54c21a669fe130cf1050501db2b188` makes a bounded second pass over
  the already completed ZIP and sets bit 11 in matching local/central headers only
  when the raw non-ASCII name is strict UTF-8. It does not rewrite file payloads,
  compression, CRCs, Zip64 offsets, symlink representation, empty directories, entry
  order, or invalid byte names.
- Remote Linux tests passed 21/21, including distinct NFC/NFD names. Backup `39`
  carried the flag on every non-ASCII entry and passed CRC validation. Restore `18`
  returned the mutated destination to the exact 15-entry manifest
  `3ba55b6127c753b58dd04b87ec44fcd33c147d142c5c12aec9e2e6399567360f`
  with no mojibake, duplicate, extra, or restore-staging path.
- The live fixture covered accented Latin NFC/NFD, Arabic, CJK, Cyrillic, emoji,
  quotes, spaces, a hidden file, zero-byte file, empty directory, and nested mixed
  names. The action was product API/task acceptance, not a browser-click UI gate.
- Backup `38` remains the retained historical unflagged artifact. Revision
  `6f49977d1a3a8d470472802c6658ecbac580634b` is deployed. It applies the same header-only
  valid-UTF-8 bit repair to the worker-owned downloaded restore copy before the
  existing CRC, path, duplicate, special-file, expansion, and disk checks; the
  committed provider object and compressed payload bytes are not changed. The
  historical-format regression first proves the filename is mojibake with bit 11
  clear, then restores the exact accented-Latin/Arabic/emoji path and payload.
  The deployed Linux image passes all 95 `apps.tests.test_restore` tests and all five
  `apps.tests.test_archive` tests with the candidate files mounted read-only.
- Revision `6e0eafd` removes that repair path's full `infolist()` allocation. It
  streams one standard/Zip64 central entry at a time, resolves Zip64 local-header
  offsets from bounded extra data, checks exact local/central filename and flag
  agreement, and keeps legitimate standard-ZIP maximum field values distinct from a
  real Zip64 locator. Revisions `129e386` and `320d5d3` then stream validation and
  spool exact duplicate/ancestor collision state to disk. The final semantic run
  preserves case and NFC/NFD distinctions while rejecting lexical ambiguity and
  conflicts in either entry order. This narrows but does not close Slice 4: measured
  external-tool memory, high-cardinality acceptance, and destination-specific
  pre-mutation collision behavior remain open.
- Signed-in restore `20` of retained backup `38` completed at attempt 1/1-of-1 after
  the fixture target was isolated safely. Source and restored trees have the same
  exact 15-entry canonical manifest SHA-256
  `2eb24411702c799d58eeeb19f6297d55ddd0352ed3ab5ffa5c24aef4b73276d9` with no
  mojibake, duplicate, or extra names. Restore `19` is retained as a fixture-layout
  failure: its bind-mounted destination could not be renamed, and it did not expose a
  reader defect. Slice 5's stated small-artifact exit gate is closed; malformed-name,
  destination-collision fuzzing, and bounded high-cardinality work remain Slice 4.

### Slice 6 — Close the deep-tree failure

Dependency: Slice 4 instrumentation and format contract.

Required work:

1. Binary-search depth and total path length to identify the actual failing stage.
2. Use a short working-root path and relative or descriptor-based traversal where it
   avoids artificial local `PATH_MAX` pressure.
3. Keep remote protocol limitations distinct from worker filesystem and archive
   limitations.
4. If a hard supported limit remains, preflight as early as safely possible and return
   a non-retryable `SOURCE_PATH_LIMIT`-style code with remediation.

Exit gate:

- Preferred: W6 at 300 levels backs up and restores with exact count/hash/path checks.
- Fallback product decision: a documented limit is enforced before repeated export
  work, with a clear UI error and no automatic retry loop.

Candidate isolation update — 2026-08-19:

- A run-owned block-storage tree with 300 `level-NNN` components produced a
  2,999-byte relative directory path and one terminal payload. Revision `e4205be`
  consumed its exact member stream, wrote/validated a 301-member ZIP (300 explicit
  directories plus one file) in 0.124 seconds, and the bounded restore path extracted
  it in 1.497 seconds. The 948,116-byte artifact has SHA-256
  `89c00663a9e13812a731c72237e24766d16ce4024876f937f39f8e1e33efe7ec`;
  the restored leaf exactly matches source SHA-256
  `37797ce614eab787966eca65cf74fb2d97c4ecca094467e38575a92fe6219b43`.
- This originally closed only the local policy scan, member-list writer, ZIP
  validation, and private extraction stages at depth 300, narrowing the historical
  instant failure to the remote mirror/product path or the older implementation. The
  later product result below supersedes the formerly open real-SFTP gate. The exact
  local candidate source/restored directory trees were removed after
  verification; the compact ZIP and member list remain in the archive-scale fixture
  directory.
- The real remote rerun fixture is now prepared separately at
  `/srv/bs-remed-website/deep300-0d08dcf` on the exact-owned Vultr VM. It is owned by
  the existing `bsfixture` SFTP account and contains 301 directories including the
  source root, one terminal `leaf.txt`, and a 2,999-byte relative directory path. The
  leaf SHA-256 is
  `8c12760e20c837a5e5d56278b4451136c4d44cc69323374c43ec2434eabb0c39`.
  Preparation did not modify `/srv/bs-remed-website/source`.
- Pre-fix product backup `40` reproduced an `lftp` parallel-mirror path assertion and
  was explicitly cancelled in the signed-in UI to prevent replay. Revision `5f3678b`
  preserves that first failure in the log, cleans the incomplete mirror, and performs
  one bounded serial retry for this exact parallel assertion. Its focused module
  passed 23/23 and the full website group passed 214/214 before deployment.
- Signed-in node `101` backup `41` then completed on attempt 1. Its 970,666-byte
  CRC-clean artifact has SHA-256
  `01223b8637d430b3c607d5e7b19118b32fcfd55f8561e7e16eb1566c391d9913`.
  Signed-in restore `21`, correlation `cb7067e4-c3ba-48d4-aed3-06af7954b6b8`,
  completed at 1/1. Source and destination each contain 301 directories plus one
  file, retain the 2,999-byte relative directory/3,008-byte leaf path, and share exact
  canonical manifest SHA-256
  `f12ad78bcb8eb00df9ac512ad2c5e76a62d8cda9a9aeefb3cc2b44a72fcdf398`.
  This closes Slice 6's preferred W6 exit gate. W6b remains an independent boundary
  regression in the final matrix.

### Slice 7 — Close two-million-file backup and restore

Dependencies: Slices 4 and 6.

Status: **Pass. Signed-in backup `44`/restore `22` close the clean path; controlled
backup `49` closes worker interruption, natural same-row takeover, exact mirror
checkpoint reuse without another source transfer, private-partial cleanup, atomic
publication, one upload, final artifact integrity, and terminal UI.**

Live acceptance record — 2026-08-19:

- Backup `44` produced and uploaded one 612,497,006-byte, 2,002,005-entry artifact;
  restore `22` reproduced exactly 2,000,000 files, 2,000 source directories,
  68,000,000 logical bytes, and the run's 4,100-file stratified witness, with no
  correlation-scoped stage residue.
- Backup `49` was interrupted only after its durable checkpoint bound the exact
  two-million-file source and a private archive was growing. Broker redelivery was
  fenced until natural lease expiry. Attempt 2 reused the checkpoint, ran no second
  source mirror, removed the old partial, and atomically published a new artifact.
  Its source/destination identity is 612,497,006 bytes and SHA-256
  `3bb9cc5b8e933e3204c99fe89ae53bf02890b22495f1e0b52d0bb6fe7fc35036`;
  CRCs, 2,002,005 entries, and the bounded 4,100-file sample pass. The UI reached
  Complete with resolved recovery and exact progress.

Required work:

1. Add disk-byte and inode preflight based on current mirror/cache state and expected
   archive overhead.
2. Persist a durable `mirror_complete` checkpoint bound to node configuration,
   source/mirror identity, and execution fence.
3. If archive creation fails while the verified mirror remains exact, retry archive
   only; do not re-transfer two million files.
4. Keep partial archives under a unique staged name and never publish/upload them.
5. Ensure retry cleanup cannot delete the shared incremental cache for another live
   execution.
6. Expose file-count progress and current stage in the UI.

Automated exit gate:

- A generated high-cardinality fixture demonstrates bounded memory and monotonically
  increasing progress.
- Worker kills during manifest, archive body, central-directory finalization, fsync,
  and publication never produce a committed partial archive.
- Archive retry reuses the exact verified mirror and does not rerun transfer.

Acceptance exit gate:

- Back up 2,000,000 files, commit/upload the artifact, and restore to an isolated
  target.
- Verify 2,000,000/2,000,000 files and a deterministic stratified hash sample across
  all directories.
- Repeat with one controlled archive-worker interruption.

### Slice 8 — Fix 100 GB multipart upload and resume

Objective: make part geometry valid for the object size and prove resume across the
1,000-part pagination boundary.

Required work:

1. Compute part size before multipart creation from object size, configured minimum,
   provider bounds, and a conservative target part count with headroom.
2. Persist the chosen part size in immutable multipart state; retries must not change
   geometry.
3. Add direct `_list_parts` pagination tests with 1,001+ parts, malformed/non-advancing
   cursors, repeated pages, missing fields, and the configured page/item bounds.
4. Stop saving the complete growing ETag list after every part. Persist bounded
   progress/checkpoints and obtain the exact final ordered part list from provider
   inventory before completion.
5. Stream bounded part bodies instead of holding an unnecessarily large adaptive part
   fully in memory.
6. Renew upload lease/progress heartbeat during long calls and after bounded batches.
7. Detect a no-progress window and transition to a visible retry/reconciliation state
   rather than indefinitely displaying active work.
8. Preserve the existing rule that an ambiguous create or complete outcome is
   reconciled before any second mutation.

Local implementation record — 2026-08-18 through 2026-08-19:

- New multipart uploads choose an MiB-aligned part size before the create request
  using exact object bytes, the configured minimum, S3 bounds, the bounded inventory
  limit, and `S3_MULTIPART_TARGET_PARTS` (default 8,000). The reported
  107,421,554,763-byte boundary computes to 13,631,488-byte parts and 7,881 parts
  instead of exceeding 10,000 parts at 8 MiB.
- The chosen `part_size_bytes` is stored in durable multipart state and validated on
  retry. A legacy upload without that field recovers its prior geometry from remote
  part sizes where available and otherwise uses the legacy configured size; unsafe
  geometry stops before another part write.
- `_list_parts` now has bounded page validation and rejects malformed collections,
  invalid/repeated/out-of-order parts, missing ETags, invalid sizes, missing cursors,
  and non-advancing cursors. Focused tests cover 1,001 parts and malformed/repeated
  pages.
- Revision `926ae46` closes the local implementation work in items 4–7. Multipart
  state now stores bounded part/byte counters, timestamps, and a final inventory
  digest rather than saving the growing ETag list after every part. Upload bodies are
  seekable views over one bounded file range; checksum-enabled providers hash in
  bounded chunks without materializing the adaptive part. Completion obtains and
  validates one fresh ordered provider inventory with exact part numbers and sizes.
- The existing renewable storage lease continues heartbeating during provider calls.
  Each new part and completion mutation now rechecks the exact live fencing token,
  while bounded progress batches revalidate it again on persistence. A stale worker
  that has lost ownership fails before its next provider mutation. Persisted progress
  tracks a bounded no-progress window; expiry changes the durable phase to
  `multipart_no_progress` and raises a retryable reconciliation outcome. The next
  bounded retry may resume from fresh provider inventory instead of remaining
  indefinitely active.
- The isolated demo-side candidate at
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
  `candidates/multipart-bounded-20260819/` passed 36 focused multipart tests, 97
  broader S3-compatible/storage tests, and 4 real-model lease-fencing tests. Those
  batches include two-part bounded-body/checksum behavior, crash adoption, missing
  final inventory rejection before completion, lost-complete HEAD-only
  reconciliation, visible no-progress recovery, and stale-lease fencing. Each test
  used an isolated disposable database, which was dropped afterward.
- The live gate is now closed on Vultr object storage. Backup `42`/point `44` used
  exact 107,421,554,763-byte source
  `bs-remediation-100gb-sparse.zip`, adaptive 13,631,488-byte geometry, and 7,881
  parts. `worker-storage` was hard-killed after durable part 1,008; fresh inventory
  exposed part 1,020 under the same upload ID, and natural attempt 2 adopted the
  twelve beyond-checkpoint parts without a second multipart creation.
- The final exact-prefix inventory has one object and zero unfinished multipart
  uploads. Provider HEAD, persisted state, the independently hashed source, and a
  full streamed provider read all agree on 107,421,554,763 bytes and SHA-256
  `71ec61b44453a81201295bcb2f480c74b653f18333319821857cab74ba0775d1`.
  The object ETag is `f85bcf1d85f95ec5b2047c0b45e530fa-7881`. The temporary
  Docker bind target was detached only after this proof; retained source/object
  evidence was not deleted.

Automated exit gate:

- Geometry never exceeds the provider/repository part limit for boundary object sizes.
- Resume works with inventories below, at, and above 1,000 parts.
- Kill after a part upload but before local checkpoint: remote inventory is adopted.
- Kill after complete request but before response: exact object is adopted or remains
  safely pending; no second multipart upload starts.
- A stale worker cannot upload or complete after lease takeover.

Acceptance exit gate:

- Upload the reported roughly 100 GB archive to an isolated prefix.
- Verify exact object bytes/SHA-256 metadata and final provider object state.
- Interrupt one upload after it crosses 1,000 parts and prove resume without duplicate
  upload/object identity.

Status: **Pass.** All three live acceptance bullets above are satisfied by backup
`42`/point `44`; the distinct full website restore gate remains listed in the final
website matrix.

Active full-restore execution — 2026-08-20 UTC:

- The capacity gate passed before execution: `/mnt/blockstorage` had more than
  944,981,000,000 free bytes versus the required 322,264,664,289. Run-owned exact-image
  files/storage workers share
  `website-100gb-restore-work/worker-shared`; the isolated key-only SFTP container
  `bs-remed-100gb-sftp-20260820` writes only to run-owned path
  `sftp-data/deep300-0d08dcf`. The normal files/storage workers remain stopped.
- Connection `79` and auth row `10` were created for this exact destination. Only node
  `101` was moved from shared connection `60` to connection `79`; connection `60` was
  not mutated because nodes `89` and `106` also use it. Strict known-host and key-only
  validation passed before the restore request.
- Restore `23` proves the pre-fix zero-length HEAD failure is safe and destination-
  preserving. Restore `24` is the active signed-in retry row, with delete-extras
  disabled. It crossed deployments without row replacement and now persists
  `RESTORE_ARCHIVE_NOT_READY` because exact authenticated provider HEAD reports
  `VULTR_ARCHIVE`, `Content-Length: 0`, the committed multipart ETag/metadata, and
  `ongoing-request="true"`. No GET is attempted while that state is true; zero target
  files, zero provider partials, and zero worker restart/OOM remain true.
- The live wait exposed a second bounded defect: the orderly Celery countdown and
  one-minute durable recovery sweep both dispatched the same due row, while each
  lease-busy duplicate retried itself. The files queue grew to twelve scheduled
  deliveries, and one pre-fix boundary advanced attempts `47→49`. Revision `61d9fad`
  persists an orderly-retry reservation beyond the due time, makes recovery respect
  it, consumes it on the successful claim, acknowledges materialized duplicates, and
  extends only `RESTORE_ARCHIVE_NOT_READY` to a 2,880-retry budget. Exact-image tests
  pass 167/167 focused and 1,909/1,909 complete. After deployment the twelve old
  deliveries converged to one; `49→50→51→52` each advanced exactly once; three
  recovery sweeps left dispatch count `11`; and one future retry remained scheduled.
- Revision `cecdac0` crossed the same live wait without replacing restore `24`. Its
  destination-name probe is deliberately after provider fetch and archive validation,
  so archive-not-ready attempts perform no fidelity probe or website staging. The
  deployment-window `80→83` movement is exactly the normal 09:43/09:45/09:47 UTC
  cadence, not amplification; the next postdeploy interval advanced once to `84` at
  09:49 UTC. Recovery dispatch count remains `11`, the files queue remains zero ready
  and one scheduled, and exact target probe/stage residue remains zero.
- The original gate required restore `24` itself to complete after rehydration. The
  resume finding below makes that impossible and retains `24` as a pre-fix control.
  The replacement exit gate requires one explicit new signed-in restore through the
  deployed fix, destination containing only `bs-remediation-100gb-zero-payload.bin`
  at exactly 107,421,554,467 bytes, remote-only source-member and destination SHA-256
  values matching, retained ZIP CRC passing, queues/reserved deliveries converging to
  zero, run-scoped work residue cleaned, and terminal UI appearing only after the
  durable completion checkpoint.
- On the 2026-08-22 resume read, rehydration had completed but restore `24` had failed
  safely at attempt `165` before GET. Vultr's archive transition changed the provider
  ETag from the committed 7,881-part value to a 1,025-part value while the exact key,
  full 107,421,554,763-byte HEAD/range identity, SHA metadata, and zero-unfinished-
  upload inventory remained consistent. Target files/directories and probe/stage
  residue remained zero. This converts the first sentence of the prior gate from a
  provider wait into a confirmed compatibility defect; restore `24` is retained as
  the pre-fix fail-closed control and cannot itself be called complete.
- Pushed candidate `bf10816` adds a narrow transport-identity rule for this lifecycle:
  only an explicitly transitioning `VULTR_ARCHIVE` object with a committed multipart
  ETag may present a new live ETag; that live ETag must remain exact across GET and the
  final HEAD, while committed key/ownership/bytes/SHA/version checks and full streamed
  bytes/SHA remain mandatory. Changed standard/single-part ETags, GET drift, final-HEAD
  drift, ownership drift, and content drift still fail before publication. The red
  test and 112/112 no-database green tests pass. Exact-image/full-suite/deployment and
  a new signed-in full restore remain required while the current readable copy expires
  on 2026-08-27 at 12:33:52 GMT.

### Slice 9 — Clean owned orphan multipart uploads

Dependency: Slice 8 exact ownership and completion-state contract.

Required work:

1. Define abort eligibility: exact account/destination, bucket, object key, upload ID,
   backup ownership marker, terminal state, and no ambiguous completion outcome.
2. Abort immediately only after a definitive terminal failure where the above proof is
   complete.
3. Add a bounded maintenance sweep for stale exact-owned uploads; paginate and retain
   a durable cleanup witness.
4. Recommend/provider-configure lifecycle cleanup as defense in depth, but do not treat
   provider lifecycle as application correctness.
5. Never abort foreign, markerless, active, recently ambiguous, or multiply matched
   uploads.

Implemented and accepted — 2026-08-19:

- The current isolated candidate adds a durable multipart creation witness plus exact
  account, storage-row, bucket, expected-owner, object-key, upload-ID, backup-marker,
  operation-marker, and pre-create-inventory bindings. Legacy/markerless state is not
  auto-adopted for cleanup. Completion-pending, committed, verifying, active,
  foreign, multiply matched, malformed, and object-present cases all stop before an
  abort call.
- Eligible terminal cleanup performs an exact object-absence read, exact-key
  multipart inventory, provider owner/initiator and initiation-boundary comparison,
  and bounded ordered-part witness. It persists the full abort intent before the
  provider mutation. A lost abort response is reconciled from fresh inventory; a
  retry with an existing `abort_outcome_unknown` witness never replays the abort.
- A cleanup-purpose storage lease reuses the existing renewable fencing token without
  changing the customer-visible terminal status, upload attempt count, upload task
  identity, or safe error. Definitive terminal upload failures enqueue the exact
  point only after releasing the upload lease. A six-hour bounded/keyset-paginated
  sweep republishes stale eligible points to the storage queue; provider lifecycle
  expiry remains defense in depth rather than correctness evidence.
- The candidate is retained at
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
  `candidates/multipart-owned-cleanup-20260819/`. Local no-database checks pass 70/70
  focused verified-S3/adapter tests. The same 70/70 tests pass in an isolated demo
  container. Ten real-model lease/task/sweep/routing tests pass against a disposable demo
  PostgreSQL test database, which Django destroyed; a follow-up exact database read
  found no retained test database. A first 131-test broader run inherited the demo's
  production HTTPS redirect setting and therefore returned HTTP 301 in request-view
  tests that expected their underlying 404/200 responses; this was a test-runner
  configuration error, not a product failure. Repeating the exact 131-test storage,
  verified-S3, adapter, timeout, lease, Vultr-integrity, and Celery-routing set with
  `DJANGO_HTTPS=false` passed 131/131 in 70.899 seconds. Django destroyed that database
  too, and an exact follow-up database read found no retained `test_bs_mp_*` database.
  Django system check, migration drift check, Python compilation, and diff whitespace
  validation are clean.
- Revision `a351ce2` (`Clean exact-owned multipart uploads`) is committed and pushed to
  `origin/develop`. Before deployment, the mode-0600 database snapshot
  `demo-pre-a351ce2-20260819T1948Z.dump` was written under this run's block-storage
  root: 1,060,922 bytes, SHA-256
  `ddbb4d5b5594ad9a8804092023ee7fd8bccccf9f30c3d00d1d23a69247f98788`.
  The app, storage worker, and beat scheduler were then recreated only from image
  `sha256:3df06dd02620692ed3b9cfbf18672cb53c9c7e30e903f01b776ce9152b3356d9`
  with exact revision label `a351ce2df3598276d8ca52faeb67ab1389b173fb`.
  `worker-files` was deliberately not recreated and remained on `b4cb5c5` while backup
  `44` continued `archive_building`; its heartbeat advanced across the deployment at
  2,000,000/2,000,000 files. Public `/healthz/`, Django system check, storage-queue
  consumer, both cleanup task registrations/routes, and the six-hour beat entry are
  clean.
- The live Vultr canary root is bucket `bs-remed-0d08dcf-100gb-20260819`, prefix
  `bs-remed-20260818-0d08dcf/slice9-live-20260819t1954z/`. Backup `45`/point `47`
  used the deployed verified uploader to create one exact-owned multipart upload and
  accept one 5,242,880-byte part before a controlled definitive second-part failure.
  Cleanup task `bs-remed-slice9-live-20260819t1954z-owned-cleanup` durably recorded
  `complete/aborted`; fresh provider inventory and HEAD show zero uploads and no object.
  Point `47` remained `Upload Failed`, attempt count `1`, retained its original upload
  task ID and `STORAGE_TEST_INJECTED` error, and released its cleanup lease.
- Backup `46`/point `48` held a real one-part upload in
  `multipart_complete_outcome_unknown` with a complete completion intent. Cleanup task
  `bs-remed-slice9-live-20260819t1954z-ambiguous-cleanup` returned `not_eligible`;
  the exact upload and its part remained present and unchanged until explicit canary
  cleanup. Backup `47`/point `49` held owned and deliberately foreign uploads under the
  same exact key. Cleanup task `bs-remed-slice9-live-20260819t1954z-foreign-cleanup`
  returned `not_eligible`, retained both one-part uploads, and recorded
  `blocked/exact_inventory_not_unique`, count `2`, inventory SHA-256
  `2dd8f73c3d0bd13819e875429c406f38e73fda12426ed346ce3fc3e6c06398a6`.
- Backup `48`/point `50` retained one live one-part upload while a controlled malformed
  inventory collection was returned after the live provider HEAD. Deployed cleanup
  returned typed `S3MalformedMultipartInventory`, recorded
  `blocked/malformed_inventory`, and the abort boundary was never crossed. The upload
  and part stayed present until exact canary cleanup. After collecting all no-abort
  witnesses, only the four exact canary upload IDs were explicitly aborted. A fresh
  paginated inventory of the whole canary prefix reports zero objects and zero
  multipart uploads; no retained 100 GB object or foreign prefix was changed.

Exit gate:

- Deliberate failed uploads leave no eligible owned parts after cleanup.
- Ambiguous-completion tests issue no abort.
- Foreign-upload and malformed-inventory canaries remain untouched.

### Slice 10 — Improve MySQL/MariaDB restore performance

Dependency: Slice 3 duplicate-free fork convergence.

Status: **Pass. The declared MySQL 1M/5M performance and compatibility targets,
bounded-memory behavior, MySQL 10/25 GB restores, and PostgreSQL 10/25 GB restores
all have signed-in product and exact-content evidence.**

Required work:

1. Remove `--skip-extended-insert` for new MySQL/MariaDB backups, using bounded vendor
   defaults or explicit safe packet sizing.
2. Persist the exact dump options on each backup for compatibility and diagnostics.
3. Benchmark backup size, dump time, restore time, memory, and crash behavior against
   historical row-by-row artifacts.
4. Keep restore support for existing row-by-row backups.

Local implementation record — 2026-08-19:

- Revision `8f2198b` removes the unconditional `--skip-extended-insert` from new
  MySQL and MariaDB dumps. Normal backups now pass explicit `--extended-insert`
  together with the existing 512 MiB client packet ceiling; the database clients
  continue to bound individual statements according to their vendor dump behavior.
  A node with the deliberate `skip-opt` setting remains row-by-row rather than being
  silently overridden.
- Each new backup persists the exact ordered flags in `option_mysql` or
  `option_mariadb` and a bounded `metadata.logical_dump` contract containing schema
  version, engine, selected client/version, flags, extended-insert decision, and
  packet ceiling. No credential path, password, or raw command output is persisted.
  Restore execution remains format-agnostic through the same vendor client, so
  already stored row-by-row artifacts retain their existing compatibility path.
- The isolated candidate at
  `/mnt/blockstorage/backupsheep-remediation/bs-remed-20260818-0d08dcf/`
  `candidates/database-extended-insert-20260819/` passed 16 focused MySQL/MariaDB
  direct/SSH tests and a broader 23/23 database dispatch/engine run that also covered
  PostgreSQL regression paths. Both isolated test databases were dropped afterward.
- The writer is deployed. New MySQL 1M backup `76` persisted the exact extended-insert
  flags, completed its backup task in 59.862 seconds, and produced a 53,396,706-byte
  ZIP around a 1,084,928,638-byte SQL entry. Normal restore `72` completed its task in
  94.450 seconds. Deployed fault restore `74` imported the same immutable SQL on its
  attempt-2 generation in 92.919 seconds from claim and retained exact every-row
  correctness. These are the first real extended-insert 1M product observations.
- The controlled same-host 1M comparison is complete: current imports took 49.80,
  51.41, and 52.86 seconds versus 3,795.03 seconds for the retained row-by-row
  artifact. All outputs have the same exact digest. The 51.41-second median is 73.82x
  faster and 98.65% less elapsed time; client/worker memory is also materially lower.
- The release performance target was fixed on 2026-08-20 while the 5M historical
  import was still active, before its elapsed result was available: under the declared
  2-CPU/4-GB same-host MySQL profile, the current extended-insert format must retain
  exact output, complete the controlled 1M median within 120 seconds and the controlled
  5M median within 600 seconds, improve each retained historical baseline by at least
  10x, keep the import client below 256 MiB RSS, and produce no cgroup/kernel OOM event.
  A faster result does not waive exact row/schema/default verification or the separate
  signed-in product restore and crash-recovery gates.
- A deliberate 5M row-by-row product backup first confirmed an independent writer
  defect: `--skip-opt` also disabled `--quick`, so the dump client buffered toward
  1,847,884 KiB anonymous RSS and the kernel OOM-killed it during concurrent website
  work. Revision `9454507` adds `--quick` after intentional `--skip-opt`; two focused
  regressions, 123/123 broader database-engine tests, exact-image repetition, Django
  checks, and migration drift pass.
- After deployment, signed-in backup `90`/point `94`, UUID
  `bs-bs-remed-20260818-0d08dc-n108-b90`, persisted
  `--single-transaction --skip-opt --quick --column-statistics=0
  --set-gtid-purged=OFF --no-tablespaces --max_allowed_packet=512M`. It streamed a
  5,598,892,551-byte SQL file with 12,276 KiB maximum dump-client RSS, 212,760 KiB
  maximum worker-child RSS, 1,547,857,920-byte cgroup peak, and zero OOM/OOM-kill
  events. The 264,535,256-byte mode-0600 destination artifact is CRC-clean and has
  source/destination SHA-256
  `ecd191cfda06639690b8c9eaceda27ef6c7a8b9e0fa584989c07d91fb7e73e7d`; exactly
  one upload completed. Its signed-in row exposes Complete, Phase Complete, and exact
  264,535,256/264,535,256-byte progress. Mode-0600 telemetry is retained with SHA-256
  `000b25e55b4f0424d7855bda3bd023b9a129aa0f19df44a0e99daa6619e5b048`.
- The controlled same-host 5M comparison uses immutable backup `88` current SQL
  (5,429,070,081 bytes, SHA-256
  `c35a62390b0c9ab6a067c6871153a1e8835d7053ccea6be70b2fdce3a732e8b3`) and backup
  `90` row SQL (5,598,892,551 bytes, SHA-256
  `672337ca157921aa808a5ad53f566553a9a71ddf364a06f29d34e35d81f7e912`). Under one
  exact MySQL 8.4.11 container limited to 2 CPUs/4 GB on demo block storage, current
  imports completed in 239.20, 249.94, and 255.83 seconds. Every run produced
  5,000,000 rows/distinct IDs, range 0–4,999,999, ID sum 12,499,997,500,000,
  5,185,000,000 payload bytes, the required metadata/defaults, and ordered digest
  `f3bc144b812d2f45f87a06c2f9ee0db53643540e24b42eea40e46606d3a59359`.
  The 249.94-second median is sealed. The matching historical row-by-row import under
  the identical profile completed in 16,956.91 seconds (4:42:36.91), making the
  current median 67.84x faster and 98.53% shorter. It independently produced exactly
  5,000,000 rows/distinct IDs, range 0–4,999,999, ID sum 12,499,997,500,000,
  5,185,000,000 payload bytes, three fixture metadata rows, source defaults
  `utf8mb4`/`utf8mb4_0900_ai_ci`, and the same ordered digest
  `f3bc144b812d2f45f87a06c2f9ee0db53643540e24b42eea40e46606d3a59359`.
- Two directly sampled current-format imports peaked at 27,248 and 27,520 KiB client
  RSS; the historical run peaked at 26,260 KiB across 14,372 samples. The first
  current run's separate client sampler was unavailable and is not used for the
  client-memory claim. Current container peaks were 607.3/431.6/464.3 MiB; historical
  peak was 457.9 MiB. The exact benchmark container reports zero `oom`, `oom_kill`,
  `oom_group_kill`, and restarts. This passes the target fixed before the historical
  result was known.
- Historical timing, verification, and client-sample evidence is retained mode-0600
  with SHA-256 respectively
  `16a14cb4dd17a86ffc3efc8d55f3bd8982f7b2dd2f4fee57429f7edb2a664ec1`,
  `311ef150332a7111165534db7a8ba16bdfb21fe04893da58cf3b1f98b0cebf3e`, and
  `01b63a30e601774ee79b7a2ff50477d190e14257d6ec5f1832ca8e68eeb868c7`.
  The MySQL 10/25 GB and PostgreSQL 10/25 GB support claims are closed by the live
  product records below and in Slice 1.

Exit gate:

- Exact correctness remains green for all fixtures and kill points.
- Establish and document a performance target before release. At minimum, 1,000,000
  and 5,000,000 rows must show a substantial improvement over the report baselines.
- Do not claim 10/25 GB restore support until those restores actually complete and are
  verified. This condition is now satisfied for MySQL and PostgreSQL.

Completed 10/25 GB execution record — 2026-08-23:

- MySQL 10 GB backup `95`/restore `86` and 25 GB backup `97`/restore `88` were run
  sequentially through the signed-in UI. Both have exact source/fork data, schema,
  marker, terminal-UI, queue, worker-health, and cleanup proof. Restore `88` includes
  a deliberate mid-import worker loss and natural attempt-2 takeover on one row.
- PostgreSQL 10M-row backup `99`/restore `93` and 25M-row backup `100`/restore `90`
  were likewise run through the signed-in UI and independently verified. Restore
  `93` proves transaction rollback, same-row natural takeover, and namespaced cleanup
  after a real exit `137`; restore `90` supplies the separate 25 GB-class exact
  content/schema/marker gate.
- Revision `be41098` removes only exact run-owned PostgreSQL combined/temp restore
  remnants after rollback or takeover. It passed 138/138 focused and 1,941/1,941
  repository tests before deployment; the live 10M crash repetition left zero
  namespaced local SQL/partial files and zero remote correlation artifacts.
- No large artifact crossed the MacBook and no local Docker workload was used. The
  retained Vultr host/volume and demo block storage supplied all fixture, restore,
  and verification capacity.

### Slice 11 — Restore MySQL/MariaDB events and all required objects

Status: **Pass — automated, deployed, and live cross-engine restore evidence.**

Required work:

1. Include vendor event definitions when the connection/object policy requests full
   database objects.
2. Verify required privileges and return an actionable validation error if events
   cannot be read.
3. Ensure restore imports event definitions without enabling unrelated global
   scheduler behavior as a test side effect.

Exit gate:

- Objects fixture proves PK/FK/index/view/trigger/procedure/function/event fidelity for
  MySQL and MariaDB.
- PostgreSQL objects fixture independently proves schemas, sequences, views, triggers,
  functions/procedures, indexes, and FKs.

Implementation record — 2026-08-18:

- Full-object MySQL/MariaDB dumps now include `--events` alongside routines and
  triggers. Event export remains tied to the existing full-object connection policy;
  table/data-only backups do not silently broaden their object scope.
- Backup failures caused by unreadable scheduled events use stable public code
  `DATABASE_EVENT_PRIVILEGE_REQUIRED`, stage `authorization`, and a non-retryable
  grant/revalidate remediation without exposing raw client output.
- Connection validation proactively executes `SHOW EVENTS` for every selected
  non-system database when the full-object policy is active. Direct, SSH, and
  all-databases modes share the same bounded contract.
- The database validation view and shared exception helper preserve the outer safe
  `ClassifiedConnectionError` instead of replacing it with a generic response or
  descending into an unsafe wrapped client exception.
- Setup guidance now explicitly identifies scheduled events and the MySQL/MariaDB
  `EVENT` privilege. Focused source contracts keep that requirement visible.

Live update — 2026-08-18:

- MySQL backup `65`/restore `49` and MariaDB backup `66`/restore `50` were created
  through the deployed product path. ZIP CRC, SQL definitions, exact row digests,
  canonical object digests, restore markers, and PK/FK/index/view/trigger/function/
  procedure/event inventories match source to fork. Both events remain disabled.
- MySQL's global event scheduler was `ON` before and after its restore; MariaDB's was
  `OFF` before and after its restore. Neither test changed global scheduler behavior.
- PostgreSQL independently passed schemas/relations, sequences, views, trigger,
  functions, constraints/FKs, and indexes in the exact 1,000,000-row SSH fixture and
  restore evidence recorded under Slice 1.
- Exact-owned MySQL connection `69` uses a real account with object-read permissions
  but no `EVENT` privilege. Live authenticated validation returns HTTP 400 with
  `DATABASE_EVENT_PRIVILEGE_REQUIRED`, `authorization`, `retryable=false`, and the
  safe grant/revalidate action. This proves the deployed validation/API contract, not
  only a mocked classifier.
- At the Slice 11 gate, app revision `bc354015` used image
  `sha256:f9709aa388839535080b665235873bcb0a8bb8b27939f4dcfdcb3370c12ad3bf`
  while the database worker used revision `698f655`/image
  `sha256:bda82b7d18c4afb7e4493146ddbd6144da315304041f2b3e48b3f0bc4e2f0f23`;
  that split was safe because the last two commits affect only API presentation.
  Subsequent Slice 1 fault-test restarts recreated the database worker from the
  already-built `bc354015` image. The later recovery-reservation deployment advanced
  `app`, `worker-database`, and `worker-cloud` together to `f4adce3`/
  `sha256:c84dd1e0d4d730e2a6260f8f6b7eea2a759e1d90d59f06e945f633ccb93eefb0`;
  that deployment does not alter the already-passed Slice 11 artifact evidence.
- The later persistent-TLS restore did not invalidate this fidelity gate, but it
  exposed a missing pre-mutation privilege check for MySQL trigger/function creation
  when binary logging is enabled and trusted function creators are disabled. Revision
  `fecf40a` detects that archive requirement, recognizes standard escaped database
  wildcard grants correctly, and rejects an insufficient account before creating a
  target. The deployed no-mutation probe passed. Full-object backup `65`/restore `49`
  remains the event/routine fidelity proof; TLS node `102` intentionally disabled
  stored procedures/events and therefore does not substitute for it.

Slice 11 is complete against its stated exit gate. This does not close Slice 10's
restore-performance/progress problem or the broader eight-family and large-database
acceptance matrix.

### Slice 12 — Reject empty or contradictory database selections

Required work:

1. Add authoritative serializer validation for create and partial update.
2. For a connection bound to one database, require `all_tables=true` or at least one
   table.
3. For an all-databases connection, require `all_databases=true` or at least one
   database.
4. Enforce mutual consistency: an all-mode flag and an explicit list cannot both be
   active; table and database modes cannot be mixed.
5. Default `Backup All Tables` on for the common single-database UI flow, or require an
   explicit choice before enabling Save.
6. Render field-level errors and preserve the user's valid selections.

Local implementation record — 2026-08-18:

- `CoreDatabaseWriteSerializer` now validates the merged effective state for create
  and partial update. Empty, malformed, blank-name, mixed table/database,
  all-plus-explicit, and connection-mode-incompatible selections fail before model
  mutation.
- Partial updates no longer attempt to update the nested node when the field is
  omitted. The existing nested node serializer still performs membership/account
  authorization for requests that change the node.
- The UI defaults the connection-appropriate all-mode and disables Save until a
  non-empty selection exists. Existing-node data still replaces the default after it
  loads.
- Focused serializer tests cover create, partial-update merge behavior, valid all and
  explicit modes, contradictions, and malformed lists. HTTP 400 execution, rendered
  field-error behavior, existing-node UI regression, and account-scope execution were
  pending at this local-only checkpoint.

Live update — 2026-08-18:

- An authenticated PATCH against isolated PostgreSQL source `41` attempted to clear
  all table/database selectors. It returned HTTP 400 with the `all_tables` field
  message `Enable Backup All Tables or select at least one table.` and the before/after
  model state was identical.
- This proves the HTTP no-mutation contract for one single-database path. Browser
  Save gating, rendered error preservation, all-databases UI, existing-node save, and
  explicit cross-account attempts remained open at this checkpoint.

Signed-in browser update — 2026-08-19 CDT / 2026-08-20 UTC:

- Existing MySQL all-database node `104` loaded its exact eight selected fixture
  databases. Removing all eight only in the browser disabled `Modify Node`; no request
  could be submitted. Reloading the page discarded the unsaved state and restored all
  eight selections. Durable source `54` remained `all_databases=false`,
  `all_tables=false`, with the original exact eight database names and empty table
  list. This closes the empty-selection Save-gating and selection-preservation
  observation without mutating the node.
- A note-only signed-in save then exercised the valid existing-node path without
  changing selection semantics: all eight database names, both all-mode flags, and
  the empty table list remained exact. A second signed-in save restored the original
  note, and a final durable read matches the pre-test record. No backup/restore task
  was created.
- On the isolated exact `3d40faf` app, a CSRF-correct signed-in primary user from account
  `1` attempted to read account `2` database node `1`, request its backup using account
  `2` storage `1`, and restore account `2` backup `1`. The node read, backup request,
  and restore request each returned a scoped HTTP 404 (`No CoreNode`/`No
  CoreDatabaseBackup matches the given query`). `CoreBackupRequest` and
  `CoreDatabaseRestore` counts remained zero, the database queue stayed `0/0`, and the
  foreign backup status/modified timestamp did not change. The first attempt without a
  CSRF header was rejected by CSRF before authorization and is not counted as evidence.
- A real headless Chromium 140 session, driven by Playwright `1.55.0` on the isolated
  Vultr host, loaded owned account/source `1`/`2` through the exact `3d40faf` app image.
  The object-discovery response alone was replaced with an empty successful list so the
  fake fixture connection did not make an external database call. Before save, the page
  showed `scope-owned-db`, `Backup All Tables=true`, an enabled `Modify Node` button,
  and no object-discovery error.
- To reach the server-error branch that the now-correct UI itself prevents, the browser
  route captured the valid outbound PATCH (`all_tables=true`, `tables=null`) and changed
  only its selection to `all_tables=false`, `tables=[]` before forwarding it to the real
  API. The API returned HTTP 400; the page rendered
  `Enable Backup All Tables or select at least one table.` under `all_tables`, stayed on
  `/console/integration/database/2/database/2/`, retained the node name and
  `Backup All Tables=true`, and kept Modify enabled. A final independent database read
  found source/node `2` still named `scope-owned-db` with `all_tables=true`,
  `tables=null`, `all_databases=false`, and `databases=null`; backup-request and restore
  counts remained `0/0`.
- This closes rendered field-error preservation. All Slice 12 exit conditions are now
  evidence-backed, so Slice 12 is **Pass**.

Exit gate:

- Invalid create/update requests fail with HTTP 400 before creating/changing a node.
- UI cannot submit an empty selection.
- Existing valid nodes load and save without semantic changes.
- Authorization/account scoping remains covered.

### Slice 13 — Make diagnostics and transfer logs actionable

Status: **Pass. Public-safe stage/code guidance, bounded refresh-stable attempt
history, operator-only correlation, worker-restart survival, and secret-canary
redaction are implemented, deployed, and browser/live proven.**

Required work:

1. Add stable, public-safe stage codes for mirror, path limit, manifest, archive,
   archive validation, disk/inode, timeout, and storage stall outcomes.
2. Persist bounded per-attempt timestamps, stage, code, retry decision, and correlation
   ID without raw stderr/provider bodies.
3. Keep secured raw diagnostics operator-only and retention-bounded.
4. Decide one transfer-log product behavior:
   - securely stream a redacted local log through a tenant-scoped permission check;
     return 410 when it has been pruned, or
   - remove/disable the button and direct the user to correlation-based diagnostics.
5. Do not leave a visible action whose expected response is HTTP 404.

Local implementation record — 2026-08-18:

- The website/database backup table no longer renders or calls the self-hosted
  transfer-log download action whose normal result is HTTP 404.
- Eligible rows now direct the user to `Technical details` and the correlation ID;
  the unused client-side downloader was removed.
- A template source contract asserts that the dead action/label are absent and the
  replacement guidance remains present.
- At this checkpoint, required work items 1–3 and the stage-specific diagnostic exit
  gates remained open; this first change did not claim raw operator diagnostics or
  attempt history. The 2026-08-23 closure below completes those items.

Live update — 2026-08-18:

- Browser inspection of PostgreSQL backup `63` first showed truthful terminal badges
  but hid the historical rows' phase/progress and offered no per-row correlation/error
  details. Commit `cb7fbc8` makes the existing redacted execution-status contract
  visible in each recent row without reading raw `error`, provider metadata, worker
  fields, or lease data.
- On the deployed app, restores `60` and `61` visibly show the allowlisted
  reconciliation guidance. Their expandable `Technical details` expose only the
  exact public correlation ID and `RESTORE_RECONCILIATION_REQUIRED`; neither row
  offers verification resume. The dead Log File action remains absent.
- MariaDB restore `62` then proved the resumable-error variant. Its failed historical
  row exposed the safe generic message, exact correlation ID,
  `RESTORE_TARGET_REJECTED`, and one bounded resume action without rendering wrapper
  output or a remote path. After recovery it rendered Complete/1-of-1 and no longer
  offered resume.
- At this 2026-08-18 checkpoint, terminal historical-row diagnostics and one
  resumable import-error row were closed; bounded attempt history, stage-specific
  archive/storage failures, and secured operator diagnostics still remained. The
  2026-08-23 closure below supersedes that limitation.

Live closure update — 2026-08-23:

- Commit `5b4775ed8e6bcc334dc87138f5bd4ca5f114f579` adds a bounded 20-record
  public attempt ledger. Each record contains only attempt number, start/finish time,
  allowlisted stage and code, retry decision, and correlation ID. Duplicate delivery
  updates the same running attempt. Raw exceptions are never copied into models,
  account logs, notifications, API output, or transfer logs; they are captured only
  in retention-controlled Sentry events tagged with the safe correlation, attempt,
  stage, and code.
- The exact candidate passed 97/97 focused, 218/218 adjacent, and 1,941/1,941 full
  tests. Evidence SHA-256 values are respectively
  `86260cfa61840ed013c930b130fe0f96c342e73f13b3f6240773d6e3eff6ea55`,
  `7fc65e792fcc9f0da212411cc232387356a209d52366b4e38e4add74c724f828`,
  and `d38fcbe75badd1388cc6dd934baeb43adf3cbbc06862b0018ceb24cfbbac98ce`.
- Signed-in live cases now span every stated public stage family: unsafe-manifest
  backup `64`, target-collision restore `39`, archive-failure/retry backup `65`,
  storage-stall/resume backup `69`, and website worker-loss restore `41`. Backup `65`
  shows attempt 1 at Website Archive with `ARCHIVE_CREATION_FAILED` / Scheduled Retry
  and attempt 2 Complete. Backup `69` retains `STORAGE_STALLED` in history after its
  provider-visible resume. Restore `41`, correlation
  `8aa0068b-c347-47c6-aaa3-d92caa525704`, shows attempt 1 Website Staging / Lease Lost
  and natural attempt 2 completion on the same row.
- Restore `41` was interrupted only after its exact private stage existed. The old
  target sentinel stayed byte-identical until takeover; after terminal completion the
  target contained exactly 103,573 files, 473 directories, and 1,339,687,255 logical
  bytes, with zero stage/previous residue. Entry, directory, and full-content
  manifests match the retained baseline at SHA-256
  `4aa40bac6787e8e0a3a730471169b8ca0af054844d98fc0c410ab2ca4c68797d`,
  `6045657eea446e83ffffe2b5d7f5d9d5d64ad3205cd99549372a99d2f431744b`,
  and `d5361ebb5aabb3c2760c2decaeb2c120ad790ff4d5c52fdbd5b2a2784272d907`.
- Redaction backup `70`, point `72`, correlation
  `cee8bc03-794f-438d-b23d-22c2d7165303`, used an isolated C0-control filename
  canary and failed at Website Manifest with `SOURCE_SPECIAL_FILE_UNSUPPORTED`.
  The canary was absent from the expanded backup row, signed-in Activity view, and
  scoped files/default/app logs. The failure created no artifact and made no storage
  upload attempt. The original three-file fixture was restored exactly afterward.
- The live recovery rows exposed a presentation-only defect: a durable Complete row
  could retain a prior attempt's error rollup and present it as current. Commit
  `8dba19be0a4a87650a86c00202006858913e6c72` clears the parent rollup only when
  successful finalization confirms true Complete, preserves Partial failures, and
  suppresses legacy stale rollups in the public serializer while retaining attempt
  history. It passed 24/24 focused and 105/105 adjacent tests; the green adjacent log
  hashes to
  `ed768b79eab65677ce1bfce7f5ef2d872a06b698842876e33594b5e71b103c8b`.
- After exact deployment, the signed-in node `109` row shows backup `65` Complete with
  no current error while its attempt history still contains
  `ARCHIVE_CREATION_FAILED`. Node `111` shows backup `69` Complete with no current
  error while its history still contains `STORAGE_STALLED`. This proves the UI fix
  without erasing audit evidence.

Exit gate:

- Each archive/restore/storage failure shows a safe stage-specific code and useful
  remediation.
- Retry count/history survives refresh and worker restart.
- Secret canaries in credentials, stderr, provider bodies, local paths, worker fields,
  and metadata never appear in API/UI/log downloads.

### Slice 14 — Correct phase labels and storage counters

Status: **Pass. Queued acceptance, source-ready waiting, scheduled retry, terminal
partial/action replacement, terminal/reconciliation states, refreshed-active polling,
one-timezone restore timestamps, and current local-storage counters are
browser-proven.**

Required work:

1. Create an explicit legacy-status-to-public-phase map instead of substring matching.
2. Terminal parent status must override a stale active phase.
3. Rename `DOWNLOAD_COMPLETE` presentation to `Source archive ready` or equivalent;
   keep the overall run active while destinations upload/verify.
4. Populate per-storage website/database/SaaS counts and bytes using tenant-scoped,
   completed-point aggregations without N+1 queries or cross-join double counting.
5. Reuse a common aggregation contract where possible so category and total byte
   values reconcile.

Local implementation record — 2026-08-18:

- Backup and restore execution serializers now resolve legacy statuses through an
  explicit map. True terminal parent states override stale active ledger phases;
  `DOWNLOAD_COMPLETE`/`ready_for_upload` resolve to `source_ready`.
- Commit `f9669c5` extends that explicit contract to the granular durable restore
  phases emitted inside database and website restore engines. Per-component
  `database_complete`, `database_restore_complete`, and `website_complete` phases
  remain publicly `restoring` while their parent row is active; archive/permission
  checkpoints remain `validating`. A terminal parent still overrides every stale
  active phase.
- The UI renders `source_ready` as `Source archive ready`, continues polling, and
  recognizes the full `partial_some_destinations_failed` token as terminal partial
  rather than generic complete.
- `CoreStorage.cost_summary_for_account()` now exposes category source count, backup
  count, and stored bytes from completed through-table rows, explicitly scoped to the
  account. Four grouped family queries avoid destination-count N+1 behavior and M2M
  cross-join multiplication; website/database/SaaS category bytes share the same
  rows as total cost bytes.
- Focused regressions cover stale terminal/source phases, truthful partial/source
  display, completed-point filtering, fixed query count, foreign-account exclusion,
  category/total reconciliation, and setup-view field mapping. The original local
  checkpoint had no live browser evidence; the remote and browser runs below now
  supersede that limitation for the specified rows.

Live update — 2026-08-18:

- On real local storage `9`, the initial serializer gate reported website `3` and
  database `2`, exactly matching the completed rows at that checkpoint. After the
  retained matrix and fault artifacts were added, a fresh deployed summary reports
  website `3`/one source/10,315 bytes and database `14`/seven sources/172,031,949
  bytes, for 172,042,264 total bytes; those values again exactly match completed
  storage-point rows.
- New block-backed local storage `10` independently reports database `2`, two sources,
  and 4,812,149,953 bytes after 1/5 GB backups `70`/`71`; its category bytes and total
  bytes are identical and match its two completed point rows exactly.
- Database restores `37` and `39` and website restores `17` and `18` expose terminal
  phase `complete`; the intentionally failed MariaDB restore `38` exposes `failed`.
- Deployed PostgreSQL restores `60` and `61` visibly render `Manual review required`,
  `Phase: Failed`, `0 / 1 databases`, the safe failure guidance, and exact public
  technical details in the signed-in restore modal. The 7-test focused, 31-test
  adjacent/exact-image, and 215-test broad gates passed before deployment.
- MariaDB restore `62` visibly rendered Terminal failure/Failed/0-of-1 with its safe
  details and enabled resume, then Actively running/Validating/0-of-1 immediately
  after the bounded action, and finally Complete/Complete/1-of-1 on the same logical
  row. This closes one active recovery transition and proves that polling continued
  until the real terminal state.
- PostgreSQL matrix restore `63` then exposed the missing component/parent
  distinction: the signed-in modal rendered Complete/5-of-8 and stopped its interval
  while the worker was still active. The durable row and worker correctly continued
  to 8/8, so this was a public phase/polling defect rather than early restore
  finalization.
- After app-only deployment of `f9669c5`, signed-in restore `64` remained Actively
  running through Validating 0/8 and Restoring 0/8, 1/8, 3/8, and 7/8, then rendered
  Complete/8-of-8 only after the parent row became terminal. All eight database/file
  checkpoints and exact target markers were complete. This closes the observed
  multi-database premature-terminal/polling gate.
- Signed-in 1 GB restore `65` subsequently rendered active validation/restoration and
  then Complete/1-of-1 only after its one target checkpoint and terminal parent were
  complete. Exact row/schema verification independently proves that final label.
- Signed-in 5 GB restore `66` likewise stayed Actively running at 0/1 while the marker
  was importing and the target table remained transactionally invisible, then
  rendered Complete/1-of-1 only after atomic commit. Exact every-row/schema/marker
  verification independently proves the final label.
- MariaDB matrix restore `67` independently exercised a real failed/resumable path:
  active Validating/Restoring advanced to Terminal failure at 5/8, signed-in manual
  resume changed the same row to Recovering/reconciling at 5/8 with an explicit
  “No second restore was created” notice, and the modal changed to Complete only after
  durable state and all eight markers reached 8/8. Exact target verification proves
  the terminal label rather than relying on the UI alone.
- A fresh account-scoped summary after backups `72`/`73` reports storage `9` website
  `3`/one source/10,315 bytes and database `16`/eight sources/258,094,049 bytes, for
  258,104,364 total bytes. Storage `10` remains database `2`/two sources/
  4,812,149,953 bytes. Category bytes, source counts, backup counts, and destination
  totals reconcile exactly to completed point rows for both destinations.
- After MariaDB 5 GB backup `74`, deep-tree website backup `41`, and MySQL TLS backup
  `75`, a fresh completed-point aggregation reports storage `9` website `4` across
  two sources/980,981 bytes and database `17` across nine sources/262,821,371 bytes,
  total 263,802,352 bytes. Storage `10` reports database `3` across three sources/
  8,774,225,340 bytes. MariaDB restore `68`, historical Unicode restore `20`,
  deep-tree restore `21`, and MySQL TLS restore `71` each visibly reached Complete
  only at 1/1, with independent exact-content proof.
- After MySQL 1M backup `76`/point `80`, the same completed-point aggregation leaves
  storage `9` unchanged and reports storage `10` database `4` across four sources/
  8,827,622,046 bytes. Signed-in fault restore `74` stayed active through natural
  stale-lease takeover and replay, then visibly reached Complete only at 1/1 with
  independent exact-content and zero-residue proof.
- Controlled request `155` first closed the durable queued-acceptance boundary: with
  both consumers stopped, one `CoreBackupRequest` was dispatched once, RabbitMQ held
  one database delivery, no concrete backup row existed yet, and the signed-in toast
  said the request was durably queued. Once the database worker claimed it, pre-fix
  backup `91` had a verified 4,727,334-byte source artifact and ready point with zero
  upload attempts, but the browser rendered generic In Progress. This was the exact
  failing control for the source-ready remediation.
- Revisions `ab2efce` and `7bc0aef` preserve `DOWNLOAD_COMPLETE` until a fenced
  destination claim and bulk-resolve local phases from point status. The 5/5 focused,
  67/67 adjacent, and 67/67 exact-image gates passed. Deployed backup `92` then held
  at `Download Complete`, point `96` ready/zero attempts, while its signed-in row
  visibly rendered Source archive ready and exact 4,727,334/4,727,334-byte progress.
  Starting storage produced exactly one upload and terminal completion; source and
  destination SHA-256 both equal
  `4bf72f7a076e52c9b8b58c9db698a80eeb2ce244296bb8f00660c1a2d9870084`.
- That first live completion exposed a second contradiction: status polling changed
  backup `92` to Complete while its server-rendered action cell still offered Cancel
  until reload. Revision `59d15bc` moves phase and action state into the same per-row
  Alpine component. The UI/restore set passed 55/55 and the exact final image passed
  110/110. Deployed backup `93` visibly showed Source archive ready plus Cancel, then
  the same DOM row changed after its next poll to Complete plus Download/Restore/Delete
  with Cancel absent and no manual reload. It completed one upload; source and
  destination SHA-256 both equal
  `9930d67f333875436b3b85ecbae6818d33cf34d8fce4d82b4dba0d861c82ea8f`.
- The three completed controlled backups update storage `9` to website `4`/two
  sources/980,981 bytes and database `24`/ten sources/444,201,165 bytes, for
  445,182,146 total bytes. This closes queued/source-ready/action consistency and the
  current local-destination reconciliation gate. The isolated exact-image gate below
  closes retrying/partial state transitions; destination/account cases beyond this
  slice's stated exit gate remain separately tracked.
- Signed-in request `158` created two-destination backup `94`, UUID
  `bs-bs-remed-20260818-0d08dc-n102-b94`, with points `98` on storage `9` and `99`
  on exact run-owned storage `12`. After source-ready proof, point `98` uploaded once
  and point `99` entered `UPLOAD_RETRY` on attempt 1 under a controlled local-path
  failure. The same browser row visibly changed to Scheduled retry / Retrying with a
  real next-retry time, safe guidance, and Cancel. This did **not** pass the retry
  gate: `notify_upload_fail()` passed a string to Sentry before `self.retry()`, raised
  `ValueError`, and left no queued or scheduled retry. Revision `330d442` passes the
  original exception plus its allowlisted classification and tolerates legacy safe
  message callers. The first isolated module run exposed only a test-isolation error:
  the legacy-string assertion allowed an email task to resolve the intentionally
  absent RabbitMQ hostname and then observed that separate captured exception.
  Revision `d242178` mocks that unrelated email boundary. The exact `d242178` image
  passes the module 12/12 and the complete suite 1,895/1,895. Demo deployment and
  durable recovery of backup `94` remain pending behind exact demo job/queue/source
  preflight; the controlled 5M comparison has released the build host, and the isolated
  exact-image repetition below closes the slice's retry-to-partial acceptance gate
  independently.
- On the isolated exact `3d40faf` control, two-destination backup `2` reproduced a
  second public contradiction: after the invalid destination exhausted its budget,
  the terminal partial row retained transient guidance that processing would resume
  later even though no retry or Cancel action remained. This is the failing control
  for the finalizer/UI correction.
- Revision `8d2d669456c857c1e80106f3fcc2463655f807ec` makes the normal local-backup
  finalizer replace a stale transient parent error with terminal
  `STORAGE_RETRIES_EXHAUSTED` whenever a failed destination has that exact terminal
  code. The browser allowlist renders the safe instruction to review the failed
  destination before starting another upload. Focused persistent-parent, API, and UI
  regressions pass 57/57.
- The clean Git tree built on the isolated host as exact image
  `sha256:e5a9666d2a5b98a84409eb9a281018bc196ae0e8ae0af3c82e160ffc0672aad4`
  (1,260,814,347 bytes). Exact-image backup `3`, UUID
  `bs-slice14-exact-8d2d669-20260820`, used node `2`, points `3`/`4`, and local
  storages `4`/`5`. Its verified source artifact is 187 bytes with SHA-256
  `2f7780c6b259d4ada109f92d9105e1733786f1f7a292531d3f0ec5b0e53cec15`.
- Point `3` completed on attempt 1. Point `4` entered `UPLOAD_RETRY` on attempt 1 with
  a real 900-second ETA; the same Chromium row visibly changed from Source archive
  ready/Cancel to Scheduled retry/Retrying with that next-retry time, safe guidance,
  and Cancel. The exact delivery was then revoked, and a controlled Celery retry
  header of `96` exercised the max-retry boundary without pretending to wait through
  the production 24-hour backoff. Point `4` became `UPLOAD_FAILED` on attempt 2 with
  `STORAGE_RETRIES_EXHAUSTED`.
- The unmodified exact-image finalizer made parent backup `3` status Partial, phase
  Complete, no next retry, and summary configured 2/accepted 2/uploaded 1/failed 1.
  The same browser row rendered Partially complete, Phase Complete, exact 187/187-byte
  progress, the new safe exhausted-retry guidance, Download/Restore/Delete, and no
  Cancel, with no browser error. After stopping the exact storage worker and purging
  only the previously revoked scheduled test delivery, the storage queue was exactly
  zero ready, zero unacknowledged, and zero consumers. These observations close every
  previously stated Slice 14 phase/action/counter gate; demo backup `94` remains a
  deployment-smoke recovery, not a prerequisite for this isolated acceptance result.
- Post-`cecdac0` signed-in smoke on live website restore `24` found one separate UI
  consistency defect: the modal mixed a server-formatted creation timestamp with a
  browser-formatted next-retry value. Revision `ac13059` adds a failing-first template
  contract and routes both values through one browser-local formatter, using
  `created_display` only as a compatibility fallback when the raw ISO timestamp is
  missing or malformed. Its exact image passes 121/121 affected tests and 1,913/1,913
  complete tests.
- The first deployed refresh proved the timezone correction but exposed that opening
  an already-active restore loaded its list only once. Revision `79dc391` adds a
  failing-first regression and starts the existing five-second poll whenever the
  refreshed latest row is nonterminal; terminal rows still clear the poll. Its exact
  image passes 122/122 affected tests and 1,914/1,914 complete tests in 447.733
  seconds. The signed-in refreshed modal showed creation at Aug 20, 2026, 1:29 AM and
  next retry at 5:58 AM, then changed next retry to 6:00 AM without another refresh
  while creation remained stable. This was a real attempt boundary (`117→118`), not a
  mocked clock. The page emitted no new browser warnings/errors, and durable evidence
  remained one row, one files countdown delivery, `recovery_dispatch_count=11`, and
  zero destination probe/stage residue. This closes the remaining Slice 14 display and
  refresh-polling gate.

Exit gate:

- Failed, timeout, cancelled, partial, source-ready, uploading, verifying, complete,
  retrying, and reconciling states have non-contradictory labels.
- UI polling stops only for real terminal states.
- Category totals sum to the expected completed storage-point bytes and never include
  another account.

### Slice 15 — Make MySQL TLS behavior deterministic

Status: **Pass for the stated gate. Revisions `a5b3d69` and `6cbc93d` are deployed;
automated negative classifications pass; and persistent product connection `73`,
backup `75`, and restore `71` prove required TLS through exact restored data. Revision
`fecf40a` additionally closes two restore-preflight defects exposed by this gate.**

Implementation update — 2026-08-19:

- MySQL no longer uses its `PREFERRED` client mode when the database TLS switch is on.
  Validation uses `--ssl-mode=REQUIRED`, backup and restore defaults files use
  `ssl-mode=Required`, and an explicit opt-out maps to `DISABLED`. MariaDB retains its
  supported `ssl=1` option-file contract and never receives MySQL-only `ssl-mode`.
- New MySQL 8.4 connections default database TLS on in both the signed-in form and API
  serializer. An explicit false is preserved, and existing connection updates are not
  rewritten silently.
- Known MySQL error 3159/`require_secure_transport` and secure-authentication refusals
  become secret-free `TLS_REQUIRED`, stage `tls`, `retryable=false`, with an
  `Enable SSL/TLS` remediation. TLS failures during event capability probes retain
  this classification instead of being mislabeled as an EVENT privilege failure.
- First live-candidate validation exposed that an unsaved create serializer selected
  its still-empty instance version and therefore the system MariaDB binaries rather
  than the submitted MySQL 8.4 client bundle. Revision `6cbc93d` selects the requested
  version explicitly. The same live probe also established that an account-level
  MySQL `REQUIRE SSL` rule returns error 1045 for plaintext, indistinguishable from a
  wrong password by message alone. One bounded TLS-required `SELECT 1` hint probe now
  classifies it as `TLS_REQUIRED` only when the same credentials succeed under TLS;
  otherwise the original `AUTH_FAILED` result is preserved.
- The final candidate passed 86 focused connection/error/serializer/UI/MySQL/MariaDB backup
  tests and all 69 database-restore hardening tests in disposable demo-side test
  databases. The files were mounted read-only over the deployed image; both test
  databases were destroyed. This is pre-deployment evidence only.
- A real run-owned MySQL 8.4 account constrained with `REQUIRE SSL` passed four
  non-persistent candidate probes through a temporary SSH tunnel: TLS on succeeded on
  the first attempt; explicit plaintext returned `TLS_REQUIRED`/`tls`/non-retryable;
  the wrong password returned `AUTH_FAILED`/`authentication`/non-retryable; and a
  closed port returned `CONNECTION_REFUSED`/`tcp`/retryable. No BackupSheep connection,
  node, backup, or restore row was created. A temporary host-firewall rule was tested,
  found insufficient because the provider firewall remained closed, and removed;
  fixture ingress is back to SSH only.
- The same exact-owned account was then saved as persistent connection/auth `73`/`52`
  with `use_ssl=true`. Its stored product credentials negotiate
  `TLS_AES_128_GCM_SHA256`; signed-in node `102` and backup `75` completed on the
  first attempt. The 4,727,322-byte artifact passes CRC and its SHA-256 is
  `8c8af78531d1f41688018b21a968b54bbe3e5038874d7b30e6d701953d2eddf7`.
- The first restore attempt found two non-TLS defects in the privilege preflight.
  Restore `69` failed before mutation because `SHOW GRANTS` displays the escaped
  run-scope wildcard with doubled backslashes and the parser treated it as unrelated.
  After a temporary diagnostic grant, restore `70` reached trigger creation and
  exposed MySQL error 1419 because binary logging was on,
  `log_bin_trust_function_creators` was off, and the restricted account lacked
  `SUPER`. This was an incomplete restore-account fixture and a product preflight gap,
  not a TLS failure.
- After granting only the documented privileges needed by the selected source,
  signed-in resume kept restore `71` as the same logical row, rebuilt its exact-owned
  fork, and completed attempt 2 at 1/1. Source/fork streaming data digest
  `0f018f9e06d7694bc094698724571895a9e9bc9e11f927aed8f3cc8b1841d78b`
  and normalized schema digest
  `dc99017f02cf600e75d73a13031df526c7de8ad56d7c5334930be712e2b5f0c1`
  match, as do exact counts, view, trigger, and completion marker. The node's explicit
  no-stored-procedure policy explains the absent routines/event.
- Revision `fecf40a` collapses MySQL's one layer of grant-display escaping before
  wildcard matching, detects real `CREATE FUNCTION`/`CREATE TRIGGER` statements in
  the validated archive, and, when `SUPER` is absent, reads only `@@GLOBAL.log_bin`
  and `@@GLOBAL.log_bin_trust_function_creators`. An unsafe `1/0` combination now
  returns actionable `DATABASE_RESTORE_PERMISSION_DENIED` before target creation;
  global `SUPER` or safe settings bypass that denial. Malformed settings fail closed.
  Row data containing those strings does not trigger the requirement.
- The candidate passed 73/73 focused tests and 93/93 broader restore hardening,
  manual-resume, and logical crash-safety tests. Deployed `fecf40a` then recognized
  the exact escaped run grant and left `bs_restore_probe_0d08dcf` absent. App/database
  worker provenance, health, migrations, worker ping, and queue checks all passed.

Required work:

1. Reproduce the fresh-account MySQL 8.4 path and capture the actual connector/client
   code without exposing credentials.
2. During connection validation, detect the known TLS requirement and surface it
   immediately with an `Enable SSL/TLS` remediation.
3. Do not treat a deterministic configuration requirement as a generic transient
   backup retry.
4. Decide whether MySQL 8.4 connections should default SSL/TLS on; preserve an explicit
   opt-out only where supported and safe.

Exit gate:

- First validation of a fresh account either succeeds or fails once with the correct
  actionable TLS code.
- A subsequent backup does not depend on authentication-cache warming.
- Wrong-password and unreachable-host negative tests remain distinct.

### Slice 16 — Define and enforce concurrency capacity

Status: **Pass. The 30-minute late-ack failure is reproduced; revision
`2bda859`'s 25-hour broker timeout and revision `f4cf2d0`'s stable node identity are
deployed and live-proven. Revision `9454507` closes the reproduced 5M row-by-row
dump-client memory boundary, and requests/backups `155`/`92`/`93` close the durable
queued/source-ready UI boundary. Exact image `3d40faf` passes all 1,896 automated tests
and both declared export/restore parallel phases on an isolated 2-vCPU/4-GB/8-GB-swap
NVMe host without an OOM or worker restart. Revision `3d40faf` documents and locks the
stock queue limits and explicit latency targets. Current release successor `8dba19b`
passes 1,953/1,953 repository tests and is deployed healthy on the app and four scoped
workers.**

Live update — 2026-08-19 through 2026-08-20:

- Restore `68` proved that the demo broker's 1,800-second consumer timeout is lower
  than a supported large logical restore. RabbitMQ closed the database consumer's
  channel and requeued the unacknowledged delivery while the fenced child and its
  remote MariaDB client safely continued. No duplicate attempt or target mutation was
  observed, but the database queue had zero consumers until that child could exit.
- Revision `2bda859` configures `consumer_timeout = 90000000` through a read-only
  RabbitMQ `conf.d` mount. The value is intentionally finite and exceeds the existing
  23-hour command budget by two hours. Focused application tests, resolved Compose
  validation, and an isolated RabbitMQ 3.13 runtime query pass. It must be deployed
  after the active long restore settled. The live broker returned the exact value
  before and after controlled recreation; the MariaDB delivery had already exceeded
  30 minutes and completed once, with its queued redelivery draining as a terminal
  no-op.
- The first recreation also proved that a container-ID RabbitMQ hostname disconnects
  a preserved volume from its prior Mnesia node identity. Revision `f4cf2d0` pins the
  stable `rabbitmq` hostname. The recovered durable delivery remained exactly one
  across a second controlled recreation and all five workers reconnected.
- While controlled two-million-file backup `49` was active, the first intentional
  MySQL 5M row-by-row dump ran with `--skip-opt` but not `--quick`. The client grew to
  1,847,884 KiB anonymous RSS and the kernel globally OOM-killed it; the database
  worker cgroup recorded the kill. The exact backup row was cancelled before retry,
  no dump client remained, and queues drained. This is a real concurrency/memory
  boundary, not a synthetic estimate.
- Deployed revision `9454507` restores streaming as `--skip-opt --quick`. Signed-in
  backup `90` repeated the same 5M row-by-row source with 12,276 KiB maximum dump
  client RSS, 212,760 KiB maximum worker-child RSS, a 1,547,857,920-byte cgroup peak
  dominated by I/O cache, and zero cgroup OOM/OOM-kill events. It completed one
  verified upload and terminal UI. This closes only the exact dump-buffering defect;
  it does not establish a safe multi-workload host profile.
- With database and storage consumers intentionally stopped, request `155` remained
  one durable dispatched row and one database-queue delivery with no concrete backup;
  the UI acknowledged durable queueing. After the database consumer resumed while
  storage stayed stopped, deployed backups `92`/`93` visibly remained source-ready
  with zero upload attempts. Each later completed exactly once after storage resumed.
  At that checkpoint this closed the visible queued/source-capacity handoff, not yet a
  queue-latency or minimum-host throughput target; the following 2026-08-20 phases close
  those remaining measurements.
- The exact `3d40faf` application image completed the entire 1,896-test suite in
  478.193 seconds on the isolated 2-vCPU/4-GB Vultr host. The host reported no kernel
  OOM event and 67,208,527,872 bytes free afterward.
- Latest exact image `8d2d669` independently completed the same 1,896-test suite in
  437.445 seconds (465.73 seconds wall) with no kernel OOM evidence and
  63,573,880,832 bytes free afterward. Its runtime delta is limited to terminal local-
  storage finalization and browser guidance; the measured parallel-capacity evidence
  remains the deliberately controlled `3d40faf` phase A/B run below.
- With the complete stock stack running privately, phase A simultaneously executed one
  real 1M-row database export, one 100,000-file collect/archive, two 1-GB storage copies,
  and continuous signed-in/health probes. All exact artifacts verified, all 212 probes
  returned HTTP 200, console/health p95 was 0.7106/0.0081 seconds, and no process OOMed
  or restarted. Phase B repeated that envelope with a real restore of phase A's dump;
  exact row, payload, primary/expression-index, archive-entry, and storage-hash evidence
  passed. All 516 probes returned HTTP 200, console/health p95 was 0.2671/0.0112 seconds,
  queues ended empty, and no process OOMed or restarted.
- The measured host used swap under both phases. The minimum policy therefore explicitly
  requires 2 vCPU, 4 GB RAM, 8 GB SSD-backed swap, SSD/NVMe work storage, the stock
  cloud/database/files/storage/logs concurrency `4/1/1/2/2`, and prefetch `1` for every
  lane. Signed-in console p95 must stay at or below 1 second and `/healthz/` p95 at or
  below 100 milliseconds. Sustained swap I/O, queue growth, or a latency breach requires
  a larger host or lower concurrency, not a hidden limit increase.
- Revision `3d40faf` updates the tracked scaling guide and adds a contract test binding
  those documented values to the Compose/sample-environment defaults. The focused
  capacity plus retry module gate passes 23/23. This, together with request `155` and
  backups `92`/`93`, closes the declared workload, queued-excess, latency, OOM, and
  documentation exit gates.
- Final release successor `8dba19b` was built as image
  `sha256:17bc006e472c9bc399582b5e2f48b325e4495717270d16993bf2666f1dbf856c`
  after a 1,217,545-byte predeploy database snapshot whose SHA-256 is
  `b303f5ef01a8b2e0d642d48d19a4db4e4babb95a0be342131c4d80a4903a30d4`.
  Django checks and migration drift are clean. The exact app plus default, files,
  storage, and database workers run that revision; the app is healthy, all six workers
  respond idle, and default/files/storage/database/logs queues are empty. The one
  cloud unacknowledged reconciliation delivery predates this release and was not
  touched.
- The final full suite used a dedicated database and isolated RabbitMQ vhost on the
  demo host, never the production queues. It passed 1,953/1,953 tests in 394.677
  seconds; its remote log SHA-256 is
  `eb712e08dc991a936069b500ac772781ce9a5091729edde4afb5e7ce1c1c3863`.
  The disposable test container, database, broker user/vhost, and failed RabbitMQ
  image tag were removed afterward.

Completed work:

1. Measure CPU, memory, I/O, queue latency, web latency, and worker OOM behavior at
   declared host sizes.
2. Separate source export, database dump/restore, and storage-upload concurrency where
   resource profiles differ.
3. Add configurable worker/prefetch/concurrency guidance; retain the now-proven
   visible durable queued/source-ready state.
4. Preserve durable acceptance of requests; capacity throttling must delay work, not
   duplicate or lose it.

Exit gate: **Pass.**

- On the minimum supported host profile, the declared parallel workload does not OOM
  workers and the UI remains within an explicit latency target.
- If fourteen-way concurrency exceeds the supported profile, the product queues
  excess work transparently and documents the limit. The stock profile permits only
  one database, one files, and two storage jobs at once; request `155` and backups
  `92`/`93` prove accepted excess work remains durable and drains exactly once.

## Verification ladder for every slice

Run verification in this order and stop at the first failing gate:

1. Focused unit/contract tests for the changed module.
2. Real-client Docker integration test for the affected engine/archive/storage path.
3. Focused crash/lease/reconciliation tests at every external mutation boundary.
4. Relevant existing `apps.tests` regression groups.
5. Full Docker `apps.tests` suite.
6. Static/Django checks and migration checks where applicable.
7. Isolated UI acceptance against the affected small fixture.
8. Scale acceptance only after small correctness and crash gates pass.
9. Deployment and live verification only with fresh authorization and exact provenance.

Passing unit tests is not deployment approval. Passing backup creation is not restore
approval. Passing a control-plane restore request is not data verification.

## Final acceptance matrix

This matrix is now recorded with exact evidence and is complete against the stated
Slice 0–16 scope. Future support claims require their own new acceptance entries.

### Databases

For each MySQL, MariaDB, and PostgreSQL engine:

| Fixture | Backup | Restore | Required verification |
| --- | --- | --- | --- |
| Tiny | PostgreSQL direct/SSH and eight-family UI pass; MariaDB direct/SSH and eight-family UI pass; MySQL direct, persistent TLS, and eight-family UI backups `78`/`79`/`81` pass | PostgreSQL direct/SSH and matrix restore `64` fork pass; MariaDB direct/SSH and matrix restore `67` fork pass; MySQL direct, persistent TLS restore `71`, and matrix restore `82` pass | All three engines have exact rows/views, database defaults where applicable, source-equal normalized data/schema hashes, and exact markers |
| Medium | PostgreSQL UI backups `68`/`69`, MariaDB UI backups `72`/`73`, and MySQL UI backups `78`/`79`/`81` pass | PostgreSQL restore `64`, MariaDB restore `67`, and MySQL restore `82` pass | All three engines have exact related-table counts, zero orphan drift, FKs, and source-equal normalized whole-data/schema hashes |
| 1M rows | PostgreSQL SSH/UI, MariaDB UI, and MySQL signed-in backups `76` and matrix backup `81` pass. Smaller 100,000-row MySQL/MariaDB crash artifacts also pass | PostgreSQL SSH normal/UI and forced-kill replay pass; MariaDB UI restore `67` passes; MySQL matrix restore `82`, normal restore `72`, and forced committed-row restore `74` pass | All three engines have exact count/distinct/min/max and sum/full ordered coverage with source-equal data/schema hashes and exact markers. MySQL restore `74` additionally proves one-row natural lease takeover, visible active-to-terminal recovery, and zero prior/current fenced work residue at the required 1M count |
| 5M rows | MariaDB backup `74`, MySQL current backup `88`, and bounded row-by-row backup `90` pass with exact persisted dump contracts and one verified upload each | MariaDB restore `68`, MySQL clean restore `83`, and MySQL forced committed-row restore `84` pass | MariaDB and MySQL retain exact count/distinct/range/sum/payload, schema/object, marker, residue, and terminal UI evidence. MySQL restore `84` proves natural same-row attempt-2 takeover after 1,898,218 committed rows. The current 5M controlled import median is 249.94 seconds versus 16,956.91 seconds for the exact historical row-by-row run, a 67.84x/98.53% improvement. Both formats produce identical aggregate/default/metadata and ordered digest evidence with zero benchmark OOM events; the predeclared performance gate passes |
| Many tables/schemas | PostgreSQL UI backups `68`/`69`, MariaDB UI backups `72`/`73`, and MySQL UI backups `78`/`79`/`81` pass | PostgreSQL restore `64`, MariaDB restore `67`, and MySQL restore `82` pass | PostgreSQL's three-schema/450-table inventory and both MySQL-family 400-table inventories have matching normalized schema/data hashes |
| Blobs/text | PostgreSQL UI backups `68`/`69`, MariaDB UI backups `72`/`73`, and MySQL UI backups `78`/`79`/`81` pass | PostgreSQL restore `64`, MariaDB restore `67`, and MySQL restore `82` pass | All three engines preserve exact 8 MiB binary and 2 MiB text values with source-equal whole-data/schema hashes |
| Unicode | PostgreSQL UI backups `68`/`69`, MariaDB UI backups `72`/`73`, and MySQL UI backups `78`/`79`/`81` pass | PostgreSQL restore `64`, MariaDB restore `67`, and MySQL restore `82` pass | All three engines have eight byte-exact rows and matching normalized whole-data/schema hashes |
| Objects | PostgreSQL SSH/UI, MySQL direct/UI, and MariaDB SSH/UI full-object backups pass | PostgreSQL SSH/UI, MySQL direct/UI restore `82`, and MariaDB SSH/UI isolated forks pass | Exact views, triggers, routines/functions, events, sequences where applicable, indexes, and FKs match. MySQL/MariaDB events retain their disabled state and global schedulers are unchanged |
| Mutable second run | PostgreSQL backups `68`/`69`, MariaDB backups `72`/`73`, and MySQL backups `78`/`79`/`81` pass | PostgreSQL restore `64`, MariaDB restore `67`, and MySQL restore `82` pass | All three generation-2 restores exactly reflect ten updates, five deletes, twenty inserts, 115 final rows, and source-equal whole-data/schema hashes |

Large database restore gates after the above:

- MySQL: **1, 5, 10, and 25 GB passed**, including the 25 GB crash-resume gate in
  restore `88`.
- PostgreSQL: **1 GB passed** as backup `70`/restore `65`; **5 GB passed** as backup
  `71`/restore `66`; **10 GB-class passed** as backup `99`/controlled-crash restore
  `93`; **25 GB-class passed** as backup `100`/restore `90`.
- MariaDB: **5 GB passed** as backup `74`/restore `68`; additional sizes only if
  claimed as supported.

For at least one large MySQL/MariaDB and PostgreSQL restore, force a worker restart and
prove exact final data with no duplicate operation or partial target. This is closed by
MySQL 25 GB restore `88` and PostgreSQL 10M-row restore `93`, each on one logical row
with natural takeover, exact final content/marker verification, and zero scoped
residue.

### Websites

| Fixture | Current evidence | Required final result |
| --- | --- | --- |
| W1 tiny | Backup `50`/restore `25`: 3 files, 2 directories, 93 bytes; exact combined source/restored manifest | **Pass through signed-in UI** |
| W2 nested/mixed | Backup `50`/restore `25`: 146 files, 11 directories, 9,568,256 bytes; delete-extras atomic swap and exact manifest | **Pass through signed-in UI** |
| W3 large individual files | Backup `50`/restore `25`: four 64 MiB files, 268,435,456 bytes, all exact hashes | **Pass through signed-in UI** |
| W4 1 GB | Backup `50`/restore `25`: 1,000 one-MiB files, 1,048,576,000 bytes, all exact hashes | **Pass through signed-in UI** |
| W5 102,400 files | Backup `50`/restore `25`: exactly 102,400 files in 401 directories, 13,107,200 bytes, exact manifest | **Pass through signed-in UI** |
| W6 300 levels | Signed-in product backup `41`/restore `21` pass with exact 301-directory/one-file manifest | **Pass**; retain W6b as the separate boundary regression |
| W6b 40 levels | Backup `50`/restore `25`: one file and 41 directories including root; exact directory manifest | **Pass through signed-in UI** |
| W7 empty files/dirs | Backup `50`/restore `25`: ten zero-byte files, eight empty directories, sentinel, and delete-extras atomic swap | **Pass through signed-in UI** |
| W8 special names | New-archive product restore `39`/`18` and retained historical unflagged backup `38`/signed-in restore `20` pass exact 15-entry manifests. Case-folding backup `52` and signed-in restore `29` prove a destination that collapses case and NFC/NFD pairs is rejected once as `RESTORE_TARGET_NAME_COLLISION` before publication, with unchanged target hashes and zero residue. FTP/FTPS backups `57`/`58` and restores `34`/`35` preserve the broader legal-name matrix; backup `56`/restore `33` reject C0 controls before publication/mutation | **Pass for current/historical artifacts, live destination collision rejection, legal path fuzz, and portable-control enforcement** |
| W9 hidden files | Backup `50`/restore `25`: eight metadata/hidden files including four hidden basenames; exact manifest | **Pass through signed-in UI** |
| FTP and explicit FTPS | Plain-FTP backup `53`/restore `30` and explicit-FTPS backup `54`/restore `31` completed through the signed-in UI. Broader backups `57`/`58` and restores `34`/`35` round-trip 28 files/12 directories across spaces, long and Unicode components, quoted/metacharacter names, hidden/zero/empty entries, and case/NFC/NFD distinctions at identical manifest `d6b4cbf…`. Backup `56` and restore `33` fail closed on C0 controls. Every accepted restore completed once at 1/1 with delete-extras and zero residue | **Pass for functional and broader legal path-component backup/restore over both protocols** |
| 10/25/50 GB | Signed-in backups `59`/`60`/`61` and points `61`/`62`/`63` produced CRC-clean, source/destination-identical artifacts of 10,740,698,272 / 26,851,743,727 / 53,703,486,152 bytes. The retained 25 GiB control naturally recovered on the same backup row after deployment; 10 and 50 GiB each completed on storage attempt 1 | Signed-in restores `36`/`37`/`38` completed once at 1/1 and reproduced exactly 10/25/50 one-GiB files and 10,737,418,240 / 26,843,545,600 / 53,687,091,200 bytes. Every restored file has SHA-256 `1804b990…b220f`; archive hashes, CRC, queues, leases, stage/work residue, restart/OOM, and original-fixture restoration pass. **Pass** |
| 100 GB | Backup `42`/point `44` passes 7,881-part same-upload-ID resume after a hard kill, exact one-object/zero-unfinished inventory, metadata, and full 107,421,554,763-byte source-equal SHA-256 stream | Signed-in restore `27` on exact deployed `bf10816` completes once at 1/1. The retained archive CRC passes; its 107,421,554,467-byte member and the sole destination file share SHA-256 `9b2b8afb1f2d9eb176e291b8ecf0e045c591c229a5203d9fbcfed10347af1229`. Provider HEAD/metadata, queue/active/reserved drain, zero residue, and zero restart/OOM pass. **Pass** |
| 2,000,000 files | Signed-in clean backup `44`/restore `22` and interrupted backup `49` pass. Both artifacts are 612,497,006 bytes with 2,002,005 CRC-clean entries; restore `22` reproduces exactly 2,000,000 files/2,000 directories/68,000,000 bytes and the 4,100-file witness. Backup `49` proves one-row natural takeover, exact checkpoint reuse, no second source transfer, private-partial cleanup, atomic publication, one upload, matching destination identity, and signed-in Complete/Resolved recovery | **Pass for clean backup/restore and controlled archive interruption** |

### Operational acceptance

- One logical request produces one logical backup, restore, and storage operation.
- Worker kill resumes from durable state for the MySQL 100k, required MySQL 1M, and
  PostgreSQL 1M fixtures above. MySQL 1M now proves committed-row rebuild plus exact
  prior/current local-work cleanup, pre-client replay, post-client lost-response
  rebuild, post-marker adoption without re-import, and markerless/forged-target
  no-drop behavior; PostgreSQL covers pre-client, mid-import rollback/replay, and
  committed-marker lost-response adoption. MySQL 5M restore `84` adds a required
  committed-row kill, natural attempt-2 takeover, exact 5M full-row/schema/marker
  proof, terminal 1/1 UI, and zero targeted residue. Host reboot and deliberately
  repeated cross-engine cases are still open.
- Multipart resume crosses the 1,000-part inventory boundary.
- No exact-owned orphan multipart remains after a definitive failed test.
- UI now exposes the tested running, manual, failed, reconciling, and complete database
  states truthfully, including an eight-target restore that stayed active through 7/8
  and a separate eight-target restore that failed/reconciled at 5/8 before completion,
  MySQL restore `82` active from Validating 0/8 through Restoring 7/8 before
  Complete/8-of-8, its preceding restore `81` failing safely at validation 0/8,
  plus MySQL 1M restores `74`–`77` active during their natural stale-lease takeovers
  before Complete/1-of-1, MySQL 5M restore `84` active across a natural attempt-2
  takeover before Complete/1-of-1, and restores `78`/`79` visibly failing closed as
  Manual review required without offering automatic verification resume. Durable
  request `155` and backups `92`/`93` additionally prove queued acceptance,
  source-ready waiting, and same-row terminal action replacement. Exact-image backup
  `3` additionally proves Scheduled retry/Retrying with a real next-retry time followed
  by terminal Partially complete/Complete with consistent actions and safe exhausted-
  retry guidance. Remaining provider-specific transitions beyond this local-
  destination gate still require live observation.
- Persistent MySQL connection `73` proves first-attempt required TLS, backup `75`, and
  exact restore `71`; deployed `fecf40a` proves the related privilege preflight does
  not create a target.
- No secret canary appears in public responses or downloads.
- Exact image `3d40faf` passes the complete automated suite 1,896/1,896 in 478.193
  seconds on the isolated 2-vCPU/4-GB Vultr regression host. Subsequent exact images
  through `cecdac0` pass their recorded complete suites. Exact `ac13059` passes 121/121
  affected UI/restore tests and 1,913/1,913 complete tests; latest exact `79dc391`
  passes 122/122 affected tests and 1,914/1,914 complete tests in 447.733 seconds. The
  app is deployed on `79dc391`; the functionally identical execution workers remain on
  exact `ac13059`. Exact `bf10816` subsequently passes 22/22 focused integrity tests
  and 1,919/1,919 complete tests in 370.610 seconds, and is deployed to the app plus
  affected execution services. Signed-in customer-path proof retains restore `24`'s
  safe pre-fix failure and closes the corrected path with restore `27` at Complete
  1/1 after exact 100 GB verification. Every affected container reports zero
  restart/OOM, and live files/storage/default/database queues plus worker
  active/reserved inventories are drained. Exact successor `7657d27` passes 6/6 new
  focused regressions, 324/324 affected tests, and repository-wide discovery
  1,925/1,925 in 419.018 seconds with exit `0`, zero OOM, and zero restart. Its exact
  image `sha256:e3587e93ef6b1b2c289d8be78ef095488d143f789e83656a06f879c7e1803c88`
  is deployed to app/database/default/files after the verified snapshot recorded
  above. Restore `29` passes its live public collision-code/no-mutation gate; all
  affected services remained on that exact image with empty relevant queues. Current
  successor `81ea8a25ad1078e993893d0ab8e194c99dc21e88` passes 19/19 focused,
  94/94 adjacent, and 1,930/1,930 repository tests in 476.825 seconds. Exact image
  `sha256:2970f18b951b33fa238ced36acf3755118c17feea91124e084251910cc80c8d4`
  is deployed to the app and run-scoped storage worker after verified snapshot
  `f667e34c…`; its 25/50 GiB live gates pass with empty queues and zero restart/OOM.
- Both declared minimum-host capacity phases returned HTTP 200 for every health and
  signed-in probe. Worst console p95 was 0.7106 seconds against the 1-second target;
  worst health p95 was 0.0112 seconds against the 0.1-second target. No worker OOMed
  or restarted, and exact data/schema/archive/storage verification passed.
- Created test resources and ongoing costs are inventoried; cleanup requires explicit
  authorization and exact ownership proof.

## Definition of done

This remediation program is complete only when all of the following are true:

1. Every primary failure is Pass or explicitly approved/documented Not Supported.
2. Every blocked restore has been unblocked and verified, or its support claim removed.
3. Every unverified matrix entry has a recorded outcome.
4. Crash tests prove durable resume, duplicate suppression, stale-worker fencing, and
   visible progress.
5. Full automated verification is green in the supported Docker environment.
6. The exact implementation commit is deployed only after explicit authorization.
7. Migrations/checks/health/UI smoke and application-level restore verification pass
   on the deployed revision.
8. No unrelated worktree changes are included in commits.
9. Release notes state the remaining limits honestly; tests/builds/commits alone do not
   establish release approval.

Current state: **all nine conditions are satisfied for the stated remediation scope**
on deployed revision `8dba19b`. Retained Vultr fixture cost/cleanup is documented
separately and does not weaken the completed backup/restore evidence.

## Resume instructions for the next implementation agent

1. Read both source acceptance reports and this document in full.
2. Inspect `git status`, branch, HEAD, and deployment provenance. Preserve unrelated
   modifications.
3. No slice is currently incomplete. Do not change code unless a new acceptance scope
   is explicitly approved; provider cleanup remains separate from implementation.
4. Reproduce the issue in an isolated demo/Vultr fixture before editing. Under the
   active constraints, do not use local Docker or place large artifacts on the MacBook.
5. Add the failing automated test first, then make the smallest safe implementation
   change that satisfies the slice invariants.
6. Run the slice's verification ladder and record exact pass/fail counts and unfinished
   gates.
7. Reuse only the exact run-scoped resources recorded above while the current
   authorization remains valid. Do not use unrelated live acceptance resources or
   delete any provider/demo object without fresh explicit cleanup authorization and
   exact ownership evidence.
8. Do not claim a scenario fixed until the required restore and data verification exit
   gate passes.
9. Update this document's matrix and slice status with evidence when authorized to
   maintain documentation.

Recommended next action: **do not start another remediation implementation slice;
all Slices 0–16 meet their stated exit gates.** If work resumes, limit it to one of:

1. provider cleanup of the retained exact-owned Vultr VM/volume after a fresh API
   credential and ownership read are available, or
2. a separately approved acceptance expansion for a new database size, engine, or
   deliberately repeated cross-engine boundary.

The release baseline is commit `8dba19b`, deployed as the exact image recorded in
Slice 16. Its focused/adjacent/full tests, signed-in completed-state UI regression,
large PostgreSQL/MySQL restores, website crash recovery, canary redaction, queue
drain, and demo-side cleanup are evidence-backed. Retained product rows and large
acceptance artifacts remain evidence, not permission for broad filesystem deletion.
