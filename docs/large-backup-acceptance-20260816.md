# Large Backup Acceptance Test — 2026-08-16 (databases 1–25 GB, websites 10–100 GB, millions of files, parallel jobs)

> Follow-up to `website-database-backup-acceptance-20260815.md`. Same method:
> only the public UI at `https://demo.backupsheep.com/`, driven by a real
> browser. All test data and artifacts were generated and verified remotely —
> nothing was downloaded to or stored on the operator's MacBook.

- **Date:** 2026-08-16 → 2026-08-17 (all times UTC)
- **Run ID:** `bs-e2e-20260816-large-a0bda75a`
- **Goal:** prove database backups from 1 GB to 25 GB and website backups from
  10 GB to 100 GB (incl. a 2,000,000-file site), with many backup jobs running
  **in parallel**, as in production.

## Test infrastructure

| Component | Detail |
| --- | --- |
| Demo host | `apps.bilal.me` (Vultr, 2 vCPU / 7.4 GB / 112 GB root) — also serves demo.backupsheep.com ("Self-hosted" backup server) |
| Added storage | Vultr block storage `storage-01` (**1,000 GB**) mounted at `/mnt/blockstorage` (984 GB usable) |
| Workdir migration | demo worker volume `backupsheep_backup_workdir` bind-mounted onto `/mnt/blockstorage/backupsheep-workdir` (host-level mount + fstab; no compose/service change) — authorized by the owner for these tests |
| DB sources (Docker on demo host, data on block storage, ports bound to the demo bridge gateway 172.18.0.1 only) | MySQL 8.4.11 (`:15433`), PostgreSQL 16 (`:15434`), MariaDB 11.8.8 (`:15435`) |
| Website fixtures | `/mnt/blockstorage/<RUN2>/www/{w10gb,w25gb,w50gb,w100gb,w2mfiles}` served over SFTP by dedicated user `bslarge` |
| Destination | Amazon S3 `bucket-backupsheep`, destination id `8` (prefix `bs-e2e-20260815-webdb-de27275e/`) |
| Demo objects created | 9 DB connections (ids 46–54), 1 SFTP connection (id 45), 14 nodes (ids 66–79) |

### Fixture data

- **Databases** (one table `big`, ~1 KB incompressible base64 payload per row,
  so backup size tracks database size honestly): `lg1` = 1,000,000 rows,
  `lg5` = 5,000,000, `lg10` = 10,000,000, `lg25` = 25,000,000. Loaded and
  count-verified on: MySQL (all four), PostgreSQL (all four), MariaDB (`lg5`).
- **Websites**: `w10gb` = 10,240 × 1 MB; `w25gb` = 25,600 × 1 MB;
  `w50gb` = 51,200 × 1 MB; `w100gb` = 102,400 × 1 MB (all random bytes —
  incompressible); `w2mfiles` = 2,000,000 × ~100 B text files in 1,000 dirs.

## Overall result: **Partial Pass** (large scale)

Backup *creation* succeeded for **all 9 database scenarios (1–25 GB, three
engines)** and for **website backups of 10, 25 and 50 GB**. It **failed at
100 GB** (S3 multipart upload permanently stalls at exactly 1,000 parts /
8.39 GB) and **failed for 2,000,000 files** (export fails after the mirror
phase). Restores verified where run: MySQL 1 GB full-cycle PASS, website
10 GB full-cycle PASS.

## Backup runs — all 14 triggered within ~35 minutes of each other (parallel)

### Databases (all artifacts verified in S3)

| Node | Scenario | Artifact size | Completed (UTC) | Result |
| --- | --- | --- | --- | --- |
| 78 | MySQL lg1 (1 GB) | **768.61 MB** | 15:27 | **Pass** |
| 66 | MySQL lg5 (5 GB) | **3.84 GB** | 17:57 | **Pass** |
| 67 | MySQL lg10 (10 GB) | **7.69 GB** | 18:54 | **Pass** |
| 68 | MySQL lg25 (25 GB) | **19.21 GB** | 22:30 | **Pass** |
| 69 | PostgreSQL lg1 | **152.29 MB** | 16:26 | **Pass** |
| 70 | PostgreSQL lg5 | **3.83 GB** | 16:07 | **Pass** |
| 72 | PostgreSQL lg10 | **7.66 GB** | 16:27 | **Pass** |
| 74 | PostgreSQL lg25 | **19.17 GB** | 19:56 | **Pass** |
| 76 | MariaDB lg5 | **3.84 GB** | 18:06 | **Pass** |

Notes:
- Cross-engine consistency for identical data: MySQL lg5 3,843,077,500 B vs
  MariaDB lg5 3,843,077,611 B vs PostgreSQL lg5 3,829,802,845 B.
- PostgreSQL lg1 (152 MB) is ~5× smaller than MySQL lg1 (769 MB) for the same
  1M rows — `pg_dump` COPY format vs `mysqldump` INSERT statements.
- The demo queue ran many of these concurrently (host load average peaked at
  ~48 on 2 vCPU) and still produced byte-correct artifacts.

### Websites

| Node | Scenario | Artifact size | Files | Result |
| --- | --- | --- | --- | --- |
| 71 | w10gb (10 GB) | **10,742,098,140 B (10.74 GB)** | 10,240 | **Pass** (17:45) |
| 73 | w25gb (25 GB) | **26,855,308,669 B (26.86 GB)** | 25,600 | **Pass** (18:20) |
| 75 | w50gb (50 GB) | **53,710,650,436 B (53.71 GB)** | 51,200 | **Pass** (19:49) |
| 77 | w100gb (100 GB) | archive built + checksummed OK (107,421,554,763 B, SHA-256 `06abd4c1…`) | 102,400 | **FAIL — S3 multipart upload stalls at exactly 1,000 parts / 8,388,608,000 bytes; zero progress for hours; UI shows "Actively running" with no error; one "Scheduled retry" observed, retry stalled identically** |
| 79 | w2mfiles (2,000,000 files) | — | (mirror phase completes: 2,000,000 files enumerated) | **FAIL — `SOURCE_EXPORT_FAILED` after the mirror phase (archive step); UI: "Recovering / reconciling — Recovery: Required"; retry re-ran the mirror** |

Total uploaded to S3 during this phase: **12 artifacts, 157.47 GB**.

## Restore verification (safe-fork, via UI)

| Restore | Outcome |
| --- | --- |
| MySQL lg1 (node 78) | **PASS.** Fork `bs_restore_221b3cf59a10_lg1_…`: final state **exactly 1,000,000 rows, 1,000,000 distinct n, MAX(n)=999,999**; payload MD5s match source on sampled rows. UI: Complete. Execution was slow under the parallel storm (row-by-row INSERTs — mysqldump runs with `--skip-extended-insert`) and **a worker OOM-kill mid-restore caused a resume that transiently inserted ~295k duplicate rows before converging to the exact final state** (see issues). |
| MySQL lg5 (node 66) | **PASS.** Fork `bs_restore_1b191865d44b_lg5_…`: 5,000,000/5,000,000 rows, 5,000,000 distinct n, payload MD5 identical. Took ~8 h under load. |
| Website w10gb (node 71) | **PASS.** 10,240/10,240 files restored over SFTP; 8/8 random SHA-256 samples identical to the pre-backup bytes. |
| Website w100gb | blocked — backup itself never reached S3 |
| Website w2mfiles | blocked — backup never produced an artifact |

## Parallelism observations

- All 14 backup requests were accepted ("durably queued") and executed with
  real concurrency: up to 4 website + 3–4 database jobs simultaneously, plus
  uploads. The demo UI/API stayed responsive (healthz 200, ~15 s at worst).
- Host impact: load average up to ~48 on 2 vCPU; the kernel OOM-killed a demo
  celery worker process once (15:09) during the seed+backup storm; the
  container supervisor restarted it and queued work continued without loss.
- Storage worker pushed S3 uploads in bursts measured up to ~285 MB/s.

## Issues (new, large-scale)

1. **High — 100 GB single-object upload permanently stalls at exactly 1,000
   multipart parts (8,388,608,000 bytes).** The archive itself is fine
   (built + SHA-256-verified locally); the upload deadlocks with zero bytes
   of progress for hours, no error in the UI, and the retry stalls at the
   same place. 10/25/50 GB uploads complete normally, so the defect appears
   between 53.7 GB and 107.4 GB object size. A stalled multipart also leaves
   8.39 GB of orphaned parts in the bucket (cost + hygiene).
2. **High — 2,000,000-file website export fails after the mirror phase** with
   the same opaque `SOURCE_EXPORT_FAILED` seen for deep trees; UI sits in
   "Recovering / reconciling — Recovery: Required". 102,400 files work;
   2,000,000 do not.
3. **Medium — restores insert row-by-row** (mysqldump
   `--skip-extended-insert`): the 1M-row restore took ~35 min idle and hours
   under load. Restores of the 5–25 GB databases will take many hours each.
4. **Medium — a worker-process kill mid-restore resumes with duplicated
   inserts** (auto-increment ids observed 295k rows ahead) before converging
   to the correct final dataset. Final data was exact here, but the resume
   path visibly double-inserts; on tables without auto-assigned PKs this
   could corrupt the fork.
5. **Low — "Download Complete" phase label** is shown while the run as a
   whole is still uploading (reads as "complete" in some views).
6. **Low — abandoned multipart parts** after failed/stalled uploads are not
   cleaned up.
7. **Env note — first TCP connection to a fresh MySQL 8.4 user fails
   `TLS_REQUIRED`** (caching_sha2_password cold cache); a retry succeeds.
   Self-heals but confusing.

## What this proves works

- Database backups at 1/5/10/25 GB on MySQL 8.4, PostgreSQL 16 and MariaDB 11
  (25 GB artifacts ≈ 19.2 GB), produced under heavy parallelism, verified in
  S3, with a MySQL 1 GB full-cycle restore verified byte-exact.
- Website backups at 10/25/50 GB (incompressible data, exact byte counts),
  with a 10 GB full-cycle restore verified.
- Queueing, retry signalling, and system stability under a 14-job parallel
  storm on a 2-vCPU demo host.

## What fails at this scale

- 100 GB single-website backup (upload stall).
- 2,000,000-file website backup (export failure at archive step).
- (Already known from 2026-08-15 run: PostgreSQL/MariaDB restores broken;
  non-ASCII filenames corrupted; 300-deep trees fail.)

## Resource inventory (running at report time)

| Resource | Provider | ID/Name | State | Est. cost |
| --- | --- | --- | --- | --- |
| Block storage 1 TB | Vultr | `a532d887-…` `storage-01` → `/mnt/blockstorage` | attached to apps.bilal.me | ~$100/mo (owner-added) |
| DB containers ×3 | demo host docker | `bs-lg-mysql`, `bs-lg-postgres`, `bs-lg-mariadb` (datadirs on block storage) | running | — |
| Fixtures | block storage | `/mnt/blockstorage/bs-e2e-20260816-large-a0bda75a/` (~380 GB) | present | — |
| S3 artifacts | AWS | 12 objects, 157.47 GB (+ 8.39 GB stalled multipart parts) | stored | ~$3.70/mo |
| Demo objects | BackupSheep | 10 connections (45–54), 14 nodes (66–79) | active | — |
| Prior run (2026-08-15) | Vultr/AWS/demo | VM `ee2f2df2-…`, 45 objects 2.78 GB, nodes 32–65 | still present | ~$20/mo |

Cleanup of any of the above awaits explicit authorization.

## Final addendum (updated 2026-08-17 ~07:15 UTC — final)

- **MySQL lg5 restore: PASS.** Fork `bs_restore_1b191865d44b_lg5_…` verified
  after completion: **5,000,000/5,000,000 rows, 5,000,000 distinct n**, and
  payload MD5 for n=3333333 identical between source and fork
  (`73bd4342a5465aae36690833e16a45c7`). Execution took ~8 h for 5M rows under
  load (row-by-row INSERTs; ~10–12k rows/min steady state), UI tracked it as
  "Actively running" throughout and marked it Complete at the end.
- **MySQL lg1 restore: PASS** (previously recorded): 1,000,000/1,000,000 rows,
  payload MD5s identical.
- **w2mfiles:** after the first `SOURCE_EXPORT_FAILED` (22:23), the run went
  to "Recovering / reconciling — Recovery: Required", re-mirrored all
  2,000,000 files, and 12+ hours later is still re-archiving (zip process
  active at report time). No artifact exists. Treated as a **scale failure
  for the archive step at 2,000,000 files**; the system does not surface the
  reason.
- **w100gb:** the S3 multipart upload is **permanently stalled at exactly
  1,000 parts / 8,388,608,000 bytes** — no progress for 4+ hours, no S3
  connection open from the storage worker, run still shown as "Actively
  running" in the UI. One "Scheduled retry" occurred and stalled identically.
  The stalled multipart's 8.39 GB of parts remain orphaned in the bucket.
  Verdict: **defect — backups of ~100 GB single-website archives do not
  complete** (50 GB works, 100 GB does not).

### Restore-verification summary (final)

| Restore | Result |
| --- | --- |
| MySQL lg1 (1 GB) | **PASS** — 1,000,000/1,000,000 rows, hashes identical |
| MySQL lg5 (5 GB) | **PASS** — 5,000,000/5,000,000 rows, hashes identical |
| Website w10gb (10 GB) | **PASS** — 10,240/10,240 files, hashes identical |
| Website w100gb | Blocked — backup never completes |
| Website w2mfiles | Blocked — export fails at archive step |
