# Website & Database Backup Acceptance Test — 2026-08-15

> End-to-end acceptance test of BackupSheep's website and database backup
> features from a normal customer's perspective, using only the public UI at
> `https://demo.backupsheep.com/`.

- **Date:** 2026-08-15 (all times UTC, matching the demo UI's timezone)
- **Run ID:** `bs-e2e-20260815-webdb-de27275e`
- **Method:** real browser driven against the public UI. Test sources lived on a
  new, isolated Vultr VM; destination was a new prefix in the authorized S3
  bucket. No BackupSheep backend, API, Django admin, SSH to the demo host,
  server logs, or source code was used or modified.
- **Account:** demo owner account (console login).

## Overall result: **Partial Pass**

Backup *creation* works end-to-end for all 24 database scenarios and 9/10
website scenarios, with correct artifacts verified in S3. Restore works fully
for **MySQL** and for **websites with ASCII names**, but **PostgreSQL and
MariaDB restores fail**, **non-ASCII filenames are corrupted**, and
**300-level deep websites fail to back up**.

---

## Environment under test

| Component | Detail |
| --- | --- |
| Demo UI | `https://demo.backupsheep.com/` (backup server IPv4 `64.177.125.68`, "Self-hosted") |
| Test VM | Vultr `ord`, `vc2-2c-4gb`, Ubuntu 24.04, `137.220.60.63` (created for this test) |
| DB engines (Docker on VM) | MySQL 8.4.11 (`:3306`), MariaDB 11.8.8 (`:3307`), PostgreSQL 16.15 (`:5432`), plus empty restore-target containers (`:13306`, `:13307`, `:15432`) |
| Website fixtures | `/var/www/w1-tiny` … `w9-hidden`, served over SFTP by a dedicated unprivileged user |
| Destination | Amazon S3 `bucket-backupsheep` (us-east-1), prefix `bs-e2e-20260815-webdb-de27275e/` (storage destination id `8`) |
| Demo objects created | 1 SFTP connection (id 20), 24 DB connections (ids 21–44), 34 nodes (ids 32–65), 1 paused schedule (id 5) |

Website fixtures: `w1-tiny` (3 files), `w2-medium` (146 files nested/mixed
types, ~8 MB), `w3-largefiles` (4 × 64 MB), `w4-large` (1,000 × 1 MB = 1 GB),
`w5-manyfiles` (102,400 × ~128 B), `w6-deep` (300-level tree),
`w6b-deep40` (40-level tree, boundary probe), `w7-empty` (10 zero-byte files +
8 empty dirs), `w8-special` (spaces/quotes/Unicode/emoji/CJK/Cyrillic names),
`w9-hidden` (dotfiles, `.git/`, `.htaccess`).

Database fixtures per engine: `tiny` (1 table/3 rows), `medium` (8 tables,
~35k rows, FKs), `large` (1 table, 1,000,000 rows), `manytables` (400 tables;
PostgreSQL: 3 schemas × 150), `blobs` (3 rows incl. 8 MB binary + ~2 MB text),
`unicode` (8 rows: emoji/CJK/Arabic/Cyrillic/combining/quotes/newlines),
`objects` (PK/FK/index/view/trigger/procedure/function/custom sequence;
MySQL/MariaDB also an EVENT), `mutable` (100 rows; then +20/upd 10/del 5
before the second backup).

---

## Coverage matrix — websites (SFTP, node mode = Incremental)

| ID | Scenario | Backup run 1 | Run 2 | Restore verification | Result |
| --- | --- | --- | --- | --- | --- |
| W1 | Tiny static (3 files) | Complete 1.66 KB / 3 files, 20:12 | Complete, identical | UI restore → SHA-256 hashes identical | **Pass** |
| W2 | Small-medium nested/mixed (146 files) | Complete 3.24 MB, 20:42 | Complete, identical | UI restore → 146/146 hashes identical | **Pass** |
| W3 | Large individual files (4 × 64 MB) | Complete 268.48 MB / 4 files, 20:42 | Complete, identical | S3 object present; restore not re-run (mechanics proven by W4) | **Pass (backup)** |
| W4 | Large site (1 GB, 1,000 files) | Complete 1.05 GB / 1,000, 20:47 | Complete, identical | UI restore (~2 min) → **1,000/1,000 hashes identical** | **Pass** |
| W5 | Many small files (102,400) | Complete 24.81 MB / 102,400 files, 20:48 (~1 min) | Complete, identical | Zip: 102,400/102,400 entries; 5 random SHA-256 samples match source | **Pass** |
| W6 | Deep structure (300 levels) | **Failed** instantly 20:42; retest failed 21:12 (`SOURCE_EXPORT_FAILED`) | — | — | **Fail** |
| W6b | Deep structure (40 levels) | Complete 16.1 KB, 21:13 | — | S3 object verified | Pass (boundary probe) |
| W7 | Empty files + empty dirs | Complete 6.58 KB / 11 files, 20:41 | Complete | Restore + *delete-extras* option: planted extras deleted, empty dirs + 0-byte files restored | **Pass** |
| W8 | Special filenames | Complete 6.06 KB / 19 files, 20:41 | Complete | Content byte-identical; **non-ASCII names mangled** (zip stores names without UTF-8 flag → CP437 mojibake on disk) | **Partial — filename defect** |
| W9 | Hidden files/metadata | Complete 2.8 KB / 8 files, 20:41 | Complete | Restore → all dotfiles (`.htaccess`, `.git/*`, `.env.example`) identical | **Pass** |

Millions-of-files target: not attempted — judged uneconomical for a timed
acceptance run; 102,400 files completed in ~1 minute, so the practical ceiling
is high, but 1M+ remains **unverified**.

## Coverage matrix — databases (all artifacts confirmed in S3)

| Engine | tiny | medium | large (1M rows) | many tables | blobs | unicode | objects | mutable (2nd run) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MySQL 8.4.11 | ✅ 1.09 KB | ✅ 217.7 KB | ✅ 28.4 MB | ✅ 16.3 KB (400 tbl) | ✅ 54.2 KB | ✅ 1.65 KB | ✅ 2.31 KB | ✅ 1.97 KB |
| MariaDB 11.8.8 | ✅ 1.17 KB | ✅ 208.1 KB | ✅ 28.4 MB | ✅ 17.1 KB | ✅ 54.3 KB | ✅ 1.65 KB | ✅ 2.38 KB | ✅ 2.06 KB |
| PostgreSQL 16.15 | ✅ 1.21 KB | ✅ 484.0 KB | ✅ 26.6 MB | ✅ 41.2 KB (450 tbl, 3 schemas) | ✅ 70.7 KB | ✅ 1.65 KB | ✅ 2.31 KB | ✅ 1.90 KB |

All 24 first runs Complete 20:38–20:47 UTC.

## Restore verification (safe-fork restores via the UI)

| Target | Result |
| --- | --- |
| MySQL — all 8 scenarios | **Pass.** Fork DBs (`bs_restore_*`) verified: exact row counts (9,999 / 10,000 / 5,000 / 1,000 in medium), 1,000,000 rows in the large fork, blob MD5s identical, unicode MD5 identical, 400+ tables, view/FK/trigger/routines present and functionally correct (view returns correct aggregates; trigger log row present). Mutable 2nd-backup fork: 115 rows, gen2 = 20 present, deletions absent, updates applied — exact mutated state. Caveat: MySQL `EVENT` object not carried into the fork. |
| PostgreSQL — tiny/objects/manytables/mutable (2 attempts each) | **Fail.** UI: "Terminal failure"; fork DB created but empty (only `__backupsheep_restore.marker`). Independent re-test: the artifact loads into a fresh DB only with a *tolerant* client — the dump begins with DROP statements that error under strict load; with a tolerant load all rows come back. → The product's own restore cannot restore its own PG backups. |
| MariaDB — tiny/objects/mutable (2 attempts each) | **Fail.** Same "Terminal failure", empty fork. Artifact itself is valid: loads cleanly with the matching `mariadb` client (3/3 rows). → The demo's restore path rejects the vendor dump (sandbox-mode header). |
| Website — w1/w2/w4/w7/w9 | **Pass** (hashes/counts above). w7 also proved the "delete files not in backup" option works exactly as labeled. |
| Website — w8 | Content pass; **non-ASCII filenames corrupted** (see issues). |

## Configuration, scheduling, status, negative cases

- Connection creation/validation: SFTP (with **SSH host-key approval flow** —
  the fingerprint shown in the UI matched the server's host key exactly),
  MySQL, MariaDB, PostgreSQL — all Active; "Validation passed. Integration is
  good for backups."
- Manual run initiation, visible in-progress state ("Actively running", phase,
  progress bytes, Cancel), completion with timestamps/size/file counts: all
  present and accurate.
- Schedule: rate-based 30-minute schedule created (retention 3, Etc/UTC,
  storage selected) — **fired on time at 21:30**, run labeled
  `Scheduled (sched-medium-30…)`, then paused.
- **NEG-1** MySQL wrong password → 400 `CONNECTION_VALIDATION_FAILED`, clear
  remediation. **NEG-2** unreachable host → `TCP_TIMEOUT`, "did not respond
  before the connection timeout", retryable, firewall/port remediation
  (~25 s). **NEG-3** SFTP wrong password → `AUTH_FAILED` with remediation.
  All clear and useful.

---

## Issues by severity

1. **High — PostgreSQL restores are broken.** Every PG restore fails
   ("Terminal failure", empty fork); the product's strict loader fails on the
   DROP statements its own dump generator emits. Backup creation is fine;
   recovery is not.
2. **High — MariaDB restores are broken.** Same failure shape; the artifact is
   valid and loadable with the vendor client, so the demo's restore path is at
   fault (sandbox-mode dump header).
3. **High — Non-ASCII filenames corrupted.** Zip entries written without the
   UTF-8 filename flag; restore creates mojibake-named duplicates
   (`café` → `caf├⌐`, `中文` → `Σ╕¡µûç`, 🚀 → `≡ƒÜÇ`). Content is intact;
   names are not — a restore onto a live site would duplicate files under
   wrong names.
4. **Medium — Deep websites fail at export.** A 300-level tree fails instantly
   (`SOURCE_EXPORT_FAILED`, reproducible on retest); 40 levels works. The
   failure boundary lies between.
5. **Medium — DB node creation defaults to "Backup All Tables" = OFF with zero
   tables included.** All 24 nodes initially backed up nothing and failed
   opaquely until the toggle was found and enabled. A node with nothing
   selected should fail validation at creation, not at run time.
6. **Medium — Failure diagnostics are opaque.** `SOURCE_EXPORT_FAILED` /
   "will retry without exposing sensitive diagnostics" with no actionable
   detail; retry loops show no attempt history.
7. **Low — Failed-run "Log File" button 404s**
   (`/api/v1/backups/database/<id>/download_transfer_log/` → 404).
8. **Low — Terminally-failed rows keep the "Phase: In Progress" label**
   (misleading).
9. **Low — MySQL EVENT not restored** (trigger/view/routines/FK were).
10. **Low — Storage page category counters show 0**
    ("Websites/Databases — 0 bytes") while "2.6 GB stored" is correct in total.
11. **Perf note — PG/MySQL restore of 1M rows took ~35 min** (backup of the
    same data: seconds). Correctness fine; speed noteworthy.

## What works (user-facing evidence)

End-to-end: connect → SSH host-key approval → node → run → in-progress →
complete → artifact in S3 → safe-fork restore → verified contents — for MySQL
(all 8 scenarios) and websites (ASCII), including 1 GB and 102,400-file sites,
empty/hidden/special-char files, incremental 2nd runs (identical sizes), a
mutable-data second backup capturing add/update/delete exactly, and on-time
scheduled execution.

---

## Test resources created (left in place — cleanup not authorized at test time)

| Resource | Provider | ID/Name | State | Est. cost |
| --- | --- | --- | --- | --- |
| VPS 2 vCPU / 4 GB / 80 GB, Ubuntu 24.04 | Vultr `ord` | `ee2f2df2-f340-496a-bfb0-e6d31f204a18` `bs-e2e-20260815-webdb-de27275e` (`137.220.60.63`) | active; 6 Docker DB containers + fixtures | ~$0.03/h (~$20/mo prorated) |
| Firewall group (SSH open; DB ports open) | Vultr | `2e39d4b8-6c6d-44e5-a9a5-b8c62799aa14` | attached | free |
| SSH key registration | Vultr | `393911f2-7f38-4657-9af6-65315dfdce56` | registered | free |
| S3 objects: 45 backup zips, 2.78 GB | AWS `bucket-backupsheep` | prefix `bs-e2e-20260815-webdb-de27275e/` | stored | < $0.10/mo |
| Demo account objects | BackupSheep | 25 connections (1 SFTP + 24 DB), 34 nodes (ids 32–65), S3 storage destination (id 8), 1 paused schedule (id 5), `bs_restore_*` forks on the VM | active/paused | — |

Pre-existing resources (Vultr instance `apps.bilal.me`, SSH key
"Bilal-Macbook-Pro", demo nodes 22–30, connections/storage from earlier runs,
the shared UpCloud fixtures) were **not modified or deleted**; one on-demand
backup was attempted on shared fixture node 28 as a control but never executed
(HTTP 503, no storage selected — no state change). No code, configuration, or
infrastructure of the demo environment was changed.

## Recommended next actions

1. Fix PG restore: make the restore loader tolerant of its own dump's leading
   DROP statements (or strip DROPs for fork restores).
2. Fix MariaDB restore: use a MariaDB-aware client/loader that accepts the
   sandbox-mode dump header.
3. Write zips with the UTF-8 filename flag (or normalize names) so non-ASCII
   names round-trip.
4. Fail fast with a clear reason for deep trees (or raise the limit).
5. Validate "nothing selected to back up" at node creation; attach real error
   details to failed runs; fix the Log File 404 and the stale
   "Phase: In Progress" on failed rows; restore MySQL events.
6. Open follow-ups if needed: million-file scale, deep-tree boundary, W3
   restore, and cleanup of the VM/S3/demo objects (requires explicit
   authorization).
