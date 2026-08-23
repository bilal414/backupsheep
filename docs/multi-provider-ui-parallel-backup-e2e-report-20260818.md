# Multi-Provider UI E2E Backup Test — demo.backupsheep.com (2026-08-18)

End-to-end test of BackupSheep backup jobs driven **entirely through the web UI** of
https://demo.backupsheep.com (Playwright/Chromium, headless) against disposable test
resources on five cloud providers. Cloud provider APIs were used **only** to provision
and delete test resources; all BackupSheep interaction (connect accounts, link nodes,
schedules, trigger, verify, delete) went through the UI. No BackupSheep API calls.

Run marker: `bsui260818`. Artifacts (scripts, screenshots, JSON logs):
`_docs/runtime/ui-e2e-20260818/`

## 1. Test resources created (via provider APIs)

| Provider | Server | Volume | Region |
|---|---|---|---|
| Vultr | `vc2-1c-1gb` (1 vCPU/1 GB/25 GB), Ubuntu 24.04 — `d175ce64-…` | 40 GB `storage_opt` block — `82bea632-…` | ewr (New Jersey) |
| UpCloud | `1xCPU-1GB` (25 GB MaxIOPS), Ubuntu 24.04 — `0000f9f7-…` | 10 GB MaxIOPS storage — `01fb328a-…` | fi-hel1 |
| Hetzner | `cx23` (2 vCPU/4 GB/40 GB), Ubuntu 24.04 — `162558458` | 10 GB volume — `106644733` | fsn1 |
| Oracle Cloud | `VM.Standard.E2.1.Micro`, Oracle Linux 8 (AD-3) — `ocid1.instance…udlga` | 50 GB block volume — `ocid1.volume…zokq` | us-ashburn-1 (new compartment `bsui260818-compartment` + VCN/IGW/subnets) |
| DigitalOcean | `s-1vcpu-1gb` (25 GB), Ubuntu 24.04 — `593209851` | 10 GB volume — `b906bbd0-…` | fra1 |

## 2. Backup jobs configured (via UI only)

- 5 provider connections created via `/console/integration/<code>/` (modal: name + API
  credentials + backup-server endpoint "Self-hosted 64.177.125.68"). All validated live
  against provider APIs and returned HTTP 201. Oracle connection takes profile, user OCID,
  fingerprint, tenancy OCID, region (free text), PEM private key — no compartment field;
  the integration discovers all ACTIVE compartments in the tenancy.
- 9 nodes linked via "Create Server/Volume Node" → "Link Node" (correct provider
  `unique_id` verified in every POST payload). Note: Hetzner has **no volume tab** in the
  UI, so only the Hetzner server was backed up.
- Schedule per node: `bsui260818-sched`, rate **every 1 hour**, retention **keep last 3**,
  timezone UTC (HTTP 201 for all 9).

## 3. Parallel execution (8 jobs fired simultaneously, all times UTC)

All 8 on-demand snapshots triggered from 8 parallel browser tabs within a 289 ms spread
(08:37:05.988–08:37:06.277), every POST returned 201. Hetzner was triggered separately
at 08:49:40 (provider API rate limit delayed its provisioning, see §5).

| Node | Resource | Triggered | Complete (observed) | Duration | Size |
|---|---|---|---|---|---|
| 81 | Vultr volume 40 GB | 08:37:06 | 08:38:32 | ~1m26s | 42.95 GB |
| 82 | UpCloud server 25 GB | 08:37:06 | 08:38:39 | ~1m33s | 25.0 GB |
| 83 | UpCloud volume 10 GB | 08:37:06 | 08:38:43 | ~1m37s | 10.0 GB |
| 84 | DO droplet 25 GB | 08:37:06 | 08:38:47 | ~1m41s | 25.0 GB |
| 85 | DO volume 10 GB | 08:37:06 | 08:38:51 | ~1m45s | 10.0 GB |
| 87 | OCI volume 50 GB | 08:37:06 | 08:38:59 | ~1m53s | 50.0 GB |
| 86 | OCI instance (boot vol) | 08:37:06 | 08:40:56 | ~3m50s | 47 GB |
| 80 | Vultr server 25 GB | 08:37:06 | 08:46:40 | ~9m34s | 26.84 GB |
| 88 | Hetzner server 40 GB | 08:49:40 | 08:51:52 | ~2m12s | 40.0 GB |

**Result: 9/9 backup jobs completed successfully under concurrent load.** No failures,
no retries, no UI stalls. Completion times are poll observations (≤30 s granularity);
statuses live-updated correctly on the node pages (Alpine polling).

## 4. Bugs and issues found

1. **Oracle backup deletion can never complete (product bug, two stages).** After deleting
   the OCI snapshots via UI (HTTP 204; OCI accepted and moved backups to `TERMINATED`):
   - *Stage 1 (infinite reconcile):* nodes stayed "Delete Requested" for 11+ hours with log
     entries every 2 minutes: *"Backup ... is still being reconciled by Oracle Cloud."*
     `apps/_tasks/integration/oracle.py` `delete_backup` only treats a provider **404**
     (`PROVIDER_NOT_FOUND`) as proof of deletion, but OCI keeps deleted backups queryable
     with `lifecycleState=TERMINATED` for ~11.5 hours, so the reconciler returns
     IN_PROGRESS indefinitely. `_TERMINAL_BACKUP_STATES` exists but is never consulted on
     the delete path.
   - *Stage 2 (false failure):* once OCI finally purged the record and `get_volume_backup`
     returned 404, the reconciler marked the backup **"Delete Failed"** ("Invalid response
     from Oracle API") instead of deleted. Root cause: OCI's 404 code is
     `NotAuthorizedOrNotFound`, which `classify_oracle_error` maps to
     `PROVIDER_NOT_FOUND_OR_UNAUTHORIZED` (deliberately distinct from `PROVIDER_NOT_FOUND`,
     see the anti-enumeration comment), and the delete path's absence check only matches
     `PROVIDER_NOT_FOUND` — so the post-purge 404 is treated as a rejection even though
     ownership was already verified.
   Side effects: node rows linger, the connection cannot be deleted — `DELETE
   /api/v1/connections/...` returns **409 "The integration is attached to 2 node(s)"** —
   and the "Delete Failed" backup row offers **no Retry/Delete action** in the UI, so there
   is no user-facing remediation. Suggested fix: (a) treat a 200 response whose
   lifecycleState is in `_TERMINAL_BACKUP_STATES` as verified absence; (b) accept
   `PROVIDER_NOT_FOUND_OR_UNAUTHORIZED` as absence when `ownership_verified` is set.
2. **Vultr server node shows the wrong name.** Node displays `bs-e2e` (the instance's last
   Vultr tag) instead of its label `bsui260818-vultr-srv`. Underlying `unique_id` is
   correct, but the listing/node name mapping picks the tag over `label`.
3. **DigitalOcean snapshot rows show "Provider: Unknown"** in the status detail line
   (other providers show e.g. "Provider: Complete/Online/Available") — telemetry gap.
4. **Version drift:** the deployed demo runs a newer dashboard UI than this repo checkout
   (routes `/console/integration/…` vs repo's `/console/setup/integration/…`, which 404 on
   demo). Any UI automation/docs written against the repo templates need the new routes.
5. **Destructive actions lack confirmation:** schedule Delete and connection Delete fire
   immediately with no confirm modal (node/snapshot Delete do have one). Easy to misclick.
6. Minor UX: login form does not submit on Enter — the "Sign in" button must be clicked
   (submit is `type="button"` calling JS). Custom Alpine listboxes (backup server,
   timezone) are not keyboard-native `<select>`s.
7. **Hetzner API token was 429 rate-limited** (3600 req/h shared token exhausted by prior
   e2e runs), delaying Hetzner provisioning ~25 min. Not a BackupSheep defect, but the
   token quota is shared infrastructure worth isolating per test run.
8. Provisioning-side API changes noted (not BackupSheep bugs): Vultr block storage types
   are now `high_perf`/`storage_opt`/`storage_dev` (old `hdd`/`nvme` rejected;
   `storage_opt` minimum 40 GB) — worth checking restore flows that create Vultr block
   storage. OCI `VM.Standard.E2.1.Micro` exists only in AD-3 of us-ashburn-1; launching it
   into AD-1 fails with a misleading `NotAuthorizedOrNotFound`.

Pre-existing leftovers from earlier (2026-08-12) test runs are still present in the demo
account (nodes 23–30, UpCloud/DO/Oracle fixtures) and on providers (old DO droplets,
Vultr restore-test block devices, old OCI compartment with 3 RUNNING E2.1 instances).
They were **not** touched by this run's cleanup.

## 5. Cleanup

BackupSheep (UI only): schedules → snapshots → nodes → connections deleted in that order.
7/9 nodes and 4/5 connections fully removed (snapshot DELETE 204, node delete 200,
connection DELETE 204 each). The 2 Oracle nodes (86/87) and the Oracle connection
(`bsui260818-oracle`) **cannot be removed through the UI** due to bug #1: node 87's backup
reached the terminal "Delete Failed" state (with no Retry/Delete action offered) and the
node row still does not finalize; node 86's backup remains in the reconcile loop and will
hit the same false "Delete Failed" once OCI purges its boot-volume-backup record. Clearing
this residue requires the code fix suggested in §4 (or admin/DB access) — no UI path
exists. The residual rows reference provider resources that are fully deleted; nothing
bills and no schedules remain.

**Follow-up #1 (+2 h, 11:41 UTC):** nodes 86/87 still in "Delete Requested"; reconciler
still logging every 2 minutes. Direct OCI `get_volume_backup` on the deleted backup still
returns **200 + TERMINATED** (not 404) 2.5 hours after deletion — confirming the loop
persists as long as OCI serves the terminated record. Follow-up rescheduled hourly.

**Follow-up #2 (+3 h, 12:49 UTC):** unchanged — nodes still "Delete Requested", OCI GET
still returns `TERMINATED` 3.5 h after deletion.

**Follow-up #3 (+4 h, 13:53 UTC):** unchanged — OCI GET still returns `TERMINATED`
4.5 h after deletion.

**Follow-up #4 (+5 h, 14:57 UTC):** unchanged — OCI GET still returns `TERMINATED`
5.5 h after deletion.

**Follow-up #5 (+6 h, 16:03 UTC):** unchanged — OCI GET still returns `TERMINATED`
6.5 h after deletion.

**Follow-up #6 (+7 h, 17:09 UTC):** unchanged — OCI GET still returns `TERMINATED`
7.5 h after deletion.

**Follow-up #7 (+8 h, 18:13 UTC):** unchanged — OCI GET still returns `TERMINATED`
8.5 h after deletion.

**Follow-up #8 (+9 h, 19:17 UTC):** unchanged — OCI GET still returns `TERMINATED`
9.5 h after deletion.

**Follow-up #9 (+10 h, 20:23 UTC):** unchanged — OCI GET still returns `TERMINATED`
10.5 h after deletion.

**Follow-up #10 (+11 h, 21:27 UTC):** OCI finally purged the volume-backup record
(`get_volume_backup` now returns 404, ~11.5 h after deletion). The reconciler then flipped
node 87's backup to **"Delete Failed"** ("Invalid response from Oracle API", 21:12 UTC) —
confirming bug #1 stage 2. The node row still did not finalize 35 min later, so node
deletion does not tolerate the failed backup either. Node 86's boot-volume backup is still
served as TERMINATED; it will follow the same path. Hourly watch stopped: the residual
state cannot clear via the UI without the §4 fix.

Providers (API, then verified by re-listing):

- Vultr: instance + block deleted (204); only pre-existing resources remain; no snapshots.
- UpCloud: server deleted with `?storages=1` (cloned system disk included) + volume (204);
  no `bsui260818` storages remain.
- Hetzner: server (200) + volume (204); zero servers/volumes/snapshots left.
- DigitalOcean: droplet + volume (204); my snapshot records absent.
- Oracle: instance TERMINATED, volume deleted, subnets/IGW/route rules/VCN deleted,
  compartment `bsui260818-compartment` → **DELETED** (empty compartment delete accepted).

**No orphan resources or ongoing charges remain from this test run** (OCI `TERMINATED`
backup records are metadata-only and are purged by OCI; they do not bill).

## 6. Reproduction assets

- `_docs/runtime/ui-e2e-20260818/provision.py` — provider provisioning/cleanup + ledger
- `connect_providers.js`, `link_nodes.js`, `add_schedules.js`, `trigger_parallel.js`,
  `verify_parallel.js`, `verify_hz.js`, `bs_cleanup2.js` — Playwright UI drivers
- `trigger-results.json`, `verify-log.json`, `bs-cleanup-log.json` — raw timings
- `shots/` — screenshots incl. completed node pages (`95-final-*.png`, `99-hetzner-final.png`)
