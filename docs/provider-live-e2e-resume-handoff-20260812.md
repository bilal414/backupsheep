# UpCloud, Oracle Cloud, and DigitalOcean live E2E handoff — 2026-08-12

This is the authoritative resume document for the 2026-08-12 provider-integration
work. It is intentionally secret-free. Do not add API tokens, access keys,
customer-secret values, SSH private keys, browser cookies, or decrypted database
passwords to this file.

## Non-negotiable safety boundary

- Work on branch `develop`.
- Use only resources created and durably ledgered for the exact E2E run.
- A ledger entry alone is not deletion authority. Re-read the provider and match
  account/team/tenancy, immutable ID, generated name, labels/tags, source
  relationship, region/zone/compartment, and request fingerprint before mutation.
- Stop on zero ambiguous matches, multiple matches, missing ownership fields, or
  an unreadable provider response. Never guess.
- DigitalOcean calls must remain in Personal team UUID
  `0ba41777-3fbc-4093-9193-0f2709d2948a`.
- Never touch AWS Lightsail. AWS is not part of this provider pass.
- Preserve `/opt/backupsheep/docker-compose.override.yml`; its expected SHA-256
  is `90c8c98923b97e32a077f27ddefe5e8e7236a9249d91a24e8e9c4b32f94a1462`.
- Do not run a cleanup until its provider harness has fresh read-only ownership
  proof and crash-safe delete intents.

## Credential handling and required rotation

Credentials remain only in ignored local files and external mode-0600 runtime
files. `_docs/` is ignored locally and excluded from Docker build context. The
deployed image was verified to contain none of `/code/_docs`, `/code/.env`, or
`/code/.git`.

During this long-running session, terminal/tool output exposed a DigitalOcean
PAT, an UpCloud API token, and the UpCloud fixture SSH private key. Do not copy
their values into tickets or documentation. After the final live tests:

1. Rotate/revoke the DigitalOcean PAT.
2. Rotate/revoke the UpCloud API token.
3. Destroy the exact-owned UpCloud fixture server or rotate its root SSH key.
4. Review retained terminal/transcript access.

Oracle private-key contents and S3 customer-secret values were not printed.

## Git and deployment checkpoint

- Repository: `/Users/bilal/Projects/BackupSheep/backupsheep`
- Branch: `develop`
- Candidate commit: `28ee48d5483f501de6b3838eb0f3b230df1a0c45`
- Candidate pushed to `origin/develop`: yes
- Demo checkout: `/opt/backupsheep` on `64.177.125.68`
- Demo exact SHA after deployment: `28ee48d5483f501de6b3838eb0f3b230df1a0c45`
- Migration container exit: `0`
- Deployed `python manage.py check`: no issues
- App container: healthy
- Public `https://demo.backupsheep.com/healthz/`: HTTP 200, body `ok`
- One HTTP 502 occurred during container replacement before Gunicorn finished
  starting; the repeat probe returned 200.

Pre-deployment database snapshot:

- Path: `/var/backups/backupsheep/predeploy-28ee48d-20260812T212907Z.sql.gz`
- Size: 227,105 bytes
- Mode: `0600`
- gzip integrity: passed
- SHA-256:
  `6561284d6eef2d3dc5a8c9f451ba522dc2d3e9c175da51abb3865eee89505e78`

## Automated verification at the candidate checkpoint

All application tests ran in Docker and made no live-provider calls.

| Verification | Result |
| --- | --- |
| Focused UpCloud, Oracle harness, and restore set | 201/201 passed |
| UpCloud provider-focused set | 96/96 passed |
| UpCloud firewall module after crash-hook addition | 9/9 passed |
| Full Django suite | 1,511/1,511 passed in 204.864 seconds |
| Django system check | Passed |
| Migration drift | No changes detected |
| Harness Python compilation | Passed |
| `git diff --check` | Passed |
| Tracked-secret pattern scan | No real provider credential matched |

The full suite deliberately prints fail-closed cleanup-refusal JSON and expected
negative-path log messages. The test process exited zero.

## DigitalOcean live E2E

### Scope and ownership

- Run ID: `bs-e2e-do-20260812-c91a7e52`
- Durable ledger:
  `/Users/bilal/.backupsheep-e2e/digitalocean/bs-e2e-do-20260812-c91a7e52/ledger.json`
- Live `GET /v2/account` after the token update returned active status, team name
  `Personal`, and the exact required team UUID.
- UI connection: `15`
- Droplet node: `22`
- Volume node: `23`
- Spaces storage: `5`

Exact-owned source graph:

- Droplet: `591905892`
- Volume: `4a300611-966c-11f1-8ac3-5a82d57d1373`
- Cloud firewall: `cd108ca8-949c-4a6f-9689-dc9e6a57c4ca`
- Spaces bucket:
  `bs-e2e-bs-e2e-do-20260812-c91a7e52-fc4b8129a3a5ec908bde`
- Region: `nyc3`
- Bucket versioning: enabled

### Native backup and restore results

| Case | BackupSheep row | Provider result | Status |
| --- | ---: | --- | --- |
| Droplet snapshot | backup `1` | snapshot `240881466` | Complete |
| Volume snapshot | backup `2` | snapshot `6fa34c67-9685-11f1-9250-ea23293535eb` | Complete |
| Droplet safe-fork restore | restore `17` | droplet `591950219` | Complete |
| Volume old contract attempt | restore `18` | exact empty test target deleted and 404 verified | Historical failed path |
| Volume missing-size attempt | restore `22` | provider returned definite 400; no target | Failed safely |
| Volume current API contract | restore `24` | volume `5e6e20a0-9695-11f1-9250-ea23293535eb` | Complete |

Restore row `24` was initiated through the signed-in UI after deploying
`28ee48d`. Durable adoption occurred on the first attempt; polling completed on
attempt two. The exact provider readback matched:

- name `bs-bs-e2e-do-20260812-c91a7-cloud-volume-12c91a7n23b2-r3`;
- region `nyc3`;
- size 1 GiB;
- no Droplet attachment;
- marker tag `backupsheep-restore-24`;
- kind tag `backupsheep-restore-volume`;
- exact source-derived ownership tag.

The UI's recent-restore list showed this target as Complete.

The current DigitalOcean volume API accepts `snapshot` plus a positive integer
`size_gigabytes`. It does not echo a snapshot/source field in either the HTTP
201 response or later GET response. Reconciliation therefore requires the
durable source-derived tag plus exact name, type, region, and size; if a future
API begins returning a source field, that field must also match.

### Spaces website/database backup and restore

The versioned Spaces bucket contains exact UI-created artifacts with persisted
integrity witnesses:

| Kind | Backup row | Bytes | SHA-256 | ETag | Version ID |
| --- | ---: | ---: | --- | --- | --- |
| Website | `10` | 69,165 | `50b7af806f49fffdd9fa6d98d39c490b5bcce363e3b065926e6803be1a9f5f1b` | `51c300543d61b435b97d2af108bb97d6` | `P8U2oMq.hHQARP2LemzD0ASJKZ8aefM` |
| PostgreSQL | `9` | 5,103 | `f67fe72bcd104c5e10d5bf63e5e5835f9ee80e11f2df9fc21923d4011c3a94d0` | `62070413ef36bb5f6fc699f1f51e2a69` | `FOR7J4MWv8-S0lOZmCGRmZTvs9lmgMy` |

Website restore row `6` used DigitalOcean storage point `8` and completed.
Database restore row `13` used DigitalOcean storage point `9` and completed.
The source/target website payload and database fixture data were verified in the
shared live workload run.

### DigitalOcean remaining gates

- Integrate the independent harness audit: manifest prefix/envelope checks,
  stronger creation-fingerprint ownership, and crash-safe firewall/cleanup
  intents.
- Rerun the affected offline harness tests.
- Do not cleanup until the hardened harness re-verifies every exact ID.
- Rotate the exposed PAT after final provider calls.

## Oracle Cloud live E2E

### Scope and ownership

- Run ID: `bs-e2e-oracle-20260812-a7c42f91`
- Dedicated test compartment:
  `ocid1.compartment.oc1..aaaaaaaa4d75gbzsnzwwnqjjq7m346w2ju6rqoqvy5d5mp7fov3lqm2xuc6a`
- UI connection: `16`
- Compute node: `24`
- Boot-volume node: `25`
- Block-volume node: `26`
- Oracle Object Storage destination: `7`

Only the exact dedicated compartment graph, run-tagged IAM graph, and
run-versioned bucket are in scope. The supplied existing subnet/image were read
but not modified.

### Native backup, restore, and crash recovery

| Case | Backup row | Restore row | Exact provider target | Status |
| --- | ---: | ---: | --- | --- |
| Compute image / launch | `4` | `19` | `ocid1.instance.oc1.iad.anuwcljrt7i4d2acgqtfdfarokcj2vmm4mu7tjwxbdzyd7qp3dblrwgt7e5a` | Complete |
| Boot-volume backup / fork | `5` | `23` | `ocid1.bootvolume.oc1.iad.abuwcljrwnwf4sdk3lx7kritcixsv2tynbg3dxfj2xxknvtvjiv6sl4gpapa` | Complete |
| Block-volume backup / fork | `6` | `21` | `ocid1.volume.oc1.iad.abuwcljrh2wlhranf3nnqdayc7x7v6o6zv3fsrdy2hj54uu4i3qdvpowmlta` | Complete |

Restore row `23` is the controlled hard-crash result:

1. An exact selector-locked isolated cloud worker was armed only for restore
   row `23` and marker `backupsheep-restore-23`.
2. OCI accepted the boot-volume create.
3. The worker was SIGKILLed before the resource OCID could be persisted; exit
   code was 137.
4. The durable row remained `create_unknown` with no resource pointer.
5. Provider inventory showed exactly one source-bound, run-tagged target.
6. After lease expiry the normal recovery dispatcher redelivered the operation.
7. Duplicate original/recovery messages were fenced; one exact target was
   adopted and no second create occurred.
8. The row completed with the exact OCID, attempt count 3, recovery dispatch
   count 1, and the fault marked consumed.

The signed-in UI showed the recovered row as Complete. The isolated worker was
removed; the normal cloud worker and Beat remained running.

The Oracle harness boot verifier was corrected after live OCI showed that an
instance launched from an existing boot volume still reports the original
`image_id`. The authoritative witness is now exactly one `ATTACHED` boot-volume
attachment matching the restored boot OCID. The full Oracle harness then passed
all compute, block, and boot restore verification.

Guest-data verification matched the deterministic 1 MiB payload SHA-256
`974eff3f...` and exact byte count 1,048,576 on compute, block-volume, and
boot-volume verification paths. See the external ledger/evidence sidecar for the
complete hash; do not infer deletion authority from this abbreviated value.

### Oracle Object Storage website/database backup and restore

| Kind | Backup row | Bytes | SHA-256 | ETag | Version ID |
| --- | ---: | ---: | --- | --- | --- |
| Website | `10` | 69,165 | `50b7af806f49fffdd9fa6d98d39c490b5bcce363e3b065926e6803be1a9f5f1b` | `51c300543d61b435b97d2af108bb97d6` | `ac6538da-c4d7-4e4f-87a0-2327c0465be1` |
| PostgreSQL | `9` | 5,103 | `f67fe72bcd104c5e10d5bf63e5e5835f9ee80e11f2df9fc21923d4011c3a94d0` | `62070413ef36bb5f6fc699f1f51e2a69` | `0763de95-389f-4fb9-810f-8c7776563be7` |

Website restore row `8` used Oracle storage point `10` and completed. Database
restore row `15` used Oracle storage point `11` and completed.

### Oracle remaining gates

- Integrate the independent harness audit: validated non-symlink secret loading,
  exact secret scope, crash-safe graph/object/IAM cleanup intents, and sanitized
  diagnostics.
- Rerun Oracle harness tests and the full suite.
- Re-run read-only ownership inventory before exact cleanup.
- Update `docs/oracle-enterprise-reliability-20260812.md`; its opening offline-only
  statement is now historical and stale.

## UpCloud live E2E

### Scope and ownership

- Run ID: `bs-e2e-upcloud-20260812-74c9f2a1`
- Durable ledger:
  `/Users/bilal/.backupsheep-e2e/upcloud/bs-e2e-upcloud-20260812-74c9f2a1/ledger.json`
- Live account: `bilal414`
- UI website node: `27`
- UI PostgreSQL node: `28`
- UI Cloud Server node: `29`
- UI data-volume node: `30`
- UI connection: `19`
- Managed Object Storage destination: `6`

Exact-owned source graph:

- Cloud Server: `00e6027e-d4e5-4779-bc3f-18080a4ee0d3`
- Public IPv4: `152.44.38.25`
- Boot storage: `01e47e4e-c6de-4870-b3e2-1347f011c2bb`
- Data volume: `01279e53-5678-40e8-9210-dce5a0559e9e`
- Volume backup: `01cc2f4e-cca0-43e5-a9d6-0477009ea39f`
- Managed Object Storage service:
  `12a6acc5-091e-4bbe-ac96-ace1be725864`
- Bucket:
  `bs-bs-e2e-upcloud-20260812-74c9f2a1-objects-c25b6ce19f`
- Exact prefix:
  `backupsheep-e2e/bs-e2e-upcloud-20260812-74c9f2a1/`

The source firewall is enabled and has exactly seven ordered inbound rules:
three allow rules from the demo IPv4 for TCP 22/80/5432, three equivalent allow
rules from the local test IPv4, then one default inbound drop. The current code
captures and fingerprints the complete canonical chain before snapshot mutation.

### Website/database results

Website backup `10` and PostgreSQL backup `9` both uploaded successfully to
UpCloud storage. Their checksum, byte-count, and ETag metadata match the same
payloads listed above. Website restore row `7` used UpCloud storage point `9`
and completed. Database restore row `14` used UpCloud storage point `10` and
completed.

The bucket was not version-enabled before those UI uploads, so both committed
UpCloud storage-point records have an empty version ID. This does not satisfy the
final object-storage acceptance criterion. The exact two objects must be removed
through ownership-checked application/harness logic, versioning enabled, then
fresh website/database backups and restores run through the UI with non-empty
version IDs.

### Native volume result and local remediation status

Volume backup row `2` completed and created the exact online backup above. UI
restore row `25` was initiated on the deployed candidate. No target was created;
the provider returned a definite conflict and the row remains visibly in
reconciliation.

Live evidence explained the contract gap: UpCloud's backup response omits the
source tier (`null`), while the original exact data volume is `tier=standard`,
`encrypted=yes`. The local remediation now persists provider-authoritative tier
and encryption in the volume witness before backup mutation, sends both exact
values on clone, and requires both on target readback. A definite provider 409
is classified as `PROVIDER_CONFLICT`, durably marked `clone_rejected`, and is
not blindly replayed. A fresh volume backup is still required because row 25's
old durable witness is incomplete.

### Native server result and local remediation status

Server backup row `3` failed before provider mutation. UpCloud reports two disk
devices and `boot_disk=0` for both. The actual OS disk is uniquely attached at
`virtio:0` and uniquely carries UpCloud system labels including `_os_type` and
`_template_uuid`; the data disk is at `scsi:0:0`. The current safe selector
accepts one explicit `boot_disk=1`, or one total disk, and therefore stopped on
this live shape.

The local fix now supports this shape only when `boot_order=disk`, exactly one
`virtio:0` candidate has provider OS/template labels, and all storage IDs and
addresses are unique. Explicit `boot_disk=1` remains the first-choice witness;
duplicate or ambiguous candidates still fail closed.

Server restore now creates firewall-enabled targets without public interfaces,
reads back the exact witnessed firewall chain, persists durable staged public-IP
intents, and assigns public families only after the network shape is exact. The
UpCloud API documents that firewall changes can take 1-2 minutes to take effect,
so the local state machine persists `firewall_verified_at`, keeps the target
publicly isolated for a 120-second stabilization window, and schedules retries
without blocking a worker. It also reconciles crash/lost-response boundaries
without duplicate server, firewall, or IP mutations. These changes are offline
verified only; no provider/UI mutation was performed in this continuation.

### UpCloud remaining gates

1. Deploy the locally verified candidate and run a fresh read-only ownership
   check before resuming any UpCloud row.
2. Create a fresh UI server backup and a fresh UI volume backup if needed.
3. Run controlled crash tests after server acceptance, firewall overwrite
   acceptance, and public-IP acceptance; verify one target and no duplicate
   mutations after recovery.
4. Finish volume safe-fork restore and verify exact zone, tier, encryption,
   origin, name, and state.
5. Remove only the two exact old UpCloud objects, enable bucket versioning,
   rerun UI website/database backups, and verify non-empty version IDs,
   checksum, bytes, and ETag.
6. Restore the new website/database backups specifically from UpCloud storage.
7. Run the complete harness verification and exact-owned cleanup audit.
8. Rotate the exposed UpCloud API token and fixture SSH key.

## Independent review findings being remediated

The Luna Max safety audit found no tracked hardcoded provider credential, but it
identified these release gates:

- DigitalOcean manifest keys were not strictly bound to the run prefix and
  cleanup did not re-check that scope.
- DigitalOcean firewall attachment and cleanup mutations lacked durable
  pre-call intents at every boundary.
- DigitalOcean destructive ownership checks did not revalidate every immutable
  creation fingerprint field.
- Oracle S3 verification could bypass the strict secret loader and did not
  reject every unsafe file shape.
- Oracle graph/object/IAM cleanup needed durable unknown-outcome reconciliation.
- UpCloud's fixture/server restore could not treat an empty firewall chain as
  proven default-deny.
- Shared harness errors must remain redacted before persistence or stdout.

Three disjoint GPT-5.6 Luna Max remediation agents were started for these
provider harness/code slices. After integration and live completion, the user
requires a separate GPT-5.6 Sol Max final review followed by Luna Max fixes for
all actionable feedback.

## Exact resume order

1. Inspect the three Luna Max agent results and review every diff; do not blindly
   accept generated cleanup logic.
2. Run provider-focused Docker tests and the full suite.
3. Commit/push, take a new database snapshot, deploy, and verify exact SHA.
4. Resume UpCloud rows only after the new durable witnesses are present; prefer
   fresh backup rows over backfilling missing ownership evidence.
5. Finish UpCloud native server/volume and versioned storage UI workflows.
6. Re-run DigitalOcean/Oracle harness verification affected by the audit fixes.
7. Run fresh read-only before/after inventories for all three providers.
8. Run GPT-5.6 Sol Max review; apply accepted feedback via GPT-5.6 Luna Max.
9. Rerun full Docker verification, commit, push, deploy, verify HTTPS/UI, and
   update this document with the final SHA and acceptance matrix.
10. Perform only exact-owned cleanup, or explicitly document retained resources
    and cost exposure if cleanup is deferred.
11. Rotate the exposed credentials.
