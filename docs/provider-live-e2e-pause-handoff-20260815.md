# BackupSheep provider live E2E pause handoff — 2026-08-15 UTC

This is the authoritative continuation document for the DigitalOcean,
UpCloud, and Oracle Cloud live acceptance run. It records the enterprise
hardening deployed on 2026-08-15, the new signed-in UI backups completed after
that deployment, the exact no-work-in-progress pause point, and the remaining
work required before any of the three integrations can be marked fully end to
end tested.

It supersedes the status and resume instructions in:

- `provider-live-e2e-final-handoff-20260813.md`;
- `provider-live-e2e-resume-handoff-20260812.md`;
- `provider-live-e2e-wrap-up-20260812.md`.

Historical evidence in those documents remains useful, but this document wins
wherever instructions or status differ. In particular, **do not revoke, rotate,
delete, or replace any API token, object-storage access key, SSH key, runtime
secret, or integration credential**. The user explicitly retained those
credentials for later work.

This file contains no provider tokens, object-storage secrets, database
passwords, private keys, browser cookies, decrypted integration credentials, or
restored-workload public IP addresses.

## Executive status

| Gate | State at pause | Meaning |
| --- | --- | --- |
| Product reliability hardening | Complete and deployed | The reviewed code is on `develop` and the demo image was rebuilt from the exact code commit. |
| Automated validation | Complete | 1,708/1,708 complete `apps.tests` tests passed after the final fixes. |
| Independent review | Complete | GPT-5.6 Sol Max reported no remaining findings after the Luna Max correction pass. |
| Fresh UI website backup | Complete | Backup row `12` uploaded through the signed-in UI to DigitalOcean Spaces, UpCloud Managed Object Storage, and Oracle Object Storage. |
| Fresh UI PostgreSQL backup | Complete | Backup row `12` uploaded through the signed-in UI to the same three destinations. |
| Fresh UI website restores | Not started for the new row | Three restores from backup `12` remain. No restore request was submitted in the final open modal. |
| Fresh UI PostgreSQL restores | Not started for the new row | Three safe-fork restores from backup `12` remain. |
| Current artifact/application verification | Pending | Export and verify one immutable generation immediately after each provider's website/database restore pair. |
| Native provider guest/data proof | Pending | UpCloud, DigitalOcean, and Oracle still have the explicit provider-specific gates below. |
| Exact-owned cleanup | Pending | Test resources were deliberately retained. No broad or provider cleanup was performed in this continuation. |
| Credential revocation/rotation | Forbidden | Retain every current token and key for later tasks. |

No integration should be labeled **fully E2E tested** from this checkpoint
alone. The product code and fresh backup/upload side are proven; the new restore
pairs, strict application/data proof, remaining native-resource proof, and
exact-owned cleanup receipts are still open.

## Non-negotiable safety rules

1. Work on `develop`. Verify local `develop`, `origin/develop`, the demo
   checkout, and the running image provenance before changing or deploying.
2. Never modify or delete AWS Lightsail resources.
3. DigitalOcean mutations are restricted to Personal team UUID
   `0ba41777-3fbc-4093-9193-0f2709d2948a`.
4. Before every provider mutation or deletion, perform a fresh exact read that
   proves the account/team/tenancy, immutable resource ID, run ID/name,
   ownership markers/tags, location, source relationship, and creation witness.
5. A local ledger or this document is not mutation authority. Stop on missing
   fingerprints, incomplete pagination, duplicate or zero marker matches,
   changed relationships, ambiguous ownership, or any failed provider read.
6. Never revoke, rotate, delete, replace, or invalidate any token, key,
   credential file, SSH key, object-storage access key, runtime secret, or
   BackupSheep integration credential.
7. Never print `_docs`, runtime secret files, environment variables, decrypted
   integrations, private-key material, browser cookies, or secret-bearing
   provider response bodies.
8. Preserve `/opt/backupsheep/docker-compose.override.yml`. Its required
   SHA-256 is
   `90c8c98923b97e32a077f27ddefe5e8e7236a9249d91a24e8e9c4b32f94a1462`.
9. Preserve unrelated local work. At the pause, `README.md`, `SECURITY.md`,
   `bruno/`, and the pre-existing untracked documentation trees listed below
   were not part of this acceptance change and must not be discarded or swept
   into a later commit accidentally.
10. Cleanup, when resumed, must be exact-ID, ownership-gated, dependency-aware,
    and followed by before/after inventories. Never use an account-wide or
    prefix-wide delete.

## Exact stop point

The final browser action opened the restore dialog for PostgreSQL backup `12`
on node `28`. No storage radio button was selected, the acknowledgement was not
checked, the Restore button remained disabled, and the dialog was then canceled.
There was no restore POST.

Read-only database checks at the pause proved:

| Restore family | Maximum row ID | Pending/in-progress rows | Relevant newest rows |
| --- | ---: | ---: | --- |
| Website restore | `9` | `0` | `9` |
| Database restore | `16` | `0` | `16` |
| Native cloud restore | `26` | `0` | `17` through `26` |

Therefore, no IDs have been allocated for the six new workload restores. Do not
assume the next IDs on resume; query the database before and after each UI
submission and bind manifests to the rows actually created.

The final queue read showed `cloud`, `database`, `default`, `files`, `logs`, and
`storage` with `0` ready, `0` unacknowledged, and one consumer each.

## Repository and demo checkpoint

- Local checkout: `/Users/bilal/Projects/BackupSheep/backupsheep`
- Branch: `develop`
- Remote: `origin/develop`
- Demo URL: `https://demo.backupsheep.com`
- Demo host checkout: `/opt/backupsheep`
- Code-bearing commit:
  `b40fde9119f656fd314c51faf58f17097c36e095`
  (`Harden provider live acceptance and restore recovery`)
- Local `HEAD`, `origin/develop`, demo `HEAD`, and demo `origin/develop` were all
  exactly the code-bearing commit before this documentation-only handoff was
  published.
- The demo application image was rebuilt from that exact code commit. A later
  documentation-only fast-forward does not change the executable image
  provenance.
- Public health returned HTTP `200`.
- App, PostgreSQL, and RabbitMQ were healthy; Beat and every worker were
  running.
- No migrations were added by the hardening commit. Deployment migration and
  application checks passed.

Resolve the documentation commit containing this handoff instead of copying a
future stale abbreviated hash:

```sh
git log -1 --format=%H -- docs/provider-live-e2e-pause-handoff-20260815.md
```

### Preserved pre-deployment snapshot

The snapshot is on the demo host, owned by root and mode `0600`:

| Purpose | Path | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Before deploying `b40fde9` | `/var/backups/backupsheep/predeploy-b40fde9-20260815T173346Z.sql.gz` | 251499 | `b549aadffcfae59d5768ebbe51cb4c412674133bbd395180a0ed7cdbf5fba165` |

### Unrelated local work to preserve

The following paths were already modified or untracked and were intentionally
excluded from the acceptance commit and this handoff commit, except for the two
explicit handoff files:

- modified: `README.md`, `SECURITY.md`;
- untracked: `bruno/`, `docs/README.md`, `docs/ai-implementation-plan/`,
  `docs/api/`, `docs/features/`, `docs/guides/`, `docs/reference/`, and
  `docs/releases/`.

Stage exact file paths only. Do not use a blanket add.

## Product hardening completed in `b40fde9`

The deployed change closes the implementation and deterministic-test gaps
identified in the 2026-08-13 handoff:

- UI restore lost-response recovery now uses a strict public UUIDv4
  `recovery_id` plus the intended target name. Opaque idempotency keys remain
  hashed, node-scoped UUIDv5 correlation remains stable, and legacy
  fingerprints remain readable.
- Native restore history chooses the newest durable restore row instead of a
  stale first match.
- Provider lifecycle status is persisted and exposed through the safe status
  surface.
- Safe restore failure handling locks and reloads the durable row, merges
  parameters, and re-raises stale lease/fencing errors instead of
  misclassifying them as provider failures.
- DigitalOcean native volume verification now supports an exact-owned source
  Droplet and firewall, pinned SSH identity, durable attach/detach/seed intents,
  deterministic source bytes, and read-only restored-byte proof. A caller hash
  cannot manufacture FULL_E2E status.
- The DigitalOcean harness now has legacy normalization, a strict read-only
  report, stronger restore ownership checks, and fresh Spaces scope/versioning
  checks.
- The Oracle harness now supports a strict protected runtime scope, manifest
  export/report/verification, workload verification, orphan reconciliation,
  and exact cleanup gates.
- UpCloud manifest generation is provider-neutral for workload storage and
  strictly binds an immutable generation directory, ownership marker, row IDs,
  artifacts, checksums, and generation digest.

### Review and automated-test receipt

- Final GPT-5.6 Sol Max review: **no remaining findings**.
- Integrated changed surface: **481/481 passed**.
- Cross-module compatibility set: **65/65 passed**.
- Complete Docker `apps.tests`: **1,708/1,708 passed** in `208.598s`.
- Python compilation of the changed modules passed.
- `git diff --check` passed.
- No migration files were required.

These results establish the implementation gate. They do not substitute for
the remaining signed-in UI and live-provider/data-plane gates.

## Fresh signed-in UI backup evidence

All actions below were performed through the signed-in
`demo.backupsheep.com` UI after `b40fde9` was deployed. Only the exact three
test destinations were selected; existing AWS S3 and Vultr destinations were
not selected or modified.

Common fixture scope:

- account `1`;
- website node `27`;
- PostgreSQL node `28`;
- DigitalOcean Spaces storage `5`;
- UpCloud Managed Object Storage `6`;
- Oracle Object Storage `7`.

### Website backup `12`

UI notes:
`Provider live E2E completion 2026-08-15: website to DO, UpCloud, OCI`

The UI displayed a durable-queue success message and then visibly showed the
new row Complete. All three storage points are upload-complete (`status=3`).

| Provider | Storage point | Artifact | Object key | Bytes | SHA-256 | ETag | Version ID |
| --- | ---: | ---: | --- | ---: | --- | --- | --- |
| DigitalOcean Spaces | `12` | `32` | `ui/bs-e2e-do-20260812-c91a7e52/bs-upcloud-website-fixture-n27-b12.zip` | 69165 | `8b94ab9085cc1de4a25920147e9ab10e43ed7bda421c574b679ed7a1aeb61947` | `d336700dd8d9404d2be8427af2fb8fe0` | `6uhKXAKKpcvqwlosPTXXHoASBdpZY0G` |
| UpCloud MOS | `13` | `33` | `backupsheep-e2e/bs-e2e-upcloud-20260812-74c9f2a1/bs-upcloud-website-fixture-n27-b12.zip` | 69165 | same | same | `1786815441009` |
| Oracle Object Storage | `14` | `34` | `bs-e2e-oracle-20260812-a7c42f91/bs-upcloud-website-fixture-n27-b12.zip` | 69165 | same | same | `023ffa15-9889-4cac-b055-d3b4de092f3a` |

### PostgreSQL backup `12`

UI notes:
`Provider live E2E completion 2026-08-15: PostgreSQL to DO, UpCloud, OCI`

The UI displayed a durable-queue success message and then visibly showed the
new row Complete. All three storage points are upload-complete (`status=3`).

| Provider | Storage point | Artifact | Object key | Bytes | SHA-256 | ETag | Version ID |
| --- | ---: | ---: | --- | ---: | --- | --- | --- |
| DigitalOcean Spaces | `14` | `37` | `ui/bs-e2e-do-20260812-c91a7e52/bs-upcloud-postgresql-fixtu-n28-b12.zip` | 5123 | `e15f61a57d6b189518172d6569a31bd2337019fac5076ccb804ff1a03af4dcfb` | `3e847815a5f81c79ac1479e5301d9e9d` | `ojpu4KIbMj8xWuubkf2mQq--HCpzH-Q` |
| UpCloud MOS | `15` | `36` | `backupsheep-e2e/bs-e2e-upcloud-20260812-74c9f2a1/bs-upcloud-postgresql-fixtu-n28-b12.zip` | 5123 | same | same | `1786815488997` |
| Oracle Object Storage | `16` | `38` | `bs-e2e-oracle-20260812-a7c42f91/bs-upcloud-postgresql-fixtu-n28-b12.zip` | 5123 | same | same | `10fafb0f-1c84-45dc-8e99-5f2187980c59` |

The database and website objects have persisted byte count, SHA-256, ETag, and
non-empty version ID evidence for every provider.

## Durable demo resource map

| Provider/workload | UI connection | Node | Source resource |
| --- | ---: | ---: | --- |
| DigitalOcean Droplet | `15` | `22` | `591905892` |
| DigitalOcean volume | `15` | `23` | `4a300611-966c-11f1-8ac3-5a82d57d1373` |
| Oracle compute | `16` | `24` | See protected Oracle ledger and durable node row. |
| Oracle boot volume | `16` | `25` | See protected Oracle ledger and durable node row. |
| Oracle block volume | `16` | `26` | See protected Oracle ledger and durable node row. |
| Shared website fixture | `19` | `27` | Owned UpCloud fixture guest |
| Shared PostgreSQL fixture | `19` | `28` | Owned UpCloud fixture guest |
| UpCloud Cloud Server | `19` | `29` | `00e6027e-d4e5-4779-bc3f-18080a4ee0d3` |
| UpCloud data volume | `19` | `30` | `01279e53-5678-40e8-9210-dce5a0559e9e` |

Storage rows are DigitalOcean Spaces `5`, UpCloud MOS `6`, and Oracle Object
Storage `7`.

## Native provider checkpoint

The IDs in this section are durable/last-known checkpoint evidence. Provider
inventories were not refreshed after the user requested the pause. Fresh reads
are mandatory before using any ID as mutation or cleanup authority.

### DigitalOcean

- Run ID: `bs-e2e-do-20260812-c91a7e52`
- Personal team UUID:
  `0ba41777-3fbc-4093-9193-0f2709d2948a`
- Region: `nyc3`
- Source Droplet: `591905892`
- Source volume: `4a300611-966c-11f1-8ac3-5a82d57d1373`
- Exact test firewall: `cd108ca8-949c-4a6f-9689-dc9e6a57c4ca`
- Droplet snapshot backup row `1`: snapshot `240881466`, Complete
- Volume snapshot backup row `2`:
  `6fa34c67-9685-11f1-9250-ea23293535eb`, Complete
- Droplet restore row `17`: Droplet `591950219`, Complete
- Volume restore row `24`:
  `5e6e20a0-9695-11f1-9250-ea23293535eb`, Complete
- Historical volume rows `18` and `22` are failed/manual-review receipts and
  must not be confused with successful targets.
- Versioned Spaces bucket:
  `bs-e2e-bs-e2e-do-20260812-c91a7e52-fc4b8129a3a5ec908bde`

Remaining native gate: use the hardened native-volume verifier to seed
deterministic bytes on the exact source volume, create a fresh native volume
backup and safe-fork restore through the UI, then prove restored bytes via the
owned verifier Droplet with read-only attachment/mount semantics. Re-verify the
existing restored Droplet at guest/data level as well. Do not award FULL_E2E
from caller-provided hashes or control-plane status alone.

### UpCloud

- Run ID: `bs-e2e-upcloud-20260812-74c9f2a1`
- Account: `bilal414`
- Zone: `us-chi1`
- Source server: `00e6027e-d4e5-4779-bc3f-18080a4ee0d3`
- Source data volume: `01279e53-5678-40e8-9210-dce5a0559e9e`
- Source volume backup:
  `01cc2f4e-cca0-43e5-a9d6-0477009ea39f`
- Server backup:
  `01e3e859-77b4-4502-96f2-87ced534783a`
- Volume restore row `25`:
  `014913a9-3217-4f09-b541-1f5ba2173c96`, Complete
- Server restore row `26`:
  `00434b40-ffc2-4f85-baa9-6bfbb77c4fe9`, Complete
- Row `26` marker:
  `backupsheep-upcloud-server-26-c8d13216324ea7ca399d0f80`
- Row `26` cloned boot storage:
  `010656e3-1b94-444b-a600-393b2750cbbf`
- Managed Object Storage service:
  `12a6acc5-091e-4bbe-ac96-ace1be725864`
- Bucket:
  `bs-bs-e2e-upcloud-20260812-74c9f2a1-objects-c25b6ce19f`

Row `26` already passed real post-provider-accept/pre-pointer SIGKILL adoption
and exact control-plane/power/network reconciliation. It still needs explicit
guest boot, pinned SSH or agent access, restored-data validation, and guest
awareness/reachability of the restored public interface. Row `25` needs current
strict generation export and read-only restored-volume byte verification.

### Oracle Cloud

- Run ID: `bs-e2e-oracle-20260812-a7c42f91`
- Dedicated test compartment:
  `ocid1.compartment.oc1..aaaaaaaa4d75gbzsnzwwnqjjq7m346w2ju6rqoqvy5d5mp7fov3lqm2xuc6a`
- Native backups: compute `4`, boot volume `5`, block volume `6`
- Compute restore row `19`:
  `ocid1.instance.oc1.iad.anuwcljrt7i4d2acgqtfdfarokcj2vmm4mu7tjwxbdzyd7qp3dblrwgt7e5a`, Complete
- Block-volume restore row `21`:
  `ocid1.volume.oc1.iad.abuwcljrh2wlhranf3nnqdayc7x7v6o6zv3fsrdy2hj54uu4i3qdvpowmlta`, Complete
- Boot-volume restore row `23`:
  `ocid1.bootvolume.oc1.iad.abuwcljrwnwf4sdk3lx7kritcixsv2tynbg3dxfj2xxknvtvjiv6sl4gpapa`, Complete
- Restore row `23` passed a real post-accept/pre-pointer SIGKILL adoption test.
- Restore row `20` remains historical manual review and has a known exact-owned
  orphan candidate recorded in prior evidence. Do not infer or delete it from
  row `20` alone; use the new orphan report/reconciliation path and fresh
  compartment/tag/source reads.
- Old failed native backup rows `1` through `3` may still have provider
  resources. Include them in the same strict orphan inventory before cleanup.

The protected runtime scope was normalized on 2026-08-15. Remaining gates are
to repair/verify storage scope evidence, build current immutable generations,
run read-only reports, run explicitly gated mutating guest/data verification,
reconcile exact orphans, and clean the owned graph in dependency order. Oracle
network cleanup remains a separate exact-owned phase after UI resource cleanup.

## Retained runtime and credential integrity

All files below existed at the pause. Secret-bearing runtime and private-key
files were mode `0600`; run directories were mode `0700`. Values must never be
printed. The hashes are retention/integrity evidence, not authorization to
rotate or delete anything.

| File | SHA-256 |
| --- | --- |
| `_docs/digitalocean.txt` | `891cfd4a888b480738b70b7aa0ef8e17e64d0eda0e110f7c1b9330c79dc2f7d0` |
| `_docs/upcloud.txt` | `9a9962fb5bd3563f5cae497771261de8e0272f3949ff6ed74b7402094f46cf9d` |
| `_docs/oracle.txt` | `fd6f0af86b1ba17f5a0408e842c82e787455222ebe18b9d0caaa22a3f6938bbc` |
| DigitalOcean `spaces.json` | `eac49b45415b88aadd4a62259abd11a436e6f24393fdef5cb9f7367d847ed7fd` |
| UpCloud `runtime.json` | `12fbd1ff97468cdf9f3c57551a9a9650590297846832fd9f9e47bf3ab88effac` |
| UpCloud compute runtime | `754338924befff9c7a53e56e14ffa2a81b73465e07dee4fee8aa31cd4b48bd46` |
| UpCloud SSH private key | `f318b9155086b86489c00447654cdd8e5cd994b8641ebcdcec7effd7af251bc6` |
| Oracle `object-storage.json` | `cff7b2872bde0a3d636707ae76a13a829763c2ca24c102a6ace64d92ceb2831f` |
| Oracle `runtime-scope-20260815.json` | `42a35c867215b940c4c269a94b024fdf81ff4a1c5cd115b67c11c477300eddc5` |
| Oracle SSH private key | `58ccc94f9ba77b58d6b77ab4ed111138b5a8b20303bd06298efb1579292e9bf5` |

Run directories:

- DigitalOcean:
  `/Users/bilal/.backupsheep-e2e/digitalocean/bs-e2e-do-20260812-c91a7e52/`
- UpCloud:
  `/Users/bilal/.backupsheep-e2e/upcloud/bs-e2e-upcloud-20260812-74c9f2a1/`
- Oracle:
  `/Users/bilal/.backupsheep-e2e/oracle/bs-e2e-oracle-20260812-a7c42f91/`

The Oracle UI cleanup receipt, when one is eventually created, belongs at:

`/Users/bilal/.backupsheep-e2e/oracle/bs-e2e-oracle-20260812-a7c42f91/ui-cleanup-receipt-20260815.json`

Do not fabricate that receipt before cleanup actually succeeds.

## Ordered resume procedure

### 1. Re-establish the safe baseline

1. Verify local and remote branch provenance.
2. Verify demo Git provenance, override checksum, running image commit, health,
   migrations, workers, and queues.
3. Query max restore IDs and prove there are no pending/in-progress rows.
4. Hash every retained credential/runtime file above and compare it byte for
   byte. A mismatch is a stop condition for the affected provider until the new
   credential scope is deliberately established without printing values.
5. Perform fresh complete, cursor-aware provider inventories and exact source,
   backup, target, bucket/service, marker/tag, region/zone/compartment, and
   relationship reads. Do this before any provider write.

### 2. Complete the six signed-in workload restores

Use the web UI, not direct API calls. Work one provider pair at a time in this
order: DigitalOcean, UpCloud, then Oracle. This ordering is operational, not an
ownership shortcut.

For each provider:

1. On node `28`, restore PostgreSQL backup `12` from that provider's exact
   storage destination. Confirm the UI says **Safe fork** and creates a new
   database; never restore over or drop the source database.
2. Record the new database restore row ID from a durable database query. Wait
   until it is Complete and refresh the signed-in UI until the same status is
   visible.
3. On node `27`, restore website backup `12` from the same provider. This is an
   in-place restore of the owned test fixture only.
4. Record the new website restore row ID. Wait until Complete and refresh the
   UI until the same status is visible.
5. Immediately export and verify that provider's immutable workload generation
   before the next provider's website restore overwrites the fixture target.
6. Capture failure evidence honestly. A UI success toast proves durable queueing,
   not restore completion or data correctness.

Exact UI labels and exporter mapping:

| Provider | UI storage label | Storage ID | Provider code |
| --- | --- | ---: | --- |
| DigitalOcean | `DO Spaces E2E 2026-08-12 c91a7e52` | `5` | `do_spaces` |
| UpCloud | `UpCloud MOS E2E 2026-08-12 74c9f2a1` | `6` | `upcloud` |
| Oracle | `Oracle Object E2E 2026-08-12 a7c42f91` | `7` | `oracle` |

Do not select the existing AWS S3 or Vultr destinations.

### 3. Export one immutable generation after each pair

The workload fixture and restore path are owned by the shared UpCloud fixture,
so `--run-id` is
`bs-e2e-upcloud-20260812-74c9f2a1` for all three provider-code exports. The
provider code, storage row, object keys, version IDs, row bindings, and artifact
bindings identify the actual storage provider.

Run this inside the demo app container after substituting the exact provider
mapping and newly created restore row IDs:

```sh
python scripts/workload_manifest_export.py \
  --account-id 1 \
  --run-id bs-e2e-upcloud-20260812-74c9f2a1 \
  --storage-id PROVIDER_STORAGE_ID \
  --provider-code PROVIDER_CODE \
  --website-backup-id 12 \
  --website-restore-id NEW_WEBSITE_RESTORE_ID \
  --database-backup-id 12 \
  --database-restore-id NEW_DATABASE_RESTORE_ID \
  --output-dir /var/backups/backupsheep/e2e-manifests/UNIQUE_PROVIDER_GENERATION
```

Requirements:

- output must be a new absolute path outside the Git worktree;
- never reuse or overwrite a generation directory;
- keep directory mode `0700` and generation files mode `0600`;
- copy the complete directory, including its ownership marker, to the local
  protected run area;
- pass the generation directory to `verify-workloads`; a loose manifest file
  is intentionally rejected;
- use the UpCloud fixture's protected compute runtime and pinned SSH key without
  printing either;
- retain the exporter receipt and verifier result for the final handoff.

Expected application-level data:

- website restore root:
  `/srv/backupsheep-e2e/bs-e2e-upcloud-20260812-74c9f2a1/`;
- PostgreSQL: 120 customer rows, 480 event rows, 600 total;
- canonical data SHA-256:
  `f8621cd4a65a00c394f8ead3e427e16859248450bc7cc23ebf529764c5934cb7`;
- schema SHA-256:
  `4768a03a122f1e6f2fe7b2dd8a609174e0c9ccaa5391012d8472c4484b76df87`.

### 4. Finish UpCloud native proof

1. Generate a current strict UpCloud compute/native generation from durable
   rows plus fresh exact provider reads.
2. Run `verify-compute` on the complete generation.
3. Prove row `26` guest boot, pinned SSH/agent access, restored data, and guest
   awareness and reachability of its restored public interface.
4. Prove row `25` restored-volume bytes using read-only attachment/mount
   semantics.
5. Run current object-storage verification for the row-12 objects and bucket
   versioning. The version IDs above must match provider readback.
6. Capture complete before/after inventories. Do not clean up yet if Oracle or
   DigitalOcean verification still depends on the shared fixture.

### 5. Finish DigitalOcean native proof

1. Run the hardened legacy-ledger normalization report and strict read-only
   ownership report first.
2. Re-prove the active token is in the exact Personal team UUID.
3. Use the native-volume verifier's `prepare-source` action to attach the exact
   source volume only to the exact owned verifier Droplet, seed deterministic
   bytes durably, and detach safely.
4. Create a fresh volume snapshot backup through the signed-in UI on node `23`.
5. Create a fresh safe-fork volume restore through the signed-in UI. Record the
   actual backup and restore IDs; do not reuse historical row `24` as proof of
   the newly seeded bytes.
6. Run `verify-restored` and prove exact region, size, unattached precondition,
   ownership tags, read-only attach/mount, byte count, and SHA-256.
7. Re-verify Droplet restore row `17` at guest/data level using the exact owned
   firewall and pinned host identity.
8. Verify Spaces bucket creation/versioning and both row-12 objects from fresh
   provider reads.

Every constructor option that can mutate provider state, including attaching a
firewall, requires explicit apply and team-UUID gates. Run report mode before
each apply action.

### 6. Finish Oracle native proof and orphan reconciliation

1. Use `runtime-scope-20260815.json`; do not modify or print the original OCI
   CLI configuration or secret files.
2. Repair and freshly prove the exact Object Storage `storage_scope` evidence.
3. Export current secret-free immutable generations for native and workload
   rows.
4. Run the strict read-only report first.
5. Run mutating verification only with its explicit apply gate. It may tag,
   attach read-only, launch an exact verifier instance/VNIC, SSH, and mount;
   describe it as mutating.
6. Prove compute, boot-volume, block-volume, website, and PostgreSQL restored
   bytes/data from current provider and guest reads.
7. Run the orphan report. Resolve row `20` and provider resources associated
   with old failed backup rows `1` through `3` only after exact compartment,
   OCID, tag, name, source, and request-token relationships pass.
8. Create the UI cleanup receipt only after those exact UI-owned resources are
   successfully removed and absence is freshly verified.
9. Clean the owned network graph separately and in dependency order.

### 7. Exact-owned cleanup and final acceptance

Cleanup is the last provider phase, not an implicit side effect of verification.
For each provider:

1. capture a complete before inventory;
2. resolve every deletion target to one immutable ID and full ownership
   contract;
3. persist a durable deletion intent before the provider request;
4. reconcile lost responses through fresh exact readback;
5. verify absence without replaying a delete blindly;
6. capture a complete after inventory and list retained resources;
7. re-run demo durable-row and queue audits;
8. re-hash credential/runtime files and prove they remain unchanged.

Do not delete or invalidate tokens, keys, runtime files, SSH identities, or
integration credentials during cleanup.

## Completion definition

A provider may be marked fully E2E tested only when one final receipt contains:

- signed-in UI backup initiation and visible completion;
- signed-in UI restore initiation and visible completion;
- durable row IDs and status history;
- provider ownership and lifecycle readback;
- checksum, byte count, ETag, and non-empty version ID for object storage;
- downloaded/restored byte validation, not metadata alone;
- application-level website and database validation;
- native guest/volume data proof where applicable;
- controlled crash/lost-response adoption proof for the provider path under
  test, with one durable row and one provider target;
- exact-owned cleanup and verified absence, or an explicit retained-resource
  list approved for a later task;
- unchanged credential hashes;
- final demo SHA, health, migration, worker, and queue audit.

Until every applicable item exists, use a qualified status such as
`backup/upload proven`, `control-plane restore proven`, or
`guest/data verification pending`.

## Secret-safe resume checks

Local repository:

```sh
cd /Users/bilal/Projects/BackupSheep/backupsheep
git status --short --branch
git fetch origin develop
git rev-list --left-right --count develop...origin/develop
git log -1 --oneline
git diff --check
```

Demo provenance:

```sh
ssh -o BatchMode=yes root@64.177.125.68 \
  'cd /opt/backupsheep && git rev-parse HEAD && git rev-parse origin/develop && git status --short --branch && sha256sum docker-compose.override.yml'
```

Public health:

```sh
curl -fsS --max-time 20 -o /dev/null \
  -w '%{http_code} %{url_effective}\n' \
  https://demo.backupsheep.com/healthz/
```

Before any provider write, repeat the complete inventory, exact account/team or
tenancy read, marker uniqueness check, exact source/backup/target read,
ownership validation, durable-row read, and unresolved-intent check. Live
provider state—not this document—decides whether a mutation is safe.

## Pause receipt

At handoff creation:

- no new website or database restore had been submitted for backup row `12`;
- no website, database, or native-cloud restore was pending or in progress;
- the six primary queues were drained;
- the public health endpoint returned `200`;
- the demo checkout and executable image remained on the reviewed hardening
  commit;
- all listed credentials and runtime secrets remained present and byte-identical;
- no token/key was revoked, rotated, deleted, or replaced;
- no provider cleanup was attempted after the user requested the pause.

Resume from **Ordered resume procedure**, not from an earlier handoff.
