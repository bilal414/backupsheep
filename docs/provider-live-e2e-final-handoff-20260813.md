# BackupSheep provider live E2E final handoff — 2026-08-13 UTC

This is the authoritative continuation document for the UpCloud, Oracle Cloud,
and DigitalOcean acceptance work plus the final independent-review hardening
and automated validation completed on 2026-08-13. It supersedes the status and
resume instructions in
`provider-live-e2e-wrap-up-20260812.md`,
`provider-live-e2e-resume-handoff-20260812.md`, and
`upcloud-enterprise-reliability-20260812.md` wherever they disagree.

This file intentionally contains no provider tokens, object-storage secrets,
database passwords, private keys, browser cookies, decrypted integration
credentials, or public IP address assigned to a restored customer workload.

## Non-negotiable safety rules

1. Work on `develop`. Verify local, `origin/develop`, and the demo checkout
   before changing or deploying anything.
2. Never modify or delete AWS Lightsail resources.
3. DigitalOcean work is restricted to Personal team UUID
   `0ba41777-3fbc-4093-9193-0f2709d2948a`.
4. Provider resources may be changed or deleted only after fresh reads prove the
   exact account/team/tenancy, immutable resource ID, generated run name,
   marker/labels, region/zone/compartment, source relationship, and creation
   witness.
5. A local ledger entry is not deletion authority. Missing fingerprints,
   partial inventory, zero or duplicate marker matches, changed relationships,
   or any provider read failure must stop mutation.
6. Preserve `/opt/backupsheep/docker-compose.override.yml`. Its expected
   SHA-256 is
   `90c8c98923b97e32a077f27ddefe5e8e7236a9249d91a24e8e9c4b32f94a1462`.
7. Never print `_docs`, runtime secret files, environment variables, decrypted
   integration values, OCI private-key material, or provider response bodies.
8. The live run resources are test resources, but cleanup remains exact-ID and
   ownership-gated. Do not use broad name prefixes or account-wide deletion.

## Repository and deployment checkpoint

- Local checkout: `/Users/bilal/Projects/BackupSheep/backupsheep`
- Branch and remote: `develop`, `origin/develop`
- Demo host and checkout: `64.177.125.68`, `/opt/backupsheep`
- Demo URL: `https://demo.backupsheep.com`
- UpCloud empty-firewall fix: `b7d44b9151bf3bec2db9a296a6af2c6463f89abf`
- UpCloud power-safe network restore: `5a5542e` (`Make UpCloud network restores crash-safe`)
- Final review hardening:
  `7e93c22f5dfbf5a3c7540bf3d7a924f267de9dd7`
- The final authoritative SHA is the commit containing this document. Resolve
  it instead of copying a stale abbreviated hash:

  ```sh
  git log -1 --format=%H -- docs/provider-live-e2e-final-handoff-20260813.md
  ```

At the live acceptance checkpoint, `5a5542e` was pushed to `origin/develop`,
fast-forwarded on the demo, rebuilt, and migrated. The post-review code-bearing
commit `7e93c22` was subsequently pushed, rebuilt, migrated, and audited on the
demo. The exact receipt is below.

### Preserved demo database snapshots

All listed files are on the demo host under `/var/backups/backupsheep`, owned by
root, and mode `0600`.

| Purpose | Snapshot | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Before controlled row-26 SIGKILL | `pre-upcloud-row26-sigkill-20260813T025815Z.sql.gz` | 244227 | `a290d85031de7ccf4535594c9ed5396d84487e2d57e2e4caa18a55aa5ca2fc01` |
| Before deploying empty-firewall fix | `predeploy-b7d44b9-20260813T030507Z.sql.gz` | 245340 | `3fda060bce74b803c9db960a245e4fc00cd992ef67b05474dd82f3c53b19f404` |
| Before power-sequence implementation/deploy | `pre-upcloud-power-sequence-20260813T031044Z.sql.gz` | 249502 | `d76a19b08148252314dd76abf3e7f5a6c5c647d75284bc462fb183f8fba86722` |
| Before final post-review deploy | `predeploy-7e93c22-20260813T041532Z.sql.gz` | 254908 | `6d9c6655ac6cfff3c145e98fb87d50acae057894c1fa8b74893135a1ef645697` |

Earlier snapshots remain documented in
`provider-live-e2e-wrap-up-20260812.md`.

### Final post-review demo deployment receipt

Verified at `2026-08-13T04:16:40Z` after rebuilding and restarting from
`7e93c22f5dfbf5a3c7540bf3d7a924f267de9dd7`:

- demo `HEAD` and `origin/develop` were exactly the code-bearing SHA above;
- the only expected checkout-local paths remained untracked `_docs/` and
  `docker-compose.override.yml`;
- the override SHA-256 remained
  `90c8c98923b97e32a077f27ddefe5e8e7236a9249d91a24e8e9c4b32f94a1462`;
- migration container exit code was `0`, `migrate --check --plan` reported no
  planned operations, and `manage.py check` reported no issues;
- app, beat, PostgreSQL, RabbitMQ, and the cloud, database, files, logs, and
  storage workers were running; app, PostgreSQL, and RabbitMQ were healthy;
- `cloud`, `database`, `default`, `files`, `logs`, and `storage` queues all had
  zero ready and zero unacknowledged messages with one consumer each;
- native cloud, website, logical database, and Vultr managed-database restores
  all had zero pending/in-progress rows;
- row `26` remained `Complete` with operation/execution phase `complete`, exact
  provider pointer `00434b40-ffc2-4f85-baa9-6bfbb77c4fe9`, empty last error,
  unknown outcome `false`, and manual resume count `3`;
- node `29` still had exactly restore row `[26]`, and global native cloud
  restore max ID remained `26`;
- `https://demo.backupsheep.com/healthz/` returned HTTP `200`.

The documentation-only receipt commit that contains this section must be
fast-forwarded on the demo after publication. It does not require another app
image rebuild because it changes no executable or deployment input.

## What changed in the final continuation

### Empty UpCloud firewall preflight

Fresh live readback showed that a newly created UpCloud server can return HTTP
200 with an enabled but empty firewall chain before BackupSheep installs the
source witness. The adapter previously classified that exact pre-install state
as a malformed provider response.

`b7d44b9` made firewall normalization strict by default while allowing an empty
chain only for the restored-server preflight. Source backup capture remains
strict. The exact source firewall is still required before the target can be
adopted.

### Crash-safe stop, address assignment, and restart

The provider then returned a definitive conflict when BackupSheep attempted to
assign public IPv4 to a running server. Current UpCloud documentation requires
the target to be powered down before changing its public network attachment.

`5a5542e` added a durable state machine:

1. Persist the restored target's observed pre-network power state; this is not
   the source/original server's power state.
2. Persist an exact stop request witness and request fingerprint before POST.
3. Reconcile `started`/`maintenance`/`stopped` from the exact owned server;
   never replay a stop while its witness is unresolved. Each read and every
   subsequent provider write revalidates the complete ownership contract.
4. Assign each witnessed public IP family only while the server is stopped.
5. Persist each address-assignment witness before POST and reconcile lost
   responses from exact network readback. The witness binds the exact server
   UUID, ordinal, address family, and request fingerprint.
6. If the restored target's observed pre-network state was `started`, persist a
   start witness, start once, and reconcile until `started`. The stop is
   ACPI-only with no provider hard-stop timeout; the durable deadline bounds
   reconciliation, and hard-stop escalation is not automatic.
7. Retain the unknown-outcome fence while any accepted mutation has an
   unresolved witness, active mutation, or failed/malformed post-2xx readback.
   Clear a mutation's witness/fence only after a fresh exact owned readback
   proves that specific mutation and no unresolved witness remains. Provider
   errors, authentication failures, rate limits, timeouts, conflicts, and
   malformed readbacks are not proof. Adopt only after firewall, network, boot
   storage, labels, source, marker, zone, and configuration all match.

The firewall readback path was also changed so an already-correct firewall does
not overwrite an unresolved stop/IP/start witness on a later Celery delivery.

### New deterministic coverage

The UpCloud fixture now models real provider power state. New tests cover:

- lost stop response;
- worker crash immediately after stop acceptance;
- asynchronous stop transition without a duplicate stop;
- address assignment only while stopped;
- lost address-assignment response and post-accept worker crash;
- lost start response;
- worker crash immediately after start acceptance;
- asynchronous start transition without a duplicate start;
- exact request payloads and fingerprints for stop/start;
- a marker-adopted server with no persisted candidate pointer at every power
  boundary;
- exact server-bound public-IP witness validation for pointerless manual
  reconciliation;
- post-2xx exact-read authentication, request, and malformed-response failures;
- stale-worker lease rotation before and after provider acceptance;
- ownership drift in UUID, labels, source, boot storage, zone, and config;
- rate limit, conflict, transient outage, error-state, and bounded-deadline
  behavior;
- one boot clone, one restored server, one address assignment, and bounded
  reconciliation throughout.

## UpCloud row 26 live acceptance receipt

This receipt is provider control-plane acceptance only. It proves the exact
provider target, ownership, boot storage, firewall, power state, public-network
attachment, durable pointer, and same-row crash adoption contract. It does not
prove guest boot, SSH or agent access, restored-data validation, or the guest
operating system's awareness and reachability of the newly attached interface.
Those remain explicit recovery gates below.

### Immutable scope

- Run ID: `bs-e2e-upcloud-20260812-74c9f2a1`
- UI connection `19`; cloud-server node `29`; backup row `4`; restore row `26`
- Source server: `00e6027e-d4e5-4779-bc3f-18080a4ee0d3`
- Source backup: `01e3e859-77b4-4502-96f2-87ced534783a`
- Accepted restored server: `00434b40-ffc2-4f85-baa9-6bfbb77c4fe9`
- Cloned boot storage: `010656e3-1b94-444b-a600-393b2750cbbf`
- Server marker:
  `backupsheep-upcloud-server-26-c8d13216324ea7ca399d0f80`
- Storage marker:
  `backupsheep-upcloud-storage-26-c8d13216324ea7ca399d0f80`

### Controlled crash and recovery

The exact row passed a real SIGKILL acceptance test before this final fix:

1. Normal `worker-cloud` was scaled to zero.
2. The signed-in UI reused restore row `26`; no new restore row was inserted.
3. A one-off worker was armed only for row `26` and the exact server marker at
   the post-provider-accept/pre-pointer-persist boundary.
4. UpCloud exposed exactly one matching server while BackupSheep still had no
   provider pointer.
5. The named one-off container was sent SIGKILL and exited `137`.
6. The row remained queryable in progress with its durable acceptance witness.
7. The normal worker later adopted the one exact server rather than issuing a
   second create.

The acceptance witness contains only a marker SHA-256, stage, timestamp, and
consumed flag; it does not persist credentials.

### Final live power/network sequence

After deploying `5a5542e`:

This is live provider evidence from the `5a5542e` control-plane run. It is
retained as the crash-adoption and restore receipt. The stricter post-review
fencing was validated offline against deterministic provider failure and
worker-crash boundaries; it was not used to create another live UpCloud target.

- Preflight found a complete server inventory of two account servers (the
  exact source plus the restored target), one page, and exactly one row-26
  marker match.
- The restored target and cloned boot storage both passed fresh ownership
  checks before the cloud worker was started.
- At `2026-08-13T03:20:19Z`, row `26` durably entered
  `server_stop_requested`; UpCloud readback progressed from `maintenance` to
  `stopped` while the same stop witness remained active.
- The next scheduled poll cleared the proven stop witness, attached the exact
  witnessed public IPv4 family while stopped, and durably entered
  `server_start_requested`.
- Provider readback showed public family `IPv4` and state `started` with the
  start witness still durable.
- At `2026-08-13T03:24:39Z`, the next poll cleared the start witness, adopted
  server `00434b40-ffc2-4f85-baa9-6bfbb77c4fe9`, and completed row `26`.

Final durable and provider evidence:

| Check | Result |
| --- | --- |
| Restore row/status | `26`, `Complete` |
| Operation/execution phase | `complete` / `complete` |
| Provider pointer | exact restored server ID above |
| Last error / unknown outcome | empty / `false` |
| Manual resume count | `3` on the same row |
| Node 29 restore rows | exactly `[26]` |
| Global max native restore ID | still `26`; no replacement row was created |
| Provider server inventory | complete, 2 items, exactly 1 marker match |
| Server ownership | passed |
| Server state | `started` |
| Public network witness | exactly `IPv4` |
| Boot device | exact cloned storage ID above |
| Firewall | exact 7-rule source witness |
| Firewall fingerprint | `a52f94f9f7563b1e012fb8a74c163cea6d19b6f1db9ec7d9e078129d2f2d0293` |
| Boot storage ownership | passed; online, normal, `us-chi1`, 10 GB, standard, encrypted `yes` |
| Guest-level recovery | not exercised by this receipt; explicit gate for guest boot, SSH/agent, data, and interface awareness/reachability |

The signed-in `demo.backupsheep.com` UI showed the same restore target as
`Complete`, provider state `started`, and the exact provider resource ID. The
modal offered `Restore another copy` only after completion. This UI state is
also provider control-plane evidence, not guest-level recovery proof.

## Automated test receipt

Final post-review receipt from the rebuilt local Docker image:

- 70/70 combined UpCloud server reliability, cloud manual-resume, and native
  cloud restore UI tests passed in `15.091s`.
- 1,583/1,583 tests in the complete Docker `apps.tests` suite passed in
  `201.121s` with exit code `0` and `OK`.
- Python compilation of all three changed Python modules passed.
- `git diff --check` passed.

The full-suite output included intentional negative-path logging for duplicate
suppression, lost broker acknowledgements, notification failures, and refused
provider cleanup without explicit apply gates. Those lines are test evidence,
not live provider failures.

## Independent review status

GPT-5.6 Sol Max reviewed the power-state restore implementation and found
blockers around unresolved post-accept readbacks and unknown-outcome fencing,
full ownership revalidation before later mutations, and safe soft-stop
semantics. GPT-5.6 Luna Max implemented the accepted corrections, including
conservative fence preservation, ownership checks, ACPI-only stop requests,
bounded transition deadlines, and stale-worker tests. The integration pass then
closed the marker-adoption edge case by binding stop/IP/start witnesses to an
exact provider UUID even when a crash prevented `candidate_server_id` from
being persisted. The final focused and complete suites above passed afterward.

This closes the independent code-review and automated-test gate. It does not
turn the row-26 control-plane receipt into guest-level recovery proof or satisfy
the remaining provider artifact, cleanup, and credential-rotation gates.

## UpCloud run artifacts and remaining verification

- Runtime directory:
  `/Users/bilal/.backupsheep-e2e/upcloud/bs-e2e-upcloud-20260812-74c9f2a1/`
- Ledger: `ledger.json`, mode `0600`, 19 resources, no pending mutation intents
- Protected object runtime: `runtime.json`; it contains credentials and must not
  be printed
- Protected compute runtime: the run-specific `upcloud-compute.json`; it
  contains a database password and must not be printed
- Current account proven by fresh reads: `bilal414`

Completed live UI workloads:

- website backup `11`, website restore `9`;
- PostgreSQL backup `10`, database restore `16`;
- cloud-server backup `4`, cloud-server restore `26`;
- volume restore `25`.

Exact workload verification expectations:

- Website restore path:
  `/srv/backupsheep-e2e/bs-e2e-upcloud-20260812-74c9f2a1/restores/9`
- PostgreSQL target:
  `bs_restore_45c7b8c781e6_bs_e2e_50d32a3bb404_b51c2326c3b4`
- Expected PostgreSQL data: 120 customer rows, 480 event rows, 600 total
- Canonical data SHA-256:
  `f8621cd4a65a00c394f8ead3e427e16859248450bc7cc23ebf529764c5934cb7`
- Schema SHA-256:
  `4768a03a122f1e6f2fe7b2dd8a609174e0c9ccaa5391012d8472c4484b76df87`

Object evidence needed to build the current verifier manifest:

| Kind | Backup | Key suffix | Bytes | SHA-256 | ETag | Version ID |
| --- | ---: | --- | ---: | --- | --- | --- |
| Website | `11` | `bs-upcloud-website-fixture-n27-b11.zip` | 69165 | `b314a0a5904870745888360bab2b2c65a9fb4519e7dcb02b2dfb231983ce1e19` | `3ee4294c9255347ad26dcebc26631774` | `1786575272066` |
| PostgreSQL | `10` | `bs-upcloud-postgresql-fixtu-n28-b10.zip` | 5129 | `b2a91db4540e66cca7db61d28723eb9ca0b9a05a28f6efc0fe31d72ae0aaa8bd` | `2ea8fb94f064c943c0c0689f81e2fb96` | `1786575287925` |

The common key prefix is
`backupsheep-e2e/bs-e2e-upcloud-20260812-74c9f2a1/`.

Remaining UpCloud artifact work:

1. Build secret-free current-schema compute, workload, and object verification
   manifests from durable rows plus fresh provider reads.
2. The object verifier requires an active `mos_bucket_configuration` ledger
   witness. The current ledger does not contain that kind even though bucket
   versioning and the exact objects were read successfully. Recover this from a
   fresh exact service/bucket read; do not invent it from prose.
3. Run `verify-compute`, `verify-workloads`, and object verification with the
   normalized manifests.
4. Perform fresh before/after provider inventories, then clean up only exact
   resources whose current creation fingerprints and relationships pass.
5. Rotate the exposed UpCloud API token and remove or re-key the exact fixture
   server after the final required call.

The row-26 provider receipt above does not include guest-level recovery proof.
Before treating the restored server as operationally recoverable, explicitly
verify guest boot, SSH or agent access, restored data, and operating-system
awareness and reachability of the newly attached public interface.

## DigitalOcean checkpoint and remaining work

- Run ID: `bs-e2e-do-20260812-c91a7e52`
- Runtime directory:
  `/Users/bilal/.backupsheep-e2e/digitalocean/bs-e2e-do-20260812-c91a7e52/`
- Ledger: schema 1, 12 eligible resources, no pending mutation intents
- Spaces secret file exists at mode `0600`; never print it
- UI connection `15`; Droplet node `22`; volume node `23`; Spaces storage `5`
- Droplet restore `17`, volume restore `24`, website restore `6`, and database
  restore `13` completed live through the demo UI

The current `ui-storage-manifest.json` has internally consistent object rows but
is rejected by the hardened verifier because it lacks the current envelope and
per-object backup binding. Normalize it to include:

- top-level `schema: 1`, exact `run_id`, and exact `prefix`;
- per-object positive `backup_id`;
- exact website/database kind, key, non-null version ID, SHA-256, ETag, byte
  count, and metadata;
- metadata keys exactly `backupsheep-backup-id`, `backupsheep-bytes`, and
  `backupsheep-sha256`.

Do not use the stale `backupsheep-size` documentation field.

Current DigitalOcean harness gaps found by independent audit:

1. There is no legacy-ledger migration/normalization command.
2. There is no strict read-only report mode; verification writes local ledger
   evidence.
3. `--verify-ui-droplet-restore` can attach a firewall but is not currently
   included in constructor mutation/apply/team-UUID gating. Fix this before any
   such run.
4. Volume restore ownership verification does not yet require expected region,
   size, and unattached state.
5. Spaces object verification does not freshly read bucket versioning and
   creation state.
6. The old ledger lacks current creation fingerprints and exact restore-target
   entries. Fresh provider reads are required before cleanup can be authorized.

Do not clean up from the current DigitalOcean ledger alone. Rotate the exposed
PAT after the final Personal-team call.

## Oracle Cloud checkpoint and remaining work

- Run ID: `bs-e2e-oracle-20260812-a7c42f91`
- UI connection `16`; compute node `24`; boot-volume node `25`; block-volume
  node `26`; Object Storage destination `7`
- Native backup rows `4`, `5`, `6`; completed restore rows `19`, `21`, `23`
- Website restore `8` and database restore `15` completed from Object Storage
- Restore `23` passed a real post-accept/pre-pointer SIGKILL adoption test
- Source ledger has 24 rows: 22 active and 2 deleted; evidence and network
  sidecars exist; no current `ui-manifest.json` exists

Current Oracle harness/credential gaps found by independent audit:

1. The currently located credential artifact lacks the tenancy/compartment
   fields required by the hardened verifier. Re-read the configured OCI CLI and
   `_docs/oracle.txt` without printing secrets, then create the canonical
   protected runtime artifact.
2. Build a secret-free `ui-manifest.json` binding the exact run, compartment,
   source IDs, backups, restore IDs/names/markers/request tokens, and both
   object key/version/ETag/SHA-256/byte-count records.
3. The existing `--phase verify` is mutating: it can tag the boot volume,
   attach the restored block volume read-only, launch a boot-verifier instance
   and VNIC, and SSH/mount the target. It requires the explicit apply gate and
   must not be described as read-only.
4. Required `storage_scope` evidence is absent. A current verify run may mutate
   and then fail until this artifact is repaired.
5. There is no automatic manifest builder or read-only verify phase, and the
   harness does not yet verify Oracle website/database restores at the
   application layer.
6. Cleanup requires fresh OCID, compartment, tag, name, and relationship reads.
   Network graph cleanup is a separate exact-owned phase after UI cleanup.

## Credential incident

During the live sessions, terminal/tool output exposed the DigitalOcean PAT,
UpCloud API token, and UpCloud fixture root SSH private key. Their values are
not repeated here. After final verification calls:

1. revoke or rotate both exposed API credentials;
2. destroy the exact-owned UpCloud fixture server or rotate its root SSH key;
3. review access to retained terminal/transcript output.

OCI private-key contents and object-storage secrets were not printed in the
recorded acceptance work.

## Remaining acceptance gates, in order

The application has strong live evidence, and the accepted review fixes passed
the final automated suites. Enterprise-wide acceptance is not yet claimed.
Resume in this order:

1. Complete the row-26 guest-level recovery gates: guest boot, SSH/agent,
   restored-data validation, and operating-system awareness and reachability of
   the newly attached interface.
2. Normalize and run UpCloud compute/workload/object verification artifacts.
3. Fix the DigitalOcean mutation gate and ownership gaps, normalize artifacts,
   and run fresh Personal-team verification.
4. Repair Oracle protected scope/manifest artifacts, then run the explicitly
   mutating exact-owned verification.
5. Perform fresh before/after inventories and exact-owned cleanup for each run.
   Stop wherever current ownership proof is missing.
6. Rotate exposed credentials.
7. Repeat the final demo/runtime audit after any future code or provider
   mutation: exact SHA, zero pending migrations, healthy containers, intended
   queues drained, and public HTTPS health.

## Secret-safe resume commands

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
  'cd /opt/backupsheep && git rev-parse HEAD && git status --short --branch && sha256sum docker-compose.override.yml'
```

Public health:

```sh
curl -fsS --max-time 20 -o /dev/null \
  -w '%{http_code} %{url_effective}\n' \
  https://demo.backupsheep.com/healthz/
```

Before any provider mutation, repeat the account/team/tenancy check, complete
bounded inventory, marker count, exact source and target reads, ownership
validation, and durable-row read. Do not continue from this document alone when
the live provider state can be checked.
