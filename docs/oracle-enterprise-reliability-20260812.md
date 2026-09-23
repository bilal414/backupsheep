# Oracle Cloud enterprise reliability handoff

Date: 2026-08-12
Branch initially inspected: `develop` at `05f2ebeb9c2e`
Live validation checkpoint: `28ee48d5483f501de6b3838eb0f3b230df1a0c45`

## Safety statement

The first provider-specific implementation pass described by this document was
offline. A later controlled live pass used the configured OCI profile and a
dedicated test compartment, created only run-tagged resources, and exercised the
wired Oracle integration through `demo.backupsheep.com`.

The live pass completed compute-image, boot-volume, and block-volume backups;
safe-fork restores for all three resource kinds; versioned Object Storage
website/PostgreSQL uploads and application restores; and a real SIGKILL after
OCI accepted a boot-volume restore but before BackupSheep persisted its OCID.
Recovery adopted exactly one provider target and completed the original durable
row. Exact rows, OCIDs, payload witnesses, deployment evidence, and remaining
cleanup/credential gates are recorded in
`docs/provider-live-e2e-resume-handoff-20260812.md`.

The original offline-only language and unwired checklist later in this file are
retained as implementation history, not current product status. Cleanup still
requires a fresh, exact ownership inventory and durable pre-mutation intents.

## Native resource scope

Implemented provider-specific engines cover:

- Compute instances: custom-image backup, exact image adoption/poll/delete, and
  launch-a-new-instance restore from the image.
- Block volumes: full volume backup, restore to a new block volume, poll, and
  ownership-checked delete.
- Boot volumes: full boot-volume backup, restore to a new boot volume, poll, and
  ownership-checked delete.
- Object Storage: a versioned S3-compatible **destination** for website/database
  archives. It is not represented as an OCI native snapshot source.

All native creates persist a deterministic OCI `opc-retry-token` and a durable
ownership witness before mutation. Reconciliation requires one exact match on
OCID, compartment, display name, immutable source OCID, BackupSheep marker,
resource kind, and retry-token tag. Zero matches after an unknown response stays
in bounded reconciliation; multiple or foreign same-name matches fail closed for
manual review.

The adapter categorizes authentication, explicit not-found, OCI's deliberately
ambiguous `NotAuthorizedOrNotFound`, quota, rate-limit, timeout, transient
outage, malformed response, and terminal provider failures separately. An
ambiguous Oracle 404 is never treated as proof that deletion completed.

## Initial offline hardening completed

- Bounded OCI SDK connect/read timeouts and `NoneRetryStrategy` at mutation
  boundaries. BackupSheep owns retry/reconciliation timing.
- Bounded `opc-next-page` cursor traversal with repeated-cursor, page-count, and
  item-count failure gates.
- Provider-authoritative compute/block/boot discovery across the root and every
  accessible active compartment.
- Immutable cloud/volume API linkage: the submitted OCID is rediscovered, exact
  provider metadata replaces client metadata, duplicate attachment is rejected,
  and creation is serialized on the connection row.
- Compute restore creates a tagged VNIC as part of the new-instance graph. Public
  IP assignment is explicit and defaults off.
- Oracle Object Storage endpoint construction is canonical, path-style SigV4,
  bounded, and rejects namespace/region/endpoint injection. The existing shared
  verified-S3 uploader persists SHA-256, byte count, ETag, and version ID.
- Connection and storage writes are atomic; Oracle storage input validates the
  namespace, canonical region endpoint, bucket, and prefix before SDK use.

## Safety-gated live UI support harness

`scripts/oracle_live_ui_e2e.py` is inert by default. `--phase plan` does not read
the OCI profile and makes no network request. It uses only the normal OCI
CLI/SDK config profile selected by `OCI_CLI_CONFIG_FILE` and `OCI_CLI_PROFILE`;
it accepts no provider credential value on the command line.

Provider mutations require both exact compartment confirmations:

```text
BACKUPSHEEP_E2E_RUN_ID=bs-oracle-e2e-<unique>
BACKUPSHEEP_E2E_LEDGER_PATH=/durable/path/oracle-ledger.json
OCI_CLI_CONFIG_FILE=~/.oci/config
OCI_CLI_PROFILE=<explicit-profile>
ORACLE_E2E_COMPARTMENT_OCID=<test-compartment-ocid>
ORACLE_E2E_ALLOWED_COMPARTMENT_OCID=<same-test-compartment-ocid>
ORACLE_E2E_AVAILABILITY_DOMAIN=<exact-ad-name>
ORACLE_E2E_SUBNET_OCID=<subnet-in-that-compartment>
ORACLE_E2E_IMAGE_OCID=<available-linux-image-ocid>
ORACLE_E2E_SHAPE=<available-shape>
ORACLE_E2E_SSH_USER=<image-default-user>
ORACLE_E2E_ALLOWED_TENANCY_OCID=<profile-tenancy-ocid>
ORACLE_E2E_SECRET_FILE=/outside/repository/oracle-storage.json
```

The tenancy confirmation is required only because IAM users/groups are tenancy
resources. The bucket, policy, compute, VNIC, and volumes remain in the explicit
test compartment. The supplied subnet and image are read and used but never
modified. `ORACLE_E2E_ASSIGN_PUBLIC_IP=YES` is optional and explicit; otherwise
the harness must be able to reach the exact provider-reported private VNIC IP.

Provisioning is a separate, explicit write:

```bash
python scripts/oracle_live_ui_e2e.py --phase plan
BACKUPSHEEP_E2E_APPLY=YES \
  python scripts/oracle_live_ui_e2e.py --phase provision
```

Provisioning creates and ledgers only uniquely named/tagged resources for the
run:

1. One block volume.
2. One compute instance, its tagged boot volume, tagged VNIC, and exact block
   attachment.
3. A run-scoped SSH key stored beside the ledger, never printed.
4. A private, version-enabled Object Storage bucket.
5. One test IAM user, group, membership, compartment policy, and customer-secret
   key. The policy can inspect buckets and manage objects only in the one run
   bucket.
6. A customer-secret runtime JSON file with mode `0600`. The harness refuses a
   path inside `_docs` and refuses a repository path unless Git ignores it.

The instance gets deterministic payload bytes in both its boot filesystem and
the attached block-volume ext4 filesystem. The harness records SHA-256 and byte
count only after both paths match and `sync` completes. It also performs a
versioned S3 preflight and records its SHA-256, byte count, ETag, and version ID.
No credential value appears in stdout, the ledger, report, test fixture, or docs.

## Exact live UI E2E procedure (executed; retained for regression)

### 1. Preflight and provision

1. Create/select a dedicated empty test compartment. Set both compartment
   variables to its exact OCID and separately set the exact profile tenancy OCID.
2. Use a subnet in that compartment. The harness verifies its OCID, compartment,
   and active state before launch.
3. Run `plan`; review deterministic names and confirm `live_calls: false`.
4. Set `BACKUPSHEEP_E2E_APPLY=YES` and run `provision` once.
5. Preserve the fsynced ledger, evidence sidecar, SSH material, and storage secret
   file. A missing one-time customer secret blocks reprovisioning instead of
   silently creating another credential.
6. Record the three exact `ui_attachment` OCIDs from stdout: compute instance,
   block volume, and boot volume.

### 2. Attach sources through the BackupSheep UI

1. In `demo.backupsheep.com`, add an Oracle connection using the same OCI test
   profile values after the shared wiring below is deployed.
2. Under Cloud Servers, choose the exact compute instance OCID. Confirm the UI
   displays the expected run name, compartment, AD, and `RUNNING` state.
3. Under Volumes, add the exact block and boot volume OCIDs. Confirm their type
   and AD. Do not select any other discovered resource.
4. Add Oracle Object Storage using values from the chmod-600 secret file. Set the
   exact bucket and the run prefix shown by the harness. Never paste these values
   into a repository file, screenshot, ticket, or terminal transcript.

### 3. Create and crash-test backups

For compute, block, and boot resources separately:

1. Start one on-demand backup in the UI and capture its BackupSheep backup UUID.
2. Confirm the durable execution API/UI shows create intent, retry token,
   correlation ID, provider status, and then provider OCID.
3. At the test-only post-provider/pre-pointer fault hook, kill the Celery worker
   after OCI accepts the request. Restart the worker/server.
4. Confirm recovery adopts exactly one matching image/backup and does not issue a
   second provider create.
5. Repeat a worker restart during polling. Confirm the backup remains visible as
   in progress and reaches complete.
6. Confirm a typed 429/timeout/transient fault stays retryable, a provider terminal
   failure is failed, explicit 404 is not in progress, and
   `NotAuthorizedOrNotFound` requires manual review.

### 4. Restore through the UI

1. Restore the custom image to a **new** instance in the same compartment/AD and
   exact test subnet. Select `assign_public_ip` only if the harness host needs it.
2. Restore block and boot backups to **new** volumes. Never select in-place/source
   replacement.
3. Repeat the post-provider/pre-pointer worker crash for each restore. After
   restart, require one exact target and no second launch/create.
4. Capture restore OCID, target name, durable restore marker, and durable request
   token from the restore API. These become the verification manifest.

### 5. Website/database Object Storage workflow

1. Create one website fixture and one database fixture with deterministic content
   and independent pre-backup SHA-256/row-count evidence.
2. Run each backup from the UI using only the Oracle destination and run prefix.
3. From BackupSheep's artifact API capture exact object key, SHA-256, byte count,
   ETag, and non-null version ID. Add one `website` and one `database` entry to
   `storage.objects` in the manifest.
4. Restore each archive through the UI to a new test path/database. Recompute the
   website file hash and database canonical dump hash/row counts at the target.
   Object verification alone is not proof of application-level restore.

### 6. Verification manifest

Store this outside `_docs` and outside the repository (values abbreviated):

```json
{
  "schema": 1,
  "run_id": "bs-oracle-e2e-<unique>",
  "compartment_id": "ocid1.compartment...",
  "compute": {
    "source_ocid": "ocid1.instance...",
    "backup": {"ocid": "ocid1.image...", "marker": "<backup-uuid>"},
    "restore": {
      "ocid": "ocid1.instance...",
      "name": "<exact-name>",
      "marker": "<durable-restore-marker>",
      "request_token": "bs-<61-hex>"
    }
  },
  "block": {
    "source_ocid": "ocid1.volume...",
    "backup": {"ocid": "ocid1.volumebackup...", "marker": "<backup-uuid>"},
    "restore": {
      "ocid": "ocid1.volume...",
      "name": "<exact-name>",
      "marker": "<durable-restore-marker>",
      "request_token": "bs-<61-hex>"
    }
  },
  "boot": {
    "source_ocid": "ocid1.bootvolume...",
    "backup": {"ocid": "ocid1.bootvolumebackup...", "marker": "<backup-uuid>"},
    "restore": {
      "ocid": "ocid1.bootvolume...",
      "name": "<exact-name>",
      "marker": "<durable-restore-marker>",
      "request_token": "bs-<61-hex>"
    }
  },
  "storage": {
    "objects": [
      {
        "kind": "website",
        "key": "<run-prefix>/<backup>.zip",
        "sha256": "<64-hex>",
        "byte_count": 123,
        "etag": "<etag>",
        "version_id": "<non-null-version>"
      },
      {
        "kind": "database",
        "key": "<run-prefix>/<backup>.zip",
        "sha256": "<64-hex>",
        "byte_count": 456,
        "etag": "<etag>",
        "version_id": "<non-null-version>"
      }
    ]
  }
}
```

Run verification only with the mutation gate because it attaches the exact
restored block volume read-only and launches a test-owned verifier from the exact
restored boot volume:

```bash
BACKUPSHEEP_E2E_APPLY=YES \
  python scripts/oracle_live_ui_e2e.py --phase verify \
  --ui-manifest /outside/repository/oracle-ui-manifest.json
```

Verification passes only if:

- all source, backup, restore, compartment, AD, marker, source, kind, retry-token,
  and OCID witnesses match;
- the compute-image restore's boot payload matches SHA-256 and byte count;
- the restored block volume mounts from its exact read-only OCI attachment and
  matches SHA-256 and byte count;
- a new tagged verifier launched from the exact restored boot volume matches the
  boot payload SHA-256 and byte count; and
- every declared website/database object version matches key, metadata SHA-256,
  byte count, ETag, version ID, and a streamed SHA-256 read.

If SSH is unreachable, the image lacks passwordless `sudo`, OCI does not expose a
safe paravirtualized device, the restored boot volume cannot be launched, or the
filesystem is not the expected ext4 graph, verification fails closed. Such a run
must be reported as metadata-only/incomplete; it is never data-level acceptance.

### 7. Cleanup

Cleanup requires a second gate and never searches for resources to infer
ownership:

```bash
BACKUPSHEEP_E2E_APPLY=YES BACKUPSHEEP_E2E_CLEANUP=YES \
  python scripts/oracle_live_ui_e2e.py --phase cleanup
```

It can address only fsynced ledger OCIDs whose current names, compartments,
relationships, and ownership tags still match. It detaches volumes, terminates
verification/restore instances while preserving ledgered boot volumes, deletes
backups/restores/sources, and confirms bounded authorized inventories. The IAM
credential is revoked before bucket/IAM cleanup. Every object version/delete
marker is enumerated; cleanup blocks if any key is outside the run prefix. Only
an empty exact-owned bucket is deleted. IAM policy/membership/group/user are then
removed in dependency order. The secret and SSH files are deleted only after
their provider graph is gone. A duplicate, changed witness, unknown ledger kind,
or incomplete dependency ledger stops cleanup for manual review.

## Historical shared-wiring checklist (superseded by the integrated checkpoint)

The list below records gaps at the initial offline checkpoint. The native
backup/restore and recovery routes needed by the tested compute, boot-volume,
block-volume, and Object Storage workflows were integrated before the live run.
It should not be used as a current readiness checklist; current evidence and
remaining gates live in `docs/provider-live-e2e-resume-handoff-20260812.md`.

1. Add `path("", include("apps.api.v1.cloud.oracle.urls"))` to the shared cloud
   URL router. The new Oracle cloud endpoint is otherwise unreachable.
2. Enable Oracle in the shared Cloud Servers setup template/navigation.
3. Delegate `CoreOracle.validate/create_snapshot/restore_snapshot/check_restore`
   to the Oracle adapters for both cloud and volume nodes.
4. Delegate `CoreOracleBackup.poll_status/soft_delete` to the typed Oracle
   compute/volume adapters. Current shared polling still assumes volume backup
   APIs and cannot poll/delete a custom image correctly.
5. Route server-reboot recovery and successor polling through the same adapters;
   do not call legacy model methods on redelivery.
6. In `run_provider_create`, bind the claimed backup's lease owner/token before
   invoking the provider callback. `ensure_execution_fence()` is intentionally a
   compatibility no-op when no fence was bound, so mutation-boundary fencing is
   not complete without this shared change.
7. Add a database uniqueness constraint/migration for active Oracle connection +
   provider OCID. The serializer's connection-row lock prevents normal races but
   is not a substitute for a durable invariant.
8. Expose/validate Oracle compute restore inputs (`compartment_id`, AD, shape,
   subnet, boolean public-IP choice) in shared restore UI/API code.
9. Add a durable deletion lease/task and adapter dispatch. The Oracle delete
   methods are exact and typed, but the current shared synchronous soft-delete
   path does not invoke them.
10. Add a test-only, post-provider/pre-pointer crash hook for live acceptance.
    Offline lost-response tests cannot prove worker-kill timing in production.

## Deliberately unsupported OCI services

No claim is made for Autonomous Database, Base Database Service/Exadata, MySQL
HeatWave, OCI PostgreSQL, NoSQL, File Storage snapshots, Kubernetes Engine,
load balancers, networking configuration, Container Registry, or cross-region
Object Storage replication. Each needs a separate provider model, source/target
ownership contract, restore semantics, deletion rules, and live acceptance.
Object Storage in this scope is solely a verified destination for BackupSheep
website/database archives.

## Official OCI behavior references

- SDK retries: <https://docs.oracle.com/en-us/iaas/tools/python/latest/sdk_behaviors/retries.html>
- SDK waiters: <https://docs.oracle.com/en-us/iaas/tools/python/latest/waiters.html>
- SDK request timeouts: <https://docs.oracle.com/en-us/iaas/tools/python/latest/customize_service_client/connection_read_timeout.html>
- OCI API errors: <https://docs.oracle.com/en-us/iaas/Content/API/References/apierrors.htm>
- Block-volume backup API: <https://docs.oracle.com/en-us/iaas/tools/python/2.157.1/api/core/client/oci.core.BlockstorageClient.html>
- S3 compatibility: <https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/s3compatibleapi.htm>
- S3 API/version compatibility: <https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/s3compatibleapi_topic-Amazon_S3_Compatibility_API_Support.htm>
