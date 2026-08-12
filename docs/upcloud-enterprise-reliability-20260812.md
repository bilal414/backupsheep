# UpCloud enterprise reliability handoff — 2026-08-12

## Evidence boundary

This work was completed offline. No UpCloud credential was read, no live API or
UI call was made, and no provider resource was created, changed, or deleted.
Passing tests prove deterministic code behavior; they do not constitute live
UpCloud or `demo.backupsheep.com` acceptance.

## Implemented application behavior

- API-token authentication is preferred and encrypted at rest; existing
  username/password connections remain compatible. Read APIs expose only
  configured/not-configured metadata.
- Server and storage discovery use complete, bounded `limit=100`/`offset`
  pagination with finite request timeouts, duplicate/repeated-page rejection,
  strict response shapes, type filtering, and the live-compatible
  `sort_by` + `order=asc` parameters. The harness deliberately does not send
  the rejected `order_by=asc` spelling.
- An omitted UpCloud `object_type` discovers Cloud Servers. Explicit
  `object_type=volume` discovers normal Block Storage.
- Volume backups persist a source/zone/marker witness before mutation, adopt
  only one exact backup, suppress duplicate POSTs after lost responses, and
  durably persist provider IDs.
- Cloud Server backups snapshot the exact boot storage and persist the safe
  server configuration witness needed for restore.
- Volume restores clone to new normal storage. Cloud Server restores clone boot
  storage and create a new server from the copied safe configuration. Both
  state machines use source-bound markers, exact origin/zone/type/config
  matching, bounded reconciliation, disabled exact-row crash hooks, and strict
  polling/deletion ownership.
- Provider 404, authentication, rate-limit, quota, conflict, timeout, transient
  outage, malformed response, and terminal failures remain distinct from
  `IN_PROGRESS`.
- Managed Object Storage endpoints are restricted to documented UpCloud hosts.
  S3 uploads use bounded clients and retain checksum, byte count, ETag, version
  ID, multipart state, and verification metadata.

## Live UI support harness

`scripts/upcloud_live_ui_e2e.py plan` is the default and performs no network or
credential access. Live commands require an API token through the environment;
the harness never reads `_docs`.

### Safety controls

- Setup/provisioning: `BACKUPSHEEP_E2E_APPLY=YES`.
- Cleanup: APPLY plus `BACKUPSHEEP_E2E_CLEANUP=YES`.
- Acceptance cleanup: `cleanup-compute --require-evidence` additionally refuses
  to proceed until compute and workload restore evidence is durable.
- Account identity must exactly equal `UPCLOUD_E2E_ALLOWED_ACCOUNT`.
- Every mutation has a durable pre-request intent. A lost create response is
  reconciled by exact ID/title/labels/source/zone/type/config and never retried
  merely because the response was lost.
- Cleanup uses only ledgered immutable IDs and re-verifies ownership immediately
  before detach/delete. An unledgered title match, duplicate match, foreign
  attachment, or changed witness fails closed.
- Network access requires `UPCLOUD_E2E_ALLOWED_CIDRS`. Only exact IPv4 `/32` and
  IPv6 `/128` host CIDRs are accepted; broad/world CIDRs are rejected. The
  source server is created with the UpCloud provider firewall set to `on`.
  Before any SSH or workload interaction, the harness reads the provider
  firewall inventory and atomically replaces it through the official
  [`PUT /server/{uuid}/firewall_rule`](https://developers.upcloud.com/1.3/11-firewall/)
  endpoint with only exact TCP 22, 80, and
  5432 host rules plus an explicit inbound default `drop`. Outbound traffic is
  left at the provider default so package installation remains possible.
  The provider chain is bounded to the documented 1,000-rule limit, positions
  are validated, duplicate rules fail closed, and the exact chain is persisted
  in the run ledger. A lost firewall mutation response is adopted only after
  exact read-back; it is never re-issued blindly.
- Source-server ownership and cleanup re-read the provider firewall state and
  require it to remain enabled. Cleanup deletes only the six ledger-owned
  allow rules by their current provider positions, with a durable intent per
  deletion, and retains the inbound default drop until the server itself is
  deleted. A foreign, duplicate, missing, or changed rule stops cleanup.
- Generated SSH and PostgreSQL credentials exist only in ignored
  `scripts/.upcloud-runtime/` files (or an explicitly external runtime path),
  with mode `0600`. Secrets are not put in the ownership ledger or stdout.

### Compute and Block Storage workflow

Required environment inputs include exact account, zone, server plan, Linux
cloud-init template UUID, allowed host CIDRs, durable ledger path, and run ID.

1. `setup-compute` creates one uniquely named/labeled encrypted Standard normal
   volume, one server, and its uniquely named/labeled boot storage. The server
   is born with the provider firewall enabled; the exact provider chain is
   installed and read back before the command opens SSH. It outputs the exact
   server, source-volume, and boot-storage IDs for UI attachment.
2. The source server receives deterministic bytes on both the boot filesystem
   and attached volume. SHA-256 and byte count are read back after `sync` and
   persisted as evidence.
3. The command also creates a deterministic four-file website tree and a
   PostgreSQL fixture with 120 customers and 480 events. It persists per-file
   hashes, aggregate tree hash/bytes, schema hash, canonical-data hash, and row
   counts.
4. Through the UI, back up/restore both the Cloud Server and standalone Volume.
   Export exact provider IDs and markers into this non-secret manifest shape:

```json
{
  "schema": 1,
  "run_id": "bs-e2e-...",
  "volume": {
    "backup_resource_id": "UUID",
    "backup_marker": "BACKUP_UUID",
    "restore_resource_id": "UUID",
    "restore_marker": "backupsheep-upcloud-..."
  },
  "server": {
    "backup_resource_id": "UUID",
    "backup_marker": "BACKUP_UUID",
    "restore_storage_id": "UUID",
    "restore_storage_marker": "backupsheep-upcloud-storage-...",
    "restore_server_id": "UUID",
    "restore_server_marker": "backupsheep-upcloud-server-...",
    "restore_hostname": "bs-upcloud-..."
  }
}
```

5. `verify-compute --manifest ...` proves unique marker inventory, exact
   ID/origin/zone/type, safe server configuration, and boot-storage attachment.
   It temporarily attaches the restored standalone volume only to the run-owned
   source server, mounts it read-only, checks SHA-256 and bytes, unmounts, and
   detaches under durable intents. It also verifies the restored server's boot
   bytes over its copied run-scoped SSH key.
6. `cleanup-compute --require-evidence` removes only exact ledger-owned restore
   server/storage, backups, source server/storage, and runtime material in
   dependency order.

### Website and PostgreSQL workflow

The `setup-compute` output gives paths to protected connection material and the
prescribed restore root/database prefix. The same source node can be used for
UI backups to UpCloud Managed Object Storage, Oracle Object Storage, and
DigitalOcean Spaces.

After UI restore, run `verify-workloads --manifest ...` with:

```json
{
  "schema": 1,
  "run_id": "bs-e2e-...",
  "website": {
    "backup_id": "BACKUP_ROW_ID",
    "restore_id": "RESTORE_ROW_ID",
    "restore_path": "/srv/backupsheep-e2e/RUN_ID/restores/RESTORE_ROW_ID"
  },
  "postgresql": {
    "backup_id": "BACKUP_ROW_ID",
    "restore_id": "RESTORE_ROW_ID",
    "restore_database": "RUN_SCOPED_DATABASE_NAME"
  }
}
```

The verifier rejects paths/database names outside the run scope and compares
the restored website's exact file set/hash/bytes plus PostgreSQL schema hash,
canonical-data hash, and per-table/total row counts. The selected object-storage
harness must separately verify the backup object's checksum, bytes, ETag, and
version ID.

### Managed Object Storage workflow

1. `setup-object-storage` creates a unique service, public network, bucket,
   user, prefix-scoped least-privilege policy, and one access key.
2. The one-time key secret is written only to the mode-0600 ignored runtime
   file. The ledger stores a hash, never the key or secret.
3. After UI destination validation removes its probe, `arm-object-storage`
   proves the bucket is empty and enables versioning.
4. `verify-object-storage --manifest ...` independently HEADs/GETs exact UI
   objects and checks metadata, SHA-256, byte count, ETag, and version ID.
5. `cleanup-object-storage` enumerates versions, delete markers, and multipart
   uploads; any unledgered item blocks cleanup. It then removes exact
   dependencies and deletes the service with `force=false`.

The object manifest keeps the numeric BackupSheep ownership marker separate from
the UUID used in the provider object key. Each website/database row must include
`backup_id` as the positive numeric BackupSheep backup row ID, `backup_uuid` as
the exact backup UUID, and `object_key` equal to `<prefix><backup_uuid>.zip`.
The verifier requires provider metadata
`backupsheep-backup-id=<backup_id>`; it never derives that metadata from the
object key.

## Offline test evidence

- Named regression:
  `OVHUpCloudReliabilityTests.test_upcloud_restore_page_two_adoption_duplicate_and_no_post`
  passed. Its mock now gives the exact backup-source GET separately and drives
  the real storage scanner through offsets 0 and 1; duplicate candidates split
  across pages still block POST/adoption.
- New compute/workload harness safety tests: 13 passed.
- Existing object-storage harness plus named regression: included in a 25-test
  focused run.
- Full UpCloud-focused application/compatibility suite: 108 tests passed.
- Django system check and migration drift check must remain green before live
  use.

## Remaining live acceptance

No live result exists yet. Enterprise acceptance still requires an explicitly
gated run against the intended UpCloud account and `demo.backupsheep.com`,
including lost-response/worker-crash adoption, UI in-progress status across a
worker restart, byte/hash/database verification, exact cleanup proof, and a
before/after inventory proving no pre-existing resource changed.
