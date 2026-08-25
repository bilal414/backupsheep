# Private staging and ciphertext handoff

Status: the Docker filesystem boundary, BSE1 handoff API, and backup/restore task
pipeline integration are implemented. There is intentionally no plaintext
compatibility mount.

## Runtime identities

The stock image and Compose model reserve one fixed primary UID/GID per trust lane:

| Lane | UID:GID | Private work volume | Shared transfer group |
| --- | --- | --- | --- |
| Web | `10001:10001` | none | no |
| Database source/restore | `10002:10002` | `database_workdir` | database-transfer writer `10989`, reader `10990`, database-restore reader `10994` |
| Files source/restore | `10003:10003` | `files_workdir` | files-transfer writer `10991`, reader `10992`, files-restore reader `10993` |
| Storage upload | `10004:10004` | `storage_workdir` | database/files transfer readers `10990`/`10992`; restore writer `10995` and target readers `10993`/`10994` |
| Logs | `10005:10005` | none | no |
| Beat | `10006:10006` | none | no |
| Migration/preflight | `10007:10007` | none | no |
| Cloud/API-only worker | `10008:10008` | none | no |

Every private work volume and the local-storage volume are owned by exactly their
lane and mode `0700`. All image
entrypoints retain `umask 077`; plaintext files therefore remain `0600` and cannot
be read, replaced, or deleted by another worker UID. Long-running roles remain
non-root, drop every capability, use no-new-privileges, and have a read-only root
filesystem.

SSH host trust is the only other cross-identity file. It uses a separate reader
group `10997`: web owns the setgid `ssh_trust` root and updates `known_hosts`
atomically at mode `0640`; database/files mount it read-only and join `10997`;
storage, logs, Beat, migration and cloud roles neither mount it nor join the group.
The API rejects unsafe directory ownership/mode, links, foreign ownership and any
non-canonical file mode instead of repairing live drift.

## BSE1 transfer contract

`backupsheep.staging` is the only supported shared-disk handoff:

1. A database or files worker validates its private `/code/_storage` root with
   `private_plaintext_root()`.
2. It calls `create_ciphertext_fence(backup_uuid)`. Database fences live under
   `/var/lib/backupsheep/transfer/database`; files fences live under
   `/var/lib/backupsheep/transfer/files`. Each path is a different Docker volume.
   Database uses writer/reader GIDs `10989`/`10990`; files uses `10991`/`10992`.
   Each root is setgid and sticky (`3771`), and each fence is source-owned, reader-
   grouped, and mode `2750`. Storage has both reader groups but no writer group, so
   it can traverse a known completed fence but cannot enumerate or pre-create root
   entries. Database and files receive neither the other volume mount nor its
   groups, so they cannot enumerate, traverse, read, replace, or delete each other's
   ciphertext even when a backup UUID is known.
3. It calls `artifact_crypto.seal_file` with the private work root as
   `trusted_source_root`, the fence as `trusted_destination_root`, and the canonical
   backup UUID as the BSE1 envelope ID. The completed output must use a bounded
   `*.bse1` name and remains private mode `0600`.
4. Only after the durable envelope/key record is ready, it calls
   `publish_ciphertext`. Publication checks the marker, owner, group, mode, link
   count, no-follow path, BSE1 structure and fence-bound envelope UUID before the
   single `0600 -> 0640` transition.
5. The storage worker calls `private_storage_root()` and `open_ciphertext` with the
   durable source lane, checks it against the durable
   envelope record, and atomically materializes those same BSE1 bytes in its private
   `/code/_storage/<uuid>.zip`. The historical extension exists only for adapter
   compatibility: provider objects contain BSE1 ciphertext, never a decrypted ZIP.
   The storage role can read a published envelope but cannot write or delete the
   source fence.
6. Storage deletes only its private ciphertext copy. A task routed to the recorded source
   lane calls `cleanup_ciphertext_fence`; cleanup validates the complete inventory
   first and deletes only the exact source-owned UUID fence. A complete, validated
   BSE1 file left mode `0600` by a crash immediately before publication can also be
   discarded by its source owner. An already-absent exact fence is an idempotent
   no-op after role, installation and transfer-root validation, so a crash after
   filesystem deletion but before its database witness does not strand the retry.

The installation ID, backup UUID, source lane, owner UID and schema are bound in a
canonical fence marker. Symlinks, hard links, unexpected names, unsafe modes,
cross-installation/root reuse, lane/root mismatches and partial/unpublished
ciphertext all fail closed.

## KMS credential and encryption-context boundary

The installer requires two different canonical AWS credential inputs and stores
them as `artifact_kms_database_aws_credentials` and
`artifact_kms_files_aws_credentials`. Compose mounts only the database secret into
the database worker and only the files secret into the files worker. Web, cloud,
storage, logs, Beat, migration and preflight receive neither secret, and the image
entrypoint rejects a wrong-lane or unexpected credential mount. The installer also
rejects identical files and identical AWS access-key IDs. This is a container
boundary, not proof of the upstream IAM principal's permissions.

Operators must use two AWS principals and enforce the same lane separation in both
their identity policies and the KMS key policy. Each allow statement for
`kms:GenerateDataKey`, `kms:Decrypt`, `kms:ReEncryptFrom` and `kms:ReEncryptTo` must
at least require these exact encryption-context conditions (substitute the stable
installation ID and one lane):

```json
{
  "StringEquals": {
    "kms:EncryptionContext:bse:installation-id": "<64-hex-installation-id>",
    "kms:EncryptionContext:bse:lane": "database",
    "kms:EncryptionContext:bse:purpose": "backup-artifact-v1"
  },
  "ForAllValues:StringEquals": {
    "kms:EncryptionContextKeys": [
      "bse:account-id", "bse:backup-id", "bse:backup-model",
      "bse:context-sha256", "bse:installation-id", "bse:lane",
      "bse:node-id", "bse:purpose"
    ]
  }
}
```

The files principal uses the same condition with `bse:lane` equal to `files`.
Do not grant either principal an unconditional KMS cryptographic action through a
second identity policy, key-policy statement, grant, role, instance profile or
container credential endpoint. Validate both allowed-lane and denied-cross-lane
calls before enabling operations.

Key-wrap rotation is lane-scoped. Run the read-only plan and then `--apply` inside
the matching worker with `--lane database` or `--lane files`; the command filters
and revalidates every durable artifact context before KMS use. Rotate both lanes
separately. Keep the old KMS key enabled and in the allowlist until each lane reports
`remaining_source=0`, then wait through the maximum in-flight backup/restore retry
and retention grace before disabling it. Key deletion remains an operator-controlled
AWS action and is never performed by BackupSheep.

## Restore ciphertext handoff

The reverse path never grants a restore/source worker access to `/backups`. This is
important on upgrades because a populated local-storage volume may still contain
historical plaintext ZIPs even when new writes are BSE1-only.

Storage writes only to `/var/lib/backupsheep/restore-transfer`. Its root is owned by
restore-writer GID `10995`, mode `3771`, so source lanes cannot list or create
handoffs. Every fence is named by the restore execution's canonical correlation UUID
and binds that handoff, the backup UUID, installation ID and exact target lane.
Database fences use reader GID `10994`; files fences use `10993`. The source roles
join only their own reader group, so raw filesystem access cannot cross the two
restore lanes.

`create_restore_ciphertext_fence`, `publish_restore_ciphertext`,
`open_restore_ciphertext` and `cleanup_restore_ciphertext_fence` mirror the forward
fence invariants. Storage first downloads or copies a provider/local BSE1 object into
its private work volume and verifies its exact durable byte count and SHA-256. It
then copies into the storage-owned fence at mode `0600`; publication validates BSE1
framing and the backup-bound envelope ID before mode `0640`. The target source opens
a held read-only descriptor, copies and re-hashes it into its private volume, and
only then performs full authenticated decryption. Source cannot modify or delete the
handoff. Storage cleanup validates the complete inventory and is idempotent only for
an already-absent exact fence after root, role and installation checks.

`private_plaintext_root`, `private_storage_root`, `require_private_capacity`,
`require_transfer_capacity` and `require_restore_transfer_capacity` use free
blocks/inodes available to the unprivileged caller. Configured byte/inode reserves
are additive to the current operation's
declared requirement. Fence creation and publication recheck transfer headroom, so
an exhausted filesystem fails before another handoff is exposed.

## Existing installations

`deploy/staging/provision-volumes.sh` is a root one-shot; it is not a long-running
service. It requires a 64-hex witness derived from the stable installation ID and an
explicit intent:

```text
sha256("BackupSheep/staging-layout/v2|<installation-id>|<intent>")
```

Allowed intents are `new-empty-v2` and `migrate-empty-legacy-v2`. The provisioner
first proves that every target is a dedicated mount and all new work/transfer
volumes, including both source-specific forward volumes and the reverse restore-
transfer volume, are empty. For migration,
the historical `backup_workdir` must also be
empty. A populated `backup_storage` can be migrated because it has one unambiguous
owner: the provisioner accepts only private regular files/directories owned by the
historical or new storage UID, rejects links, special files and foreign ownership,
and then changes that tree to `10004:10004`. It assigns exact root ownership/modes
and commits a root-only durable witness in `staging_layout_witness`. Reruns verify
rather than repair witnessed state.

The same one-shot migrates only the bounded SSH trust inventory (`known_hosts` and
its lock): both must be single-link regular files owned by the historical web UID
with an allowlisted private/read-only mode. It assigns trust GID `10997`, directory
mode `2750`, `known_hosts` mode `0640`, and leaves the writer-only lock at `0600`.
Unknown files, links, special files or foreign ownership block the migration.

The one-shot also checks a configurable minimum free-byte and free-inode reserve on
every new work, transfer and local-storage mount before changing ownership. The
stock defaults are 512 MiB and 1,024 inodes; production values should reflect the
largest supported concurrent backup and temporary-copy policy.

A non-empty historical shared work volume is deliberately ambiguous: it can mix
database data, website data, credentials, partial files and logs under one old UID.
The provisioner will not guess a lane, copy it, or delete it. Quiesce operations and
drain or separately quarantine that volume before authorizing the migration.

## Verification

The focused Django tests cover path confinement, canonical fences, permission
transitions, links, cross-lane ownership, installation binding and fail-closed
cleanup. `deploy/staging/test-cross-uid.sh` exercises real Linux UIDs against
disposable mounts and proves that database/files/storage cannot read or mutate each
other's plaintext, database and files cannot enumerate or read the other's
ciphertext, storage cannot create or enumerate forward-transfer entries, source
roles cannot create reverse-transfer entries, and each restore lane can read only
its own published ciphertext.

Docker named volumes do not provide a portable per-volume quota or storage-at-rest
encryption control. Host-backed volume capacity, inode quotas, encrypted disks and
snapshot policy remain operator/host responsibilities; the application reserve is a
fail-closed preflight, not a claim that Docker enforces those host controls.
