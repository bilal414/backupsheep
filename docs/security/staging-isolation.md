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

The root staging provisioner is a networkless, restart-disabled one-shot. It drops every
capability except `CHOWN`, `FOWNER`, `DAC_OVERRIDE`, and `FSETID`; the last is required
only to preserve the reviewed setgid bit when ownership and mode `3771` are applied to a
fresh transfer root. No long-running or networked role receives those capabilities.

SSH host trust is not a cross-identity filesystem. Exact account-scoped approvals
and append-only approval/replacement/revocation events live in PostgreSQL. A
database/files operation receives only its current approval material in a transient
mode-`0600` file below that worker's private runtime; the file is removed after use.
Stock Compose has no shared trust volume or global `known_hosts` file.

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

## Local-file root-key boundary

The installer generates two independent 256-bit root keys in strict versioned
keyrings named `artifact_local_file_database_keyring` and
`artifact_local_file_files_keyring`. Compose mounts only the matching keyring into
each database/files source worker. Web, cloud, storage, logs, Beat, migration and
preflight receive neither a keyring nor a keyring path. The image entrypoint rejects
wrong-lane mounts, links, unexpected ownership or mode, and any keyring visible to a
non-source role.

Each keyring is bound to one installation ID and one lane, and contains one active key ID
followed by at most seven retained legacy key IDs. AES-256-GCM-SIV wraps authenticate the complete canonical
artifact context and the wrapping key ID. A database keyring therefore cannot unwrap
a files artifact, and changing the installation, account, node, backup, model, lane,
purpose, key ID, nonce, or ciphertext fails authentication.

Keyring creation is no-clobber and atomic. Installer reruns validate and preserve the
exact bytes; a missing keyring in an existing installation is treated as key loss and
is never silently regenerated. Keep protected, encrypted, independently access-audited
copies of both keyrings with the PostgreSQL recovery set. Losing one keyring makes every
BSE1 artifact in that lane whose required key is absent cryptographically unrecoverable.

Rotation is lane-scoped and deliberately two-phase:

1. use the reviewed Compose wrapper to bring the entire operations profile down and
   remove its worker containers, then run `install.sh --rotate-artifact-keyring
   database` or `files`; stopped, paused, and restarting containers are also refused
   because they retain the old bind-mounted inode. Rotation atomically prepends a
   random active key while retaining every prior key;
2. run `rotate_artifact_key_wraps` first as a read-only plan and then with `--apply`
   inside the matching source role, using the old key ID, exact lane, and installation-ID
   witness until it reports `remaining_source=0`;
3. retain the legacy key through the maximum in-flight backup/restore retry and retention
   grace. BackupSheep provides no automatic eviction operation. A separately reviewed
   prune may occur only after database evidence proves no non-retired wrap references it;
   pending and manual-review generations must be reconciled or explicitly retired first.

The keyring is capped at eight entries and another rotation refuses rather than evicting
recovery material. The non-Docker `scripts/manage_artifact_keyring.py` tool provides the
same create, inspect, and rotate rules for owner-controlled mode-`0700` directories and
mode-`0400` keyrings; it prints IDs and counts, never root key material.

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
sha256("BackupSheep/staging-layout/v3|<installation-id>|<intent>")
```

Allowed intents are `new-empty-v3` and `migrate-empty-legacy-v3`. The provisioner
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

The v2 witness and layout were prerelease-only and are not accepted as v3 evidence.
An operator must select the explicit v3 migration intent; the installer will not
silently reinterpret an old witness. A develop-era, canonical project-owned
`ssh_trust` volume is accepted only after the normal exact ownership, physical-name
and label checks succeed. It is then preserved detached as rollback evidence: the
v3 provisioner has no trust path or trust group, stock Compose does not mount it,
and the wrapper rejects every `--volume` override. Its global `known_hosts` inventory
is never imported into the account-scoped approval ledger. After migration,
operators independently verify and explicitly reapprove every exact
account/host/port/key before enabling SSH work. Any noncanonical, foreign or
ambiguously owned trust volume fails closed.

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
