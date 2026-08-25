# PostgreSQL Alpine/ICU storage migration

BackupSheep's bundled database is PostgreSQL 18.6 on the digest-pinned Alpine 3.24
image. It runs as UID/GID `70:70`, initializes every connectable database with ICU
locale `und`, and uses the `postgres_data_v1` volume. The image will not mount or
adopt the older Debian/glibc `pgdata` volume.

Fresh installations create and witness the new volume automatically. An existing
stock installation requires the explicit one-time installer flag:

```bash
./install.sh \
  --ref "$(git rev-parse HEAD)" \
  --install-dir "$PWD" \
  --project-name backupsheep \
  --domain backups.example.com \
  --migrate-postgres-runtime
```

Supply the same KMS and other deployment arguments used for the installation. Do
not edit the storage-generation variables or rename Docker volumes by hand.

## Fail-closed source contract

The automated path is intentionally limited to the exact stock database topology.
Before copying any data it proves:

- exact PostgreSQL `server_version_num=180006`, a retained glibc image running as
  `999:999`, the canonical `${project}_pgdata` volume, and no foreign attachment;
- only the configured BackupSheep database plus `postgres`;
- exactly the ten configured stock roles and reviewed privilege attributes;
- only `plpgsql`, with no non-stock collations, tablespaces, database ACLs,
  database/role settings, event triggers, foreign-data wrappers/servers/tables/user
  mappings, publications, subscriptions, or replication slots; and
- an authoritative primary, not a server in recovery.

If an operator added any excluded object, migrate it with a separately reviewed
PostgreSQL procedure. Do not weaken the allowlist to force the stock migration
through.

## What the installer does

The installer records the exact retained source image before changing the image tag,
validates an attached legacy database as the single owned Compose `db` container,
and then removes the complete application topology. It requires the old volume to be
detached immediately before migration.

The migration starts the old and new servers with `network=none`, read-only root
filesystems, all capabilities dropped, `no-new-privileges`, bounded PIDs, exact UIDs,
and separate project-owned Unix-socket volumes. The old server never mounts a
password. Short-lived helpers receive the legacy password as a read-only file. The
new server receives a different random file-backed bootstrap credential; the role
restore replaces it with the retained bootstrap identity before application data is
accepted, and the random file is removed after both servers stop.

Roles are restored inside one fail-closed transaction. The one allowlisted database
is pre-created with ICU `und`, then its schema and data are restored in a separate
transaction. This is not described as a cluster-wide transaction: PostgreSQL database
creation cannot be part of that transaction. Dumps stream only through isolated Docker
pipes; no plaintext dump is written to the host or a volume. A secret-derived fixed
`\restrict` key prevents dump content from introducing helper-side psql commands while
keeping source/target fingerprints reproducible.

The gate compares canonical role, schema, and data dump hashes after removing only
the exact PostgreSQL version-header differences. It then writes a content/image
receipt and finally changes the storage marker to `complete`. The environment
generation changes last. The old `pgdata` volume remains retained and detached as
rollback evidence.

## Interruption and retry

Rerun the same installer command with `--migrate-postgres-runtime`. A target is reset
only when its canonical name and project, installation, logical-volume, and migration
witness labels all match. A completed receipt with a still-pending marker is treated
as interrupted and the exact target is recreated. A completed marker is accepted only
with a valid receipt and locally available reviewed source/target image IDs. A foreign,
attached, unlabeled, or unexpectedly nonempty target fails closed.

The source volume is never deleted. Keep its exact image ID until database/application
verification and a restore rehearsal have passed.

## Rollback boundary

The stock Compose model never remounts retired `pgdata`. If rollback is required,
stop the entire topology and use the recorded old revision, old Compose model, exact
retained image ID, and detached old volume in a separately reviewed recovery. Never
mount the Debian/UID-999 volume in the Alpine/UID-70 image, and never overwrite the
new ICU target. Preserve both generations until the rollback-retention decision is
recorded.
