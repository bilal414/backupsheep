# PostgreSQL Alpine/ICU storage migration

BackupSheep's bundled database is PostgreSQL 18.6 on the digest-pinned Alpine 3.24
image. It runs as UID/GID `70:70`, initializes every connectable database with ICU
locale `und`, and uses the `postgres_data_v1` volume. The image never mounts or adopts
the retired Debian/glibc `pgdata` volume.

Fresh installations create and witness the new volume automatically. Automatic
runtime migration is available only for an exact, installation-witnessed generation-2
or generation-3 stock database. It is not a general PostgreSQL migration tool.

## Unsupported shared-superuser databases

A legacy database with a blank identity generation used an application-held
superuser credential. Its database body cannot be treated as trusted input, so the
installer refuses to migrate it even when both migration flags are supplied. Do not
set a generation marker, relabel a volume, or weaken the checks.

For an installation whose disposable data can be replaced, stop the old project and
retain its checkout, configuration, exact images and volumes unchanged as rollback
evidence. Create the target in a clean installation directory with a new exact Compose
project name. This initializes a fresh PostgreSQL 18/ICU volume and generation-3
identities without deleting, renaming, mounting or adopting the old `pgdata` volume.
Any data recovery from the old shared-superuser database requires a separate,
schema-reviewed and data-only procedure.

## Authorized stock paths

For a generation-2 source, use both one-time flags with the normal installation
arguments:

```bash
./install.sh \
  --ref "$(git rev-parse HEAD)" \
  --install-dir "$PWD" \
  --project-name backupsheep \
  --domain backups.example.com \
  --migrate-postgres-runtime \
  --migrate-database-identities
```

For an already sealed generation-3 source, use only
`--migrate-postgres-runtime`. Preserve the protected artifact keyrings and supply the
same deployment arguments used for the installation. Never edit the storage or
identity generation variables by hand.

## Fail-closed source contracts

The generation-2 contract requires exactly bootstrap, migrator and runtime roles with
installation-bound v2 comments. It validates every role attribute, SCRAM password
state, expiry, inheritance, connection limit, membership and role setting. It also
requires the exact stock database/schema grants, the exact three default-ACL records
and their grantors, and migrator ownership of the database, `public` schema and public
objects.

The generation-3 contract requires the exact configured ten active roles, or those ten
plus the one installation-bound retired-v2 runtime role. It validates every role
attribute, comment, SCRAM/NULL password state, expiry, connection limit, membership,
four per-role settings, database/schema ACL and grantor, the exact two owner-only
default-ACL records, and migrator ownership. Extra, missing or renamed roles and any
attribute, ACL, setting or ownership drift are refused.

Before a dump is allowed, the migration also proves:

- exact PostgreSQL `server_version_num=180006`, the retained glibc source image and
  UID/GID `999:999`, the canonical detached `${project}_pgdata` volume, and an
  authoritative primary;
- only the configured BackupSheep database and `postgres`, and only the stock
  `plpgsql` extension;
- no non-stock collation, tablespace, event trigger, foreign-data object, publication,
  subscription, replication slot, prepared transaction, large object, parameter ACL,
  security label, shared security label, or routine in an unreviewed language; and
- the exact generation-specific identities, settings, ownership, ACL rows and ACL
  grantors described above.

Custom or drifted sources require a separately reviewed procedure. Never broaden the
allowlist to force a migration through.

## Isolated restore boundary

The installer first records the immutable source image ID, validates the one owned
Compose database attachment, and removes the complete application topology. The
migration servers have `network=none`, read-only root filesystems, all capabilities
dropped, `no-new-privileges`, bounded PIDs, exact UIDs and separate witnessed Unix
socket volumes. Dangerous preload, archive/recovery execution, worker, JIT and logging
settings are overridden on the isolated source. Short catalog probes use a fixed
`pg_catalog` search path.

Credentials and dump bytes do not share a helper boundary:

- the source dump producer receives only the source socket and retained source secret;
- the target restore consumer receives only the target socket and a distinct random
  restore secret; and
- bootstrap/admin helpers never consume dump bytes.

No source-generated global SQL is executed. The target creates only the fixed
configured generation-3 placeholder roles. A dedicated ephemeral restore role is
`NOINHERIT`, non-superuser, has no memberships or settings, and temporarily owns only
the target database and `public` schema. A custom archive streams directly from
`pg_dump` to `pg_restore --single-transaction --no-owner --no-acl
--no-security-labels`; no dump is written to host storage.

After restore, fixed SQL disables and terminates the restore role, reassigns reviewed
objects to the configured target migrator, drops owned residue, normalizes database and
schema ownership, revokes public database/schema/table/sequence/function/routine
access, and uses safely quoted catalog-driven statements to revoke public usage from
every manageable restored type/domain. The restore role is then dropped. Effective
ACL checks include hard-wired defaults for databases, routines and types, plus exact
relation, column, default, parameter and security-label zero vectors. Array and
multirange rows that PostgreSQL does not permit `GRANT`/`REVOKE` against are excluded
by the same exact catalog predicate in both revocation and attestation.

Canonical source identity evidence and canonical schema/data dumps are hashed. The
target must match the schema and data hashes and the fixed target role/ownership/ACL
contract before the in-volume receipt can complete. Receipt version 2 binds the restore
strategy, source identity contract, source image, exact current target image, and all
three hashes. The environment storage generation changes only after `db-provision`,
`migrate`, `db-seal` and the in-volume witness succeed. The old volume and image remain
detached rollback evidence.

## Interruption and retry

Rerun with the flags required by the still-pending state. Recovery recognizes only the
canonical migration server names with exact installation, purpose, image, user,
runtime and mount evidence. Anonymous `--rm` helpers are stopped and removed only when
their installation/witness labels, reviewed image, network isolation, runtime and
source-or-target-only mount boundary are exact. Any drift is refused.

Before stale migration credentials are unlinked, every exact
`.migration-bootstrap.*` or `.migration-restore.*` residue must have the canonical
eight-character suffix, regular non-symlink type, expected owner, mode `0444`, one
link, exact 64-hex content, and no Docker bind attachment. Other paths are never swept.

A partial target is reset only when its canonical name and project, installation,
logical-volume and migration-witness labels all match. A completed target reconciles
only through the exact v2 receipt, and the recorded target image ID must equal the image
ID resolved from the current target reference.

Generation-2 has two bounded configuration crash windows:

- generation `2` or `3-pending-upgrade` before sealing requires both migration flags;
- generation `3` with storage still pending requires the existing completed target,
  `--migrate-postgres-runtime`, and no database-identity flag. It cannot create or
  erase a target.

An already-generation-3 source always uses only the runtime flag. Foreign, attached,
unlabeled, unexpectedly nonempty or stale-image targets fail closed.

## Rollback boundary

The current Compose model never remounts retired `pgdata`. For rollback, stop the
entire target topology and use the recorded old revision, old Compose model, exact
retained image, matching configuration/secrets and detached old volume in a separately
reviewed recovery. Never mount a Debian/UID-999 volume in the Alpine/UID-70 image or
overwrite the new ICU target. Preserve both generations until the rollback-retention
decision and restore rehearsal are recorded.
