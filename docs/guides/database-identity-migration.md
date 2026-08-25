# PostgreSQL identity generation 2

The stock Docker stack uses three PostgreSQL logins with separate credentials:

| Identity | Lifetime and authority | Secret recipients |
| --- | --- | --- |
| Bootstrap | Bundled-cluster superuser required by the official PostgreSQL initializer and the transactional identity provisioner | `db`, `db-provision` |
| Migrator | Non-superuser owner of the BackupSheep database and `public` schema; runs Django migrations | `db-provision`, `migrate` |
| Runtime | Non-owner login with table DML, sequence use and execution of public routines, but no database/schema DDL or temporary-table privilege | `db-provision`, app, preflight, workers, Beat |

Fresh verified installs create this boundary automatically. This runbook is only for an
existing stock Docker database whose old `DB_USER` is also the PostgreSQL bootstrap
superuser. It does not apply to managed/external PostgreSQL or a deployment with
`DATABASE_URL`; those identities and grants are operator-managed.

## Safety boundary

Identity conversion changes durable PostgreSQL ownership and credentials. It is not a
normal configuration edit. Before starting:

1. Use the exact current and target commits and the normal
   [upgrade ownership checks](upgrades.md#before-the-change).
2. Stop the app, every worker and Beat. Prove there are no database-backed application
   processes or broker consumers still running.
3. Create and verify an encrypted off-host recovery set containing a PostgreSQL custom
   dump, a recoverable `pgdata` snapshot, `.env`, the complete `.secrets` directory,
   Compose overrides, exact Git commit and both image IDs. A dump alone does not contain
   cluster roles and is not a complete rollback for this change.
4. Confirm the legacy `DB_USER` and database name are the intended stock installation.
   Never copy a secret or generation marker from another installation.

The provisioner intentionally accepts only a narrow legacy topology. The current
database and its relations must be owned by the legacy bootstrap or the marked migrator,
and application relations/routines must be in `public`. Custom schemas, extensions,
standalone types and unsupported catalog/cluster object classes fail closed. Review and transfer
those objects manually in a separate change; do not weaken the inventory or edit the
generation witness to bypass it.

## Stage the credential transition

After checking out the reviewed target commit, run the verified installer once with
startup disabled and the explicit migration flag. Include the same domain, project name
and approved override arguments used by this installation:

```bash
TARGET_COMMIT='<40-character-reviewed-release-commit>'
./install.sh \
  --ref "${TARGET_COMMIT}" \
  --install-dir "$PWD" \
  --project-name backupsheep \
  --migrate-database-identities \
  --skip-start
```

This local, resumable transition:

- atomically moves the legacy `db_password` file to `db_bootstrap_password`;
- creates new random `db_migrator_password` and runtime `db_password` files;
- preserves the legacy role name as `DB_BOOTSTRAP_USER`;
- sets fixed, distinct migrator/runtime role names and writes identity generation `2`
  only after every file and environment rewrite succeeds.

The installer accepts only the ordered resumable file states produced by those steps.
An unexpected combination stops as ambiguous and requires restoring the protected
configuration from the rollback set. If a later independent installer gate stops after
generation `2` was recorded, retain the evidence and rerun without
`--migrate-database-identities`; the one-time option is deliberately rejected once the
local transition is complete.

Do not start an old Compose model after staging. Do not rename or delete either new
credential, and do not expose their values in shell output, logs or tickets.

## Provision and verify

Run the same exact installer normally, without the one-time flag:

```bash
./install.sh \
  --ref "${TARGET_COMMIT}" \
  --install-dir "$PWD" \
  --project-name backupsheep
```

`db-provision` connects over its dedicated internal bridge and applies one PostgreSQL
transaction. It marks this installation's roles, rejects pre-existing unmarked roles or
unsafe attributes/memberships, transfers reviewed ownership, applies grants/default
privileges and rotates both application-role passwords. `migrate` cannot run unless that
transaction commits; the app cannot run unless migration and the independent security
preflight both pass.

Verify all three one-shots and retain their exit codes in the change record:

```bash
./backupsheep-compose ps --all
./backupsheep-compose logs --tail=200 db-provision migrate preflight
```

The preflight connects as `DB_USER` and independently proves:

- the active role carries this installation's runtime marker;
- it has no superuser, create-role, create-database, replication or row-security-bypass
  attributes and no role memberships;
- the migrator owns the database and `public` schema;
- the runtime cannot create database/schema objects or temporary tables;
- all migrations are applied.

Keep operations stopped until the ordinary upgrade, recovery and provider-ownership
review is complete. The generation-2 foundation still uses one shared runtime DML role
for the web and worker lanes; per-lane table grants are a separate hardening phase.

## Failure and rollback

Provisioning errors are deliberately generic so connection diagnostics cannot disclose
credentials. Leave failed containers and volumes in place for evidence. First inspect
the bounded `db-provision`, `migrate` and `preflight` logs; do not repeatedly edit role
comments, grants or `.env` to force a pass.

If PostgreSQL provisioning never committed, restore `.env` and the entire `.secrets`
directory together from the verified recovery set before returning to the old release.
If it committed, use the recoverable `pgdata` snapshot plus its matching configuration
for the cleanest rollback. Do not delete the new roles or partially reassign ownership
in place. A logical database dump does not restore cluster-role attributes/passwords;
using it requires an independently reviewed role-reconstruction procedure.

After any rollback, prove the old app can authenticate, verify migrations and durable
work state, and keep provider operations disabled until reconciliation is complete.
