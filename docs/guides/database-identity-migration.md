# PostgreSQL identity generation 3

Stock Docker uses ten independently authenticated PostgreSQL logins. No web,
worker, scheduler, or preflight container receives another lane's password.

| Identity | Lifetime | Database authority |
| --- | --- | --- |
| Bootstrap | PostgreSQL plus `db-provision` and `db-seal` only | Bundled-cluster superuser required by the official initializer and the two transactional boundary phases |
| Migrator | `migrate` one-shot only | Non-superuser owner of the database, `public` schema, application relations, sequences and routines |
| App | Long-lived web | Control-plane DML needed by the console/API, without schema DDL, temporary tables, task-replay access, or migration writes |
| Preflight | One-shot gate | Read-only migration evidence and PostgreSQL catalogs needed to validate the complete boundary |
| Beat | Long-lived scheduler | Beat tables plus narrowly scoped scheduled-backup occurrence/outbox writes; no member, destination-configuration, source-worker, notification, or replay-row access |
| Cloud | Cloud/default worker | Explicit remote-provider tables and only cloud-scoped shared rows |
| Database | Database worker | Database source/backup/restore rows and database-scoped shared rows; no destination-configuration reads |
| Files | Files worker | Website and Basecamp source rows and files-scoped shared rows; no destination-configuration reads |
| Storage | Storage worker | Storage configuration, local artifact handoff, deletion and recovery rows; no user/session/token, source-auth, cloud-auth, notification-secret, or Beat tables |
| Logs | Logs worker | Run-log/notification delivery rows and bounded terminal replay cleanup |

All eight runtime identities are non-owners with no superuser, role creation,
database creation, replication, row-security bypass, schema creation, database
temporary-table, or role-membership authority. Exact table/column/sequence/routine
grants replace broad schema grants after every migration.

Row-level security separates shared ledgers that cannot safely be split into
different tables:

- Celery replay rows are restricted by `target_lane`; only logs may delete expired
  terminal rows.
- Artifact wrap/context and execution rows are restricted by source lane and content
  type.
- Managed-SSH operations are restricted by `source_lane`; database/files can update
  only worker-result columns, never immutable intent columns, and no runtime role
  can delete proof rows directly. A lane-authenticated security-definer retention
  routine clamps retention to 7–365 days and batch size to 1–500; it never removes
  the newest successful validation for a connection's current generation.
- The app/database/files-only single-account predicate counts accounts outside the
  caller's RLS view. A second account therefore disables and fences installation-
  managed SSH globally and cannot be hidden from one source lane by row filtering.
- Shared connection rows are restricted by integration type. Database/files may
  update only validation status, and database may update only the reviewed database
  type/version metadata columns.
- Every local backup destination through row is storage-owned. Database/files have
  SELECT-only access to the non-secret point id and authorization witness and have no
  privilege on any `core_storage*` table. A source task first commits its concrete
  backup, stops before source/provider access, and asks storage to validate the
  frozen destination selection. Storage commits the accepted-point witnesses before
  republishing the stable source task. The storage and source recovery sweeps repair
  either broker/crash gap; missing or forged source metadata never opens the gate.

The policy is an exact inventory. A new or missing application table, routine,
trigger, RLS expression, privilege, default ACL, owner, role marker, or connection
limit causes `db-seal` or preflight to fail closed.

## Scope

Fresh verified installs create generation 3 automatically. This runbook covers an
existing stock Docker database on generation 2 or the older shared-superuser model.
It does not automatically rewrite identities for external/managed PostgreSQL or a
deployment using `DATABASE_URL`; that operator owns its roles and equivalent grants.

The provisioner accepts only the reviewed stock database shape: application objects
in `public`, the expected Django tables/routines/triggers, and ownership by the marked
bootstrap/migrator identities. Custom schemas, extensions, standalone types,
unsupported relation kinds, unmarked role collisions, unsafe attributes, or unknown
objects stop the migration. Review those objects manually; never weaken the inventory
or edit an installation marker to bypass it.

## Before the change

Identity conversion changes durable cluster roles, ownership, passwords, ACLs and
RLS. Before starting:

1. Pin the exact current and target commits and complete the normal
   [upgrade ownership checks](upgrades.md#before-the-change).
2. Stop the app, every worker and Beat. Prove that no application database sessions
   or broker consumers remain.
3. Create and restore-test an encrypted off-host recovery set containing a PostgreSQL
   custom dump, a recoverable `pgdata` snapshot, `.env`, the complete `.secrets`
   directory, approved Compose overrides, exact Git commit and image IDs. A logical
   dump does not contain cluster roles and is not sufficient by itself.
4. Confirm the old database/user and Compose project are the intended installation.
   Never copy a password or generation witness from another installation.

## Stage the transition

Run the verified installer with the explicit database migration flag and all normal
installation/KMS arguments. `--skip-start` is useful for a change-review pause:

```bash
TARGET_COMMIT='<40-character-reviewed-release-commit>'
CURRENT_DOMAIN='<existing-public-hostname>'
KMS_KEY_ARN='<resolved-symmetric-kms-key-arn>'
KMS_REGION='<aws-region>'
KMS_ALLOWED_KEY_ARNS="${KMS_KEY_ARN}"
KMS_DATABASE_CREDENTIALS='<canonical-private-database-lane-credentials-file>'
KMS_FILES_CREDENTIALS='<different-canonical-private-files-lane-credentials-file>'
./install.sh \
  --ref "${TARGET_COMMIT}" \
  --install-dir "$PWD" \
  --project-name backupsheep \
  --domain "${CURRENT_DOMAIN}" \
  --migrate-database-identities \
  --artifact-kms-key-id "${KMS_KEY_ARN}" \
  --artifact-kms-region "${KMS_REGION}" \
  --artifact-kms-allowed-key-arns "${KMS_ALLOWED_KEY_ARNS}" \
  --artifact-kms-database-aws-credentials-file "${KMS_DATABASE_CREDENTIALS}" \
  --artifact-kms-files-aws-credentials-file "${KMS_FILES_CREDENTIALS}" \
  --skip-start
```

The local stage:

- preserves the current bootstrap credential and migrator credential where present;
- creates distinct random credentials for app, preflight, Beat, cloud, database,
  files, storage and logs;
- writes fixed per-lane role names and keeps `DB_USER` as the app compatibility alias;
- records `3-pending-upgrade` (or `3-pending-fresh`) before a new secret can appear;
- accepts only the exact ordered resumable secret prefix; and
- deliberately leaves the generation pending when startup is skipped.

A pending deployment cannot start a long-lived lane: database runtime validation
requires completed generation 3. For an interrupted existing-install transition,
preserve evidence and rerun with `--migrate-database-identities`. Do not manually set
the marker to `3`, remove a pending secret, or start an older Compose model.

## Seal and promote

Run the same installer without `--skip-start`; keep the migration flag while an
existing-install transition remains pending:

```bash
./install.sh \
  --ref "${TARGET_COMMIT}" \
  --install-dir "$PWD" \
  --project-name backupsheep \
  --domain "${CURRENT_DOMAIN}" \
  --artifact-kms-key-id "${KMS_KEY_ARN}" \
  --artifact-kms-region "${KMS_REGION}" \
  --artifact-kms-allowed-key-arns "${KMS_ALLOWED_KEY_ARNS}" \
  --artifact-kms-database-aws-credentials-file "${KMS_DATABASE_CREDENTIALS}" \
  --artifact-kms-files-aws-credentials-file "${KMS_FILES_CREDENTIALS}" \
  --migrate-database-identities
```

Startup is intentionally two phase:

1. Provider workers and Beat remain stopped.
2. `db-provision` creates/rotates marked roles, transfers reviewed ownership, revokes
   public/default/runtime access, retires the marked generation-2 runtime and exits.
3. `migrate` runs only as the non-superuser owner.
4. `db-seal` inventories the migrated schema, applies exact ACLs and RLS, and
   records installation-bound policy witnesses.
5. Only after `db-seal` exits zero does the installer remove the retired shared
   password and atomically promote `.env` to generation `3`.
6. Preflight connects as the unprivileged preflight role and validates the complete
   catalog contract before the web service can start.
7. Every long-lived worker repeats the image/schema check before accepting work. Its
   only additional schema-version privilege is `SELECT` on `django_migrations`; the
   seal does not broaden any other table or sequence grant.

An interruption before step 5 leaves the durable marker pending. An interruption
after step 5 is safe because `db-seal` has committed, and Compose still requires
preflight to succeed before app/workers/Beat.

Retain these bounded logs and one-shot exit codes in the change record:

```bash
./backupsheep-compose ps --all
./backupsheep-compose logs --tail=200 db-provision migrate db-seal preflight
```

The release test suite also provisions a fresh PostgreSQL instance, applies all
migrations, seals the policy and runs direct adversarial connections. It proves
cross-lane reads/writes, Beat mutation, DDL, schema creation, temporary tables, role
elevation, replay crossover, source reads of every destination credential table,
source rewrites of storage-owned authorization witnesses, and immutable managed-SSH
intent rewrites are denied. Authenticated database/files sessions additionally prove
that direct proof deletion fails and bounded retention cannot erase the current
validation witness or another lane's rows.

Keep operations stopped until ordinary recovery and provider-ownership review is
complete. Then start operations only through the reviewed wrapper and explicit
operations profile.

## Failure and rollback

Leave failed containers and volumes in place for evidence. Inspect only the bounded
one-shot logs; do not repeatedly edit role comments, grants, RLS policies, `.env`, or
secret files to force a pass.

If provisioning did not commit, restore `.env` and the complete `.secrets` directory
together before returning to the old release. If provisioning/sealing committed, the
clean rollback is the matching recoverable `pgdata` snapshot plus its configuration.
Do not delete new roles or partially reassign ownership in place. A logical dump needs
an independently reviewed cluster-role reconstruction procedure.

After rollback, prove old application authentication, migrations and durable work
state, and keep provider operations disabled until reconciliation completes.
