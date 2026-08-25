# RabbitMQ identity and authenticated-task migration

Stock Docker generation 2 removes the shared broker login. The web app, preflight,
Beat, and each worker lane receive a distinct file-backed RabbitMQ password. Workers
have no configure permission and can read only their own fixed durable queue. The
broker topology is imported before any application role starts and the one-shot
provisioner deletes legacy/unknown users, reconciles exact permissions, verifies the
stored salted hash and algorithm for every file-backed credential without placing
plaintext in process arguments, and fails on user, vhost, exchange, queue, binding,
tag, permission, or topic-permission drift. Preflight and each real Celery consumer
then prove their own AMQP login when they connect.

Task-authorization generation 3 is a separate boundary. Each publishing lane has one Ed25519
private key; consumers receive only the installation-bound public-key registry. The
signed protocol-2 envelope binds task/id/retry, body and canvas, route, scheduling and
time-limit fields, lineage/stamps, audit headers, publisher, target, installation,
nonce, issue time, and a reviewed maximum expiry. Consumers reject unsigned, expired,
modified, cross-installation,
wrong-lane, or policy-invalid work before task code. The database replay ledger ignores
completed and conflicting deliveries. An exact broker redelivery of unfinished work is
accepted because workers use late acknowledgements; durable task-specific execution
fences remain the final idempotency boundary after a worker crash. The signed nonce
identifies one publication, so a durable recovery sweep can issue a newly signed
publication for the same reserved task id after broker loss without treating it as a
broker replay. A single source of
truth lists every production task, queue, permitted publisher, target lane, durable
intent resolver and maximum age. CI, Docker preflight, workers and Beat all compare
the configured routes and imported registry with that manifest and refuse drift; there
is no implicit/default task route.

Every fixed queue has broker-enforced `max-length=10000` and
`max-length-bytes=67108864` limits with `overflow=reject-publish`. Publisher confirms
surface a full queue instead of silently dropping an older backup/restore intent. The
one-shot provisioner applies this as an in-place policy, so upgrading does not delete or
redeclare a durable queue.

## Fresh installs

`install.sh` creates all passwords and Ed25519 keys under `.secrets`, writes the version-2
public registry at signing-key generation 1, and records the broker-identity and
task-authentication witnesses last. Do not populate these files or
witnesses manually. Long-running RabbitMQ starts directly as UID/GID `100:101` with an
empty capability bounding set. A non-networked, capability-free one-shot first verifies
the complete named-volume ownership, rejects symlinks/group-world-writable entries, and
creates an installation/data-generation-bound witness. RabbitMQ verifies that witness
again before reading its bootstrap secret.

Provider workers and Beat remain off unless the operator explicitly enables the
`operations` profile.

## Existing stock installs

Treat this as a maintenance-window credential and authorization migration, independent
from the RabbitMQ data-format upgrade:

1. Stop Beat and every provider worker. Let active work finish or confirm it is safely
   requeued from durable BackupSheep state.
2. Capture an encrypted, restorable backup of `.env`, `.secrets`, PostgreSQL, and the
   `rabbitmq_data` volume. Do not use `down --volumes`.
3. If the data-generation witness is blank, follow the coordinated
   [RabbitMQ 4.3 data migration](rabbitmq-upgrade.md). That runbook stages and then
   completes this identity transition after the 4.3 witness; do not run a competing
   identity-only command in parallel.
4. When the data witness is already `4.3`, run the exact installer once with all normal
   domain/project/KMS inputs plus `--migrate-rabbitmq-identities`. Also pass
   `--migrate-database-identities` and/or `--migrate-staging-layout` when those current
   gates are pending. Do not enable operations on this run.
5. Wait for `rabbitmq-volume-init`, `rabbitmq-provision`, `staging-provision`, database
   provisioning, migration, `db-seal` and security preflight to complete. Any partial
   `2-pending-*` witness,
   missing key, duplicate credential, legacy secret, or broker drift stops the install;
   restore the protected rollback before retrying if the cause is not understood.
6. Smoke-test one task per lane, then explicitly enable operations.

An installation that already has RabbitMQ identity generation 2 but
`BACKUPSHEEP_CELERY_SECURITY_GENERATION=2` needs a separate, explicit signing-key
rotation after its database recovery sweeps complete:

1. Run every durable recovery sweep on the old generation and wait for its outcomes.
2. Stop the web app, Beat and every worker. Keep the exact owned RabbitMQ container
   running and prove all six queues have zero ready and zero unacknowledged messages.
3. Preserve the database/broker/configuration recovery set, then run the verified
   installer with `--rotate-celery-signing-keys` and without `--enable-operations`.
4. The installer re-proves Compose ownership and broker identity, refuses a running
   publisher/consumer or non-empty/unreviewed queue, prepares all seven keys plus the
   registry, atomically replaces private keys first and the registry last, and publishes
   generation 3 only after validation. An interruption remains `3-pending-rotation`;
   rerun the same explicit command to activate the same candidates.

Use the same procedure for a later deliberate rotation. The registry's signing-key
generation increments, so every signature from the retired generation becomes invalid
immediately. Never rotate merely to clear messages: reconcile them from durable database
state first.

The legacy shared password is moved only to the bootstrap role during the transition.
It is never placed in environment variables or process arguments. The provisioner
hashes high-entropy per-role secrets locally and sends pre-hashed values over the local
Erlang control channel; application containers never mount bootstrap or another lane's
password/signing key.

## Explicit cross-lane handoffs

- web and Beat have no blanket control grant; each task names its permitted publishers;
- every worker may republish only tasks whose manifest entry includes that lane;
- database/files may publish upload/finalization/local-restore handoffs to storage;
- storage may return only reviewed ciphertext-fence cleanup tasks to database/files;
- cloud recovery may publish only the exact backup/restore routes backed by matching
  durable rows;
- destructive, restore, cleanup, managed-SSH and provider operations recompute a
  task-specific durable intent at publication and consumption.

RabbitMQ exchange-write permission is slightly broader where a signed handoff is
required, but the target consumer verifies the exact publisher/task/target policy. No
worker can read or configure another lane's queue. Celery uses `no_declare` against the
precreated topology; an active queue/exchange declaration remains access-refused.

Completed/retry replay rows are retained for at least the maximum seven-day signed
lifetime plus clock skew, then the logs lane deletes them in bounded batches. Active
rows are never pruned, so unfinished broker redelivery remains available.

Never copy secret contents into support output. Safe evidence includes container UID,
the five zero capability fields in `/proc/1/status`, one successful provisioner exit,
the fixed user/permission/queue inventory, and one consumer per expected queue.
