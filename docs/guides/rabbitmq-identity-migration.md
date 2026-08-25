# RabbitMQ identity and authenticated-task migration

Stock Docker generation 2 removes the shared broker login. The web app, preflight,
Beat, and each worker lane receive a distinct file-backed RabbitMQ password. Workers
have no configure permission and can read only their own fixed durable queue. The
broker topology is imported before any application role starts and the one-shot
provisioner deletes legacy/unknown users, reconciles exact permissions, authenticates
every credential, and fails on user, vhost, exchange, queue, binding, tag, permission,
or topic-permission drift.

Task authorization is a separate boundary. Each publishing lane has one Ed25519
private key; consumers receive only the installation-bound public-key registry. The
signed protocol-2 envelope binds task/id/retry, body and canvas, route, scheduling and
time-limit fields, lineage/stamps, audit headers, publisher, target, installation,
nonce, and issue time. Consumers reject unsigned, modified, cross-installation,
wrong-lane, or policy-invalid work before task code. The database replay ledger ignores
completed and conflicting deliveries. An exact broker redelivery of unfinished work is
accepted because workers use late acknowledgements; durable task-specific execution
fences remain the final idempotency boundary after a worker crash.

## Fresh installs

`install.sh` creates all passwords and Ed25519 keys under `.secrets`, writes the public
registry, and records both generation witnesses last. Do not populate these files or
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
3. Complete the [RabbitMQ 4.3 data migration](rabbitmq-upgrade.md) first if the existing
   data-generation witness is blank.
4. From the exact reviewed checkout, run the installer once with
   `--migrate-rabbitmq-identities`. If the database identity split is also pending, pass
   `--migrate-database-identities` in the same invocation. Do not enable operations on
   this run.
5. Wait for `rabbitmq-volume-init`, `rabbitmq-provision`, database provisioning,
   migrations, and security preflight to complete. Any partial `2-pending-*` witness,
   missing key, duplicate credential, legacy secret, or broker drift stops the install;
   restore the protected rollback before retrying if the cause is not understood.
6. Smoke-test one task per lane, then explicitly enable operations.

The legacy shared password is moved only to the bootstrap role during the transition.
It is never placed in environment variables or process arguments. The provisioner
hashes high-entropy per-role secrets locally and sends pre-hashed values over the local
Erlang control channel; application containers never mount bootstrap or another lane's
password/signing key.

## Fixed cross-lane handoffs

- web and Beat control publishers may dispatch reviewed routes;
- every worker may publish its own lane and `send_log_to_db` to logs;
- database/files may publish upload/finalization/local-restore handoffs to storage;
- storage may return only reviewed ciphertext-fence cleanup tasks to database/files;
- cloud may publish only reviewed recovery handoffs to database/files.

RabbitMQ exchange-write permission is slightly broader where a signed handoff is
required, but the target consumer verifies the exact publisher/task/target policy. No
worker can read or configure another lane's queue. Celery uses `no_declare` against the
precreated topology; an active queue/exchange declaration remains access-refused.

Never copy secret contents into support output. Safe evidence includes container UID,
the five zero capability fields in `/proc/1/status`, one successful provisioner exit,
the fixed user/permission/queue inventory, and one consumer per expected queue.
