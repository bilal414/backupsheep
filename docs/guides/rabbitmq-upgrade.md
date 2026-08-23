# RabbitMQ 3.13 to 4.3 migration gate

The stock Compose target is the digest-pinned RabbitMQ 4.3.5 image. That target is safe
for a fresh volume, but **must not be started directly against an existing 3.13 volume**.
RabbitMQ's supported path is 3.13.x to 4.2.x, enable all feature flags, then 4.3.x.

`RABBITMQ_DEFAULT_USER`, `RABBITMQ_DEFAULT_PASS` and `RABBITMQ_DEFAULT_VHOST` initialize
only a blank broker database. Changing `.env` does not create or rotate credentials in an
existing `rabbitmq_data` volume. For that reason, `install.sh` refuses to replace legacy
bundled-broker credentials in an existing `.env`; complete this operator-run migration
first.

## Required upgrade sequence

Schedule a maintenance window and stop if any gate cannot be proven:

1. Record the current image ID/version, node health, enabled feature flags, users, vhosts,
   queue names, durable flag, ready/unacknowledged message counts and consumer counts.
2. Stop Beat from scheduling new work, stop producers, and let workers finish or safely
   requeue their in-flight jobs. Export broker definitions and take a recoverable snapshot
   of the `rabbitmq_data` volume. Do not use `docker compose down --volumes`.
3. While still on 3.13, create the dedicated `backupsheep` user and `backupsheep` vhost
   through a trusted server console, grant that user configure/write/read permissions only
   on that vhost, update the mode-0600 `.env`, and verify all app roles reconnect. Do not
   put the password in documentation, tickets or unattended logs.
4. On 3.13, enable every stable feature flag and confirm the node is healthy. Resolve any
   disabled/deprecated feature before continuing.
5. Start the compatibility image using the reviewed overlay:

   ```bash
   docker compose \
     -f docker-compose.yml \
     -f deploy/rabbitmq/upgrade-4.2.9.compose.yml \
     up --detach --no-deps rabbitmq
   ```

   Confirm it reports RabbitMQ 4.2.9, then enable every stable 4.2 feature flag. Re-run
   the node, vhost, permission, durable-queue, message and consumer evidence checks. Take
   another recoverable volume snapshot.
6. Remove the temporary overlay from the command and start the pinned 4.3.5 target:

   ```bash
   docker compose up --detach --no-deps rabbitmq
   ```

   Enable every stable 4.3 feature flag and repeat the same evidence checks before
   restarting Beat/producers. Run a scheduled-backup smoke test and verify one durable
   request, one broker delivery and one terminal backup result.

If a hop fails, stop and restore the volume snapshot with the exact prior image. Do not
attempt a downgrade against a data directory already migrated by a newer RabbitMQ release.
