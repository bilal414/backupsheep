# Installation

BackupSheep runs as a hardened Docker Compose stack. The canonical, maintained
instructions are in the [verified installation guide](guides/installation.md).

## Security boundary

The BackupSheep installer manages only its application checkout, configuration, secret
files, images, containers, networks and named volumes. It does **not** install Git or
Docker, add package repositories, enable or restart services, edit Docker daemon
configuration, open a firewall, change kernel settings, create host users, or require
root. The host operator must provide and secure:

- Git and Bash;
- Docker Engine 28.0.0 or newer;
- Docker Compose 2.33.1 or newer;
- access to the intended Docker daemon;
- a user-owned installation path and sufficient CPU, memory and storage;
- host/network/TLS policy, monitoring, patching and recovery.

## Verified installer

Download the installer from the exact release commit you intend to run. Never pipe a
mutable remote script into a privileged shell:

```bash
COMMIT='<40-character-reviewed-release-commit>'
KMS_KEY_ARN='arn:aws:kms:us-east-1:123456789012:key/<reviewed-key-id>'
KMS_REGION='us-east-1'
KMS_DATABASE_CREDENTIALS='/absolute/protected/kms-database.credentials'
KMS_FILES_CREDENTIALS='/absolute/protected/kms-files.credentials'
curl -fSLo install.sh \
  "https://raw.githubusercontent.com/bilal414/backupsheep/${COMMIT}/install.sh"
less install.sh
chmod 700 install.sh
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com \
  --artifact-kms-key-id "${KMS_KEY_ARN}" \
  --artifact-kms-region "${KMS_REGION}" \
  --artifact-kms-allowed-key-arns "${KMS_KEY_ARN}" \
  --artifact-kms-database-aws-credentials-file "${KMS_DATABASE_CREDENTIALS}" \
  --artifact-kms-files-aws-credentials-file "${KMS_FILES_CREDENTIALS}"
```

The KMS credential inputs must be distinct canonical, user-owned mode-`0400`/`0600`
files for separate database/files AWS identities with matching encryption-context policy.

Run it as the same unprivileged user that is already authorized for the intended Docker
daemon. The installer refuses root and `sudo`; it does not provision or reconfigure the
host.

The installer fetches that exact commit from the canonical HTTPS repository, verifies
the checkout and its own bytes, creates protected file-backed secrets, explicitly builds
commit-tagged application, PostgreSQL and namespace-guard images, and starts only the core
database/broker, provision/migrate/seal/preflight gates, app guard and web UI. The web
listener stays on `127.0.0.1:8000`.
Application, PostgreSQL and egress-guard roles use `pull_policy: never`; the installer will
not substitute registry images if a reviewed local build is missing. The PostgreSQL build
starts from the digest-pinned official PostgreSQL 18.6 Alpine 3.24 image, verifies the
official entrypoint, installs exact `su-exec=0.3-r0`, replaces and deletes `gosu`, and
declares UID/GID `70:70`. Stock Compose starts it directly as that user with every Linux
capability dropped and an installation-bound ICU/storage-generation witness. Existing
Debian `pgdata` requires the explicit
[Alpine/ICU logical migration gate](guides/postgres-runtime-migration.md); the Alpine
image never mounts or auto-adopts that volume.

It also creates a stable random 64-hex installation ID and an empty labeled sentinel
volume, then verifies Compose resource ownership before mutation. It enumerates every
exact project network/volume name and rejects an unlabeled or foreign collision rather
than letting Compose adopt it. A project-name collision, foreign/missing ownership
evidence or ambiguous legacy resource fails closed. Existing RabbitMQ data is accepted
only with the installer-owned `4.3` generation witness or exactly one running, healthy
project broker. A blank witness on existing data requires the explicit wrapper migration
or reconciliation path so the pinned image and Khepri state are attested; the installer
never guesses at or migrates a 3.13/4.2 data directory.

An old stock deployment that was taken down before identity sentinels existed may have
only its four labeled data volumes left. Use the guarded one-time
`--adopt-legacy-project NAME` workflow in the
[verified installation guide](guides/installation.md#one-time-legacy-compose-down-adoption).
It accepts no containers, networks, extra project-prefixed volumes, newer volume names
or label drift, creates and re-inspects only the identity sentinel, and leaves the
ordinary ownership checks intact. Do not simulate adoption by editing `.env` directly.

When exact-path legacy containers are still present, the installer automatically creates
that sentinel only after the complete container, network and volume inventory passes its
exact path/model/service/logical-name/physical-name and blank-identity checks. The wrapper
uses the matching sentinel to permit those immutable blank container labels only until
the reviewed Compose commands recreate them; foreign or partial identities still fail
closed.

Development staging layout v2 was prerelease-only. Its canonical project-owned
`ssh_trust` volume may pass the ordinary exact ownership/name/label checks, but it is
preserved detached as rollback evidence during the explicit v3 migration. Layout v3 has
no shared trust mount, group or provisioning path, and the wrapper rejects every
`--volume` override. The retired global host-key inventory is never imported; operators
must reapprove each exact account/host/port/key in the PostgreSQL ledger. A foreign or
ambiguous legacy trust volume fails closed.

Provider workers and the scheduler are intentionally disabled by default. Review
credentials and durable recovery/queue state before explicitly enabling operations:

```bash
./install.sh \
  --ref "${COMMIT}" \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --domain backups.example.com \
  --artifact-kms-key-id "${KMS_KEY_ARN}" \
  --artifact-kms-region "${KMS_REGION}" \
  --artifact-kms-allowed-key-arns "${KMS_KEY_ARN}" \
  --artifact-kms-database-aws-credentials-file "${KMS_DATABASE_CREDENTIALS}" \
  --artifact-kms-files-aws-credentials-file "${KMS_FILES_CREDENTIALS}" \
  --enable-operations
```

This opt-in can execute queued or recoverable provider work. The installer never
performs an in-place source upgrade and never deletes containers or volumes as an
automatic rollback.

## Secrets

The installer writes `.env` as mode `0600` and `.secrets` as a mode `0700` directory.
The Django key, database bootstrap/migrator/per-lane passwords, RabbitMQ
bootstrap/per-lane passwords, task-signing material, KMS lane credentials and onboarding
token are separate mode-`0444` files inside it. Directory traversal protection keeps them
private on the host while Docker mounts each individual file read-only only in its granted
role. Their direct `.env` keys remain blank, so values do not appear in Compose-expanded
configuration or container inspection.

Optional `.secrets/ssh_managed_database_private_key` and
`.secrets/ssh_managed_files_private_key` files follow the same host mode; leave both empty
to disable managed identities. The database key is mounted only in `worker-database`, and
the files key only in `worker-files`; the app and other roles receive neither. The
entrypoint validates each non-empty Ed25519 key, copies the lane's source to private tmpfs
at `/run/backupsheep/ssh/managed_private_key` with mode `0600`, and never points SSH at the
mode-`0444` source. The two identities must be distinct and are supported only while the
installation has exactly one account. Multi-account deployments use customer-supplied
private keys. Existing installations must follow the explicit legacy-identity retirement
and host-key reapproval procedure in the [upgrade guide](guides/upgrades.md).

Retrieve the onboarding token only from the trusted host shell:

```bash
cd "$HOME/.local/share/backupsheep"
cat .secrets/onboarding_token
```

Then use an SSH tunnel to reach the loopback listener and complete first-run setup. See
the [production deployment guide](deployment.md) before exposing the service publicly.
Warning-level HTTPS findings from Django's deployment check are expected only in this
deliberate loopback HTTP/SSH-tunnel mode. Public access requires real TLS,
`DJANGO_HTTPS=true`, `APP_PROTOCOL=https://`, the exact public domain/allowed hosts, and
review of every deployment warning.

Every application-image command passes through the hardened entrypoint, which neutralizes
startup-loader hooks, verifies the runtime boundary and repeats the deployment preflight
before web, worker and Beat processes. Automatic restarts therefore do not rely only on a
previous one-shot preflight result, and any unapplied Django migration stops startup.
