# BackupSheep Docker and container cyber-defense assessment

**Assessment window:** 2026-08-23 through 2026-08-25 UTC
**Repository:** `bilal414/backupsheep`
**Original evidence branch/commit:** `codex/security-hardening-20260823` / `7be0729374e61558740f7a564248a7c4491049be`
**Current candidate branch/PR:** `codex/security-enterprise-blockers-20260825` / [PR #73](https://github.com/bilal414/backupsheep/pull/73)
**Historical demo deployment:** `demo.backupsheep.com`, project `backupsheepsecure`, evidenced at `7be0729...`
**Historical deployment mode:** core only; all provider workers and Celery Beat stopped
**Review boundary:** repository-supplied images, Compose topology, installer, wrapper,
entrypoint, secret loading, startup checks, and application changes required to make
those boundaries trustworthy

> **Current-repository follow-up, 2026-08-25:** The commit, image digests, 2,298-test
> run, scans and demo observations below remain an immutable evidence snapshot for
> `7be0729...`. The current working tree subsequently implemented BSE1 chunked
> AES-256-GCM-SIV artifact envelopes with an AWS KMS integration/policy contract,
> private per-lane staging and ciphertext-only handoffs, generation-3 database/task
> identities, and namespace egress guards. It also hardened the CodeQL-reported
> credential-output, temporary-file and public exception-message paths. Those
> follow-up changes are **not** covered by the old digests, scan counts, demo state or
> regression count.
> The current [PR checks](https://github.com/bilal414/backupsheep/pull/73/checks) are the
> repository gate; protected signed publication, deployed topology inspection and
> provider backup/restore/chaos proof remain separate operational gates.
> The current egress-guard candidate now uses digest-pinned official Alpine 3.22.5
> (`sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce`)
> for both build and runtime stages. A fresh no-cache Trivy candidate scan reported zero
> High/Critical findings. The earlier Alpine 3.22.2 candidate result (17 High and 2
> Critical fixed CVEs) is retired, not current release evidence; the next exact-release
> scan and published provenance remain authoritative.
> The application-image follow-up also replaces the vulnerable Debian runtime with a
> digest-pinned Ubuntu 26.04 runtime, installs an authenticated package closure offline,
> removes Pebble, Perl and `pip`, and preserves exact source/binary provenance for the
> minimal MariaDB dump client. The 2026-08-25 no-cache arm64 candidate and current
> Trivy database reported zero High/Critical matches. This is candidate remediation
> evidence, not a zero-vulnerability or released-multi-architecture claim; Canonical
> still has relevant 26.04 issues in `Needs evaluation`, as detailed below.

## 2026-08-25 predecessor local candidate evidence (`0e76142`)

This section is a non-demo predecessor evidence cut for implementation commit
`0e76142...`. It does not rewrite the historical `7be0729...` deployment record and it
is not a signed release claim. The locally scanned application runtime's Python source
matched that implementation tree byte for byte. Later CodeQL remediations changed
application source, and the bounded-DNS reconciliation fix changed the egress image, so
the app/egress identities below are retained only as predecessor evidence. The current
PR's native-amd64 rebuild, scans and tests are authoritative for the merge candidate;
the protected multi-architecture release workflow remains authoritative for publication.

The release-candidate gate now saves each locally built image by its immutable Docker
ID, verifies the Docker/OCI archive descriptor chain from the outer index to the exact
config, and then requires both Syft and Trivy to identify that config and the same
archive path. A swapped archive, swapped scanner ID/path, multiple-image archive,
descriptor traversal, cyclic/oversized graph or content/digest mismatch fails closed.
The validator accepts only Syft 1.51.0/schema 16.1.10 and Trivy 0.74.0/schema 2,
recomputes Trivy's tag-context artifact identity, independently matches its config
image ID, and requires exact cross-scanner OS package-name parity. A scanner/schema
upgrade therefore fails closed until reviewed. No ignore file, ignored-unfixed
relaxation or vulnerability allowlist was used.

| Image | Docker outer ID | Archive config ID | Archive SHA-256 | Syft packages | Trivy packages | High/Critical |
| --- | --- | --- | --- | ---: | ---: | ---: |
| Application | `sha256:f74c087440e6d7b0af8b4eff0e21f92c0713c8f80d581279cdb0b10282a6e8b1` | `sha256:20334bdbe6f7df2889b17d7b76f7a4d93fe2e6fe11dcb5fc5d5b09dff09e62bf` | `8b10b40493b14b9feca8a358872651a2f3dc98704e66055cb0147cc4b06daa3c` | 279 | 270 | 0 |
| PostgreSQL | `sha256:1cb6ad4fca79e4632ec2c327dfcb5a4563e732f68e1c331c71bb1252d2ec78cc` | `sha256:c0b3e3ac548276f3c9076002195648ad949278261502954116bbb8dc8d7b261c` | `45028fda4cb978c4a3a37812a94dbaef40ce555a3c2c43c9c1b36b3528ca42c0` | 55 | 54 | 0 |
| Egress guard | `sha256:49b0a02814e44c84a65f3058a63ba17f9f5b98bd8487d2391509ea748fe8b46e` | `sha256:f2af23dda1a317c706cee7607c7cb7d8013bdd6ec27d7f06f000a9affa348d6b` | `fb931fd1c55f557d11ac903d43555959b72dbe51b6b02e2ef42afe02750c5aab` | 30 | 30 | 0 |

The predecessor candidate runtime passed **2,667 tests in 395.261 seconds** with one
intentional provider-harness skip. A concurrency test also passed ten consecutive
isolated repetitions after its Celery thread-local proxy was replaced by one explicit
test app; the complete ordered run then passed the former failure point. Bruno coverage
validated 920 API operations plus one health operation across 528 paths and 921 request
files. Enterprise documentation validated the same 921 operations and 289 configuration
variables. The focused installer/wrapper, topology, deployment/image, release and static
policy contracts also passed.

The production-like local topology passed generation-3 database provisioning and
sealing, authenticated per-lane RabbitMQ access, real preflight, healthy web/worker
startup, default-deny egress, guard-loss and lease-expiry attacks, unhealthy fencing and
paired recovery. The complete egress attack harness passed. PostgreSQL logical migration
passed first run, forced interruption and receipt/marker recovery, restart, rollback,
ICU verification, schema/data/role hashes, row verification and secret/helper cleanup.
All temporary containers, networks and volumes from those gates were removed by exact
owned identity.

The Compose project-name fix is covered across installer, wrapper, PostgreSQL migration
and CI cleanup. The project name is persisted and exact-matched under the C locale;
duplicate/ambient overrides, option-shaped names, malformed or NUL-bearing environment
files and hostile locale behavior are rejected. Security-sensitive Docker labels use
bounded byte-length plus terminal-sentinel framing and reject control bytes, embedded
marker tricks and shell newline/NUL normalization before any mutation.

### Current pull-request evidence gate

The candidate closes the known repository-owned Docker, installer, workflow and static-
analysis blockers only when the current PR head has green GitHub Advanced Security
CodeQL, both language analyses, pinned Bandit/source scanning, dependency/deployment
checks, exact native-amd64 image scans, the full application suite and the production-
topology/egress attack gates. The PR's successful evidence artifacts, not the predecessor
image table above, bind those checks to the exact head under review.

Those repository checks do not close protected signed multi-architecture publication,
fresh-host or demo deployment, production KMS/IAM custody and denied cross-lane calls,
or live provider backup/restore/chaos acceptance. The historical Google API credential
incident below also remains open until provider-side revocation is proven.

## Executive decision

At the original evidence cut, BackupSheep had a strong secure-by-default Docker
baseline. The `7be0729...` demo ran the application as UID/GID `10001:10001` and
PostgreSQL as `999:999` on healthy exact commit-tagged images. The web process was
capability-free, read-only, bounded by CPU/memory/PID limits, isolated from the Docker
socket and backup work volume, and exposed only on host loopback. RabbitMQ and
PostgreSQL published no host ports, core secrets were file-backed, and provider-mutating
workers and the scheduler remained stopped.

The current candidate changes PostgreSQL to direct UID/GID `70:70` on the digest-pinned
Alpine/ICU runtime without `gosu`, and adds BSE1, per-lane identities/staging and guarded
egress. Those controls have local and pull-request gates but have not replaced the
historical demo deployment. Its earlier Debian/UID-999 volume is accepted only by the
explicit logical migration gate and remains detached rollback evidence.

The result passed a clean 2,298-test regression run, two independent image scanners,
source/secret/config scanning, adversarial container checks, migration/startup
preflight, and a rollback-protected demo rollout. No fixable High/Critical finding was
reported in the exact application or PostgreSQL runtime payload by either scanner.

This is not an “attack-proof” or enterprise-certified result. No defensible review can
promise that. The current repository materially improves the original evidence cut: it
now implements authenticated per-backup encryption, an external KMS integration/policy
contract, per-lane filesystem/database/broker identities and guarded egress.
Enterprise approval is still conditional on exact-release validation and the residual
gates below. A compromised
source lane can still read the plaintext it must back up, a broadly permitted outbound
policy can still exfiltrate that lane's data, and a host/Docker-daemon compromise remains
outside the container boundary.

### Status summary

| Area | Result | Decision |
| --- | --- | --- |
| Application image containment | Candidate-gated | Strong non-root immutable baseline; historical live and current PR evidence remain distinct |
| PostgreSQL image containment | Candidate-gated | Current fixed UID/GID 70, zero capabilities, read-only root and authenticated probe; demo still historical UID 999 |
| RabbitMQ containment | Pass in repository integration | UID/GID 100:101, all capability sets zero, witness-gated volume, per-lane identities; demo redeploy still required |
| Compose topology | Pass | Loopback web publication, no DB/broker host ports, role-specific internal networks, operations opt-in |
| Installer/update safety | Pass in tests; demo exception documented | Exact commit, no host provisioning, fail-closed ownership/collision/generation checks |
| Runtime secrets | Pass with residual | Values absent from direct env; a compromised granted process can still read its mounted files |
| Supply chain | Candidate-gated | Pinned/verified CI inputs and strict findings policy; signed publication remains pending |
| Regression suite | Candidate-gated | 2,298 historical demo tests; 2,667 predecessor-candidate tests; current PR full-suite check is authoritative |
| Historical demo core rollout | Pass at `7be0729...` | App/DB/Rabbit healthy, preflight passed, queue preserved, operations stopped; current candidate not deployed |
| Provider operations and restores | Held | Not enabled or treated as proven by this Docker review |
| Backup application-layer encryption | Local candidate pass; operational proof pending | BSE1 AES-256-GCM-SIV and AWS KMS policy/custody require signed-release and live restore proof |
| Private staging and ciphertext handoff | Local candidate pass; deployment proof pending | Per-lane work volumes and fenced forward/reverse transfers passed local cross-UID gates; repeat on exact deployment |
| Database/broker lane identity | Local candidate pass; deployment proof pending | Generation-3 database roles and signed broker task contracts passed local gates; exact rollout evidence remains required |
| Container egress policy | Implemented with residual | Generation-2 deny default, exact DB/broker and outward TCP tuples, split strict DNS boundary; same-IP/same-port shared tenancy and deployment-specific NAT64 remain residuals |

## Scope and responsibility boundary

This assessment owns:

- [`Dockerfile`](../../Dockerfile), [`Dockerfile.postgres`](../../Dockerfile.postgres),
  [`.dockerignore`](../../.dockerignore), and dependency/build inputs;
- [`docker-compose.yml`](../../docker-compose.yml), service profiles, networks, mounts,
  secrets, limits, health checks, and log bounds;
- [`install.sh`](../../install.sh) and [`backupsheep-compose`](../../backupsheep-compose);
- [`init.sh`](../../init.sh),
  [`runtime_secrets.py`](../../backupsheep/runtime_secrets.py), and
  [`docker_preflight.py`](../../apps/management/commands/docker_preflight.py);
- application behavior necessary to make the container boundary safe, including
  transport policy, command execution, destructive-worker routing, durable leases,
  request hardening, authorization, and secret-safe task contracts.

As requested, the stock installer does **not** install Docker, edit the firewall,
change sysctls, create host users, modify daemon configuration, install a reverse
proxy, issue certificates, or otherwise assume host administration. It requires a
supported Docker Engine and Compose plugin, an unprivileged user already authorized
to use the selected daemon, and a user-owned installation directory.

The following remain the operator's host responsibility:

- kernel, operating-system, Docker Engine, container runtime, and firmware patching;
- rootless Docker or daemon user-namespace configuration;
- host firewall, reverse proxy, TLS certificates, DNS, AppArmor/SELinux, auditd,
  disk encryption, storage quotas, backups of Docker state, and physical security;
- protecting Docker daemon access. Docker socket or `docker`-group access is
  effectively host-root authority and is not a security boundary this image can
  defend against.

## Threat model

The review assumed an attacker could:

1. exploit an internet-facing BackupSheep route and execute code as the web process;
2. steal or forge a browser/API credential and probe tenant, member, node, backup,
   restore, notification, and connection authorization boundaries;
3. poison a checkout, mutable Git reference, build context, dependency, base image,
   environment file, loader hook, or Compose control variable;
4. inspect container metadata, logs, process environment, mounted files, and networks;
5. attempt filesystem persistence, privilege escalation, Docker-socket access,
   cross-role movement, task forgery, arbitrary egress, and resource exhaustion;
6. supply hostile archive members, paths, redirects, hosts, filenames, database
   identifiers, or FTP/SFTP/FTPS endpoints;
7. crash a job before or after database commit, broker publication, provider request,
   artifact write, deletion, or terminal-state recording;
8. compromise PostgreSQL, RabbitMQ, a destination, or Local Storage without first
   escaping to the host.

The highest-impact path is web or broker compromise to a privileged execution lane,
then provider credential abuse, backup exfiltration, restore tampering, or destructive
provider action. Docker containment reduces that blast radius; it does not replace
tenant authorization, durable occurrence records, provider ownership witnesses, or
authenticated backup cryptography.

## Implemented controls

### Image and build chain

- The Dockerfile frontend and every base image are digest-pinned.
- Python runtime dependencies are installed from a hash-locked file with
  `--require-hashes`; unreviewed resolution cannot silently enter the final image.
- PostgreSQL clients, MySQL client artifacts, Ubuntu/Debian packages, repository keys, and
  downloaded inputs are version-, checksum-, signature-, and/or fingerprint-checked.
- `.dockerignore` is default-deny. Only reviewed runtime inputs enter the context;
  `.env`, `.secrets`, Git metadata, tests, private keys, cloud configuration, dumps,
  databases, logs, and new unreviewed top-level files are excluded.
- Multi-stage builds keep compilers, headers, Git, Make, curl, GPG, package indexes,
  and `pip` out of the final application image.
- Runtime source is root-owned and mode `0444/0555`. Symlinks and hard-linked runtime
  files are refused; setuid/setgid bits are cleared and verified absent.
- Static assets are collected during the build, allowing the runtime root and source
  trees to remain read-only.

### Application runtime

- The current Compose model uses fixed primary UID/GID identities per trust lane: web
  `10001`, database `10002`, files `10003`, storage `10004`, logs `10005`, Beat `10006`,
  migration/preflight `10007`, and cloud `10008`. The image entrypoint rejects a role/
  identity mismatch.
- All Linux capabilities are dropped; `no-new-privileges`, Docker's seccomp filter,
  private PID/IPC/cgroup namespaces, Docker init, and disabled core dumps are enforced.
- The immutable entrypoint checks its effective identity, all capability sets,
  `NoNewPrivs`, seccomp, Docker init, absence of the Docker socket, required mounts,
  tmpfs flags, and finite cgroup ceilings before starting application code.
- Root filesystem, `/code`, `/etc`, and the image's empty `/backups` path are immutable
  to the web role. Only bounded `noexec,nosuid,nodev` tmpfs and specifically granted
  volumes are writable.
- The web container has no work, transfer, Local Storage or SSH-trust mount. Only the
  storage lane receives `backup_storage` at `/backups`, read/write. Account-scoped SSH
  approvals and append-only audit events live in PostgreSQL; source workers materialize
  exact per-operation trust only in private runtime.
- CPU, memory, PID, no-file, shared-memory, tmpfs, shutdown, and JSON log rotation
  limits are explicit per role. The entrypoint independently rejects missing,
  unlimited, or implausibly large CPU/memory/PID cgroup values.
- No Docker socket, host namespace, privileged mode, device, or host filesystem mount
  is part of the stock topology.

### PostgreSQL and RabbitMQ

- PostgreSQL uses a custom image with fixed `USER 70:70`, `cap_drop: [ALL]`,
  read-only root, `no-new-privileges`, private namespaces, and bounded resources.
- The custom PostgreSQL image verifies the upstream entrypoint before replacing
  `gosu` with pinned `su-exec`; `gosu` is then removed. The live process has all
  capability sets at zero and data checksums enabled.
- PostgreSQL and RabbitMQ publish no host ports and are reachable only on explicit
  role-specific internal networks.
- RabbitMQ is digest-pinned to `4.3.5-alpine`, uses an authenticated health check,
  has bounded resources and logs, and runs `beam.smp` as UID `100`, GID `101`.
- The hardened repository starts RabbitMQ directly as UID/GID `100:101`; integration
  proof showed inherited, permitted, effective, bounding, and ambient capability sets
  all zero, with `NoNewPrivs=1` and seccomp mode 2. A non-networked, capability-free
  one-shot validates the complete volume ownership and an installation/generation
  witness before the server starts. This evidence is not a claim that the demo has
  already been redeployed.
- RabbitMQ data-generation fencing prevents a 4.3 image from guessing at a legacy
  3.13/4.2 volume. The installer/wrapper require exact state witnesses and the
  documented Khepri transition path.
- Current database identity generation 3 separates bootstrap, schema-owning migrator,
  app, preflight, Beat and five worker logins. Exact grants, column restrictions and
  row-level policies replace the earlier shared runtime DML identity; `db-seal` and
  preflight refuse catalog, ownership, role or policy drift.
- RabbitMQ identity generation 2 gives every publisher/consumer a separate password and
  fixed queue ACL. Task-authorization generation 3 separately signs the complete Celery
  protocol envelope with per-publisher Ed25519 keys, a target-lane policy manifest and a
  durable replay ledger. These current-repository controls still need exact-release
  rollout evidence.

### Secrets and configuration

- Django, per-lane PostgreSQL/RabbitMQ identities, per-publisher task-signing keys,
  onboarding, optional lane-specific managed SSH keys, and separate database/files KMS
  credentials are stored in a host-private `.secrets` directory and mounted only into
  granted roles.
- Direct `DJANGO_SECRET_KEY`, `DB_PASSWORD`, `RABBITMQ_PASSWORD`, and onboarding-token
  environment values are blank. File-backed values take precedence through a strict
  allowlist and fixed `/run/secrets` root.
- Compose retains `.env` compatibility but blanks every known deployment-wide integration
  credential family before granting it to an exact consumer: web receives all families
  for setup/OAuth callbacks, cloud only DigitalOcean/OVH, files only Basecamp, storage
  only Dropbox/pCloud/Microsoft/Google, and logs only
  Postmark/Mailgun/SES/Slack/Telegram; database, Beat and one-shots receive none. The
  entrypoint re-enforces the matrix and refuses a misplaced non-empty value. The Sentry
  DSN is intentionally shared because each Django/Celery process initializes the scrubbed
  client and a DSN is an event-ingest identifier rather than provider authorization.
- Secret loading rejects paths outside the secret root, subdirectories, symlinks,
  hard links, non-regular files, unsafe modes, invalid sizes, NULs, invalid UTF-8,
  empty values, and multiline values.
- Distinct database/files Ed25519 keys are copied into the matching worker's private tmpfs
  as mode `0600` only after validation. The app and other roles receive neither private
  key. Managed mode is limited to exactly-one-account installations.
- Installer and wrapper reject Docker/Compose control variables, loader hooks,
  TLS-key-log settings, duplicate/malformed keys, URL overrides that bypass reviewed
  fragments, and unsafe environment-file ownership or permissions.

File-backed secrets reduce exposure through `docker inspect`, child-process
environments, crash reports, and logs. They are not a vault: code executing inside a
role can read every secret deliberately granted to that role.

### Artifact custody and private staging (current repository)

- Database and files source lanes create chunked BSE1 envelopes with
  AES-256-GCM-SIV, canonical authenticated context and a per-artifact data key. The
  stock production policy requires AWS KMS wrapping, a resolved key-ARN allowlist and
  distinct database/files credential files. KMS encryption context binds the
  installation, lane, account, node, backup, model, purpose and context digest.
- The database and files workers alone receive their matching KMS identity and private
  plaintext work volume. Storage receives no KMS credential. It reads only published,
  validated BSE1 bytes through source-specific read-only transfer mounts and keeps its
  own ciphertext materialization private.
- Restore reverses that boundary: storage writes one target-lane fenced ciphertext
  handoff; database or files can read only its exact lane and performs full authenticated
  decryption in its private work volume before destination writes. No source role mounts
  `/backups`.
- The networkless `staging-provision` one-shot proves dedicated, empty private/transfer
  targets, validates any populated Local Storage tree before assigning UID/GID
  `10004:10004`, and commits an installation-bound layout-v3 witness. The legacy shared
  work volume must be empty and is never mounted by a runtime role.

These are current source controls, not new live release evidence. External IAM/key-policy
review, denied-cross-lane KMS calls, key-loss/rotation, tamper/swap, provider and full
restore tests must pass for the exact release before the original encryption/staging
blockers can be closed operationally.

### Compose topology and operations boundary

- The app publishes only `127.0.0.1:8000`; the expected public path is through an
  operator-managed TLS reverse proxy.
- App, cloud, database, files, storage, logs, Beat, migration, and preflight roles use
  distinct database/broker networks. Each Internet-capable long-lived role shares a
  network namespace with a no-secret guard on a separate egress bridge. The guard admits
  PostgreSQL and RabbitMQ only as exact directly connected interface/address/TCP-port
  tuples on two distinct internal interfaces; no bridge subnet is trusted. It refreshes
  peer addresses every second and blocks both internal peers while resolution is absent
  or ambiguous.
- Generation-2 stock `deny` mode permits no outward destination. `allowlist` accepts only
  reviewed exact IPv4 `CIDR:port` or IPv6 `[CIDR]:port` TCP tuples. `public` is an
  explicit compatibility risk opt-in that permits ordinary public addresses; exact tuples
  are special-range exceptions intended only for narrow reviewed private targets. Fixed
  `never` destinations and discovered gateways remain blocked; the fixed set includes
  both well-known NAT64 prefixes and no tuple can override them. A tuple can override
  only the ordinary private/reserved set. Only the guard retains `NET_ADMIN`,
  after dropping to UID/GID `10020`; secret-bearing application processes keep zero
  capabilities.
- Public mode uses ordinary DNS and requires an empty exact-name list. In strict modes,
  workload Docker-DNS queries are redirected to a loopback-only zero-capability
  UID-`10021` hostile-packet parser. It can send only an immutable allowed-name index and
  A/AAAA selector over a Unix socket to the separate zero-capability UID-`10022`
  forwarder. That forwarder authenticates the parser, constructs the canonical query and
  alone reaches Docker DNS. The complete policy is capped at 66 unique names including
  DB/broker names; every CNAME target must be listed. Direct external TCP/UDP 53 is
  blocked.
- Exact DNS and IP/port grants are independent transport-level controls, not resource
  authorization. A compromised lane can still reach another tenant/resource on the same
  IP and port, so enterprise operations require dedicated/private endpoints or a
  resource-aware controlled proxy. Deployment-specific NAT64 prefixes remain a
  host/network control.
- Each workload retains a private PID namespace and shares only its network namespace
  with the guard. The wrapper refuses independent guard lifecycle commands, guards use
  restart policy `"no"`, and the pair must be recreated together. Kernel-expiring peer
  and strict-workload leases are renewed on every complete observation; health requires
  a fresh renewal within the lease rather than PID-1 liveness alone. Workload health
  separately proves local web/worker readiness and fresh database/broker TCP connections
  through those current sets, making guard loss or a stranded namespace visible.
- Every libc peer lookup is bounded to one second by the pinned GNU coreutils 9.7
  `timeout --foreground` supervisor. Foreground supervision ensures a killed lookup is
  reaped instead of accumulating under the deliberately minimal PID 1. The lease is
  three polling intervals plus twelve seconds (15 seconds at the stock one-second
  interval), exceeding the 8.4-second worst sequential two-peer lookup budget while
  retaining a kernel-enforced deadline. The current hostile harness replaced `getent`
  with a never-returning fixture and proved health became blocked, peer tuples and the
  workload lease expired, the database connection was denied, and no zombie remained.
  The exact no-cache ARM64 image used by that harness contained 38 Alpine packages;
  pinned Trivy 0.74.0 reported zero High/Critical matches for the saved image archive.
- `BACKUPSHEEP_EGRESS_POLICY_GENERATION=2` is mandatory and address-only allowlist values
  fail closed. The one-time `--migrate-egress-policy` installer authorization accepts
  only uniform stock public/blank, blank/blank, or deny/blank state, resets all six roles
  to deny, clears every list and is refused after generation 2. Customized/mixed legacy
  policy requires manual review and reset.
- The stock default is core-only: database, broker, migrations, preflight, and web.
  All provider workers and Beat require the explicit `operations` profile.
- After an operator explicitly enables operations, those workers and Beat use
  `restart: unless-stopped` for backup availability; guards use `restart: "no"`. The
  installer removes the complete container/network topology with ordinary `down` before
  every build or migration while preserving named volumes, then uses exact paired
  recreation after the reviewed opt-in. A later daemon/container application restart
  reruns the hardened entrypoint and deployment preflight, but cannot recover or attest a
  `restart: "no"` guard. Daemon-restart and guard-loss recovery therefore use the exact
  paired command. Operators stop workers and Beat explicitly for a durable provider pause.
  Provision/migrate/seal/preflight one-shots use `restart: "no"`.
- The app can request an incremental-cache reset, but it runs in the files lane under
  the same node lock as archive/mirror work. `delete_old_logs` prunes files-private run
  logs at 03:00, `delete_old_database_logs` prunes database-private run logs at 03:05,
  `delete_old_storage_logs` prunes storage-private destination-upload logs at 03:10, and
  `delete_old_db_logs` prunes PostgreSQL `CoreLog` rows through the logs lane at 03:30.
  Destructive paths are anchored, no-follow, and serialized against live writers.
- Notification fan-out uses durable outbox/row IDs rather than placing arbitrary
  error bodies, webhook URLs, or credential material in new broker messages.
- Startup preflight checks Django deploy settings, migrations, database authentication,
  a non-consuming broker connection, static immutability, file-backed secrets, and the
  live runtime boundary. Long-running roles repeat the gate on every start, including
  daemon-triggered restarts.

### Installer and wrapper

- `install.sh` refuses root and `sudo`, accepts only a full 40-character commit, uses
  an isolated HTTPS Git process, verifies the object database, and requires its own
  bytes to match the selected commit.
- It explicitly builds the commit-tagged `db`, `app`, and `app-egress-guard` images.
  Stock services use `pull_policy: never`, so a missing local image fails rather than
  silently substituting registry content.
- It does not upgrade a checkout in place and does not provision the host.
- Install paths, parents, checkout files, `.env`, secrets, overrides, and resource
  ownership are validated before mutation.
- A stable random installation ID labels containers, networks, volumes, and an empty
  sentinel volume. Exact-name inventory prevents Compose from adopting a foreign or
  unlabeled resource that label-only discovery would miss.
- The persisted Compose project name is parsed under the C locale with one lowercase,
  bounded grammar; duplicate flags, ambient Compose overrides, option-shaped names and
  NUL-bearing environment files fail closed. Security-sensitive Docker label reads use
  a byte-length plus terminal-sentinel frame and reject control bytes, so shell newline
  or NUL normalization cannot turn a hostile ownership label into the expected value.
  The same framed ownership check protects installer/wrapper cleanup, CI cleanup and the
  PostgreSQL migration's temporary containers, sockets, target volume and image label.
- Staging layout v3 uses explicit `new-empty-v3` or `migrate-empty-legacy-v3` intent and
  a versioned installation-bound witness. Layout v2 was prerelease-only. A canonical
  project-owned develop-era `ssh_trust` volume is accepted only after exact ownership,
  name and label validation, then remains detached as rollback evidence; v3 has no trust
  mount, group or provisioning path.
- Secret migration is atomic and fail-closed. Existing secret values are preserved,
  moved to files, and blanked from `.env` without being printed.
- RabbitMQ generation transitions, legacy-project adoption, runtime overrides,
  deletion, and additional Compose files require narrow, value-bearing gates.
- The wrapper rejects privilege, entrypoint, environment, volume, port, build,
  orphan-removal, image-removal, and volume-deletion escape routes unless the exact
  reviewed maintenance operation is explicitly authorized.
- Every `--volume` override is rejected, including during maintenance, so a retired
  global host-trust file or volume cannot be remounted or imported through the wrapper.

### Connected application hardening

Container isolation would be undermined by unsafe application behavior, so this review
also closed connected attack paths:

- plaintext FTP is disabled by default; SFTP/FTPS use strict host/TLS verification,
  with insecure FTP requiring an explicit risk opt-in;
- SSH host-key approvals and append-only audit events are account-scoped PostgreSQL
  state. Workers receive one exact approval in a transient private-runtime file; legacy
  global trust inventories are never imported and require explicit per-endpoint
  reapproval after migration;
- Managed-SSH connection witnesses use domain-separated HMAC-SHA256 derived from the
  file-backed Django secret over the canonical snapshot, including already randomized
  encrypted credential fields. This defense-in-depth change removes stable unkeyed
  ciphertext fingerprints and makes secret-key rotation invalidate prior witnesses. A
  CodeQL report about the earlier plain SHA-256 construction did not establish plaintext
  dictionary exposure because its inputs were encrypted BinaryField ciphertext; the HMAC
  construction is now covered by the pull-request CodeQL gate;
- MySQL/MariaDB local option files now use mode-`0600` `mkstemp` staging plus atomic
  replacement without following a symlink or hard link. Remote SFTP option files use
  exclusive creation and chmod the empty inode before any credential byte is written.
  Paramiko-normalized private-key output is likewise precreated mode `0600` before
  unencrypted key bytes are emitted. These changes close the temporary-file paths behind
  the prior CodeQL findings and are exercised by the pull-request security suite;
- connection-test failures no longer return or log exception text. Database and website
  endpoints classify failures into fixed public codes/messages and record only a fixed
  stage and classification, keeping provider responses, URLs and credential-bearing
  diagnostics out of API bodies and telemetry;
- the UpCloud live-acceptance harness registers runtime secrets for output rejection and
  sources emitted bucket/prefix fields from canonical run state rather than credential
  responses. Its public JSON path screens every result and rejects compact and
  camel-case secret keys, authorization schemes, URL userinfo, query/fragment tokens,
  raw or nested percent encoding, registered secret values and noncanonical credential
  paths; its error path always emits one fixed diagnostic rather than provider text;
- shell-string execution was removed from reviewed backup/restore paths, credentials
  are passed through protected files or stdin, and GNU tar operands are separated with
  `--` after reviewed options;
- dangerous/unused HTTP methods are rejected, malformed early requests fail safely,
  and native/browser authentication audit events remain exactly-once;
- tenant and nested-resource authorization, authentication throttling, token/session
  expiry, MFA, CSRF-bound invite acceptance, callback state, redirects, and credential
  encryption were tightened across the broader security branch;
- backup, upload, deletion, restore, and notification work uses durable leases/outboxes
  and opaque IDs so Celery state is not treated as recovery truth.

## Adversarial validation

### Historical live web-container attack checks (`7be0729...`)

Observed on `demo.backupsheep.com` after the historical `7be0729...` deployment:

| Check | Result |
| --- | --- |
| Identity | `10001:10001` |
| Root filesystem | Read-only |
| PID / memory / CPU | `512` / `2 GiB` / `2 CPUs` |
| Namespaces | Private IPC and cgroup namespaces; Docker init active |
| Capabilities | Inherited, permitted, effective, bounding, and ambient all zero |
| Kernel controls | `NoNewPrivs=1`, `Seccomp=2` |
| Docker socket | Absent |
| Direct core-secret env values | Blank |
| Secret mounts | Present only as reviewed read-only files |
| Write to `/code` | Refused |
| Write to `/backups` | Refused on the assessed deployment's read-only mount |
| Write to protected `/tmp` | Succeeded, then probe removed |
| `pip` | Absent |
| Setuid/setgid files | None |
| Published port | `127.0.0.1:8000` only |
| Networks | app-broker, app-database, app-egress only |
| Log bounds | `json-file`, `10m`, five files |

The `/backups` refusal was historical write-containment evidence; it did not prove that
the web role lacked the mount. Current stock Compose removes that mount entirely and must
be inspected again on the exact release. This table otherwise demonstrates containment
of an ordinary web-process compromise. It does not prove
containment from a kernel/container-runtime vulnerability, Docker-daemon compromise, or
credentials intentionally readable by the web process.

### Historical live database and broker checks (`7be0729...`)

- PostgreSQL is healthy as `999:999`, read-only, capability-free, NNP/seccomp enabled,
  bounded to 256 PIDs, 2 GiB, and 2 CPUs. `gosu` is absent. An authenticated TCP query
  returned the exact `backupsheep|backupsheep` user/database pair, and checksums are on.
- RabbitMQ is healthy as server UID/GID `100:101`, NNP/seccomp enabled, with zero
  inherited/permitted/effective/ambient capabilities and the documented bootstrap
  bounding ceiling. It has no published host port.
- The application could not discover a Docker socket or write immutable source/system
  paths. PostgreSQL/RabbitMQ are not reachable directly from the public host network.

### Historical HTTP attacker probes (`7be0729...`)

- Public `/healthz/`: `200`.
- Direct invalid `Host`: `400` from Django.
- Public `GET`, `HEAD`, and `OPTIONS` on `/`: authentication redirects; no anonymous
  privileged action.
- Public HTTP/1.1 `TRACE`, `TRACK`, `CONNECT`, and `PROPFIND`: `405`.
- Direct HTTPS-context `TRACE`, `TRACK`, `CONNECT`, and `PROPFIND`: `405`.
- Plain HTTP redirects to HTTPS and the public response includes HSTS, CSP, frame
  denial, `nosniff`, Permissions-Policy, and Referrer-Policy.

During the same review, an unknown public Host and one HTTP/2 CONNECT form received an
empty Caddy `200` without establishing a tunnel. Caddy is host/reverse-proxy scope and
was intentionally not changed in this Docker-only phase. The Django endpoint itself
rejects the methods and invalid Host. The edge behavior remains a documented host-layer
residual.

### Historical deployed regression tests (`7be0729...`)

The historical deployed source state passed:

```text
Found 2298 test(s).
Ran 2298 tests in 357.870s
OK
```

The run used the exact final application runtime payload, non-root identity, read-only
root/source mounts, all capabilities dropped, `no-new-privileges`, finite cgroups, and
the same isolated PostgreSQL network. The only test-only relaxation was a disposable
executable `/tmp` volume because installer/wrapper regression tests must copy and
execute shell fixtures. Production Compose retains `noexec,nosuid,nodev` tmpfs.

The final secure-transport subset also passed 30/30 tests covering FTPS restore behavior
and explicit plaintext-FTP rejection together.

## Historical image and source scanning (`7be0729...`)

The final `7be0729...` build produced the same runtime platform manifests and config
digests as the exact scanned `c9d0d72...` build; intervening commits changed only tests,
which are excluded by the default-deny build context. Therefore the amd64 scanner
evidence applies byte-for-byte to the final runtime payload.

| Artifact | Final platform manifest | Config digest |
| --- | --- | --- |
| Application | `sha256:084d738048f546d78647e9aa5b1840b2e78fd25958b651e59e47448c1e7df3df` | `sha256:6c86b7cdad3d7d6beb5708be85753f661f5fa984d3f2a1b087b183a38cff8c54` |
| PostgreSQL | `sha256:60f73a002af8ef32ad3a0d4aa36ff0ed32c726c5084e00b083d050e635c9560d` | `sha256:4cf70f72dce1a12c1ac5407db4e77a0eb118694878d62248199b269a67b808f3` |

The final locally built/deployed multi-platform image indexes are
`sha256:d9b865bba377db534736961b8c0f7aaaf700faaf45e2b2bdedca7ef644bf174c`
for the app and
`sha256:c9b56c47d66fbba968a29edaddc13ddca806604959113dde7031e366c815a193`
for PostgreSQL. The image tags are the full final implementation commit.

### Scanner results

| Image | Trivy High/Critical matches (unique CVEs) | Grype High/Critical matches (unique CVEs) | Fixable H/C |
| --- | ---: | ---: | ---: |
| Application | 39 (21) | 52 (31) | 0 in both |
| PostgreSQL | 49 (14) | 80 (24) | 0 in both |
| RabbitMQ exact pinned image | 0 | 3 (1) | Scanner disagreement; see below |

These counts are not a claim that the images have no vulnerabilities. They mean neither
scanner reported a currently fixable High/Critical package finding in the application
or PostgreSQL payload at this evidence cut. Unfixed findings remain tracked risk and
must be rescanned whenever the vulnerability database or image inputs change.

#### 2026-08-25 application-runtime remediation

The exact pre-remediation application image `bsci-local-app:topology`
(`sha256:d7af448a51494124ff4bfcc03ad1187d8a9b42d9bab77e22c19562263b676418`)
had 39 Trivy High/Critical occurrences across 21 unique CVEs. Every finding had an
empty `FixedVersion`, and a live package-policy check found installed version equal to
candidate version for every affected Debian package. Updating that Debian stable image
alone therefore did not provide a clean package-level remediation.

The remediated Dockerfile keeps the official digest-pinned Python 3.14.7 build/runtime
tree (`sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4`)
but copies its pristine `/usr/local` into the official Ubuntu 26.04 runtime index
`sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b`.
Ubuntu packages and their complete dependency closure are downloaded from signed
indexes in a preparation stage, hashed, and installed with networking disabled in the
final stage. Exact-version assertions fail the build on repository drift. The final
image also removes the base image's Pebble and essential `perl-base`, retains no `pip`
or `msgpack`, and keeps the required PostgreSQL 14–18 and Oracle MySQL 8.4.11 clients.
Because `perl-base` is normally an Ubuntu essential package, in-container package
maintenance is intentionally unsupported: updates must rebuild and replace the image,
not run `apt` or `dpkg` in a live application container.

MariaDB's full client would retain unrelated Perl scripts. The build instead downloads
the authenticated `mariadb-client=1:11.8.6-5ubuntu0.1` archive and repackages only
`mariadb-dump` as `backupsheep-mariadb-dump`. Its installed package metadata declares
the upstream Ubuntu source `mariadb=1:11.8.6-5ubuntu0.1`, so future source-package
advisories remain scanner-visible. Installed provenance records the source archive
SHA-256 `86c3ecb2b7158897aba416497e746b66637c5e72ec9c90782304001d75dffa59`
and binary SHA-256
`afd445848715926b427469f3693372b952b9c1cbe7f2f42c5cd2da8507fc3e14`.
Syft independently catalogs that package, file hash, ELF dependency list, stack canary,
NX, full RELRO and PIE; a read-only, capability-free, no-network runtime test proved
the binary and the other required clients have no unresolved dynamic dependencies.

The previously raw PGDG and Oracle client trees are also installed packages now, rather
than anonymous copied files. The build authenticates and pins each upstream artifact,
copies only the required client payload, creates a package with exact upstream
`Source`, `Built-Using`, version and file ownership, and installs immutable provenance
under `/usr/share/backupsheep/provenance`. This makes the component visible in both
`dpkg` and Syft while preserving the existing runtime paths and ABI.

| Installed package | Installed version | Declared upstream source |
| --- | --- | --- |
| `backupsheep-mariadb-dump` | `11.8.6-5ubuntu0.1+backupsheep1` | `mariadb 1:11.8.6-5ubuntu0.1` |
| `backupsheep-postgresql-client-14` | `14.24-1.pgdg13+2+backupsheep1` | `postgresql-14 14.24-1.pgdg13+2` |
| `backupsheep-postgresql-client-15` | `15.19-1.pgdg13+2+backupsheep1` | `postgresql-15 15.19-1.pgdg13+2` |
| `backupsheep-postgresql-client-16` | `16.15-1.pgdg13+2+backupsheep1` | `postgresql-16 16.15-1.pgdg13+2` |
| `backupsheep-postgresql-client-17` | `17.11-1.pgdg13+2+backupsheep1` | `postgresql-17 17.11-1.pgdg13+2` |
| `backupsheep-postgresql-client-18` | `18.6-1.pgdg13+2+backupsheep1` | `postgresql-18 18.6-1.pgdg13+2` |
| `backupsheep-oracle-mysql-client` | `8.4.11+backupsheep1` | `mysql-community 8.4.11` |

PGDG downloads are authenticated by its checksum-pinned signing key with fingerprint
`B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8`. The following source-archive and copied
payload SHA-256 values are fail-closed for each architecture:

| Client | amd64 archive / payload | arm64 archive / payload |
| --- | --- | --- |
| PG 14 | `2a17bc01dd3c4345d4ac85b084a11d7fb74265aead805e75cf0a296552f0f42e` / `61983f6ae42ee31c3e3477cfed77d7a42c58956e7abbfeed06e4c6e176042454` | `4ac24008059ecc1993d9a944648ed36d0730b95d01f6a3522407795b2d00a47f` / `65a052e5e9563563d2a502f58066c9bb074e4ef63ef2c321bcfba97ab4a15c0b` |
| PG 15 | `718b5a25eb99db5ee37b165ebeeefea50ecf993c9cde1db26eb401e6bbe0be08` / `ec63ed182c6f3719e6b820bdf44a854597574af0a683d1a49e3cc81f68e3d855` | `29b55286e8de51c79ad317968e03d7a311c66c101e8536e2b635d860da3648af` / `0f4126aaa556bf544961f8e20fd2a9926a872f9afdf09924b32bc548231ca760` |
| PG 16 | `82e1dfb1c8f6aed02811c43bff4ead374343ebafe61bca9af3662fc75a83a4b7` / `3c2bff97c4547d2106e2fd0f9ba2738d1d0a217baf84ea228f1d411d1f0fa620` | `98f1b6ea41235282173901ef49dfb7b4c254810e9e23a2f2b3aeb758aedd2604` / `5964afee95ca55cd1816cb725d0289fba0c6f42159edc5f139676500f1a2157f` |
| PG 17 | `c36408bb62178bc9193c113da65e30fc6a5237648de5e9db1ea594214df9ae4b` / `e2ca95d99073796d6dc4578282cd1f1789f81507b17c97158f024ef05d43eff0` | `706c9fde003d98ff423a3d73bd5ac1115379481cb86daabf251e02f240d660d3` / `e9fe0d1133b2cd6db2447a8ccc7e92794ca98572909de790a7ec8509cc929877` |
| PG 18 | `9af40c99f7074f8ff3798155af2f07f1a4e1e3bd4edce44ef928c1e03aea620e` / `17e395f57433689ac3f8ed6cbeb631cf91dbb4e21d10573d4cc7b7f1f36a8f4b` | `098492efc9f576ffee23e1871d31682b332a3c6582072d3ef8f99b6b72573bc7` / `1ac98a12bb3d68cf67413cfa68bc4f96e658eb8bdc88fa43b0a1dd6207c78473` |

Oracle MySQL's archive and detached signature are both SHA-pinned and verified with the
checksum-pinned release key fingerprint
`BCA43417C3B485DD128EC6D4B7B3B788A8D3785C`. The amd64 archive, signature and two-file
payload hashes are `94e204cc94dede3746d2773fa5818f28f555cd8368c75ca0612eac124e6f3e58`,
`23bcbef86b5125deceef25726a39f165094448c48e5263ba8e8fd89a90f9c17a`, and
`91f3d13d4d651794a4f746d9503605641d129cf700a7abaa6793768851383346`.
The corresponding arm64 hashes are
`04b2f9791d314167a9eb83abcb476f45a7cd9e4aa88fa7a638cba40d1bc2a109`,
`81fe648f43050d3af5e5f3d5a2b915a5c60c8f04141eafeb34047e75295ee9a1`, and
`b019990ef3b06aff37c9e7e6c7739cc73fed13de591cacc22f40b010be075a09`.
Build-time and offline-CI assertions recompute payload hashes, verify every package and
source version, and prove `dpkg` owns every shipped database-client executable. The
definitive image also passed `apt-get check` with networking disabled, an empty
`dpkg --audit`, and `dpkg --verify` for all seven custom client packages.

The definitive local validation was a no-cache `linux/arm64` build. Its local OCI index
is `sha256:b837b5c86cc00a19f9457628084970551dcc8abaa3ffa35209b75f01eec7c154`,
archive platform manifest is
`sha256:58ec571cb0d1b04a136b5ebab62b4c885b12d945dd5a6f0d90c28229e05bef7b`,
and config digest is
`sha256:ad2f4fe7fbfdbe7df655425c31ab5018e75c013056c9ca53d578e4fd3e9bf9af`.
Syft 1.51.0 cataloged 279 packages, including all seven custom client packages and
their upstream package URLs. Trivy 0.74.0, with database version 2 updated 2026-08-25
13:00:57 UTC, scanned the exact saved archive with OS and library scanners,
`--list-all-pkgs`, High/Critical severity, `--ignore-unfixed=false`, an empty config,
an empty ignore file and exit code 1. It exited 0 with zero matched High/Critical
advisories. No allowlist or policy relaxation was used.

Replaying the strengthened current image validator against this exact saved predecessor
archive also parsed all 120 top-level hash-locked Python requirements and required exact
normalized name/version equality in both scanner reports. Syft and Trivy each reported
132 Python components, of which exactly 120 were top-level and matched the lock; the
remaining 12 were separately scanned setuptools-vendored components and could not
satisfy a top-level requirement. Missing, wrong-version, duplicate, unlocked,
vendored-only, inactive-runtime, legacy-metadata, malformed, or scanner-omitted
inventory now fails closed. The direct inventory is bound to
`/usr/local/lib/python3.14/site-packages` and recognizes case variants plus `.dist-info`,
`.egg-info`, and `.egg/EGG-INFO` metadata. Both scanners also agreed on all 138 OS
package names. This metadata gate does not independently verify every installed module
or `RECORD` byte, and identical omissions by both scanners remain a residual. The
canonical top-level inventory SHA-256 was
`0a4b340e77002b845d37e136bf41f40d01cd97cb645c9fe68df588855007a5f1`.

| Validated evidence | SHA-256 |
| --- | --- |
| Docker archive | `4bfb975f12d0b3ddfbb396ad2b6fd3cfbcd090af60a2f0ce6d3824bd1c2ee253` |
| Syft JSON | `857b85c34286e8dcf1761f7f951844f24f71bb1e3a32d2a4f2273bebcdd5b297` |
| SPDX JSON | `4991e0fc9558bb0566a1028e26a7bd9880442b10ecfdf7ba89dbb16032489ff3` |
| CycloneDX JSON | `ef86f6e820a50ee0bb37ce82fd707312414b18ba4c2e897a13d480ed24f2a25c` |
| Trivy JSON | `3a8db0746011cb657a8e042857476f2cd39255c9ce067f6a1b41f56a560b0c6b` |

Zero scanner matches is not a statement that the image has zero vulnerabilities.
Canonical reports MariaDB [CVE-2026-44172](https://ubuntu.com/security/CVE-2026-44172)
fixed in the exact selected `1:11.8.6-5ubuntu0.1` package and OpenSSH
[CVE-2026-60002](https://ubuntu.com/security/CVE-2026-60002) fixed in
`1:10.2p1-2ubuntu3.4`; this image uses the later `...3.5`. Canonical still marks
[CVE-2026-54369](https://ubuntu.com/security/CVE-2026-54369) (`acl`) and
[CVE-2026-14456](https://ubuntu.com/security/CVE-2026-14456) (OpenSSL QUIC server) for
26.04 as `Needs evaluation`. `libacl1` and OpenSSL remain present, but the default
runtime has no privileged ACL caller, no capabilities/setuid bits, and no QUIC
server/listener; those reachability reductions are not vendor fixes or waivers.
Canonical also marks Perl
[CVE-2026-13221](https://ubuntu.com/security/CVE-2026-13221) `Needs evaluation`; Perl is
absent from this final payload.

The selected PGDG versions are the PostgreSQL project's current 2026-08-13 security
releases and address the client-side issues listed in the
[PostgreSQL security register](https://www.postgresql.org/support/security/), including
`CVE-2026-19385`, `CVE-2026-18408`, and `CVE-2026-6464`. Oracle's
[July 2026 CPU](https://www.oracle.com/security-alerts/cpujul2026.html) lists affected
MySQL branches through 8.4.10; the selected generic client archive is the subsequent
[MySQL 8.4.11 release](https://dev.mysql.com/doc/relnotes/mysql/8.4/en/news-8-4-11.html).
The later [8.4.12 note](https://dev.mysql.com/doc/relnotes/mysql/8.4/en/news-8-4-12.html)
explicitly scopes that update to the MySQL Server Docker image, so it does not replace
the 8.4.11 generic client archive used here.

Trivy correctly maps the custom packages back to `mariadb`, `postgresql-14` through
`postgresql-18`, and `mysql-community`, but its Ubuntu advisory feed is not evidence of
complete Oracle or PGDG vendor-advisory coverage. A manual vendor-advisory comparison
against those exact versions is therefore a mandatory release gate, alongside a fresh
SBOM and strict scan. The local host natively proved arm64 and separately proved every
amd64 client artifact and hash; a full locally emulated amd64 build was limited by
Docker Desktop's older QEMU returning `Function not implemented` from target-architecture
`dpkg-deb`. Native amd64 CI and the pinned QEMU v10 multi-architecture release build,
signed publication, and exact release-digest scans remain authoritative gates.

The egress guard did not exist at this historical evidence cut. In the 2026-08-25
working tree, its builder, runtime, and policy-test fixture use official digest-pinned
Alpine 3.22.5. A fresh no-cache Trivy scan of that candidate reported 0 High and 0
Critical findings. The immediately prior Alpine 3.22.2 candidate reported 17 High and
2 Critical fixed CVEs and was replaced; do not reuse that stale candidate result as a
current claim. This candidate scan is useful remediation evidence, not a substitute for
scanning and signing the exact release image.

Grype alone reported `CVE-2026-14456` in RabbitMQ's bundled `/opt/openssl`; Trivy did not.
The issue affects OpenSSL QUIC server listener allocation. BackupSheep does not expose or
use OpenSSL QUIC in RabbitMQ, which materially reduces reachability, but this is not a
waiver. Track the vendor image and rebuild when a reviewed fix is available.

Exact amd64 evidence hashes:

| Evidence | SHA-256 |
| --- | --- |
| Application image tar | `2efaa493833f3df3381b433f247095a5369f17fdbd3e18f87a83797d5016d9b6` |
| PostgreSQL image tar | `26acb82e17060dea45a40298a50d7d5c68b1651c616d125729bbf9d9dea8dfd5` |
| Trivy app JSON | `91d93e24901cab98e1b68f550064b5cc5b35f62a884595b449f44edebeecd0b5` |
| Trivy PostgreSQL JSON | `d13e474e9434c1d460fb39fb42692a7aa0664843d2f9ec49d2f5424f2ff6fefd` |
| Grype app JSON | `4a6b0e21c87c9961f477457063d1a210317358ceab9524dfdb1148207d6cec8b` |
| Grype PostgreSQL JSON | `563aca8c64725b030b4128683c40e5f2fa87589e614c9ac3fdb4f37cb753bea0` |
| Trivy source JSON | `a685ea3fde3f730bd6fc08dda2d4a1d05cc0cfda9a493d517d80053026ea7011` |

The exact `c9d0d72...` source snapshot scan reported zero vulnerabilities, zero secrets,
and zero High/Critical misconfigurations. Remaining configuration findings were one
Medium Dockerfile style finding (`RUN cd`) and two Low missing-image-`HEALTHCHECK`
findings; Compose supplies role-specific health checks, so a single image-level check
would be incorrect for every role. The commits after that scan changed tests only, were
diff-reviewed, and cannot enter the default-deny runtime context; a full-tree Trivy
secret scan was not repeated at `7be0729...`. `pip-audit` reported zero dependency
vulnerabilities at its evidence cut. Bandit reported zero High findings; Medium/Low
heuristic results were triaged rather than silently counted as proof of safety.

The 2026-08-25 follow-up converted that triage into a release-blocking control. The
reusable supply-chain workflow (which the signed-image workflow must complete before
building) installs `bandit==1.9.4` and its complete CPython 3.14/Linux dependency closure
from a whole-file and artifact-hash-locked binary-wheel manifest, scans `apps`,
`backupsheep`, and `scripts` at Medium-or-higher severity, and validates every accepted
result against `deploy/static-analysis-policy.json`. Repository `.bandit`/YAML
configuration and inline `# nosec` suppression are explicitly disabled and covered by a
malicious-suppression canary. The current report contains 60 Medium and one High
heuristic: B104 (1), B108 (8), B310 (3), B402 (1), B601 (7), and B608 (41). B402 is the
content-pinned standard-library `ftplib` import required by `FTP_TLS`; its plaintext
subclass checks the default-off `ALLOW_INSECURE_FTP` gate before network access.
Each accepted
finding has a code-content fingerprint and a written review; a new result, removed
result, scanner error, or changed code sample fails the gate. An AST policy separately
rejects `AutoAddPolicy`, `WarningPolicy`, and any unapproved
`set_missing_host_key_policy(...)` expression, including conditional patterns Bandit
can miss.

The dependency-audit job now applies the same installer discipline to `pip-audit`
2.10.1: its complete CPython 3.14/Linux wheel closure and the lockfile itself are
SHA-256 pinned before it audits the exact hash-locked application runtime inventory
with dependency resolution disabled. The current exact-lock replay reported no known
advisories; the current PR run remains authoritative.

### Current full-tree source and secret gate

The current candidate adds a separate fail-closed Trivy 0.74.0 filesystem gate to the
pinned static-analysis job. It verifies the scanner asset hash, requires a clean checkout
at the exact GitHub SHA, clears ambient configuration, scans the full dependency tree
for High/Critical vulnerabilities, and requires Trivy configuration coverage for all
three repository Dockerfiles. Compose and workflow semantics are covered separately by
the rendered deployment tests and hash-verified actionlint 1.7.12 running over every
workflow in the same required job. The source validator requires the exact Python and
npm dependency-result identities plus all three Dockerfile results, so losing either
dependency ecosystem or a clean Dockerfile result cannot pass on aggregate package counts.
In a normal detached GitHub checkout, pinned Trivy classifies `filesystem .` as a
repository. The validator therefore recomputes Trivy's repository artifact ID from the
sanitized HTTPS Git remote and final commit, matches the bounded author, committer and
message metadata to the checkout, and requires the vulnerability and secret reports to
share that exact identity. Linked worktrees retain the separately validated filesystem
form, while the generated private canary directory must always remain filesystem-only.
Secret scanning is deliberately a separate all-severity pass: its generated immutable configuration disables every Trivy
0.74 built-in path allow rule and default skip pattern, including tests, examples,
vendor, Markdown and lockfiles. Five private canaries prove those normally skipped paths
are actually inspected on every run. The secret report must retain the exact Python
inventory identity as well; an unrelated inventory cannot mask its disappearance.

The exact local gate exercise reported zero High/Critical dependency findings and zero
secret findings at any severity. Trivy reported two High Dockerfile heuristics: DS-0017
for the authenticated, version/hash-pinned APT download/repackaging stage and DS-0002 for
the egress guard's root-only nftables bootstrap before it drops to UID 10020 with only
`NET_ADMIN`. Both reviews pin the complete target bytes and complete finding JSON; an
extra, missing, duplicated or changed result fails. Raw secret reports remain mode 0600
in a private runner directory, are deleted before upload, and only a zero-sensitive
summary is retained. The current PR's exact-SHA execution remains authoritative.

Repository secret scanning, push protection, Dependabot updates and private vulnerability
reporting are enabled. Provider validity checks and non-provider secret patterns remained
disabled when requested through the GitHub API, so they are treated as a platform/account
capability gap rather than silently claimed as active. Current-tree scanning also does
not close the historical Google credential incident described below.

Two real issues found during that review were remediated rather than allowlisted:

- Oracle and UpCloud live acceptance harnesses no longer use trust on first use. Each
  SSH connection requires an independently collected exact OpenSSH SHA-256 host-key
  fingerprint before connecting. Oracle uses the host-specific
  `ORACLE_E2E_SOURCE_SSH_HOST_KEY_SHA256`,
  `ORACLE_E2E_COMPUTE_RESTORE_SSH_HOST_KEY_SHA256`, or
  `ORACLE_E2E_BOOT_VERIFY_SSH_HOST_KEY_SHA256` witness; UpCloud uses
  `UPCLOUD_E2E_SOURCE_SSH_HOST_KEY_SHA256` or
  `UPCLOUD_E2E_RESTORE_SSH_HOST_KEY_SHA256`. Obtain these through the authenticated
  provider console/serial channel (or another independently authenticated path), not
  from the SSH connection being verified or an unauthenticated `ssh-keyscan` alone.
  Missing or mismatched pins fail before remote commands run.
- MySQL and MariaDB backup builders now reject database/table operands beginning with
  `-` and place an explicit `--` option terminator before positional targets. This
  prevents names such as `--result-file=...` or `--tab=...` from becoming client
  options while preserving ordinary database identifiers.

## Historical demo deployment and recovery evidence (`7be0729...`)

### Pre-change recovery boundary

Before changing the demo, the review created and validated encrypted rollback material:

| Artifact | Location | SHA-256 | Size |
| --- | --- | --- | ---: |
| Complete live bundle | `/mnt/blockstorage/backupsheep-security-rollbacks/20260824T001036Z-pre-157337b-live.tar.gz.enc` | `93ee3ecc4c3d55f044f09137de114f88b76781220cb193e4f13afc8810202c76` | 27,997,488 bytes |
| Cold PostgreSQL volume archive | Encrypted rollback set | `924177f7b3733f21f6155d49b173603e5a697ad27666c05a41f9477602caa762` | 28,858,176 bytes |
| Cold RabbitMQ volume archive | Encrypted rollback set | `d0f6ed8ffecc5f07d3cf004c33c60193256f988e01ccedaa368d938119d54c64` | 98,608 bytes |

The decryption key is stored separately at root-only path
`/root/.backupsheep-rollback-keys/20260824T001036Z-pre-157337b.key`. Its value was never
printed or placed beside the ciphertext. Archive listings, checksums, and decryptability
were validated. Original legacy core containers/volumes were retained cold; unrelated
remediation containers were not deleted or moved. No prune, orphan removal, or volume
deletion was used.

### Historical final live state

| Component | Exact image | State |
| --- | --- | --- |
| App | `backupsheep:7be0729374e61558740f7a564248a7c4491049be` | Healthy |
| PostgreSQL | `backupsheep-postgres:7be0729374e61558740f7a564248a7c4491049be` | Healthy |
| RabbitMQ | `rabbitmq:4.3.5-alpine@sha256:d07d6a0657affe0354ae61b3ca1a3e4d244c247ac5d7e25940c8759658ce7ad7` | Healthy |

- Remote checkout: exact detached `7be0729374e61558740f7a564248a7c4491049be`.
- Migrations: applied; final Docker security preflight passed after app and database
  recreation.
- Public health: `200`; app remains bound only to `127.0.0.1:8000`.
- Operations workers/Beat running: `0`.
- Preserved `/` vhost `cloud` queue: `7` ready, `0` unacknowledged, `0` consumers before
  and after deployment.
- The final app/database tag alignment did not recreate RabbitMQ or consume a message.

The demo could not exercise the stock installer end-to-end because `/opt/backupsheep`
is root-owned and Docker is available to the SSH account only through passwordless
`sudo`; the hardened installer intentionally refuses both root and `sudo`. After the
encrypted rollback boundary was established, this deployment used an explicit
environment-specific administrative path and the reviewed Compose wrapper. This is a
documented demo exception, not evidence that the installer should weaken its ownership
model. Installer behavior is covered by the clean regression suite; a separate fresh
user-owned host acceptance test is still recommended.

On 2026-08-25 the public HTTPS endpoint remained reachable, but every available SSH
identity was rejected by the server. The current candidate therefore has not been
deployed or inspected on the demo host; no historical live fact in this section should
be read as current-candidate deployment evidence.

## Residual risk register

### Critical

1. **A historically committed Google API key remains an open credential incident.**
   GitHub secret scanning identifies one publicly leaked Google API key introduced in
   2024. The unused helper that contained it is absent from the current main, develop and
   candidate tips, but deleting source does not revoke a credential and public forks
   retain historical copies. The Google Cloud owner must revoke or rotate the key,
   inspect its restrictions, usage, audit/billing records and downstream dependencies,
   and then resolve the GitHub alert as revoked. A history rewrite may reduce casual
   discovery only after revocation; it cannot erase existing clones or forks.
2. **The new artifact-custody and staging boundary is implemented but not
   release-proven.** The original demo/digests do not include BSE1, the KMS policy boundary or
   private layout v3. Do not treat the old 2,298-test run as closure. Cut and attest an
   exact release, exercise the fresh installer and existing-volume migration, prove
   denied cross-lane KMS calls and filesystem access, and run tamper, tenant/context-swap,
   rotation, key-loss, provider-upload and authenticated restore-before-write tests.
3. **A source-lane compromise remains high-impact by design.** Database/files workers
   must temporarily read the plaintext they collect and hold their own KMS identity.
   Stock egress now denies outward traffic, but a role must receive some network path to
   perform Internet-dependent work. A remote-code-execution flaw in one of those lanes
   can abuse whatever source/provider path that role legitimately receives. Exact
   IP/port policy does not distinguish resources or tenants behind the same endpoint.
   Enterprise deployments must use dedicated/private endpoints or a resource-aware
   controlled proxy and treat source-worker code execution as a critical credential/data
   incident.

### High

1. **RabbitMQ/database lane authorization needs exact-release rollout evidence.**
   RabbitMQ identity generation 2 and task-auth generation 3 now provide distinct
   credentials, fixed queue ACLs, per-publisher signatures and replay policy. PostgreSQL
   identity generation 3 provides ten identities with exact grants/RLS. Preserve fresh
   provision/seal/preflight output plus adversarial cross-lane connection and real
   Rabbit/Kombu/Celery evidence before closing this gate. Unfinished late-ack redelivery
   still relies on durable task-specific execution fences after a worker crash.
2. **Transport allowlisting is not resource authorization.** The generation-2 default is
   deny, and `allowlist` narrows outward access to exact IP/CIDR and TCP-port tuples, but
   another tenant or resource on the same IP and port remains reachable. `public` remains
   an explicit broad compatibility opt-in. Enterprise source lanes require dedicated/
   private endpoints or a resource-aware controlled proxy and denied-destination proof.
   The hard well-known NAT64 blocks do not discover a site-specific translation prefix,
   which must be controlled and tested at the host/network boundary. The isolated
   guard's retained `NET_ADMIN` capability remains a component requiring hardening and
   monitoring.
3. **A granted process can read its own secrets.** Per-lane DB, broker, signing, SSH and
   KMS files prevent casual cross-role sharing, but file mounts do not protect a secret
   from code executing in the role that legitimately receives it. Integrate short-lived
   external identity where feasible and exercise rotation/revocation.
4. **No portable volume byte/inode quotas or guaranteed encryption.** A job or attacker
   can fill Docker storage, and named-volume confidentiality depends on the host.
   Require capacity/inode alarms, retention controls, filesystem/project quotas where
   supported, encrypted storage, and documented emergency recovery.
5. **Unsigned local image distribution.** Inputs are pinned and builds are evidenced,
   but release consumers do not yet verify a signed image, SBOM, provenance statement,
   or transparency-log record tied to a protected release commit.
6. **Provider and restore behavior remains held.** Core health does not prove provider
   mutation, duplicate avoidance, crash reconciliation, destination integrity, or
   restoration. Keep operations off until durable work and provider ownership are
   reviewed and representative backup/restore/chaos gates pass.
7. **Enterprise identity lifecycle is incomplete.** Organization-enforced MFA,
   SAML/OIDC SSO policy, SCIM deprovisioning, governed break-glass access, scoped
   selector-verifier API credentials, and immutable off-host audit evidence remain
   incomplete or unproven.
8. **WordPress has been retired from the product.** Runtime models, routes, tasks,
   connector/plugin code, UI, configuration, packaging and current product documentation
   are removed. The retirement migration disables historical schedules, nodes,
   connections and the integration while deliberately retaining the old database tables
   and columns for non-destructive upgrades. Runtime database lanes have no access to
   those retained tables.
9. **Basecamp BSE1 recovery remains intentionally unavailable.** Direct archive download
   correctly fails closed for encrypted artifacts, and Basecamp still lacks an
   authenticated plaintext-export or automatic-restore path. Existing rows remain visible
   for retention and investigation, while new enterprise protection is blocked before
   mutation or dispatch. Treat this as a feature acceptance gate, not as recovery
   coverage; do not advertise or re-enable it until an exact-lane export/restore workflow
   is implemented, authorization-tested and rehearsed end to end.

### Medium and operational

1. Same-host PostgreSQL/RabbitMQ transport is plaintext. Internal unpublished networks
   are an accepted single-host exception, not suitable across an untrusted boundary.
2. RabbitMQ and the new egress guards' capability boundaries must be demonstrated after
   the exact demo/production rollout with their matching volume/network witnesses.
3. Grype/Trivy disagree on the RabbitMQ OpenSSL QUIC issue. QUIC is not exposed, but the
   pinned vendor image must be rescanned and updated when a reviewed fix lands.
4. At-least-once outbox delivery can duplicate a notification after an unknown publish
   outcome; consumers need durable idempotency.
5. The image contains SSH and several database client families required for supported
   backups. They are useful post-exploitation tools and increase update surface.
6. The Caddy unknown-Host/HTTP2-CONNECT behavior is a host-layer residual. Correct it in
   an isolated default route with regression proof, not by weakening the app.
7. The demo's administrative deployment exception means fresh-host installer behavior
   is test-proven but not live-proven on that root-owned path.
8. GitHub provider validity checks and non-provider secret patterns remain disabled at
   the repository capability layer. Core secret scanning and push protection are active,
   but provider-side revocation and the strict repository CI scan remain necessary.

## Enterprise remediation order

### P0 — before claiming enterprise protection for sensitive backups

1. Revoke or rotate the historically exposed Google API key at the provider, review
   restrictions, use, audit and billing evidence, update any legitimate dependent
   workload, and resolve the repository alert only after provider-side revocation is
   proven.
2. Cut an exact release and run the complete tests, CodeQL/source/secret scans and image
   scans; publish signed multi-architecture images, SBOMs and provenance tied to the
   protected commit.
3. Exercise the exact-ref installer on a fresh user-owned host and the fail-closed v3
   migration on a recoverable existing-volume copy. Inspect every resulting mount,
   identity, capability, healthcheck, restart policy and egress namespace.
4. Review the AWS IAM/key policies and prove allowed same-lane plus denied cross-lane KMS
   operations, BSE1 context/tamper/swap rejection, key-wrap rotation and key-loss
   recovery. Keep the old key until every durable envelope is rewrapped and rehearsed.
5. Prove storage and Local Storage contain BSE1 ciphertext only, source lanes cannot
   mount `/backups`, and no role can read or mutate another lane's private/transfer data.
6. Put database/files lanes in reviewed egress `allowlist` mode (or a controlled proxy)
   before sensitive operation, without broadening the exact internal DB/broker tuples.
7. Deploy and retain evidence for generation-3 database identity, generation-2 RabbitMQ
   identity and generation-3 signed-task/replay enforcement.
8. Run provider-specific backup, restore, crash, retry, duplicate and unknown-outcome
   reconciliation gates with fresh ownership evidence.

### P1 — production hardening

1. Maintain reviewed per-role destination allowlists and alert on guard policy drift,
   blocked peer resolution and unexpected outward attempts.
2. Add encrypted/quota-controlled storage, byte/inode alerts, and recurring encrypted
   control-plane backups with restore drills.
3. Integrate an external secret manager and exercise key rotation/revocation.
4. Verify RabbitMQ's zero bounding set and volume witness after every image/data upgrade.
5. Add immutable off-host audit export and alerting for auth abuse, preflight changes,
   unexpected task publishers, outbound destinations, disk growth, queue age, and
   container restarts.
6. Complete enterprise identity, API credential, and invite work.

### P2 — continuous assurance

- Rescan exact digests on every build and on vulnerability-database refresh.
- Re-run the full suite and hostile build-context tests after Dockerfile/Compose changes.
- Test cgroup v1/v2, amd64/arm64, Docker Engine upgrades, reboot/restart behavior, and
  supported PostgreSQL/RabbitMQ upgrade paths.
- Offer host guidance for rootless Docker, AppArmor/SELinux, firewalling, encryption,
  quotas, log shipping, and daemon protection without silently changing the host.

## Safe installation and operation

For a fresh installation, use an unprivileged Docker-authorized account and a user-owned
directory. Stock installation requires Docker Engine 28 or newer and Compose 2.33.1 or
newer; it does not modify the host. Inspect the installer downloaded from the same exact
reviewed commit. Supply a resolved symmetric KMS key ARN, its region/allowlist and two
different canonical user-owned mode-`0400` or `0600` AWS credential files whose IAM
policies enforce the matching database/files encryption context:

```bash
COMMIT='<40-character-reviewed-release-commit>'
ARTIFACT_KMS_KEY_ARN='<resolved-symmetric-kms-key-arn>'
ARTIFACT_KMS_REGION='<aws-region>'
DATABASE_KMS_CREDENTIALS_FILE='<canonical-private-database-lane-credentials-file>'
FILES_KMS_CREDENTIALS_FILE='<different-canonical-private-files-lane-credentials-file>'
curl -fSLo install.sh \
  "https://raw.githubusercontent.com/bilal414/backupsheep/${COMMIT}/install.sh"
less install.sh
chmod 700 install.sh
./install.sh \
  --ref "${COMMIT}" \
  --domain backups.example.com \
  --install-dir "$HOME/.local/share/backupsheep" \
  --project-name backupsheep \
  --artifact-kms-key-id "${ARTIFACT_KMS_KEY_ARN}" \
  --artifact-kms-region "${ARTIFACT_KMS_REGION}" \
  --artifact-kms-allowed-key-arns "${ARTIFACT_KMS_KEY_ARN}" \
  --artifact-kms-database-aws-credentials-file "${DATABASE_KMS_CREDENTIALS_FILE}" \
  --artifact-kms-files-aws-credentials-file "${FILES_KMS_CREDENTIALS_FILE}"
```

Do not add `--enable-operations` during initial installation. Review credentials,
durable backup/restore rows, schedules, broker queues, destinations, and provider
ownership first. A profile-less startup is intentionally core-only.

Use the reviewed wrapper for manual operations and always pass a present local override
explicitly:

```bash
./backupsheep-compose ps --all
./backupsheep-compose run --rm --no-deps preflight
./backupsheep-compose logs --tail=200 app db rabbitmq
```

Only after the operations safety gate passes:

```bash
./backupsheep-compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
./backupsheep-compose --profile operations up --detach --no-build --no-deps beat
```

Broad, guard-only and workload-only `up` are refused after a pair exists. A lost guard
requires exact paired force-recreation; it is never restarted independently.

Never use `down --volumes`, `rm -v`, image pruning, or orphan removal as routine
maintenance. These can destroy the control plane, queue, Local Storage, work
state, or installation-identity witness. Follow
[`operations.md`](../guides/operations.md),
[`disaster-recovery.md`](../guides/disaster-recovery.md), and
[`rabbitmq-upgrade.md`](../guides/rabbitmq-upgrade.md).

## Evidence limitations

- Scanners report known data in their databases, not absence of exploitable behavior.
- A clean current-tree source/secret scan does not prove that Git history, forks, build
  logs or previously published artifacts are clean; the historical Google key alert is
  direct evidence of that distinction.
- Static and unit/integration tests cannot prove kernel/runtime isolation against an
  unknown container escape.
- Core health and an empty consumer set intentionally do not prove providers, backups,
  restores, or cleanup.
- A `Completed` application status is not restoration evidence. Enterprise acceptance
  needs provider-side ownership, persisted artifact integrity, and successful restore
  validation.
- The rollback bundle was validated for integrity/decryption/listing. A full destructive
  rollback rehearsal was not performed on the live demo after the final deployment.
- Current demo server inspection and rollout were blocked by SSH public-key rejection;
  the current candidate therefore has no live-demo containment or migration proof.
- Host reverse-proxy, daemon, firewall, MAC, patching, encryption, and rootless posture
  are explicitly outside this Docker-owned boundary.

## Final conclusion

The assessed Docker setup was defensible as a hardened core-only baseline against common
web-RCE, secret-leakage, persistence, lateral-movement, supply-chain, unsafe-startup and
resource-exhaustion attacks. The original demo deployment and regression evidence support
that historical conclusion. The current candidate adds materially stronger artifact,
identity, staging and egress boundaries plus fail-closed project-name, output-redaction,
exception and source-scan controls. Its exact PR checks are the repository evidence cut;
they are not signed-release, provider, KMS or live-deployment evidence.

Enterprise use should remain conditional, not marketed as attack-proof. The historical
Google key must first be revoked and investigated. Exact-release proof of external-KMS
BSE1, per-lane identities/staging/egress, signed provenance, deployed containment and
real provider/restore/chaos proof must also close before BackupSheep can credibly claim
enterprise-grade protection for high-value backup data.

## Authoritative references

- [Docker Engine security](https://docs.docker.com/engine/security/)
- [Docker rootless mode](https://docs.docker.com/engine/security/rootless/)
- [Docker Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/)
- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)
- [Docker Compose profiles](https://docs.docker.com/compose/how-tos/profiles/)
- [Docker build best practices](https://docs.docker.com/build/building/best-practices/)
- [RabbitMQ upgrade guide](https://www.rabbitmq.com/docs/upgrade)
- [RabbitMQ Khepri enablement](https://www.rabbitmq.com/docs/metadata-store/how-to-enable-khepri)
- [RabbitMQ 4.3 release notes](https://www.rabbitmq.com/blog/2026/04/23/rabbitmq-4.3-release)
- [Debian tracker for CVE-2026-14456](https://security-tracker.debian.org/tracker/CVE-2026-14456)
- [Ubuntu tracker for CVE-2026-44172](https://ubuntu.com/security/CVE-2026-44172)
- [Ubuntu tracker for CVE-2026-60002](https://ubuntu.com/security/CVE-2026-60002)
- [Ubuntu tracker for CVE-2026-54369](https://ubuntu.com/security/CVE-2026-54369)
- [Ubuntu tracker for CVE-2026-14456](https://ubuntu.com/security/CVE-2026-14456)
- [Ubuntu tracker for CVE-2026-13221](https://ubuntu.com/security/CVE-2026-13221)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [NIST SP 800-218 Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Django deployment checks](https://docs.djangoproject.com/en/6.0/ref/checks/)
