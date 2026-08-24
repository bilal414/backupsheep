# BackupSheep Docker and container cyber-defense assessment

**Assessment window:** 2026-08-23 through 2026-08-24 UTC  
**Repository:** `bilal414/backupsheep`  
**Branch:** `codex/security-hardening-20260823`  
**Final implementation commit:** `7be0729374e61558740f7a564248a7c4491049be`  
**Demo deployment:** `demo.backupsheep.com`, project `backupsheepsecure`  
**Deployment mode:** core only; all provider workers and Celery Beat remain stopped  
**Review boundary:** repository-supplied images, Compose topology, installer, wrapper,
entrypoint, secret loading, startup checks, and application changes required to make
those boundaries trustworthy

## Executive decision

BackupSheep now has a strong secure-by-default Docker baseline. The final application
and PostgreSQL containers on the demo are healthy on exact commit-tagged images. The
web process is non-root, capability-free, read-only, bounded by CPU/memory/PID limits,
isolated from the Docker socket and backup work volume, and exposed only on host
loopback. PostgreSQL runs directly as UID/GID `999:999` without `gosu`. RabbitMQ and
PostgreSQL publish no host ports. Core secrets are file-backed and direct secret
environment variables are blank. A normal profile-less start does not launch any
provider-mutating worker or scheduler.

The result passed a clean 2,298-test regression run, two independent image scanners,
source/secret/config scanning, adversarial container checks, migration/startup
preflight, and a rollback-protected demo rollout. No fixable High/Critical finding was
reported in the exact application or PostgreSQL runtime payload by either scanner.

This is not an “attack-proof” or enterprise-certified result. No defensible review can
promise that. BackupSheep should be described as **materially hardened and suitable for
controlled core-only self-hosting**, with enterprise approval still conditional on the
Critical and High residual risks in this report. Most importantly, backup payloads do
not yet have per-backup authenticated encryption with an externally controlled KMS key.
A sufficiently privileged worker, local-storage reader, database/storage compromise,
or host compromise can still disclose or tamper with backup material.

### Status summary

| Area | Result | Decision |
| --- | --- | --- |
| Application image containment | Pass | Strong non-root immutable baseline demonstrated live |
| PostgreSQL image containment | Pass | Fixed non-root identity, zero capabilities, read-only root, authenticated probe |
| RabbitMQ containment | Conditional pass | Non-root server with zero effective/permitted capabilities; bootstrap bounding-set residual remains |
| Compose topology | Pass | Loopback web publication, no DB/broker host ports, role-specific internal networks, operations opt-in |
| Installer/update safety | Pass in tests; demo exception documented | Exact commit, no host provisioning, fail-closed ownership/collision/generation checks |
| Runtime secrets | Pass with residual | Values absent from direct env; a compromised granted process can still read its mounted files |
| Supply chain | Conditional pass | Pinned/verified inputs and zero fixable H/C; unsigned local images and no enforced release provenance |
| Regression suite | Pass | 2,298/2,298 tests |
| Demo core rollout | Pass | App/DB/Rabbit healthy, preflight passed, queue preserved, operations stopped |
| Provider operations and restores | Held | Not enabled or treated as proven by this Docker review |
| Backup application-layer encryption | Fail | Critical enterprise blocker |

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
- PostgreSQL clients, MySQL client artifacts, Debian packages, repository keys, and
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

- Image and Compose both require UID/GID `10001:10001`.
- All Linux capabilities are dropped; `no-new-privileges`, Docker's seccomp filter,
  private PID/IPC/cgroup namespaces, Docker init, and disabled core dumps are enforced.
- The immutable entrypoint checks its effective identity, all capability sets,
  `NoNewPrivs`, seccomp, Docker init, absence of the Docker socket, required mounts,
  tmpfs flags, and finite cgroup ceilings before starting application code.
- Root filesystem, `/code`, `/etc`, and `/backups` are read-only to the web role.
  Only bounded `noexec,nosuid,nodev` tmpfs and specifically granted volumes are writable.
- The web container has no `backup_workdir` mount. It receives Local Storage at
  `/backups` read-only and a dedicated SSH trust volume writable only for the reviewed
  trust-on-approval workflow.
- CPU, memory, PID, no-file, shared-memory, tmpfs, shutdown, and JSON log rotation
  limits are explicit per role. The entrypoint independently rejects missing,
  unlimited, or implausibly large CPU/memory/PID cgroup values.
- No Docker socket, host namespace, privileged mode, device, or host filesystem mount
  is part of the stock topology.

### PostgreSQL and RabbitMQ

- PostgreSQL uses a custom image with fixed `USER 999:999`, `cap_drop: [ALL]`,
  read-only root, `no-new-privileges`, private namespaces, and bounded resources.
- The custom PostgreSQL image verifies the upstream entrypoint before replacing
  `gosu` with `setpriv`; `gosu` is then removed. The live process has all capability
  sets at zero and data checksums enabled.
- PostgreSQL and RabbitMQ publish no host ports and are reachable only on explicit
  role-specific internal networks.
- RabbitMQ is digest-pinned to `4.3.5-alpine`, uses an authenticated health check,
  has bounded resources and logs, and runs `beam.smp` as UID `100`, GID `101`.
- The live RabbitMQ server has zero inherited, permitted, effective, and ambient
  capabilities, `NoNewPrivs=1`, and seccomp mode 2. Its bounding set remains `0xcb`
  because the vendor root bootstrap receives five ownership/UID transition
  capabilities. This is recorded as a residual, not reported as full capability-free
  parity with the app and database.
- RabbitMQ data-generation fencing prevents a 4.3 image from guessing at a legacy
  3.13/4.2 volume. The installer/wrapper require exact state witnesses and the
  documented Khepri transition path.

### Secrets and configuration

- Django, PostgreSQL, RabbitMQ, onboarding, and optional managed SSH-key material are
  stored in a host-private `.secrets` directory and mounted only into granted roles.
- Direct `DJANGO_SECRET_KEY`, `DB_PASSWORD`, `RABBITMQ_PASSWORD`, and onboarding-token
  environment values are blank. File-backed values take precedence through a strict
  allowlist and fixed `/run/secrets` root.
- Secret loading rejects paths outside the secret root, subdirectories, symlinks,
  hard links, non-regular files, unsafe modes, invalid sizes, NULs, invalid UTF-8,
  empty values, and multiline values.
- The optional SSH key is copied into role-private tmpfs as mode `0600` only after
  validation. It is never taken from shared backup staging.
- Installer and wrapper reject Docker/Compose control variables, loader hooks,
  TLS-key-log settings, duplicate/malformed keys, URL overrides that bypass reviewed
  fragments, and unsafe environment-file ownership or permissions.

File-backed secrets reduce exposure through `docker inspect`, child-process
environments, crash reports, and logs. They are not a vault: code executing inside a
role can read every secret deliberately granted to that role.

### Compose topology and operations boundary

- The app publishes only `127.0.0.1:8000`; the expected public path is through an
  operator-managed TLS reverse proxy.
- App, cloud, database, files, storage, logs, Beat, migration, and preflight roles use
  distinct database/broker networks. Egress bridges are also role-specific and disable
  inter-container communication.
- The stock default is core-only: database, broker, migrations, preflight, and web.
  All provider workers and Beat require the explicit `operations` profile.
- `restart: "no"` is used for operations roles so an old or intentionally stopped
  worker does not silently resume after daemon restart.
- The app can request destructive cache/log work, but the storage worker performs it
  under durable ownership and lease rules. Destructive paths are anchored, no-follow,
  and serialized against live writers.
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
- It does not upgrade a checkout in place and does not provision the host.
- Install paths, parents, checkout files, `.env`, secrets, overrides, and resource
  ownership are validated before mutation.
- A stable random installation ID labels containers, networks, volumes, and an empty
  sentinel volume. Exact-name inventory prevents Compose from adopting a foreign or
  unlabeled resource that label-only discovery would miss.
- Secret migration is atomic and fail-closed. Existing secret values are preserved,
  moved to files, and blanked from `.env` without being printed.
- RabbitMQ generation transitions, legacy-project adoption, runtime overrides,
  deletion, and additional Compose files require narrow, value-bearing gates.
- The wrapper rejects privilege, entrypoint, environment, volume, port, build,
  orphan-removal, image-removal, and volume-deletion escape routes unless the exact
  reviewed maintenance operation is explicitly authorized.

### Connected application hardening

Container isolation would be undermined by unsafe application behavior, so this review
also closed connected attack paths:

- plaintext FTP is disabled by default; SFTP/FTPS use strict host/TLS verification,
  with insecure FTP requiring an explicit risk opt-in;
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

### Live web-container attack checks

Observed on `demo.backupsheep.com` after final deployment:

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
| Write to `/backups` | Refused |
| Write to protected `/tmp` | Succeeded, then probe removed |
| `pip` | Absent |
| Setuid/setgid files | None |
| Published port | `127.0.0.1:8000` only |
| Networks | app-broker, app-database, app-egress only |
| Log bounds | `json-file`, `10m`, five files |

This demonstrates containment of an ordinary web-process compromise. It does not prove
containment from a kernel/container-runtime vulnerability, Docker-daemon compromise, or
credentials intentionally readable by the web process.

### Live database and broker checks

- PostgreSQL is healthy as `999:999`, read-only, capability-free, NNP/seccomp enabled,
  bounded to 256 PIDs, 2 GiB, and 2 CPUs. `gosu` is absent. An authenticated TCP query
  returned the exact `backupsheep|backupsheep` user/database pair, and checksums are on.
- RabbitMQ is healthy as server UID/GID `100:101`, NNP/seccomp enabled, with zero
  inherited/permitted/effective/ambient capabilities and the documented bootstrap
  bounding ceiling. It has no published host port.
- The application could not discover a Docker socket or write immutable source/system
  paths. PostgreSQL/RabbitMQ are not reachable directly from the public host network.

### HTTP attacker probes

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

### Regression tests

The final source state passed:

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

## Image and source scanning

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

## Demo deployment and recovery evidence

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

### Final live state

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

## Residual risk register

### Critical

1. **No per-backup AEAD with external KMS custody.** Backup archives and staged restore
   data do not have a tenant/context-bound authenticated-encryption envelope whose key
   is unavailable to a database/storage-only attacker. Implement a per-backup DEK,
   misuse-resistant AEAD, tenant/account/node/artifact AAD, external KMS/HSM wrapping,
   versioned envelopes, authenticated restore-before-write, rotation, key-loss, and
   tamper/tenant-swap tests.
2. **Privileged data lanes can read or modify plaintext.** Database, files, and storage
   workers share writable `backup_workdir`; the app can read Local Storage at `/backups`.
   A compromise of a granted role can exfiltrate or tamper with material without a host
   escape. Split work/transfer/cache/log/lock volumes, make producer/consumer mounts
   read-only where possible, and authenticate every artifact before upload and restore.

### High

1. **Shared RabbitMQ identity/vhost.** A compromised authenticated role can publish a
   crafted task to another lane. Add per-role publisher/consumer users, queue ACLs or
   vhosts, authenticated task envelopes, task/argument authorization, and alerts for
   unexpected publisher/consumer combinations.
2. **Shared PostgreSQL principal.** Application roles and migrations do not yet prove
   separate least-privilege database identities. Split schema owner/migrator and
   runtime roles, then narrow grants by service responsibility.
3. **Unrestricted outbound internet access.** Role-specific egress bridges isolate
   containers but do not allowlist destinations or universally block cloud metadata.
   Portable Compose cannot supply a complete host egress firewall. Add an explicit
   per-role egress proxy/firewall and deny link-local metadata by default.
4. **Secrets are shared with every role that needs them.** File mounts reduce passive
   leakage but not post-compromise reads. Split signing/service keys by role/purpose,
   integrate an external secret manager, and test rotation/revocation.
5. **No portable volume byte/inode quotas or guaranteed encryption.** A job or attacker
   can fill Docker storage, and named-volume confidentiality depends on the host.
   Require capacity/inode alarms, retention controls, filesystem/project quotas where
   supported, encrypted storage, and documented emergency recovery.
6. **Unsigned local image distribution.** Inputs are pinned and builds are evidenced,
   but release consumers do not yet verify a signed image, SBOM, provenance statement,
   or transparency-log record tied to a protected release commit.
7. **Provider and restore behavior remains held.** Core health does not prove provider
   mutation, duplicate avoidance, crash reconciliation, destination integrity, or
   restoration. Keep operations off until durable work and provider ownership are
   reviewed and representative backup/restore/chaos gates pass.
8. **Enterprise identity lifecycle is incomplete.** Organization-enforced MFA,
   SAML/OIDC SSO policy, SCIM deprovisioning, governed break-glass access, scoped
   selector-verifier API credentials, and immutable off-host audit evidence remain
   incomplete or unproven.
9. **WordPress protocol compatibility remains a rollout blocker.** The hardened client
   avoids query-string key disclosure, while the existing plugin contract may still
   expect it. Release a compatible plugin, rotate keys, and prove URLs/logs stay clean
   before enabling WordPress work.

### Medium and operational

1. Same-host PostgreSQL/RabbitMQ transport is plaintext. Internal unpublished networks
   are an accepted single-host exception, not suitable across an untrusted boundary.
2. RabbitMQ's server process retains bootstrap capabilities in its bounding set even
   though permitted/effective sets are zero and NNP is active. A custom verified
   entrypoint or separately initialized pre-owned volume can remove that ceiling.
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

## Enterprise remediation order

### P0 — before claiming enterprise protection for sensitive backups

1. Add per-backup AEAD and external KMS/HSM envelope custody.
2. Authenticate artifact identity, tenant context, provenance, and integrity before any
   restore writes to a destination.
3. Split RabbitMQ users/permissions and database migration/runtime roles by lane.
4. Split writable staging volumes and reduce the web/worker data each compromised role
   can read.
5. Publish signed multi-architecture images, SBOMs, provenance, and a verified exact-ref
   installer flow under protected release governance.
6. Run provider-specific backup, restore, crash, retry, duplicate, and unknown-outcome
   reconciliation gates with fresh ownership evidence.

### P1 — production hardening

1. Add per-role egress enforcement and metadata denial.
2. Add encrypted/quota-controlled storage, byte/inode alerts, and recurring encrypted
   control-plane backups with restore drills.
3. Integrate an external secret manager and exercise key rotation/revocation.
4. Remove RabbitMQ's residual bounding set through a verified non-root initialization
   design.
5. Add immutable off-host audit export and alerting for auth abuse, preflight changes,
   unexpected task publishers, outbound destinations, disk growth, queue age, and
   container restarts.
6. Complete enterprise identity, API credential, invite, and WordPress compatibility
   work.

### P2 — continuous assurance

- Rescan exact digests on every build and on vulnerability-database refresh.
- Re-run the full suite and hostile build-context tests after Dockerfile/Compose changes.
- Test cgroup v1/v2, amd64/arm64, Docker Engine upgrades, reboot/restart behavior, and
  supported PostgreSQL/RabbitMQ upgrade paths.
- Offer host guidance for rootless Docker, AppArmor/SELinux, firewalling, encryption,
  quotas, log shipping, and daemon protection without silently changing the host.

## Safe installation and operation

For a fresh installation, use an unprivileged Docker-authorized account and a user-owned
directory. Inspect the installer downloaded from the same exact commit:

```bash
COMMIT=7be0729374e61558740f7a564248a7c4491049be
curl -fSLo install.sh \
  "https://raw.githubusercontent.com/bilal414/backupsheep/${COMMIT}/install.sh"
less install.sh
chmod 700 install.sh
./install.sh \
  --ref "${COMMIT}" \
  --domain backups.example.com \
  --install-dir "$HOME/.local/share/backupsheep"
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
./backupsheep-compose --profile operations up --detach
```

Never use `down --volumes`, `rm -v`, image pruning, or orphan removal as routine
maintenance. These can destroy the control plane, queue, Local Storage, SSH trust, work
state, or installation-identity witness. Follow
[`operations.md`](../guides/operations.md),
[`disaster-recovery.md`](../guides/disaster-recovery.md), and
[`rabbitmq-upgrade.md`](../guides/rabbitmq-upgrade.md).

## Evidence limitations

- Scanners report known data in their databases, not absence of exploitable behavior.
- Static and unit/integration tests cannot prove kernel/runtime isolation against an
  unknown container escape.
- Core health and an empty consumer set intentionally do not prove providers, backups,
  restores, or cleanup.
- A `Completed` application status is not restoration evidence. Enterprise acceptance
  needs provider-side ownership, persisted artifact integrity, and successful restore
  validation.
- The rollback bundle was validated for integrity/decryption/listing. A full destructive
  rollback rehearsal was not performed on the live demo after the final deployment.
- Host reverse-proxy, daemon, firewall, MAC, patching, encryption, and rootless posture
  are explicitly outside this Docker-owned boundary.

## Final conclusion

The Docker setup is now defensible as a hardened default and substantially more secure
against common web-RCE, secret-leakage, persistence, lateral-movement, supply-chain,
unsafe-startup, and resource-exhaustion attacks. The final core-only demo deployment and
full regression evidence support that conclusion.

Enterprise use should remain conditional, not marketed as attack-proof. The P0 items—
especially external-KMS authenticated backup encryption, role-specific broker/database
identities, reduced shared staging, signed release provenance, and real provider/restore
proof—must close before BackupSheep can credibly claim enterprise-grade protection for
high-value backup data.

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
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [NIST SP 800-218 Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Django deployment checks](https://docs.djangoproject.com/en/6.0/ref/checks/)
