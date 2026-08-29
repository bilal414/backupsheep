# BackupSheep Docker cyber-defense assessment: 2026-08-29 addendum

**Status:** release candidate; not yet merged or deployed  
**Repository:** `bilal414/backupsheep`  
**Candidate branch:** `codex/cyber-defense-completion-20260829`  
**Initial evidence snapshot:** `9d70584173860c0b251becc88e9ac0dda9358c4c`  
**Primary change:** replace the application artifact-encryption dependency on AWS KMS
with installation-local, lane-scoped wrapping-key files  
**Parent assessment:**
[`docker-hardening-20260823.md`](docker-hardening-20260823.md)

This addendum records the current repository-owned Docker and application-security
delta. It does not revise the historical image digests, test counts, live observations,
or deployment claims in the parent assessment.

## Decision

The stock BackupSheep artifact-encryption path no longer requires an AWS account, AWS
credentials, an IAM role, or an AWS KMS API. Production Docker installations use two
independent local keyrings: one for the database source/restore lane and one for the
files source/restore lane. Each backup still receives a fresh random data-encryption
key; the lane keyring protects only that data key. Storage workers receive ciphertext
and do not receive either lane keyring.

This is a strong self-hosted default, but it is not equivalent to a non-exportable HSM
key. Code execution in a source lane can read that lane's plaintext inputs and mounted
keyring. Lane separation prevents that compromise from automatically granting the
other lane's wrapping key, and storage-lane compromise alone does not grant decryption.

The result must not be described as “bulletproof” or “attack proof.” The defensible
claim is narrower: the AWS KMS runtime dependency has been removed, the replacement is
fail-closed and lane-separated, and exact-release operational gates remain before an
enterprise release.

## Responsibility boundary

This assessment owns the repository-supplied application code, images, entrypoint,
Compose model, installer, wrapper, migration behavior, secret mounts, and release
verification path.

As requested, it does not own or change:

- the host operating system, kernel, firewall, TLS proxy, DNS, storage encryption,
  audit service, or patch policy;
- Docker Engine installation, daemon configuration, socket authorization, rootless
  mode, user namespaces, AppArmor, or SELinux;
- host-user security, physical security, or protection from a malicious Docker-daemon
  administrator.

The installer validates the Docker capabilities it needs and fails closed when its
container contract is absent. It does not modify the host to create those conditions.

## Updated threat model

The KMS replacement assumes an attacker may:

1. obtain code execution in the public web, storage, database, or files role;
2. inspect environment variables, Docker metadata, logs, process arguments, and every
   file deliberately mounted into a compromised role;
3. tamper with a keyring, substitute another installation's keyring, swap lanes, reuse a
   wrapped data key, alter an envelope, or remove a legacy rotation key;
4. interrupt installation, migration, rotation, encryption, upload, or restore at an
   arbitrary instruction boundary;
5. supply hostile settings, paths, symlinks, hard links, filesystems, Git objects,
   Compose controls, image references, or release evidence;
6. compromise storage without first compromising a source/restore lane.

The trusted boundary still includes the installing user and Docker daemon. A process
with Docker control can replace images, mounts, entrypoints, or keyring files and is
therefore outside the protection this Compose model can provide.

## AWS-free artifact custody

### Cryptographic construction

- BSE1 v2 uses AES-256-GCM-SIV authenticated encryption for backup payloads.
- Every artifact receives a random 256-bit data key and a random 96-bit wrapping nonce.
- The local provider wraps the data key with AES-256-GCM-SIV under the active 256-bit
  lane root key.
- The wrap's authenticated context binds the installation, lane, account, node,
  backup UUID, Django model, purpose, context digest, provider, and root-key ID.
- A wrapped key copied to a different backup, installation, model, or lane fails
  authentication.
- Public artifact headers omit the backup identity and plaintext/context digests;
  decrypting workers verify private terminal metadata before publishing plaintext.

Implementation anchors:

- `backupsheep/artifact_crypto/providers/local_file.py`
- `backupsheep/artifact_crypto/context.py`
- `backupsheep/artifact_crypto/envelope.py`
- `apps/_tasks/artifact_encryption.py`

### Keyring format and lifecycle

- The installer generates separate database and files keyrings from the operating
  system CSPRNG. Key material is never accepted through an environment variable,
  command-line argument, application setting, image layer, or Git file.
- Each canonical keyring is bound to one 64-character installation identity and one
  exact lane. Unknown fields, duplicate IDs, duplicate key material, malformed bytes,
  noncanonical encoding, oversize files, and more than eight keys are rejected.
- The active key must be the first entry. Rotation prepends a new key and preserves all
  older keys needed to restore existing artifacts.
- Rotation requires the expected current active-key ID as a replay/staleness witness,
  requires the corresponding source worker to be stopped, publishes atomically, and
  refuses to evict a key when the eight-key bound is reached.
- A missing keyring on an existing installation is never silently regenerated. Losing
  every copy of a required root key makes the corresponding backups unrecoverable.
- Direct non-Docker lifecycle operations require an owner-controlled mode-0700 parent
  and mode-0400 single-link file. Installer-managed Docker keyrings are handled only
  under the installer's deployment mutation lock.

Implementation anchors:

- `scripts/manage_artifact_keyring.py`
- `install.sh`
- `apps/management/commands/rotate_artifact_key_wraps.py`

### Docker custody and blast-radius controls

- Compose mounts the database keyring only into `worker-database` and the files
  keyring only into `worker-files`.
- The app, Beat, cloud, logs, migration, preflight, staging, storage, database, broker,
  egress guards, and release helpers receive no artifact root key.
- The entrypoint requires the exact reviewed keyring path, a read-only mount, safe
  metadata, one link, the matching runtime role, and absence of the other lane's key.
- Production settings accept only the `local-file` provider. The
  `local-development` provider remains test/development-only and is rejected in
  production or enterprise mode.
- Ambient AWS credentials, roles, metadata credentials, profiles, credential files,
  and SDK endpoint overrides are cleared by Compose and rejected at startup. This
  prevents an unrelated optional AWS integration from becoming implicit artifact-key
  authority.
- Ciphertext storage paths use randomized transfer identities. Storage workers neither
  need nor receive private backup-context identifiers or decryption keys.

Implementation anchors:

- `docker-compose.yml`
- `init.sh`
- `backupsheep/settings.py`
- `apps/management/commands/docker_preflight.py`
- `apps/_tasks/integration/storage/lease.py`
- `apps/_tasks/integration/storage/tasks.py`

## Migration and rollback behavior

The repository retains the literal historical provider name `aws-kms` only where it is
needed to recognize old database or installer state and fail safely. It is not a
selectable runtime provider, and no AWS KMS client is imported or constructed by the
artifact-encryption path.

Automatic migration is deliberately limited to an empty artifact estate. It refuses
the transition when it finds any existing data-key wrap, legacy artifact, historical
backup row, or storage-point row. BackupSheep does not pretend it can decrypt or convert
an AWS KMS wrap without the old KMS authority. The installer preserves the exact prior
policy and credential files in its rollback set until the empty-estate transition is
accepted, then removes obsolete artifact-KMS files from the live secret inventory.

This fail-closed policy avoids silent backup loss. An installation with real historical
AWS KMS artifacts needs a separately designed, operator-authorized migration while its
old KMS access is still available.

Implementation anchors:

- `apps/_migrations/0049_local_file_artifact_key_provider.py`
- `apps/management/commands/migrate_and_verify_artifact_provider.py`
- `install.sh`

## Optional AWS functionality that remains

Removing AWS KMS from artifact encryption does not remove BackupSheep's optional AWS
backup source, S3/S3-compatible destination, or SES capabilities. Their SDK packages
and domain-specific KMS fields may therefore remain in the monolithic application
image. Those integrations are inactive unless an operator configures them and do not
provide the root keys used by BSE1 artifact encryption.

The `aliyun-python-sdk-kms` package is a transitive dependency of the optional Alibaba
OSS integration; it is not used as the BackupSheep artifact key provider. Provider-
specific images could reduce this dormant dependency surface in a future release, but
it is not an AWS-account dependency in the stock encryption path.

## Signed-release lifecycle boundary

Fresh signed-release installation remains supported: the consumer authenticates the exact
release descriptor, manifest, image digests, provenance labels, verifier identity and local
image receipts before the installer mutates the runtime. Automatic signed-to-signed upgrade
and rollback are intentionally unsupported. The unfinished controller, journal tests,
source/target evidence states, runtime image copy, and stage-upgrade consumer branch were
removed rather than exposing an unaudited partial recovery protocol.

The consumer now accepts only the exact fresh-install argument shape. Former stage/upgrade
forms fail before the mutation lock, Docker access, downloads, or installation writes. A
signed deployment must move releases through a separately verified restore into a fresh
project while the old project remains intact. This is a material enterprise patching gap,
but the fail-closed boundary is safer than shipping dormant privileged orchestration code.

## Evidence at this snapshot

| Evidence | Result | Scope |
| --- | --- | --- |
| Focused installer/runtime/migration/keyring tests | 129 passed | AWS-free provider installation, migration, mounts, rotation, and fail-closed contracts |
| Adversarial provider/settings tests | 19 passed | foreign lane/installation, tamper, context swap, unsafe metadata, production policy |
| Independent macOS provider/lifecycle rerun | 24 passed | provider wrapping, normative vector, keyring lifecycle; excludes Linux-only anonymous-file tests |
| Static runtime-provider audit | Pass | no AWS KMS provider export, factory branch, client construction, or dynamic provider import |
| Rendered Compose mount review | Pass | only matching source workers receive matching keyrings; storage receives neither |
| Signed-upgrade refusal contract | Pass | former stage/upgrade forms made no Docker call, mutation lock, or installation byte/metadata change |
| Shell syntax and whitespace checks | Pass | candidate snapshot |

The complete BSE1 envelope suite depends on Linux `O_TMPFILE`/`linkat` behavior and is
therefore a Linux release gate, not a macOS compatibility claim. Those real-filesystem
primitives were not re-executed for this macOS evidence cut and must run against the
final merged commit.

## Open release gates

This addendum is not release approval. At the initial evidence snapshot:

- signed cross-version in-place upgrade is intentionally unsupported; an enterprise
  patching strategy based on separately verified fresh-project restore remains required;
- the final full application, installer, image, topology, migration, and adversarial
  suites had not yet run against one frozen final commit;
- the current branch had not been pushed to the pull request, approved, or merged into
  `develop`;
- fresh exact-image multi-architecture build, SBOM, provenance, CodeQL, locked Trivy
  database, and zero-High/Critical gates had not yet completed for that final commit;
- live key creation, backup, ciphertext-only storage, restore, cross-lane denial,
  rotation, old-key restore, tamper, key-loss, restart, and crash recovery had not yet
  been evidenced on the final demo deployment;
- SSH to `demo.backupsheep.com:22` was refusing connections, so revision, runtime,
  rollback, and deployment provenance could not be verified or changed.

## Enterprise release acceptance

Close this addendum only when one exact commit has all of the following evidence:

1. green local and GitHub application/security regression gates;
2. signed, digest-pinned release descriptors for every production image and platform;
3. matching SBOM/scanner identities with no unreviewed High/Critical finding;
4. a fresh installation with two distinct keyrings and no AWS account or ambient AWS
   credential;
5. real database and files backups whose destination contains only BSE1 ciphertext;
6. successful restore with the correct lane, denied restore with the other lane,
   denied tampered/swapped artifact, and denied missing-key restore;
7. key rotation followed by successful restore of both pre- and post-rotation backups;
8. interruption/resume proof around encryption, upload, restore, and migration, plus proof
   that unsupported signed upgrade forms fail before Docker or filesystem mutation;
9. exact live container identity, image digest, mount, capability, namespace, network,
   resource, health, and preflight evidence;
10. rollback proof that preserves volumes, keyrings, and recoverability without
    claiming success from an HTTP health check alone.

Until those gates are attached to the merged release, the correct status is
**implemented candidate with AWS-free encryption; final release and deployment evidence
pending**.
