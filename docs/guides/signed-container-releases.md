# Signed container releases

BackupSheep's release workflow is checked in but deliberately dormant. Merging it
does not build, sign, promote, or publish anything. An administrator must protect
the `signed-release` environment and set
`BACKUPSHEEP_SIGNED_RELEASES_ENABLED=true` before a SemVer tag can start it.

## Trust and promotion model

The release is an ordered, fail-closed chain:
`release_regression` -> `build_scan` -> `protected_rescan` -> `sign_promote` ->
`publish_evidence`. Each job must succeed before the next one can run, and the five jobs have separate
permission boundaries:

1. `release_regression` calls the repository's reusable
   `supply-chain-security.yml` workflow against the exact tagged commit with only
   `contents: read`. It reruns the dependency audits, manifest and egress-policy
   validation, production image builds, and application/security regression suite.
   It has no package, OIDC, or release-publication permission and publishes no
   candidate image. A failure prevents `build_scan` from starting.
2. `build_scan` also has only `contents: read`. It builds and scans private local
   OCI layouts and uploads an explicitly untrusted preview artifact for diagnostics.
   That artifact is not downloaded, parsed, or reused by either protected job. The
   preview has neither package-write nor OIDC permission and cannot publish to a
   registry.
3. `protected_rescan` is protected by the `signed-release` environment. It has
   package-write permission for quarantine but no OIDC permission. After approval it
   independently rebuilds all five multi-platform OCI layouts from the exact remote
   commit with the pinned QEMU, BuildKit, and build action. It does not download the
   preview artifact. From those protected layouts it freshly extracts the raw indexes
   and BuildKit provenance, regenerates the migration transition, Syft/SPDX/CycloneDX
   SBOMs, Trivy and Grype reports for all ten release-image platform children, all
   verifier evidence, the release manifest, and the descriptor. It prepares fresh
   copies of both exact locked vulnerability databases, exports only the exact
   manifest-derived inventory into new private files, and pushes only the protected
   layouts to the explicit `*-quarantine` repositories. No producer-authored layout,
   SBOM, provenance, transition record, scan, manifest, or descriptor crosses this
   boundary.
4. `sign_promote` has package-write and OIDC permission but receives only that
   protected exact-inventory artifact. It does not install or execute scanners and
   never downloads or opens a producer OCI layout. Before registry credentials it
   revalidates the exact inventory, policy, manifest, descriptor, scanner outputs, and
   database receipts. It then re-fetches and byte-compares all five quarantine indexes,
   ten release platform manifests, ten attestation manifests, and two verifier child
   manifests before requesting an OIDC signature. Only after signing and online
   verification does it
   copy the exact OCI index digest to an official SemVer tag. It signs the official
   digest separately and reruns the complete online verifier. Before promotion it
   also creates a canonical sixteen-line V2 consumer descriptor binding the tag,
   source commit, release-manifest SHA-256, all five official digest references,
   and the independently distributed verifier contract. It signs that descriptor
   as a blob with the same OIDC identity and verifies the bundle exactly.
5. `publish_evidence` can write GitHub release contents but cannot write packages
   or request an OIDC token. It verifies the signed archive before publishing it.

No candidate is built or published unless the read-only regression gate passes.
A candidate rejected by `build_scan` never reaches a registry. After quarantine
verification, the workflow copies each exact index to a commit/run-bound `staged-*`
tag in its official repository so the official digest can be signed and verified.
Those non-SemVer staging tags can remain after an interrupted run, but no official
SemVer tag is written until final verification succeeds. Promotion refuses a
mismatched existing tag and treats authentication, network, TLS, and unexpected
registry errors as failures, not as evidence that a tag is absent. Regression success
is necessary but is not release proof: the digest-bound build, scan, signing,
promotion, and evidence gates must also succeed.

The release set is completeness-gated and resumable, and contains five separately
scanned and signed images: the application, its PostgreSQL runtime, the no-secret
egress guard, RabbitMQ 4.3 runtime, and the isolated RabbitMQ 4.2 upgrade helper.
An interruption can leave a partial set of exact SemVer tags; a rerun
verifies every existing digest and publishes only the missing exact tags. A missing or
unverifiable image blocks completion and release-evidence publication.

## Immutable inputs and real provenance

Every GitHub Action is pinned to a full commit. BuildKit and QEMU container images
are digest pinned. Cosign, ORAS, Syft, Trivy, and Grype are downloaded directly from exact
release asset URLs and installed only after their checked-in SHA-256 values match.
No release installer script from another repository is executed.

Each build uses the remote Git URL at the exact 40-character release commit rather
than the runner workspace. BuildKit is requested to emit SLSA v1 provenance with
`mode=max` and the release workflow as builder ID. The collector retrieves the raw
OCI index, each index-bound attestation manifest, and the actual in-toto provenance
blob. It does not synthesize a replacement predicate. The verifier requires:

- the retained raw index bytes to hash to the declared registry digest;
- exactly `linux/amd64` and `linux/arm64` child descriptors;
- exactly one attestation manifest bound to every child digest;
- the provenance blob digest to be a layer in that attestation manifest;
- an in-toto Statement v1 subject containing the exact child digest;
- the exact remote Git commit, Dockerfile, OCI labels, and workflow builder ID;
- complete BuildKit request and dependency metadata; and
- nonempty `mode=max` LLB, source, and layer data.

These fields follow BuildKit's documented [SLSA provenance
definition](https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md).

## Signed transition authorization

Manifest schema 4 carries a bounded transition record; a SemVer comparison is never
upgrade authorization. The reviewed source input is
`deploy/release-transition-policy.json`. It assigns one positive, monotonically increasing
release epoch and either an empty predecessor list (fresh installs only) or at most eight
exact predecessor tuples. Each tuple binds the source tag, epoch, commit, manifest,
descriptor and descriptor-bundle digests, complete migration-set and leaf-set digests, and
the source verifier's immutable index, platform/config, runtime-contract and trusted-root
identity. Ranges, wildcards, mutable references, equal/higher source epochs, duplicates and
unknown keys are rejected.

The protected rebuild job materializes the release application's exact amd64 child from
the same protected remote-commit build inputs as the retained multi-platform OCI layout.
Before running it, the collector requires the local image configuration ID to equal the
config digest in that exact OCI child and checks the release source/revision/version labels.
It then executes the immutable image ID—not its mutable local tag—with no network, a read-only root,
dropped capabilities, `no-new-privileges`, bounded memory/CPU/PIDs and a private hardened
tmpfs. The model-free inventory command loads Django's complete migration graph without a
database, refuses replacement or non-transactional migrations, and emits canonical sorted
complete and leaf sets with domain-separated SHA-256 digests.

The reviewed policy bytes and generated migration contract are private, no-clobber files
under `transition/`. Their hashes and normalized content are embedded in the manifest and
revalidated before signing; both files are also required members of the deterministic
signed evidence archive. Editing the reviewed policy or migration artifact after generation
therefore invalidates the release. The initial checked-in epoch has no accepted predecessor,
so it authorizes fresh installation only. Adding a predecessor requires explicit security
review of every exact field. This publication metadata does not enable runtime mutation.
Automatic signed-to-signed upgrade and rollback are intentionally unsupported, and the
application image contains no staged-upgrade controller or source/target journal.

## Scanner and SBOM policy

Trivy, Grype, and Syft run in cleared environments with explicit trusted empty config
files. Trivy also receives an explicit empty ignore file. Repository-local scanner
configuration, ignore files, update settings, and hidden fixed-only flags cannot silently
weaken the gate. Release Grype scans are VEX-free and reject every ignored finding.

The recurring source and exact-image gates do not let Trivy resolve or update its
mutable default vulnerability database. `deploy/trivy-db-lock.json` records one reviewed
`ghcr.io/aquasecurity/trivy-db` OCI manifest, its only layer, the compressed layer
size/hash, both extracted file sizes/hashes, and the database timestamps. The pinned
ORAS binary fetches the manifest and blob by those digests with an empty home and
Docker configuration. `scripts/prepare_trivy_db.py` then rejects links, paths other
than `trivy.db` and `metadata.json`, duplicate/archive-extension records, unexpected
types, size drift, hash drift, metadata drift, and a stale `NextUpdate`. Trivy runs
against that isolated cache with database, Java-database, and check updates disabled
and with offline scanning enabled. The cache is rehashed after every image scan, and
each retained source/image summary binds the lock, manifest, layer, database, and
preparation evidence hashes.

Grype uses a separate reviewed database and therefore supplies independent coverage.
`deploy/grype-db-lock.json` binds one exact official v6 archive URL, archive size/hash,
database schema/build/expiry, extracted database size/hash, and import metadata.
`scripts/prepare_grype_db.py` refuses redirects, verifies the pinned Grype 0.116.1
binary, imports the exact archive into a private cache, checks the only permitted cache
members, and compares Grype's own database status with the lock. Scans disable database
and application updates, reverify the cache after every image, and fail when the reviewed
database expires. Both database locks and preparation records are hash-bound into the
signed release manifest. Each individual Trivy and Grype report record also embeds the
exact lock, preparation-record, extracted-database, schema, and generation-time receipt.
The verifier checks Grype's own `descriptor.db` status and checks every report receipt
against the protected database evidence, so a producer-authored report is never
sufficient for signing.

The upstream database artifact is digest-locked; this control does not claim that
upstream signs it. A lock refresh is therefore a deliberate reviewed change, never an
automatic acceptance of whatever `:2` points to:

1. Resolve the current official `trivy-db:2` manifest and review its raw OCI structure,
   media types, creation time, single layer, and schema-2 metadata using the policy-
   pinned ORAS version and the official
   [Trivy database documentation](https://github.com/aquasecurity/trivy/blob/main/docs/guide/configuration/db.md)
   and [database repository](https://github.com/aquasecurity/trivy-db).
2. Independently hash the raw manifest, compressed layer, `metadata.json`, and
   `trivy.db`; record the exact byte sizes and `UpdatedAt`/`NextUpdate` values in the
   lock. Never copy only a mutable tag or a digest printed by an unreviewed script.
3. Review the lock diff and focused archive/freshness tests in a pull request. Until a
   fresh lock is merged, the scan is intentionally red once its exact `NextUpdate` is
   reached.

The lock refreshed on 2026-08-30 uses manifest
`sha256:b50899ac59bda25cea33ba1305154a041f916cc5aeb9e1e0b4efe56caebdbd52`
and expires at `2026-08-31T19:01:43.110911954Z`. It is evidence for that bounded
window, not a permanent vulnerability result.

Every exact platform child must have:

- a Syft source catalog whose input and manifest digest match the quarantine
  `repository@sha256` reference and whose artifact inventory is nonempty;
- an SPDX document with at least one package;
- a CycloneDX document with at least one component; and
- a structurally complete Trivy report with target/class/type metadata and a
  nonempty package inventory; and
- a Grype report whose embedded child manifest, image configuration, compressed layers,
  tool version, effective no-suppression policy, and digest reference all match the same
  exact platform child.

Any HIGH or CRITICAL vulnerability reported by either scanner fails, including one
without a vendor fix. The checked-in release policy has no allowlist or VEX exception.
Scanner evidence, signing, registry lookup, and
consumer verification always use digest references; tags are never verification
boundaries.

## Evidence and independent verification

The untrusted preview and final workflow artifacts use GitHub's 90-day maximum retention.
After final registry verification, the workflow makes a deterministic archive of
the manifest, raw OCI objects, BuildKit provenance, SBOMs, Trivy and Grype reports, policy
snapshot, and Sigstore bundles. It signs that archive and publishes the archive,
checksum, signature bundle, release manifest, manifest bundle, and policy as assets
on the immutable Git tag's GitHub release.

The protected artifact handed to the OIDC job is stricter than the final archive:
`scripts/protect_release_evidence.py` derives its complete file and directory inventory
from the validated manifest, copies each permitted input into a fresh `0600` file, and
rejects missing files, hard links, symbolic links, unknown files, and unknown directories.
The signer repeats that exact-inventory validation before obtaining registry credentials.

With an extracted evidence archive and the policy-pinned Cosign and ORAS versions:

```bash
python3 scripts/verify_release.py \
  --policy deploy/release-policy.json \
  --manifest release-artifacts/release-manifest.json \
  --artifacts-dir release-artifacts \
  --manifest-bundle release-artifacts/release-manifest.bundle.json \
  --cosign /trusted/path/cosign \
  --oras /trusted/path/oras \
  --phase final
```

The default verifier is online and fail closed. It refetches the OCI index by
digest from both quarantine and official repositories, requires byte-for-byte
identity with retained evidence, and verifies the manifest, index, platform,
provenance, and SBOM signatures against the GitHub workflow/tag/commit identity.

`--offline` validates structure, completeness, OCI membership, source binding, and
file hashes only. Its success message states that registry state and signatures
were not checked. Offline success is not release authorization.

## Docker installer consumption

`install.sh --ref COMMIT --release-tag TAG` is the current in-checkout signed-release
consumer entry point.
It requires the exact v-prefixed SemVer tag and the tag's exact lowercase 40-character
commit. Local build remains the default when `--release-tag` is absent.

The installer downloads only the V2 descriptor, descriptor bundle, and release manifest
from immutable GitHub release asset names. It bootstraps only BackupSheep's reviewed
first-party verifier, built from Cosign 3.1.3 and pinned by OCI index plus exact
amd64/arm64 child and configuration digests in `deploy/release-policy.json`. That
container runs as UID/GID 65532 with no Docker socket, a read-only root, all capabilities
dropped, `no-new-privileges`, bounded PIDs/CPU/memory, and a private `noexec,nosuid,nodev`
tmpfs. It runs with `--network none` and receives only read-only copies of the public
descriptor, bundle, and reviewed root in `deploy/release/sigstore-trusted-root.json`.

The descriptor blob signature must match the exact workflow URL for the tag, GitHub Actions
OIDC issuer, repository, workflow SHA, tag ref, and `push` trigger. The
descriptor parser accepts only its sixteen-line fixed order and five exact official
repositories. Its verifier fields are assertions against the independently distributed
bootstrap policy and cannot select the verifier that authenticates the descriptor; it
does not use `eval`, `source`, JSON interpolation, or tag-based image selection. The
workflow has already verified every official image signature online before signing that
descriptor. The consumer verifies the descriptor bundle offline; its authenticated digest
references then make Docker's content-addressed pulls the only registry operation. The
manifest hash, local `RepoDigests`,
image IDs, and OCI labels must also match. Compose is
then rendered through `deploy/release/signed-release.compose.yml`, which is forced last,
resets all application/PostgreSQL/egress/RabbitMQ build definitions, uses only the five
pre-pulled first-party digests, and sets `pull_policy: never`.

The same bounded client pre-pulls and records the descriptor-bound first-party RabbitMQ
4.3 runtime and 4.2 migration-hop digests. Signed Compose models set `pull_policy: never` for every
RabbitMQ service, including the migration overlay, so startup cannot trigger an implicit
registry request outside the watchdog. This guarantee is specific to signed-release mode.
The default local-build path still delegates `compose build --pull` to the operator's Docker
daemon and has no portable installer-side deadline for a daemon-side base-image transfer;
operators must enforce Docker/build network timeouts at the host or CI layer.

Rollback is not an `.env` image edit. The consumer accepts only the exact fresh-install
interface. Former stage/upgrade forms and every other argument shape are rejected before a
mutation lock is created, Docker is contacted, or installation files are changed. BackupSheep
does not ship an automatic signed-upgrade controller or journal because an incomplete
checkout + evidence + configuration + database transition would create an unsafe recovery
boundary. Do not apply the generic source-upgrade procedure to a signed-release installation
and do not edit the provenance fields. Use signed-release mode only for a fresh project whose
recovery plan is a separately verified restore into another fresh project; preserve the old
project intact. This limitation means the signed consumer is not an enterprise
security-patching channel.

### Sigstore trust-root rotation

The consumer never trusts a root downloaded beside release assets. The checked-in root is
copied from `sigstore/root-signing` commit
`0d8bd7c40a20b5291c18fb80fbe8c9f598685a2c`, path `targets/trusted_root.json`, and its
required SHA-256 is pinned in both policy and consumer code. A rotation requires a dedicated
security review of the root-signing/TUF history and key validity, then one atomic source
change updating the reviewed bytes, source commit, and hash. Release publishers or assets
cannot override it. The fresh-cache, network-disabled Cosign acceptance gate must pass before
the rotated root can authorize a release.

The first-party verifier has already completed its one-time bootstrap and the ordinary
release workflow neither rebuilds nor republishes it. Any reviewed verifier rotation that
reuses the bootstrap publisher must first pre-create and grant authenticated read/write
access to both exact GHCR package repositories:
`ghcr.io/bilal414/backupsheep-release-verifier-quarantine` and
`ghcr.io/bilal414/backupsheep-release-verifier`. Before its first write, the publisher
requires a successful, bounded JSON tag inventory from both repositories. A `404` string
or any other failed registry response is not evidence that a repository or tag is absent;
GHCR can mask unreadable packages as not found, so that condition fails closed.

## Administrator-owned controls and remaining rollout gates

Repository code cannot enforce these external controls. Before opt-in:

- protect `main` and release tags against force-update and deletion;
- require reviewers on `signed-release` and disable administrator bypass;
- restrict Actions to reviewed full-commit-pinned actions;
- pre-create and authorize every policy-listed quarantine and official GHCR package for
  authenticated inventory and workflow writes, while denying unnecessary human write
  access; a failed lookup or `404` is never an empty tag inventory;
- configure lifecycle retention for rejected quarantine candidates and orphaned
  commit/run-bound official `staged-*` tags, without deleting a digest or referrer
  reachable from an official SemVer release;
- protect official package/tag deletion through organization policy and audit it;
- make the release workflow a required release status; and
- mirror GitHub release evidence to organization-controlled immutable storage if
  policy requires retention beyond the life of the repository or GitHub account.

Run one protected pre-release tag as a controlled acceptance test before production
use. Confirm the read-only `release_regression` job completes before `build_scan`
and cannot publish packages or release contents. Then confirm GitHub OIDC issuance,
GHCR referrer behavior, ORAS graph copying, BuildKit's complete `mode=max` fields
for all five Dockerfiles, Cosign bundle verification, official tag refusal on
replay, fresh-cache descriptor verification under `--network none` using the checked-in
trust root, and GitHub release asset publication. This checked-in foundation does not
itself configure those GitHub/GHCR controls and has not published or deployed a
release.
