# Signed container releases

BackupSheep's release workflow is checked in but deliberately dormant. Merging it
does not build, sign, promote, or publish anything. An administrator must protect
the `signed-release` environment and set
`BACKUPSHEEP_SIGNED_RELEASES_ENABLED=true` before a SemVer tag can start it.

## Trust and promotion model

The release is an ordered, fail-closed chain:
`release_regression` -> `build_scan` -> `sign_promote` -> `publish_evidence`.
Each job must succeed before the next one can run, and the four jobs have separate
permission boundaries:

1. `release_regression` calls the repository's reusable
   `supply-chain-security.yml` workflow against the exact tagged commit with only
   `contents: read`. It reruns the dependency audits, manifest and egress-policy
   validation, production image builds, and application/security regression suite.
   It has no package, OIDC, or release-publication permission and publishes no
   candidate image. A failure prevents `build_scan` from starting.
2. `build_scan` also has only `contents: read`. It builds and scans private local
   OCI layouts, records their digest-bound evidence, and uploads the candidate
   workflow artifact. It has neither package-write nor OIDC permission and cannot
   publish to a registry.
3. `sign_promote` is protected by the `signed-release` environment. It installs
   hash-verified Cosign and ORAS binaries, revalidates all downloaded evidence,
   and is the only job with package-write and OIDC permission. After approval it
   pushes the exact verified layouts only to the explicit `*-quarantine`
   repositories, signs those digests, and verifies them online. Only then does it
   copy the exact OCI index digest to an official SemVer tag. It signs the official
   digest separately and reruns the complete online verifier.
4. `publish_evidence` can write GitHub release contents but cannot write packages
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

The release set is completeness-gated and resumable, and contains three separately
scanned and signed images: the application, its PostgreSQL runtime, and the no-secret
egress guard. An interruption can leave a partial set of exact SemVer tags; a rerun
verifies every existing digest and publishes only the missing exact tags. A missing or
unverifiable image blocks completion and release-evidence publication.

## Immutable inputs and real provenance

Every GitHub Action is pinned to a full commit. BuildKit and QEMU container images
are digest pinned. Cosign, ORAS, Syft, and Trivy are downloaded directly from exact
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

## Scanner and SBOM policy

Trivy and Syft run in a cleared environment with explicit trusted empty config
files. Trivy also receives an explicit empty ignore file. Repository-local
`.syft.yaml`, `trivy.yaml`, `.trivyignore`, environment overrides, and a hidden
`--ignore-unfixed` flag cannot silently weaken the gate.

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

The lock checked in on 2026-08-29 uses manifest
`sha256:b494387b91d0e201f9a8945709a02eb66558cba454efa265b4638e7edde45132`
and expires at `2026-08-30T13:02:57.331758258Z`. It is evidence for that bounded
window, not a permanent vulnerability result.

Every exact platform child must have:

- a Syft source catalog whose input and manifest digest match the quarantine
  `repository@sha256` reference and whose artifact inventory is nonempty;
- an SPDX document with at least one package;
- a CycloneDX document with at least one component; and
- a structurally complete Trivy report with target/class/type metadata and a
  nonempty package inventory.

Any HIGH or CRITICAL vulnerability fails, including one without a vendor fix. The
checked-in policy has no allowlist. Scanner evidence, signing, registry lookup, and
consumer verification always use digest references; tags are never verification
boundaries.

## Evidence and independent verification

Both candidate and final workflow artifacts use GitHub's 90-day maximum retention.
After final registry verification, the workflow makes a deterministic archive of
the manifest, raw OCI objects, BuildKit provenance, SBOMs, Trivy reports, policy
snapshot, and Sigstore bundles. It signs that archive and publishes the archive,
checksum, signature bundle, release manifest, manifest bundle, and policy as assets
on the immutable Git tag's GitHub release.

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

## Administrator-owned controls and remaining rollout gates

Repository code cannot enforce these external controls. Before opt-in:

- protect `main` and release tags against force-update and deletion;
- require reviewers on `signed-release` and disable administrator bypass;
- restrict Actions to reviewed full-commit-pinned actions;
- create/authorize both quarantine GHCR packages and official packages for the
  workflow token, while denying unnecessary human write access;
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
for all three Dockerfiles, Cosign bundle verification, official tag refusal on
replay, and GitHub release asset publication. This checked-in foundation does not
itself configure those GitHub/GHCR controls and has not published or deployed a
release.
