# Signed container release foundation

BackupSheep's signed-image workflow is checked in but intentionally disabled. Merging
the workflow does **not** publish an image. An administrator must first protect the
`signed-release` GitHub environment and then set the repository variable
`BACKUPSHEEP_SIGNED_RELEASES_ENABLED=true`.

The release job accepts only a SemVer-shaped tag whose exact commit is contained in
`main`. It builds the application and bundled PostgreSQL images for `linux/amd64` and
`linux/arm64`, with pinned BuildKit/QEMU inputs and BuildKit `mode=max` provenance. A
unique, run-scoped registry tag is used only to push each OCI index. Every scan,
signature, attestation, manifest entry, and consumer verification uses
`repository@sha256:digest`; the run-scoped tag is never a trust boundary.

## Evidence and release gate

For each platform manifest, the workflow:

1. resolves and validates the exact child digest from the OCI index;
2. runs Trivy 0.74.0 against that digest and rejects every HIGH or CRITICAL finding,
   including an unfixed finding;
3. creates SPDX JSON and CycloneDX JSON SBOMs from that digest;
4. keyless-signs the platform digest through GitHub Actions OIDC; and
5. keyless-attests both SBOM predicates to that digest.

It also keyless-signs each multi-platform index, attaches a SLSA provenance v1
predicate to it, signs the release manifest as a blob, and reruns the checked-in
verifier against the registry. There is no vulnerability allowlist in the initial
policy. Introducing one requires an explicit policy and review design; a scanner flag
or ignore file is not an accepted exception mechanism.

The retained `signed-release-candidate-<run>-<attempt>` artifact contains the release
manifest, policy snapshot, OCI indexes, scan reports, both SBOM formats, provenance,
and Sigstore bundles. A partial artifact from a failed run is diagnostic evidence,
not a release. A release is eligible for promotion only after the final verification
step succeeds.

## Verification

With the downloaded evidence directory and Cosign 3.1.3 on `PATH`, run:

```bash
python3 scripts/verify_release.py \
  --policy deploy/release-policy.json \
  --manifest release-artifacts/release-manifest.json \
  --artifacts-dir release-artifacts \
  --manifest-bundle release-artifacts/release-manifest.bundle.json
```

The default verifier is online and fail closed. It checks the manifest signature,
index and platform signatures, GitHub repository/workflow/tag/commit certificate
claims, Rekor-backed keyless verification, SLSA predicate contents, and exact SBOM
predicate contents. It also recomputes every evidence hash and independently rejects
HIGH/CRITICAL entries in the Trivy reports.

`--offline` validates only structure and hashes. Its success message explicitly says
that signatures were not checked; it must never be used as release authorization.

## Administrative prerequisites

Before enabling the repository variable:

- protect `main` and release tags against force-update and deletion;
- protect the `signed-release` environment with required reviewers and prevent
  administrator bypass;
- restrict Actions to reviewed, commit-pinned actions;
- confirm GHCR package visibility and retention for both image repositories;
- make the signed-release workflow a required release status; and
- choose who may create release tags and approve vulnerability-policy changes.

Keyless GitHub OIDC signing needs no long-lived signing key. GHCR and GitHub governance
still require repository-administrator decisions and cannot be enforced by this commit
alone.
