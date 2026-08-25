#!/usr/bin/env python3
"""Build the deterministic manifest and SLSA predicates for a release run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    ReleaseVerificationError,
    _digest,
    _load_json,
    _safe_artifact,
    _timestamp,
    _validate_policy,
    validate_release,
)


INDEX_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}
ATTESTATION_ANNOTATION = "vnd.docker.reference.type"


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return f"sha256:{hasher.hexdigest()}"


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _platform_digests(index_path: Path, expected_platforms: list[str]) -> dict[str, str]:
    index = _load_json(index_path, maximum_bytes=MAX_CONTROL_FILE_BYTES)
    if not isinstance(index, dict) or index.get("mediaType") not in INDEX_MEDIA_TYPES:
        raise ReleaseVerificationError(f"{index_path} is not an OCI/Docker image index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise ReleaseVerificationError(f"{index_path} has no manifests")

    result: dict[str, str] = {}
    for position, descriptor in enumerate(manifests):
        if not isinstance(descriptor, dict):
            raise ReleaseVerificationError(f"{index_path} manifest {position} is not an object")
        platform = descriptor.get("platform")
        if not isinstance(platform, dict):
            raise ReleaseVerificationError(f"{index_path} manifest {position} has no platform")
        os_name = platform.get("os")
        architecture = platform.get("architecture")
        platform_name = f"{os_name}/{architecture}"
        if platform_name in expected_platforms:
            if platform_name in result:
                raise ReleaseVerificationError(f"{index_path} repeats {platform_name}")
            result[platform_name] = _digest(
                descriptor.get("digest"),
                f"{index_path} manifest {position} digest",
            )
            continue

        annotations = descriptor.get("annotations") or {}
        if (
            os_name == "unknown"
            and architecture == "unknown"
            and isinstance(annotations, dict)
            and annotations.get(ATTESTATION_ANNOTATION) == "attestation-manifest"
        ):
            _digest(descriptor.get("digest"), f"{index_path} attestation manifest digest")
            continue
        raise ReleaseVerificationError(f"{index_path} contains unauthorized platform {platform_name}")

    if list(result) != expected_platforms:
        # The OCI descriptor order is part of the release contract so consumers and
        # evidence generation cannot silently disagree about the preferred platform.
        raise ReleaseVerificationError(
            f"{index_path} must contain exactly {expected_platforms} in policy order"
        )
    return result


def _artifact_record(artifacts_dir: Path, relative_name: str) -> tuple[Path, dict[str, str]]:
    path = _safe_artifact(artifacts_dir, relative_name, relative_name)
    return path, {"file": relative_name, "sha256": _sha256(path)}


def build_manifest(
    *,
    policy: dict[str, Any],
    artifacts_dir: Path,
    tag: str,
    source_commit: str,
    workflow_run: str,
    created_at: str,
    image_inputs: dict[str, tuple[str, Path]],
) -> dict[str, Any]:
    policy = _validate_policy(policy)
    _timestamp(created_at, "created_at")
    if set(image_inputs) != set(policy["images"]):
        raise ReleaseVerificationError("generator requires exactly the policy image set")
    release = {
        "tag": tag,
        "source_repository": policy["source_repository"],
        "source_commit": source_commit,
        "workflow_identity": (
            f"https://github.com/{policy['source_repository']}/{policy['release_workflow']}"
            f"@refs/tags/{tag}"
        ),
        "workflow_run": workflow_run,
        "created_at": created_at,
    }
    images: dict[str, Any] = {}
    for image_name in policy["images"]:
        index_digest, index_path = image_inputs[image_name]
        index_digest = _digest(index_digest, f"{image_name} index digest")
        repository = policy["images"][image_name]
        platforms = _platform_digests(index_path, policy["platforms"])
        dockerfile = "Dockerfile" if image_name == "app" else "Dockerfile.postgres"
        provenance = {
            "buildDefinition": {
                "buildType": "https://mobyproject.org/buildkit@v1",
                "externalParameters": {
                    "source_repository": release["source_repository"],
                    "source_commit": source_commit,
                    "image_repository": repository,
                    "dockerfile": dockerfile,
                    "platforms": policy["platforms"],
                },
                "internalParameters": {},
                "resolvedDependencies": [
                    {
                        "uri": f"git+https://github.com/{release['source_repository']}.git",
                        "digest": {"gitCommit": source_commit},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": release["workflow_identity"]},
                "metadata": {
                    "invocationId": workflow_run,
                    "startedOn": created_at,
                },
            },
        }
        provenance_name = f"provenance/{image_name}.slsa-v1.json"
        _write_json(artifacts_dir / provenance_name, provenance)
        _, provenance_artifact = _artifact_record(artifacts_dir, provenance_name)
        provenance_artifact = {
            "predicate_type": policy["attestations"]["provenance_predicate_type"],
            **provenance_artifact,
        }

        sboms: list[dict[str, Any]] = []
        reports: list[dict[str, Any]] = []
        for platform in policy["platforms"]:
            platform_slug = platform.replace("/", "-")
            for sbom_format in policy["attestations"]["sbom_predicate_types"]:
                extension = "cdx.json" if sbom_format == "cyclonedx-json" else "spdx.json"
                relative_name = f"sbom/{image_name}-{platform_slug}.{extension}"
                _, artifact = _artifact_record(artifacts_dir, relative_name)
                sboms.append(
                    {
                        "platform": platform,
                        "format": sbom_format,
                        "predicate_type": policy["attestations"]["sbom_predicate_types"][sbom_format],
                        **artifact,
                    }
                )
            report_name = f"scans/{image_name}-{platform_slug}.trivy.json"
            _, report_artifact = _artifact_record(artifacts_dir, report_name)
            reports.append(
                {
                    "platform": platform,
                    "scanner": policy["vulnerability_policy"]["scanner"],
                    "scanner_version": policy["vulnerability_policy"]["scanner_version"],
                    "fail_severities": policy["vulnerability_policy"]["fail_severities"],
                    "ignore_unfixed": policy["vulnerability_policy"]["ignore_unfixed"],
                    **report_artifact,
                }
            )

        images[image_name] = {
            "repository": repository,
            "digest": index_digest,
            "reference": f"{repository}@{index_digest}",
            "platforms": platforms,
            "provenance": provenance_artifact,
            "sboms": sboms,
            "vulnerability_reports": reports,
        }
    return {"schema_version": 1, "release": release, "images": images}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--workflow-run", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--app-digest", required=True)
    parser.add_argument("--app-index", type=Path, required=True)
    parser.add_argument("--postgres-digest", required=True)
    parser.add_argument("--postgres-index", type=Path, required=True)
    arguments = parser.parse_args()

    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        artifacts_dir = arguments.artifacts_dir.resolve(strict=True)
        if arguments.output.parent.resolve(strict=True) != artifacts_dir:
            raise ReleaseVerificationError("release manifest output must be directly inside artifacts-dir")
        output_stat = arguments.output.lstat() if arguments.output.exists() else None
        if output_stat is not None and (stat.S_ISLNK(output_stat.st_mode) or not stat.S_ISREG(output_stat.st_mode)):
            raise ReleaseVerificationError("release manifest output must be a regular non-symlink file")
        manifest = build_manifest(
            policy=policy,
            artifacts_dir=artifacts_dir,
            tag=arguments.tag,
            source_commit=arguments.source_commit,
            workflow_run=arguments.workflow_run,
            created_at=arguments.created_at,
            image_inputs={
                "app": (arguments.app_digest, arguments.app_index),
                "postgres": (arguments.postgres_digest, arguments.postgres_index),
            },
        )
        _write_json(arguments.output, manifest)
        validate_release(policy, manifest, artifacts_dir)
        return 0
    except (OSError, ReleaseVerificationError) as exc:
        print(f"release manifest generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
