#!/usr/bin/env python3
"""Build a deterministic manifest over already-collected release evidence."""

from __future__ import annotations

import argparse
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
    _parse_oci_index,
    _safe_artifact,
    _sha256_path,
    _timestamp,
    _validate_attestation_manifest,
    _validate_policy,
    validate_release,
)
import release_transition


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Release evidence may contain detailed build inputs. Keep it private on
        # the runner and let the artifact/release transport set access controls.
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _platform_digests(index_path: Path, expected_platforms: list[str]) -> dict[str, str]:
    index = _load_json(index_path, maximum_bytes=MAX_CONTROL_FILE_BYTES)
    platforms, _ = _parse_oci_index(index, expected_platforms, str(index_path))
    return platforms


def _artifact_record(artifacts_dir: Path, relative_name: str) -> tuple[Path, dict[str, str]]:
    path = _safe_artifact(artifacts_dir, relative_name, relative_name)
    return path, {"file": relative_name, "sha256": _sha256_path(path)}


def _consumer_record(policy: dict[str, Any], artifacts_dir: Path) -> dict[str, Any]:
    consumer = policy["consumer"]
    trusted_policy = consumer["trusted_root"]
    _, trusted_artifact = _artifact_record(
        artifacts_dir, "consumer/sigstore-trusted-root.json"
    )
    trusted_root = {
        **trusted_artifact,
        "source_repository": trusted_policy["source_repository"],
        "source_commit": trusted_policy["source_commit"],
        "source_path": trusted_policy["source_path"],
    }

    verifier = consumer["cosign_image"]
    platform_records: list[dict[str, Any]] = []
    for platform in policy["platforms"]:
        slug = platform.replace("/", "-")
        _, source_catalog = _artifact_record(
            artifacts_dir, f"consumer/release-verifier-{slug}.syft.json"
        )
        _, vulnerability_report = _artifact_record(
            artifacts_dir, f"consumer/release-verifier-{slug}.trivy.json"
        )
        platform_records.append(
            {
                "platform": platform,
                "manifest_digest": verifier["platforms"][platform]["manifest_digest"],
                "config_digest": verifier["platforms"][platform]["config_digest"],
                "source_catalog": {
                    "format": "syft-json",
                    "generator": "syft",
                    "generator_version": policy["tools"]["syft"]["version"],
                    **source_catalog,
                },
                "vulnerability_report": {
                    "scanner": policy["vulnerability_policy"]["scanner"],
                    "scanner_version": policy["vulnerability_policy"]["scanner_version"],
                    "fail_severities": policy["vulnerability_policy"]["fail_severities"],
                    "ignore_unfixed": policy["vulnerability_policy"]["ignore_unfixed"],
                    **vulnerability_report,
                },
            }
        )
    return {
        "descriptor_filename": consumer["descriptor_filename"],
        "descriptor_bundle_filename": consumer["descriptor_bundle_filename"],
        "manifest_filename": consumer["manifest_filename"],
        "consumer_script_filename": consumer["consumer_script_filename"],
        "consumer_script_bundle_filename": consumer["consumer_script_bundle_filename"],
        "trusted_root": trusted_root,
        "cosign_image": {
            "version": verifier["version"],
            "runtime_contract_version": verifier["runtime_contract_version"],
            "repository": verifier["repository"],
            "index_digest": verifier["index_digest"],
            "reference": verifier["reference"],
            "platforms": platform_records,
        },
    }


def _vulnerability_database_record(artifacts_dir: Path) -> dict[str, Any]:
    _, lock = _artifact_record(
        artifacts_dir, "vulnerability/trivy-db-lock.json"
    )
    _, preparation_evidence = _artifact_record(
        artifacts_dir, "vulnerability/trivy-db-evidence.json"
    )
    return {"lock": lock, "preparation_evidence": preparation_evidence}


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
            f"https://github.com/{policy['source_repository']}/{policy['release_workflow']}@refs/tags/{tag}"
        ),
        "workflow_run": workflow_run,
        "created_at": created_at,
    }
    images: dict[str, Any] = {}
    predicate_type = policy["attestations"]["provenance_predicate_type"]

    for image_name in policy["images"]:
        index_digest, index_path = image_inputs[image_name]
        index_digest = _digest(index_digest, f"{image_name} index digest")
        relative_index = index_path.resolve(strict=True).relative_to(artifacts_dir.resolve(strict=True)).as_posix()
        actual_index_path, index_record = _artifact_record(artifacts_dir, relative_index)
        if index_record["sha256"] != index_digest:
            raise ReleaseVerificationError(f"{image_name} raw OCI index does not match its registry digest")
        index = _load_json(actual_index_path, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        platforms, attestation_digests = _parse_oci_index(
            index, policy["platforms"], f"{image_name} OCI index"
        )

        attestation_manifests: list[dict[str, Any]] = []
        provenance: list[dict[str, Any]] = []
        source_catalogs: list[dict[str, Any]] = []
        sboms: list[dict[str, Any]] = []
        reports: list[dict[str, Any]] = []
        for platform in policy["platforms"]:
            platform_slug = platform.replace("/", "-")
            attestation_name = f"oci/{image_name}-{platform_slug}.attestation.json"
            _, attestation_record = _artifact_record(artifacts_dir, attestation_name)
            attestation_digest = attestation_digests[platform]
            if attestation_record["sha256"] != attestation_digest:
                raise ReleaseVerificationError(
                    f"{image_name} {platform} attestation manifest does not match its OCI digest"
                )
            attestation_document = _load_json(
                artifacts_dir / attestation_name, maximum_bytes=MAX_CONTROL_FILE_BYTES
            )
            blob_digest = _validate_attestation_manifest(
                attestation_document,
                predicate_type,
                f"{image_name} {platform} attestation manifest",
            )
            attestation_manifests.append(
                {
                    "platform": platform,
                    "digest": attestation_digest,
                    **attestation_record,
                }
            )

            provenance_name = f"provenance/{image_name}-{platform_slug}.intoto.json"
            _, provenance_record = _artifact_record(artifacts_dir, provenance_name)
            if provenance_record["sha256"] != blob_digest:
                raise ReleaseVerificationError(
                    f"{image_name} {platform} provenance is not the OCI attestation blob"
                )
            provenance.append(
                {
                    "platform": platform,
                    "predicate_type": predicate_type,
                    "mode": policy["attestations"]["provenance_mode"],
                    "attestation_manifest_digest": attestation_digest,
                    "blob_digest": blob_digest,
                    **provenance_record,
                }
            )

            catalog_name = f"sbom/{image_name}-{platform_slug}.syft.json"
            _, catalog_record = _artifact_record(artifacts_dir, catalog_name)
            source_catalogs.append(
                {
                    "platform": platform,
                    "format": "syft-json",
                    "generator": "syft",
                    "generator_version": policy["tools"]["syft"]["version"],
                    **catalog_record,
                }
            )
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

        image_policy = policy["images"][image_name]
        quarantine = image_policy["quarantine_repository"]
        official = image_policy["official_repository"]
        images[image_name] = {
            "quarantine_repository": quarantine,
            "official_repository": official,
            "digest": index_digest,
            "quarantine_reference": f"{quarantine}@{index_digest}",
            "official_reference": f"{official}@{index_digest}",
            "oci_index": index_record,
            "platforms": platforms,
            "attestation_manifests": attestation_manifests,
            "provenance": provenance,
            "source_catalogs": source_catalogs,
            "sboms": sboms,
            "vulnerability_reports": reports,
        }
    reviewed_path = _safe_artifact(
        artifacts_dir,
        "transition/reviewed-policy.json",
        "reviewed transition policy",
    )
    migration_path = _safe_artifact(
        artifacts_dir,
        "transition/django-migrations.json",
        "Django migration contract",
    )
    reviewed_transition = release_transition.load_json(reviewed_path)
    migration_contract = release_transition.load_json(migration_path)
    transition_record = release_transition.build_transition_record(
        reviewed_policy=reviewed_transition,
        migration_contract=migration_contract,
        reviewed_policy_file="transition/reviewed-policy.json",
        reviewed_policy_sha256=_sha256_path(reviewed_path),
        migration_contract_file="transition/django-migrations.json",
        migration_contract_sha256=_sha256_path(migration_path),
    )
    return {
        "schema_version": 4,
        "release": release,
        "transition": transition_record,
        "vulnerability_database": _vulnerability_database_record(artifacts_dir),
        "consumer": _consumer_record(policy, artifacts_dir),
        "images": images,
    }


def main(argv: list[str] | None = None) -> int:
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
    parser.add_argument("--egress-digest", required=True)
    parser.add_argument("--egress-index", type=Path, required=True)
    parser.add_argument("--rabbitmq-digest", required=True)
    parser.add_argument("--rabbitmq-index", type=Path, required=True)
    parser.add_argument("--rabbitmq-upgrade-digest", required=True)
    parser.add_argument("--rabbitmq-upgrade-index", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        artifacts_dir = arguments.artifacts_dir.resolve(strict=True)
        if arguments.output.parent.resolve(strict=True) != artifacts_dir:
            raise ReleaseVerificationError("release manifest output must be directly inside artifacts-dir")
        output_stat = arguments.output.lstat() if arguments.output.exists() else None
        if output_stat is not None and (
            stat.S_ISLNK(output_stat.st_mode) or not stat.S_ISREG(output_stat.st_mode)
        ):
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
                "egress": (arguments.egress_digest, arguments.egress_index),
                "rabbitmq": (arguments.rabbitmq_digest, arguments.rabbitmq_index),
                "rabbitmq-upgrade": (
                    arguments.rabbitmq_upgrade_digest,
                    arguments.rabbitmq_upgrade_index,
                ),
            },
        )
        _write_json(arguments.output, manifest)
        validate_release(policy, manifest, artifacts_dir)
        return 0
    except (OSError, ValueError, ReleaseVerificationError) as exc:
        print(f"release manifest generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
