#!/usr/bin/env python3
"""Fail-closed verification for BackupSheep container release evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "deploy" / "release-policy.json"
MAX_CONTROL_FILE_BYTES = 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 256 * 1024 * 1024
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
INDEX_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
}
ATTESTATION_TYPE_ANNOTATION = "vnd.docker.reference.type"
ATTESTATION_DIGEST_ANNOTATION = "vnd.docker.reference.digest"
PREDICATE_ANNOTATION = "in-toto.io/predicate-type"
IN_TOTO_MEDIA_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
IN_TOTO_STATEMENT_V01_TYPE = "https://in-toto.io/Statement/v0.1"


class ReleaseVerificationError(ValueError):
    """A release input violated the checked-in trust policy."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseVerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReleaseVerificationError(f"non-finite JSON number is forbidden: {value}")


def _load_json(path: Path, *, maximum_bytes: int) -> Any:
    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise ReleaseVerificationError(f"cannot inspect {path}: {exc}") from exc
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise ReleaseVerificationError(f"JSON input must be a regular non-symlink file: {path}")
    if file_stat.st_size > maximum_bytes:
        raise ReleaseVerificationError(f"JSON input is too large: {path}")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseVerificationError(f"invalid JSON in {path}: {exc}") from exc


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseVerificationError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReleaseVerificationError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseVerificationError(f"{label} must be a non-empty string")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ReleaseVerificationError(f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReleaseVerificationError(f"{label} must be an integer")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing={missing}")
        if unknown:
            details.append(f"unknown={unknown}")
        raise ReleaseVerificationError(f"{label} has invalid keys ({', '.join(details)})")


def _unique_strings(value: Any, label: str) -> list[str]:
    result = [_string(item, f"{label}[]") for item in _list(value, label)]
    if len(result) != len(set(result)):
        raise ReleaseVerificationError(f"{label} contains duplicates")
    return result


def _digest(value: Any, label: str) -> str:
    result = _string(value, label)
    if not DIGEST_RE.fullmatch(result):
        raise ReleaseVerificationError(f"{label} must be a lowercase sha256 digest")
    return result


def _timestamp(value: Any, label: str) -> str:
    result = _string(value, label)
    if not UTC_RE.fullmatch(result):
        raise ReleaseVerificationError(f"{label} must be second-precision UTC ending in Z")
    try:
        datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ReleaseVerificationError(f"{label} is not a valid UTC timestamp") from exc
    return result


def _validate_repository(value: Any, registry: str, label: str) -> str:
    repository = _string(value, label)
    if repository != repository.lower() or not repository.startswith(f"{registry}/"):
        raise ReleaseVerificationError(f"{label} is not an authorized registry repository")
    if "@" in repository or ":" in repository.removeprefix(f"{registry}/"):
        raise ReleaseVerificationError(f"{label} must not contain a tag or digest")
    return repository


def _validate_policy(policy: Any) -> dict[str, Any]:
    policy = _mapping(policy, "policy")
    _exact_keys(
        policy,
        {
            "schema_version",
            "source_repository",
            "release_workflow",
            "registry",
            "images",
            "platforms",
            "release_tag_regex",
            "identity",
            "attestations",
            "tools",
            "vulnerability_policy",
            "evidence",
        },
        "policy",
    )
    if _integer(policy["schema_version"], "policy.schema_version") != 2:
        raise ReleaseVerificationError("unsupported release policy schema")

    source_repository = _string(policy["source_repository"], "policy.source_repository")
    if source_repository != source_repository.lower() or source_repository.count("/") != 1:
        raise ReleaseVerificationError("policy.source_repository must be lowercase owner/repository")
    workflow = _string(policy["release_workflow"], "policy.release_workflow")
    if not workflow.startswith(".github/workflows/") or not workflow.endswith((".yml", ".yaml")):
        raise ReleaseVerificationError("policy.release_workflow is not a workflow path")
    registry = _string(policy["registry"], "policy.registry")
    if registry != "ghcr.io":
        raise ReleaseVerificationError("only ghcr.io is authorized by this verifier")

    images = _mapping(policy["images"], "policy.images")
    if set(images) != {"app", "postgres", "egress"}:
        raise ReleaseVerificationError(
            "policy.images must contain exactly app, postgres, and egress"
        )
    all_repositories: list[str] = []
    for image_name, raw_image in images.items():
        image = _mapping(raw_image, f"policy.images.{image_name}")
        _exact_keys(
            image,
            {"quarantine_repository", "official_repository", "dockerfile"},
            f"policy.images.{image_name}",
        )
        quarantine = _validate_repository(
            image["quarantine_repository"], registry, f"policy.images.{image_name}.quarantine_repository"
        )
        official = _validate_repository(
            image["official_repository"], registry, f"policy.images.{image_name}.official_repository"
        )
        if quarantine == official or "quarantine" not in quarantine:
            raise ReleaseVerificationError(f"policy.images.{image_name} needs a distinct quarantine repository")
        all_repositories.extend((quarantine, official))
        dockerfile = _string(image["dockerfile"], f"policy.images.{image_name}.dockerfile")
        if PurePosixPath(dockerfile).is_absolute() or ".." in PurePosixPath(dockerfile).parts:
            raise ReleaseVerificationError(f"policy.images.{image_name}.dockerfile is unsafe")
    if len(all_repositories) != len(set(all_repositories)):
        raise ReleaseVerificationError("release repositories must all be distinct")

    platforms = _unique_strings(policy["platforms"], "policy.platforms")
    if platforms != ["linux/amd64", "linux/arm64"]:
        raise ReleaseVerificationError("policy.platforms must be exactly linux/amd64 and linux/arm64")
    tag_regex = _string(policy["release_tag_regex"], "policy.release_tag_regex")
    if not tag_regex.startswith("^") or not tag_regex.endswith("$"):
        raise ReleaseVerificationError("policy.release_tag_regex must be anchored")
    try:
        re.compile(tag_regex)
    except re.error as exc:
        raise ReleaseVerificationError("policy.release_tag_regex is invalid") from exc

    identity = _mapping(policy["identity"], "policy.identity")
    _exact_keys(identity, {"oidc_issuer", "certificate_identity_regex", "workflow_trigger"}, "policy.identity")
    if identity["oidc_issuer"] != "https://token.actions.githubusercontent.com":
        raise ReleaseVerificationError("the release signer must use GitHub Actions OIDC")
    identity_regex = _string(identity["certificate_identity_regex"], "policy.identity.certificate_identity_regex")
    if not identity_regex.startswith("^") or not identity_regex.endswith("$"):
        raise ReleaseVerificationError("certificate identity regex must be anchored")
    if "(?" in identity_regex or re.search(r"\\[1-9]", identity_regex):
        raise ReleaseVerificationError("certificate identity regex must use Go RE2-compatible constructs")
    try:
        re.compile(identity_regex)
    except re.error as exc:
        raise ReleaseVerificationError("certificate identity regex is invalid") from exc
    if identity["workflow_trigger"] != "push":
        raise ReleaseVerificationError("release signatures must be produced by a push workflow")

    attestations = _mapping(policy["attestations"], "policy.attestations")
    _exact_keys(
        attestations,
        {"provenance_predicate_type", "provenance_mode", "buildkit_build_type", "sbom_predicate_types"},
        "policy.attestations",
    )
    if attestations["provenance_predicate_type"] != "https://slsa.dev/provenance/v1":
        raise ReleaseVerificationError("SLSA provenance v1 is required")
    if attestations["provenance_mode"] != "max":
        raise ReleaseVerificationError("BuildKit provenance mode=max is required")
    if attestations["buildkit_build_type"] != (
        "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
    ):
        raise ReleaseVerificationError("unexpected BuildKit SLSA v1 build type")
    predicate_types = _mapping(attestations["sbom_predicate_types"], "policy.attestations.sbom_predicate_types")
    if predicate_types != {
        "cyclonedx-json": "https://cyclonedx.org/bom",
        "spdx-json": "https://spdx.dev/Document",
    }:
        raise ReleaseVerificationError("both CycloneDX JSON and SPDX JSON attestations are required")

    tools = _mapping(policy["tools"], "policy.tools")
    if set(tools) != {"cosign", "oras", "syft", "trivy"}:
        raise ReleaseVerificationError("policy.tools must contain exactly cosign, oras, syft, and trivy")
    for name, raw_tool in tools.items():
        tool = _mapping(raw_tool, f"policy.tools.{name}")
        _exact_keys(tool, {"version", "url", "sha256", "archive_member"}, f"policy.tools.{name}")
        version = _string(tool["version"], f"policy.tools.{name}.version")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ReleaseVerificationError(f"policy.tools.{name}.version must be exact SemVer")
        url = _string(tool["url"], f"policy.tools.{name}.url")
        if not url.startswith("https://github.com/") or not any(
            marker in url for marker in (f"/{version}/", f"/v{version}/")
        ):
            raise ReleaseVerificationError(f"policy.tools.{name}.url must be an exact GitHub release asset")
        sha256 = _string(tool["sha256"], f"policy.tools.{name}.sha256")
        if not HEX_SHA256_RE.fullmatch(sha256):
            raise ReleaseVerificationError(f"policy.tools.{name}.sha256 must be lowercase SHA-256")
        member = tool["archive_member"]
        if member is not None and (not isinstance(member, str) or not member or "/" in member):
            raise ReleaseVerificationError(f"policy.tools.{name}.archive_member is unsafe")

    vulnerability = _mapping(policy["vulnerability_policy"], "policy.vulnerability_policy")
    _exact_keys(
        vulnerability,
        {"scanner", "scanner_version", "fail_severities", "ignore_unfixed", "allowlist"},
        "policy.vulnerability_policy",
    )
    if vulnerability["scanner"] != "trivy":
        raise ReleaseVerificationError("Trivy is the required scanner")
    if vulnerability["scanner_version"] != tools["trivy"]["version"]:
        raise ReleaseVerificationError("Trivy policy and pinned tool versions differ")
    if _unique_strings(vulnerability["fail_severities"], "policy.vulnerability_policy.fail_severities") != [
        "HIGH",
        "CRITICAL",
    ]:
        raise ReleaseVerificationError("HIGH and CRITICAL must both fail the release")
    if _boolean(vulnerability["ignore_unfixed"], "policy.vulnerability_policy.ignore_unfixed"):
        raise ReleaseVerificationError("unfixed HIGH/CRITICAL findings may not be ignored")
    if vulnerability["allowlist"] is not None:
        raise ReleaseVerificationError("the release policy does not permit a vulnerability allowlist")

    evidence = _mapping(policy["evidence"], "policy.evidence")
    _exact_keys(evidence, {"workflow_artifact_retention_days", "durable_github_release_assets"}, "policy.evidence")
    if _integer(evidence["workflow_artifact_retention_days"], "policy.evidence.workflow_artifact_retention_days") != 90:
        raise ReleaseVerificationError("release evidence must use the 90-day workflow artifact maximum")
    if not _boolean(evidence["durable_github_release_assets"], "policy.evidence.durable_github_release_assets"):
        raise ReleaseVerificationError("durable GitHub release evidence is required")
    return policy


def _safe_artifact(root: Path, relative_name: Any, label: str) -> Path:
    name = _string(relative_name, label)
    pure = PurePosixPath(name)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ReleaseVerificationError(f"{label} is not a safe relative artifact path")
    if "\\" in name:
        raise ReleaseVerificationError(f"{label} must use POSIX path separators")
    root = root.resolve(strict=True)
    candidate = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current = current / part
        try:
            file_stat = current.lstat()
        except OSError as exc:
            raise ReleaseVerificationError(f"cannot inspect artifact {name}: {exc}") from exc
        if stat.S_ISLNK(file_stat.st_mode):
            raise ReleaseVerificationError(f"artifact path contains a symlink: {name}")
    try:
        candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise ReleaseVerificationError(f"artifact escapes the evidence directory: {name}") from exc
    file_stat = candidate.stat()
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > MAX_EVIDENCE_FILE_BYTES:
        raise ReleaseVerificationError(f"artifact is not a bounded regular file: {name}")
    return candidate


def _sha256_path(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return f"sha256:{hasher.hexdigest()}"


def _verify_file(root: Path, record: dict[str, Any], label: str) -> tuple[Path, Any]:
    expected = _digest(record["sha256"], f"{label}.sha256")
    path = _safe_artifact(root, record["file"], f"{label}.file")
    if _sha256_path(path) != expected:
        raise ReleaseVerificationError(f"artifact digest mismatch: {record['file']}")
    return path, _load_json(path, maximum_bytes=MAX_EVIDENCE_FILE_BYTES)


def _descriptor_digest(descriptor: Any, label: str) -> str:
    descriptor = _mapping(descriptor, label)
    _string(descriptor.get("mediaType"), f"{label}.mediaType")
    if _integer(descriptor.get("size"), f"{label}.size") <= 0:
        raise ReleaseVerificationError(f"{label}.size must be positive")
    return _digest(descriptor.get("digest"), f"{label}.digest")


def _parse_oci_index(document: Any, expected_platforms: list[str], label: str) -> tuple[dict[str, str], dict[str, str]]:
    document = _mapping(document, label)
    if _integer(document.get("schemaVersion"), f"{label}.schemaVersion") != 2:
        raise ReleaseVerificationError(f"{label} has an unsupported schema")
    if document.get("mediaType") not in INDEX_MEDIA_TYPES:
        raise ReleaseVerificationError(f"{label} is not an OCI/Docker image index")
    manifests = _list(document.get("manifests"), f"{label}.manifests")
    if not manifests:
        raise ReleaseVerificationError(f"{label} has no manifests")

    platforms: dict[str, str] = {}
    pending_attestations: list[tuple[str, str]] = []
    for position, raw_descriptor in enumerate(manifests):
        descriptor_label = f"{label}.manifests[{position}]"
        descriptor = _mapping(raw_descriptor, descriptor_label)
        digest = _descriptor_digest(descriptor, descriptor_label)
        platform = _mapping(descriptor.get("platform"), f"{descriptor_label}.platform")
        platform_name = f"{platform.get('os')}/{platform.get('architecture')}"
        annotations = descriptor.get("annotations") or {}
        if platform_name in expected_platforms:
            if descriptor.get("mediaType") not in MANIFEST_MEDIA_TYPES or platform_name in platforms:
                raise ReleaseVerificationError(f"{descriptor_label} is a duplicate or invalid platform manifest")
            platforms[platform_name] = digest
        elif platform_name == "unknown/unknown" and isinstance(annotations, dict):
            if annotations.get(ATTESTATION_TYPE_ANNOTATION) != "attestation-manifest":
                raise ReleaseVerificationError(f"{descriptor_label} is an unauthorized unknown platform")
            subject_digest = _digest(
                annotations.get(ATTESTATION_DIGEST_ANNOTATION),
                f"{descriptor_label}.annotations.{ATTESTATION_DIGEST_ANNOTATION}",
            )
            pending_attestations.append((subject_digest, digest))
        else:
            raise ReleaseVerificationError(f"{descriptor_label} contains unauthorized platform {platform_name}")

    if list(platforms) != expected_platforms:
        raise ReleaseVerificationError(f"{label} must contain exactly the policy platforms in order")
    digest_to_platform = {digest: platform for platform, digest in platforms.items()}
    attestations: dict[str, str] = {}
    for subject_digest, attestation_digest in pending_attestations:
        platform = digest_to_platform.get(subject_digest)
        if platform is None or platform in attestations:
            raise ReleaseVerificationError(f"{label} has an unbound or duplicate attestation manifest")
        attestations[platform] = attestation_digest
    if set(attestations) != set(expected_platforms):
        raise ReleaseVerificationError(f"{label} must bind exactly one attestation manifest to every child")
    return platforms, attestations


def _validate_attestation_manifest(document: Any, predicate_type: str, label: str) -> str:
    document = _mapping(document, label)
    if _integer(document.get("schemaVersion"), f"{label}.schemaVersion") != 2:
        raise ReleaseVerificationError(f"{label} has an unsupported schema")
    if document.get("mediaType") not in MANIFEST_MEDIA_TYPES:
        raise ReleaseVerificationError(f"{label} is not an OCI manifest")
    _descriptor_digest(document.get("config"), f"{label}.config")
    matching: list[str] = []
    for position, raw_layer in enumerate(_list(document.get("layers"), f"{label}.layers")):
        layer_label = f"{label}.layers[{position}]"
        layer = _mapping(raw_layer, layer_label)
        digest = _descriptor_digest(layer, layer_label)
        annotations = layer.get("annotations") or {}
        if (
            layer.get("mediaType") == IN_TOTO_MEDIA_TYPE
            and isinstance(annotations, dict)
            and annotations.get(PREDICATE_ANNOTATION) == predicate_type
        ):
            matching.append(digest)
    if len(matching) != 1:
        raise ReleaseVerificationError(f"{label} must contain exactly one BuildKit provenance layer")
    return matching[0]


def _subject_has_digest(statement: dict[str, Any], digest: str, label: str) -> None:
    subjects = _list(statement.get("subject"), f"{label}.subject")
    if len(subjects) != 1:
        raise ReleaseVerificationError(f"{label} must have exactly one subject")
    subject = _mapping(subjects[0], f"{label}.subject[0]")
    _string(subject.get("name"), f"{label}.subject[0].name")
    if subject.get("digest") != {"sha256": digest.removeprefix("sha256:")}:
        raise ReleaseVerificationError(f"{label} subject does not bind {digest}")


def _validate_buildkit_statement(
    statement: Any,
    *,
    release: dict[str, Any],
    child_digest: str,
    dockerfile: str,
    policy: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    statement = _mapping(statement, label)
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        raise ReleaseVerificationError(f"{label} is not an in-toto Statement v1")
    if statement.get("predicateType") != policy["attestations"]["provenance_predicate_type"]:
        raise ReleaseVerificationError(f"{label} has the wrong provenance predicate type")
    _subject_has_digest(statement, child_digest, label)
    predicate = _mapping(statement.get("predicate"), f"{label}.predicate")
    definition = _mapping(predicate.get("buildDefinition"), f"{label}.predicate.buildDefinition")
    if definition.get("buildType") != policy["attestations"]["buildkit_build_type"]:
        raise ReleaseVerificationError(f"{label} has an unexpected BuildKit build type")

    external = _mapping(definition.get("externalParameters"), f"{label}.externalParameters")
    config = _mapping(external.get("configSource"), f"{label}.externalParameters.configSource")
    source_uri = f"https://github.com/{release['source_repository']}.git#{release['source_commit']}"
    if config.get("uri") != source_uri or config.get("digest") != {"sha1": release["source_commit"]}:
        raise ReleaseVerificationError(f"{label} configSource is not the exact remote Git commit")
    if config.get("path") != dockerfile:
        raise ReleaseVerificationError(f"{label} configSource does not bind {dockerfile}")
    request = _mapping(external.get("request"), f"{label}.externalParameters.request")
    if request.get("frontend") != "dockerfile.v0":
        raise ReleaseVerificationError(f"{label} was not built by the Dockerfile frontend")
    args = _mapping(request.get("args"), f"{label}.externalParameters.request.args")
    expected_labels = {
        "label:org.opencontainers.image.source": f"https://github.com/{release['source_repository']}",
        "label:org.opencontainers.image.revision": release["source_commit"],
        "label:org.opencontainers.image.version": release["tag"],
    }
    for key, value in expected_labels.items():
        if args.get(key) != value:
            raise ReleaseVerificationError(f"{label} request is missing source-binding label {key}")

    internal = _mapping(definition.get("internalParameters"), f"{label}.internalParameters")
    build_config = _mapping(internal.get("buildConfig"), f"{label}.internalParameters.buildConfig")
    if not _list(build_config.get("llbDefinition"), f"{label}.internalParameters.buildConfig.llbDefinition"):
        raise ReleaseVerificationError(f"{label} is not complete mode=max provenance")
    _string(internal.get("builderPlatform"), f"{label}.internalParameters.builderPlatform")
    dependencies = _list(definition.get("resolvedDependencies"), f"{label}.resolvedDependencies")
    if not any(
        isinstance(dependency, dict)
        and dependency.get("uri") == source_uri
        and dependency.get("digest") == {"sha1": release["source_commit"]}
        for dependency in dependencies
    ):
        raise ReleaseVerificationError(f"{label} does not resolve the exact source commit")

    details = _mapping(predicate.get("runDetails"), f"{label}.runDetails")
    expected_builder = release["workflow_identity"]
    if _mapping(details.get("builder"), f"{label}.runDetails.builder").get("id") != expected_builder:
        raise ReleaseVerificationError(f"{label} has an unauthorized builder identity")
    metadata = _mapping(details.get("metadata"), f"{label}.runDetails.metadata")
    completeness = _mapping(metadata.get("buildkit_completeness"), f"{label}.buildkit_completeness")
    if completeness.get("request") is not True or completeness.get("resolvedDependencies") is not True:
        raise ReleaseVerificationError(f"{label} BuildKit provenance is incomplete")
    buildkit_metadata = _mapping(metadata.get("buildkit_metadata"), f"{label}.buildkit_metadata")
    if not buildkit_metadata.get("source") or not buildkit_metadata.get("layers"):
        raise ReleaseVerificationError(f"{label} lacks mode=max source or layer evidence")
    return predicate


def _validate_spdx(document: Any, label: str) -> None:
    document = _mapping(document, label)
    if not _string(document.get("spdxVersion"), f"{label}.spdxVersion").startswith("SPDX-"):
        raise ReleaseVerificationError(f"{label} is not an SPDX document")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ReleaseVerificationError(f"{label} has no SPDX document identifier")
    _string(document.get("name"), f"{label}.name")
    if not _list(document.get("packages"), f"{label}.packages"):
        raise ReleaseVerificationError(f"{label} contains no packages")


def _validate_cyclonedx(document: Any, label: str) -> None:
    document = _mapping(document, label)
    if document.get("bomFormat") != "CycloneDX":
        raise ReleaseVerificationError(f"{label} is not a CycloneDX document")
    _string(document.get("specVersion"), f"{label}.specVersion")
    if _integer(document.get("version"), f"{label}.version") < 1:
        raise ReleaseVerificationError(f"{label}.version must be positive")
    _mapping(document.get("metadata"), f"{label}.metadata")
    if not _list(document.get("components"), f"{label}.components"):
        raise ReleaseVerificationError(f"{label} contains no components")


def _validate_syft_catalog(document: Any, expected_reference: str, expected_digest: str, version: str, label: str) -> None:
    document = _mapping(document, label)
    if not _list(document.get("artifacts"), f"{label}.artifacts"):
        raise ReleaseVerificationError(f"{label} contains no artifacts")
    source = _mapping(document.get("source"), f"{label}.source")
    if source.get("type") != "image":
        raise ReleaseVerificationError(f"{label} is not an image catalog")
    metadata = _mapping(source.get("metadata"), f"{label}.source.metadata")
    if metadata.get("userInput") != expected_reference or metadata.get("manifestDigest") != expected_digest:
        raise ReleaseVerificationError(f"{label} is not bound to the exact image digest")
    descriptor = _mapping(document.get("descriptor"), f"{label}.descriptor")
    if descriptor.get("name") != "syft" or descriptor.get("version") != version:
        raise ReleaseVerificationError(f"{label} was not generated by the pinned Syft version")


def _validate_trivy_report(document: Any, expected_reference: str, fail_severities: set[str], label: str) -> None:
    document = _mapping(document, label)
    if _integer(document.get("SchemaVersion"), f"{label}.SchemaVersion") < 2:
        raise ReleaseVerificationError(f"{label} uses an unsupported Trivy schema")
    if document.get("ArtifactName") != expected_reference:
        raise ReleaseVerificationError(f"{label} is not bound to {expected_reference}")
    _string(document.get("ArtifactType"), f"{label}.ArtifactType")
    _mapping(document.get("Metadata"), f"{label}.Metadata")
    results = _list(document.get("Results"), f"{label}.Results")
    if not results:
        raise ReleaseVerificationError(f"{label} contains no scan results")
    package_count = 0
    forbidden: list[str] = []
    for position, raw_result in enumerate(results):
        result_label = f"{label}.Results[{position}]"
        result = _mapping(raw_result, result_label)
        _string(result.get("Target"), f"{result_label}.Target")
        _string(result.get("Class"), f"{result_label}.Class")
        _string(result.get("Type"), f"{result_label}.Type")
        packages = result.get("Packages") or []
        package_count += len(_list(packages, f"{result_label}.Packages"))
        vulnerabilities = result.get("Vulnerabilities") or []
        for raw_vulnerability in _list(vulnerabilities, f"{result_label}.Vulnerabilities"):
            vulnerability = _mapping(raw_vulnerability, f"{result_label}.Vulnerabilities[]")
            severity = _string(vulnerability.get("Severity"), f"{result_label}.vulnerability.Severity").upper()
            if severity in fail_severities:
                forbidden.append(f"{vulnerability.get('VulnerabilityID') or 'unknown'}:{severity}")
    if package_count == 0:
        raise ReleaseVerificationError(f"{label} contains no package inventory")
    if forbidden:
        raise ReleaseVerificationError(f"{label} contains release-blocking vulnerabilities: {', '.join(forbidden[:10])}")


def _records_by_platform(records: Any, platforms: list[str], label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for position, raw_record in enumerate(_list(records, label)):
        record = _mapping(raw_record, f"{label}[{position}]")
        platform = _string(record.get("platform"), f"{label}[{position}].platform")
        if platform not in platforms or platform in result:
            raise ReleaseVerificationError(f"{label}[{position}] is duplicate or not required")
        result[platform] = record
    if list(result) != platforms:
        raise ReleaseVerificationError(f"{label} must contain every policy platform in order")
    return result


def validate_release(policy: Any, manifest: Any, artifacts_dir: Path) -> dict[str, Any]:
    policy = _validate_policy(policy)
    manifest = _mapping(manifest, "manifest")
    _exact_keys(manifest, {"schema_version", "release", "images"}, "manifest")
    if _integer(manifest["schema_version"], "manifest.schema_version") != 2:
        raise ReleaseVerificationError("unsupported release manifest schema")
    release = _mapping(manifest["release"], "manifest.release")
    _exact_keys(
        release,
        {"tag", "source_repository", "source_commit", "workflow_identity", "workflow_run", "created_at"},
        "manifest.release",
    )
    tag = _string(release["tag"], "manifest.release.tag")
    if re.fullmatch(policy["release_tag_regex"], tag) is None:
        raise ReleaseVerificationError("release tag is not an authorized immutable version")
    if release["source_repository"] != policy["source_repository"]:
        raise ReleaseVerificationError("manifest source repository is not authorized")
    commit = _string(release["source_commit"], "manifest.release.source_commit")
    if not COMMIT_RE.fullmatch(commit):
        raise ReleaseVerificationError("manifest source commit must be a lowercase full commit")
    expected_identity = (
        f"https://github.com/{policy['source_repository']}/{policy['release_workflow']}@refs/tags/{tag}"
    )
    if release["workflow_identity"] != expected_identity:
        raise ReleaseVerificationError("manifest workflow identity does not match the release tag")
    if re.fullmatch(policy["identity"]["certificate_identity_regex"], expected_identity) is None:
        raise ReleaseVerificationError("manifest workflow identity is outside the signing policy")
    run_pattern = rf"^https://github\.com/{re.escape(policy['source_repository'])}/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*$"
    if re.fullmatch(run_pattern, _string(release["workflow_run"], "manifest.release.workflow_run")) is None:
        raise ReleaseVerificationError("manifest workflow run URL is invalid")
    _timestamp(release["created_at"], "manifest.release.created_at")

    images = _mapping(manifest["images"], "manifest.images")
    if set(images) != set(policy["images"]):
        raise ReleaseVerificationError("manifest image set does not match policy")
    verified: dict[str, Any] = {"policy": policy, "manifest": manifest, "attestation_predicates": {}}
    platforms = policy["platforms"]
    predicate_type = policy["attestations"]["provenance_predicate_type"]

    for image_name in policy["images"]:
        label = f"manifest.images.{image_name}"
        image = _mapping(images[image_name], label)
        _exact_keys(
            image,
            {
                "quarantine_repository",
                "official_repository",
                "digest",
                "quarantine_reference",
                "official_reference",
                "oci_index",
                "platforms",
                "attestation_manifests",
                "provenance",
                "source_catalogs",
                "sboms",
                "vulnerability_reports",
            },
            label,
        )
        image_policy = policy["images"][image_name]
        quarantine = image_policy["quarantine_repository"]
        official = image_policy["official_repository"]
        if image["quarantine_repository"] != quarantine or image["official_repository"] != official:
            raise ReleaseVerificationError(f"{label} repositories are not authorized")
        index_digest = _digest(image["digest"], f"{label}.digest")
        if image["quarantine_reference"] != f"{quarantine}@{index_digest}":
            raise ReleaseVerificationError(f"{label}.quarantine_reference must use its exact digest")
        if image["official_reference"] != f"{official}@{index_digest}":
            raise ReleaseVerificationError(f"{label}.official_reference must use its exact digest")

        index_record = _mapping(image["oci_index"], f"{label}.oci_index")
        _exact_keys(index_record, {"file", "sha256"}, f"{label}.oci_index")
        if index_record["sha256"] != index_digest:
            raise ReleaseVerificationError(f"{label} OCI index record does not equal the registry digest")
        index_path, index_document = _verify_file(artifacts_dir, index_record, f"{label}.oci_index")
        if _sha256_path(index_path) != index_digest:
            raise ReleaseVerificationError(f"{label} raw OCI index does not hash to the declared digest")
        parsed_platforms, parsed_attestations = _parse_oci_index(index_document, platforms, f"{label}.oci_index.document")
        platform_map = _mapping(image["platforms"], f"{label}.platforms")
        if platform_map != parsed_platforms:
            raise ReleaseVerificationError(f"{label}.platforms are not members of the raw OCI index")

        attestation_records = _records_by_platform(
            image["attestation_manifests"], platforms, f"{label}.attestation_manifests"
        )
        provenance_records = _records_by_platform(image["provenance"], platforms, f"{label}.provenance")
        provenance_predicates: dict[str, Any] = {}
        provenance_statements: dict[str, Any] = {}
        for platform in platforms:
            att_label = f"{label}.attestation_manifests[{platform}]"
            att_record = attestation_records[platform]
            _exact_keys(att_record, {"platform", "digest", "file", "sha256"}, att_label)
            att_digest = _digest(att_record["digest"], f"{att_label}.digest")
            if att_digest != parsed_attestations[platform] or att_record["sha256"] != att_digest:
                raise ReleaseVerificationError(f"{att_label} is not the index-bound attestation manifest")
            _, att_document = _verify_file(artifacts_dir, att_record, att_label)
            blob_digest = _validate_attestation_manifest(att_document, predicate_type, f"{att_label}.document")

            prov_label = f"{label}.provenance[{platform}]"
            prov_record = provenance_records[platform]
            _exact_keys(
                prov_record,
                {"platform", "predicate_type", "mode", "attestation_manifest_digest", "blob_digest", "file", "sha256"},
                prov_label,
            )
            if prov_record["predicate_type"] != predicate_type or prov_record["mode"] != "max":
                raise ReleaseVerificationError(f"{prov_label} does not claim the required provenance format")
            if prov_record["attestation_manifest_digest"] != att_digest:
                raise ReleaseVerificationError(f"{prov_label} is not bound to its OCI attestation manifest")
            if prov_record["blob_digest"] != blob_digest or prov_record["sha256"] != blob_digest:
                raise ReleaseVerificationError(f"{prov_label} is not the OCI provenance blob")
            _, statement = _verify_file(artifacts_dir, prov_record, prov_label)
            predicate = _validate_buildkit_statement(
                statement,
                release=release,
                child_digest=platform_map[platform],
                dockerfile=image_policy["dockerfile"],
                policy=policy,
                label=f"{prov_label}.statement",
            )
            provenance_statements[platform] = statement
            provenance_predicates[platform] = predicate

        catalog_records = _records_by_platform(image["source_catalogs"], platforms, f"{label}.source_catalogs")
        for platform, record in catalog_records.items():
            record_label = f"{label}.source_catalogs[{platform}]"
            _exact_keys(record, {"platform", "format", "generator", "generator_version", "file", "sha256"}, record_label)
            if (
                record["format"] != "syft-json"
                or record["generator"] != "syft"
                or record["generator_version"] != policy["tools"]["syft"]["version"]
            ):
                raise ReleaseVerificationError(f"{record_label} has an unauthorized source catalog format")
            _, catalog = _verify_file(artifacts_dir, record, record_label)
            child_reference = f"{quarantine}@{platform_map[platform]}"
            _validate_syft_catalog(
                catalog,
                child_reference,
                platform_map[platform],
                policy["tools"]["syft"]["version"],
                f"{record_label}.document",
            )

        sbom_formats = policy["attestations"]["sbom_predicate_types"]
        expected_pairs = {(platform, fmt) for platform in platforms for fmt in sbom_formats}
        actual_pairs: set[tuple[str, str]] = set()
        sbom_predicates: dict[tuple[str, str], Any] = {}
        for position, raw_record in enumerate(_list(image["sboms"], f"{label}.sboms")):
            record_label = f"{label}.sboms[{position}]"
            record = _mapping(raw_record, record_label)
            _exact_keys(record, {"platform", "format", "predicate_type", "file", "sha256"}, record_label)
            pair = (
                _string(record["platform"], f"{record_label}.platform"),
                _string(record["format"], f"{record_label}.format"),
            )
            if pair not in expected_pairs or pair in actual_pairs:
                raise ReleaseVerificationError(f"{record_label} is duplicate or not required")
            actual_pairs.add(pair)
            if record["predicate_type"] != sbom_formats[pair[1]]:
                raise ReleaseVerificationError(f"{record_label} has the wrong predicate type")
            _, document = _verify_file(artifacts_dir, record, record_label)
            (_validate_spdx if pair[1] == "spdx-json" else _validate_cyclonedx)(
                document, f"{record_label}.document"
            )
            sbom_predicates[pair] = document
        if actual_pairs != expected_pairs:
            raise ReleaseVerificationError(f"{label} does not contain every required platform SBOM")

        report_records = _records_by_platform(
            image["vulnerability_reports"], platforms, f"{label}.vulnerability_reports"
        )
        for platform, record in report_records.items():
            record_label = f"{label}.vulnerability_reports[{platform}]"
            _exact_keys(
                record,
                {"platform", "scanner", "scanner_version", "fail_severities", "ignore_unfixed", "file", "sha256"},
                record_label,
            )
            vulnerability = policy["vulnerability_policy"]
            if record["scanner"] != vulnerability["scanner"] or record["scanner_version"] != vulnerability["scanner_version"]:
                raise ReleaseVerificationError(f"{record_label} uses an unauthorized scanner")
            if record["fail_severities"] != vulnerability["fail_severities"]:
                raise ReleaseVerificationError(f"{record_label} weakens the failure severity policy")
            if _boolean(record["ignore_unfixed"], f"{record_label}.ignore_unfixed"):
                raise ReleaseVerificationError(f"{record_label} ignored unfixed vulnerabilities")
            _, report = _verify_file(artifacts_dir, record, record_label)
            _validate_trivy_report(
                report,
                f"{quarantine}@{platform_map[platform]}",
                set(vulnerability["fail_severities"]),
                f"{record_label}.report",
            )

        verified["attestation_predicates"][image_name] = {
            "provenance": provenance_predicates,
            "provenance_statements": provenance_statements,
            "sboms": sbom_predicates,
        }
    return verified


def _cosign_identity_args(policy: dict[str, Any], release: dict[str, Any]) -> list[str]:
    return [
        "--certificate-identity-regexp",
        policy["identity"]["certificate_identity_regex"],
        "--certificate-oidc-issuer",
        policy["identity"]["oidc_issuer"],
        "--certificate-github-workflow-repository",
        policy["source_repository"],
        "--certificate-github-workflow-sha",
        release["source_commit"],
        "--certificate-github-workflow-ref",
        f"refs/tags/{release['tag']}",
        "--certificate-github-workflow-trigger",
        policy["identity"]["workflow_trigger"],
    ]


def _run_tool(executable: str, arguments: list[str], env_prefixes: tuple[str, ...]) -> str:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith(env_prefixes):
            environment.pop(name, None)
    try:
        result = subprocess.run(
            [executable, *arguments],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseVerificationError(f"{Path(executable).name} invocation failed: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise ReleaseVerificationError(f"{Path(executable).name} rejected release evidence: {detail[:1000]}")
    return result.stdout


def _json_stream(text: str) -> list[Any]:
    decoder = json.JSONDecoder(object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
    values: list[Any] = []
    position = 0
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        try:
            value, position = decoder.raw_decode(text, position)
        except json.JSONDecodeError as exc:
            raise ReleaseVerificationError("Cosign emitted invalid attestation JSON") from exc
        values.append(value)
    return values


def _statements_from_cosign(output: str) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    for value in _json_stream(output):
        value = _mapping(value, "Cosign attestation output")
        if {"predicate", "predicateType", "subject"}.issubset(value):
            statements.append(value)
            continue
        payload = value.get("payload")
        if not isinstance(payload, str):
            raise ReleaseVerificationError("Cosign attestation output has no DSSE payload")
        try:
            decoded = base64.b64decode(payload, validate=True)
            statement = json.loads(decoded, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReleaseVerificationError("Cosign emitted an invalid DSSE payload") from exc
        statements.append(_mapping(statement, "Cosign in-toto statement"))
    if not statements:
        raise ReleaseVerificationError("Cosign returned no verified attestation statements")
    return statements


def _require_matching_attestation(
    statements: list[dict[str, Any]],
    *,
    digest: str,
    predicate_type: str,
    predicate: Any,
    statement_type: str = IN_TOTO_STATEMENT_TYPE,
) -> None:
    expected_digest = {"sha256": digest.removeprefix("sha256:")}
    for statement in statements:
        subjects = statement.get("subject") or []
        if (
            statement.get("_type") == statement_type
            and statement.get("predicateType") == predicate_type
            and statement.get("predicate") == predicate
            and any(isinstance(subject, dict) and subject.get("digest") == expected_digest for subject in subjects)
        ):
            return
    raise ReleaseVerificationError(f"no verified {predicate_type} attestation exactly matches {digest}")


def _fetch_and_match_index(oras: str, reference: str, expected_path: Path, expected_digest: str) -> None:
    with tempfile.TemporaryDirectory(prefix="backupsheep-oci-verify-") as temporary:
        output = Path(temporary) / "index.json"
        _run_tool(oras, ["manifest", "fetch", "--output", str(output), reference], ("ORAS_",))
        if _sha256_path(output) != expected_digest:
            raise ReleaseVerificationError(f"registry returned bytes that do not hash to {expected_digest}")
        if output.read_bytes() != expected_path.read_bytes():
            raise ReleaseVerificationError(f"registry OCI index differs from retained evidence for {reference}")


def verify_registry_evidence(
    verified: dict[str, Any],
    *,
    manifest_path: Path,
    manifest_bundle: Path,
    artifacts_dir: Path,
    cosign: str,
    oras: str,
    phase: str,
) -> None:
    policy = verified["policy"]
    manifest = verified["manifest"]
    release = manifest["release"]
    identity_args = _cosign_identity_args(policy, release)
    try:
        relative_bundle = manifest_bundle.resolve(strict=True).relative_to(artifacts_dir.resolve(strict=True)).as_posix()
    except (OSError, ValueError) as exc:
        raise ReleaseVerificationError("manifest bundle must be inside artifacts-dir") from exc
    _safe_artifact(artifacts_dir, relative_bundle, "manifest signature bundle")
    _run_tool(
        cosign,
        ["verify-blob", "--bundle", str(manifest_bundle), *identity_args, str(manifest_path)],
        ("COSIGN_", "SIGSTORE_"),
    )

    for image_name, image in manifest["images"].items():
        repositories = [image["quarantine_repository"]]
        if phase == "final":
            repositories.append(image["official_repository"])
        index_path = _safe_artifact(artifacts_dir, image["oci_index"]["file"], f"{image_name} OCI index")
        evidence = verified["attestation_predicates"][image_name]
        for repository in repositories:
            index_reference = f"{repository}@{image['digest']}"
            _fetch_and_match_index(oras, index_reference, index_path, image["digest"])
            _run_tool(cosign, ["verify", *identity_args, index_reference], ("COSIGN_", "SIGSTORE_"))
            for platform, child_digest in image["platforms"].items():
                child_reference = f"{repository}@{child_digest}"
                _run_tool(cosign, ["verify", *identity_args, child_reference], ("COSIGN_", "SIGSTORE_"))
                provenance_output = _run_tool(
                    cosign,
                    ["verify-attestation", "--type", "slsaprovenance1", *identity_args, child_reference],
                    ("COSIGN_", "SIGSTORE_"),
                )
                _require_matching_attestation(
                    _statements_from_cosign(provenance_output),
                    digest=child_digest,
                    predicate_type=policy["attestations"]["provenance_predicate_type"],
                    predicate=evidence["provenance"][platform],
                )
                for fmt in policy["attestations"]["sbom_predicate_types"]:
                    output = _run_tool(
                        cosign,
                        [
                            "verify-attestation",
                            "--type",
                            "spdxjson" if fmt == "spdx-json" else "cyclonedx",
                            *identity_args,
                            child_reference,
                        ],
                        ("COSIGN_", "SIGSTORE_"),
                    )
                    _require_matching_attestation(
                        _statements_from_cosign(output),
                        digest=child_digest,
                        predicate_type=policy["attestations"]["sbom_predicate_types"][fmt],
                        predicate=evidence["sboms"][(platform, fmt)],
                        statement_type=IN_TOTO_STATEMENT_V01_TYPE,
                    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--manifest-bundle", type=Path)
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--oras", default="oras")
    parser.add_argument("--phase", choices=("candidate", "final"), default="final")
    parser.add_argument(
        "--offline", action="store_true", help="validate structure/hashes only; never authorize a release"
    )
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        manifest = _load_json(arguments.manifest, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        artifacts_dir = arguments.artifacts_dir.resolve(strict=True)
        verified = validate_release(policy, manifest, artifacts_dir)
        if arguments.offline:
            print("Release structure and artifact hashes verified; registry/signatures were NOT checked (--offline).")
            return 0
        cosign = shutil.which(arguments.cosign)
        oras = shutil.which(arguments.oras)
        if cosign is None or oras is None:
            raise ReleaseVerificationError("pinned Cosign and ORAS executables are both required")
        bundle = arguments.manifest_bundle or arguments.manifest.with_name("release-manifest.bundle.json")
        verify_registry_evidence(
            verified,
            manifest_path=arguments.manifest,
            manifest_bundle=bundle,
            artifacts_dir=artifacts_dir,
            cosign=cosign,
            oras=oras,
            phase=arguments.phase,
        )
        print(f"Release evidence verified for {arguments.phase} repositories.")
        return 0
    except (OSError, ReleaseVerificationError) as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
