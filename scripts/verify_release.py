#!/usr/bin/env python3
"""Verify a BackupSheep signed-release manifest and its bound evidence.

The default mode is intentionally online and fail closed: every image/index digest,
SLSA provenance attestation, platform SBOM attestation, and the manifest blob itself
must verify as a keyless Sigstore identity authorized by deploy/release-policy.json.
Use --offline only to validate structure and artifact hashes without making a trust
decision (for example, in unit tests or before an image has been published).
"""

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
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "deploy" / "release-policy.json"
MAX_CONTROL_FILE_BYTES = 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 256 * 1024 * 1024
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


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
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing={missing}")
        if unknown:
            details.append(f"unknown={unknown}")
        raise ReleaseVerificationError(f"{label} has invalid keys ({', '.join(details)})")


def _unique_strings(value: Any, label: str) -> list[str]:
    items = _list(value, label)
    result = [_string(item, f"{label}[]") for item in items]
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
            "vulnerability_policy",
        },
        "policy",
    )
    if _integer(policy["schema_version"], "policy.schema_version") != 1:
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
    if set(images) != {"app", "postgres"}:
        raise ReleaseVerificationError("policy.images must contain exactly app and postgres")
    for image_name, repository in images.items():
        repository = _string(repository, f"policy.images.{image_name}")
        if repository != repository.lower() or not repository.startswith(f"{registry}/"):
            raise ReleaseVerificationError(f"policy.images.{image_name} is not an authorized GHCR repository")
        if "@" in repository or ":" in repository.removeprefix(f"{registry}/"):
            raise ReleaseVerificationError(f"policy.images.{image_name} must not contain a tag or digest")

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
    _exact_keys(attestations, {"provenance_predicate_type", "sbom_predicate_types"}, "policy.attestations")
    if attestations["provenance_predicate_type"] != "https://slsa.dev/provenance/v1":
        raise ReleaseVerificationError("SLSA provenance v1 is required")
    predicate_types = _mapping(attestations["sbom_predicate_types"], "policy.attestations.sbom_predicate_types")
    if predicate_types != {
        "cyclonedx-json": "https://cyclonedx.org/bom",
        "spdx-json": "https://spdx.dev/Document",
    }:
        raise ReleaseVerificationError("both CycloneDX JSON and SPDX JSON attestations are required")

    vulnerability = _mapping(policy["vulnerability_policy"], "policy.vulnerability_policy")
    _exact_keys(
        vulnerability,
        {"scanner", "scanner_version", "fail_severities", "ignore_unfixed", "allowlist"},
        "policy.vulnerability_policy",
    )
    if vulnerability["scanner"] != "trivy":
        raise ReleaseVerificationError("Trivy is the required scanner")
    _string(vulnerability["scanner_version"], "policy.vulnerability_policy.scanner_version")
    if _unique_strings(vulnerability["fail_severities"], "policy.vulnerability_policy.fail_severities") != [
        "HIGH",
        "CRITICAL",
    ]:
        raise ReleaseVerificationError("HIGH and CRITICAL must both fail the release")
    if _boolean(vulnerability["ignore_unfixed"], "policy.vulnerability_policy.ignore_unfixed"):
        raise ReleaseVerificationError("unfixed HIGH/CRITICAL findings may not be ignored")
    if vulnerability["allowlist"] is not None:
        raise ReleaseVerificationError("the release policy does not permit a vulnerability allowlist")
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
    if not stat.S_ISREG(file_stat.st_mode):
        raise ReleaseVerificationError(f"artifact is not a regular file: {name}")
    if file_stat.st_size > MAX_EVIDENCE_FILE_BYTES:
        raise ReleaseVerificationError(f"artifact is too large: {name}")
    return candidate


def _verify_file(root: Path, record: dict[str, Any], label: str) -> tuple[Path, Any]:
    expected_digest = _digest(record["sha256"], f"{label}.sha256").removeprefix("sha256:")
    path = _safe_artifact(root, record["file"], f"{label}.file")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    if hasher.hexdigest() != expected_digest:
        raise ReleaseVerificationError(f"artifact digest mismatch: {record['file']}")
    return path, _load_json(path, maximum_bytes=MAX_EVIDENCE_FILE_BYTES)


def _validate_spdx(document: Any, label: str) -> None:
    document = _mapping(document, label)
    if not _string(document.get("spdxVersion"), f"{label}.spdxVersion").startswith("SPDX-"):
        raise ReleaseVerificationError(f"{label} is not an SPDX document")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ReleaseVerificationError(f"{label} has no SPDX document identifier")
    _string(document.get("name"), f"{label}.name")
    _list(document.get("packages"), f"{label}.packages")


def _validate_cyclonedx(document: Any, label: str) -> None:
    document = _mapping(document, label)
    if document.get("bomFormat") != "CycloneDX":
        raise ReleaseVerificationError(f"{label} is not a CycloneDX document")
    _string(document.get("specVersion"), f"{label}.specVersion")
    if _integer(document.get("version"), f"{label}.version") < 1:
        raise ReleaseVerificationError(f"{label}.version must be positive")
    _mapping(document.get("metadata"), f"{label}.metadata")
    _list(document.get("components"), f"{label}.components")


def _validate_trivy_report(document: Any, expected_reference: str, fail_severities: set[str], label: str) -> None:
    document = _mapping(document, label)
    if _integer(document.get("SchemaVersion"), f"{label}.SchemaVersion") < 2:
        raise ReleaseVerificationError(f"{label} uses an unsupported Trivy schema")
    if document.get("ArtifactName") != expected_reference:
        raise ReleaseVerificationError(f"{label} is not bound to {expected_reference}")
    results = _list(document.get("Results"), f"{label}.Results")
    forbidden: list[str] = []
    for result in results:
        result = _mapping(result, f"{label}.Results[]")
        vulnerabilities = result.get("Vulnerabilities") or []
        for vulnerability in _list(vulnerabilities, f"{label}.Results[].Vulnerabilities"):
            vulnerability = _mapping(vulnerability, f"{label}.Results[].Vulnerabilities[]")
            severity = _string(vulnerability.get("Severity"), f"{label}.vulnerability.Severity").upper()
            if severity in fail_severities:
                identifier = str(vulnerability.get("VulnerabilityID") or "unknown")
                forbidden.append(f"{identifier}:{severity}")
    if forbidden:
        raise ReleaseVerificationError(f"{label} contains release-blocking vulnerabilities: {', '.join(forbidden[:10])}")


def _validate_provenance(
    predicate: Any,
    *,
    release: dict[str, Any],
    repository: str,
    dockerfile: str,
    platforms: list[str],
    label: str,
) -> None:
    predicate = _mapping(predicate, label)
    _exact_keys(predicate, {"buildDefinition", "runDetails"}, label)
    definition = _mapping(predicate["buildDefinition"], f"{label}.buildDefinition")
    _exact_keys(
        definition,
        {"buildType", "externalParameters", "internalParameters", "resolvedDependencies"},
        f"{label}.buildDefinition",
    )
    if definition["buildType"] != "https://mobyproject.org/buildkit@v1":
        raise ReleaseVerificationError(f"{label} has an unexpected build type")
    parameters = _mapping(definition["externalParameters"], f"{label}.externalParameters")
    _exact_keys(
        parameters,
        {"source_repository", "source_commit", "image_repository", "dockerfile", "platforms"},
        f"{label}.externalParameters",
    )
    if parameters != {
        "source_repository": release["source_repository"],
        "source_commit": release["source_commit"],
        "image_repository": repository,
        "dockerfile": dockerfile,
        "platforms": platforms,
    }:
        raise ReleaseVerificationError(f"{label} external parameters do not bind the release")
    if _mapping(definition["internalParameters"], f"{label}.internalParameters"):
        raise ReleaseVerificationError(f"{label}.internalParameters must be empty")
    dependencies = _list(definition["resolvedDependencies"], f"{label}.resolvedDependencies")
    expected_dependency = {
        "uri": f"git+https://github.com/{release['source_repository']}.git",
        "digest": {"gitCommit": release["source_commit"]},
    }
    if dependencies != [expected_dependency]:
        raise ReleaseVerificationError(f"{label} does not resolve the exact source commit")

    run_details = _mapping(predicate["runDetails"], f"{label}.runDetails")
    _exact_keys(run_details, {"builder", "metadata"}, f"{label}.runDetails")
    if run_details["builder"] != {"id": release["workflow_identity"]}:
        raise ReleaseVerificationError(f"{label} has an unauthorized builder identity")
    if run_details["metadata"] != {
        "invocationId": release["workflow_run"],
        "startedOn": release["created_at"],
    }:
        raise ReleaseVerificationError(f"{label} run metadata does not bind the release")


def validate_release(policy: Any, manifest: Any, artifacts_dir: Path) -> dict[str, Any]:
    policy = _validate_policy(policy)
    manifest = _mapping(manifest, "manifest")
    _exact_keys(manifest, {"schema_version", "release", "images"}, "manifest")
    if _integer(manifest["schema_version"], "manifest.schema_version") != 1:
        raise ReleaseVerificationError("unsupported release manifest schema")

    release = _mapping(manifest["release"], "manifest.release")
    _exact_keys(
        release,
        {
            "tag",
            "source_repository",
            "source_commit",
            "workflow_identity",
            "workflow_run",
            "created_at",
        },
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
        f"https://github.com/{policy['source_repository']}/{policy['release_workflow']}"
        f"@refs/tags/{tag}"
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
    expected_platforms = policy["platforms"]
    sbom_formats = policy["attestations"]["sbom_predicate_types"]
    vulnerability_policy = policy["vulnerability_policy"]
    fail_severities = set(vulnerability_policy["fail_severities"])

    for image_name in sorted(images):
        label = f"manifest.images.{image_name}"
        image = _mapping(images[image_name], label)
        _exact_keys(
            image,
            {"repository", "digest", "reference", "platforms", "provenance", "sboms", "vulnerability_reports"},
            label,
        )
        repository = policy["images"][image_name]
        if image["repository"] != repository:
            raise ReleaseVerificationError(f"{label}.repository is not authorized")
        index_digest = _digest(image["digest"], f"{label}.digest")
        if image["reference"] != f"{repository}@{index_digest}":
            raise ReleaseVerificationError(f"{label}.reference must use its exact digest")

        platform_map = _mapping(image["platforms"], f"{label}.platforms")
        if list(platform_map) != expected_platforms:
            raise ReleaseVerificationError(f"{label}.platforms must preserve the policy order")
        child_digests = [_digest(platform_map[platform], f"{label}.platforms.{platform}") for platform in expected_platforms]
        if len(set(child_digests)) != len(child_digests) or index_digest in child_digests:
            raise ReleaseVerificationError(f"{label} platform/index digests are not distinct")

        provenance_record = _mapping(image["provenance"], f"{label}.provenance")
        _exact_keys(provenance_record, {"predicate_type", "file", "sha256"}, f"{label}.provenance")
        if provenance_record["predicate_type"] != policy["attestations"]["provenance_predicate_type"]:
            raise ReleaseVerificationError(f"{label} has the wrong provenance predicate type")
        _, provenance = _verify_file(artifacts_dir, provenance_record, f"{label}.provenance")
        dockerfile = "Dockerfile" if image_name == "app" else "Dockerfile.postgres"
        _validate_provenance(
            provenance,
            release=release,
            repository=repository,
            dockerfile=dockerfile,
            platforms=expected_platforms,
            label=f"{label}.provenance.predicate",
        )

        sbom_records = _list(image["sboms"], f"{label}.sboms")
        expected_sbom_pairs = {(platform, fmt) for platform in expected_platforms for fmt in sbom_formats}
        actual_sbom_pairs: set[tuple[str, str]] = set()
        predicates: dict[tuple[str, str], Any] = {}
        for index, raw_record in enumerate(sbom_records):
            record_label = f"{label}.sboms[{index}]"
            record = _mapping(raw_record, record_label)
            _exact_keys(record, {"platform", "format", "predicate_type", "file", "sha256"}, record_label)
            platform = _string(record["platform"], f"{record_label}.platform")
            fmt = _string(record["format"], f"{record_label}.format")
            pair = (platform, fmt)
            if pair not in expected_sbom_pairs or pair in actual_sbom_pairs:
                raise ReleaseVerificationError(f"{record_label} is duplicate or not required")
            actual_sbom_pairs.add(pair)
            if record["predicate_type"] != sbom_formats[fmt]:
                raise ReleaseVerificationError(f"{record_label} has the wrong predicate type")
            _, document = _verify_file(artifacts_dir, record, record_label)
            if fmt == "spdx-json":
                _validate_spdx(document, f"{record_label}.document")
            else:
                _validate_cyclonedx(document, f"{record_label}.document")
            predicates[(platform, fmt)] = document
        if actual_sbom_pairs != expected_sbom_pairs:
            raise ReleaseVerificationError(f"{label} does not contain every required platform SBOM")

        report_records = _list(image["vulnerability_reports"], f"{label}.vulnerability_reports")
        report_platforms: set[str] = set()
        for index, raw_record in enumerate(report_records):
            record_label = f"{label}.vulnerability_reports[{index}]"
            record = _mapping(raw_record, record_label)
            _exact_keys(
                record,
                {"platform", "scanner", "scanner_version", "fail_severities", "ignore_unfixed", "file", "sha256"},
                record_label,
            )
            platform = _string(record["platform"], f"{record_label}.platform")
            if platform not in expected_platforms or platform in report_platforms:
                raise ReleaseVerificationError(f"{record_label} is duplicate or not required")
            report_platforms.add(platform)
            if record["scanner"] != vulnerability_policy["scanner"]:
                raise ReleaseVerificationError(f"{record_label} uses an unauthorized scanner")
            if record["scanner_version"] != vulnerability_policy["scanner_version"]:
                raise ReleaseVerificationError(f"{record_label} uses an unauthorized scanner version")
            if record["fail_severities"] != vulnerability_policy["fail_severities"]:
                raise ReleaseVerificationError(f"{record_label} weakens the failure severity policy")
            if _boolean(record["ignore_unfixed"], f"{record_label}.ignore_unfixed"):
                raise ReleaseVerificationError(f"{record_label} ignored unfixed vulnerabilities")
            _, report = _verify_file(artifacts_dir, record, record_label)
            child_reference = f"{repository}@{platform_map[platform]}"
            _validate_trivy_report(report, child_reference, fail_severities, f"{record_label}.report")
        if report_platforms != set(expected_platforms):
            raise ReleaseVerificationError(f"{label} does not contain every required platform scan")

        verified["attestation_predicates"][image_name] = {
            "provenance": provenance,
            "sboms": predicates,
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


def _run_cosign(cosign: str, arguments: list[str]) -> str:
    environment = os.environ.copy()
    # Do not let caller-controlled Cosign/Sigstore environment variables redirect
    # signature storage, weaken transparency checks, or select alternate trust roots.
    # Registry authentication still comes from Docker's ordinary credential config.
    for name in tuple(environment):
        if name.startswith(("COSIGN_", "SIGSTORE_")):
            environment.pop(name, None)
    try:
        result = subprocess.run(
            [cosign, *arguments],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseVerificationError(f"Cosign invocation failed: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise ReleaseVerificationError(f"Cosign rejected release evidence: {detail[:1000]}")
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
            statement = json.loads(
                decoded,
                object_pairs_hook=_no_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReleaseVerificationError("Cosign emitted an invalid DSSE payload") from exc
        statements.append(_mapping(statement, "Cosign in-toto statement"))
    if not statements:
        raise ReleaseVerificationError("Cosign returned no verified attestation statements")
    return statements


def _require_matching_attestation(
    statements: list[dict[str, Any]],
    *,
    repository: str,
    digest: str,
    predicate_type: str,
    predicate: Any,
) -> None:
    expected_subject = {"name": repository, "digest": {"sha256": digest.removeprefix("sha256:")}}
    for statement in statements:
        if (
            statement.get("predicateType") == predicate_type
            and statement.get("predicate") == predicate
            and expected_subject in (statement.get("subject") or [])
        ):
            return
    raise ReleaseVerificationError(f"no verified {predicate_type} attestation exactly matches {repository}@{digest}")


def verify_registry_evidence(
    verified: dict[str, Any],
    *,
    manifest_path: Path,
    manifest_bundle: Path,
    cosign: str,
) -> None:
    policy = verified["policy"]
    manifest = verified["manifest"]
    release = manifest["release"]
    identity_args = _cosign_identity_args(policy, release)

    _safe_artifact(manifest_bundle.parent, manifest_bundle.name, "manifest signature bundle")
    _run_cosign(
        cosign,
        ["verify-blob", "--bundle", str(manifest_bundle), *identity_args, str(manifest_path)],
    )

    for image_name in sorted(manifest["images"]):
        image = manifest["images"][image_name]
        repository = image["repository"]
        index_reference = image["reference"]
        _run_cosign(cosign, ["verify", *identity_args, index_reference])

        for platform, child_digest in image["platforms"].items():
            child_reference = f"{repository}@{child_digest}"
            _run_cosign(cosign, ["verify", *identity_args, child_reference])

        provenance_output = _run_cosign(
            cosign,
            ["verify-attestation", "--type", "slsaprovenance1", *identity_args, index_reference],
        )
        _require_matching_attestation(
            _statements_from_cosign(provenance_output),
            repository=repository,
            digest=image["digest"],
            predicate_type=policy["attestations"]["provenance_predicate_type"],
            predicate=verified["attestation_predicates"][image_name]["provenance"],
        )

        for (platform, fmt), predicate in verified["attestation_predicates"][image_name]["sboms"].items():
            child_digest = image["platforms"][platform]
            child_reference = f"{repository}@{child_digest}"
            cosign_type = "spdxjson" if fmt == "spdx-json" else "cyclonedx"
            output = _run_cosign(
                cosign,
                ["verify-attestation", "--type", cosign_type, *identity_args, child_reference],
            )
            _require_matching_attestation(
                _statements_from_cosign(output),
                repository=repository,
                digest=child_digest,
                predicate_type=policy["attestations"]["sbom_predicate_types"][fmt],
                predicate=predicate,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--manifest-bundle", type=Path)
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="validate structure/hashes only; never treat this as signature verification",
    )
    arguments = parser.parse_args(argv)

    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        manifest = _load_json(arguments.manifest, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        verified = validate_release(policy, manifest, arguments.artifacts_dir)
        if arguments.offline:
            print("Release structure and artifact hashes verified; signatures were NOT checked (--offline).")
            return 0
        cosign = shutil.which(arguments.cosign)
        if cosign is None:
            raise ReleaseVerificationError(f"Cosign executable not found: {arguments.cosign}")
        bundle = arguments.manifest_bundle or arguments.manifest.with_name("release-manifest.bundle.json")
        verify_registry_evidence(
            verified,
            manifest_path=arguments.manifest,
            manifest_bundle=bundle,
            cosign=cosign,
        )
        print("Release manifest, artifacts, signatures, and attestations verified.")
        return 0
    except ReleaseVerificationError as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
