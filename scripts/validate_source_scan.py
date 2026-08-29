#!/usr/bin/env python3
"""Validate private Trivy source reports and emit zero-sensitive evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit


MAX_POLICY_BYTES = 64 * 1024
MAX_REPORT_BYTES = 128 * 1024 * 1024
MAX_TARGET_BYTES = 4 * 1024 * 1024
MAX_RESULT_COUNT = 100_000
MAX_GIT_OUTPUT_BYTES = 64 * 1024
EXPECTED_REVIEWS = {
    ("Dockerfile", "DS-0017"),
    ("Dockerfile.egress", "DS-0002"),
}
EXPECTED_CONFIG_TARGETS = {
    "Dockerfile",
    "Dockerfile.egress",
    "Dockerfile.postgres",
    "deploy/ci/Dockerfile.postgres-runtime-source",
}
EXPECTED_VULNERABILITY_MISCONFIGURATION_IDENTITIES = {
    ("Dockerfile", "config", "dockerfile"),
    ("Dockerfile.egress", "config", "dockerfile"),
    ("Dockerfile.postgres", "config", "dockerfile"),
    ("deploy/ci/Dockerfile.postgres-runtime-source", "config", "dockerfile"),
    ("package-lock.json", "lang-pkgs", "npm"),
    ("requirements.txt", "lang-pkgs", "pip"),
}
EXPECTED_SECRET_INVENTORY_IDENTITIES = {
    ("requirements.txt", "lang-pkgs", "pip"),
}
EXPECTED_SCANNER = {
    "artifact_type": "filesystem",
    "name": "trivy",
    "secret_scan": {
        "disable_allow_rules": [
            "dist-info",
            "tests",
            "examples",
            "vendor",
            "usr-dirs",
            "locale-dir",
            "markdown",
            "node.js",
            "golang",
            "python",
            "rubygems",
            "wordpress",
            "anaconda-log",
        ],
        "fail_severities": ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "scanners": ["secret"],
        "skip_patterns": [],
    },
    "vulnerability_misconfiguration_scan": {
        "fail_severities": ["HIGH", "CRITICAL"],
        "scanners": ["vuln", "misconfig"],
    },
    "version": "0.74.0",
}
EXPECTED_FILESYSTEM_REPORT_FIELDS = {
    "ArtifactName",
    "ArtifactType",
    "CreatedAt",
    "ReportID",
    "Results",
    "SchemaVersion",
    "Trivy",
}
EXPECTED_REPOSITORY_REPORT_FIELDS = EXPECTED_FILESYSTEM_REPORT_FIELDS | {
    "ArtifactID",
    "Metadata",
}
KNOWN_REPORT_FIELDS = EXPECTED_REPOSITORY_REPORT_FIELDS
EXPECTED_DETACHED_REPOSITORY_METADATA_FIELDS = {
    "Author",
    "Commit",
    "CommitMsg",
    "Committer",
    "RepoURL",
}
EXPECTED_SECRET_CANARIES = Counter(
    {
        ("canary.lock", "twilio-api-key", "MEDIUM"): 1,
        ("canary.md", "twilio-api-key", "MEDIUM"): 1,
        ("examples/canary.txt", "twilio-api-key", "MEDIUM"): 1,
        ("tests/canary.txt", "twilio-api-key", "MEDIUM"): 1,
        ("vendor/canary.txt", "twilio-api-key", "MEDIUM"): 1,
    }
)


class SourceScanError(RuntimeError):
    """A bounded source-scan validation failure."""


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise SourceScanError("JSON contains a duplicate or non-string object key.")
        result[key] = value
    return result


def _read_regular(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SourceScanError(f"Could not open the {label} as a regular file.") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SourceScanError(f"The {label} must be a regular non-link file.")
        if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
            raise SourceScanError(f"The {label} is empty or exceeds its size limit.")
        chunks = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size or len(payload) > maximum_bytes:
            raise SourceScanError(f"The {label} changed while reading or is oversized.")
        return payload
    finally:
        os.close(descriptor)


def load_json(path: Path, *, maximum_bytes: int, label: str) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular(path, maximum_bytes=maximum_bytes, label=label)
    try:
        parsed = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SourceScanError(f"The {label} is not strict UTF-8 JSON.") from error
    if not isinstance(parsed, dict):
        raise SourceScanError(f"The {label} must contain one JSON object.")
    return parsed, payload


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def finding_fingerprint(finding: dict[str, Any]) -> str:
    encoded = json.dumps(
        finding, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return _sha256(encoded)


def _safe_target(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise SourceScanError("A Trivy result has an invalid target path.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SourceScanError("A Trivy result has an invalid target path.")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise SourceScanError("A Trivy result has an unsafe target path.")
    return value


def _hex_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SourceScanError(f"The source-scan policy has an invalid {label}.")
    return value


def validate_policy(policy: dict[str, Any]) -> list[dict[str, str]]:
    if set(policy) != {"schema_version", "scanner", "reviewed_misconfigurations"}:
        raise SourceScanError("The source-scan policy has unexpected or missing fields.")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise SourceScanError("The source-scan policy schema is unsupported.")
    if policy["scanner"] != EXPECTED_SCANNER:
        raise SourceScanError("The source-scan policy scanner contract is invalid.")
    reviews = policy["reviewed_misconfigurations"]
    if not isinstance(reviews, list) or len(reviews) != len(EXPECTED_REVIEWS):
        raise SourceScanError("The source-scan policy must contain exactly two reviews.")

    normalized: list[dict[str, str]] = []
    identities: set[tuple[str, str]] = set()
    required = {
        "finding_sha256",
        "id",
        "reason",
        "severity",
        "status",
        "target",
        "target_sha256",
    }
    for review in reviews:
        if not isinstance(review, dict) or set(review) != required:
            raise SourceScanError("A source-scan review is malformed.")
        target = review.get("target")
        identifier = review.get("id")
        reason = review.get("reason")
        if not isinstance(target, str) or not isinstance(identifier, str):
            raise SourceScanError("A source-scan review has an invalid identity.")
        if (target, identifier) not in EXPECTED_REVIEWS:
            raise SourceScanError("The source-scan policy contains an unauthorized review.")
        if (target, identifier) in identities:
            raise SourceScanError("The source-scan policy contains a duplicate review.")
        if review.get("severity") != "HIGH" or review.get("status") != "FAIL":
            raise SourceScanError("A source-scan review has an invalid severity or status.")
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in reason)
        ):
            raise SourceScanError("A source-scan review has an invalid explanation.")
        normalized.append(
            {
                "target": str(target),
                "id": str(identifier),
                "severity": "HIGH",
                "status": "FAIL",
                "target_sha256": _hex_digest(
                    review.get("target_sha256"), "target SHA-256"
                ),
                "finding_sha256": _hex_digest(
                    review.get("finding_sha256"), "finding SHA-256"
                ),
            }
        )
        identities.add((str(target), str(identifier)))
    if identities != EXPECTED_REVIEWS:
        raise SourceScanError("The source-scan policy reviews are incomplete.")
    return sorted(normalized, key=lambda item: (item["target"], item["id"]))


def validate_target_hashes(reviews: list[dict[str, str]], repository_root: Path) -> None:
    try:
        root_metadata = repository_root.lstat()
    except OSError as error:
        raise SourceScanError("Could not inspect the repository root.") from error
    if repository_root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise SourceScanError("The repository root must be a real directory.")
    for review in reviews:
        target = repository_root / review["target"]
        payload = _read_regular(
            target, maximum_bytes=MAX_TARGET_BYTES, label="reviewed source target"
        )
        if _sha256(payload) != review["target_sha256"]:
            raise SourceScanError("A content-pinned reviewed source target changed.")


def _nonnegative_integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise SourceScanError(f"A Trivy result has an invalid {label} count.")
    return value


def _raise_report_schema_error(
    *, label: str, actual_fields: set[Any], expected_fields: set[str]
) -> None:
    """Report only fixed field names and counts, never attacker-controlled keys."""
    missing = sorted(expected_fields - actual_fields)
    unexpected = actual_fields - expected_fields
    recognized_unexpected = sorted(unexpected & KNOWN_REPORT_FIELDS)
    unrecognized_count = len(unexpected - KNOWN_REPORT_FIELDS)
    missing_text = ",".join(missing) if missing else "none"
    recognized_text = (
        ",".join(recognized_unexpected) if recognized_unexpected else "none"
    )
    raise SourceScanError(
        f"The {label} Trivy report schema is invalid "
        f"(missing_known={missing_text}; unexpected_known={recognized_text}; "
        f"unexpected_unknown_count={unrecognized_count})."
    )


def _validated_signature(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise SourceScanError(f"The {label} repository signature is malformed.")
    match = re.fullmatch(
        r"([^\x00-\x20\x7f<>][^\x00-\x1f\x7f<>]{0,255}) "
        r"<([^\x00-\x20\x7f<>]{3,254})>",
        value,
    )
    if match is None or match.group(1).rstrip() != match.group(1):
        raise SourceScanError(f"The {label} repository signature is malformed.")
    return value


def _validated_commit_message(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 16 * 1024
        or value.strip() != value
        or any(
            character not in {"\n", "\t"} and not character.isprintable()
            for character in value
        )
    ):
        raise SourceScanError("The repository commit message metadata is malformed.")
    return value


def _validated_repository_url(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or not value.isascii()
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
    ):
        raise SourceScanError("The repository URL metadata is malformed.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise SourceScanError("The repository URL metadata is malformed.") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
        or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", parsed.hostname)
        or not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,1800}", parsed.path)
        or urlunsplit(parsed) != value
    ):
        raise SourceScanError("The repository URL metadata is malformed.")
    return value


def _repository_artifact_id(repository_url: str, commit: str) -> str:
    digest = hashlib.sha256(f"{repository_url}@{commit}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _validate_repository_report_identity(
    report: dict[str, Any], *, source_revision: str, label: str
) -> dict[str, Any]:
    metadata = report.get("Metadata")
    if (
        not isinstance(metadata, dict)
        or set(metadata) != EXPECTED_DETACHED_REPOSITORY_METADATA_FIELDS
    ):
        raise SourceScanError(
            f"The {label} Trivy report repository metadata shape is invalid."
        )
    commit = metadata.get("Commit")
    if (
        not isinstance(commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or commit != source_revision
    ):
        raise SourceScanError(
            f"The {label} Trivy report repository commit is not the final source revision."
        )
    repository_url = _validated_repository_url(metadata.get("RepoURL"))
    _validated_signature(metadata.get("Author"), label="author")
    _validated_signature(metadata.get("Committer"), label="committer")
    _validated_commit_message(metadata.get("CommitMsg"))
    artifact_id = report.get("ArtifactID")
    expected_artifact_id = _repository_artifact_id(repository_url, commit)
    if (
        not isinstance(artifact_id, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_id)
        or artifact_id != expected_artifact_id
    ):
        raise SourceScanError(
            f"The {label} Trivy report repository artifact identity is invalid."
        )
    return {
        "artifact_id": artifact_id,
        "artifact_name": report["ArtifactName"],
        "artifact_type": "repository",
        "metadata": dict(metadata),
    }


def _validate_report_header(
    report: dict[str, Any],
    artifact_name: str,
    *,
    expected_artifact_type: str,
    label: str,
    source_revision: str | None = None,
) -> tuple[Any, dict[str, Any]]:
    if expected_artifact_type == "repository":
        expected_fields = EXPECTED_REPOSITORY_REPORT_FIELDS
    elif expected_artifact_type == "filesystem":
        expected_fields = EXPECTED_FILESYSTEM_REPORT_FIELDS
    else:
        raise SourceScanError("The expected Trivy artifact type is unsupported.")
    if set(report) != expected_fields:
        _raise_report_schema_error(
            label=label,
            actual_fields=set(report),
            expected_fields=expected_fields,
        )
    if type(report["SchemaVersion"]) is not int or report["SchemaVersion"] != 2:
        raise SourceScanError(f"The {label} Trivy report schema version is unsupported.")
    if (
        report["ArtifactName"] != artifact_name
        or report["ArtifactType"] != expected_artifact_type
    ):
        raise SourceScanError(
            f"The {label} Trivy report did not identify the expected scan target."
        )
    if report["Trivy"] != {"Version": EXPECTED_SCANNER["version"]}:
        raise SourceScanError(
            f"The {label} Trivy report does not identify the pinned scanner."
        )
    if not isinstance(report["CreatedAt"], str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\x00-\x20]{1,64}Z", report["CreatedAt"]
    ):
        raise SourceScanError(f"The {label} Trivy report creation time is malformed.")
    if not isinstance(report["ReportID"], str) or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        report["ReportID"],
    ):
        raise SourceScanError(f"The {label} Trivy report identifier is malformed.")
    if expected_artifact_type == "repository":
        if source_revision is None:
            raise SourceScanError("The repository report has no source revision contract.")
        identity = _validate_repository_report_identity(
            report, source_revision=source_revision, label=label
        )
    else:
        identity = {
            "artifact_name": report["ArtifactName"],
            "artifact_type": "filesystem",
        }
    return report["Results"], identity


def validate_secret_report(
    report: dict[str, Any],
    *,
    canary: bool,
    expected_artifact_type: str,
    source_revision: str | None = None,
) -> tuple[int, dict[str, Any]]:
    label = "secret canary" if canary else "all-severity secret"
    results, report_identity = _validate_report_header(
        report,
        ".",
        expected_artifact_type=expected_artifact_type,
        label=label,
        source_revision=source_revision,
    )
    if (
        not isinstance(results, list)
        or not results
        or len(results) > MAX_RESULT_COUNT
    ):
        raise SourceScanError("The Trivy secret report results are malformed or excessive.")

    identities: set[tuple[str, str, str]] = set()
    detections: Counter[tuple[str, str, str]] = Counter()
    secret_count = 0
    package_count = 0
    for result in results:
        if not isinstance(result, dict):
            raise SourceScanError("The Trivy secret report contains a malformed result.")
        target = _safe_target(result.get("Target"))
        result_class = result.get("Class")
        if canary and result_class != "secret":
            raise SourceScanError("The Trivy canary report contains an extra result.")
        if result_class == "secret":
            if set(result) != {"Class", "Secrets", "Target"}:
                raise SourceScanError("The Trivy secret report contains a malformed result.")
            result_type = "secret"
            findings = result.get("Secrets")
            if not isinstance(findings, list) or not findings:
                raise SourceScanError("The Trivy secret findings are malformed.")
        elif result_class == "lang-pkgs":
            if set(result) != {"Class", "Packages", "Target", "Type"}:
                raise SourceScanError("The Trivy secret report contains a malformed result.")
            result_type = result.get("Type")
            packages = result.get("Packages")
            if (
                not isinstance(result_type, str)
                or not result_type
                or not isinstance(packages, list)
                or not packages
                or any(not isinstance(item, dict) for item in packages)
            ):
                raise SourceScanError("The Trivy secret report inventory is malformed.")
            package_count += len(packages)
            findings = []
        else:
            raise SourceScanError("The Trivy secret report contains an invalid result type.")
        identity = (target, result_class, result_type)
        if identity in identities:
            raise SourceScanError("The Trivy secret report contains a duplicate result.")
        identities.add(identity)
        secret_count += len(findings)
        if canary:
            for finding in findings:
                if not isinstance(finding, dict):
                    raise SourceScanError("The Trivy canary findings are malformed.")
                if set(finding) != {
                    "Category",
                    "Code",
                    "EndLine",
                    "Match",
                    "RuleID",
                    "Severity",
                    "StartLine",
                    "Title",
                }:
                    raise SourceScanError("The Trivy canary findings are malformed.")
                rule_id = finding.get("RuleID")
                severity = finding.get("Severity")
                if (
                    not isinstance(rule_id, str)
                    or not isinstance(severity, str)
                    or finding.get("Category") != "Twilio"
                    or finding.get("Title") != "Twilio API Key"
                    or type(finding.get("StartLine")) is not int
                    or finding.get("StartLine") != 1
                    or type(finding.get("EndLine")) is not int
                    or finding.get("EndLine") != 1
                    or not isinstance(finding.get("Code"), dict)
                    or not isinstance(finding.get("Match"), str)
                    or not finding.get("Match")
                ):
                    raise SourceScanError("The Trivy canary finding identity is malformed.")
                detections[(target, rule_id, severity)] += 1

    if canary:
        if detections != EXPECTED_SECRET_CANARIES:
            # Never echo Match, Code, target content, or the untrusted finding object.
            raise SourceScanError(
                "The all-severity secret canaries were missing, changed, or duplicated."
            )
    elif secret_count:
        # Do not include the target, rule, match, or source bytes in this error.
        raise SourceScanError(
            f"Trivy reported {secret_count} all-severity secret finding(s)."
        )
    elif identities != EXPECTED_SECRET_INVENTORY_IDENTITIES:
        raise SourceScanError(
            "The all-severity secret report inventory coverage is missing, changed, or unexpectedly broad."
        )
    elif package_count == 0:
        raise SourceScanError("The all-severity secret report has no source inventory.")
    return secret_count, report_identity


def validate_report(
    report: dict[str, Any],
    secret_report: dict[str, Any],
    canary_report: dict[str, Any],
    policy: dict[str, Any],
    repository_root: Path,
    source_revision: str,
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        raise SourceScanError("The source revision is not a full Git SHA-1.")
    reviews = validate_policy(policy)
    validate_target_hashes(reviews, repository_root)
    trusted_repository_identity = _trusted_repository_identity_for_checkout(
        repository_root, source_revision
    )
    expected_artifact_type = (
        "repository" if trusted_repository_identity is not None else "filesystem"
    )

    results, report_identity = _validate_report_header(
        report,
        ".",
        expected_artifact_type=expected_artifact_type,
        label="vulnerability/misconfiguration",
        source_revision=source_revision,
    )
    if not isinstance(results, list) or not results or len(results) > MAX_RESULT_COUNT:
        raise SourceScanError("The Trivy report results are absent or excessive.")

    result_identities: set[tuple[str, str, str]] = set()
    actual_misconfigurations: Counter[tuple[str, str, str, str, str]] = Counter()
    vulnerability_count = 0
    package_count = 0
    expected_config_targets: set[str] = set()
    for result in results:
        if not isinstance(result, dict):
            raise SourceScanError("The Trivy report contains a malformed result.")
        target = _safe_target(result.get("Target"))
        result_class = result.get("Class")
        result_type = result.get("Type")
        if not isinstance(result_class, str) or not result_class or len(result_class) > 128:
            raise SourceScanError("The Trivy report contains a malformed result class.")
        if not isinstance(result_type, str) or not result_type or len(result_type) > 128:
            raise SourceScanError("The Trivy report contains a malformed result type.")
        identity = (target, result_class, result_type)
        if identity in result_identities:
            raise SourceScanError("The Trivy report contains a duplicate result.")
        result_identities.add(identity)

        if result_class == "lang-pkgs":
            allowed = {"Class", "Packages", "Target", "Type", "Vulnerabilities"}
            required = {"Class", "Packages", "Target", "Type"}
            if not required.issubset(result) or not set(result).issubset(allowed):
                raise SourceScanError("The Trivy package result is malformed.")
            packages = result.get("Packages")
            vulnerabilities = result.get("Vulnerabilities", [])
            if (
                not isinstance(packages, list)
                or not packages
                or any(not isinstance(item, dict) for item in packages)
            ):
                raise SourceScanError("The Trivy package inventory is malformed.")
            if not isinstance(vulnerabilities, list):
                raise SourceScanError("The Trivy vulnerability results are malformed.")
            package_count += len(packages)
            vulnerability_count += len(vulnerabilities)
            misconfigurations = []
        elif result_class == "config":
            allowed = {
                "Class",
                "MisconfSummary",
                "Misconfigurations",
                "Target",
                "Type",
            }
            required = {"Class", "MisconfSummary", "Target", "Type"}
            if (
                result_type != "dockerfile"
                or not required.issubset(result)
                or not set(result).issubset(allowed)
            ):
                raise SourceScanError("The Trivy configuration result is malformed.")
            misconfigurations = result.get("Misconfigurations", [])
            if not isinstance(misconfigurations, list):
                raise SourceScanError("The Trivy misconfiguration results are malformed.")
            expected_config_targets.add(target)
            summary = result.get("MisconfSummary")
            if not isinstance(summary, dict) or not set(summary).issubset(
                {"Successes", "Failures", "Exceptions"}
            ) or not {"Successes", "Failures"}.issubset(summary):
                raise SourceScanError("A Trivy misconfiguration summary is malformed.")
            successes = _nonnegative_integer(summary["Successes"], "success")
            failures = _nonnegative_integer(summary["Failures"], "failure")
            exceptions = _nonnegative_integer(summary.get("Exceptions", 0), "exception")
            if successes == 0 or failures != len(misconfigurations) or exceptions != 0:
                raise SourceScanError("A Trivy misconfiguration summary is inconsistent.")
        else:
            raise SourceScanError("The Trivy report contains an invalid result class.")

        for finding in misconfigurations:
            if not isinstance(finding, dict):
                raise SourceScanError("The Trivy report contains a malformed misconfiguration.")
            identifier = finding.get("ID")
            severity = finding.get("Severity")
            status = finding.get("Status")
            if (
                not isinstance(identifier, str)
                or not re.fullmatch(r"[A-Z]{2}-[0-9]{4}", identifier)
                or not isinstance(severity, str)
                or severity not in {"HIGH", "CRITICAL"}
                or not isinstance(status, str)
                or status != "FAIL"
            ):
                raise SourceScanError("The Trivy report contains an invalid misconfiguration.")
            actual_misconfigurations[
                (target, identifier, severity, status, finding_fingerprint(finding))
            ] += 1

    if vulnerability_count:
        raise SourceScanError(
            f"Trivy reported {vulnerability_count} HIGH/CRITICAL vulnerability finding(s)."
        )
    if package_count == 0:
        raise SourceScanError("Trivy produced no dependency inventory for vulnerability scanning.")
    if result_identities != EXPECTED_VULNERABILITY_MISCONFIGURATION_IDENTITIES:
        raise SourceScanError(
            "Trivy dependency and configuration coverage is missing, changed, or unexpectedly broad."
        )
    if expected_config_targets != EXPECTED_CONFIG_TARGETS:
        raise SourceScanError(
            "Trivy configuration coverage is missing, changed, or unexpectedly broad."
        )

    expected_misconfigurations = Counter(
        (
            review["target"],
            review["id"],
            review["severity"],
            review["status"],
            review["finding_sha256"],
        )
        for review in reviews
    )
    if actual_misconfigurations != expected_misconfigurations:
        raise SourceScanError(
            "The Trivy misconfiguration set is extra, missing, changed, or duplicated."
        )

    _secret_count, secret_report_identity = validate_secret_report(
        secret_report,
        canary=False,
        expected_artifact_type=expected_artifact_type,
        source_revision=source_revision,
    )
    if report_identity != secret_report_identity:
        raise SourceScanError(
            "The vulnerability and all-severity secret reports do not share one exact artifact identity."
        )
    if (
        trusted_repository_identity is not None
        and report_identity != trusted_repository_identity
    ):
        raise SourceScanError(
            "The Trivy repository report identity does not match the detached checkout."
        )
    canary_count, _canary_identity = validate_secret_report(
        canary_report,
        canary=True,
        expected_artifact_type="filesystem",
    )

    return {
        "schema_version": 1,
        "source_revision": source_revision,
        "scanner": EXPECTED_SCANNER,
        "result": "pass",
        "findings": {
            "vulnerabilities": 0,
            "secrets": 0,
            "reviewed_misconfigurations": len(reviews),
            "unreviewed_misconfigurations": 0,
        },
        "inventory": {"packages": package_count},
        "secret_canaries": {
            "default_skipped_lockfile_medium": 1,
            "examples_path_medium": 1,
            "markdown_medium": 1,
            "tests_path_medium": 1,
            "total": canary_count,
            "vendor_path_medium": 1,
        },
        "reviews": reviews,
    }


def _git_output(
    repository_root: Path,
    arguments: list[str],
    *,
    label: str,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> tuple[int, str]:
    git_environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", os.defpath),
    }
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(repository_root),
                *arguments,
            ],
            env=git_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SourceScanError(f"Could not read the checked-out Git {label}.") from error
    if (
        completed.returncode not in allowed_returncodes
        or len(completed.stdout) > MAX_GIT_OUTPUT_BYTES
    ):
        raise SourceScanError(f"Could not read the checked-out Git {label}.")
    try:
        output = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SourceScanError(f"The checked-out Git {label} is not UTF-8.") from error
    return completed.returncode, output


def _git_head(repository_root: Path) -> str:
    _returncode, output = _git_output(
        repository_root,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        label="revision",
    )
    revision = output.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SourceScanError("Could not resolve the checked-out Git revision.")
    return revision


def _sanitized_trivy_remote_url(value: str) -> str:
    if (
        not value
        or len(value) > 2048
        or not value.isascii()
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
    ):
        raise SourceScanError("The checked-out Git remote URL is malformed.")
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise SourceScanError("The checked-out Git remote URL is malformed.") from error
    if parsed.scheme != "https" or not parsed.netloc:
        raise SourceScanError("The checked-out Git remote must use HTTPS.")
    # Trivy 0.74 removes URL userinfo before it records RepoURL and calculates
    # the repository ArtifactID. Derive that value from Git, not from the report.
    sanitized = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc.rsplit("@", 1)[-1],
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )
    return _validated_repository_url(sanitized)


def _trusted_repository_identity_for_checkout(
    repository_root: Path, source_revision: str
) -> dict[str, Any] | None:
    git_marker = repository_root / ".git"
    try:
        marker_metadata = git_marker.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SourceScanError("Could not inspect the checkout Git marker.") from error
    if git_marker.is_symlink():
        raise SourceScanError("The checkout Git marker must not be a symbolic link.")
    if stat.S_ISREG(marker_metadata.st_mode):
        # go-git, used by pinned Trivy 0.74, does not resolve linked-worktree
        # .git files during a filesystem scan and therefore emits filesystem form.
        return None
    if not stat.S_ISDIR(marker_metadata.st_mode):
        raise SourceScanError("The checkout Git marker has an unsupported type.")

    symbolic_status, symbolic_output = _git_output(
        repository_root,
        ["symbolic-ref", "-q", "HEAD"],
        label="HEAD state",
        allowed_returncodes=(0, 1),
    )
    if symbolic_status != 1 or symbolic_output:
        raise SourceScanError("The source-scan checkout must have a detached HEAD.")

    remote_url: str | None = None
    for remote in ("upstream", "origin"):
        status, output = _git_output(
            repository_root,
            ["config", "--local", "--no-includes", "--get-all", f"remote.{remote}.url"],
            label="remote URL",
            allowed_returncodes=(0, 1),
        )
        if status == 1:
            continue
        urls = output.splitlines()
        if len(urls) != 1:
            raise SourceScanError("The checked-out Git remote URL is ambiguous.")
        remote_url = _sanitized_trivy_remote_url(urls[0])
        break
    if remote_url is None:
        raise SourceScanError("The detached source-scan checkout has no trusted Git remote.")

    _status, author_output = _git_output(
        repository_root,
        ["show", "-s", "--format=%an <%ae>", source_revision],
        label="author identity",
    )
    _status, committer_output = _git_output(
        repository_root,
        ["show", "-s", "--format=%cn <%ce>", source_revision],
        label="committer identity",
    )
    _status, message_output = _git_output(
        repository_root,
        ["show", "-s", "--format=%B", source_revision],
        label="commit message",
    )
    metadata = {
        "Author": _validated_signature(author_output.strip(), label="author"),
        "Commit": source_revision,
        "CommitMsg": _validated_commit_message(message_output.strip()),
        "Committer": _validated_signature(committer_output.strip(), label="committer"),
        "RepoURL": remote_url,
    }
    return {
        "artifact_id": _repository_artifact_id(remote_url, source_revision),
        "artifact_name": ".",
        "artifact_type": "repository",
        "metadata": metadata,
    }


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    parent = path.parent
    try:
        metadata = parent.lstat()
    except OSError as error:
        raise SourceScanError("The evidence directory does not exist.") from error
    if parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise SourceScanError("The evidence directory must be a real directory.")
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise SourceScanError("Refusing to replace an existing evidence output.") from error
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise SourceScanError("Could not complete the private evidence write.")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--secret-report", type=Path, required=True)
    parser.add_argument("--canary-report", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--summary", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        policy, policy_bytes = load_json(
            arguments.policy, maximum_bytes=MAX_POLICY_BYTES, label="source-scan policy"
        )
        report, report_bytes = load_json(
            arguments.report, maximum_bytes=MAX_REPORT_BYTES, label="private Trivy report"
        )
        secret_report, secret_report_bytes = load_json(
            arguments.secret_report,
            maximum_bytes=MAX_REPORT_BYTES,
            label="private all-severity Trivy secret report",
        )
        canary_report, _canary_report_bytes = load_json(
            arguments.canary_report,
            maximum_bytes=MAX_REPORT_BYTES,
            label="private Trivy secret canary report",
        )
        repository_root = arguments.repository_root.resolve(strict=True)
        if _git_head(repository_root) != arguments.source_revision:
            raise SourceScanError("The report source revision is not the checked-out final SHA.")
        summary = validate_report(
            report,
            secret_report,
            canary_report,
            policy,
            repository_root,
            arguments.source_revision,
        )
        summary["policy_sha256"] = _sha256(policy_bytes)
        summary["private_report_sha256"] = {
            "all_severity_secrets": _sha256(secret_report_bytes),
            "high_critical_vulnerability_misconfiguration": _sha256(report_bytes),
        }
        _write_private_json(arguments.summary, summary)
    except (OSError, SourceScanError) as error:
        print(f"source scan validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Source security validation passed: 0 HIGH/CRITICAL vulnerabilities, "
        "0 all-severity secrets, 2 content-pinned reviewed misconfigurations, "
        "and 5 private secret canaries."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
