#!/usr/bin/env python3
"""Materialize the reviewed legacy-RabbitMQ VEX for one exact image digest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from build_release_manifest import _write_json
from verify_release import (
    MAX_CONTROL_FILE_BYTES,
    MAX_EVIDENCE_FILE_BYTES,
    ReleaseVerificationError,
    _digest,
    _exact_keys,
    _load_json,
    _mapping,
    _string,
    _timestamp,
)


COMPONENT_PURL = "pkg:generic/erlang@26.2.5.21"
PRODUCT_NAME = "backupsheep-rabbitmq-legacy-source"
EXPECTED_VULNERABILITIES = {
    "CVE-2026-42792",
    "CVE-2026-49759",
    "CVE-2026-55737",
    "CVE-2026-55952",
    "CVE-2026-55953",
    "CVE-2026-58227",
    "CVE-2026-59250",
    "CVE-2026-59251",
}


def product_purl(manifest_digest: str) -> str:
    return f"pkg:oci/{PRODUCT_NAME}?tag={product_tag(manifest_digest)}"


def product_tag(manifest_digest: str) -> str:
    digest = _digest(manifest_digest, "legacy image manifest digest")
    return f"manifest-{digest.removeprefix('sha256:')}"


def product_reference(manifest_digest: str) -> str:
    return f"{PRODUCT_NAME}:{product_tag(manifest_digest)}"


def validate_policy(value: Any) -> dict[str, Any]:
    policy = _mapping(value, "legacy RabbitMQ VEX policy")
    _exact_keys(
        policy,
        {"schema_version", "id_prefix", "author", "timestamp", "version", "statements"},
        "legacy RabbitMQ VEX policy",
    )
    if policy["schema_version"] != 1 or policy["version"] != 1:
        raise ReleaseVerificationError("unsupported legacy RabbitMQ VEX policy schema")
    id_prefix = _string(policy["id_prefix"], "legacy RabbitMQ VEX policy.id_prefix")
    if id_prefix != "https://backupsheep.com/security/openvex/legacy-rabbitmq-otp26":
        raise ReleaseVerificationError("legacy RabbitMQ VEX policy has the wrong identifier")
    _string(policy["author"], "legacy RabbitMQ VEX policy.author")
    _timestamp(policy["timestamp"], "legacy RabbitMQ VEX policy.timestamp")
    statements = policy["statements"]
    if not isinstance(statements, list) or len(statements) != len(EXPECTED_VULNERABILITIES):
        raise ReleaseVerificationError("legacy RabbitMQ VEX policy has the wrong statement count")
    observed: set[str] = set()
    for position, raw_statement in enumerate(statements):
        label = f"legacy RabbitMQ VEX policy.statements[{position}]"
        statement = _mapping(raw_statement, label)
        _exact_keys(
            statement,
            {"vulnerability", "component", "status", "justification", "impact_statement"},
            label,
        )
        vulnerability = _mapping(statement["vulnerability"], f"{label}.vulnerability")
        _exact_keys(vulnerability, {"name"}, f"{label}.vulnerability")
        vulnerability_id = _string(vulnerability["name"], f"{label}.vulnerability.name")
        if vulnerability_id not in EXPECTED_VULNERABILITIES or vulnerability_id in observed:
            raise ReleaseVerificationError("legacy RabbitMQ VEX policy has an unauthorized CVE")
        observed.add(vulnerability_id)
        if statement["component"] != COMPONENT_PURL:
            raise ReleaseVerificationError("legacy RabbitMQ VEX policy has the wrong component")
        if statement["status"] != "not_affected":
            raise ReleaseVerificationError("legacy RabbitMQ VEX policy has a filtering status change")
        if statement["justification"] != "vulnerable_code_cannot_be_controlled_by_adversary":
            raise ReleaseVerificationError("legacy RabbitMQ VEX policy has an unauthorized justification")
        _string(statement["impact_statement"], f"{label}.impact_statement")
    if observed != EXPECTED_VULNERABILITIES:
        raise ReleaseVerificationError("legacy RabbitMQ VEX policy is incomplete")
    return policy


def materialize(policy_value: Any, manifest_digest: str) -> dict[str, Any]:
    policy = validate_policy(policy_value)
    product = product_purl(manifest_digest)
    manifest_sha256 = _digest(
        manifest_digest, "legacy image manifest digest"
    ).removeprefix("sha256:")
    statements = []
    for source in policy["statements"]:
        statements.append(
            {
                "vulnerability": source["vulnerability"],
                "products": [
                    {
                        "@id": product,
                        "hashes": {"sha-256": manifest_sha256},
                        "subcomponents": [{"@id": COMPONENT_PURL}],
                    }
                ],
                "status": source["status"],
                "justification": source["justification"],
                "impact_statement": source["impact_statement"],
            }
        )
    document = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"{policy['id_prefix']}/{manifest_digest.removeprefix('sha256:')}",
        "author": policy["author"],
        "timestamp": policy["timestamp"],
        "version": policy["version"],
        "statements": statements,
    }
    validate_materialized(document, policy, manifest_digest)
    return document


def validate_materialized(
    value: Any, policy_value: Any, manifest_digest: str
) -> dict[str, Any]:
    policy = validate_policy(policy_value)
    document = _mapping(value, "materialized legacy RabbitMQ VEX")
    _exact_keys(
        document,
        {"@context", "@id", "author", "timestamp", "version", "statements"},
        "materialized legacy RabbitMQ VEX",
    )
    expected = materialize_without_validation(policy, manifest_digest)
    if document != expected:
        raise ReleaseVerificationError(
            "materialized legacy RabbitMQ VEX is not bound to the exact image and component"
        )
    return document


def materialize_without_validation(
    policy: dict[str, Any], manifest_digest: str
) -> dict[str, Any]:
    product = product_purl(manifest_digest)
    manifest_sha256 = _digest(
        manifest_digest, "legacy image manifest digest"
    ).removeprefix("sha256:")
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"{policy['id_prefix']}/{manifest_digest.removeprefix('sha256:')}",
        "author": policy["author"],
        "timestamp": policy["timestamp"],
        "version": policy["version"],
        "statements": [
            {
                "vulnerability": source["vulnerability"],
                "products": [
                    {
                        "@id": product,
                        "hashes": {"sha-256": manifest_sha256},
                        "subcomponents": [{"@id": COMPONENT_PURL}],
                    }
                ],
                "status": source["status"],
                "justification": source["justification"],
                "impact_statement": source["impact_statement"],
            }
            for source in policy["statements"]
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--grype-report", type=Path, required=True)
    parser.add_argument("--expected-image-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.output.exists() or arguments.output.is_symlink():
            raise ReleaseVerificationError("materialized VEX output must not pre-exist")
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        report = _mapping(
            _load_json(arguments.grype_report, maximum_bytes=MAX_EVIDENCE_FILE_BYTES),
            "baseline Grype report",
        )
        target = _mapping(
            _mapping(report.get("source"), "baseline Grype source").get("target"),
            "baseline Grype target",
        )
        expected_image_id = _digest(arguments.expected_image_id, "expected legacy image ID")
        if target.get("imageID") != expected_image_id:
            raise ReleaseVerificationError("baseline Grype report used the wrong legacy image")
        manifest_digest = _digest(
            target.get("manifestDigest"), "baseline Grype manifest digest"
        )
        document = materialize(policy, manifest_digest)
        _write_json(arguments.output, document)
        print(product_reference(manifest_digest))
        return 0
    except (OSError, KeyError, ValueError, json.JSONDecodeError, ReleaseVerificationError) as exc:
        print(f"legacy RabbitMQ VEX materialization failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
