#!/usr/bin/env python3
"""Build and validate the signed-release transition record.

The V2 descriptor signs the release-manifest digest.  Manifest schema 4 uses this
module to bind an exact target migration graph and a bounded set of exact source
releases which may transition to that target.  No SemVer range or mutable tag is
accepted by this contract.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


TRANSITION_POLICY_SCHEMA = 1
TRANSITION_RECORD_SCHEMA = 1
MIGRATION_CONTRACT_SCHEMA = 1
MAX_PREDECESSORS = 8
MAX_MIGRATIONS = 4096
MAX_JSON_BYTES = 1024 * 1024
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MIGRATION_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}\.[0-9][A-Za-z0-9_]{0,127}$")
VERIFIER_REFERENCE_RE = re.compile(r"^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$")


class TransitionContractError(ValueError):
    """A reviewed or generated transition contract is not canonical."""


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TransitionContractError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise TransitionContractError(f"{label} must be an array")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unknown = sorted(set(value) - expected)
        raise TransitionContractError(
            f"{label} has invalid keys (missing={missing}, unknown={unknown})"
        )


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2_147_483_647:
        raise TransitionContractError(f"{label} must be a positive bounded integer")
    return value


def _string(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise TransitionContractError(f"{label} is malformed")
    return value


def sha256_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def sha256_path(path: Path) -> str:
    file_stat = path.stat()
    if file_stat.st_size <= 0 or file_stat.st_size > MAX_JSON_BYTES:
        raise TransitionContractError(f"{path.name} has an invalid size")
    payload = path.read_bytes()
    if len(payload) != file_stat.st_size:
        raise TransitionContractError(f"{path.name} has an invalid size")
    return sha256_bytes(payload)


def migration_digest(names: list[str], *, leaves: bool = False) -> str:
    domain = (
        "BACKUPSHEEP-DJANGO-MIGRATION-LEAVES-V1"
        if leaves
        else "BACKUPSHEEP-DJANGO-MIGRATION-SET-V1"
    )
    return sha256_bytes((domain + "\n" + "\n".join(names) + "\n").encode("ascii"))


def _migration_names(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    names = _list(value, label)
    if len(names) > MAX_MIGRATIONS or (not names and not allow_empty):
        raise TransitionContractError(f"{label} has an invalid count")
    normalized = [_string(item, f"{label}[]", MIGRATION_RE) for item in names]
    if normalized != sorted(normalized) or len(normalized) != len(set(normalized)):
        raise TransitionContractError(f"{label} must be unique and bytewise sorted")
    return normalized


def validate_migration_contract(value: Any) -> dict[str, Any]:
    contract = _mapping(value, "migration contract")
    _exact_keys(
        contract,
        {
            "schema_version",
            "all_migrations_atomic",
            "migrations",
            "migration_set_sha256",
            "leaves",
            "leaf_set_sha256",
        },
        "migration contract",
    )
    if contract["schema_version"] != MIGRATION_CONTRACT_SCHEMA:
        raise TransitionContractError("unsupported migration-contract schema")
    if contract["all_migrations_atomic"] is not True:
        raise TransitionContractError("every signed migration must be transactional")
    migrations = _migration_names(contract["migrations"], "migration contract migrations")
    leaves = _migration_names(contract["leaves"], "migration contract leaves")
    if not set(leaves).issubset(migrations):
        raise TransitionContractError("migration leaves are not in the complete set")
    if contract["migration_set_sha256"] != migration_digest(migrations):
        raise TransitionContractError("migration complete-set digest mismatch")
    if contract["leaf_set_sha256"] != migration_digest(leaves, leaves=True):
        raise TransitionContractError("migration leaf-set digest mismatch")
    return {
        "schema_version": MIGRATION_CONTRACT_SCHEMA,
        "all_migrations_atomic": True,
        "migrations": migrations,
        "migration_set_sha256": contract["migration_set_sha256"],
        "leaves": leaves,
        "leaf_set_sha256": contract["leaf_set_sha256"],
    }


def _validate_verifier(value: Any, label: str) -> dict[str, Any]:
    verifier = _mapping(value, label)
    expected = {
        "reference",
        "runtime_contract_version",
        "linux_amd64_manifest",
        "linux_amd64_config",
        "linux_arm64_manifest",
        "linux_arm64_config",
        "trusted_root_sha256",
    }
    _exact_keys(verifier, expected, label)
    reference = _string(verifier["reference"], f"{label}.reference", VERIFIER_REFERENCE_RE)
    runtime_contract_version = _positive_integer(
        verifier["runtime_contract_version"], f"{label}.runtime_contract_version"
    )
    if runtime_contract_version != 1:
        raise TransitionContractError(f"{label}.runtime_contract_version is not supported")
    normalized = {
        "reference": reference,
        "runtime_contract_version": runtime_contract_version,
    }
    for key in (
        "linux_amd64_manifest",
        "linux_amd64_config",
        "linux_arm64_manifest",
        "linux_arm64_config",
        "trusted_root_sha256",
    ):
        normalized[key] = _string(verifier[key], f"{label}.{key}", DIGEST_RE)
    digests = [reference.rsplit("@", 1)[1]] + [
        normalized[key]
        for key in normalized
        if key not in {"reference", "runtime_contract_version"}
    ]
    if len(digests) != len(set(digests)):
        raise TransitionContractError(f"{label} contains colliding trust digests")
    return normalized


def _validate_predecessor(value: Any, target_epoch: int, position: int) -> dict[str, Any]:
    label = f"transition policy predecessor[{position}]"
    predecessor = _mapping(value, label)
    _exact_keys(
        predecessor,
        {
            "release_tag",
            "release_epoch",
            "source_commit",
            "release_manifest_sha256",
            "descriptor_sha256",
            "descriptor_bundle_sha256",
            "migration_set_sha256",
            "migration_leaf_set_sha256",
            "verifier",
        },
        label,
    )
    source_epoch = _positive_integer(predecessor["release_epoch"], f"{label}.release_epoch")
    if source_epoch >= target_epoch:
        raise TransitionContractError("every predecessor epoch must be lower than the target")
    return {
        "release_tag": _string(predecessor["release_tag"], f"{label}.release_tag", TAG_RE),
        "release_epoch": source_epoch,
        "source_commit": _string(predecessor["source_commit"], f"{label}.source_commit", COMMIT_RE),
        "release_manifest_sha256": _string(
            predecessor["release_manifest_sha256"], f"{label}.release_manifest_sha256", DIGEST_RE
        ),
        "descriptor_sha256": _string(
            predecessor["descriptor_sha256"], f"{label}.descriptor_sha256", DIGEST_RE
        ),
        "descriptor_bundle_sha256": _string(
            predecessor["descriptor_bundle_sha256"], f"{label}.descriptor_bundle_sha256", DIGEST_RE
        ),
        "migration_set_sha256": _string(
            predecessor["migration_set_sha256"], f"{label}.migration_set_sha256", DIGEST_RE
        ),
        "migration_leaf_set_sha256": _string(
            predecessor["migration_leaf_set_sha256"],
            f"{label}.migration_leaf_set_sha256",
            DIGEST_RE,
        ),
        "verifier": _validate_verifier(predecessor["verifier"], f"{label}.verifier"),
    }


def validate_transition_policy(value: Any) -> dict[str, Any]:
    policy = _mapping(value, "transition policy")
    _exact_keys(policy, {"schema_version", "release_epoch", "accepted_predecessors"}, "transition policy")
    if policy["schema_version"] != TRANSITION_POLICY_SCHEMA:
        raise TransitionContractError("unsupported transition-policy schema")
    epoch = _positive_integer(policy["release_epoch"], "transition policy release_epoch")
    raw_predecessors = _list(policy["accepted_predecessors"], "transition policy accepted_predecessors")
    if len(raw_predecessors) > MAX_PREDECESSORS:
        raise TransitionContractError("transition policy has too many predecessors")
    predecessors = [
        _validate_predecessor(item, epoch, position)
        for position, item in enumerate(raw_predecessors)
    ]
    ordering = [
        (item["release_epoch"], item["release_tag"], item["source_commit"])
        for item in predecessors
    ]
    if ordering != sorted(ordering) or len(ordering) != len(set(ordering)):
        raise TransitionContractError("predecessors must be unique and canonically ordered")
    descriptor_digests = [item["descriptor_sha256"] for item in predecessors]
    if len(descriptor_digests) != len(set(descriptor_digests)):
        raise TransitionContractError("predecessor descriptor digests collide")
    return {
        "schema_version": TRANSITION_POLICY_SCHEMA,
        "release_epoch": epoch,
        "accepted_predecessors": predecessors,
    }


def build_transition_record(
    *,
    reviewed_policy: Any,
    migration_contract: Any,
    reviewed_policy_file: str,
    reviewed_policy_sha256: str,
    migration_contract_file: str,
    migration_contract_sha256: str,
) -> dict[str, Any]:
    policy = validate_transition_policy(reviewed_policy)
    migrations = validate_migration_contract(migration_contract)
    for label, value in (
        ("reviewed transition policy digest", reviewed_policy_sha256),
        ("migration contract artifact digest", migration_contract_sha256),
    ):
        _string(value, label, DIGEST_RE)
    if reviewed_policy_file != "transition/reviewed-policy.json":
        raise TransitionContractError("reviewed transition policy artifact path is not canonical")
    if migration_contract_file != "transition/django-migrations.json":
        raise TransitionContractError("migration contract artifact path is not canonical")
    return {
        "schema_version": TRANSITION_RECORD_SCHEMA,
        "release_epoch": policy["release_epoch"],
        "reviewed_policy": {
            "file": reviewed_policy_file,
            "sha256": reviewed_policy_sha256,
        },
        "migration_contract": {
            "file": migration_contract_file,
            "sha256": migration_contract_sha256,
            **migrations,
        },
        "accepted_predecessors": policy["accepted_predecessors"],
    }


def validate_transition_record(
    value: Any,
    *,
    reviewed_policy: Any,
    migration_contract: Any,
    reviewed_policy_sha256: str,
    migration_contract_sha256: str,
) -> dict[str, Any]:
    expected = build_transition_record(
        reviewed_policy=reviewed_policy,
        migration_contract=migration_contract,
        reviewed_policy_file="transition/reviewed-policy.json",
        reviewed_policy_sha256=reviewed_policy_sha256,
        migration_contract_file="transition/django-migrations.json",
        migration_contract_sha256=migration_contract_sha256,
    )
    if value != expected:
        raise TransitionContractError("manifest transition record is not canonical")
    return expected


def load_json(path: Path) -> Any:
    file_stat = path.stat()
    if file_stat.st_size <= 0 or file_stat.st_size > MAX_JSON_BYTES:
        raise TransitionContractError(f"{path.name} has an invalid size")
    payload = path.read_bytes()
    if len(payload) != file_stat.st_size:
        raise TransitionContractError(f"{path.name} has an invalid size")
    try:
        return json.loads(
            payload,
            object_pairs_hook=lambda pairs: _reject_duplicates(pairs, path.name),
            parse_constant=lambda value: (_ for _ in ()).throw(
                TransitionContractError(f"{path.name} contains non-finite number {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransitionContractError(f"{path.name} is not strict JSON") from exc


def _reject_duplicates(pairs: list[tuple[str, Any]], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TransitionContractError(f"{label} contains duplicate key {key}")
        result[key] = value
    return result


__all__ = [
    "TransitionContractError",
    "build_transition_record",
    "load_json",
    "migration_digest",
    "sha256_path",
    "validate_migration_contract",
    "validate_transition_policy",
    "validate_transition_record",
]
