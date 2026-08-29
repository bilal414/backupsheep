#!/usr/bin/env python3
"""Validate and durably journal one authorized signed-release transition.

This module is intentionally application- and database-free.  The installer
executes it from an already authenticated application image in a networkless,
read-only container.  It never decides whether a Docker or database operation
succeeded; it only accepts exact installer-produced evidence and commits a
strict, hash-chained phase record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import release_transition


SCHEMA_VERSION = 1
WITNESS_SCHEMA_VERSION = 2
MAX_CONTROL_BYTES = 1024 * 1024
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_COMPLETED_OPERATIONS = 64
JOURNAL_ROOT_NAME = ".release-transition-journal"
OPERATIONS_NAME = "operations"
INTENT_NAME = "intent.json"
ROLLBACK_ENV_NAME = "pre-upgrade.env"
SOURCE_EVIDENCE_NAME = "source-evidence"
TARGET_EVIDENCE_NAME = "target-evidence"
SOURCE_VERIFICATION_NAME = "source-verification.json"
TARGET_ENV_NAME = "target.env"
PHASES = (
    "10-prepared",
    "20-stopped",
    "30-switched",
    "40-forward-only",
    "50-migrated",
    "60-core-accepted",
    "70-activated",
)
RECEIPT_NAMES = tuple(f"{phase}.json" for phase in PHASES)
ROLLBACK_RECEIPT_NAME = "rollback.json"
IMAGE_ROLES = ("app", "postgres", "egress", "rabbitmq", "rabbitmq-upgrade")
VOLUME_ROLES = (
    "backup_storage",
    "backup_workdir",
    "database_ciphertext_transfer",
    "database_workdir",
    "files_ciphertext_transfer",
    "files_workdir",
    "installation_identity",
    "postgres_data_v1",
    "rabbitmq_data",
    "restore_ciphertext_transfer",
    "staging_layout_witness",
    "storage_workdir",
)
CORE_SERVICES = ("db", "rabbitmq", "app-egress-guard", "app")
OPERATION_SERVICES = (
    "cloud-egress-guard",
    "worker-cloud",
    "database-egress-guard",
    "worker-database",
    "files-egress-guard",
    "worker-files",
    "storage-egress-guard",
    "worker-storage",
    "logs-egress-guard",
    "worker-logs",
    "beat",
)
ONE_SHOT_SERVICES = (
    "rabbitmq-volume-init",
    "rabbitmq-provision",
    "staging-provision",
    "db-provision",
    "migrate",
    "db-seal",
    "preflight",
)
ALL_SERVICES = CORE_SERVICES + OPERATION_SERVICES + ONE_SHOT_SERVICES
WRITER_SERVICES = ("app", "beat") + tuple(
    service for service in OPERATION_SERVICES if service.startswith("worker-")
)
IMAGE_REPOSITORIES = {
    "app": "ghcr.io/bilal414/backupsheep",
    "postgres": "ghcr.io/bilal414/backupsheep-postgres",
    "egress": "ghcr.io/bilal414/backupsheep-egress",
    "rabbitmq": "ghcr.io/bilal414/backupsheep-rabbitmq",
    "rabbitmq-upgrade": "ghcr.io/bilal414/backupsheep-rabbitmq-upgrade",
}
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
VOLUME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
PLATFORMS = ("linux/amd64", "linux/arm64")
EVIDENCE_FILES = (
    "backupsheep-release-descriptor-v2.txt",
    "backupsheep-release-descriptor-v2.sigstore.json",
    "release-manifest.json",
    "sigstore-trusted-root.json",
    "signature-verification.json",
    "local-images.txt",
)


class UpgradeJournalError(ValueError):
    """The signed transition or its durable journal is not canonical."""


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise UpgradeJournalError(
            f"{label} has invalid keys (missing={sorted(expected - set(value))}, "
            f"unknown={sorted(set(value) - expected)})"
        )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UpgradeJournalError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise UpgradeJournalError(f"{label} must be an array")
    return value


def _string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise UpgradeJournalError(f"{label} is malformed")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2_147_483_647:
        raise UpgradeJournalError(f"{label} must be a positive bounded integer")
    return value


def _nonnegative_integer(value: Any, label: str, *, maximum: int = 2_147_483_647) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise UpgradeJournalError(f"{label} must be a nonnegative bounded integer")
    return value


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UpgradeJournalError(f"JSON contains duplicate key {key}")
        result[key] = value
    return result


def _sha256_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _domain_digest(domain: str, value: Any) -> str:
    return _sha256_bytes(domain.encode("ascii") + b"\0" + _canonical_bytes(value))


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _read_regular(
    path: Path,
    *,
    maximum: int = MAX_CONTROL_BYTES,
    owner: int | None = None,
    modes: set[int] | None = None,
    links: set[int] | None = None,
    allow_empty: bool = False,
) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        allowed_links = links or {1}
        if not stat.S_ISREG(before.st_mode) or before.st_nlink not in allowed_links:
            raise UpgradeJournalError(f"{path} must be a regular file without hard links")
        if owner is not None and before.st_uid != owner:
            raise UpgradeJournalError(f"{path} has an unexpected owner")
        if modes is not None and stat.S_IMODE(before.st_mode) not in modes:
            raise UpgradeJournalError(f"{path} has unsafe permissions")
        if before.st_size < (0 if allow_empty else 1) or before.st_size > maximum:
            raise UpgradeJournalError(f"{path} has an invalid size")
        payload = bytearray()
        while len(payload) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_gid,
            stat.S_IMODE(before.st_mode),
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_gid,
            stat.S_IMODE(after.st_mode),
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise UpgradeJournalError(f"{path} changed while it was read")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _load_json(
    path: Path,
    *,
    maximum: int = MAX_CONTROL_BYTES,
    owner: int | None = None,
    modes: set[int] | None = None,
) -> Any:
    payload = _read_regular(path, maximum=maximum, owner=owner, modes=modes)
    return _load_json_bytes(payload, str(path))


def _load_json_bytes(payload: bytes, label: str) -> Any:
    try:
        return json.loads(
            payload,
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                UpgradeJournalError(f"JSON contains non-finite number {value}")
            ),
            parse_float=lambda value: (_ for _ in ()).throw(
                UpgradeJournalError(f"JSON contains unsupported float {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpgradeJournalError(f"{label} is not strict JSON") from exc


def _validate_directory(path: Path, *, owner: int, mode: int = 0o700) -> None:
    file_stat = path.lstat()
    if not stat.S_ISDIR(file_stat.st_mode) or path.is_symlink():
        raise UpgradeJournalError(f"{path} must be a real directory")
    if file_stat.st_uid != owner or stat.S_IMODE(file_stat.st_mode) != mode:
        raise UpgradeJournalError(f"{path} has an unsafe owner or mode")


def _validate_ancestor_chain(path: Path, *, owner: int) -> None:
    resolved = path.resolve(strict=True)
    if resolved != path.absolute():
        raise UpgradeJournalError("journal path must already be canonical and contain no symlink")
    current = resolved
    while True:
        file_stat = current.lstat()
        mode = stat.S_IMODE(file_stat.st_mode)
        if not stat.S_ISDIR(file_stat.st_mode) or current.is_symlink():
            raise UpgradeJournalError(f"journal ancestor is not a real directory: {current}")
        if owner == 0:
            if file_stat.st_uid != 0:
                raise UpgradeJournalError(f"root journal ancestor is not root-owned: {current}")
        elif file_stat.st_uid not in {0, owner}:
            raise UpgradeJournalError(f"journal ancestor has an unrelated owner: {current}")
        if mode & 0o022 and not (file_stat.st_uid == 0 and mode & stat.S_ISVTX):
            raise UpgradeJournalError(f"journal ancestor is attacker-writable: {current}")
        if current == Path("/"):
            break
        current = current.parent


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_regular(path: Path, *, owner: int, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != owner
            or stat.S_IMODE(file_stat.st_mode) != mode
            or file_stat.st_nlink not in {1, 2}
        ):
            raise UpgradeJournalError(
                f"interrupted publication for {path.name} has an unsafe inode"
            )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, payload: bytes, *, mode: int) -> None:
    temporary = path.with_name(f".{path.name}.new")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, mode)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise UpgradeJournalError(f"short write while publishing {path.name}")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        _fsync_directory(path.parent)
        os.unlink(temporary)
        _fsync_directory(path.parent)
    except Exception:
        # A linked final plus its exact temporary hard link is recoverable on
        # the next identical append.  Never unlink either name blindly here.
        raise


def _reconcile_exclusive(path: Path, payload: bytes, *, mode: int) -> bool:
    temporary = path.with_name(f".{path.name}.new")
    final_exists = path.exists() or path.is_symlink()
    temporary_exists = temporary.exists() or temporary.is_symlink()
    if not final_exists and not temporary_exists:
        return False
    owner = os.geteuid()
    if temporary_exists:
        temporary_payload = _read_regular(
            temporary,
            owner=owner,
            modes={mode},
            links={1, 2},
            allow_empty=True,
        )
        if temporary_payload != payload:
            temporary_stat = temporary.lstat()
            if temporary_stat.st_nlink == 1 and payload.startswith(temporary_payload):
                os.unlink(temporary)
                _fsync_directory(path.parent)
                temporary_exists = False
                if not final_exists:
                    return False
            else:
                raise UpgradeJournalError(f"interrupted publication for {path.name} differs")
    if final_exists:
        final_payload = _read_regular(path, owner=owner, modes={mode}, links={1, 2})
        if final_payload != payload:
            raise UpgradeJournalError(f"existing {path.name} differs")
    if not final_exists:
        # Reading an exact orphan proves its bytes, not their durability. Sync
        # that same inode before linking it into the durable journal namespace.
        _fsync_regular(temporary, owner=owner, mode=mode)
        os.link(temporary, path, follow_symlinks=False)
        _fsync_directory(path.parent)
    if temporary_exists:
        final_stat = path.stat()
        temporary_stat = temporary.stat()
        if (final_stat.st_dev, final_stat.st_ino) != (temporary_stat.st_dev, temporary_stat.st_ino):
            raise UpgradeJournalError(f"interrupted publication for {path.name} is ambiguous")
        os.unlink(temporary)
        _fsync_directory(path.parent)
    _read_regular(path, owner=owner, modes={mode})
    return True


def _descriptor_bytes(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise UpgradeJournalError("release descriptor is not ASCII") from exc
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise UpgradeJournalError("release descriptor is not canonical")
    lines = text[:-1].split("\n")
    keys = (
        "release_tag",
        "source_commit",
        "release_manifest_sha256",
        "app_image",
        "postgres_image",
        "egress_image",
        "rabbitmq_image",
        "rabbitmq_upgrade_image",
        "release_verifier_image",
        "release_verifier_runtime_contract_version",
        "release_verifier_linux_amd64_manifest",
        "release_verifier_linux_amd64_config",
        "release_verifier_linux_arm64_manifest",
        "release_verifier_linux_arm64_config",
        "trusted_root_sha256",
    )
    if len(lines) != 16 or lines[0] != "BACKUPSHEEP-SIGNED-RELEASE-V2":
        raise UpgradeJournalError("release descriptor is not exact V2")
    result: dict[str, str] = {}
    for line, key in zip(lines[1:], keys, strict=True):
        prefix = f"{key}="
        if not line.startswith(prefix) or len(line) == len(prefix):
            raise UpgradeJournalError(f"release descriptor field {key} is malformed")
        result[key] = line[len(prefix) :]
    _string(result["release_tag"], TAG_RE, "descriptor release tag")
    _string(result["source_commit"], COMMIT_RE, "descriptor source commit")
    for key in (
        "release_manifest_sha256",
        "release_verifier_linux_amd64_manifest",
        "release_verifier_linux_amd64_config",
        "release_verifier_linux_arm64_manifest",
        "release_verifier_linux_arm64_config",
        "trusted_root_sha256",
    ):
        _string(result[key], DIGEST_RE, f"descriptor {key}")
    if result["release_verifier_runtime_contract_version"] != "1":
        raise UpgradeJournalError("descriptor verifier runtime contract is unsupported")
    return result


def _descriptor(path: Path, *, modes: set[int] | None = None) -> dict[str, str]:
    return _descriptor_bytes(
        _read_regular(path, owner=os.geteuid(), modes=modes or {0o600})
    )


def _receipt_bytes(payload: bytes) -> dict[str, str]:
    if not payload.endswith(b"\n") or b"\r" in payload or b"\x00" in payload:
        raise UpgradeJournalError("local image receipt is not canonical")
    expected = (
        "app_image_id",
        "postgres_image_id",
        "egress_image_id",
        "rabbitmq_image_id",
        "rabbitmq_upgrade_image_id",
        "cosign_image_id",
    )
    lines = payload.decode("ascii").rstrip("\n").split("\n")
    if len(lines) != len(expected):
        raise UpgradeJournalError("local image receipt has an invalid line count")
    result: dict[str, str] = {}
    for line, key in zip(lines, expected, strict=True):
        prefix = f"{key}="
        if not line.startswith(prefix):
            raise UpgradeJournalError("local image receipt is reordered")
        result[key] = _string(line[len(prefix) :], DIGEST_RE, key)
    return result


def _receipt(path: Path, *, modes: set[int] | None = None) -> dict[str, str]:
    return _receipt_bytes(
        _read_regular(path, owner=os.geteuid(), modes=modes or {0o600})
    )


def _verifier_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    consumer = _mapping(manifest["consumer"], "manifest.consumer")
    verifier = _mapping(consumer.get("cosign_image"), "manifest.consumer.cosign_image")
    expected = {
        "version",
        "runtime_contract_version",
        "repository",
        "index_digest",
        "reference",
        "platforms",
    }
    _exact_keys(verifier, expected, "manifest.consumer.cosign_image")
    if verifier["runtime_contract_version"] != 1:
        raise UpgradeJournalError("manifest verifier runtime contract is unsupported")
    reference = _string(
        verifier["reference"], release_transition.VERIFIER_REFERENCE_RE, "manifest verifier reference"
    )
    index_digest = _string(verifier["index_digest"], DIGEST_RE, "manifest verifier index")
    if reference.rsplit("@", 1)[1] != index_digest:
        raise UpgradeJournalError("manifest verifier reference does not match its index")
    platform_values = _list(verifier["platforms"], "manifest verifier platforms")
    if len(platform_values) != len(PLATFORMS):
        raise UpgradeJournalError("manifest verifier platform set is incomplete")
    platforms: dict[str, dict[str, str]] = {}
    for index, platform in enumerate(platform_values):
        platform = _mapping(platform, "manifest verifier platform")
        required = {
            "platform",
            "manifest_digest",
            "config_digest",
            "source_catalog",
            "vulnerability_report",
        }
        _exact_keys(platform, required, "manifest verifier platform")
        if platform["platform"] != PLATFORMS[index]:
            raise UpgradeJournalError("manifest verifier platforms are reordered")
        platforms[PLATFORMS[index]] = {
            "manifest_digest": _string(
                platform["manifest_digest"], DIGEST_RE, "verifier platform manifest"
            ),
            "config_digest": _string(
                platform["config_digest"], DIGEST_RE, "verifier platform config"
            ),
        }
    return {
        "reference": reference,
        "runtime_contract_version": 1,
        "linux_amd64_manifest": platforms["linux/amd64"]["manifest_digest"],
        "linux_amd64_config": platforms["linux/amd64"]["config_digest"],
        "linux_arm64_manifest": platforms["linux/arm64"]["manifest_digest"],
        "linux_arm64_config": platforms["linux/arm64"]["config_digest"],
        "trusted_root_sha256": "",
    }


def build_release_state(
    evidence: Path, platform: str, *, file_modes: set[int] | None = None
) -> dict[str, Any]:
    evidence_modes = file_modes or {0o600}
    if platform not in PLATFORMS:
        raise UpgradeJournalError("release platform is unsupported")
    _validate_directory(evidence, owner=os.geteuid())
    expected_names = set(EVIDENCE_FILES)
    actual_names = {entry.name for entry in evidence.iterdir()}
    if actual_names != expected_names:
        raise UpgradeJournalError("release evidence has an invalid exact file set")
    descriptor_path = evidence / "backupsheep-release-descriptor-v2.txt"
    bundle_path = evidence / "backupsheep-release-descriptor-v2.sigstore.json"
    manifest_path = evidence / "release-manifest.json"
    root_path = evidence / "sigstore-trusted-root.json"
    verification_path = evidence / "signature-verification.json"
    receipt_path = evidence / "local-images.txt"
    descriptor_bytes = _read_regular(
        descriptor_path, owner=os.geteuid(), modes=evidence_modes
    )
    descriptor = _descriptor_bytes(descriptor_bytes)
    bundle = _read_regular(bundle_path, owner=os.geteuid(), modes=evidence_modes)
    root = _read_regular(root_path, maximum=65536, owner=os.geteuid(), modes=evidence_modes)
    manifest_bytes = _read_regular(manifest_path, owner=os.geteuid(), modes=evidence_modes)
    receipt_bytes = _read_regular(
        receipt_path, owner=os.geteuid(), modes=evidence_modes
    )
    manifest = _load_json_bytes(manifest_bytes, "release manifest")
    receipt = _receipt_bytes(receipt_bytes)
    manifest = _mapping(manifest, "release manifest")
    _exact_keys(
        manifest,
        {"schema_version", "release", "vulnerability_database", "consumer", "transition", "images"},
        "release manifest",
    )
    if manifest["schema_version"] != 4:
        raise UpgradeJournalError("release manifest is not schema 4")
    if descriptor["release_manifest_sha256"] != _sha256_bytes(manifest_bytes):
        raise UpgradeJournalError("descriptor does not bind the release manifest")
    if descriptor["trusted_root_sha256"] != _sha256_bytes(root):
        raise UpgradeJournalError("descriptor does not bind the retained trusted root")
    transition = release_transition.validate_embedded_transition_record(manifest["transition"])
    release = _mapping(manifest["release"], "manifest.release")
    for key, expected in (
        ("tag", descriptor["release_tag"]),
        ("source_commit", descriptor["source_commit"]),
    ):
        if release.get(key) != expected:
            raise UpgradeJournalError(f"manifest release {key} differs from descriptor")
    workflow_identity = release.get("workflow_identity")
    expected_identity = (
        "https://github.com/bilal414/backupsheep/.github/workflows/"
        f"release-images.yml@refs/tags/{descriptor['release_tag']}"
    )
    if workflow_identity != expected_identity:
        raise UpgradeJournalError("manifest workflow identity is not the exact release workflow")

    verifier = _verifier_from_manifest(manifest)
    verifier["trusted_root_sha256"] = _sha256_bytes(root)
    descriptor_verifier = {
        "reference": descriptor["release_verifier_image"],
        "runtime_contract_version": int(descriptor["release_verifier_runtime_contract_version"]),
        "linux_amd64_manifest": descriptor["release_verifier_linux_amd64_manifest"],
        "linux_amd64_config": descriptor["release_verifier_linux_amd64_config"],
        "linux_arm64_manifest": descriptor["release_verifier_linux_arm64_manifest"],
        "linux_arm64_config": descriptor["release_verifier_linux_arm64_config"],
        "trusted_root_sha256": descriptor["trusted_root_sha256"],
    }
    if verifier != descriptor_verifier:
        raise UpgradeJournalError("manifest verifier differs from signed descriptor")
    selected_config = verifier["linux_amd64_config" if platform == "linux/amd64" else "linux_arm64_config"]
    if receipt["cosign_image_id"] != selected_config:
        raise UpgradeJournalError("local verifier receipt differs from selected signed config")
    verification_bytes = _read_regular(
        verification_path, owner=os.geteuid(), modes=evidence_modes
    )
    verification = _load_json_bytes(
        verification_bytes, "signature-verification receipt"
    )
    if verification_bytes != _canonical_bytes(verification):
        raise UpgradeJournalError("signature-verification receipt is not canonical")
    verification = _mapping(verification, "signature-verification receipt")
    _exact_keys(
        verification,
        {
            "daemon_identity_sha256",
            "descriptor_bundle_sha256",
            "descriptor_sha256",
            "manifest_sha256",
            "migration_leaf_set_sha256",
            "migration_set_sha256",
            "oidc_issuer",
            "platform",
            "purpose",
            "release_epoch",
            "release_tag",
            "runtime_contract_version",
            "schema_version",
            "source_commit",
            "trigger",
            "trusted_root_sha256",
            "verifier_config_digest",
            "verifier_manifest_digest",
            "verifier_reference",
            "workflow_identity",
            "workflow_ref",
        },
        "signature-verification receipt",
    )
    expected_verification = {
        "daemon_identity_sha256": verification["daemon_identity_sha256"],
        "descriptor_bundle_sha256": _sha256_bytes(bundle),
        "descriptor_sha256": _sha256_bytes(descriptor_bytes),
        "manifest_sha256": _sha256_bytes(manifest_bytes),
        "migration_leaf_set_sha256": transition["migration_contract"]["leaf_set_sha256"],
        "migration_set_sha256": transition["migration_contract"]["migration_set_sha256"],
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "platform": platform,
        "purpose": "target",
        "release_epoch": transition["release_epoch"],
        "release_tag": descriptor["release_tag"],
        "runtime_contract_version": 1,
        "schema_version": 2,
        "source_commit": descriptor["source_commit"],
        "trigger": "push",
        "trusted_root_sha256": _sha256_bytes(root),
        "verifier_config_digest": selected_config,
        "verifier_manifest_digest": verifier[
            "linux_amd64_manifest" if platform == "linux/amd64" else "linux_arm64_manifest"
        ],
        "verifier_reference": verifier["reference"],
        "workflow_identity": workflow_identity,
        "workflow_ref": f"refs/tags/{descriptor['release_tag']}",
    }
    _string(
        verification["daemon_identity_sha256"],
        DIGEST_RE,
        "signature-verification daemon identity",
    )
    if verification != expected_verification:
        raise UpgradeJournalError("signature-verification receipt differs from signed evidence")

    images_manifest = _mapping(manifest["images"], "manifest.images")
    if set(images_manifest) != set(IMAGE_ROLES):
        raise UpgradeJournalError("manifest release image set is not exact")
    images: dict[str, Any] = {}
    for role in IMAGE_ROLES:
        record = _mapping(images_manifest[role], f"manifest image {role}")
        reference = descriptor[f"{role.replace('-', '_')}_image"]
        if record.get("official_reference") != reference:
            raise UpgradeJournalError(f"manifest {role} reference differs from descriptor")
        index_digest = _string(record.get("digest"), DIGEST_RE, f"manifest {role} index")
        if reference.rsplit("@", 1)[1] != index_digest:
            raise UpgradeJournalError(f"manifest {role} reference does not match index")
        platforms = _mapping(record.get("platforms"), f"manifest {role} platforms")
        if set(platforms) != set(PLATFORMS):
            raise UpgradeJournalError(f"manifest {role} platform set is not exact")
        child = _string(platforms[platform], DIGEST_RE, f"manifest {role} selected child")
        config = receipt[f"{role.replace('-', '_')}_image_id"]
        images[role] = {
            "reference": reference,
            "index_digest": index_digest,
            "platform": platform,
            "manifest_digest": child,
            "config_digest": config,
        }

    migration = transition["migration_contract"]
    return {
        "release_tag": descriptor["release_tag"],
        "release_epoch": transition["release_epoch"],
        "source_commit": descriptor["source_commit"],
        "descriptor_sha256": _sha256_bytes(descriptor_bytes),
        "descriptor_bundle_sha256": _sha256_bytes(bundle),
        "signature_verification_sha256": _sha256_bytes(verification_bytes),
        "signature_verification": verification,
        "local_images_sha256": _sha256_bytes(receipt_bytes),
        "manifest_sha256": _sha256_bytes(manifest_bytes),
        "trusted_root_sha256": _sha256_bytes(root),
        "workflow_identity": workflow_identity,
        "workflow_ref": f"refs/tags/{descriptor['release_tag']}",
        "verifier": verifier,
        "images": images,
        "migration": {
            "migrations": migration["migrations"],
            "migration_set_sha256": migration["migration_set_sha256"],
            "leaves": migration["leaves"],
            "leaf_set_sha256": migration["leaf_set_sha256"],
        },
        "accepted_predecessors": transition["accepted_predecessors"],
    }


def _predecessor_projection(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "release_tag": source["release_tag"],
        "release_epoch": source["release_epoch"],
        "source_commit": source["source_commit"],
        "release_manifest_sha256": source["manifest_sha256"],
        "descriptor_sha256": source["descriptor_sha256"],
        "descriptor_bundle_sha256": source["descriptor_bundle_sha256"],
        "migration_set_sha256": source["migration"]["migration_set_sha256"],
        "migration_leaf_set_sha256": source["migration"]["leaf_set_sha256"],
        "verifier": source["verifier"],
    }


def _authorized_predecessor_verification_receipt(
    *,
    source: dict[str, Any],
    target: dict[str, Any],
    daemon: dict[str, Any],
) -> dict[str, Any]:
    platform = f"{daemon['os']}/{daemon['architecture']}"
    verifier_manifest_key = (
        "linux_amd64_manifest" if platform == "linux/amd64" else "linux_arm64_manifest"
    )
    verifier_config_key = (
        "linux_amd64_config" if platform == "linux/amd64" else "linux_arm64_config"
    )
    projection_digest = _sha256_bytes(_canonical_bytes(_predecessor_projection(source)))
    return {
        "authorized_predecessor_sha256": projection_digest,
        "authorizing_target_descriptor_sha256": target["descriptor_sha256"],
        "daemon_identity_sha256": daemon["identity_sha256"],
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "platform": platform,
        "purpose": "authorized-predecessor",
        "schema_version": 3,
        "source_descriptor_bundle_sha256": source["descriptor_bundle_sha256"],
        "source_descriptor_sha256": source["descriptor_sha256"],
        "source_evidence_sha256": _state_digest(source),
        "source_manifest_sha256": source["manifest_sha256"],
        "source_migration_leaf_set_sha256": source["migration"]["leaf_set_sha256"],
        "source_migration_set_sha256": source["migration"]["migration_set_sha256"],
        "source_release_epoch": source["release_epoch"],
        "source_release_tag": source["release_tag"],
        "source_commit": source["source_commit"],
        "source_trusted_root_sha256": source["trusted_root_sha256"],
        "trigger": "push",
        # The authorized historical/source verifier is the binary which just
        # revalidated the source descriptor.  Recording the target verifier
        # here would silently erase the cross-version trust boundary and make
        # interrupted source-verifier cleanup impossible to authenticate.
        "verifier_config_digest": source["verifier"][verifier_config_key],
        "verifier_manifest_digest": source["verifier"][verifier_manifest_key],
        "verifier_reference": source["verifier"]["reference"],
        "verifier_runtime_contract_version": source["verifier"][
            "runtime_contract_version"
        ],
        "workflow_identity": source["workflow_identity"],
        "workflow_ref": source["workflow_ref"],
    }


def _validate_authorized_predecessor_verification(
    value: Any,
    *,
    source: dict[str, Any],
    target: dict[str, Any],
    daemon: dict[str, Any],
) -> dict[str, Any]:
    receipt = _mapping(value, "authorized-predecessor verification receipt")
    _exact_keys(
        receipt,
        {
            "authorized_predecessor_sha256",
            "authorizing_target_descriptor_sha256",
            "daemon_identity_sha256",
            "oidc_issuer",
            "platform",
            "purpose",
            "schema_version",
            "source_descriptor_bundle_sha256",
            "source_descriptor_sha256",
            "source_evidence_sha256",
            "source_manifest_sha256",
            "source_migration_leaf_set_sha256",
            "source_migration_set_sha256",
            "source_release_epoch",
            "source_release_tag",
            "source_commit",
            "source_trusted_root_sha256",
            "trigger",
            "verifier_config_digest",
            "verifier_manifest_digest",
            "verifier_reference",
            "verifier_runtime_contract_version",
            "workflow_identity",
            "workflow_ref",
        },
        "authorized-predecessor verification receipt",
    )
    expected = _authorized_predecessor_verification_receipt(
        source=source,
        target=target,
        daemon=daemon,
    )
    if receipt != expected:
        raise UpgradeJournalError(
            "authorized-predecessor verification receipt differs from source/target contract"
        )
    return dict(receipt)


def _validate_verifier_state(value: Any, label: str) -> dict[str, Any]:
    verifier = _mapping(value, label)
    _exact_keys(
        verifier,
        {
            "reference",
            "runtime_contract_version",
            "linux_amd64_manifest",
            "linux_amd64_config",
            "linux_arm64_manifest",
            "linux_arm64_config",
            "trusted_root_sha256",
        },
        label,
    )
    normalized = {
        "reference": _string(
            verifier["reference"], release_transition.VERIFIER_REFERENCE_RE, f"{label} reference"
        ),
        "runtime_contract_version": _positive_integer(
            verifier["runtime_contract_version"], f"{label} runtime contract"
        ),
    }
    if normalized["runtime_contract_version"] != 1:
        raise UpgradeJournalError(f"{label} runtime contract is unsupported")
    for key in (
        "linux_amd64_manifest",
        "linux_amd64_config",
        "linux_arm64_manifest",
        "linux_arm64_config",
        "trusted_root_sha256",
    ):
        normalized[key] = _string(verifier[key], DIGEST_RE, f"{label} {key}")
    if normalized["reference"].rsplit("@", 1)[1] in {
        normalized["linux_amd64_manifest"],
        normalized["linux_amd64_config"],
        normalized["linux_arm64_manifest"],
        normalized["linux_arm64_config"],
        normalized["trusted_root_sha256"],
    }:
        raise UpgradeJournalError(f"{label} trust digests collide")
    return normalized


def _validate_verification_state(
    value: Any,
    *,
    label: str,
    release: dict[str, Any],
    purpose: str,
) -> dict[str, Any]:
    verification = _mapping(value, label)
    expected_keys = {
        "daemon_identity_sha256",
        "descriptor_bundle_sha256",
        "descriptor_sha256",
        "manifest_sha256",
        "migration_leaf_set_sha256",
        "migration_set_sha256",
        "oidc_issuer",
        "platform",
        "purpose",
        "release_epoch",
        "release_tag",
        "runtime_contract_version",
        "schema_version",
        "source_commit",
        "trigger",
        "trusted_root_sha256",
        "verifier_config_digest",
        "verifier_manifest_digest",
        "verifier_reference",
        "workflow_identity",
        "workflow_ref",
    }
    _exact_keys(verification, expected_keys, label)
    platform = next(iter({item["platform"] for item in release["images"].values()}))
    manifest_key = "linux_amd64_manifest" if platform == "linux/amd64" else "linux_arm64_manifest"
    config_key = "linux_amd64_config" if platform == "linux/amd64" else "linux_arm64_config"
    expected = {
        "daemon_identity_sha256": verification["daemon_identity_sha256"],
        "descriptor_bundle_sha256": release["descriptor_bundle_sha256"],
        "descriptor_sha256": release["descriptor_sha256"],
        "manifest_sha256": release["manifest_sha256"],
        "migration_leaf_set_sha256": release["migration"]["leaf_set_sha256"],
        "migration_set_sha256": release["migration"]["migration_set_sha256"],
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "platform": platform,
        "purpose": purpose,
        "release_epoch": release["release_epoch"],
        "release_tag": release["release_tag"],
        "runtime_contract_version": release["verifier"]["runtime_contract_version"],
        "schema_version": 2,
        "source_commit": release["source_commit"],
        "trigger": "push",
        "trusted_root_sha256": release["trusted_root_sha256"],
        "verifier_config_digest": release["verifier"][config_key],
        "verifier_manifest_digest": release["verifier"][manifest_key],
        "verifier_reference": release["verifier"]["reference"],
        "workflow_identity": release["workflow_identity"],
        "workflow_ref": release["workflow_ref"],
    }
    _string(
        verification["daemon_identity_sha256"], DIGEST_RE, f"{label} daemon identity"
    )
    if verification != expected:
        raise UpgradeJournalError(f"{label} differs from its release state")
    return dict(verification)


def _validate_release_state(value: Any, label: str) -> dict[str, Any]:
    state = _mapping(value, label)
    _exact_keys(
        state,
        {
            "release_tag",
            "release_epoch",
            "source_commit",
            "descriptor_sha256",
            "descriptor_bundle_sha256",
            "signature_verification_sha256",
            "signature_verification",
            "local_images_sha256",
            "manifest_sha256",
            "trusted_root_sha256",
            "workflow_identity",
            "workflow_ref",
            "verifier",
            "images",
            "migration",
            "accepted_predecessors",
        },
        label,
    )
    release_tag = _string(state["release_tag"], TAG_RE, f"{label} release tag")
    release_epoch = _positive_integer(state["release_epoch"], f"{label} release epoch")
    source_commit = _string(state["source_commit"], COMMIT_RE, f"{label} source commit")
    normalized: dict[str, Any] = {
        "release_tag": release_tag,
        "release_epoch": release_epoch,
        "source_commit": source_commit,
    }
    for key in (
        "descriptor_sha256",
        "descriptor_bundle_sha256",
        "signature_verification_sha256",
        "local_images_sha256",
        "manifest_sha256",
        "trusted_root_sha256",
    ):
        normalized[key] = _string(state[key], DIGEST_RE, f"{label} {key}")
    expected_identity = (
        "https://github.com/bilal414/backupsheep/.github/workflows/"
        f"release-images.yml@refs/tags/{release_tag}"
    )
    if state["workflow_identity"] != expected_identity:
        raise UpgradeJournalError(f"{label} workflow identity changed")
    if state["workflow_ref"] != f"refs/tags/{release_tag}":
        raise UpgradeJournalError(f"{label} workflow ref changed")
    normalized["workflow_identity"] = expected_identity
    normalized["workflow_ref"] = state["workflow_ref"]
    verifier = _validate_verifier_state(state["verifier"], f"{label} verifier")
    if verifier["trusted_root_sha256"] != normalized["trusted_root_sha256"]:
        raise UpgradeJournalError(f"{label} verifier root differs from retained root")
    normalized["verifier"] = verifier

    images_value = _mapping(state["images"], f"{label} images")
    _exact_keys(images_value, set(IMAGE_ROLES), f"{label} images")
    images: dict[str, Any] = {}
    for role in IMAGE_ROLES:
        image = _mapping(images_value[role], f"{label} {role} image")
        _exact_keys(
            image,
            {"reference", "index_digest", "platform", "manifest_digest", "config_digest"},
            f"{label} {role} image",
        )
        index_digest = _string(image["index_digest"], DIGEST_RE, f"{label} {role} index")
        reference = image["reference"]
        if reference != f"{IMAGE_REPOSITORIES[role]}@{index_digest}":
            raise UpgradeJournalError(f"{label} {role} reference is not official and digest-bound")
        if image["platform"] not in PLATFORMS:
            raise UpgradeJournalError(f"{label} {role} platform is unsupported")
        images[role] = {
            "reference": reference,
            "index_digest": index_digest,
            "platform": image["platform"],
            "manifest_digest": _string(
                image["manifest_digest"], DIGEST_RE, f"{label} {role} child manifest"
            ),
            "config_digest": _string(
                image["config_digest"], DIGEST_RE, f"{label} {role} config"
            ),
        }
    selected_platforms = {image["platform"] for image in images.values()}
    if len(selected_platforms) != 1:
        raise UpgradeJournalError(f"{label} release images select different platforms")
    normalized["images"] = images

    migration = _mapping(state["migration"], f"{label} migration")
    _exact_keys(
        migration,
        {"migrations", "migration_set_sha256", "leaves", "leaf_set_sha256"},
        f"{label} migration",
    )
    validated_migration = release_transition.validate_migration_contract(
        {
            "schema_version": 1,
            "all_migrations_atomic": True,
            **migration,
        }
    )
    normalized["migration"] = {
        key: validated_migration[key]
        for key in ("migrations", "migration_set_sha256", "leaves", "leaf_set_sha256")
    }
    policy = release_transition.validate_transition_policy(
        {
            "schema_version": 1,
            "release_epoch": release_epoch,
            "accepted_predecessors": state["accepted_predecessors"],
        }
    )
    normalized["accepted_predecessors"] = policy["accepted_predecessors"]
    normalized["signature_verification"] = _validate_verification_state(
        state["signature_verification"],
        label=f"{label} signature verification",
        release=normalized,
        purpose="target",
    )
    if normalized["signature_verification_sha256"] != _sha256_bytes(
        _canonical_bytes(normalized["signature_verification"])
    ):
        raise UpgradeJournalError(f"{label} signature-verification digest changed")
    digest_values = [
        normalized["trusted_root_sha256"],
        normalized["verifier"]["reference"].rsplit("@", 1)[1],
        normalized["verifier"]["linux_amd64_manifest"],
        normalized["verifier"]["linux_amd64_config"],
        normalized["verifier"]["linux_arm64_manifest"],
        normalized["verifier"]["linux_arm64_config"],
    ]
    for role in IMAGE_ROLES:
        digest_values.extend(
            (
                normalized["images"][role]["index_digest"],
                normalized["images"][role]["manifest_digest"],
                normalized["images"][role]["config_digest"],
            )
        )
    if len(digest_values) != len(set(digest_values)):
        raise UpgradeJournalError(f"{label} contains colliding trust or image digests")
    return normalized


def _validate_witness_request(value: Any) -> dict[str, Any]:
    request = _mapping(value, "upgrade witness request")
    _exact_keys(
        request,
        {
            "schema_version",
            "attempt_nonce",
            "installation_id",
            "compose_project",
            "daemon",
            "checkouts",
            "compose",
            "target_active_pointer_sha256",
            "volumes",
            "artifact_provider",
        },
        "upgrade witness request",
    )
    if request["schema_version"] != WITNESS_SCHEMA_VERSION:
        raise UpgradeJournalError("unsupported upgrade witness schema")
    attempt_nonce = _string(request["attempt_nonce"], HEX_RE, "upgrade attempt nonce")
    installation_id = _string(request["installation_id"], HEX_RE, "installation ID")
    compose_project = _string(request["compose_project"], PROJECT_RE, "Compose project")
    daemon = _mapping(request["daemon"], "daemon witness")
    _exact_keys(daemon, {"os", "architecture", "identity_sha256"}, "daemon witness")
    if daemon["os"] != "linux" or daemon["architecture"] not in {"amd64", "arm64"}:
        raise UpgradeJournalError("daemon platform is unsupported")
    daemon_identity = _string(daemon["identity_sha256"], DIGEST_RE, "daemon identity")
    checkouts_value = _mapping(request["checkouts"], "checkout witnesses")
    _exact_keys(checkouts_value, {"source", "target"}, "checkout witnesses")
    checkouts: dict[str, Any] = {}
    for role in ("source", "target"):
        checkout = _mapping(checkouts_value[role], f"{role} checkout witness")
        _exact_keys(
            checkout,
            {"commit", "tree_sha256", "runtime_files_sha256"},
            f"{role} checkout witness",
        )
        checkouts[role] = {
            "commit": _string(checkout["commit"], COMMIT_RE, f"{role} checkout commit"),
            "tree_sha256": _string(
                checkout["tree_sha256"], DIGEST_RE, f"{role} checkout tree"
            ),
            "runtime_files_sha256": _string(
                checkout["runtime_files_sha256"],
                DIGEST_RE,
                f"{role} checkout runtime files",
            ),
        }
    compose = _mapping(request["compose"], "Compose witness")
    _exact_keys(
        compose, {"source_model_sha256", "target_model_sha256"}, "Compose witness"
    )
    compose = {
        key: _string(compose[key], DIGEST_RE, f"Compose {key}")
        for key in ("source_model_sha256", "target_model_sha256")
    }
    target_active_pointer_sha256 = _string(
        request["target_active_pointer_sha256"],
        DIGEST_RE,
        "target active-release pointer",
    )
    volumes_value = _mapping(request["volumes"], "volume witnesses")
    _exact_keys(volumes_value, set(VOLUME_ROLES), "volume witnesses")
    volumes: dict[str, Any] = {}
    for role in VOLUME_ROLES:
        volume = _mapping(volumes_value[role], f"{role} volume witness")
        _exact_keys(volume, {"name", "inspect_sha256", "ownership_witness_sha256"}, f"{role} volume witness")
        expected_name = f"{compose_project}_{role}"
        if volume["name"] != expected_name:
            raise UpgradeJournalError(
                f"{role} volume name does not match the exact Compose project identity"
            )
        volumes[role] = {
            "name": _string(volume["name"], VOLUME_RE, f"{role} volume name"),
            "inspect_sha256": _string(volume["inspect_sha256"], DIGEST_RE, f"{role} volume inspect"),
            "ownership_witness_sha256": _string(
                volume["ownership_witness_sha256"], DIGEST_RE, f"{role} volume ownership"
            ),
        }
    provider = _mapping(request["artifact_provider"], "artifact-provider witness")
    _exact_keys(
        provider,
        {"generation", "witness_sha256", "database_keyring_sha256", "files_keyring_sha256"},
        "artifact-provider witness",
    )
    generation = _positive_integer(provider["generation"], "artifact-provider generation")
    provider = {
        "generation": generation,
        **{
            key: _string(provider[key], DIGEST_RE, f"artifact-provider {key}")
            for key in ("witness_sha256", "database_keyring_sha256", "files_keyring_sha256")
        },
    }
    if provider["database_keyring_sha256"] == provider["files_keyring_sha256"]:
        raise UpgradeJournalError("artifact keyring digests collide")
    return {
        "schema_version": WITNESS_SCHEMA_VERSION,
        "attempt_nonce": attempt_nonce,
        "installation_id": installation_id,
        "compose_project": compose_project,
        "daemon": {"os": "linux", "architecture": daemon["architecture"], "identity_sha256": daemon_identity},
        "checkouts": checkouts,
        "compose": compose,
        "target_active_pointer_sha256": target_active_pointer_sha256,
        "volumes": volumes,
        "artifact_provider": provider,
    }


def build_intent(
    *,
    source_evidence: Path,
    target_evidence: Path,
    source_env: Path,
    target_env: Path,
    source_verification: Path,
    witness_request: Path,
) -> tuple[dict[str, Any], bytes]:
    request = _validate_witness_request(
        _load_json(witness_request, owner=os.geteuid(), modes={0o600})
    )
    platform = f"{request['daemon']['os']}/{request['daemon']['architecture']}"
    source = build_release_state(source_evidence, platform)
    target = build_release_state(target_evidence, platform)
    if (
        source["signature_verification"]["daemon_identity_sha256"]
        != request["daemon"]["identity_sha256"]
        or target["signature_verification"]["daemon_identity_sha256"]
        != request["daemon"]["identity_sha256"]
    ):
        raise UpgradeJournalError("release verification targeted another Docker daemon")
    if target["release_epoch"] <= source["release_epoch"]:
        raise UpgradeJournalError("target release epoch is not forward-only")
    if not set(source["migration"]["migrations"]).issubset(
        target["migration"]["migrations"]
    ):
        raise UpgradeJournalError(
            "target migration graph does not contain the complete source graph"
        )
    projection = _predecessor_projection(source)
    matches = [item for item in target["accepted_predecessors"] if item == projection]
    if len(matches) != 1:
        raise UpgradeJournalError("target does not authorize this exact signed predecessor")
    if (
        request["checkouts"]["source"]["commit"] != source["source_commit"]
        or request["checkouts"]["target"]["commit"] != target["source_commit"]
    ):
        raise UpgradeJournalError("checkout witness commit differs from signed release")
    source_verification_bytes = _read_regular(
        source_verification,
        owner=os.geteuid(),
        modes={0o600},
    )
    try:
        source_verification_value = json.loads(
            source_verification_bytes,
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                UpgradeJournalError(f"JSON contains non-finite number {value}")
            ),
            parse_float=lambda value: (_ for _ in ()).throw(
                UpgradeJournalError(f"JSON contains unsupported float {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpgradeJournalError(
            "authorized-predecessor verification receipt is not strict JSON"
        ) from exc
    if source_verification_bytes != _canonical_bytes(source_verification_value):
        raise UpgradeJournalError(
            "authorized-predecessor verification receipt is not canonical"
        )
    source_verification_value = _validate_authorized_predecessor_verification(
        source_verification_value,
        source=source,
        target=target,
        daemon=request["daemon"],
    )
    source_env_bytes = _read_regular(source_env, owner=os.geteuid(), modes={0o600})
    target_env_bytes = _read_regular(target_env, owner=os.geteuid(), modes={0o600})
    operation_seed = (
        "BackupSheep/signed-upgrade/v1|"
        f"{request['installation_id']}|{source['descriptor_sha256']}|"
        f"{target['descriptor_sha256']}|{request['attempt_nonce']}"
    ).encode("ascii")
    operation_id = hashlib.sha256(operation_seed).hexdigest()
    intent = {
        "schema_version": SCHEMA_VERSION,
        "attempt_nonce": request["attempt_nonce"],
        "operation_id": operation_id,
        "installation_id": request["installation_id"],
        "compose_project": request["compose_project"],
        "source": source,
        "target": target,
        "authorization": {
            "predecessor": projection,
            "predecessor_sha256": _sha256_bytes(_canonical_bytes(projection)),
            "source_verification": source_verification_value,
            "source_verification_file": SOURCE_VERIFICATION_NAME,
            "source_verification_sha256": _sha256_bytes(source_verification_bytes),
        },
        "daemon": request["daemon"],
        "checkouts": request["checkouts"],
        "compose": request["compose"],
        "target_active_pointer_sha256": request["target_active_pointer_sha256"],
        "environment": {
            "source_sha256": _sha256_bytes(source_env_bytes),
            "target_sha256": _sha256_bytes(target_env_bytes),
            "rollback_file": ROLLBACK_ENV_NAME,
            "rollback_sha256": _sha256_bytes(source_env_bytes),
            "target_file": TARGET_ENV_NAME,
        },
        "volumes": request["volumes"],
        "artifact_provider": request["artifact_provider"],
        "resource_digests": {
            "volume_records_sha256": _domain_digest(
                "BackupSheep/upgrade-volumes/v1", request["volumes"]
            ),
            "artifact_provider_sha256": _domain_digest(
                "BackupSheep/upgrade-artifact-provider/v1",
                request["artifact_provider"],
            ),
        },
    }
    return intent, source_env_bytes


def _state_digest(state: dict[str, Any]) -> str:
    return _sha256_bytes(_canonical_bytes(state))


def build_authorized_predecessor_verification(
    *,
    source_evidence: Path,
    target_evidence: Path,
    daemon_os: str,
    daemon_architecture: str,
    daemon_identity_sha256: str,
) -> dict[str, Any]:
    """Build the receipt a trusted caller publishes only after Cosign succeeds.

    This routine deliberately performs no network access and does not claim that
    signature verification happened.  The signed-release consumer calls it to
    derive the one canonical receipt, executes the authorized historical
    verifier offline, and publishes these exact bytes only after exit status 0.
    """

    if daemon_os != "linux" or daemon_architecture not in {"amd64", "arm64"}:
        raise UpgradeJournalError("daemon platform is unsupported")
    daemon = {
        "os": daemon_os,
        "architecture": daemon_architecture,
        "identity_sha256": _string(
            daemon_identity_sha256, DIGEST_RE, "daemon identity"
        ),
    }
    platform = f"{daemon_os}/{daemon_architecture}"
    source = build_release_state(source_evidence, platform)
    target = build_release_state(target_evidence, platform)
    if (
        source["signature_verification"]["daemon_identity_sha256"]
        != daemon_identity_sha256
        or target["signature_verification"]["daemon_identity_sha256"]
        != daemon_identity_sha256
    ):
        raise UpgradeJournalError("release verification targeted another Docker daemon")
    if target["release_epoch"] <= source["release_epoch"]:
        raise UpgradeJournalError("target release epoch is not forward-only")
    if not set(source["migration"]["migrations"]).issubset(
        target["migration"]["migrations"]
    ):
        raise UpgradeJournalError(
            "target migration graph does not contain the complete source graph"
        )
    projection = _predecessor_projection(source)
    matches = [item for item in target["accepted_predecessors"] if item == projection]
    if len(matches) != 1:
        raise UpgradeJournalError(
            "target does not authorize this exact signed predecessor"
        )
    return _authorized_predecessor_verification_receipt(
        source=source,
        target=target,
        daemon=daemon,
    )


def _validate_checkout_state(
    value: Any, *, expected: dict[str, Any], label: str
) -> dict[str, Any]:
    checkout = _mapping(value, label)
    _exact_keys(
        checkout,
        {"commit", "tree_sha256", "runtime_files_sha256"},
        label,
    )
    normalized = {
        "commit": _string(checkout["commit"], COMMIT_RE, f"{label} commit"),
        "tree_sha256": _string(
            checkout["tree_sha256"], DIGEST_RE, f"{label} tree"
        ),
        "runtime_files_sha256": _string(
            checkout["runtime_files_sha256"],
            DIGEST_RE,
            f"{label} runtime files",
        ),
    }
    if normalized != expected:
        raise UpgradeJournalError(f"{label} differs from immutable intent")
    return normalized


def _validate_migration_witness(
    value: Any, *, expected: dict[str, Any], label: str
) -> dict[str, Any]:
    witness = _mapping(value, label)
    _exact_keys(
        witness,
        {"count", "set_sha256", "leaf_count", "leaf_set_sha256", "missing", "unknown"},
        label,
    )
    normalized = {
        "count": _nonnegative_integer(witness["count"], f"{label} count", maximum=4096),
        "set_sha256": _string(witness["set_sha256"], DIGEST_RE, f"{label} set"),
        "leaf_count": _nonnegative_integer(
            witness["leaf_count"], f"{label} leaf count", maximum=4096
        ),
        "leaf_set_sha256": _string(
            witness["leaf_set_sha256"], DIGEST_RE, f"{label} leaf set"
        ),
        "missing": _list(witness["missing"], f"{label} missing"),
        "unknown": _list(witness["unknown"], f"{label} unknown"),
    }
    expected_normalized = {
        "count": len(expected["migrations"]),
        "set_sha256": expected["migration_set_sha256"],
        "leaf_count": len(expected["leaves"]),
        "leaf_set_sha256": expected["leaf_set_sha256"],
        "missing": [],
        "unknown": [],
    }
    if normalized != expected_normalized:
        raise UpgradeJournalError(f"{label} differs from the exact signed migration graph")
    return normalized


def _validate_resource_set(
    value: Any,
    *,
    intent: dict[str, Any],
    compose_model_sha256: str,
    label: str,
) -> dict[str, Any]:
    resources = _mapping(value, label)
    expected_keys = {
        "daemon_identity_sha256",
        "compose_model_sha256",
        "volume_records_sha256",
        "network_records_sha256",
        "container_records_sha256",
        "storage_aggregate_sha256",
        "artifact_provider_aggregate_sha256",
        "aggregate_sha256",
    }
    _exact_keys(resources, expected_keys, label)
    normalized = {
        key: _string(resources[key], DIGEST_RE, f"{label} {key}")
        for key in expected_keys
    }
    if normalized["daemon_identity_sha256"] != intent["daemon"]["identity_sha256"]:
        raise UpgradeJournalError(f"{label} targeted another Docker daemon")
    if normalized["compose_model_sha256"] != compose_model_sha256:
        raise UpgradeJournalError(f"{label} targeted another Compose model")
    if normalized["volume_records_sha256"] != intent["resource_digests"][
        "volume_records_sha256"
    ]:
        raise UpgradeJournalError(f"{label} volume identity changed")
    if normalized["storage_aggregate_sha256"] != intent["resource_digests"][
        "volume_records_sha256"
    ]:
        raise UpgradeJournalError(f"{label} storage aggregate changed")
    if normalized["artifact_provider_aggregate_sha256"] != intent["resource_digests"][
        "artifact_provider_sha256"
    ]:
        raise UpgradeJournalError(f"{label} artifact-provider identity changed")
    aggregate_input = {
        key: normalized[key] for key in sorted(expected_keys - {"aggregate_sha256"})
    }
    if normalized["aggregate_sha256"] != _domain_digest(
        "BackupSheep/upgrade-resource-set/v1", aggregate_input
    ):
        raise UpgradeJournalError(f"{label} aggregate is inconsistent")
    return normalized


def _validate_absent_services(value: Any, services: tuple[str, ...], label: str) -> list[Any]:
    records = _list(value, label)
    expected = [{"service": service, "state": "absent"} for service in services]
    if records != expected:
        raise UpgradeJournalError(f"{label} is not the exact absent service inventory")
    return records


def _validate_container_record(value: Any, *, service: str, label: str) -> dict[str, Any]:
    record = _mapping(value, label)
    if record.get("state") == "absent":
        _exact_keys(record, {"service", "state"}, label)
        if record != {"service": service, "state": "absent"}:
            raise UpgradeJournalError(f"{label} absent record is malformed")
        return dict(record)
    _exact_keys(
        record,
        {
            "service",
            "container_id",
            "image_config_sha256",
            "compose_config_sha256",
            "state",
            "health",
            "restart_count",
        },
        label,
    )
    if record["service"] != service or record["state"] not in {"running", "exited"}:
        raise UpgradeJournalError(f"{label} service or state is malformed")
    if record["health"] not in {"healthy", "none"}:
        raise UpgradeJournalError(f"{label} health is malformed")
    return {
        "service": service,
        "container_id": _string(record["container_id"], HEX_RE, f"{label} container ID"),
        "image_config_sha256": _string(
            record["image_config_sha256"], DIGEST_RE, f"{label} image config"
        ),
        "compose_config_sha256": _string(
            record["compose_config_sha256"], DIGEST_RE, f"{label} Compose config"
        ),
        "state": record["state"],
        "health": record["health"],
        "restart_count": _nonnegative_integer(
            record["restart_count"], f"{label} restart count", maximum=1_000_000
        ),
    }


def _validate_runtime_records(
    value: Any,
    *,
    services: tuple[str, ...],
    required_running: set[str],
    required_absent: set[str],
    label: str,
) -> dict[str, Any]:
    runtime = _mapping(value, label)
    _exact_keys(runtime, {"records", "records_sha256"}, label)
    raw_records = _list(runtime["records"], f"{label} records")
    if len(raw_records) != len(services):
        raise UpgradeJournalError(f"{label} service cardinality is not exact")
    records = [
        _validate_container_record(record, service=service, label=f"{label} {service}")
        for service, record in zip(services, raw_records, strict=True)
    ]
    for record in records:
        if record["service"] in required_running and record["state"] != "running":
            raise UpgradeJournalError(f"{label} required service is not running")
        if record["service"] in required_absent and record["state"] != "absent":
            raise UpgradeJournalError(f"{label} forbidden service is present")
    records_digest = _domain_digest("BackupSheep/upgrade-runtime-records/v1", records)
    if runtime["records_sha256"] != records_digest:
        raise UpgradeJournalError(f"{label} records digest is inconsistent")
    return {"records": records, "records_sha256": records_digest}


def _validate_outcome(value: Any, label: str) -> dict[str, Any]:
    outcome = _mapping(value, label)
    _exact_keys(outcome, {"outcome", "receipt_sha256"}, label)
    if outcome["outcome"] not in {"exit-zero", "reconciled-unknown"}:
        raise UpgradeJournalError(f"{label} outcome is unsupported")
    return {
        "outcome": outcome["outcome"],
        "receipt_sha256": _string(
            outcome["receipt_sha256"], DIGEST_RE, f"{label} receipt"
        ),
    }


def _validate_phase_payload(phase: str, payload: Any, intent: dict[str, Any]) -> dict[str, Any]:
    payload = _mapping(payload, f"{phase} payload")
    source_model = intent["compose"]["source_model_sha256"]
    target_model = intent["compose"]["target_model_sha256"]
    source_state = _state_digest(intent["source"])
    target_state = _state_digest(intent["target"])
    source_checkout_digest = _domain_digest(
        "BackupSheep/upgrade-checkout/v1", intent["checkouts"]["source"]
    )
    target_checkout_digest = _domain_digest(
        "BackupSheep/upgrade-checkout/v1", intent["checkouts"]["target"]
    )
    if phase == "10-prepared":
        _exact_keys(
            payload,
            {
                "source_release_sha256",
                "target_release_sha256",
                "source_verification_sha256",
                "target_verification_sha256",
                "authorized_predecessor_sha256",
                "source_checkout",
                "target_checkout",
                "source_env_sha256",
                "target_env_sha256",
                "target_model_sha256",
                "source_migrations",
                "resources",
            },
            "10-prepared payload",
        )
        normalized = {
            "source_release_sha256": _string(payload["source_release_sha256"], DIGEST_RE, "prepared source release"),
            "target_release_sha256": _string(payload["target_release_sha256"], DIGEST_RE, "prepared target release"),
            "source_verification_sha256": _string(payload["source_verification_sha256"], DIGEST_RE, "prepared source verification"),
            "target_verification_sha256": _string(payload["target_verification_sha256"], DIGEST_RE, "prepared target verification"),
            "authorized_predecessor_sha256": _string(payload["authorized_predecessor_sha256"], DIGEST_RE, "prepared predecessor"),
            "source_checkout": _validate_checkout_state(payload["source_checkout"], expected=intent["checkouts"]["source"], label="prepared source checkout"),
            "target_checkout": _validate_checkout_state(payload["target_checkout"], expected=intent["checkouts"]["target"], label="prepared target checkout"),
            "source_env_sha256": _string(payload["source_env_sha256"], DIGEST_RE, "prepared source environment"),
            "target_env_sha256": _string(payload["target_env_sha256"], DIGEST_RE, "prepared target environment"),
            "target_model_sha256": _string(payload["target_model_sha256"], DIGEST_RE, "prepared target model"),
            "source_migrations": _validate_migration_witness(payload["source_migrations"], expected=intent["source"]["migration"], label="prepared source migrations"),
            "resources": _validate_resource_set(payload["resources"], intent=intent, compose_model_sha256=source_model, label="prepared resources"),
        }
        expected = {
            "source_release_sha256": source_state,
            "target_release_sha256": target_state,
            "source_verification_sha256": intent["authorization"]["source_verification_sha256"],
            "target_verification_sha256": intent["target"]["signature_verification_sha256"],
            "authorized_predecessor_sha256": intent["authorization"]["predecessor_sha256"],
            "source_env_sha256": intent["environment"]["source_sha256"],
            "target_env_sha256": intent["environment"]["target_sha256"],
            "target_model_sha256": target_model,
        }
        for key, expected_value in expected.items():
            if normalized[key] != expected_value:
                raise UpgradeJournalError(f"prepared {key} differs from immutable intent")
        return normalized
    if phase == "20-stopped":
        _exact_keys(payload, {"source_checkout_sha256", "source_env_sha256", "source_evidence_sha256", "source_keyrings_sha256", "stopped_writer_services", "source_migrations", "detached_volume_records_sha256", "resources"}, "20-stopped payload")
        normalized = {
            "source_checkout_sha256": _string(payload["source_checkout_sha256"], DIGEST_RE, "stopped source checkout"),
            "source_env_sha256": _string(payload["source_env_sha256"], DIGEST_RE, "stopped source environment"),
            "source_evidence_sha256": _string(payload["source_evidence_sha256"], DIGEST_RE, "stopped source evidence"),
            "source_keyrings_sha256": _string(payload["source_keyrings_sha256"], DIGEST_RE, "stopped source keyrings"),
            "stopped_writer_services": _validate_absent_services(payload["stopped_writer_services"], WRITER_SERVICES, "stopped writers"),
            "source_migrations": _validate_migration_witness(payload["source_migrations"], expected=intent["source"]["migration"], label="stopped source migrations"),
            "detached_volume_records_sha256": _string(payload["detached_volume_records_sha256"], DIGEST_RE, "stopped detached volumes"),
            "resources": _validate_resource_set(payload["resources"], intent=intent, compose_model_sha256=source_model, label="stopped resources"),
        }
        expected = (source_checkout_digest, intent["environment"]["source_sha256"], source_state, intent["resource_digests"]["artifact_provider_sha256"], intent["resource_digests"]["volume_records_sha256"])
        actual = tuple(normalized[key] for key in ("source_checkout_sha256", "source_env_sha256", "source_evidence_sha256", "source_keyrings_sha256", "detached_volume_records_sha256"))
        if actual != expected:
            raise UpgradeJournalError("stopped source binding differs from immutable intent")
        return normalized
    if phase == "30-switched":
        _exact_keys(payload, {"active_checkout", "active_env_sha256", "active_evidence_sha256", "active_model_sha256", "target_code_inventory", "target_writer_inventory", "active_pointer_sha256", "resources"}, "30-switched payload")
        normalized = {
            "active_checkout": _validate_checkout_state(payload["active_checkout"], expected=intent["checkouts"]["target"], label="switched target checkout"),
            "active_env_sha256": _string(payload["active_env_sha256"], DIGEST_RE, "switched target environment"),
            "active_evidence_sha256": _string(payload["active_evidence_sha256"], DIGEST_RE, "switched target evidence"),
            "active_model_sha256": _string(payload["active_model_sha256"], DIGEST_RE, "switched target model"),
            "target_code_inventory": _list(payload["target_code_inventory"], "switched target code inventory"),
            "target_writer_inventory": _list(payload["target_writer_inventory"], "switched target writer inventory"),
            "active_pointer_sha256": _string(payload["active_pointer_sha256"], DIGEST_RE, "switched active pointer"),
            "resources": _validate_resource_set(payload["resources"], intent=intent, compose_model_sha256=target_model, label="switched resources"),
        }
        if normalized["target_code_inventory"] != [] or normalized["target_writer_inventory"] != []:
            raise UpgradeJournalError("target code exists before the forward-only boundary")
        if (normalized["active_env_sha256"], normalized["active_evidence_sha256"], normalized["active_model_sha256"], normalized["active_pointer_sha256"]) != (intent["environment"]["target_sha256"], target_state, target_model, intent["target_active_pointer_sha256"]):
            raise UpgradeJournalError("switched target binding differs from immutable intent")
        return normalized
    if phase == "40-forward-only":
        _exact_keys(payload, {"active_checkout_sha256", "active_env_sha256", "active_evidence_sha256", "active_model_sha256", "source_pre_migration", "target_code_inventory", "storage_aggregate_sha256", "artifact_provider_aggregate_sha256", "boundary_nonce", "boundary_sha256"}, "40-forward-only payload")
        normalized = {
            "active_checkout_sha256": _string(payload["active_checkout_sha256"], DIGEST_RE, "forward-only target checkout"),
            "active_env_sha256": _string(payload["active_env_sha256"], DIGEST_RE, "forward-only target environment"),
            "active_evidence_sha256": _string(payload["active_evidence_sha256"], DIGEST_RE, "forward-only target evidence"),
            "active_model_sha256": _string(payload["active_model_sha256"], DIGEST_RE, "forward-only target model"),
            "source_pre_migration": _validate_migration_witness(payload["source_pre_migration"], expected=intent["source"]["migration"], label="forward-only source migrations"),
            "target_code_inventory": _list(payload["target_code_inventory"], "forward-only target code inventory"),
            "storage_aggregate_sha256": _string(payload["storage_aggregate_sha256"], DIGEST_RE, "forward-only storage"),
            "artifact_provider_aggregate_sha256": _string(payload["artifact_provider_aggregate_sha256"], DIGEST_RE, "forward-only artifact provider"),
            "boundary_nonce": _string(payload["boundary_nonce"], HEX_RE, "forward-only boundary nonce"),
            "boundary_sha256": _string(payload["boundary_sha256"], DIGEST_RE, "forward-only boundary"),
        }
        if normalized["target_code_inventory"] != []:
            raise UpgradeJournalError("target code exists before forward-only receipt")
        binding = {key: normalized[key] for key in normalized if key != "boundary_sha256"}
        expected_boundary = _domain_digest(
            f"BackupSheep/forward-only/{intent['operation_id']}/v1", binding
        )
        if (normalized["active_checkout_sha256"], normalized["active_env_sha256"], normalized["active_evidence_sha256"], normalized["active_model_sha256"], normalized["storage_aggregate_sha256"], normalized["artifact_provider_aggregate_sha256"], normalized["boundary_nonce"], normalized["boundary_sha256"]) != (target_checkout_digest, intent["environment"]["target_sha256"], target_state, target_model, intent["resource_digests"]["volume_records_sha256"], intent["resource_digests"]["artifact_provider_sha256"], intent["attempt_nonce"], expected_boundary):
            raise UpgradeJournalError("forward-only boundary differs from immutable intent")
        return normalized
    if phase == "50-migrated":
        _exact_keys(payload, {"target_app_config_sha256", "runner", "target_migrations", "storage_aggregate_sha256"}, "50-migrated payload")
        runner = _mapping(payload["runner"], "migration runner")
        _exact_keys(runner, {"container_id", "image_config_sha256", "compose_config_sha256", "outcome", "exit_code", "receipt_sha256"}, "migration runner")
        normalized_runner = {
            "container_id": _string(runner["container_id"], HEX_RE, "migration runner container ID"),
            "image_config_sha256": _string(runner["image_config_sha256"], DIGEST_RE, "migration runner image"),
            "compose_config_sha256": _string(runner["compose_config_sha256"], DIGEST_RE, "migration runner Compose config"),
            "outcome": runner["outcome"],
            "exit_code": runner["exit_code"],
            "receipt_sha256": _string(runner["receipt_sha256"], DIGEST_RE, "migration runner receipt"),
        }
        if normalized_runner["outcome"] not in {"exit-zero", "reconciled-unknown"} or normalized_runner["exit_code"] != 0:
            raise UpgradeJournalError("migration runner did not reconcile to exact exit zero")
        if normalized_runner["image_config_sha256"] != intent["target"]["images"]["app"]["config_digest"]:
            raise UpgradeJournalError("migration runner used another application image")
        normalized = {
            "target_app_config_sha256": _string(payload["target_app_config_sha256"], DIGEST_RE, "migrated target app"),
            "runner": normalized_runner,
            "target_migrations": _validate_migration_witness(payload["target_migrations"], expected=intent["target"]["migration"], label="target migrations"),
            "storage_aggregate_sha256": _string(payload["storage_aggregate_sha256"], DIGEST_RE, "migrated storage"),
        }
        if normalized["target_app_config_sha256"] != intent["target"]["images"]["app"]["config_digest"] or normalized["storage_aggregate_sha256"] != intent["resource_digests"]["volume_records_sha256"]:
            raise UpgradeJournalError("migrated target binding differs from immutable intent")
        return normalized
    if phase == "60-core-accepted":
        _exact_keys(payload, {"db_seal", "preflight", "core_runtime", "target_migrations", "functional_probe_sha256", "resources"}, "60-core-accepted payload")
        return {
            "db_seal": _validate_outcome(payload["db_seal"], "db-seal"),
            "preflight": _validate_outcome(payload["preflight"], "preflight"),
            "core_runtime": _validate_runtime_records(payload["core_runtime"], services=CORE_SERVICES, required_running=set(CORE_SERVICES), required_absent=set(), label="core runtime"),
            "target_migrations": _validate_migration_witness(payload["target_migrations"], expected=intent["target"]["migration"], label="core target migrations"),
            "functional_probe_sha256": _string(payload["functional_probe_sha256"], DIGEST_RE, "core functional probe"),
            "resources": _validate_resource_set(payload["resources"], intent=intent, compose_model_sha256=target_model, label="core resources"),
        }
    if phase == "70-activated":
        _exact_keys(payload, {"activation_mode", "active_pointer_sha256", "active_checkout_sha256", "active_env_sha256", "active_evidence_sha256", "active_release_sha256", "local_images_sha256", "runtime", "resources"}, "70-activated payload")
        mode = payload["activation_mode"]
        if mode not in {"core-only", "operations"}:
            raise UpgradeJournalError("activation mode is unsupported")
        required_running = set(CORE_SERVICES)
        if mode == "operations":
            required_running.update(OPERATION_SERVICES)
        required_absent = set(ONE_SHOT_SERVICES)
        if mode == "core-only":
            required_absent.update(OPERATION_SERVICES)
        normalized = {
            "activation_mode": mode,
            "active_pointer_sha256": _string(payload["active_pointer_sha256"], DIGEST_RE, "activated pointer"),
            "active_checkout_sha256": _string(payload["active_checkout_sha256"], DIGEST_RE, "activated checkout"),
            "active_env_sha256": _string(payload["active_env_sha256"], DIGEST_RE, "activated environment"),
            "active_evidence_sha256": _string(payload["active_evidence_sha256"], DIGEST_RE, "activated evidence"),
            "active_release_sha256": _string(payload["active_release_sha256"], DIGEST_RE, "activated release"),
            "local_images_sha256": _string(payload["local_images_sha256"], DIGEST_RE, "activated local images"),
            "runtime": _validate_runtime_records(payload["runtime"], services=ALL_SERVICES, required_running=required_running, required_absent=required_absent, label="activated runtime"),
            "resources": _validate_resource_set(payload["resources"], intent=intent, compose_model_sha256=target_model, label="activated resources"),
        }
        expected = (intent["target_active_pointer_sha256"], target_checkout_digest, intent["environment"]["target_sha256"], target_state, target_state, intent["target"]["local_images_sha256"])
        actual = tuple(normalized[key] for key in ("active_pointer_sha256", "active_checkout_sha256", "active_env_sha256", "active_evidence_sha256", "active_release_sha256", "local_images_sha256"))
        if actual != expected:
            raise UpgradeJournalError("activated target binding differs from immutable intent")
        return normalized
    raise UpgradeJournalError("receipt phase is unsupported")


def _validate_rollback_payload(payload: Any, intent: dict[str, Any]) -> dict[str, Any]:
    payload = _mapping(payload, "rollback payload")
    _exact_keys(
        payload,
        {
            "source_checkout_sha256",
            "source_env_sha256",
            "source_evidence_sha256",
            "source_model_sha256",
            "source_migrations",
            "target_code_inventory",
            "resources",
        },
        "rollback payload",
    )
    source_checkout_sha256 = _domain_digest(
        "BackupSheep/upgrade-checkout/v1", intent["checkouts"]["source"]
    )
    normalized = {
        "source_checkout_sha256": _string(
            payload["source_checkout_sha256"], DIGEST_RE, "rollback source checkout"
        ),
        "source_env_sha256": _string(
            payload["source_env_sha256"], DIGEST_RE, "rollback source environment"
        ),
        "source_evidence_sha256": _string(
            payload["source_evidence_sha256"], DIGEST_RE, "rollback source evidence"
        ),
        "source_model_sha256": _string(
            payload["source_model_sha256"], DIGEST_RE, "rollback source model"
        ),
        "source_migrations": _validate_migration_witness(
            payload["source_migrations"],
            expected=intent["source"]["migration"],
            label="rollback source migrations",
        ),
        "target_code_inventory": _list(
            payload["target_code_inventory"], "rollback target code inventory"
        ),
        "resources": _validate_resource_set(
            payload["resources"],
            intent=intent,
            compose_model_sha256=intent["compose"]["source_model_sha256"],
            label="rollback resources",
        ),
    }
    if normalized["target_code_inventory"] != []:
        raise UpgradeJournalError("rollback is forbidden after target code creation")
    expected = (
        source_checkout_sha256,
        intent["environment"]["source_sha256"],
        _state_digest(intent["source"]),
        intent["compose"]["source_model_sha256"],
    )
    actual = tuple(
        normalized[key]
        for key in (
            "source_checkout_sha256",
            "source_env_sha256",
            "source_evidence_sha256",
            "source_model_sha256",
        )
    )
    if actual != expected:
        raise UpgradeJournalError("rollback source binding differs from immutable intent")
    return normalized


def _validate_intent(value: Any) -> dict[str, Any]:
    intent = _mapping(value, "upgrade intent")
    _exact_keys(
        intent,
        {
            "schema_version",
            "attempt_nonce",
            "operation_id",
            "installation_id",
            "compose_project",
            "source",
            "target",
            "authorization",
            "daemon",
            "checkouts",
            "compose",
            "target_active_pointer_sha256",
            "environment",
            "volumes",
            "artifact_provider",
            "resource_digests",
        },
        "upgrade intent",
    )
    if intent["schema_version"] != SCHEMA_VERSION:
        raise UpgradeJournalError("unsupported upgrade-intent schema")
    _string(intent["attempt_nonce"], HEX_RE, "upgrade attempt nonce")
    _string(intent["operation_id"], HEX_RE, "operation ID")
    _string(intent["installation_id"], HEX_RE, "installation ID")
    _string(intent["compose_project"], PROJECT_RE, "Compose project")
    _string(
        intent["target_active_pointer_sha256"],
        DIGEST_RE,
        "intent target active-release pointer",
    )
    environment = _mapping(intent["environment"], "intent environment")
    _exact_keys(
        environment,
        {
            "source_sha256",
            "target_sha256",
            "rollback_file",
            "rollback_sha256",
            "target_file",
        },
        "intent environment",
    )
    if (
        environment["rollback_file"] != ROLLBACK_ENV_NAME
        or environment["target_file"] != TARGET_ENV_NAME
    ):
        raise UpgradeJournalError("intent environment filenames are not canonical")
    for key in ("source_sha256", "target_sha256", "rollback_sha256"):
        _string(environment[key], DIGEST_RE, f"intent environment {key}")
    if environment["source_sha256"] != environment["rollback_sha256"]:
        raise UpgradeJournalError("intent rollback does not bind the source environment")
    witness_request = {
        "schema_version": WITNESS_SCHEMA_VERSION,
        "attempt_nonce": intent["attempt_nonce"],
        "installation_id": intent["installation_id"],
        "compose_project": intent["compose_project"],
        "daemon": intent["daemon"],
        "checkouts": intent["checkouts"],
        "compose": intent["compose"],
        "target_active_pointer_sha256": intent["target_active_pointer_sha256"],
        "volumes": intent["volumes"],
        "artifact_provider": intent["artifact_provider"],
    }
    normalized_request = _validate_witness_request(witness_request)
    if normalized_request != witness_request:
        raise UpgradeJournalError("intent witness request is not canonical")
    source = _validate_release_state(intent["source"], "intent source release")
    target = _validate_release_state(intent["target"], "intent target release")
    if source != intent["source"] or target != intent["target"]:
        raise UpgradeJournalError("intent release state is not canonical")
    platform = (
        f"{normalized_request['daemon']['os']}/"
        f"{normalized_request['daemon']['architecture']}"
    )
    for label, release in (("source", source), ("target", target)):
        if release["signature_verification"]["daemon_identity_sha256"] != intent[
            "daemon"
        ]["identity_sha256"]:
            raise UpgradeJournalError(f"intent {label} verification targeted another daemon")
        if any(image["platform"] != platform for image in release["images"].values()):
            raise UpgradeJournalError(f"intent {label} images target another platform")
    if not set(source["migration"]["migrations"]).issubset(
        target["migration"]["migrations"]
    ):
        raise UpgradeJournalError("intent target migration graph lost a source migration")
    if (
        source["descriptor_sha256"] == target["descriptor_sha256"]
        or source["release_tag"] == target["release_tag"]
        or source["source_commit"] == target["source_commit"]
    ):
        raise UpgradeJournalError("intent source and target releases are not distinct")
    checkouts = _mapping(intent["checkouts"], "intent checkout witnesses")
    source_checkout = _mapping(checkouts.get("source"), "intent source checkout")
    target_checkout = _mapping(checkouts.get("target"), "intent target checkout")
    if (
        source_checkout.get("commit") != source["source_commit"]
        or target_checkout.get("commit") != target["source_commit"]
    ):
        raise UpgradeJournalError("intent checkout commits differ from signed releases")
    authorization = _mapping(intent["authorization"], "intent authorization")
    _exact_keys(
        authorization,
        {
            "predecessor",
            "predecessor_sha256",
            "source_verification",
            "source_verification_file",
            "source_verification_sha256",
        },
        "intent authorization",
    )
    if authorization["predecessor"] != _predecessor_projection(source):
        raise UpgradeJournalError("intent predecessor projection changed")
    if authorization["predecessor_sha256"] != _sha256_bytes(_canonical_bytes(authorization["predecessor"])):
        raise UpgradeJournalError("intent predecessor digest changed")
    if target["accepted_predecessors"].count(authorization["predecessor"]) != 1:
        raise UpgradeJournalError("intent target no longer authorizes source")
    if authorization["source_verification_file"] != SOURCE_VERIFICATION_NAME:
        raise UpgradeJournalError("intent source-verification filename changed")
    source_verification = _validate_authorized_predecessor_verification(
        authorization["source_verification"],
        source=source,
        target=target,
        daemon=normalized_request["daemon"],
    )
    if authorization["source_verification_sha256"] != _sha256_bytes(
        _canonical_bytes(source_verification)
    ):
        raise UpgradeJournalError("intent source-verification digest changed")
    if target["release_epoch"] <= source["release_epoch"]:
        raise UpgradeJournalError("intent release epochs are not forward-only")
    expected_operation = hashlib.sha256(
        (
            "BackupSheep/signed-upgrade/v1|"
            f"{intent['installation_id']}|{source['descriptor_sha256']}|"
            f"{target['descriptor_sha256']}|{intent['attempt_nonce']}"
        ).encode("ascii")
    ).hexdigest()
    if intent["operation_id"] != expected_operation:
        raise UpgradeJournalError("intent operation ID changed")
    resource_digests = _mapping(intent["resource_digests"], "intent resource digests")
    expected_resources = {
        "volume_records_sha256": _domain_digest(
            "BackupSheep/upgrade-volumes/v1", normalized_request["volumes"]
        ),
        "artifact_provider_sha256": _domain_digest(
            "BackupSheep/upgrade-artifact-provider/v1",
            normalized_request["artifact_provider"],
        ),
    }
    if resource_digests != expected_resources:
        raise UpgradeJournalError("intent resource aggregate changed")
    return intent


def _journal_paths(install_dir: Path) -> tuple[Path, Path]:
    root = install_dir / JOURNAL_ROOT_NAME
    return root, root / OPERATIONS_NAME


def _retain_evidence(source: Path, destination: Path) -> None:
    owner = os.geteuid()
    _validate_directory(source, owner=owner)
    if not destination.exists():
        os.mkdir(destination, 0o700)
        _fsync_directory(destination.parent)
    _validate_directory(destination, owner=owner)
    source_names = {entry.name for entry in source.iterdir()}
    if source_names != set(EVIDENCE_FILES):
        raise UpgradeJournalError("source evidence file set changed during retention")
    allowed_destination = set(EVIDENCE_FILES) | {f".{name}.new" for name in EVIDENCE_FILES}
    if {entry.name for entry in destination.iterdir()} - allowed_destination:
        raise UpgradeJournalError("retained evidence contains an unexpected entry")
    for name in EVIDENCE_FILES:
        payload = _read_regular(source / name, owner=owner, modes={0o600})
        retained = destination / name
        if not _reconcile_exclusive(retained, payload, mode=0o400):
            _write_exclusive(retained, payload, mode=0o400)
    if {entry.name for entry in destination.iterdir()} != set(EVIDENCE_FILES):
        raise UpgradeJournalError("retained evidence publication is incomplete")
    _fsync_directory(destination)


def initialize_journal(
    *,
    install_dir: Path,
    source_evidence: Path,
    target_evidence: Path,
    source_env: Path,
    target_env: Path,
    source_verification: Path,
    witness_request: Path,
) -> dict[str, Any]:
    owner = os.geteuid()
    _validate_directory(install_dir, owner=owner)
    _validate_ancestor_chain(install_dir, owner=owner)
    canonical_children = {
        source_evidence: ".release-evidence",
        target_evidence: ".release-evidence.target",
        source_env: ".env",
        target_env: ".env.signed-upgrade.target",
        source_verification: ".release-evidence.source-verification.json",
        witness_request: ".signed-upgrade-witness.json",
    }
    for path, expected_name in canonical_children.items():
        if path.parent != install_dir or path.name != expected_name:
            raise UpgradeJournalError(
                f"signed upgrade input must be canonical {expected_name} under the installation"
            )
    intent, rollback = build_intent(
        source_evidence=source_evidence,
        target_evidence=target_evidence,
        source_env=source_env,
        target_env=target_env,
        source_verification=source_verification,
        witness_request=witness_request,
    )
    intent_payload = _canonical_bytes(intent)
    root, operations = _journal_paths(install_dir)
    if not root.exists():
        os.mkdir(root, 0o700)
        _fsync_directory(install_dir)
    _validate_directory(root, owner=owner)
    if not operations.exists():
        os.mkdir(operations, 0o700)
        _fsync_directory(root)
    _validate_directory(operations, owner=owner)
    if {entry.name for entry in root.iterdir()} != {OPERATIONS_NAME}:
        raise UpgradeJournalError("journal root contains an unexpected entry")
    entries = list(operations.iterdir())
    if len(entries) > MAX_COMPLETED_OPERATIONS:
        raise UpgradeJournalError("too many signed-upgrade journals")
    for entry in entries:
        if HEX_RE.fullmatch(entry.name) is None:
            raise UpgradeJournalError("journal has a noncanonical operation name")
        if entry.name == intent["operation_id"]:
            existing_names = {item.name for item in entry.iterdir()}
            if INTENT_NAME in existing_names:
                existing_intent, existing_phase = _validate_operation_directory(entry)
                if existing_intent != intent:
                    raise UpgradeJournalError("existing intent.json differs")
                if existing_phase in {"70-activated", "rolled-back"}:
                    return existing_intent
            elif ROLLBACK_RECEIPT_NAME in existing_names or any(
                name in RECEIPT_NAMES for name in existing_names
            ):
                raise UpgradeJournalError(
                    "journal has receipts without an immutable intent"
                )
            continue
        other_intent, other_phase = _validate_operation_directory(entry)
        if other_intent["operation_id"] != entry.name:
            raise UpgradeJournalError("journal operation is misnamed")
        if other_phase not in {"70-activated", "rolled-back"}:
            raise UpgradeJournalError(
                f"another signed upgrade remains open: {other_intent['operation_id']}"
            )
    active = operations / intent["operation_id"]
    if not active.exists() and len(entries) >= MAX_COMPLETED_OPERATIONS:
        raise UpgradeJournalError("signed-upgrade journal retention limit is reached")
    if not active.exists():
        os.mkdir(active, 0o700)
        _fsync_directory(operations)
    _validate_directory(active, owner=owner)
    allowed = {
        INTENT_NAME,
        ROLLBACK_ENV_NAME,
        TARGET_ENV_NAME,
        SOURCE_VERIFICATION_NAME,
        SOURCE_EVIDENCE_NAME,
        TARGET_EVIDENCE_NAME,
        f".{INTENT_NAME}.new",
        f".{ROLLBACK_ENV_NAME}.new",
        f".{TARGET_ENV_NAME}.new",
        f".{SOURCE_VERIFICATION_NAME}.new",
        ROLLBACK_RECEIPT_NAME,
        f".{ROLLBACK_RECEIPT_NAME}.new",
    }
    allowed.update(RECEIPT_NAMES)
    allowed.update(f".{name}.new" for name in RECEIPT_NAMES)
    if any(entry.name not in allowed for entry in active.iterdir()):
        raise UpgradeJournalError("active journal contains an unexpected entry")

    _retain_evidence(source_evidence, active / SOURCE_EVIDENCE_NAME)
    _retain_evidence(target_evidence, active / TARGET_EVIDENCE_NAME)
    rollback_path = active / ROLLBACK_ENV_NAME
    if not _reconcile_exclusive(rollback_path, rollback, mode=0o400):
        _write_exclusive(rollback_path, rollback, mode=0o400)
    target_env_payload = _read_regular(target_env, owner=owner, modes={0o600})
    if _sha256_bytes(target_env_payload) != intent["environment"]["target_sha256"]:
        raise UpgradeJournalError("target environment changed during journal initialization")
    target_env_path = active / TARGET_ENV_NAME
    if not _reconcile_exclusive(target_env_path, target_env_payload, mode=0o400):
        _write_exclusive(target_env_path, target_env_payload, mode=0o400)
    source_verification_payload = _read_regular(
        source_verification, owner=owner, modes={0o600}
    )
    if _sha256_bytes(source_verification_payload) != intent["authorization"][
        "source_verification_sha256"
    ]:
        raise UpgradeJournalError(
            "authorized-predecessor verification changed during journal initialization"
        )
    source_verification_path = active / SOURCE_VERIFICATION_NAME
    if not _reconcile_exclusive(
        source_verification_path, source_verification_payload, mode=0o400
    ):
        _write_exclusive(
            source_verification_path, source_verification_payload, mode=0o400
        )
    intent_path = active / INTENT_NAME
    if not _reconcile_exclusive(intent_path, intent_payload, mode=0o400):
        _write_exclusive(intent_path, intent_payload, mode=0o400)
    _fsync_directory(active)
    _validate_ancestor_chain(install_dir, owner=owner)
    validate_journal(install_dir, operation_id=intent["operation_id"])
    return intent


def _load_intent(active: Path) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular(
        active / INTENT_NAME,
        maximum=MAX_JOURNAL_BYTES,
        owner=os.geteuid(),
        modes={0o400},
    )
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpgradeJournalError("upgrade intent is not strict JSON") from exc
    if payload != _canonical_bytes(value):
        raise UpgradeJournalError("upgrade intent bytes are not canonical")
    return _validate_intent(value), payload


def _validate_operation_directory(
    active: Path, *, allow_interrupted_phase: str | None = None
) -> tuple[dict[str, Any], str | None]:
    owner = os.geteuid()
    _validate_directory(active, owner=owner)
    intent, intent_payload = _load_intent(active)
    rollback = _read_regular(active / ROLLBACK_ENV_NAME, owner=owner, modes={0o400})
    if _sha256_bytes(rollback) != intent["environment"]["rollback_sha256"]:
        raise UpgradeJournalError("protected rollback environment changed")
    target_environment = _read_regular(
        active / TARGET_ENV_NAME, owner=owner, modes={0o400}
    )
    if _sha256_bytes(target_environment) != intent["environment"]["target_sha256"]:
        raise UpgradeJournalError("protected target environment changed")
    source_verification_payload = _read_regular(
        active / SOURCE_VERIFICATION_NAME,
        owner=owner,
        modes={0o400},
    )
    if source_verification_payload != _canonical_bytes(
        intent["authorization"]["source_verification"]
    ) or _sha256_bytes(source_verification_payload) != intent["authorization"][
        "source_verification_sha256"
    ]:
        raise UpgradeJournalError("retained authorized-predecessor verification changed")
    retained_source = build_release_state(
        active / SOURCE_EVIDENCE_NAME,
        f"{intent['daemon']['os']}/{intent['daemon']['architecture']}",
        file_modes={0o400},
    )
    retained_target = build_release_state(
        active / TARGET_EVIDENCE_NAME,
        f"{intent['daemon']['os']}/{intent['daemon']['architecture']}",
        file_modes={0o400},
    )
    if retained_source != intent["source"] or retained_target != intent["target"]:
        raise UpgradeJournalError("retained release evidence differs from immutable intent")
    allowed = {
        INTENT_NAME,
        ROLLBACK_ENV_NAME,
        TARGET_ENV_NAME,
        SOURCE_VERIFICATION_NAME,
        SOURCE_EVIDENCE_NAME,
        TARGET_EVIDENCE_NAME,
        ROLLBACK_RECEIPT_NAME,
        *RECEIPT_NAMES,
    }
    temporary_names = {
        f".{INTENT_NAME}.new",
        f".{ROLLBACK_ENV_NAME}.new",
        f".{TARGET_ENV_NAME}.new",
        f".{SOURCE_VERIFICATION_NAME}.new",
        f".{ROLLBACK_RECEIPT_NAME}.new",
        *(f".{name}.new" for name in RECEIPT_NAMES),
    }
    names = {entry.name for entry in active.iterdir()}
    unexpected = names - allowed - temporary_names
    if unexpected:
        raise UpgradeJournalError(f"active journal contains unexpected entries: {sorted(unexpected)}")
    present_temporaries = names & temporary_names
    allowed_temporary = (
        {
            f".{ROLLBACK_RECEIPT_NAME}.new"
            if allow_interrupted_phase == "rolled-back"
            else f".{allow_interrupted_phase}.json.new"
        }
        if allow_interrupted_phase in {*PHASES, "rolled-back"}
        else set()
    )
    if present_temporaries - allowed_temporary:
        raise UpgradeJournalError("active journal has an interrupted publication requiring exact retry")
    intent_digest = _sha256_bytes(intent_payload)
    previous_digest = "sha256:" + "0" * 64
    highest: str | None = None
    gap_seen = False
    for phase, receipt_name in zip(PHASES, RECEIPT_NAMES, strict=True):
        path = active / receipt_name
        if receipt_name not in names:
            gap_seen = True
            continue
        if gap_seen:
            raise UpgradeJournalError("upgrade receipt chain has a gap")
        payload = _read_regular(
            path,
            maximum=MAX_JOURNAL_BYTES,
            owner=owner,
            modes={0o400},
            links={1, 2} if phase == allow_interrupted_phase else {1},
        )
        try:
            receipt = json.loads(payload, object_pairs_hook=_reject_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpgradeJournalError(f"{receipt_name} is not strict JSON") from exc
        if payload != _canonical_bytes(receipt):
            raise UpgradeJournalError(f"{receipt_name} is not canonical")
        receipt = _mapping(receipt, receipt_name)
        _exact_keys(
            receipt,
            {"schema_version", "phase", "operation_id", "installation_id", "intent_sha256", "previous_receipt_sha256", "payload"},
            receipt_name,
        )
        if receipt["schema_version"] != SCHEMA_VERSION or receipt["phase"] != phase:
            raise UpgradeJournalError(f"{receipt_name} phase or schema changed")
        if receipt["operation_id"] != intent["operation_id"] or receipt["installation_id"] != intent["installation_id"]:
            raise UpgradeJournalError(f"{receipt_name} belongs to another operation")
        if receipt["intent_sha256"] != intent_digest or receipt["previous_receipt_sha256"] != previous_digest:
            raise UpgradeJournalError(f"{receipt_name} hash chain changed")
        _validate_phase_payload(phase, receipt["payload"], intent)
        previous_digest = _sha256_bytes(payload)
        highest = phase
    if ROLLBACK_RECEIPT_NAME in names:
        if highest is not None and PHASES.index(highest) >= PHASES.index(
            "40-forward-only"
        ):
            raise UpgradeJournalError("rollback receipt exists after forward-only boundary")
        rollback_payload = _read_regular(
            active / ROLLBACK_RECEIPT_NAME,
            maximum=MAX_JOURNAL_BYTES,
            owner=owner,
            modes={0o400},
            links={1, 2} if allow_interrupted_phase == "rolled-back" else {1},
        )
        try:
            rollback_receipt = json.loads(
                rollback_payload, object_pairs_hook=_reject_duplicates
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpgradeJournalError("rollback receipt is not strict JSON") from exc
        if rollback_payload != _canonical_bytes(rollback_receipt):
            raise UpgradeJournalError("rollback receipt is not canonical")
        rollback_receipt = _mapping(rollback_receipt, "rollback receipt")
        _exact_keys(
            rollback_receipt,
            {
                "schema_version",
                "operation_id",
                "installation_id",
                "outcome",
                "intent_sha256",
                "previous_receipt_sha256",
                "payload",
            },
            "rollback receipt",
        )
        if (
            rollback_receipt["schema_version"] != SCHEMA_VERSION
            or rollback_receipt["operation_id"] != intent["operation_id"]
            or rollback_receipt["installation_id"] != intent["installation_id"]
            or rollback_receipt["outcome"] != "rolled-back"
            or rollback_receipt["intent_sha256"] != intent_digest
            or rollback_receipt["previous_receipt_sha256"] != previous_digest
        ):
            raise UpgradeJournalError("rollback receipt identity or hash chain changed")
        _validate_rollback_payload(rollback_receipt["payload"], intent)
        return intent, "rolled-back"
    return intent, highest


def validate_journal(
    install_dir: Path,
    *,
    operation_id: str | None = None,
    allow_interrupted_phase: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    owner = os.geteuid()
    _validate_directory(install_dir, owner=owner)
    _validate_ancestor_chain(install_dir, owner=owner)
    root, operations = _journal_paths(install_dir)
    _validate_directory(root, owner=owner)
    _validate_directory(operations, owner=owner)
    root_names = {entry.name for entry in root.iterdir()}
    if root_names != {OPERATIONS_NAME}:
        raise UpgradeJournalError("journal root contains an unexpected entry")
    entries = sorted(operations.iterdir(), key=lambda item: item.name)
    if not entries or len(entries) > MAX_COMPLETED_OPERATIONS:
        raise UpgradeJournalError("journal has an invalid operation count")
    if operation_id is not None:
        _string(operation_id, HEX_RE, "operation ID")
    selected: tuple[dict[str, Any], str | None] | None = None
    open_operations: list[str] = []
    completed_operations: list[tuple[dict[str, Any], str | None]] = []
    for entry in entries:
        if HEX_RE.fullmatch(entry.name) is None:
            raise UpgradeJournalError("journal has a noncanonical operation name")
        if entry.is_symlink():
            raise UpgradeJournalError("journal operation must not be a symlink")
        result = _validate_operation_directory(
            entry,
            allow_interrupted_phase=(
                allow_interrupted_phase if entry.name == operation_id else None
            ),
        )
        intent, highest = result
        if intent["operation_id"] != entry.name:
            raise UpgradeJournalError("journal operation is misnamed")
        if highest in {"70-activated", "rolled-back"}:
            completed_operations.append(result)
        else:
            open_operations.append(entry.name)
        if operation_id == entry.name:
            selected = result
    if len(open_operations) > 1:
        raise UpgradeJournalError("more than one signed upgrade remains open")
    if operation_id is not None:
        if selected is None:
            raise UpgradeJournalError("requested signed-upgrade operation does not exist")
        return selected
    if open_operations:
        open_name = open_operations[0]
        return _validate_operation_directory(
            operations / open_name,
            allow_interrupted_phase=allow_interrupted_phase,
        )
    if len(completed_operations) != 1:
        raise UpgradeJournalError(
            "completed journal selection is ambiguous; specify the operation ID"
        )
    return completed_operations[0]


def append_receipt(
    *, install_dir: Path, operation_id: str, phase: str, payload_path: Path
) -> dict[str, Any]:
    if phase not in PHASES:
        raise UpgradeJournalError("receipt phase is unsupported")
    _string(operation_id, HEX_RE, "operation ID")
    intent, highest = validate_journal(
        install_dir,
        operation_id=operation_id,
        allow_interrupted_phase=phase,
    )
    if highest == "rolled-back":
        raise UpgradeJournalError("rolled-back operation is permanently terminal")
    expected_index = 0 if highest is None else PHASES.index(highest) + 1
    phase_index = PHASES.index(phase)
    if (
        payload_path.parent != install_dir
        or re.fullmatch(r"\.[a-z0-9-]{1,64}\.payload\.json", payload_path.name) is None
    ):
        raise UpgradeJournalError("receipt payload path is not a canonical installation child")
    payload = _validate_phase_payload(
        phase,
        _load_json(
            payload_path,
            maximum=MAX_JOURNAL_BYTES,
            owner=os.geteuid(),
            modes={0o600},
        ),
        intent,
    )
    _, operations = _journal_paths(install_dir)
    active = operations / operation_id
    path = active / f"{phase}.json"
    if phase_index < expected_index:
        existing_bytes = _read_regular(
            path,
            maximum=MAX_JOURNAL_BYTES,
            owner=os.geteuid(),
            modes={0o400},
            links={1, 2},
        )
        try:
            existing = json.loads(existing_bytes, object_pairs_hook=_reject_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpgradeJournalError("existing receipt is not strict JSON") from exc
        if existing.get("payload") != payload:
            raise UpgradeJournalError("existing receipt differs from retry payload")
        _reconcile_exclusive(path, _canonical_bytes(existing), mode=0o400)
        validate_journal(install_dir, operation_id=operation_id)
        return existing
    if phase_index != expected_index:
        raise UpgradeJournalError("receipt phase is not the next contiguous phase")
    intent_payload = _read_regular(
        active / INTENT_NAME,
        maximum=MAX_JOURNAL_BYTES,
        owner=os.geteuid(),
        modes={0o400},
    )
    previous_digest = "sha256:" + "0" * 64
    if phase_index:
        previous_digest = _sha256_bytes(
            _read_regular(
                active / RECEIPT_NAMES[phase_index - 1],
                maximum=MAX_JOURNAL_BYTES,
                owner=os.geteuid(),
                modes={0o400},
            )
        )
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "phase": phase,
        "operation_id": intent["operation_id"],
        "installation_id": intent["installation_id"],
        "intent_sha256": _sha256_bytes(intent_payload),
        "previous_receipt_sha256": previous_digest,
        "payload": payload,
    }
    receipt_bytes = _canonical_bytes(receipt)
    if not _reconcile_exclusive(path, receipt_bytes, mode=0o400):
        _write_exclusive(path, receipt_bytes, mode=0o400)
    _fsync_directory(active)
    _, resulting_phase = validate_journal(install_dir, operation_id=operation_id)
    if resulting_phase != phase:
        raise UpgradeJournalError("receipt did not become the highest durable phase")
    return receipt


def append_rollback(
    *, install_dir: Path, operation_id: str, payload_path: Path
) -> dict[str, Any]:
    _string(operation_id, HEX_RE, "operation ID")
    intent, highest = validate_journal(
        install_dir,
        operation_id=operation_id,
        allow_interrupted_phase="rolled-back",
    )
    if (
        payload_path.parent != install_dir
        or payload_path.name != ".rollback.payload.json"
    ):
        raise UpgradeJournalError("rollback payload path is not canonical")
    payload = _validate_rollback_payload(
        _load_json(
            payload_path,
            maximum=MAX_JOURNAL_BYTES,
            owner=os.geteuid(),
            modes={0o600},
        ),
        intent,
    )
    _, operations = _journal_paths(install_dir)
    operation = operations / operation_id
    path = operation / ROLLBACK_RECEIPT_NAME
    if highest == "rolled-back":
        existing_payload = _read_regular(
            path,
            maximum=MAX_JOURNAL_BYTES,
            owner=os.geteuid(),
            modes={0o400},
            links={1, 2},
        )
        try:
            existing = json.loads(existing_payload, object_pairs_hook=_reject_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpgradeJournalError("existing rollback receipt is not strict JSON") from exc
        if existing.get("payload") != payload:
            raise UpgradeJournalError("existing rollback receipt differs from retry payload")
        _reconcile_exclusive(path, _canonical_bytes(existing), mode=0o400)
        validate_journal(install_dir, operation_id=operation_id)
        return existing
    if highest is not None and PHASES.index(highest) >= PHASES.index("40-forward-only"):
        raise UpgradeJournalError("rollback is forbidden after the forward-only boundary")
    intent_payload = _read_regular(
        operation / INTENT_NAME,
        maximum=MAX_JOURNAL_BYTES,
        owner=os.geteuid(),
        modes={0o400},
    )
    previous_digest = "sha256:" + "0" * 64
    if highest is not None:
        previous_digest = _sha256_bytes(
            _read_regular(
                operation / f"{highest}.json",
                maximum=MAX_JOURNAL_BYTES,
                owner=os.geteuid(),
                modes={0o400},
            )
        )
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "operation_id": operation_id,
        "installation_id": intent["installation_id"],
        "outcome": "rolled-back",
        "intent_sha256": _sha256_bytes(intent_payload),
        "previous_receipt_sha256": previous_digest,
        "payload": payload,
    }
    receipt_bytes = _canonical_bytes(receipt)
    if not _reconcile_exclusive(path, receipt_bytes, mode=0o400):
        _write_exclusive(path, receipt_bytes, mode=0o400)
    _fsync_directory(operation)
    _, resulting_phase = validate_journal(install_dir, operation_id=operation_id)
    if resulting_phase != "rolled-back":
        raise UpgradeJournalError("rollback did not become the terminal durable outcome")
    return receipt


def finalize_completed(*, install_dir: Path, operation_id: str) -> str:
    intent, highest = validate_journal(install_dir, operation_id=operation_id)
    if highest != "70-activated":
        raise UpgradeJournalError("only a fully activated journal may be finalized")
    return intent["operation_id"]


def journal_status(*, install_dir: Path, operation_id: str | None = None) -> dict[str, Any]:
    intent, highest = validate_journal(install_dir, operation_id=operation_id)
    terminal = highest in {"70-activated", "rolled-back"}
    next_phase = None if terminal else PHASES[0 if highest is None else PHASES.index(highest) + 1]
    forward_only = highest not in {None, "rolled-back"} and PHASES.index(
        highest
    ) >= PHASES.index("40-forward-only")
    state_by_phase = {
        None: "intent",
        "10-prepared": "prepared",
        "20-stopped": "stopped",
        "30-switched": "switched",
        "40-forward-only": "forward-only",
        "50-migrated": "migrated",
        "60-core-accepted": "core-accepted",
        "70-activated": "activated",
        "rolled-back": "rolled-back",
    }
    _, operations = _journal_paths(install_dir)
    operation = operations / intent["operation_id"]
    if highest is None:
        head = "sha256:" + "0" * 64
    else:
        receipt_name = (
            ROLLBACK_RECEIPT_NAME if highest == "rolled-back" else f"{highest}.json"
        )
        head = _sha256_bytes(
            _read_regular(
                operation / receipt_name,
                maximum=MAX_JOURNAL_BYTES,
                owner=os.geteuid(),
                modes={0o400},
            )
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "forward_only": forward_only,
        "highest_phase": highest or "intent",
        "next_phase": next_phase,
        "operation_id": intent["operation_id"],
        "rollback_eligible": not forward_only and not terminal,
        "source_release_tag": intent["source"]["release_tag"],
        "source_execution_allowed": not forward_only,
        "state": state_by_phase[highest],
        "target_release_tag": intent["target"]["release_tag"],
        "terminal": terminal,
        "terminal_outcome": (
            "activated"
            if highest == "70-activated"
            else "rolled-back" if highest == "rolled-back" else None
        ),
        "receipt_chain_head_sha256": head,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    authorize = subparsers.add_parser("authorize-source")
    authorize.add_argument("--source-evidence", type=Path, required=True)
    authorize.add_argument("--target-evidence", type=Path, required=True)
    authorize.add_argument("--daemon-os", choices=("linux",), required=True)
    authorize.add_argument(
        "--daemon-architecture", choices=("amd64", "arm64"), required=True
    )
    authorize.add_argument("--daemon-identity-sha256", required=True)
    initialize = subparsers.add_parser("initialize")
    initialize.add_argument("--install-dir", type=Path, required=True)
    initialize.add_argument("--source-evidence", type=Path, required=True)
    initialize.add_argument("--target-evidence", type=Path, required=True)
    initialize.add_argument("--source-env", type=Path, required=True)
    initialize.add_argument("--target-env", type=Path, required=True)
    initialize.add_argument("--source-verification", type=Path, required=True)
    initialize.add_argument("--witness-request", type=Path, required=True)
    status = subparsers.add_parser("status")
    status.add_argument("--install-dir", type=Path, required=True)
    status.add_argument("--operation-id")
    append = subparsers.add_parser("append")
    append.add_argument("--install-dir", type=Path, required=True)
    append.add_argument("--operation-id", required=True)
    append.add_argument("--phase", choices=PHASES, required=True)
    append.add_argument("--payload", type=Path, required=True)
    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--install-dir", type=Path, required=True)
    rollback.add_argument("--operation-id", required=True)
    rollback.add_argument("--payload", type=Path, required=True)
    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--install-dir", type=Path, required=True)
    finalize.add_argument("--operation-id", required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "authorize-source":
            sys.stdout.buffer.write(
                _canonical_bytes(
                    build_authorized_predecessor_verification(
                        source_evidence=arguments.source_evidence,
                        target_evidence=arguments.target_evidence,
                        daemon_os=arguments.daemon_os,
                        daemon_architecture=arguments.daemon_architecture,
                        daemon_identity_sha256=arguments.daemon_identity_sha256,
                    )
                )
            )
        elif arguments.command == "initialize":
            intent = initialize_journal(
                install_dir=arguments.install_dir,
                source_evidence=arguments.source_evidence,
                target_evidence=arguments.target_evidence,
                source_env=arguments.source_env,
                target_env=arguments.target_env,
                source_verification=arguments.source_verification,
                witness_request=arguments.witness_request,
            )
            print(intent["operation_id"])
        elif arguments.command == "status":
            sys.stdout.buffer.write(
                _canonical_bytes(
                    journal_status(
                        install_dir=arguments.install_dir,
                        operation_id=arguments.operation_id,
                    )
                )
            )
        elif arguments.command == "append":
            append_receipt(
                install_dir=arguments.install_dir,
                operation_id=arguments.operation_id,
                phase=arguments.phase,
                payload_path=arguments.payload,
            )
            print(arguments.phase)
        elif arguments.command == "rollback":
            append_rollback(
                install_dir=arguments.install_dir,
                operation_id=arguments.operation_id,
                payload_path=arguments.payload,
            )
            print("rolled-back")
        else:
            print(
                finalize_completed(
                    install_dir=arguments.install_dir,
                    operation_id=arguments.operation_id,
                )
            )
        return 0
    except (
        OSError,
        KeyError,
        TypeError,
        IndexError,
        UpgradeJournalError,
        release_transition.TransitionContractError,
    ) as exc:
        print(f"signed release transition refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
