#!/usr/bin/env python3
"""Validate and durably journal one authorized signed-release transition.

This module is intentionally application- and database-free.  The installer
executes it from an already authenticated application image in a networkless,
read-only container.  It never decides whether a Docker or database operation
succeeded; it only accepts exact installer-produced evidence and commits a
strict, hash-chained phase record.

The attempt nonce distinguishes idempotent initialization beneath one exact
lineage parent; it is not a globally unique authorization token.  A durable
rollback may therefore start the same authorized source-to-target request
again under the new rolled-back parent, while an activated target cannot be
replayed because the active-release and epoch gates have advanced.

The journal assumes its owner-controlled filesystem remains the trusted local
state boundary.  Hashes, no-clobber publication, and compare-and-swap detect
partial deletion, forks, and torn writes, but cannot detect restoration of the
entire journal and installation to one older coherent filesystem snapshot.
That stronger threat model requires an external monotonic anchor (for example,
a remote transparency witness or TPM-backed counter) and is deliberately not
claimed here.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import release_transition


SCHEMA_VERSION = 2
WITNESS_SCHEMA_VERSION = 3
MAX_CONTROL_BYTES = 1024 * 1024
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_RETAINED_OPERATIONS = 64
COMPACTION_RETAIN_OPERATIONS = 32
MAX_LINEAGE_RECORDS = 512
JOURNAL_ROOT_NAME = ".release-transition-journal"
OPERATIONS_NAME = "operations"
LINEAGE_NAME = "lineage"
PRUNING_NAME = "pruning"
HEAD_NAME = "HEAD.json"
LOCK_NAME = "journal.lock"
CHECKPOINT_NAME = "checkpoint.json"
NEXT_CHECKPOINT_NAME = ".checkpoint.json.new"
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
SERVICE_IMAGE_ROLES = {
    **{service: "app" for service in ALL_SERVICES},
    "db": "postgres",
    "rabbitmq": "rabbitmq",
    "rabbitmq-volume-init": "rabbitmq",
    "rabbitmq-provision": "rabbitmq",
    **{
        service: "egress"
        for service in ALL_SERVICES
        if service.endswith("egress-guard")
    },
}
INTERNAL_NETWORK_ROLES = (
    "app-database",
    "app-broker",
    "migrate-database",
    "cloud-database",
    "cloud-broker",
    "database-database",
    "database-broker",
    "files-database",
    "files-broker",
    "storage-database",
    "storage-broker",
    "logs-database",
    "logs-broker",
    "beat-database",
    "beat-broker",
    "preflight-database",
    "preflight-broker",
    "provision-database",
    "provision-broker",
)
EGRESS_NETWORK_ROLES = (
    "app-egress",
    "cloud-egress",
    "database-egress",
    "files-egress",
    "storage-egress",
    "logs-egress",
)
NETWORK_ROLES = INTERNAL_NETWORK_ROLES + EGRESS_NETWORK_ROLES
CORE_NETWORK_ROLES = INTERNAL_NETWORK_ROLES + ("app-egress",)
SERVICE_NETWORK_ENDPOINTS = {
    "db": tuple(network for network in INTERNAL_NETWORK_ROLES if network.endswith("-database")),
    "rabbitmq": tuple(network for network in INTERNAL_NETWORK_ROLES if network.endswith("-broker")),
    "rabbitmq-provision": ("provision-broker",),
    "db-provision": ("provision-database",),
    "db-seal": ("provision-database",),
    "migrate": ("migrate-database",),
    "preflight": ("preflight-database", "preflight-broker"),
    "app-egress-guard": ("app-database", "app-broker", "app-egress"),
    "cloud-egress-guard": ("cloud-database", "cloud-broker", "cloud-egress"),
    "database-egress-guard": (
        "database-database",
        "database-broker",
        "database-egress",
    ),
    "files-egress-guard": ("files-database", "files-broker", "files-egress"),
    "storage-egress-guard": (
        "storage-database",
        "storage-broker",
        "storage-egress",
    ),
    "logs-egress-guard": ("logs-database", "logs-broker", "logs-egress"),
    "beat": ("beat-database", "beat-broker"),
}
ZERO_HEX = "0" * 64
ZERO_DIGEST = "sha256:" + ZERO_HEX
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


def _exact_positive_integer(value: Any, expected: int, label: str) -> int:
    normalized = _positive_integer(value, label)
    if normalized != expected:
        raise UpgradeJournalError(f"{label} is unsupported")
    return normalized


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


def _atomic_replace(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    expected_previous: bytes | None,
) -> None:
    """Durably compare-and-swap one canonical control file.

    A surviving candidate is never interpreted as permission to overwrite a
    different head.  Exact old/new bytes are the CAS token, so a crash may be
    retried but concurrent or forked writers fail closed.
    """

    owner = os.geteuid()
    temporary = path.with_name(f".{path.name}.new")
    final_exists = path.exists() or path.is_symlink()
    temporary_exists = temporary.exists() or temporary.is_symlink()
    current: bytes | None = None
    if final_exists:
        current = _read_regular(path, owner=owner, modes={mode})
        if current == payload:
            if temporary_exists:
                candidate = _read_regular(
                    temporary,
                    owner=owner,
                    modes={mode},
                    links={1},
                    allow_empty=True,
                )
                if candidate != payload:
                    if not payload.startswith(candidate):
                        raise UpgradeJournalError(
                            f"interrupted replacement for {path.name} differs"
                        )
                os.unlink(temporary)
                _fsync_directory(path.parent)
            return
        if expected_previous is None or current != expected_previous:
            raise UpgradeJournalError(f"{path.name} compare-and-swap precondition failed")
    elif expected_previous is not None:
        raise UpgradeJournalError(f"{path.name} disappeared before compare-and-swap")

    if temporary_exists:
        candidate = _read_regular(
            temporary,
            owner=owner,
            modes={mode},
            links={1},
            allow_empty=True,
        )
        if candidate != payload:
            if not payload.startswith(candidate):
                raise UpgradeJournalError(
                    f"interrupted replacement for {path.name} differs"
                )
            os.unlink(temporary)
            _fsync_directory(path.parent)
            temporary_exists = False
        else:
            _fsync_regular(temporary, owner=owner, mode=mode)
    if not temporary_exists:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(temporary, flags, mode)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise UpgradeJournalError(
                        f"short write while replacing {path.name}"
                    )
                offset += written
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(path.parent)

    if path.exists() or path.is_symlink():
        current = _read_regular(path, owner=owner, modes={mode})
        if expected_previous is None or current != expected_previous:
            raise UpgradeJournalError(f"{path.name} changed during compare-and-swap")
    elif expected_previous is not None:
        raise UpgradeJournalError(f"{path.name} disappeared during compare-and-swap")
    os.replace(temporary, path)
    _fsync_directory(path.parent)
    if _read_regular(path, owner=owner, modes={mode}) != payload:
        raise UpgradeJournalError(f"{path.name} replacement did not persist exact bytes")


def _create_control_file(path: Path, *, mode: int) -> None:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _ensure_journal_layout(install_dir: Path) -> tuple[Path, Path]:
    owner = os.geteuid()
    root = install_dir / JOURNAL_ROOT_NAME
    operations = root / OPERATIONS_NAME
    lineage = root / LINEAGE_NAME
    pruning = root / PRUNING_NAME
    if not root.exists() and not root.is_symlink():
        try:
            os.mkdir(root, 0o700)
            _fsync_directory(install_dir)
        except FileExistsError:
            pass
    _validate_directory(root, owner=owner)
    for directory in (operations, lineage, pruning):
        if not directory.exists() and not directory.is_symlink():
            try:
                os.mkdir(directory, 0o700)
                _fsync_directory(root)
            except FileExistsError:
                pass
        _validate_directory(directory, owner=owner)
    lock_path = root / LOCK_NAME
    if not lock_path.exists() and not lock_path.is_symlink():
        try:
            _create_control_file(lock_path, mode=0o600)
        except FileExistsError:
            pass
    _read_regular(
        lock_path,
        maximum=0,
        owner=owner,
        modes={0o600},
        allow_empty=True,
    )
    return root, operations


@contextmanager
def _journal_lock(install_dir: Path):
    owner = os.geteuid()
    root, operations = _journal_paths(install_dir)
    lineage = root / LINEAGE_NAME
    pruning = root / PRUNING_NAME
    _validate_directory(install_dir, owner=owner)
    _validate_ancestor_chain(install_dir, owner=owner)
    _validate_directory(root, owner=owner)
    for directory in (operations, lineage, pruning):
        _validate_directory(directory, owner=owner)
    lock_path = root / LOCK_NAME
    flags = (
        os.O_RDWR
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(lock_path, flags)
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != os.geteuid()
            or stat.S_IMODE(file_stat.st_mode) != 0o600
            or file_stat.st_nlink != 1
            or file_stat.st_size != 0
        ):
            raise UpgradeJournalError("journal lock has an unsafe identity")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise UpgradeJournalError("another journal operation holds the lock") from exc
        # Re-prove the canonical layout after serialization and before any
        # caller performs recovery cleanup or publication.
        _validate_directory(install_dir, owner=owner)
        _validate_ancestor_chain(install_dir, owner=owner)
        _validate_directory(root, owner=owner)
        for directory in (operations, lineage, pruning):
            _validate_directory(directory, owner=owner)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
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
    exact_maximum = max(1, len(payload))
    final_exists = path.exists() or path.is_symlink()
    temporary_exists = temporary.exists() or temporary.is_symlink()
    if not final_exists and not temporary_exists:
        return False
    owner = os.geteuid()
    if temporary_exists:
        temporary_payload = _read_regular(
            temporary,
            maximum=exact_maximum,
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
        final_payload = _read_regular(
            path,
            maximum=exact_maximum,
            owner=owner,
            modes={mode},
            links={1, 2},
        )
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
    _read_regular(path, maximum=exact_maximum, owner=owner, modes={mode})
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
    runtime_contract_version = _exact_positive_integer(
        verifier["runtime_contract_version"],
        1,
        "manifest verifier runtime contract",
    )
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
        "runtime_contract_version": runtime_contract_version,
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
    _exact_positive_integer(manifest["schema_version"], 4, "release manifest schema")
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
    verification = dict(
        _mapping(verification, "signature-verification receipt")
    )
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
    verification["schema_version"] = _exact_positive_integer(
        verification["schema_version"], 2, "signature-verification schema"
    )
    verification["runtime_contract_version"] = _exact_positive_integer(
        verification["runtime_contract_version"],
        1,
        "signature-verification runtime contract",
    )
    verification["release_epoch"] = _positive_integer(
        verification["release_epoch"], "signature-verification release epoch"
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
    receipt = dict(
        _mapping(value, "authorized-predecessor verification receipt")
    )
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
    receipt["schema_version"] = _exact_positive_integer(
        receipt["schema_version"], 3, "authorized-predecessor schema"
    )
    receipt["verifier_runtime_contract_version"] = _exact_positive_integer(
        receipt["verifier_runtime_contract_version"],
        1,
        "authorized-predecessor verifier runtime contract",
    )
    receipt["source_release_epoch"] = _positive_integer(
        receipt["source_release_epoch"],
        "authorized-predecessor source release epoch",
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
    verification = dict(_mapping(value, label))
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
    verification["schema_version"] = _exact_positive_integer(
        verification["schema_version"], 2, f"{label} schema"
    )
    verification["runtime_contract_version"] = _exact_positive_integer(
        verification["runtime_contract_version"],
        1,
        f"{label} runtime contract",
    )
    verification["release_epoch"] = _positive_integer(
        verification["release_epoch"], f"{label} release epoch"
    )
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


def _validate_compose_contract(value: Any, label: str) -> dict[str, Any]:
    contract = _mapping(value, label)
    _exact_keys(
        contract,
        {"model_sha256", "service_config_sha256", "network_config_sha256"},
        label,
    )
    service_values = _mapping(
        contract["service_config_sha256"], f"{label} service configs"
    )
    _exact_keys(service_values, set(ALL_SERVICES), f"{label} service configs")
    network_values = _mapping(
        contract["network_config_sha256"], f"{label} network configs"
    )
    _exact_keys(network_values, set(NETWORK_ROLES), f"{label} network configs")
    normalized = {
        "service_config_sha256": {
            service: _string(
                service_values[service], DIGEST_RE, f"{label} {service} config"
            )
            for service in ALL_SERVICES
        },
        "network_config_sha256": {
            network: _string(
                network_values[network], DIGEST_RE, f"{label} {network} config"
            )
            for network in NETWORK_ROLES
        },
    }
    model = _string(contract["model_sha256"], DIGEST_RE, f"{label} model")
    expected_model = _domain_digest(
        "BackupSheep/upgrade-compose-model/v1", normalized
    )
    if model != expected_model:
        raise UpgradeJournalError(f"{label} model digest is inconsistent")
    return {"model_sha256": model, **normalized}


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
            "active_pointer_sha256",
            "source_activation_mode",
            "volumes",
            "artifact_provider",
        },
        "upgrade witness request",
    )
    _exact_positive_integer(
        request["schema_version"],
        WITNESS_SCHEMA_VERSION,
        "upgrade witness schema",
    )
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
    compose_value = _mapping(request["compose"], "Compose witness")
    _exact_keys(compose_value, {"source", "target"}, "Compose witness")
    compose = {
        side: _validate_compose_contract(
            compose_value[side], f"Compose {side} contract"
        )
        for side in ("source", "target")
    }
    active_pointer_value = _mapping(
        request["active_pointer_sha256"], "active-release pointers"
    )
    _exact_keys(
        active_pointer_value, {"source", "target"}, "active-release pointers"
    )
    active_pointer_sha256 = {
        side: _string(
            active_pointer_value[side],
            DIGEST_RE,
            f"{side} active-release pointer",
        )
        for side in ("source", "target")
    }
    source_activation_mode = request["source_activation_mode"]
    if source_activation_mode not in {"core-only", "operations"}:
        raise UpgradeJournalError("source activation mode is unsupported")
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
        "active_pointer_sha256": active_pointer_sha256,
        "source_activation_mode": source_activation_mode,
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
    source_env_sha256 = _sha256_bytes(source_env_bytes)
    target_env_sha256 = _sha256_bytes(target_env_bytes)
    expected_pointers = {
        "source": _active_release_pointer_digest(
            release=source,
            checkout=request["checkouts"]["source"],
            environment_sha256=source_env_sha256,
            compose=request["compose"]["source"],
        ),
        "target": _active_release_pointer_digest(
            release=target,
            checkout=request["checkouts"]["target"],
            environment_sha256=target_env_sha256,
            compose=request["compose"]["target"],
        ),
    }
    if request["active_pointer_sha256"] != expected_pointers:
        raise UpgradeJournalError(
            "active-release pointer digest is not derived from the signed state"
        )
    if expected_pointers["source"] == expected_pointers["target"]:
        raise UpgradeJournalError("source and target active-release pointers collide")
    intent = {
        "schema_version": SCHEMA_VERSION,
        "attempt_nonce": request["attempt_nonce"],
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
        "active_pointer_sha256": expected_pointers,
        "source_activation_mode": request["source_activation_mode"],
        "environment": {
            "source_sha256": source_env_sha256,
            "target_sha256": target_env_sha256,
            "rollback_file": ROLLBACK_ENV_NAME,
            "rollback_sha256": source_env_sha256,
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


def _active_release_pointer_digest(
    *,
    release: dict[str, Any],
    checkout: dict[str, Any],
    environment_sha256: str,
    compose: dict[str, Any],
) -> str:
    return _domain_digest(
        "BackupSheep/active-signed-release/v1",
        {
            "release": _lineage_release_projection(release),
            "checkout_sha256": _domain_digest(
                "BackupSheep/upgrade-checkout/v1", checkout
            ),
            "environment_sha256": environment_sha256,
            "compose_model_sha256": compose["model_sha256"],
            "local_images_sha256": release["local_images_sha256"],
        },
    )


def _lineage_release_projection(release: dict[str, Any]) -> dict[str, Any]:
    return {
        "release_tag": release["release_tag"],
        "release_epoch": release["release_epoch"],
        "source_commit": release["source_commit"],
        "descriptor_sha256": release["descriptor_sha256"],
        "manifest_sha256": release["manifest_sha256"],
        "state_sha256": _state_digest(release),
    }


def _operation_id_for_intent(
    base_intent: dict[str, Any], *, parent_head_sha256: str
) -> str:
    _string(parent_head_sha256, DIGEST_RE, "operation parent head")
    # attempt_nonce is an idempotence discriminator only within one exact
    # parent and one exact request.  Bind every immutable request byte so a
    # crash before intent publication cannot reinterpret the same operation
    # directory as a changed daemon/model/environment/resource request.
    return hashlib.sha256(
        b"BackupSheep/signed-upgrade-operation/v3\0"
        + _canonical_bytes(base_intent)
        + parent_head_sha256.encode("ascii")
    ).hexdigest()


def _bind_intent_lineage(
    base_intent: dict[str, Any], *, parent_head: dict[str, Any]
) -> dict[str, Any]:
    source_projection = _lineage_release_projection(base_intent["source"])
    target_projection = _lineage_release_projection(base_intent["target"])
    if source_projection != parent_head["active_release"]:
        raise UpgradeJournalError(
            "signed-upgrade source differs from the globally active release"
        )
    maximum_epoch = _nonnegative_integer(
        parent_head["maximum_activated_epoch"],
        "parent maximum activated epoch",
    )
    if target_projection["release_epoch"] <= maximum_epoch:
        raise UpgradeJournalError(
            "signed-upgrade target epoch does not advance global activated history"
        )
    parent_digest = _sha256_bytes(_canonical_bytes(parent_head))
    operation_id = _operation_id_for_intent(
        base_intent, parent_head_sha256=parent_digest
    )
    intent = dict(base_intent)
    intent["operation_id"] = operation_id
    intent["lineage"] = {
        "parent_sequence": parent_head["sequence"],
        "parent_head_sha256": parent_digest,
        "parent_record_sha256": parent_head["record_sha256"],
        "parent_operation_id": parent_head["operation_id"],
        "parent_terminal_receipt_sha256": parent_head[
            "terminal_receipt_sha256"
        ],
        "parent_outcome": parent_head["state"],
        "started_sequence": parent_head["sequence"] + 1,
        "source_release_sha256": source_projection["state_sha256"],
        "target_release_sha256": target_projection["state_sha256"],
    }
    return intent


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
    compose: dict[str, Any],
    network_records_sha256: str,
    container_records_sha256: str,
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
    if normalized["compose_model_sha256"] != compose["model_sha256"]:
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
    if normalized["network_records_sha256"] != network_records_sha256:
        raise UpgradeJournalError(f"{label} network inventory changed")
    if normalized["container_records_sha256"] != container_records_sha256:
        raise UpgradeJournalError(f"{label} container inventory changed")
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


def _validate_container_record(
    value: Any,
    *,
    service: str,
    release: dict[str, Any],
    compose: dict[str, Any],
    label: str,
) -> dict[str, Any]:
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
    normalized = {
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
    expected_image = release["images"][SERVICE_IMAGE_ROLES[service]]["config_digest"]
    expected_compose = compose["service_config_sha256"][service]
    if normalized["image_config_sha256"] != expected_image:
        raise UpgradeJournalError(f"{label} used another signed image role")
    if normalized["compose_config_sha256"] != expected_compose:
        raise UpgradeJournalError(f"{label} used another Compose service config")
    return normalized


def _validate_runtime_records(
    value: Any,
    *,
    services: tuple[str, ...],
    required_running: set[str],
    required_absent: set[str],
    release: dict[str, Any],
    compose: dict[str, Any],
    label: str,
    require_zero_restarts: bool = True,
) -> dict[str, Any]:
    runtime = _mapping(value, label)
    _exact_keys(
        runtime,
        {
            "records",
            "records_sha256",
            "project_container_ids",
            "project_container_ids_sha256",
        },
        label,
    )
    raw_records = _list(runtime["records"], f"{label} records")
    if len(raw_records) != len(services):
        raise UpgradeJournalError(f"{label} service cardinality is not exact")
    records = [
        _validate_container_record(
            record,
            service=service,
            release=release,
            compose=compose,
            label=f"{label} {service}",
        )
        for service, record in zip(services, raw_records, strict=True)
    ]
    if required_running | required_absent != set(services):
        raise UpgradeJournalError(f"{label} service state policy is incomplete")
    for record in records:
        if record["service"] in required_running and record["state"] != "running":
            raise UpgradeJournalError(f"{label} required service is not running")
        if record["service"] in required_absent and record["state"] != "absent":
            raise UpgradeJournalError(f"{label} forbidden service is present")
        if record["state"] == "running":
            expected_health = "none" if record["service"] == "beat" else "healthy"
            if record["health"] != expected_health or (
                require_zero_restarts and record["restart_count"] != 0
            ):
                raise UpgradeJournalError(
                    f"{label} running service is unhealthy or restarted"
                )
    present_ids = [
        record["container_id"] for record in records if record["state"] != "absent"
    ]
    if len(set(present_ids)) != len(present_ids):
        raise UpgradeJournalError(f"{label} repeats a container ID")
    claimed_ids = _list(runtime["project_container_ids"], f"{label} project IDs")
    if any(not isinstance(value, str) or HEX_RE.fullmatch(value) is None for value in claimed_ids):
        raise UpgradeJournalError(f"{label} project container ID is malformed")
    if claimed_ids != sorted(claimed_ids) or claimed_ids != sorted(present_ids):
        raise UpgradeJournalError(
            f"{label} does not cover the complete exact project container inventory"
        )
    project_ids_digest = _domain_digest(
        "BackupSheep/upgrade-project-container-ids/v1", claimed_ids
    )
    if runtime["project_container_ids_sha256"] != project_ids_digest:
        raise UpgradeJournalError(f"{label} project container digest is inconsistent")
    records_digest = _domain_digest("BackupSheep/upgrade-runtime-records/v1", records)
    if runtime["records_sha256"] != records_digest:
        raise UpgradeJournalError(f"{label} records digest is inconsistent")
    return {
        "records": records,
        "records_sha256": records_digest,
        "project_container_ids": claimed_ids,
        "project_container_ids_sha256": project_ids_digest,
    }


def _validate_network_records(
    value: Any,
    *,
    intent: dict[str, Any],
    compose: dict[str, Any],
    runtime: dict[str, Any],
    required_present: set[str],
    required_absent: set[str],
    label: str,
) -> dict[str, Any]:
    if required_present | required_absent != set(NETWORK_ROLES):
        raise UpgradeJournalError(f"{label} network state policy is incomplete")
    networks = _mapping(value, label)
    _exact_keys(networks, {"records", "records_sha256"}, label)
    raw_records = _list(networks["records"], f"{label} records")
    if len(raw_records) != len(NETWORK_ROLES):
        raise UpgradeJournalError(f"{label} network cardinality is not exact")
    records: list[dict[str, Any]] = []
    for network, raw in zip(NETWORK_ROLES, raw_records, strict=True):
        record = _mapping(raw, f"{label} {network}")
        if network in required_absent:
            expected = {"network": network, "state": "absent"}
            if record != expected:
                raise UpgradeJournalError(
                    f"{label} {network} is not the exact absent record"
                )
            records.append(expected)
            continue
        _exact_keys(
            record,
            {
                "network",
                "name",
                "network_id",
                "compose_config_sha256",
                "endpoint_container_ids",
                "endpoint_container_ids_sha256",
                "state",
            },
            f"{label} {network}",
        )
        normalized = {
            "network": network,
            "name": record["name"],
            "network_id": _string(
                record["network_id"], HEX_RE, f"{label} {network} ID"
            ),
            "compose_config_sha256": _string(
                record["compose_config_sha256"],
                DIGEST_RE,
                f"{label} {network} Compose config",
            ),
            "endpoint_container_ids": _list(
                record["endpoint_container_ids"],
                f"{label} {network} endpoint container IDs",
            ),
            "endpoint_container_ids_sha256": _string(
                record["endpoint_container_ids_sha256"],
                DIGEST_RE,
                f"{label} {network} endpoint set",
            ),
            "state": record["state"],
        }
        if (
            normalized["network"] != record["network"]
            or normalized["state"] != "present"
            or normalized["name"] != f"{intent['compose_project']}_{network}"
            or normalized["compose_config_sha256"]
            != compose["network_config_sha256"][network]
        ):
            raise UpgradeJournalError(
                f"{label} {network} differs from the exact Compose network"
            )
        endpoint_ids = normalized["endpoint_container_ids"]
        if any(
            not isinstance(container_id, str)
            or HEX_RE.fullmatch(container_id) is None
            for container_id in endpoint_ids
        ) or endpoint_ids != sorted(set(endpoint_ids)):
            raise UpgradeJournalError(
                f"{label} {network} endpoint set is malformed or repeated"
            )
        expected_endpoint_ids = sorted(
            runtime_record["container_id"]
            for runtime_record in runtime["records"]
            if runtime_record["state"] != "absent"
            and network
            in SERVICE_NETWORK_ENDPOINTS.get(runtime_record["service"], ())
        )
        endpoint_digest = _domain_digest(
            "BackupSheep/upgrade-network-endpoints/v1", endpoint_ids
        )
        if (
            endpoint_ids != expected_endpoint_ids
            or normalized["endpoint_container_ids_sha256"] != endpoint_digest
        ):
            raise UpgradeJournalError(
                f"{label} {network} endpoints differ from the complete runtime topology"
            )
        records.append(normalized)
    present_ids = [
        record["network_id"] for record in records if record["state"] == "present"
    ]
    if len(set(present_ids)) != len(present_ids):
        raise UpgradeJournalError(f"{label} repeats a Docker network ID")
    digest_value = _domain_digest("BackupSheep/upgrade-network-records/v1", records)
    if networks["records_sha256"] != digest_value:
        raise UpgradeJournalError(f"{label} records digest is inconsistent")
    return {"records": records, "records_sha256": digest_value}


def _validate_one_shot_runner(
    value: Any, *, intent: dict[str, Any], service: str, label: str
) -> dict[str, Any]:
    runner = _mapping(value, label)
    _exact_keys(
        runner,
        {
            "service",
            "container_id",
            "image_config_sha256",
            "compose_config_sha256",
            "state",
            "exit_code",
            "restart_count",
            "outcome",
            "inspect_sha256",
        },
        label,
    )
    normalized = {
        "service": runner["service"],
        "container_id": _string(
            runner["container_id"], HEX_RE, f"{label} container ID"
        ),
        "image_config_sha256": _string(
            runner["image_config_sha256"], DIGEST_RE, f"{label} image config"
        ),
        "compose_config_sha256": _string(
            runner["compose_config_sha256"], DIGEST_RE, f"{label} Compose config"
        ),
        "state": runner["state"],
        "exit_code": _nonnegative_integer(
            runner["exit_code"], f"{label} exit code", maximum=255
        ),
        "restart_count": _nonnegative_integer(
            runner["restart_count"], f"{label} restart count", maximum=1_000_000
        ),
        "outcome": runner["outcome"],
        "inspect_sha256": _string(
            runner["inspect_sha256"], DIGEST_RE, f"{label} inspect"
        ),
    }
    expected_image = intent["target"]["images"][SERVICE_IMAGE_ROLES[service]][
        "config_digest"
    ]
    expected_compose = intent["compose"]["target"]["service_config_sha256"][
        service
    ]
    if (
        normalized["service"] != service
        or normalized["image_config_sha256"] != expected_image
        or normalized["compose_config_sha256"] != expected_compose
        or normalized["state"] != "exited"
        or normalized["exit_code"] != 0
        or normalized["restart_count"] != 0
        or normalized["outcome"] not in {"exit-zero", "reconciled-unknown"}
    ):
        raise UpgradeJournalError(f"{label} differs from the exact target runner")
    expected_inspect = _domain_digest(
        "BackupSheep/upgrade-one-shot-runner/v1",
        {
            "operation_id": intent["operation_id"],
            "installation_id": intent["installation_id"],
            "daemon_identity_sha256": intent["daemon"]["identity_sha256"],
            "runner": {
                key: normalized[key] for key in normalized if key != "inspect_sha256"
            },
        },
    )
    if normalized["inspect_sha256"] != expected_inspect:
        raise UpgradeJournalError(f"{label} inspect digest is inconsistent")
    return normalized


def _validate_functional_probe(
    value: Any,
    *,
    intent: dict[str, Any],
    container_id: str,
    purpose: str,
    label: str,
) -> dict[str, Any]:
    probe = _mapping(value, label)
    _exact_keys(
        probe,
        {
            "schema_version",
            "operation_id",
            "installation_id",
            "daemon_identity_sha256",
            "purpose",
            "service",
            "container_id",
            "endpoint",
            "status_code",
            "outcome",
            "body_sha256",
            "attempts",
            "receipt_sha256",
        },
        label,
    )
    normalized = {
        "schema_version": _exact_positive_integer(
            probe["schema_version"], 1, f"{label} schema"
        ),
        "operation_id": _string(
            probe["operation_id"], HEX_RE, f"{label} operation ID"
        ),
        "installation_id": _string(
            probe["installation_id"], HEX_RE, f"{label} installation ID"
        ),
        "daemon_identity_sha256": _string(
            probe["daemon_identity_sha256"], DIGEST_RE, f"{label} daemon"
        ),
        "purpose": probe["purpose"],
        "service": probe["service"],
        "container_id": _string(
            probe["container_id"], HEX_RE, f"{label} container ID"
        ),
        "endpoint": probe["endpoint"],
        "status_code": _nonnegative_integer(
            probe["status_code"], f"{label} status", maximum=599
        ),
        "outcome": probe["outcome"],
        "body_sha256": _string(
            probe["body_sha256"], DIGEST_RE, f"{label} response body"
        ),
        "attempts": _positive_integer(probe["attempts"], f"{label} attempts"),
        "receipt_sha256": _string(
            probe["receipt_sha256"], DIGEST_RE, f"{label} receipt"
        ),
    }
    if (
        normalized["schema_version"] != 1
        or normalized["operation_id"] != intent["operation_id"]
        or normalized["installation_id"] != intent["installation_id"]
        or normalized["daemon_identity_sha256"]
        != intent["daemon"]["identity_sha256"]
        or normalized["purpose"] != purpose
        or normalized["service"] != "app"
        or normalized["container_id"] != container_id
        or normalized["endpoint"] != "http://127.0.0.1:8000/healthz"
        or normalized["status_code"] != 200
        or normalized["outcome"] != "accepted"
        or normalized["attempts"] > 20
    ):
        raise UpgradeJournalError(f"{label} differs from the exact acceptance probe")
    expected_receipt = _domain_digest(
        "BackupSheep/upgrade-functional-probe/v1",
        {key: normalized[key] for key in normalized if key != "receipt_sha256"},
    )
    if normalized["receipt_sha256"] != expected_receipt:
        raise UpgradeJournalError(f"{label} receipt is inconsistent")
    return normalized


def _validate_phase_payload(phase: str, payload: Any, intent: dict[str, Any]) -> dict[str, Any]:
    payload = _mapping(payload, f"{phase} payload")
    source_compose = intent["compose"]["source"]
    target_compose = intent["compose"]["target"]
    source_model = source_compose["model_sha256"]
    target_model = target_compose["model_sha256"]
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
                "source_runtime",
                "source_networks",
                "resources",
            },
            "10-prepared payload",
        )
        source_running = set(CORE_SERVICES)
        if intent["source_activation_mode"] == "operations":
            source_running.update(OPERATION_SERVICES)
        source_absent = set(ALL_SERVICES) - source_running
        source_network_present = (
            set(NETWORK_ROLES)
            if intent["source_activation_mode"] == "operations"
            else set(CORE_NETWORK_ROLES)
        )
        source_runtime = _validate_runtime_records(
            payload["source_runtime"],
            services=ALL_SERVICES,
            required_running=source_running,
            required_absent=source_absent,
            release=intent["source"],
            compose=source_compose,
            label="prepared source runtime",
            require_zero_restarts=False,
        )
        source_networks = _validate_network_records(
            payload["source_networks"],
            intent=intent,
            compose=source_compose,
            runtime=source_runtime,
            required_present=source_network_present,
            required_absent=set(NETWORK_ROLES) - source_network_present,
            label="prepared source networks",
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
            "source_runtime": source_runtime,
            "source_networks": source_networks,
            "resources": _validate_resource_set(
                payload["resources"],
                intent=intent,
                compose=source_compose,
                network_records_sha256=source_networks["records_sha256"],
                container_records_sha256=source_runtime["records_sha256"],
                label="prepared resources",
            ),
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
        _exact_keys(payload, {"source_checkout_sha256", "source_env_sha256", "source_evidence_sha256", "source_keyrings_sha256", "stopped_writer_services", "source_migrations", "detached_volume_records_sha256", "runtime", "networks", "resources"}, "20-stopped payload")
        runtime = _validate_runtime_records(
            payload["runtime"],
            services=ALL_SERVICES,
            required_running=set(),
            required_absent=set(ALL_SERVICES),
            release=intent["source"],
            compose=source_compose,
            label="stopped runtime",
        )
        networks = _validate_network_records(
            payload["networks"],
            intent=intent,
            compose=source_compose,
            runtime=runtime,
            required_present=set(),
            required_absent=set(NETWORK_ROLES),
            label="stopped networks",
        )
        normalized = {
            "source_checkout_sha256": _string(payload["source_checkout_sha256"], DIGEST_RE, "stopped source checkout"),
            "source_env_sha256": _string(payload["source_env_sha256"], DIGEST_RE, "stopped source environment"),
            "source_evidence_sha256": _string(payload["source_evidence_sha256"], DIGEST_RE, "stopped source evidence"),
            "source_keyrings_sha256": _string(payload["source_keyrings_sha256"], DIGEST_RE, "stopped source keyrings"),
            "stopped_writer_services": _validate_absent_services(payload["stopped_writer_services"], WRITER_SERVICES, "stopped writers"),
            "source_migrations": _validate_migration_witness(payload["source_migrations"], expected=intent["source"]["migration"], label="stopped source migrations"),
            "detached_volume_records_sha256": _string(payload["detached_volume_records_sha256"], DIGEST_RE, "stopped detached volumes"),
            "runtime": runtime,
            "networks": networks,
            "resources": _validate_resource_set(
                payload["resources"],
                intent=intent,
                compose=source_compose,
                network_records_sha256=networks["records_sha256"],
                container_records_sha256=runtime["records_sha256"],
                label="stopped resources",
            ),
        }
        expected = (source_checkout_digest, intent["environment"]["source_sha256"], source_state, intent["resource_digests"]["artifact_provider_sha256"], intent["resource_digests"]["volume_records_sha256"])
        actual = tuple(normalized[key] for key in ("source_checkout_sha256", "source_env_sha256", "source_evidence_sha256", "source_keyrings_sha256", "detached_volume_records_sha256"))
        if actual != expected:
            raise UpgradeJournalError("stopped source binding differs from immutable intent")
        return normalized
    if phase == "30-switched":
        _exact_keys(payload, {"active_checkout", "active_env_sha256", "active_evidence_sha256", "active_model_sha256", "target_code_inventory", "target_writer_inventory", "active_pointer_sha256", "runtime", "networks", "resources"}, "30-switched payload")
        runtime = _validate_runtime_records(
            payload["runtime"],
            services=ALL_SERVICES,
            required_running=set(),
            required_absent=set(ALL_SERVICES),
            release=intent["target"],
            compose=target_compose,
            label="switched runtime",
        )
        networks = _validate_network_records(
            payload["networks"],
            intent=intent,
            compose=target_compose,
            runtime=runtime,
            required_present=set(),
            required_absent=set(NETWORK_ROLES),
            label="switched networks",
        )
        normalized = {
            "active_checkout": _validate_checkout_state(payload["active_checkout"], expected=intent["checkouts"]["target"], label="switched target checkout"),
            "active_env_sha256": _string(payload["active_env_sha256"], DIGEST_RE, "switched target environment"),
            "active_evidence_sha256": _string(payload["active_evidence_sha256"], DIGEST_RE, "switched target evidence"),
            "active_model_sha256": _string(payload["active_model_sha256"], DIGEST_RE, "switched target model"),
            "target_code_inventory": _list(payload["target_code_inventory"], "switched target code inventory"),
            "target_writer_inventory": _list(payload["target_writer_inventory"], "switched target writer inventory"),
            "active_pointer_sha256": _string(payload["active_pointer_sha256"], DIGEST_RE, "switched active pointer"),
            "runtime": runtime,
            "networks": networks,
            "resources": _validate_resource_set(
                payload["resources"],
                intent=intent,
                compose=target_compose,
                network_records_sha256=networks["records_sha256"],
                container_records_sha256=runtime["records_sha256"],
                label="switched resources",
            ),
        }
        if normalized["target_code_inventory"] != [] or normalized["target_writer_inventory"] != []:
            raise UpgradeJournalError("target code exists before the forward-only boundary")
        if (normalized["active_env_sha256"], normalized["active_evidence_sha256"], normalized["active_model_sha256"], normalized["active_pointer_sha256"]) != (intent["environment"]["target_sha256"], target_state, target_model, intent["active_pointer_sha256"]["target"]):
            raise UpgradeJournalError("switched target binding differs from immutable intent")
        return normalized
    if phase == "40-forward-only":
        _exact_keys(payload, {"active_checkout_sha256", "active_env_sha256", "active_evidence_sha256", "active_model_sha256", "source_pre_migration", "target_code_inventory", "runtime", "networks", "resources", "boundary_nonce", "boundary_sha256"}, "40-forward-only payload")
        runtime = _validate_runtime_records(
            payload["runtime"],
            services=ALL_SERVICES,
            required_running=set(),
            required_absent=set(ALL_SERVICES),
            release=intent["target"],
            compose=target_compose,
            label="forward-only runtime",
        )
        networks = _validate_network_records(
            payload["networks"],
            intent=intent,
            compose=target_compose,
            runtime=runtime,
            required_present=set(),
            required_absent=set(NETWORK_ROLES),
            label="forward-only networks",
        )
        resources = _validate_resource_set(
            payload["resources"],
            intent=intent,
            compose=target_compose,
            network_records_sha256=networks["records_sha256"],
            container_records_sha256=runtime["records_sha256"],
            label="forward-only resources",
        )
        normalized = {
            "active_checkout_sha256": _string(payload["active_checkout_sha256"], DIGEST_RE, "forward-only target checkout"),
            "active_env_sha256": _string(payload["active_env_sha256"], DIGEST_RE, "forward-only target environment"),
            "active_evidence_sha256": _string(payload["active_evidence_sha256"], DIGEST_RE, "forward-only target evidence"),
            "active_model_sha256": _string(payload["active_model_sha256"], DIGEST_RE, "forward-only target model"),
            "source_pre_migration": _validate_migration_witness(payload["source_pre_migration"], expected=intent["source"]["migration"], label="forward-only source migrations"),
            "target_code_inventory": _list(payload["target_code_inventory"], "forward-only target code inventory"),
            "runtime": runtime,
            "networks": networks,
            "resources": resources,
            "boundary_nonce": _string(payload["boundary_nonce"], HEX_RE, "forward-only boundary nonce"),
            "boundary_sha256": _string(payload["boundary_sha256"], DIGEST_RE, "forward-only boundary"),
        }
        if normalized["target_code_inventory"] != []:
            raise UpgradeJournalError("target code exists before forward-only receipt")
        binding = {key: normalized[key] for key in normalized if key != "boundary_sha256"}
        expected_boundary = _domain_digest(
            f"BackupSheep/forward-only/{intent['operation_id']}/v1", binding
        )
        if (normalized["active_checkout_sha256"], normalized["active_env_sha256"], normalized["active_evidence_sha256"], normalized["active_model_sha256"], normalized["boundary_nonce"], normalized["boundary_sha256"]) != (target_checkout_digest, intent["environment"]["target_sha256"], target_state, target_model, intent["attempt_nonce"], expected_boundary):
            raise UpgradeJournalError("forward-only boundary differs from immutable intent")
        return normalized
    if phase == "50-migrated":
        _exact_keys(payload, {"runner", "target_migrations", "runtime", "networks", "resources"}, "50-migrated payload")
        normalized_runner = _validate_one_shot_runner(
            payload["runner"], intent=intent, service="migrate", label="migration runner"
        )
        infrastructure_running = {"db", "rabbitmq"}
        runtime = _validate_runtime_records(
            payload["runtime"],
            services=ALL_SERVICES,
            required_running=infrastructure_running,
            required_absent=set(ALL_SERVICES) - infrastructure_running,
            release=intent["target"],
            compose=target_compose,
            label="migrated runtime",
        )
        networks = _validate_network_records(
            payload["networks"],
            intent=intent,
            compose=target_compose,
            runtime=runtime,
            required_present=set(CORE_NETWORK_ROLES),
            required_absent=set(NETWORK_ROLES) - set(CORE_NETWORK_ROLES),
            label="migrated networks",
        )
        normalized = {
            "runner": normalized_runner,
            "target_migrations": _validate_migration_witness(payload["target_migrations"], expected=intent["target"]["migration"], label="target migrations"),
            "runtime": runtime,
            "networks": networks,
            "resources": _validate_resource_set(
                payload["resources"],
                intent=intent,
                compose=target_compose,
                network_records_sha256=networks["records_sha256"],
                container_records_sha256=runtime["records_sha256"],
                label="migrated resources",
            ),
        }
        if normalized_runner["container_id"] in runtime["project_container_ids"]:
            raise UpgradeJournalError(
                "migration runner collides with the accepted runtime inventory"
            )
        return normalized
    if phase == "60-core-accepted":
        _exact_keys(payload, {"db_seal", "preflight", "runtime", "networks", "target_migrations", "functional_probe", "resources"}, "60-core-accepted payload")
        runtime = _validate_runtime_records(
            payload["runtime"],
            services=ALL_SERVICES,
            required_running=set(CORE_SERVICES),
            required_absent=set(ALL_SERVICES) - set(CORE_SERVICES),
            release=intent["target"],
            compose=target_compose,
            label="core runtime",
        )
        networks = _validate_network_records(
            payload["networks"],
            intent=intent,
            compose=target_compose,
            runtime=runtime,
            required_present=set(CORE_NETWORK_ROLES),
            required_absent=set(NETWORK_ROLES) - set(CORE_NETWORK_ROLES),
            label="core networks",
        )
        db_seal = _validate_one_shot_runner(
            payload["db_seal"], intent=intent, service="db-seal", label="db-seal runner"
        )
        preflight = _validate_one_shot_runner(
            payload["preflight"], intent=intent, service="preflight", label="preflight runner"
        )
        if db_seal["container_id"] == preflight["container_id"] or any(
            runner["container_id"] in runtime["project_container_ids"]
            for runner in (db_seal, preflight)
        ):
            raise UpgradeJournalError(
                "core one-shot runner collides with another accepted container"
            )
        app_record = runtime["records"][ALL_SERVICES.index("app")]
        normalized_probe = _validate_functional_probe(
            payload["functional_probe"],
            intent=intent,
            container_id=app_record["container_id"],
            purpose="core-acceptance",
            label="core functional probe",
        )
        return {
            "db_seal": db_seal,
            "preflight": preflight,
            "runtime": runtime,
            "networks": networks,
            "target_migrations": _validate_migration_witness(payload["target_migrations"], expected=intent["target"]["migration"], label="core target migrations"),
            "functional_probe": normalized_probe,
            "resources": _validate_resource_set(
                payload["resources"],
                intent=intent,
                compose=target_compose,
                network_records_sha256=networks["records_sha256"],
                container_records_sha256=runtime["records_sha256"],
                label="core resources",
            ),
        }
    if phase == "70-activated":
        _exact_keys(payload, {"activation_mode", "active_pointer_sha256", "active_checkout_sha256", "active_env_sha256", "active_evidence_sha256", "active_release_sha256", "local_images_sha256", "runtime", "networks", "resources"}, "70-activated payload")
        mode = payload["activation_mode"]
        if mode not in {"core-only", "operations"}:
            raise UpgradeJournalError("activation mode is unsupported")
        required_running = set(CORE_SERVICES)
        if mode == "operations":
            required_running.update(OPERATION_SERVICES)
        required_absent = set(ONE_SHOT_SERVICES)
        if mode == "core-only":
            required_absent.update(OPERATION_SERVICES)
        runtime = _validate_runtime_records(
            payload["runtime"],
            services=ALL_SERVICES,
            required_running=required_running,
            required_absent=required_absent,
            release=intent["target"],
            compose=target_compose,
            label="activated runtime",
        )
        present_networks = (
            set(NETWORK_ROLES) if mode == "operations" else set(CORE_NETWORK_ROLES)
        )
        networks = _validate_network_records(
            payload["networks"],
            intent=intent,
            compose=target_compose,
            runtime=runtime,
            required_present=present_networks,
            required_absent=set(NETWORK_ROLES) - present_networks,
            label="activated networks",
        )
        normalized = {
            "activation_mode": mode,
            "active_pointer_sha256": _string(payload["active_pointer_sha256"], DIGEST_RE, "activated pointer"),
            "active_checkout_sha256": _string(payload["active_checkout_sha256"], DIGEST_RE, "activated checkout"),
            "active_env_sha256": _string(payload["active_env_sha256"], DIGEST_RE, "activated environment"),
            "active_evidence_sha256": _string(payload["active_evidence_sha256"], DIGEST_RE, "activated evidence"),
            "active_release_sha256": _string(payload["active_release_sha256"], DIGEST_RE, "activated release"),
            "local_images_sha256": _string(payload["local_images_sha256"], DIGEST_RE, "activated local images"),
            "runtime": runtime,
            "networks": networks,
            "resources": _validate_resource_set(
                payload["resources"],
                intent=intent,
                compose=target_compose,
                network_records_sha256=networks["records_sha256"],
                container_records_sha256=runtime["records_sha256"],
                label="activated resources",
            ),
        }
        expected = (intent["active_pointer_sha256"]["target"], target_checkout_digest, intent["environment"]["target_sha256"], target_state, target_state, intent["target"]["local_images_sha256"])
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
            "active_pointer_sha256",
            "active_checkout_sha256",
            "active_env_sha256",
            "active_evidence_sha256",
            "active_release_sha256",
            "local_images_sha256",
            "active_model_sha256",
            "source_migrations",
            "runtime",
            "networks",
            "target_absence",
            "functional_probe",
            "resources",
        },
        "rollback payload",
    )
    source_checkout_sha256 = _domain_digest(
        "BackupSheep/upgrade-checkout/v1", intent["checkouts"]["source"]
    )
    source_compose = intent["compose"]["source"]
    source_running = set(CORE_SERVICES)
    if intent["source_activation_mode"] == "operations":
        source_running.update(OPERATION_SERVICES)
    source_absent = set(ALL_SERVICES) - source_running
    runtime = _validate_runtime_records(
        payload["runtime"],
        services=ALL_SERVICES,
        required_running=source_running,
        required_absent=source_absent,
        release=intent["source"],
        compose=source_compose,
        label="rollback source runtime",
    )
    present_networks = (
        set(NETWORK_ROLES)
        if intent["source_activation_mode"] == "operations"
        else set(CORE_NETWORK_ROLES)
    )
    networks = _validate_network_records(
        payload["networks"],
        intent=intent,
        compose=source_compose,
        runtime=runtime,
        required_present=present_networks,
        required_absent=set(NETWORK_ROLES) - present_networks,
        label="rollback source networks",
    )
    expected_target_absence = []
    for service in ALL_SERVICES:
        role = SERVICE_IMAGE_ROLES[service]
        source_pair = (
            intent["source"]["images"][role]["config_digest"],
            source_compose["service_config_sha256"][service],
        )
        target_pair = (
            intent["target"]["images"][role]["config_digest"],
            intent["compose"]["target"]["service_config_sha256"][service],
        )
        if source_pair != target_pair:
            expected_target_absence.append(
                {
                    "service": service,
                    "target_image_config_sha256": target_pair[0],
                    "target_compose_config_sha256": target_pair[1],
                    "state": "absent",
                }
            )
    target_absence_value = _mapping(
        payload["target_absence"], "rollback target absence"
    )
    _exact_keys(
        target_absence_value,
        {"project_container_ids_sha256", "records"},
        "rollback target absence",
    )
    target_absence = {
        "project_container_ids_sha256": _string(
            target_absence_value["project_container_ids_sha256"],
            DIGEST_RE,
            "rollback target-absence project inventory",
        ),
        "records": _list(
            target_absence_value["records"], "rollback target-absence records"
        ),
    }
    if (
        target_absence["project_container_ids_sha256"]
        != runtime["project_container_ids_sha256"]
        or target_absence["records"] != expected_target_absence
    ):
        raise UpgradeJournalError(
            "rollback does not bind target absence to the complete project inventory"
        )
    app_record = runtime["records"][ALL_SERVICES.index("app")]
    normalized_probe = _validate_functional_probe(
        payload["functional_probe"],
        intent=intent,
        container_id=app_record["container_id"],
        purpose="rollback-source",
        label="rollback functional probe",
    )
    normalized = {
        "active_pointer_sha256": _string(
            payload["active_pointer_sha256"], DIGEST_RE, "rollback source pointer"
        ),
        "active_checkout_sha256": _string(
            payload["active_checkout_sha256"], DIGEST_RE, "rollback source checkout"
        ),
        "active_env_sha256": _string(
            payload["active_env_sha256"], DIGEST_RE, "rollback source environment"
        ),
        "active_evidence_sha256": _string(
            payload["active_evidence_sha256"], DIGEST_RE, "rollback source evidence"
        ),
        "active_release_sha256": _string(
            payload["active_release_sha256"], DIGEST_RE, "rollback source release"
        ),
        "local_images_sha256": _string(
            payload["local_images_sha256"], DIGEST_RE, "rollback local images"
        ),
        "active_model_sha256": _string(
            payload["active_model_sha256"], DIGEST_RE, "rollback source model"
        ),
        "source_migrations": _validate_migration_witness(
            payload["source_migrations"],
            expected=intent["source"]["migration"],
            label="rollback source migrations",
        ),
        "runtime": runtime,
        "networks": networks,
        "target_absence": target_absence,
        "functional_probe": normalized_probe,
        "resources": _validate_resource_set(
            payload["resources"],
            intent=intent,
            compose=source_compose,
            network_records_sha256=networks["records_sha256"],
            container_records_sha256=runtime["records_sha256"],
            label="rollback resources",
        ),
    }
    expected = (
        intent["active_pointer_sha256"]["source"],
        source_checkout_sha256,
        intent["environment"]["source_sha256"],
        _state_digest(intent["source"]),
        _state_digest(intent["source"]),
        intent["source"]["local_images_sha256"],
        source_compose["model_sha256"],
    )
    actual = tuple(
        normalized[key]
        for key in (
            "active_pointer_sha256",
            "active_checkout_sha256",
            "active_env_sha256",
            "active_evidence_sha256",
            "active_release_sha256",
            "local_images_sha256",
            "active_model_sha256",
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
            "lineage",
            "installation_id",
            "compose_project",
            "source",
            "target",
            "authorization",
            "daemon",
            "checkouts",
            "compose",
            "active_pointer_sha256",
            "source_activation_mode",
            "environment",
            "volumes",
            "artifact_provider",
            "resource_digests",
        },
        "upgrade intent",
    )
    _exact_positive_integer(
        intent["schema_version"], SCHEMA_VERSION, "upgrade-intent schema"
    )
    _string(intent["attempt_nonce"], HEX_RE, "upgrade attempt nonce")
    _string(intent["operation_id"], HEX_RE, "operation ID")
    _string(intent["installation_id"], HEX_RE, "installation ID")
    _string(intent["compose_project"], PROJECT_RE, "Compose project")
    active_pointer_sha256 = _mapping(
        intent["active_pointer_sha256"], "intent active-release pointers"
    )
    _exact_keys(
        active_pointer_sha256,
        {"source", "target"},
        "intent active-release pointers",
    )
    for side in ("source", "target"):
        _string(
            active_pointer_sha256[side],
            DIGEST_RE,
            f"intent {side} active-release pointer",
        )
    if intent["source_activation_mode"] not in {"core-only", "operations"}:
        raise UpgradeJournalError("intent source activation mode is unsupported")
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
        "active_pointer_sha256": intent["active_pointer_sha256"],
        "source_activation_mode": intent["source_activation_mode"],
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
    lineage = _mapping(intent["lineage"], "intent lineage")
    _exact_keys(
        lineage,
        {
            "parent_sequence",
            "parent_head_sha256",
            "parent_record_sha256",
            "parent_operation_id",
            "parent_terminal_receipt_sha256",
            "parent_outcome",
            "started_sequence",
            "source_release_sha256",
            "target_release_sha256",
        },
        "intent lineage",
    )
    parent_sequence = _nonnegative_integer(
        lineage["parent_sequence"], "intent lineage parent sequence", maximum=10**18
    )
    if lineage["started_sequence"] != parent_sequence + 1:
        raise UpgradeJournalError("intent lineage started sequence changed")
    for key in (
        "parent_head_sha256",
        "parent_record_sha256",
        "parent_terminal_receipt_sha256",
        "source_release_sha256",
        "target_release_sha256",
    ):
        _string(lineage[key], DIGEST_RE, f"intent lineage {key}")
    _string(lineage["parent_operation_id"], HEX_RE, "intent lineage parent operation")
    if lineage["parent_outcome"] not in {"genesis", "activated", "rolled-back"}:
        raise UpgradeJournalError("intent lineage parent is not terminal")
    if (
        lineage["source_release_sha256"] != _state_digest(source)
        or lineage["target_release_sha256"] != _state_digest(target)
    ):
        raise UpgradeJournalError("intent lineage release binding changed")
    if lineage["parent_outcome"] == "genesis":
        if (
            lineage["parent_operation_id"] != ZERO_HEX
            or lineage["parent_terminal_receipt_sha256"] != ZERO_DIGEST
        ):
            raise UpgradeJournalError("intent genesis lineage parent is malformed")
    elif (
        lineage["parent_operation_id"] == ZERO_HEX
        or lineage["parent_terminal_receipt_sha256"] == ZERO_DIGEST
    ):
        raise UpgradeJournalError("intent terminal lineage parent is incomplete")
    base_intent = dict(intent)
    base_intent.pop("operation_id")
    base_intent.pop("lineage")
    expected_operation = _operation_id_for_intent(
        base_intent,
        parent_head_sha256=lineage["parent_head_sha256"],
    )
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


def _validate_lineage_release(value: Any, label: str) -> dict[str, Any]:
    release = _mapping(value, label)
    _exact_keys(
        release,
        {
            "release_tag",
            "release_epoch",
            "source_commit",
            "descriptor_sha256",
            "manifest_sha256",
            "state_sha256",
        },
        label,
    )
    return {
        "release_tag": _string(release["release_tag"], TAG_RE, f"{label} tag"),
        "release_epoch": _positive_integer(
            release["release_epoch"], f"{label} epoch"
        ),
        "source_commit": _string(
            release["source_commit"], COMMIT_RE, f"{label} commit"
        ),
        "descriptor_sha256": _string(
            release["descriptor_sha256"], DIGEST_RE, f"{label} descriptor"
        ),
        "manifest_sha256": _string(
            release["manifest_sha256"], DIGEST_RE, f"{label} manifest"
        ),
        "state_sha256": _string(
            release["state_sha256"], DIGEST_RE, f"{label} state"
        ),
    }


def _lineage_record_bytes(value: dict[str, Any]) -> bytes:
    body = dict(value)
    body.pop("history_sha256", None)
    value = {
        **body,
        "history_sha256": _domain_digest(
            "BackupSheep/upgrade-lineage-history/v1", body
        ),
    }
    return _canonical_bytes(value)


def _build_lineage_record(
    *,
    sequence: int,
    event: str,
    previous_record_sha256: str,
    previous_history_sha256: str,
    installation_id: str,
    operation_id: str,
    intent_sha256: str,
    source_release: dict[str, Any],
    target_release: dict[str, Any],
    active_release: dict[str, Any],
    terminal_receipt_sha256: str,
    maximum_activated_epoch: int,
) -> dict[str, Any]:
    body = {
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
        "event": event,
        "previous_record_sha256": previous_record_sha256,
        "previous_history_sha256": previous_history_sha256,
        "installation_id": installation_id,
        "operation_id": operation_id,
        "intent_sha256": intent_sha256,
        "source_release": source_release,
        "target_release": target_release,
        "active_release": active_release,
        "terminal_receipt_sha256": terminal_receipt_sha256,
        "maximum_activated_epoch": maximum_activated_epoch,
    }
    return {
        **body,
        "history_sha256": _domain_digest(
            "BackupSheep/upgrade-lineage-history/v1", body
        ),
    }


def _head_from_record(record: dict[str, Any], record_bytes: bytes) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "installation_id": record["installation_id"],
        "sequence": record["sequence"],
        "record_sha256": _sha256_bytes(record_bytes),
        "history_sha256": record["history_sha256"],
        "state": record["event"],
        "operation_id": record["operation_id"],
        "terminal_receipt_sha256": record["terminal_receipt_sha256"],
        "active_release": record["active_release"],
        "maximum_activated_epoch": record["maximum_activated_epoch"],
    }


def _validate_head(value: Any, label: str = "journal head") -> dict[str, Any]:
    head = _mapping(value, label)
    _exact_keys(
        head,
        {
            "schema_version",
            "installation_id",
            "sequence",
            "record_sha256",
            "history_sha256",
            "state",
            "operation_id",
            "terminal_receipt_sha256",
            "active_release",
            "maximum_activated_epoch",
        },
        label,
    )
    _exact_positive_integer(head["schema_version"], SCHEMA_VERSION, f"{label} schema")
    state = head["state"]
    if state not in {"genesis", "started", "activated", "rolled-back"}:
        raise UpgradeJournalError(f"{label} state is unsupported")
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "installation_id": _string(
            head["installation_id"], HEX_RE, f"{label} installation ID"
        ),
        "sequence": _nonnegative_integer(
            head["sequence"], f"{label} sequence", maximum=10**18
        ),
        "record_sha256": _string(
            head["record_sha256"], DIGEST_RE, f"{label} record"
        ),
        "history_sha256": _string(
            head["history_sha256"], DIGEST_RE, f"{label} history"
        ),
        "state": state,
        "operation_id": _string(
            head["operation_id"], HEX_RE, f"{label} operation"
        ),
        "terminal_receipt_sha256": _string(
            head["terminal_receipt_sha256"],
            DIGEST_RE,
            f"{label} terminal receipt",
        ),
        "active_release": _validate_lineage_release(
            head["active_release"], f"{label} active release"
        ),
        "maximum_activated_epoch": _positive_integer(
            head["maximum_activated_epoch"], f"{label} maximum activated epoch"
        ),
    }
    if state == "genesis" and (
        normalized["operation_id"] != ZERO_HEX
        or normalized["terminal_receipt_sha256"] != ZERO_DIGEST
    ):
        raise UpgradeJournalError("genesis head has a nonempty operation")
    if state == "started" and normalized["terminal_receipt_sha256"] != ZERO_DIGEST:
        raise UpgradeJournalError("open journal head has a terminal receipt")
    if state in {"activated", "rolled-back"} and (
        normalized["operation_id"] == ZERO_HEX
        or normalized["terminal_receipt_sha256"] == ZERO_DIGEST
    ):
        raise UpgradeJournalError("terminal journal head is incomplete")
    return normalized


def _validate_lineage_record(
    value: Any,
    *,
    expected_sequence: int,
    previous: dict[str, Any] | None,
    previous_bytes: bytes | None,
) -> dict[str, Any]:
    record = _mapping(value, f"lineage record {expected_sequence}")
    _exact_keys(
        record,
        {
            "schema_version",
            "sequence",
            "event",
            "previous_record_sha256",
            "previous_history_sha256",
            "history_sha256",
            "installation_id",
            "operation_id",
            "intent_sha256",
            "source_release",
            "target_release",
            "active_release",
            "terminal_receipt_sha256",
            "maximum_activated_epoch",
        },
        f"lineage record {expected_sequence}",
    )
    sequence = _nonnegative_integer(
        record["sequence"],
        f"lineage record {expected_sequence} sequence",
        maximum=10**18,
    )
    schema_version = _exact_positive_integer(
        record["schema_version"],
        SCHEMA_VERSION,
        f"lineage record {expected_sequence} schema",
    )
    if sequence != expected_sequence:
        raise UpgradeJournalError("lineage record schema or sequence changed")
    event = record["event"]
    if event not in {"genesis", "started", "activated", "rolled-back"}:
        raise UpgradeJournalError("lineage event is unsupported")
    normalized = {
        "schema_version": schema_version,
        "sequence": sequence,
        "event": event,
        "previous_record_sha256": _string(
            record["previous_record_sha256"], DIGEST_RE, "lineage previous record"
        ),
        "previous_history_sha256": _string(
            record["previous_history_sha256"], DIGEST_RE, "lineage previous history"
        ),
        "history_sha256": _string(
            record["history_sha256"], DIGEST_RE, "lineage history"
        ),
        "installation_id": _string(
            record["installation_id"], HEX_RE, "lineage installation ID"
        ),
        "operation_id": _string(
            record["operation_id"], HEX_RE, "lineage operation ID"
        ),
        "intent_sha256": _string(
            record["intent_sha256"], DIGEST_RE, "lineage intent"
        ),
        "source_release": _validate_lineage_release(
            record["source_release"], "lineage source release"
        ),
        "target_release": _validate_lineage_release(
            record["target_release"], "lineage target release"
        ),
        "active_release": _validate_lineage_release(
            record["active_release"], "lineage active release"
        ),
        "terminal_receipt_sha256": _string(
            record["terminal_receipt_sha256"],
            DIGEST_RE,
            "lineage terminal receipt",
        ),
        "maximum_activated_epoch": _positive_integer(
            record["maximum_activated_epoch"], "lineage maximum activated epoch"
        ),
    }
    expected_body = dict(normalized)
    expected_history = expected_body.pop("history_sha256")
    if expected_history != _domain_digest(
        "BackupSheep/upgrade-lineage-history/v1", expected_body
    ):
        raise UpgradeJournalError("lineage history accumulator changed")
    if previous is None:
        if (
            expected_sequence != 0
            or event != "genesis"
            or normalized["previous_record_sha256"] != ZERO_DIGEST
            or normalized["previous_history_sha256"] != ZERO_DIGEST
            or normalized["operation_id"] != ZERO_HEX
            or normalized["intent_sha256"] != ZERO_DIGEST
            or normalized["terminal_receipt_sha256"] != ZERO_DIGEST
            or normalized["source_release"] != normalized["target_release"]
            or normalized["source_release"] != normalized["active_release"]
            or normalized["maximum_activated_epoch"]
            != normalized["active_release"]["release_epoch"]
        ):
            raise UpgradeJournalError("journal genesis is malformed")
        return normalized
    if previous_bytes is None:
        raise UpgradeJournalError("lineage previous bytes are unavailable")
    if (
        normalized["previous_record_sha256"] != _sha256_bytes(previous_bytes)
        or normalized["previous_history_sha256"] != previous["history_sha256"]
        or normalized["installation_id"] != previous["installation_id"]
    ):
        raise UpgradeJournalError("lineage previous-record binding changed")
    if event == "started":
        if previous["event"] not in {"genesis", "activated", "rolled-back"}:
            raise UpgradeJournalError("lineage has two open operations")
        if (
            normalized["operation_id"] == ZERO_HEX
            or normalized["intent_sha256"] == ZERO_DIGEST
            or normalized["terminal_receipt_sha256"] != ZERO_DIGEST
            or normalized["active_release"] != normalized["source_release"]
            or normalized["source_release"] != previous["active_release"]
            or normalized["target_release"]["release_epoch"]
            <= previous["maximum_activated_epoch"]
            or normalized["maximum_activated_epoch"]
            != previous["maximum_activated_epoch"]
        ):
            raise UpgradeJournalError("started lineage record is inconsistent")
    else:
        if previous["event"] != "started" or event not in {"activated", "rolled-back"}:
            raise UpgradeJournalError("lineage terminal event has no matching start")
        if any(
            normalized[key] != previous[key]
            for key in ("operation_id", "intent_sha256", "source_release", "target_release")
        ) or normalized["terminal_receipt_sha256"] == ZERO_DIGEST:
            raise UpgradeJournalError("lineage terminal identity changed")
        if event == "activated":
            if (
                normalized["active_release"] != normalized["target_release"]
                or normalized["maximum_activated_epoch"]
                != normalized["target_release"]["release_epoch"]
            ):
                raise UpgradeJournalError("activated lineage state is inconsistent")
        elif (
            normalized["active_release"] != normalized["source_release"]
            or normalized["maximum_activated_epoch"]
            != previous["maximum_activated_epoch"]
        ):
            raise UpgradeJournalError("rolled-back lineage state is inconsistent")
    return normalized


def _lineage_filename(sequence: int) -> str:
    return f"{sequence:020d}.json"


def _read_canonical_json_control(
    path: Path, *, mode: int = 0o400, maximum: int = MAX_JOURNAL_BYTES
) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular(
        path,
        maximum=maximum,
        owner=os.geteuid(),
        modes={mode},
        links={1},
    )
    value = _load_json_bytes(payload, str(path))
    if payload != _canonical_bytes(value):
        raise UpgradeJournalError(f"{path.name} is not canonical")
    return _mapping(value, path.name), payload


def _validate_checkpoint_boundary(value: Any) -> dict[str, Any]:
    record = _mapping(value, "checkpoint boundary record")
    _exact_keys(
        record,
        {
            "schema_version",
            "sequence",
            "event",
            "previous_record_sha256",
            "previous_history_sha256",
            "history_sha256",
            "installation_id",
            "operation_id",
            "intent_sha256",
            "source_release",
            "target_release",
            "active_release",
            "terminal_receipt_sha256",
            "maximum_activated_epoch",
        },
        "checkpoint boundary record",
    )
    event = record["event"]
    schema_version = _exact_positive_integer(
        record["schema_version"], SCHEMA_VERSION, "checkpoint boundary schema"
    )
    if event not in {
        "activated",
        "rolled-back",
    }:
        raise UpgradeJournalError("checkpoint boundary is not a terminal lineage record")
    normalized = {
        "schema_version": schema_version,
        "sequence": _positive_integer(record["sequence"], "checkpoint boundary sequence"),
        "event": event,
        "previous_record_sha256": _string(
            record["previous_record_sha256"], DIGEST_RE, "checkpoint previous record"
        ),
        "previous_history_sha256": _string(
            record["previous_history_sha256"], DIGEST_RE, "checkpoint previous history"
        ),
        "history_sha256": _string(
            record["history_sha256"], DIGEST_RE, "checkpoint history"
        ),
        "installation_id": _string(
            record["installation_id"], HEX_RE, "checkpoint installation ID"
        ),
        "operation_id": _string(
            record["operation_id"], HEX_RE, "checkpoint operation ID"
        ),
        "intent_sha256": _string(
            record["intent_sha256"], DIGEST_RE, "checkpoint intent"
        ),
        "source_release": _validate_lineage_release(
            record["source_release"], "checkpoint source release"
        ),
        "target_release": _validate_lineage_release(
            record["target_release"], "checkpoint target release"
        ),
        "active_release": _validate_lineage_release(
            record["active_release"], "checkpoint active release"
        ),
        "terminal_receipt_sha256": _string(
            record["terminal_receipt_sha256"],
            DIGEST_RE,
            "checkpoint terminal receipt",
        ),
        "maximum_activated_epoch": _positive_integer(
            record["maximum_activated_epoch"], "checkpoint maximum activated epoch"
        ),
    }
    body = dict(normalized)
    history = body.pop("history_sha256")
    if history != _domain_digest("BackupSheep/upgrade-lineage-history/v1", body):
        raise UpgradeJournalError("checkpoint lineage history accumulator changed")
    if (
        normalized["operation_id"] == ZERO_HEX
        or normalized["intent_sha256"] == ZERO_DIGEST
        or normalized["terminal_receipt_sha256"] == ZERO_DIGEST
        or normalized["target_release"]["release_epoch"]
        <= normalized["source_release"]["release_epoch"]
    ):
        raise UpgradeJournalError("checkpoint boundary identity is incomplete")
    if event == "activated":
        if (
            normalized["active_release"] != normalized["target_release"]
            or normalized["maximum_activated_epoch"]
            != normalized["target_release"]["release_epoch"]
        ):
            raise UpgradeJournalError("activated checkpoint boundary is inconsistent")
    elif (
        normalized["active_release"] != normalized["source_release"]
        or normalized["maximum_activated_epoch"]
        != normalized["source_release"]["release_epoch"]
        or normalized["maximum_activated_epoch"]
        >= normalized["target_release"]["release_epoch"]
    ):
        raise UpgradeJournalError("rolled-back checkpoint boundary is inconsistent")
    return normalized


def _validate_compacted_operation(value: Any, label: str) -> dict[str, Any]:
    summary = _mapping(value, label)
    _exact_keys(
        summary,
        {
            "operation_id",
            "outcome",
            "intent_sha256",
            "source_release_sha256",
            "target_release_sha256",
            "terminal_receipt_sha256",
        },
        label,
    )
    if summary["outcome"] not in {"activated", "rolled-back"}:
        raise UpgradeJournalError(f"{label} outcome is unsupported")
    return {
        "operation_id": _string(summary["operation_id"], HEX_RE, f"{label} ID"),
        "outcome": summary["outcome"],
        "intent_sha256": _string(
            summary["intent_sha256"], DIGEST_RE, f"{label} intent"
        ),
        "source_release_sha256": _string(
            summary["source_release_sha256"], DIGEST_RE, f"{label} source"
        ),
        "target_release_sha256": _string(
            summary["target_release_sha256"], DIGEST_RE, f"{label} target"
        ),
        "terminal_receipt_sha256": _string(
            summary["terminal_receipt_sha256"], DIGEST_RE, f"{label} terminal receipt"
        ),
    }


def _validate_checkpoint(
    value: Any, *, root: Path
) -> dict[str, Any]:
    checkpoint = _mapping(value, "journal checkpoint")
    _exact_keys(
        checkpoint,
        {
            "schema_version",
            "installation_id",
            "previous_checkpoint_sha256",
            "boundary_record",
            "boundary_record_sha256",
            "boundary_head",
            "compacted_operation_count",
            "previous_compacted_operations_sha256",
            "compacted_operations_sha256",
            "pruned_operations",
        },
        "journal checkpoint",
    )
    _exact_positive_integer(
        checkpoint["schema_version"], SCHEMA_VERSION, "journal checkpoint schema"
    )
    boundary = _validate_checkpoint_boundary(checkpoint["boundary_record"])
    boundary_bytes = _canonical_bytes(boundary)
    boundary_digest = _sha256_bytes(boundary_bytes)
    boundary_path = root / LINEAGE_NAME / _lineage_filename(boundary["sequence"])
    actual_boundary = _read_regular(
        boundary_path,
        maximum=MAX_JOURNAL_BYTES,
        owner=os.geteuid(),
        modes={0o400},
        links={1},
    )
    if actual_boundary != boundary_bytes:
        raise UpgradeJournalError("journal checkpoint boundary bytes changed")
    summaries_value = _list(checkpoint["pruned_operations"], "pruned operations")
    if not 1 <= len(summaries_value) <= MAX_RETAINED_OPERATIONS:
        raise UpgradeJournalError("journal checkpoint pruned-operation count is invalid")
    summaries = [
        _validate_compacted_operation(item, f"pruned operation {index}")
        for index, item in enumerate(summaries_value)
    ]
    operation_ids = [item["operation_id"] for item in summaries]
    if len(set(operation_ids)) != len(operation_ids):
        raise UpgradeJournalError("journal checkpoint repeats an operation")
    last = summaries[-1]
    if (
        last["operation_id"] != boundary["operation_id"]
        or last["outcome"] != boundary["event"]
        or last["intent_sha256"] != boundary["intent_sha256"]
        or last["source_release_sha256"]
        != boundary["source_release"]["state_sha256"]
        or last["target_release_sha256"]
        != boundary["target_release"]["state_sha256"]
        or last["terminal_receipt_sha256"]
        != boundary["terminal_receipt_sha256"]
    ):
        raise UpgradeJournalError("journal checkpoint summary misses its boundary")
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "installation_id": _string(
            checkpoint["installation_id"], HEX_RE, "checkpoint installation ID"
        ),
        "previous_checkpoint_sha256": _string(
            checkpoint["previous_checkpoint_sha256"],
            DIGEST_RE,
            "previous checkpoint",
        ),
        "boundary_record": boundary,
        "boundary_record_sha256": _string(
            checkpoint["boundary_record_sha256"],
            DIGEST_RE,
            "checkpoint boundary digest",
        ),
        "boundary_head": _validate_head(
            checkpoint["boundary_head"], "checkpoint boundary head"
        ),
        "compacted_operation_count": _positive_integer(
            checkpoint["compacted_operation_count"], "compacted operation count"
        ),
        "previous_compacted_operations_sha256": _string(
            checkpoint["previous_compacted_operations_sha256"],
            DIGEST_RE,
            "previous compacted operations",
        ),
        "compacted_operations_sha256": _string(
            checkpoint["compacted_operations_sha256"],
            DIGEST_RE,
            "compacted operations",
        ),
        "pruned_operations": summaries,
    }
    if (
        normalized["installation_id"] != boundary["installation_id"]
        or normalized["boundary_record_sha256"] != boundary_digest
        or normalized["boundary_head"] != _head_from_record(boundary, boundary_bytes)
        or boundary["sequence"] % 2 != 0
        or normalized["compacted_operation_count"] != boundary["sequence"] // 2
        or normalized["compacted_operation_count"] < len(summaries)
    ):
        raise UpgradeJournalError("journal checkpoint boundary binding changed")
    aggregate = {
        "previous_checkpoint_sha256": normalized["previous_checkpoint_sha256"],
        "previous_compacted_operations_sha256": normalized[
            "previous_compacted_operations_sha256"
        ],
        "boundary_record_sha256": normalized["boundary_record_sha256"],
        "compacted_operation_count": normalized["compacted_operation_count"],
        "operations": summaries,
    }
    if normalized["compacted_operations_sha256"] != _domain_digest(
        "BackupSheep/upgrade-compacted-operations/v2", aggregate
    ):
        raise UpgradeJournalError("journal checkpoint operation aggregate changed")
    return normalized


def _checkpoint_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "operation_id": record["operation_id"],
        "outcome": record["event"],
        "intent_sha256": record["intent_sha256"],
        "source_release_sha256": record["source_release"]["state_sha256"],
        "target_release_sha256": record["target_release"]["state_sha256"],
        "terminal_receipt_sha256": record["terminal_receipt_sha256"],
    }


def _validate_checkpoint_extension(
    candidate: dict[str, Any],
    *,
    previous: dict[str, Any] | None,
    previous_bytes: bytes | None,
    root: Path,
) -> None:
    if previous is None:
        start_sequence = 0
        prior_record: dict[str, Any] | None = None
        prior_bytes: bytes | None = None
        previous_boundary = -1
        previous_count = 0
        previous_aggregate = ZERO_DIGEST
        expected_previous_checkpoint = ZERO_DIGEST
    else:
        start_sequence = previous["boundary_record"]["sequence"]
        prior_record = previous["boundary_record"]
        prior_bytes = _canonical_bytes(prior_record)
        previous_boundary = start_sequence
        previous_count = previous["compacted_operation_count"]
        previous_aggregate = previous["compacted_operations_sha256"]
        if previous_bytes is None:
            raise UpgradeJournalError("previous checkpoint bytes are unavailable")
        expected_previous_checkpoint = _sha256_bytes(previous_bytes)
    boundary_sequence = candidate["boundary_record"]["sequence"]
    if boundary_sequence <= previous_boundary:
        raise UpgradeJournalError("checkpoint boundary did not advance")
    entries = sorted((root / LINEAGE_NAME).iterdir(), key=lambda item: item.name)
    terminal_interval: list[dict[str, Any]] = []
    found_boundary = False
    for offset, entry in enumerate(entries):
        sequence = start_sequence + offset
        if entry.name != _lineage_filename(sequence) or entry.is_symlink():
            raise UpgradeJournalError("checkpoint extension lineage has a gap")
        value, payload = _read_canonical_json_control(entry)
        if previous is not None and offset == 0:
            record = _validate_checkpoint_boundary(value)
            if record != prior_record or payload != prior_bytes:
                raise UpgradeJournalError("previous checkpoint boundary changed")
        else:
            record = _validate_lineage_record(
                value,
                expected_sequence=sequence,
                previous=prior_record,
                previous_bytes=prior_bytes,
            )
        if previous_boundary < sequence <= boundary_sequence and record["event"] in {
            "activated",
            "rolled-back",
        }:
            terminal_interval.append(record)
        if sequence == boundary_sequence:
            if record != candidate["boundary_record"]:
                raise UpgradeJournalError("checkpoint selected another lineage boundary")
            found_boundary = True
            break
        prior_record, prior_bytes = record, payload
    if not found_boundary:
        raise UpgradeJournalError("checkpoint boundary is absent from lineage")
    expected_summaries = [_checkpoint_summary(record) for record in terminal_interval]
    if candidate["pruned_operations"] != expected_summaries:
        raise UpgradeJournalError("checkpoint does not summarize the exact next interval")
    if (
        candidate["previous_checkpoint_sha256"] != expected_previous_checkpoint
        or candidate["previous_compacted_operations_sha256"] != previous_aggregate
        or candidate["compacted_operation_count"]
        != previous_count + len(expected_summaries)
    ):
        raise UpgradeJournalError("checkpoint cumulative lineage binding changed")


def _load_checkpoint_locked(
    root: Path,
) -> tuple[dict[str, Any] | None, bytes | None]:
    checkpoint_path = root / CHECKPOINT_NAME
    candidate_path = root / NEXT_CHECKPOINT_NAME
    final_exists = checkpoint_path.exists() or checkpoint_path.is_symlink()
    candidate_exists = candidate_path.exists() or candidate_path.is_symlink()
    final: dict[str, Any] | None = None
    final_bytes: bytes | None = None
    if final_exists:
        final_value, final_bytes = _read_canonical_json_control(checkpoint_path)
        final = _validate_checkpoint(final_value, root=root)
    if candidate_exists:
        candidate_value, candidate_bytes = _read_canonical_json_control(candidate_path)
        candidate = _validate_checkpoint(candidate_value, root=root)
        if final_bytes == candidate_bytes:
            expected_previous = final_bytes
        else:
            expected_previous_digest = (
                _sha256_bytes(final_bytes) if final_bytes is not None else ZERO_DIGEST
            )
            if candidate["previous_checkpoint_sha256"] != expected_previous_digest:
                raise UpgradeJournalError(
                    "interrupted checkpoint does not extend the durable checkpoint"
                )
            _validate_checkpoint_extension(
                candidate,
                previous=final,
                previous_bytes=final_bytes,
                root=root,
            )
            expected_previous = final_bytes
        _atomic_replace(
            checkpoint_path,
            candidate_bytes,
            mode=0o400,
            expected_previous=expected_previous,
        )
        final_value, final_bytes = _read_canonical_json_control(checkpoint_path)
        final = _validate_checkpoint(final_value, root=root)
    return final, final_bytes


def _discard_torn_checkpoint_candidate_for_exact_retry(root: Path) -> None:
    candidate = root / NEXT_CHECKPOINT_NAME
    if not (candidate.exists() or candidate.is_symlink()):
        return
    try:
        _read_canonical_json_control(candidate)
        return
    except (OSError, UpgradeJournalError):
        # A checkpoint candidate is published before any pruning.  A nlink-one
        # noncanonical prefix therefore has authorized no deletion and may be
        # discarded only by an explicit mutating initialize/compact retry.
        _read_regular(
            candidate,
            maximum=MAX_JOURNAL_BYTES,
            owner=os.geteuid(),
            modes={0o400},
            links={1},
            allow_empty=True,
        )
        os.unlink(candidate)
        _fsync_directory(root)


def _remove_validated_tree(path: Path) -> None:
    file_stat = path.lstat()
    if not stat.S_ISDIR(file_stat.st_mode) or path.is_symlink():
        raise UpgradeJournalError("compaction target is not a real operation directory")
    for entry in list(path.iterdir()):
        entry_stat = entry.lstat()
        if stat.S_ISDIR(entry_stat.st_mode) and not entry.is_symlink():
            _remove_validated_tree(entry)
        elif stat.S_ISREG(entry_stat.st_mode) and not entry.is_symlink():
            os.unlink(entry)
        else:
            raise UpgradeJournalError("compaction target contains a special file")
    os.rmdir(path)


def _reconcile_checkpoint_pruning(root: Path, checkpoint: dict[str, Any]) -> None:
    lineage = root / LINEAGE_NAME
    boundary_sequence = checkpoint["boundary_record"]["sequence"]
    for entry in list(lineage.iterdir()):
        match = re.fullmatch(r"([0-9]{20})\.json", entry.name)
        if match is None:
            raise UpgradeJournalError("journal lineage contains an unexpected entry")
        if int(match.group(1)) < boundary_sequence:
            if entry.is_symlink():
                raise UpgradeJournalError("compacted lineage record is a symlink")
            os.unlink(entry)
            _fsync_directory(lineage)
    operations = root / OPERATIONS_NAME
    for summary in checkpoint["pruned_operations"]:
        operation = operations / summary["operation_id"]
        if operation.exists() or operation.is_symlink():
            _remove_validated_tree(operation)
            _fsync_directory(operations)


def _publish_lineage_and_head(
    *,
    root: Path,
    record: dict[str, Any],
    expected_head: dict[str, Any] | None,
) -> dict[str, Any]:
    lineage = root / LINEAGE_NAME
    record_bytes = _canonical_bytes(record)
    path = lineage / _lineage_filename(record["sequence"])
    if not _reconcile_exclusive(path, record_bytes, mode=0o400):
        _write_exclusive(path, record_bytes, mode=0o400)
    new_head = _head_from_record(record, record_bytes)
    previous_bytes = _canonical_bytes(expected_head) if expected_head is not None else None
    _atomic_replace(
        root / HEAD_NAME,
        _canonical_bytes(new_head),
        mode=0o400,
        expected_previous=previous_bytes,
    )
    return new_head


def _reconcile_lineage_publication_names(lineage: Path) -> None:
    """Finish only the no-clobber name publication begun by this journal.

    The immutable lineage bytes are still validated against their predecessor,
    intent, and terminal receipt before HEAD is advanced.  This helper merely
    closes the portable link/unlink crash window so an exact retry can reach
    that validation.
    """

    owner = os.geteuid()
    entries = list(lineage.iterdir())
    temporaries = [
        entry
        for entry in entries
        if re.fullmatch(r"\.[0-9]{20}\.json\.new", entry.name)
    ]
    if len(temporaries) > 1:
        raise UpgradeJournalError("journal lineage has multiple interrupted publications")
    unexpected_temporaries = [
        entry for entry in entries if entry.name.startswith(".") and entry not in temporaries
    ]
    if unexpected_temporaries:
        raise UpgradeJournalError("journal lineage has an unexpected temporary entry")
    if not temporaries:
        return
    temporary = temporaries[0]
    final = lineage / temporary.name[1:-4]
    temporary_payload = _read_regular(
        temporary,
        maximum=MAX_JOURNAL_BYTES,
        owner=owner,
        modes={0o400},
        links={1, 2},
        allow_empty=True,
    )
    if not (final.exists() or final.is_symlink()):
        # Only a caller that can derive the exact expected lineage event may
        # decide whether a temp-only prefix is recoverable.
        return
    final_payload = _read_regular(
        final,
        maximum=MAX_JOURNAL_BYTES,
        owner=owner,
        modes={0o400},
        links={1, 2},
    )
    final_stat = final.lstat()
    temporary_stat = temporary.lstat()
    if (
        final_payload != temporary_payload
        or (final_stat.st_dev, final_stat.st_ino)
        != (temporary_stat.st_dev, temporary_stat.st_ino)
    ):
        raise UpgradeJournalError("interrupted lineage publication differs from final")
    os.unlink(temporary)
    _fsync_directory(lineage)


def _load_lineage_locked(
    root: Path,
) -> tuple[
    list[tuple[dict[str, Any], bytes]],
    dict[str, Any],
    dict[str, Any] | None,
    bytes,
    ]:
    lineage = root / LINEAGE_NAME
    _reconcile_lineage_publication_names(lineage)
    checkpoint, _ = _load_checkpoint_locked(root)
    if checkpoint is not None:
        _reconcile_checkpoint_pruning(root, checkpoint)
    entries = sorted(lineage.iterdir(), key=lambda item: item.name)
    if not entries or len(entries) > MAX_LINEAGE_RECORDS:
        raise UpgradeJournalError("journal lineage has an invalid record count")
    records: list[tuple[dict[str, Any], bytes]] = []
    if checkpoint is None:
        start_sequence = 0
        previous: dict[str, Any] | None = None
        previous_bytes: bytes | None = None
    else:
        start_sequence = checkpoint["boundary_record"]["sequence"]
        previous = checkpoint["boundary_record"]
        previous_bytes = _canonical_bytes(previous)
    for offset, entry in enumerate(entries):
        sequence = start_sequence + offset
        if entry.name != _lineage_filename(sequence) or entry.is_symlink():
            raise UpgradeJournalError("journal lineage is noncanonical or has a gap")
        value, payload = _read_canonical_json_control(entry)
        if checkpoint is not None and offset == 0:
            record = _validate_checkpoint_boundary(value)
            if record != checkpoint["boundary_record"] or payload != previous_bytes:
                raise UpgradeJournalError("journal checkpoint boundary changed")
        else:
            record = _validate_lineage_record(
                value,
                expected_sequence=sequence,
                previous=previous,
                previous_bytes=previous_bytes,
            )
        records.append((record, payload))
        previous, previous_bytes = record, payload
    head_path = root / HEAD_NAME
    head_value, head_bytes = _read_canonical_json_control(head_path)
    head = _validate_head(head_value)
    expected_head = _head_from_record(records[-1][0], records[-1][1])
    pending_head: dict[str, Any] | None = None
    if head != expected_head:
        # The only recoverable ordering is a durable single next lineage record
        # followed by a crash before the head CAS.  Anything else is a fork.
        if len(records) < 2:
            raise UpgradeJournalError("journal head differs from genesis")
        previous_head = _head_from_record(records[-2][0], records[-2][1])
        if head != previous_head:
            raise UpgradeJournalError("journal head and lineage diverged")
        pending_head = expected_head
    return records, head, pending_head, head_bytes


def _initialize_genesis_locked(
    *, root: Path, installation_id: str, source_release: dict[str, Any]
) -> dict[str, Any]:
    lineage = root / LINEAGE_NAME
    head_path = root / HEAD_NAME
    projection = _lineage_release_projection(source_release)
    genesis = _build_lineage_record(
        sequence=0,
        event="genesis",
        previous_record_sha256=ZERO_DIGEST,
        previous_history_sha256=ZERO_DIGEST,
        installation_id=installation_id,
        operation_id=ZERO_HEX,
        intent_sha256=ZERO_DIGEST,
        source_release=projection,
        target_release=projection,
        active_release=projection,
        terminal_receipt_sha256=ZERO_DIGEST,
        maximum_activated_epoch=projection["release_epoch"],
    )
    genesis_path = lineage / _lineage_filename(0)
    genesis_temporary = genesis_path.with_name(f".{genesis_path.name}.new")
    if genesis_temporary.exists() or genesis_temporary.is_symlink():
        if not _reconcile_exclusive(genesis_path, _canonical_bytes(genesis), mode=0o400):
            _write_exclusive(genesis_path, _canonical_bytes(genesis), mode=0o400)
    _reconcile_lineage_publication_names(lineage)
    entries = list(lineage.iterdir())
    if entries and not (head_path.exists() or head_path.is_symlink()):
        if len(entries) != 1 or entries[0] != genesis_path:
            raise UpgradeJournalError("interrupted journal genesis differs from source")
        payload = _read_regular(
            genesis_path,
            maximum=MAX_JOURNAL_BYTES,
            owner=os.geteuid(),
            modes={0o400},
        )
        if payload != _canonical_bytes(genesis):
            raise UpgradeJournalError("interrupted journal genesis bytes changed")
        head = _head_from_record(genesis, payload)
        _atomic_replace(
            head_path,
            _canonical_bytes(head),
            mode=0o400,
            expected_previous=None,
        )
        return head
    if entries or head_path.exists() or head_path.is_symlink():
        if not (head_path.exists() or head_path.is_symlink()):
            raise UpgradeJournalError("journal lineage exists without a durable head")
        head_value, _ = _read_canonical_json_control(head_path)
        return _validate_head(head_value)
    return _publish_lineage_and_head(root=root, record=genesis, expected_head=None)


def _started_lineage_record(
    *, intent: dict[str, Any], intent_bytes: bytes, head: dict[str, Any]
) -> dict[str, Any]:
    source = _lineage_release_projection(intent["source"])
    target = _lineage_release_projection(intent["target"])
    return _build_lineage_record(
        sequence=head["sequence"] + 1,
        event="started",
        previous_record_sha256=head["record_sha256"],
        previous_history_sha256=head["history_sha256"],
        installation_id=intent["installation_id"],
        operation_id=intent["operation_id"],
        intent_sha256=_sha256_bytes(intent_bytes),
        source_release=source,
        target_release=target,
        active_release=source,
        terminal_receipt_sha256=ZERO_DIGEST,
        maximum_activated_epoch=head["maximum_activated_epoch"],
    )


def _terminal_lineage_record(
    *,
    intent: dict[str, Any],
    intent_bytes: bytes,
    head: dict[str, Any],
    outcome: str,
    terminal_receipt_sha256: str,
) -> dict[str, Any]:
    if head["state"] != "started" or head["operation_id"] != intent["operation_id"]:
        raise UpgradeJournalError("terminal lineage does not match the open operation")
    source = _lineage_release_projection(intent["source"])
    target = _lineage_release_projection(intent["target"])
    active = target if outcome == "activated" else source
    maximum_epoch = (
        target["release_epoch"]
        if outcome == "activated"
        else head["maximum_activated_epoch"]
    )
    return _build_lineage_record(
        sequence=head["sequence"] + 1,
        event=outcome,
        previous_record_sha256=head["record_sha256"],
        previous_history_sha256=head["history_sha256"],
        installation_id=intent["installation_id"],
        operation_id=intent["operation_id"],
        intent_sha256=_sha256_bytes(intent_bytes),
        source_release=source,
        target_release=target,
        active_release=active,
        terminal_receipt_sha256=terminal_receipt_sha256,
        maximum_activated_epoch=maximum_epoch,
    )


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
    # Refuse malformed or unauthorized inputs before creating any journal
    # namespace.  Rebuild under the journal lock below and require byte-for-byte
    # semantic equality so the preflight is not a TOCTOU trust decision.
    preflight_intent, preflight_rollback = build_intent(
        source_evidence=source_evidence,
        target_evidence=target_evidence,
        source_env=source_env,
        target_env=target_env,
        source_verification=source_verification,
        witness_request=witness_request,
    )
    root, operations = _ensure_journal_layout(install_dir)
    with _journal_lock(install_dir):
        base_intent, rollback = build_intent(
            source_evidence=source_evidence,
            target_evidence=target_evidence,
            source_env=source_env,
            target_env=target_env,
            source_verification=source_verification,
            witness_request=witness_request,
        )
        _discard_torn_checkpoint_candidate_for_exact_retry(root)
        if base_intent != preflight_intent or rollback != preflight_rollback:
            raise UpgradeJournalError(
                "signed-upgrade inputs changed between preflight and journal lock"
            )
        head = _initialize_genesis_locked(
            root=root,
            installation_id=base_intent["installation_id"],
            source_release=base_intent["source"],
        )
        _reconcile_expected_lineage_candidate(
            install_dir, base_intent=base_intent
        )
        records, current_head, pending_head, _ = _load_lineage_locked(root)
        if pending_head is not None:
            # Only validation of the exact operation referenced by that record
            # may finish a torn head update.  General initialization must not
            # silently adopt an unrelated lineage event.
            candidate_id = pending_head["operation_id"]
            if candidate_id == ZERO_HEX or not (operations / candidate_id).is_dir():
                raise UpgradeJournalError(
                    "interrupted global lineage cannot be attributed to an operation"
                )
            _validate_journal_locked(install_dir, operation_id=candidate_id)
            records, current_head, pending_head, _ = _load_lineage_locked(root)
            if pending_head is not None:
                raise UpgradeJournalError("interrupted global head did not reconcile")
        head = current_head
        if head["installation_id"] != base_intent["installation_id"]:
            raise UpgradeJournalError("journal belongs to another installation")

        if head["state"] == "started":
            active = operations / head["operation_id"]
            existing_intent, _ = _load_intent(active)
            if len(records) < 2:
                raise UpgradeJournalError("open operation has no stable lineage parent")
            parent_head = _head_from_record(records[-2][0], records[-2][1])
            expected_intent = _bind_intent_lineage(
                base_intent, parent_head=parent_head
            )
            if existing_intent != expected_intent:
                raise UpgradeJournalError(
                    f"another signed upgrade remains open: {head['operation_id']}"
                )
            _validate_journal_locked(
                install_dir, operation_id=existing_intent["operation_id"]
            )
            return existing_intent
        if head["state"] not in {"genesis", "activated", "rolled-back"}:
            raise UpgradeJournalError("journal head is not stable")

        intent = _bind_intent_lineage(base_intent, parent_head=head)
        intent_payload = _canonical_bytes(intent)
        active = operations / intent["operation_id"]
        entries = list(operations.iterdir())
        started_ids = {
            record["operation_id"]
            for index, (record, _) in enumerate(records)
            if record["event"] == "started"
            and not (index == 0 and record["sequence"] > 0)
        }
        entry_names: set[str] = set()
        for entry in entries:
            if HEX_RE.fullmatch(entry.name) is None or entry.is_symlink():
                raise UpgradeJournalError("journal has an unsafe operation entry")
            entry_names.add(entry.name)
        unstarted = entry_names - started_ids
        if unstarted and unstarted != {intent["operation_id"]}:
            raise UpgradeJournalError(
                "another interrupted unstarted operation requires its exact retry"
            )
        if not unstarted and entries:
            _validate_journal_locked(install_dir)
        if not unstarted and len(entries) >= MAX_RETAINED_OPERATIONS:
            _compact_journal_locked(install_dir)
            records, head, pending_head, _ = _load_lineage_locked(root)
            if pending_head is not None or head["state"] not in {
                "genesis",
                "activated",
                "rolled-back",
            }:
                raise UpgradeJournalError("journal compaction did not reach a stable head")
            intent = _bind_intent_lineage(base_intent, parent_head=head)
            intent_payload = _canonical_bytes(intent)
            active = operations / intent["operation_id"]
        if not active.exists() and not active.is_symlink():
            try:
                os.mkdir(active, 0o700)
                _fsync_directory(operations)
            except FileExistsError:
                pass
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
        }
        if any(entry.name not in allowed for entry in active.iterdir()):
            raise UpgradeJournalError("unstarted journal contains an unexpected entry")

        _retain_evidence(source_evidence, active / SOURCE_EVIDENCE_NAME)
        _retain_evidence(target_evidence, active / TARGET_EVIDENCE_NAME)
        rollback_path = active / ROLLBACK_ENV_NAME
        if not _reconcile_exclusive(rollback_path, rollback, mode=0o400):
            _write_exclusive(rollback_path, rollback, mode=0o400)
        target_env_payload = _read_regular(target_env, owner=owner, modes={0o600})
        if _sha256_bytes(target_env_payload) != intent["environment"]["target_sha256"]:
            raise UpgradeJournalError(
                "target environment changed during journal initialization"
            )
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
        _validate_journal_locked(
            install_dir,
            operation_id=intent["operation_id"],
            pending_unstarted_operation=intent["operation_id"],
        )
        started = _started_lineage_record(
            intent=intent, intent_bytes=intent_payload, head=head
        )
        _publish_lineage_and_head(root=root, record=started, expected_head=head)
        validated, phase = _validate_journal_locked(
            install_dir, operation_id=intent["operation_id"]
        )
        if validated != intent or phase is not None:
            raise UpgradeJournalError("new journal intent did not become globally open")
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
    rollback_path = active / ROLLBACK_ENV_NAME
    target_environment_path = active / TARGET_ENV_NAME
    rollback_present = rollback_path.exists() or rollback_path.is_symlink()
    target_environment_present = (
        target_environment_path.exists() or target_environment_path.is_symlink()
    )
    if rollback_present:
        rollback = _read_regular(rollback_path, owner=owner, modes={0o400})
        if _sha256_bytes(rollback) != intent["environment"]["rollback_sha256"]:
            raise UpgradeJournalError("protected rollback environment changed")
    if target_environment_present:
        target_environment = _read_regular(
            target_environment_path, owner=owner, modes={0o400}
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
    one_shot_container_ids: set[str] = set()
    normalized_phases: dict[str, dict[str, Any]] = {}
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
        _exact_positive_integer(
            receipt["schema_version"],
            SCHEMA_VERSION,
            f"{receipt_name} schema",
        )
        if receipt["phase"] != phase:
            raise UpgradeJournalError(f"{receipt_name} phase or schema changed")
        if receipt["operation_id"] != intent["operation_id"] or receipt["installation_id"] != intent["installation_id"]:
            raise UpgradeJournalError(f"{receipt_name} belongs to another operation")
        if receipt["intent_sha256"] != intent_digest or receipt["previous_receipt_sha256"] != previous_digest:
            raise UpgradeJournalError(f"{receipt_name} hash chain changed")
        normalized_phase = _validate_phase_payload(phase, receipt["payload"], intent)
        normalized_phases[phase] = normalized_phase
        phase_runners: list[dict[str, Any]] = []
        if phase == "50-migrated":
            phase_runners.append(normalized_phase["runner"])
        elif phase == "60-core-accepted":
            phase_runners.extend(
                (normalized_phase["db_seal"], normalized_phase["preflight"])
            )
        for runner in phase_runners:
            container_id = runner["container_id"]
            if container_id in one_shot_container_ids:
                raise UpgradeJournalError(
                    "one-shot acceptance container ID is reused across phases"
                )
            one_shot_container_ids.add(container_id)
        runtime_value = normalized_phase.get("runtime") or normalized_phase.get(
            "source_runtime"
        )
        if runtime_value is not None and one_shot_container_ids.intersection(
            runtime_value["project_container_ids"]
        ):
            raise UpgradeJournalError(
                "one-shot acceptance container ID collides with runtime inventory"
            )
        if (
            phase == allow_interrupted_phase
            and f".{receipt_name}.new" in present_temporaries
        ):
            # A crash after link(2) but before unlink(2) leaves the durable
            # receipt and its temporary name pointing at the same inode.  The
            # global lineage validator below deliberately rereads terminal
            # receipts with the normal single-link contract, so finish this
            # exact, caller-authorized publication before that reread.
            _reconcile_exclusive(path, payload, mode=0o400)
        if phase == "70-activated":
            core_phase = normalized_phases.get("60-core-accepted", {})
            core_runtime = core_phase.get("runtime")
            core_networks = core_phase.get("networks")
            if core_runtime is None or core_networks is None:
                raise UpgradeJournalError("activation has no core acceptance inventory")
            for service in CORE_SERVICES:
                index = ALL_SERVICES.index(service)
                if normalized_phase["runtime"]["records"][index] != core_runtime[
                    "records"
                ][index]:
                    raise UpgradeJournalError(
                        "activated core runtime differs from probed core acceptance"
                    )
            for network in CORE_NETWORK_ROLES:
                index = NETWORK_ROLES.index(network)
                if normalized_phase["networks"]["records"][index] != core_networks[
                    "records"
                ][index]:
                    raise UpgradeJournalError(
                        "activated core networks differ from probed core acceptance"
                    )
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
        _exact_positive_integer(
            rollback_receipt["schema_version"],
            SCHEMA_VERSION,
            "rollback receipt schema",
        )
        if (
            rollback_receipt["operation_id"] != intent["operation_id"]
            or rollback_receipt["installation_id"] != intent["installation_id"]
            or rollback_receipt["outcome"] != "rolled-back"
            or rollback_receipt["intent_sha256"] != intent_digest
            or rollback_receipt["previous_receipt_sha256"] != previous_digest
        ):
            raise UpgradeJournalError("rollback receipt identity or hash chain changed")
        _validate_rollback_payload(rollback_receipt["payload"], intent)
        if (
            allow_interrupted_phase == "rolled-back"
            and f".{ROLLBACK_RECEIPT_NAME}.new" in present_temporaries
        ):
            _reconcile_exclusive(
                active / ROLLBACK_RECEIPT_NAME,
                rollback_payload,
                mode=0o400,
            )
        for retired in (rollback_path, target_environment_path):
            if retired.exists() or retired.is_symlink():
                os.unlink(retired)
                _fsync_directory(active)
        return intent, "rolled-back"
    forward_only = highest is not None and PHASES.index(highest) >= PHASES.index(
        "40-forward-only"
    )
    if not rollback_present and not forward_only:
        raise UpgradeJournalError("protected rollback environment disappeared too early")
    if rollback_present and forward_only:
        os.unlink(rollback_path)
        _fsync_directory(active)
    activated = highest == "70-activated"
    if not target_environment_present and not activated:
        raise UpgradeJournalError("protected target environment disappeared too early")
    if target_environment_present and activated:
        os.unlink(target_environment_path)
        _fsync_directory(active)
    return intent, highest


def _load_normalized_phase_payload(
    active: Path, *, phase: str, intent: dict[str, Any]
) -> dict[str, Any]:
    receipt_bytes = _read_regular(
        active / f"{phase}.json",
        maximum=MAX_JOURNAL_BYTES,
        owner=os.geteuid(),
        modes={0o400},
    )
    receipt = _mapping(
        _load_json_bytes(receipt_bytes, f"{phase}.json"), f"{phase}.json"
    )
    if receipt_bytes != _canonical_bytes(receipt) or receipt.get("phase") != phase:
        raise UpgradeJournalError(f"{phase} receipt changed during append")
    return _validate_phase_payload(phase, receipt.get("payload"), intent)


def _validate_cross_phase_candidate_before_publish(
    *, active: Path, phase: str, candidate: dict[str, Any], intent: dict[str, Any]
) -> None:
    candidate_runners: list[dict[str, Any]] = []
    prior_runners: list[dict[str, Any]] = []
    if phase == "50-migrated":
        candidate_runners.append(candidate["runner"])
    elif phase == "60-core-accepted":
        migrated = _load_normalized_phase_payload(
            active, phase="50-migrated", intent=intent
        )
        prior_runners.append(migrated["runner"])
        candidate_runners.extend((candidate["db_seal"], candidate["preflight"]))
    elif phase == "70-activated":
        accepted = _load_normalized_phase_payload(
            active, phase="60-core-accepted", intent=intent
        )
        for service in CORE_SERVICES:
            index = ALL_SERVICES.index(service)
            if candidate["runtime"]["records"][index] != accepted["runtime"][
                "records"
            ][index]:
                raise UpgradeJournalError(
                    "activated core runtime differs from probed core acceptance"
                )
        for network in CORE_NETWORK_ROLES:
            index = NETWORK_ROLES.index(network)
            if candidate["networks"]["records"][index] != accepted["networks"][
                "records"
            ][index]:
                raise UpgradeJournalError(
                    "activated core networks differ from probed core acceptance"
                )
        migrated = _load_normalized_phase_payload(
            active, phase="50-migrated", intent=intent
        )
        prior_runners.extend(
            (migrated["runner"], accepted["db_seal"], accepted["preflight"])
        )
    runner_ids = [runner["container_id"] for runner in prior_runners + candidate_runners]
    if len(set(runner_ids)) != len(runner_ids):
        raise UpgradeJournalError("one-shot acceptance container ID is reused")
    runtime_ids = set(candidate.get("runtime", {}).get("project_container_ids", []))
    if runtime_ids.intersection(runner_ids):
        raise UpgradeJournalError(
            "one-shot acceptance container ID collides with runtime inventory"
        )


def _reconcile_expected_lineage_candidate(
    install_dir: Path, *, base_intent: dict[str, Any] | None = None
) -> None:
    root, operations = _journal_paths(install_dir)
    lineage = root / LINEAGE_NAME
    _reconcile_lineage_publication_names(lineage)
    temporaries = [
        entry
        for entry in lineage.iterdir()
        if re.fullmatch(r"\.[0-9]{20}\.json\.new", entry.name)
    ]
    if not temporaries:
        return
    if len(temporaries) != 1:
        raise UpgradeJournalError("journal lineage has multiple interrupted publications")
    head_value, _ = _read_canonical_json_control(root / HEAD_NAME)
    head = _validate_head(head_value)
    expected_path = lineage / _lineage_filename(head["sequence"] + 1)
    temporary = temporaries[0]
    if temporary != expected_path.with_name(f".{expected_path.name}.new"):
        raise UpgradeJournalError("interrupted lineage publication has another sequence")
    if head["state"] in {"genesis", "activated", "rolled-back"}:
        candidates: list[tuple[dict[str, Any], bytes]] = []
        if base_intent is not None:
            intent = _bind_intent_lineage(base_intent, parent_head=head)
            operation = operations / intent["operation_id"]
            if operation.is_dir() and not operation.is_symlink():
                loaded, intent_bytes = _load_intent(operation)
                if loaded == intent:
                    _, highest = _validate_operation_directory(operation)
                    if highest is None:
                        candidates.append((loaded, intent_bytes))
        else:
            for operation in operations.iterdir():
                if not operation.is_dir() or operation.is_symlink():
                    continue
                try:
                    loaded, intent_bytes = _load_intent(operation)
                    candidate_base = dict(loaded)
                    candidate_base.pop("operation_id")
                    candidate_base.pop("lineage")
                    if _bind_intent_lineage(candidate_base, parent_head=head) != loaded:
                        continue
                    _, highest = _validate_operation_directory(operation)
                    if highest is None:
                        candidates.append((loaded, intent_bytes))
                except (OSError, KeyError, TypeError, IndexError, UpgradeJournalError):
                    continue
        if len(candidates) != 1:
            raise UpgradeJournalError(
                "interrupted started-lineage publication has no unique exact intent"
            )
        intent, intent_bytes = candidates[0]
        expected_record = _started_lineage_record(
            intent=intent, intent_bytes=intent_bytes, head=head
        )
    else:
        operation = operations / head["operation_id"]
        intent, intent_bytes = _load_intent(operation)
        _, highest = _validate_operation_directory(operation)
        if highest == "70-activated":
            outcome = "activated"
            receipt_name = "70-activated.json"
        elif highest == "rolled-back":
            outcome = "rolled-back"
            receipt_name = ROLLBACK_RECEIPT_NAME
        else:
            raise UpgradeJournalError(
                "interrupted terminal-lineage publication has no terminal receipt"
            )
        receipt_sha256 = _sha256_bytes(
            _read_regular(
                operation / receipt_name,
                maximum=MAX_JOURNAL_BYTES,
                owner=os.geteuid(),
                modes={0o400},
            )
        )
        expected_record = _terminal_lineage_record(
            intent=intent,
            intent_bytes=intent_bytes,
            head=head,
            outcome=outcome,
            terminal_receipt_sha256=receipt_sha256,
        )
    expected_bytes = _canonical_bytes(expected_record)
    if not _reconcile_exclusive(expected_path, expected_bytes, mode=0o400):
        _write_exclusive(expected_path, expected_bytes, mode=0o400)
    _reconcile_lineage_publication_names(lineage)


def _validate_journal_locked(
    install_dir: Path,
    *,
    operation_id: str | None = None,
    allow_interrupted_phase: str | None = None,
    reconcile_terminal: bool = True,
    pending_unstarted_operation: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    owner = os.geteuid()
    _validate_directory(install_dir, owner=owner)
    _validate_ancestor_chain(install_dir, owner=owner)
    root, operations = _journal_paths(install_dir)
    _validate_directory(root, owner=owner)
    _validate_directory(operations, owner=owner)
    _validate_directory(root / LINEAGE_NAME, owner=owner)
    _validate_directory(root / PRUNING_NAME, owner=owner)
    if list((root / PRUNING_NAME).iterdir()):
        raise UpgradeJournalError("journal pruning directory is not empty")
    root_names = {entry.name for entry in root.iterdir()}
    allowed_root_names = {
        OPERATIONS_NAME,
        LINEAGE_NAME,
        PRUNING_NAME,
        HEAD_NAME,
        LOCK_NAME,
        CHECKPOINT_NAME,
        NEXT_CHECKPOINT_NAME,
        f".{HEAD_NAME}.new",
    }
    if root_names - allowed_root_names:
        raise UpgradeJournalError("journal root contains an unexpected entry")
    if not {OPERATIONS_NAME, LINEAGE_NAME, PRUNING_NAME, HEAD_NAME, LOCK_NAME}.issubset(
        root_names
    ):
        raise UpgradeJournalError("journal root is incomplete")
    _reconcile_expected_lineage_candidate(install_dir)
    records, head, pending_head, head_bytes = _load_lineage_locked(root)
    entries = sorted(operations.iterdir(), key=lambda item: item.name)
    if not entries or len(entries) > MAX_RETAINED_OPERATIONS:
        raise UpgradeJournalError("journal has an invalid operation count")
    if operation_id is not None:
        _string(operation_id, HEX_RE, "operation ID")
    operation_results: dict[str, tuple[dict[str, Any], str | None, bytes]] = {}
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
        intent_bytes = _read_regular(
            entry / INTENT_NAME,
            maximum=MAX_JOURNAL_BYTES,
            owner=owner,
            modes={0o400},
        )
        operation_results[entry.name] = (intent, highest, intent_bytes)

    started: dict[str, tuple[int, dict[str, Any]]] = {}
    terminal: dict[str, tuple[int, dict[str, Any]]] = {}
    for index, (record, _) in enumerate(records):
        if index == 0 and record["sequence"] > 0:
            # The retained terminal boundary is authenticated by checkpoint.json;
            # its detailed operation directory was deliberately compacted.
            continue
        if record["event"] == "started":
            if record["operation_id"] in started:
                raise UpgradeJournalError("lineage replays an operation ID")
            started[record["operation_id"]] = (index, record)
        elif record["event"] in {"activated", "rolled-back"}:
            if record["operation_id"] in terminal:
                raise UpgradeJournalError("lineage repeats a terminal operation")
            terminal[record["operation_id"]] = (index, record)

    extra_operations = set(operation_results) - set(started)
    missing_operations = set(started) - set(operation_results)
    allowed_extra = (
        {pending_unstarted_operation} if pending_unstarted_operation is not None else set()
    )
    if missing_operations or extra_operations != allowed_extra:
        raise UpgradeJournalError(
            "journal operation directories and global lineage differ"
        )
    open_operations: list[str] = []
    for operation_name, (intent, highest, intent_bytes) in operation_results.items():
        if operation_name == pending_unstarted_operation and operation_name not in started:
            if highest is not None:
                raise UpgradeJournalError("unstarted operation already contains a receipt")
            effective_parent = pending_head or head
            base_intent = dict(intent)
            base_intent.pop("operation_id")
            base_intent.pop("lineage")
            if (
                effective_parent["state"] not in {"genesis", "activated", "rolled-back"}
                or _bind_intent_lineage(base_intent, parent_head=effective_parent)
                != intent
            ):
                raise UpgradeJournalError(
                    "unstarted operation differs from stable global head"
                )
            continue
        started_index, started_record = started[operation_name]
        if started_index == 0:
            raise UpgradeJournalError("started lineage record has no parent")
        parent_record, parent_bytes = records[started_index - 1]
        parent_head = _head_from_record(parent_record, parent_bytes)
        base_intent = dict(intent)
        base_intent.pop("operation_id")
        base_intent.pop("lineage")
        if _bind_intent_lineage(base_intent, parent_head=parent_head) != intent:
            raise UpgradeJournalError("operation intent differs from global lineage parent")
        if (
            started_record["intent_sha256"] != _sha256_bytes(intent_bytes)
            or started_record["source_release"]
            != _lineage_release_projection(intent["source"])
            or started_record["target_release"]
            != _lineage_release_projection(intent["target"])
        ):
            raise UpgradeJournalError("started lineage record differs from immutable intent")
        terminal_record = terminal.get(operation_name)
        if highest in {"70-activated", "rolled-back"}:
            receipt_name = (
                ROLLBACK_RECEIPT_NAME
                if highest == "rolled-back"
                else "70-activated.json"
            )
            receipt_digest = _sha256_bytes(
                _read_regular(
                    operations / operation_name / receipt_name,
                    maximum=MAX_JOURNAL_BYTES,
                    owner=owner,
                    modes={0o400},
                )
            )
            expected_event = "rolled-back" if highest == "rolled-back" else "activated"
            if terminal_record is None:
                if not reconcile_terminal:
                    raise UpgradeJournalError(
                        "terminal receipt is not committed to global lineage"
                    )
                effective_head = pending_head or head
                if (
                    effective_head["state"] != "started"
                    or effective_head["operation_id"] != operation_name
                    or effective_head["sequence"] != started_record["sequence"]
                ):
                    raise UpgradeJournalError(
                        "terminal receipt cannot be reconciled with global head"
                    )
                if pending_head is not None:
                    _atomic_replace(
                        root / HEAD_NAME,
                        _canonical_bytes(pending_head),
                        mode=0o400,
                        expected_previous=head_bytes,
                    )
                    return _validate_journal_locked(
                        install_dir,
                        operation_id=operation_id,
                        allow_interrupted_phase=allow_interrupted_phase,
                        reconcile_terminal=reconcile_terminal,
                        pending_unstarted_operation=pending_unstarted_operation,
                    )
                record = _terminal_lineage_record(
                    intent=intent,
                    intent_bytes=intent_bytes,
                    head=head,
                    outcome=expected_event,
                    terminal_receipt_sha256=receipt_digest,
                )
                _publish_lineage_and_head(
                    root=root, record=record, expected_head=head
                )
                return _validate_journal_locked(
                    install_dir,
                    operation_id=operation_id,
                    allow_interrupted_phase=allow_interrupted_phase,
                    reconcile_terminal=False,
                    pending_unstarted_operation=pending_unstarted_operation,
                )
            _, terminal_value = terminal_record
            if (
                terminal_value["event"] != expected_event
                or terminal_value["terminal_receipt_sha256"] != receipt_digest
                or terminal_value["intent_sha256"] != _sha256_bytes(intent_bytes)
            ):
                raise UpgradeJournalError(
                    "terminal lineage record differs from durable receipt"
                )
        else:
            if terminal_record is not None:
                raise UpgradeJournalError(
                    "global lineage is terminal but operation receipts are incomplete"
                )
            open_operations.append(operation_name)

    if len(open_operations) > 1:
        raise UpgradeJournalError("more than one signed upgrade remains open")
    effective_head = pending_head or head
    if open_operations:
        if (
            effective_head["state"] != "started"
            or effective_head["operation_id"] != open_operations[0]
        ):
            raise UpgradeJournalError("open operation differs from global journal head")
    elif effective_head["state"] == "started":
        raise UpgradeJournalError("global journal head references no open operation")

    if pending_head is not None:
        _atomic_replace(
            root / HEAD_NAME,
            _canonical_bytes(pending_head),
            mode=0o400,
            expected_previous=head_bytes,
        )
        return _validate_journal_locked(
            install_dir,
            operation_id=operation_id,
            allow_interrupted_phase=allow_interrupted_phase,
            reconcile_terminal=reconcile_terminal,
            pending_unstarted_operation=pending_unstarted_operation,
        )
    head_candidate = root / f".{HEAD_NAME}.new"
    if head_candidate.exists() or head_candidate.is_symlink():
        _atomic_replace(
            root / HEAD_NAME,
            _canonical_bytes(head),
            mode=0o400,
            expected_previous=_canonical_bytes(head),
        )

    selected_name = operation_id
    if selected_name is None:
        if head["state"] == "genesis":
            raise UpgradeJournalError("journal has no signed-upgrade operation")
        selected_name = head["operation_id"]
    selected = operation_results.get(selected_name)
    if selected is None:
        raise UpgradeJournalError("requested signed-upgrade operation does not exist")
    return selected[0], selected[1]


def _compact_journal_locked(
    install_dir: Path, *, retain_operations: int = COMPACTION_RETAIN_OPERATIONS
) -> bool:
    if not 1 <= retain_operations < MAX_RETAINED_OPERATIONS:
        raise UpgradeJournalError("journal compaction retention is invalid")
    root, operations = _journal_paths(install_dir)
    recovery_pending = (root / NEXT_CHECKPOINT_NAME).exists() or (
        root / NEXT_CHECKPOINT_NAME
    ).is_symlink()
    checkpoint_path = root / CHECKPOINT_NAME
    if checkpoint_path.exists() or checkpoint_path.is_symlink():
        checkpoint_value, _ = _read_canonical_json_control(checkpoint_path)
        durable_checkpoint = _validate_checkpoint(checkpoint_value, root=root)
        recovery_pending = recovery_pending or any(
            (operations / summary["operation_id"]).exists()
            or (operations / summary["operation_id"]).is_symlink()
            for summary in durable_checkpoint["pruned_operations"]
        )
    _discard_torn_checkpoint_candidate_for_exact_retry(root)
    _validate_journal_locked(install_dir)
    records, head, pending_head, _ = _load_lineage_locked(root)
    if pending_head is not None or head["state"] == "started":
        raise UpgradeJournalError("an open or interrupted journal cannot be compacted")
    operation_entries = sorted(operations.iterdir(), key=lambda item: item.name)
    if len(operation_entries) <= retain_operations:
        return recovery_pending
    terminal_records = [
        record
        for index, (record, _) in enumerate(records)
        if record["event"] in {"activated", "rolled-back"}
        and not (index == 0 and record["sequence"] > 0)
    ]
    if len(terminal_records) != len(operation_entries):
        raise UpgradeJournalError("journal operations cannot be correlated for compaction")
    prune_count = len(operation_entries) - retain_operations
    records_to_prune = terminal_records[:prune_count]
    summaries = [
        {
            "operation_id": record["operation_id"],
            "outcome": record["event"],
            "intent_sha256": record["intent_sha256"],
            "source_release_sha256": record["source_release"]["state_sha256"],
            "target_release_sha256": record["target_release"]["state_sha256"],
            "terminal_receipt_sha256": record["terminal_receipt_sha256"],
        }
        for record in records_to_prune
    ]
    operation_names = {entry.name for entry in operation_entries}
    if any(summary["operation_id"] not in operation_names for summary in summaries):
        raise UpgradeJournalError("journal compaction selected an absent operation")
    boundary = records_to_prune[-1]
    boundary_path = root / LINEAGE_NAME / _lineage_filename(boundary["sequence"])
    boundary_bytes = _read_regular(
        boundary_path,
        maximum=MAX_JOURNAL_BYTES,
        owner=os.geteuid(),
        modes={0o400},
    )
    if boundary_bytes != _canonical_bytes(boundary):
        raise UpgradeJournalError("journal compaction boundary changed")
    previous_checkpoint, previous_checkpoint_bytes = _load_checkpoint_locked(root)
    previous_checkpoint_sha256 = (
        _sha256_bytes(previous_checkpoint_bytes)
        if previous_checkpoint_bytes is not None
        else ZERO_DIGEST
    )
    previous_compacted = (
        previous_checkpoint["compacted_operations_sha256"]
        if previous_checkpoint is not None
        else ZERO_DIGEST
    )
    compacted_operation_count = (
        previous_checkpoint["compacted_operation_count"]
        if previous_checkpoint is not None
        else 0
    ) + prune_count
    boundary_digest = _sha256_bytes(boundary_bytes)
    aggregate_input = {
        "previous_checkpoint_sha256": previous_checkpoint_sha256,
        "previous_compacted_operations_sha256": previous_compacted,
        "boundary_record_sha256": boundary_digest,
        "compacted_operation_count": compacted_operation_count,
        "operations": summaries,
    }
    checkpoint = {
        "schema_version": SCHEMA_VERSION,
        "installation_id": head["installation_id"],
        "previous_checkpoint_sha256": previous_checkpoint_sha256,
        "boundary_record": boundary,
        "boundary_record_sha256": boundary_digest,
        "boundary_head": _head_from_record(boundary, boundary_bytes),
        "compacted_operation_count": compacted_operation_count,
        "previous_compacted_operations_sha256": previous_compacted,
        "compacted_operations_sha256": _domain_digest(
            "BackupSheep/upgrade-compacted-operations/v2", aggregate_input
        ),
        "pruned_operations": summaries,
    }
    checkpoint_bytes = _canonical_bytes(checkpoint)
    _validate_checkpoint(checkpoint, root=root)
    _validate_checkpoint_extension(
        checkpoint,
        previous=previous_checkpoint,
        previous_bytes=previous_checkpoint_bytes,
        root=root,
    )
    _atomic_replace(
        root / CHECKPOINT_NAME,
        checkpoint_bytes,
        mode=0o400,
        expected_previous=previous_checkpoint_bytes,
    )
    loaded, _ = _load_checkpoint_locked(root)
    if loaded != checkpoint:
        raise UpgradeJournalError("journal checkpoint did not persist exact bytes")
    _reconcile_checkpoint_pruning(root, checkpoint)
    _validate_journal_locked(install_dir)
    return True


def compact_journal(
    *, install_dir: Path, retain_operations: int = COMPACTION_RETAIN_OPERATIONS
) -> bool:
    with _journal_lock(install_dir):
        return _compact_journal_locked(
            install_dir, retain_operations=retain_operations
        )


def export_checkpoint(*, install_dir: Path) -> dict[str, Any]:
    with _journal_lock(install_dir):
        root, _ = _journal_paths(install_dir)
        _validate_journal_locked(install_dir)
        checkpoint, _ = _load_checkpoint_locked(root)
        if checkpoint is None:
            raise UpgradeJournalError("journal has not produced a compaction checkpoint")
        return checkpoint


def validate_journal(
    install_dir: Path,
    *,
    operation_id: str | None = None,
    allow_interrupted_phase: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    with _journal_lock(install_dir):
        return _validate_journal_locked(
            install_dir,
            operation_id=operation_id,
            allow_interrupted_phase=allow_interrupted_phase,
        )


def _append_receipt_locked(
    *, install_dir: Path, operation_id: str, phase: str, payload_path: Path
) -> dict[str, Any]:
    if phase not in PHASES:
        raise UpgradeJournalError("receipt phase is unsupported")
    _string(operation_id, HEX_RE, "operation ID")
    intent, highest = _validate_journal_locked(
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
    _validate_cross_phase_candidate_before_publish(
        active=active, phase=phase, candidate=payload, intent=intent
    )
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
        _validate_journal_locked(install_dir, operation_id=operation_id)
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
    _, resulting_phase = _validate_journal_locked(
        install_dir, operation_id=operation_id
    )
    if resulting_phase != phase:
        raise UpgradeJournalError("receipt did not become the highest durable phase")
    return receipt


def append_receipt(
    *, install_dir: Path, operation_id: str, phase: str, payload_path: Path
) -> dict[str, Any]:
    with _journal_lock(install_dir):
        return _append_receipt_locked(
            install_dir=install_dir,
            operation_id=operation_id,
            phase=phase,
            payload_path=payload_path,
        )


def _append_rollback_locked(
    *, install_dir: Path, operation_id: str, payload_path: Path
) -> dict[str, Any]:
    _string(operation_id, HEX_RE, "operation ID")
    intent, highest = _validate_journal_locked(
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
        _validate_journal_locked(install_dir, operation_id=operation_id)
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
    _, resulting_phase = _validate_journal_locked(
        install_dir, operation_id=operation_id
    )
    if resulting_phase != "rolled-back":
        raise UpgradeJournalError("rollback did not become the terminal durable outcome")
    return receipt


def append_rollback(
    *, install_dir: Path, operation_id: str, payload_path: Path
) -> dict[str, Any]:
    with _journal_lock(install_dir):
        return _append_rollback_locked(
            install_dir=install_dir,
            operation_id=operation_id,
            payload_path=payload_path,
        )


def finalize_completed(*, install_dir: Path, operation_id: str) -> str:
    with _journal_lock(install_dir):
        intent, highest = _validate_journal_locked(
            install_dir, operation_id=operation_id
        )
        if highest != "70-activated":
            raise UpgradeJournalError("only a fully activated journal may be finalized")
        return intent["operation_id"]


def journal_status(*, install_dir: Path, operation_id: str | None = None) -> dict[str, Any]:
    with _journal_lock(install_dir):
        return _journal_status_locked(
            install_dir=install_dir, operation_id=operation_id
        )


def _journal_status_locked(
    *, install_dir: Path, operation_id: str | None = None
) -> dict[str, Any]:
    intent, highest = _validate_journal_locked(
        install_dir, operation_id=operation_id
    )
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
    compact = subparsers.add_parser("compact")
    compact.add_argument("--install-dir", type=Path, required=True)
    compact.add_argument(
        "--retain-operations",
        type=int,
        default=COMPACTION_RETAIN_OPERATIONS,
    )
    export = subparsers.add_parser("export-checkpoint")
    export.add_argument("--install-dir", type=Path, required=True)
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
        elif arguments.command == "finalize":
            print(
                finalize_completed(
                    install_dir=arguments.install_dir,
                    operation_id=arguments.operation_id,
                )
            )
        elif arguments.command == "compact":
            print(
                "compacted"
                if compact_journal(
                    install_dir=arguments.install_dir,
                    retain_operations=arguments.retain_operations,
                )
                else "unchanged"
            )
        else:
            sys.stdout.buffer.write(
                _canonical_bytes(export_checkpoint(install_dir=arguments.install_dir))
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
