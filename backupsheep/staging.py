"""Filesystem boundary between private plaintext work and shared ciphertext.

The database and files workers have different UIDs and different private work
volumes.  The only filesystem they share with the storage worker is the transfer
volume managed here.  A file is made group-readable there only after it is a
complete, structurally valid BSE1 envelope.

This module deliberately does not encrypt data itself.  Callers must first use
``backupsheep.artifact_crypto.seal_file`` with the returned fence as its trusted
destination root, persist the envelope/key metadata, and only then publish it.
"""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


DATABASE_TRANSFER_ROOT = Path("/var/lib/backupsheep/transfer/database")
FILES_TRANSFER_ROOT = Path("/var/lib/backupsheep/transfer/files")
RESTORE_TRANSFER_ROOT = Path("/var/lib/backupsheep/restore-transfer")
PLAINTEXT_ROOT = Path("/code/_storage")
RESTORE_FILES_READER_GID = 10993
RESTORE_DATABASE_READER_GID = 10994
RESTORE_WRITER_GID = 10995
DATABASE_TRANSFER_WRITER_GID = 10989
DATABASE_TRANSFER_READER_GID = 10990
FILES_TRANSFER_WRITER_GID = 10991
FILES_TRANSFER_READER_GID = 10992
ROOT_UID = 0
ROOT_MODE = 0o3771  # writers can list/create; storage can traverse only a known fence
FENCE_MODE = 0o2750  # owner mutates; the transfer group can only read/traverse
PRIVATE_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
PUBLISHED_FILE_MODE = 0o640
FENCE_MARKER_MODE = 0o440
FENCE_MARKER = ".backupsheep-ciphertext-fence-v1.json"
RESTORE_FENCE_MARKER = ".backupsheep-restore-ciphertext-fence-v1.json"
DEFAULT_MIN_FREE_BYTES = 512 * 1024 * 1024
DEFAULT_MIN_FREE_INODES = 1024
PRODUCTION_MIN_FREE_BYTES = 64 * 1024 * 1024
PRODUCTION_MIN_FREE_INODES = 128

ROLE_IDENTITIES = {
    "web": (10001, 10001),
    "database": (10002, 10002),
    "files": (10003, 10003),
    "storage": (10004, 10004),
    "logs": (10005, 10005),
    "beat": (10006, 10006),
    "migration": (10007, 10007),
    "cloud": (10008, 10008),
}
SOURCE_ROLES = frozenset({"database", "files"})
TRANSFER_ROOTS = {
    "database": DATABASE_TRANSFER_ROOT,
    "files": FILES_TRANSFER_ROOT,
}
TRANSFER_ROOT_VARIABLES = {
    "database": "BACKUPSHEEP_DATABASE_CIPHERTEXT_TRANSFER_ROOT",
    "files": "BACKUPSHEEP_FILES_CIPHERTEXT_TRANSFER_ROOT",
}
TRANSFER_WRITER_GIDS = {
    "database": DATABASE_TRANSFER_WRITER_GID,
    "files": FILES_TRANSFER_WRITER_GID,
}
TRANSFER_READER_GIDS = {
    "database": DATABASE_TRANSFER_READER_GID,
    "files": FILES_TRANSFER_READER_GID,
}
RESTORE_READER_GIDS = {
    "database": RESTORE_DATABASE_READER_GID,
    "files": RESTORE_FILES_READER_GID,
}
_INSTALLATION_ID = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.bse1$")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


class StagingIsolationError(RuntimeError):
    """A filesystem or runtime identity violated the staging contract."""


class _CiphertextFenceNotFound(StagingIsolationError):
    """The exact canonical fence is absent after the root boundary was proven."""


class _RestoreCiphertextFenceNotFound(StagingIsolationError):
    """The exact canonical restore handoff is absent under its proven root."""


@dataclass(frozen=True, slots=True)
class CiphertextFence:
    backup_uuid: str
    installation_id: str
    lane: str
    owner_uid: int
    path: Path


@dataclass(frozen=True, slots=True)
class RestoreCiphertextFence:
    handoff_uuid: str
    backup_uuid: str
    installation_id: str
    target_lane: str
    owner_uid: int
    path: Path


def _mode(metadata: os.stat_result) -> int:
    return stat.S_IMODE(metadata.st_mode)


def _bounded_capacity_value(variable: str, default: int) -> int:
    raw = os.environ.get(variable, str(default))
    if not re.fullmatch(r"[0-9]+", raw):
        raise StagingIsolationError(f"{variable} must be a non-negative integer.")
    value = int(raw)
    if value > (2**63 - 1):
        raise StagingIsolationError(f"{variable} exceeds the supported bound.")
    if os.environ.get("DJANGO_SERVER", "prod") == "prod":
        floor = (
            PRODUCTION_MIN_FREE_BYTES
            if variable.endswith("_BYTES")
            else PRODUCTION_MIN_FREE_INODES
        )
        if value < floor:
            raise StagingIsolationError(f"{variable} is below the production safety floor.")
    return value


def _required_capacity_value(label: str, value: int) -> int:
    if type(value) is not int or value < 0 or value > (2**63 - 1):
        raise StagingIsolationError(f"{label} must be a bounded non-negative integer.")
    return value


def _verify_capacity(
    descriptor: int,
    *,
    bytes_variable: str,
    inodes_variable: str,
    required_bytes: int = 0,
    required_inodes: int = 0,
) -> None:
    requested_bytes = _required_capacity_value("required_bytes", required_bytes)
    requested_inodes = _required_capacity_value("required_inodes", required_inodes)
    minimum_bytes = _bounded_capacity_value(bytes_variable, DEFAULT_MIN_FREE_BYTES)
    minimum_inodes = _bounded_capacity_value(inodes_variable, DEFAULT_MIN_FREE_INODES)
    if requested_bytes > (2**63 - 1) - minimum_bytes:
        raise StagingIsolationError("The required staging-byte capacity overflows its bound.")
    if requested_inodes > (2**63 - 1) - minimum_inodes:
        raise StagingIsolationError("The required staging-inode capacity overflows its bound.")
    filesystem = os.fstatvfs(descriptor)
    available_bytes = filesystem.f_bavail * filesystem.f_frsize
    available_inodes = filesystem.f_favail
    if available_bytes < minimum_bytes + requested_bytes:
        raise StagingIsolationError("The staging filesystem has insufficient free bytes.")
    if available_inodes < minimum_inodes + requested_inodes:
        raise StagingIsolationError("The staging filesystem has insufficient free inodes.")


def _canonical_backup_uuid(value: object) -> str:
    try:
        normalized = str(uuid.UUID(str(value)))
    except (AttributeError, TypeError, ValueError):
        raise StagingIsolationError("The backup identifier must be a canonical UUID.") from None
    if normalized != str(value):
        raise StagingIsolationError("The backup identifier must be a canonical UUID.")
    return normalized


def _canonical_handoff_uuid(value: object) -> str:
    try:
        normalized = str(uuid.UUID(str(value)))
    except (AttributeError, TypeError, ValueError):
        raise StagingIsolationError(
            "The restore handoff identifier must be a canonical UUID."
        ) from None
    if normalized != str(value):
        raise StagingIsolationError(
            "The restore handoff identifier must be a canonical UUID."
        )
    return normalized


def _target_lane(value: object) -> str:
    lane = str(value)
    if lane not in SOURCE_ROLES:
        raise StagingIsolationError(
            "The restore ciphertext target must be database or files."
        )
    return lane


def _installation_id(value: str | None) -> str:
    candidate = value if value is not None else os.environ.get("BACKUPSHEEP_INSTALLATION_ID", "")
    if not _INSTALLATION_ID.fullmatch(candidate):
        raise StagingIsolationError(
            "The staging fence requires the stable 64-character installation identity."
        )
    return candidate


def _runtime_role(*, allowed: frozenset[str] | None = None) -> tuple[str, int, int]:
    role = os.environ.get("BACKUPSHEEP_RUNTIME_ROLE", "")
    identity = ROLE_IDENTITIES.get(role)
    if identity is None or (allowed is not None and role not in allowed):
        raise StagingIsolationError("This runtime role is not allowed at the staging boundary.")
    expected_uid, expected_gid = identity
    if os.geteuid() != expected_uid or os.getegid() != expected_gid:
        raise StagingIsolationError("The staging role does not match the process UID/GID.")
    groups = set(os.getgroups()) | {os.getegid()}
    permitted_groups = {expected_gid}
    if role in SOURCE_ROLES:
        permitted_groups.update(
            {
                TRANSFER_WRITER_GIDS[role],
                TRANSFER_READER_GIDS[role],
            }
        )
        permitted_groups.add(RESTORE_READER_GIDS[role])
    elif role == "storage":
        permitted_groups.update(
            {
                *TRANSFER_READER_GIDS.values(),
                RESTORE_WRITER_GID,
                RESTORE_DATABASE_READER_GID,
                RESTORE_FILES_READER_GID,
            }
        )
    if groups != permitted_groups:
        raise StagingIsolationError("The runtime role has an unsafe transfer-group set.")
    return role, expected_uid, expected_gid


def _configured_root(variable: str, default: Path) -> Path:
    configured = Path(os.environ.get(variable, str(default)))
    if not configured.is_absolute():
        raise StagingIsolationError(f"{variable} must be an absolute path.")
    # Production paths are immutable image/Compose contracts.  Tests may use a
    # temporary root without creating host directories or weakening production.
    if os.environ.get("DJANGO_SERVER", "prod") == "prod" and configured != default:
        raise StagingIsolationError(f"{variable} cannot override the stock production path.")
    return configured


def _open_directory_tree(path: Path) -> int:
    """Open every path component without following an ancestor symlink."""

    try:
        descriptor = os.open(path.anchor, _DIRECTORY_FLAGS)
        for component in path.parts[1:]:
            next_descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
        raise StagingIsolationError("A staging path is missing, unsafe, or not a directory.") from error


def _verify_transfer_root(lane: str) -> tuple[Path, int]:
    lane = _target_lane(lane)
    root = _configured_root(TRANSFER_ROOT_VARIABLES[lane], TRANSFER_ROOTS[lane])
    descriptor = _open_directory_tree(root)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != ROOT_UID
        or metadata.st_gid != TRANSFER_WRITER_GIDS[lane]
        or _mode(metadata) != ROOT_MODE
    ):
        os.close(descriptor)
        raise StagingIsolationError(
            "The ciphertext transfer root has unsafe ownership or permissions."
        )
    return root, descriptor


def _verify_restore_transfer_root() -> tuple[Path, int]:
    root = _configured_root(
        "BACKUPSHEEP_RESTORE_CIPHERTEXT_TRANSFER_ROOT", RESTORE_TRANSFER_ROOT
    )
    descriptor = _open_directory_tree(root)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != ROOT_UID
        or metadata.st_gid != RESTORE_WRITER_GID
        or _mode(metadata) != ROOT_MODE
    ):
        os.close(descriptor)
        raise StagingIsolationError(
            "The restore ciphertext transfer root has unsafe ownership or permissions."
        )
    return root, descriptor


def _private_work_root(
    *,
    allowed_roles: frozenset[str],
    required_bytes: int = 0,
    required_inodes: int = 0,
) -> Path:
    _role, expected_uid, expected_gid = _runtime_role(allowed=allowed_roles)
    root = _configured_root("BACKUPSHEEP_PLAINTEXT_ROOT", PLAINTEXT_ROOT)
    descriptor = _open_directory_tree(root)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or _mode(metadata) != PRIVATE_MODE
        ):
            raise StagingIsolationError(
                "The plaintext work root is not private to this source lane."
            )
        _verify_capacity(
            descriptor,
            bytes_variable="BACKUPSHEEP_PRIVATE_MIN_FREE_BYTES",
            inodes_variable="BACKUPSHEEP_PRIVATE_MIN_FREE_INODES",
            required_bytes=required_bytes,
            required_inodes=required_inodes,
        )
    finally:
        os.close(descriptor)
    return root


def private_plaintext_root() -> Path:
    """Return a source lane's private plaintext root after exact validation."""

    return _private_work_root(allowed_roles=SOURCE_ROLES)


def private_storage_root() -> Path:
    """Return storage's private BSE1 materialization root after validation."""

    return _private_work_root(allowed_roles=frozenset({"storage"}))


def require_private_capacity(
    *, required_bytes: int = 0, required_inodes: int = 0
) -> Path:
    """Validate private-lane headroom in addition to the configured reserve."""

    return _private_work_root(
        allowed_roles=SOURCE_ROLES | {"storage"},
        required_bytes=required_bytes,
        required_inodes=required_inodes,
    )


def require_transfer_capacity(
    *, required_bytes: int = 0, required_inodes: int = 0
) -> Path:
    """Validate shared ciphertext headroom before a source starts sealing."""

    role, _uid, _gid = _runtime_role(allowed=SOURCE_ROLES)
    root, descriptor = _verify_transfer_root(role)
    try:
        _verify_capacity(
            descriptor,
            bytes_variable="BACKUPSHEEP_TRANSFER_MIN_FREE_BYTES",
            inodes_variable="BACKUPSHEEP_TRANSFER_MIN_FREE_INODES",
            required_bytes=required_bytes,
            required_inodes=required_inodes,
        )
    finally:
        os.close(descriptor)
    return root


def require_restore_transfer_capacity(
    *, required_bytes: int = 0, required_inodes: int = 0
) -> Path:
    """Validate reverse-handoff headroom before storage downloads ciphertext."""

    _runtime_role(allowed=frozenset({"storage"}))
    root, descriptor = _verify_restore_transfer_root()
    try:
        _verify_capacity(
            descriptor,
            bytes_variable="BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_BYTES",
            inodes_variable="BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_INODES",
            required_bytes=required_bytes,
            required_inodes=required_inodes,
        )
    finally:
        os.close(descriptor)
    return root


def _marker_bytes(fence: CiphertextFence) -> bytes:
    return (
        json.dumps(
            {
                "backup_uuid": fence.backup_uuid,
                "installation_id": fence.installation_id,
                "lane": fence.lane,
                "owner_uid": fence.owner_uid,
                "schema": 1,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _read_marker(directory_fd: int, lane: str) -> CiphertextFence:
    lane = _target_lane(lane)
    try:
        descriptor = os.open(FENCE_MARKER, _FILE_FLAGS, dir_fd=directory_fd)
    except OSError as error:
        raise StagingIsolationError("The ciphertext fence marker is missing or unsafe.") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_gid != TRANSFER_READER_GIDS[lane]
            or _mode(metadata) != FENCE_MARKER_MODE
        ):
            raise StagingIsolationError("The ciphertext fence marker metadata is unsafe.")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            raw = source.read(2049)
        if len(raw) > 2048:
            raise StagingIsolationError("The ciphertext fence marker is oversized.")
        try:
            values = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise StagingIsolationError("The ciphertext fence marker is invalid.") from None
        if not isinstance(values, dict) or set(values) != {
            "backup_uuid",
            "installation_id",
            "lane",
            "owner_uid",
            "schema",
        }:
            raise StagingIsolationError("The ciphertext fence marker fields are invalid.")
        backup_uuid = _canonical_backup_uuid(values["backup_uuid"])
        installation_id = _installation_id(str(values["installation_id"]))
        marker_lane = str(values["lane"])
        owner_uid = values["owner_uid"]
        if (
            values["schema"] != 1
            or marker_lane != lane
            or type(owner_uid) is not int
            or ROLE_IDENTITIES[marker_lane][0] != owner_uid
            or metadata.st_uid != owner_uid
        ):
            raise StagingIsolationError("The ciphertext fence marker identity is invalid.")
        fence = CiphertextFence(
            backup_uuid=backup_uuid,
            installation_id=installation_id,
            lane=marker_lane,
            owner_uid=owner_uid,
            path=Path(),
        )
        if raw != _marker_bytes(fence):
            raise StagingIsolationError("The ciphertext fence marker is not canonical.")
        return fence
    finally:
        os.close(descriptor)


def _open_fence(
    root_fd: int,
    root: Path,
    backup_uuid: str,
    installation_id: str,
    lane: str,
) -> tuple[CiphertextFence, int]:
    lane = _target_lane(lane)
    try:
        descriptor = os.open(backup_uuid, _DIRECTORY_FLAGS, dir_fd=root_fd)
    except FileNotFoundError as error:
        raise _CiphertextFenceNotFound("The ciphertext fence is absent.") from error
    except OSError as error:
        raise StagingIsolationError("The ciphertext fence is missing or unsafe.") from error
    try:
        metadata = os.fstat(descriptor)
        marker = _read_marker(descriptor, lane)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_gid != TRANSFER_READER_GIDS[lane]
            or _mode(metadata) != FENCE_MODE
            or metadata.st_uid != marker.owner_uid
            or marker.backup_uuid != backup_uuid
            or marker.installation_id != installation_id
        ):
            raise StagingIsolationError("The ciphertext fence identity is inconsistent.")
        return CiphertextFence(
            backup_uuid=marker.backup_uuid,
            installation_id=marker.installation_id,
            lane=marker.lane,
            owner_uid=marker.owner_uid,
            path=root / backup_uuid,
        ), descriptor
    except BaseException:
        os.close(descriptor)
        raise


def create_ciphertext_fence(
    backup_uuid: object, *, installation_id: str | None = None
) -> CiphertextFence:
    """Create or validate the source lane's immutable backup ownership fence."""

    role, current_uid, _current_gid = _runtime_role(allowed=SOURCE_ROLES)
    canonical_uuid = _canonical_backup_uuid(backup_uuid)
    installation = _installation_id(installation_id)
    root, root_fd = _verify_transfer_root(role)
    try:
        _verify_capacity(
            root_fd,
            bytes_variable="BACKUPSHEEP_TRANSFER_MIN_FREE_BYTES",
            inodes_variable="BACKUPSHEEP_TRANSFER_MIN_FREE_INODES",
            required_inodes=2,
        )
        try:
            os.mkdir(canonical_uuid, mode=0o700, dir_fd=root_fd)
            created = True
        except FileExistsError:
            created = False
        if created:
            directory_fd = -1
            try:
                directory_fd = os.open(canonical_uuid, _DIRECTORY_FLAGS, dir_fd=root_fd)
                metadata = os.fstat(directory_fd)
                if (
                    metadata.st_uid != current_uid
                    or metadata.st_gid != TRANSFER_WRITER_GIDS[role]
                ):
                    raise StagingIsolationError(
                        "The transfer filesystem did not inherit the ciphertext group."
                    )
                os.fchown(directory_fd, -1, TRANSFER_READER_GIDS[role])
                os.fchmod(directory_fd, FENCE_MODE)
                fence = CiphertextFence(
                    backup_uuid=canonical_uuid,
                    installation_id=installation,
                    lane=role,
                    owner_uid=current_uid,
                    path=root / canonical_uuid,
                )
                marker_fd = os.open(
                    FENCE_MARKER,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o400,
                    dir_fd=directory_fd,
                )
                try:
                    marker = _marker_bytes(fence)
                    written = os.write(marker_fd, marker)
                    if written != len(marker):
                        raise OSError("short staging marker write")
                    os.fchmod(marker_fd, FENCE_MARKER_MODE)
                    os.fsync(marker_fd)
                finally:
                    os.close(marker_fd)
                os.fsync(directory_fd)
            except BaseException:
                if directory_fd >= 0:
                    try:
                        os.unlink(FENCE_MARKER, dir_fd=directory_fd)
                    except OSError:
                        pass
                    os.close(directory_fd)
                try:
                    os.rmdir(canonical_uuid, dir_fd=root_fd)
                except OSError:
                    pass
                raise
            else:
                os.close(directory_fd)
                os.fsync(root_fd)
        fence, fence_fd = _open_fence(
            root_fd, root, canonical_uuid, installation, role
        )
        os.close(fence_fd)
        if fence.lane != role or fence.owner_uid != current_uid:
            raise StagingIsolationError("A different source lane owns this backup fence.")
        return fence
    finally:
        os.close(root_fd)


def _artifact_name(value: object) -> str:
    name = str(value)
    if not _ARTIFACT_NAME.fullmatch(name) or name in {".", "..", FENCE_MARKER}:
        raise StagingIsolationError("The ciphertext artifact name is invalid.")
    return name


def _validate_bse1_descriptor(
    descriptor: int, fence: CiphertextFence | RestoreCiphertextFence
) -> None:
    # Lazy import keeps the filesystem policy usable during image/bootstrap checks
    # without initializing the artifact-crypto implementation.
    from backupsheep.artifact_crypto import read_envelope_header_from_descriptor

    envelope = read_envelope_header_from_descriptor(descriptor)
    if str(envelope.envelope_id) != fence.backup_uuid:
        raise StagingIsolationError("The BSE1 envelope is not bound to its backup fence.")


def publish_ciphertext(
    backup_uuid: object,
    artifact_name: object,
    *,
    installation_id: str | None = None,
) -> Path:
    """Make one completed BSE1 envelope readable by the storage role.

    The BSE1 writer must leave the file at mode 0600.  This function is the only
    transition to 0640, and it occurs after structural validation and fence binding.
    """

    role, current_uid, _current_gid = _runtime_role(allowed=SOURCE_ROLES)
    canonical_uuid = _canonical_backup_uuid(backup_uuid)
    installation = _installation_id(installation_id)
    name = _artifact_name(artifact_name)
    root, root_fd = _verify_transfer_root(role)
    try:
        _verify_capacity(
            root_fd,
            bytes_variable="BACKUPSHEEP_TRANSFER_MIN_FREE_BYTES",
            inodes_variable="BACKUPSHEEP_TRANSFER_MIN_FREE_INODES",
        )
        fence, fence_fd = _open_fence(
            root_fd, root, canonical_uuid, installation, role
        )
        try:
            if fence.lane != role or fence.owner_uid != current_uid:
                raise StagingIsolationError("A different source lane owns this backup fence.")
            try:
                descriptor = os.open(name, _FILE_FLAGS, dir_fd=fence_fd)
            except OSError as error:
                raise StagingIsolationError("The ciphertext artifact is missing or unsafe.") from error
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != current_uid
                    or before.st_gid != TRANSFER_READER_GIDS[role]
                    or _mode(before) != PRIVATE_FILE_MODE
                ):
                    raise StagingIsolationError(
                        "Only a private, single-link source-owned file can be published."
                    )
                _validate_bse1_descriptor(descriptor, fence)
                held_after = os.fstat(descriptor)
                after = os.stat(name, dir_fd=fence_fd, follow_symlinks=False)
                if (
                    held_after.st_dev,
                    held_after.st_ino,
                    held_after.st_size,
                    held_after.st_mtime_ns,
                    held_after.st_ctime_ns,
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                ) != (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                ):
                    raise StagingIsolationError("The ciphertext artifact changed during validation.")
                os.fchmod(descriptor, PUBLISHED_FILE_MODE)
                os.fsync(descriptor)
                os.fsync(fence_fd)
            finally:
                os.close(descriptor)
            return fence.path / name
        finally:
            os.close(fence_fd)
    finally:
        os.close(root_fd)


def open_ciphertext(
    backup_uuid: object,
    artifact_name: object,
    *,
    source_lane: object,
    installation_id: str | None = None,
) -> BinaryIO:
    """Open a published BSE1 envelope for a storage upload, fail closed."""

    _runtime_role(allowed=frozenset({"storage"}))
    lane = _target_lane(source_lane)
    canonical_uuid = _canonical_backup_uuid(backup_uuid)
    installation = _installation_id(installation_id)
    name = _artifact_name(artifact_name)
    root, root_fd = _verify_transfer_root(lane)
    try:
        fence, fence_fd = _open_fence(
            root_fd, root, canonical_uuid, installation, lane
        )
        try:
            try:
                descriptor = os.open(name, _FILE_FLAGS, dir_fd=fence_fd)
            except OSError as error:
                raise StagingIsolationError("The ciphertext artifact is missing or unsafe.") from error
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != fence.owner_uid
                    or before.st_gid != TRANSFER_READER_GIDS[lane]
                    or _mode(before) != PUBLISHED_FILE_MODE
                ):
                    raise StagingIsolationError("The published ciphertext metadata is unsafe.")
                _validate_bse1_descriptor(descriptor, fence)
                held_after = os.fstat(descriptor)
                after = os.stat(name, dir_fd=fence_fd, follow_symlinks=False)
                if (
                    held_after.st_dev,
                    held_after.st_ino,
                    held_after.st_size,
                    held_after.st_mtime_ns,
                    held_after.st_ctime_ns,
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    _mode(after),
                ) != (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    PUBLISHED_FILE_MODE,
                ):
                    raise StagingIsolationError("The ciphertext artifact changed during validation.")
                return os.fdopen(descriptor, "rb")
            except BaseException:
                os.close(descriptor)
                raise
        finally:
            os.close(fence_fd)
    finally:
        os.close(root_fd)


def cleanup_ciphertext_fence(
    backup_uuid: object, *, installation_id: str | None = None
) -> bool:
    """Delete one owned fence, returning false only when its exact path is absent."""

    role, current_uid, _current_gid = _runtime_role(allowed=SOURCE_ROLES)
    canonical_uuid = _canonical_backup_uuid(backup_uuid)
    installation = _installation_id(installation_id)
    root, root_fd = _verify_transfer_root(role)
    try:
        try:
            fence, fence_fd = _open_fence(
                root_fd, root, canonical_uuid, installation, role
            )
        except _CiphertextFenceNotFound:
            return False
        try:
            if fence.lane != role or fence.owner_uid != current_uid:
                raise StagingIsolationError("A different source lane owns this backup fence.")
            names = os.listdir(fence_fd)
            artifacts: list[str] = []
            for name in names:
                if name == FENCE_MARKER:
                    continue
                normalized = _artifact_name(name)
                metadata = os.stat(normalized, dir_fd=fence_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != current_uid
                    or metadata.st_gid != TRANSFER_READER_GIDS[role]
                    or _mode(metadata)
                    not in {PRIVATE_FILE_MODE, PUBLISHED_FILE_MODE}
                ):
                    raise StagingIsolationError(
                        "The fence contains an unowned or unsafe path; cleanup refused."
                    )
                # A crash after BSE1's atomic link but before publication leaves a
                # complete source-owned 0600 envelope.  It is safe for that same
                # source lane to discard; partial or non-BSE1 files still block the
                # entire cleanup before any mutation.
                descriptor = os.open(normalized, _FILE_FLAGS, dir_fd=fence_fd)
                try:
                    _validate_bse1_descriptor(descriptor, fence)
                finally:
                    os.close(descriptor)
                artifacts.append(normalized)
            # Validate the whole inventory before the first mutation.
            for name in artifacts:
                os.unlink(name, dir_fd=fence_fd)
            os.unlink(FENCE_MARKER, dir_fd=fence_fd)
            os.fsync(fence_fd)
        finally:
            os.close(fence_fd)
        os.rmdir(canonical_uuid, dir_fd=root_fd)
        os.fsync(root_fd)
        return True
    finally:
        os.close(root_fd)


def _restore_marker_bytes(fence: RestoreCiphertextFence) -> bytes:
    return (
        json.dumps(
            {
                "backup_uuid": fence.backup_uuid,
                "handoff_uuid": fence.handoff_uuid,
                "installation_id": fence.installation_id,
                "owner_uid": fence.owner_uid,
                "schema": 1,
                "target_lane": fence.target_lane,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _read_restore_marker(directory_fd: int) -> RestoreCiphertextFence:
    try:
        descriptor = os.open(RESTORE_FENCE_MARKER, _FILE_FLAGS, dir_fd=directory_fd)
    except OSError as error:
        raise StagingIsolationError(
            "The restore ciphertext fence marker is missing or unsafe."
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != ROLE_IDENTITIES["storage"][0]
            or _mode(metadata) != FENCE_MARKER_MODE
        ):
            raise StagingIsolationError(
                "The restore ciphertext fence marker metadata is unsafe."
            )
        with os.fdopen(os.dup(descriptor), "rb") as source:
            raw = source.read(2049)
        if len(raw) > 2048:
            raise StagingIsolationError(
                "The restore ciphertext fence marker is oversized."
            )
        try:
            values = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise StagingIsolationError(
                "The restore ciphertext fence marker is invalid."
            ) from None
        if not isinstance(values, dict) or set(values) != {
            "backup_uuid",
            "handoff_uuid",
            "installation_id",
            "owner_uid",
            "schema",
            "target_lane",
        }:
            raise StagingIsolationError(
                "The restore ciphertext fence marker fields are invalid."
            )
        handoff_uuid = _canonical_handoff_uuid(values["handoff_uuid"])
        backup_uuid = _canonical_backup_uuid(values["backup_uuid"])
        installation_id = _installation_id(str(values["installation_id"]))
        target_lane = _target_lane(values["target_lane"])
        owner_uid = values["owner_uid"]
        if (
            values["schema"] != 1
            or type(owner_uid) is not int
            or owner_uid != ROLE_IDENTITIES["storage"][0]
            or metadata.st_gid != RESTORE_READER_GIDS[target_lane]
        ):
            raise StagingIsolationError(
                "The restore ciphertext fence marker identity is invalid."
            )
        fence = RestoreCiphertextFence(
            handoff_uuid=handoff_uuid,
            backup_uuid=backup_uuid,
            installation_id=installation_id,
            target_lane=target_lane,
            owner_uid=owner_uid,
            path=Path(),
        )
        if raw != _restore_marker_bytes(fence):
            raise StagingIsolationError(
                "The restore ciphertext fence marker is not canonical."
            )
        return fence
    finally:
        os.close(descriptor)


def _open_restore_fence(
    root_fd: int,
    root: Path,
    handoff_uuid: str,
    backup_uuid: str,
    installation_id: str,
    target_lane: str,
) -> tuple[RestoreCiphertextFence, int]:
    try:
        descriptor = os.open(handoff_uuid, _DIRECTORY_FLAGS, dir_fd=root_fd)
    except FileNotFoundError as error:
        raise _RestoreCiphertextFenceNotFound(
            "The restore ciphertext fence is absent."
        ) from error
    except OSError as error:
        raise StagingIsolationError(
            "The restore ciphertext fence is missing or unsafe."
        ) from error
    try:
        metadata = os.fstat(descriptor)
        marker = _read_restore_marker(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != ROLE_IDENTITIES["storage"][0]
            or metadata.st_gid != RESTORE_READER_GIDS[target_lane]
            or _mode(metadata) != FENCE_MODE
            or marker.handoff_uuid != handoff_uuid
            or marker.backup_uuid != backup_uuid
            or marker.installation_id != installation_id
            or marker.target_lane != target_lane
        ):
            raise StagingIsolationError(
                "The restore ciphertext fence identity is inconsistent."
            )
        return RestoreCiphertextFence(
            handoff_uuid=marker.handoff_uuid,
            backup_uuid=marker.backup_uuid,
            installation_id=marker.installation_id,
            target_lane=marker.target_lane,
            owner_uid=marker.owner_uid,
            path=root / handoff_uuid,
        ), descriptor
    except BaseException:
        os.close(descriptor)
        raise


def create_restore_ciphertext_fence(
    handoff_uuid: object,
    *,
    backup_uuid: object,
    target_lane: object,
    installation_id: str | None = None,
) -> RestoreCiphertextFence:
    """Create or validate storage's exact ciphertext-only restore handoff."""

    _role, current_uid, _current_gid = _runtime_role(
        allowed=frozenset({"storage"})
    )
    canonical_handoff = _canonical_handoff_uuid(handoff_uuid)
    canonical_backup = _canonical_backup_uuid(backup_uuid)
    installation = _installation_id(installation_id)
    lane = _target_lane(target_lane)
    reader_gid = RESTORE_READER_GIDS[lane]
    root, root_fd = _verify_restore_transfer_root()
    try:
        _verify_capacity(
            root_fd,
            bytes_variable="BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_BYTES",
            inodes_variable="BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_INODES",
            required_inodes=2,
        )
        try:
            os.mkdir(canonical_handoff, mode=0o700, dir_fd=root_fd)
            created = True
        except FileExistsError:
            created = False
        if created:
            directory_fd = -1
            try:
                directory_fd = os.open(
                    canonical_handoff, _DIRECTORY_FLAGS, dir_fd=root_fd
                )
                metadata = os.fstat(directory_fd)
                if (
                    metadata.st_uid != current_uid
                    or metadata.st_gid != RESTORE_WRITER_GID
                ):
                    raise StagingIsolationError(
                        "The restore transfer filesystem did not inherit its writer group."
                    )
                os.fchown(directory_fd, -1, reader_gid)
                os.fchmod(directory_fd, FENCE_MODE)
                fence = RestoreCiphertextFence(
                    handoff_uuid=canonical_handoff,
                    backup_uuid=canonical_backup,
                    installation_id=installation,
                    target_lane=lane,
                    owner_uid=current_uid,
                    path=root / canonical_handoff,
                )
                marker_fd = os.open(
                    RESTORE_FENCE_MARKER,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o400,
                    dir_fd=directory_fd,
                )
                try:
                    marker_metadata = os.fstat(marker_fd)
                    if (
                        not stat.S_ISREG(marker_metadata.st_mode)
                        or marker_metadata.st_nlink != 1
                        or marker_metadata.st_uid != current_uid
                        or marker_metadata.st_gid != reader_gid
                    ):
                        raise StagingIsolationError(
                            "The restore fence marker did not inherit safe ownership."
                        )
                    marker = _restore_marker_bytes(fence)
                    written = os.write(marker_fd, marker)
                    if written != len(marker):
                        raise OSError("short restore staging marker write")
                    os.fchmod(marker_fd, FENCE_MARKER_MODE)
                    os.fsync(marker_fd)
                finally:
                    os.close(marker_fd)
                os.fsync(directory_fd)
            except BaseException:
                if directory_fd >= 0:
                    try:
                        os.unlink(RESTORE_FENCE_MARKER, dir_fd=directory_fd)
                    except OSError:
                        pass
                    os.close(directory_fd)
                try:
                    os.rmdir(canonical_handoff, dir_fd=root_fd)
                except OSError:
                    pass
                raise
            else:
                os.close(directory_fd)
                os.fsync(root_fd)
        fence, fence_fd = _open_restore_fence(
            root_fd,
            root,
            canonical_handoff,
            canonical_backup,
            installation,
            lane,
        )
        os.close(fence_fd)
        if fence.owner_uid != current_uid:
            raise StagingIsolationError(
                "A foreign identity owns this restore ciphertext fence."
            )
        return fence
    finally:
        os.close(root_fd)


def publish_restore_ciphertext(
    handoff_uuid: object,
    artifact_name: object,
    *,
    backup_uuid: object,
    target_lane: object,
    installation_id: str | None = None,
) -> Path:
    """Publish storage-owned BSE1 bytes read-only to one restore source lane."""

    _role, current_uid, _current_gid = _runtime_role(
        allowed=frozenset({"storage"})
    )
    canonical_handoff = _canonical_handoff_uuid(handoff_uuid)
    canonical_backup = _canonical_backup_uuid(backup_uuid)
    installation = _installation_id(installation_id)
    lane = _target_lane(target_lane)
    name = _artifact_name(artifact_name)
    root, root_fd = _verify_restore_transfer_root()
    try:
        _verify_capacity(
            root_fd,
            bytes_variable="BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_BYTES",
            inodes_variable="BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_INODES",
        )
        fence, fence_fd = _open_restore_fence(
            root_fd,
            root,
            canonical_handoff,
            canonical_backup,
            installation,
            lane,
        )
        try:
            try:
                descriptor = os.open(name, _FILE_FLAGS, dir_fd=fence_fd)
            except OSError as error:
                raise StagingIsolationError(
                    "The restore ciphertext artifact is missing or unsafe."
                ) from error
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != current_uid
                    or before.st_gid != RESTORE_READER_GIDS[lane]
                    or _mode(before) != PRIVATE_FILE_MODE
                ):
                    raise StagingIsolationError(
                        "Only a private, single-link storage-owned restore file can be published."
                    )
                _validate_bse1_descriptor(descriptor, fence)
                held_after = os.fstat(descriptor)
                after = os.stat(name, dir_fd=fence_fd, follow_symlinks=False)
                if (
                    held_after.st_dev,
                    held_after.st_ino,
                    held_after.st_size,
                    held_after.st_mtime_ns,
                    held_after.st_ctime_ns,
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                ) != (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                ):
                    raise StagingIsolationError(
                        "The restore ciphertext changed during validation."
                    )
                os.fchmod(descriptor, PUBLISHED_FILE_MODE)
                os.fsync(descriptor)
                os.fsync(fence_fd)
            finally:
                os.close(descriptor)
            return fence.path / name
        finally:
            os.close(fence_fd)
    finally:
        os.close(root_fd)


def open_restore_ciphertext(
    handoff_uuid: object,
    artifact_name: object,
    *,
    backup_uuid: object,
    target_lane: object,
    installation_id: str | None = None,
) -> BinaryIO:
    """Open one published restore envelope for its exact source lane."""

    role, _current_uid, _current_gid = _runtime_role(allowed=SOURCE_ROLES)
    lane = _target_lane(target_lane)
    if role != lane:
        raise StagingIsolationError(
            "This source lane does not own the restore ciphertext handoff."
        )
    canonical_handoff = _canonical_handoff_uuid(handoff_uuid)
    canonical_backup = _canonical_backup_uuid(backup_uuid)
    installation = _installation_id(installation_id)
    name = _artifact_name(artifact_name)
    root, root_fd = _verify_restore_transfer_root()
    try:
        fence, fence_fd = _open_restore_fence(
            root_fd,
            root,
            canonical_handoff,
            canonical_backup,
            installation,
            lane,
        )
        try:
            try:
                descriptor = os.open(name, _FILE_FLAGS, dir_fd=fence_fd)
            except OSError as error:
                raise StagingIsolationError(
                    "The restore ciphertext artifact is missing or unsafe."
                ) from error
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != ROLE_IDENTITIES["storage"][0]
                    or before.st_gid != RESTORE_READER_GIDS[lane]
                    or _mode(before) != PUBLISHED_FILE_MODE
                ):
                    raise StagingIsolationError(
                        "The published restore ciphertext metadata is unsafe."
                    )
                _validate_bse1_descriptor(descriptor, fence)
                held_after = os.fstat(descriptor)
                after = os.stat(name, dir_fd=fence_fd, follow_symlinks=False)
                if (
                    held_after.st_dev,
                    held_after.st_ino,
                    held_after.st_size,
                    held_after.st_mtime_ns,
                    held_after.st_ctime_ns,
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    _mode(after),
                ) != (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    PUBLISHED_FILE_MODE,
                ):
                    raise StagingIsolationError(
                        "The restore ciphertext changed during validation."
                    )
                return os.fdopen(descriptor, "rb")
            except BaseException:
                os.close(descriptor)
                raise
        finally:
            os.close(fence_fd)
    finally:
        os.close(root_fd)


def cleanup_restore_ciphertext_fence(
    handoff_uuid: object,
    *,
    backup_uuid: object,
    target_lane: object,
    installation_id: str | None = None,
) -> bool:
    """Delete one exact storage-owned restore handoff after full validation."""

    _role, current_uid, _current_gid = _runtime_role(
        allowed=frozenset({"storage"})
    )
    canonical_handoff = _canonical_handoff_uuid(handoff_uuid)
    canonical_backup = _canonical_backup_uuid(backup_uuid)
    installation = _installation_id(installation_id)
    lane = _target_lane(target_lane)
    root, root_fd = _verify_restore_transfer_root()
    try:
        try:
            fence, fence_fd = _open_restore_fence(
                root_fd,
                root,
                canonical_handoff,
                canonical_backup,
                installation,
                lane,
            )
        except _RestoreCiphertextFenceNotFound:
            return False
        try:
            names = os.listdir(fence_fd)
            artifacts: list[str] = []
            for name in names:
                if name == RESTORE_FENCE_MARKER:
                    continue
                normalized = _artifact_name(name)
                metadata = os.stat(normalized, dir_fd=fence_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != current_uid
                    or metadata.st_gid != RESTORE_READER_GIDS[lane]
                    or _mode(metadata)
                    not in {PRIVATE_FILE_MODE, PUBLISHED_FILE_MODE}
                ):
                    raise StagingIsolationError(
                        "The restore fence contains an unsafe path; cleanup refused."
                    )
                descriptor = os.open(normalized, _FILE_FLAGS, dir_fd=fence_fd)
                try:
                    _validate_bse1_descriptor(descriptor, fence)
                finally:
                    os.close(descriptor)
                artifacts.append(normalized)
            for name in artifacts:
                os.unlink(name, dir_fd=fence_fd)
            os.unlink(RESTORE_FENCE_MARKER, dir_fd=fence_fd)
            os.fsync(fence_fd)
        finally:
            os.close(fence_fd)
        os.rmdir(canonical_handoff, dir_fd=root_fd)
        os.fsync(root_fd)
        return True
    finally:
        os.close(root_fd)


__all__ = [
    "CiphertextFence",
    "RestoreCiphertextFence",
    "StagingIsolationError",
    "cleanup_ciphertext_fence",
    "cleanup_restore_ciphertext_fence",
    "create_ciphertext_fence",
    "create_restore_ciphertext_fence",
    "open_ciphertext",
    "open_restore_ciphertext",
    "private_plaintext_root",
    "private_storage_root",
    "publish_ciphertext",
    "publish_restore_ciphertext",
    "require_private_capacity",
    "require_restore_transfer_capacity",
    "require_transfer_capacity",
]
