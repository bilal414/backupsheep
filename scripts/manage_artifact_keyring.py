#!/usr/bin/env python3
"""Manage non-Docker local-file keyrings or derive their policy witness.

Installer-managed deployments should use install.sh, which holds the deployment
mutation lock and enforces worker state. This tool provides the same bounded
keyring format for direct Python deployments. It never prints root key material
and intentionally has no key-eviction operation.
"""

from __future__ import annotations

import os
import sys


def _pin_repository_import_root() -> str:
    """Put this script's real repository root ahead of ambient import paths."""

    script_path = os.path.realpath(__file__)
    repository_root = os.path.dirname(os.path.dirname(script_path))
    package_root = os.path.join(repository_root, "backupsheep")
    package_init = os.path.join(package_root, "__init__.py")
    if (
        os.path.basename(script_path) != "manage_artifact_keyring.py"
        or os.path.basename(os.path.dirname(script_path)) != "scripts"
        or not os.path.isdir(package_root)
        or os.path.islink(package_root)
        or not os.path.isfile(package_init)
        or os.path.islink(package_init)
    ):
        raise RuntimeError(
            "artifact keyring management must run from a complete BackupSheep repository"
        )

    ambient_paths = {
        os.path.realpath(entry or os.getcwd())
        for entry in os.environ.get("PYTHONPATH", "").split(os.pathsep)
    }
    sanitized_paths = []
    for entry in sys.path:
        resolved_entry = os.path.realpath(entry or os.getcwd())
        if resolved_entry == repository_root or resolved_entry in ambient_paths:
            continue
        sanitized_paths.append(entry)
    sys.path[:] = [repository_root, *sanitized_paths]
    os.environ.pop("PYTHONPATH", None)
    return repository_root


_REPOSITORY_ROOT = _pin_repository_import_root()

import argparse  # noqa: E402
import fcntl  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import secrets  # noqa: E402
import stat  # noqa: E402
from pathlib import Path  # noqa: E402

from backupsheep.artifact_crypto.context import (  # noqa: E402
    artifact_provider_policy_witness,
)
from backupsheep.artifact_crypto.providers.base import zeroize  # noqa: E402
from backupsheep.artifact_crypto.providers.local_file import (  # noqa: E402
    KEYRING_MAGIC,
    KEYRING_VERSION,
    MAX_KEYRING_BYTES,
    MAX_KEYRING_KEYS,
    LocalFileKeyProvider,
    canonical_keyring_bytes,
    open_keyring_parent_directory,
)


class KeyringLifecycleError(RuntimeError):
    pass


_MAX_TEMPORARY_RESIDUES = 64
_TEMPORARY_TOKEN_LENGTH = 24
_LOWER_HEXADECIMAL = frozenset("0123456789abcdef")
_KEY_ID_PATTERN = re.compile(r"^lfk-[0-9a-f]{32}$")
_KEY_ENTRY_PATTERN = re.compile(r"^key=(lfk-[0-9a-f]{32}):([0-9a-f]{64})$")
_INSTALLATION_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_LANES = frozenset({"database", "files"})


class _ValidatedKeyring:
    """A descriptor-relative strict keyring view with explicit zeroization."""

    def __init__(self, active_key_id: str, keys: dict[str, bytearray]):
        self.active_key_id = active_key_id
        self._keys = keys
        self._destroyed = False

    @property
    def key_ids(self) -> tuple[str, ...]:
        if self._destroyed:
            raise KeyringLifecycleError("the validated keyring has been destroyed")
        return tuple(self._keys)

    def destroy(self) -> None:
        if self._destroyed:
            return
        for key in self._keys.values():
            zeroize(key)
        self._keys.clear()
        self.active_key_id = ""
        self._destroyed = True


def _path(value: str) -> Path:
    if not os.path.isabs(value):
        raise argparse.ArgumentTypeError("keyring path must be absolute")
    return Path(value)


def _installation_id(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError(
            "installation ID must be exactly 64 lowercase hexadecimal characters"
        )
    return value


def _open_locked_parent(path: Path) -> int:
    try:
        descriptor = open_keyring_parent_directory(path)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise KeyringLifecycleError(
                "the keyring parent must be an owner-controlled mode-0700 directory"
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise KeyringLifecycleError(
            "another keyring mutation holds the parent-directory lock"
        ) from None
    except OSError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise KeyringLifecycleError(
            "the keyring path contains an unsafe or unavailable ancestor"
        ) from None
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _secure_parent_metadata(metadata: os.stat_result) -> bool:
    return bool(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def _attest_locked_parent(path: Path, parent: int) -> None:
    """Require the supplied pathname to still name the locked directory inode."""

    try:
        locked = os.fstat(parent)
    except OSError as error:
        raise KeyringLifecycleError(
            "the locked keyring parent directory became unavailable"
        ) from error
    if not _secure_parent_metadata(locked):
        raise KeyringLifecycleError(
            "the locked keyring parent directory metadata changed"
        )

    reopened = None
    try:
        reopened = open_keyring_parent_directory(path)
        named = os.fstat(reopened)
    except OSError as error:
        raise KeyringLifecycleError(
            "the keyring parent path no longer names the locked directory"
        ) from error
    finally:
        if reopened is not None:
            os.close(reopened)

    if (
        not _secure_parent_metadata(named)
        or named.st_dev != locked.st_dev
        or named.st_ino != locked.st_ino
    ):
        raise KeyringLifecycleError(
            "the keyring parent path no longer names the locked directory"
        )


def _temporary_name(path: Path) -> str:
    return f".{path.name}.{secrets.token_hex(12)}.tmp"


def _temporary_residue_names(path: Path, parent: int) -> list[str]:
    """Return only names that this tool can generate for this destination."""

    prefix = f".{path.name}."
    suffix = ".tmp"
    try:
        entries = os.listdir(parent)
    except OSError as error:
        raise KeyringLifecycleError(
            "the keyring parent could not be inspected for interrupted operations"
        ) from error
    residues = []
    for name in entries:
        if not name.startswith(prefix) or not name.endswith(suffix):
            continue
        token = name[len(prefix) : -len(suffix)]
        if len(token) != _TEMPORARY_TOKEN_LENGTH or any(
            character not in _LOWER_HEXADECIMAL for character in token
        ):
            continue
        residues.append(name)
    if len(residues) > _MAX_TEMPORARY_RESIDUES:
        raise KeyringLifecycleError(
            "too many interrupted keyring operation residues exist"
        )
    return sorted(residues)


def _stat_at(parent: int, name: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as error:
        raise KeyringLifecycleError(
            "an interrupted keyring operation residue changed concurrently"
        ) from error


def _metadata_identity(metadata: os.stat_result) -> tuple[object, ...]:
    return tuple(
        getattr(metadata, field)
        for field in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_nlink",
        )
    )


def _unlink_attested(
    path: Path,
    parent: int,
    name: str,
    *,
    expected: os.stat_result | None = None,
    missing_ok: bool = False,
) -> None:
    """Remove one descriptor-relative name and still report a parent swap.

    Cleanup remains safe when the named parent has been replaced because the
    unlink is anchored to the locked directory descriptor.  The operation must
    nevertheless fail closed: an identity failure observed before or after the
    unlink is re-raised after the attested residue has been removed.
    """

    identity_error = None
    try:
        _attest_locked_parent(path, parent)
    except KeyringLifecycleError as error:
        identity_error = error

    removed = _unlink_exact_at(
        parent,
        name,
        expected=expected,
        missing_ok=missing_ok,
    )
    if removed:
        try:
            os.fsync(parent)
        except OSError as error:
            raise KeyringLifecycleError(
                "an attested keyring operation name could not be durably removed"
            ) from error

    try:
        _attest_locked_parent(path, parent)
    except KeyringLifecycleError as error:
        if identity_error is None:
            identity_error = error
    if identity_error is not None:
        raise identity_error


def _unlink_exact_at(
    parent: int,
    name: str,
    *,
    expected: os.stat_result | None = None,
    missing_ok: bool = False,
) -> bool:
    """Unlink one descriptor-relative name only at its exact witnessed identity."""

    try:
        observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return False
        raise KeyringLifecycleError(
            "an attested keyring operation name disappeared before cleanup"
        ) from None
    except OSError as error:
        raise KeyringLifecycleError(
            "an attested keyring operation name could not be inspected before cleanup"
        ) from error
    if expected is not None and _metadata_identity(observed) != _metadata_identity(
        expected
    ):
        raise KeyringLifecycleError(
            "an attested keyring operation name changed before cleanup"
        )
    try:
        os.unlink(name, dir_fd=parent)
    except OSError as error:
        raise KeyringLifecycleError(
            "an attested keyring operation name could not be removed"
        ) from error
    return True


def _cleanup_created_publication(
    path: Path,
    parent: int,
    temporary: tuple[str, os.stat_result] | None,
    published: os.stat_result | None,
    candidate: os.stat_result | None,
) -> None:
    """Remove only an unambiguous create attempt from the locked directory."""

    temporary_metadata = None
    if temporary is not None:
        try:
            temporary_metadata = os.stat(
                temporary[0],
                dir_fd=parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise KeyringLifecycleError(
                "the failed keyring candidate could not be inspected"
            ) from error

    destination_metadata = None
    if published is not None:
        try:
            destination_metadata = os.stat(
                path.name,
                dir_fd=parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise KeyringLifecycleError(
                "the failed keyring publication could not be inspected"
            ) from error

    if temporary_metadata is not None and destination_metadata is not None:
        if (
            candidate is None
            or temporary_metadata.st_dev != candidate.st_dev
            or temporary_metadata.st_ino != candidate.st_ino
            or destination_metadata.st_dev != candidate.st_dev
            or destination_metadata.st_ino != candidate.st_ino
            or not _safe_linked_publication(
                temporary_metadata,
                destination_metadata,
            )
        ):
            raise KeyringLifecycleError(
                "the failed keyring publication has an ambiguous link identity"
            )
        _unlink_exact_at(
            parent,
            temporary[0],
            expected=temporary_metadata,
        )
        destination_metadata = _stat_at(parent, path.name)
        if not (
            stat.S_ISREG(destination_metadata.st_mode)
            and destination_metadata.st_uid == os.geteuid()
            and stat.S_IMODE(destination_metadata.st_mode) == 0o400
            and destination_metadata.st_nlink == 1
            and destination_metadata.st_dev == candidate.st_dev
            and destination_metadata.st_ino == candidate.st_ino
            and destination_metadata.st_size == candidate.st_size
        ):
            raise KeyringLifecycleError(
                "the failed keyring publication changed during cleanup"
            )
        _unlink_exact_at(
            parent,
            path.name,
            expected=destination_metadata,
        )
    elif temporary_metadata is not None:
        if published is not None or temporary is None:
            raise KeyringLifecycleError(
                "the failed keyring publication lost one of its witnessed links"
            )
        _unlink_exact_at(
            parent,
            temporary[0],
            expected=temporary[1],
        )
    elif destination_metadata is not None:
        if (
            temporary is not None
            or published is None
            or candidate is None
            or not stat.S_ISREG(destination_metadata.st_mode)
            or destination_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(destination_metadata.st_mode) != 0o400
            or destination_metadata.st_nlink != 1
            or destination_metadata.st_dev != candidate.st_dev
            or destination_metadata.st_ino != candidate.st_ino
            or destination_metadata.st_size != candidate.st_size
        ):
            raise KeyringLifecycleError(
                "the failed keyring publication no longer names the created inode"
            )
        _unlink_exact_at(
            parent,
            path.name,
            expected=destination_metadata,
        )

    try:
        os.fsync(parent)
    except OSError as error:
        raise KeyringLifecycleError(
            "the failed keyring publication cleanup could not be durably flushed"
        ) from error


def _safe_unpublished_residue(metadata: os.stat_result) -> bool:
    # A kill may land after O_EXCL creation but before fchmod(2). The requested
    # creation mode is already no broader than 0400, so mode 0000 is also a safe
    # unpublished state to remove from the owner-only parent.
    return bool(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) in {0o000, 0o400}
        and metadata.st_nlink == 1
        and 0 <= metadata.st_size <= MAX_KEYRING_BYTES
    )


def _safe_linked_publication(
    residue: os.stat_result,
    destination: os.stat_result,
) -> bool:
    return bool(
        stat.S_ISREG(residue.st_mode)
        and stat.S_ISREG(destination.st_mode)
        and residue.st_uid == os.geteuid()
        and destination.st_uid == os.geteuid()
        and stat.S_IMODE(residue.st_mode) == 0o400
        and stat.S_IMODE(destination.st_mode) == 0o400
        and residue.st_nlink == destination.st_nlink == 2
        and residue.st_dev == destination.st_dev
        and residue.st_ino == destination.st_ino
        and residue.st_size == destination.st_size
        and 1 <= residue.st_size <= MAX_KEYRING_BYTES
    )


def _reconcile_linked_publication(
    path: Path,
    residue_name: str,
    parent: int,
    lane: str,
    installation_id: str,
    expected: os.stat_result,
) -> None:
    """Drop one attested second name, then strictly validate its destination."""

    _attest_locked_parent(path, parent)
    if _metadata_identity(_stat_at(parent, residue_name)) != _metadata_identity(
        expected
    ):
        raise KeyringLifecycleError(
            "the linked keyring publication residue changed concurrently"
        )
    _unlink_attested(path, parent, residue_name, expected=expected)

    provider = None
    try:
        surviving = _stat_at(parent, path.name)
        if not (
            stat.S_ISREG(surviving.st_mode)
            and surviving.st_uid == os.geteuid()
            and stat.S_IMODE(surviving.st_mode) == 0o400
            and surviving.st_nlink == 1
            and surviving.st_dev == expected.st_dev
            and surviving.st_ino == expected.st_ino
            and surviving.st_size == expected.st_size
        ):
            raise KeyringLifecycleError(
                "the recovered keyring destination changed identity"
            )
        provider = _validate_at(path, parent, lane, installation_id)
    except BaseException:
        # Preserve an invalid or interrupted state for operator inspection rather
        # than silently blessing or destroying it. Re-create the exact second
        # name only when the destination is still the inode we just attested.
        try:
            surviving = _stat_at(parent, path.name)
            if (
                stat.S_ISREG(surviving.st_mode)
                and surviving.st_uid == os.geteuid()
                and stat.S_IMODE(surviving.st_mode) == 0o400
                and surviving.st_nlink == 1
                and surviving.st_dev == expected.st_dev
                and surviving.st_ino == expected.st_ino
            ):
                os.link(
                    path.name,
                    residue_name,
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                    follow_symlinks=False,
                )
                os.fsync(parent)
                _attest_locked_parent(path, parent)
        except OSError:
            pass
        raise
    finally:
        if provider is not None:
            provider.destroy()


def _reconcile_temporary_residues(
    path: Path,
    parent: int,
    lane: str,
    installation_id: str,
) -> bool:
    """Converge safe SIGKILL residues while refusing ambiguous hard links."""

    _attest_locked_parent(path, parent)
    names = _temporary_residue_names(path, parent)
    _attest_locked_parent(path, parent)
    if not names:
        return False

    snapshots = {name: _stat_at(parent, name) for name in names}
    linked_name = None
    destination = None
    try:
        destination = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise KeyringLifecycleError(
            "the keyring destination could not be inspected during recovery"
        ) from error

    for name, metadata in snapshots.items():
        if _safe_unpublished_residue(metadata):
            continue
        if (
            destination is not None
            and _safe_linked_publication(metadata, destination)
            and linked_name is None
        ):
            linked_name = name
            continue
        raise KeyringLifecycleError(
            "an interrupted keyring operation residue has an unsafe or ambiguous identity"
        )

    changed = False
    for name, metadata in snapshots.items():
        if name == linked_name:
            continue
        if _metadata_identity(_stat_at(parent, name)) != _metadata_identity(metadata):
            raise KeyringLifecycleError(
                "an interrupted keyring operation residue changed concurrently"
            )
        _unlink_attested(path, parent, name, expected=metadata)
        changed = True

    recovered_publication = linked_name is not None
    if linked_name is not None:
        _reconcile_linked_publication(
            path,
            linked_name,
            parent,
            lane,
            installation_id,
            snapshots[linked_name],
        )
        changed = True
    if changed:
        try:
            os.fsync(parent)
        except OSError as error:
            raise KeyringLifecycleError(
                "interrupted keyring operation recovery could not be durably flushed"
            ) from error
        _attest_locked_parent(path, parent)
    return recovered_publication


def _write_temporary(
    path: Path,
    parent: int,
    content: bytes,
    *,
    mode: int,
) -> tuple[str, os.stat_result]:
    temporary = _temporary_name(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    _attest_locked_parent(path, parent)
    descriptor = os.open(temporary, flags, mode, dir_fd=parent)
    try:
        os.fchmod(descriptor, mode)
        written = 0
        while written < len(content):
            count = os.write(descriptor, content[written:])
            if count <= 0:
                raise OSError("the temporary keyring write made no progress")
            written += count
        os.fsync(descriptor)
    except BaseException:
        expected = os.fstat(descriptor)
        os.close(descriptor)
        _unlink_attested(
            path,
            parent,
            temporary,
            expected=expected,
            missing_ok=True,
        )
        raise
    expected = os.fstat(descriptor)
    os.close(descriptor)
    try:
        _attest_locked_parent(path, parent)
    except BaseException:
        _unlink_attested(
            path,
            parent,
            temporary,
            expected=expected,
            missing_ok=True,
        )
        raise
    return temporary, expected


def _new_key() -> tuple[str, bytearray]:
    return f"lfk-{secrets.token_hex(16)}", bytearray(secrets.token_bytes(32))


def _rotation_file_witness(path: Path, parent: int) -> tuple[object, ...]:
    """Return metadata plus a full digest from one stable, no-follow read."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    _attest_locked_parent(path, parent)
    descriptor = os.open(path.name, flags, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_nlink != 1
        ):
            raise KeyringLifecycleError(
                "direct keyring rotation requires an owner-controlled mode-0400 "
                "single-link file; installer-managed mode-0444 keyrings must be "
                "rotated through install.sh"
            )
        digest = hashlib.sha256()
        observed_size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed_size += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        metadata_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_nlink",
        )
        before_metadata = tuple(getattr(before, field) for field in metadata_fields)
        after_metadata = tuple(getattr(after, field) for field in metadata_fields)
        if before_metadata != after_metadata or observed_size != before.st_size:
            raise KeyringLifecycleError(
                "the keyring changed concurrently; refusing rotation"
            )
        try:
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise KeyringLifecycleError(
                "the keyring changed concurrently; refusing rotation"
            ) from error
        if _metadata_identity(named) != _metadata_identity(after):
            raise KeyringLifecycleError(
                "the keyring changed concurrently; refusing rotation"
            )
        witness = (*after_metadata, digest.digest())
    finally:
        os.close(descriptor)
    _attest_locked_parent(path, parent)
    return witness


def _read_validated_keyring_at(
    path: Path,
    parent: int,
    lane: str,
    installation_id: str,
) -> _ValidatedKeyring:
    """Strictly load a direct keyring without reopening its absolute parent."""

    if lane not in _LANES or _INSTALLATION_ID_PATTERN.fullmatch(installation_id) is None:
        raise ValueError("the direct keyring scope is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.name, flags, dir_fd=parent)
    raw = bytearray()
    decoded_keys: dict[str, bytearray] = {}
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_nlink != 1
            or not 1 <= before.st_size <= MAX_KEYRING_BYTES
        ):
            raise ValueError("unsafe direct keyring metadata")
        while len(raw) <= MAX_KEYRING_BYTES:
            chunk = os.read(descriptor, min(512, MAX_KEYRING_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        try:
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise ValueError("the direct keyring name changed") from error
        if (
            _metadata_identity(before) != _metadata_identity(after)
            or _metadata_identity(named) != _metadata_identity(after)
            or len(raw) != before.st_size
            or len(raw) > MAX_KEYRING_BYTES
        ):
            raise ValueError("the direct keyring changed while it was read")

        try:
            text = bytes(raw).decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("the direct keyring is not ASCII") from error
        if not text.endswith("\n") or "\r" in text or "\x00" in text:
            raise ValueError("the direct keyring framing is invalid")
        lines = text[:-1].split("\n")
        if len(lines) < 5 or lines[0] != KEYRING_MAGIC:
            raise ValueError("the direct keyring version is unsupported")
        if lines[1] != f"installation={installation_id}":
            raise ValueError("the direct keyring installation identity is invalid")
        if lines[2] != f"lane={lane}":
            raise ValueError("the direct keyring lane is invalid")
        if not lines[3].startswith("active="):
            raise ValueError("the direct keyring active key is invalid")
        active_key_id = lines[3][len("active=") :]
        if _KEY_ID_PATTERN.fullmatch(active_key_id) is None:
            raise ValueError("the direct keyring active key is invalid")
        key_lines = lines[4:]
        if not 1 <= len(key_lines) <= MAX_KEYRING_KEYS:
            raise ValueError("the direct keyring key count is invalid")

        canonical_keys: list[tuple[str, str]] = []
        seen_material: set[str] = set()
        for line in key_lines:
            match = _KEY_ENTRY_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError("the direct keyring contains an invalid key")
            key_id, key_hex = match.groups()
            if key_id in decoded_keys or key_hex in seen_material:
                raise ValueError("the direct keyring contains a duplicate key")
            decoded_keys[key_id] = bytearray.fromhex(key_hex)
            canonical_keys.append((key_id, key_hex))
            seen_material.add(key_hex)
        if active_key_id != canonical_keys[0][0]:
            raise ValueError("the direct keyring active key is not first")
        if raw != canonical_keyring_bytes(
            installation_id=installation_id,
            lane=lane,
            active_key_id=active_key_id,
            keys=canonical_keys,
        ):
            raise ValueError("the direct keyring is not canonical")

        result = _ValidatedKeyring(active_key_id, decoded_keys)
        decoded_keys = {}
        return result
    finally:
        os.close(descriptor)
        for key in decoded_keys.values():
            zeroize(key)
        zeroize(raw)
        try:
            del text, lines, key_lines, canonical_keys, seen_material
        except UnboundLocalError:
            pass


def _validate_at(
    path: Path,
    parent: int,
    lane: str,
    installation_id: str,
) -> _ValidatedKeyring:
    provider = None
    _attest_locked_parent(path, parent)
    try:
        provider = _read_validated_keyring_at(
            path,
            parent,
            lane,
            installation_id,
        )
        _attest_locked_parent(path, parent)
        return provider
    except KeyringLifecycleError:
        if provider is not None:
            provider.destroy()
        raise
    except Exception as error:
        if provider is not None:
            provider.destroy()
        raise KeyringLifecycleError("the keyring failed strict validation") from error


def _validate(
    path: Path, lane: str, installation_id: str
) -> LocalFileKeyProvider:
    try:
        return LocalFileKeyProvider(
            path,
            lane=lane,
            installation_id=installation_id,
        )
    except Exception as error:
        raise KeyringLifecycleError("the keyring failed strict validation") from error


def create(path: Path, lane: str, installation_id: str) -> dict[str, object]:
    parent = _open_locked_parent(path)
    key = None
    temporary: tuple[str, os.stat_result] | None = None
    published: os.stat_result | None = None
    candidate: os.stat_result | None = None
    try:
        _attest_locked_parent(path, parent)
        recovered_publication = _reconcile_temporary_residues(
            path,
            parent,
            lane,
            installation_id,
        )
        if recovered_publication:
            provider = _validate_at(path, parent, lane, installation_id)
            try:
                return {
                    "active_key_id": provider.active_key_id,
                    "key_count": len(provider.key_ids),
                    "lane": lane,
                    "version": KEYRING_VERSION,
                }
            finally:
                provider.destroy()
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise KeyringLifecycleError(
                "the keyring destination could not be inspected"
            ) from error
        else:
            raise KeyringLifecycleError("refusing to overwrite an existing keyring path")
        key_id, key = _new_key()
        content = canonical_keyring_bytes(
            installation_id=installation_id,
            lane=lane,
            active_key_id=key_id,
            keys=[(key_id, bytes(key).hex())],
        )
        temporary = _write_temporary(path, parent, content, mode=0o400)
        candidate = temporary[1]
        # link(2) is an atomic no-clobber publication on the same filesystem.
        _attest_locked_parent(path, parent)
        os.link(
            temporary[0],
            path.name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
            follow_symlinks=False,
        )
        linked_temporary = _stat_at(parent, temporary[0])
        published = _stat_at(parent, path.name)
        if (
            linked_temporary.st_dev != candidate.st_dev
            or linked_temporary.st_ino != candidate.st_ino
            or linked_temporary.st_size != candidate.st_size
            or not _safe_linked_publication(linked_temporary, published)
        ):
            raise KeyringLifecycleError(
                "the keyring publication changed identity while it was linked"
            )
        temporary = (temporary[0], linked_temporary)
        _attest_locked_parent(path, parent)
        _unlink_exact_at(
            parent,
            temporary[0],
            expected=temporary[1],
        )
        temporary = None
        activated = _stat_at(parent, path.name)
        if not (
            stat.S_ISREG(activated.st_mode)
            and activated.st_uid == os.geteuid()
            and stat.S_IMODE(activated.st_mode) == 0o400
            and activated.st_nlink == 1
            and activated.st_dev == candidate.st_dev
            and activated.st_ino == candidate.st_ino
            and activated.st_size == candidate.st_size
        ):
            raise KeyringLifecycleError(
                "the keyring publication changed identity after activation"
            )
        published = activated
        os.fsync(parent)
        _attest_locked_parent(path, parent)
        provider = _validate_at(path, parent, lane, installation_id)
        try:
            return {
                "active_key_id": provider.active_key_id,
                "key_count": len(provider.key_ids),
                "lane": lane,
                "version": KEYRING_VERSION,
            }
        finally:
            provider.destroy()
    except BaseException as operation_error:
        try:
            _cleanup_created_publication(
                path,
                parent,
                temporary,
                published,
                candidate,
            )
        except BaseException as cleanup_error:
            raise cleanup_error from operation_error
        raise
    finally:
        try:
            if temporary is not None:
                _unlink_attested(
                    path,
                    parent,
                    temporary[0],
                    expected=temporary[1],
                    missing_ok=True,
                )
        finally:
            try:
                zeroize(key)
            finally:
                os.close(parent)


def inspect(path: Path, lane: str, installation_id: str) -> dict[str, object]:
    provider = _validate(path, lane, installation_id)
    try:
        return {
            "active_key_id": provider.active_key_id,
            "key_count": len(provider.key_ids),
            "key_ids": list(provider.key_ids),
            "lane": lane,
            "version": KEYRING_VERSION,
        }
    finally:
        provider.destroy()


def rotate(
    path: Path,
    lane: str,
    installation_id: str,
    expected_active_key_id: str,
) -> dict[str, object]:
    parent = _open_locked_parent(path)
    new_key = None
    temporary: tuple[str, os.stat_result] | None = None
    provider = None
    try:
        _attest_locked_parent(path, parent)
        _reconcile_temporary_residues(
            path,
            parent,
            lane,
            installation_id,
        )
        original = _rotation_file_witness(path, parent)
        provider = _validate_at(path, parent, lane, installation_id)
        if _rotation_file_witness(path, parent) != original:
            raise KeyringLifecycleError(
                "the keyring changed concurrently; refusing rotation"
            )
        if provider.active_key_id != expected_active_key_id:
            raise KeyringLifecycleError(
                "the expected active key ID does not match; refusing repeated or stale rotation"
            )
        if len(provider.key_ids) >= MAX_KEYRING_KEYS:
            raise KeyringLifecycleError(
                "the keyring is full; no legacy key was evicted"
            )
        new_key_id, new_key = _new_key()
        entries = [(new_key_id, bytes(new_key).hex())]
        entries.extend(
            (key_id, bytes(provider._keys[key_id]).hex())  # noqa: SLF001
            for key_id in provider.key_ids
        )
        content = canonical_keyring_bytes(
            installation_id=installation_id,
            lane=lane,
            active_key_id=new_key_id,
            keys=entries,
        )
        temporary = _write_temporary(path, parent, content, mode=0o400)
        if _rotation_file_witness(path, parent) != original:
            raise KeyringLifecycleError(
                "the keyring changed concurrently; refusing rotation"
            )
        _attest_locked_parent(path, parent)
        os.replace(
            temporary[0],
            path.name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
        )
        temporary = None
        os.fsync(parent)
        _attest_locked_parent(path, parent)
        rotated = _validate_at(path, parent, lane, installation_id)
        try:
            return {
                "active_key_id": rotated.active_key_id,
                "key_count": len(rotated.key_ids),
                "lane": lane,
                "retained_key_ids": list(rotated.key_ids[1:]),
                "version": KEYRING_VERSION,
            }
        finally:
            rotated.destroy()
    finally:
        try:
            if provider is not None:
                provider.destroy()
        finally:
            try:
                if temporary is not None:
                    _unlink_attested(
                        path,
                        parent,
                        temporary[0],
                        expected=temporary[1],
                        missing_ok=True,
                    )
            finally:
                try:
                    zeroize(new_key)
                finally:
                    os.close(parent)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    for command in ("create", "inspect"):
        child = subparsers.add_parser(command)
        child.add_argument("--path", required=True, type=_path)
        child.add_argument("--lane", required=True, choices=("database", "files"))
        child.add_argument("--installation-id", required=True, type=_installation_id)
    child = subparsers.add_parser("rotate")
    child.add_argument("--path", required=True, type=_path)
    child.add_argument("--lane", required=True, choices=("database", "files"))
    child.add_argument("--installation-id", required=True, type=_installation_id)
    child.add_argument("--expected-active-key-id", required=True)
    child = subparsers.add_parser("policy-witness")
    child.add_argument("--installation-id", required=True, type=_installation_id)
    child.add_argument(
        "--generation",
        required=True,
        choices=("1", "1-pending-empty"),
    )
    return result


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "create":
            outcome = create(
                arguments.path,
                arguments.lane,
                arguments.installation_id,
            )
        elif arguments.command == "inspect":
            outcome = inspect(
                arguments.path,
                arguments.lane,
                arguments.installation_id,
            )
        elif arguments.command == "rotate":
            outcome = rotate(
                arguments.path,
                arguments.lane,
                arguments.installation_id,
                arguments.expected_active_key_id,
            )
        else:
            outcome = {
                "generation": arguments.generation,
                "provider": "local-file",
                "witness": artifact_provider_policy_witness(
                    arguments.installation_id,
                    arguments.generation,
                ),
            }
    except KeyringLifecycleError as error:
        print(f"artifact keyring operation refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
