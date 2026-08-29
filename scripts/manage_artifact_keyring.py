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
import secrets  # noqa: E402
import stat  # noqa: E402
from pathlib import Path  # noqa: E402

from backupsheep.artifact_crypto.context import (  # noqa: E402
    artifact_provider_policy_witness,
)
from backupsheep.artifact_crypto.providers.base import zeroize  # noqa: E402
from backupsheep.artifact_crypto.providers.local_file import (  # noqa: E402
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


def _temporary_path(path: Path) -> Path:
    return path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"


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

    if _metadata_identity(_stat_at(parent, residue_name)) != _metadata_identity(
        expected
    ):
        raise KeyringLifecycleError(
            "the linked keyring publication residue changed concurrently"
        )
    try:
        os.unlink(residue_name, dir_fd=parent)
    except OSError as error:
        raise KeyringLifecycleError(
            "the linked keyring publication residue could not be removed"
        ) from error

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
        provider = _validate(path, lane, installation_id)
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

    names = _temporary_residue_names(path, parent)
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
        try:
            os.unlink(name, dir_fd=parent)
        except OSError as error:
            raise KeyringLifecycleError(
                "an unpublished keyring operation residue could not be removed"
            ) from error
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
    return recovered_publication


def _write_temporary(path: Path, content: bytes, *, mode: int) -> Path:
    temporary = _temporary_path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, mode)
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
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    os.close(descriptor)
    return temporary


def _new_key() -> tuple[str, bytearray]:
    return f"lfk-{secrets.token_hex(16)}", bytearray(secrets.token_bytes(32))


def _rotation_file_witness(path: Path) -> tuple[object, ...]:
    """Return metadata plus a full digest from one stable, no-follow read."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
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
        return (*after_metadata, digest.digest())
    finally:
        os.close(descriptor)


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
    temporary = None
    published = False
    try:
        recovered_publication = _reconcile_temporary_residues(
            path,
            parent,
            lane,
            installation_id,
        )
        if recovered_publication:
            provider = _validate(path, lane, installation_id)
            try:
                return {
                    "active_key_id": provider.active_key_id,
                    "key_count": len(provider.key_ids),
                    "lane": lane,
                    "version": KEYRING_VERSION,
                }
            finally:
                provider.destroy()
        if path.exists() or path.is_symlink():
            raise KeyringLifecycleError("refusing to overwrite an existing keyring path")
        key_id, key = _new_key()
        content = canonical_keyring_bytes(
            installation_id=installation_id,
            lane=lane,
            active_key_id=key_id,
            keys=[(key_id, bytes(key).hex())],
        )
        temporary = _write_temporary(path, content, mode=0o400)
        try:
            # link(2) is an atomic no-clobber publication on the same filesystem.
            os.link(temporary, path, follow_symlinks=False)
            published = True
            temporary.unlink()
            temporary = None
            os.fsync(parent)
        except BaseException:
            if published:
                path.unlink(missing_ok=True)
            raise
        provider = _validate(path, lane, installation_id)
        try:
            return {
                "active_key_id": provider.active_key_id,
                "key_count": len(provider.key_ids),
                "lane": lane,
                "version": KEYRING_VERSION,
            }
        finally:
            provider.destroy()
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        zeroize(key)
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
    temporary = None
    provider = None
    try:
        _reconcile_temporary_residues(
            path,
            parent,
            lane,
            installation_id,
        )
        original = _rotation_file_witness(path)
        provider = _validate(path, lane, installation_id)
        if _rotation_file_witness(path) != original:
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
        temporary = _write_temporary(path, content, mode=0o400)
        if _rotation_file_witness(path) != original:
            raise KeyringLifecycleError(
                "the keyring changed concurrently; refusing rotation"
            )
        os.replace(temporary, path)
        temporary = None
        os.fsync(parent)
        rotated = _validate(path, lane, installation_id)
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
        if provider is not None:
            provider.destroy()
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        zeroize(new_key)
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
