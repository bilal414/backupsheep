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
    MAX_KEYRING_KEYS,
    LocalFileKeyProvider,
    canonical_keyring_bytes,
)


class KeyringLifecycleError(RuntimeError):
    pass


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
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path.parent, flags)
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
        raise KeyringLifecycleError(
            "another keyring mutation holds the parent-directory lock"
        ) from None
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _temporary_path(path: Path) -> Path:
    return path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"


def _write_temporary(path: Path, content: bytes, *, mode: int) -> Path:
    temporary = _temporary_path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, mode)
    try:
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
    os.chmod(temporary, mode, follow_symlinks=False)
    return temporary


def _new_key() -> tuple[str, bytearray]:
    return f"lfk-{secrets.token_hex(16)}", bytearray(secrets.token_bytes(32))


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
        direct_metadata = os.lstat(path)
        if (
            not stat.S_ISREG(direct_metadata.st_mode)
            or direct_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(direct_metadata.st_mode) != 0o400
            or direct_metadata.st_nlink != 1
        ):
            raise KeyringLifecycleError(
                "direct keyring rotation requires an owner-controlled mode-0400 "
                "single-link file; installer-managed mode-0444 keyrings must be "
                "rotated through install.sh"
            )
        provider = _validate(path, lane, installation_id)
        if provider.active_key_id != expected_active_key_id:
            raise KeyringLifecycleError(
                "the expected active key ID does not match; refusing repeated or stale rotation"
            )
        if len(provider.key_ids) >= MAX_KEYRING_KEYS:
            raise KeyringLifecycleError(
                "the keyring is full; no legacy key was evicted"
            )
        original = os.lstat(path)
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
        mode = stat.S_IMODE(original.st_mode)
        temporary = _write_temporary(path, content, mode=mode)
        current = os.lstat(path)
        if (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
            current.st_nlink,
        ) != (
            original.st_dev,
            original.st_ino,
            original.st_size,
            original.st_mtime_ns,
            original.st_nlink,
        ):
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
