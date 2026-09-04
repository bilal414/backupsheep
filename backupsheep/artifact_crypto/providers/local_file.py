"""Strict file-backed wrapping keys for production BSE1 artifacts.

The keyring is deliberately small, canonical, and line oriented so both the
Python runtime and the dependency-free shell installer can validate identical
bytes.  Root key material never belongs in settings, environment variables, or
the application image.  A keyring is bound to one installation and source lane and keeps
the active key plus a bounded set of legacy keys needed for recovery while data
key wraps are rotated.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from ..context import ArtifactContext
from ..errors import (
    KeyProviderConfigurationError,
    KeyProviderIntegrityError,
    KeyProviderNotFoundError,
)
from .base import GeneratedDataKey, WrappedDataKey, zeroize

KEYRING_MAGIC = "BACKUPSHEEP-ARTIFACT-KEYRING-V1"
KEYRING_VERSION = 1
WRAP_ALGORITHM = "AES-256-GCM-SIV"
MAX_KEYRING_KEYS = 8
MAX_KEYRING_BYTES = 2048
_KEY_ID = re.compile(r"^lfk-[0-9a-f]{32}$")
_LANES = frozenset({"database", "files"})
_WRAP_MAGIC = b"BSLW1"
_NONCE_BYTES = 12
_DATA_KEY_BYTES = 32
_TAG_BYTES = 16
_WRAPPED_BYTES = len(_WRAP_MAGIC) + _NONCE_BYTES + _DATA_KEY_BYTES + _TAG_BYTES
_AAD_DOMAIN = b"BackupSheep/BSE1/local-file-wrap/v1\x00"


def open_keyring_parent_directory(path: Path) -> int:
    """Open an absolute keyring parent without following any path component."""

    path = Path(path)
    if not path.is_absolute() or not path.name or ".." in path.parts:
        raise OSError("The local-file keyring path is not canonical.")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("Safe local-file keyring path traversal is unavailable.")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    descriptor = os.open(os.path.sep, flags)
    try:
        for component in path.parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise OSError("The local-file keyring path is not canonical.")
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def canonical_keyring_bytes(
    *,
    installation_id: str,
    lane: str,
    active_key_id: str,
    keys: list[tuple[str, str]],
) -> bytes:
    """Return the only accepted on-disk representation of a keyring."""

    lines = [
        KEYRING_MAGIC,
        f"installation={installation_id}",
        f"lane={lane}",
        f"active={active_key_id}",
    ]
    lines.extend(f"key={key_id}:{key_hex}" for key_id, key_hex in keys)
    return ("\n".join(lines) + "\n").encode("ascii")


class LocalFileKeyProvider:
    """Versioned AES-256-GCM-SIV data-key wrapping backed by one strict lane keyring."""

    name = "local-file"
    external = False

    def __init__(
        self,
        keyring_path: str | os.PathLike[str],
        *,
        lane: str,
        installation_id: str,
    ):
        if lane not in _LANES:
            raise KeyProviderConfigurationError(
                "The local-file keyring lane must be database or files."
            )
        if not re.fullmatch(r"[0-9a-f]{64}", installation_id):
            raise KeyProviderConfigurationError(
                "The local-file keyring installation identity is invalid."
            )
        supplied_path = os.fspath(keyring_path)
        if not os.path.isabs(supplied_path):
            raise KeyProviderConfigurationError(
                "The local-file keyring path must be absolute."
            )
        path = Path(supplied_path)
        self.path = path
        self.lane = lane
        self.installation_id = installation_id
        self.active_key_id = ""
        self._keys: dict[str, bytearray] = {}
        self._destroyed = False
        self._load()

    @property
    def enterprise_eligible(self) -> bool:
        return not self._destroyed and bool(self._keys)

    @property
    def key_ids(self) -> tuple[str, ...]:
        self._require_live()
        return tuple(self._keys)

    def _secure_metadata(
        self,
        metadata: os.stat_result,
        parent_metadata: os.stat_result,
    ) -> bool:
        mode = stat.S_IMODE(metadata.st_mode)
        protected_owner_directory = bool(
            stat.S_ISDIR(parent_metadata.st_mode)
            and parent_metadata.st_uid == os.geteuid()
            and stat.S_IMODE(parent_metadata.st_mode) == 0o700
        )
        expected_docker_path = Path(
            f"/run/secrets/artifact_local_file_{self.lane}_keyring"
        )
        protected_docker_directory = bool(
            self.path == expected_docker_path
            and stat.S_ISDIR(parent_metadata.st_mode)
            and parent_metadata.st_uid == 0
            and stat.S_IMODE(parent_metadata.st_mode) & 0o022 == 0
        )
        # Direct non-Docker deployments use an owner-only 0400 file. Docker
        # Compose file secrets retain the host file UID, so the exact reviewed
        # path accepts any UID with mode 0444. init.sh independently requires a
        # read-only bind mount under the protected root-owned /run/secrets and
        # checks that no other role or source lane can see it.
        return bool(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and (
                (
                    metadata.st_uid == os.geteuid()
                    and mode == 0o400
                    and protected_owner_directory
                )
                or (
                    metadata.st_uid == os.geteuid()
                    and mode == 0o444
                    and protected_owner_directory
                )
                # Compose implements file-backed secrets as read-only bind
                # mounts and retains the host file UID. It cannot portably
                # remap uid/gid for this source type. At the exact reviewed
                # lane path, the protected root-owned parent plus read-only
                # mount check in init.sh is the trust boundary; do not require
                # a particular host-dependent file UID here.
                or (mode == 0o444 and protected_docker_directory)
            )
        )

    def _load(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        parent_descriptor = None
        try:
            parent_descriptor = open_keyring_parent_directory(self.path)
            parent_metadata = os.fstat(parent_descriptor)
            descriptor = os.open(self.path.name, flags, dir_fd=parent_descriptor)
        except OSError:
            if parent_descriptor is not None:
                os.close(parent_descriptor)
            raise KeyProviderConfigurationError(
                "The local-file keyring cannot be opened safely."
            ) from None
        raw = bytearray()
        try:
            metadata = os.fstat(descriptor)
            if not self._secure_metadata(metadata, parent_metadata):
                raise KeyProviderConfigurationError(
                    "The local-file keyring metadata is unsafe."
                )
            if not 1 <= metadata.st_size <= MAX_KEYRING_BYTES:
                raise KeyProviderConfigurationError(
                    "The local-file keyring size is invalid."
                )
            while len(raw) <= MAX_KEYRING_BYTES:
                chunk = os.read(descriptor, min(512, MAX_KEYRING_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) != metadata.st_size or len(raw) > MAX_KEYRING_BYTES:
                raise KeyProviderConfigurationError(
                    "The local-file keyring changed while it was read."
                )
        finally:
            os.close(descriptor)
            os.close(parent_descriptor)

        decoded_keys: dict[str, bytearray] = {}
        try:
            try:
                text = bytes(raw).decode("ascii")
            except UnicodeDecodeError:
                raise KeyProviderConfigurationError(
                    "The local-file keyring is not canonical ASCII."
                ) from None
            if not text.endswith("\n") or "\r" in text or "\x00" in text:
                raise KeyProviderConfigurationError(
                    "The local-file keyring framing is invalid."
                )
            lines = text[:-1].split("\n")
            if len(lines) < 5 or lines[0] != KEYRING_MAGIC:
                raise KeyProviderConfigurationError(
                    "The local-file keyring version is unsupported."
                )
            if lines[1] != f"installation={self.installation_id}":
                raise KeyProviderConfigurationError(
                    "The local-file keyring belongs to a different installation."
                )
            if lines[2] != f"lane={self.lane}":
                raise KeyProviderConfigurationError(
                    "The local-file keyring belongs to a different source lane."
                )
            if not lines[3].startswith("active="):
                raise KeyProviderConfigurationError(
                    "The local-file keyring active key is invalid."
                )
            active_key_id = lines[3][len("active=") :]
            if not _KEY_ID.fullmatch(active_key_id):
                raise KeyProviderConfigurationError(
                    "The local-file keyring active key is invalid."
                )
            key_lines = lines[4:]
            if not 1 <= len(key_lines) <= MAX_KEYRING_KEYS:
                raise KeyProviderConfigurationError(
                    "The local-file keyring must contain one to eight keys."
                )
            canonical_keys: list[tuple[str, str]] = []
            seen_material: set[str] = set()
            for line in key_lines:
                match = re.fullmatch(r"key=(lfk-[0-9a-f]{32}):([0-9a-f]{64})", line)
                if match is None:
                    raise KeyProviderConfigurationError(
                        "The local-file keyring contains an invalid key entry."
                    )
                key_id, key_hex = match.groups()
                if key_id in decoded_keys or key_hex in seen_material:
                    raise KeyProviderConfigurationError(
                        "The local-file keyring contains a duplicate key."
                    )
                decoded_keys[key_id] = bytearray.fromhex(key_hex)
                canonical_keys.append((key_id, key_hex))
                seen_material.add(key_hex)
            if active_key_id != canonical_keys[0][0]:
                raise KeyProviderConfigurationError(
                    "The local-file active key must be the first key entry."
                )
            if raw != canonical_keyring_bytes(
                installation_id=self.installation_id,
                lane=self.lane,
                active_key_id=active_key_id,
                keys=canonical_keys,
            ):
                raise KeyProviderConfigurationError(
                    "The local-file keyring is not canonically encoded."
                )
            self.active_key_id = active_key_id
            self._keys = decoded_keys
            decoded_keys = {}
        except BaseException:
            for key in decoded_keys.values():
                zeroize(key)
            raise
        finally:
            zeroize(raw)
            try:
                # Best effort only: Python strings are immutable, but dropping
                # references promptly avoids retaining parsed hexadecimal keys.
                del text, lines, key_lines, canonical_keys, seen_material
            except UnboundLocalError:
                pass

    def _require_live(self) -> None:
        if self._destroyed:
            raise KeyProviderConfigurationError(
                "The local-file key provider has been destroyed."
            )

    def _require_context(self, context: ArtifactContext) -> None:
        self._require_live()
        if context.installation_id != self.installation_id:
            raise KeyProviderConfigurationError(
                "The artifact context belongs to a different installation."
            )
        if context.lane != self.lane:
            raise KeyProviderConfigurationError(
                "The artifact context belongs to a different source lane."
            )

    def _require_key(self, key_id: object) -> bytearray:
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise KeyProviderConfigurationError(
                "The local-file wrapping key identifier is invalid."
            )
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyProviderNotFoundError(
                "The wrapped data key needs a legacy key absent from this keyring."
            ) from None

    def _aad(self, context: ArtifactContext, key_id: str) -> bytes:
        self._require_context(context)
        return _AAD_DOMAIN + key_id.encode("ascii") + b"\x00" + context.canonical_bytes()

    def _wrap(self, plaintext: bytearray, context: ArtifactContext, key_id: str) -> WrappedDataKey:
        key = self._require_key(key_id)
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCMSIV(bytes(key)).encrypt(
            nonce,
            bytes(plaintext),
            self._aad(context, key_id),
        )
        return WrappedDataKey(self.name, key_id, _WRAP_MAGIC + nonce + ciphertext)

    def generate_data_key(self, context: ArtifactContext) -> GeneratedDataKey:
        self._require_context(context)
        plaintext = bytearray(os.urandom(_DATA_KEY_BYTES))
        try:
            wrapped = self._wrap(plaintext, context, self.active_key_id)
            return GeneratedDataKey(plaintext=plaintext, wrapped=wrapped)
        except BaseException:
            zeroize(plaintext)
            raise

    def unwrap_data_key(
        self, wrapped: WrappedDataKey, context: ArtifactContext
    ) -> bytearray:
        self._require_context(context)
        if (
            wrapped.provider_name != self.name
            or not isinstance(wrapped.ciphertext, (bytes, bytearray))
            or len(wrapped.ciphertext) != _WRAPPED_BYTES
            or not bytes(wrapped.ciphertext).startswith(_WRAP_MAGIC)
        ):
            raise KeyProviderConfigurationError(
                "The wrapped data key does not belong to the local-file provider."
            )
        key_id = wrapped.wrapping_key_id
        key = self._require_key(key_id)
        payload = bytes(wrapped.ciphertext)
        nonce = payload[len(_WRAP_MAGIC) : len(_WRAP_MAGIC) + _NONCE_BYTES]
        ciphertext = payload[len(_WRAP_MAGIC) + _NONCE_BYTES :]
        try:
            plaintext = AESGCMSIV(bytes(key)).decrypt(
                nonce,
                ciphertext,
                self._aad(context, key_id),
            )
        except (InvalidTag, ValueError):
            raise KeyProviderIntegrityError(
                "The wrapped data key could not be authenticated."
            ) from None
        if len(plaintext) != _DATA_KEY_BYTES:
            raise KeyProviderIntegrityError(
                "The wrapped data key has an invalid plaintext length."
            )
        return bytearray(plaintext)

    def rewrap_data_key(
        self,
        wrapped: WrappedDataKey,
        context: ArtifactContext,
        *,
        destination_key_id: str,
    ) -> WrappedDataKey:
        self._require_context(context)
        self._require_key(destination_key_id)
        plaintext = self.unwrap_data_key(wrapped, context)
        try:
            return self._wrap(plaintext, context, destination_key_id)
        finally:
            zeroize(plaintext)

    def destroy(self) -> None:
        for key in self._keys.values():
            zeroize(key)
        self._keys.clear()
        self.active_key_id = ""
        self._destroyed = True

    def __enter__(self) -> "LocalFileKeyProvider":
        self._require_live()
        return self

    def __exit__(self, *_args: object) -> None:
        self.destroy()
