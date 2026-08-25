"""Key-provider contracts for per-backup envelope encryption."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..context import ArtifactContext


def zeroize(value: bytearray | None) -> None:
    """Best-effort overwrite of mutable key bytes."""

    if value is not None:
        value[:] = b"\x00" * len(value)


@dataclass(frozen=True, slots=True)
class WrappedDataKey:
    provider_name: str
    wrapping_key_id: str
    ciphertext: bytes


@dataclass(slots=True)
class GeneratedDataKey:
    plaintext: bytearray
    wrapped: WrappedDataKey

    def destroy(self) -> None:
        zeroize(self.plaintext)

    def __enter__(self) -> "GeneratedDataKey":
        return self

    def __exit__(self, *_args: object) -> None:
        self.destroy()


@runtime_checkable
class KeyProvider(Protocol):
    """Minimal provider interface used by artifact seal/open operations."""

    name: str
    external: bool

    def generate_data_key(self, context: ArtifactContext) -> GeneratedDataKey:
        """Generate a fresh AES-256 key and return its provider-wrapped form."""

    def unwrap_data_key(
        self, wrapped: WrappedDataKey, context: ArtifactContext
    ) -> bytearray:
        """Return the authenticated 32-byte plaintext data key."""

    def rewrap_data_key(
        self,
        wrapped: WrappedDataKey,
        context: ArtifactContext,
        *,
        destination_key_id: str,
    ) -> WrappedDataKey:
        """Rotate provider custody without exposing plaintext to the caller."""
