"""Explicit development-only key provider.

This provider is useful for deterministic unit and local integration tests.  It
must never be accepted by enterprise policy because its root wrapping key lives
inside the application configuration rather than an external KMS/HSM boundary.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)

from ..context import ArtifactContext
from ..errors import (
    KeyProviderConfigurationError,
    KeyProviderIntegrityError,
)
from .base import GeneratedDataKey, WrappedDataKey, zeroize


class LocalDevelopmentKeyProvider:
    name = "local-development"
    external = False

    @property
    def enterprise_eligible(self) -> bool:
        return False

    def __init__(self, wrapping_key: bytes | bytearray, *, key_id: str = "local-v1"):
        if len(wrapping_key) != 32:
            raise KeyProviderConfigurationError(
                "The local development wrapping key must be exactly 32 bytes."
            )
        if not key_id or len(key_id) > 255:
            raise KeyProviderConfigurationError(
                "The local development wrapping key identifier is invalid."
            )
        self._wrapping_key = bytearray(wrapping_key)
        self.key_id = str(key_id)
        self._destroyed = False

    def _require_live(self) -> None:
        if self._destroyed:
            raise KeyProviderConfigurationError(
                "The local development key provider has been destroyed."
            )

    def _context_key(self, context: ArtifactContext) -> bytearray:
        self._require_live()
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"BackupSheep/BSE1/local-development-provider",
            info=context.canonical_bytes(),
        ).derive(bytes(self._wrapping_key))
        return bytearray(derived)

    def generate_data_key(self, context: ArtifactContext) -> GeneratedDataKey:
        plaintext = bytearray(os.urandom(32))
        context_key = self._context_key(context)
        try:
            ciphertext = aes_key_wrap(bytes(context_key), bytes(plaintext))
        finally:
            zeroize(context_key)
        return GeneratedDataKey(
            plaintext=plaintext,
            wrapped=WrappedDataKey(
                provider_name=self.name,
                wrapping_key_id=self.key_id,
                ciphertext=ciphertext,
            ),
        )

    def unwrap_data_key(
        self, wrapped: WrappedDataKey, context: ArtifactContext
    ) -> bytearray:
        if wrapped.provider_name != self.name or wrapped.wrapping_key_id != self.key_id:
            raise KeyProviderConfigurationError(
                "The wrapped data key does not belong to this key provider."
            )
        context_key = self._context_key(context)
        try:
            plaintext = aes_key_unwrap(bytes(context_key), bytes(wrapped.ciphertext))
        except (InvalidUnwrap, ValueError):
            raise KeyProviderIntegrityError(
                "The wrapped data key could not be authenticated."
            ) from None
        finally:
            zeroize(context_key)
        if len(plaintext) != 32:
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
        if destination_key_id != self.key_id:
            raise KeyProviderConfigurationError(
                "The local development provider cannot rotate to an unknown key."
            )
        plaintext = self.unwrap_data_key(wrapped, context)
        context_key = self._context_key(context)
        try:
            ciphertext = aes_key_wrap(bytes(context_key), bytes(plaintext))
        finally:
            zeroize(plaintext)
            zeroize(context_key)
        return WrappedDataKey(self.name, self.key_id, ciphertext)

    def destroy(self) -> None:
        zeroize(self._wrapping_key)
        self._destroyed = True
