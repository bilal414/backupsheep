"""Public interface for BackupSheep backup-artifact envelope encryption."""

from .context import ArtifactContext
from .envelope import (
    ALGORITHM,
    DEFAULT_CHUNK_SIZE,
    FORMAT_VERSION,
    EnvelopeDescriptor,
    EnvelopeExpectation,
    SealedArtifact,
    decrypt_file,
    encrypt_file,
    open_artifact_source,
    read_envelope_header,
    read_envelope_header_from_descriptor,
    seal_file,
    unseal_file,
)
from .errors import *  # noqa: F403
from .providers import (
    AWSKMSConfig,
    AWSKMSKeyProvider,
    KeyProvider,
    KeyProviderRegistry,
    LocalDevelopmentKeyProvider,
    WrappedDataKey,
)

__all__ = [
    "ALGORITHM",
    "AWSKMSConfig",
    "AWSKMSKeyProvider",
    "ArtifactContext",
    "DEFAULT_CHUNK_SIZE",
    "EnvelopeDescriptor",
    "EnvelopeExpectation",
    "FORMAT_VERSION",
    "KeyProvider",
    "KeyProviderRegistry",
    "LocalDevelopmentKeyProvider",
    "SealedArtifact",
    "WrappedDataKey",
    "decrypt_file",
    "encrypt_file",
    "open_artifact_source",
    "read_envelope_header",
    "read_envelope_header_from_descriptor",
    "seal_file",
    "unseal_file",
]
