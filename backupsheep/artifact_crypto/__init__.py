"""Public interface for BackupSheep backup-artifact envelope encryption."""

from .context import ArtifactContext, artifact_provider_policy_witness
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
    KeyProvider,
    KeyProviderRegistry,
    LocalDevelopmentKeyProvider,
    LocalFileKeyProvider,
    WrappedDataKey,
)

__all__ = [
    "ALGORITHM",
    "ArtifactContext",
    "artifact_provider_policy_witness",
    "DEFAULT_CHUNK_SIZE",
    "EnvelopeDescriptor",
    "EnvelopeExpectation",
    "FORMAT_VERSION",
    "KeyProvider",
    "KeyProviderRegistry",
    "LocalDevelopmentKeyProvider",
    "LocalFileKeyProvider",
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
