"""Typed, operator-safe failures for encrypted backup artifacts.

Exceptions in this module deliberately carry stable messages. Provider and
filesystem errors can include sensitive paths or deployment metadata and must
never become backup logs or API responses.
"""


class ArtifactCryptoError(RuntimeError):
    """Base class for an expected artifact-encryption failure."""


class ArtifactConfigurationError(ArtifactCryptoError):
    """The requested cryptographic policy or parameter is unsafe."""


class ArtifactFormatError(ArtifactCryptoError):
    """The artifact is not a well-formed supported envelope."""


class UnsupportedArtifactFormatError(ArtifactFormatError):
    """The artifact version or algorithm is not supported."""


class ArtifactTruncatedError(ArtifactFormatError):
    """The artifact ended before its authenticated terminal record."""


class ArtifactContextMismatchError(ArtifactCryptoError):
    """The artifact belongs to a different installation, backup, or lane."""


class ArtifactIntegrityError(ArtifactCryptoError):
    """Authenticated artifact bytes did not verify."""


class ArtifactSourceChangedError(ArtifactCryptoError):
    """The source changed while it was being sealed."""


class ArtifactDestinationExistsError(ArtifactCryptoError):
    """A no-clobber destination already exists."""


class KeyProviderError(ArtifactCryptoError):
    """Base class for a sanitized key-provider failure."""


class KeyProviderConfigurationError(KeyProviderError):
    """The selected key provider is missing or unsafe for the current mode."""


class KeyProviderUnavailableError(KeyProviderError):
    """The key provider could not complete the operation."""


class KeyProviderAccessDeniedError(KeyProviderError):
    """The key provider denied the operation."""


class KeyProviderNotFoundError(KeyProviderError):
    """The configured wrapping key was not found."""


class KeyProviderIntegrityError(KeyProviderError):
    """A wrapped data key could not be authenticated or unwrapped."""


class KeyProviderResponseError(KeyProviderError):
    """The key provider returned an incomplete or invalid response."""
