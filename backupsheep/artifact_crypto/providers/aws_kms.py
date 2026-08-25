"""AWS KMS implementation of the BackupSheep data-key provider contract."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from ..context import ArtifactContext
from ..errors import (
    KeyProviderAccessDeniedError,
    KeyProviderConfigurationError,
    KeyProviderIntegrityError,
    KeyProviderNotFoundError,
    KeyProviderResponseError,
    KeyProviderUnavailableError,
)
from .base import GeneratedDataKey, WrappedDataKey

_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-\d+$")
_ACCESS_DENIED = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "ForbiddenException",
        "UnauthorizedException",
    }
)
_NOT_FOUND = frozenset({"NotFound", "NotFoundException"})
_INTEGRITY = frozenset(
    {
        "IncorrectKeyException",
        "InvalidCiphertextException",
        "InvalidGrantTokenException",
    }
)


@dataclass(frozen=True, slots=True)
class AWSKMSConfig:
    key_id: str
    region_name: str
    endpoint_url: str | None = None
    connect_timeout_seconds: int = 5
    read_timeout_seconds: int = 30
    max_attempts: int = 3
    allow_insecure_endpoint: bool = False

    def __post_init__(self) -> None:
        key_id = str(self.key_id or "")
        if not key_id or len(key_id) > 2048 or key_id != key_id.strip():
            raise KeyProviderConfigurationError(
                "The AWS KMS wrapping key identifier is invalid."
            )
        if not _REGION.fullmatch(str(self.region_name or "")):
            raise KeyProviderConfigurationError("The AWS KMS region is invalid.")
        if not 1 <= int(self.connect_timeout_seconds) <= 60:
            raise KeyProviderConfigurationError(
                "The AWS KMS connect timeout must be between 1 and 60 seconds."
            )
        if not 1 <= int(self.read_timeout_seconds) <= 120:
            raise KeyProviderConfigurationError(
                "The AWS KMS read timeout must be between 1 and 120 seconds."
            )
        if not 1 <= int(self.max_attempts) <= 5:
            raise KeyProviderConfigurationError(
                "AWS KMS retry attempts must be between 1 and 5."
            )
        if self.endpoint_url:
            parsed = urlparse(self.endpoint_url)
            allowed_scheme = parsed.scheme == "https" or (
                self.allow_insecure_endpoint and parsed.scheme == "http"
            )
            if not allowed_scheme or not parsed.hostname or parsed.username:
                raise KeyProviderConfigurationError(
                    "The AWS KMS endpoint URL is invalid."
                )


class AWSKMSKeyProvider:
    name = "aws-kms"
    external = True

    def __init__(self, config: AWSKMSConfig, *, client=None):
        self.config = config
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import boto3

            self._client = boto3.client(
                "kms",
                region_name=self.config.region_name,
                endpoint_url=self.config.endpoint_url,
                config=Config(
                    connect_timeout=self.config.connect_timeout_seconds,
                    read_timeout=self.config.read_timeout_seconds,
                    retries={
                        "mode": "standard",
                        "max_attempts": self.config.max_attempts,
                    },
                    tcp_keepalive=True,
                ),
            )
        return self._client

    @staticmethod
    def _raise_provider_error(error: BaseException) -> None:
        code = ""
        if isinstance(error, ClientError):
            code = str(error.response.get("Error", {}).get("Code", ""))
        if code in _ACCESS_DENIED:
            raise KeyProviderAccessDeniedError(
                "The key provider denied the cryptographic operation."
            ) from None
        if code in _NOT_FOUND:
            raise KeyProviderNotFoundError(
                "The configured wrapping key was not found."
            ) from None
        if code in _INTEGRITY:
            raise KeyProviderIntegrityError(
                "The wrapped data key could not be authenticated."
            ) from None
        raise KeyProviderUnavailableError(
            "The key provider could not complete the cryptographic operation."
        ) from None

    def generate_data_key(self, context: ArtifactContext) -> GeneratedDataKey:
        try:
            response = self.client.generate_data_key(
                KeyId=self.config.key_id,
                KeySpec="AES_256",
                EncryptionContext=context.key_provider_context(),
            )
        except (BotoCoreError, ClientError) as error:
            self._raise_provider_error(error)
        plaintext = response.get("Plaintext")
        ciphertext = response.get("CiphertextBlob")
        resolved_key_id = response.get("KeyId") or self.config.key_id
        if (
            not isinstance(plaintext, (bytes, bytearray))
            or len(plaintext) != 32
            or not isinstance(ciphertext, (bytes, bytearray))
            or not ciphertext
            or not isinstance(resolved_key_id, str)
            or not resolved_key_id
        ):
            raise KeyProviderResponseError(
                "The key provider returned an invalid data-key response."
            )
        return GeneratedDataKey(
            plaintext=bytearray(plaintext),
            wrapped=WrappedDataKey(
                provider_name=self.name,
                wrapping_key_id=resolved_key_id,
                ciphertext=bytes(ciphertext),
            ),
        )

    def unwrap_data_key(
        self, wrapped: WrappedDataKey, context: ArtifactContext
    ) -> bytearray:
        if wrapped.provider_name != self.name or not wrapped.wrapping_key_id:
            raise KeyProviderConfigurationError(
                "The wrapped data key does not belong to the AWS KMS provider."
            )
        try:
            response = self.client.decrypt(
                CiphertextBlob=bytes(wrapped.ciphertext),
                KeyId=wrapped.wrapping_key_id,
                EncryptionAlgorithm="SYMMETRIC_DEFAULT",
                EncryptionContext=context.key_provider_context(),
            )
        except (BotoCoreError, ClientError) as error:
            self._raise_provider_error(error)
        plaintext = response.get("Plaintext")
        if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) != 32:
            raise KeyProviderResponseError(
                "The key provider returned an invalid plaintext data key."
            )
        return bytearray(plaintext)

    def rewrap_data_key(
        self,
        wrapped: WrappedDataKey,
        context: ArtifactContext,
        *,
        destination_key_id: str,
    ) -> WrappedDataKey:
        if wrapped.provider_name != self.name or not wrapped.wrapping_key_id:
            raise KeyProviderConfigurationError(
                "The wrapped data key does not belong to the AWS KMS provider."
            )
        if not destination_key_id or destination_key_id != destination_key_id.strip():
            raise KeyProviderConfigurationError(
                "The destination AWS KMS key identifier is invalid."
            )
        try:
            response = self.client.re_encrypt(
                CiphertextBlob=bytes(wrapped.ciphertext),
                SourceKeyId=wrapped.wrapping_key_id,
                DestinationKeyId=destination_key_id,
                SourceEncryptionContext=context.key_provider_context(),
                DestinationEncryptionContext=context.key_provider_context(),
            )
        except (BotoCoreError, ClientError) as error:
            self._raise_provider_error(error)
        ciphertext = response.get("CiphertextBlob")
        resolved_key_id = response.get("KeyId") or destination_key_id
        if (
            not isinstance(ciphertext, (bytes, bytearray))
            or not ciphertext
            or not isinstance(resolved_key_id, str)
            or not resolved_key_id
        ):
            raise KeyProviderResponseError(
                "The key provider returned an invalid rewrapped data key."
            )
        return WrappedDataKey(self.name, resolved_key_id, bytes(ciphertext))
