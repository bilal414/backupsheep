"""AWS KMS implementation of the BackupSheep data-key provider contract."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
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
_KMS_KEY_ARN = re.compile(
    r"^arn:(?P<partition>[a-z0-9-]+):kms:(?P<region>[a-z0-9-]+):"
    r"(?P<account>\d{12}):key/(?P<key_id>[A-Za-z0-9-]+)$"
)
_ACCESS_DENIED = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "ForbiddenException",
        "UnauthorizedException",
    }
)


def _bounded_integer(name: str, value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is int:
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        parsed = int(value)
    else:
        raise KeyProviderConfigurationError(
            f"{name} must be an integer between {minimum} and {maximum}."
        )
    if not minimum <= parsed <= maximum:
        raise KeyProviderConfigurationError(
            f"{name} must be between {minimum} and {maximum}."
        )
    return parsed


def _normalized_key_allowlist(value: object, *, region_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise KeyProviderConfigurationError(
            "The AWS KMS decrypt-key allowlist must be a sequence of resolved key ARNs."
        )
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or item != item.strip():
            raise KeyProviderConfigurationError(
                "The AWS KMS decrypt-key allowlist contains an invalid key ARN."
            )
        match = _KMS_KEY_ARN.fullmatch(item)
        if match is None or match.group("region") != region_name:
            raise KeyProviderConfigurationError(
                "The AWS KMS decrypt-key allowlist must contain resolved key ARNs "
                "from the configured region."
            )
        if item not in normalized:
            normalized.append(item)
    return tuple(normalized)


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
    allowed_key_ids: tuple[str, ...] = ()
    endpoint_url: str | None = None
    connect_timeout_seconds: int = 5
    read_timeout_seconds: int = 30
    max_attempts: int = 3
    allow_insecure_endpoint: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str):
            raise KeyProviderConfigurationError(
                "The AWS KMS wrapping key identifier is invalid."
            )
        key_id = self.key_id
        if not key_id or len(key_id) > 2048 or key_id != key_id.strip():
            raise KeyProviderConfigurationError(
                "The AWS KMS wrapping key identifier is invalid."
            )
        if not isinstance(self.region_name, str) or not _REGION.fullmatch(
            self.region_name
        ):
            raise KeyProviderConfigurationError("The AWS KMS region is invalid.")
        object.__setattr__(
            self,
            "connect_timeout_seconds",
            _bounded_integer(
                "The AWS KMS connect timeout",
                self.connect_timeout_seconds,
                minimum=1,
                maximum=60,
            ),
        )
        object.__setattr__(
            self,
            "read_timeout_seconds",
            _bounded_integer(
                "The AWS KMS read timeout",
                self.read_timeout_seconds,
                minimum=1,
                maximum=120,
            ),
        )
        object.__setattr__(
            self,
            "max_attempts",
            _bounded_integer(
                "AWS KMS retry attempts", self.max_attempts, minimum=1, maximum=5
            ),
        )
        if type(self.allow_insecure_endpoint) is not bool:
            raise KeyProviderConfigurationError(
                "The AWS KMS insecure-endpoint flag must be a boolean."
            )
        object.__setattr__(
            self,
            "allowed_key_ids",
            _normalized_key_allowlist(
                self.allowed_key_ids, region_name=self.region_name
            ),
        )
        configured_arn = _KMS_KEY_ARN.fullmatch(key_id)
        if configured_arn and key_id not in self.allowed_key_ids:
            raise KeyProviderConfigurationError(
                "A resolved AWS KMS wrapping key ARN must be present in the "
                "decrypt-key allowlist."
            )
        if self.endpoint_url:
            if not isinstance(self.endpoint_url, str):
                raise KeyProviderConfigurationError(
                    "The AWS KMS endpoint URL is invalid."
                )
            parsed = urlparse(self.endpoint_url)
            allowed_scheme = parsed.scheme == "https" or (
                self.allow_insecure_endpoint and parsed.scheme == "http"
            )
            if (
                not allowed_scheme
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.params
                or parsed.query
                or parsed.fragment
            ):
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
    def enterprise_eligible(self) -> bool:
        return bool(
            self.config.endpoint_url is None
            and self.config.allow_insecure_endpoint is False
            and self.config.allowed_key_ids
        )

    def _require_allowed_key(self, key_id: object) -> str:
        if not isinstance(key_id, str) or not key_id:
            raise KeyProviderResponseError(
                "The key provider returned an invalid wrapping key identity."
            )
        if self.config.allowed_key_ids and key_id not in self.config.allowed_key_ids:
            raise KeyProviderIntegrityError(
                "The key provider used a wrapping key outside the configured allowlist."
            )
        return key_id

    @staticmethod
    def _require_wrapped_data_key(wrapped: WrappedDataKey) -> None:
        if (
            wrapped.provider_name != AWSKMSKeyProvider.name
            or not isinstance(wrapped.wrapping_key_id, str)
            or not wrapped.wrapping_key_id
            or not isinstance(wrapped.ciphertext, (bytes, bytearray))
            or not 1 <= len(wrapped.ciphertext) <= 8192
        ):
            raise KeyProviderConfigurationError(
                "The wrapped data key does not belong to the AWS KMS provider."
            )

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
                    # Environment/shared-config endpoint overrides must not
                    # silently redirect enterprise KMS traffic.
                    ignore_configured_endpoint_urls=True,
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
        if not isinstance(response, Mapping):
            raise KeyProviderResponseError(
                "The key provider returned an invalid data-key response."
            )
        plaintext = response.get("Plaintext")
        ciphertext = response.get("CiphertextBlob")
        resolved_key_id = response.get("KeyId") or self.config.key_id
        if (
            not isinstance(plaintext, (bytes, bytearray))
            or len(plaintext) != 32
            or not isinstance(ciphertext, (bytes, bytearray))
            or not ciphertext
            or len(ciphertext) > 8192
        ):
            raise KeyProviderResponseError(
                "The key provider returned an invalid data-key response."
            )
        mutable_plaintext = bytearray(plaintext)
        try:
            resolved_key_id = self._require_allowed_key(resolved_key_id)
            return GeneratedDataKey(
                plaintext=mutable_plaintext,
                wrapped=WrappedDataKey(
                    provider_name=self.name,
                    wrapping_key_id=resolved_key_id,
                    ciphertext=bytes(ciphertext),
                ),
            )
        except BaseException:
            mutable_plaintext[:] = b"\x00" * len(mutable_plaintext)
            raise

    def unwrap_data_key(
        self, wrapped: WrappedDataKey, context: ArtifactContext
    ) -> bytearray:
        self._require_wrapped_data_key(wrapped)
        self._require_allowed_key(wrapped.wrapping_key_id)
        try:
            response = self.client.decrypt(
                CiphertextBlob=bytes(wrapped.ciphertext),
                KeyId=wrapped.wrapping_key_id,
                EncryptionAlgorithm="SYMMETRIC_DEFAULT",
                EncryptionContext=context.key_provider_context(),
            )
        except (BotoCoreError, ClientError) as error:
            self._raise_provider_error(error)
        if not isinstance(response, Mapping):
            raise KeyProviderResponseError(
                "The key provider returned an invalid plaintext data key."
            )
        plaintext = response.get("Plaintext")
        resolved_key_id = self._require_allowed_key(response.get("KeyId"))
        if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) != 32:
            raise KeyProviderResponseError(
                "The key provider returned an invalid plaintext data key."
            )
        if resolved_key_id != wrapped.wrapping_key_id:
            raise KeyProviderIntegrityError(
                "The key provider decrypted the data key with an unexpected wrapping key."
            )
        return bytearray(plaintext)

    def rewrap_data_key(
        self,
        wrapped: WrappedDataKey,
        context: ArtifactContext,
        *,
        destination_key_id: str,
    ) -> WrappedDataKey:
        self._require_wrapped_data_key(wrapped)
        self._require_allowed_key(wrapped.wrapping_key_id)
        if (
            not isinstance(destination_key_id, str)
            or not destination_key_id
            or len(destination_key_id) > 2048
            or destination_key_id != destination_key_id.strip()
        ):
            raise KeyProviderConfigurationError(
                "The destination AWS KMS key identifier is invalid."
            )
        if _KMS_KEY_ARN.fullmatch(destination_key_id):
            self._require_allowed_key(destination_key_id)
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
        if not isinstance(response, Mapping):
            raise KeyProviderResponseError(
                "The key provider returned an invalid rewrapped data key."
            )
        ciphertext = response.get("CiphertextBlob")
        resolved_key_id = response.get("KeyId") or destination_key_id
        source_key_id = response.get("SourceKeyId")
        if (
            not isinstance(ciphertext, (bytes, bytearray))
            or not ciphertext
            or len(ciphertext) > 8192
        ):
            raise KeyProviderResponseError(
                "The key provider returned an invalid rewrapped data key."
            )
        resolved_key_id = self._require_allowed_key(resolved_key_id)
        if source_key_id is not None and source_key_id != wrapped.wrapping_key_id:
            raise KeyProviderIntegrityError(
                "The key provider rewrapped an unexpected source key."
            )
        return WrappedDataKey(self.name, resolved_key_id, bytes(ciphertext))
