from botocore.client import Config
from botocore.exceptions import BotoCoreError, ClientError
from dataclasses import dataclass

from apps._tasks.exceptions import StorageVultrUploadFailedError
from apps._tasks.integration.storage.s3_verified import (
    S3ObjectIntegrityError,
    S3UploadReconciliationRequired,
    upload_verified_s3,
)
from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.api.v1.utils.boto import bounded_boto3_client


VULTR_OBJECT_METADATA_KEY = "vultr_s3_object"


@dataclass(frozen=True)
class _SafeS3Failure:
    """Private classification data; never serialize provider details."""

    code: str
    message: str
    retryable: bool
    retry_after: int | None = None
    provider_code: str = ""


_AUTH_CODES = {
    "accessdenied",
    "expiredtoken",
    "expiredtokenexception",
    "invalidaccesskeyid",
    "invalidclienttokenid",
    "invalidsecuritytoken",
    "invalidtoken",
    "signaturedoesnotmatch",
    "unauthorized",
}
_NOT_FOUND_CODES = {
    "404",
    "bucketdeleted",
    "nosuchbucket",
    "nosuchkey",
    "notfound",
}
_RATE_LIMIT_CODES = {
    "ratelimitexceeded",
    "requestlimitexceeded",
    "slowdown",
    "throttling",
    "throttlingexception",
    "toomanyrequests",
    "toomanyrequestsexception",
}
_RECONCILIATION_CODES = {
    "conditionalrequestconflict",
    "invalidpart",
    "invalidpartorder",
    "nosuchupload",
    "preconditionfailed",
}
_QUOTA_CODES = {"quotaexceeded", "storagequotaexceeded"}


def _exception_chain(error):
    current = error
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )


def _provider_response(error):
    for current in _exception_chain(error):
        if not isinstance(current, ClientError):
            continue
        response = current.response if isinstance(current.response, dict) else {}
        error_data = response.get("Error") or {}
        if not isinstance(error_data, dict):
            error_data = {}
        provider_code = error_data.get("Code")
        provider_code = provider_code.lower() if isinstance(provider_code, str) else ""
        response_metadata = response.get("ResponseMetadata") or {}
        if not isinstance(response_metadata, dict):
            response_metadata = {}
        status = response_metadata.get("HTTPStatusCode")
        if isinstance(status, str) and status.isdigit():
            status = int(status)
        if not isinstance(status, int):
            status = None
        headers = response_metadata.get("HTTPHeaders") or {}
        if not isinstance(headers, dict):
            headers = {}
        return provider_code, status, headers
    return "", None, {}


def _retry_after(headers):
    if not isinstance(headers, dict):
        return None
    value = None
    for name, candidate in headers.items():
        if isinstance(name, str) and name.lower() == "retry-after":
            value = candidate
            break
    if isinstance(value, int):
        seconds = value
    elif isinstance(value, str) and value.strip().isdigit():
        seconds = int(value.strip())
    else:
        return None
    return max(1, min(seconds, 86400))


def _declared_retry_after(error):
    for current in _exception_chain(error):
        value = getattr(current, "retry_after", None)
        if isinstance(value, int):
            return max(1, min(value, 86400))
        if isinstance(value, str) and value.strip().isdigit():
            return max(1, min(int(value.strip()), 86400))
    return None


def _declared_code(error):
    for current in _exception_chain(error):
        value = getattr(current, "error_code", None) or getattr(current, "code", None)
        if isinstance(value, str):
            return value.upper()
    return ""


def _safe_s3_failure(error):
    """Return stable storage semantics without reading provider body text."""
    for current in _exception_chain(error):
        if isinstance(current, S3ObjectIntegrityError):
            return _SafeS3Failure(
                "STORAGE_INTEGRITY_FAILED",
                "The uploaded object failed integrity verification; the local backup changed after this upload operation started or the provider copy did not match.",
                False,
            )
        if isinstance(current, S3UploadReconciliationRequired):
            return _SafeS3Failure(
                "STORAGE_RECONCILIATION_REQUIRED",
                "The provider returned ambiguous upload state; Multiple unfinished uploads or another reconciliation conflict requires review.",
                False,
            )

    declared_code = _declared_code(error)
    if declared_code in {
        "STORAGE_INTEGRITY_FAILED",
        "STORAGE_RECONCILIATION_REQUIRED",
        "STORAGE_AUTH_FAILED",
        "STORAGE_DESTINATION_NOT_FOUND",
        "STORAGE_RATE_LIMITED",
        "STORAGE_QUOTA_EXCEEDED",
        "STORAGE_TIMEOUT",
        "PROVIDER_TIMEOUT",
        "PROVIDER_TRANSIENT_FAILURE",
        "PROVIDER_MALFORMED_RESPONSE",
    }:
        messages = {
            "STORAGE_INTEGRITY_FAILED": "The uploaded object failed integrity verification.",
            "STORAGE_RECONCILIATION_REQUIRED": "The provider returned ambiguous upload state; automatic writes were stopped safely.",
            "STORAGE_AUTH_FAILED": "The storage destination rejected its configured credentials.",
            "STORAGE_DESTINATION_NOT_FOUND": "The configured storage destination or object was not found.",
            "STORAGE_RATE_LIMITED": "The storage provider rate limit was reached; upload will resume automatically.",
            "STORAGE_QUOTA_EXCEEDED": "The storage destination has reached its configured capacity quota.",
            "STORAGE_TIMEOUT": "The storage operation timed out and will resume automatically.",
            "PROVIDER_TIMEOUT": "The storage operation timed out and will resume automatically.",
            "PROVIDER_TRANSIENT_FAILURE": "The storage provider could not complete the operation; upload will resume automatically.",
            "PROVIDER_MALFORMED_RESPONSE": "The provider returned a malformed response; automatic writes were stopped safely.",
        }
        retryable = declared_code in {
            "STORAGE_RATE_LIMITED",
            "STORAGE_TIMEOUT",
            "PROVIDER_TIMEOUT",
            "PROVIDER_TRANSIENT_FAILURE",
        }
        return _SafeS3Failure(
            declared_code,
            messages[declared_code],
            retryable,
            _declared_retry_after(error),
        )

    provider_code, status, headers = _provider_response(error)
    retry_after = _retry_after(headers)
    if provider_code in _QUOTA_CODES or status == 507:
        return _SafeS3Failure(
            "STORAGE_QUOTA_EXCEEDED",
            "The storage destination has reached its configured capacity quota.",
            False,
            provider_code=provider_code,
        )
    if provider_code in _AUTH_CODES or status in {401, 403}:
        return _SafeS3Failure(
            "STORAGE_AUTH_FAILED",
            "The storage destination rejected its configured credentials.",
            False,
            provider_code=provider_code,
        )
    if provider_code in _NOT_FOUND_CODES or status == 404:
        return _SafeS3Failure(
            "STORAGE_DESTINATION_NOT_FOUND",
            "The configured storage destination or object was not found.",
            False,
            provider_code=provider_code,
        )
    if provider_code in _RATE_LIMIT_CODES or status == 429:
        return _SafeS3Failure(
            "STORAGE_RATE_LIMITED",
            "The storage provider rate limit was reached; upload will resume automatically.",
            True,
            retry_after,
            provider_code,
        )
    if provider_code in _RECONCILIATION_CODES or status in {409, 412}:
        return _SafeS3Failure(
            "STORAGE_RECONCILIATION_REQUIRED",
            "The provider returned ambiguous upload state; automatic writes were stopped safely.",
            False,
            provider_code=provider_code,
        )
    if any(
        token in type(current).__name__.lower()
        for current in _exception_chain(error)
        for token in ("responseparser", "paramvalidation", "malformedresponse")
    ):
        return _SafeS3Failure(
            "PROVIDER_MALFORMED_RESPONSE",
            "The provider returned a malformed response; automatic writes were stopped safely.",
            False,
            provider_code=provider_code,
        )
    if any(
        "checksum" in type(current).__name__.lower()
        for current in _exception_chain(error)
    ):
        return _SafeS3Failure(
            "STORAGE_INTEGRITY_FAILED",
            "The uploaded object failed integrity verification.",
            False,
            provider_code=provider_code,
        )
    has_provider_response = bool(provider_code or status is not None)
    if (
        (
            isinstance(error, (BotoCoreError, TimeoutError, ConnectionError))
            and not has_provider_response
        )
        or any(
            token in type(current).__name__.lower()
            for current in _exception_chain(error)
            for token in ("timeout", "connectionclosed", "endpointconnection")
        )
        or provider_code in {"requesttimeout", "requesttimeoutexception"}
        or status in {408}
    ):
        is_timeout = (
            isinstance(error, TimeoutError)
            or provider_code in {"requesttimeout", "requesttimeoutexception"}
            or status == 408
            or any(
                "timeout" in type(current).__name__.lower()
                for current in _exception_chain(error)
            )
        )
        return _SafeS3Failure(
            "STORAGE_TIMEOUT" if is_timeout else "PROVIDER_TRANSIENT_FAILURE",
            "The storage operation timed out and will resume automatically."
            if is_timeout
            else "The storage provider could not complete the operation; upload will resume automatically.",
            True,
            retry_after,
            provider_code,
        )
    if status is not None and 400 <= status < 500:
        return _SafeS3Failure(
            "PROVIDER_MALFORMED_RESPONSE",
            "The provider returned a malformed response; automatic writes were stopped safely.",
            False,
            provider_code=provider_code,
        )
    return _SafeS3Failure(
        "PROVIDER_TRANSIENT_FAILURE",
        "The storage provider could not complete the operation; upload will resume automatically.",
        True,
        retry_after,
        provider_code,
    )


def _safe_upload_exception(exception_type, stored_backup, error, *, failure=None):
    failure = failure or _safe_s3_failure(error)
    wrapped = exception_type(
        stored_backup.backup.uuid_str,
        stored_backup.backup.attempt_no,
        stored_backup.backup.type,
        failure.message,
    )
    wrapped.error_code = failure.code
    wrapped.code = failure.code
    wrapped.retryable = failure.retryable
    wrapped.retry_after = failure.retry_after
    return wrapped


def _s3_client(storage, encryption_key):
    vultr = storage.storage_vultr
    return bounded_boto3_client(
        "s3",
        allow_retries=True,
        aws_access_key_id=bs_decrypt(vultr.access_key, encryption_key),
        aws_secret_access_key=bs_decrypt(vultr.secret_key, encryption_key),
        endpoint_url=f"https://{vultr.endpoint}",
        config=Config(
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def storage_vultr(stored_backup):
    try:
        local_zip = f"_storage/{stored_backup.backup.uuid}.zip"
        storage = stored_backup.storage
        encryption_key = storage.account.get_encryption_key()
        vultr = storage.storage_vultr

        prefix = vultr.prefix or ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        key = f"{prefix}{stored_backup.backup.uuid}.zip"

        upload_verified_s3(
            stored_backup,
            client=_s3_client(storage, encryption_key),
            bucket=vultr.bucket_name,
            key=key,
            local_path=local_zip,
            metadata_key=VULTR_OBJECT_METADATA_KEY,
            # Vultr is S3 compatible but does not expose every AWS checksum feature;
            # the portable SHA-256 metadata plus byte-count verification is used.
            supports_checksum=False,
        )
    except FileNotFoundError:
        stored_backup.status = stored_backup.Status.UPLOAD_FAILED_FILE_NOT_FOUND
        stored_backup.save(update_fields=["status", "modified"])
    except Exception as error:
        raise _safe_upload_exception(
            StorageVultrUploadFailedError, stored_backup, error
        ) from error
import boto3
