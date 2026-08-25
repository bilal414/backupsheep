from rest_framework import serializers

from apps.console.connection.reliability import (
    classify_and_record_connection_error,
)


MANAGED_SSH_SINGLE_ACCOUNT_VALIDATION_DETAIL = (
    "Installation-managed SSH authentication is available only for a "
    "single-account installation. Multi-account installations must use a "
    "customer-supplied private key."
)


def _restore_retryable_booleans(value):
    """Undo DRF's string coercion for the classifier's boolean contract field."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "retryable" and str(item).lower() in {"true", "false"}:
                value[key] = str(item).lower() == "true"
            else:
                _restore_retryable_booleans(item)
    elif isinstance(value, list):
        for item in value:
            _restore_retryable_booleans(item)


class StructuredConnectionValidationMixin:
    """Preserve typed nested connection errors when DRF raises serializer errors."""

    def is_valid(self, *, raise_exception=False):
        valid = super().is_valid(raise_exception=False)
        if not valid and raise_exception:
            validation_error = serializers.ValidationError(self.errors)
            _restore_retryable_booleans(validation_error.detail)
            raise validation_error
        return valid


def safe_connection_validation_error(error, *, stage="connection"):
    """Build the nested DRF contract from the shared connection classifier.

    The original exception is deliberately never included. Client libraries can put
    usernames, hostnames, SQL, and command fragments in exception messages.
    """
    failure = classify_and_record_connection_error(error, stage=stage)
    detail = serializers.ErrorDetail(
        failure.detail,
        code=failure.code.lower(),
    )
    validation_error = serializers.ValidationError(
        {
            "non_field_errors": [detail],
            "connection_error": {
                "code": serializers.ErrorDetail(
                    failure.code,
                    code=failure.code.lower(),
                ),
                "detail": detail,
                "stage": serializers.ErrorDetail(
                    failure.stage,
                    code=failure.code.lower(),
                ),
                "retryable": serializers.ErrorDetail(
                    str(failure.retryable).lower(),
                    code=failure.code.lower(),
                ),
                "remediation": serializers.ErrorDetail(
                    failure.remediation,
                    code=failure.code.lower(),
                ),
            },
        }
    )
    # DRF coerces every ValidationError leaf to ErrorDetail. Restore the contract's
    # boolean type now and again at the parent serializer boundary.
    _restore_retryable_booleans(validation_error.detail)
    return validation_error
