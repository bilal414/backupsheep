"""Connection failure classification shared by API validation and workers.

The source exception is deliberately not returned to API clients or copied into
telemetry. Database and SSH libraries routinely include usernames, host strings,
and occasionally command fragments in their messages. BackupSheep records only
the classifier's stable code and stage for these boundaries while exposing a
stable, non-secret error contract to operators.
"""

from __future__ import annotations

import errno
import logging
import socket
from dataclasses import dataclass
from typing import Optional


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ConnectionFailure:
    code: str
    detail: str
    stage: str
    retryable: bool
    remediation: str

    def as_dict(self):
        return {
            "code": self.code,
            "detail": self.detail,
            "stage": self.stage,
            "retryable": self.retryable,
            "remediation": self.remediation,
        }


class ClassifiedConnectionError(Exception):
    """Safe exception wrapper carrying the public validation error contract."""

    def __init__(self, failure: ConnectionFailure):
        self.failure = failure
        super().__init__(failure.detail)

    @property
    def code(self):
        return self.failure.code

    def as_dict(self):
        return self.failure.as_dict()


class DatabaseClientCapabilityError(Exception):
    """Internal signal for a missing or incompatible logical-database client.

    ``internal_detail`` is retained only for exception telemetry.  The shared
    classifier deliberately never places it in the public validation contract.
    """

    def __init__(self, engine: str, *, internal_detail: str = ""):
        self.engine = str(engine or "").lower()
        self.internal_detail = str(internal_detail or "")
        super().__init__(f"database client capability check failed for {self.engine}")


class DatabaseTLSRequiredError(Exception):
    """Internal, secret-free signal for a rejected plaintext database client."""

    def __init__(self):
        super().__init__("database server requires an SSL/TLS connection")


class SSHHostKeyApprovalRequiredError(Exception):
    """Internal signal that this account has no approved key for the endpoint."""

    def __init__(self):
        super().__init__("account-scoped SSH host-key approval is required")


def database_tls_required_message(value: object) -> bool:
    """Recognize stable MySQL-family secure-transport failures."""
    message = str(value or "").lower()
    return any(
        marker in message
        for marker in (
            "er_secure_transport_required",
            "require_secure_transport",
            "insecure transport are prohibited",
            "insecure transport is prohibited",
            "authentication requires secure connection",
            "requires a secure connection",
            "ssl connection is required",
            "ssl/tls connection is required",
        )
    )


DATABASE_EVENT_PRIVILEGE_DETAIL = (
    "The database account cannot export scheduled event definitions. Grant the "
    "EVENT privilege for every selected database, validate the connection, and "
    "retry the backup."
)


class DatabaseEventPrivilegeError(Exception):
    """Internal signal that a full-object policy cannot read scheduled events."""

    def __init__(self, *, internal_detail: str = ""):
        self.internal_detail = str(internal_detail or "")
        super().__init__("database event privilege validation failed")


def _failure(code, detail, stage, retryable, remediation):
    return ConnectionFailure(code, detail, stage, retryable, remediation)


def classify_connection_error(error: BaseException, stage: str = "connection") -> ConnectionFailure:
    """Map transport/client errors to a stable, secret-free operator message."""

    if isinstance(error, ClassifiedConnectionError):
        return error.failure

    if isinstance(error, DatabaseClientCapabilityError):
        if error.engine == "mariadb":
            return _failure(
                "DATABASE_CLIENT_UNSUPPORTED",
                "BackupSheep cannot use the configured MariaDB client tools for this connection.",
                "worker_preflight",
                False,
                "Install a MariaDB client and mariadb-dump release that supports the sandbox dump header on every relevant worker or SSH server, then validate again.",
            )
        if error.engine == "mysql":
            return _failure(
                "DATABASE_CLIENT_UNSUPPORTED",
                "BackupSheep cannot use the configured MySQL client tools for this connection.",
                "worker_preflight",
                False,
                "Install MySQL mysql and mysqldump clients at least as new as the configured server version on every relevant worker or SSH server, then validate again.",
            )
        return _failure(
            "DATABASE_CLIENT_UNSUPPORTED",
            "BackupSheep cannot use the required database client tools for this connection.",
            "worker_preflight",
            False,
            "Install compatible database client tools on every relevant worker or SSH server, then validate again.",
        )

    if isinstance(error, DatabaseTLSRequiredError):
        return _failure(
            "TLS_REQUIRED",
            "The destination requires an SSL/TLS database connection.",
            "tls",
            False,
            "Enable SSL/TLS for this connection and validate again.",
        )

    if isinstance(error, DatabaseEventPrivilegeError):
        return _failure(
            "DATABASE_EVENT_PRIVILEGE_REQUIRED",
            DATABASE_EVENT_PRIVILEGE_DETAIL,
            "authorization",
            False,
            "Grant the EVENT privilege on every database selected for backup, then validate the connection again.",
        )

    if isinstance(error, SSHHostKeyApprovalRequiredError):
        return _failure(
            "HOST_KEY_UNKNOWN",
            "The SSH host key has not been reviewed for this destination.",
            "host_key",
            False,
            "Verify the fingerprint out of band and approve it for this BackupSheep account before retrying.",
        )

    # Import optional client libraries lazily so this helper remains usable from
    # migration/test environments where a provider dependency may be unavailable.
    try:
        import paramiko
    except Exception:  # pragma: no cover - dependency is installed in production
        paramiko = None

    if paramiko and isinstance(error, paramiko.BadHostKeyException):
        return _failure(
            "HOST_KEY_CHANGED",
            "The server presented a different SSH host key. Connection was refused.",
            "host_key",
            False,
            "Verify the server identity and explicitly replace the reviewed host key before retrying.",
        )
    if paramiko and isinstance(error, paramiko.AuthenticationException):
        return _failure(
            "AUTH_FAILED",
            "The server rejected the supplied authentication credentials.",
            "authentication",
            False,
            "Check the username and selected password or key authentication mode.",
        )
    if paramiko and isinstance(error, paramiko.PasswordRequiredException):
        return _failure(
            "KEY_PASSPHRASE_REQUIRED",
            "The private key is encrypted and requires a valid passphrase.",
            "authentication",
            False,
            "Enter the private-key passphrase and validate again.",
        )
    if paramiko and isinstance(error, paramiko.ssh_exception.NoValidConnectionsError):
        errors = list((error.errors or {}).values())
        if any(getattr(item, "errno", None) == errno.ECONNREFUSED for item in errors):
            return _failure(
                "CONNECTION_REFUSED",
                "The destination refused the network connection.",
                "tcp",
                True,
                "Confirm the service is running and its firewall allows the BackupSheep worker address and port.",
            )

    if isinstance(error, socket.gaierror):
        return _failure(
            "DNS_FAILURE",
            "The destination hostname could not be resolved.",
            "dns",
            True,
            "Check the hostname and DNS records, then retry.",
        )
    if isinstance(error, (socket.timeout, TimeoutError)) or getattr(error, "errno", None) == errno.ETIMEDOUT:
        return _failure(
            "TCP_TIMEOUT",
            "The destination did not respond before the connection timeout.",
            "tcp",
            True,
            "Allow the BackupSheep worker address through the firewall and confirm the configured port is reachable.",
        )
    if (
        isinstance(error, ConnectionRefusedError)
        or getattr(error, "errno", None) == errno.ECONNREFUSED
        or (
            "can't connect to mysql server" in str(error).lower()
            and "(111)" in str(error).lower()
        )
    ):
        return _failure(
            "CONNECTION_REFUSED",
            "The destination refused the network connection.",
            "tcp",
            True,
            "Confirm the service is running and its firewall allows the BackupSheep worker address and port.",
        )
    if isinstance(error, FileNotFoundError):
        return _failure(
            "CLIENT_OR_KEY_MISSING",
            "A required backup client or managed SSH key is not installed on this worker.",
            "worker_preflight",
            False,
            "Install the required client or configure the managed SSH key on every relevant worker.",
        )

    message = str(error).lower()
    if "not found in known_hosts" in message or "known_hosts" in message and "not found" in message:
        return _failure(
            "HOST_KEY_UNKNOWN",
            "The SSH host key has not been reviewed for this destination.",
            "host_key",
            False,
            "Verify the fingerprint out of band and approve it for this BackupSheep account before retrying.",
        )
    if "host key" in message and ("changed" in message or "mismatch" in message):
        return _failure(
            "HOST_KEY_CHANGED",
            "The server presented a different SSH host key. Connection was refused.",
            "host_key",
            False,
            "Verify the server identity and explicitly replace the reviewed host key before retrying.",
        )
    if "password authentication failed" in message or "access denied for user" in message or "authentication failed" in message:
        return _failure(
            "AUTH_FAILED",
            "The service rejected the supplied credentials.",
            "authentication",
            False,
            "Check the username, password, database name, and selected authentication mode.",
        )
    if "connection refused" in message:
        return _failure(
            "CONNECTION_REFUSED",
            "The destination refused the network connection.",
            "tcp",
            True,
            "Confirm the service is running and its firewall allows the BackupSheep worker address and port.",
        )
    if "timeout" in message or "timed out" in message:
        return _failure(
            "TCP_TIMEOUT",
            "The destination did not respond before the connection timeout.",
            "tcp",
            True,
            "Allow the BackupSheep worker address through the firewall and confirm the configured port is reachable.",
        )
    if "no pg_hba.conf entry" in message or "permission denied" in message or "not permitted" in message:
        return _failure(
            "PERMISSION_DENIED",
            "The account connected but does not have the required permission.",
            "authorization",
            False,
            "Grant the minimum read/export permissions required for this backup and validate again.",
        )
    if database_tls_required_message(message) or (
        "ssl" in message and ("required" in message or "tls" in message)
    ):
        return _failure(
            "TLS_REQUIRED",
            "The destination requires an SSL/TLS database connection.",
            "tls",
            False,
            "Enable SSL/TLS for this connection and validate again.",
        )

    return _failure(
        "CONNECTION_VALIDATION_FAILED",
        "BackupSheep could not validate the destination connection.",
        stage,
        False,
        "Review the destination address, credentials, permissions, and worker connectivity, then retry validation.",
    )


def classify_and_record_connection_error(
    error: BaseException,
    stage: str = "connection",
) -> ConnectionFailure:
    """Classify a failure and emit only bounded, non-secret telemetry.

    Do not use ``logger.exception`` or interpolate ``error`` here. Provider and
    client exceptions can contain credentials, private hostnames, SQL fragments,
    or command lines. The classifier code and stage are fixed public-contract
    values and are sufficient for aggregate operational monitoring.
    """

    failure = classify_connection_error(error, stage=stage)
    logger.warning(
        "Connection operation failed.",
        extra={
            "connection_failure_code": failure.code,
            "connection_failure_stage": failure.stage,
        },
    )
    return failure


def classified_connection_error(error: BaseException, stage: str = "connection") -> ClassifiedConnectionError:
    return ClassifiedConnectionError(classify_connection_error(error, stage=stage))
