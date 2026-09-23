"""Strict, bounded SSH client construction shared by validation and workers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import socket
import stat
import tempfile
from dataclasses import dataclass

import paramiko
from django.conf import settings

from .reliability import (
    ClassifiedConnectionError,
    SSHHostKeyApprovalRequiredError,
    classified_connection_error,
)


class SSHHostKeyScanError(Exception):
    """Safe, typed failure raised while reading a server's SSH host key."""

    def __init__(self, code: str, detail: str, status_code: int = 502):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status_code = status_code


STRICT_KEX_ALGORITHMS = (
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group16-sha512",
)
STRICT_CIPHERS = (
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
)
STRICT_MACS = (
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
)
STRICT_HOST_KEY_ALGORITHMS = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
)
STRICT_AUTH_KEY_ALGORITHMS = STRICT_HOST_KEY_ALGORITHMS


@dataclass(frozen=True)
class SSHHostKeyScanResult:
    key: paramiko.PKey
    wire_key_type: str
    negotiated_host_key_algorithm: str
    bits: int


def validate_ssh_public_key(key, *, managed=False) -> None:
    """Enforce one explicit key-strength policy before authentication."""

    key_type = str(key.get_name())
    bits = int(key.get_bits())
    if managed:
        if key_type != "ssh-ed25519" or bits != 256:
            raise ValueError("Installation-managed SSH keys must be Ed25519")
        return
    if key_type == "ssh-ed25519" and bits == 256:
        return
    if {
        "ecdsa-sha2-nistp256": 256,
        "ecdsa-sha2-nistp384": 384,
        "ecdsa-sha2-nistp521": 521,
    }.get(key_type) == bits:
        return
    if key_type == "ssh-rsa" and 3072 <= bits <= 16384:
        return
    raise ValueError("The SSH key type or strength is not permitted")


def _strict_transport(sock, *, disabled_algorithms=None, host_key_algorithms=None):
    """Construct a pinned Paramiko transport with no compatibility algorithms."""

    transport = paramiko.Transport(
        sock,
        disabled_algorithms=disabled_algorithms,
        strict_kex=True,
    )
    security = transport.get_security_options()
    # Assignment validates that every reviewed name exists in the pinned Paramiko
    # runtime. An image/library drift therefore fails closed before the handshake.
    security.kex = STRICT_KEX_ALGORITHMS
    security.ciphers = STRICT_CIPHERS
    security.digests = STRICT_MACS
    security.key_types = tuple(host_key_algorithms or STRICT_HOST_KEY_ALGORITHMS)
    security.compression = ("none",)
    available_pubkeys = set(getattr(transport, "_key_info", {}))
    if any(name not in available_pubkeys for name in STRICT_AUTH_KEY_ALGORITHMS):
        transport.close()
        raise ValueError("The SSH public-key policy is unavailable")
    transport._preferred_pubkeys = STRICT_AUTH_KEY_ALGORITHMS
    return transport


def strict_transport_factory(sock, *, disabled_algorithms=None):
    return _strict_transport(sock, disabled_algorithms=disabled_algorithms)


def _transport_factory_for_host_keys(host_key_algorithms):
    allowed = tuple(host_key_algorithms)

    def factory(sock, *, disabled_algorithms=None):
        return _strict_transport(
            sock,
            disabled_algorithms=disabled_algorithms,
            host_key_algorithms=allowed,
        )

    return factory


def _timeout(name: str, default: int) -> int:
    try:
        return max(1, int(getattr(settings, name, default)))
    except (TypeError, ValueError):
        return default


def known_hosts_path() -> str:
    return os.path.abspath(str(settings.SSH_KNOWN_HOSTS_PATH))


def normalize_ssh_host(host) -> str:
    raw = str(host or "").strip()
    if not raw or len(raw) > 255 or any(ord(character) < 32 for character in raw):
        raise ValueError("A valid SSH host is required")
    candidate = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    if "%" in candidate:
        raise ValueError("A valid SSH host is required")
    try:
        parsed_ip = ipaddress.ip_address(candidate)
        if isinstance(parsed_ip, ipaddress.IPv6Address) and (
            parsed_ip.ipv4_mapped is not None
            or (
                parsed_ip in ipaddress.IPv6Network("::/96")
                and parsed_ip not in (ipaddress.IPv6Address("::"), ipaddress.IPv6Address("::1"))
            )
        ):
            raise ValueError("IPv4-embedded IPv6 SSH hosts are not supported")
        normalized_ip = parsed_ip.compressed.lower()
        if all(character in "0123456789." for character in candidate) and (
            candidate != normalized_ip
        ):
            raise ValueError("A canonical IPv4 address is required")
        return normalized_ip
    except ValueError:
        if ":" in candidate or all(
            character in "0123456789." for character in candidate
        ):
            raise ValueError("A valid SSH host is required") from None
        try:
            normalized = candidate.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("A valid SSH host is required") from error
        labels = normalized.split(".")
        if (
            not normalized
            or len(normalized) > 253
            or any(
                not 1 <= len(label) <= 63
                or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                is None
                for label in labels
            )
        ):
            raise ValueError("A valid SSH host is required")
        return normalized


def configure_host_keys(client: paramiko.SSHClient) -> None:
    """Load the same reviewed host-key database used by command-line SSH."""

    client.load_system_host_keys()
    path = known_hosts_path()
    if os.path.isfile(path):
        client.load_host_keys(path)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())


def _load_private_key(path: str, passphrase=None, *, managed=False):
    parse_errors = []
    for key_cls in (
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
    ):
        try:
            key = key_cls.from_private_key_file(path, password=passphrase or None)
            validate_ssh_public_key(key, managed=managed)
            return key
        except Exception as error:
            parse_errors.append(error)
    # Preserve PasswordRequiredException/AuthenticationException for accurate
    # classification, but never expose parser details or key material to callers.
    raise parse_errors[-1] if parse_errors else ValueError("Unsupported private key")


def _private_runtime_ssh_dir() -> str:
    """Return a verified, same-UID 0700 directory outside persistent work data."""

    runtime_dir = str(os.environ.get("XDG_RUNTIME_DIR") or "").strip()
    if runtime_dir:
        if not os.path.isabs(runtime_dir):
            raise ValueError("XDG_RUNTIME_DIR must be absolute")
    else:
        if str(getattr(settings, "DJANGO_SERVER", "prod")) == "prod":
            raise ValueError("A private runtime directory is required for SSH material")
        runtime_dir = os.path.join(
            tempfile.gettempdir(), f"backupsheep-runtime-{os.geteuid()}"
        )

    for directory in (runtime_dir, os.path.join(runtime_dir, "ssh")):
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        metadata = os.lstat(directory)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("The SSH runtime directory is not private")
    return os.path.join(runtime_dir, "ssh")


def materialize_temporary_private_key(private_key: str) -> str:
    """Create one O_EXCL, owner-only private key in the ephemeral runtime."""

    material = (private_key or "").replace("\r\n", "\n").replace("\r", "\n")
    if material:
        material = material.rstrip("\n") + "\n"
    descriptor, path = tempfile.mkstemp(
        prefix="ssh-key-", dir=_private_runtime_ssh_dir()
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = None
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.remove(path)
        except OSError:
            pass
        raise
    return path


def _temporary_private_key(private_key: str) -> str:
    """Backward-compatible private helper used by existing callers/tests."""

    return materialize_temporary_private_key(private_key)


def managed_private_key_path(*, account_id) -> str:
    from .managed_ssh import assert_managed_ssh_single_account

    assert_managed_ssh_single_account(account_id)
    path = getattr(settings, "SSH_MANAGED_PRIVATE_KEY_PATH", "") or getattr(
        settings, "SSH_KEY_PATH", ""
    )
    path = os.path.abspath(str(path)) if path else ""
    if not path or not os.path.isfile(path):
        raise FileNotFoundError("Managed SSH private key is not configured")
    return path


def _host_alias(host, port) -> str:
    return str(host) if int(port) == 22 else f"[{host}]:{int(port)}"


def _validate_configured_host_keys(client, host, port) -> None:
    hostname = _host_alias(host, port)
    matched = []
    for host_keys in (client._system_host_keys, client._host_keys):
        lookup = host_keys.lookup(hostname)
        if lookup:
            matched.extend(lookup.values())
    for key in matched:
        validate_ssh_public_key(key)


def _approval_key(approval):
    try:
        key_blob = base64.b64decode(approval.public_key_base64, validate=True)
        key = paramiko.PKey.from_type_string(approval.wire_key_type, key_blob)
    except Exception as error:
        raise ValueError("The approved SSH host key is malformed") from error
    validate_ssh_public_key(key)
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(key.asbytes()).digest()
    ).decode("ascii").rstrip("=")
    if (
        fingerprint != approval.fingerprint
        or int(key.get_bits()) != approval.bits
        or str(key.get_name()) != approval.wire_key_type
    ):
        raise ValueError("The approved SSH host-key witness is inconsistent")
    return key


def configure_account_host_keys(
    client,
    *,
    account_id,
    host,
    port,
    expected_witness=None,
):
    from apps.console.connection.models import CoreSSHHostKeyApproval

    normalized_host = normalize_ssh_host(host)
    try:
        port = int(port)
    except (TypeError, ValueError) as error:
        raise ValueError("A valid SSH port is required") from error
    approvals = CoreSSHHostKeyApproval.objects.filter(
        account_id=account_id,
        normalized_host=normalized_host,
        port=port,
    ).order_by("pk")
    if expected_witness:
        approvals = approvals.filter(pk=expected_witness["approval_id"])
    approvals = list(approvals)
    if not approvals:
        raise SSHHostKeyApprovalRequiredError()

    host_algorithms = []
    alias = _host_alias(normalized_host, port)
    for approval in approvals:
        if expected_witness and (
            approval.generation != expected_witness["generation"]
            or approval.fingerprint != expected_witness["fingerprint"]
            or approval.negotiated_host_key_algorithm
            != expected_witness["negotiated_host_key_algorithm"]
        ):
            raise ValueError("The SSH host-key approval changed")
        key = _approval_key(approval)
        client.get_host_keys().add(alias, approval.wire_key_type, key)
        if approval.negotiated_host_key_algorithm not in STRICT_HOST_KEY_ALGORITHMS:
            raise ValueError("The approved SSH host-key algorithm is not permitted")
        host_algorithms.append(approval.negotiated_host_key_algorithm)
    allowed = tuple(
        algorithm
        for algorithm in STRICT_HOST_KEY_ALGORITHMS
        if algorithm in set(host_algorithms)
    )
    if not allowed:
        raise ValueError("No approved SSH host-key algorithm is available")
    return _transport_factory_for_host_keys(allowed)


def open_ssh_client(
    *,
    host,
    port,
    username,
    password=None,
    private_key=None,
    private_key_passphrase=None,
    use_managed_key=False,
    allow_legacy_rsa=False,
    account_id=None,
    host_key_witness=None,
    managed_key_fingerprint=None,
):
    """Return ``(SSHClient, temporary_key_path)`` using strict host-key checks."""

    if allow_legacy_rsa:
        raise ValueError("Legacy RSA/SHA-1 SSH authentication is not supported")
    temporary_key_path = None
    client = paramiko.SSHClient()
    try:
        host = normalize_ssh_host(host)
        if account_id is None:
            if str(getattr(settings, "DJANGO_SERVER", "prod")) == "prod":
                raise ValueError("An account-scoped SSH host-key approval is required")
            configure_host_keys(client)
            _validate_configured_host_keys(client, host, port)
            transport_factory = strict_transport_factory
        else:
            if not host_key_witness:
                raise ValueError(
                    "An exact account-scoped SSH host-key witness is required"
                )
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            transport_factory = configure_account_host_keys(
                client,
                account_id=account_id,
                host=host,
                port=port,
                expected_witness=host_key_witness,
            )
        connect = {
            "hostname": host,
            "port": int(port),
            "username": username,
            "timeout": _timeout("SSH_CONNECT_TIMEOUT", 15),
            "banner_timeout": _timeout("SSH_BANNER_TIMEOUT", 15),
            "auth_timeout": _timeout("SSH_AUTH_TIMEOUT", 15),
            "allow_agent": False,
            "look_for_keys": False,
            "compress": False,
            "transport_factory": transport_factory,
        }
        if use_managed_key:
            if not managed_key_fingerprint:
                raise ValueError("An exact managed SSH identity witness is required")
            managed_key = _load_private_key(
                managed_private_key_path(account_id=account_id), managed=True
            )
            actual_fingerprint = hashlib.sha256(managed_key.asbytes()).hexdigest()
            if not hmac.compare_digest(
                actual_fingerprint, str(managed_key_fingerprint)
            ):
                raise ValueError("The managed SSH private identity changed")
            connect["pkey"] = managed_key
        elif private_key:
            temporary_key_path = _temporary_private_key(private_key)
            connect["pkey"] = _load_private_key(
                temporary_key_path, private_key_passphrase
            )
        else:
            connect["password"] = password

        client.connect(**connect)
        transport = client.get_transport()
        if transport:
            transport.set_keepalive(_timeout("SSH_KEEPALIVE_SECONDS", 30))
        return client, temporary_key_path
    except Exception as error:
        client.close()
        if temporary_key_path and os.path.exists(temporary_key_path):
            os.remove(temporary_key_path)
        if isinstance(error, ClassifiedConnectionError):
            raise
        raise classified_connection_error(error, stage="ssh") from error


def cleanup_temporary_key(path) -> None:
    if path and os.path.exists(path):
        os.remove(path)


def materialize_approved_known_hosts(host, port, witness) -> tuple[str, str]:
    """Write one exact approval to a private ephemeral OpenSSH trust file."""

    normalized_host = normalize_ssh_host(host)
    try:
        expected_port = int(port)
        approval_id = int(witness["approval_id"])
        generation = int(witness["generation"])
        witness_port = int(witness["port"])
        witness_host = str(witness["normalized_host"])
        wire_key_type = str(witness["wire_key_type"])
        public_key_base64 = str(witness["public_key_base64"])
        fingerprint = str(witness["fingerprint"])
        negotiated_algorithm = str(witness["negotiated_host_key_algorithm"])
        bits = int(witness["bits"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("The approved SSH host-key witness is incomplete") from error
    if (
        approval_id < 1
        or generation < 1
        or witness_host != normalized_host
        or witness_port != expected_port
        or negotiated_algorithm not in STRICT_HOST_KEY_ALGORITHMS
    ):
        raise ValueError("The approved SSH host-key witness changed")

    approval = type(
        "DetachedSSHHostKeyApproval",
        (),
        {
            "wire_key_type": wire_key_type,
            "public_key_base64": public_key_base64,
            "fingerprint": fingerprint,
            "bits": bits,
        },
    )()
    _approval_key(approval)
    descriptor, path = tempfile.mkstemp(
        prefix="known-hosts-", dir=_private_runtime_ssh_dir()
    )
    try:
        os.fchmod(descriptor, 0o600)
        line = (
            f"{_host_alias(normalized_host, expected_port)} "
            f"{wire_key_type} {public_key_base64}\n"
        )
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            descriptor = None
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        return path, negotiated_algorithm
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.remove(path)
        except OSError:
            pass
        raise


def scan_host_key(host, port, timeout=None) -> SSHHostKeyScanResult:
    """Complete only the SSH transport handshake and return the server key.

    This deliberately never calls an authentication method.  The TCP socket and
    Paramiko handshake each receive a finite timeout so preview/approval cannot
    pin an API worker indefinitely.  The caller is responsible for comparing the
    returned key with an approved fingerprint before allowing authenticated SSH.
    """

    bounded_timeout = timeout
    if bounded_timeout is None:
        bounded_timeout = _timeout("SSH_HOST_KEY_SCAN_TIMEOUT", 10)
    try:
        bounded_timeout = max(1, min(float(bounded_timeout), 30.0))
    except (TypeError, ValueError):
        bounded_timeout = 10.0

    raw_socket = None
    transport = None
    try:
        raw_socket = socket.create_connection(
            (str(host), int(port)), timeout=bounded_timeout
        )
        raw_socket.settimeout(bounded_timeout)
        transport = strict_transport_factory(raw_socket)
        transport.start_client(timeout=bounded_timeout)
        key = transport.get_remote_server_key()
        if key is None:
            raise paramiko.SSHException("missing server host key")
        validate_ssh_public_key(key)
        negotiated = str(getattr(transport, "host_key_type", "") or "")
        if negotiated not in STRICT_HOST_KEY_ALGORITHMS:
            raise paramiko.SSHException("unapproved host-key negotiation")
        return SSHHostKeyScanResult(
            key=key,
            wire_key_type=str(key.get_name()),
            negotiated_host_key_algorithm=negotiated,
            bits=int(key.get_bits()),
        )
    except (socket.timeout, TimeoutError):
        raise SSHHostKeyScanError(
            "ssh_timeout", "SSH host-key scan timed out.", status_code=504
        )
    except (OSError, socket.error):
        raise SSHHostKeyScanError(
            "ssh_unreachable", "Unable to reach the SSH host.", status_code=502
        )
    except paramiko.SSHException:
        raise SSHHostKeyScanError(
            "ssh_handshake_failed", "SSH handshake failed.", status_code=502
        )
    except SSHHostKeyScanError:
        raise
    except Exception:
        raise SSHHostKeyScanError(
            "ssh_scan_failed", "Unable to read the SSH host key.", status_code=502
        )
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        elif raw_socket is not None:
            try:
                raw_socket.close()
            except Exception:
                pass
