"""Strict, bounded SSH client construction shared by validation and workers."""

from __future__ import annotations

import os
import socket
import tempfile

import paramiko
from django.conf import settings

from .reliability import ClassifiedConnectionError, classified_connection_error


class SSHHostKeyScanError(Exception):
    """Safe, typed failure raised while reading a server's SSH host key."""

    def __init__(self, code: str, detail: str, status_code: int = 502):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status_code = status_code


def _timeout(name: str, default: int) -> int:
    try:
        return max(1, int(getattr(settings, name, default)))
    except (TypeError, ValueError):
        return default


def known_hosts_path() -> str:
    return os.path.abspath(str(settings.SSH_KNOWN_HOSTS_PATH))


def configure_host_keys(client: paramiko.SSHClient) -> None:
    """Load the same reviewed host-key database used by command-line SSH."""

    client.load_system_host_keys()
    path = known_hosts_path()
    if os.path.isfile(path):
        client.load_host_keys(path)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())


def _load_private_key(path: str, passphrase=None):
    parse_errors = []
    for key_cls in (
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
    ):
        try:
            return key_cls.from_private_key_file(path, password=passphrase or None)
        except Exception as error:
            parse_errors.append(error)
    # Preserve PasswordRequiredException/AuthenticationException for accurate
    # classification, but never expose parser details or key material to callers.
    raise parse_errors[-1] if parse_errors else ValueError("Unsupported private key")


def _temporary_private_key(private_key: str) -> str:
    # Private keys supplied for a single validation/connection must never land in
    # the persistent shared backup work volume. Stock containers provide a private,
    # noexec tmpfs through XDG_RUNTIME_DIR; non-container development falls back to
    # tempfile's secure O_EXCL file creation in the platform temp directory.
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    workdir = None
    if runtime_dir:
        workdir = os.path.join(runtime_dir, "ssh")
        os.makedirs(workdir, mode=0o700, exist_ok=True)
        os.chmod(workdir, 0o700)
    descriptor, path = tempfile.mkstemp(prefix="ssh-key-", dir=workdir)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(private_key)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if os.path.exists(path):
            os.remove(path)
        raise
    return path


def managed_private_key_path() -> str:
    path = getattr(settings, "SSH_MANAGED_PRIVATE_KEY_PATH", "") or getattr(
        settings, "SSH_KEY_PATH", ""
    )
    path = os.path.abspath(str(path)) if path else ""
    if not path or not os.path.isfile(path):
        raise FileNotFoundError("Managed SSH private key is not configured")
    return path


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
):
    """Return ``(SSHClient, temporary_key_path)`` using strict host-key checks."""

    temporary_key_path = None
    client = paramiko.SSHClient()
    configure_host_keys(client)
    try:
        connect = {
            "hostname": host,
            "port": int(port),
            "username": username,
            "timeout": _timeout("SSH_CONNECT_TIMEOUT", 15),
            "banner_timeout": _timeout("SSH_BANNER_TIMEOUT", 15),
            "auth_timeout": _timeout("SSH_AUTH_TIMEOUT", 15),
            "allow_agent": False,
            "look_for_keys": False,
        }
        if allow_legacy_rsa:
            connect["disabled_algorithms"] = {
                "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]
            }
        if use_managed_key:
            connect["pkey"] = _load_private_key(managed_private_key_path())
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


def scan_host_key(host, port, timeout=None):
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
        transport = paramiko.Transport(raw_socket)
        transport.start_client(timeout=bounded_timeout)
        key = transport.get_remote_server_key()
        if key is None:
            raise paramiko.SSHException("missing server host key")
        return key
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
