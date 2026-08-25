"""Crash-safe SSH host-key preview and approval workflow.

The API intentionally separates key discovery from authenticated SSH use.  A
preview token identifies the exact account, user, endpoint, algorithm, and
fingerprint that the user reviewed.  Approval re-fetches the key and performs a
locked, atomic update of the shared OpenSSH known_hosts file.
"""

from __future__ import annotations

import base64
import contextlib
import errno
import fcntl
import hashlib
import hmac
import logging
import os
import stat
import tempfile
from dataclasses import dataclass

import paramiko
from django.conf import settings
from django.core import signing
from rest_framework import status

from apps.console.connection import ssh
from apps.console.log.models import CoreLog


logger = logging.getLogger(__name__)

TOKEN_SALT = "backupsheep.ssh-host-key-approval.v1"
DEFAULT_TOKEN_MAX_AGE = 10 * 60
STOCK_SSH_TRUST_GID = 10997
SSH_TRUST_DIRECTORY_MODE = 0o2750
SSH_TRUST_FILE_MODE = 0o640


class SSHHostKeyFlowError(Exception):
    """A client-safe, typed error for the host-key approval endpoints."""

    def __init__(self, code: str, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status_code = status_code


class SSHHostKeyStorageError(SSHHostKeyFlowError):
    def __init__(self):
        super().__init__(
            "known_hosts_unavailable",
            "The SSH host-key database is temporarily unavailable.",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@dataclass(frozen=True)
class ScannedHostKey:
    host: str
    port: int
    key_type: str
    fingerprint: str
    key: object


def _token_max_age() -> int:
    value = getattr(settings, "SSH_HOST_KEY_APPROVAL_TOKEN_MAX_AGE", DEFAULT_TOKEN_MAX_AGE)
    try:
        return max(1, min(int(value), 24 * 60 * 60))
    except (TypeError, ValueError):
        return DEFAULT_TOKEN_MAX_AGE


def _known_hosts_path() -> str:
    return ssh.known_hosts_path()


def _ssh_trust_gid() -> int:
    raw = os.environ.get("BACKUPSHEEP_SSH_TRUST_GID", "")
    if getattr(settings, "DJANGO_SERVER", "prod") == "prod":
        if raw != str(STOCK_SSH_TRUST_GID):
            raise SSHHostKeyStorageError()
        return STOCK_SSH_TRUST_GID
    if not raw:
        return os.getegid()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise SSHHostKeyStorageError() from None
    if value < 0:
        raise SSHHostKeyStorageError()
    return value


def _open_trust_directory(directory: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(directory, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != _ssh_trust_gid()
            or stat.S_IMODE(metadata.st_mode) != SSH_TRUST_DIRECTORY_MODE
        ):
            raise OSError(errno.EPERM, "unsafe SSH trust directory metadata")
        return descriptor
    except Exception:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
        logger.warning("Unable to validate the SSH host-key directory")
        raise SSHHostKeyStorageError() from None


def _open_known_hosts(directory_fd: int, basename: str) -> int | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(basename, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError:
        raise SSHHostKeyStorageError() from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != _ssh_trust_gid()
            or stat.S_IMODE(metadata.st_mode) != SSH_TRUST_FILE_MODE
        ):
            raise SSHHostKeyStorageError()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _load_known_hosts_descriptor(descriptor: int) -> paramiko.HostKeys:
    """Parse only the inode that passed the no-follow metadata checks."""

    host_keys = paramiko.HostKeys()
    with os.fdopen(os.dup(descriptor), "r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entry = paramiko.hostkeys.HostKeyEntry.from_line(line, line_number)
            except paramiko.SSHException:
                # Match Paramiko's HostKeys.load compatibility behavior for an
                # unsupported line, while still failing on I/O or encoding errors.
                continue
            if entry is None:
                continue
            for hostname in list(entry.hostnames):
                if host_keys.check(hostname, entry.key):
                    entry.hostnames.remove(hostname)
            if entry.hostnames:
                host_keys._entries.append(entry)
    return host_keys


def _validate_endpoint(host, port):
    if not isinstance(host, str):
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH host is required.")
    host = host.strip()
    if not host or len(host) > 255 or any(ord(char) < 32 for char in host):
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH host is required.")
    if isinstance(port, bool):
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH port is required.")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH port is required.")
    if not 1 <= port <= 65535:
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH port is required.")
    return host, port


def _request_payload(payload):
    if not hasattr(payload, "get"):
        raise SSHHostKeyFlowError("invalid_request", "A JSON object is required.")
    return payload


def _fingerprint(key) -> str:
    try:
        digest = hashlib.sha256(key.asbytes()).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    except Exception:
        raise SSHHostKeyFlowError(
            "ssh_handshake_failed", "SSH handshake did not provide a usable host key.", 502
        )


def scan_remote_host_key(host: str, port: int) -> ScannedHostKey:
    try:
        key = ssh.scan_host_key(host, port)
        key_type = key.get_name()
        if not isinstance(key_type, str) or not key_type:
            raise ValueError("missing key type")
        return ScannedHostKey(
            host=host,
            port=port,
            key_type=key_type,
            fingerprint=_fingerprint(key),
            key=key,
        )
    except SSHHostKeyFlowError:
        raise
    except ssh.SSHHostKeyScanError as error:
        raise SSHHostKeyFlowError(error.code, error.detail, error.status_code)
    except Exception:
        logger.warning("SSH host-key scan failed")
        raise SSHHostKeyFlowError(
            "ssh_scan_failed", "Unable to read the SSH host key.", status.HTTP_502_BAD_GATEWAY
        )


def _scan_for_approval(host: str, port: int) -> ScannedHostKey:
    """Keep even unexpected scanner adapters inside the safe error contract."""

    try:
        return scan_remote_host_key(host, port)
    except SSHHostKeyFlowError:
        raise
    except Exception:
        logger.warning("SSH host-key scan adapter failed")
        raise SSHHostKeyFlowError(
            "ssh_scan_failed", "Unable to read the SSH host key.", status.HTTP_502_BAD_GATEWAY
        )


def _host_alias(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def _token_signer() -> signing.TimestampSigner:
    return signing.TimestampSigner(salt=TOKEN_SALT)


def _make_approval_token(request, account, scanned: ScannedHostKey) -> str:
    payload = {
        "version": 1,
        "account_id": str(account.pk),
        "user_id": str(request.user.pk),
        "host": scanned.host,
        "port": scanned.port,
        "key_type": scanned.key_type,
        "fingerprint": scanned.fingerprint,
    }
    return _token_signer().sign_object(payload)


def _current_account(request):
    try:
        account = request.user.member.get_current_account()
    except Exception:
        account = None
    if account is None or account.pk is None:
        raise SSHHostKeyFlowError(
            "account_unavailable",
            "A current BackupSheep account is required.",
            status.HTTP_403_FORBIDDEN,
        )
    return account


def _read_known_hosts(path: str) -> paramiko.HostKeys:
    directory = os.path.dirname(path) or "."
    basename = os.path.basename(path)
    directory_fd = None
    descriptor = None
    try:
        directory_fd = _open_trust_directory(directory)
        descriptor = _open_known_hosts(directory_fd, basename)
        if descriptor is None:
            return paramiko.HostKeys()
        return _load_known_hosts_descriptor(descriptor)
    except SSHHostKeyStorageError:
        raise
    except Exception:
        logger.warning("Unable to read the SSH host-key database")
        raise SSHHostKeyStorageError()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)


def _token_matches(hostname: str, token: str) -> bool:
    if token == hostname:
        return True
    if not token.startswith("|1|"):
        return False
    try:
        return paramiko.HostKeys.hash_host(hostname, token) == token
    except Exception:
        return False


def _matching_entries(host_keys: paramiko.HostKeys, hostname: str):
    entries = []
    for entry in getattr(host_keys, "_entries", ()):
        if any(_token_matches(hostname, token) for token in entry.hostnames):
            entries.append(entry)
    return entries


def _host_key_state(host_keys: paramiko.HostKeys, scanned: ScannedHostKey):
    hostname = _host_alias(scanned.host, scanned.port)
    entries = _matching_entries(host_keys, hostname)
    keys = [entry.key for entry in entries if entry.key is not None]
    same_algorithm = [key for key in keys if key.get_name() == scanned.key_type]
    approved = any(
        hmac.compare_digest(_fingerprint(key), scanned.fingerprint)
        for key in same_algorithm
    )
    if approved:
        return "already_approved", False
    if same_algorithm:
        return "changed", True
    if keys:
        return "changed", False
    return "unknown", False


@contextlib.contextmanager
def _known_hosts_lock(path: str):
    directory = os.path.dirname(path) or "."
    basename = os.path.basename(path)
    lock_basename = f"{basename}.lock"
    directory_fd = None
    descriptor = None
    try:
        directory_fd = _open_trust_directory(directory)
        lock_flags = (
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(
                lock_basename,
                lock_flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
        except FileExistsError:
            # Existing trust metadata is an operator-owned security boundary.
            # Never repair it in a live process: the witnessed provisioner is
            # the only reviewed migration path.
            descriptor = os.open(lock_basename, lock_flags, dir_fd=directory_fd)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != _ssh_trust_gid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise OSError(errno.EPERM, "unsafe SSH trust lock metadata")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except Exception:
        logger.warning("Unable to lock the SSH host-key database")
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if directory_fd is not None:
            os.close(directory_fd)
        raise SSHHostKeyStorageError()
    try:
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
            os.close(directory_fd)


def _remove_same_algorithm_entries(host_keys: paramiko.HostKeys, hostname: str, key_type: str):
    """Remove all matching same-algorithm entries, preserving other aliases."""

    retained = []
    for entry in getattr(host_keys, "_entries", ()):
        if entry.key is None or entry.key.get_name() != key_type:
            retained.append(entry)
            continue
        remaining_hosts = [
            token for token in entry.hostnames if not _token_matches(hostname, token)
        ]
        if remaining_hosts:
            entry.hostnames = remaining_hosts
            retained.append(entry)
    host_keys._entries = retained


def _atomic_save_known_hosts(host_keys: paramiko.HostKeys, path: str) -> None:
    directory = os.path.dirname(path) or "."
    basename = os.path.basename(path)
    directory_fd = None
    descriptor = None
    temporary_path = None
    try:
        directory_fd = _open_trust_directory(directory)
        existing = _open_known_hosts(directory_fd, basename)
        if existing is not None:
            os.close(existing)
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{basename}.", suffix=".tmp", dir=directory
        )
        metadata = os.fstat(descriptor)
        if (
            metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != _ssh_trust_gid()
        ):
            raise OSError(errno.EPERM, "unsafe temporary SSH trust ownership")
        os.fchmod(descriptor, SSH_TRUST_FILE_MODE)
        os.close(descriptor)
        descriptor = None

        host_keys.save(temporary_path)
        descriptor = os.open(
            temporary_path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        os.fchmod(descriptor, SSH_TRUST_FILE_MODE)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != _ssh_trust_gid()
            or stat.S_IMODE(metadata.st_mode) != SSH_TRUST_FILE_MODE
        ):
            raise OSError(errno.EPERM, "unsafe temporary SSH trust metadata")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None

        os.replace(
            os.path.basename(temporary_path),
            basename,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_path = None
        descriptor = _open_known_hosts(directory_fd, basename)
        if descriptor is None:
            raise OSError(errno.ENOENT, "published SSH trust file disappeared")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.fsync(directory_fd)
    except SSHHostKeyStorageError:
        raise
    except Exception:
        logger.warning("Unable to atomically publish the SSH host-key database")
        raise SSHHostKeyStorageError()
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
        if directory_fd is not None:
            os.close(directory_fd)


def preview_host_key(request, payload):
    payload = _request_payload(payload)
    account = _current_account(request)
    host, port = _validate_endpoint(payload.get("host"), payload.get("port"))
    path = _known_hosts_path()
    with _known_hosts_lock(path):
        scanned = _scan_for_approval(host, port)
        host_keys = _read_known_hosts(path)
        state, replace_required = _host_key_state(host_keys, scanned)
    return {
        "host": scanned.host,
        "port": scanned.port,
        "key_type": scanned.key_type,
        "fingerprint": scanned.fingerprint,
        "status": state,
        "approval_token": _make_approval_token(request, account, scanned),
        "replace_required": replace_required,
    }


def _unsign_approval_token(request, account, token):
    if not isinstance(token, str) or not token:
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    try:
        payload = _token_signer().unsign_object(token, max_age=_token_max_age())
    except signing.SignatureExpired:
        raise SSHHostKeyFlowError("approval_expired", "The approval token has expired.")
    except signing.BadSignature:
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    if not isinstance(payload, dict):
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    required = ("version", "account_id", "user_id", "host", "port", "key_type", "fingerprint")
    if any(field not in payload for field in required):
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    if payload.get("version") != 1:
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    if not hmac.compare_digest(str(payload["account_id"]), str(account.pk)):
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is not valid for this account.")
    if not hmac.compare_digest(str(payload["user_id"]), str(request.user.pk)):
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is not valid for this user.")
    try:
        host, port = _validate_endpoint(payload["host"], payload["port"])
    except SSHHostKeyFlowError:
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    if not isinstance(payload["key_type"], str) or not isinstance(payload["fingerprint"], str):
        raise SSHHostKeyFlowError("approval_invalid", "The approval token is invalid.")
    payload["host"] = host
    payload["port"] = port
    return payload


def _requested_fingerprint(payload):
    fingerprint = payload.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint or len(fingerprint) > 128:
        raise SSHHostKeyFlowError("invalid_request", "A valid SSH fingerprint is required.")
    return fingerprint


def approve_host_key(request, payload):
    payload = _request_payload(payload)
    account = _current_account(request)
    approval = _unsign_approval_token(request, account, payload.get("approval_token"))
    requested_fingerprint = _requested_fingerprint(payload)
    if not hmac.compare_digest(requested_fingerprint, str(approval["fingerprint"])):
        raise SSHHostKeyFlowError(
            "approval_invalid", "The fingerprint does not match the approval token."
        )
    replacement = payload.get("replace", False)
    if not isinstance(replacement, bool):
        raise SSHHostKeyFlowError("invalid_request", "The replace flag must be boolean.")

    path = _known_hosts_path()
    with _known_hosts_lock(path):
        # The lock covers the second network read and local-file comparison. This
        # prevents two workers from racing a replacement or publishing duplicates.
        scanned = _scan_for_approval(approval["host"], approval["port"])
        if (
            scanned.key_type != approval["key_type"]
            or not hmac.compare_digest(scanned.fingerprint, str(approval["fingerprint"]))
        ):
            raise SSHHostKeyFlowError(
                "host_key_changed",
                "The SSH host key changed after preview; preview it again.",
                status.HTTP_409_CONFLICT,
            )
        host_keys = _read_known_hosts(path)
        state, replace_required = _host_key_state(host_keys, scanned)
        if state == "changed" and replace_required and not replacement:
            raise SSHHostKeyFlowError(
                "host_key_changed",
                "The approved SSH host key changed; explicit replacement is required.",
                status.HTTP_409_CONFLICT,
            )
        if state != "already_approved":
            hostname = _host_alias(scanned.host, scanned.port)
            if replace_required and replacement:
                _remove_same_algorithm_entries(host_keys, hostname, scanned.key_type)
            host_keys.add(hostname, scanned.key_type, scanned.key)
            _atomic_save_known_hosts(host_keys, path)

    CoreLog.record(
        account,
        CoreLog.Type.CONNECTION,
        {
            "message": f"SSH host key approved for {scanned.host}:{scanned.port}.",
            "action": "ssh_host_key_approve",
            "actor_email": request.user.email,
            "host": scanned.host,
            "port": scanned.port,
            "key_type": scanned.key_type,
            "fingerprint": scanned.fingerprint,
            "replace": replacement,
            "status": state,
        },
    )
    return {
        "detail": "SSH host key approved.",
        "status": "already_approved" if state == "already_approved" else "approved",
        "host": scanned.host,
        "port": scanned.port,
        "key_type": scanned.key_type,
        "fingerprint": scanned.fingerprint,
    }
