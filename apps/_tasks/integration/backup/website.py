"""Website / files backup engine.

One public entry point -- `snapshot_website(backup)` -- which dispatches between:

  * Incremental mirror (node.website.incremental=True): lftp mirrors the remote
    FTP / FTPS / SFTP source into a per-node persistent cache under
    ``_storage/website_cache/{node.uuid}/``. Unchanged files are never
    re-downloaded; ``--delete`` keeps the cache an exact mirror. Every backup zip
    is still a complete standalone snapshot, built from the full cache contents.
    An exclusive flock on ``_storage/website_cache/{node.uuid}.lock`` serializes
    concurrent backups of the same node around the whole mirror+zip, and a
    fingerprint of the backup configuration
    (``_storage/website_cache/{node.uuid}.meta.json``) invalidates the cache when
    the connection, paths or filters change.
  * Full mirror (default): lftp re-downloads every file into a per-backup
    ``_storage/{backup.uuid}/`` working directory, then zips it and discards the
    directory -- the historical behavior.
  * Server-side tar (backup_type FULL_V2 with private/public-key auth): the
    remote server tars the configured paths over SSH, the tar is pulled down via
    SFTP, listed for the file manifest and zipped locally.

Differences from the old SaaS implementation:
  * lftp is the locally-installed binary (the worker image builds it) -- no
    `sudo docker run bs-lftp`, no `sudo docker stop`, no `sudo chown ubuntu`.
  * the lftp command script (credentials included) is fed on STDIN, never on the process
    argv, and is built ONCE by `_build_lftp_script` for every protocol/auth combination
    instead of being copy-pasted eight times.
  * lftp's process exit code is checked after every transfer (`_check_lftp_result`):
    a mirror/get with failed transfers fails the backup loudly with the offending
    file names instead of producing a "successful" partial snapshot.
  * a disk-space preflight (`ensure_disk_space`) runs before any download, sized
    from the node's most recent COMPLETE backup.
  * the per-backup file manifest lives at top-level ``_storage/{uuid}.files``,
    OUTSIDE the zip (it used to bloat every archive by tens of MB on large sites).
  * SFTP uses the system `ssh`, so every key type works (Ed25519/ECDSA/RSA), and
    passphrase-protected keys are normalized to an unencrypted temp key so ssh never
    prompts.

FTPS TLS certificate verification follows the connection's `verify_ssl` flag (default
on); turn it off per-connection for hosts with self-signed/mismatched certs.
"""
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile

import paramiko
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.utils import timezone
from sentry_sdk import capture_exception
from apps._tasks.integration.backup.errors import safe_backup_failure

from apps._tasks.exceptions import NodeBackupFailedError, NodeBackupTimeoutError
from apps._tasks.integration.backup._archive import (
    ArchiveSourcePolicyError,
    create_zip,
)
from apps.api.v1.utils.api_helpers import bs_decrypt, mkdir_p, create_directory_v2, ensure_disk_space
from apps.console.connection.models import CoreAuthWebsite
from apps.console.connection.ssh import managed_private_key_path
from apps._tasks.helper.tasks import delete_from_disk
from apps.console.utils.models import BackupExecutionLeaseLostError, UtilBackup

# Hard cap on a single lftp transfer (12h).
COMMAND_TIMEOUT = 12 * 3600

_LFTP_BASE_SETTINGS = (
    "set net:reconnect-interval-base 5",
    "set net:reconnect-interval-multiplier 1",
    "set net:max-retries 5",
    # Never accept an SSH/SFTP host key automatically.  The worker must have the
    # reviewed key in SSH_KNOWN_HOSTS_PATH (or the system known_hosts file).
    "set sftp:auto-confirm false",
    "set ftp:use-mdtm off",
    "set mirror:set-permissions off",
)
_LFTP_MIRROR_SETTINGS = (
    "set ftp:list-options -a",
    "set ftp:use-mode-z true",
    "set ftp:use-tvfs true",
    "set ftp:prefer-epsv true",
    "set mirror:parallel-directories true",
)

_LFTP_DEPTH_ASSERTION = re.compile(
    r"SMTask\.cc:\d+:.*SMTask::Enter.*SMTASK_MAX_DEPTH",
    re.DOTALL,
)
_LFTP_PARALLEL_OPTION = re.compile(
    r"(?<!\S)--parallel=([1-9][0-9]*)(?=\s|$)"
)


def _lftp_depth_stack_exhausted(proc):
    """Return true only for lftp's internal deep-tree task-stack abort."""
    return bool(
        getattr(proc, "returncode", 0) != 0
        and _LFTP_DEPTH_ASSERTION.search(str(getattr(proc, "stdout", "") or ""))
    )


def _serial_lftp_script(script):
    """Reduce one parallel mirror script to a single traversal worker.

    lftp 4.9.x can abort in ``SMTask::Enter`` on a sufficiently deep tree when
    ``mirror --parallel`` is greater than one. Leave file transfers and already
    serial mirrors unchanged so callers can fence the fallback to that exact
    operation with a changed-script check.
    """
    match = _LFTP_PARALLEL_OPTION.search(script or "")
    if match is None or int(match.group(1)) <= 1:
        return script
    serial = re.sub(
        r"(?m)^set net:connection-limit [1-9][0-9]*$",
        "set net:connection-limit 1",
        script,
    )
    return _LFTP_PARALLEL_OPTION.sub("--parallel=1", serial)


def _lftp_quote(value):
    """Quote a value for use inside an lftp command (double-quoted, backslash-escaped).
    Newlines are stripped so a value can never break onto a new script line."""
    value = (value or "").replace("\r", "").replace("\n", "")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _redact(text, username, password):
    out = text or ""
    if password:
        out = out.replace(password, "******")
    if username:
        out = out.replace(username, "******")
    return out.replace("_storage/", "")


def _check_ssh_command(stdout, stderr, description):
    """Read a remote command result and fail on a non-zero SSH exit status."""
    stdout_data = stdout.read()
    stderr_data = stderr.read()
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        if isinstance(stderr_data, bytes):
            stderr_data = stderr_data.decode("utf-8", "replace")
        detail = (stderr_data or "").strip()
        raise RuntimeError(
            f"Remote {description} failed with exit code {exit_status}"
            + (f": {detail[-1000:]}" if detail else "")
        )
    return stdout_data


# Minimum free-space floor for the preflight check (1 GiB).
_PREFLIGHT_FLOOR = 1 << 30
_PREFLIGHT_INODE_FLOOR = 1024
_WEBSITE_CHECKPOINT_KEY = "_website_mirror_checkpoint"
_WEBSITE_CHECKPOINT_VERSION = 1
_WEBSITE_PROGRESS_BATCH = 10000
_CHECKPOINT_PHASES = {
    "mirror_complete",
    "archive_building",
    "archive_published",
}


def _last_complete_backup(backup, **node_filter):
    return (
        backup.__class__.objects.filter(
            status__in=UtilBackup.SUCCESS_STATUSES,
            **node_filter,
        )
        .order_by("-created")
        .first()
    )


def _last_complete_zip_size(backup, **node_filter):
    """Size in bytes of the node's most recent COMPLETE backup of the same class
    (0 when there is none) -- the basis for the disk-space preflight estimate."""
    last = _last_complete_backup(backup, **node_filter)
    return last.size if last and last.size else 0


def _check_lftp_result(node, backup, proc, username, password, what="lftp"):
    """Fail the backup/restore when lftp had failed transfers.

    Mechanism -- lftp's process exit code, verified empirically against the lftp
    4.9.2 binary in the worker image (throwaway atmoz/sftp server on the compose
    network with chmod-000 files/dirs as failure fixtures):

      * mirror (download AND -R upload), get and put all exit NON-ZERO when any
        transfer failed -- even with the trailing `bye` in the script (`bye`
        preserves the failed command's status), and the error line names the
        file, e.g. ``mirror: Access failed: Permission denied (secret.txt)``;
      * clean transfers exit 0 with zero false positives -- verified for a full
        mirror, an empty remote directory, a no-op incremental re-mirror with
        --delete, and clean get/put;
      * alternatives probed and rejected: ``set cmd:fail yes`` (same exit status
        but aborts the script at the first failed command, which adds nothing
        for a one-transfer script) and ``transfer && echo MARKER`` (works, but
        requires scanning stdout for a marker line).

    Transient per-file errors fail the run on purpose (celery retries; a loud
    failure beats a silent partial backup). The raised error carries the
    redacted output tail so the notification/run log names the failed files --
    users can then fix permissions or add excludes.
    """
    if proc.returncode == 0:
        return
    tail = "\n".join((proc.stdout or "").splitlines()[-10:])
    raise NodeBackupFailedError(
        node,
        backup.uuid_str,
        backup.attempt_no,
        backup.type,
        message=(
            f"{what} reported failed transfers (exit code {proc.returncode}). "
            "Fix the permissions of the files below or add excludes for them "
            f"(full output in the run log):\n{_redact(tail, username, password)}"
        ),
    )


def _normalize_ssh_key(path, passphrase):
    """Rewrite the private key unencrypted (any key type) so the system ssh that lftp
    spawns never prompts for a passphrase. Tries paramiko first; when paramiko can
    parse the key but not re-write it (paramiko's Ed25519Key cannot serialize private
    keys), falls back to the system `ssh-keygen -p` to strip the passphrase in place
    (only when a passphrase was supplied -- without one, ssh would not do better).
    Normalization is staged through a temporary file: some Paramiko versions can
    truncate or corrupt the destination before raising, which would turn a valid
    Ed25519 key into an unusable `error in libcrypto` key for lftp. If everything
    fails, the original key is left in place for ssh to try."""
    os.chmod(path, 0o600)

    # An unencrypted key is already usable by the system ssh. In particular, do
    # not round-trip Ed25519 through Paramiko just to rewrite it: older Paramiko
    # releases may mutate the file before reporting that serialization failed.
    if not passphrase:
        return

    normalized_path = f"{path}.normalized"
    try:
        os.remove(normalized_path)
    except FileNotFoundError:
        pass

    for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            key = key_cls.from_private_key_file(path, password=passphrase)
            key.write_private_key_file(normalized_path)
            os.chmod(normalized_path, 0o600)
            # Do not replace the source until the staged result can be parsed
            # without the passphrase.
            key_cls.from_private_key_file(normalized_path)
            os.replace(normalized_path, path)
            return
        except Exception:
            try:
                os.remove(normalized_path)
            except FileNotFoundError:
                pass

    # Paramiko cannot serialize every key type it can parse (notably Ed25519 in
    # older releases).  Cryptography handles OpenSSH and PEM keys without ever
    # placing the passphrase in process arguments or the environment.
    try:
        with open(path, "rb") as source:
            key_data = source.read()
        private_key = None
        for loader in (
            serialization.load_ssh_private_key,
            serialization.load_pem_private_key,
        ):
            try:
                private_key = loader(key_data, password=passphrase.encode("utf-8"))
                break
            except (TypeError, ValueError):
                continue
        if private_key is None:
            raise ValueError("Private key could not be decrypted.")
        normalized = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        descriptor = os.open(
            normalized_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(normalized)
        os.replace(normalized_path, path)
        os.chmod(path, 0o600)
        return
    except Exception as error:
        try:
            os.remove(normalized_path)
        except FileNotFoundError:
            pass
        raise RuntimeError(
            "The private key could not be decrypted with the supplied passphrase."
        ) from error


def _materialize_ssh_private_key(path, private_key):
    """Write decrypted key material in the format required by system OpenSSH.

    Text fields and serializers commonly remove the final newline from an
    OpenSSH private key. Paramiko accepts that representation, but the system
    ``ssh`` process used by lftp rejects it with ``error in libcrypto``. Keep
    line endings canonical, restore exactly one terminal newline, and create the
    file with owner-only permissions before any external process can observe it.
    """
    material = (private_key or "").replace("\r\n", "\n").replace("\r", "\n")
    if material:
        material = material.rstrip("\n") + "\n"

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as key_file:
            descriptor = None
            key_file.write(material)
            key_file.flush()
            os.fsync(key_file.fileno())
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _build_lftp_script(*, auth, host_url, port, username, password, ssh_key_path,
                       parallel, transfer, mirror):
    """Compose the full lftp command script for one transfer (settings + connect + auth
    + the get/mirror line). Returned as text to feed lftp on stdin."""
    lines = [f"set net:connection-limit {parallel}", *_LFTP_BASE_SETTINGS]

    # FTPS TLS certificate verification, per the connection's verify_ssl flag.
    lines.append(f"set ssl:verify-certificate {'yes' if getattr(auth, 'verify_ssl', True) else 'no'}")

    if auth.protocol == CoreAuthWebsite.Protocol.FTP:
        lines += ["set ftp:ssl-allow false", "set ftp:ssl-protect-data false"]
    else:
        lines += ["set ftp:ssl-allow true", "set ftp:ssl-protect-data true"]
    if auth.protocol == CoreAuthWebsite.Protocol.FTPS and auth.ftps_use_explicit_ssl:
        lines.append("set ftps:initial-prot P")
    if mirror:
        lines += list(_LFTP_MIRROR_SETTINGS)

    if auth.protocol == CoreAuthWebsite.Protocol.SFTP:
        # Every SFTP auth mode must use the same reviewed host-key file as Paramiko
        # validation. Without this, a connection can validate in the web process and
        # then fail (or trust a different key) in lftp on the files worker.
        known_hosts_path = shlex.quote(settings.SSH_KNOWN_HOSTS_PATH)
        connect_parts = [
            f"ssh -a -x -o StrictHostKeyChecking=yes "
            f"-o UserKnownHostsFile={known_hosts_path} "
            f"-o ConnectTimeout={int(getattr(settings, 'SSH_CONNECT_TIMEOUT', 15))} "
            f"-o ServerAliveInterval={int(getattr(settings, 'SSH_KEEPALIVE_SECONDS', 30))} "
            f"-p {int(port)} -l {shlex.quote(username)}"
        ]
        if ssh_key_path:
            connect_parts.append(
                f"-o IdentitiesOnly=yes -i {shlex.quote(ssh_key_path)}"
            )
        connect = " ".join(connect_parts)
        lines.append(f"set sftp:connect-program {_lftp_quote(connect)}")
        lines.append(f"open -p {port} {_lftp_quote(host_url)}")
        if not ssh_key_path:
            lines.append(f"user {_lftp_quote(username)} {_lftp_quote(password)}")
    else:
        lines.append(f"open -p {port} {_lftp_quote(host_url)}")
        lines.append(f"user {_lftp_quote(username)} {_lftp_quote(password)}")

    lines.append(transfer)
    lines.append("bye")
    return "\n".join(lines) + "\n"


def _write_log(backup, text):
    """Append to the backup's shared run log (_storage/{uuid}.log)."""
    with open(f"_storage/{backup.uuid}.log", "a+") as log_file:
        log_file.write(text)


def _cache_paths(node):
    """(mirror dir, meta file, lock file) of a node's persistent incremental cache."""
    base = f"_storage/website_cache/{node.uuid_str}"
    return base + "/", base + ".meta.json", base + ".lock"


def _backup_source_selection(backup, website):
    """Return the source paths frozen on a backup request when available."""
    if backup is not None and (
        backup.all_paths is not None or backup.paths is not None
    ):
        return backup.all_paths, backup.paths
    return website.all_paths, website.paths


def _cache_fingerprint(website, auth, username, *, backup=None):
    """sha256 fingerprint of everything that defines the mirror cache contents; any
    change (host, port, protocol, credentials, paths, include/exclude filters) means
    the cached mirror no longer matches the configuration and must be rebuilt."""
    get_display = getattr(auth, "get_protocol_display", None)
    all_paths, paths = _backup_source_selection(backup, website)
    payload = {
        "version": 1,
        "host": auth.host,
        "port": auth.port,
        "protocol": get_display() if callable(get_display) else getattr(auth, "protocol", None),
        "username": username,
        # A credential edit can change the remote account's visible root even when
        # the username stays the same. Bind checkpoints to the auth-row revision,
        # without persisting or hashing the credential material itself.
        "auth_id": getattr(auth, "pk", None),
        "auth_modified": str(getattr(auth, "modified", "") or ""),
        "all_paths": all_paths,
        "paths": paths,
        "includes_regex": website.includes_regex,
        "includes_glob": website.includes_glob,
        "excludes_regex": website.excludes_regex,
        "excludes_glob": website.excludes_glob,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _existing_parent(path):
    candidate = os.path.abspath(path)
    while not os.path.exists(candidate):
        parent = os.path.dirname(candidate)
        if parent == candidate:
            return os.path.abspath(".")
        candidate = parent
    return candidate


def _ensure_inode_capacity(path, needed_inodes, *, what):
    """Fail before work when the destination cannot hold the required entries."""
    needed_inodes = max(1, int(needed_inodes))
    statvfs = os.statvfs(_existing_parent(path))
    # A zero inode total/free pair means the filesystem does not report inode
    # capacity. Byte preflight still applies; do not manufacture a false failure.
    if statvfs.f_files and statvfs.f_favail < needed_inodes:
        raise RuntimeError(
            f"Not enough free inodes for {what}: need ~{needed_inodes}, "
            f"have ~{statvfs.f_favail} free"
        )


def _preflight_website_capacity(backup, local_dir, *, incremental):
    """Estimate mirror bytes/inodes from the latest successful same-node run."""
    last = _last_complete_backup(backup, website__node=backup.website.node)
    multiplier = 1.2 if incremental else 2
    last_size = int(last.size or 0) if last else 0
    needed_bytes = int(max(multiplier * last_size, _PREFLIGHT_FLOOR))
    last_entries = 0
    if last:
        last_entries = int(last.total_files or 0) + int(last.total_folders or 0)
    needed_inodes = max(last_entries + 16, _PREFLIGHT_INODE_FLOOR)
    capacity_path = _existing_parent(local_dir)
    ensure_disk_space(needed_bytes, path=capacity_path, what="website backup")
    _ensure_inode_capacity(
        capacity_path,
        needed_inodes,
        what="website backup",
    )


def _archive_capacity_bytes(identity):
    # The mirror already occupies disk. Reserve a conservative uncompressed ZIP
    # body plus local/central headers and the path bytes used by those records.
    entries = int(identity["file_count"]) + int(identity["directory_count"])
    overhead = entries * 256 + int(identity["path_bytes"]) * 3
    return max(_PREFLIGHT_FLOOR, int(identity["logical_bytes"]) + overhead)


def _report_website_progress(backup, stage, completed=0, total=None):
    callback = getattr(backup, "_execution_progress_callback", None)
    if not callable(callback):
        return
    floor = max(
        int(getattr(backup, "_execution_progress_floor", 0) or 0),
        int(completed or 0),
    )
    safe_total = None if total is None else int(total)
    if safe_total is not None and safe_total < floor:
        safe_total = None
    callback(
        floor,
        safe_total,
        unit="files",
        metadata_updates={"public_stage": stage},
    )
    backup._execution_progress_floor = floor


def _workspace_identity(backup, local_dir):
    value = f"{backup.pk}\0{backup.uuid_str}\0{os.path.realpath(local_dir)}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _checkpoint_identity(identity):
    return {
        key: identity[key]
        for key in (
            "file_count",
            "directory_count",
            "logical_bytes",
            "path_bytes",
            "tree_sha256",
            "manifest_sha256",
            "members_sha256",
        )
    }


def _valid_checkpoint_identity(identity):
    if not isinstance(identity, dict):
        return False
    for key in ("file_count", "directory_count", "logical_bytes", "path_bytes"):
        try:
            if int(identity.get(key)) < 0:
                return False
        except (TypeError, ValueError):
            return False
    for key in ("tree_sha256", "manifest_sha256", "members_sha256"):
        value = str(identity.get(key) or "")
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            return False
    return True


def _website_checkpoint(backup):
    metadata = backup.metadata if isinstance(backup.metadata, dict) else {}
    checkpoint = metadata.get(_WEBSITE_CHECKPOINT_KEY)
    return dict(checkpoint) if isinstance(checkpoint, dict) else {}


def _website_local_dir(backup):
    if backup.website.incremental:
        return _cache_paths(backup.website.node)[0]
    return f"_storage/{backup.uuid_str}/"


def website_mirror_checkpoint_candidate(backup):
    """Whether a retry must preserve the workspace for fenced revalidation."""
    checkpoint = _website_checkpoint(backup)
    local_dir = _website_local_dir(backup)
    return bool(
        checkpoint.get("version") == _WEBSITE_CHECKPOINT_VERSION
        and checkpoint.get("backup_uuid") == backup.uuid_str
        and checkpoint.get("phase") in _CHECKPOINT_PHASES
        and checkpoint.get("workspace_sha256")
        == _workspace_identity(backup, local_dir)
        and _valid_checkpoint_identity(checkpoint.get("identity"))
        and os.path.isdir(local_dir)
    )


def _persist_mirror_checkpoint(
    backup,
    local_dir,
    configuration_sha256,
    identity,
    *,
    phase,
):
    execution = backup.ensure_execution_fence()
    if execution is None:
        execution = backup.get_execution_state(create=False)
    metadata = dict(backup.metadata or {})
    metadata[_WEBSITE_CHECKPOINT_KEY] = {
        "version": _WEBSITE_CHECKPOINT_VERSION,
        "phase": phase,
        "backup_uuid": backup.uuid_str,
        "workspace_sha256": _workspace_identity(backup, local_dir),
        "configuration_sha256": configuration_sha256,
        "execution_correlation_id": (
            str(execution.correlation_id) if execution is not None else ""
        ),
        "identity": _checkpoint_identity(identity),
        "updated_at": timezone.now().isoformat(),
    }
    backup.metadata = metadata
    backup.save(update_fields=["metadata", "modified"])


def _enumerate_website_mirror(backup, local_dir):
    """Write bounded manifests and return a stable identity for the mirror."""
    source_root = os.path.abspath(local_dir)
    root_mode = os.lstat(source_root).st_mode
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise ArchiveSourcePolicyError("source_root")

    manifest_path = f"_storage/{backup.uuid}.files"
    members_path = f"_storage/{backup.uuid}.members"
    parent = os.path.dirname(manifest_path) or "."
    os.makedirs(parent, exist_ok=True)
    manifest_fd, staged_manifest = tempfile.mkstemp(
        prefix=f".{backup.uuid}.files.",
        suffix=".partial",
        dir=parent,
        text=True,
    )
    try:
        members_fd, staged_members = tempfile.mkstemp(
            prefix=f".{backup.uuid}.members.",
            suffix=".partial",
            dir=parent,
            text=True,
        )
    except Exception:
        os.close(manifest_fd)
        os.remove(staged_manifest)
        raise

    tree_digest = hashlib.sha256()
    manifest_digest = hashlib.sha256()
    members_digest = hashlib.sha256()
    file_count = directory_count = logical_bytes = path_bytes = 0

    def raise_walk_error(error):
        raise error

    def inspect_member(root, name, *, expected_directory):
        path = os.path.join(root, name)
        relative = os.path.relpath(path, source_root).replace(os.sep, "/")
        if any(character in relative for character in ("\x00", "\r", "\n", "\\")):
            raise ArchiveSourcePolicyError("invalid_path", relative_path=relative)
        observed = os.lstat(path)
        if stat.S_ISLNK(observed.st_mode):
            raise ArchiveSourcePolicyError("symlink", relative_path=relative)
        if expected_directory:
            if not stat.S_ISDIR(observed.st_mode):
                raise ArchiveSourcePolicyError("special", relative_path=relative)
        elif not stat.S_ISREG(observed.st_mode):
            raise ArchiveSourcePolicyError("special", relative_path=relative)
        return relative, observed

    published = False
    _report_website_progress(backup, "website_enumerating", 0, None)
    try:
        with os.fdopen(
            manifest_fd, "w", encoding="utf-8", newline="\n"
        ) as manifest, os.fdopen(
            members_fd, "w", encoding="utf-8", newline="\n"
        ) as members:
            for root, dirs, files in os.walk(
                source_root,
                topdown=True,
                onerror=raise_walk_error,
                followlinks=False,
            ):
                dirs.sort()
                files.sort()
                for name in dirs:
                    relative, observed = inspect_member(
                        root, name, expected_directory=True
                    )
                    line = (relative + "/\n").encode("utf-8")
                    members.write(line.decode("utf-8"))
                    members_digest.update(line)
                    tree_digest.update(
                        f"D\0{relative}\0{observed.st_mode}\0{observed.st_mtime_ns}\n".encode(
                            "utf-8"
                        )
                    )
                    directory_count += 1
                    path_bytes += len(relative.encode("utf-8")) + 1
                for name in files:
                    relative, observed = inspect_member(
                        root, name, expected_directory=False
                    )
                    line = (relative + "\n").encode("utf-8")
                    text_line = line.decode("utf-8")
                    manifest.write(text_line)
                    members.write(text_line)
                    manifest_digest.update(line)
                    members_digest.update(line)
                    tree_digest.update(
                        f"F\0{relative}\0{observed.st_mode}\0{observed.st_size}\0{observed.st_mtime_ns}\n".encode(
                            "utf-8"
                        )
                    )
                    file_count += 1
                    logical_bytes += observed.st_size
                    path_bytes += len(relative.encode("utf-8"))
                    if file_count % _WEBSITE_PROGRESS_BATCH == 0:
                        _report_website_progress(
                            backup,
                            "website_enumerating",
                            file_count,
                            None,
                        )
            manifest.flush()
            os.fsync(manifest.fileno())
            members.flush()
            os.fsync(members.fileno())

        identity = {
            "file_count": file_count,
            "directory_count": directory_count,
            "logical_bytes": logical_bytes,
            "path_bytes": path_bytes,
            "tree_sha256": tree_digest.hexdigest(),
            "manifest_sha256": manifest_digest.hexdigest(),
            "members_sha256": members_digest.hexdigest(),
        }
        ensure_disk_space(
            _archive_capacity_bytes(identity),
            path=_existing_parent(parent),
            what="website archive",
        )
        _ensure_inode_capacity(parent, 8, what="website archive")
        backup.ensure_execution_fence()
        os.replace(staged_manifest, manifest_path)
        os.replace(staged_members, members_path)
        published = True
        _report_website_progress(
            backup,
            "website_enumerating",
            file_count,
            file_count,
        )
        return {
            "identity": identity,
            "manifest_path": manifest_path,
            "members_path": members_path,
        }
    finally:
        for path in (staged_manifest, staged_members):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        if not published:
            # Previously published checkpoint manifests, if any, remain untouched.
            pass


def _checkpoint_matches_current_execution(
    backup,
    local_dir,
    configuration_sha256,
    enumeration,
):
    checkpoint = _website_checkpoint(backup)
    execution = backup.ensure_execution_fence()
    if execution is None:
        execution = backup.get_execution_state(create=False)
    expected_correlation = str(execution.correlation_id) if execution else ""
    return bool(
        checkpoint.get("version") == _WEBSITE_CHECKPOINT_VERSION
        and checkpoint.get("backup_uuid") == backup.uuid_str
        and checkpoint.get("phase") in _CHECKPOINT_PHASES
        and checkpoint.get("workspace_sha256")
        == _workspace_identity(backup, local_dir)
        and checkpoint.get("configuration_sha256") == configuration_sha256
        and checkpoint.get("execution_correlation_id", "") == expected_correlation
        and checkpoint.get("identity")
        == _checkpoint_identity(enumeration["identity"])
    )


def _remove_exact_staged_archives(backup):
    parent = os.path.abspath("_storage")
    prefix = f".{backup.uuid}.zip."
    suffix = ".partial.zip"
    try:
        with os.scandir(parent) as entries:
            for entry in entries:
                if (
                    entry.name.startswith(prefix)
                    and entry.name.endswith(suffix)
                    and entry.is_file(follow_symlinks=False)
                ):
                    os.remove(entry.path)
    except FileNotFoundError:
        pass


def _finalize_zip(
    backup,
    local_dir,
    *,
    keep_dir,
    configuration_sha256=None,
    enumeration=None,
):
    """Checkpoint one verified mirror, then atomically build its standalone ZIP."""
    local_zip = f"_storage/{backup.uuid}.zip"
    if configuration_sha256 is None:
        configuration_sha256 = _cache_fingerprint(
            backup.website,
            backup.website.node.connection.auth_website,
            "",
            backup=backup,
        )
    enumeration = enumeration or _enumerate_website_mirror(backup, local_dir)
    identity = enumeration["identity"]

    _persist_mirror_checkpoint(
        backup,
        local_dir,
        configuration_sha256,
        identity,
        phase="mirror_complete",
    )
    backup.total_files = identity["file_count"]
    backup.total_folders = identity["directory_count"]
    backup.raw_size = identity["logical_bytes"]
    backup.save(
        update_fields=["total_files", "total_folders", "raw_size", "modified"]
    )

    _report_website_progress(
        backup,
        "website_archiving",
        identity["file_count"],
        identity["file_count"],
    )
    backup.ensure_execution_fence()
    _remove_exact_staged_archives(backup)
    _persist_mirror_checkpoint(
        backup,
        local_dir,
        configuration_sha256,
        identity,
        phase="archive_building",
    )
    create_zip(
        local_dir,
        local_zip,
        timeout=COMMAND_TIMEOUT,
        before_publish=backup.ensure_execution_fence,
        member_list_path=enumeration["members_path"],
        expected_member_count=(
            int(identity["file_count"]) + int(identity["directory_count"])
        ),
        expected_member_list_sha256=identity["members_sha256"],
        expected_source_bytes=identity["logical_bytes"],
        during_write=backup.ensure_execution_fence,
    )
    _report_website_progress(
        backup,
        "website_archive_publishing",
        identity["file_count"],
        identity["file_count"],
    )
    _persist_mirror_checkpoint(
        backup,
        local_dir,
        configuration_sha256,
        identity,
        phase="archive_published",
    )
    backup.size = os.stat(local_zip).st_size
    backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
    backup.save(update_fields=["size", "status", "modified"])
    try:
        os.remove(enumeration["members_path"])
    except FileNotFoundError:
        pass
    _write_log(backup, f"Size (compressed): {backup.size_display()}\n")

    if not keep_dir:
        # The working directory is no longer needed; the zip is what gets uploaded.
        delete_from_disk.apply_async(args=[backup.uuid_str, "dir"])


def snapshot_website(backup):
    node = backup.website.node
    auth = node.connection.auth_website

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    log_file_path = f"_storage/{backup.uuid}.log"
    with open(log_file_path, "a+") as log_file:
        log_file.write(f"Node: {node.name}\n")
        log_file.write(f"UUID: {backup.uuid}\n")
        log_file.write(f"Time: {backup.created}\n")
        log_file.write(f"Attempt Number: {backup.attempt_no}\n")

    if node.website.incremental:
        _snapshot_lftp(backup, base_dir=_cache_paths(node)[0], incremental=True)
    elif node.website.backup_type == node.website.BackupType.FULL_V2 and (
            auth.use_private_key or auth.use_public_key
    ):
        _snapshot_tar(backup)
    else:
        _snapshot_lftp(backup, base_dir=f"_storage/{backup.uuid}/", incremental=False)


def _snapshot_lftp(backup, *, base_dir, incremental):
    """Mirror the remote source with lftp and zip the result.

    incremental=False: full re-download into a per-backup working directory which is
    discarded after zipping (historical behavior). incremental=True: base_dir is the
    node's persistent mirror cache; unchanged files are not re-downloaded, the cache
    is kept, and the whole mirror+zip runs under the node's flock."""
    node = backup.website.node
    auth = node.connection.auth_website
    website = node.website
    encryption_key = node.connection.account.get_encryption_key()

    local_dir = base_dir

    username = bs_decrypt(auth.username, encryption_key) or ""
    password = bs_decrypt(auth.password, encryption_key) or ""
    ssh_key_path = None
    temporary_ssh_key = False
    lock_file = None

    try:
        protocol = auth.get_protocol_display().lower()  # ftp / sftp / ftps
        if auth.protocol == CoreAuthWebsite.Protocol.FTPS and auth.ftps_use_explicit_ssl:
            protocol = "ftp"  # explicit FTPS connects as ftp:// then upgrades
        host_url = f"{protocol}://{auth.host}"

        parallel = website.parallel or 3
        verbose = "--verbose=3" if website.verbose else ""

        exclude_rules = ["--exclude-glob=*.sock"]
        for rx in (website.excludes_regex or []):
            exclude_rules.append(f"--exclude={_lftp_quote(rx)}")
        for gl in (website.excludes_glob or []):
            exclude_rules.append(f"--exclude-glob={_lftp_quote(gl)}")
        include_rules = []
        for rx in (website.includes_regex or []):
            include_rules.append(f"--include={_lftp_quote(rx)}")
        for gl in (website.includes_glob or []):
            include_rules.append(f"--include-glob={_lftp_quote(gl)}")

        if incremental:
            # Today's options minus --ignore-time/--ignore-size (so unchanged files
            # are skipped) plus --delete (so the cache stays an exact mirror).
            mirror_opts = (
                f"--continue --recursion=always --no-perms --no-umask --delete "
                f"--use-pget=1 --parallel={parallel} {verbose}"
            )
        else:
            mirror_opts = (
                f"--continue --recursion=always --ignore-time --no-perms --no-umask "
                f"--ignore-size --use-pget=1 --parallel={parallel} {verbose}"
            )

        all_paths, configured_paths = _backup_source_selection(backup, website)
        if all_paths:
            sources = [{"path": ".", "type": "directory"}]
        else:
            sources = [
                {"path": p["path"], "type": p["type"]}
                for p in (configured_paths or [])
            ]
        fingerprint = _cache_fingerprint(
            website, auth, username, backup=backup
        )

        _write_log(backup, f"Parallel: {parallel}\nIncludes: {' '.join(include_rules)}\n"
                           f"Excludes: {' '.join(exclude_rules)}\n")

        if incremental:
            cache_dir, meta_path, lock_path = _cache_paths(node)
            os.makedirs(os.path.dirname(meta_path), exist_ok=True)
            lock_file = open(lock_path, "a+")
            # Serialize concurrent backups of this node around the whole mirror+zip.
            fcntl.flock(lock_file, fcntl.LOCK_EX)

        try:
            checkpoint_candidate = website_mirror_checkpoint_candidate(backup)
            if checkpoint_candidate:
                enumeration = _enumerate_website_mirror(backup, local_dir)
                if _checkpoint_matches_current_execution(
                    backup,
                    local_dir,
                    fingerprint,
                    enumeration,
                ):
                    _write_log(
                        backup,
                        "Verified mirror checkpoint; retrying archive without "
                        "another source transfer.\n",
                    )
                    _finalize_zip(
                        backup,
                        local_dir,
                        keep_dir=incremental,
                        configuration_sha256=fingerprint,
                        enumeration=enumeration,
                    )
                    if incremental:
                        with open(meta_path, "w") as fh:
                            json.dump({"fingerprint": fingerprint}, fh)
                    return
                _write_log(
                    backup,
                    "Mirror checkpoint no longer matches the workspace; "
                    "rebuilding the exact source mirror.\n",
                )
                if not incremental:
                    shutil.rmtree(local_dir, ignore_errors=True)

            # These checks and key materialization can touch the source. Keep them
            # after exact checkpoint revalidation so an archive-only retry remains
            # independent of source availability. Byte and inode preflight still
            # runs before any fresh transfer; _finalize_zip performs the separate
            # exact archive-capacity check for a reused mirror.
            _preflight_website_capacity(
                backup,
                local_dir,
                incremental=incremental,
            )
            auth.check_connection()

            if auth.use_public_key:
                ssh_key_path = managed_private_key_path()
            elif auth.use_private_key:
                # lftp starts the system ssh from its own process context. Use an
                # absolute path so a relative `_storage/...` key cannot resolve
                # against an unexpected working directory and fail authentication.
                ssh_key_path = os.path.abspath(f"_storage/ssh_{backup.uuid}")
                _materialize_ssh_private_key(
                    ssh_key_path,
                    bs_decrypt(auth.private_key, encryption_key),
                )
                _normalize_ssh_key(ssh_key_path, password)
                temporary_ssh_key = True

            if incremental:
                stored_fingerprint = None
                if os.path.exists(meta_path):
                    try:
                        with open(meta_path) as fh:
                            stored_fingerprint = json.load(fh).get("fingerprint")
                    except (ValueError, OSError, AttributeError):
                        stored_fingerprint = None
                if stored_fingerprint != fingerprint:
                    # Missing/stale fingerprint: the cache cannot be trusted.
                    shutil.rmtree(local_dir, ignore_errors=True)
                    os.makedirs(local_dir, exist_ok=True)
                    _write_log(backup, "Backup configuration changed; initializing snapshot cache.\n")
                    if stored_fingerprint is None:
                        _write_log(backup, "First incremental backup: all files will be "
                                           "downloaded; later backups only fetch changes.\n")
                os.makedirs(local_dir, exist_ok=True)
            else:
                # A verified website snapshot must contain only source members.
                # The historical placeholder would make a 2,000,000-file source
                # publish 2,000,001 members and breaks exact restore semantics.
                mkdir_p(local_dir, add_bs_file=False)

            _report_website_progress(backup, "website_mirroring", 0, None)
            for source in sources:
                target = local_dir if source["path"] == "." else (local_dir + source["path"]).replace("//", "/")
                create_directory_v2(target)

                if source["type"] == "file":
                    # NB: `-P` is a BOOLEAN flag for get/put in lftp 4.9.2 (pget with
                    # net:connection-limit connections). `-P 3` makes lftp fetch an
                    # extra file literally named "3" and exit non-zero (verified).
                    transfer = f'get -P {_lftp_quote(source["path"])} -o {_lftp_quote(target)}'
                    mirror = False
                else:
                    transfer = (
                        f'mirror {mirror_opts} {" ".join(include_rules)} {" ".join(exclude_rules)} '
                        f'{_lftp_quote(source["path"])} {_lftp_quote(target)}'
                    )
                    mirror = True

                script = _build_lftp_script(
                    auth=auth, host_url=host_url, port=auth.port, username=username,
                    password=password, ssh_key_path=ssh_key_path, parallel=parallel,
                    transfer=transfer, mirror=mirror,
                )
                _write_log(backup, f"\nPath: {source['path']} -> {target}\n")
                _write_log(backup, _redact(script, username, password) + "\n")

                def run_lftp(current_script):
                    try:
                        return subprocess.run(
                            ["lftp"], input=current_script,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=COMMAND_TIMEOUT, text=True, errors="ignore",
                        )
                    except FileNotFoundError:
                        raise NodeBackupFailedError(
                            node, backup.uuid_str, backup.attempt_no, backup.type,
                            "lftp is not installed in the worker image.",
                        )

                def record_lftp_output(current_proc):
                    for line in (current_proc.stdout or "").splitlines():
                        _write_log(
                            backup,
                            "LFTP: " + _redact(line, username, password) + "\n",
                        )
                        low = line.lower()
                        if (
                            "421 too many connections" in low
                            and (website.parallel or 0) > 1
                        ):
                            website.parallel = max(1, (website.parallel or 2) // 2)
                            website.save()
                        if (
                            "login failed" in low
                            or "login incorrect" in low
                            or ("fatal error" in low and "too many" in low)
                        ):
                            raise NodeBackupFailedError(
                                node,
                                backup.uuid_str,
                                backup.attempt_no,
                                backup.type,
                                message=_redact(line, username, password),
                            )

                proc = run_lftp(script)
                record_lftp_output(proc)
                if _lftp_depth_stack_exhausted(proc):
                    serial_script = _serial_lftp_script(script)
                    if serial_script != script:
                        _write_log(
                            backup,
                            "LFTP deep-tree limit reached; retrying this path with "
                            "serial directory traversal.\n",
                        )
                        proc = run_lftp(serial_script)
                        record_lftp_output(proc)

                # A mirror with failed transfers must not produce a "successful"
                # (partial) backup: lftp's exit code reports them (see the helper
                # for the verified mechanism).
                _check_lftp_result(node, backup, proc, username, password)

            _finalize_zip(
                backup,
                local_dir,
                keep_dir=incremental,
                configuration_sha256=fingerprint,
            )

            if incremental:
                # Only stamp the cache after a successful mirror+zip, so a failed run
                # never marks a partial cache as current.
                with open(meta_path, "w") as fh:
                    json.dump({"fingerprint": fingerprint}, fh)
        finally:
            if lock_file is not None:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
                lock_file.close()

    except NodeBackupFailedError:
        cleanup_kind = (
            "zip" if website_mirror_checkpoint_candidate(backup) else "both"
        )
        delete_from_disk.apply_async(args=[backup.uuid_str, cleanup_kind])
        raise
    except BackupExecutionLeaseLostError:
        # A replacement worker owns the canonical workspace/archive now. A stale
        # worker must not schedule broad cleanup that could delete its successor's
        # committed files.
        raise
    except Exception as e:
        capture_exception(e)
        failure = safe_backup_failure(e, stage="website_backup")
        _write_log(backup, f"Error [{failure.code}]: {failure.detail}\n")
        cleanup_kind = (
            "zip" if website_mirror_checkpoint_candidate(backup) else "both"
        )
        delete_from_disk.apply_async(args=[backup.uuid_str, cleanup_kind])
        if failure.code == "BACKUP_TIMEOUT":
            raise NodeBackupTimeoutError(node, backup.uuid_str, backup.attempt_no, backup.type)
        raise NodeBackupFailedError(
            node,
            backup.uuid_str,
            backup.attempt_no,
            backup.type,
            failure.detail,
            public_failure=failure,
        )
    finally:
        if temporary_ssh_key and ssh_key_path and os.path.exists(ssh_key_path):
            os.remove(ssh_key_path)


def _snapshot_tar(backup):
    """Server-side tar transport: the remote server tars the configured paths over
    SSH, the tar is downloaded via SFTP, listed for the file manifest and zipped
    locally (the zip wraps the tar)."""
    node = backup.website.node
    auth_website = node.connection.auth_website

    local_zip = f"_storage/{backup.uuid}.zip"
    local_dir = f"_storage/{backup.uuid}/"
    mkdir_p(local_dir)

    # backup files log
    backup_file_list_path = f"{local_dir}{backup.uuid}.files"

    # 24 hours
    command_timeout = 24 * 3600

    ssh_key_path = None
    sftp = None
    ssh = None

    try:
        # Disk-space preflight before the tar is pulled down (~2x the last
        # snapshot: downloaded tar plus the final zip).
        ensure_disk_space(
            int(max(2 * _last_complete_zip_size(backup, website__node=node),
                    _PREFLIGHT_FLOOR)),
            what="website backup",
        )

        all_paths, configured_paths = _backup_source_selection(
            backup, node.website
        )
        sources = ["."] if all_paths else [
            path["path"] for path in (configured_paths or [])
        ]

        # Exclude flags for the remote tar --create command. tar_temp_backup_dir and
        # the backup paths are user-controlled: every value interpolated into a remote
        # shell command MUST be shlex-quoted. The previous naive double-quote
        # wrapping ('"{0}"') allowed metacharacters (", $, `, ;) to break out and
        # execute arbitrary commands on the target server as the SSH user.
        exclude_flags = [f"--exclude={shlex.quote('*.sock')}"]
        if node.website.tar_exclude_vcs_ignores:
            exclude_flags.append("--exclude-vcs-ignores")
        if node.website.tar_exclude_vcs:
            exclude_flags.append("--exclude-vcs")
        if node.website.tar_exclude_backups:
            exclude_flags.append("--exclude-backups")
        if node.website.tar_exclude_caches:
            exclude_flags.append("--exclude-caches")
        for glob in (node.website.excludes_glob or []):
            exclude_flags.append(f"--exclude={shlex.quote(glob)}")
        exclude_rules = " ".join(exclude_flags)

        """
        Checking for connection
        """
        auth_website.check_connection()

        sftp, ssh, ssh_key_path = auth_website.get_sftp_client()

        # BackupSheep directory path on user server.
        bs_backup_directory = f"{node.website.tar_temp_backup_dir}/{node.uuid_str}"
        bs_backup_tar = f"{bs_backup_directory}/{backup.uuid_str}.tar"
        bs_backup_sources = " ".join(shlex.quote(x) for x in sources)

        # Create backup directory
        _stdin, _stdout, _stderr = ssh.exec_command(f"mkdir -p {shlex.quote(bs_backup_directory)}")
        _check_ssh_command(_stdout, _stderr, "backup directory creation")

        # Remove any existing backup tar
        _stdin, _stdout, _stderr = ssh.exec_command(f"rm -rf {shlex.quote(bs_backup_tar)}")
        _check_ssh_command(_stdout, _stderr, "old archive cleanup")

        command = (
            f"tar --create --no-check-device {exclude_rules} "
            f"--file={shlex.quote(bs_backup_tar)} {bs_backup_sources}"
        )
        _stdin, _stdout, _stderr = ssh.exec_command(command, timeout=command_timeout)
        _check_ssh_command(_stdout, _stderr, "remote tar creation")

        # Download Backup file
        sftp.get(bs_backup_tar, f"{local_dir}{backup.uuid}.tar")

        # Cleanup files from remote server.
        sftp.remove(bs_backup_tar)

        """
        Get list of files in tar.
        """
        backup.total_files = 0

        execstr = ["tar", "-list", "--file", f"{backup.uuid}.tar"]
        process = subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=command_timeout,
            cwd=local_dir,
            universal_newlines=True,
        )
        if process.returncode != 0:
            raise RuntimeError(
                f"Downloaded tar failed validation with exit code {process.returncode}: "
                f"{(process.stderr or '').strip()[-1000:]}"
            )
        with open(backup_file_list_path, "a+") as backup_file_list:
            for line in process.stdout.splitlines():
                backup_file_list.write(f"{line}\n")
                if not line.endswith("/"):
                    backup.total_files += 1
        backup.save()

        """
        Create final backup zip folder
        """
        create_zip(
            local_dir,
            local_zip,
            timeout=command_timeout,
            before_publish=backup.ensure_execution_fence,
        )
        backup.size = os.stat(local_zip).st_size
        backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
        backup.save()
        _write_log(backup, f"Size (compressed): {backup.size_display()}\n")

        """
        Delete directory because no need for it now that we have zip
        """
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "dir"],
        )

    except BackupExecutionLeaseLostError:
        raise
    except Exception as e:
        capture_exception(e)
        failure = safe_backup_failure(e, stage="website_backup")
        _write_log(backup, f"Error [{failure.code}]: {failure.detail}\n")

        """
        Delete files
        """
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "both"],
        )

        if failure.code == "BACKUP_TIMEOUT":
            raise NodeBackupTimeoutError(node, backup.uuid_str, backup.attempt_no, backup.type)
        else:
            raise NodeBackupFailedError(
                node,
                backup.uuid_str,
                backup.attempt_no,
                backup.type,
                failure.detail,
                public_failure=failure,
            )
    finally:
        """
        Delete temp SSH Key
        """
        if ssh_key_path and os.path.exists(ssh_key_path):
            os.remove(ssh_key_path)
        for client in (sftp, ssh):
            try:
                if client:
                    client.close()
            except Exception:
                pass
