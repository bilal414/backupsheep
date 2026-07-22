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
import shlex
import shutil
import subprocess

import paramiko
from sentry_sdk import capture_exception

from apps._tasks.exceptions import NodeBackupFailedError, NodeBackupTimeoutError
from apps.api.v1.utils.api_helpers import bs_decrypt, mkdir_p, create_directory_v2, ensure_disk_space
from apps.console.connection.models import CoreAuthWebsite
from apps._tasks.helper.tasks import delete_from_disk
from apps.console.utils.models import UtilBackup

# Hard cap on a single lftp transfer (12h).
COMMAND_TIMEOUT = 12 * 3600

_LFTP_BASE_SETTINGS = (
    "set net:reconnect-interval-base 5",
    "set net:reconnect-interval-multiplier 1",
    "set net:max-retries 5",
    "set sftp:auto-confirm true",
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


# Minimum free-space floor for the preflight check (1 GiB).
_PREFLIGHT_FLOOR = 1 << 30


def _last_complete_zip_size(backup, **node_filter):
    """Size in bytes of the node's most recent COMPLETE backup of the same class
    (0 when there is none) -- the basis for the disk-space preflight estimate."""
    last = (
        backup.__class__.objects.filter(status=UtilBackup.Status.COMPLETE, **node_filter)
        .order_by("-created")
        .first()
    )
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
    If everything fails, the original key is left in place for ssh to try."""
    for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            key = key_cls.from_private_key_file(path, password=passphrase or None)
            key.write_private_key_file(path)
            os.chmod(path, 0o600)
            return
        except Exception:
            continue
    if passphrase:
        # The passphrase travels only on the argv of this local subprocess and is
        # never logged; stdin is closed so ssh-keygen can never prompt.
        try:
            proc = subprocess.run(
                ["ssh-keygen", "-p", "-P", passphrase, "-N", "", "-f", path],
                input="", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=60, text=True,
            )
            if proc.returncode == 0:
                os.chmod(path, 0o600)
        except Exception:
            pass


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

    if ssh_key_path:
        # SFTP via the system ssh -> supports every key type. lftp runs the
        # connect-program through a shell, so shell-quote the username/key path (then
        # lftp-quote the whole value) to keep an exotic username from injecting.
        connect = f"ssh -a -x -p {port} -l {shlex.quote(username)} -i {shlex.quote(ssh_key_path)}"
        lines.append(f"set sftp:connect-program {_lftp_quote(connect)}")
        lines.append(f"open -p {port} {host_url}")
    else:
        lines.append(f"open -p {port} {host_url}")
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


def _cache_fingerprint(website, auth, username):
    """sha256 fingerprint of everything that defines the mirror cache contents; any
    change (host, port, protocol, credentials, paths, include/exclude filters) means
    the cached mirror no longer matches the configuration and must be rebuilt."""
    get_display = getattr(auth, "get_protocol_display", None)
    payload = {
        "version": 1,
        "host": auth.host,
        "port": auth.port,
        "protocol": get_display() if callable(get_display) else getattr(auth, "protocol", None),
        "username": username,
        "all_paths": website.all_paths,
        "paths": website.paths,
        "includes_regex": website.includes_regex,
        "includes_glob": website.includes_glob,
        "excludes_regex": website.excludes_regex,
        "excludes_glob": website.excludes_glob,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _finalize_zip(backup, local_dir, *, keep_dir):
    """Build the standalone snapshot zip from a downloaded tree.

    Writes the file manifest to TOP-LEVEL ``_storage/{backup.uuid}.files`` (NOT
    inside the tree): on a million-file site a ~50-100MB manifest would
    otherwise bloat every backup zip. The zip therefore contains pure site
    content; the manifest sits next to the run log, where `delete_old_logs`
    prunes it after the retention window. Records backup.total_files, zips the
    tree to ``_storage/{backup.uuid}.zip`` and marks the backup
    DOWNLOAD_COMPLETE. With keep_dir (incremental cache) the tree is left in
    place for the next run; otherwise the working directory is discarded once
    the zip exists."""
    local_zip = f"_storage/{backup.uuid}.zip"
    backup_file_list_path = f"_storage/{backup.uuid}.files"

    # File list + count (Python walk; no `sudo find` / md5sum). The manifest is
    # outside local_dir, so the walk never sees it.
    backup.total_files = 0
    with open(backup_file_list_path, "w") as flist:
        for root, _dirs, files in os.walk(local_dir):
            for name in files:
                rel = os.path.relpath(os.path.join(root, name), local_dir)
                flist.write(rel + "\n")
                backup.total_files += 1
    backup.save()

    # Zip the downloaded tree (no sudo / no chown). The zip path must be absolute:
    # cwd is local_dir, which in incremental mode is the node's cache directory.
    subprocess.run(
        ["zip", "-y", "-r", os.path.abspath(local_zip), ".", "-i", "*"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=COMMAND_TIMEOUT, cwd=local_dir,
    )

    if os.path.exists(local_zip):
        backup.size = os.stat(local_zip).st_size
        backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
        backup.save()
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
    lock_file = None

    try:
        # Disk-space preflight before a single byte is downloaded: a full mirror
        # needs the tree plus the zip (~2x the last snapshot); the incremental
        # cache already exists, so only the new zip needs headroom (~1.2x).
        multiplier = 1.2 if incremental else 2
        ensure_disk_space(
            int(max(multiplier * _last_complete_zip_size(backup, website__node=node),
                    _PREFLIGHT_FLOOR)),
            what="website backup",
        )

        auth.check_connection()

        if auth.use_public_key:
            # SaaS-only "BackupSheep adds its shared key to your server" auth.
            raise NodeBackupFailedError(
                node, backup.uuid_str, backup.attempt_no, backup.type,
                "Managed public-key auth is not available in self-hosted BackupSheep. "
                "Use a private key or username/password.",
            )

        if auth.use_private_key:
            ssh_key_path = f"_storage/ssh_{backup.uuid}"
            with open(ssh_key_path, "w") as fh:
                fh.write(bs_decrypt(auth.private_key, encryption_key) or "")
            os.chmod(ssh_key_path, 0o600)
            _normalize_ssh_key(ssh_key_path, password)

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

        if website.all_paths:
            sources = [{"path": ".", "type": "directory"}]
        else:
            sources = [{"path": p["path"], "type": p["type"]} for p in (website.paths or [])]

        _write_log(backup, f"Parallel: {parallel}\nIncludes: {' '.join(include_rules)}\n"
                           f"Excludes: {' '.join(exclude_rules)}\n")

        if incremental:
            cache_dir, meta_path, lock_path = _cache_paths(node)
            os.makedirs(os.path.dirname(meta_path), exist_ok=True)
            lock_file = open(lock_path, "a+")
            # Serialize concurrent backups of this node around the whole mirror+zip.
            fcntl.flock(lock_file, fcntl.LOCK_EX)

        try:
            if incremental:
                fingerprint = _cache_fingerprint(website, auth, username)
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
                mkdir_p(local_dir)

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

                try:
                    proc = subprocess.run(
                        ["lftp"], input=script, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, timeout=COMMAND_TIMEOUT, text=True, errors="ignore",
                    )
                except FileNotFoundError:
                    raise NodeBackupFailedError(
                        node, backup.uuid_str, backup.attempt_no, backup.type,
                        "lftp is not installed in the worker image.",
                    )

                for line in (proc.stdout or "").splitlines():
                    _write_log(backup, "LFTP: " + _redact(line, username, password) + "\n")
                    low = line.lower()
                    if "421 too many connections" in low and (website.parallel or 0) > 1:
                        website.parallel = max(1, (website.parallel or 2) // 2)
                        website.save()
                    if ("login failed" in low or "login incorrect" in low
                            or ("fatal error" in low and "too many" in low)):
                        raise NodeBackupFailedError(
                            node, backup.uuid_str, backup.attempt_no, backup.type,
                            message=_redact(line, username, password),
                        )

                # A mirror with failed transfers must not produce a "successful"
                # (partial) backup: lftp's exit code reports them (see the helper
                # for the verified mechanism).
                _check_lftp_result(node, backup, proc, username, password)

            _finalize_zip(backup, local_dir, keep_dir=incremental)

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
        delete_from_disk.apply_async(args=[backup.uuid_str, "both"])
        raise
    except Exception as e:
        _write_log(backup, f"Error: {e}\n")
        capture_exception(e)
        delete_from_disk.apply_async(args=[backup.uuid_str, "both"])
        if "timed out after" in str(e):
            raise NodeBackupTimeoutError(node, backup.uuid_str, backup.attempt_no, backup.type)
        raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, str(e))
    finally:
        if ssh_key_path and os.path.exists(ssh_key_path):
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

    try:
        # Disk-space preflight before the tar is pulled down (~2x the last
        # snapshot: downloaded tar plus the final zip).
        ensure_disk_space(
            int(max(2 * _last_complete_zip_size(backup, website__node=node),
                    _PREFLIGHT_FLOOR)),
            what="website backup",
        )

        sources = []
        for path in (node.website.paths or []):
            sources.append(path["path"])

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
        _stdout.channel.set_combine_stderr(True)
        output = _stdout.readlines()

        # Remove any existing backup tar
        _stdin, _stdout, _stderr = ssh.exec_command(f"rm -rf {shlex.quote(bs_backup_tar)}")
        _stdout.channel.set_combine_stderr(True)
        output = _stdout.readlines()

        command = (
            f"tar --create --no-check-device {exclude_rules} "
            f"--file={shlex.quote(bs_backup_tar)} {bs_backup_sources}"
        )
        _stdin, _stdout, _stderr = ssh.exec_command(command, timeout=command_timeout)
        _stdout.channel.set_combine_stderr(True)
        output = _stdout.readlines()

        # Download Backup file
        sftp.get(bs_backup_tar, f"{local_dir}{backup.uuid}.tar")

        # Cleanup files from remote server.
        sftp.remove(bs_backup_tar)

        """
        Get list of files in tar.
        """
        backup.total_files = 0

        execstr = f'tar -list --file="{backup.uuid}.tar"'
        process = subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=command_timeout,
            shell=True,
            cwd=local_dir,
            universal_newlines=True,
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
        execstr = rf"/usr/bin/zip -y -r ../{backup.uuid_str} . -i \*"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=command_timeout,
            shell=True,
            cwd=local_dir,
        )

        if os.path.exists(local_zip):
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

    except Exception as e:
        _write_log(backup, f"Error: {e}\n")

        capture_exception(e)

        """
        Delete files
        """
        delete_from_disk.apply_async(
            args=[backup.uuid_str, "both"],
        )

        error = e.__str__()
        if "timed out after" in e.__str__():
            raise NodeBackupTimeoutError(node, backup.uuid_str, backup.attempt_no, backup.type)
        else:
            raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, error)
    finally:
        """
        Delete temp SSH Key
        """
        if ssh_key_path and os.path.exists(ssh_key_path):
            os.remove(ssh_key_path)
