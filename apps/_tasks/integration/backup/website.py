"""Full website / files backup via lftp.

Mirrors a remote FTP / FTPS / SFTP source into local _storage, then zips it.

Differences from the old SaaS implementation:
  * lftp is the locally-installed binary (the worker image builds it) -- no
    `sudo docker run bs-lftp`, no `sudo docker stop`, no `sudo chown ubuntu`.
  * the lftp command script (credentials included) is fed on STDIN, never on the process
    argv, and is built ONCE by `_build_lftp_script` for every protocol/auth combination
    instead of being copy-pasted eight times.
  * SFTP uses the system `ssh`, so every key type works (Ed25519/ECDSA/RSA), and
    passphrase-protected keys are normalized to an unencrypted temp key so ssh never
    prompts.

NOTE: TLS certificate verification is disabled (`ssl:verify-certificate no`) because
managed hosting commonly uses self-signed/mismatched certs. Add a per-connection verify
flag to CoreAuthWebsite to tighten this.
"""
import os
import shlex
import subprocess

import paramiko
from sentry_sdk import capture_exception

from apps._tasks.exceptions import NodeBackupFailedError, NodeBackupTimeoutError
from apps.api.v1.utils.api_helpers import bs_decrypt, mkdir_p, create_directory_v2
from apps.console.connection.models import CoreAuthWebsite
from apps._tasks.helper.tasks import delete_from_disk
from apps.console.utils.models import UtilBackup

# Hard cap on a single lftp transfer (24h).
COMMAND_TIMEOUT = 12 * 3600

_LFTP_BASE_SETTINGS = (
    "set ssl:verify-certificate no",
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


def _normalize_ssh_key(path, passphrase):
    """Rewrite the private key unencrypted (any key type) so the system ssh that lftp
    spawns never prompts for a passphrase. If paramiko can't parse it, the original key
    is left in place for ssh to try."""
    for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            key = key_cls.from_private_key_file(path, password=passphrase or None)
            key.write_private_key_file(path)
            os.chmod(path, 0o600)
            return
        except Exception:
            continue


def _build_lftp_script(*, auth, host_url, port, username, password, ssh_key_path,
                       parallel, transfer, mirror):
    """Compose the full lftp command script for one transfer (settings + connect + auth
    + the get/mirror line). Returned as text to feed lftp on stdin."""
    lines = [f"set net:connection-limit {parallel}", *_LFTP_BASE_SETTINGS]

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


def snapshot_website(backup):
    node = backup.website.node
    auth = node.connection.auth_website
    encryption_key = node.connection.account.get_encryption_key()

    backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
    backup.save()

    local_dir = f"_storage/{backup.uuid}/"
    local_zip = f"_storage/{backup.uuid}.zip"
    mkdir_p(local_dir)

    log_file_path = f"_storage/{backup.uuid}.log"
    log_file = open(log_file_path, "a+")
    log_file.write(f"Node: {node.name}\n")
    log_file.write(f"UUID: {backup.uuid}\n")
    log_file.write(f"Time: {backup.created}\n")
    log_file.write(f"Attempt Number: {backup.attempt_no}\n")

    backup_file_list_path = f"{local_dir}{backup.uuid}.files"

    username = bs_decrypt(auth.username, encryption_key) or ""
    password = bs_decrypt(auth.password, encryption_key) or ""
    ssh_key_path = None

    try:
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

        parallel = node.website.parallel or 3
        verbose = "--verbose=3" if node.website.verbose else ""

        exclude_rules = ["--exclude-glob=*.sock"]
        for rx in (node.website.excludes_regex or []):
            exclude_rules.append(f"--exclude={_lftp_quote(rx)}")
        for gl in (node.website.excludes_glob or []):
            exclude_rules.append(f"--exclude-glob={_lftp_quote(gl)}")
        include_rules = []
        for rx in (node.website.includes_regex or []):
            include_rules.append(f"--include={_lftp_quote(rx)}")
        for gl in (node.website.includes_glob or []):
            include_rules.append(f"--include-glob={_lftp_quote(gl)}")

        mirror_opts = (
            f"--continue --recursion=always --ignore-time --no-perms --no-umask "
            f"--ignore-size --use-pget=1 --parallel={parallel} {verbose}"
        )

        if node.website.all_paths:
            sources = [{"path": ".", "type": "directory"}]
        else:
            sources = [{"path": p["path"], "type": p["type"]} for p in (node.website.paths or [])]

        log_file.write(f"Parallel: {parallel}\nIncludes: {' '.join(include_rules)}\n"
                       f"Excludes: {' '.join(exclude_rules)}\n")

        for source in sources:
            target = local_dir if source["path"] == "." else (local_dir + source["path"]).replace("//", "/")
            create_directory_v2(target)

            if source["type"] == "file":
                transfer = f'get -P {parallel} {_lftp_quote(source["path"])} -o {_lftp_quote(target)}'
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
            log_file.write(f"\nPath: {source['path']} -> {target}\n")
            log_file.write(_redact(script, username, password) + "\n")

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
                log_file.write("LFTP: " + _redact(line, username, password) + "\n")
                low = line.lower()
                if "421 too many connections" in low and (node.website.parallel or 0) > 1:
                    node.website.parallel = max(1, (node.website.parallel or 2) // 2)
                    node.website.save()
                if ("login failed" in low or "login incorrect" in low
                        or ("fatal error" in low and "too many" in low)):
                    raise NodeBackupFailedError(
                        node, backup.uuid_str, backup.attempt_no, backup.type,
                        message=_redact(line, username, password),
                    )

        # File list + count (Python walk; no `sudo find` / md5sum).
        backup.total_files = 0
        with open(backup_file_list_path, "w") as flist:
            for root, _dirs, files in os.walk(local_dir):
                for name in files:
                    rel = os.path.relpath(os.path.join(root, name), local_dir)
                    if rel == f"{backup.uuid}.files":
                        continue
                    flist.write(rel + "\n")
                    backup.total_files += 1
        backup.save()

        # Zip the downloaded tree (no sudo / no chown).
        subprocess.run(
            ["zip", "-y", "-r", f"../{backup.uuid_str}", ".", "-i", "*"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=COMMAND_TIMEOUT, cwd=local_dir,
        )

        if os.path.exists(local_zip):
            backup.size = os.stat(local_zip).st_size
            backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
            backup.save()
            log_file.write(f"Size (compressed): {backup.size_display()}\n")

        # The working directory is no longer needed; the zip is what gets uploaded.
        delete_from_disk.apply_async(args=[backup.uuid_str, "dir"])

    except NodeBackupFailedError:
        delete_from_disk.apply_async(args=[backup.uuid_str, "both"])
        raise
    except Exception as e:
        log_file.write(f"Error: {e}\n")
        capture_exception(e)
        delete_from_disk.apply_async(args=[backup.uuid_str, "both"])
        if "timed out after" in str(e):
            raise NodeBackupTimeoutError(node, backup.uuid_str, backup.attempt_no, backup.type)
        raise NodeBackupFailedError(node, backup.uuid_str, backup.attempt_no, backup.type, str(e))
    finally:
        log_file.close()
        if ssh_key_path and os.path.exists(ssh_key_path):
            os.remove(ssh_key_path)
