"""Website / files restore engine.

One public entry point -- `restore_website(backup, restore)`:

  1. fetch the stored backup zip (local copy or streamed download URL),
  2. extract it (unwrapping the legacy server-side tar transport when present),
  3. push the tree back onto the source server with lftp -- the exact reverse of
     the backup mirror: `mirror -R` for directories, `put` for file sources.

`--delete` is only added when the user explicitly opted in
(restore.params["delete"]): it removes remote files that are not in the backup.
The backup-side artifacts planted in every archive (the {uuid}.files manifest and
the backupsheep.txt placeholder) are excluded so they are never pushed onto the
site -- and, with --delete, never removed from it either.

Everything is appended to a run log at _storage/restore_{uuid}.log (credentials
redacted); the working files (_storage/restore_{uuid}.zip + extracted dir) are
always discarded afterwards, success or failure. On incremental nodes the
restore leaves the local snapshot cache untouched -- it re-syncs from the
server on the next backup, picking up the restored state automatically.

Two hardening measures: a disk-space preflight (~3x the stored zip) runs before
the zip is fetched, and lftp's exit code is checked after every push so a
transfer with failed files fails the restore loudly (naming the files) instead
of leaving a silently incomplete site behind.
"""
import os
import subprocess

from sentry_sdk import capture_exception

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.helper.tasks import delete_from_disk
from apps._tasks.integration.backup.website import (
    COMMAND_TIMEOUT,
    _PREFLIGHT_FLOOR,
    _build_lftp_script,
    _check_lftp_result,
    _lftp_quote,
    _normalize_ssh_key,
    _redact,
)
from apps._tasks.integration.restore_common import (
    RestoreError,
    extract_backup_zip,
    fetch_backup_zip,
    maybe_extract_tar,
)
from apps.api.v1.utils.api_helpers import bs_decrypt, ensure_disk_space
from apps.console.connection.models import CoreAuthWebsite


def _write_log(backup, text):
    """Append to the restore's run log (_storage/restore_{uuid}.log)."""
    with open(f"_storage/restore_{backup.uuid_str}.log", "a+") as log_file:
        log_file.write(text)


def restore_website(backup, restore):
    node = backup.website.node
    auth = node.connection.auth_website
    website = node.website
    encryption_key = node.connection.account.get_encryption_key()

    local_zip = f"_storage/restore_{backup.uuid_str}.zip"
    local_dir = f"_storage/restore_{backup.uuid_str}/"
    ssh_key_path = None

    _write_log(backup, f"Node: {node.name}\n")
    _write_log(backup, f"Backup UUID: {backup.uuid}\n")
    _write_log(backup, f"Restore: {restore.name}\n")

    try:
        # Disk-space preflight: the fetched zip plus its extracted tree plus
        # import headroom (~3x the stored zip) must fit before fetching.
        ensure_disk_space(
            int(max(3 * (backup.size or 0), _PREFLIGHT_FLOOR)),
            what="website restore",
        )

        stored_backup = restore.storage_point
        if stored_backup is None:
            raise RestoreError(
                "the storage point this restore was created from no longer exists."
            )

        _write_log(backup, f"Fetching backup zip from storage: {stored_backup.storage.name}\n")
        fetch_backup_zip(stored_backup, local_zip)
        extract_backup_zip(local_zip, local_dir)
        tree_root = maybe_extract_tar(local_dir, backup.uuid_str)

        auth.check_connection()

        if auth.use_public_key:
            # SaaS-only "BackupSheep adds its shared key to your server" auth.
            raise NodeBackupFailedError(
                node, backup.uuid_str, backup.attempt_no, backup.type,
                "Managed public-key auth is not available in self-hosted BackupSheep. "
                "Use a private key or username/password.",
            )

        username = bs_decrypt(auth.username, encryption_key) or ""
        password = bs_decrypt(auth.password, encryption_key) or ""

        if auth.use_private_key:
            ssh_key_path = f"_storage/ssh_restore_{backup.uuid_str}"
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
        delete = "--delete" if (restore.params or {}).get("delete") else ""

        # Backup-side artifacts planted in every archive: never pushed to the site.
        exclude_rules = [
            f"--exclude-glob={_lftp_quote(f'{backup.uuid}.files')}",
            f"--exclude-glob={_lftp_quote('backupsheep.txt')}",
        ]

        # NOTE: never add --ignore-time/--ignore-size here. Verified live against
        # lftp 4.9.2: with both ignore flags mirror -R has no comparison criterion
        # left and SKIPS every file that already exists remotely -- a restore would
        # only push missing files and never overwrite modified/corrupt ones. With
        # default comparison (size + mtime) differing files are re-uploaded; since
        # zipfile extraction does not preserve mtimes, extracted files also read as
        # newer than the remote and are always pushed, i.e. a full overwrite.
        mirror_opts = (
            f"-R --continue --no-perms --no-umask "
            f"--use-pget=1 --parallel={parallel} {verbose} {delete}"
        )

        if website.all_paths:
            sources = [{"path": ".", "type": "directory"}]
        else:
            sources = [{"path": p["path"], "type": p["type"]} for p in (website.paths or [])]

        for source in sources:
            if source["path"] == ".":
                source_path = tree_root
            else:
                # Absolute paths were archived with the leading slash stripped.
                source_path = os.path.join(tree_root, source["path"].lstrip("/"))

            if source["type"] == "file":
                if not os.path.isfile(source_path):
                    raise RestoreError(
                        f"the backup archive does not contain {source['path']}."
                    )
                transfer = (
                    # `-P` is a boolean flag for put in lftp 4.9.2; `-P 3` would
                    # make lftp upload an extra file literally named "3".
                    f"put -P {_lftp_quote(source_path)} "
                    f"-o {_lftp_quote(source['path'])}"
                )
                mirror = False
            else:
                if not os.path.isdir(source_path):
                    raise RestoreError(
                        f"the backup archive does not contain {source['path']}."
                    )
                transfer = (
                    f"mirror {mirror_opts} {' '.join(exclude_rules)} "
                    f"{_lftp_quote(source_path)} {_lftp_quote(source['path'])}"
                )
                mirror = True

            script = _build_lftp_script(
                auth=auth, host_url=host_url, port=auth.port, username=username,
                password=password, ssh_key_path=ssh_key_path, parallel=parallel,
                transfer=transfer, mirror=mirror,
            )
            _write_log(backup, f"\nPath: {source['path']} <- {source_path}\n")
            _write_log(backup, _redact(script, username, password) + "\n")

            try:
                proc = subprocess.run(
                    ["lftp"], input=script, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=COMMAND_TIMEOUT, text=True,
                    errors="ignore",
                )
            except FileNotFoundError:
                raise NodeBackupFailedError(
                    node, backup.uuid_str, backup.attempt_no, backup.type,
                    "lftp is not installed in the worker image.",
                )

            for line in (proc.stdout or "").splitlines():
                _write_log(backup, "LFTP: " + _redact(line, username, password) + "\n")
                low = line.lower()
                if ("login failed" in low or "login incorrect" in low
                        or ("fatal error" in low and "too many" in low)):
                    raise NodeBackupFailedError(
                        node, backup.uuid_str, backup.attempt_no, backup.type,
                        message=_redact(line, username, password),
                    )

            # A push with failed transfers must not leave a "successful" partial
            # restore behind: lftp's exit code reports them (see website.py's
            # _check_lftp_result for the verified mechanism).
            _check_lftp_result(node, backup, proc, username, password)

        if website.incremental:
            _write_log(
                backup,
                "Restore complete. Files changed by this restore differ from the "
                "incremental snapshot cache; the cache re-syncs automatically on "
                "the next backup.\n",
            )
        else:
            _write_log(backup, "Restore complete.\n")

    except (RestoreError, NodeBackupFailedError):
        raise
    except Exception as e:
        _write_log(backup, f"Error: {e}\n")
        capture_exception(e)
        raise NodeBackupFailedError(
            node, backup.uuid_str, backup.attempt_no, backup.type, str(e)
        )
    finally:
        # The fetched zip + extracted tree are always discarded; the run log is
        # kept (delete_from_disk never touches .log files).
        delete_from_disk.apply_async(args=[f"restore_{backup.uuid_str}", "both"])
        if ssh_key_path and os.path.exists(ssh_key_path):
            os.remove(ssh_key_path)
