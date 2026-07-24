"""Shared helpers for the website/database restore engines.

A restore starts by materializing the stored backup zip onto the local disk:

  * 'Local Storage' backends keep the zip as a plain file under
    settings.LOCAL_STORAGE_ROOT (storage_file_id is its absolute path) -- it is
    copied from there, confined to the storage root.
  * Every remote backend yields a 24h download URL via
    stored_backup.generate_download_url() -- streamed to disk in chunks.
  * Glacier/Deep Archive copies are cold: generate_download_url() returns the
    "restore_requested" / "restore_in_progress" sentinels instead of a URL,
    which becomes a clear RestoreError telling the user to thaw the archive
    with the storage provider first.

Extraction is path-traversal-safe for both the outer zip and the legacy
tar-wrapped website layout (backup_type FULL_V2 zips wrap {uuid}.tar).
"""
import os
import shutil
import tarfile
import zipfile

import requests
from django.conf import settings
from sentry_sdk import capture_exception

# (connect, read) timeout for the download URL fetch; 1 MiB stream chunks.
DOWNLOAD_TIMEOUT = (30, 300)
CHUNK_SIZE = 1024 * 1024

GLACIER_SENTINELS = ("restore_requested", "restore_in_progress")


class RestoreError(Exception):
    """Fatal, user-facing restore failure; the task marks the restore FAILED with it."""


def _local_source_path(storage_file_id):
    """Resolve a Local Storage backend's storage_file_id, confined to LOCAL_STORAGE_ROOT."""
    root = os.path.realpath(settings.LOCAL_STORAGE_ROOT)
    target = os.path.realpath(storage_file_id or "")
    if target == root or not target.startswith(root + os.sep):
        raise RestoreError("stored backup path escapes the local storage root.")
    if not os.path.isfile(target):
        raise RestoreError("stored backup file was not found on local storage.")
    return target


def fetch_backup_zip(stored_backup, dest_zip_path):
    """Materialize the stored backup zip at dest_zip_path (a local file path)."""
    if stored_backup.storage.type.code == "local":
        shutil.copyfile(_local_source_path(stored_backup.storage_file_id), dest_zip_path)
    else:
        url = stored_backup.generate_download_url()
        if url in GLACIER_SENTINELS:
            raise RestoreError(
                "backup is archived in Glacier/Deep Archive — restore it with the storage provider first"
            )
        if not url:
            raise RestoreError("unable to generate a download URL for the stored backup.")
        try:
            with requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT) as response:
                response.raise_for_status()
                with open(dest_zip_path, "wb") as out:
                    for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                        out.write(chunk)
        except Exception as e:
            raise RestoreError(f"unable to download the stored backup: {e}")
    if os.path.getsize(dest_zip_path) == 0:
        raise RestoreError("stored backup zip is empty (0 bytes).")
    return dest_zip_path


def _check_members(names, dest_root, kind):
    """Reject archive members whose extraction path would escape dest_root."""
    for name in names:
        target = os.path.realpath(os.path.join(dest_root, name))
        if target != dest_root and not target.startswith(dest_root + os.sep):
            raise RestoreError(f"unsafe path in backup {kind}: {name}")


def extract_backup_zip(zip_path, dest_dir):
    """Extract a backup zip into dest_dir, rejecting path-traversal members."""
    dest_root = os.path.realpath(dest_dir)
    os.makedirs(dest_root, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path) as zf:
            _check_members(zf.namelist(), dest_root, "zip")
            zf.extractall(dest_root)
    except zipfile.BadZipFile as e:
        raise RestoreError(f"stored backup is not a valid zip file: {e}")
    return dest_root


def maybe_extract_tar(dest_dir, backup_uuid_str):
    """Unwrap legacy tar-wrapped website zips (backup_type FULL_V2).

    Those zips contain {uuid}.tar (+ {uuid}.files, backupsheep.txt) instead of the
    mirrored tree. When the tar is present it is extracted (same traversal safety)
    and removed. Returns the directory holding the restored tree (dest_dir either
    way).
    """
    dest_root = os.path.realpath(dest_dir)
    tar_path = os.path.join(dest_root, f"{backup_uuid_str}.tar")
    if not os.path.exists(tar_path):
        return dest_root
    with tarfile.open(tar_path) as tf:
        _check_members(tf.getnames(), dest_root, "tar")
        # filter="data" additionally blocks link members pointing outside dest_root.
        tf.extractall(dest_root, filter="data")
    os.remove(tar_path)
    return dest_root


# ---------------------------------------------------------------------------
# Restore notifications (email + activity log)
#
# The restore tasks in restore.py call the three notify_restore_* helpers at
# each status transition. Both side effects are individually wrapped so a
# notification problem can never break the restore itself:
#
#   * an activity-log entry via CoreLog.record(account, CoreLog.Type.RESTORE, data)
#   * an email (restore_started / restore_completed / restore_failed template)
#     to every get_notification_recipients() member -- "success" for a completed
#     restore, "fail" for started/failed.
#
# `backup` is None-tolerant throughout: a cloud restore only stores backup_id,
# and the source snapshot may be gone by the time the poll task finalizes.
# ---------------------------------------------------------------------------


def _restore_backup_name(backup, restore):
    if backup is not None:
        return backup.uuid_str
    return getattr(restore, "backup_id", None)


def _restore_context(node, backup, restore, message, error=None):
    """Context shared by the restore_* email templates. The action_url back to
    the node page is built in-template from the injected site_app_url + node_id."""
    return {
        "message": message,
        "node_id": node.id,
        "node_name": node.name,
        "connection_id": node.connection.id,
        "connection_name": node.connection.name,
        "backup_id": backup.id if backup is not None else None,
        "backup_name": _restore_backup_name(backup, restore),
        "restore_id": restore.id,
        "restore_name": restore.name,
        "error_details": str(error) if error else "",
        "help_url": "https://support.backupsheep.com",
        "sender_name": "BackupSheep - Notification Bot",
    }


def _record_restore_event(node, backup, restore, message):
    """Emit a RESTORE activity-log entry; a log failure never breaks a restore."""
    try:
        from apps.console.log.models import CoreLog

        account = node.connection.account
        data = {
            "message": message,
            "node_id": node.id,
            "node_name": node.name,
            "connection_id": node.connection.id,
            "connection_name": node.connection.name,
            "backup_id": backup.id if backup is not None else None,
            "backup_name": _restore_backup_name(backup, restore),
            "restore_id": restore.id,
            "restore_name": restore.name,
        }
        CoreLog.record(account, CoreLog.Type.RESTORE, data)
    except Exception as e:
        capture_exception(e)


def _email_restore_recipients(node, event, template, context):
    """Email a restore notification to every eligible member for `event`."""
    try:
        from apps._tasks.helper.tasks import send_postmark_email

        account = node.connection.account
        for _member, to_email in account.get_notification_recipients(event):
            send_postmark_email.delay(to_email, template, context)
    except Exception as e:
        capture_exception(e)


def notify_restore_started(node, backup, restore):
    message = (
        f"Restore ({restore.name}) of backup {_restore_backup_name(backup, restore)} "
        f"for node {node.name} has started."
    )
    _record_restore_event(node, backup, restore, message)
    _email_restore_recipients(
        node, "fail", "restore_started", _restore_context(node, backup, restore, message)
    )


def notify_restore_completed(node, backup, restore):
    message = (
        f"Restore ({restore.name}) of backup {_restore_backup_name(backup, restore)} "
        f"for node {node.name} has completed."
    )
    _record_restore_event(node, backup, restore, message)
    _email_restore_recipients(
        node, "success", "restore_completed", _restore_context(node, backup, restore, message)
    )


def notify_restore_failed(node, backup, restore, error):
    message = (
        f"Restore ({restore.name}) of backup {_restore_backup_name(backup, restore)} "
        f"for node {node.name} has failed."
    )
    _record_restore_event(node, backup, restore, message)
    _email_restore_recipients(
        node, "fail", "restore_failed",
        _restore_context(node, backup, restore, message, error=error),
    )
