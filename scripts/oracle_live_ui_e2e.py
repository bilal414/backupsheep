#!/usr/bin/env python3
"""Safety-gated Oracle Cloud source provisioning and UI result verification.

This script is deliberately inert by default.  ``plan`` performs no OCI config
read and no network request.  Provider creates require
``BACKUPSHEEP_E2E_APPLY=YES``.  Provider cleanup additionally requires
``BACKUPSHEEP_E2E_CLEANUP=YES`` and can address only exact OCIDs already stored
in the fsynced run ledger.

The OCI signer is loaded only through the normal OCI CLI/SDK profile selected by
``OCI_CLI_CONFIG_FILE`` and ``OCI_CLI_PROFILE``.  Credential values are never
accepted as arguments, copied into the ledger, or printed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import io
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.live_e2e_ledger import (  # noqa: E402
    DurableMutationIntentStore,
    DurableResourceLedger,
    LedgerError,
    bounded_error,
    require_run_id,
)


class HarnessError(RuntimeError):
    """A bounded, credential-free safety failure."""

    def __init__(
        self,
        message,
        *,
        code="",
        definitive_rejection=False,
        mutation_outcome_unknown=False,
    ):
        # HarnessError is the only exception type intentionally rendered by
        # the CLI. Keep even caller-supplied messages bounded and redacted so
        # an SDK response cannot accidentally reach the terminal or ledger.
        super().__init__(bounded_error(message))
        self.code = str(code or "")
        self.mutation_outcome_unknown = bool(mutation_outcome_unknown)
        self.definitive_rejection = bool(definitive_rejection)


OCI_OCID_RE = re.compile(r"^ocid1\.[a-z0-9-]+\.[a-z0-9-]*\.[a-z0-9-]*\..+$")
PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
SAFE_BACKUP_MARKER_RE = re.compile(
    r"^(?:bs|backupsheep)-[a-z0-9][a-z0-9._-]{4,124}$"
)
SSH_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
MAX_PAGES = 100
MAX_ITEMS = 10_000
REQUEST_TIMEOUT = (10.0, 60.0)
SOURCE_BLOCK_DEVICE = "/dev/oracleoci/oraclevdb"
RESTORE_BLOCK_DEVICE = "/dev/oracleoci/oraclevdc"

E2E_RUN_TAG = "BACKUPSHEEP_E2E_RUN"
E2E_OWNED_TAG = "BACKUPSHEEP_E2E_OWNED"
E2E_KIND_TAG = "BACKUPSHEEP_E2E_KIND"

BACKUP_MARKER_TAG = "BACKUPSHEEP__UUID"
BACKUP_SOURCE_TAG = "BACKUPSHEEP__SOURCE"
BACKUP_KIND_TAG = "BACKUPSHEEP__KIND"
BACKUP_REQUEST_TAG = "BACKUPSHEEP__REQUEST"
RESTORE_MARKER_TAG = "BACKUPSHEEP_RESTORE"
RESTORE_SOURCE_TAG = "BACKUPSHEEP_RESTORE_SOURCE"
RESTORE_ORIGIN_TAG = "BACKUPSHEEP_RESTORE_ORIGIN"

SOURCE_KINDS = {
    "source_block_volume",
    "source_block_attachment",
    "source_instance",
    "source_boot_volume",
    "source_vnic",
}
UI_KINDS = {
    "ui_compute_backup",
    "ui_compute_restore",
    "ui_compute_restore_boot_volume",
    "ui_compute_restore_vnic",
    "ui_block_backup",
    "ui_boot_backup",
    "ui_block_restore",
    "ui_block_restore_attachment",
    "ui_boot_restore",
    "ui_boot_verify_instance",
    "ui_boot_verify_vnic",
}
ALL_KINDS = SOURCE_KINDS | UI_KINDS
STORAGE_KINDS = {
    "object_bucket",
    "iam_user",
    "iam_group",
    "iam_policy",
    "iam_membership",
    "customer_secret_key",
}
USER_RETAINED_STORAGE_KINDS = frozenset(
    {
        "customer_secret_key",
        "iam_membership",
        "iam_policy",
        "iam_group",
        "iam_user",
    }
)
ALL_KINDS |= STORAGE_KINDS
TAGGABLE_SOURCE_KINDS = {
    "source_block_volume",
    "source_instance",
    "source_boot_volume",
    "source_vnic",
}

STORAGE_SECRET_KEYS = frozenset(
    {
        "access_key_id",
        "secret_access_key",
        "bucket",
        "namespace",
        "region",
        "endpoint",
        "prefix",
        "user_ocid",
        "tenancy_ocid",
        "compartment_ocid",
    }
)
STORAGE_SCOPE_KEYS = frozenset(
    {
        "bucket",
        "namespace",
        "region",
        "endpoint",
        "prefix",
        "user_ocid",
        "tenancy_ocid",
        "compartment_ocid",
    }
)
CLEANUP_INTENT_PREFIX = "cleanup:"
RUNTIME_SCOPE_SCHEMA = 1
UI_MANIFEST_SCHEMA = 3
ORPHAN_RECONCILIATION_SCHEMA = 1
STORAGE_SCOPE_REPAIR_SCHEMA = 2
CLEANUP_RECEIPT_SCHEMA = 1
RUNTIME_SCOPE_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "profile",
        "tenancy_id",
        "compartment_id",
        "subnet_id",
        "availability_domain",
        "region",
        "ui_ledger_path",
        "network_ledger_path",
    }
)
STORAGE_SCOPE_REPAIR_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "runtime_scope_digest",
        "scope_identity_sha256",
        "storage_scope",
        "bucket_witness",
        "user_witness",
        "customer_secret_witness",
    }
)
STORAGE_LEDGER_WITNESS_KEYS = frozenset(
    {"kind", "resource_id", "name", "ownership", "source_witness"}
)
WORKLOAD_GUEST_SCOPE_KEYS = frozenset(
    {
        "provider",
        "run_id",
        "durable_ledger_path",
        "durable_ledger_scope",
        "source_server_id",
        "safe_root",
        "website_source_root",
        "source_database",
        "ssh_host",
        "ssh_port",
        "ssh_user",
        "ssh_private_key_path",
        "ssh_private_key_sha256",
        "known_hosts_path",
        "known_hosts_sha256",
        "known_host_key_type",
        "known_host_fingerprint",
    }
)
WORKLOAD_ROW_WITNESS_KEYS = frozenset(
    {
        "node_row_id",
        "backup_row_id",
        "backup_status",
        "backup_marker",
        "restore_row_id",
        "restore_status",
        "restore_target",
    }
)
ORPHAN_ADOPTION_KINDS = frozenset(
    {
        "ui_compute_backup",
        "ui_block_backup",
        "ui_boot_backup",
        "ui_compute_restore",
        "ui_block_restore",
        "ui_boot_restore",
        "ui_compute_restore_boot_volume",
        "ui_compute_restore_vnic",
    }
)
ORPHAN_MANIFEST_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "profile",
        "tenancy_id",
        "compartment_id",
        "resources",
    }
)
ORPHAN_RESOURCE_KEYS = frozenset(
    {
        "kind",
        "provider_ocid",
        "name",
        "freeform_tags",
        "lifecycle_state",
        "source_relationship",
        "demo_row_witness",
    }
)
ORPHAN_RELATIONSHIP_KEYS = frozenset({"kind", "ocid"})
ORPHAN_ROW_WITNESS_KEYS = frozenset(
    {"row_type", "row_id", "status", "marker", "provider_ocid"}
)
ORPHAN_RELATION_KINDS = {
    "ui_compute_backup": "source_instance",
    "ui_block_backup": "source_block_volume",
    "ui_boot_backup": "source_boot_volume",
    "ui_compute_restore": "ui_compute_backup",
    "ui_block_restore": "ui_block_backup",
    "ui_boot_restore": "ui_boot_backup",
    "ui_compute_restore_boot_volume": "ui_compute_restore",
    "ui_compute_restore_vnic": "ui_compute_restore",
}
ORPHAN_RESOURCE_TYPES = {
    "ui_compute_backup": "image",
    "ui_block_backup": "volumebackup",
    "ui_boot_backup": "bootvolumebackup",
    "ui_compute_restore": "instance",
    "ui_block_restore": "volume",
    "ui_boot_restore": "bootvolume",
    "ui_compute_restore_boot_volume": "bootvolume",
    "ui_compute_restore_vnic": "vnic",
}
ORPHAN_ALLOWED_TAG_KEYS = frozenset(
    {
        E2E_RUN_TAG,
        E2E_OWNED_TAG,
        E2E_KIND_TAG,
        BACKUP_MARKER_TAG,
        BACKUP_SOURCE_TAG,
        BACKUP_KIND_TAG,
        BACKUP_REQUEST_TAG,
        RESTORE_MARKER_TAG,
        RESTORE_SOURCE_TAG,
        RESTORE_ORIGIN_TAG,
    }
)
_CREDENTIAL_FIELD_RE = re.compile(
    r"(?i)(?:^|_)(?:access_key|api_key|authorization|credential|password|private_key|secret|secret_key)(?:$|_)"
)
_SAFE_REFERENCE_FIELDS = frozenset(
    {"ssh_private_key_path", "ssh_private_key_sha256"}
)
CLEANUP_TRANSITIONAL_STATES = frozenset(
    {
        "ATTACHING",
        "DETACHING",
        "DETACHED",
        "DELETING",
        "TERMINATING",
        "UPDATING",
        "PENDING",
        "IN_PROGRESS",
    }
)


def _safe_path(value, *, variable):
    if not value:
        raise HarnessError(f"{variable} is required.")
    path = Path(value).expanduser().resolve()
    if "_docs" in path.parts:
        raise HarnessError(f"{variable} must not point inside _docs.")
    return path


def _external_path(value, *, variable):
    path = _safe_path(value, variable=variable)
    try:
        path.relative_to(ROOT)
    except ValueError:
        return path
    raise HarnessError(f"{variable} must point outside the repository.")


def _external_nonsymlink_path(value, *, variable):
    """Resolve one external path only after rejecting lexical symlink components."""

    raw = Path(str(value or "")).expanduser()
    _reject_symlink_components(raw, variable=variable)
    path = _external_path(raw, variable=variable)
    _reject_symlink_components(path, variable=variable)
    return path


def _reject_symlink_components(path, *, variable):
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            if current.is_symlink():
                raise HarnessError(f"{variable} must not use symlinked path components.")
        except OSError as error:
            raise HarnessError(f"{variable} could not be inspected safely.") from error


def _read_private_json(path_value, *, variable, exact_keys=None, maximum=256 * 1024):
    raw_path = Path(str(path_value or "")).expanduser()
    _reject_symlink_components(raw_path, variable=variable)
    path = _external_path(raw_path, variable=variable)
    _reject_symlink_components(path, variable=variable)
    try:
        before = path.lstat()
    except OSError as error:
        raise HarnessError(f"{variable} is missing or could not be inspected.") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size > maximum
    ):
        raise HarnessError(f"{variable} must be a regular 0600 file within the size limit.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            descriptor = None
            opened = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
            ):
                raise HarnessError(f"{variable} changed while being opened.")
            payload = json.load(source)
    except HarnessError:
        raise
    except (OSError, ValueError) as error:
        raise HarnessError(f"{variable} is unreadable or malformed.") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(payload, dict) or (
        exact_keys is not None and set(payload) != set(exact_keys)
    ):
        raise HarnessError(f"{variable} has an unsupported or incomplete schema.")
    return path, payload


def _publish_private_bytes(path, payload, *, variable):
    """Create one 0600 file through a pinned, non-writable parent directory."""

    path = Path(os.path.abspath(os.fspath(path)))
    _reject_symlink_components(path.parent, variable=variable)
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW

    # Walk from the filesystem root with directory-relative opens. Missing
    # components are created through an already pinned parent descriptor, so
    # a concurrent symlink swap cannot redirect publication elsewhere.
    directory_fd = None
    try:
        directory_fd = os.open(path.parent.anchor, directory_flags)
        for component in path.parent.parts[1:]:
            created = False
            try:
                child_fd = os.open(
                    component, directory_flags, dir_fd=directory_fd
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                    created = True
                except FileExistsError:
                    pass
                child_fd = os.open(
                    component, directory_flags, dir_fd=directory_fd
                )
            opened = os.fstat(child_fd)
            if not stat.S_ISDIR(opened.st_mode):
                os.close(child_fd)
                raise HarnessError(f"{variable} parent path is not a directory.")
            if created:
                os.fchmod(child_fd, 0o700)
                os.fsync(child_fd)
            os.close(directory_fd)
            directory_fd = child_fd
    except HarnessError:
        if directory_fd is not None:
            os.close(directory_fd)
        raise
    except OSError as error:
        if directory_fd is not None:
            os.close(directory_fd)
        raise HarnessError(f"{variable} parent directory could not be pinned.") from error
    temporary_name = f".{path.name}.{os.urandom(12).hex()}.tmp"
    target_created = False
    published = False
    cleanup_error = None
    try:
        pinned = os.fstat(directory_fd)
        try:
            visible = os.stat(path.parent, follow_symlinks=False)
        except OSError as error:
            raise HarnessError(f"{variable} parent directory changed.") from error
        if (
            not stat.S_ISDIR(pinned.st_mode)
            or pinned.st_dev != visible.st_dev
            or pinned.st_ino != visible.st_ino
            or stat.S_IMODE(pinned.st_mode) & 0o022
        ):
            raise HarnessError(f"{variable} parent directory is unsafe or changed.")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                descriptor = None
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        finally:
            if descriptor is not None:
                os.close(descriptor)
        try:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            target_created = True
        except FileExistsError as error:
            raise HarnessError(
                f"{variable} appeared during the write; refusing replacement."
            ) from error
        except OSError as error:
            raise HarnessError(f"{variable} could not be published safely.") from error
        try:
            current = os.stat(path.parent, follow_symlinks=False)
        except OSError as error:
            raise HarnessError(
                f"{variable} parent directory changed during publication."
            ) from error
        if current.st_dev != pinned.st_dev or current.st_ino != pinned.st_ino:
            raise HarnessError(f"{variable} parent directory changed during publication.")
        os.fsync(directory_fd)
        published = True
    finally:
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError as error:
            cleanup_error = error
        if target_created and (not published or cleanup_error is not None):
            try:
                os.unlink(path.name, dir_fd=directory_fd)
                os.fsync(directory_fd)
                target_created = False
                published = False
            except FileNotFoundError:
                target_created = False
            except OSError as error:
                cleanup_error = cleanup_error or error
        os.close(directory_fd)
        if cleanup_error is not None:
            raise HarnessError(
                f"{variable} publication rollback could not be completed safely."
            ) from cleanup_error
    return path


def _atomic_private_json(path_value, payload, *, variable, refuse_existing=True):
    raw_path = Path(str(path_value or "")).expanduser()
    _reject_symlink_components(raw_path, variable=variable)
    path = _external_path(raw_path, variable=variable)
    _reject_symlink_components(path, variable=variable)
    if not refuse_existing:
        raise HarnessError(f"{variable} replacement writes are not supported.")
    if path.exists():
        raise HarnessError(f"{variable} already exists; refusing to overwrite it.")
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return _publish_private_bytes(path, encoded, variable=variable)


def _file_digest(path, *, variable):
    path = Path(path)
    _reject_symlink_components(path, variable=variable)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise HarnessError(f"{variable} is missing.") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise HarnessError(f"{variable} must be a regular file.")
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            raise HarnessError(f"{variable} changed while being opened.")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _read_private_bytes(path_value, *, variable, maximum=1024 * 1024):
    raw_path = Path(str(path_value or "")).expanduser()
    _reject_symlink_components(raw_path, variable=variable)
    path = _external_path(raw_path, variable=variable)
    _reject_symlink_components(path, variable=variable)
    try:
        before = path.lstat()
    except OSError as error:
        raise HarnessError(f"{variable} is missing or could not be inspected.") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 0 < before.st_size <= maximum
    ):
        raise HarnessError(f"{variable} must be a non-empty regular 0600 file.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
            raise HarnessError(f"{variable} changed while being opened.")
        chunks = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum:
                raise HarnessError(f"{variable} exceeded the size limit.")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    return path, payload, hashlib.sha256(payload).hexdigest()


def _assert_no_credential_fields(value, *, path="manifest"):
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                _CREDENTIAL_FIELD_RE.search(str(key))
                and str(key) not in _SAFE_REFERENCE_FIELDS
            ):
                raise HarnessError(f"{path} contains a credential-shaped field.")
            _assert_no_credential_fields(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_no_credential_fields(child, path=f"{path}[{index}]")


class _ReadOnlyIntentStore:
    def __init__(self, path, *, provider, run_id, scope, suffix):
        base = Path(path).expanduser()
        self.path = base.with_name(base.name + suffix)
        self.provider = provider
        self.run_id = run_id
        self.scope = scope

    def _payload(self):
        try:
            _path, payload = _read_private_json(
                self.path,
                variable="read-only durable state",
                exact_keys={"schema", "provider", "run_id", "scope", "pending"},
            )
        except HarnessError as error:
            raise LedgerError("The read-only durable state could not be read.") from error
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != 1
            or payload.get("provider") != self.provider
            or payload.get("run_id") != self.run_id
            or payload.get("scope") != self.scope
            or not isinstance(payload.get("pending"), dict)
        ):
            raise LedgerError("The read-only durable state scope is malformed.")
        return payload

    def get(self, key):
        value = self._payload()["pending"].get(str(key))
        return dict(value) if isinstance(value, dict) else None

    def pending(self):
        return {key: dict(value) for key, value in self._payload()["pending"].items()}

    def put(self, *_args, **_kwargs):
        raise LedgerError("Read-only verification cannot write durable state.")

    update = put
    clear = put


class _ReadOnlyResourceLedger:
    def __init__(self, path, *, provider, run_id, scope):
        self.path = Path(path).expanduser()
        self.provider = provider
        self.run_id = run_id
        self.scope = scope

    def _payload(self):
        try:
            _path, payload = _read_private_json(
                self.path,
                variable="read-only resource ledger",
                exact_keys={
                    "schema",
                    "provider",
                    "run_id",
                    "scope",
                    "created_at",
                    "resources",
                },
            )
        except HarnessError as error:
            raise LedgerError("The read-only resource ledger could not be read.") from error
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != 1
            or payload.get("provider") != self.provider
            or payload.get("run_id") != self.run_id
            or payload.get("scope") != self.scope
            or not isinstance(payload.get("resources"), list)
        ):
            raise LedgerError("The read-only resource ledger scope is malformed.")
        return payload

    def entries(self, kind=None):
        rows = [dict(row) for row in self._payload()["resources"]]
        return rows if kind is None else [row for row in rows if row.get("kind") == str(kind)]

    def get(self, kind, resource_id):
        matches = [
            row
            for row in self.entries(kind)
            if str(row.get("resource_id")) == str(resource_id)
        ]
        if len(matches) > 1:
            raise LedgerError("The read-only ledger contains duplicate provider IDs.")
        return matches[0] if matches else None

    def record(self, *_args, **_kwargs):
        raise LedgerError("Read-only verification cannot write the resource ledger.")

    mark_cleanup = record


def _required(environment, name):
    value = str(environment.get(name) or "").strip()
    if not value:
        raise HarnessError(f"{name} is required.")
    return value


def _require_ocid(value, *, label, resource_type=None):
    value = str(value or "").strip()
    if not OCI_OCID_RE.fullmatch(value):
        raise HarnessError(f"{label} must be an OCI OCID.")
    if resource_type and not value.startswith(f"ocid1.{resource_type}."):
        raise HarnessError(f"{label} must be an {resource_type} OCID.")
    return value


def _require_customer_secret_key_id(value):
    """Validate the non-OCID access-key identifier returned by OCI S3 auth."""

    value = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9]{16,128}", value):
        raise HarnessError("customer secret key ID is malformed.")
    return value


def _safe_backup_marker(value, *, field="backup marker"):
    raw = str(value or "")
    value = raw.strip()
    if (
        raw != value
        or not SAFE_BACKUP_MARKER_RE.fullmatch(value)
        or value in {".", ".."}
        or ".." in value
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise HarnessError(f"Oracle UI manifest {field} is not a safe BackupSheep marker.")
    return value


def _retry_token(value):
    return "bs-" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:61]


def _data(response):
    return response.get("data") if isinstance(response, dict) else getattr(response, "data", None)


def _status(response):
    value = response.get("status") if isinstance(response, dict) else getattr(response, "status", None)
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _headers(response):
    value = response.get("headers") if isinstance(response, dict) else getattr(response, "headers", None)
    return value if isinstance(value, dict) else {}


def _header(headers, name):
    expected = str(name).casefold()
    for key, value in (headers or {}).items():
        if str(key).casefold() == expected:
            return value
    return None


def _next_page(response):
    value = response.get("opc_next_page") if isinstance(response, dict) else getattr(response, "opc_next_page", None)
    if value is None:
        value = _header(_headers(response), "opc-next-page")
    return str(value).strip() if value not in (None, "") else ""


def _value(resource, name, default=None):
    if isinstance(resource, dict):
        return resource.get(name, default)
    return getattr(resource, name, default)


def _tags(resource):
    value = _value(resource, "freeform_tags", {})
    return {str(key): str(item) for key, item in value.items()} if isinstance(value, dict) else {}


def _source_id(resource):
    details = _value(resource, "source_details")
    for name in ("image_id", "boot_volume_backup_id", "volume_backup_id", "id"):
        value = _value(details, name) if details is not None else None
        if value:
            return str(value)
    return ""


def _provider_error_code(error):
    status = getattr(error, "status", None) or getattr(error, "status_code", None)
    code = str(getattr(error, "code", "") or "").casefold()
    if code.startswith("provider_"):
        return code.upper()
    if code == "notauthorizedornotfound":
        return "PROVIDER_NOT_FOUND_OR_UNAUTHORIZED"
    if status in {401, 403} or code in {"notauthenticated", "notauthorized"}:
        return "PROVIDER_AUTH_FAILED"
    if status == 404 or code == "notfound":
        return "PROVIDER_NOT_FOUND"
    if status == 429 or code in {"toomanyrequests", "throttled", "throttling"}:
        return "PROVIDER_RATE_LIMIT"
    name = error.__class__.__name__.casefold()
    if status in {408, 504} or "timeout" in name:
        return "PROVIDER_TIMEOUT"
    if (isinstance(status, int) and status >= 500) or any(
        token in name for token in ("connection", "requestexception")
    ):
        return "PROVIDER_TRANSIENT_OUTAGE"
    return "PROVIDER_REQUEST_FAILED"


def _provider_error_outcome(error):
    """Classify an OCI exception without guessing about unknown outcomes."""

    status = getattr(error, "status", None) or getattr(error, "status_code", None)
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    code = _provider_error_code(error)
    if status in {408, 504} or (
        isinstance(status, int) and status >= 500
    ) or code in {"PROVIDER_TIMEOUT", "PROVIDER_TRANSIENT_OUTAGE"}:
        return "unknown"
    if (
        isinstance(status, int)
        and 400 <= status < 500
        and status != 408
    ) or code in {
        "PROVIDER_AUTH_FAILED",
        "PROVIDER_NOT_FOUND",
        "PROVIDER_NOT_FOUND_OR_UNAUTHORIZED",
        "PROVIDER_RATE_LIMIT",
    }:
        return "definite"
    # A generic SDK/parser/application exception does not prove that the
    # provider rejected the mutation.  Keep the intent for reconciliation.
    return "unknown"


def _checked(response, accepted):
    status = _status(response)
    if status not in set(accepted):
        if status == 404:
            raise HarnessError(
                "OCI resource was not found.", code="PROVIDER_NOT_FOUND", definitive_rejection=True
            )
        if status == 429:
            raise HarnessError(
                "OCI provider rate limit was returned.", code="PROVIDER_RATE_LIMIT"
            )
        if status in {401, 403}:
            raise HarnessError(
                "OCI provider authorization failed.", code="PROVIDER_AUTH_FAILED"
            )
        if status in {408, 504} or (isinstance(status, int) and status >= 500):
            raise HarnessError(
                "OCI provider returned a transient failure.",
                code=("PROVIDER_TIMEOUT" if status in {408, 504} else "PROVIDER_TRANSIENT_OUTAGE"),
                mutation_outcome_unknown=True,
            )
        raise HarnessError("OCI returned an unexpected response status.")
    return response


def iter_pages(method, **kwargs):
    """Consume OCI ``opc-next-page`` cursors with hard inventory bounds."""

    cursor = ""
    seen = set()
    count = 0
    for _ in range(MAX_PAGES):
        request = dict(kwargs)
        request["limit"] = min(100, MAX_ITEMS - count)
        if cursor:
            request["page"] = cursor
        response = _checked(method(**request), {200})
        items = _data(response)
        if not isinstance(items, (list, tuple)):
            raise HarnessError("OCI returned a malformed inventory page.")
        for item in items:
            count += 1
            if count > MAX_ITEMS:
                raise HarnessError("OCI inventory exceeded the safety limit.")
            yield item
        next_cursor = _next_page(response)
        if not next_cursor:
            return
        if next_cursor in seen:
            raise HarnessError("OCI returned a repeated inventory cursor.")
        seen.add(next_cursor)
        cursor = next_cursor
    raise HarnessError("OCI inventory exceeded the page safety limit.")


@dataclass(frozen=True)
class RuntimeScope:
    run_id: str
    profile: str
    tenancy_id: str
    compartment_id: str
    subnet_id: str
    availability_domain: str
    region: str
    ui_ledger_path: Path
    network_ledger_path: Path
    source_path: Path
    digest: str

    @classmethod
    def load(cls, path_value, *, environment=None):
        path, payload = _read_private_json(
            path_value,
            variable="ORACLE_E2E_RUNTIME_SCOPE_FILE",
            exact_keys=RUNTIME_SCOPE_KEYS,
        )
        if payload.get("schema") != RUNTIME_SCOPE_SCHEMA:
            raise HarnessError("Oracle runtime scope schema is unsupported.")
        run_id = require_run_id(payload.get("run_id"))
        profile = str(payload.get("profile") or "")
        if not PROFILE_RE.fullmatch(profile):
            raise HarnessError("Oracle runtime scope profile is malformed.")
        tenancy_id = _require_ocid(
            payload.get("tenancy_id"), label="runtime tenancy", resource_type="tenancy"
        )
        compartment_id = _require_ocid(
            payload.get("compartment_id"),
            label="runtime compartment",
            resource_type="compartment",
        )
        subnet_id = _require_ocid(
            payload.get("subnet_id"), label="runtime subnet", resource_type="subnet"
        )
        availability_domain = str(payload.get("availability_domain") or "").strip()
        region = str(payload.get("region") or "").strip()
        if not availability_domain or len(availability_domain) > 128:
            raise HarnessError("Oracle runtime availability domain is malformed.")
        if not re.fullmatch(r"[a-z0-9-]{3,64}", region):
            raise HarnessError("Oracle runtime region is malformed.")
        ui_ledger_path = _external_nonsymlink_path(
            payload.get("ui_ledger_path"), variable="runtime ui_ledger_path"
        )
        network_ledger_path = _external_nonsymlink_path(
            payload.get("network_ledger_path"), variable="runtime network_ledger_path"
        )
        if ui_ledger_path == network_ledger_path:
            raise HarnessError("Oracle runtime ledgers must use separate paths.")
        expected_environment = {
            "BACKUPSHEEP_E2E_RUN_ID": run_id,
            "OCI_CLI_PROFILE": profile,
            "ORACLE_E2E_ALLOWED_TENANCY_OCID": tenancy_id,
            "ORACLE_E2E_COMPARTMENT_OCID": compartment_id,
            "ORACLE_E2E_ALLOWED_COMPARTMENT_OCID": compartment_id,
            "ORACLE_E2E_SUBNET_OCID": subnet_id,
            "ORACLE_E2E_AVAILABILITY_DOMAIN": availability_domain,
            "ORACLE_E2E_REGION": region,
            "BACKUPSHEEP_E2E_LEDGER_PATH": str(ui_ledger_path),
            "BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH": str(network_ledger_path),
        }
        environment = dict(environment or {})
        for name, expected in expected_environment.items():
            actual = str(environment.get(name) or "").strip()
            if actual and (
                str(_external_nonsymlink_path(actual, variable=name))
                if name.endswith("LEDGER_PATH")
                else actual
            ) != str(expected):
                raise HarnessError(f"{name} does not match the protected runtime scope.")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return cls(
            run_id=run_id,
            profile=profile,
            tenancy_id=tenancy_id,
            compartment_id=compartment_id,
            subnet_id=subnet_id,
            availability_domain=availability_domain,
            region=region,
            ui_ledger_path=ui_ledger_path,
            network_ledger_path=network_ledger_path,
            source_path=path,
            digest=hashlib.sha256(canonical).hexdigest(),
        )

    def payload(self):
        return {
            "schema": RUNTIME_SCOPE_SCHEMA,
            "run_id": self.run_id,
            "profile": self.profile,
            "tenancy_id": self.tenancy_id,
            "compartment_id": self.compartment_id,
            "subnet_id": self.subnet_id,
            "availability_domain": self.availability_domain,
            "region": self.region,
            "ui_ledger_path": str(self.ui_ledger_path),
            "network_ledger_path": str(self.network_ledger_path),
        }


@dataclass(frozen=True)
class HarnessConfig:
    run_id: str
    ledger_path: Path
    profile: str
    config_file: Path
    compartment_id: str
    availability_domain: str
    apply: bool
    cleanup: bool
    poll_seconds: int
    timeout_seconds: int
    runtime_scope: RuntimeScope

    @classmethod
    def from_environment(cls, environment=None):
        environment = dict(os.environ if environment is None else environment)
        runtime_scope = RuntimeScope.load(
            _required(environment, "ORACLE_E2E_RUNTIME_SCOPE_FILE"),
            environment=environment,
        )
        run_id = runtime_scope.run_id
        requested = runtime_scope.compartment_id
        profile = runtime_scope.profile
        config_file = _safe_path(
            environment.get("OCI_CLI_CONFIG_FILE", "~/.oci/config"),
            variable="OCI_CLI_CONFIG_FILE",
        )
        try:
            poll_seconds = max(int(environment.get("ORACLE_E2E_POLL_SECONDS", "10")), 2)
            timeout_seconds = max(int(environment.get("ORACLE_E2E_TIMEOUT_SECONDS", "1800")), 60)
        except (TypeError, ValueError) as error:
            raise HarnessError("Oracle E2E wait settings must be integers.") from error
        return cls(
            run_id=run_id,
            ledger_path=runtime_scope.ui_ledger_path,
            profile=profile,
            config_file=config_file,
            compartment_id=requested,
            availability_domain=runtime_scope.availability_domain,
            apply=environment.get("BACKUPSHEEP_E2E_APPLY") == "YES",
            cleanup=environment.get("BACKUPSHEEP_E2E_CLEANUP") == "YES",
            poll_seconds=poll_seconds,
            timeout_seconds=min(timeout_seconds, 7200),
            runtime_scope=runtime_scope,
        )


class OracleLiveUIHarness:
    """Provision exact test sources, verify UI outputs, and clean a run ledger."""

    def __init__(
        self,
        config,
        *,
        environment=None,
        clients=None,
        sleep=time.sleep,
        read_only=False,
    ):
        self.config = config
        self.environment = dict(os.environ if environment is None else environment)
        provided_clients = dict(clients or {})
        self._oci_config = provided_clients.pop("_config", None)
        self._clients = provided_clients
        self._sleep = sleep
        self.read_only = bool(read_only)
        self.names = {
            "source_block_volume": f"{config.run_id}-block-source",
            "source_block_attachment": f"{config.run_id}-block-attachment",
            "source_instance": f"{config.run_id}-boot-source-instance",
            "source_boot_volume": f"{config.run_id}-boot-source",
            "source_vnic": f"{config.run_id}-boot-source-vnic",
            "ui_block_restore_attachment": f"{config.run_id}-block-restore-attachment",
            "ui_boot_verify_instance": f"{config.run_id}-boot-verify-instance",
            "ui_boot_verify_vnic": f"{config.run_id}-boot-verify-vnic",
            "ui_compute_restore_boot_volume": f"{config.run_id}-compute-restore-boot",
            "object_bucket": f"{config.run_id}-objects",
            "iam_user": f"{config.run_id}-s3-user",
            "iam_group": f"{config.run_id}-s3-group",
            "iam_policy": f"{config.run_id}-s3-policy",
            "customer_secret_key": f"{config.run_id}-s3-key",
        }
        scope = (
            f"oci:{config.profile}:{config.compartment_id}:"
            f"{config.availability_domain}"
        )
        durable_paths = {
            config.ledger_path,
            config.ledger_path.with_name(config.ledger_path.name + ".lock"),
            config.ledger_path.with_name(
                config.ledger_path.name + ".oracle-intents.json"
            ),
            config.ledger_path.with_name(
                config.ledger_path.name + ".oracle-intents.json.lock"
            ),
            config.ledger_path.with_name(
                config.ledger_path.name + ".oracle-evidence.json"
            ),
            config.ledger_path.with_name(
                config.ledger_path.name + ".oracle-evidence.json.lock"
            ),
        }
        for path in durable_paths:
            _reject_symlink_components(path, variable="Oracle durable state")
        ledger_class = _ReadOnlyResourceLedger if self.read_only else DurableResourceLedger
        intent_class = _ReadOnlyIntentStore if self.read_only else DurableMutationIntentStore
        self.ledger = ledger_class(
            config.ledger_path,
            provider="oracle_cloud",
            run_id=config.run_id,
            scope=scope,
        )
        self.intents = intent_class(
            config.ledger_path,
            provider="oracle_cloud",
            run_id=config.run_id,
            scope=scope,
            suffix=".oracle-intents.json",
        )
        self.evidence = intent_class(
            config.ledger_path,
            provider="oracle_cloud",
            run_id=config.run_id,
            scope=scope,
            suffix=".oracle-evidence.json",
        )

    def _source_tags(self, kind):
        if kind not in TAGGABLE_SOURCE_KINDS and kind not in {
            "ui_boot_verify_instance",
            "ui_boot_verify_vnic",
            "ui_compute_restore_boot_volume",
        }:
            raise HarnessError("Unsupported Oracle source kind.")
        return {
            E2E_RUN_TAG: self.config.run_id,
            E2E_OWNED_TAG: "true",
            E2E_KIND_TAG: kind,
        }

    def _load_clients(self):
        if self._clients:
            required = {"identity", "compute", "block", "network", "object"}
            if not required.issubset(self._clients):
                raise HarnessError("Injected OCI clients are incomplete.")
            configured = self._oci_config or {}
            if (
                str(configured.get("tenancy") or "")
                != self.config.runtime_scope.tenancy_id
                or str(configured.get("region") or "")
                != self.config.runtime_scope.region
            ):
                raise HarnessError("Injected OCI scope does not match the protected runtime scope.")
            return self._clients
        try:
            import oci

            config = oci.config.from_file(
                file_location=str(self.config.config_file),
                profile_name=self.config.profile,
            )
            oci.config.validate_config(config)
            if (
                str(config.get("tenancy") or "")
                != self.config.runtime_scope.tenancy_id
                or str(config.get("region") or "")
                != self.config.runtime_scope.region
            ):
                raise HarnessError(
                    "OCI profile tenancy/region does not match the protected runtime scope."
                )
            retry = oci.retry.NoneRetryStrategy()
            kwargs = {"timeout": REQUEST_TIMEOUT, "retry_strategy": retry}
            self._clients = {
                "identity": oci.identity.IdentityClient(config, **kwargs),
                "compute": oci.core.ComputeClient(config, **kwargs),
                "block": oci.core.BlockstorageClient(config, **kwargs),
                "network": oci.core.VirtualNetworkClient(config, **kwargs),
                "object": oci.object_storage.ObjectStorageClient(config, **kwargs),
            }
            self._oci_config = {
                "tenancy": str(config.get("tenancy") or ""),
                "region": str(config.get("region") or ""),
            }
        except HarnessError:
            raise
        except Exception as error:
            raise HarnessError(
                f"OCI profile loading failed: {_provider_error_code(error)}."
            ) from error
        return self._clients

    def _models(self):
        try:
            import oci

            return oci.core.models
        except Exception as error:
            raise HarnessError("The OCI Python SDK is required.") from error

    def _call(self, method, *args, accepted=(200,), mutation=False, **kwargs):
        try:
            response = method(*args, **kwargs)
            status = _status(response)
            if status not in set(accepted):
                if (
                    isinstance(status, int)
                    and 400 <= status < 500
                    and status != 408
                ):
                    raise HarnessError(
                        "OCI definitively rejected the bounded request.",
                        code=_provider_error_code(
                            SimpleNamespace(status=status, code="")
                        ),
                        definitive_rejection=True,
                    )
                outcome_unknown = mutation
                if status in {408, 504}:
                    code = "PROVIDER_TIMEOUT"
                elif isinstance(status, int) and status >= 500:
                    code = "PROVIDER_TRANSIENT_OUTAGE"
                else:
                    code = "PROVIDER_REQUEST_FAILED"
                raise HarnessError(
                    "OCI returned an unexpected response status; the mutation "
                    "outcome may be unknown.",
                    code=code,
                    mutation_outcome_unknown=outcome_unknown,
                )
            return response
        except HarnessError:
            raise
        except Exception as error:
            code = _provider_error_code(error)
            outcome = _provider_error_outcome(error)
            definitive = outcome == "definite"
            outcome_unknown = mutation and not definitive
            suffix = " The mutation outcome may be unknown." if outcome_unknown else ""
            raise HarnessError(
                f"OCI request failed: {code}.{suffix}",
                code=code,
                definitive_rejection=definitive,
                mutation_outcome_unknown=outcome_unknown,
            ) from error

    def _require_apply(self):
        if not self.config.apply:
            raise HarnessError(
                "Provider or guest mutations require BACKUPSHEEP_E2E_APPLY=YES."
            )

    def _require_cleanup(self):
        if not self.config.cleanup:
            raise HarnessError(
                "Provider cleanup requires BACKUPSHEEP_E2E_CLEANUP=YES."
            )
        self._require_apply()

    def _validate_scope(self):
        clients = self._load_clients()
        tenancy = str((self._oci_config or {}).get("tenancy") or "")
        region = str((self._oci_config or {}).get("region") or "")
        if (
            tenancy != self.config.runtime_scope.tenancy_id
            or region != self.config.runtime_scope.region
            or self.config.compartment_id != self.config.runtime_scope.compartment_id
            or self.config.availability_domain
            != self.config.runtime_scope.availability_domain
        ):
            raise HarnessError("Oracle scope drifted from the protected runtime artifact.")
        compartment = _data(
            self._call(
                clients["identity"].get_compartment,
                compartment_id=self.config.compartment_id,
            )
        )
        if (
            str(_value(compartment, "id") or "") != self.config.compartment_id
            or str(_value(compartment, "compartment_id") or "") != tenancy
            or str(_value(compartment, "lifecycle_state") or "").upper() != "ACTIVE"
        ):
            raise HarnessError("The explicitly allowed compartment is not active.")

        if tenancy:
            domains = self._list_unpaged(
                clients["identity"].list_availability_domains,
                compartment_id=tenancy,
            )
            matches = [
                item
                for item in domains
                if str(_value(item, "name") or "") == self.config.availability_domain
            ]
            if len(matches) != 1:
                raise HarnessError("The configured availability domain is not exact.")

    def plan(self):
        """Return an inert plan without loading OCI config or making live calls."""

        return {
            "phase": "PLAN",
            "live_calls": False,
            "run_id": self.config.run_id,
            "profile": self.config.profile,
            "compartment_id": self.config.compartment_id,
            "availability_domain": self.config.availability_domain,
            "names": dict(self.names),
            "apply_enabled": self.config.apply,
            "cleanup_enabled": self.config.cleanup,
        }

    @staticmethod
    def inert_plan():
        """Build the CLI plan without reading provider configuration or state."""

        return {
            "phase": "PLAN",
            "live_calls": False,
            "config_loaded": False,
            "profile_loaded": False,
            "ledger_initialized": False,
            "harness_initialized": False,
            "client_initialized": False,
        }

    def _list(self, method, **kwargs):
        try:
            return list(iter_pages(method, **kwargs))
        except HarnessError:
            raise
        except Exception as error:
            raise HarnessError(
                f"OCI inventory failed: {_provider_error_code(error)}."
            ) from error

    def _list_unpaged(self, method, **kwargs):
        rows = _data(self._call(method, **kwargs))
        if not isinstance(rows, (list, tuple)) or len(rows) > MAX_ITEMS:
            raise HarnessError("OCI unpaged inventory is malformed or over limit.")
        return list(rows)

    def _expected_proof(
        self,
        *,
        name,
        tags,
        availability_domain=None,
        source_id="",
    ):
        return {
            "compartment_id": self.config.compartment_id,
            "availability_domain": str(availability_domain or ""),
            "display_name": str(name),
            "tags": {str(key): str(value) for key, value in tags.items()},
            "source_id": str(source_id or ""),
        }

    def _assert_exact(
        self,
        resource,
        *,
        resource_id,
        proof,
        source_id=None,
    ):
        if str(_value(resource, "id") or "") != str(resource_id):
            raise HarnessError("Oracle resource OCID did not match the exact witness.")
        if str(_value(resource, "compartment_id") or "") != proof["compartment_id"]:
            raise HarnessError("Oracle resource escaped the explicitly allowed compartment.")
        if str(_value(resource, "display_name") or "") != proof["display_name"]:
            raise HarnessError("Oracle resource name did not match the exact witness.")
        expected_ad = proof.get("availability_domain") or ""
        if expected_ad and str(_value(resource, "availability_domain") or "") != expected_ad:
            raise HarnessError("Oracle resource availability domain did not match.")
        actual_tags = _tags(resource)
        if any(actual_tags.get(key) != value for key, value in proof["tags"].items()):
            raise HarnessError("Oracle resource ownership tags did not match exactly.")
        exact_tags = proof.get("exact_freeform_tags")
        if exact_tags is not None and actual_tags != exact_tags:
            raise HarnessError("Oracle resource exact freeform tags changed.")
        for field in (
            "instance_id",
            "volume_id",
            "subnet_id",
            "boot_volume_id",
            "device",
        ):
            expected = str(proof.get(field) or "")
            if expected and str(_value(resource, field) or "") != expected:
                raise HarnessError(f"Oracle resource {field} did not match the ledger.")
        expected_source = str(proof.get("source_id") or "")
        actual_source = (
            str(source_id)
            if source_id is not None
            else str(_value(resource, "image_id") or _source_id(resource) or "")
        )
        if expected_source and actual_source != expected_source:
            raise HarnessError("Oracle resource source witness did not match the ledger.")
        return resource

    def _active_ledger_entry(self, kind):
        rows = [
            row
            for row in self.ledger.entries(kind)
            if row.get("cleanup_state") in {"eligible", "failed", "manual_review"}
        ]
        if len(rows) > 1:
            raise HarnessError(f"The Oracle ledger has duplicate {kind} entries.")
        return rows[0] if rows else None

    def _record(
        self,
        kind,
        resource,
        proof,
        *,
        source_witness="",
        source_id=None,
    ):
        if kind not in ALL_KINDS:
            raise HarnessError("Refusing to ledger an unsupported Oracle resource kind.")
        resource_id = _require_ocid(
            _value(resource, "id"), label=f"{kind} provider ID"
        )
        self._assert_exact(
            resource,
            resource_id=resource_id,
            proof=proof,
            source_id=source_id,
        )
        return self.ledger.record(
            kind=kind,
            resource_id=resource_id,
            name=proof["display_name"],
            ownership=proof,
            source_witness=source_witness,
        )

    def _wait_state(self, fetch, *, resource_id, ready, failed):
        deadline = time.monotonic() + self.config.timeout_seconds
        while True:
            resource = _data(fetch(resource_id))
            state = str(_value(resource, "lifecycle_state") or "").upper()
            if state in ready:
                return resource
            if state in failed or not state:
                raise HarnessError("Oracle resource entered a failed lifecycle state.")
            if time.monotonic() >= deadline:
                raise HarnessError("Oracle waiter reached its bounded timeout.")
            self._sleep(self.config.poll_seconds)

    def _find_named(self, method, *, name, tags, **kwargs):
        resources = self._list(method, **kwargs)
        named = [
            item for item in resources if str(_value(item, "display_name") or "") == name
        ]
        exact = [
            item
            for item in named
            if str(_value(item, "compartment_id") or "") == self.config.compartment_id
            and all(_tags(item).get(key) == value for key, value in tags.items())
        ]
        if len(exact) > 1:
            raise HarnessError("Multiple exact Oracle resources matched one run witness.")
        if any(item not in exact for item in named):
            raise HarnessError("A foreign Oracle resource uses the reserved E2E name.")
        return exact[0] if exact else None

    def _put_intent(self, kind, *, operation, name):
        current = self.intents.get(kind)
        if current and not current.get("provider_resource_id"):
            raise HarnessError(
                f"Oracle {kind} has an unresolved durable mutation intent; cleanup or manual review is required."
            )
        return self.intents.put(
            kind,
            {
                "operation": operation,
                "kind": kind,
                "name": name,
                "marker": self.config.run_id,
                "mutation_started_at": time.time(),
            },
        )

    def _bind_intent_resource(self, kind, resource_id):
        resource_id = _require_ocid(resource_id, label=f"{kind} intent OCID")
        self.intents.update(kind, provider_resource_id=resource_id)
        return resource_id

    def _clear_definitely_rejected_intent(self, kind, error):
        """Release only intents whose provider response proves no mutation occurred."""

        if (
            getattr(error, "definitive_rejection", False)
            and not getattr(error, "mutation_outcome_unknown", False)
        ):
            self.intents.clear(kind)

    def _mutation_call(self, intent_key, method, *args, **kwargs):
        """Run an OCI mutation and release only a definitively rejected intent."""

        try:
            return self._call(method, *args, mutation=True, **kwargs)
        except HarnessError as error:
            self._clear_definitely_rejected_intent(intent_key, error)
            raise

    def _source_from_ledger(self, kind, getter, id_argument):
        row = self._active_ledger_entry(kind)
        if not row:
            return None
        try:
            resource = _data(
                self._call(
                    getter,
                    **{id_argument: row["resource_id"]},
                )
            )
        except HarnessError:
            raise HarnessError(
                f"Ledgered Oracle {kind} could not be reverified; no replacement will be created."
            )
        self._assert_exact(
            resource,
            resource_id=row["resource_id"],
            proof=row["ownership"],
        )
        return resource

    def _validate_instance_inputs(self):
        subnet_id = self.config.runtime_scope.subnet_id
        image_id = _require_ocid(
            _required(self.environment, "ORACLE_E2E_IMAGE_OCID"),
            label="ORACLE_E2E_IMAGE_OCID",
            resource_type="image",
        )
        shape = _required(self.environment, "ORACLE_E2E_SHAPE")
        subnet = _data(
            self._call(self._clients["network"].get_subnet, subnet_id=subnet_id)
        )
        if (
            str(_value(subnet, "id") or "") != subnet_id
            or str(_value(subnet, "compartment_id") or "")
            != self.config.compartment_id
            or str(_value(subnet, "lifecycle_state") or "").upper() != "AVAILABLE"
        ):
            raise HarnessError("The supplied subnet is not active in the allowed compartment.")
        image = _data(self._call(self._clients["compute"].get_image, image_id=image_id))
        if (
            str(_value(image, "id") or "") != image_id
            or str(_value(image, "lifecycle_state") or "").upper() != "AVAILABLE"
        ):
            raise HarnessError("The supplied source image is not available.")
        return subnet_id, image_id, shape

    def _provision_block_volume(self):
        client = self._clients["block"]
        existing = self._source_from_ledger(
            "source_block_volume", client.get_volume, "volume_id"
        )
        if existing:
            return existing
        kind = "source_block_volume"
        name = self.names[kind]
        tags = self._source_tags(kind)
        proof = self._expected_proof(
            name=name,
            tags=tags,
            availability_domain=self.config.availability_domain,
        )
        candidate = self._find_named(
            client.list_volumes,
            name=name,
            tags=tags,
            compartment_id=self.config.compartment_id,
            availability_domain=self.config.availability_domain,
            display_name=name,
        )
        if candidate is None:
            try:
                size = int(self.environment.get("ORACLE_E2E_BLOCK_SIZE_GBS", "50"))
            except (TypeError, ValueError) as error:
                raise HarnessError("ORACLE_E2E_BLOCK_SIZE_GBS must be an integer.") from error
            if not 50 <= size <= 32_768:
                raise HarnessError("ORACLE_E2E_BLOCK_SIZE_GBS is outside safe bounds.")
            token = _retry_token(f"{self.config.run_id}:{kind}")
            self._put_intent(kind, operation="create", name=name)
            details = self._models().CreateVolumeDetails(
                availability_domain=self.config.availability_domain,
                compartment_id=self.config.compartment_id,
                display_name=name,
                freeform_tags=tags,
                size_in_gbs=size,
            )
            try:
                response = self._mutation_call(
                    kind,
                    client.create_volume,
                    create_volume_details=details,
                    opc_retry_token=token,
                    accepted=(200, 202),
                )
                candidate = _data(response)
            except HarnessError as error:
                candidate = self._find_named(
                    client.list_volumes,
                    name=name,
                    tags=tags,
                    compartment_id=self.config.compartment_id,
                    availability_domain=self.config.availability_domain,
                    display_name=name,
                )
                if candidate is None:
                    self._clear_definitely_rejected_intent(kind, error)
                    raise
        resource_id = _require_ocid(
            _value(candidate, "id"), label="created block volume", resource_type="volume"
        )
        resource = self._wait_state(
            lambda value: self._call(client.get_volume, volume_id=value),
            resource_id=resource_id,
            ready={"AVAILABLE"},
            failed={"FAULTY", "TERMINATED", "TERMINATING"},
        )
        self._record(kind, resource, proof)
        self.intents.clear(kind)
        return resource

    def _provision_instance(self, subnet_id, image_id, shape):
        client = self._clients["compute"]
        existing = self._source_from_ledger(
            "source_instance", client.get_instance, "instance_id"
        )
        if existing:
            return existing
        kind = "source_instance"
        name = self.names[kind]
        tags = self._source_tags(kind)
        proof = self._expected_proof(
            name=name,
            tags=tags,
            availability_domain=self.config.availability_domain,
            source_id=image_id,
        )
        candidate = self._find_named(
            client.list_instances,
            name=name,
            tags=tags,
            compartment_id=self.config.compartment_id,
            display_name=name,
        )
        if candidate is None:
            token = _retry_token(f"{self.config.run_id}:{kind}")
            _private_key, public_key = self._ensure_ssh_key()
            self._put_intent(kind, operation="create", name=name)
            models = self._models()
            details = models.LaunchInstanceDetails(
                availability_domain=self.config.availability_domain,
                compartment_id=self.config.compartment_id,
                display_name=name,
                freeform_tags=tags,
                shape=shape,
                source_details=models.InstanceSourceViaImageDetails(image_id=image_id),
                metadata={"ssh_authorized_keys": public_key},
                create_vnic_details=models.CreateVnicDetails(
                    assign_public_ip=self._assign_public_ip(),
                    display_name=self.names["source_vnic"],
                    freeform_tags=self._source_tags("source_vnic"),
                    subnet_id=subnet_id,
                ),
            )
            try:
                response = self._mutation_call(
                    kind,
                    client.launch_instance,
                    launch_instance_details=details,
                    opc_retry_token=token,
                    accepted=(200, 202),
                )
                candidate = _data(response)
            except HarnessError as error:
                candidate = self._find_named(
                    client.list_instances,
                    name=name,
                    tags=tags,
                    compartment_id=self.config.compartment_id,
                    display_name=name,
                )
                if candidate is None:
                    self._clear_definitely_rejected_intent(kind, error)
                    raise
        resource_id = _require_ocid(
            _value(candidate, "id"), label="created instance", resource_type="instance"
        )
        resource = self._wait_state(
            lambda value: self._call(client.get_instance, instance_id=value),
            resource_id=resource_id,
            ready={"RUNNING", "STOPPED"},
            failed={"TERMINATED", "TERMINATING"},
        )
        actual_source = str(_value(resource, "image_id") or _source_id(resource))
        if actual_source != image_id:
            raise HarnessError("Created instance image did not match the exact input.")
        self._record(kind, resource, proof, source_witness=image_id)
        self.intents.clear(kind)
        return resource

    def _assign_public_ip(self):
        value = str(self.environment.get("ORACLE_E2E_ASSIGN_PUBLIC_IP", "NO")).upper()
        if value not in {"YES", "NO"}:
            raise HarnessError("ORACLE_E2E_ASSIGN_PUBLIC_IP must be YES or NO.")
        return value == "YES"

    def _key_paths(self):
        private_key = self.config.ledger_path.with_name(
            self.config.ledger_path.name + ".oracle-ssh-key"
        )
        public_key = private_key.with_name(private_key.name + ".pub")
        known_hosts = private_key.with_name(private_key.name + ".known-hosts")
        for path in (private_key, public_key, known_hosts):
            if "_docs" in path.resolve().parts:
                raise HarnessError("Oracle E2E SSH artifacts must not be inside _docs.")
        return private_key, public_key, known_hosts

    @staticmethod
    def _atomic_private_write(path, payload, mode):
        path = Path(path)
        if mode != 0o600:
            raise HarnessError("Protected Oracle files must be created with mode 0600.")
        _reject_symlink_components(path, variable="protected Oracle file")
        if path.exists():
            raise HarnessError("Protected Oracle file already exists; refusing overwrite.")
        return _publish_private_bytes(
            path, bytes(payload), variable="protected Oracle file"
        )

    def _ensure_ssh_key(self):
        private_path, public_path, _known_hosts = self._key_paths()
        if private_path.exists() != public_path.exists():
            raise HarnessError("The run-scoped Oracle SSH key pair is incomplete.")
        if not private_path.exists():
            self._require_apply()
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import rsa

                key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                private_payload = key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.OpenSSH,
                    serialization.NoEncryption(),
                )
                public_payload = key.public_key().public_bytes(
                    serialization.Encoding.OpenSSH,
                    serialization.PublicFormat.OpenSSH,
                ) + b"\n"
                self._atomic_private_write(private_path, private_payload, 0o600)
                self._atomic_private_write(public_path, public_payload, 0o600)
            except HarnessError:
                raise
            except Exception as error:
                raise HarnessError("Could not create the run-scoped SSH key.") from error
        private_path.chmod(0o600)
        public = public_path.read_text(encoding="ascii").strip()
        if not public.startswith("ssh-rsa "):
            raise HarnessError("The run-scoped SSH public key is malformed.")
        return private_path, public

    def _provision_vnic(self, instance):
        kind = "source_vnic"
        existing = self._source_from_ledger(
            kind, self._clients["network"].get_vnic, "vnic_id"
        )
        if existing:
            return existing
        instance_id = str(_value(instance, "id") or "")
        attachments = self._list(
            self._clients["compute"].list_vnic_attachments,
            compartment_id=self.config.compartment_id,
            instance_id=instance_id,
        )
        attachments = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "lifecycle_state") or "").upper() == "ATTACHED"
        ]
        if len(attachments) != 1:
            raise HarnessError("The source instance does not have one exact VNIC.")
        vnic_id = _require_ocid(
            _value(attachments[0], "vnic_id"), label="source VNIC", resource_type="vnic"
        )
        vnic = _data(
            self._call(self._clients["network"].get_vnic, vnic_id=vnic_id)
        )
        proof = self._expected_proof(
            name=self.names[kind],
            tags=self._source_tags(kind),
        )
        proof["subnet_id"] = _require_ocid(
            _value(vnic, "subnet_id"), label="source VNIC subnet", resource_type="subnet"
        )
        self._record(kind, vnic, proof, source_witness=instance_id)
        return vnic

    def _provision_boot_volume(self, instance):
        client = self._clients["block"]
        kind = "source_boot_volume"
        existing = self._source_from_ledger(kind, client.get_boot_volume, "boot_volume_id")
        if existing:
            return existing
        instance_id = str(_value(instance, "id") or "")
        attachments = self._list(
            self._clients["compute"].list_boot_volume_attachments,
            availability_domain=self.config.availability_domain,
            compartment_id=self.config.compartment_id,
            instance_id=instance_id,
        )
        attachments = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "lifecycle_state") or "").upper() == "ATTACHED"
        ]
        if len(attachments) != 1:
            raise HarnessError("The source instance does not have one exact boot volume.")
        boot_id = _require_ocid(
            _value(attachments[0], "boot_volume_id"),
            label="source boot volume",
            resource_type="bootvolume",
        )
        boot = _data(self._call(client.get_boot_volume, boot_volume_id=boot_id))
        if (
            str(_value(boot, "compartment_id") or "") != self.config.compartment_id
            or str(_value(boot, "availability_domain") or "")
            != self.config.availability_domain
        ):
            raise HarnessError("The source boot volume escaped the allowed graph.")
        tags = self._source_tags(kind)
        current_tags = _tags(boot)
        foreign_run = current_tags.get(E2E_RUN_TAG)
        if foreign_run and foreign_run != self.config.run_id:
            raise HarnessError("The source boot volume carries a foreign run tag.")
        if (
            str(_value(boot, "display_name") or "") != self.names[kind]
            or any(current_tags.get(key) != value for key, value in tags.items())
        ):
            self._put_intent(kind, operation="tag", name=self.names[kind])
            details = self._models().UpdateBootVolumeDetails(
                display_name=self.names[kind],
                freeform_tags={**current_tags, **tags},
            )
            self._mutation_call(
                kind,
                client.update_boot_volume,
                boot_volume_id=boot_id,
                update_boot_volume_details=details,
                accepted=(200,),
            )
        boot = self._wait_state(
            lambda value: self._call(client.get_boot_volume, boot_volume_id=value),
            resource_id=boot_id,
            ready={"AVAILABLE"},
            failed={"FAULTY", "TERMINATED", "TERMINATING"},
        )
        proof = self._expected_proof(
            name=self.names[kind],
            tags=tags,
            availability_domain=self.config.availability_domain,
        )
        self._record(kind, boot, proof, source_witness=instance_id)
        self.intents.clear(kind)
        return boot

    def _ledger_compute_restore_boot(self, instance):
        """Tag and ledger the boot volume created with a UI compute restore."""

        kind = "ui_compute_restore_boot_volume"
        existing = self._source_from_ledger(
            kind, self._clients["block"].get_boot_volume, "boot_volume_id"
        )
        if existing:
            return existing
        instance_id = str(_value(instance, "id") or "")
        attachments = self._list(
            self._clients["compute"].list_boot_volume_attachments,
            availability_domain=self.config.availability_domain,
            compartment_id=self.config.compartment_id,
            instance_id=instance_id,
        )
        exact = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "lifecycle_state") or "").upper() == "ATTACHED"
        ]
        if len(exact) != 1:
            raise HarnessError("UI compute restore boot-volume relationship is ambiguous.")
        boot_id = _require_ocid(
            _value(exact[0], "boot_volume_id"),
            label="UI compute restore boot volume",
            resource_type="bootvolume",
        )
        boot = _data(
            self._call(
                self._clients["block"].get_boot_volume,
                boot_volume_id=boot_id,
            )
        )
        tags = self._source_tags(kind)
        current = _tags(boot)
        foreign = current.get(E2E_RUN_TAG)
        if foreign and foreign != self.config.run_id:
            raise HarnessError("UI compute restore boot volume has a foreign run tag.")
        self._put_intent(kind, operation="tag", name=self.names[kind])
        details = self._models().UpdateBootVolumeDetails(
            display_name=self.names[kind],
            freeform_tags={**current, **tags},
        )
        self._mutation_call(
            kind,
            self._clients["block"].update_boot_volume,
            boot_volume_id=boot_id,
            update_boot_volume_details=details,
            accepted=(200,),
        )
        boot = _data(
            self._call(
                self._clients["block"].get_boot_volume,
                boot_volume_id=boot_id,
            )
        )
        proof = self._expected_proof(
            name=self.names[kind],
            tags=tags,
            availability_domain=self.config.availability_domain,
        )
        self._record(kind, boot, proof, source_witness=instance_id)
        self.intents.clear(kind)
        return boot

    def _attach_source_block(self, instance, volume):
        client = self._clients["compute"]
        kind = "source_block_attachment"
        existing = self._source_from_ledger(
            kind, client.get_volume_attachment, "volume_attachment_id"
        )
        if existing:
            return existing
        instance_id = str(_value(instance, "id") or "")
        volume_id = str(_value(volume, "id") or "")
        attachments = self._list(
            client.list_volume_attachments,
            compartment_id=self.config.compartment_id,
            instance_id=instance_id,
            volume_id=volume_id,
        )
        attachments = [
            item
            for item in attachments
            if str(_value(item, "lifecycle_state") or "").upper() != "DETACHED"
        ]
        device = self._require_attachment_device(
            instance_id, SOURCE_BLOCK_DEVICE
        )
        matching = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "volume_id") or "") == volume_id
            and str(_value(item, "display_name") or "") == self.names[kind]
            and str(_value(item, "device") or "") == device
        ]
        if len(matching) > 1 or any(item not in matching for item in attachments):
            raise HarnessError("The source block-volume attachment is ambiguous.")
        candidate = matching[0] if matching else None
        if candidate is None:
            self._put_intent(kind, operation="attach", name=self.names[kind])
            details = self._models().AttachParavirtualizedVolumeDetails(
                display_name=self.names[kind],
                instance_id=instance_id,
                is_read_only=False,
                is_shareable=False,
                device=device,
                volume_id=volume_id,
            )
            try:
                candidate = _data(
                    self._mutation_call(
                        kind,
                        client.attach_volume,
                        attach_volume_details=details,
                        accepted=(200, 202),
                    )
                )
            except HarnessError as error:
                attachments = self._list(
                    client.list_volume_attachments,
                    compartment_id=self.config.compartment_id,
                    instance_id=instance_id,
                    volume_id=volume_id,
                )
                attachments = [
                    item
                    for item in attachments
                    if str(_value(item, "lifecycle_state") or "").upper()
                    != "DETACHED"
                ]
                matching = [
                    item
                    for item in attachments
                    if str(_value(item, "instance_id") or "") == instance_id
                    and str(_value(item, "volume_id") or "") == volume_id
                    and str(_value(item, "display_name") or "") == self.names[kind]
                    and str(_value(item, "device") or "") == device
                ]
                if len(matching) != 1:
                    if not matching:
                        self._clear_definitely_rejected_intent(kind, error)
                    raise
                candidate = matching[0]
        attachment_id = _require_ocid(
            _value(candidate, "id"),
            label="source block attachment",
            resource_type="volumeattachment",
        )
        attachment = self._wait_state(
            lambda value: self._call(
                client.get_volume_attachment, volume_attachment_id=value
            ),
            resource_id=attachment_id,
            ready={"ATTACHED"},
            failed={"DETACHED", "DETACHING"},
        )
        proof = self._expected_proof(name=self.names[kind], tags={})
        proof.update(
            {"instance_id": instance_id, "volume_id": volume_id, "device": device}
        )
        self._record(
            kind,
            attachment,
            proof,
            source_witness=f"{instance_id}:{volume_id}",
        )
        self.intents.clear(kind)
        return attachment

    def _require_attachment_device(self, instance_id, expected):
        if expected not in {SOURCE_BLOCK_DEVICE, RESTORE_BLOCK_DEVICE}:
            raise HarnessError("Oracle attachment device is outside the safe allowlist.")
        devices = self._list_unpaged(
            self._clients["compute"].list_instance_devices,
            instance_id=instance_id,
        )
        matches = [
            item for item in devices if str(_value(item, "name") or "") == expected
        ]
        if len(matches) != 1 or _value(matches[0], "is_available") is not True:
            raise HarnessError(
                "The exact consistent Oracle attachment device is not available."
            )
        return expected

    def _payload(self):
        try:
            byte_count = int(self.environment.get("ORACLE_E2E_DATA_BYTES", "1048576"))
        except (TypeError, ValueError) as error:
            raise HarnessError("ORACLE_E2E_DATA_BYTES must be an integer.") from error
        if not 4096 <= byte_count <= 64 * 1024 * 1024:
            raise HarnessError("ORACLE_E2E_DATA_BYTES is outside safe bounds.")
        chunks = []
        remaining = byte_count
        counter = 0
        while remaining:
            chunk = hashlib.sha256(
                f"{self.config.run_id}:oracle-e2e:{counter}".encode("utf-8")
            ).digest()
            chunks.append(chunk[:remaining])
            remaining -= min(len(chunk), remaining)
            counter += 1
        payload = b"".join(chunks)
        return payload, hashlib.sha256(payload).hexdigest(), byte_count

    def _ssh_client(self, vnic, *, host_variable="ORACLE_E2E_SSH_HOST"):
        try:
            import paramiko
        except Exception as error:
            raise HarnessError("Paramiko is required for Oracle data verification.") from error
        private_path, _public = self._ensure_ssh_key()
        _private, _public_path, known_hosts = self._key_paths()
        addresses = {
            str(_value(vnic, "public_ip") or "").strip(),
            str(_value(vnic, "private_ip") or "").strip(),
        } - {""}
        configured_host = str(
            self.environment.get(host_variable)
            or self.environment.get("ORACLE_E2E_SSH_HOST")
            or ""
        ).strip()
        host = configured_host or str(_value(vnic, "public_ip") or "").strip()
        if not host:
            host = str(_value(vnic, "private_ip") or "").strip()
        if not host or host not in addresses:
            raise HarnessError("SSH host must be an exact provider-reported VNIC address.")
        user = _required(self.environment, "ORACLE_E2E_SSH_USER")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise HarnessError("ORACLE_E2E_SSH_USER is malformed.")
        client = paramiko.SSHClient()
        if known_hosts.exists():
            client.load_host_keys(str(known_hosts))
        first_connection = host not in client.get_host_keys()
        if first_connection:
            # This is trust-on-first-use for a fresh, exact-OCID test instance.
            # Only deterministic non-secret test bytes traverse this connection.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            key = paramiko.RSAKey.from_private_key_file(str(private_path))
            client.connect(
                hostname=host,
                username=user,
                pkey=key,
                allow_agent=False,
                look_for_keys=False,
                timeout=REQUEST_TIMEOUT[0],
                banner_timeout=REQUEST_TIMEOUT[1],
                auth_timeout=REQUEST_TIMEOUT[1],
            )
            if first_connection:
                known_hosts.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                client.save_host_keys(str(known_hosts))
                known_hosts.chmod(0o600)
            return client
        except Exception as error:
            client.close()
            raise HarnessError("SSH connection to the exact test VNIC failed.") from error

    @staticmethod
    def _ssh_run(client, command):
        try:
            _stdin, stdout, _stderr = client.exec_command(command, timeout=60)
            payload = stdout.read(4096).decode("utf-8", "strict").strip()
            status = stdout.channel.recv_exit_status()
        except Exception as error:
            raise HarnessError("Remote data command failed.") from error
        if status != 0:
            raise HarnessError("Remote data command returned a non-zero status.")
        return payload

    def _upload_payload(self, client, payload):
        remote = f"/tmp/{self.config.run_id}-oracle-payload.bin"
        try:
            sftp = client.open_sftp()
            with sftp.file(remote, "wb") as target:
                target.write(payload)
                target.flush()
            sftp.close()
        except Exception as error:
            raise HarnessError("Could not upload deterministic Oracle test bytes.") from error
        return remote

    def _mount_volume(self, client, attachment, *, mount_path, read_only):
        device = str(_value(attachment, "device") or "")
        if not re.fullmatch(r"/dev/[A-Za-z0-9_./-]{1,120}", device) or ".." in device:
            raise HarnessError("OCI did not return a safe attached-volume device path.")
        quoted_device = shlex.quote(device)
        quoted_mount = shlex.quote(mount_path)
        deadline = time.monotonic() + min(self.config.timeout_seconds, 300)
        while True:
            try:
                self._ssh_run(client, f"sudo test -b {quoted_device}")
                break
            except HarnessError:
                if time.monotonic() >= deadline:
                    raise HarnessError(
                        "The exact OCI attachment device did not appear within the bounded waiter."
                    )
                self._sleep(self.config.poll_seconds)
        filesystem = self._ssh_run(
            client, f"sudo lsblk -no FSTYPE {quoted_device} | head -n 1"
        )
        if read_only:
            if filesystem != "ext4":
                raise HarnessError("Restored block volume does not contain the expected ext4 filesystem.")
        elif not filesystem:
            self._ssh_run(client, f"sudo mkfs.ext4 -F {quoted_device} >/dev/null")
        elif filesystem != "ext4":
            raise HarnessError("Source block volume contains an unexpected filesystem.")
        self._ssh_run(client, f"sudo mkdir -p {quoted_mount}")
        option = "-o ro,noload" if read_only else ""
        self._ssh_run(
            client,
            "if ! mountpoint -q {mount}; then sudo mount {option} {device} {mount}; fi".format(
                mount=quoted_mount,
                option=option,
                device=quoted_device,
            ),
        )
        actual = self._ssh_run(
            client, f"findmnt -n -o SOURCE --target {quoted_mount}"
        )
        if not actual.startswith("/dev/"):
            raise HarnessError("Mounted Oracle volume could not be tied to a block device.")
        expected_real = self._ssh_run(client, f"readlink -f {quoted_device}")
        actual_real = self._ssh_run(client, f"readlink -f {shlex.quote(actual)}")
        if expected_real != actual_real:
            raise HarnessError("Mounted filesystem is not the exact OCI attachment device.")

    def _remote_evidence(self, client, path):
        quoted = shlex.quote(path)
        digest = self._ssh_run(client, f"sudo sha256sum {quoted} | cut -d' ' -f1")
        size = self._ssh_run(client, f"sudo stat -c %s {quoted}")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise HarnessError("Remote SHA-256 evidence was malformed.")
        try:
            byte_count = int(size)
        except (TypeError, ValueError) as error:
            raise HarnessError("Remote byte-count evidence was malformed.") from error
        return {"sha256": digest, "byte_count": byte_count}

    def _seed_data(self, vnic, source_attachment, *, instance_id, block_volume_id, boot_volume_id):
        payload, expected_sha256, expected_bytes = self._payload()
        client = self._ssh_client(vnic, host_variable="ORACLE_E2E_SOURCE_SSH_HOST")
        boot_path = f"/var/lib/backupsheep-e2e/{self.config.run_id}/payload.bin"
        mount_path = f"/mnt/backupsheep-e2e-{self.config.run_id}"
        block_path = f"{mount_path}/payload.bin"
        try:
            remote = self._upload_payload(client, payload)
            self._ssh_run(
                client,
                f"sudo mkdir -p {shlex.quote(str(Path(boot_path).parent))}",
            )
            self._ssh_run(
                client,
                f"sudo install -m 0600 {shlex.quote(remote)} {shlex.quote(boot_path)}",
            )
            self._mount_volume(
                client,
                source_attachment,
                mount_path=mount_path,
                read_only=False,
            )
            self._ssh_run(
                client,
                f"sudo install -m 0600 {shlex.quote(remote)} {shlex.quote(block_path)}",
            )
            self._ssh_run(client, "sudo sync")
            boot = self._remote_evidence(client, boot_path)
            block = self._remote_evidence(client, block_path)
        finally:
            client.close()
        expected = {"sha256": expected_sha256, "byte_count": expected_bytes}
        if boot != expected or block != expected:
            raise HarnessError("Seeded Oracle data did not match local hash evidence.")
        evidence = {
            "operation": "evidence",
            "kind": "payload",
            "name": self.config.run_id,
            "marker": self.config.run_id,
            "sha256": expected_sha256,
            "byte_count": expected_bytes,
            "boot_path": boot_path,
            "block_path": block_path,
            "source_instance_ocid": instance_id,
            "source_block_volume_ocid": block_volume_id,
            "source_boot_volume_ocid": boot_volume_id,
            "filesystem_flushed": True,
        }
        self.evidence.put("payload", evidence)
        return evidence

    def _storage_context(self):
        config = self._oci_config or {}
        tenancy_id = _require_ocid(
            config.get("tenancy"), label="OCI profile tenancy", resource_type="tenancy"
        )
        allowed_tenancy = _require_ocid(
            _required(self.environment, "ORACLE_E2E_ALLOWED_TENANCY_OCID"),
            label="ORACLE_E2E_ALLOWED_TENANCY_OCID",
            resource_type="tenancy",
        )
        if tenancy_id != allowed_tenancy:
            raise HarnessError("OCI profile tenancy does not match the explicit allowlist.")
        region = str(config.get("region") or "").strip()
        if not re.fullmatch(r"[a-z0-9-]{3,64}", region):
            raise HarnessError("OCI profile region is malformed.")
        namespace_response = self._call(
            self._clients["object"].get_namespace,
            compartment_id=tenancy_id,
        )
        namespace = str(_data(namespace_response) or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", namespace):
            raise HarnessError("OCI Object Storage namespace is malformed.")
        return tenancy_id, region, namespace

    def _storage_tags(self, kind):
        return {
            E2E_RUN_TAG: self.config.run_id,
            E2E_OWNED_TAG: "true",
            E2E_KIND_TAG: kind,
        }

    def _record_storage(
        self,
        kind,
        resource,
        *,
        resource_id,
        name,
        compartment_id,
        tags=None,
        relationships=None,
    ):
        if kind not in STORAGE_KINDS:
            raise HarnessError("Unsupported Oracle storage-ledger kind.")
        if kind == "customer_secret_key":
            resource_id = _require_customer_secret_key_id(resource_id)
        else:
            resource_id = _require_ocid(resource_id, label=f"{kind} OCID")
        if str(_value(resource, "id") or "") != resource_id:
            raise HarnessError("OCI IAM/Object Storage OCID did not match.")
        if name and str(
            _value(resource, "name")
            or _value(resource, "display_name")
            or ""
        ) != name:
            raise HarnessError("OCI IAM/Object Storage name did not match.")
        if compartment_id and str(_value(resource, "compartment_id") or "") != compartment_id:
            raise HarnessError("OCI IAM/Object Storage compartment did not match.")
        expected_tags = {str(key): str(value) for key, value in (tags or {}).items()}
        if expected_tags and any(
            _tags(resource).get(key) != value for key, value in expected_tags.items()
        ):
            raise HarnessError("OCI IAM/Object Storage ownership tags did not match.")
        for field, expected in (relationships or {}).items():
            if str(_value(resource, field) or "") != str(expected):
                raise HarnessError(f"OCI {kind} {field} relationship did not match.")
        ownership = {
            "compartment_id": str(compartment_id or ""),
            "name": str(name or ""),
            "tags": expected_tags,
            "relationships": {
                str(key): str(value) for key, value in (relationships or {}).items()
            },
        }
        return self.ledger.record(
            kind=kind,
            resource_id=resource_id,
            name=name,
            ownership=ownership,
            source_witness=json.dumps(ownership["relationships"], sort_keys=True),
        )

    def _find_identity_named(self, method, *, compartment_id, name, tags):
        rows = self._list(method, compartment_id=compartment_id, name=name)
        named = [row for row in rows if str(_value(row, "name") or "") == name]
        exact = [
            row
            for row in named
            if str(_value(row, "compartment_id") or "") == compartment_id
            and all(_tags(row).get(key) == value for key, value in tags.items())
        ]
        if len(exact) > 1:
            raise HarnessError("Multiple exact OCI IAM resources matched one witness.")
        if any(row not in exact for row in named):
            raise HarnessError("A foreign OCI IAM resource uses the reserved name.")
        return exact[0] if exact else None

    def _provision_iam_named(
        self,
        *,
        kind,
        tenancy_id,
        list_method,
        create_method,
        details_class,
    ):
        row = self._active_ledger_entry(kind)
        getter = getattr(self._clients["identity"], f"get_{kind.removeprefix('iam_')}")
        id_argument = f"{kind.removeprefix('iam_')}_id"
        tags = self._storage_tags(kind)
        name = self.names[kind]
        if row:
            resource = _data(self._call(getter, **{id_argument: row["resource_id"]}))
            self._record_storage(
                kind,
                resource,
                resource_id=row["resource_id"],
                name=name,
                compartment_id=tenancy_id,
                tags=tags,
            )
            return resource
        candidate = self._find_identity_named(
            list_method,
            compartment_id=tenancy_id,
            name=name,
            tags=tags,
        )
        if candidate is None:
            self._put_intent(kind, operation="create", name=name)
            details_kwargs = {
                "compartment_id": tenancy_id,
                "description": f"BackupSheep live E2E {self.config.run_id}",
                "freeform_tags": tags,
                "name": name,
            }
            if kind == "iam_user":
                # Tenancies backed by OCI Identity Domains require a primary
                # email.  ``example.invalid`` is reserved and cannot deliver
                # mail, while remaining deterministic for crash adoption.
                details_kwargs["email"] = f"{self.config.run_id}@example.invalid"
            details = details_class(**details_kwargs)
            try:
                candidate = _data(
                    self._mutation_call(
                        kind,
                        create_method,
                        **{f"create_{kind.removeprefix('iam_')}_details": details},
                        opc_retry_token=_retry_token(f"{self.config.run_id}:{kind}"),
                        accepted=(200,),
                    )
                )
            except HarnessError as error:
                candidate = self._find_identity_named(
                    list_method,
                    compartment_id=tenancy_id,
                    name=name,
                    tags=tags,
                )
                if candidate is None:
                    self._clear_definitely_rejected_intent(kind, error)
                    raise
        resource_id = _require_ocid(_value(candidate, "id"), label=f"{kind} OCID")
        candidate = _data(self._call(getter, **{id_argument: resource_id}))
        self._record_storage(
            kind,
            candidate,
            resource_id=resource_id,
            name=name,
            compartment_id=tenancy_id,
            tags=tags,
        )
        self.intents.clear(kind)
        return candidate

    def _provision_bucket(self, namespace):
        kind = "object_bucket"
        client = self._clients["object"]
        tags = self._storage_tags(kind)
        name = self.names[kind]
        row = self._active_ledger_entry(kind)
        if row:
            bucket = _data(
                self._call(client.get_bucket, namespace_name=namespace, bucket_name=name)
            )
            self._record_storage(
                kind,
                bucket,
                resource_id=row["resource_id"],
                name=name,
                compartment_id=self.config.compartment_id,
                tags=tags,
            )
            return bucket
        buckets = self._list(
            client.list_buckets,
            namespace_name=namespace,
            compartment_id=self.config.compartment_id,
        )
        named = [item for item in buckets if str(_value(item, "name") or "") == name]
        exact = [
            item
            for item in named
            if str(_value(item, "compartment_id") or "") == self.config.compartment_id
            and all(_tags(item).get(key) == value for key, value in tags.items())
        ]
        if len(exact) > 1 or any(item not in exact for item in named):
            raise HarnessError("The reserved OCI bucket name is ambiguous or foreign.")
        bucket = exact[0] if exact else None
        if bucket is None:
            # Object Storage models live in another SDK namespace.
            import oci

            details = oci.object_storage.models.CreateBucketDetails(
                compartment_id=self.config.compartment_id,
                freeform_tags=tags,
                name=name,
                public_access_type=oci.object_storage.models.CreateBucketDetails.PUBLIC_ACCESS_TYPE_NO_PUBLIC_ACCESS,
                storage_tier=oci.object_storage.models.CreateBucketDetails.STORAGE_TIER_STANDARD,
                versioning=oci.object_storage.models.CreateBucketDetails.VERSIONING_ENABLED,
            )
            self._put_intent(kind, operation="create", name=name)
            try:
                bucket = _data(
                    self._mutation_call(
                        kind,
                        client.create_bucket,
                        namespace_name=namespace,
                        create_bucket_details=details,
                        opc_client_request_id=_retry_token(f"{self.config.run_id}:{kind}"),
                        accepted=(200,),
                    )
                )
            except HarnessError as error:
                buckets = self._list(
                    client.list_buckets,
                    namespace_name=namespace,
                    compartment_id=self.config.compartment_id,
                )
                exact = [
                    item
                    for item in buckets
                    if str(_value(item, "name") or "") == name
                    and all(_tags(item).get(key) == value for key, value in tags.items())
                ]
                if len(exact) != 1:
                    if not exact:
                        self._clear_definitely_rejected_intent(kind, error)
                    raise
                bucket = exact[0]
        bucket = _data(
            self._call(client.get_bucket, namespace_name=namespace, bucket_name=name)
        )
        bucket_id = _require_ocid(_value(bucket, "id"), label="bucket OCID", resource_type="bucket")
        if str(_value(bucket, "versioning") or "").upper() != "ENABLED":
            raise HarnessError("The test bucket must have versioning enabled.")
        self._record_storage(
            kind,
            bucket,
            resource_id=bucket_id,
            name=name,
            compartment_id=self.config.compartment_id,
            tags=tags,
        )
        self.intents.clear(kind)
        return bucket

    def _provision_membership(self, tenancy_id, user, group):
        kind = "iam_membership"
        user_id = str(_value(user, "id") or "")
        group_id = str(_value(group, "id") or "")
        row = self._active_ledger_entry(kind)
        if row:
            membership = _data(
                self._call(
                    self._clients["identity"].get_user_group_membership,
                    user_group_membership_id=row["resource_id"],
                )
            )
        else:
            memberships = self._list(
                self._clients["identity"].list_user_group_memberships,
                compartment_id=tenancy_id,
                user_id=user_id,
                group_id=group_id,
            )
            exact = [
                item
                for item in memberships
                if str(_value(item, "user_id") or "") == user_id
                and str(_value(item, "group_id") or "") == group_id
                and str(_value(item, "lifecycle_state") or "").upper() == "ACTIVE"
            ]
            if len(exact) > 1 or any(item not in exact for item in memberships):
                raise HarnessError("OCI IAM group membership is ambiguous.")
            membership = exact[0] if exact else None
            if membership is None:
                import oci

                self._put_intent(kind, operation="create", name=kind)
                details = oci.identity.models.AddUserToGroupDetails(
                    group_id=group_id,
                    user_id=user_id,
                )
                try:
                    membership = _data(
                        self._mutation_call(
                            kind,
                            self._clients["identity"].add_user_to_group,
                            add_user_to_group_details=details,
                            opc_retry_token=_retry_token(f"{self.config.run_id}:{kind}"),
                            accepted=(200,),
                        )
                    )
                except HarnessError as error:
                    memberships = self._list(
                        self._clients["identity"].list_user_group_memberships,
                        compartment_id=tenancy_id,
                        user_id=user_id,
                        group_id=group_id,
                    )
                    exact = [
                        item
                        for item in memberships
                        if str(_value(item, "user_id") or "") == user_id
                        and str(_value(item, "group_id") or "") == group_id
                    ]
                    if len(exact) != 1:
                        if not exact:
                            self._clear_definitely_rejected_intent(kind, error)
                        raise
                    membership = exact[0]
        membership_id = _require_ocid(
            _value(membership, "id"), label="IAM membership OCID"
        )
        self._record_storage(
            kind,
            membership,
            resource_id=membership_id,
            name="",
            compartment_id=tenancy_id,
            relationships={"user_id": user_id, "group_id": group_id},
        )
        self.intents.clear(kind)
        return membership

    def _policy_statements(self, group_name):
        bucket_name = self.names["object_bucket"]
        compartment = self.config.compartment_id
        return [
            f"Allow group {group_name} to inspect buckets in compartment id {compartment}",
            (
                f"Allow group {group_name} to manage objects in compartment id "
                f"{compartment} where target.bucket.name = '{bucket_name}'"
            ),
        ]

    def _provision_policy(self, group):
        kind = "iam_policy"
        client = self._clients["identity"]
        name = self.names[kind]
        group_name = str(_value(group, "name") or "")
        statements = self._policy_statements(group_name)
        tags = self._storage_tags(kind)
        row = self._active_ledger_entry(kind)
        if row:
            policy = _data(self._call(client.get_policy, policy_id=row["resource_id"]))
        else:
            policy = self._find_identity_named(
                client.list_policies,
                compartment_id=self.config.compartment_id,
                name=name,
                tags=tags,
            )
            if policy is None:
                import oci

                self._put_intent(kind, operation="create", name=name)
                details = oci.identity.models.CreatePolicyDetails(
                    compartment_id=self.config.compartment_id,
                    description=f"BackupSheep live E2E {self.config.run_id}",
                    freeform_tags=tags,
                    name=name,
                    statements=statements,
                )
                try:
                    policy = _data(
                        self._mutation_call(
                            kind,
                            client.create_policy,
                            create_policy_details=details,
                            opc_retry_token=_retry_token(f"{self.config.run_id}:{kind}"),
                            accepted=(200,),
                        )
                    )
                except HarnessError as error:
                    policy = self._find_identity_named(
                        client.list_policies,
                        compartment_id=self.config.compartment_id,
                        name=name,
                        tags=tags,
                    )
                    if policy is None:
                        self._clear_definitely_rejected_intent(kind, error)
                        raise
        policy_id = _require_ocid(_value(policy, "id"), label="IAM policy OCID")
        policy = _data(self._call(client.get_policy, policy_id=policy_id))
        if list(_value(policy, "statements") or []) != statements:
            raise HarnessError("OCI IAM policy statements did not match exactly.")
        self._record_storage(
            kind,
            policy,
            resource_id=policy_id,
            name=name,
            compartment_id=self.config.compartment_id,
            tags=tags,
        )
        self.intents.clear(kind)
        return policy

    def _secret_path(self):
        configured = self.environment.get("ORACLE_E2E_SECRET_FILE")
        if configured:
            raw_path = Path(configured).expanduser()
            variable = "ORACLE_E2E_SECRET_FILE"
        else:
            raw_path = self.config.ledger_path.with_name(
                self.config.ledger_path.name + ".oracle-object-storage-credentials.json"
            )
            variable = "ORACLE_E2E_SECRET_FILE"
        self._reject_secret_symlink_components(raw_path, variable=variable)
        path = _safe_path(raw_path, variable=variable)
        self._reject_secret_symlink_components(path, variable=variable)
        try:
            relative = path.relative_to(ROOT)
        except ValueError:
            return path
        if relative.parts and relative.parts[0] == ".git":
            return path
        ignored = subprocess.run(
            ["git", "check-ignore", "--quiet", "--", str(path)],
            cwd=ROOT,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0
        if not ignored:
            raise HarnessError(
                "ORACLE_E2E_SECRET_FILE must be outside the repository or Git-ignored."
            )
        return path

    @staticmethod
    def _reject_secret_symlink_components(path, *, variable):
        """Reject symlink indirection before resolving a secret path."""

        absolute = Path(os.path.abspath(os.fspath(path)))
        current = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            current /= component
            try:
                if current.is_symlink():
                    raise HarnessError(f"{variable} must not use symlinked path components.")
            except OSError as error:
                raise HarnessError(f"{variable} could not be inspected safely.") from error

    @staticmethod
    def _storage_endpoint(namespace, region):
        return f"https://{namespace}.compat.objectstorage.{region}.oraclecloud.com"

    def _storage_scope(self, *, bucket_name, namespace, region, user_ocid):
        tenancy_id = _require_ocid(
            self.config.runtime_scope.tenancy_id,
            label="OCI profile tenancy",
            resource_type="tenancy",
        )
        configured_tenancy = str((self._oci_config or {}).get("tenancy") or "")
        if configured_tenancy and configured_tenancy != tenancy_id:
            raise HarnessError("OCI profile tenancy drifted from the protected runtime scope.")
        compartment_id = _require_ocid(
            self.config.compartment_id,
            label="Oracle E2E compartment",
            resource_type="compartment",
        )
        user_ocid = _require_ocid(
            user_ocid,
            label="OCI storage user",
            resource_type="user",
        )
        namespace = str(namespace or "").strip()
        region = str(region or "").strip()
        bucket_name = str(bucket_name or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", namespace):
            raise HarnessError("OCI Object Storage namespace is malformed.")
        if not re.fullmatch(r"[a-z0-9-]{3,64}", region):
            raise HarnessError("OCI profile region is malformed.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,254}", bucket_name):
            raise HarnessError("OCI Object Storage bucket name is malformed.")
        return {
            "bucket": bucket_name,
            "namespace": namespace,
            "region": region,
            "endpoint": self._storage_endpoint(namespace, region),
            "prefix": f"{self.config.run_id}/",
            "user_ocid": user_ocid,
            "tenancy_ocid": tenancy_id,
            "compartment_ocid": compartment_id,
        }

    def _assert_storage_scope_ledger(self, expected, *, require_evidence=True):
        """Require storage scope to match both durable witnesses and config."""

        if set(expected) != STORAGE_SCOPE_KEYS:
            raise HarnessError("Oracle storage scope is incomplete.")
        bucket_row = self._active_ledger_entry("object_bucket")
        user_row = self._active_ledger_entry("iam_user")
        if not bucket_row or not user_row:
            raise HarnessError(
                "Oracle storage scope lacks durable bucket and IAM-user witnesses."
            )
        if (
            str(bucket_row.get("name") or "") != expected["bucket"]
            or str((bucket_row.get("ownership") or {}).get("compartment_id") or "")
            != expected["compartment_ocid"]
            or str(user_row.get("resource_id") or "") != expected["user_ocid"]
            or str((user_row.get("ownership") or {}).get("compartment_id") or "")
            != expected["tenancy_ocid"]
        ):
            raise HarnessError("Oracle storage scope does not match durable ownership witnesses.")
        if require_evidence:
            durable = self.evidence.get("storage_scope")
            if not isinstance(durable, dict) or any(
                str(durable.get(field) or "") != str(expected[field])
                for field in STORAGE_SCOPE_KEYS
            ):
                raise HarnessError(
                    "Oracle storage scope does not match durable configuration evidence."
                )
        return expected

    def _storage_ledger_witness(self, kind):
        """Return only immutable, non-secret ownership fields for one exact row."""

        if kind not in {"object_bucket", "iam_user", "customer_secret_key"}:
            raise HarnessError("Unsupported Oracle storage-scope witness kind.")
        row = self._active_ledger_entry(kind)
        if not isinstance(row, dict):
            raise HarnessError(f"Oracle storage scope lacks the exact {kind} row.")
        ownership = row.get("ownership")
        if not isinstance(ownership, dict) or not ownership:
            raise HarnessError("Oracle storage ownership witness is malformed.")
        witness = {
            "kind": kind,
            "resource_id": str(row.get("resource_id") or ""),
            "name": str(row.get("name") or ""),
            "ownership": ownership,
            "source_witness": str(row.get("source_witness") or ""),
        }
        if set(witness) != STORAGE_LEDGER_WITNESS_KEYS:
            raise HarnessError("Oracle storage ownership witness is incomplete.")
        _assert_no_credential_fields(witness, path=f"storage_scope.{kind}")
        if kind == "customer_secret_key":
            _require_customer_secret_key_id(witness["resource_id"])
        else:
            _require_ocid(witness["resource_id"], label=f"{kind} ledger ID")
        return json.loads(json.dumps(witness, sort_keys=True))

    def _storage_scope_identity(self, scope, witnesses):
        if set(scope) != STORAGE_SCOPE_KEYS or set(witnesses) != {
            "bucket_witness",
            "user_witness",
            "customer_secret_witness",
        }:
            raise HarnessError("Oracle storage immutable scope identity is incomplete.")
        identity = {
            "run_id": self.config.run_id,
            "profile": self.config.runtime_scope.profile,
            "tenancy_id": self.config.runtime_scope.tenancy_id,
            "compartment_id": self.config.runtime_scope.compartment_id,
            "region": self.config.runtime_scope.region,
            "storage_scope": scope,
            **witnesses,
        }
        return hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _storage_scope_witnesses(self):
        return {
            "bucket_witness": self._storage_ledger_witness("object_bucket"),
            "user_witness": self._storage_ledger_witness("iam_user"),
            "customer_secret_witness": self._storage_ledger_witness(
                "customer_secret_key"
            ),
        }

    def _persist_storage_scope(self, expected):
        """Persist the non-secret S3 scope before any S3 client is created."""

        self._assert_storage_scope_ledger(expected, require_evidence=False)
        current = self.evidence.get("storage_scope")
        if current and any(
            str(current.get(field) or "") != str(expected[field])
            for field in STORAGE_SCOPE_KEYS
        ):
            raise HarnessError("Oracle storage scope changed across resumptions.")
        self.evidence.put(
            "storage_scope",
            {
                "operation": "evidence",
                "kind": "storage_scope",
                "name": expected["bucket"],
                "marker": self.config.run_id,
                **expected,
            },
        )
        return expected

    def _validate_storage_secret_payload(self, payload):
        if not isinstance(payload, dict) or set(payload) != STORAGE_SECRET_KEYS:
            raise HarnessError(
                "Oracle storage credential file contains an unsupported or incomplete key set."
            )
        for field in STORAGE_SECRET_KEYS:
            if not isinstance(payload.get(field), str) or not payload[field].strip():
                raise HarnessError("Oracle storage credential file contains an invalid value.")
        _require_customer_secret_key_id(payload["access_key_id"])
        _require_ocid(payload["user_ocid"], label="OCI storage user", resource_type="user")
        _require_ocid(
            payload["tenancy_ocid"], label="OCI storage tenancy", resource_type="tenancy"
        )
        _require_ocid(
            payload["compartment_ocid"],
            label="OCI storage compartment",
            resource_type="compartment",
        )
        parsed = urlsplit(payload["endpoint"])
        expected_endpoint = self._storage_endpoint(
            payload["namespace"], payload["region"]
        )
        if (
            payload["endpoint"] != expected_endpoint
            or parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise HarnessError("Oracle storage credential endpoint is not canonical.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", payload["namespace"]):
            raise HarnessError("Oracle storage credential namespace is malformed.")
        if not re.fullmatch(r"[a-z0-9-]{3,64}", payload["region"]):
            raise HarnessError("Oracle storage credential region is malformed.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,254}", payload["bucket"]):
            raise HarnessError("Oracle storage credential bucket is malformed.")
        if payload["prefix"] != f"{self.config.run_id}/":
            raise HarnessError("Oracle storage credential prefix is not run-scoped.")
        return dict(payload)

    def _write_storage_secret(self, payload):
        path = self._secret_path()
        self._validate_storage_secret_payload(payload)
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        self._atomic_private_write(path, encoded, 0o600)
        try:
            mode = stat.S_IMODE(path.lstat().st_mode)
        except OSError as error:
            raise HarnessError("Oracle storage credential file could not be verified.") from error
        if (
            not stat.S_ISREG(path.lstat().st_mode)
            or mode != 0o600
            or path.is_symlink()
        ):
            raise HarnessError("Oracle storage credential file permissions are unsafe.")
        return path

    def _read_storage_secret(self, *, expected_scope=None, require_evidence=True):
        """Load one exact, non-symlinked, scope-bound credential document."""

        path = self._secret_path()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise HarnessError("Oracle storage credential file could not be inspected.") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise HarnessError("Oracle storage credential file must be a regular 0600 file.")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = None
        try:
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "r", encoding="utf-8") as source:
                descriptor = None
                opened = os.fstat(source.fileno())
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or stat.S_IMODE(opened.st_mode) != 0o600
                    or opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                ):
                    raise HarnessError(
                        "Oracle storage credential file must be a regular 0600 file."
                    )
                payload = json.load(source)
        except HarnessError:
            raise
        except (OSError, ValueError) as error:
            raise HarnessError("Oracle storage credential file is malformed.") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        payload = self._validate_storage_secret_payload(payload)
        if expected_scope is not None:
            if set(expected_scope) != STORAGE_SCOPE_KEYS:
                raise HarnessError("Oracle storage scope is incomplete.")
            self._assert_storage_scope_ledger(
                expected_scope, require_evidence=require_evidence
            )
            if any(
                payload[field] != str(expected_scope[field])
                for field in STORAGE_SCOPE_KEYS
            ):
                raise HarnessError("Oracle storage credential scope does not match the run.")
        return payload

    def _provision_customer_secret_key(self, user, *, namespace, region, bucket):
        kind = "customer_secret_key"
        client = self._clients["identity"]
        user_id = str(_value(user, "id") or "")
        name = self.names[kind]
        expected_secret_scope = self._storage_scope(
            bucket_name=str(_value(bucket, "name") or ""),
            namespace=namespace,
            region=region,
            user_ocid=user_id,
        )
        secret_file = self._read_storage_secret(expected_scope=expected_secret_scope)
        keys = self._list_unpaged(client.list_customer_secret_keys, user_id=user_id)
        named = [item for item in keys if str(_value(item, "display_name") or "") == name]
        row = self._active_ledger_entry(kind)
        if len(named) > 1:
            raise HarnessError("Multiple OCI customer secret keys use the run name.")
        if any(str(_value(item, "user_id") or "") != user_id for item in named):
            raise HarnessError("OCI customer secret key ownership is ambiguous.")
        key = named[0] if named else None
        if row:
            if key is None or str(_value(key, "id") or "") != row["resource_id"]:
                raise HarnessError("Ledgered OCI customer secret key could not be reverified.")
            if not secret_file or secret_file.get("access_key_id") != row["resource_id"]:
                raise HarnessError(
                    "The one-time OCI storage secret is unavailable; cleanup is required before reprovisioning."
                )
        elif key is not None:
            if not secret_file or secret_file.get("access_key_id") != str(_value(key, "id") or ""):
                self._record_storage(
                    kind,
                    key,
                    resource_id=_value(key, "id"),
                    name=name,
                    compartment_id="",
                    relationships={"user_id": user_id},
                )
                raise HarnessError(
                    "An exact customer secret key exists but its one-time secret was lost; cleanup is required."
                )
        else:
            import oci

            self._put_intent(kind, operation="create", name=name)
            details = oci.identity.models.CreateCustomerSecretKeyDetails(display_name=name)
            try:
                key = _data(
                    self._mutation_call(
                        kind,
                        client.create_customer_secret_key,
                        create_customer_secret_key_details=details,
                        user_id=user_id,
                        opc_retry_token=_retry_token(f"{self.config.run_id}:{kind}"),
                        accepted=(200,),
                    )
                )
            except HarnessError as error:
                keys = self._list_unpaged(
                    client.list_customer_secret_keys, user_id=user_id
                )
                exact = [
                    item for item in keys if str(_value(item, "display_name") or "") == name
                ]
                if len(exact) == 1:
                    self._record_storage(
                        kind,
                        exact[0],
                        resource_id=_value(exact[0], "id"),
                        name=name,
                        compartment_id="",
                        relationships={"user_id": user_id},
                    )
                    raise HarnessError(
                        "OCI accepted the customer-secret request but the one-time secret response was lost; cleanup is required."
                    )
                if not exact:
                    self._clear_definitely_rejected_intent(kind, error)
                raise
            secret = str(_value(key, "key") or "")
            key_id = _require_customer_secret_key_id(_value(key, "id"))
            if not secret:
                raise HarnessError("OCI omitted the one-time customer secret value.")
            endpoint = f"https://{namespace}.compat.objectstorage.{region}.oraclecloud.com"
            secret_file = {
                "access_key_id": key_id,
                "secret_access_key": secret,
                "bucket": str(_value(bucket, "name") or ""),
                "namespace": namespace,
                "region": region,
                "endpoint": endpoint,
                "prefix": f"{self.config.run_id}/",
                "user_ocid": user_id,
                "tenancy_ocid": expected_secret_scope["tenancy_ocid"],
                "compartment_ocid": expected_secret_scope["compartment_ocid"],
            }
            self._write_storage_secret(secret_file)
        if not secret_file or any(
            str(secret_file.get(field) or "") != expected
            for field, expected in expected_secret_scope.items()
        ):
            raise HarnessError("Oracle storage credential file scope does not match the run.")
        key_id = _require_customer_secret_key_id(_value(key, "id"))
        self._record_storage(
            kind,
            key,
            resource_id=key_id,
            name=name,
            compartment_id="",
            relationships={"user_id": user_id},
        )
        self.intents.clear(kind)
        return key, self._secret_path()

    def _s3_preflight(self, secret_path):
        client, secret = self._storage_s3_client(secret_path)
        payload = hashlib.sha256(
            f"{self.config.run_id}:oracle-object-storage".encode("utf-8")
        ).digest()
        digest = hashlib.sha256(payload).hexdigest()
        key = f"{secret['prefix']}_harness/preflight.bin"
        deadline = time.monotonic() + min(self.config.timeout_seconds, 300)
        while True:
            try:
                result = client.put_object(
                    Bucket=secret["bucket"],
                    Key=key,
                    Body=payload,
                    ContentLength=len(payload),
                    Metadata={"backupsheep-sha256": digest, "backupsheep-run": self.config.run_id},
                )
                head = client.head_object(Bucket=secret["bucket"], Key=key)
                break
            except Exception as error:
                if time.monotonic() >= deadline:
                    raise HarnessError(
                        "OCI least-privilege S3 credential did not become usable within the bounded waiter."
                    ) from error
                self._sleep(self.config.poll_seconds)
        if (
            int(head.get("ContentLength") or -1) != len(payload)
            or str((head.get("Metadata") or {}).get("backupsheep-sha256") or "")
            != digest
            or not str(result.get("ETag") or head.get("ETag") or "").strip('"')
            or not str(result.get("VersionId") or head.get("VersionId") or "")
        ):
            raise HarnessError("OCI S3 preflight did not return complete integrity/version evidence.")
        evidence = {
            "operation": "evidence",
            "kind": "object_storage_preflight",
            "name": key,
            "marker": self.config.run_id,
            "sha256": digest,
            "byte_count": len(payload),
            "etag": str(result.get("ETag") or head.get("ETag") or "").strip('"'),
            "version_id": str(result.get("VersionId") or head.get("VersionId") or ""),
            "object_key": key,
        }
        self.evidence.put("object_storage_preflight", evidence)
        return evidence

    def _storage_scope_for_s3(self):
        durable = self.evidence.get("storage_scope")
        repaired = False
        if not isinstance(durable, dict) or any(
            not str(durable.get(field) or "") for field in STORAGE_SCOPE_KEYS
        ):
            durable = self._load_repaired_storage_scope()
            repaired = True
        expected = self._storage_scope(
            bucket_name=durable["bucket"],
            namespace=durable["namespace"],
            region=durable["region"],
            user_ocid=durable["user_ocid"],
        )
        if any(
            str(durable.get(field) or "") != str(expected[field])
            for field in STORAGE_SCOPE_KEYS
        ):
            raise HarnessError("Oracle S3 storage scope does not match OCI configuration.")
        return self._assert_storage_scope_ledger(expected, require_evidence=not repaired)

    def _load_repaired_storage_scope(self):
        path_value = self.environment.get("ORACLE_E2E_STORAGE_SCOPE_FILE")
        if not path_value:
            raise HarnessError(
                "Oracle S3 use requires durable storage scope evidence or an exact "
                "protected repaired scope artifact."
            )
        _path, payload = _read_private_json(
            path_value,
            variable="ORACLE_E2E_STORAGE_SCOPE_FILE",
            exact_keys=STORAGE_SCOPE_REPAIR_KEYS,
        )
        if (
            payload.get("schema") != STORAGE_SCOPE_REPAIR_SCHEMA
            or payload.get("run_id") != self.config.run_id
            or payload.get("runtime_scope_digest") != self.config.runtime_scope.digest
        ):
            raise HarnessError("Repaired Oracle storage scope does not match this exact run.")
        scope = payload.get("storage_scope")
        if not isinstance(scope, dict) or set(scope) != STORAGE_SCOPE_KEYS:
            raise HarnessError("Repaired Oracle storage scope is malformed.")
        expected = self._storage_scope(
            bucket_name=scope.get("bucket"),
            namespace=scope.get("namespace"),
            region=scope.get("region"),
            user_ocid=scope.get("user_ocid"),
        )
        if any(str(scope.get(key) or "") != str(expected[key]) for key in STORAGE_SCOPE_KEYS):
            raise HarnessError("Repaired Oracle storage scope drifted from runtime scope.")
        witnesses = self._storage_scope_witnesses()
        if any(payload.get(key) != value for key, value in witnesses.items()):
            raise HarnessError("Repaired Oracle storage scope ledger witnesses changed.")
        secret = self._read_storage_secret(require_evidence=False)
        if secret is None:
            raise HarnessError("Oracle Object Storage credential file is missing.")
        if (
            secret["access_key_id"]
            != witnesses["customer_secret_witness"]["resource_id"]
            or secret["user_ocid"] != witnesses["user_witness"]["resource_id"]
            or secret["bucket"] != witnesses["bucket_witness"]["name"]
            or any(secret[key] != str(expected[key]) for key in STORAGE_SCOPE_KEYS)
        ):
            raise HarnessError("Repaired Oracle storage scope no longer binds the exact key row.")
        identity = self._storage_scope_identity(expected, witnesses)
        if payload.get("scope_identity_sha256") != identity:
            raise HarnessError("Repaired Oracle storage immutable identity changed.")
        return scope

    def repair_storage_scope(self, output_path):
        """Create a new non-secret scope artifact; never alter legacy evidence."""

        secret = self._read_storage_secret()
        if secret is None:
            raise HarnessError("Oracle Object Storage credential file is missing.")
        expected = self._storage_scope(
            bucket_name=secret["bucket"],
            namespace=secret["namespace"],
            region=secret["region"],
            user_ocid=secret["user_ocid"],
        )
        self._assert_storage_scope_ledger(expected, require_evidence=False)
        if any(secret[field] != str(expected[field]) for field in STORAGE_SCOPE_KEYS):
            raise HarnessError("Oracle storage secret and exact ledger/runtime scope disagree.")
        witnesses = self._storage_scope_witnesses()
        if (
            witnesses["bucket_witness"]["name"] != expected["bucket"]
            or witnesses["user_witness"]["resource_id"] != expected["user_ocid"]
            or witnesses["customer_secret_witness"]["resource_id"]
            != secret["access_key_id"]
            or str(
                (
                    witnesses["customer_secret_witness"]["ownership"].get(
                        "relationships"
                    )
                    or {}
                ).get("user_id")
                or ""
            )
            != expected["user_ocid"]
        ):
            raise HarnessError("Oracle storage repair witnesses do not bind one exact key graph.")
        raw_output = Path(str(output_path or "")).expanduser()
        _reject_symlink_components(raw_output, variable="--output")
        output = _external_path(raw_output, variable="--output")
        protected_sources = {
            self.config.runtime_scope.source_path,
            self._secret_path(),
            self.config.ledger_path,
            self.evidence.path,
        }
        if output in protected_sources:
            raise HarnessError("Storage-scope repair must not overwrite a source artifact.")
        payload = {
            "schema": STORAGE_SCOPE_REPAIR_SCHEMA,
            "run_id": self.config.run_id,
            "runtime_scope_digest": self.config.runtime_scope.digest,
            "scope_identity_sha256": self._storage_scope_identity(
                expected, witnesses
            ),
            "storage_scope": expected,
            **witnesses,
        }
        written = _atomic_private_json(output, payload, variable="--output")
        return {
            "phase": "STORAGE_SCOPE_REPAIRED",
            "run_id": self.config.run_id,
            "output": str(written),
            "source_overwritten": False,
        }

    def _storage_s3_client(self, secret_path=None):
        expected_scope = self._storage_scope_for_s3()
        canonical_path = self._secret_path()
        if secret_path is not None:
            requested_path = Path(secret_path).expanduser()
            self._reject_secret_symlink_components(
                requested_path, variable="ORACLE_E2E_SECRET_FILE"
            )
            requested_path = _safe_path(
                requested_path, variable="ORACLE_E2E_SECRET_FILE"
            )
            if requested_path != canonical_path:
                raise HarnessError("Oracle S3 client received an unexpected credential path.")
        secret = self._read_storage_secret(
            expected_scope=expected_scope, require_evidence=False
        )
        if secret is None:
            raise HarnessError("Oracle Object Storage credential file is missing.")
        try:
            import boto3
            from botocore.config import Config

            client = boto3.client(
                "s3",
                aws_access_key_id=secret["access_key_id"],
                aws_secret_access_key=secret["secret_access_key"],
                endpoint_url=secret["endpoint"],
                region_name=secret["region"],
                config=Config(
                    signature_version="s3v4",
                    connect_timeout=REQUEST_TIMEOUT[0],
                    read_timeout=REQUEST_TIMEOUT[1],
                    retries={"max_attempts": 3, "mode": "standard"},
                    s3={"addressing_style": "path"},
                    request_checksum_calculation="when_required",
                    response_checksum_validation="when_required",
                ),
            )
        except Exception as error:
            raise HarnessError("Could not initialize the OCI S3 compatibility client.") from error
        return client, secret

    def _provision_storage(self):
        tenancy_id, region, namespace = self._storage_context()
        import oci

        bucket = self._provision_bucket(namespace)
        user = self._provision_iam_named(
            kind="iam_user",
            tenancy_id=tenancy_id,
            list_method=self._clients["identity"].list_users,
            create_method=self._clients["identity"].create_user,
            details_class=oci.identity.models.CreateUserDetails,
        )
        storage_scope = self._storage_scope(
            bucket_name=str(_value(bucket, "name") or ""),
            namespace=namespace,
            region=region,
            user_ocid=str(_value(user, "id") or ""),
        )
        self._persist_storage_scope(storage_scope)
        group = self._provision_iam_named(
            kind="iam_group",
            tenancy_id=tenancy_id,
            list_method=self._clients["identity"].list_groups,
            create_method=self._clients["identity"].create_group,
            details_class=oci.identity.models.CreateGroupDetails,
        )
        membership = self._provision_membership(tenancy_id, user, group)
        policy = self._provision_policy(group)
        key, secret_path = self._provision_customer_secret_key(
            user,
            namespace=namespace,
            region=region,
            bucket=bucket,
        )
        preflight = self._s3_preflight(secret_path)
        return {
            "bucket_ocid": str(_value(bucket, "id") or ""),
            "bucket_name": str(_value(bucket, "name") or ""),
            "namespace": namespace,
            "region": region,
            "prefix": f"{self.config.run_id}/",
            "iam_user_ocid": str(_value(user, "id") or ""),
            "iam_group_ocid": str(_value(group, "id") or ""),
            "iam_membership_ocid": str(_value(membership, "id") or ""),
            "iam_policy_ocid": str(_value(policy, "id") or ""),
            "credential_file": str(secret_path),
            "credential_values_printed": False,
            "preflight": preflight,
        }

    @staticmethod
    def _positive_row_id(value, *, field):
        try:
            value = int(value)
        except (TypeError, ValueError) as error:
            raise HarnessError(f"Oracle UI manifest {field} must be a positive row ID.") from error
        if value <= 0:
            raise HarnessError(f"Oracle UI manifest {field} must be a positive row ID.")
        return value

    @staticmethod
    def _backup_marker(value, *, field):
        return _safe_backup_marker(value, field=field)

    @staticmethod
    def _exact_mapping(value, keys, *, field):
        if not isinstance(value, dict) or set(value) != set(keys):
            raise HarnessError(f"Oracle UI manifest {field} has an unsupported schema.")
        return value

    @staticmethod
    def _hash_evidence(value, *, field, database=False):
        keys = (
            {"schema_sha256", "table_count", "row_count", "data_sha256"}
            if database
            else {"tree_sha256", "file_count", "byte_count", "mode_sha256"}
        )
        value = OracleLiveUIHarness._exact_mapping(value, keys, field=field)
        hashes = ("schema_sha256", "data_sha256") if database else ("tree_sha256", "mode_sha256")
        counts = ("table_count", "row_count") if database else ("file_count", "byte_count")
        result = {}
        for name in hashes:
            token = str(value.get(name) or "").lower()
            if not re.fullmatch(r"[a-f0-9]{64}", token):
                raise HarnessError(f"Oracle UI manifest {field}.{name} is malformed.")
            result[name] = token
        for name in counts:
            try:
                count = int(value.get(name))
            except (TypeError, ValueError) as error:
                raise HarnessError(f"Oracle UI manifest {field}.{name} is malformed.") from error
            if count < 0:
                raise HarnessError(f"Oracle UI manifest {field}.{name} is malformed.")
            result[name] = count
        return result

    def _validate_workload_row_witness(self, value, *, field, target):
        value = self._exact_mapping(value, WORKLOAD_ROW_WITNESS_KEYS, field=field)
        normalized = {
            "node_row_id": self._positive_row_id(
                value.get("node_row_id"), field=f"{field}.node_row_id"
            ),
            "backup_row_id": self._positive_row_id(
                value.get("backup_row_id"), field=f"{field}.backup_row_id"
            ),
            "backup_status": str(value.get("backup_status") or ""),
            "backup_marker": self._backup_marker(
                value.get("backup_marker"), field=f"{field}.backup_marker"
            ),
            "restore_row_id": self._positive_row_id(
                value.get("restore_row_id"), field=f"{field}.restore_row_id"
            ),
            "restore_status": str(value.get("restore_status") or ""),
            "restore_target": str(value.get("restore_target") or ""),
        }
        if (
            normalized["backup_status"] != "Complete"
            or normalized["restore_status"] != "Complete"
            or normalized["restore_target"] != target
        ):
            raise HarnessError(f"Oracle UI manifest {field} row witness is inconsistent.")
        return normalized

    def _validate_workload_guest_scope(self, value):
        value = self._exact_mapping(
            value, WORKLOAD_GUEST_SCOPE_KEYS, field="workload_guest_scope"
        )
        provider = str(value.get("provider") or "")
        guest_run_id = require_run_id(value.get("run_id"))
        if provider != "upcloud" or not guest_run_id.startswith("bs-e2e-upcloud-"):
            raise HarnessError("Workload guest scope must identify the exact UpCloud E2E run.")
        safe_root = str(value.get("safe_root") or "")
        website_root = str(value.get("website_source_root") or "")
        source_database = str(value.get("source_database") or "")
        if (
            safe_root != f"/srv/backupsheep-e2e/{guest_run_id}"
            or website_root != f"{safe_root}/website"
            or not re.fullmatch(r"bs_e2e_[a-z0-9_]{8,54}", source_database)
        ):
            raise HarnessError("Workload guest source paths or database are not run-scoped.")
        try:
            ssh_host = str(ipaddress.ip_address(str(value.get("ssh_host") or "")))
            ssh_port = int(value.get("ssh_port"))
        except (ValueError, TypeError) as error:
            raise HarnessError("Workload guest SSH endpoint is malformed.") from error
        ssh_user = str(value.get("ssh_user") or "")
        if ssh_port != 22 or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", ssh_user):
            raise HarnessError("Workload guest SSH user or port is outside the safe contract.")
        key_path = _external_nonsymlink_path(
            value.get("ssh_private_key_path"), variable="workload SSH private key"
        )
        known_hosts_path = _external_nonsymlink_path(
            value.get("known_hosts_path"), variable="workload known-hosts file"
        )
        ledger_path = _external_nonsymlink_path(
            value.get("durable_ledger_path"), variable="workload durable ledger"
        )
        if len({key_path, known_hosts_path, ledger_path}) != 3:
            raise HarnessError("Workload guest protected artifacts must use distinct paths.")
        hashes = {
            "ssh_private_key_sha256": str(
                value.get("ssh_private_key_sha256") or ""
            ).lower(),
            "known_hosts_sha256": str(value.get("known_hosts_sha256") or "").lower(),
        }
        if any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in hashes.values()):
            raise HarnessError("Workload guest protected-file digest is malformed.")
        key_type = str(value.get("known_host_key_type") or "")
        fingerprint = str(value.get("known_host_fingerprint") or "")
        if (
            not re.fullmatch(r"ssh-(?:rsa|ed25519)|ecdsa-sha2-nistp(?:256|384|521)", key_type)
            or not SSH_FINGERPRINT_RE.fullmatch(fingerprint)
        ):
            raise HarnessError("Workload known-host fingerprint is malformed.")
        source_server_id = str(value.get("source_server_id") or "")
        if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", source_server_id):
            raise HarnessError("Workload UpCloud source server ID is malformed.")
        ledger_scope = str(value.get("durable_ledger_scope") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", ledger_scope):
            raise HarnessError("Workload durable-ledger scope is malformed.")
        return {
            "provider": provider,
            "run_id": guest_run_id,
            "durable_ledger_path": str(ledger_path),
            "durable_ledger_scope": ledger_scope,
            "source_server_id": source_server_id,
            "safe_root": safe_root,
            "website_source_root": website_root,
            "source_database": source_database,
            "ssh_host": ssh_host,
            "ssh_port": ssh_port,
            "ssh_user": ssh_user,
            "ssh_private_key_path": str(key_path),
            **hashes,
            "known_hosts_path": str(known_hosts_path),
            "known_host_key_type": key_type,
            "known_host_fingerprint": fingerprint,
        }

    def _validate_ui_manifest(self, manifest):
        _assert_no_credential_fields(manifest)
        top_keys = {
            "schema",
            "run_id",
            "profile",
            "tenancy_id",
            "compartment_id",
            "compute",
            "block",
            "boot",
            "storage",
            "workload_guest_scope",
            "workloads",
        }
        self._exact_mapping(manifest, top_keys, field="root")
        runtime = self.config.runtime_scope
        if (
            manifest.get("schema") != UI_MANIFEST_SCHEMA
            or manifest.get("run_id") != runtime.run_id
            or manifest.get("profile") != runtime.profile
            or manifest.get("tenancy_id") != runtime.tenancy_id
            or manifest.get("compartment_id") != runtime.compartment_id
        ):
            raise HarnessError("Oracle UI manifest does not match the protected runtime scope.")

        normalized = {key: manifest[key] for key in top_keys}
        native_backup_keys = {
            "backup_row_id",
            "backup_uuid",
            "ocid",
            "marker",
            "request_token",
        }
        native_restore_keys = {
            "restore_row_id",
            "ocid",
            "name",
            "marker",
            "request_token",
        }
        for kind in ("compute", "block", "boot"):
            section = self._exact_mapping(
                manifest.get(kind), {"source_ocid", "backup", "restore"}, field=kind
            )
            source_type = {"compute": "instance", "block": "volume", "boot": "bootvolume"}[kind]
            source_ocid = _require_ocid(
                section.get("source_ocid"),
                label=f"{kind} source OCID",
                resource_type=source_type,
            )
            backup = self._exact_mapping(section.get("backup"), native_backup_keys, field=f"{kind}.backup")
            backup_uuid = self._backup_marker(
                backup.get("backup_uuid"), field=f"{kind}.backup.backup_uuid"
            )
            marker = self._backup_marker(
                backup.get("marker"), field=f"{kind}.backup.marker"
            )
            if marker != backup_uuid or str(backup.get("request_token") or "") != _retry_token(marker):
                raise HarnessError(f"Oracle UI manifest {kind} backup witness is inconsistent.")
            backup_ocid = _require_ocid(backup.get("ocid"), label=f"{kind} backup OCID")
            restore = self._exact_mapping(
                section.get("restore"), native_restore_keys, field=f"{kind}.restore"
            )
            restore_type = {"compute": "instance", "block": "volume", "boot": "bootvolume"}[kind]
            restore_ocid = _require_ocid(
                restore.get("ocid"), label=f"{kind} restore OCID", resource_type=restore_type
            )
            restore_marker = self._backup_marker(
                restore.get("marker"), field=f"{kind}.restore.marker"
            )
            restore_name = str(restore.get("name") or "")
            restore_token = str(restore.get("request_token") or "")
            if (
                not restore_name
                or len(restore_name) > 255
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in restore_name
                )
                or restore_token != _retry_token(restore_marker)
            ):
                raise HarnessError(f"Oracle UI manifest {kind} restore witness is malformed.")
            normalized[kind] = {
                "source_ocid": source_ocid,
                "backup": {
                    "backup_row_id": self._positive_row_id(
                        backup.get("backup_row_id"), field=f"{kind}.backup.backup_row_id"
                    ),
                    "backup_uuid": backup_uuid,
                    "ocid": backup_ocid,
                    "marker": marker,
                    "request_token": _retry_token(marker),
                },
                "restore": {
                    "restore_row_id": self._positive_row_id(
                        restore.get("restore_row_id"), field=f"{kind}.restore.restore_row_id"
                    ),
                    "ocid": restore_ocid,
                    "name": restore_name,
                    "marker": restore_marker,
                    "request_token": _retry_token(restore_marker),
                },
            }

        storage = self._exact_mapping(manifest.get("storage"), {"objects"}, field="storage")
        objects = storage.get("objects")
        if not isinstance(objects, list) or len(objects) != 2:
            raise HarnessError("Oracle UI manifest must contain exactly two storage objects.")
        object_keys = {
            "kind",
            "backup_row_id",
            "backup_uuid",
            "storage_point_id",
            "restore_row_id",
            "key",
            "sha256",
            "byte_count",
            "etag",
            "version_id",
        }
        normalized_objects = []
        seen_kinds = set()
        seen_identity = set()
        for index, item in enumerate(objects):
            item = self._exact_mapping(item, object_keys, field=f"storage.objects[{index}]")
            kind = str(item.get("kind") or "")
            if kind not in {"website", "database"} or kind in seen_kinds:
                raise HarnessError("Oracle UI manifest storage kinds must be exactly website and database.")
            seen_kinds.add(kind)
            key = str(item.get("key") or "")
            backup_marker = self._backup_marker(
                item.get("backup_uuid"), field=f"storage.{kind}.backup_uuid"
            )
            checksum = str(item.get("sha256") or "").lower()
            etag = str(item.get("etag") or "").strip('"')
            version_id = str(item.get("version_id") or "")
            try:
                byte_count = int(item.get("byte_count"))
            except (TypeError, ValueError) as error:
                raise HarnessError("Oracle UI manifest storage byte count is malformed.") from error
            identity = (key, version_id)
            if (
                not key.startswith(f"{self.config.run_id}/")
                or ".." in Path(key).parts
                or Path(key).name != f"{backup_marker}.zip"
                or not re.fullmatch(r"[a-f0-9]{64}", checksum)
                or byte_count <= 0
                or not etag
                or len(etag) > 1024
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in etag
                )
                or not version_id
                or len(version_id) > 1024
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in version_id
                )
                or version_id == "null"
                or identity in seen_identity
            ):
                raise HarnessError("Oracle UI manifest storage witness is malformed.")
            seen_identity.add(identity)
            normalized_objects.append(
                {
                    "kind": kind,
                    "backup_row_id": self._positive_row_id(
                        item.get("backup_row_id"), field=f"storage.{kind}.backup_row_id"
                    ),
                    "backup_uuid": backup_marker,
                    "storage_point_id": self._positive_row_id(
                        item.get("storage_point_id"), field=f"storage.{kind}.storage_point_id"
                    ),
                    "restore_row_id": self._positive_row_id(
                        item.get("restore_row_id"), field=f"storage.{kind}.restore_row_id"
                    ),
                    "key": key,
                    "sha256": checksum,
                    "byte_count": byte_count,
                    "etag": etag,
                    "version_id": version_id,
                }
            )
        normalized["storage"] = {"objects": sorted(normalized_objects, key=lambda row: row["kind"])}

        guest_scope = self._validate_workload_guest_scope(
            manifest.get("workload_guest_scope")
        )
        normalized["workload_guest_scope"] = guest_scope
        workloads = self._exact_mapping(
            manifest.get("workloads"), {"website", "database"}, field="workloads"
        )
        website = self._exact_mapping(
            workloads.get("website"),
            {
                "backup_row_id",
                "restore_row_id",
                "restore_path",
                "row_witness",
                "source",
                "restored",
            },
            field="workloads.website",
        )
        database = self._exact_mapping(
            workloads.get("database"),
            {
                "backup_row_id",
                "restore_row_id",
                "restore_database",
                "row_witness",
                "source",
                "restored",
            },
            field="workloads.database",
        )
        restore_path = str(website.get("restore_path") or "")
        restore_database = str(database.get("restore_database") or "")
        website_restore_id = self._positive_row_id(
            website.get("restore_row_id"), field="workloads.website.restore_row_id"
        )
        database_restore_id = self._positive_row_id(
            database.get("restore_row_id"), field="workloads.database.restore_row_id"
        )
        if restore_path != f"{guest_scope['safe_root']}/restores/{website_restore_id}":
            raise HarnessError("Website restore path is not bound to the UpCloud run and row.")
        if not re.fullmatch(r"bs_restore_[a-z0-9_]{8,52}", restore_database):
            raise HarnessError("Database restore target is not a safe BackupSheep restore name.")
        website_row = self._validate_workload_row_witness(
            website.get("row_witness"),
            field="workloads.website.row_witness",
            target=restore_path,
        )
        database_row = self._validate_workload_row_witness(
            database.get("row_witness"),
            field="workloads.database.row_witness",
            target=restore_database,
        )
        normalized["workloads"] = {
            "website": {
                "backup_row_id": self._positive_row_id(
                    website.get("backup_row_id"), field="workloads.website.backup_row_id"
                ),
                "restore_row_id": website_restore_id,
                "restore_path": restore_path,
                "row_witness": website_row,
                "source": self._hash_evidence(
                    website.get("source"), field="workloads.website.source"
                ),
                "restored": self._hash_evidence(
                    website.get("restored"), field="workloads.website.restored"
                ),
            },
            "database": {
                "backup_row_id": self._positive_row_id(
                    database.get("backup_row_id"), field="workloads.database.backup_row_id"
                ),
                "restore_row_id": database_restore_id,
                "restore_database": restore_database,
                "row_witness": database_row,
                "source": self._hash_evidence(
                    database.get("source"), field="workloads.database.source", database=True
                ),
                "restored": self._hash_evidence(
                    database.get("restored"), field="workloads.database.restored", database=True
                ),
            },
        }
        by_kind = {row["kind"]: row for row in normalized["storage"]["objects"]}
        for kind in ("website", "database"):
            workload = normalized["workloads"][kind]
            if (
                workload["backup_row_id"] != by_kind[kind]["backup_row_id"]
                or workload["restore_row_id"] != by_kind[kind]["restore_row_id"]
                or workload["row_witness"]["backup_row_id"]
                != workload["backup_row_id"]
                or workload["row_witness"]["restore_row_id"]
                != workload["restore_row_id"]
                or workload["row_witness"]["backup_marker"]
                != by_kind[kind]["backup_uuid"]
            ):
                raise HarnessError(f"Oracle {kind} object and workload row IDs do not match.")
        if (
            normalized["workloads"]["website"]["row_witness"]["node_row_id"]
            == normalized["workloads"]["database"]["row_witness"]["node_row_id"]
        ):
            raise HarnessError("Website and database workload node rows must be distinct.")
        return normalized

    def _load_ui_manifest(self, path):
        _path, manifest = _read_private_json(path, variable="--ui-manifest")
        return self._validate_ui_manifest(manifest)

    def build_manifest(self, source_path, output_path):
        source, candidate = _read_private_json(
            source_path, variable="--manifest-source"
        )
        raw_output = Path(str(output_path or "")).expanduser()
        _reject_symlink_components(raw_output, variable="--output")
        output = _external_path(raw_output, variable="--output")
        if source == output:
            raise HarnessError("Manifest output must not overwrite the source evidence artifact.")
        normalized = self._validate_ui_manifest(candidate)
        written = _atomic_private_json(output, normalized, variable="--output")
        return {
            "phase": "MANIFEST_BUILT",
            "run_id": self.config.run_id,
            "output": str(written),
            "source_overwritten": False,
        }

    @staticmethod
    def _normalize_exact_tags(value, *, field):
        if not isinstance(value, dict) or len(value) > 64:
            raise HarnessError(f"Oracle orphan manifest {field} tags are malformed.")
        normalized = {}
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or not isinstance(item, str)
                or key not in ORPHAN_ALLOWED_TAG_KEYS
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", key)
                or len(item) > 255
                or any(ord(character) < 32 or ord(character) == 127 for character in item)
            ):
                raise HarnessError(
                    f"Oracle orphan manifest {field} tags are malformed."
                )
            normalized[key] = item
        return normalized

    def _validate_orphan_manifest(self, payload):
        _assert_no_credential_fields(payload, path="orphan_manifest")
        if not isinstance(payload, dict) or set(payload) != ORPHAN_MANIFEST_KEYS:
            raise HarnessError("Oracle orphan manifest has an unsupported schema.")
        runtime = self.config.runtime_scope
        if (
            payload.get("schema") != ORPHAN_RECONCILIATION_SCHEMA
            or payload.get("run_id") != runtime.run_id
            or payload.get("profile") != runtime.profile
            or payload.get("tenancy_id") != runtime.tenancy_id
            or payload.get("compartment_id") != runtime.compartment_id
        ):
            raise HarnessError("Oracle orphan manifest does not match protected scope.")
        resources = payload.get("resources")
        if not isinstance(resources, list) or not 1 <= len(resources) <= len(
            ORPHAN_ADOPTION_KINDS
        ):
            raise HarnessError("Oracle orphan manifest resource inventory is malformed.")
        normalized = []
        seen_kinds = set()
        seen_ids = set()
        for index, value in enumerate(resources):
            field = f"resources[{index}]"
            if not isinstance(value, dict) or set(value) != ORPHAN_RESOURCE_KEYS:
                raise HarnessError(f"Oracle orphan manifest {field} has an unsupported schema.")
            kind = str(value.get("kind") or "")
            if kind not in ORPHAN_ADOPTION_KINDS or kind in seen_kinds:
                raise HarnessError("Oracle orphan manifest kinds are unsupported or duplicated.")
            seen_kinds.add(kind)
            provider_ocid = _require_ocid(
                value.get("provider_ocid"),
                label=f"orphan {kind} OCID",
                resource_type=ORPHAN_RESOURCE_TYPES[kind],
            )
            if provider_ocid in seen_ids:
                raise HarnessError("Oracle orphan manifest reuses a provider OCID.")
            seen_ids.add(provider_ocid)
            name = str(value.get("name") or "")
            if (
                not 1 <= len(name) <= 255
                or any(ord(character) < 32 or ord(character) == 127 for character in name)
            ):
                raise HarnessError("Oracle orphan manifest resource name is malformed.")
            lifecycle = str(value.get("lifecycle_state") or "")
            ready_states = {
                "ui_compute_backup": {"AVAILABLE"},
                "ui_block_backup": {"AVAILABLE"},
                "ui_boot_backup": {"AVAILABLE"},
                "ui_compute_restore": {"RUNNING", "STOPPED"},
                "ui_block_restore": {"AVAILABLE"},
                "ui_boot_restore": {"AVAILABLE"},
                "ui_compute_restore_boot_volume": {"AVAILABLE"},
                "ui_compute_restore_vnic": {"AVAILABLE"},
            }[kind]
            if lifecycle not in ready_states:
                raise HarnessError("Oracle orphan manifest lifecycle is not cleanup-safe.")
            tags = self._normalize_exact_tags(value.get("freeform_tags"), field=field)
            relation = value.get("source_relationship")
            if not isinstance(relation, dict) or set(relation) != ORPHAN_RELATIONSHIP_KEYS:
                raise HarnessError("Oracle orphan source relationship is malformed.")
            relation_kind = str(relation.get("kind") or "")
            if relation_kind != ORPHAN_RELATION_KINDS[kind]:
                raise HarnessError("Oracle orphan source relationship kind is incorrect.")
            relation_ocid = _require_ocid(
                relation.get("ocid"), label="orphan source relationship"
            )
            witness = value.get("demo_row_witness")
            if not isinstance(witness, dict) or set(witness) != ORPHAN_ROW_WITNESS_KEYS:
                raise HarnessError("Oracle orphan demo-row witness is malformed.")
            row_type = str(witness.get("row_type") or "")
            expected_row_type = (
                "backup" if kind.endswith("_backup") else "restore"
            )
            marker = self._backup_marker(
                witness.get("marker"), field=f"orphan.{kind}.demo_row_witness.marker"
            )
            row_provider_ocid = _require_ocid(
                witness.get("provider_ocid"), label="orphan demo-row provider OCID"
            )
            dependency = kind in {
                "ui_compute_restore_boot_volume",
                "ui_compute_restore_vnic",
            }
            if (
                row_type != expected_row_type
                or str(witness.get("status") or "") not in {"Complete", "Failed"}
                or row_provider_ocid != (relation_ocid if dependency else provider_ocid)
            ):
                raise HarnessError("Oracle orphan demo-row witness is inconsistent.")
            normalized_witness = {
                "row_type": row_type,
                "row_id": self._positive_row_id(
                    witness.get("row_id"), field=f"orphan.{kind}.row_id"
                ),
                "status": str(witness.get("status") or ""),
                "marker": marker,
                "provider_ocid": row_provider_ocid,
            }
            if kind.endswith("_backup"):
                provider_kind = {
                    "ui_compute_backup": "compute_image",
                    "ui_block_backup": "block",
                    "ui_boot_backup": "boot",
                }[kind]
                required_tags = self._backup_tags(
                    marker, relation_ocid, provider_kind
                )
                if any(tags.get(key) != item for key, item in required_tags.items()):
                    raise HarnessError("Oracle orphan backup tags do not bind its row marker.")
            elif not dependency:
                target_type = {
                    "ui_compute_restore": "instance",
                    "ui_block_restore": "volume",
                    "ui_boot_restore": "boot_volume",
                }[kind]
                required_tags = {
                    RESTORE_MARKER_TAG: marker,
                    RESTORE_SOURCE_TAG: relation_ocid,
                    BACKUP_KIND_TAG: target_type,
                    BACKUP_REQUEST_TAG: _retry_token(marker),
                }
                if any(tags.get(key) != item for key, item in required_tags.items()):
                    raise HarnessError("Oracle orphan restore tags do not bind its row marker.")
            else:
                run_tag = tags.get(E2E_RUN_TAG)
                if run_tag and (
                    run_tag != self.config.run_id
                    or tags.get(E2E_OWNED_TAG) != "true"
                    or tags.get(E2E_KIND_TAG) != kind
                ):
                    raise HarnessError("Oracle orphan dependency carries foreign ownership tags.")
            normalized.append(
                {
                    "kind": kind,
                    "provider_ocid": provider_ocid,
                    "name": name,
                    "freeform_tags": tags,
                    "lifecycle_state": lifecycle,
                    "source_relationship": {
                        "kind": relation_kind,
                        "ocid": relation_ocid,
                    },
                    "demo_row_witness": normalized_witness,
                }
            )
        return {
            "schema": ORPHAN_RECONCILIATION_SCHEMA,
            "run_id": runtime.run_id,
            "profile": runtime.profile,
            "tenancy_id": runtime.tenancy_id,
            "compartment_id": runtime.compartment_id,
            "resources": normalized,
        }

    def _load_orphan_manifest(self, path):
        _path, payload = _read_private_json(
            path, variable="--reconciliation-manifest"
        )
        return self._validate_orphan_manifest(payload)

    def _orphan_relation_target(self, row, manifest_by_kind):
        relation = row["source_relationship"]
        related = manifest_by_kind.get(relation["kind"])
        if related is not None:
            if related["provider_ocid"] != relation["ocid"]:
                raise HarnessError("Oracle orphan manifest source graph is inconsistent.")
            return related
        matches = [
            item
            for item in self.ledger.entries(relation["kind"])
            if item.get("cleanup_state") in {"eligible", "failed", "manual_review"}
        ]
        if (
            len(matches) != 1
            or str(matches[0].get("resource_id") or "") != relation["ocid"]
        ):
            raise HarnessError("Oracle orphan source is not exactly ledgered or adopted.")
        return matches[0]

    def _orphan_provider_relationship(self, row, resource, *, attachments):
        kind = row["kind"]
        if kind == "ui_compute_backup":
            return str(_tags(resource).get(BACKUP_SOURCE_TAG) or "")
        if kind == "ui_block_backup":
            return str(_value(resource, "volume_id") or "")
        if kind == "ui_boot_backup":
            return str(_value(resource, "boot_volume_id") or "")
        if kind == "ui_compute_restore":
            return str(_value(resource, "image_id") or _source_id(resource) or "")
        if kind in {"ui_block_restore", "ui_boot_restore"}:
            return _source_id(resource)
        if kind == "ui_compute_restore_boot_volume":
            matches = [
                item
                for item in attachments["boot"]
                if str(_value(item, "boot_volume_id") or "") == row["provider_ocid"]
                and str(_value(item, "instance_id") or "")
                == row["source_relationship"]["ocid"]
                and str(_value(item, "lifecycle_state") or "").upper()
                not in {"DETACHED", "DETACHING"}
            ]
        elif kind == "ui_compute_restore_vnic":
            matches = [
                item
                for item in attachments["vnic"]
                if str(_value(item, "vnic_id") or "") == row["provider_ocid"]
                and str(_value(item, "instance_id") or "")
                == row["source_relationship"]["ocid"]
                and str(_value(item, "lifecycle_state") or "").upper()
                not in {"DETACHED", "DETACHING"}
            ]
        else:  # pragma: no cover - schema validation makes this unreachable
            raise HarnessError("Unsupported Oracle orphan relationship kind.")
        if len(matches) != 1:
            raise HarnessError("Oracle orphan dependency relationship is zero or duplicated.")
        return row["source_relationship"]["ocid"]

    def _orphan_ledger_entry(self, row, resource):
        kind = row["kind"]
        relationship = row["source_relationship"]
        proof = self._expected_proof(
            name=row["name"],
            tags=row["freeform_tags"],
            availability_domain=(
                self.config.availability_domain
                if kind
                in {
                    "ui_compute_restore",
                    "ui_block_restore",
                    "ui_boot_restore",
                    "ui_compute_restore_boot_volume",
                }
                else ""
            ),
            source_id=(
                relationship["ocid"]
                if kind
                not in {
                    "ui_compute_restore_boot_volume",
                    "ui_compute_restore_vnic",
                }
                else ""
            ),
        )
        proof["exact_freeform_tags"] = row["freeform_tags"]
        proof["adoption_relationship"] = relationship
        proof["demo_row_witness"] = row["demo_row_witness"]
        if kind == "ui_compute_restore_vnic":
            proof["subnet_id"] = _require_ocid(
                _value(resource, "subnet_id"),
                label="adopted restore VNIC subnet",
                resource_type="subnet",
            )
        return {
            "kind": kind,
            "resource_id": row["provider_ocid"],
            "name": row["name"],
            "ownership": proof,
            "source_witness": relationship["ocid"],
        }

    def _atomic_adopt_orphan_entries(self, entries):
        if self.read_only:
            raise HarnessError("Orphan reconciliation requires a mutable ledger harness.")
        with self.ledger._locked():
            payload = self.ledger._validate(self.ledger._read_unlocked())
            candidate = json.loads(json.dumps(payload))
            proposed_by_kind = {entry["kind"]: entry for entry in entries}
            for entry in entries:
                relation = (entry.get("ownership") or {}).get(
                    "adoption_relationship"
                ) or {}
                related = proposed_by_kind.get(str(relation.get("kind") or ""))
                if related is not None:
                    if related["resource_id"] != str(relation.get("ocid") or ""):
                        raise HarnessError(
                            "Oracle orphan source graph changed before ledger publication."
                        )
                    continue
                exact_sources = [
                    row
                    for row in candidate["resources"]
                    if row.get("kind") == relation.get("kind")
                    and str(row.get("resource_id") or "")
                    == str(relation.get("ocid") or "")
                    and row.get("cleanup_state")
                    in {"eligible", "failed", "manual_review"}
                ]
                active_same_kind = [
                    row
                    for row in candidate["resources"]
                    if row.get("kind") == relation.get("kind")
                    and row.get("cleanup_state")
                    in {"eligible", "failed", "manual_review"}
                ]
                if len(exact_sources) != 1 or len(active_same_kind) != 1:
                    raise HarnessError(
                        "Oracle orphan source graph changed before ledger publication."
                    )
            additions = []
            existing_count = 0
            for entry in entries:
                same_id = [
                    row
                    for row in candidate["resources"]
                    if str(row.get("resource_id") or "") == entry["resource_id"]
                ]
                same_kind_active = [
                    row
                    for row in candidate["resources"]
                    if row.get("kind") == entry["kind"]
                    and row.get("cleanup_state")
                    in {"eligible", "failed", "manual_review"}
                ]
                exact = [
                    row
                    for row in same_id
                    if row.get("kind") == entry["kind"]
                    and all(
                        row.get(key) == entry[key]
                        for key in (
                            "kind",
                            "resource_id",
                            "name",
                            "ownership",
                            "source_witness",
                        )
                    )
                ]
                if exact:
                    if (
                        len(exact) != 1
                        or len(same_id) != 1
                        or len(same_kind_active) != 1
                    ):
                        raise HarnessError("Oracle orphan ledger contains duplicate ownership rows.")
                    existing_count += 1
                    continue
                if same_id or same_kind_active:
                    raise HarnessError("Oracle orphan conflicts with an existing ledger witness.")
                additions.append(entry)
            if not additions:
                return 0, existing_count
            created_at = DurableResourceLedger._now()
            for entry in additions:
                candidate["resources"].append(
                    {
                        **entry,
                        "created_at": created_at,
                        "cleanup_state": "eligible",
                        "cleanup_error": "",
                    }
                )
            self.ledger._validate(candidate)
            self.ledger._write_unlocked(candidate)
            return len(additions), existing_count

    def reconcile_orphans(self, manifest_path):
        """Adopt exact old UI resources after complete inventory/readback proof."""

        self._require_apply()
        manifest = self._load_orphan_manifest(manifest_path)
        if self.intents.pending():
            raise HarnessError("Oracle orphan adoption is blocked by mutation intents.")
        self._load_clients()
        self._validate_scope()
        manifest_by_kind = {row["kind"]: row for row in manifest["resources"]}
        # Enumerate every supported orphan family before any ledger write. A
        # manifest cannot turn a direct GET into ownership proof, and a partial
        # inventory cannot establish zero/one cardinality safely.
        inventory_family = {
            "ui_boot_restore": "boot_volumes",
            "ui_compute_restore_boot_volume": "boot_volumes",
        }
        family_cache = {}
        inventories = {}
        for kind in sorted(ORPHAN_ADOPTION_KINDS):
            family = inventory_family.get(kind, kind)
            if family not in family_cache:
                family_cache[family] = self._graph_inventory(kind)
            inventories[kind] = family_cache[family]
        attachments = {
            "boot": self._list(
                self._clients["compute"].list_boot_volume_attachments,
                compartment_id=self.config.compartment_id,
                availability_domain=self.config.availability_domain,
            ),
            "vnic": self._list(
                self._clients["compute"].list_vnic_attachments,
                compartment_id=self.config.compartment_id,
            ),
        }
        entries = []
        for row in manifest["resources"]:
            self._orphan_relation_target(row, manifest_by_kind)
            matches = [
                item
                for item in inventories[row["kind"]]
                if str(_value(item, "id") or "") == row["provider_ocid"]
            ]
            if len(matches) != 1:
                raise HarnessError("Oracle orphan inventory returned zero or duplicate exact IDs.")
            resource = matches[0]
            if (
                str(_value(resource, "compartment_id") or "")
                != self.config.compartment_id
                or str(
                    _value(resource, "display_name")
                    or _value(resource, "name")
                    or ""
                )
                != row["name"]
                or _tags(resource) != row["freeform_tags"]
                or str(_value(resource, "lifecycle_state") or "").upper()
                != row["lifecycle_state"]
            ):
                raise HarnessError("Oracle orphan provider readback does not match manifest.")
            if row["kind"] in {
                "ui_compute_restore",
                "ui_block_restore",
                "ui_boot_restore",
                "ui_compute_restore_boot_volume",
            } and str(_value(resource, "availability_domain") or "") != str(
                self.config.availability_domain
            ):
                raise HarnessError("Oracle orphan availability domain changed.")
            relationship = self._orphan_provider_relationship(
                row, resource, attachments=attachments
            )
            if relationship != row["source_relationship"]["ocid"]:
                raise HarnessError("Oracle orphan provider source relationship changed.")
            if row["kind"] in {
                "ui_compute_restore_boot_volume",
                "ui_compute_restore_vnic",
            }:
                related = self._orphan_relation_target(row, manifest_by_kind)
                if "demo_row_witness" in related:
                    related_marker = str(
                        (related.get("demo_row_witness") or {}).get("marker") or ""
                    )
                else:
                    related_marker = str(
                        ((related.get("ownership") or {}).get("tags") or {}).get(
                            RESTORE_MARKER_TAG
                        )
                        or ""
                    )
                if related_marker != row["demo_row_witness"]["marker"]:
                    raise HarnessError("Oracle orphan dependency demo row marker changed.")
            entries.append(self._orphan_ledger_entry(row, resource))
        added, existing = self._atomic_adopt_orphan_entries(entries)
        return {
            "phase": "ORPHANS_RECONCILED",
            "run_id": self.config.run_id,
            "provider_mutations": False,
            "ledger_rows_added": added,
            "ledger_rows_already_exact": existing,
            "resource_ids": sorted(entry["resource_id"] for entry in entries),
        }

    @staticmethod
    def _backup_tags(marker, source_id, kind):
        return {
            BACKUP_MARKER_TAG: marker,
            BACKUP_SOURCE_TAG: source_id,
            BACKUP_KIND_TAG: kind,
            BACKUP_REQUEST_TAG: _retry_token(marker),
        }

    @staticmethod
    def _restore_tags(evidence, *, source_backup_id, source_id, target_type):
        marker = str(evidence.get("marker") or "")
        request_token = str(evidence.get("request_token") or "")
        if not marker or not re.fullmatch(r"bs-[a-f0-9]{61}", request_token):
            raise HarnessError("Oracle UI restore marker/request token is malformed.")
        return {
            RESTORE_MARKER_TAG: marker,
            RESTORE_SOURCE_TAG: source_backup_id,
            RESTORE_ORIGIN_TAG: source_id,
            BACKUP_KIND_TAG: target_type,
            BACKUP_REQUEST_TAG: request_token,
        }

    def _verify_ui_backup(self, kind, section, source_row, *, record=True):
        evidence = section["backup"]
        marker = str(evidence.get("marker") or "")
        if not marker:
            raise HarnessError(f"Oracle UI {kind} backup marker is required.")
        source_id = _require_ocid(section["source_ocid"], label=f"{kind} source OCID")
        if source_id != source_row["resource_id"]:
            raise HarnessError(f"Oracle UI {kind} source OCID is not ledger-owned.")
        backup_id = _require_ocid(evidence.get("ocid"), label=f"{kind} backup OCID")
        if kind == "compute":
            resource = _data(
                self._call(self._clients["compute"].get_image, image_id=backup_id)
            )
            provider_kind = "compute_image"
            ledger_kind = "ui_compute_backup"
            actual_source = _tags(resource).get(BACKUP_SOURCE_TAG)
        elif kind == "boot":
            resource = _data(
                self._call(
                    self._clients["block"].get_boot_volume_backup,
                    boot_volume_backup_id=backup_id,
                )
            )
            provider_kind = "boot"
            ledger_kind = "ui_boot_backup"
            actual_source = _value(resource, "boot_volume_id")
        else:
            resource = _data(
                self._call(
                    self._clients["block"].get_volume_backup,
                    volume_backup_id=backup_id,
                )
            )
            provider_kind = "block"
            ledger_kind = "ui_block_backup"
            actual_source = _value(resource, "volume_id")
        if str(_value(resource, "lifecycle_state") or "").upper() != "AVAILABLE":
            raise HarnessError(f"Oracle UI {kind} backup is not AVAILABLE.")
        tags = self._backup_tags(marker, source_id, provider_kind)
        proof = self._expected_proof(name=marker, tags=tags, source_id=source_id)
        self._assert_exact(
            resource,
            resource_id=backup_id,
            proof=proof,
            source_id=actual_source,
        )
        if record:
            self._record(
                ledger_kind,
                resource,
                proof,
                source_witness=source_id,
                source_id=actual_source,
            )
        return resource

    def _verify_ui_restore(self, kind, section, source_row, backup, *, record=True):
        evidence = section["restore"]
        source_id = source_row["resource_id"]
        backup_id = str(_value(backup, "id") or "")
        restore_id = _require_ocid(evidence.get("ocid"), label=f"{kind} restore OCID")
        name = str(evidence.get("name") or "")
        if not name:
            raise HarnessError(f"Oracle UI {kind} restore name is required.")
        if kind == "compute":
            resource = _data(
                self._call(self._clients["compute"].get_instance, instance_id=restore_id)
            )
            target_type = "instance"
            ledger_kind = "ui_compute_restore"
            ready = {"RUNNING", "STOPPED"}
        elif kind == "boot":
            resource = _data(
                self._call(
                    self._clients["block"].get_boot_volume,
                    boot_volume_id=restore_id,
                )
            )
            target_type = "boot_volume"
            ledger_kind = "ui_boot_restore"
            ready = {"AVAILABLE"}
        else:
            resource = _data(
                self._call(self._clients["block"].get_volume, volume_id=restore_id)
            )
            target_type = "volume"
            ledger_kind = "ui_block_restore"
            ready = {"AVAILABLE"}
        if str(_value(resource, "lifecycle_state") or "").upper() not in ready:
            raise HarnessError(f"Oracle UI {kind} restore is not ready for verification.")
        tags = self._restore_tags(
            evidence,
            source_backup_id=backup_id,
            source_id=source_id,
            target_type=target_type,
        )
        proof = self._expected_proof(
            name=name,
            tags=tags,
            availability_domain=self.config.availability_domain,
            source_id=backup_id,
        )
        self._assert_exact(
            resource,
            resource_id=restore_id,
            proof=proof,
            source_id=_source_id(resource),
        )
        if record:
            self._record(
                ledger_kind,
                resource,
                proof,
                source_witness=backup_id,
                source_id=_source_id(resource),
            )
        return resource

    def _record_instance_vnic(self, instance, *, ledger_kind, name, tags):
        instance_id = str(_value(instance, "id") or "")
        row = self._active_ledger_entry(ledger_kind)
        if row:
            vnic = _data(
                self._call(
                    self._clients["network"].get_vnic,
                    vnic_id=row["resource_id"],
                )
            )
        else:
            attachments = self._list(
                self._clients["compute"].list_vnic_attachments,
                compartment_id=self.config.compartment_id,
                instance_id=instance_id,
            )
            exact = [
                item
                for item in attachments
                if str(_value(item, "instance_id") or "") == instance_id
                and str(_value(item, "lifecycle_state") or "").upper() == "ATTACHED"
            ]
            if len(exact) != 1:
                raise HarnessError("Oracle verification instance VNIC is ambiguous.")
            vnic_id = _require_ocid(
                _value(exact[0], "vnic_id"), label="verification VNIC", resource_type="vnic"
            )
            vnic = _data(
                self._call(self._clients["network"].get_vnic, vnic_id=vnic_id)
            )
        proof = self._expected_proof(name=name, tags=tags)
        proof["subnet_id"] = _require_ocid(
            _value(vnic, "subnet_id"), label="verification VNIC subnet", resource_type="subnet"
        )
        self._record(
            ledger_kind,
            vnic,
            proof,
            source_witness=instance_id,
        )
        return vnic

    def _attach_restored_block(self, instance, restored_volume):
        kind = "ui_block_restore_attachment"
        client = self._clients["compute"]
        existing = self._source_from_ledger(
            kind, client.get_volume_attachment, "volume_attachment_id"
        )
        if existing:
            return existing
        instance_id = str(_value(instance, "id") or "")
        volume_id = str(_value(restored_volume, "id") or "")
        attachments = self._list(
            client.list_volume_attachments,
            compartment_id=self.config.compartment_id,
            volume_id=volume_id,
        )
        attachments = [
            item
            for item in attachments
            if str(_value(item, "lifecycle_state") or "").upper() != "DETACHED"
        ]
        device = self._require_attachment_device(
            instance_id, RESTORE_BLOCK_DEVICE
        )
        matching = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "volume_id") or "") == volume_id
            and str(_value(item, "display_name") or "") == self.names[kind]
            and bool(_value(item, "is_read_only"))
            and str(_value(item, "device") or "") == device
        ]
        if len(matching) > 1 or any(item not in matching for item in attachments):
            raise HarnessError("Restored block volume has a foreign or ambiguous attachment.")
        candidate = matching[0] if matching else None
        if candidate is None:
            self._put_intent(kind, operation="attach_read_only", name=self.names[kind])
            details = self._models().AttachParavirtualizedVolumeDetails(
                display_name=self.names[kind],
                instance_id=instance_id,
                is_read_only=True,
                is_shareable=False,
                device=device,
                volume_id=volume_id,
            )
            try:
                candidate = _data(
                    self._mutation_call(
                        kind,
                        client.attach_volume,
                        attach_volume_details=details,
                        accepted=(200, 202),
                    )
                )
            except HarnessError as error:
                attachments = self._list(
                    client.list_volume_attachments,
                    compartment_id=self.config.compartment_id,
                    volume_id=volume_id,
                )
                attachments = [
                    item
                    for item in attachments
                    if str(_value(item, "lifecycle_state") or "").upper()
                    != "DETACHED"
                ]
                matching = [
                    item
                    for item in attachments
                    if str(_value(item, "instance_id") or "") == instance_id
                    and str(_value(item, "volume_id") or "") == volume_id
                    and str(_value(item, "display_name") or "") == self.names[kind]
                    and bool(_value(item, "is_read_only"))
                    and str(_value(item, "device") or "") == device
                ]
                if len(matching) != 1:
                    if not matching:
                        self._clear_definitely_rejected_intent(kind, error)
                    raise
                candidate = matching[0]
        attachment_id = _require_ocid(
            _value(candidate, "id"), label="restored block attachment", resource_type="volumeattachment"
        )
        attachment = self._wait_state(
            lambda value: self._call(
                client.get_volume_attachment, volume_attachment_id=value
            ),
            resource_id=attachment_id,
            ready={"ATTACHED"},
            failed={"DETACHED", "DETACHING"},
        )
        proof = self._expected_proof(name=self.names[kind], tags={})
        proof.update(
            {"instance_id": instance_id, "volume_id": volume_id, "device": device}
        )
        self._record(
            kind,
            attachment,
            proof,
            source_witness=f"{instance_id}:{volume_id}",
        )
        self.intents.clear(kind)
        return attachment

    def _launch_boot_verifier(self, restored_boot, *, subnet_id, shape):
        kind = "ui_boot_verify_instance"
        client = self._clients["compute"]
        boot_id = _require_ocid(
            _value(restored_boot, "id"),
            label="restored boot volume",
            resource_type="bootvolume",
        )
        row = self._active_ledger_entry(kind)
        if row:
            if (
                str(row.get("source_witness") or "") != boot_id
                or str((row.get("ownership") or {}).get("source_id") or "")
                != boot_id
            ):
                raise HarnessError(
                    "The boot verifier ledger source does not match the restored boot volume."
                )
            instance = _data(
                self._call(client.get_instance, instance_id=row["resource_id"])
            )
            self._verify_instance_boot_attachment(row["resource_id"], boot_id)
            self._assert_exact(
                instance,
                resource_id=row["resource_id"],
                proof=row["ownership"],
                source_id=boot_id,
            )
            return instance
        name = self.names[kind]
        tags = self._source_tags(kind)
        candidate = self._find_named(
            client.list_instances,
            name=name,
            tags=tags,
            compartment_id=self.config.compartment_id,
            display_name=name,
        )
        if candidate is None:
            _private, public_key = self._ensure_ssh_key()
            models = self._models()
            details = models.LaunchInstanceDetails(
                availability_domain=self.config.availability_domain,
                compartment_id=self.config.compartment_id,
                create_vnic_details=models.CreateVnicDetails(
                    assign_public_ip=self._assign_public_ip(),
                    display_name=self.names["ui_boot_verify_vnic"],
                    freeform_tags=self._source_tags("ui_boot_verify_vnic"),
                    subnet_id=subnet_id,
                ),
                display_name=name,
                freeform_tags=tags,
                metadata={"ssh_authorized_keys": public_key},
                shape=shape,
                source_details=models.InstanceSourceViaBootVolumeDetails(
                    boot_volume_id=boot_id
                ),
            )
            self._put_intent(kind, operation="launch", name=name)
            try:
                candidate = _data(
                    self._mutation_call(
                        kind,
                        client.launch_instance,
                        launch_instance_details=details,
                        opc_retry_token=_retry_token(f"{self.config.run_id}:{kind}"),
                        accepted=(200, 202),
                    )
                )
            except HarnessError as error:
                candidate = self._find_named(
                    client.list_instances,
                    name=name,
                    tags=tags,
                    compartment_id=self.config.compartment_id,
                    display_name=name,
                )
                if candidate is None:
                    self._clear_definitely_rejected_intent(kind, error)
                    raise
        instance_id = _require_ocid(
            _value(candidate, "id"), label="boot verifier instance", resource_type="instance"
        )
        instance = self._wait_state(
            lambda value: self._call(client.get_instance, instance_id=value),
            resource_id=instance_id,
            ready={"RUNNING", "STOPPED"},
            failed={"TERMINATED", "TERMINATING"},
        )
        self._verify_instance_boot_attachment(instance_id, boot_id)
        proof = self._expected_proof(
            name=name,
            tags=tags,
            availability_domain=self.config.availability_domain,
            source_id=boot_id,
        )
        self._record(
            kind,
            instance,
            proof,
            source_witness=boot_id,
            # OCI reports the original image_id on an instance launched from an
            # existing boot volume. The exact attached boot-volume relationship
            # above is the provider-authoritative source witness.
            source_id=boot_id,
        )
        self.intents.clear(kind)
        return instance

    def _verify_instance_boot_attachment(self, instance_id, expected_boot_id):
        """Require one exact ATTACHED boot volume for a verifier instance."""

        instance_id = _require_ocid(
            instance_id,
            label="boot verifier instance",
            resource_type="instance",
        )
        expected_boot_id = _require_ocid(
            expected_boot_id,
            label="restored boot volume",
            resource_type="bootvolume",
        )
        attachments = self._list(
            self._clients["compute"].list_boot_volume_attachments,
            availability_domain=self.config.availability_domain,
            compartment_id=self.config.compartment_id,
            instance_id=instance_id,
        )
        exact = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "lifecycle_state") or "").upper()
            == "ATTACHED"
        ]
        if len(exact) != 1:
            raise HarnessError(
                "The boot verifier instance attachment graph is ambiguous."
            )
        attached_boot_id = _require_ocid(
            _value(exact[0], "boot_volume_id"),
            label="boot verifier attached volume",
            resource_type="bootvolume",
        )
        if attached_boot_id != expected_boot_id:
            raise HarnessError(
                "The boot verifier instance is attached to a different boot volume."
            )
        return exact[0]

    def _verify_restored_data(
        self,
        *,
        source_instance,
        source_vnic,
        compute_restore,
        block_restore,
        boot_restore,
        compute_restore_tags,
        compute_restore_name,
        subnet_id,
        shape,
    ):
        evidence = self.evidence.get("payload")
        if not isinstance(evidence, dict) or not evidence.get("filesystem_flushed"):
            raise HarnessError("Durable source hash evidence is missing.")
        expected = {
            "sha256": str(evidence.get("sha256") or ""),
            "byte_count": int(evidence.get("byte_count") or -1),
        }
        if not re.fullmatch(r"[a-f0-9]{64}", expected["sha256"]) or expected["byte_count"] <= 0:
            raise HarnessError("Durable source hash evidence is malformed.")

        compute_vnic = self._record_instance_vnic(
            compute_restore,
            ledger_kind="ui_compute_restore_vnic",
            name=f"{compute_restore_name}-vnic"[:255],
            tags=compute_restore_tags,
        )
        self._ledger_compute_restore_boot(compute_restore)
        compute_ssh = self._ssh_client(
            compute_vnic,
            host_variable="ORACLE_E2E_COMPUTE_RESTORE_SSH_HOST",
        )
        try:
            compute_actual = self._remote_evidence(compute_ssh, evidence["boot_path"])
        finally:
            compute_ssh.close()
        if compute_actual != expected:
            raise HarnessError("Compute image restore failed boot-filesystem hash verification.")

        block_attachment = self._attach_restored_block(source_instance, block_restore)
        source_ssh = self._ssh_client(
            source_vnic,
            host_variable="ORACLE_E2E_SOURCE_SSH_HOST",
        )
        restore_mount = f"/mnt/backupsheep-e2e-{self.config.run_id}-restored"
        try:
            self._mount_volume(
                source_ssh,
                block_attachment,
                mount_path=restore_mount,
                read_only=True,
            )
            block_actual = self._remote_evidence(
                source_ssh, f"{restore_mount}/payload.bin"
            )
        finally:
            source_ssh.close()
        if block_actual != expected:
            raise HarnessError("Block-volume restore failed byte/hash verification.")

        boot_instance = self._launch_boot_verifier(
            boot_restore,
            subnet_id=subnet_id,
            shape=shape,
        )
        boot_vnic = self._record_instance_vnic(
            boot_instance,
            ledger_kind="ui_boot_verify_vnic",
            name=self.names["ui_boot_verify_vnic"],
            tags=self._source_tags("ui_boot_verify_vnic"),
        )
        boot_ssh = self._ssh_client(
            boot_vnic,
            host_variable="ORACLE_E2E_BOOT_VERIFY_SSH_HOST",
        )
        try:
            boot_actual = self._remote_evidence(boot_ssh, evidence["boot_path"])
        finally:
            boot_ssh.close()
        if boot_actual != expected:
            raise HarnessError("Boot-volume restore failed byte/hash verification.")
        result = {
            "expected": expected,
            "compute": compute_actual,
            "block": block_actual,
            "boot": boot_actual,
            "all_hashes_match": True,
        }
        self.evidence.put(
            "restore_verification",
            {
                "operation": "evidence",
                "kind": "restore_verification",
                "name": self.config.run_id,
                "marker": self.config.run_id,
                **result,
            },
        )
        return result

    def _verify_storage_objects(self, storage_manifest, *, record=True):
        client, secret = self._storage_s3_client()
        objects = storage_manifest.get("objects") or []
        kinds = {str(item.get("kind") or "") for item in objects if isinstance(item, dict)}
        if not {"website", "database"}.issubset(kinds):
            raise HarnessError(
                "Oracle storage evidence must include website and database backup objects."
            )
        try:
            maximum = int(
                self.environment.get("ORACLE_E2E_MAX_VERIFY_BYTES", str(20 * 1024**3))
            )
        except (TypeError, ValueError) as error:
            raise HarnessError("ORACLE_E2E_MAX_VERIFY_BYTES must be an integer.") from error
        if not 1 <= maximum <= 1024**4:
            raise HarnessError("ORACLE_E2E_MAX_VERIFY_BYTES is outside safe bounds.")
        verified = []
        seen = set()
        for item in objects:
            if not isinstance(item, dict):
                raise HarnessError("Oracle storage object evidence is malformed.")
            key = str(item.get("key") or "")
            version_id = str(item.get("version_id") or "")
            etag = str(item.get("etag") or "").strip('"')
            checksum = str(item.get("sha256") or "").lower()
            try:
                byte_count = int(item.get("byte_count"))
            except (TypeError, ValueError) as error:
                raise HarnessError("Oracle storage byte-count evidence is malformed.") from error
            identity = (key, version_id)
            if identity in seen:
                raise HarnessError("Oracle storage manifest contains a duplicate object version.")
            seen.add(identity)
            if (
                not key.startswith(secret["prefix"])
                or ".." in Path(key).parts
                or not version_id
                or version_id == "null"
                or not etag
                or not re.fullmatch(r"[a-f0-9]{64}", checksum)
                or byte_count < 0
                or byte_count > maximum
            ):
                raise HarnessError("Oracle storage object witness failed validation.")
            try:
                head = client.head_object(
                    Bucket=secret["bucket"], Key=key, VersionId=version_id
                )
                result = client.get_object(
                    Bucket=secret["bucket"], Key=key, VersionId=version_id
                )
                digest = hashlib.sha256()
                observed = 0
                while True:
                    chunk = result["Body"].read(1024 * 1024)
                    if not chunk:
                        break
                    observed += len(chunk)
                    if observed > maximum:
                        raise HarnessError("Oracle storage object exceeded the byte safety limit.")
                    digest.update(chunk)
                result["Body"].close()
            except HarnessError:
                raise
            except Exception as error:
                raise HarnessError("Oracle storage object verification failed.") from error
            metadata = head.get("Metadata") or {}
            if (
                str(head.get("VersionId") or "") != version_id
                or str(head.get("ETag") or "").strip('"') != etag
                or int(head.get("ContentLength") or -1) != byte_count
                or str(metadata.get("backupsheep-sha256") or "").lower() != checksum
                or str(metadata.get("backupsheep-bytes") or "") != str(byte_count)
                or observed != byte_count
                or digest.hexdigest() != checksum
            ):
                raise HarnessError("Oracle storage object failed hash/version/size verification.")
            witness = {
                "kind": str(item.get("kind") or ""),
                "key": key,
                "version_id": version_id,
                "etag": etag,
                "sha256": checksum,
                "byte_count": byte_count,
            }
            if record:
                self.evidence.put(
                    f"storage-{hashlib.sha256(f'{key}:{version_id}'.encode()).hexdigest()[:24]}",
                    {
                        "operation": "evidence",
                        "kind": "storage_object",
                        "name": key,
                        "marker": self.config.run_id,
                        **witness,
                    },
                )
            verified.append(witness)
        return {"objects_verified": len(verified), "objects": verified}

    def _validate_workload_guest_durable_scope(self, scope):
        _path, payload = _read_private_json(
            scope["durable_ledger_path"],
            variable="workload durable ledger",
            exact_keys={
                "schema",
                "provider",
                "run_id",
                "scope",
                "created_at",
                "resources",
            },
        )
        if (
            payload.get("schema") != 1
            or payload.get("provider") != "upcloud"
            or payload.get("run_id") != scope["run_id"]
            or payload.get("scope") != scope["durable_ledger_scope"]
            or not isinstance(payload.get("resources"), list)
        ):
            raise HarnessError("Workload durable ledger does not match the guest scope.")
        matches = []
        for row in payload["resources"]:
            if not isinstance(row, dict):
                raise HarnessError("Workload durable ledger contains a malformed row.")
            ownership = row.get("ownership") or {}
            if (
                row.get("kind") == "compute_workload_fixture"
                and str(row.get("resource_id") or "") == scope["source_server_id"]
                and row.get("cleanup_state") in {"eligible", "failed"}
                and isinstance(ownership, dict)
                and ownership.get("account") == scope["durable_ledger_scope"]
                and ownership.get("run_id") == scope["run_id"]
                and ownership.get("server_id") == scope["source_server_id"]
                and ownership.get("website_root") == scope["website_source_root"]
                and ownership.get("database_name") == scope["source_database"]
                and str(row.get("name") or "") == scope["safe_root"]
                and str(row.get("source_witness") or "") == scope["source_server_id"]
            ):
                matches.append(row)
        if len(matches) != 1:
            raise HarnessError(
                "Workload guest scope requires one exact durable UpCloud fixture row."
            )
        return matches[0]

    def _validate_workload_guest_files(self, scope):
        key_path, key_bytes, key_digest = _read_private_bytes(
            scope["ssh_private_key_path"], variable="workload SSH private key"
        )
        known_hosts_path, _known_hosts, known_hosts_digest = _read_private_bytes(
            scope["known_hosts_path"], variable="workload known-hosts file"
        )
        if (
            key_digest != scope["ssh_private_key_sha256"]
            or known_hosts_digest != scope["known_hosts_sha256"]
        ):
            raise HarnessError("Workload SSH protected-file binding changed.")
        return key_path, known_hosts_path, key_bytes

    @staticmethod
    def _ssh_key_fingerprint(key):
        try:
            raw = key.asbytes()
        except Exception as error:
            raise HarnessError("Pinned workload SSH host key is unreadable.") from error
        if not isinstance(raw, bytes) or not raw:
            raise HarnessError("Pinned workload SSH host key is malformed.")
        return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode(
            "ascii"
        ).rstrip("=")

    def _readonly_workload_ssh_client(self, scope):
        """Connect only through preexisting key material and a pinned host key."""

        self._validate_workload_guest_durable_scope(scope)
        _key_path, known_hosts_path, key_bytes = self._validate_workload_guest_files(
            scope
        )
        try:
            import paramiko
        except Exception as error:
            raise HarnessError("Paramiko is required for workload verification.") from error
        client = paramiko.SSHClient()
        try:
            client.load_host_keys(str(known_hosts_path))
            host_keys = client.get_host_keys().lookup(scope["ssh_host"])
            if not isinstance(host_keys, Mapping):
                raise HarnessError("Workload SSH host is absent from the pinned file.")
            key = host_keys.get(scope["known_host_key_type"])
            if (
                key is None
                or self._ssh_key_fingerprint(key)
                != scope["known_host_fingerprint"]
            ):
                raise HarnessError("Workload SSH host fingerprint does not match.")
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            try:
                private_key_text = key_bytes.decode("ascii", "strict")
            except UnicodeDecodeError as error:
                raise HarnessError("Workload SSH private key is not canonical text.") from error
            private_key = paramiko.RSAKey.from_private_key(
                io.StringIO(private_key_text)
            )
            client.connect(
                hostname=scope["ssh_host"],
                port=scope["ssh_port"],
                username=scope["ssh_user"],
                pkey=private_key,
                allow_agent=False,
                look_for_keys=False,
                timeout=REQUEST_TIMEOUT[0],
                banner_timeout=REQUEST_TIMEOUT[1],
                auth_timeout=REQUEST_TIMEOUT[1],
            )
            remote = client.get_transport().get_remote_server_key()
            if (
                remote.get_name() != scope["known_host_key_type"]
                or self._ssh_key_fingerprint(remote)
                != scope["known_host_fingerprint"]
            ):
                raise HarnessError("Workload SSH server changed after connection.")
            # Re-read both files after connection. This proves the read-only
            # path neither chmods nor performs TOFU/known-host publication.
            self._validate_workload_guest_files(scope)
            return client
        except HarnessError:
            client.close()
            raise
        except Exception as error:
            client.close()
            raise HarnessError("Pinned workload SSH connection failed.") from error

    def _website_workload_evidence(self, client, path, *, safe_root):
        path = str(path or "")
        if (
            not path.startswith(f"{safe_root}/")
            or ".." in Path(path).parts
        ):
            raise HarnessError("Website evidence path escaped the exact guest root.")
        program = (
            "import hashlib,json,os,stat,sys;root=sys.argv[1];rows=[];modes=[];total=0;"
            "\nif not os.path.isdir(root) or os.path.islink(root): raise SystemExit(3)"
            "\nroot_stat=os.lstat(root);modes.append(['D','.',stat.S_IMODE(root_stat.st_mode)])"
            "\nfor base,dirs,files in os.walk(root,followlinks=False):"
            "\n dirs.sort();files.sort()"
            "\n for name in dirs:"
            "\n  p=os.path.join(base,name);s=os.lstat(p)"
            "\n  if not stat.S_ISDIR(s.st_mode): raise SystemExit(4)"
            "\n  rel=os.path.relpath(p,root);rows.append(['D',rel]);modes.append(['D',rel,stat.S_IMODE(s.st_mode)])"
            "\n for name in files:"
            "\n  p=os.path.join(base,name);s=os.lstat(p)"
            "\n  if not stat.S_ISREG(s.st_mode): raise SystemExit(4)"
            "\n  rel=os.path.relpath(p,root);h=hashlib.sha256()"
            "\n  with open(p,'rb') as f:"
            "\n   while True:"
            "\n    b=f.read(1048576)"
            "\n    if not b: break"
            "\n    h.update(b)"
            "\n  rows.append(['F',rel,s.st_size,h.hexdigest()]);modes.append(['F',rel,stat.S_IMODE(s.st_mode)]);total+=s.st_size"
            "\ncanon=json.dumps(rows,separators=(',',':'),ensure_ascii=True).encode();"
            "mode=json.dumps(modes,separators=(',',':'),ensure_ascii=True).encode();"
            "file_count=sum(1 for row in rows if row[0]=='F');"
            "print(json.dumps({'tree_sha256':hashlib.sha256(canon).hexdigest(),'file_count':file_count,'byte_count':total,'mode_sha256':hashlib.sha256(mode).hexdigest()},sort_keys=True))"
        )
        output = self._ssh_run(
            client,
            f"python3 -c {shlex.quote(program)} {shlex.quote(path)}",
        )
        try:
            evidence = json.loads(output)
        except (TypeError, ValueError) as error:
            raise HarnessError("Oracle website evidence output is malformed.") from error
        return self._hash_evidence(evidence, field="website readback")

    def _database_workload_evidence(self, client, database, *, allowed_databases):
        database = str(database or "")
        if (
            not re.fullmatch(r"[a-z][a-z0-9_]{2,62}", database)
            or database not in {str(item) for item in allowed_databases}
        ):
            raise HarnessError("Database evidence target escaped the exact workload manifest.")
        db = shlex.quote(database)
        psql = (
            "sudo -n -u postgres psql --no-psqlrc -At -v ON_ERROR_STOP=1 "
            f"-d {db}"
        )
        schema_query = (
            "SELECT table_schema || '|' || table_name || '|' || column_name || '|' || "
            "ordinal_position::text || '|' || data_type || '|' || udt_schema || '.' || "
            "udt_name || '|' || is_nullable || '|' || coalesce(column_default,'') "
            "FROM information_schema.columns WHERE table_schema NOT IN "
            "('pg_catalog','information_schema') ORDER BY table_schema,table_name,ordinal_position;"
        )
        data_query = (
            "SELECT format('SELECT %L || ''|'' || to_jsonb(t)::text FROM %I.%I AS t "
            "ORDER BY to_jsonb(t)::text COLLATE \"C\";', schemaname || '.' || tablename, "
            "schemaname, tablename) FROM pg_catalog.pg_tables WHERE schemaname NOT IN "
            "('pg_catalog','information_schema') ORDER BY schemaname,tablename;"
        )
        schema_pipeline = (
            f"LC_ALL=C {psql} -c {shlex.quote(schema_query)} "
            "| sha256sum | awk '{print $1}'"
        )
        data_pipeline = (
            f"LC_ALL=C {psql} -c {shlex.quote(data_query)} | {psql} "
            "| sha256sum | awk '{print $1}'"
        )
        schema_command = "bash -o pipefail -c " + shlex.quote(schema_pipeline)
        data_command = "bash -o pipefail -c " + shlex.quote(data_pipeline)
        table_command = (
            f"{psql} -c "
            + shlex.quote(
                "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname NOT IN "
                "('pg_catalog','information_schema');"
            )
        )
        row_query = (
            "SELECT format('SELECT count(*) FROM %I.%I;',schemaname,tablename) "
            "FROM pg_catalog.pg_tables WHERE schemaname NOT IN "
            "('pg_catalog','information_schema') ORDER BY schemaname,tablename;"
        )
        row_pipeline = (
            f"{psql} -c {shlex.quote(row_query)} | {psql} "
            "| awk '{s+=$1} END {print s+0}'"
        )
        row_command = "bash -o pipefail -c " + shlex.quote(row_pipeline)
        values = {
            "schema_sha256": self._ssh_run(client, schema_command).strip(),
            "data_sha256": self._ssh_run(client, data_command).strip(),
            "table_count": self._ssh_run(client, table_command).strip(),
            "row_count": self._ssh_run(client, row_command).strip(),
        }
        return self._hash_evidence(values, field="database readback", database=True)

    def _verify_workloads_manifest(self, manifest, *, record=False):
        """Perform guest readbacks for an already preflighted exact manifest."""

        scope = manifest["workload_guest_scope"]
        website = manifest["workloads"]["website"]
        database = manifest["workloads"]["database"]
        allowed_databases = {
            scope["source_database"],
            database["restore_database"],
        }
        client = self._readonly_workload_ssh_client(scope)
        try:
            actual = {
                "website": {
                    "source": self._website_workload_evidence(
                        client,
                        scope["website_source_root"],
                        safe_root=scope["safe_root"],
                    ),
                    "restored": self._website_workload_evidence(
                        client,
                        website["restore_path"],
                        safe_root=scope["safe_root"],
                    ),
                },
                "database": {
                    "source": self._database_workload_evidence(
                        client,
                        scope["source_database"],
                        allowed_databases=allowed_databases,
                    ),
                    "restored": self._database_workload_evidence(
                        client,
                        database["restore_database"],
                        allowed_databases=allowed_databases,
                    ),
                },
            }
        finally:
            client.close()
        for kind in ("website", "database"):
            if (
                actual[kind]["source"] != manifest["workloads"][kind]["source"]
                or actual[kind]["restored"] != manifest["workloads"][kind]["restored"]
                or actual[kind]["source"] != actual[kind]["restored"]
            ):
                raise HarnessError(f"Oracle {kind} UI restore failed application verification.")
        result = {
            "website": actual["website"]["restored"],
            "database": actual["database"]["restored"],
            "all_evidence_matches": True,
        }
        if record:
            self.evidence.put(
                "workload_restore_verification",
                {
                    "operation": "evidence",
                    "kind": "workload_restore_verification",
                    "name": self.config.run_id,
                    "marker": self.config.run_id,
                    **result,
                },
            )
        return result

    def verify_workloads(self, manifest_path, *, record=False):
        """Verify workloads only after complete local/storage/scope preflight."""

        if record:
            self._require_apply()
        local = self._local_verification_preflight(manifest_path)
        return self._verify_workloads_manifest(local["manifest"], record=record)

    def verify_workloads_read_only(self, manifest_path):
        """Run workload reads only after every local/storage preflight passes."""

        if not self.read_only:
            raise HarnessError("Read-only workload verification requires a read-only harness.")
        return self.verify_workloads(manifest_path, record=False)

    def provision(self):
        """Create only run-owned sources and destination fixtures under APPLY."""

        self._require_apply()
        self._load_clients()
        self._validate_scope()
        subnet_id, image_id, shape = self._validate_instance_inputs()
        self._ensure_ssh_key()
        block = self._provision_block_volume()
        instance = self._provision_instance(subnet_id, image_id, shape)
        vnic = self._provision_vnic(instance)
        boot = self._provision_boot_volume(instance)
        attachment = self._attach_source_block(instance, block)
        data = self._seed_data(
            vnic,
            attachment,
            instance_id=str(_value(instance, "id") or ""),
            block_volume_id=str(_value(block, "id") or ""),
            boot_volume_id=str(_value(boot, "id") or ""),
        )
        storage = self._provision_storage()
        return {
            "phase": "PROVISIONED",
            "run_id": self.config.run_id,
            "compartment_id": self.config.compartment_id,
            "availability_domain": self.config.availability_domain,
            "ui_attachment": {
                "compute_instance_ocid": str(_value(instance, "id") or ""),
                "block_volume_ocid": str(_value(block, "id") or ""),
                "boot_volume_ocid": str(_value(boot, "id") or ""),
            },
            "source_graph": {
                "vnic_ocid": str(_value(vnic, "id") or ""),
                "block_attachment_ocid": str(_value(attachment, "id") or ""),
            },
            "data_evidence": {
                "sha256": data["sha256"],
                "byte_count": data["byte_count"],
                "filesystem_flushed": data["filesystem_flushed"],
            },
            "object_storage": storage,
        }

    def _local_verification_preflight(self, manifest_path):
        """Validate every local artifact before provider or guest I/O."""

        manifest = self._load_ui_manifest(manifest_path)
        source_rows = {
            "compute": self._active_ledger_entry("source_instance"),
            "block": self._active_ledger_entry("source_block_volume"),
            "boot": self._active_ledger_entry("source_boot_volume"),
        }
        if any(row is None for row in source_rows.values()):
            raise HarnessError("All Oracle source OCIDs must exist in the durable ledger.")
        for kind, row in source_rows.items():
            if manifest[kind]["source_ocid"] != row["resource_id"]:
                raise HarnessError(f"Oracle {kind} manifest source is not ledger-owned.")
        payload = self.evidence.get("payload")
        try:
            payload_bytes = int(payload.get("byte_count") or 0) if isinstance(payload, dict) else 0
        except (TypeError, ValueError):
            payload_bytes = 0
        if (
            not isinstance(payload, dict)
            or not payload.get("filesystem_flushed")
            or not re.fullmatch(r"[a-f0-9]{64}", str(payload.get("sha256") or ""))
            or payload_bytes <= 0
        ):
            raise HarnessError("Durable source payload evidence is missing or malformed.")
        storage_scope = self._storage_scope_for_s3()
        secret = self._read_storage_secret(
            expected_scope=storage_scope, require_evidence=False
        )
        if secret is None:
            raise HarnessError("Oracle Object Storage credential file is missing.")
        self._validate_workload_guest_durable_scope(
            manifest["workload_guest_scope"]
        )
        self._validate_workload_guest_files(manifest["workload_guest_scope"])
        if self.intents.pending():
            raise HarnessError("Oracle verification is blocked by unresolved mutation intents.")
        return {
            "manifest": manifest,
            "source_rows": source_rows,
            "storage_scope": storage_scope,
            "ui_ledger_digest": _file_digest(
                self.config.ledger_path, variable="Oracle UI ledger"
            ),
        }

    def _provider_verification_preflight(self, local):
        """Perform readbacks only; this method cannot write durable state."""

        self._load_clients()
        self._validate_scope()
        subnet_id, _image_id, shape = self._validate_instance_inputs()
        manifest = local["manifest"]
        source_rows = local["source_rows"]
        source_instance = self._source_from_ledger(
            "source_instance", self._clients["compute"].get_instance, "instance_id"
        )
        source_vnic = self._source_from_ledger(
            "source_vnic", self._clients["network"].get_vnic, "vnic_id"
        )
        backups = {
            kind: self._verify_ui_backup(
                kind, manifest[kind], source_rows[kind], record=False
            )
            for kind in ("compute", "block", "boot")
        }
        restores = {
            kind: self._verify_ui_restore(
                kind,
                manifest[kind],
                source_rows[kind],
                backups[kind],
                record=False,
            )
            for kind in ("compute", "block", "boot")
        }
        storage = self._verify_storage_objects(manifest["storage"], record=False)
        return {
            **local,
            "subnet_id": subnet_id,
            "shape": shape,
            "source_instance": source_instance,
            "source_vnic": source_vnic,
            "backups": backups,
            "restores": restores,
            "storage": storage,
        }

    def report(self, manifest_path):
        """Read-only ownership/object/workload report with no durable writes."""

        if not self.read_only:
            raise HarnessError("Read-only report requires a read-only harness instance.")
        local = self._local_verification_preflight(manifest_path)
        checked = self._provider_verification_preflight(local)
        workloads = self._verify_workloads_manifest(
            checked["manifest"], record=False
        )
        return {
            "phase": "READ_ONLY_REPORT",
            "run_id": self.config.run_id,
            "provider_mutations": False,
            "guest_mutations": False,
            "local_writes": False,
            "backup_ocids": {
                kind: str(_value(resource, "id") or "")
                for kind, resource in checked["backups"].items()
            },
            "restore_ocids": {
                kind: str(_value(resource, "id") or "")
                for kind, resource in checked["restores"].items()
            },
            "storage_evidence": checked["storage"],
            "workload_evidence": workloads,
            "requires_verify_apply": [
                "compute restore boot-filesystem bytes",
                "restored block-volume read-only attachment bytes",
                "restored boot-volume verifier bytes",
            ],
        }

    def verify_apply(self, manifest_path):
        """Apply-gated byte verification after complete read-only preflight."""

        self._require_apply()
        local = self._local_verification_preflight(manifest_path)
        checked = self._provider_verification_preflight(local)
        # Workload reads occur only after every local/storage/provider preflight
        # has passed. They are read-only, but still guest actions.
        workload_readback = self._verify_workloads_manifest(
            checked["manifest"], record=False
        )
        manifest = checked["manifest"]
        source_rows = checked["source_rows"]
        backups = {
            kind: self._verify_ui_backup(kind, manifest[kind], source_rows[kind])
            for kind in ("compute", "block", "boot")
        }
        restores = {
            kind: self._verify_ui_restore(
                kind, manifest[kind], source_rows[kind], backups[kind]
            )
            for kind in ("compute", "block", "boot")
        }
        compute_restore_evidence = manifest["compute"]["restore"]
        compute_tags = self._restore_tags(
            compute_restore_evidence,
            source_backup_id=str(_value(backups["compute"], "id") or ""),
            source_id=source_rows["compute"]["resource_id"],
            target_type="instance",
        )
        data = self._verify_restored_data(
            source_instance=checked["source_instance"],
            source_vnic=checked["source_vnic"],
            compute_restore=restores["compute"],
            block_restore=restores["block"],
            boot_restore=restores["boot"],
            compute_restore_tags=compute_tags,
            compute_restore_name=str(compute_restore_evidence["name"]),
            subnet_id=checked["subnet_id"],
            shape=checked["shape"],
        )
        storage = self._verify_storage_objects(manifest["storage"])
        self.evidence.put(
            "workload_restore_verification",
            {
                "operation": "evidence",
                "kind": "workload_restore_verification",
                "name": self.config.run_id,
                "marker": self.config.run_id,
                **workload_readback,
            },
        )
        workloads = workload_readback
        return {
            "phase": "VERIFIED_APPLY",
            "run_id": self.config.run_id,
            "backup_ocids": {
                kind: str(_value(resource, "id") or "")
                for kind, resource in backups.items()
            },
            "restore_ocids": {
                kind: str(_value(resource, "id") or "")
                for kind, resource in restores.items()
            },
            "data_evidence": data,
            "storage_evidence": storage,
            "workload_evidence": workloads,
            "metadata_only": False,
        }

    def _graph_inventory(self, kind):
        compute = self._clients["compute"]
        block = self._clients["block"]
        network = self._clients["network"]
        compartment = self.config.compartment_id
        availability_domain = self.config.availability_domain
        if kind in {"source_instance", "ui_compute_restore", "ui_boot_verify_instance"}:
            return self._list(compute.list_instances, compartment_id=compartment)
        if kind in {"source_block_volume", "ui_block_restore"}:
            return self._list(
                block.list_volumes,
                compartment_id=compartment,
                availability_domain=availability_domain,
            )
        if kind in {
            "source_boot_volume",
            "ui_boot_restore",
            "ui_compute_restore_boot_volume",
        }:
            return self._list(
                block.list_boot_volumes,
                compartment_id=compartment,
                availability_domain=availability_domain,
            )
        if kind == "ui_compute_backup":
            return self._list(compute.list_images, compartment_id=compartment)
        if kind == "ui_block_backup":
            return self._list(block.list_volume_backups, compartment_id=compartment)
        if kind == "ui_boot_backup":
            return self._list(block.list_boot_volume_backups, compartment_id=compartment)
        if kind in {"source_block_attachment", "ui_block_restore_attachment"}:
            return self._list(
                compute.list_volume_attachments,
                compartment_id=compartment,
            )
        if kind in {"source_vnic", "ui_compute_restore_vnic", "ui_boot_verify_vnic"}:
            attachments = self._list(
                compute.list_vnic_attachments,
                compartment_id=compartment,
            )
            resources = []
            seen = set()
            for attachment in attachments:
                if str(_value(attachment, "lifecycle_state") or "").upper() in {
                    "DETACHED",
                    "DETACHING",
                }:
                    continue
                vnic_id = str(_value(attachment, "vnic_id") or "")
                if not vnic_id or vnic_id in seen:
                    continue
                seen.add(vnic_id)
                resources.append(
                    _data(self._call(network.get_vnic, vnic_id=vnic_id))
                )
            return resources
        raise HarnessError(f"Unsupported Oracle cleanup kind: {kind}.")

    def _exact_graph_resource(self, kind, row):
        matches = [
            item
            for item in self._graph_inventory(kind)
            if str(_value(item, "id") or "") == str(row["resource_id"])
        ]
        if len(matches) > 1:
            raise HarnessError("Oracle cleanup inventory contains a duplicate OCID.")
        if not matches:
            return None
        resource = matches[0]
        if kind == "ui_compute_backup":
            source_id = _tags(resource).get(BACKUP_SOURCE_TAG)
        elif kind == "ui_block_backup":
            source_id = _value(resource, "volume_id")
        elif kind == "ui_boot_backup":
            source_id = _value(resource, "boot_volume_id")
        else:
            source_id = None
        self._assert_exact(
            resource,
            resource_id=row["resource_id"],
            proof=row["ownership"],
            source_id=source_id,
        )
        return resource

    def _wait_graph_absent(self, kind, resource_id, *, terminal_ok=False):
        deadline = time.monotonic() + self.config.timeout_seconds
        while True:
            matches = [
                item
                for item in self._graph_inventory(kind)
                if str(_value(item, "id") or "") == str(resource_id)
            ]
            if not matches:
                return
            if len(matches) > 1:
                raise HarnessError("Oracle cleanup inventory contains a duplicate OCID.")
            state = str(_value(matches[0], "lifecycle_state") or "").upper()
            if terminal_ok and state == "TERMINATED":
                return
            if time.monotonic() >= deadline:
                raise HarnessError("Oracle cleanup waiter reached its bounded timeout.")
            self._sleep(self.config.poll_seconds)

    def _unmount_test_attachment(self, kind):
        if kind not in {"source_block_attachment", "ui_block_restore_attachment"}:
            raise HarnessError("Unsupported Oracle attachment unmount kind.")
        instance_row = self._active_ledger_entry("source_instance")
        vnic_row = self._active_ledger_entry("source_vnic")
        if not instance_row or not vnic_row:
            raise HarnessError(
                "Oracle attachment cleanup lacks its exact instance/VNIC ledger graph."
            )
        instance = self._exact_graph_resource("source_instance", instance_row)
        vnic = self._exact_graph_resource("source_vnic", vnic_row)
        if instance is None or vnic is None:
            raise HarnessError(
                "Oracle attachment cleanup cannot reach its exact test-owned host."
            )
        mount_path = (
            f"/mnt/backupsheep-e2e-{self.config.run_id}"
            if kind == "source_block_attachment"
            else f"/mnt/backupsheep-e2e-{self.config.run_id}-restored"
        )
        client = self._ssh_client(
            vnic,
            host_variable="ORACLE_E2E_SOURCE_SSH_HOST",
        )
        try:
            quoted = shlex.quote(mount_path)
            self._ssh_run(
                client,
                f"if mountpoint -q {quoted}; then sudo umount {quoted}; fi",
            )
            self._ssh_run(client, "sudo sync")
        finally:
            client.close()

    def _cleanup_intent_key(self, kind, resource_id, operation, discriminator=""):
        fingerprint = hashlib.sha256(
            json.dumps(
                [
                    self.config.run_id,
                    str(kind),
                    str(resource_id),
                    str(operation),
                    str(discriminator),
                ],
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:32]
        return f"{CLEANUP_INTENT_PREFIX}{kind}:{fingerprint}"

    @staticmethod
    def _cleanup_state(resource):
        return str(_value(resource, "lifecycle_state") or "").upper()

    def _cleanup_complete(self, key, row, *, mark_ledger=True):
        if mark_ledger:
            self.ledger.mark_cleanup(
                row["kind"], row["resource_id"], state="deleted"
            )
        self.intents.clear(key)
        return "DELETED"

    def _cleanup_manual_review(self, key, row, *, reason="PROVIDER_AMBIGUOUS"):
        """Persist an ambiguity and make subsequent runs refuse replay."""

        self.intents.update(
            key,
            state="manual_review",
            reconciliation="PROVIDER_AMBIGUOUS",
            reconciliation_reason=str(reason or "PROVIDER_AMBIGUOUS")[:120],
        )
        self.ledger.mark_cleanup(
            row["kind"],
            row["resource_id"],
            state="manual_review",
            error="PROVIDER_AMBIGUOUS",
        )
        raise HarnessError(
            "Oracle cleanup outcome is ambiguous; the provider request will not be replayed."
        )

    def _reconcile_cleanup_intent(
        self,
        key,
        row,
        *,
        probe,
        operation=None,
        terminal_states=(),
        mark_ledger=True,
    ):
        intent = self.intents.get(key)
        if not intent:
            return None
        if (
            str(intent.get("provider_resource_id") or "") != str(row["resource_id"])
            or str(intent.get("kind") or "") != str(row["kind"])
            or (operation and str(intent.get("operation") or "") != str(operation))
        ):
            self._cleanup_manual_review(key, row, reason="OWNERSHIP_WITNESS_CHANGED")
        try:
            resource = probe()
        except HarnessError as error:
            self._cleanup_manual_review(key, row, reason=error.code or "PROVIDER_READ_FAILED")
        if resource is None or self._cleanup_state(resource) in set(terminal_states):
            return self._cleanup_complete(key, row, mark_ledger=mark_ledger)

        state = str(intent.get("state") or "").lower()
        provider_state = self._cleanup_state(resource)
        if state == "accepted" or (
            state == "submitted" and provider_state in CLEANUP_TRANSITIONAL_STATES
        ):
            return self._wait_cleanup_intent(
                key,
                row,
                probe=probe,
                terminal_states=terminal_states,
                mark_ledger=mark_ledger,
            )
        self._cleanup_manual_review(key, row)

    def _wait_cleanup_intent(
        self,
        key,
        row,
        *,
        probe,
        terminal_states=(),
        mark_ledger=True,
    ):
        deadline = time.monotonic() + self.config.timeout_seconds
        while True:
            try:
                resource = probe()
            except HarnessError as error:
                self._cleanup_manual_review(
                    key, row, reason=error.code or "PROVIDER_READ_FAILED"
                )
            if resource is None or self._cleanup_state(resource) in set(terminal_states):
                return self._cleanup_complete(key, row, mark_ledger=mark_ledger)
            intent = self.intents.get(key)
            state = str((intent or {}).get("state") or "").lower()
            provider_state = self._cleanup_state(resource)
            if state != "accepted" and provider_state not in CLEANUP_TRANSITIONAL_STATES:
                self._cleanup_manual_review(key, row)
            if time.monotonic() >= deadline:
                self._cleanup_manual_review(key, row, reason="PROVIDER_TIMEOUT")
            self._sleep(self.config.poll_seconds)

    def _run_cleanup_mutation(
        self,
        row,
        *,
        operation,
        method,
        operation_kwargs,
        probe,
        terminal_states=(),
        discriminator="",
        mark_ledger=True,
    ):
        kind = row["kind"]
        resource_id = row["resource_id"]
        key = self._cleanup_intent_key(
            kind, resource_id, operation, discriminator=discriminator
        )
        current = self.intents.get(key)
        if current:
            expected_fingerprint = hashlib.sha256(
                json.dumps(
                    operation_kwargs, sort_keys=True, default=str, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            if (
                str(current.get("provider_resource_id") or "") != str(resource_id)
                or str(current.get("request_fingerprint") or "") != expected_fingerprint
            ):
                self._cleanup_manual_review(key, row, reason="OWNERSHIP_WITNESS_CHANGED")
            return self._reconcile_cleanup_intent(
                key,
                row,
                probe=probe,
                terminal_states=terminal_states,
                mark_ledger=mark_ledger,
            )

        request_fingerprint = hashlib.sha256(
            json.dumps(
                operation_kwargs, sort_keys=True, default=str, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.intents.put(
            key,
            {
                "operation": operation,
                "kind": kind,
                "name": str(row.get("name") or resource_id),
                "marker": self.config.run_id,
                "provider_resource_id": resource_id,
                "request_fingerprint": request_fingerprint,
                "state": "prepared",
            },
        )
        # A crash after this fsync and before the provider call is deliberately
        # treated the same as a lost response. Cleanup never blindly replays a
        # request whose acceptance cannot be proven.
        self.intents.update(key, state="submitted")
        try:
            self._call(
                method,
                accepted=(200, 202, 204),
                mutation=True,
                **operation_kwargs,
            )
        except HarnessError as error:
            self.intents.update(
                key,
                state="rejected" if error.definitive_rejection else "submitted",
                provider_error=error.code or "PROVIDER_REQUEST_FAILED",
            )
            return self._reconcile_cleanup_intent(
                key,
                row,
                probe=probe,
                terminal_states=terminal_states,
                mark_ledger=mark_ledger,
            )
        self.intents.update(key, state="accepted")
        return self._wait_cleanup_intent(
            key,
            row,
            probe=probe,
            terminal_states=terminal_states,
            mark_ledger=mark_ledger,
        )

    def _cleanup_graph_kind(self, kind):
        row = self._active_ledger_entry(kind)
        if row is None:
            return "NOT_LEDGERED"
        resource_id = row["resource_id"]
        operation = {
            "source_block_attachment": "detach",
            "ui_block_restore_attachment": "detach",
            "source_instance": "terminate",
            "ui_compute_restore": "terminate",
            "ui_boot_verify_instance": "terminate",
            "ui_compute_backup": "delete_image",
            "ui_block_backup": "delete_volume_backup",
            "ui_boot_backup": "delete_boot_volume_backup",
            "source_block_volume": "delete_volume",
            "ui_block_restore": "delete_volume",
            "source_boot_volume": "delete_boot_volume",
            "ui_boot_restore": "delete_boot_volume",
            "ui_compute_restore_boot_volume": "delete_boot_volume",
        }.get(kind)
        if not operation:
            if kind in {"source_vnic", "ui_compute_restore_vnic", "ui_boot_verify_vnic"}:
                resource = self._exact_graph_resource(kind, row)
                if resource is None:
                    self.ledger.mark_cleanup(kind, resource_id, state="absent")
                    return "ABSENT"
                raise HarnessError(
                    "A ledgered VNIC still exists after its exact parent instance was terminated."
                )
            raise HarnessError("Unsupported Oracle graph cleanup kind.")

        probe = lambda: self._exact_graph_resource(kind, row)
        key = self._cleanup_intent_key(kind, resource_id, operation)
        if self.intents.get(key):
            return self._reconcile_cleanup_intent(
                key,
                row,
                probe=probe,
                operation=operation,
                terminal_states={"TERMINATED"} if operation == "terminate" else set(),
            )
        resource = probe()
        if resource is None:
            self.ledger.mark_cleanup(kind, resource_id, state="absent")
            return "ABSENT"
        if operation == "detach":
            operation_kwargs = {"volume_attachment_id": resource_id}
        elif operation == "terminate":
            operation_kwargs = {
                "instance_id": resource_id,
                "preserve_boot_volume": True,
            }
        elif operation == "delete_image":
            operation_kwargs = {"image_id": resource_id}
        elif operation == "delete_volume_backup":
            operation_kwargs = {"volume_backup_id": resource_id}
        elif operation == "delete_boot_volume_backup":
            operation_kwargs = {"boot_volume_backup_id": resource_id}
        elif operation == "delete_volume":
            operation_kwargs = {"volume_id": resource_id}
        else:
            operation_kwargs = {"boot_volume_id": resource_id}
        if operation == "detach":
            self._unmount_test_attachment(kind)
        method = {
            "detach": self._clients["compute"].detach_volume,
            "terminate": self._clients["compute"].terminate_instance,
            "delete_image": self._clients["compute"].delete_image,
            "delete_volume_backup": self._clients["block"].delete_volume_backup,
            "delete_boot_volume_backup": self._clients["block"].delete_boot_volume_backup,
            "delete_volume": self._clients["block"].delete_volume,
            "delete_boot_volume": self._clients["block"].delete_boot_volume,
        }[operation]
        try:
            return self._run_cleanup_mutation(
                row,
                operation=operation,
                method=method,
                operation_kwargs=operation_kwargs,
                probe=probe,
                terminal_states={"TERMINATED"} if operation == "terminate" else set(),
            )
        except Exception as error:
            current = self.ledger.get(kind, resource_id)
            if not current or current.get("cleanup_state") != "manual_review":
                self.ledger.mark_cleanup(
                    kind,
                    resource_id,
                    state="failed",
                    error=_provider_error_code(error),
                )
            raise

    def _object_inventory(self, namespace, bucket):
        client = self._clients["object"]
        versions = []
        page = ""
        seen_pages = set()
        for _ in range(MAX_PAGES):
            request = {
                "namespace_name": namespace,
                "bucket_name": bucket,
                "limit": 1000,
            }
            if page:
                request["page"] = page
            response = self._call(client.list_object_versions, **request)
            data = _data(response)
            rows = (
                data
                if isinstance(data, (list, tuple))
                else _value(data, "items", _value(data, "objects"))
            )
            if not isinstance(rows, (list, tuple)):
                raise HarnessError("OCI object-version inventory is malformed.")
            versions.extend(rows)
            if len(versions) > MAX_ITEMS:
                raise HarnessError("OCI object-version inventory exceeded the safety limit.")
            next_page = _next_page(response)
            if not next_page:
                break
            if next_page in seen_pages:
                raise HarnessError("OCI object-version inventory repeated a cursor.")
            seen_pages.add(next_page)
            page = next_page
        else:
            raise HarnessError("OCI object-version inventory exceeded the page limit.")

        objects = []
        start = ""
        seen_starts = set()
        for _ in range(MAX_PAGES):
            request = {
                "namespace_name": namespace,
                "bucket_name": bucket,
                "limit": 1000,
            }
            if start:
                request["start"] = start
            response = self._call(client.list_objects, **request)
            data = _data(response)
            rows = _value(data, "objects")
            if not isinstance(rows, (list, tuple)):
                raise HarnessError("OCI current-object inventory is malformed.")
            objects.extend(rows)
            if len(objects) > MAX_ITEMS:
                raise HarnessError("OCI current-object inventory exceeded the safety limit.")
            next_start = str(_value(data, "next_start_with") or "")
            if not next_start:
                break
            if next_start in seen_starts:
                raise HarnessError("OCI current-object inventory repeated a cursor.")
            seen_starts.add(next_start)
            start = next_start
        else:
            raise HarnessError("OCI current-object inventory exceeded the page limit.")
        return versions, objects

    def _exact_storage_resource(self, kind, row, *, tenancy_id, namespace):
        identity = self._clients["identity"]
        if kind == "object_bucket":
            try:
                response = self._clients["object"].get_bucket(
                    namespace_name=namespace,
                    bucket_name=row["name"],
                )
                items = [_data(_checked(response, {200}))]
            except Exception as error:
                code = _provider_error_code(error)
                if code == "PROVIDER_NOT_FOUND":
                    return None
                raise HarnessError(
                    f"OCI bucket ownership read failed: {code}."
                ) from error
        elif kind == "iam_user":
            items = self._list(identity.list_users, compartment_id=tenancy_id)
        elif kind == "iam_group":
            items = self._list(identity.list_groups, compartment_id=tenancy_id)
        elif kind == "iam_policy":
            items = self._list(
                identity.list_policies,
                compartment_id=self.config.compartment_id,
            )
        elif kind == "iam_membership":
            relationships = row["ownership"].get("relationships") or {}
            items = self._list(
                identity.list_user_group_memberships,
                compartment_id=tenancy_id,
                user_id=relationships.get("user_id"),
                group_id=relationships.get("group_id"),
            )
        elif kind == "customer_secret_key":
            user_id = (row["ownership"].get("relationships") or {}).get("user_id")
            items = self._list_unpaged(
                identity.list_customer_secret_keys, user_id=user_id
            )
        else:
            raise HarnessError("Unsupported OCI storage cleanup kind.")
        matches = [
            item
            for item in items
            if str(_value(item, "id") or "") == str(row["resource_id"])
            and str(_value(item, "lifecycle_state") or "").upper()
            not in {"DELETED", "TERMINATED"}
        ]
        if len(matches) > 1:
            raise HarnessError("OCI IAM/Object Storage inventory contains a duplicate OCID.")
        if not matches:
            return None
        resource = matches[0]
        ownership = row["ownership"]
        if ownership.get("name") and str(
            _value(resource, "name") or _value(resource, "display_name") or ""
        ) != ownership["name"]:
            raise HarnessError("OCI cleanup resource name changed.")
        if ownership.get("compartment_id") and str(
            _value(resource, "compartment_id") or ""
        ) != ownership["compartment_id"]:
            raise HarnessError("OCI cleanup resource compartment changed.")
        expected_tags = ownership.get("tags") or {}
        if any(_tags(resource).get(key) != value for key, value in expected_tags.items()):
            raise HarnessError("OCI cleanup resource ownership tags changed.")
        for field, expected in (ownership.get("relationships") or {}).items():
            if str(_value(resource, field) or "") != str(expected):
                raise HarnessError("OCI cleanup resource relationship changed.")
        if kind == "iam_policy":
            group = self._active_ledger_entry("iam_group")
            if not group:
                raise HarnessError("OCI policy cleanup lacks its group ledger witness.")
            expected = self._policy_statements(group["name"])
            if list(_value(resource, "statements") or []) != expected:
                raise HarnessError("OCI policy statements changed before cleanup.")
        return resource

    def _wait_storage_absent(self, kind, row, *, tenancy_id, namespace):
        deadline = time.monotonic() + self.config.timeout_seconds
        while True:
            if self._exact_storage_resource(
                kind,
                row,
                tenancy_id=tenancy_id,
                namespace=namespace,
            ) is None:
                return
            if time.monotonic() >= deadline:
                raise HarnessError("OCI IAM/Object Storage cleanup waiter timed out.")
            self._sleep(self.config.poll_seconds)

    def _assert_object_inventory_owned(self, versions, objects):
        prefix = f"{self.config.run_id}/"
        inventory = [*versions, *objects]
        if any(
            not str(_value(item, "name") or "").startswith(prefix)
            for item in inventory
        ):
            raise HarnessError(
                "The exact test bucket contains an object outside the run prefix; cleanup is blocked."
            )

    def _object_probe(self, *, namespace, bucket_name, object_name, version_id):
        versions, objects = self._object_inventory(namespace, bucket_name)
        self._assert_object_inventory_owned(versions, objects)
        if version_id:
            matches = [
                item
                for item in versions
                if str(_value(item, "name") or "") == object_name
                and str(_value(item, "version_id") or "") == version_id
            ]
        else:
            matches = [
                item
                for item in objects
                if str(_value(item, "name") or "") == object_name
            ]
        if len(matches) > 1:
            raise HarnessError("OCI object cleanup inventory contains a duplicate witness.")
        return matches[0] if matches else None

    def _cleanup_bucket(self, row, *, namespace):
        bucket_name = row["name"]
        delete_operation = "delete_bucket"
        delete_key = self._cleanup_intent_key(
            "object_bucket", row["resource_id"], delete_operation
        )
        delete_probe = lambda: self._exact_storage_resource(
            "object_bucket", row, tenancy_id="", namespace=namespace
        )
        if self.intents.get(delete_key):
            return self._reconcile_cleanup_intent(
                delete_key,
                row,
                probe=delete_probe,
                operation=delete_operation,
            )
        bucket = self._exact_storage_resource(
            "object_bucket",
            row,
            tenancy_id="",
            namespace=namespace,
        )
        if bucket is None:
            self.ledger.mark_cleanup("object_bucket", row["resource_id"], state="absent")
            return "ABSENT"
        versions, objects = self._object_inventory(namespace, bucket_name)
        self._assert_object_inventory_owned(versions, objects)
        deleted_versions = set()
        for item in versions:
            name = str(_value(item, "name") or "")
            version_id = str(_value(item, "version_id") or "")
            if not name or not version_id:
                raise HarnessError("OCI object-version cleanup witness is malformed.")
            self._run_cleanup_mutation(
                row,
                operation="delete_object_version",
                method=self._clients["object"].delete_object,
                operation_kwargs={
                    "namespace_name": namespace,
                    "bucket_name": bucket_name,
                    "object_name": name,
                    "version_id": version_id,
                },
                probe=lambda name=name, version_id=version_id: self._object_probe(
                    namespace=namespace,
                    bucket_name=bucket_name,
                    object_name=name,
                    version_id=version_id,
                ),
                discriminator=f"{name}:{version_id}",
                mark_ledger=False,
            )
            deleted_versions.add((name, version_id))
        # A versioning-disabled/null object may not appear with a usable version
        # identifier. Delete only current keys inside the exact run prefix.
        versioned_names = {name for name, _version in deleted_versions}
        for item in objects:
            name = str(_value(item, "name") or "")
            if name not in versioned_names:
                self._run_cleanup_mutation(
                    row,
                    operation="delete_object",
                    method=self._clients["object"].delete_object,
                    operation_kwargs={
                        "namespace_name": namespace,
                        "bucket_name": bucket_name,
                        "object_name": name,
                    },
                    probe=lambda name=name: self._object_probe(
                        namespace=namespace,
                        bucket_name=bucket_name,
                        object_name=name,
                        version_id="",
                    ),
                    discriminator=name,
                    mark_ledger=False,
                )
        remaining_versions, remaining_objects = self._object_inventory(namespace, bucket_name)
        self._assert_object_inventory_owned(remaining_versions, remaining_objects)
        if remaining_versions or remaining_objects:
            self.ledger.mark_cleanup(
                "object_bucket",
                row["resource_id"],
                state="manual_review",
                error="PROVIDER_AMBIGUOUS",
            )
            raise HarnessError("OCI bucket inventory is not empty after exact object cleanup.")
        return self._run_cleanup_mutation(
            row,
            operation=delete_operation,
            method=self._clients["object"].delete_bucket,
            operation_kwargs={
                "namespace_name": namespace,
                "bucket_name": bucket_name,
            },
            probe=delete_probe,
        )

    def _cleanup_storage_kind(self, kind, *, tenancy_id, namespace):
        if kind in USER_RETAINED_STORAGE_KINDS:
            raise HarnessError(
                "Oracle cleanup preserves customer credentials and their IAM dependencies."
            )
        row = self._active_ledger_entry(kind)
        if row is None:
            return "NOT_LEDGERED"
        if kind == "object_bucket":
            return self._cleanup_bucket(row, namespace=namespace)
        raise HarnessError("Unsupported Oracle storage cleanup kind.")

    def _assert_cleanup_graph_complete(self):
        requirements = {
            "source_instance": {"source_boot_volume", "source_vnic"},
            "ui_compute_restore": {
                "ui_compute_restore_boot_volume",
                "ui_compute_restore_vnic",
            },
            "ui_boot_verify_instance": {"ui_boot_verify_vnic"},
        }
        for parent, dependencies in requirements.items():
            parent_rows = self.ledger.entries(parent)
            if parent_rows and any(not self.ledger.entries(kind) for kind in dependencies):
                raise HarnessError(
                    f"Oracle cleanup is blocked because {parent} has an incomplete dependency ledger."
                )

    def _validate_preserved_storage_credentials_local(self):
        """Bind the retained access key to its exact local IAM dependency graph."""

        rows = {}
        for kind in USER_RETAINED_STORAGE_KINDS:
            matches = self.ledger.entries(kind)
            if len(matches) > 1:
                raise HarnessError("Oracle credential ledger contains duplicate dependency rows.")
            rows[kind] = matches[0] if matches else None
        present = {kind for kind, row in rows.items() if row is not None}
        if not present:
            if self._secret_path().exists():
                raise HarnessError(
                    "Oracle cleanup found an unledgered credential file and stopped."
                )
            return {"retained": False, "resource_ids": []}
        if present != set(USER_RETAINED_STORAGE_KINDS):
            raise HarnessError(
                "Oracle credential preservation requires the complete key/user/group/policy/membership ledger graph."
            )
        if any(
            str(row.get("cleanup_state") or "")
            not in {"eligible", "failed", "manual_review"}
            for row in rows.values()
        ):
            raise HarnessError(
                "Oracle credential preservation cannot prove a terminal credential row is still user-retained."
            )
        secret = self._read_storage_secret(require_evidence=False)
        if secret is None:
            raise HarnessError("Oracle cleanup will not revoke a key whose secret file is missing.")
        bucket_rows = self.ledger.entries("object_bucket")
        if len(bucket_rows) != 1 or secret["bucket"] != str(
            bucket_rows[0].get("name") or ""
        ):
            raise HarnessError("Oracle retained credential bucket witness changed.")
        user = rows["iam_user"]
        group = rows["iam_group"]
        membership = rows["iam_membership"]
        customer = rows["customer_secret_key"]
        membership_relationships = (membership.get("ownership") or {}).get(
            "relationships"
        ) or {}
        customer_relationships = (customer.get("ownership") or {}).get(
            "relationships"
        ) or {}
        if (
            secret["access_key_id"] != customer["resource_id"]
            or secret["user_ocid"] != user["resource_id"]
            or customer_relationships.get("user_id") != user["resource_id"]
            or membership_relationships.get("user_id") != user["resource_id"]
            or membership_relationships.get("group_id") != group["resource_id"]
        ):
            raise HarnessError("Oracle retained credential dependency graph changed.")
        return {
            "retained": True,
            "resource_ids": sorted(
                str(rows[kind]["resource_id"])
                for kind in USER_RETAINED_STORAGE_KINDS
            ),
            "secret_path": str(self._secret_path()),
        }

    def _validate_preserved_storage_credentials_provider(
        self, credential_scope, *, tenancy_id, namespace
    ):
        """Prove every retained IAM/key dependency exists before cleanup mutates."""

        if not credential_scope["retained"]:
            return {}
        verified = {}
        for kind in sorted(USER_RETAINED_STORAGE_KINDS):
            row = self._active_ledger_entry(kind)
            if row is None:
                raise HarnessError(
                    "Oracle retained credential graph changed before cleanup."
                )
            resource = self._exact_storage_resource(
                kind, row, tenancy_id=tenancy_id, namespace=namespace
            )
            if resource is None:
                raise HarnessError(
                    "Oracle retained credential dependency is absent; cleanup stopped before mutation."
                )
            verified[kind] = resource
        return verified

    def _retain_storage_kind(self, kind, *, tenancy_id, namespace):
        if kind not in USER_RETAINED_STORAGE_KINDS:
            raise HarnessError("Unsupported Oracle retained credential kind.")
        row = self._active_ledger_entry(kind)
        if row is None:
            return "NOT_LEDGERED"
        resource = self._exact_storage_resource(
            kind, row, tenancy_id=tenancy_id, namespace=namespace
        )
        if resource is None:
            raise HarnessError(
                "Oracle retained credential dependency disappeared; cleanup stopped without revocation."
            )
        return "USER_RETAINED"

    def cleanup_plan(self):
        """Read-only exact-ID cleanup inventory; never alters ledger state."""

        if not self.read_only:
            raise HarnessError("Cleanup plan requires a read-only harness instance.")
        self._load_clients()
        self._validate_scope()
        tenancy_id, _region, namespace = self._storage_context()
        credential_scope = self._validate_preserved_storage_credentials_local()
        unknown = sorted(
            {
                str(row.get("kind") or "")
                for row in self.ledger.entries()
                if str(row.get("kind") or "") not in ALL_KINDS
            }
        )
        if unknown:
            raise HarnessError("Oracle ledger contains unsupported resource kinds.")
        self._assert_cleanup_graph_complete()
        blockers = []
        resources = []
        for row in self.ledger.entries():
            kind = str(row.get("kind") or "")
            if row.get("cleanup_state") in {"deleted", "absent"}:
                resources.append(
                    {"kind": kind, "resource_id": row["resource_id"], "state": row["cleanup_state"]}
                )
                continue
            try:
                resource = (
                    self._exact_storage_resource(
                        kind, row, tenancy_id=tenancy_id, namespace=namespace
                    )
                    if kind in STORAGE_KINDS
                    else self._exact_graph_resource(kind, row)
                )
            except HarnessError:
                blockers.append({"kind": kind, "resource_id": row.get("resource_id"), "reason": "OWNERSHIP_OR_READBACK_FAILED"})
                continue
            resources.append(
                {
                    "kind": kind,
                    "resource_id": row["resource_id"],
                    "state": (
                        "USER_RETAINED"
                        if kind in USER_RETAINED_STORAGE_KINDS
                        and resource is not None
                        else "PRESENT" if resource is not None else "ABSENT"
                    ),
                }
            )
        pending = sorted(self.intents.pending())
        if pending:
            blockers.append({"reason": "UNRESOLVED_MUTATION_INTENTS", "keys": pending})
        return {
            "phase": "CLEANUP_PLAN",
            "run_id": self.config.run_id,
            "provider_mutations": False,
            "local_writes": False,
            "resources": resources,
            "credentials_preserved": credential_scope["retained"],
            "blockers": blockers,
            "cleanup_allowed": not blockers,
        }

    def _cleanup_receipt_payload(self):
        unknown = sorted(
            {
                str(row.get("kind") or "")
                for row in self.ledger.entries()
                if str(row.get("kind") or "") not in ALL_KINDS
            }
        )
        if unknown:
            raise HarnessError("Oracle cleanup receipt contains unsupported resource kinds.")
        terminal = []
        for row in self.ledger.entries():
            state = str(row.get("cleanup_state") or "")
            if str(row.get("kind") or "") in USER_RETAINED_STORAGE_KINDS:
                if state not in {"eligible", "failed", "manual_review"}:
                    raise HarnessError(
                        "Oracle cleanup receipt cannot mark a terminal credential row as user-retained."
                    )
                state = "user_retained"
            elif state not in {"deleted", "absent"}:
                raise HarnessError("Oracle cleanup receipt requires every UI ledger row terminal.")
            terminal.append(
                {
                    "kind": str(row.get("kind") or ""),
                    "resource_id": str(row.get("resource_id") or ""),
                    "state": state,
                }
            )
        terminal.sort(key=lambda row: (row["kind"], row["resource_id"]))
        return {
            "schema": CLEANUP_RECEIPT_SCHEMA,
            "run_id": self.config.run_id,
            "tenancy_id": self.config.runtime_scope.tenancy_id,
            "compartment_id": self.config.compartment_id,
            "runtime_scope_digest": self.config.runtime_scope.digest,
            "ui_ledger_path": str(self.config.ledger_path),
            "ui_ledger_digest": _file_digest(
                self.config.ledger_path, variable="Oracle UI ledger"
            ),
            "terminal_resources": terminal,
        }

    def _validate_existing_cleanup_receipt(self, receipt_path):
        _path, existing = _read_private_json(
            receipt_path,
            variable="ORACLE_E2E_UI_CLEANUP_RECEIPT",
            exact_keys={
                "schema",
                "run_id",
                "tenancy_id",
                "compartment_id",
                "runtime_scope_digest",
                "ui_ledger_path",
                "ui_ledger_digest",
                "terminal_resources",
            },
        )
        expected = self._cleanup_receipt_payload()
        if existing != expected:
            raise HarnessError("Existing Oracle cleanup receipt does not match exact ledger state.")
        return existing

    def _write_cleanup_receipt(self, receipt_path):
        raw = Path(str(receipt_path or "")).expanduser()
        _reject_symlink_components(raw, variable="ORACLE_E2E_UI_CLEANUP_RECEIPT")
        receipt_path = _external_path(
            raw, variable="ORACLE_E2E_UI_CLEANUP_RECEIPT"
        )
        if receipt_path.exists():
            self._validate_existing_cleanup_receipt(receipt_path)
            return str(receipt_path)
        payload = self._cleanup_receipt_payload()
        written = _atomic_private_json(
            receipt_path,
            payload,
            variable="ORACLE_E2E_UI_CLEANUP_RECEIPT",
        )
        return str(written)

    def cleanup(self, receipt_path=None):
        """Delete only exact ledger-owned resources under the separate gate."""

        self._require_cleanup()
        receipt_path = receipt_path or self.environment.get(
            "ORACLE_E2E_UI_CLEANUP_RECEIPT"
        )
        if not receipt_path:
            raise HarnessError("Oracle UI cleanup requires a new cleanup receipt path.")
        raw_receipt_path = Path(str(receipt_path)).expanduser()
        _reject_symlink_components(
            raw_receipt_path, variable="ORACLE_E2E_UI_CLEANUP_RECEIPT"
        )
        receipt_path = _external_path(
            raw_receipt_path, variable="ORACLE_E2E_UI_CLEANUP_RECEIPT"
        )
        _reject_symlink_components(
            receipt_path, variable="ORACLE_E2E_UI_CLEANUP_RECEIPT"
        )
        if receipt_path.exists():
            self._validate_existing_cleanup_receipt(receipt_path)
            credential_scope = self._validate_preserved_storage_credentials_local()
            return {
                "phase": "ALREADY_CLEANED",
                "run_id": self.config.run_id,
                "provider_mutations": False,
                "credentials_preserved": credential_scope["retained"],
                "cleanup_receipt": str(receipt_path),
            }
        credential_scope = self._validate_preserved_storage_credentials_local()
        self._load_clients()
        self._validate_scope()
        tenancy_id, _region, namespace = self._storage_context()
        self._validate_preserved_storage_credentials_provider(
            credential_scope,
            tenancy_id=tenancy_id,
            namespace=namespace,
        )
        unknown = sorted(
            {
                str(row.get("kind") or "")
                for row in self.ledger.entries()
                if str(row.get("kind") or "") not in ALL_KINDS
            }
        )
        if unknown:
            raise HarnessError("Oracle ledger contains unsupported resource kinds.")
        active_ids = [
            str(row.get("resource_id") or "")
            for row in self.ledger.entries()
            if row.get("cleanup_state") in {"eligible", "failed", "manual_review"}
        ]
        if len(active_ids) != len(set(active_ids)):
            raise HarnessError("Oracle ledger reuses one OCID across active resources.")
        self._assert_cleanup_graph_complete()
        graph_order = [
            "ui_block_restore_attachment",
            "source_block_attachment",
            "ui_boot_verify_instance",
            "ui_boot_verify_vnic",
            "ui_compute_restore",
            "ui_compute_restore_vnic",
            "ui_compute_restore_boot_volume",
            "ui_compute_backup",
            "ui_block_backup",
            "ui_boot_backup",
            "ui_block_restore",
            "ui_boot_restore",
            "source_block_volume",
            "source_instance",
            "source_vnic",
            "source_boot_volume",
        ]
        report = {"graph": {}, "storage": {}, "local_artifacts": {}}
        for kind in graph_order:
            report["graph"][kind] = self._cleanup_graph_kind(kind)

        storage_order = [
            "object_bucket",
            "customer_secret_key",
            "iam_policy",
            "iam_membership",
            "iam_group",
            "iam_user",
        ]
        for kind in storage_order:
            method = (
                self._retain_storage_kind
                if kind in USER_RETAINED_STORAGE_KINDS
                else self._cleanup_storage_kind
            )
            report["storage"][kind] = method(
                kind, tenancy_id=tenancy_id, namespace=namespace
            )
        report["local_artifacts"]["storage_credentials"] = (
            "USER_RETAINED" if credential_scope["retained"] else "NOT_LEDGERED"
        )

        remaining_graph = [
            row
            for row in self.ledger.entries()
            if row.get("kind") in SOURCE_KINDS | UI_KINDS
            and row.get("cleanup_state") not in {"deleted", "absent"}
        ]
        if not remaining_graph:
            for path in self._key_paths():
                if path.exists():
                    path.unlink()
            report["local_artifacts"]["ssh_material"] = "DELETED"
        else:
            report["local_artifacts"]["ssh_material"] = "RETAINED"
        receipt = self._write_cleanup_receipt(receipt_path)
        return {
            "phase": "CLEANED",
            "run_id": self.config.run_id,
            "credentials_preserved": credential_scope["retained"],
            "cleanup": report,
            "cleanup_receipt": receipt,
        }


def build_parser():
    parser = argparse.ArgumentParser(
        description="Safety-gated Oracle Cloud live UI support harness."
    )
    parser.add_argument(
        "--phase",
        choices=(
            "plan",
            "provision",
            "build-manifest",
            "report",
            "verify-workloads",
            "verify-apply",
            "verify",
            "reconcile-orphans",
            "repair-storage-scope",
            "cleanup-plan",
            "cleanup",
        ),
        default="plan",
    )
    parser.add_argument(
        "--ui-manifest",
        help="Exact UI-created OCIDs, markers, and artifact integrity evidence.",
    )
    parser.add_argument("--manifest-source", help="Protected non-secret manifest source.")
    parser.add_argument(
        "--reconciliation-manifest",
        help="Protected exact-ID orphan reconciliation manifest.",
    )
    parser.add_argument("--output", help="New protected output path outside the repository.")
    parser.add_argument("--cleanup-receipt", help="New protected UI cleanup receipt path.")
    return parser


def main(argv=None, *, environment=None):
    args = build_parser().parse_args(argv)
    if args.phase == "plan":
        print(json.dumps(OracleLiveUIHarness.inert_plan(), indent=2, sort_keys=True))
        return 0
    if args.phase == "verify":
        print(
            json.dumps(
                {
                    "status": "FAILED_SAFE",
                    "error": (
                        "Legacy verify is disabled: byte-level verification may create "
                        "provider resources and write guest/evidence state. Use report for "
                        "read-only checks or verify-apply with the explicit apply gate."
                    ),
                }
            )
        )
        return 2
    environment = dict(os.environ if environment is None else environment)
    try:
        config = HarnessConfig.from_environment(environment)
        read_only = args.phase in {
            "build-manifest",
            "report",
            "verify-workloads",
            "repair-storage-scope",
            "cleanup-plan",
        }
        harness = OracleLiveUIHarness(
            config, environment=environment, read_only=read_only
        )
        if args.phase == "provision":
            result = harness.provision()
        elif args.phase == "build-manifest":
            if not args.manifest_source or not args.output:
                raise HarnessError(
                    "--manifest-source and --output are required for build-manifest."
                )
            result = harness.build_manifest(args.manifest_source, args.output)
        elif args.phase == "report":
            if not args.ui_manifest:
                raise HarnessError("--ui-manifest is required for report.")
            result = harness.report(args.ui_manifest)
        elif args.phase == "verify-workloads":
            if not args.ui_manifest:
                raise HarnessError("--ui-manifest is required for verify-workloads.")
            result = harness.verify_workloads_read_only(args.ui_manifest)
        elif args.phase == "verify-apply":
            if not args.ui_manifest:
                raise HarnessError("--ui-manifest is required for verify-apply.")
            result = harness.verify_apply(args.ui_manifest)
        elif args.phase == "reconcile-orphans":
            if not args.reconciliation_manifest:
                raise HarnessError(
                    "--reconciliation-manifest is required for reconcile-orphans."
                )
            result = harness.reconcile_orphans(args.reconciliation_manifest)
        elif args.phase == "repair-storage-scope":
            if not args.output:
                raise HarnessError("--output is required for repair-storage-scope.")
            result = harness.repair_storage_scope(args.output)
        elif args.phase == "cleanup-plan":
            result = harness.cleanup_plan()
        else:
            result = harness.cleanup(args.cleanup_receipt)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (HarnessError, LedgerError) as error:
        print(json.dumps({"status": "FAILED_SAFE", "error": str(error)}))
        return 2
    except Exception as error:
        # Never let an SDK/boto/SSH exception render a credential-bearing body.
        print(
            json.dumps(
                {
                    "status": "FAILED_SAFE",
                    "error": f"Oracle harness failed: {_provider_error_code(error)}.",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
