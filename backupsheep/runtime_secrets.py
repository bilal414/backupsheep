"""Strict file-backed secret loading for the stock Docker deployment.

Docker Compose mounts each granted secret as a read-only file below
``/run/secrets``.  Keeping the generated control-plane credentials out of process
environment variables prevents ordinary container inspection, crash diagnostics,
and child-process environment inheritance from disclosing them.

Only the four explicitly supported settings are resolved here.  An operator cannot
turn an arbitrary ``*_FILE`` variable into a file-read primitive, and a compromised
configuration cannot escape the dedicated secret mount directory.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Mapping

from django.core.exceptions import ImproperlyConfigured


DOCKER_SECRET_ROOT = Path("/run/secrets")
MAX_SECRET_BYTES = 4096
SECRET_FILE_SETTINGS = {
    "DJANGO_SECRET_KEY": "DJANGO_SECRET_KEY_FILE",
    "DB_PASSWORD": "DB_PASSWORD_FILE",
    "RABBITMQ_PASSWORD": "RABBITMQ_PASSWORD_FILE",
    # ONBOARDING_INSTALL_TOKEN_FILE already names the application's generated-token
    # output path, so the mounted input uses a deliberately distinct setting name.
    "ONBOARDING_INSTALL_TOKEN": "ONBOARDING_INSTALL_TOKEN_SECRET_FILE",
}


def _secret_error(setting_name: str, detail: str) -> ImproperlyConfigured:
    return ImproperlyConfigured(f"{setting_name} secret file {detail}.")


def _read_secret_file(
    setting_name: str,
    raw_path: object,
    *,
    secret_root: Path = DOCKER_SECRET_ROOT,
) -> str:
    root = secret_root.resolve(strict=True)
    path = Path(str(raw_path))
    if not path.is_absolute():
        raise _secret_error(setting_name, "must use an absolute path")

    try:
        unresolved_metadata = path.lstat()
        if stat.S_ISLNK(unresolved_metadata.st_mode):
            raise _secret_error(setting_name, "must not be a symbolic link")
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root)
    except ImproperlyConfigured:
        raise
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as error:
        raise _secret_error(
            setting_name, f"must be an existing file directly below {root}"
        ) from error

    if len(relative.parts) != 1:
        raise _secret_error(setting_name, f"must be directly below {root}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise _secret_error(setting_name, "could not be opened safely") from error

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _secret_error(setting_name, "must be a regular file")
        if metadata.st_nlink != 1:
            raise _secret_error(setting_name, "must not have multiple hard links")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise _secret_error(setting_name, "must not be group/world writable")
        if metadata.st_size <= 0 or metadata.st_size > MAX_SECRET_BYTES:
            raise _secret_error(
                setting_name, f"must contain between 1 and {MAX_SECRET_BYTES} bytes"
            )

        chunks = []
        remaining = MAX_SECRET_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)

    if len(payload) > MAX_SECRET_BYTES:
        raise _secret_error(setting_name, f"must not exceed {MAX_SECRET_BYTES} bytes")
    try:
        value = payload.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise _secret_error(setting_name, "must contain UTF-8 text") from error
    if not value:
        raise _secret_error(setting_name, "must not be empty")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise _secret_error(setting_name, "must contain exactly one line")
    return value


def resolve_file_backed_secrets(
    values: Mapping[str, object],
    *,
    secret_root: Path = DOCKER_SECRET_ROOT,
) -> dict[str, object]:
    """Return a copy of ``values`` with allowlisted mounted secrets resolved.

    A file-backed value intentionally wins over the corresponding direct value.  The
    stock Compose file also blanks the direct variables, so legacy ``.env`` secrets do
    not remain in the container environment during a migration.
    """

    resolved_values = dict(values)
    for setting_name, file_setting_name in SECRET_FILE_SETTINGS.items():
        secret_path = resolved_values.get(file_setting_name)
        if not secret_path:
            continue
        resolved_values[setting_name] = _read_secret_file(
            setting_name,
            secret_path,
            secret_root=secret_root,
        )
    return resolved_values
