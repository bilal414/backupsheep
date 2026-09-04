"""Validation for browser-facing backup download targets.

Provider SDKs are allowed to produce signed links, but their output is not a
browser trust decision.  Keep the small set of values the web console can act
on explicit: HTTPS provider links, the exact authenticated local-download
route, and the two cold-storage preparation states.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


DOWNLOAD_PREPARATION_STATES = frozenset(
    {
        "restore_requested",
        "restore_in_progress",
    }
)

_LOCAL_DOWNLOAD_PATH = re.compile(
    r"/api/v1/storage/local/file/"
    r"(?:website|database|basecamp)/[1-9][0-9]*/"
)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)
_MAX_TARGET_LENGTH = 32 * 1024


class UnsafeBrowserDownloadTarget(ValueError):
    """Raised when provider output is not safe to expose to a browser."""


def _valid_https_hostname(hostname: str) -> bool:
    candidate = hostname.rstrip(".")
    if not candidate:
        return False

    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass

    try:
        ascii_hostname = candidate.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return False

    return (
        len(ascii_hostname) <= 253
        and all(_HOST_LABEL.fullmatch(label) for label in ascii_hostname.split("."))
    )


def validated_browser_download_target(value: object) -> str:
    """Return a browser-safe download target or fail closed.

    Relative targets are limited to the authenticated local-storage streaming
    endpoint.  All other URLs must be absolute HTTPS URLs without credentials,
    invalid ports, raw whitespace/control characters, or ambiguous backslashes.
    """

    if not isinstance(value, str):
        raise UnsafeBrowserDownloadTarget("Download target must be a string.")
    if value in DOWNLOAD_PREPARATION_STATES:
        return value
    if not value or len(value) > _MAX_TARGET_LENGTH or value != value.strip():
        raise UnsafeBrowserDownloadTarget("Download target has an invalid shape.")
    if "\\" in value or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in value
    ):
        raise UnsafeBrowserDownloadTarget("Download target contains unsafe characters.")

    if value.startswith("/"):
        if _LOCAL_DOWNLOAD_PATH.fullmatch(value):
            return value
        raise UnsafeBrowserDownloadTarget("Local download target is not allowlisted.")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        raise UnsafeBrowserDownloadTarget("Download target is malformed.") from None

    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (port is not None and not 1 <= port <= 65535)
        or not _valid_https_hostname(parsed.hostname)
    ):
        raise UnsafeBrowserDownloadTarget("Download target is not an allowlisted HTTPS URL.")

    return value
