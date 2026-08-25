#!/usr/bin/env python3
"""Install release tools from policy-pinned assets after verifying SHA-256."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from verify_release import MAX_CONTROL_FILE_BYTES, ReleaseVerificationError, _load_json, _validate_policy


MAX_TOOL_ASSET_BYTES = 300 * 1024 * 1024
ALLOWED_DOWNLOAD_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        from urllib.parse import urlsplit

        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
            raise ReleaseVerificationError(f"tool download redirected to an unauthorized URL: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str) -> bytes:
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise ReleaseVerificationError(f"tool asset must use an HTTPS github.com URL: {url}")
    opener = urllib.request.build_opener(_HttpsOnlyRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "backupsheep-release-tool-installer/1"})
    try:
        with opener.open(request, timeout=60) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in ALLOWED_DOWNLOAD_HOSTS:
                raise ReleaseVerificationError("tool download ended at an unauthorized URL")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_TOOL_ASSET_BYTES:
                raise ReleaseVerificationError("tool asset exceeds the size limit")
            payload = response.read(MAX_TOOL_ASSET_BYTES + 1)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise ReleaseVerificationError(f"tool download failed: {exc}") from exc
    if not payload or len(payload) > MAX_TOOL_ASSET_BYTES:
        raise ReleaseVerificationError("tool asset is empty or exceeds the size limit")
    return payload


def _binary_from_asset(payload: bytes, archive_member: Any) -> bytes:
    if archive_member is None:
        return payload
    if not isinstance(archive_member, str) or not archive_member or "/" in archive_member:
        raise ReleaseVerificationError("tool archive_member must be a plain filename")
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            matches = [
                member
                for member in archive.getmembers()
                if member.name.removeprefix("./") == archive_member
            ]
            if len(matches) != 1:
                raise ReleaseVerificationError(f"archive must contain exactly one {archive_member!r}")
            member = matches[0]
            if not member.isfile() or member.issym() or member.islnk():
                raise ReleaseVerificationError("tool archive member must be a regular non-link file")
            stream = archive.extractfile(member)
            if stream is None:
                raise ReleaseVerificationError("tool archive member could not be read")
            binary = stream.read(MAX_TOOL_ASSET_BYTES + 1)
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseVerificationError(f"invalid tool archive: {exc}") from exc
    if not binary or len(binary) > MAX_TOOL_ASSET_BYTES:
        raise ReleaseVerificationError("tool binary is empty or exceeds the size limit")
    return binary


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def install(policy: dict[str, Any], destination: Path, names: list[str]) -> None:
    policy = _validate_policy(policy)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination_stat = destination.lstat()
    if stat.S_ISLNK(destination_stat.st_mode) or not stat.S_ISDIR(destination_stat.st_mode):
        raise ReleaseVerificationError("tool destination must be a real directory")
    os.chmod(destination, 0o700)

    tools = policy["tools"]
    if not names:
        names = sorted(tools)
    if len(names) != len(set(names)) or not set(names).issubset(tools):
        raise ReleaseVerificationError("requested tool set is duplicate or not authorized by policy")

    installed: dict[str, str] = {}
    for name in names:
        record = tools[name]
        payload = _download(record["url"])
        actual = hashlib.sha256(payload).hexdigest()
        if actual != record["sha256"]:
            raise ReleaseVerificationError(
                f"{name} asset SHA-256 mismatch (expected {record['sha256']}, got {actual})"
            )
        binary = _binary_from_asset(payload, record["archive_member"])
        _atomic_write(destination / name, binary, 0o500)
        installed[name] = record["version"]

    # Explicit empty configuration is passed to scanners so repository-local
    # .syft.yaml, trivy.yaml, and .trivyignore files cannot weaken a release.
    _atomic_write(destination / "empty-syft.yaml", b"{}\n", 0o600)
    _atomic_write(destination / "empty-trivy.yaml", b"{}\n", 0o600)
    _atomic_write(destination / "empty-trivy.ignore", b"", 0o600)
    _atomic_write(
        destination / "installed-tools.json",
        (json.dumps(installed, sort_keys=True) + "\n").encode("utf-8"),
        0o600,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--tool", action="append", default=[])
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        install(policy, arguments.destination, arguments.tool)
        return 0
    except (OSError, ReleaseVerificationError) as exc:
        print(f"release tool installation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
