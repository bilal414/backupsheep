#!/usr/bin/env python3
"""Publish verified release evidence as durable assets on an existing Git tag."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from verify_release import (
    COMMIT_RE,
    MAX_CONTROL_FILE_BYTES,
    ReleaseVerificationError,
    _load_json,
    _validate_policy,
)


MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024


def _request(url: str, token: str, *, method: str = "GET", payload: bytes | None = None, content_type: str = "application/json"):
    request = urllib.request.Request(
        url,
        data=payload,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type,
            "User-Agent": "backupsheep-release-evidence/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ReleaseVerificationError("GitHub API response exceeded the size limit")
            return response.status, body
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise ReleaseVerificationError(f"GitHub API returned {exc.code}: {detail}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise ReleaseVerificationError(f"GitHub API request failed: {exc}") from exc


def _json_response(body: bytes, label: str) -> dict:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseVerificationError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ReleaseVerificationError(f"{label} returned a non-object response")
    return value


def _release_exists(url: str, token: str) -> bool:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "backupsheep-release-evidence/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            response.read(MAX_RESPONSE_BYTES + 1)
            return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        detail = exc.read(4096).decode("utf-8", "replace")
        raise ReleaseVerificationError(f"GitHub release preflight returned {exc.code}: {detail}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise ReleaseVerificationError(f"GitHub release preflight failed: {exc}") from exc


def publish(policy: dict, tag: str, commit: str, assets: list[Path], token: str) -> None:
    policy = _validate_policy(policy)
    if not token:
        raise ReleaseVerificationError("GITHUB_TOKEN is required")
    if not COMMIT_RE.fullmatch(commit):
        raise ReleaseVerificationError("source commit must be a lowercase full commit")
    import re

    if re.fullmatch(policy["release_tag_regex"], tag) is None:
        raise ReleaseVerificationError("release tag is not authorized by policy")
    if not assets or len({asset.name for asset in assets}) != len(assets):
        raise ReleaseVerificationError("release assets must be nonempty with unique filenames")
    for asset in assets:
        file_stat = asset.lstat()
        if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
            raise ReleaseVerificationError(f"release asset must be a regular non-link file: {asset}")
        if file_stat.st_size <= 0 or file_stat.st_size > MAX_ASSET_BYTES:
            raise ReleaseVerificationError(f"release asset has an invalid size: {asset}")

    repository = policy["source_repository"]
    api_root = f"https://api.github.com/repos/{repository}"
    encoded_tag = urllib.parse.quote(tag, safe="")
    if _release_exists(f"{api_root}/releases/tags/{encoded_tag}", token):
        raise ReleaseVerificationError(f"refusing to replace existing GitHub release {tag}")
    body = json.dumps(
        {
            "tag_name": tag,
            "target_commitish": commit,
            "name": f"BackupSheep {tag}",
            "body": "Signed container release evidence. Verify with scripts/verify_release.py.",
            "draft": True,
            "prerelease": "-" in tag,
        }
    ).encode("utf-8")
    _, created_body = _request(f"{api_root}/releases", token, method="POST", payload=body)
    created = _json_response(created_body, "create release")
    release_id = created.get("id")
    upload_url = created.get("upload_url")
    if not isinstance(release_id, int) or not isinstance(upload_url, str):
        raise ReleaseVerificationError("GitHub did not return a release id and upload URL")
    upload_root = upload_url.split("{", 1)[0]
    if not upload_root.startswith("https://uploads.github.com/"):
        raise ReleaseVerificationError("GitHub returned an unauthorized asset upload URL")

    for asset in sorted(assets, key=lambda item: item.name):
        asset_url = f"{upload_root}?name={urllib.parse.quote(asset.name, safe='')}"
        _request(
            asset_url,
            token,
            method="POST",
            payload=asset.read_bytes(),
            content_type="application/octet-stream",
        )
    publish_body = json.dumps({"draft": False}).encode("utf-8")
    _request(f"{api_root}/releases/{release_id}", token, method="PATCH", payload=publish_body)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--asset", type=Path, action="append", required=True)
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy, maximum_bytes=MAX_CONTROL_FILE_BYTES)
        publish(
            policy,
            arguments.tag,
            arguments.source_commit,
            arguments.asset,
            os.environ.get("GITHUB_TOKEN", ""),
        )
        return 0
    except (OSError, ReleaseVerificationError) as exc:
        print(f"release evidence publication failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
