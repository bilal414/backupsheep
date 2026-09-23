#!/usr/bin/env python3
"""Publish verified release evidence as durable assets on an existing Git tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
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
MAX_MANAGED_ASSETS = 64
ASSET_LIST_PAGE_SIZE = 100
RELEASE_LIST_PAGE_SIZE = 100
MAX_RELEASE_LIST_PAGES = 100
RELEASE_BODY = (
    "Signed container release evidence. Verify with scripts/verify_release.py."
)
RETRYABLE_HTTP_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
PUBLISH_RETRY_DELAYS = (1.0, 3.0)


class RetryableGitHubRequestError(ReleaseVerificationError):
    """A bounded retry is safe for an idempotent GitHub request."""


@dataclass(frozen=True)
class AssetIdentity:
    path: Path
    name: str
    size: int
    digest: str
    device: int
    inode: int


def _request(
    url: str,
    token: str,
    *,
    method: str = "GET",
    payload: bytes | None = None,
    content_type: str = "application/json",
) -> tuple[int, bytes]:
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
                raise ReleaseVerificationError(
                    "GitHub API response exceeded the size limit"
                )
            return response.status, body
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        error_type = (
            RetryableGitHubRequestError
            if exc.code in RETRYABLE_HTTP_STATUSES
            else ReleaseVerificationError
        )
        raise error_type(f"GitHub API returned {exc.code}: {detail}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RetryableGitHubRequestError(
            f"GitHub API request failed: {exc}"
        ) from exc


def _request_with_retry(
    url: str,
    token: str,
    *,
    method: str,
    payload: bytes,
) -> tuple[int, bytes]:
    for attempt in range(len(PUBLISH_RETRY_DELAYS) + 1):
        try:
            return _request(url, token, method=method, payload=payload)
        except RetryableGitHubRequestError:
            if attempt == len(PUBLISH_RETRY_DELAYS):
                raise
            time.sleep(PUBLISH_RETRY_DELAYS[attempt])
    raise AssertionError("unreachable retry state")


def _json_value(body: bytes, label: str) -> object:
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseVerificationError(f"{label} returned invalid JSON") from exc


def _json_response(body: bytes, label: str) -> dict:
    value = _json_value(body, label)
    if not isinstance(value, dict):
        raise ReleaseVerificationError(f"{label} returned a non-object response")
    return value


def _json_list_response(body: bytes, label: str) -> list:
    value = _json_value(body, label)
    if not isinstance(value, list):
        raise ReleaseVerificationError(f"{label} returned a non-list response")
    return value


def _check_asset_stat(path: Path, file_stat: os.stat_result) -> None:
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise ReleaseVerificationError(
            f"release asset must be a regular non-link file: {path}"
        )
    if file_stat.st_nlink != 1:
        raise ReleaseVerificationError(
            f"release asset must not have multiple hard links: {path}"
        )
    if file_stat.st_size <= 0 or file_stat.st_size > MAX_ASSET_BYTES:
        raise ReleaseVerificationError(f"release asset has an invalid size: {path}")


def _read_asset(
    path: Path,
    *,
    include_payload: bool,
) -> tuple[os.stat_result, str, bytes | None]:
    before = path.lstat()
    _check_asset_stat(path, before)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    chunks: list[bytes] | None = [] if include_payload else None
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        _check_asset_stat(path, opened)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ReleaseVerificationError(
                f"release asset changed while it was opened: {path}"
            )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise ReleaseVerificationError(
                f"release asset changed while it was read: {path}"
            )
    finally:
        os.close(descriptor)
    current = path.lstat()
    _check_asset_stat(path, current)
    if (current.st_dev, current.st_ino, current.st_size) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
    ):
        raise ReleaseVerificationError(f"release asset changed after it was read: {path}")
    payload = b"".join(chunks) if chunks is not None else None
    return before, f"sha256:{digest.hexdigest()}", payload


def _asset_identity(path: Path) -> AssetIdentity:
    if not path.name or path.name in {".", ".."}:
        raise ReleaseVerificationError("release asset has an invalid filename")
    if len(path.name.encode("utf-8")) > 255 or any(
        ord(character) < 32 or ord(character) == 127 for character in path.name
    ):
        raise ReleaseVerificationError(
            f"release asset has an unsafe filename: {path.name!r}"
        )
    file_stat, digest, _ = _read_asset(path, include_payload=False)
    return AssetIdentity(
        path=path,
        name=path.name,
        size=file_stat.st_size,
        digest=digest,
        device=file_stat.st_dev,
        inode=file_stat.st_ino,
    )


def _verify_asset_identity(
    identity: AssetIdentity,
    file_stat: os.stat_result,
    digest: str,
) -> None:
    if (
        file_stat.st_dev != identity.device
        or file_stat.st_ino != identity.inode
        or file_stat.st_size != identity.size
        or digest != identity.digest
    ):
        raise ReleaseVerificationError(
            f"release asset identity changed before publication: {identity.path}"
        )


def _asset_payload(identity: AssetIdentity) -> bytes:
    file_stat, digest, payload = _read_asset(identity.path, include_payload=True)
    _verify_asset_identity(identity, file_stat, digest)
    if payload is None:
        raise AssertionError("release asset payload was not retained")
    return payload


def _revalidate_asset(identity: AssetIdentity) -> None:
    file_stat, digest, _ = _read_asset(identity.path, include_payload=False)
    _verify_asset_identity(identity, file_stat, digest)


def _expected_release_fields(tag: str, commit: str) -> dict[str, object]:
    return {
        "tag_name": tag,
        "target_commitish": commit,
        "name": f"BackupSheep {tag}",
        "body": RELEASE_BODY,
        "draft": True,
        "prerelease": "-" in tag,
    }


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReleaseVerificationError(f"{label} must be a positive integer")
    return value


def _validate_release(
    release: dict,
    *,
    repository: str,
    tag: str,
    commit: str,
    expected_draft: bool,
) -> tuple[int, str]:
    expected = _expected_release_fields(tag, commit)
    expected["draft"] = expected_draft
    for field in ("tag_name", "target_commitish", "name", "body"):
        if not isinstance(release.get(field), str) or release.get(field) != expected[field]:
            raise ReleaseVerificationError(
                f"GitHub release has an unexpected {field} value"
            )
    for field in ("draft", "prerelease"):
        if not isinstance(release.get(field), bool) or release.get(field) is not expected[field]:
            raise ReleaseVerificationError(
                f"GitHub release has an unexpected {field} value"
            )
    release_id = _positive_integer(release.get("id"), "GitHub release id")
    expected_upload_url = (
        f"https://uploads.github.com/repos/{repository}/releases/{release_id}/"
        "assets{?name,label}"
    )
    if release.get("upload_url") != expected_upload_url:
        raise ReleaseVerificationError(
            "GitHub release has an unexpected asset upload URL"
        )
    return release_id, expected_upload_url.split("{", 1)[0]


def _get_release(
    api_root: str,
    tag: str,
    commit: str,
    token: str,
) -> dict | None:
    expected = _expected_release_fields(tag, commit)
    candidates: list[dict] = []
    for page in range(1, MAX_RELEASE_LIST_PAGES + 1):
        status, body = _request(
            f"{api_root}/releases?per_page={RELEASE_LIST_PAGE_SIZE}&page={page}",
            token,
        )
        if status != 200:
            raise ReleaseVerificationError(
                f"list GitHub releases returned unexpected status {status}"
            )
        records = _json_list_response(body, "list GitHub releases")
        if len(records) > RELEASE_LIST_PAGE_SIZE:
            raise ReleaseVerificationError(
                "GitHub release listing exceeded the requested page size"
            )
        for record in records:
            if not isinstance(record, dict):
                raise ReleaseVerificationError(
                    "GitHub release listing returned a non-object release"
                )
            # The list endpoint is the only documented way for the workflow token
            # to rediscover drafts. Treat a collision with any of our durable
            # identity markers as managed-but-invalid rather than creating a
            # second release around suspicious state.
            if (
                record.get("tag_name") == tag
                or record.get("name") == expected["name"]
                or (
                    record.get("body") == expected["body"]
                    and record.get("target_commitish") == commit
                )
            ):
                candidates.append(record)
        if len(records) < RELEASE_LIST_PAGE_SIZE:
            break
    else:
        raise ReleaseVerificationError(
            "GitHub release listing exceeded the bounded search limit"
        )
    if len(candidates) > 1:
        raise ReleaseVerificationError(
            "GitHub returned multiple releases with managed identity markers"
        )
    return candidates[0] if candidates else None


def _create_release(
    api_root: str,
    tag: str,
    commit: str,
    token: str,
) -> dict:
    payload = json.dumps(
        _expected_release_fields(tag, commit),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    status, body = _request(
        f"{api_root}/releases",
        token,
        method="POST",
        payload=payload,
    )
    if status != 201:
        raise ReleaseVerificationError(
            f"create GitHub release returned unexpected status {status}"
        )
    return _json_response(body, "create GitHub release")


def _list_release_assets(
    api_root: str,
    release_id: int,
    token: str,
) -> list:
    status, body = _request(
        f"{api_root}/releases/{release_id}/assets"
        f"?per_page={ASSET_LIST_PAGE_SIZE}&page=1",
        token,
    )
    if status != 200:
        raise ReleaseVerificationError(
            f"list GitHub release assets returned unexpected status {status}"
        )
    return _json_list_response(body, "list GitHub release assets")


def _reconcile_assets(
    records: list,
    expected: dict[str, AssetIdentity],
    *,
    api_root: str,
    require_complete: bool,
) -> set[str]:
    if len(records) > len(expected):
        raise ReleaseVerificationError("GitHub release contains unmanaged assets")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ReleaseVerificationError(
                "GitHub release returned a non-object asset"
            )
        name = record.get("name")
        if not isinstance(name, str) or name not in expected:
            raise ReleaseVerificationError("GitHub release contains an unmanaged asset")
        if name in seen:
            raise ReleaseVerificationError(
                f"GitHub release contains duplicate asset {name}"
            )
        seen.add(name)
        identity = expected[name]
        asset_id = _positive_integer(
            record.get("id"), f"GitHub release asset {name} id"
        )
        if record.get("url") != f"{api_root}/releases/assets/{asset_id}":
            raise ReleaseVerificationError(
                f"GitHub release asset {name} has an unexpected API URL"
            )
        if record.get("state") != "uploaded":
            raise ReleaseVerificationError(
                f"GitHub release asset {name} is not completely uploaded"
            )
        size = record.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size != identity.size:
            raise ReleaseVerificationError(
                f"GitHub release asset {name} has an unexpected size"
            )
        if record.get("digest") != identity.digest:
            raise ReleaseVerificationError(
                f"GitHub release asset {name} has an unexpected digest"
            )
        if record.get("content_type") != "application/octet-stream":
            raise ReleaseVerificationError(
                f"GitHub release asset {name} has an unexpected content type"
            )
        if record.get("label") is not None:
            raise ReleaseVerificationError(
                f"GitHub release asset {name} has an unexpected label"
            )
    missing = set(expected) - seen
    if require_complete and missing:
        raise ReleaseVerificationError("GitHub release is missing managed assets")
    return missing


def _upload_asset(
    api_root: str,
    upload_root: str,
    identity: AssetIdentity,
    token: str,
) -> None:
    asset_url = f"{upload_root}?name={urllib.parse.quote(identity.name, safe='')}"
    status, body = _request(
        asset_url,
        token,
        method="POST",
        payload=_asset_payload(identity),
        content_type="application/octet-stream",
    )
    if status != 201:
        raise ReleaseVerificationError(
            f"upload GitHub release asset returned unexpected status {status}"
        )
    record = _json_response(body, f"upload GitHub release asset {identity.name}")
    _reconcile_assets(
        [record],
        {identity.name: identity},
        api_root=api_root,
        require_complete=True,
    )


def _publish_release(
    api_root: str,
    release_id: int,
    repository: str,
    tag: str,
    commit: str,
    token: str,
) -> None:
    payload = json.dumps(
        {"draft": False}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    status, body = _request_with_retry(
        f"{api_root}/releases/{release_id}",
        token,
        method="PATCH",
        payload=payload,
    )
    if status != 200:
        raise ReleaseVerificationError(
            f"publish GitHub release returned unexpected status {status}"
        )
    published = _json_response(body, "publish GitHub release")
    published_id, _ = _validate_release(
        published,
        repository=repository,
        tag=tag,
        commit=commit,
        expected_draft=False,
    )
    if published_id != release_id:
        raise ReleaseVerificationError("GitHub published a different release")


def publish(policy: dict, tag: str, commit: str, assets: list[Path], token: str) -> None:
    policy = _validate_policy(policy)
    if not token:
        raise ReleaseVerificationError("GITHUB_TOKEN is required")
    if not COMMIT_RE.fullmatch(commit):
        raise ReleaseVerificationError("source commit must be a lowercase full commit")
    if re.fullmatch(policy["release_tag_regex"], tag) is None:
        raise ReleaseVerificationError("release tag is not authorized by policy")
    if not assets or len(assets) > MAX_MANAGED_ASSETS:
        raise ReleaseVerificationError(
            "release asset count is outside the managed limit"
        )

    identities = [_asset_identity(asset) for asset in assets]
    expected = {identity.name: identity for identity in identities}
    if len(expected) != len(identities):
        raise ReleaseVerificationError("release assets must have unique filenames")

    repository = policy["source_repository"]
    api_root = f"https://api.github.com/repos/{repository}"
    release = _get_release(api_root, tag, commit, token)
    if release is None:
        release = _create_release(api_root, tag, commit, token)
    if release.get("draft") is False:
        release_id, _ = _validate_release(
            release,
            repository=repository,
            tag=tag,
            commit=commit,
            expected_draft=False,
        )
        _reconcile_assets(
            _list_release_assets(api_root, release_id, token),
            expected,
            api_root=api_root,
            require_complete=True,
        )
        for identity in identities:
            _revalidate_asset(identity)
        return
    release_id, upload_root = _validate_release(
        release,
        repository=repository,
        tag=tag,
        commit=commit,
        expected_draft=True,
    )

    records = _list_release_assets(api_root, release_id, token)
    missing = _reconcile_assets(
        records,
        expected,
        api_root=api_root,
        require_complete=False,
    )
    for name in sorted(missing):
        _upload_asset(api_root, upload_root, expected[name], token)

    current = _get_release(api_root, tag, commit, token)
    if current is None:
        raise ReleaseVerificationError("GitHub draft release disappeared")
    current_id, current_upload_root = _validate_release(
        current,
        repository=repository,
        tag=tag,
        commit=commit,
        expected_draft=True,
    )
    if current_id != release_id or current_upload_root != upload_root:
        raise ReleaseVerificationError("GitHub draft release identity changed")
    _reconcile_assets(
        _list_release_assets(api_root, release_id, token),
        expected,
        api_root=api_root,
        require_complete=True,
    )
    for identity in identities:
        _revalidate_asset(identity)

    _publish_release(
        api_root,
        release_id,
        repository,
        tag,
        commit,
        token,
    )
    _reconcile_assets(
        _list_release_assets(api_root, release_id, token),
        expected,
        api_root=api_root,
        require_complete=True,
    )


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
