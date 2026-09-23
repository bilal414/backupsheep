#!/usr/bin/env python3
"""Fail when the Bruno method-level surface drifts from Django's URL resolver."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.dont_write_bytecode = True

from route_inventory import REPO_ROOT, operations


BRUNO_ROOT = REPO_ROOT / "bruno"
MANIFEST_PATH = BRUNO_ROOT / "route-manifest.json"


def fail(errors: list[str]):
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)


def main():
    errors: list[str] = []
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest_rows = manifest.get("operations", [])
    actual_rows = operations()

    manifest_keys = [(row["method"], row["path"]) for row in manifest_rows]
    actual_keys = [row.key for row in actual_rows]
    duplicate_manifest = [key for key, count in Counter(manifest_keys).items() if count > 1]
    duplicate_actual = [key for key, count in Counter(actual_keys).items() if count > 1]
    if duplicate_manifest:
        errors.append(f"duplicate manifest operations: {duplicate_manifest}")
    if duplicate_actual:
        errors.append(f"duplicate Django operations: {duplicate_actual}")

    missing = sorted(set(actual_keys) - set(manifest_keys))
    stale = sorted(set(manifest_keys) - set(actual_keys))
    if missing:
        errors.append(f"operations missing from Bruno: {missing}")
    if stale:
        errors.append(f"operations no longer exposed by Django: {stale}")

    manifest_by_key = {
        (row["method"], row["path"]): row for row in manifest_rows
    }
    actual_by_key = {row.key: row for row in actual_rows}
    for key in sorted(set(actual_keys) & set(manifest_keys)):
        expected = actual_by_key[key]
        row = manifest_by_key[key]
        for field, value in (
            ("view", expected.view_name),
            ("action", expected.action),
            ("source", expected.source),
            ("auth", expected.auth),
            ("safety", expected.safety),
            ("kind", expected.kind),
        ):
            if row.get(field) != value:
                errors.append(
                    f"{key} {field} drift: manifest={row.get(field)!r}, Django={value!r}"
                )

        request_file = BRUNO_ROOT / row["file"]
        if not request_file.is_file():
            errors.append(f"{key} request file is missing: {row['file']}")
            continue
        text = request_file.read_text(encoding="utf-8")
        expected_request = f"{expected.method.lower()} {{"
        expected_url = f"url: {{{{baseUrl}}}}{expected.path}"
        if expected_request not in text:
            errors.append(f"{key} has no `{expected_request}` block in {row['file']}")
        if expected_url not in text:
            errors.append(f"{key} has the wrong URL in {row['file']}")
        if "Authorization: Bearer" in text:
            errors.append(f"{key} incorrectly uses Bearer auth in {row['file']}")
        if expected.auth in {"token", "optional-token"}:
            if "Authorization: Token {{apiToken}}" not in text:
                errors.append(f"{key} is missing DRF Token auth in {row['file']}")
        elif "Authorization:" in text:
            errors.append(f"{key} unexpectedly sends authorization in {row['file']}")
        guarded = expected.safety in {"mutation", "stateful-get"}
        has_guard = "allowMutations" in text and "script:pre-request" in text
        if guarded != has_guard:
            errors.append(
                f"{key} mutation guard mismatch in {row['file']}: expected={guarded}"
            )

    request_files = {
        str(path.relative_to(BRUNO_ROOT))
        for path in (BRUNO_ROOT / "requests").rglob("*.bru")
        if path.name != "folder.bru"
    }
    referenced_files = {row["file"] for row in manifest_rows}
    extra_files = sorted(request_files - referenced_files)
    unmaterialized = sorted(referenced_files - request_files)
    if extra_files:
        errors.append(f"request files absent from manifest: {extra_files}")
    if unmaterialized:
        errors.append(f"manifest references missing request files: {unmaterialized}")

    counts = manifest.get("counts", {})
    expected_api_count = sum(1 for row in actual_rows if row.path.startswith("/api/v1/"))
    expected_total = len(actual_rows)
    expected_paths = len({row.path for row in actual_rows})
    if counts.get("api_operations") != expected_api_count:
        errors.append("manifest api_operations count is stale")
    if counts.get("total_operations") != expected_total:
        errors.append("manifest total_operations count is stale")
    if counts.get("unique_paths") != expected_paths:
        errors.append("manifest unique_paths count is stale")

    all_bru_text = "\n".join(
        path.read_text(encoding="utf-8") for path in BRUNO_ROOT.rglob("*.bru")
    )
    if re.search(r"Authorization:\s*Bearer", all_bru_text, re.IGNORECASE):
        errors.append("collection contains an Authorization: Bearer header")

    if errors:
        fail(errors)
    print(
        f"Bruno coverage verified: {expected_api_count} API operations + "
        f"{expected_total - expected_api_count} health operation across "
        f"{expected_paths} paths; {len(request_files)} request files."
    )


if __name__ == "__main__":
    main()
