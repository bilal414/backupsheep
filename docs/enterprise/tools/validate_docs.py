#!/usr/bin/env python3
"""Validate the self-contained enterprise documentation package."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
DOC_ROOT = REPO_ROOT / "docs" / "enterprise"
CATALOG_PATH = DOC_ROOT / "generated" / "catalog.js"
MANIFEST_PATH = REPO_ROOT / "bruno" / "route-manifest.json"
ENV_SAMPLE_PATH = REPO_ROOT / ".env_sample"
SETTINGS_PATH = REPO_ROOT / "backupsheep" / "settings.py"

REQUIRED_FILES = (
    "index.html",
    "styles.css",
    "app.js",
    "README.md",
    "generated/catalog.js",
    "assets/backupsheep-wordmark.png",
)


class BalancedHTMLParser(HTMLParser):
    """Small structural check that also understands embedded SVG element names."""

    void_elements = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, int]] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in self.void_elements:
            self.stack.append((tag, self.getpos()[0]))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        return

    def handle_endtag(self, tag: str) -> None:
        if not self.stack:
            self.errors.append(f"Unexpected closing </{tag}> on line {self.getpos()[0]}")
            return
        opened, line = self.stack.pop()
        if opened != tag:
            self.errors.append(
                f"Mismatched </{tag}> on line {self.getpos()[0]}; expected </{opened}> for line {line}"
            )

    def close(self) -> None:
        super().close()
        for tag, line in reversed(self.stack):
            self.errors.append(f"Unclosed <{tag}> from line {line}")


def fail(messages: list[str], message: str) -> None:
    messages.append(message)


def catalog_payload() -> dict[str, object]:
    text = CATALOG_PATH.read_text(encoding="utf-8")
    prefix = "window.BACKUPSHEEP_DOC_CATALOG = "
    if not text.startswith("/* Generated") or prefix not in text:
        raise ValueError("generated/catalog.js does not have the expected wrapper")
    return json.loads(text.split(prefix, 1)[1].rstrip().removesuffix(";"))


def catalog_manifest(payload: dict[str, object]) -> dict[str, object]:
    metadata = payload.get("metadata", {})
    provenance = metadata.get("provenance", {}) if isinstance(metadata, dict) else {}
    catalog_source = provenance.get("catalogSource") if isinstance(provenance, dict) else None
    revision = provenance.get("sourceRevision") if isinstance(provenance, dict) else None

    if catalog_source == "git-ref" and isinstance(revision, str):
        try:
            result = subprocess.run(
                ["git", "show", f"{revision}:bruno/route-manifest.json"],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            return json.loads(result.stdout)
        except (FileNotFoundError, subprocess.CalledProcessError, json.JSONDecodeError):
            # Exported source archives may not contain Git history. The checked-out
            # manifest is an acceptable fallback only when it describes this catalog.
            current = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            api_metadata = metadata.get("api", {}) if isinstance(metadata, dict) else {}
            if current.get("counts") == api_metadata:
                return current
            raise ValueError(
                f"Cannot resolve catalog source revision {revision!r} and the working-tree manifest differs"
            )

    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def sample_env_names() -> set[str]:
    pattern = re.compile(r"^([A-Z][A-Z0-9_]*)=")
    names: set[str] = set()
    for line in ENV_SAMPLE_PATH.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line.strip())
        if match:
            names.add(match.group(1))
    return names


def settings_env_names() -> set[str]:
    text = SETTINGS_PATH.read_text(encoding="utf-8")
    patterns = (
        r'config\.get\(\s*["\']([A-Z][A-Z0-9_]*)["\']',
        r'os\.environ\.get\(\s*["\']([A-Z][A-Z0-9_]*)["\']',
    )
    names: set[str] = set()
    for pattern in patterns:
        names.update(re.findall(pattern, text))
    return names


def validate() -> list[str]:
    errors: list[str] = []
    for relative in REQUIRED_FILES:
        if not (DOC_ROOT / relative).is_file():
            fail(errors, f"Missing required file: {relative}")

    if errors:
        return errors

    html = (DOC_ROOT / "index.html").read_text(encoding="utf-8")
    css = (DOC_ROOT / "styles.css").read_text(encoding="utf-8")
    script = (DOC_ROOT / "app.js").read_text(encoding="utf-8")

    parser = BalancedHTMLParser()
    parser.feed(html)
    parser.close()
    errors.extend(parser.errors)

    page_ids = set(re.findall(r'data-page="([a-z0-9-]+)"', html))
    route_ids = set(re.findall(r'data-route="([a-z0-9-]+)"', html))
    if page_ids != route_ids:
        fail(
            errors,
            "Navigation/page mismatch: "
            f"missing pages={sorted(route_ids - page_ids)}, missing routes={sorted(page_ids - route_ids)}",
        )

    element_ids = set(re.findall(r'\sid="([A-Za-z][A-Za-z0-9_-]*)"', html))
    all_element_ids = re.findall(r'\sid="([A-Za-z][A-Za-z0-9_-]*)"', html)
    duplicate_ids = sorted({value for value in all_element_ids if all_element_ids.count(value) > 1})
    if duplicate_ids:
        fail(errors, f"Duplicate HTML element IDs: {duplicate_ids}")
    for fragment in re.findall(r'href="#([A-Za-z][A-Za-z0-9_-]*)"', html):
        if fragment not in element_ids and fragment not in page_ids:
            fail(errors, f"Unresolved HTML fragment: #{fragment}")

    for local_ref in re.findall(r'(?:href|src)="([^"#?]+)', html):
        if local_ref.startswith(("http://", "https://", "mailto:", "data:")):
            continue
        target = (DOC_ROOT / local_ref).resolve()
        if not target.exists():
            fail(errors, f"Missing local HTML target: {local_ref}")

    payload = catalog_payload()
    try:
        manifest = catalog_manifest(payload)
    except ValueError as error:
        fail(errors, str(error))
        return errors
    generated_operations = payload["operations"]  # type: ignore[index]
    if len(generated_operations) != manifest["counts"]["total_operations"]:
        fail(errors, "Generated API operation count differs from route manifest")

    operation_ids = [entry["operation_id"] for entry in generated_operations]
    if len(operation_ids) != len(set(operation_ids)):
        fail(errors, "Generated API catalog contains duplicate operation IDs")

    comparison_keys = ("operation_id", "method", "path", "view", "action", "source", "file")
    generated_core = [
        {key: entry[key] for key in comparison_keys} for entry in generated_operations
    ]
    manifest_core = [
        {key: entry[key] for key in comparison_keys} for entry in manifest["operations"]
    ]
    if generated_core != manifest_core:
        fail(errors, "Generated API catalog content differs from the route manifest")

    unique_paths = len({entry["path"] for entry in generated_operations})
    if unique_paths != manifest["counts"]["unique_paths"]:
        fail(errors, "Route manifest unique-path count does not match its operations")

    for entry in generated_operations:
        source = REPO_ROOT / entry["source"]
        request = REPO_ROOT / "bruno" / entry["file"]
        if not source.is_file():
            fail(errors, f"API catalog source does not exist: {entry['source']}")
        if not request.is_file():
            fail(errors, f"API catalog Bruno request does not exist: {entry['file']}")

    generated_names = {entry["name"] for entry in payload["configuration"]}  # type: ignore[index]
    if len(generated_names) != len(payload["configuration"]):  # type: ignore[index]
        fail(errors, "Generated configuration catalog contains duplicate variable names")
    source_names = sample_env_names() | settings_env_names()
    if generated_names != source_names:
        fail(
            errors,
            "Generated configuration drift: "
            f"missing={sorted(source_names - generated_names)}, extra={sorted(generated_names - source_names)}",
        )

    combined = "\n".join((html, css, script))
    for placeholder in ("lorem ipsum", "TODO", "TBD", "coming later"):
        if placeholder.lower() in combined.lower():
            fail(errors, f"Placeholder text remains: {placeholder}")

    if "prefers-reduced-motion" not in css:
        fail(errors, "Reduced-motion handling is missing")
    if "aria-live" not in html:
        fail(errors, "Search/status live-region markup is missing")

    generic_description = "Optional runtime setting. Review the operator configuration guide before changing it."
    if any(entry["description"] == generic_description for entry in payload["configuration"]):  # type: ignore[index]
        fail(errors, "Configuration catalog still contains generic placeholder descriptions")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("Enterprise documentation validation failed:")
        for message in errors:
            print(f"- {message}")
        return 1

    payload = catalog_payload()
    print(
        "Enterprise documentation validation passed: "
        f"{len(payload['operations'])} API operations, "
        f"{len(payload['configuration'])} configuration variables."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
