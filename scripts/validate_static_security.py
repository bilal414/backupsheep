#!/usr/bin/env python3
"""Fail closed on new Bandit findings and permissive SSH host-key policies.

Bandit intentionally reports a small set of reviewed false positives in this
repository.  The policy records a content fingerprint for every accepted
finding so a new finding, a removed finding, or a changed code sample requires
an explicit review.  The additional AST pass catches conditional
``AutoAddPolicy``/TOFU expressions which Bandit B507 can miss.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path, PurePosixPath


class StaticSecurityError(RuntimeError):
    """A bounded policy-validation failure."""


def _load_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StaticSecurityError(f"Could not read valid JSON from {path}.") from error
    if not isinstance(payload, dict):
        raise StaticSecurityError(f"{path} must contain a JSON object.")
    return payload


def _relative_path(value: object, repository_root: Path) -> str:
    raw = str(value or "")
    path = Path(raw)
    try:
        if path.is_absolute():
            path = path.resolve(strict=False).relative_to(repository_root)
    except ValueError as error:
        raise StaticSecurityError("Bandit reported a path outside the repository.") from error
    normalized = PurePosixPath(path.as_posix())
    if not normalized.parts or normalized.is_absolute() or ".." in normalized.parts:
        raise StaticSecurityError("Bandit reported an unsafe source path.")
    return normalized.as_posix()


def _normalized_code(value: object) -> str:
    # Bandit prefixes each rendered source line with its current line number.
    # Excluding only that prefix keeps the review stable across unrelated line
    # insertions while still requiring review for any code change.
    code = str(value or "")
    return re.sub(r"(?m)^\s*\d+\s+", "", code).strip()


def finding_identity(result: dict, repository_root: Path) -> tuple[str, str, str]:
    if not isinstance(result, dict):
        raise StaticSecurityError("Bandit results must be JSON objects.")
    path = _relative_path(result.get("filename"), repository_root)
    test_id = str(result.get("test_id") or "")
    if not re.fullmatch(r"B[0-9]{3}", test_id):
        raise StaticSecurityError("Bandit returned a malformed test identifier.")
    evidence = {
        "path": path,
        "test_id": test_id,
        "severity": str(result.get("issue_severity") or ""),
        "confidence": str(result.get("issue_confidence") or ""),
        "issue_text": str(result.get("issue_text") or ""),
        "code": _normalized_code(result.get("code")),
    }
    encoded = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return path, test_id, hashlib.sha256(encoded).hexdigest()


def _expected_identities(policy: dict) -> Counter:
    reviews = policy.get("reviews")
    findings = policy.get("reviewed_findings")
    if (
        policy.get("schema") != 1
        or policy.get("bandit_version") != "1.9.4"
        or policy.get("minimum_severity") != "MEDIUM"
        or not isinstance(reviews, dict)
        or not isinstance(findings, list)
    ):
        raise StaticSecurityError("Static-analysis policy schema is invalid.")
    identities = []
    for item in findings:
        if not isinstance(item, dict):
            raise StaticSecurityError("Reviewed findings must be JSON objects.")
        path = str(item.get("path") or "")
        test_id = str(item.get("test_id") or "")
        fingerprint = str(item.get("fingerprint") or "")
        review = str(item.get("review") or "")
        if (
            not path
            or not re.fullmatch(r"B[0-9]{3}", test_id)
            or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
            or not isinstance(reviews.get(review), str)
            or not reviews[review].strip()
        ):
            raise StaticSecurityError("A reviewed Bandit finding is malformed or unexplained.")
        identities.append((path, test_id, fingerprint))
    return Counter(identities)


def validate_bandit_report(report: dict, policy: dict, repository_root: Path) -> None:
    if report.get("errors") != []:
        raise StaticSecurityError("Bandit reported scanner errors.")
    results = report.get("results")
    if not isinstance(results, list):
        raise StaticSecurityError("Bandit report has no results array.")
    expected = _expected_identities(policy)
    actual = Counter(finding_identity(result, repository_root) for result in results)
    if actual == expected:
        return

    unexpected = actual - expected
    missing = expected - actual
    details = []
    if unexpected:
        samples = ", ".join(
            f"{path}:{test_id}" for path, test_id, _fingerprint in sorted(unexpected)[:5]
        )
        details.append(f"unexpected or changed findings: {samples}")
    if missing:
        samples = ", ".join(
            f"{path}:{test_id}" for path, test_id, _fingerprint in sorted(missing)[:5]
        )
        details.append(f"missing or changed reviewed findings: {samples}")
    raise StaticSecurityError("Bandit review mismatch; " + "; ".join(details) + ".")


def _policy_expression_is_fail_closed(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    function = node.func
    if isinstance(function, ast.Name):
        name = function.id
    elif isinstance(function, ast.Attribute):
        name = function.attr
    else:
        return False
    return name in {"RejectPolicy", "_ExactHostKeyPolicy"}


def validate_ssh_host_key_policies(policy: dict, repository_root: Path) -> None:
    source_roots = policy.get("source_roots")
    excluded = policy.get("excluded_prefixes")
    if not isinstance(source_roots, list) or not isinstance(excluded, list):
        raise StaticSecurityError("Static-analysis source policy is invalid.")
    excluded_prefixes = tuple(str(value).rstrip("/") + "/" for value in excluded)
    violations = []
    for root_name in source_roots:
        root = repository_root / str(root_name)
        if not root.is_dir() or root.is_symlink():
            raise StaticSecurityError(f"Static-analysis source root is unsafe: {root_name}.")
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(repository_root).as_posix()
            if relative.startswith(excluded_prefixes):
                continue
            if path.is_symlink() or not path.is_file():
                raise StaticSecurityError(f"Static-analysis source path is unsafe: {relative}.")
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, UnicodeDecodeError, SyntaxError) as error:
                raise StaticSecurityError(f"Could not parse security source: {relative}.") from error
            for node in ast.walk(tree):
                name = ""
                if isinstance(node, ast.Name):
                    name = node.id
                elif isinstance(node, ast.Attribute):
                    name = node.attr
                if name in {"AutoAddPolicy", "WarningPolicy"}:
                    violations.append(f"{relative}:{getattr(node, 'lineno', 0)}:{name}")
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "set_missing_host_key_policy"
                    and (
                        len(node.args) != 1
                        or node.keywords
                        or not _policy_expression_is_fail_closed(node.args[0])
                    )
                ):
                    violations.append(
                        f"{relative}:{getattr(node, 'lineno', 0)}:unapproved-host-key-policy"
                    )
    if violations:
        raise StaticSecurityError(
            "Permissive or unreviewed SSH host-key policy detected: "
            + ", ".join(violations[:10])
            + "."
        )


def validate(report: dict, policy: dict, repository_root: Path) -> None:
    repository_root = repository_root.resolve(strict=True)
    validate_bandit_report(report, policy, repository_root)
    validate_ssh_host_key_policies(policy, repository_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--repository-root", default=Path.cwd(), type=Path)
    arguments = parser.parse_args(argv)
    try:
        policy = _load_json(arguments.policy)
        report = _load_json(arguments.report)
        validate(report, policy, arguments.repository_root)
    except StaticSecurityError as error:
        print(f"static security validation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"Static security validation passed with {len(report['results'])} "
        "content-pinned reviewed findings."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
