#!/usr/bin/env python3
"""Validate exact per-platform OCI projections before invoking scanners."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from validate_release_verifier_layout import (
    ValidationError,
    preflight,
    preflight_source,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--index-digest", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--scan-layout-amd64", type=Path)
    parser.add_argument("--scan-layout-arm64", type=Path)
    arguments = parser.parse_args(argv)
    try:
        scan_arguments = (
            arguments.scan_layout_amd64,
            arguments.scan_layout_arm64,
        )
        if arguments.source_only:
            if any(value is not None for value in scan_arguments):
                raise ValidationError(
                    "--source-only cannot be combined with scan projection paths"
                )
            images, layout_binding = preflight_source(
                layout=arguments.layout,
                index_digest=arguments.index_digest,
                repository=arguments.repository,
                tag=arguments.tag,
            )
            identities: dict[str, str] = {}
        else:
            if any(value is None for value in scan_arguments):
                raise ValidationError(
                    "both scan projection paths are required unless --source-only is set"
                )
            images, layout_binding, identities = preflight(
                layout=arguments.layout,
                index_digest=arguments.index_digest,
                repository=arguments.repository,
                tag=arguments.tag,
                scan_layouts={
                    "linux/amd64": arguments.scan_layout_amd64,
                    "linux/arm64": arguments.scan_layout_arm64,
                },
            )
    except (OSError, ValidationError, json.JSONDecodeError) as exc:
        print(f"release verifier scan preflight failed: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "index_digest": arguments.index_digest,
                "layout_control_sha256": layout_binding,
                "platforms": {
                    platform: {
                        "manifest_digest": images[platform].manifest_digest,
                        "config_digest": images[platform].config_digest,
                        **(
                            {"scan_identity": identities[platform]}
                            if identities
                            else {}
                        ),
                    }
                    for platform in sorted(images)
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
