#!/usr/bin/env python3
"""Generate method-complete Bruno requests from BackupSheep's Django resolver."""

from __future__ import annotations

import json
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path

sys.dont_write_bytecode = True

from route_inventory import REPO_ROOT, Operation, operations


BRUNO_ROOT = REPO_ROOT / "bruno"
REQUESTS_ROOT = BRUNO_ROOT / "requests"
GENERATED_MARKER = REQUESTS_ROOT / ".generated-by-backupsheep"
MANIFEST_PATH = BRUNO_ROOT / "route-manifest.json"


CATEGORIES = {
    "health": ("00 Health", 0),
    "auth": ("01 Authentication", 1),
    "check": ("02 Session", 2),
    "mobile": ("02 Session", 2),
    "callback": ("03 OAuth Callbacks", 3),
    "members": ("10 Account and Team", 10),
    "accounts": ("10 Account and Team", 10),
    "groups": ("10 Account and Team", 10),
    "invites": ("10 Account and Team", 10),
    "connections": ("20 Connections", 20),
    "nodes": ("30 Nodes", 30),
    "clouds": ("40 Cloud Resources", 40),
    "saas": ("50 SaaS Resources", 50),
    "volumes": ("60 Volumes", 60),
    "databases": ("70 Backup Sources", 70),
    "websites": ("70 Backup Sources", 70),
    "storage": ("80 Storage", 80),
    "backups": ("90 Backups", 90),
    "schedules": ("91 Schedules", 91),
    "logs": ("92 Reporting", 92),
    "stats": ("92 Reporting", 92),
    "notifications-slack": ("93 Notifications", 93),
    "notifications-telegram": ("93 Notifications", 93),
    "notifications-email": ("93 Notifications", 93),
    "utils": ("94 Utilities", 94),
}

PROVIDER_GROUPS = {
    "connections": {
        "aws",
        "aws_rds",
        "basecamp",
        "database",
        "digitalocean",
        "google_cloud",
        "hetzner",
        "lightsail",
        "oracle",
        "ovh_ca",
        "ovh_eu",
        "ovh_us",
        "upcloud",
        "vultr",
        "website",
    },
    "clouds": {
        "aws",
        "aws_rds",
        "digitalocean",
        "google_cloud",
        "hetzner",
        "lightsail",
        "lightsail_bucket_replications",
        "lightsail_database",
        "oracle",
        "ovh_ca",
        "ovh_eu",
        "ovh_us",
        "upcloud",
        "vultr",
        "vultr_database",
    },
    "saas": {"basecamp"},
    "volumes": {
        "aws",
        "digitalocean",
        "google_cloud",
        "lightsail",
        "oracle",
        "ovh_ca",
        "ovh_eu",
        "ovh_us",
        "upcloud",
        "vultr",
    },
    "backups": {
        "aws",
        "aws_rds",
        "basecamp",
        "database",
        "digitalocean",
        "google_cloud",
        "hetzner",
        "lightsail",
        "oracle",
        "ovh_ca",
        "ovh_eu",
        "ovh_us",
        "upcloud",
        "vultr",
        "vultr_database",
        "website",
    },
    "storage": {
        "alibaba",
        "all",
        "aws_s3",
        "azure",
        "backblaze_b2",
        "cloudflare",
        "do_spaces",
        "dropbox",
        "exoscale",
        "filebase",
        "google_cloud",
        "google_drive",
        "ibm",
        "idrive",
        "ionos",
        "leviia",
        "linode",
        "local",
        "onedrive",
        "oracle",
        "pcloud",
        "rackcorp",
        "scaleway",
        "tencent",
        "upcloud",
        "vultr",
        "wasabi",
    },
}


def slug(value: str) -> str:
    value = value.replace("{{", "-").replace("}}", "-")
    value = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()
    return value or "root"


def operation_id(operation: Operation) -> str:
    return f"{operation.method.lower()}-{slug(operation.path)}"


def grouping(operation: Operation) -> tuple[str, str | None, int]:
    if operation.path == "/healthz/":
        category_key = "health"
        segments = []
    else:
        segments = [segment for segment in operation.path.split("/") if segment]
        category_key = segments[2] if len(segments) > 2 else "utils"
    category, category_seq = CATEGORIES.get(category_key, ("99 Other API", 99))

    subgroup = None
    if category_key in PROVIDER_GROUPS:
        candidate = segments[3] if len(segments) > 3 else None
        subgroup = candidate if candidate in PROVIDER_GROUPS[category_key] else "Aggregate"
    elif category_key in {"members", "accounts", "groups", "invites"}:
        subgroup = category_key
    elif category_key in {"databases", "websites"}:
        subgroup = category_key
    elif category_key.startswith("notifications-"):
        subgroup = category_key.removeprefix("notifications-")
    return category, subgroup, category_seq


def _camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(part.title() for part in parts[1:])


def _placeholder(name: str, field=None):
    from rest_framework import serializers

    lowered = name.lower()
    if any(
        token in lowered
        for token in (
            "password",
            "secret",
            "access_key",
            "api_key",
            "token",
            "credential",
            "consumer_key",
        )
    ):
        return "{{providerCredential}}"
    if "private_key" in lowered:
        return "{{providerPrivateKey}}"
    id_variables = {
        "account": "accountId",
        "member": "memberId",
        "membership": "membershipId",
        "group": "groupId",
        "connection": "connectionId",
        "node": "nodeId",
        "storage": "storageId",
        "storage_point": "storagePointId",
        "backup": "backupId",
        "restore": "restoreId",
        "schedule": "scheduleId",
        "invite": "inviteId",
        "location": "locationId",
    }
    normalized = lowered.removesuffix("_id").removesuffix("_ids")
    if normalized in id_variables:
        value = "{{" + id_variables[normalized] + "}}"
        return [value] if lowered.endswith("_ids") else value
    if lowered in {"email", "username"}:
        return "{{email}}"
    if lowered in {"host", "hostname", "server"}:
        return "{{sshHost}}"
    if lowered == "port":
        return 22
    if lowered == "name":
        return "Example resource"
    if "url" in lowered or "endpoint" in lowered:
        return "https://provider.example.com"
    if "bucket" in lowered or lowered in {"container", "folder", "path"}:
        return "backup-example"
    if lowered in {"region", "zone", "location"}:
        return "example-region-1"
    if lowered in {"timezone"}:
        return "UTC"
    if "notes" in lowered:
        return "Created from the BackupSheep Bruno collection"

    if field is not None:
        if isinstance(field, serializers.BooleanField):
            return False
        if isinstance(field, (serializers.IntegerField, serializers.FloatField, serializers.DecimalField)):
            return 1
        if isinstance(field, serializers.DateTimeField):
            return "2030-01-01T00:00:00Z"
        if isinstance(field, serializers.DateField):
            return "2030-01-01"
        if isinstance(field, serializers.UUIDField):
            return "{{requestId}}"
        if isinstance(field, serializers.IPAddressField):
            return "192.0.2.10"
    return "replace-with-" + slug(name)


def _field_example(name, field, depth=0):
    from rest_framework import serializers

    if depth > 6:
        return {}
    if isinstance(field, serializers.ListSerializer):
        return [_serializer_example(field.child, depth + 1)]
    if isinstance(field, serializers.BaseSerializer):
        return _serializer_example(field, depth + 1)
    if isinstance(field, serializers.ManyRelatedField):
        return [_placeholder(name.removesuffix("_ids") + "_id")]
    if isinstance(field, serializers.PrimaryKeyRelatedField):
        return _placeholder(name + ("" if name.endswith("_id") else "_id"))
    if isinstance(field, serializers.ChoiceField):
        try:
            for key in field.choices:
                if key not in {"", None}:
                    return key
        except Exception:
            pass
    if isinstance(field, serializers.ListField):
        return []
    if isinstance(field, (serializers.DictField, serializers.JSONField)):
        return {}
    return _placeholder(name, field)


def _serializer_example(serializer_or_class, depth=0):
    from rest_framework import serializers

    try:
        serializer = (
            serializer_or_class()
            if isinstance(serializer_or_class, type)
            else serializer_or_class
        )
        fields = serializer.fields
    except Exception:
        return {}
    result = {}
    for name, field in fields.items():
        if field.read_only or isinstance(field, serializers.HiddenField):
            continue
        if not field.required and name not in {"notes"}:
            continue
        result[name] = _field_example(name, field, depth + 1)
    return result


def _serializer_for(operation: Operation):
    view_class = getattr(operation.callback, "cls", None) or getattr(
        operation.callback, "view_class", None
    )
    if not view_class:
        return None
    return getattr(view_class, "write_serializer_class", None) or getattr(
        view_class, "serializer_class", None
    )


def custom_body(operation: Operation):
    path = operation.path
    action = operation.action
    method = operation.method

    if path == "/api/v1/auth/login/":
        return {"email": "{{email}}", "password": "{{password}}"}
    if path == "/api/v1/auth/reset/" and method == "POST":
        return {"email": "{{email}}"}
    if path == "/api/v1/auth/reset/" and method == "PATCH":
        return {
            "password": "{{password}}",
            "password_confirm": "{{password}}",
            "password_token": "{{passwordResetToken}}",
        }
    if path.endswith("/ssh-host-keys/preview/"):
        return {"host": "{{sshHost}}", "port": "{{sshPort}}"}
    if path.endswith("/ssh-host-keys/approve/"):
        return {
            "approval_token": "{{sshApprovalToken}}",
            "fingerprint": "{{sshFingerprint}}",
            "replace": False,
        }
    action_bodies = {
        "take_snapshot": {
            "notes": "On-demand backup from Bruno",
            "storage_point_ids": ["{{storageId}}"],
            "request_id": "{{idempotencyKey}}",
        },
        "backup_request_status": None,
        "restore_backup": {
            "backup_id": "{{backupId}}",
            "name": "Bruno restore target",
            "params": {},
            "confirm": True,
            "request_id": "{{idempotencyKey}}",
        },
        "resume_restore": {"restore_id": "{{restoreId}}"},
        "remove_membership": {"membership_id": "{{membershipId}}"},
        "leave_membership": {"membership_id": "{{membershipId}}"},
        "switch_current_account": {"account_id": "{{accountId}}"},
        "update_membership": {
            "groups": ["{{groupId}}"],
            "notify_on_success": True,
            "notify_on_fail": True,
        },
        "auth_multi_factor_token_setup": {"display_name": "BackupSheep Bruno"},
        "auth_multi_factor_token_verify": {
            "auth_multi_factor_id": "replace-with-factor-id",
            "auth_multi_factor_token": "replace-with-factor-token",
            "display_name": "BackupSheep Bruno",
        },
        "auth_multi_factor_token_revoke": {},
        "run": {"request_id": "{{idempotencyKey}}"},
        "trigger": {"request_id": "{{idempotencyKey}}"},
        "approve": {},
    }
    if action in action_bodies:
        return action_bodies[action]
    if action == "restore":
        if "/lightsail_bucket_replications/" in path:
            return {
                "source_run_id": "{{runId}}",
                "restore_prefix": "restore-example/",
                "target_prefix": "restored/",
                "request_id": "{{idempotencyKey}}",
            }
        if "/vultr_database/" in path:
            return {
                "name": "Bruno restored database",
                "params": {},
                "confirm": True,
                "request_id": "{{idempotencyKey}}",
            }
        return {
            "confirm": True,
            "storage_point_id": "{{storagePointId}}",
            "delete": False,
        }
    if method == "POST" and action == "create":
        return _serializer_example(_serializer_for(operation))
    if method == "PUT" and action == "update":
        return _serializer_example(_serializer_for(operation))
    if method == "PATCH" and action == "partial_update":
        full = _serializer_example(_serializer_for(operation))
        if "name" in full:
            return {"name": "Updated example resource"}
        if full:
            key = next(iter(full))
            return {key: full[key]}
        return {}
    if method in {"POST", "PUT", "PATCH"}:
        return {}
    return None


def query_params(operation: Operation) -> dict[str, str]:
    path = operation.path
    action = operation.action
    if path.startswith("/api/v1/callback/"):
        return {"code": "{{oauthCode}}", "state": "{{oauthState}}"}
    if action == "backup_request_status":
        return {"request_id": "{{requestId}}"}
    if action == "download":
        return {"storage_point_id": "{{storagePointId}}"}
    if action == "highcharts":
        return {"date_from": "2030-01-01", "date_to": "2030-01-31"}
    return {}


def needs_idempotency_header(operation: Operation) -> bool:
    return operation.action in {"take_snapshot", "restore_backup", "restore", "run"}


def render_request(operation: Operation, seq: int) -> str:
    body = custom_body(operation)
    guarded = operation.safety in {"mutation", "stateful-get"}
    lines = [
        "meta {",
        f"  name: {operation.method} {operation.path}",
        "  type: http",
        f"  seq: {seq}",
        "}",
        "",
        f"{operation.method.lower()} {{",
        f"  url: {{{{baseUrl}}}}{operation.path}",
        f"  body: {'json' if body is not None else 'none'}",
        "  auth: none",
        "}",
    ]
    params = query_params(operation)
    if params:
        lines.extend(["", "params:query {"])
        for key, value in params.items():
            lines.append(f"  {key}: {value}")
        lines.append("}")

    lines.extend(["", "headers {"])
    if operation.auth in {"token", "optional-token"}:
        lines.append("  Authorization: Token {{apiToken}}")
    if body is not None:
        lines.append("  Content-Type: application/json")
    if needs_idempotency_header(operation):
        lines.append("  Idempotency-Key: {{idempotencyKey}}")
    lines.append("}")

    if body is not None:
        body_text = json.dumps(body, indent=2)
        lines.extend(["", "body:json {"])
        lines.extend("  " + line for line in body_text.splitlines())
        lines.append("}")

    if guarded:
        lines.extend(
            [
                "",
                "script:pre-request {",
                "  if (String(bru.getEnvVar(\"allowMutations\")) !== \"true\") {",
                "    throw new Error(\"Blocked by default: set allowMutations=true only after reviewing this exact request.\");",
                "  }",
                "}",
            ]
        )

    if operation.path == "/api/v1/auth/login/":
        lines.extend(
            [
                "",
                "script:post-response {",
                "  if (res.getStatus() >= 200 && res.getStatus() < 300) {",
                "    const payload = res.getBody();",
                "    if (payload && payload.api_key) {",
                "      bru.setVar(\"apiToken\", String(payload.api_key));",
                "    }",
                "  }",
                "}",
            ]
        )

    if operation.path == "/healthz/":
        test_lines = [
            '  test("health endpoint returns 200", function () {',
            "    expect(res.getStatus()).to.equal(200);",
            "  });",
        ]
    elif operation.path == "/api/v1/utils/test/":
        test_lines = [
            '  test("API version endpoint returns 200", function () {',
            "    expect(res.getStatus()).to.equal(200);",
            "  });",
        ]
    else:
        test_lines = [
            '  test("request does not fail with an unhandled server error", function () {',
            "    expect(res.getStatus()).to.be.below(500);",
            "  });",
        ]
    lines.extend(["", "tests {", *test_lines, "}"])

    auth_text = {
        "none": "No authentication required.",
        "optional-token": "Token is optional; include it to test the signed-in state.",
        "token": "Requires `Authorization: Token <key>`.",
        "browser-session-csrf": (
            "Requires the authenticated browser session and its Django CSRF token; "
            "API-token authentication is intentionally rejected."
        ),
    }[operation.auth]
    safety_text = {
        "safe-read": "Read-only request.",
        "safe-auth": "Authentication request; stores the returned token in memory only.",
        "download": "Read-only download or signed-download-URL request.",
        "live-read": "Live network probe; no durable approval is written.",
        "mutation": "State-changing request; blocked unless `allowMutations=true`.",
        "stateful-get": "Legacy/stateful GET; blocked unless `allowMutations=true`.",
    }[operation.safety]
    lines.extend(
        [
            "",
            "docs {",
            f"  Operation ID: `{operation_id(operation)}`",
            "",
            f"  {auth_text} {safety_text}",
            "",
            f"  Django action: `{operation.view_name}.{operation.action}`",
            f"  Source: `{operation.source}`",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def write_folder_metadata(folder: Path, name: str, seq: int):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "folder.bru").write_text(
        f"meta {{\n  name: {name}\n  seq: {seq}\n}}\n", encoding="utf-8"
    )


def main():
    inventory = operations()
    duplicate_keys = [
        key
        for key, count in __import__("collections").Counter(
            operation.key for operation in inventory
        ).items()
        if count > 1
    ]
    if duplicate_keys:
        raise SystemExit(f"Django exposes duplicate method/path operations: {duplicate_keys}")

    if REQUESTS_ROOT.exists():
        if not GENERATED_MARKER.exists():
            raise SystemExit(
                f"Refusing to replace {REQUESTS_ROOT}: generated marker is missing."
            )
        shutil.rmtree(REQUESTS_ROOT)
    REQUESTS_ROOT.mkdir(parents=True)
    GENERATED_MARKER.write_text(
        "Generated by bruno/scripts/generate_collection.py.\n", encoding="utf-8"
    )

    grouped: dict[tuple[str, str | None, int], list[Operation]] = defaultdict(list)
    for operation in inventory:
        grouped[grouping(operation)].append(operation)

    manifest_operations = []
    category_names = sorted({key[0:3:2] for key in grouped}, key=lambda item: item[1])
    for category, category_seq in category_names:
        category_folder = REQUESTS_ROOT / category
        write_folder_metadata(category_folder, category, category_seq)

    for (category, subgroup, category_seq), group_operations in sorted(
        grouped.items(), key=lambda item: (item[0][2], item[0][1] or "")
    ):
        folder = REQUESTS_ROOT / category
        if subgroup:
            subgroup_name = subgroup.replace("_", " ").title()
            folder = folder / subgroup_name
            write_folder_metadata(folder, subgroup_name, 1)
        for seq, operation in enumerate(group_operations, start=1):
            filename = f"{seq:03d}-{operation.method.lower()}-{slug(operation.action)}.bru"
            target = folder / filename
            target.write_text(render_request(operation, seq), encoding="utf-8")
            relative_file = str(target.relative_to(BRUNO_ROOT))
            manifest_operations.append(
                {
                    "operation_id": operation_id(operation),
                    "method": operation.method,
                    "path": operation.path,
                    "regex_route": operation.regex_route,
                    "view": operation.view_name,
                    "action": operation.action,
                    "source": operation.source,
                    "auth": operation.auth,
                    "safety": operation.safety,
                    "kind": operation.kind,
                    "file": relative_file,
                }
            )

    api_operations = [
        operation for operation in manifest_operations if operation["path"].startswith("/api/v1/")
    ]
    manifest = {
        "schema_version": 1,
        "generated_from": "Django root URL resolver on the checked-out branch",
        "scope": {
            "included": ["/api/v1/**", "/healthz/"],
            "excluded": [
                "/django-admin/** (HTML administrator)",
                "/api-auth/** (DRF browser UI)",
                "/login, /logout, /reset/**, /onboarding/**, /console/**, /invite/** (HTML console)",
                "static/media URL patterns",
                "apps.api.v1.incoming.urls (no active patterns)",
            ],
        },
        "counts": {
            "api_operations": len(api_operations),
            "health_operations": len(manifest_operations) - len(api_operations),
            "total_operations": len(manifest_operations),
            "unique_paths": len({item["path"] for item in manifest_operations}),
        },
        "operations": sorted(
            manifest_operations, key=lambda item: (item["path"], item["method"])
        ),
    }
    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Generated {manifest['counts']['total_operations']} requests across "
        f"{manifest['counts']['unique_paths']} paths."
    )


if __name__ == "__main__":
    main()
