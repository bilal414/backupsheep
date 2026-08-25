#!/usr/bin/env python3
"""Build the enterprise documentation's source-derived reference catalog.

Only committed, non-secret inputs are read:

* bruno/route-manifest.json for the Django resolver-derived API inventory
* .env_sample for public configuration names, sample defaults, and comments
* backupsheep/settings.py for settings-only environment reads

The generated JavaScript is intentionally usable from file:// as well as HTTP so the
documentation can be reviewed without a web build or runtime dependency.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
DOC_ROOT = REPO_ROOT / "docs" / "enterprise"
GENERATED_ROOT = DOC_ROOT / "generated"

MANIFEST_PATH = REPO_ROOT / "bruno" / "route-manifest.json"
ENV_SAMPLE_PATH = REPO_ROOT / ".env_sample"
SETTINGS_PATH = REPO_ROOT / "backupsheep" / "settings.py"

SENSITIVE_NAME = re.compile(
    r"(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY|ACCESS_KEY|API_KEY|BOT_KEY|DSN)$"
    r"|(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY|ACCESS_KEY|API_KEY|BOT_KEY|DSN)_",
    re.IGNORECASE,
)
ENV_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")


def api_family(path: str) -> str:
    if path == "/healthz/":
        return "health"
    remainder = path.removeprefix("/api/v1/")
    return remainder.split("/", 1)[0] or "root"


def normalize_comment(lines: list[str]) -> str:
    kept: list[str] = []
    for raw in lines:
        value = raw.lstrip("#").strip()
        if not value or set(value) <= {"─", "-", "="}:
            continue
        if value.lower().startswith("learn more:"):
            continue
        kept.append(value)
    text = " ".join(kept)
    return re.sub(r"\s+", " ", text).strip()


def config_category(name: str) -> str:
    if "FAULT" in name:
        return "Test-only fault injection"
    if name.startswith(("DJANGO_", "APP_", "ONBOARDING_")):
        return "Application and security"
    if name.startswith(("DB_", "DATABASE_URL")):
        return "PostgreSQL"
    if name.startswith(("CELERY_", "RABBITMQ_")):
        return "Queues and worker capacity"
    if name.startswith(("BACKUP_", "RESTORE_")):
        return "Durable execution and recovery"
    if name.startswith(("SSH_", "DATABASE_CONNECT", "DATABASE_STATEMENT", "DATABASE_LOCK", "DATABASE_COMMAND", "DATABASE_VALIDATION")):
        return "Source connectivity and trust"
    if name.startswith(("PROVIDER_HTTP_", "S3_MULTIPART_", "DROPBOX_UPLOAD_", "SOURCE_ARCHIVE_")):
        return "Network, upload, and command limits"
    if name in {"LOG_RETENTION_DAYS", "SENTRY_DSN", "S3_DOWNLOAD_URL_EXPIRES"}:
        return "Observability and retention"
    if name.startswith(("POSTMARK_", "SES_", "MAILGUN_", "EMAIL_")):
        return "Transactional email"
    if name.startswith(("SLACK_", "TELEGRAM_")):
        return "Notification channels"
    if name.startswith(("DROPBOX_", "PCLOUD_", "BASECAMP_", "MS_", "GOOGLE_")):
        return "OAuth applications"
    if name.startswith(("OVH_", "DIGITALOCEAN_", "HETZNER_", "UPCLOUD_", "VULTR_", "GOOGLE_COMPUTE_", "GOOGLE_RESOURCE_")):
        return "Provider endpoints and credentials"
    if name.startswith("S3_"):
        return "Application-log object storage"
    return "Advanced and integration settings"


def display_default(name: str, raw_value: str) -> tuple[str, bool]:
    value = raw_value.strip().strip("'").strip('"')
    sensitive = bool(SENSITIVE_NAME.search(name))
    if sensitive:
        return ("Not set" if not value else "Secret value — replace sample", True)
    return (value if value else "Not set", False)


SETTINGS_ONLY_DESCRIPTIONS = {
    "BACKUPSHEEP_SECRETS": "Optional JSON object used by supported managed deployment environments to supply runtime secrets.",
    "BS_LOCAL_STORAGE_PATH": "Durable root for the Local Storage destination. Stock Compose mounts it read/write only in worker-storage; every other runtime role must have no Local Storage mount.",
    "BASECAMP_OAUTH_ENDPOINT": "Basecamp authorization endpoint override.",
    "BASECAMP_REDIRECT_URL": "Basecamp OAuth callback path or URL override; it must match the registered public application callback.",
    "BASECAMP_TOKEN_ENDPOINT": "Basecamp OAuth token endpoint override.",
    "DIGITALOCEAN_API": "DigitalOcean API base URL override.",
    "DIGITALOCEAN_APP_CLIENT_ID": "DigitalOcean OAuth application client identifier for self-hosted OAuth connections.",
    "DIGITALOCEAN_APP_CLIENT_SECRET": "DigitalOcean OAuth application secret for self-hosted OAuth connections.",
    "DIGITALOCEAN_TOKEN_URL": "DigitalOcean OAuth token endpoint override.",
    "GOOGLE_COMPUTE_API": "Google Compute Engine API base URL override.",
    "GOOGLE_OAUTH_TOKEN_URL": "Google OAuth token endpoint override.",
    "GOOGLE_RESOURCE_API": "Google Cloud Resource Manager API base URL override.",
    "GOOGLE_RESPONSE_TYPE": "OAuth response type used by the Google Drive connection flow.",
    "HETZNER_API": "Hetzner Cloud API base URL override.",
    "PCLOUD_AUTH_URL": "pCloud OAuth authorization endpoint override.",
    "PCLOUD_OAUTH_TOKEN_URL": "pCloud OAuth token endpoint override.",
    "PCLOUD_REDIRECT_URL": "pCloud OAuth callback path or URL override.",
    "PCLOUD_RESPONSE_TYPE": "OAuth response type used by the pCloud connection flow.",
    "PUBLIC_IPV4_LOOKUP_URL": "External endpoint used for optional public IPv4 discovery. Review its availability and privacy before use.",
    "PUBLIC_IPV6_LOOKUP_URL": "External endpoint used for optional public IPv6 discovery. Review its availability and privacy before use.",
    "S3_MULTIPART_CLEANUP_BATCH_SIZE": "Maximum number of stale multipart-upload cleanup records processed in one maintenance batch.",
    "S3_MULTIPART_CLEANUP_RETRY_AFTER_SECONDS": "Delay before retrying a failed S3 multipart cleanup operation.",
    "S3_MULTIPART_CLEANUP_SCAN_LIMIT": "Maximum number of candidate multipart cleanup records scanned per maintenance pass.",
    "S3_MULTIPART_CLEANUP_STALE_SECONDS": "Age after which an unfinished multipart upload is eligible for reconciliation or cleanup.",
    "UPCLOUD_API": "UpCloud API base URL override.",
    "VULTR_API": "Vultr API base URL override.",
    "VULTR_API_CONNECT_TIMEOUT": "Vultr-specific HTTP connection timeout in seconds.",
    "VULTR_API_READ_TIMEOUT": "Vultr-specific HTTP read timeout in seconds.",
}


ENV_DESCRIPTIONS = {
    "WEBSITE_RESTORE_INLINE_FILE_LIMIT": "Maximum website-archive member count handled by the inline preflight path before the restore uses the scalable inventory path. Zero disables inline enumeration.",
    "APP_NAME": "Human-facing installation name used in application and notification copy.",
    "APP_PROTOCOL": "Canonical public URL scheme, including ://. Keep it aligned with TLS termination, secure cookies, CSRF origins, links, and OAuth callbacks.",
    "DJANGO_SERVER": "Runtime profile selector. The prod value activates production safety checks such as rejection of the sample Django signing key.",
    "DJANGO_SETTINGS_MODULE": "Python settings module loaded by Django and every web, worker, migration, and scheduler process.",
    "S3_ENDPOINT_URL": "Optional endpoint for the S3 bucket used by application logs and related internal storage; required for compatible non-AWS services.",
    "S3_SECRET_ACCESS_KEY": "Secret half of the credential for the application-log S3 bucket. Supply through protected runtime secret custody.",
    "S3_SIGNATURE_VERSION": "AWS request-signing version used for the application-log S3 client; s3v4 is the normal value.",
    "S3_STORAGE_BUCKET_NAME": "Existing bucket used for application logs and related internal storage, not a customer backup destination record.",
    "BACKUP_CREATE_LEASE_SECONDS": "Exclusive lease duration for a provider-create or create-reconciliation phase. Too short risks competing owners; too long delays takeover.",
    "BACKUP_DELETE_LEASE_SECONDS": "Exclusive lease duration for provider or storage deletion work before another worker may reclaim it.",
    "BACKUP_POLL_INTERVAL": "Default seconds between provider-state reads while a cloud backup is pending; also influences stale polling recovery timing.",
    "BACKUP_RECOVERY_BATCH_SIZE": "Maximum stale backup executions examined by one recovery sweep.",
    "BACKUP_REQUEST_CLAIM_TIMEOUT_MAX_SECONDS": "Upper bound for the extended claim window used after ambiguous broker publication outcomes.",
    "BACKUP_REQUEST_CLAIM_TIMEOUT_SECONDS": "Initial seconds an outbox request remains claimed after publication so duplicate dispatchers do not immediately republish it.",
    "BACKUP_REQUEST_DISPATCH_LEASE_SECONDS": "Lease duration for one dispatcher to publish a durable backup request from the outbox.",
    "BACKUP_REQUEST_RECOVERY_BATCH_SIZE": "Maximum pending or stale outbox requests reconsidered in one dispatch-recovery pass.",
    "BACKUP_REQUEST_RETRY_MAX_SECONDS": "Maximum backoff between retries after a definite backup-request publication failure.",
    "BACKUP_REQUEST_RETRY_SECONDS": "Initial backoff after a definite backup-request publication failure; later attempts are capped by the maximum.",
    "BACKUP_STORAGE_HEARTBEAT_SECONDS": "Heartbeat cadence for a worker that owns one destination-copy lease.",
    "BACKUP_STORAGE_LEASE_SECONDS": "Exclusive lease duration for one destination upload or reconciliation attempt.",
    "BACKUP_STORAGE_STALE_SECONDS": "Age after which unfinished destination-copy state is eligible for stale-work recovery review.",
    "BACKUP_WORKER_HEARTBEAT_SECONDS": "Heartbeat cadence for the worker that owns the main backup execution lease.",
    "BACKUP_WORKER_LEASE_SECONDS": "Exclusive main backup-execution lease duration. Keep heartbeats comfortably below one third of this value.",
    "RESTORE_DISK_RESERVE_BYTES": "Free-space reserve that must remain after restore staging estimates; protects the host from complete disk exhaustion.",
    "RESTORE_MAX_ARCHIVE_MEMBERS": "Maximum number of ZIP members accepted by website/database restore safety validation.",
    "RESTORE_MAX_COMPRESSION_RATIO": "Maximum permitted uncompressed-to-compressed ratio for an archive member or aggregate restore safety check.",
    "RESTORE_MAX_UNCOMPRESSED_BYTES": "Maximum total expanded bytes accepted during archive validation and extraction.",
    "RESTORE_RECOVERY_BATCH_SIZE": "Maximum stale restore executions dispatched by one recovery sweep.",
    "RESTORE_RECOVERY_DISPATCH_LEASE_SECONDS": "Lease duration protecting one stale-restore recovery dispatch from duplicate publishers.",
    "RESTORE_RECOVERY_STALE_SECONDS": "Heartbeat age at which an active restore becomes eligible for recovery evaluation.",
    "RESTORE_WORKER_HEARTBEAT_SECONDS": "Heartbeat cadence for the worker that owns a restore execution lease.",
    "RESTORE_WORKER_LEASE_SECONDS": "Exclusive restore-execution lease duration; premature tuning can create competing restore owners.",
    "DROPBOX_UPLOAD_CHUNK_SIZE_BYTES": "Chunk size for Dropbox resumable upload sessions; affects memory, request count, and retry granularity.",
    "PROVIDER_HTTP_BACKOFF_FACTOR": "Multiplier used by bounded retry backoff for eligible provider HTTP reads or definitively safe retries.",
    "PROVIDER_HTTP_CONNECT_TIMEOUT": "Seconds allowed to establish a provider HTTP connection before the attempt is classified as timed out.",
    "PROVIDER_HTTP_MAX_POOL_CONNECTIONS": "Maximum reusable provider HTTP connections retained by the shared client pool.",
    "PROVIDER_HTTP_MAX_RETRIES": "Maximum bounded HTTP retry count for eligible failures; it does not authorize blind replay of ambiguous mutations.",
    "PROVIDER_HTTP_MAX_TIMEOUT": "Upper bound in seconds applied to provider-directed retry or timeout intervals.",
    "PROVIDER_HTTP_READ_TIMEOUT": "Seconds allowed to wait for provider response bytes after connection establishment.",
    "S3_MULTIPART_CHECKPOINT_PARTS": "Number of uploaded parts between durable multipart-ledger checkpoints.",
    "S3_MULTIPART_HASH_CHUNK_BYTES": "Local read chunk size used while hashing source data for multipart integrity evidence.",
    "S3_MULTIPART_NO_PROGRESS_RETRY_AFTER_SECONDS": "Delay before retrying a multipart upload that crossed the no-progress threshold.",
    "S3_MULTIPART_NO_PROGRESS_SECONDS": "Maximum time without multipart progress before the attempt becomes eligible for retry/reconciliation.",
    "S3_MULTIPART_PART_SIZE_BYTES": "Target S3 multipart part size; must remain compatible with provider part-count and minimum-size rules.",
    "S3_MULTIPART_TARGET_PARTS": "Planning target used to increase part size for very large objects while staying below the provider part limit.",
    "S3_MULTIPART_THRESHOLD_BYTES": "Object-size threshold at which the verified S3 uploader switches from one PUT to durable multipart upload.",
    "SOURCE_ARCHIVE_VERIFY_TIMEOUT_SECONDS": "Maximum seconds allowed for full ZIP integrity verification before an artifact can be published as verified.",
    "TELEGRAM_BOT_KEY": "Deployment-wide Telegram bot token used to deliver account notifications to configured chats.",
    "MS_APPLICATION_ID": "Microsoft Entra application identifier used by the OneDrive OAuth integration when required by the registered app.",
    "MS_CLIENT_SECRET_ID": "Identifier or label for the Microsoft application secret; it is not the secret value itself.",
    "MS_CLIENT_SECRET_VALUE": "Secret value for the Microsoft/OneDrive OAuth application. Protect it as a deployment credential.",
    "MS_GRAPH_ENDPOINT": "Microsoft Graph API base URL used for OneDrive discovery, upload, verification, and download operations.",
    "MS_OAUTH_ENDPOINT": "Microsoft authorization endpoint used to begin the OneDrive account-grant flow.",
    "MS_OAUTH_TOKEN_URL": "Microsoft token endpoint used to exchange and refresh OneDrive OAuth grants.",
    "MS_OBJECT_ID": "Optional Microsoft Entra object identifier associated with the registered application configuration.",
    "MS_REDIRECT_URL": "Public callback path registered for the Microsoft/OneDrive OAuth application.",
    "MS_RESPONSE_TYPE": "OAuth response type requested from Microsoft; code is the supported authorization-code flow.",
    "MS_SCOPE": "Space-separated Microsoft permissions requested for OneDrive access and refresh capability.",
    "MS_TENANT_ID": "Microsoft tenant selector for the OAuth application; common permits multi-tenant sign-in when the app registration allows it.",
    "DB_HOST": "PostgreSQL hostname used when DATABASE_URL is unset. In the bundled Compose topology this is the private db service.",
    "DB_PASSWORD": "Password for the PostgreSQL application role and bundled database initialization. Replace the sample and protect it as a secret.",
    "DB_PORT": "PostgreSQL TCP port used when DATABASE_URL is unset.",
    "DB_USER": "PostgreSQL role used by the app, workers, scheduler, and migrations when DATABASE_URL is unset.",
    "RABBITMQ_PASSWORD": "Password fragment used to construct the RabbitMQ broker URL when RABBITMQ_HOST is set.",
    "RABBITMQ_PORT": "RabbitMQ AMQP port used when constructing the broker URL from fragments.",
    "RABBITMQ_USER": "RabbitMQ username used when constructing the broker URL from fragments.",
    "RABBITMQ_VHOST": "RabbitMQ virtual host used when constructing the broker URL from fragments.",
    "DATABASE_COMMAND_TIMEOUT": "Maximum seconds allowed for a full logical database dump command, including large exports.",
    "DATABASE_CONNECT_TIMEOUT": "Maximum seconds allowed to establish a database source connection during backup or validation.",
    "DATABASE_LOCK_TIMEOUT_MS": "Database-session lock wait ceiling in milliseconds used to avoid indefinitely blocked logical dump work.",
    "DATABASE_STATEMENT_TIMEOUT_MS": "Database-session statement ceiling in milliseconds used for bounded validation and metadata queries.",
    "DATABASE_VALIDATION_COMMAND_TIMEOUT": "Maximum seconds allowed for short database client validation commands.",
    "SSH_AUTH_TIMEOUT": "Seconds allowed for SSH authentication after transport and banner negotiation.",
    "SSH_BANNER_TIMEOUT": "Seconds allowed to receive the remote SSH identification banner.",
    "SSH_CONNECT_TIMEOUT": "Seconds allowed to establish an SSH/SFTP source connection.",
    "SSH_KEEPALIVE_SECONDS": "Interval for SSH keepalive probes during long website/database operations; zero may disable probes depending on the client.",
    "SSH_KNOWN_HOSTS_PATH": "Compatibility-only file path for separately reviewed non-stock deployments. Stock Compose stores account-scoped approvals/audit in PostgreSQL and materializes transient exact per-operation trust.",
    "SSH_MANAGED_DATABASE_PUBLIC_KEY": "Public half of the optional database-worker Ed25519 identity; must match its lane secret and differ from the files identity.",
    "SSH_MANAGED_FILES_PUBLIC_KEY": "Public half of the optional files-worker Ed25519 identity; must match its lane secret and differ from the database identity.",
    "SSH_MANAGED_LANE_ISOLATION_REQUIRED": "Fail-closed stock guard requiring distinct database/files identities and lane-only private-key custody.",
    "SSH_MANAGED_PRIVATE_KEY_PATH": "Legacy shared path that stays blank in stock configuration; an eligible database/files worker exports its validated lane-private runtime target internally.",
    "SSH_MANAGED_PUBLIC_KEY": "Legacy shared public-key setting that must remain blank in stock Compose.",
    "MAILGUN_API_KEY": "Secret API key used by the Mailgun transactional-email provider.",
    "MAILGUN_API_URL": "Mailgun API base URL, including the appropriate regional endpoint when required.",
    "MAILGUN_EMAIL": "Verified Mailgun sender address used for application email.",
    "POSTMARK_API_URL": "Postmark API base URL used for transactional email delivery.",
    "POSTMARK_DOMAIN": "Verified Postmark sender domain associated with the configured server token.",
    "POSTMARK_EMAIL": "Verified Postmark sender address used for application email.",
    "SES_ACCESS_KEY_ID": "AWS access-key identifier for the IAM principal permitted to send transactional email through SES.",
    "SES_REGION_ENDPOINT": "Regional SES service hostname used by the email client.",
    "SES_SECRET_ACCESS_KEY": "Secret half of the AWS credential used for SES transactional email.",
}


def inferred_env_description(name: str) -> str:
    if name in ENV_DESCRIPTIONS:
        return ENV_DESCRIPTIONS[name]

    worker_match = re.fullmatch(r"CELERY_(CLOUD|DATABASE|FILES|STORAGE|LOGS)_(CONCURRENCY|PREFETCH_MULTIPLIER)", name)
    if worker_match:
        lane, control = worker_match.groups()
        lane_name = lane.lower()
        if control == "CONCURRENCY":
            return f"Maximum worker processes for the {lane_name} queue in the stock deployment; raising it multiplies resource and upstream load."
        return f"Number of {lane_name} tasks each worker process may reserve ahead; keep at 1 for long-running, late-acknowledged work unless measured."

    ovh_match = re.fullmatch(r"OVH_(CA|EU|US)_APP_(KEY|SECRET)", name)
    if ovh_match:
        region, credential = ovh_match.groups()
        kind = "public application key" if credential == "KEY" else "application secret"
        return f"OVH {region} {kind} used for the matching regional instance and volume API; credentials are not interchangeable across OVH regions."

    if name.endswith(("_CLIENT_SECRET", "_APP_SECRET", "_API_KEY")):
        provider = name.rsplit("_", 2)[0].replace("_", " ").title()
        return f"Deployment OAuth/API credential for {provider}; protect it as a secret and rotate it through the provider application workflow."
    if name.endswith(("_CLIENT_ID", "_APP_KEY")):
        provider = name.rsplit("_", 2)[0].replace("_", " ").title()
        return f"Public application identifier for the {provider} integration; it must match the registered callback configuration."
    if name.endswith(("_TOKEN_URL", "_OAUTH_ENDPOINT", "_AUTH_URL")):
        return f"Authorization or token-service endpoint used by {name.split('_', 1)[0].title()}; override only for a reviewed provider environment."
    if name.endswith(("_API_URL", "_ENDPOINT")):
        return f"Service endpoint override for {name.split('_', 1)[0].title()}; keep the documented HTTPS provider host unless a regional endpoint is required."

    return f"Advanced {config_category(name).lower()} control read at process start. Review its implementation references, unit, and restart scope before changing {name}."


def setting_default(node: ast.Call) -> str:
    if len(node.args) < 2:
        return "Application default"
    try:
        value = ast.literal_eval(node.args[1])
    except (ValueError, TypeError):
        return "Computed by application"
    if value in (None, ""):
        return "Not set"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def settings_only_catalog(existing_names: set[str]) -> list[dict[str, object]]:
    tree = ast.parse(SETTINGS_PATH.read_text(encoding="utf-8"))
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        function = node.func
        is_config_get = (
            isinstance(function, ast.Attribute)
            and function.attr == "get"
            and isinstance(function.value, ast.Name)
            and function.value.id == "config"
        )
        is_environ_get = (
            isinstance(function, ast.Attribute)
            and function.attr == "get"
            and isinstance(function.value, ast.Attribute)
            and function.value.attr == "environ"
        )
        if not (is_config_get or is_environ_get):
            continue
        if not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
            continue
        name = node.args[0].value
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or name in existing_names:
            continue
        found.setdefault(name, setting_default(node))

    catalog: list[dict[str, object]] = []
    for name, raw_default in sorted(found.items()):
        default, sensitive = display_default(name, raw_default)
        description = SETTINGS_ONLY_DESCRIPTIONS.get(
            name,
            "Test/support setting read by the application but not included in the normal operator sample. Do not enable it in production without reviewing the implementation.",
        )
        catalog.append(
            {
                "name": name,
                "category": config_category(name),
                "default": default,
                "sensitive": sensitive,
                "required": False,
                "description": description,
                "source": "backupsheep/settings.py",
            }
        )
    return catalog


def build_config_catalog() -> list[dict[str, object]]:
    catalog: list[dict[str, object]] = []
    comments: list[str] = []

    for raw_line in ENV_SAMPLE_PATH.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("#"):
            comments.append(stripped)
            continue
        if not stripped:
            comments = []
            continue

        match = ENV_ASSIGNMENT.match(stripped)
        if not match:
            comments = []
            continue

        name, raw_value = match.groups()
        default, sensitive = display_default(name, raw_value)
        description = normalize_comment(comments)
        if not description:
            description = inferred_env_description(name)

        catalog.append(
            {
                "name": name,
                "category": config_category(name),
                "default": default,
                "sensitive": sensitive,
                "required": "change-this" in raw_value or name in {"DJANGO_SECRET_KEY", "DB_PASSWORD"},
                "description": description,
                "source": ".env_sample",
            }
        )
        comments = []

    catalog.extend(settings_only_catalog({str(entry["name"]) for entry in catalog}))
    return sorted(catalog, key=lambda entry: (str(entry["category"]), str(entry["name"])))


def build_api_catalog(manifest: dict[str, object]) -> list[dict[str, object]]:
    operations: list[dict[str, object]] = []
    for raw in manifest["operations"]:  # type: ignore[index]
        operation = dict(raw)
        operation["family"] = api_family(str(operation["path"]))
        operation["source_href"] = "../../" + str(operation["source"])
        operation["bruno_href"] = "../../bruno/" + str(operation["file"])
        operations.append(operation)
    return operations


def git_text(*arguments: str) -> str:
    """Return a small, non-secret Git value when built inside a checkout."""

    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ""
    return result.stdout.strip()


def api_provenance(
    manifest: dict[str, object],
    *,
    source_revision: str,
    catalog_source: str,
) -> dict[str, object]:
    status = git_text(
        "status",
        "--porcelain",
        "--",
        "apps/api/v1",
        "backupsheep/urls.py",
        "bruno/route-manifest.json",
        "bruno/requests",
    )
    committed_counts = manifest["counts"]  # type: ignore[index]
    committed_manifest = git_text("show", "HEAD:bruno/route-manifest.json")
    if committed_manifest:
        try:
            committed_counts = json.loads(committed_manifest)["counts"]
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return {
        "sourceRevision": source_revision,
        "catalogSource": catalog_source,
        "workingTreeApiChanges": bool(status),
        "includesWorkingTreeApiChanges": catalog_source == "working-tree" and bool(status),
        "committedApi": committed_counts,
    }


def sync_brand_asset() -> None:
    asset_root = DOC_ROOT / "assets"
    asset_root.mkdir(parents=True, exist_ok=True)
    source = REPO_ROOT / "apps" / "console" / "_static" / "console" / "images" / "logo_white_small.png"
    shutil.copyfile(source, asset_root / "backupsheep-wordmark.png")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the source-derived enterprise API and configuration catalogs."
    )
    parser.add_argument(
        "--git-ref",
        help=(
            "Read bruno/route-manifest.json from this Git revision instead of the "
            "working tree. Use HEAD for a release-consistent documentation-only commit."
        ),
    )
    return parser.parse_args()


def manifest_input(git_ref: str | None) -> tuple[dict[str, object], str, str]:
    if not git_ref:
        revision = git_text("rev-parse", "--short=12", "HEAD") or "unknown"
        return (
            json.loads(MANIFEST_PATH.read_text(encoding="utf-8")),
            revision,
            "working-tree",
        )

    manifest_text = git_text("show", f"{git_ref}:bruno/route-manifest.json")
    revision = git_text("rev-parse", "--short=12", git_ref)
    if not manifest_text or not revision:
        raise SystemExit(f"Unable to read the API manifest from Git revision {git_ref!r}")
    return json.loads(manifest_text), revision, "git-ref"


def main() -> None:
    args = parse_args()
    manifest, source_revision, catalog_source = manifest_input(args.git_ref)
    operations = build_api_catalog(manifest)
    configuration = build_config_catalog()

    payload = {
        "metadata": {
            "schemaVersion": 1,
            "api": manifest["counts"],
            "generatedFrom": manifest["generated_from"],
            "configurationVariables": len(configuration),
            "provenance": api_provenance(
                manifest,
                source_revision=source_revision,
                catalog_source=catalog_source,
            ),
        },
        "operations": operations,
        "configuration": configuration,
    }

    GENERATED_ROOT.mkdir(parents=True, exist_ok=True)
    output = GENERATED_ROOT / "catalog.js"
    serialized = json.dumps(payload, indent=2, ensure_ascii=False)
    output.write_text(
        "/* Generated by tools/build_catalogs.py. Do not edit by hand. */\n"
        f"window.BACKUPSHEEP_DOC_CATALOG = {serialized};\n",
        encoding="utf-8",
    )
    sync_brand_asset()

    print(
        "Generated enterprise catalog: "
        f"{len(operations)} API operations, {len(configuration)} configuration variables."
    )


if __name__ == "__main__":
    main()
