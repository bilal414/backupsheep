"""Crash-safe live E2E harness for the native AWS EC2/EBS paths.

The harness is intentionally disposable and account-scoped.  It creates one
uniquely tagged EC2 fixture containing a tiny website/database fixture, one
standalone EBS volume, then exercises BackupSheep's durable AMI and EBS
snapshot/restore state machines against those resources.  It is read-only
unless ``BACKUPSHEEP_E2E_APPLY=YES`` is present.  Cleanup is a second explicit
opt-in and requires ``BACKUPSHEEP_E2E_CLEANUP=YES`` as well.

The resource ledger is authoritative for cleanup.  A provider response, a
generated name, or a matching inventory row is never enough: every resource is
read back with its exact account/region/tags before its provider ID is recorded.
Mutation intents are persisted beside the ledger before non-idempotent calls so
a lost response cannot cause a later invocation to issue a second create.

Credentials are read only from the process environment.  The script does not
read repository credential files.  It is intended to run inside the app image,
for example:

    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
      BACKUPSHEEP_E2E_RUN_ID=bs-e2e-20260810-5b4a6b63 \
      BACKUPSHEEP_E2E_LEDGER_PATH=/code/_storage/e2e-ledgers/aws-ec2.json \
      BACKUPSHEEP_E2E_APPLY=YES \
      python scripts/aws_ec2_ebs_e2e.py

No live mutation is performed by this module's tests; the command above is
only an example for an explicitly approved disposable run.
"""

from __future__ import annotations

import fcntl
import html
import ipaddress
import json
import os
import re
import shlex
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import boto3
import django
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)
from cryptography.fernet import Fernet


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backupsheep.settings")
django.setup()

from django.contrib.auth import get_user_model  # noqa: E402

from apps.api.v1.utils.api_helpers import bs_encrypt  # noqa: E402
from apps.console.account.models import CoreAccount  # noqa: E402
from apps.console.backup.models import CoreAWSBackup, CoreCloudRestore  # noqa: E402
from apps.console.connection.models import (  # noqa: E402
    CoreAuthAWS,
    CoreAWSRegion,
    CoreConnection,
    CoreConnectionLocation,
    CoreIntegration,
)
from apps.console.member.models import CoreMember, CoreMemberAccount  # noqa: E402
from apps.console.node.models import CoreAWS, CoreNode  # noqa: E402
from apps.console.utils.models import UtilBackup  # noqa: E402
from scripts.live_e2e_ledger import (  # noqa: E402
    DurableResourceLedger,
    LedgerError,
    require_run_id,
)


REGION = os.environ.get("AWS_E2E_REGION", "us-east-2")
INSTANCE_TYPE = os.environ.get("AWS_E2E_INSTANCE_TYPE", "t3.micro")
VOLUME_SIZE_GIB = max(int(os.environ.get("AWS_E2E_VOLUME_SIZE_GIB", "8")), 1)
POLL_SECONDS = max(int(os.environ.get("AWS_E2E_POLL_SECONDS", "15")), 3)
TIMEOUT_SECONDS = max(
    int(os.environ.get("AWS_E2E_TIMEOUT_SECONDS", "1800")), 60
)
APPLY = os.environ.get("BACKUPSHEEP_E2E_APPLY") == "YES"
CLEANUP = os.environ.get("BACKUPSHEEP_E2E_CLEANUP") == "YES"
AWS_CONFIG = Config(
    connect_timeout=10,
    read_timeout=60,
    retries={"total_max_attempts": 1, "mode": "standard"},
)

OWNERSHIP_TAG = "BackupSheepE2E"
ROLE_TAG = "BackupSheepE2ERole"
PARENT_TAG = "BackupSheepE2EParent"
RESTORE_TAG = "BackupSheepRestore"
SOURCE_TAG = "BackupSheepSource"
UBUNTU_OWNER = "099720109477"


class HarnessError(RuntimeError):
    """A live harness invariant failed closed."""


class AmbiguousMutation(HarnessError):
    """A provider mutation may have been accepted but its response was lost."""


class MutationIntentStore:
    """Small atomic sidecar for pre-mutation intent and ambiguous outcomes."""

    def __init__(self, path, *, run_id, scope):
        if not path:
            raise LedgerError("A ledger path is required for mutation intents.")
        self.path = Path(path).expanduser().resolve().with_name(
            Path(path).name + ".intents.json"
        )
        self.run_id = require_run_id(run_id)
        self.scope = str(scope)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        with self._locked():
            if self.path.exists():
                self._validate(self._read())
            else:
                self._write(
                    {
                        "schema": 1,
                        "run_id": self.run_id,
                        "scope": self.scope,
                        "pending": {},
                    }
                )

    def _locked(self):
        store = self

        class Lock:
            def __enter__(self):
                self.handle = open(store.lock_path, "a+", encoding="utf-8")
                os.chmod(store.lock_path, 0o600)
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
                return self.handle

            def __exit__(self, exc_type, exc, tb):
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
                self.handle.close()

        return Lock()

    def _read(self):
        try:
            with open(self.path, encoding="utf-8") as source:
                return json.load(source)
        except (OSError, ValueError) as error:
            raise LedgerError("The mutation intent sidecar could not be read.") from error

    def _validate(self, payload):
        if not isinstance(payload, dict):
            raise LedgerError("The mutation intent sidecar is malformed.")
        if payload.get("schema") != 1:
            raise LedgerError("The mutation intent sidecar schema is unsupported.")
        if payload.get("run_id") != self.run_id or payload.get("scope") != self.scope:
            raise LedgerError("The mutation intent sidecar scope does not match.")
        if not isinstance(payload.get("pending"), dict):
            raise LedgerError("The mutation intent sidecar pending map is malformed.")
        return payload

    def _write(self, payload):
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(payload, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def get(self, key):
        with self._locked():
            payload = self._validate(self._read())
            value = payload["pending"].get(str(key))
            return dict(value) if isinstance(value, dict) else None

    def set(self, key, value):
        if not isinstance(value, dict) or not value.get("marker"):
            raise LedgerError("A mutation intent requires a deterministic marker.")
        with self._locked():
            payload = self._validate(self._read())
            current = payload["pending"].get(str(key))
            if current is not None and current != value:
                raise LedgerError("A mutation intent already exists with another witness.")
            payload["pending"][str(key)] = dict(value)
            self._write(payload)

    def clear(self, key):
        with self._locked():
            payload = self._validate(self._read())
            payload["pending"].pop(str(key), None)
            self._write(payload)

    def clear_all(self):
        with self._locked():
            payload = self._validate(self._read())
            payload["pending"] = {}
            self._write(payload)

    def pending(self):
        with self._locked():
            payload = self._validate(self._read())
            return {key: dict(value) for key, value in payload["pending"].items()}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _safe_error(error):
    """Return bounded diagnostic text without dumping request configuration."""
    return str(error or "")[:500]


def _tag_map(tags):
    if isinstance(tags, dict):
        return {str(key): str(value) for key, value in tags.items()}
    return {
        str(item.get("Key")): str(item.get("Value", ""))
        for item in tags or []
        if isinstance(item, dict) and item.get("Key") is not None
    }


def _tags(prefix, role, **extra):
    values = {OWNERSHIP_TAG: prefix, ROLE_TAG: role}
    aliases = {"Parent": PARENT_TAG, "Source": SOURCE_TAG, "Restore": RESTORE_TAG}
    values.update(
        {
            aliases.get(str(key), str(key)): str(value)
            for key, value in extra.items()
            if value is not None
        }
    )
    return [{"Key": key, "Value": value} for key, value in values.items()]


def _not_found(error):
    if not isinstance(error, ClientError):
        return False
    code = str((error.response.get("Error") or {}).get("Code") or "")
    return code.lower() in {
        "invalidinstanceid.notfound",
        "invalidvolume.notfound",
        "invalidsnapshot.notfound",
        "invalidamiid.notfound",
        "invalidgroup.notfound",
        "invalidkeypair.notfound",
        "invalidgroup.notfound",
        "invalidid.notfound",
        "notfound",
    }


def _ambiguous_error(error):
    return isinstance(
        error,
        (
            AmbiguousMutation,
            BotoCoreError,
            ConnectTimeoutError,
            EndpointConnectionError,
            ReadTimeoutError,
            TimeoutError,
            OSError,
        ),
    )


def _flatten_instances(response):
    if not isinstance(response, dict):
        raise HarnessError("EC2 returned a malformed instance response.")
    instances = []
    for reservation in response.get("Reservations") or []:
        if not isinstance(reservation, dict):
            raise HarnessError("EC2 returned a malformed reservation.")
        page = reservation.get("Instances")
        if not isinstance(page, list):
            raise HarnessError("EC2 returned a malformed instance collection.")
        instances.extend(page)
    return instances


def _paged(method, key, **params):
    """Read all bounded EC2 pages while refusing repeated cursors."""
    items = []
    token = None
    seen = set()
    for _ in range(1000):
        request = dict(params)
        request["MaxResults"] = min(int(request.get("MaxResults", 100)), 1000)
        if token:
            request["NextToken"] = token
        response = method(**request)
        if not isinstance(response, dict) or not isinstance(response.get(key), list):
            raise HarnessError("EC2 returned a malformed paginated response.")
        items.extend(response[key])
        next_token = response.get("NextToken")
        if not next_token:
            return items
        if not isinstance(next_token, str) or next_token in seen or next_token == token:
            raise HarnessError("EC2 returned a repeated pagination cursor.")
        seen.add(next_token)
        token = next_token
    raise HarnessError("EC2 pagination exceeded the bounded reconciliation limit.")


def _describe_instance(ec2, instance_id):
    try:
        instances = _flatten_instances(ec2.describe_instances(InstanceIds=[str(instance_id)]))
    except ClientError as error:
        if _not_found(error):
            return None
        raise
    matches = [
        item
        for item in instances
        if isinstance(item, dict) and str(item.get("InstanceId")) == str(instance_id)
    ]
    if len(matches) > 1:
        raise HarnessError("EC2 returned duplicate instance IDs.")
    return matches[0] if matches else None


def _describe_volume(ec2, volume_id):
    try:
        volumes = ec2.describe_volumes(VolumeIds=[str(volume_id)]).get("Volumes") or []
    except ClientError as error:
        if _not_found(error):
            return None
        raise
    matches = [
        item
        for item in volumes
        if isinstance(item, dict) and str(item.get("VolumeId")) == str(volume_id)
    ]
    if len(matches) > 1:
        raise HarnessError("EC2 returned duplicate volume IDs.")
    return matches[0] if matches else None


def _describe_image(ec2, image_id, account_id):
    try:
        images = ec2.describe_images(
            Owners=[str(account_id)], ImageIds=[str(image_id)]
        ).get("Images") or []
    except ClientError as error:
        if _not_found(error):
            return None
        raise
    matches = [
        item
        for item in images
        if isinstance(item, dict) and str(item.get("ImageId")) == str(image_id)
    ]
    if len(matches) > 1:
        raise HarnessError("EC2 returned duplicate AMI IDs.")
    return matches[0] if matches else None


def _describe_snapshot(ec2, snapshot_id, account_id):
    try:
        snapshots = ec2.describe_snapshots(
            OwnerIds=[str(account_id)], SnapshotIds=[str(snapshot_id)]
        ).get("Snapshots") or []
    except ClientError as error:
        if _not_found(error):
            return None
        raise
    matches = [
        item
        for item in snapshots
        if isinstance(item, dict) and str(item.get("SnapshotId")) == str(snapshot_id)
    ]
    if len(matches) > 1:
        raise HarnessError("EC2 returned duplicate snapshot IDs.")
    return matches[0] if matches else None


def _describe_key_pair(ec2, key_pair_id):
    try:
        rows = ec2.describe_key_pairs(KeyPairIds=[str(key_pair_id)]).get(
            "KeyPairs"
        ) or []
    except ClientError as error:
        if _not_found(error):
            return None
        raise
    matches = [
        item
        for item in rows
        if isinstance(item, dict)
        and str(item.get("KeyPairId") or "") == str(key_pair_id)
    ]
    if len(matches) > 1:
        raise HarnessError("EC2 returned duplicate key-pair IDs.")
    return matches[0] if matches else None


def _owned_tags(resource, prefix, role, *, marker=None, source_id=None, parent=None):
    tags = _tag_map((resource or {}).get("Tags"))
    if tags.get(OWNERSHIP_TAG) != str(prefix) or tags.get(ROLE_TAG) != str(role):
        return False
    if marker is not None and tags.get(RESTORE_TAG) != str(marker):
        return False
    if source_id is not None and tags.get(SOURCE_TAG) != str(source_id):
        return False
    if parent is not None and tags.get(PARENT_TAG) != str(parent):
        return False
    return True


def _candidate_instances(ec2, prefix, role):
    rows = _paged(
        ec2.describe_instances,
        "Reservations",
        Filters=[
            {"Name": f"tag:{OWNERSHIP_TAG}", "Values": [str(prefix)]},
            {"Name": f"tag:{ROLE_TAG}", "Values": [str(role)]},
        ],
    )
    candidates = []
    for reservation in rows:
        if not isinstance(reservation, dict):
            raise HarnessError("EC2 returned a malformed instance page.")
        page = reservation.get("Instances")
        if not isinstance(page, list):
            raise HarnessError("EC2 returned a malformed instance page.")
        candidates.extend(page)
    unique = {}
    for item in candidates:
        if isinstance(item, dict) and item.get("InstanceId"):
            unique[str(item["InstanceId"])] = item
    return list(unique.values())


def _candidate_volumes(ec2, prefix, role):
    rows = _paged(
        ec2.describe_volumes,
        "Volumes",
        Filters=[
            {"Name": f"tag:{OWNERSHIP_TAG}", "Values": [str(prefix)]},
            {"Name": f"tag:{ROLE_TAG}", "Values": [str(role)]},
        ],
    )
    unique = {}
    for item in rows:
        if isinstance(item, dict) and item.get("VolumeId"):
            unique[str(item["VolumeId"])] = item
    return list(unique.values())


def _candidate_images(ec2, prefix, marker, account_id):
    rows = _paged(
        ec2.describe_images,
        "Images",
        Owners=[str(account_id)],
        Filters=[
            {"Name": "name", "Values": [str(marker)]},
            {"Name": f"tag:{OWNERSHIP_TAG}", "Values": [str(prefix)]},
            {"Name": f"tag:{ROLE_TAG}", "Values": ["ami"]},
        ],
    )
    unique = {}
    for item in rows:
        if isinstance(item, dict) and item.get("ImageId"):
            unique[str(item["ImageId"])] = item
    return list(unique.values())


def _candidate_snapshots(ec2, prefix, role, account_id, *, parent=None, marker=None):
    filters = [
        {"Name": f"tag:{OWNERSHIP_TAG}", "Values": [str(prefix)]},
        {"Name": f"tag:{ROLE_TAG}", "Values": [str(role)]},
    ]
    if parent is not None:
        filters.append({"Name": f"tag:{PARENT_TAG}", "Values": [str(parent)]})
    if marker is not None:
        filters.append({"Name": "description", "Values": [str(marker)]})
    rows = _paged(
        ec2.describe_snapshots,
        "Snapshots",
        OwnerIds=[str(account_id)],
        Filters=filters,
    )
    unique = {}
    for item in rows:
        if isinstance(item, dict) and item.get("SnapshotId"):
            unique[str(item["SnapshotId"])] = item
    return list(unique.values())


def _source_volume_id(instance):
    mappings = instance.get("BlockDeviceMappings") or []
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        ebs = mapping.get("Ebs") or {}
        if mapping.get("DeviceName") == instance.get("RootDeviceName") and ebs.get("VolumeId"):
            return str(ebs["VolumeId"])
    for mapping in mappings:
        ebs = mapping.get("Ebs") if isinstance(mapping, dict) else None
        if isinstance(ebs, dict) and ebs.get("VolumeId"):
            return str(ebs["VolumeId"])
    return ""


def _wait(label, callback, complete, failed=(), timeout=TIMEOUT_SECONDS):
    started = time.monotonic()
    history = []
    while True:
        value = callback()
        history.append(str(value))
        if value in complete:
            return value, history
        if value in set(failed):
            raise HarnessError(f"{label} failed with state {value!r}.")
        if time.monotonic() - started >= timeout:
            raise TimeoutError(f"Timed out waiting for {label}: {history[-8:]}")
        time.sleep(POLL_SECONDS)


def _mutation(intents, key, marker, operation, callback):
    """Persist intent before a mutation and refuse a blind second attempt."""
    pending = intents.get(key)
    if pending:
        raise HarnessError(
            f"Pending {operation} intent exists for {marker}; reconcile read-only before retry."
        )
    intents.set(
        key,
        {
            "marker": str(marker),
            "operation": str(operation),
            "created_at": _now(),
        },
    )
    try:
        return callback()
    except Exception as error:
        raise AmbiguousMutation(
            f"{operation} outcome is unknown for {marker}; no retry was issued: {_safe_error(error)}"
        ) from error


def _record(
    ledger,
    *,
    kind,
    resource_id,
    name,
    prefix,
    role,
    source="",
    marker=None,
    source_id=None,
    parent=None,
):
    ownership = {
        "tag_key": OWNERSHIP_TAG,
        "tag_value": str(prefix),
        "role": str(role),
    }
    if marker is not None:
        ownership["restore_marker"] = str(marker)
    if source_id is not None:
        ownership["source_id"] = str(source_id)
    if parent is not None:
        ownership["parent_id"] = str(parent)
    return ledger.record(
        kind=kind,
        resource_id=str(resource_id),
        name=name,
        ownership=ownership,
        source_witness=source,
    )


def _entry_matches(resource, entry):
    ownership = entry.get("ownership") or {}
    tags = _tag_map((resource or {}).get("Tags"))
    if tags.get(str(ownership.get("tag_key") or OWNERSHIP_TAG)) != str(
        ownership.get("tag_value") or ""
    ):
        return False
    if ownership.get("role") is not None and tags.get(ROLE_TAG) != str(ownership["role"]):
        return False
    if ownership.get("restore_marker") is not None and tags.get(RESTORE_TAG) != str(
        ownership["restore_marker"]
    ):
        return False
    if ownership.get("source_id") is not None and tags.get(SOURCE_TAG) != str(
        ownership["source_id"]
    ):
        return False
    if ownership.get("parent_id") is not None and tags.get(PARENT_TAG) != str(
        ownership["parent_id"]
    ):
        return False
    return True


def _fixture_user_data(prefix):
    database_user = str(
        os.environ.get("AWS_E2E_POSTGRES_USER") or "backupsheep"
    )
    database_name = str(
        os.environ.get("AWS_E2E_POSTGRES_DATABASE") or "backupsheep_e2e"
    )
    database_password = str(
        os.environ.get("AWS_E2E_POSTGRES_PASSWORD") or ""
    )
    identifier = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
    if not identifier.fullmatch(database_user) or not identifier.fullmatch(
        database_name
    ):
        raise HarnessError(
            "AWS E2E PostgreSQL user/database names must be lowercase SQL identifiers."
        )
    if len(database_password) < 20:
        raise HarnessError(
            "AWS_E2E_POSTGRES_PASSWORD must contain at least 20 characters."
        )
    website_marker = f"{prefix}:website-fixture"
    database_marker = f"{prefix}:database-fixture"
    html_body = html.escape(website_marker)
    html_database = html.escape(database_marker)
    sql_marker = database_marker.replace("'", "''")
    sql_password = database_password.replace("'", "''")
    role_sql = shlex.quote(
        "DO $do$ BEGIN "
        f"IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{database_user}') "
        f"THEN CREATE ROLE {database_user} LOGIN PASSWORD '{sql_password}'; "
        f"ELSE ALTER ROLE {database_user} WITH LOGIN PASSWORD '{sql_password}'; "
        "END IF; END $do$;"
    )
    fixture_sql = shlex.quote(
        "CREATE TABLE IF NOT EXISTS backupsheep_e2e_fixture "
        "(id integer primary key, marker text not null, payload text not null); "
        "INSERT INTO backupsheep_e2e_fixture (id, marker, payload) "
        f"SELECT value, '{sql_marker}', md5(value::text || '{sql_marker}') "
        "FROM generate_series(1, 250) AS value "
        "ON CONFLICT (id) DO UPDATE SET marker = EXCLUDED.marker, "
        "payload = EXCLUDED.payload; "
        f"GRANT USAGE ON SCHEMA public TO {database_user}; "
        f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {database_user}; "
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {database_user};"
    )
    return f"""#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y nginx postgresql
systemctl enable --now nginx
systemctl enable --now postgresql
runuser -u postgres -- psql --set ON_ERROR_STOP=1 -c {role_sql}
runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname = '{database_name}'" | grep -q 1 || runuser -u postgres -- createdb --owner={database_user} {database_name}
runuser -u postgres -- psql --set ON_ERROR_STOP=1 --dbname={database_name} -c {fixture_sql}
cat > /var/www/html/index.html <<'EOF'
<!doctype html><html><body><h1>{html_body}</h1><p>{html_database}</p></body></html>
EOF
mkdir -p /var/www/html/datasets
for value in $(seq 1 50); do printf '%s,%s,%s\n' "$value" '{website_marker}' "$(printf '%s' "$value:{website_marker}" | sha256sum | cut -d' ' -f1)" >> /var/www/html/datasets/records.csv; done
chown -R www-data:www-data /var/www/html
touch /var/lib/backupsheep-e2e-database-ready
"""


def _get_or_create_graph(prefix, region, access_key, secret_key, source_instance_id, source_volume_id):
    """Create one deterministic local graph so a rerun reuses restore markers."""
    User = get_user_model()
    email = f"{prefix}-aws-ec2@example.invalid"
    user, user_created = User.objects.get_or_create(
        username=email,
        defaults={"email": email},
    )
    if user_created:
        user.set_password("backup-sheep-e2e-local-only")
        user.save(update_fields=["password"])
    member, _ = CoreMember.objects.get_or_create(user=user, defaults={"timezone": "UTC"})
    account, account_created = CoreAccount.objects.get_or_create(
        name=f"BackupSheep AWS EC2 E2E {prefix}",
        defaults={"encryption_key": Fernet.generate_key()},
    )
    if account_created or not account.encryption_key:
        account.encryption_key = account.encryption_key or Fernet.generate_key()
        account.save(update_fields=["encryption_key", "modified"])
    CoreMemberAccount.objects.get_or_create(
        member=member,
        account=account,
        defaults={
            "status": CoreMemberAccount.Status.ACTIVE,
            "current": True,
            "primary": True,
        },
    )
    integration = CoreIntegration.objects.get(code="aws")
    location, _ = CoreConnectionLocation.objects.get_or_create(code="test-loc")
    connection, _ = CoreConnection.objects.get_or_create(
        account=account,
        integration=integration,
        name=f"BackupSheep E2E AWS {prefix}",
        defaults={"location": location, "added_by": member},
    )
    region_object = CoreAWSRegion.objects.get(code=region)
    key = account.get_encryption_key()
    CoreAuthAWS.objects.update_or_create(
        connection=connection,
        defaults={
            "region": region_object,
            "access_key": bs_encrypt(access_key, key),
            "secret_key": bs_encrypt(secret_key, key),
        },
    )

    def node_and_resource(name, node_type, resource_type, resource_id):
        node, _ = CoreNode.objects.get_or_create(
            connection=connection,
            name=name,
            defaults={"type": node_type, "added_by": member},
        )
        aws, _ = CoreAWS.objects.get_or_create(
            node=node,
            defaults={
                "name": name,
                "unique_id": resource_id,
                "resource_type": resource_type,
            },
        )
        changed = []
        if aws.unique_id != resource_id:
            aws.unique_id = resource_id
            changed.append("unique_id")
        if aws.resource_type != resource_type:
            aws.resource_type = resource_type
            changed.append("resource_type")
        if changed:
            aws.save(update_fields=changed + ["modified"])
        return node, aws

    source_node, source_aws = node_and_resource(
        f"{prefix}-webdb",
        CoreNode.Type.CLOUD,
        CoreAWS.ResourceType.INSTANCE,
        source_instance_id,
    )
    volume_node, volume_aws = node_and_resource(
        f"{prefix}-ebs",
        CoreNode.Type.VOLUME,
        CoreAWS.ResourceType.VOLUME,
        source_volume_id,
    )
    return account, member, source_node, source_aws, volume_node, volume_aws


def _backup_row(aws, marker):
    backup = (
        CoreAWSBackup.objects.filter(aws=aws, uuid=marker).order_by("id").first()
    )
    if backup is None:
        backup = CoreAWSBackup.objects.create(
            aws=aws,
            uuid=marker,
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
    return backup


def _restore_row(node, backup, name, params):
    restore = (
        CoreCloudRestore.objects.filter(
            node=node, backup_id=backup.id, name=name
        )
        .order_by("id")
        .first()
    )
    if restore is None:
        return CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name=name,
            params=dict(params),
        )
    if not restore.resource_id:
        merged = dict(restore.params or {})
        merged.update(dict(params))
        if merged != restore.params:
            restore.params = merged
            restore.save(update_fields=["params", "modified"])
    return restore


def _wait_backup(backup, label):
    def poll():
        state = backup.poll_status()
        backup.refresh_from_db()
        return state

    state, history = _wait(
        label,
        poll,
        {UtilBackup.Status.COMPLETE},
        {UtilBackup.Status.FAILED, UtilBackup.Status.TIMEOUT},
    )
    return {
        "status": backup.get_status_display(),
        "state": int(state),
        "history": [str(item) for item in history[-8:]],
        "provider_id": str(backup.unique_id),
    }


def _wait_restore(restore, label):
    def poll():
        state = restore.poll_status()
        restore.refresh_from_db()
        return state

    state, history = _wait(
        label,
        poll,
        {CoreCloudRestore.Status.COMPLETE},
        {CoreCloudRestore.Status.FAILED},
    )
    if restore.status != state:
        restore.status = state
        restore.save(update_fields=["status", "modified"])
    return {
        "status": restore.get_status_display(),
        "state": int(state),
        "history": [str(item) for item in history[-8:]],
        "provider_id": str(restore.resource_id),
        "marker": str(restore.restore_marker),
    }


def _ensure_tagged_resource(
    ec2,
    ledger,
    intents,
    *,
    prefix,
    kind,
    role,
    marker,
    candidates,
    readback,
    create,
    name,
    source="",
    marker_for_ledger=None,
    source_id=None,
    parent=None,
):
    """Adopt one exact resource or create once after persisting intent."""

    def _id_for(item):
        return str(
            item.get("id")
            or item.get("GroupId")
            or item.get("InstanceId")
            or item.get("VolumeId")
            or item.get("ImageId")
            or item.get("SnapshotId")
            or item.get("KeyPairId")
            or ""
        )

    entries = ledger.entries(kind)
    if len(entries) > 1:
        raise HarnessError(f"Multiple durable ledger entries exist for {kind}.")
    if entries:
        entry = entries[0]
        resource_id = str(entry.get("resource_id") or "")
        resource = readback(resource_id)
        if resource is None:
            raise HarnessError(f"Ledgered {kind} {resource_id} is absent; use a new run ID.")
        if not _entry_matches(resource, entry):
            raise HarnessError(f"Ledgered {kind} {resource_id} failed ownership read-back.")
        return resource_id, resource

    pending = intents.get(kind)
    matches = [
        item for item in candidates() if _id_for(item) and readback(_id_for(item)) is not None
    ]
    if len(matches) > 1:
        raise HarnessError(f"Multiple exact owned {kind} resources matched.")
    if len(matches) == 1:
        item = matches[0]
        resource_id = _id_for(item)
        resource = readback(resource_id)
        if resource is None:
            raise HarnessError(f"Owned {kind} candidate disappeared during read-back.")
        _record(
            ledger,
            kind=kind,
            resource_id=resource_id,
            name=name,
            prefix=prefix,
            role=role,
            source=source,
            marker=marker_for_ledger,
            source_id=source_id,
            parent=parent,
        )
        intents.clear(kind)
        return resource_id, resource

    if pending:
        raise HarnessError(
            f"No exact {kind} resource is visible for pending marker {marker}; manual review required."
        )
    response = _mutation(intents, kind, marker, role, create)
    resource_id = str(
        (response or {}).get("InstanceId")
        or (response or {}).get("GroupId")
        or (response or {}).get("VolumeId")
        or (response or {}).get("ImageId")
        or (response or {}).get("SnapshotId")
        or (response or {}).get("KeyPairId")
        or ""
    )
    if not resource_id:
        raise AmbiguousMutation(f"{role} returned no provider resource ID.")
    resource = readback(resource_id)
    if resource is None:
        raise AmbiguousMutation(f"{role} {resource_id} was not visible after create.")
    _record(
        ledger,
        kind=kind,
        resource_id=resource_id,
        name=name,
        prefix=prefix,
        role=role,
        source=source,
        marker=marker_for_ledger,
        source_id=source_id,
        parent=parent,
    )
    intents.clear(kind)
    return resource_id, resource


def _ensure_tags(ec2, intents, *, resource_ids, key, tags, readback):
    expected = _tag_map(tags)
    observed = readback()
    if all(observed.get(name) == value for name, value in expected.items()):
        intents.clear(key)
        return observed
    _mutation(
        intents,
        key,
        key,
        "tag resources",
        lambda: ec2.create_tags(Resources=[str(item) for item in resource_ids], Tags=tags),
    )
    observed = readback()
    if any(observed.get(name) != value for name, value in expected.items()):
        raise AmbiguousMutation(f"Tag read-back failed for {key}.")
    intents.clear(key)
    return observed


def _group_exists(ec2, group_id):
    try:
        groups = ec2.describe_security_groups(GroupIds=[str(group_id)]).get("SecurityGroups") or []
    except ClientError as error:
        if _not_found(error):
            return False
        raise
    return bool(groups)


def _terminate_instance_and_wait(ec2, instance_id, resource):
    root_ids = []
    for mapping in resource.get("BlockDeviceMappings") or []:
        ebs = mapping.get("Ebs") if isinstance(mapping, dict) else None
        if isinstance(ebs, dict) and ebs.get("VolumeId"):
            root_ids.append(str(ebs["VolumeId"]))
    state = str((resource.get("State") or {}).get("Name") or "")
    if state not in {"terminated", "shutting-down"}:
        ec2.terminate_instances(InstanceIds=[str(instance_id)])

    def instance_state():
        current = _describe_instance(ec2, instance_id)
        if current is None:
            return "terminated"
        return str((current.get("State") or {}).get("Name") or "unknown")

    _wait(
        f"EC2 instance {instance_id} termination",
        instance_state,
        {"terminated"},
    )
    for volume_id in root_ids:
        def volume_state(rid=volume_id):
            current = _describe_volume(ec2, rid)
            if current is None:
                return "absent"
            return str(current.get("State") or "unknown")

        _wait(
            f"EC2 root volume {volume_id} detach",
            volume_state,
            {"absent", "available"},
        )


def _delete_volume_and_wait(ec2, volume_id, resource):
    if str(resource.get("State") or "") != "deleting":
        ec2.delete_volume(VolumeId=str(volume_id))
    _wait(
        f"EBS volume {volume_id} deletion",
        lambda: "absent" if _describe_volume(ec2, volume_id) is None else "deleting",
        {"absent"},
    )


def _deregister_image_and_wait(ec2, image_id, resource):
    ec2.deregister_image(ImageId=str(image_id))
    owner_id = resource.get("OwnerId")
    _wait(
        f"AMI {image_id} deregistration",
        lambda: "absent" if _describe_image(ec2, image_id, owner_id) is None else "visible",
        {"absent"},
    )


def _delete_snapshot_and_wait(ec2, snapshot_id, resource):
    ec2.delete_snapshot(SnapshotId=str(snapshot_id))
    owner_id = resource.get("OwnerId")
    _wait(
        f"EBS snapshot {snapshot_id} deletion",
        lambda: "absent" if _describe_snapshot(ec2, snapshot_id, owner_id) is None else "visible",
        {"absent"},
    )


def _delete_security_group_and_wait(ec2, group_id, resource):
    ec2.delete_security_group(GroupId=str(group_id))
    _wait(
        f"security group {group_id} deletion",
        lambda: "absent" if not _group_exists(ec2, group_id) else "visible",
        {"absent"},
    )


def _delete_key_pair_and_wait(ec2, key_pair_id, resource):
    ec2.delete_key_pair(KeyPairId=str(key_pair_id))
    _wait(
        f"key pair {key_pair_id} deletion",
        lambda: (
            "absent"
            if _describe_key_pair(ec2, key_pair_id) is None
            else "visible"
        ),
        {"absent"},
    )


def _network(ec2):
    vpcs = ec2.describe_vpcs(
        Filters=[{"Name": "is-default", "Values": ["true"]}]
    ).get("Vpcs") or []
    if len(vpcs) != 1 or not vpcs[0].get("VpcId"):
        raise HarnessError("Exactly one default VPC is required for the disposable fixture.")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "default-for-az", "Values": ["true"]},
        ]
    ).get("Subnets") or []
    if not subnets:
        raise HarnessError("At least one available default subnet is required.")
    subnet = sorted(
        subnets,
        key=lambda item: (str(item.get("AvailabilityZone")), str(item.get("SubnetId"))),
    )[0]
    return vpc_id, subnet["SubnetId"], subnet["AvailabilityZone"]


def _source_ami(ec2):
    requested = str(os.environ.get("AWS_E2E_AMI_ID") or "").strip()
    if requested:
        images = ec2.describe_images(ImageIds=[requested]).get("Images") or []
        if len(images) != 1 or images[0].get("State") != "available":
            raise HarnessError("AWS_E2E_AMI_ID did not resolve to one available AMI.")
        return images[0]
    images = _paged(
        ec2.describe_images,
        "Images",
        Owners=[UBUNTU_OWNER],
        Filters=[
            {"Name": "state", "Values": ["available"]},
            {"Name": "architecture", "Values": ["x86_64"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
            {
                "Name": "name",
                "Values": ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"],
            },
        ],
    )
    if not images:
        raise HarnessError("No available Ubuntu 24.04 EBS-backed AMI was found.")
    return sorted(
        images,
        key=lambda item: (str(item.get("CreationDate")), str(item.get("ImageId"))),
        reverse=True,
    )[0]


def _ensure_ssh_key_pair(ec2, ledger, intents, prefix):
    name = f"{prefix}-ssh"
    public_key = str(os.environ.get("AWS_E2E_SSH_PUBLIC_KEY") or "").strip()
    if not public_key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
        raise HarnessError(
            "AWS_E2E_SSH_PUBLIC_KEY must contain an OpenSSH public key."
        )

    def readback(resource_id):
        key_pair = _describe_key_pair(ec2, resource_id)
        if key_pair is None:
            return None
        if key_pair.get("KeyName") != name:
            return None
        if not _owned_tags(key_pair, prefix, "ssh-key"):
            return None
        return key_pair

    def candidates():
        response = ec2.describe_key_pairs(
            Filters=[
                {"Name": f"tag:{OWNERSHIP_TAG}", "Values": [prefix]},
                {"Name": f"tag:{ROLE_TAG}", "Values": ["ssh-key"]},
            ],
        )
        rows = response.get("KeyPairs") if isinstance(response, dict) else None
        if not isinstance(rows, list):
            raise HarnessError("EC2 returned a malformed key-pair collection.")
        return rows

    try:
        exact_name = ec2.describe_key_pairs(KeyNames=[name]).get("KeyPairs") or []
    except ClientError as error:
        if not _not_found(error):
            raise
        exact_name = []
    if exact_name and not candidates():
        raise HarnessError(f"EC2 key-pair name collision for {name}.")

    return _ensure_tagged_resource(
        ec2,
        ledger,
        intents,
        prefix=prefix,
        kind="key_pair",
        role="ssh-key",
        marker=name,
        candidates=candidates,
        readback=readback,
        create=lambda: ec2.import_key_pair(
            KeyName=name,
            PublicKeyMaterial=public_key.encode("utf-8"),
            TagSpecifications=[
                {"ResourceType": "key-pair", "Tags": _tags(prefix, "ssh-key")}
            ],
        ),
        name=name,
    )


def _ensure_security_group(ec2, ledger, intents, prefix, vpc_id):
    name = f"{prefix}-webdb-sg"

    def readback(resource_id):
        try:
            groups = ec2.describe_security_groups(GroupIds=[str(resource_id)]).get(
                "SecurityGroups"
            ) or []
        except ClientError as error:
            if _not_found(error):
                return None
            raise
        if len(groups) != 1 or groups[0].get("GroupId") != str(resource_id):
            raise HarnessError("EC2 security-group ownership read-back was ambiguous.")
        group = groups[0]
        if group.get("VpcId") != vpc_id or group.get("GroupName") != name:
            return None
        if not _owned_tags(group, prefix, "security-group"):
            return None
        return group

    def candidates():
        return ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": f"tag:{OWNERSHIP_TAG}", "Values": [prefix]},
                {"Name": f"tag:{ROLE_TAG}", "Values": ["security-group"]},
            ]
        ).get("SecurityGroups") or []

    exact_name = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": [name]},
        ]
    ).get("SecurityGroups") or []
    if exact_name and not candidates():
        raise HarnessError(f"Security-group name collision for {name}.")

    return _ensure_tagged_resource(
        ec2,
        ledger,
        intents,
        prefix=prefix,
        kind="security_group",
        role="security-group",
        marker=name,
        candidates=candidates,
        readback=readback,
        create=lambda: ec2.create_security_group(
            GroupName=name,
            Description=f"Disposable BackupSheep E2E {prefix}",
            VpcId=vpc_id,
            TagSpecifications=[
                {"ResourceType": "security-group", "Tags": _tags(prefix, "security-group")}
            ],
        ),
        name=name,
    )


def _ensure_web_ingress(ec2, intents, security_group_id, prefix):
    group = ec2.describe_security_groups(GroupIds=[security_group_id])["SecurityGroups"][0]
    for permission in group.get("IpPermissions") or []:
        if (
            permission.get("IpProtocol") == "tcp"
            and permission.get("FromPort") == 80
            and permission.get("ToPort") == 80
            and any(item.get("CidrIp") == "0.0.0.0/0" for item in permission.get("IpRanges") or [])
        ):
            return
    _mutation(
        intents,
        "security_group_ingress",
        f"{prefix}:tcp-80",
        "authorize web ingress",
        lambda: ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0", "Description": "BackupSheep E2E website"}
                    ],
                }
            ],
        ),
    )
    refreshed = ec2.describe_security_groups(GroupIds=[security_group_id])["SecurityGroups"][0]
    if not any(
        permission.get("IpProtocol") == "tcp"
        and permission.get("FromPort") == 80
        and permission.get("ToPort") == 80
        and any(item.get("CidrIp") == "0.0.0.0/0" for item in permission.get("IpRanges") or [])
        for permission in refreshed.get("IpPermissions") or []
    ):
        raise AmbiguousMutation("Web ingress read-back failed.")
    intents.clear("security_group_ingress")


def _ensure_ssh_ingress(ec2, intents, security_group_id, prefix):
    configured = str(os.environ.get("AWS_E2E_SSH_CIDRS") or "").strip()
    if not configured:
        raise HarnessError(
            "AWS_E2E_SSH_CIDRS is required and must include explicit runner CIDRs."
        )
    cidrs = []
    for value in configured.split(","):
        network = ipaddress.ip_network(value.strip(), strict=False)
        if network.version != 4:
            raise HarnessError("AWS E2E SSH ingress currently requires IPv4 CIDRs.")
        cidrs.append(str(network))
    cidrs = sorted(set(cidrs))
    group = ec2.describe_security_groups(GroupIds=[security_group_id])["SecurityGroups"][0]
    observed = {
        item.get("CidrIp")
        for permission in (group.get("IpPermissions") or [])
        if permission.get("IpProtocol") == "tcp"
        and permission.get("FromPort") == 22
        and permission.get("ToPort") == 22
        for item in (permission.get("IpRanges") or [])
    }
    missing = [cidr for cidr in cidrs if cidr not in observed]
    if not missing:
        intents.clear("security_group_ssh_ingress")
        return
    _mutation(
        intents,
        "security_group_ssh_ingress",
        f"{prefix}:tcp-22:{','.join(cidrs)}",
        "authorize SSH ingress",
        lambda: ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": cidr,
                            "Description": "BackupSheep E2E SSH runner",
                        }
                        for cidr in missing
                    ],
                }
            ],
        ),
    )
    refreshed = ec2.describe_security_groups(GroupIds=[security_group_id])[
        "SecurityGroups"
    ][0]
    refreshed_cidrs = {
        item.get("CidrIp")
        for permission in (refreshed.get("IpPermissions") or [])
        if permission.get("IpProtocol") == "tcp"
        and permission.get("FromPort") == 22
        and permission.get("ToPort") == 22
        for item in (permission.get("IpRanges") or [])
    }
    if any(cidr not in refreshed_cidrs for cidr in cidrs):
        raise AmbiguousMutation("SSH ingress read-back failed.")
    intents.clear("security_group_ssh_ingress")


def _ensure_source_instance(
    ec2,
    ledger,
    intents,
    prefix,
    subnet_id,
    security_group_id,
    key_name,
    ami,
):
    name = f"{prefix}-webdb"
    role = "source-instance"

    def readback(resource_id):
        instance = _describe_instance(ec2, resource_id)
        if instance is None:
            return None
        if not _owned_tags(instance, prefix, role) or _tag_map(instance.get("Tags")).get("Name") != name:
            return None
        state = str((instance.get("State") or {}).get("Name") or "")
        if state in {"shutting-down", "terminated"}:
            raise HarnessError(f"Source instance {resource_id} is terminal: {state}.")
        return instance

    def candidates():
        return [
            item
            for item in _candidate_instances(ec2, prefix, role)
            if _tag_map(item.get("Tags")).get("Name") == name
        ]

    return _ensure_tagged_resource(
        ec2,
        ledger,
        intents,
        prefix=prefix,
        kind="source_instance",
        role=role,
        marker=name,
        candidates=candidates,
        readback=readback,
        create=lambda: (
            ec2.run_instances(
                ImageId=ami["ImageId"],
                InstanceType=INSTANCE_TYPE,
                KeyName=key_name,
                MinCount=1,
                MaxCount=1,
                UserData=_fixture_user_data(prefix),
                NetworkInterfaces=[
                    {
                        "DeviceIndex": 0,
                        "SubnetId": subnet_id,
                        "Groups": [security_group_id],
                        "AssociatePublicIpAddress": True,
                    }
                ],
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": _tags(prefix, role, Name=name),
                    },
                    {
                        "ResourceType": "volume",
                        "Tags": _tags(prefix, "source-root-volume", Parent=name),
                    },
                ],
            )["Instances"][0]
        ),
        name=name,
        source=str(ami["ImageId"]),
    )


def _ensure_volume(ec2, ledger, intents, prefix, role, name, availability_zone, source=""):
    def readback(resource_id):
        volume = _describe_volume(ec2, resource_id)
        if volume is None:
            return None
        if volume.get("AvailabilityZone") != availability_zone:
            return None
        if not _owned_tags(volume, prefix, role):
            return None
        return volume

    def candidates():
        return [
            item
            for item in _candidate_volumes(ec2, prefix, role)
            if item.get("AvailabilityZone") == availability_zone
            and _tag_map(item.get("Tags")).get("Name") == name
        ]

    return _ensure_tagged_resource(
        ec2,
        ledger,
        intents,
        prefix=prefix,
        kind=role.replace("-", "_"),
        role=role,
        marker=name,
        candidates=candidates,
        readback=readback,
        create=lambda: ec2.create_volume(
            AvailabilityZone=availability_zone,
            Size=VOLUME_SIZE_GIB,
            VolumeType="gp3",
            Encrypted=True,
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": _tags(prefix, role, Name=name),
                }
            ],
        ),
        name=name,
        source=source,
    )


def _wait_instance_running(ec2, instance_id):
    def state():
        instance = _describe_instance(ec2, instance_id)
        if instance is None:
            return "not-found"
        return str((instance.get("State") or {}).get("Name") or "unknown")

    return _wait(
        f"EC2 instance {instance_id} running",
        state,
        {"running"},
        {"terminated", "shutting-down", "not-found"},
    )


def _wait_volume_available(ec2, volume_id):
    def state():
        volume = _describe_volume(ec2, volume_id)
        return "not-found" if volume is None else str(volume.get("State") or "unknown")

    return _wait(
        f"EBS volume {volume_id} available",
        state,
        {"available", "in-use"},
        {"deleted", "error", "not-found"},
    )


def _verify_website_fixture(ec2, instance_id, prefix):
    instance = _describe_instance(ec2, instance_id) or {}
    address = instance.get("PublicIpAddress")
    if not address:
        raise HarnessError("Source instance has no public IPv4 for fixture validation.")
    expected = (f"{prefix}:website-fixture", f"{prefix}:database-fixture")
    started = time.monotonic()
    recent_error = ""
    while True:
        try:
            with urllib.request.urlopen(f"http://{address}/", timeout=10) as response:
                body = response.read(64 * 1024).decode(
                    "utf-8", errors="replace"
                )
            if all(value in body for value in expected):
                return {
                    "status": "PASS",
                    "public_ip": address,
                    "markers": list(expected),
                }
            recent_error = "fixture markers were not present"
        except (OSError, urllib.error.URLError, TimeoutError) as error:
            recent_error = _safe_error(error)
        if time.monotonic() - started > min(TIMEOUT_SECONDS, 600):
            raise HarnessError(
                "Website/database cloud-init fixture did not become ready: "
                + recent_error
            )
        time.sleep(min(POLL_SECONDS, 10))


def _tag_native_resource(ec2, intents, resource_id, key, tags, readback):
    return _ensure_tags(
        ec2,
        intents,
        resource_ids=[resource_id],
        key=key,
        tags=tags,
        readback=readback,
    )


def _run_backup_and_restore(
    *,
    ec2,
    ledger,
    intents,
    prefix,
    account_id,
    source_node,
    source_aws,
    volume_node,
    volume_aws,
    source_instance_id,
    source_volume_id,
    source_az,
    report,
):
    ami_marker = f"{prefix}-ami-backup"
    ami_backup = _backup_row(source_aws, ami_marker)
    if not ami_backup.unique_id or ami_backup.status != UtilBackup.Status.COMPLETE:
        result = source_aws.create_snapshot(ami_backup)
        if result is None:
            raise HarnessError("AMI create did not retain the durable backup lease.")
    report["tests"]["AMI backup status"] = _wait_backup(ami_backup, "AMI backup")
    ami_backup.refresh_from_db()
    ami_id = str(ami_backup.unique_id or "")
    if not ami_id:
        raise HarnessError("AMI backup completed without an AMI ID.")
    ami = _describe_image(ec2, ami_id, account_id)
    if ami is None or str(ami.get("Name")) != ami_marker:
        raise HarnessError("AMI ownership/status read-back failed.")
    ami_tags = _tag_map(ami.get("Tags"))
    if ami_tags.get("BackupSheepBackup") != ami_marker:
        raise HarnessError("AMI BackupSheep marker read-back failed.")
    _tag_native_resource(
        ec2,
        intents,
        ami_id,
        "ami_tags",
        _tags(prefix, "ami", Name=ami_marker),
        lambda: _tag_map((_describe_image(ec2, ami_id, account_id) or {}).get("Tags")),
    )
    ami = _describe_image(ec2, ami_id, account_id)
    _record(
        ledger,
        kind="ami",
        resource_id=ami_id,
        name=ami_marker,
        prefix=prefix,
        role="ami",
        source=source_instance_id,
    )
    child_snapshots = []
    for mapping in ami.get("BlockDeviceMappings") or []:
        snapshot_id = str(((mapping.get("Ebs") or {}).get("SnapshotId") or ""))
        if not snapshot_id:
            continue
        snapshot = _describe_snapshot(ec2, snapshot_id, account_id)
        if snapshot is None:
            raise HarnessError(f"AMI child snapshot {snapshot_id} was not visible.")
        _tag_native_resource(
            ec2,
            intents,
            snapshot_id,
            f"ami_child_tags_{snapshot_id}",
            _tags(prefix, "ami-child-snapshot", Parent=ami_id),
            lambda sid=snapshot_id: _tag_map((_describe_snapshot(ec2, sid, account_id) or {}).get("Tags")),
        )
        snapshot = _describe_snapshot(ec2, snapshot_id, account_id)
        if snapshot is None or not _owned_tags(snapshot, prefix, "ami-child-snapshot", parent=ami_id):
            raise HarnessError(f"AMI child snapshot {snapshot_id} ownership read-back failed.")
        _record(
            ledger,
            kind="ami_snapshot",
            resource_id=snapshot_id,
            name=ami_marker,
            prefix=prefix,
            role="ami-child-snapshot",
            source=ami_id,
            parent=ami_id,
        )
        child_snapshots.append(snapshot_id)
    report["tests"]["AMI snapshot"] = {
        "status": "PASS",
        "ami_id": ami_id,
        "child_snapshot_ids": child_snapshots,
    }

    # A second call is the live duplicate/restart assertion.  The durable row
    # already contains the provider ID, so this must remain the same AMI.
    before = ami_id
    source_aws.create_snapshot(ami_backup)
    ami_backup.refresh_from_db()
    if str(ami_backup.unique_id) != before:
        raise HarnessError("Repeated AMI backup changed the provider ID.")
    report["tests"]["AMI backup duplicate/resume"] = {"status": "PASS", "ami_id": before}

    ami_restore = _restore_row(
        source_node,
        ami_backup,
        f"{prefix}-ami-restore",
        {"instance_type": INSTANCE_TYPE},
    )
    source_aws.restore_snapshot(ami_backup, ami_restore)
    report["tests"]["AMI restore status"] = _wait_restore(ami_restore, "AMI restore")
    ami_restore.refresh_from_db()
    restored_instance_id = str(ami_restore.resource_id or "")
    if not restored_instance_id:
        raise HarnessError("AMI restore completed without an instance ID.")
    restore_marker = str(ami_restore.restore_marker)
    restored = _describe_instance(ec2, restored_instance_id)
    if restored is None or not _owned_tags(
        restored,
        prefix,
        "restore-instance",
        marker=restore_marker,
        source_id=ami_id,
    ):
        _tag_native_resource(
            ec2,
            intents,
            restored_instance_id,
            "ami_restore_tags",
            _tags(
                prefix,
                "restore-instance",
                **{RESTORE_TAG: restore_marker, SOURCE_TAG: ami_id},
            ),
            lambda: _tag_map((_describe_instance(ec2, restored_instance_id) or {}).get("Tags")),
        )
        restored = _describe_instance(ec2, restored_instance_id)
    if restored is None or not _owned_tags(
        restored,
        prefix,
        "restore-instance",
        marker=restore_marker,
        source_id=ami_id,
    ):
        raise HarnessError("AMI restore ownership read-back failed.")
    restored_root_id = _source_volume_id(restored)
    if not restored_root_id:
        raise HarnessError("AMI restore root EBS volume ID was not returned.")
    _tag_native_resource(
        ec2,
        intents,
        restored_root_id,
        "ami_restore_root_volume_tags",
        _tags(
            prefix,
            "restore-root-volume",
            Parent=restored_instance_id,
            **{RESTORE_TAG: restore_marker, SOURCE_TAG: ami_id},
        ),
        lambda: _tag_map((_describe_volume(ec2, restored_root_id) or {}).get("Tags")),
    )
    restored_root = _describe_volume(ec2, restored_root_id)
    if restored_root is None or not _owned_tags(
        restored_root,
        prefix,
        "restore-root-volume",
        marker=restore_marker,
        source_id=ami_id,
        parent=restored_instance_id,
    ):
        raise HarnessError("AMI restore root volume ownership read-back failed.")
    _record(
        ledger,
        kind="ami_restore_root_volume",
        resource_id=restored_root_id,
        name=f"{prefix}-ami-restore-root",
        prefix=prefix,
        role="restore-root-volume",
        source=restored_instance_id,
        marker=restore_marker,
        source_id=ami_id,
        parent=restored_instance_id,
    )
    _record(
        ledger,
        kind="ami_restore_instance",
        resource_id=restored_instance_id,
        name=ami_restore.name,
        prefix=prefix,
        role="restore-instance",
        source=ami_id,
        marker=restore_marker,
        source_id=ami_id,
    )
    # The row's persisted resource ID makes redelivery a read-only no-op.
    source_aws.restore_snapshot(ami_backup, ami_restore)
    ami_restore.refresh_from_db()
    if str(ami_restore.resource_id) != restored_instance_id:
        raise HarnessError("Repeated AMI restore changed the provider ID.")
    report["tests"]["AMI restore duplicate/resume"] = {
        "status": "PASS",
        "instance_id": restored_instance_id,
    }

    volume_marker = str(
        os.environ.get("AWS_E2E_EBS_BACKUP_MARKER")
        or f"{prefix}-ebs-backup"
    )
    if not volume_marker.startswith(prefix) or len(volume_marker) > 255:
        raise HarnessError(
            "AWS_E2E_EBS_BACKUP_MARKER must be run-prefixed and at most 255 characters."
        )
    volume_backup = _backup_row(volume_aws, volume_marker)
    if not volume_backup.unique_id or volume_backup.status != UtilBackup.Status.COMPLETE:
        result = volume_aws.create_snapshot(volume_backup)
        if result is None:
            raise HarnessError("EBS create did not retain the durable backup lease.")
    report["tests"]["EBS backup status"] = _wait_backup(volume_backup, "EBS snapshot backup")
    volume_backup.refresh_from_db()
    snapshot_id = str(volume_backup.unique_id or "")
    if not snapshot_id:
        raise HarnessError("EBS backup completed without a snapshot ID.")
    snapshot = _describe_snapshot(ec2, snapshot_id, account_id)
    if snapshot is None or str(snapshot.get("Description")) != volume_marker:
        raise HarnessError("EBS snapshot ownership/status read-back failed.")
    _tag_native_resource(
        ec2,
        intents,
        snapshot_id,
        "ebs_snapshot_tags",
        _tags(prefix, "ebs-snapshot", Source=source_volume_id),
        lambda: _tag_map((_describe_snapshot(ec2, snapshot_id, account_id) or {}).get("Tags")),
    )
    snapshot = _describe_snapshot(ec2, snapshot_id, account_id)
    if snapshot is None or not _owned_tags(snapshot, prefix, "ebs-snapshot", source_id=source_volume_id):
        raise HarnessError("EBS snapshot tag ownership read-back failed.")
    _record(
        ledger,
        kind="ebs_snapshot",
        resource_id=snapshot_id,
        name=volume_marker,
        prefix=prefix,
        role="ebs-snapshot",
        source=source_volume_id,
        source_id=source_volume_id,
    )
    report["tests"]["EBS snapshot"] = {"status": "PASS", "snapshot_id": snapshot_id}

    volume_backup_before = snapshot_id
    volume_aws.create_snapshot(volume_backup)
    volume_backup.refresh_from_db()
    if str(volume_backup.unique_id) != volume_backup_before:
        raise HarnessError("Repeated EBS backup changed the provider ID.")
    report["tests"]["EBS backup duplicate/resume"] = {
        "status": "PASS",
        "snapshot_id": volume_backup_before,
    }

    volume_restore = _restore_row(
        volume_node,
        volume_backup,
        f"{prefix}-ebs-restore",
        {"availability_zone": source_az},
    )
    volume_aws.restore_snapshot(volume_backup, volume_restore)
    report["tests"]["EBS restore status"] = _wait_restore(volume_restore, "EBS volume restore")
    volume_restore.refresh_from_db()
    restored_volume_id = str(volume_restore.resource_id or "")
    if not restored_volume_id:
        raise HarnessError("EBS restore completed without a volume ID.")
    volume_restore_marker = str(volume_restore.restore_marker)
    restored_volume = _describe_volume(ec2, restored_volume_id)
    if restored_volume is None or not _owned_tags(
        restored_volume,
        prefix,
        "restore-volume",
        marker=volume_restore_marker,
        source_id=snapshot_id,
    ):
        _tag_native_resource(
            ec2,
            intents,
            restored_volume_id,
            "ebs_restore_tags",
            _tags(
                prefix,
                "restore-volume",
                **{RESTORE_TAG: volume_restore_marker, SOURCE_TAG: snapshot_id},
            ),
            lambda: _tag_map((_describe_volume(ec2, restored_volume_id) or {}).get("Tags")),
        )
        restored_volume = _describe_volume(ec2, restored_volume_id)
    if restored_volume is None or not _owned_tags(
        restored_volume,
        prefix,
        "restore-volume",
        marker=volume_restore_marker,
        source_id=snapshot_id,
    ):
        raise HarnessError("EBS restore ownership read-back failed.")
    _record(
        ledger,
        kind="ebs_restore_volume",
        resource_id=restored_volume_id,
        name=volume_restore.name,
        prefix=prefix,
        role="restore-volume",
        source=snapshot_id,
        marker=volume_restore_marker,
        source_id=snapshot_id,
    )
    volume_aws.restore_snapshot(volume_backup, volume_restore)
    volume_restore.refresh_from_db()
    if str(volume_restore.resource_id) != restored_volume_id:
        raise HarnessError("Repeated EBS restore changed the provider ID.")
    report["tests"]["EBS restore duplicate/resume"] = {
        "status": "PASS",
        "volume_id": restored_volume_id,
    }


def _cleanup_resource(ledger, kind, resource_id, readback, owns, delete, report):
    if not ledger.cleanup_eligible(kind, resource_id):
        return
    entry = ledger.get(kind, resource_id)
    if entry is None:
        return
    try:
        resource = readback(resource_id)
        if resource is None:
            ledger.mark_cleanup(kind, resource_id, state="absent")
            report.append({"kind": kind, "resource_id": resource_id, "state": "absent"})
            return
        if not owns(resource, entry):
            ledger.mark_cleanup(kind, resource_id, state="manual_review", error="ownership mismatch")
            report.append({"kind": kind, "resource_id": resource_id, "state": "manual_review", "error": "ownership mismatch"})
            return
        delete(resource_id, resource)
        remaining = readback(resource_id)
        if remaining is not None and not (
            kind.endswith("instance")
            and str((remaining.get("State") or {}).get("Name") or "") == "terminated"
        ):
            raise AmbiguousMutation(f"{kind} {resource_id} remained visible after delete.")
        ledger.mark_cleanup(kind, resource_id, state="deleted")
        report.append({"kind": kind, "resource_id": resource_id, "state": "deleted"})
    except ClientError as error:
        if _not_found(error):
            ledger.mark_cleanup(kind, resource_id, state="absent")
            report.append({"kind": kind, "resource_id": resource_id, "state": "absent"})
        else:
            message = f"ambiguous cleanup outcome: {_safe_error(error)}"
            ledger.mark_cleanup(kind, resource_id, state="manual_review", error=message)
            report.append({"kind": kind, "resource_id": resource_id, "state": "manual_review", "error": message})
    except Exception as error:
        remaining = None
        try:
            remaining = readback(resource_id)
        except Exception:
            remaining = None
        if remaining is None or (
            kind.endswith("instance")
            and str((remaining.get("State") or {}).get("Name") or "") == "terminated"
        ):
            ledger.mark_cleanup(kind, resource_id, state="absent")
            report.append({"kind": kind, "resource_id": resource_id, "state": "absent"})
            return
        message = f"ambiguous cleanup outcome: {_safe_error(error)}"
        ledger.mark_cleanup(kind, resource_id, state="manual_review", error=message)
        report.append({"kind": kind, "resource_id": resource_id, "state": "manual_review", "error": message})


def _has_ledgered_root_volume(ledger, instance_kind, instance_id):
    root_kind = (
        "ami_restore_root_volume"
        if instance_kind == "ami_restore_instance"
        else "source_root_volume"
    )
    return any(
        str(entry.get("source_witness") or "") == str(instance_id)
        for entry in ledger.entries(root_kind)
    )


def _cleanup(ec2, ledger, intents, prefix, account_id):
    results = []
    # Restores and their child volumes leave the account first.
    for kind in ("ami_restore_instance", "ebs_restore_volume", "source_instance"):
        for entry in ledger.entries(kind):
            resource_id = str(entry.get("resource_id") or "")
            if kind.endswith("instance") and not _has_ledgered_root_volume(
                ledger, kind, resource_id
            ):
                ledger.mark_cleanup(
                    kind,
                    resource_id,
                    state="manual_review",
                    error="refusing instance cleanup without a ledgered root volume",
                )
                results.append(
                    {
                        "kind": kind,
                        "resource_id": resource_id,
                        "state": "manual_review",
                        "error": "refusing instance cleanup without a ledgered root volume",
                    }
                )
                continue
            if kind.endswith("instance"):
                readback = lambda rid: _describe_instance(ec2, rid)
            else:
                readback = lambda rid: _describe_volume(ec2, rid)
            _cleanup_resource(
                ledger,
                kind,
                resource_id,
                readback,
                lambda resource, row: _entry_matches(resource, row),
                lambda rid, resource: (
                    _terminate_instance_and_wait(ec2, rid, resource)
                    if kind.endswith("instance")
                    else _delete_volume_and_wait(ec2, rid, resource)
                ),
                results,
            )

    # Standalone/root volumes can be removed only from the exact ledger.
    for kind in (
        "ami_restore_root_volume",
        "source_root_volume",
        "source_data_volume",
    ):
        for entry in ledger.entries(kind):
            resource_id = str(entry.get("resource_id") or "")
            _cleanup_resource(
                ledger,
                kind,
                resource_id,
                lambda rid: _describe_volume(ec2, rid),
                lambda resource, row: _entry_matches(resource, row),
                lambda rid, resource: _delete_volume_and_wait(ec2, rid, resource),
                results,
            )

    # Deregister the AMI before its exact, ledgered child snapshots.
    for entry in ledger.entries("ami"):
        resource_id = str(entry.get("resource_id") or "")
        _cleanup_resource(
            ledger,
            "ami",
            resource_id,
            lambda rid: _describe_image(ec2, rid, account_id),
            lambda resource, row: _entry_matches(resource, row),
            lambda rid, resource: _deregister_image_and_wait(ec2, rid, resource),
            results,
        )
    for kind in ("ami_snapshot", "ebs_snapshot"):
        for entry in ledger.entries(kind):
            resource_id = str(entry.get("resource_id") or "")
            _cleanup_resource(
                ledger,
                kind,
                resource_id,
                lambda rid: _describe_snapshot(ec2, rid, account_id),
                lambda resource, row: _entry_matches(resource, row),
                lambda rid, resource: _delete_snapshot_and_wait(ec2, rid, resource),
                results,
            )
    for entry in ledger.entries("security_group"):
        resource_id = str(entry.get("resource_id") or "")

        def group_readback(rid):
            try:
                groups = ec2.describe_security_groups(GroupIds=[rid]).get("SecurityGroups") or []
            except ClientError as error:
                if _not_found(error):
                    return None
                raise
            return groups[0] if len(groups) == 1 else None

        _cleanup_resource(
            ledger,
            "security_group",
            resource_id,
            group_readback,
            lambda resource, row: _entry_matches(resource, row),
            lambda rid, resource: _delete_security_group_and_wait(ec2, rid, resource),
            results,
        )
    for entry in ledger.entries("key_pair"):
        resource_id = str(entry.get("resource_id") or "")
        _cleanup_resource(
            ledger,
            "key_pair",
            resource_id,
            lambda rid: _describe_key_pair(ec2, rid),
            lambda resource, row: _entry_matches(resource, row),
            lambda rid, resource: _delete_key_pair_and_wait(
                ec2, rid, resource
            ),
            results,
        )
    if not any(item.get("state") == "manual_review" for item in results):
        intents.clear_all()
    return results


def _cleanup_local_graph(prefix):
    """Delete only the exact provider-specific local fixture graph."""
    email = f"{prefix}-aws-ec2@example.invalid"
    users = list(
        get_user_model().objects.filter(username=email, email=email)[:2]
    )
    if not users:
        return {"kind": "local_graph", "state": "absent"}
    if len(users) != 1:
        raise HarnessError("Multiple exact AWS EC2 E2E users were found.")
    user = users[0]
    try:
        member = user.member
    except Exception as error:
        raise HarnessError("The exact AWS EC2 E2E user has no member graph.") from error
    memberships = list(member.memberships.select_related("account")[:2])
    if len(memberships) != 1:
        raise HarnessError(
            "The exact AWS EC2 E2E user does not own exactly one account."
        )
    account = memberships[0].account
    if account.name != f"BackupSheep AWS EC2 E2E {prefix}":
        raise HarnessError("The AWS EC2 E2E local account ownership name mismatched.")
    connections = list(account.connections.select_related("integration"))
    if any(
        connection.name != f"BackupSheep E2E AWS {prefix}"
        or connection.integration.code != "aws"
        for connection in connections
    ):
        raise HarnessError(
            "The AWS EC2 E2E local account contains an unrelated connection."
        )
    account_id = account.id
    user_id = user.id
    account.delete()
    user.delete()
    return {
        "kind": "local_graph",
        "state": "deleted",
        "account_id": account_id,
        "user_id": user_id,
    }


def _preflight(ec2, account_id, prefix, report):
    vpc_id, subnet_id, availability_zone = _network(ec2)
    ami = _source_ami(ec2)
    report["preflight"] = {
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "availability_zone": availability_zone,
        "source_ami_id": ami.get("ImageId"),
        "source_ami_owner": ami.get("OwnerId"),
    }
    return vpc_id, subnet_id, availability_zone, ami


def main():
    report = {"region": REGION, "tests": {}, "cleanup": []}
    ledger = None
    intents = None
    try:
        prefix = require_run_id(os.environ.get("BACKUPSHEEP_E2E_RUN_ID"))
        ledger_path = os.environ.get("BACKUPSHEEP_E2E_LEDGER_PATH")
        if not ledger_path:
            raise LedgerError("BACKUPSHEEP_E2E_LEDGER_PATH is required.")
        if CLEANUP and not APPLY:
            raise HarnessError(
                "Cleanup is a write and requires BACKUPSHEEP_E2E_APPLY=YES plus BACKUPSHEEP_E2E_CLEANUP=YES."
            )
        if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get("AWS_SECRET_ACCESS_KEY"):
            raise HarnessError("AWS credentials must be supplied through the process environment.")

        sts = boto3.client("sts", region_name=REGION, config=AWS_CONFIG)
        identity = sts.get_caller_identity()
        account_id = str(identity.get("Account") or "")
        if not account_id.isdigit() or len(account_id) != 12:
            raise HarnessError("AWS caller identity did not return a valid account ID.")
        report.update({"run_id": prefix, "account": account_id, "caller": str(identity.get("Arn") or "").split("/")[-1]})
        ledger = DurableResourceLedger(
            ledger_path,
            provider="aws",
            run_id=prefix,
            scope=f"{account_id}:{REGION}",
        )
        intents = MutationIntentStore(
            ledger_path,
            run_id=prefix,
            scope=f"{account_id}:{REGION}",
        )
        report["ledger_path"] = str(ledger.path)
        ec2 = boto3.client("ec2", region_name=REGION, config=AWS_CONFIG)

        if not APPLY:
            _preflight(ec2, account_id, prefix, report)
            report["status"] = "PREFLIGHT_PASS"
            report["mode"] = "read_only"
            return 0, report

        if CLEANUP:
            report["cleanup"] = _cleanup(ec2, ledger, intents, prefix, account_id)
            if not any(
                item.get("state") == "manual_review"
                for item in report["cleanup"]
            ):
                report["cleanup"].append(_cleanup_local_graph(prefix))
            report["status"] = (
                "CLEANUP_PASS"
                if not any(item.get("state") == "manual_review" for item in report["cleanup"])
                else "CLEANUP_MANUAL_REVIEW"
            )
            return 0 if report["status"] == "CLEANUP_PASS" else 2, report

        vpc_id, subnet_id, availability_zone, ami = _preflight(
            ec2, account_id, prefix, report
        )
        security_group_id, _security_group = _ensure_security_group(
            ec2, ledger, intents, prefix, vpc_id
        )
        _ensure_web_ingress(ec2, intents, security_group_id, prefix)
        _ensure_ssh_ingress(ec2, intents, security_group_id, prefix)
        key_pair_id, key_pair = _ensure_ssh_key_pair(
            ec2, ledger, intents, prefix
        )
        key_name = str(key_pair.get("KeyName") or "")
        if not key_name:
            raise HarnessError("The imported AWS SSH key has no key name.")
        report["resources"] = {
            "security_group_id": security_group_id,
            "key_pair_id": key_pair_id,
            "key_name": key_name,
        }

        source_instance_id, source_instance = _ensure_source_instance(
            ec2,
            ledger,
            intents,
            prefix,
            subnet_id,
            security_group_id,
            key_name,
            ami,
        )
        _wait_instance_running(ec2, source_instance_id)
        source_instance = _describe_instance(ec2, source_instance_id)
        if source_instance is None:
            raise HarnessError("Source instance disappeared after becoming running.")
        root_volume_id = _source_volume_id(source_instance)
        if not root_volume_id:
            raise HarnessError("Source instance root EBS volume ID was not returned.")
        root_volume = _describe_volume(ec2, root_volume_id)
        if root_volume is None:
            raise HarnessError("Source root EBS volume was not returned.")
        _tag_native_resource(
            ec2,
            intents,
            root_volume_id,
            "source_root_volume_tags",
            _tags(prefix, "source-root-volume", Parent=source_instance_id),
            lambda: _tag_map((_describe_volume(ec2, root_volume_id) or {}).get("Tags")),
        )
        root_volume = _describe_volume(ec2, root_volume_id)
        if root_volume is None or not _owned_tags(
            root_volume, prefix, "source-root-volume", parent=source_instance_id
        ):
            raise HarnessError("Source root volume ownership read-back failed.")
        _record(
            ledger,
            kind="source_root_volume",
            resource_id=root_volume_id,
            name=f"{prefix}-source-root",
            prefix=prefix,
            role="source-root-volume",
            source=source_instance_id,
            parent=source_instance_id,
        )
        source_az = str((source_instance.get("Placement") or {}).get("AvailabilityZone") or availability_zone)
        source_volume_id, source_volume = _ensure_volume(
            ec2,
            ledger,
            intents,
            prefix,
            "source-data-volume",
            f"{prefix}-data",
            source_az,
            source=source_instance_id,
        )
        _wait_volume_available(ec2, source_volume_id)
        source_volume = _describe_volume(ec2, source_volume_id)
        if source_volume is None:
            raise HarnessError("Source data volume disappeared after creation.")

        # Record the instance only after its exact tags/read-back and root-volume
        # identity are known.  The instance ledger entry is used for cleanup.
        source_instance = _describe_instance(ec2, source_instance_id)
        if source_instance is None or not _owned_tags(source_instance, prefix, "source-instance"):
            raise HarnessError("Source instance ownership read-back failed.")
        report["resources"].update(
            {
                "source_instance_id": source_instance_id,
                "source_root_volume_id": root_volume_id,
                "source_data_volume_id": source_volume_id,
            }
        )
        report["tests"]["cloud-init website/database fixture"] = _verify_website_fixture(
            ec2, source_instance_id, prefix
        )

        (
            account,
            member,
            source_node,
            source_aws,
            volume_node,
            volume_aws,
        ) = _get_or_create_graph(
            prefix,
            REGION,
            os.environ["AWS_ACCESS_KEY_ID"],
            os.environ["AWS_SECRET_ACCESS_KEY"],
            source_instance_id,
            source_volume_id,
        )
        _run_backup_and_restore(
            ec2=ec2,
            ledger=ledger,
            intents=intents,
            prefix=prefix,
            account_id=account_id,
            source_node=source_node,
            source_aws=source_aws,
            volume_node=volume_node,
            volume_aws=volume_aws,
            source_instance_id=source_instance_id,
            source_volume_id=source_volume_id,
            source_az=source_az,
            report=report,
        )
        report["status"] = "PASS"
        return 0, report
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = _safe_error(error)
        traceback.print_exc()
        return 1, report


if __name__ == "__main__":
    exit_code, output = main()
    print(json.dumps(output, indent=2, sort_keys=True, default=str))
    sys.exit(exit_code)
