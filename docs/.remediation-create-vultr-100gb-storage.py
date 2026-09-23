import json

from botocore.client import Config
from django.db import transaction

from apps.api.v1.utils.api_helpers import bs_decrypt
from apps.api.v1.utils.boto import bounded_boto3_client
from apps.console.storage.models import CoreStorage, CoreStorageVultr


RUN_ID = "bs-remed-20260818-0d08dcf"
SOURCE_STORAGE_ID = 1
BUCKET = "bs-remed-0d08dcf-100gb-20260819"
PREFIX = f"{RUN_ID}/100gb"
MARKER_KEY = f"{PREFIX}/ownership.json"
STORAGE_NAME = f"{RUN_ID} Vultr 100GB multipart"
PURPOSE = "website-database-remediation-100gb-multipart"


source = CoreStorage.objects.select_related("account", "type", "added_by").get(
    pk=SOURCE_STORAGE_ID,
    status=CoreStorage.Status.ACTIVE,
)
provider = source.storage_vultr
encryption_key = source.account.get_encryption_key()
access_key = bs_decrypt(provider.access_key, encryption_key)
secret_key = bs_decrypt(provider.secret_key, encryption_key)
client = bounded_boto3_client(
    "s3",
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    endpoint_url=f"https://{provider.endpoint}",
    config=Config(
        request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
    ),
)

inventory = client.list_buckets()
bucket_names = {
    str(item.get("Name") or "") for item in inventory.get("Buckets", [])
}
created_bucket = BUCKET not in bucket_names
marker_payload = json.dumps(
    {
        "run_id": RUN_ID,
        "purpose": PURPOSE,
        "bucket": BUCKET,
        "prefix": PREFIX,
    },
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")

if created_bucket:
    response = client.create_bucket(Bucket=BUCKET)
    if int(response.get("ResponseMetadata", {}).get("HTTPStatusCode") or 0) not in {
        200,
        204,
    }:
        raise RuntimeError("Vultr bucket creation did not return a definitive success")
    client.put_object(
        Bucket=BUCKET,
        Key=MARKER_KEY,
        Body=marker_payload,
        ContentType="application/json",
        Metadata={"run-id": RUN_ID, "purpose": PURPOSE},
    )
else:
    response = client.get_object(Bucket=BUCKET, Key=MARKER_KEY)
    body = response["Body"].read(4097)
    response["Body"].close()
    if len(body) > 4096 or body != marker_payload:
        raise RuntimeError(
            "Refusing to adopt an existing bucket without the exact ownership marker"
        )

marker = client.head_object(Bucket=BUCKET, Key=MARKER_KEY)
if int(marker.get("ContentLength") or 0) != len(marker_payload):
    raise RuntimeError("The Vultr ownership marker length does not match")
if marker.get("Metadata", {}).get("run-id") != RUN_ID:
    raise RuntimeError("The Vultr ownership marker metadata does not match")

with transaction.atomic():
    storage = (
        CoreStorage.objects.select_for_update()
        .filter(account=source.account, name=STORAGE_NAME)
        .first()
    )
    created_storage = storage is None
    if created_storage:
        storage = CoreStorage.objects.create(
            account=source.account,
            status=CoreStorage.Status.ACTIVE,
            type=source.type,
            name=STORAGE_NAME,
            added_by=source.added_by,
            is_air_gapped=False,
            storage_cost_usd_per_gib_month=source.storage_cost_usd_per_gib_month,
            cold_storage_cost_usd_per_gib_month=(
                source.cold_storage_cost_usd_per_gib_month
            ),
            retrieval_cost_usd_per_gib=source.retrieval_cost_usd_per_gib,
        )
        CoreStorageVultr.objects.create(
            storage=storage,
            secret_key=provider.secret_key,
            access_key=provider.access_key,
            bucket_name=BUCKET,
            prefix=PREFIX,
            endpoint=provider.endpoint,
            no_delete=True,
            encryption_updated=provider.encryption_updated,
        )

    storage.refresh_from_db()
    stored_provider = storage.storage_vultr
    expected = {
        "account_id": source.account_id,
        "type_id": source.type_id,
        "status": CoreStorage.Status.ACTIVE,
        "bucket_name": BUCKET,
        "prefix": PREFIX,
        "endpoint": provider.endpoint,
        "no_delete": True,
    }
    actual = {
        "account_id": storage.account_id,
        "type_id": storage.type_id,
        "status": storage.status,
        "bucket_name": stored_provider.bucket_name,
        "prefix": stored_provider.prefix,
        "endpoint": stored_provider.endpoint,
        "no_delete": stored_provider.no_delete,
    }
    if actual != expected:
        raise RuntimeError(
            f"Refusing mismatched Vultr storage row: expected={expected!r} "
            f"actual={actual!r}"
        )

print(
    {
        "bucket_created": created_bucket,
        "storage_created": created_storage,
        "storage_id": storage.pk,
        "bucket": BUCKET,
        "prefix": PREFIX,
        "endpoint": provider.endpoint,
        "marker_key": MARKER_KEY,
        "marker_bytes": len(marker_payload),
    }
)
