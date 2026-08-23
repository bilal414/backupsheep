"""Create the exact-owned synthetic website backup row for the 100 GB upload gate."""

import json

from django.db import transaction

from apps.console.backup.models import (
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
)
from apps.console.node.models import CoreWebsite
from apps.console.storage.models import CoreStorage
from apps.console.utils.models import UtilBackup


RUN_ID = "bs-remed-20260818-0d08dcf"
PURPOSE = "100 GB multipart upload and crash-resume acceptance"
ARCHIVE_BYTES = 107_421_554_763
MEMBER_BYTES = 107_421_554_467
WEBSITE_ID = 24
STORAGE_ID = 11


with transaction.atomic():
    website = CoreWebsite.objects.select_related("node").get(pk=WEBSITE_ID)
    storage = CoreStorage.objects.select_related("type").get(pk=STORAGE_ID)
    if website.node_id != 101 or website.node.type != website.node.Type.WEBSITE:
        raise RuntimeError("the retained website fixture identity changed")
    if storage.name != f"{RUN_ID} Vultr 100GB multipart":
        raise RuntimeError("the exact-owned 100 GB storage identity changed")
    if storage.type.code != "vultr":
        raise RuntimeError("the exact-owned storage is not Vultr Object Storage")

    backup = CoreWebsiteBackup.objects.filter(
        website=website,
        metadata__remediation_run_id=RUN_ID,
        metadata__remediation_purpose=PURPOSE,
    ).first()
    created = backup is None
    if backup is None:
        backup = CoreWebsiteBackup.objects.create(
            website=website,
            uuid=f"{RUN_ID}-100gb-pending",
            name=f"{RUN_ID} 100 GB multipart acceptance",
            status=UtilBackup.Status.UPLOAD_READY,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            size=ARCHIVE_BYTES,
            zip_size=ARCHIVE_BYTES,
            raw_size=MEMBER_BYTES,
            total_files=1,
            total_folders=0,
            total_files_n_folders_calculated=True,
            all_paths=True,
            metadata={
                "schema": 1,
                "remediation_run_id": RUN_ID,
                "remediation_purpose": PURPOSE,
                "synthetic_scale_fixture": True,
                "archive_bytes": ARCHIVE_BYTES,
                "member_bytes": MEMBER_BYTES,
                "member_crc32": "7d0c1b6a",
                "provider_bucket": "bs-remed-0d08dcf-100gb-20260819",
                "provider_prefix": f"{RUN_ID}/100gb",
            },
        )
        backup.uuid = f"bs-{RUN_ID}-n{website.node_id}-b{backup.pk}-100gb"
        backup.save(update_fields=["uuid", "modified"])

    point, point_created = CoreWebsiteBackupStoragePoints.objects.get_or_create(
        backup=backup,
        storage=storage,
        defaults={"status": CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY},
    )
    if not point_created and point.status not in {
        CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY,
        CoreWebsiteBackupStoragePoints.Status.UPLOAD_RETRY,
        CoreWebsiteBackupStoragePoints.Status.UPLOAD_IN_PROGRESS,
        CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
    }:
        raise RuntimeError("the existing exact-owned point has an unexpected status")

print(
    json.dumps(
        {
            "created": created,
            "backup_id": backup.pk,
            "backup_uuid": backup.uuid_str,
            "backup_status": backup.get_status_display(),
            "point_id": point.pk,
            "point_status": point.get_status_display(),
            "node_id": website.node_id,
            "storage_id": storage.pk,
            "storage_name": storage.name,
            "archive_bytes": backup.size,
        },
        sort_keys=True,
    )
)
