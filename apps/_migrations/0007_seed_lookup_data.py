# Hand-written data migration: seed all lookup/reference data so a fresh
# install is fully usable after `manage.py migrate` alone.
#
# Rows come from the SaaS-era pg_dump (db.sql), see seed_lookup_data.py.
# Empty-in-dump tables (core_alibab_region, core_wasabi_region, util_country,
# util_mysql_options, util_mariadb_options) are intentionally not seeded.
# Everything is idempotent (get_or_create on unique keys) so it also applies
# cleanly on databases that were already seeded by hand.

from django.db import migrations
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from . import _seed_lookup_data as seed_lookup_data

# Not present in the dump; defined here. (code, name) in display order.
STORAGE_TYPES = [
    ("aws_s3", "AWS S3", "console/images/storage/amazon-s3.svg"),
    ("alibaba", "Alibaba Cloud OSS", "console/images/storage/alibaba.svg"),
    ("azure", "Azure Blob Storage", "console/images/storage/azure.svg"),
    ("backblaze_b2", "Backblaze B2", "console/images/storage/backblaze.svg"),
    ("cloudflare", "Cloudflare R2", "console/images/storage/cloudflare.svg"),
    ("do_spaces", "DigitalOcean Spaces", "console/images/storage/digitalocean.svg"),
    ("dropbox", "Dropbox", "console/images/storage/dropbox.svg"),
    ("exoscale", "Exoscale SOS", "console/images/storage/exoscale.svg"),
    ("filebase", "Filebase", "console/images/storage/filebase.svg"),
    ("google_cloud", "Google Cloud Storage", "console/images/storage/google_cloud.svg"),
    ("google_drive", "Google Drive", "console/images/storage/google_drive.svg"),
    ("ibm", "IBM Cloud Object Storage", "console/images/storage/ibm.svg"),
    ("idrive", "IDrive e2", "console/images/storage/idrive.svg"),
    ("ionos", "IONOS S3", "console/images/storage/ionos.svg"),
    ("leviia", "Leviia", "console/images/storage/leviia.svg"),
    ("linode", "Linode Object Storage", "console/images/storage/linode.svg"),
    ("onedrive", "OneDrive", "console/images/storage/onedrive.svg"),
    ("oracle", "Oracle Cloud Storage", "console/images/storage/oracle.svg"),
    ("pcloud", "pCloud", "console/images/storage/pcloud.svg"),
    ("rackcorp", "RackCorp", "console/images/storage/rackcorp.svg"),
    ("scaleway", "Scaleway Object Storage", "console/images/storage/scaleway.svg"),
    ("tencent", "Tencent COS", "console/images/storage/tencent.svg"),
    ("upcloud", "UpCloud Object Storage", "console/images/storage/upcloud.svg"),
    ("vultr", "Vultr Object Storage", "console/images/storage/vultr.svg"),
    ("wasabi", "Wasabi", "console/images/storage/wasabi.svg"),
]


def seed_lookup_data_forwards(apps, schema_editor):
    now = timezone.now()

    for model_name, (lookup_fields, rows) in seed_lookup_data.SEED_TABLES.items():
        model = apps.get_model("apps", model_name)
        for row in rows:
            lookup = {}
            defaults = {}
            for field, value in row.items():
                if field in ("created", "modified"):
                    value = parse_datetime(value)
                if field in lookup_fields:
                    lookup[field] = value
                else:
                    defaults[field] = value
            model.objects.get_or_create(defaults=defaults, **lookup)

    core_storage_type = apps.get_model("apps", "CoreStorageType")
    for position, (code, name, image) in enumerate(STORAGE_TYPES, start=1):
        core_storage_type.objects.get_or_create(
            code=code,
            defaults={"name": name, "is_enabled": True, "position": position, "image": image},
        )

    # Single self-hosted location instead of the dead SaaS worker nodes.
    core_connection_location = apps.get_model("apps", "CoreConnectionLocation")
    location, _ = core_connection_location.objects.get_or_create(
        code="local",
        defaults={
            "name": "Local",
            "location": "Self-hosted",
            "queue": "celery",
            "task_list": seed_lookup_data.LOCAL_LOCATION_TASK_LIST,
        },
    )

    # The wizard endpoints APIs filter locations by integration code, so link
    # the local location to every integration.
    core_integration = apps.get_model("apps", "CoreIntegration")
    core_connection_location_integration = apps.get_model(
        "apps", "CoreConnectionLocationIntegration"
    )
    for integration in core_integration.objects.all():
        core_connection_location_integration.objects.get_or_create(
            location=location,
            integration=integration,
            defaults={"created": now, "modified": now},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("apps", "0006_alter_coreauthdatabase_version"),
    ]

    operations = [
        migrations.RunPython(seed_lookup_data_forwards, migrations.RunPython.noop),
    ]
