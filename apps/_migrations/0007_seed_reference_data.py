"""Seed the reference data a fresh install needs to be usable.

On a clean deploy only `migrate` runs (no db.sql/loaddata), which previously left the
catalog tables empty -- so the setup UI could list neither backup sources nor storage
destinations. This migration populates them from apps/_migrations/seed_data/reference_data.json:

  - core_integration   : the 20 backup sources (DigitalOcean, AWS, Hetzner, Website, ...)
  - core_storage_type  : the 25 supported storage providers (slim BYO catalog; the SaaS
                         managed-vs-BYO "bs" tier is intentionally not seeded)
  - lookup tables      : per-provider backup statuses, server status/type, backup type,
                         connection status, pg_dump options and util_setting -- the
                         backup code .get(code=...)'s these at runtime, so a fresh
                         install crashes without them
  - core_connection_location : one self-hosted "local" location linked to every
                         integration (connection serializers require a location and the
                         endpoint APIs filter locations by integration)
  - region tables      : S3-style provider regions (AWS, Lightsail, DO Spaces, Oracle, ...)

Idempotent (get_or_create by the unique `code`), so re-running never duplicates or
clobbers operator edits.
"""
import json
import os

from django.db import migrations

SEED_FILE = os.path.join(os.path.dirname(__file__), "seed_data", "reference_data.json")


def _load():
    with open(SEED_FILE, encoding="utf-8") as fh:
        return json.load(fh)


def seed_reference_data(apps, schema_editor):
    data = _load()

    CoreIntegration = apps.get_model("apps", "CoreIntegration")
    for row in data["integrations"]:
        CoreIntegration.objects.get_or_create(
            code=row["code"], defaults={k: v for k, v in row.items() if k != "code"}
        )

    CoreStorageType = apps.get_model("apps", "CoreStorageType")
    for row in data["storage_types"]:
        CoreStorageType.objects.get_or_create(
            code=row["code"], defaults={k: v for k, v in row.items() if k != "code"}
        )

    for model_name, table in data["lookups"].items():
        Model = apps.get_model("apps", model_name)
        for row in table["rows"]:
            Model.objects.get_or_create(
                **{field: row[field] for field in table["lookup"]},
                defaults={k: v for k, v in row.items() if k not in table["lookup"]},
            )

    CoreConnectionLocation = apps.get_model("apps", "CoreConnectionLocation")
    CoreConnectionLocationIntegration = apps.get_model(
        "apps", "CoreConnectionLocationIntegration"
    )
    for row in data["connection_locations"]:
        location, _ = CoreConnectionLocation.objects.get_or_create(
            code=row["code"], defaults={k: v for k, v in row.items() if k != "code"}
        )
        for integration in CoreIntegration.objects.all():
            CoreConnectionLocationIntegration.objects.get_or_create(
                location=location, integration=integration
            )

    for model_name, rows in data["regions"].items():
        Model = apps.get_model("apps", model_name)
        for row in rows:
            Model.objects.get_or_create(
                code=row["code"], defaults={k: v for k, v in row.items() if k != "code"}
            )


class Migration(migrations.Migration):

    dependencies = [
        ("apps", "0006_alter_coreauthdatabase_version"),
    ]

    operations = [
        # Reverse is a no-op: reference data is shared catalog, not user data, and region
        # rows are PROTECT-referenced by storage configs once created.
        migrations.RunPython(seed_reference_data, migrations.RunPython.noop),
    ]
