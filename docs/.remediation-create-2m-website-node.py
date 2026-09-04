"""Create the exact-owned BackupSheep website node for the 2M fixture."""

import json

from django.db import transaction

from apps.console.node.models import CoreNode, CoreWebsite


RUN_ID = "bs-remed-20260818-0d08dcf"
NAME = f"{RUN_ID} Website 2M files"
SOURCE_PATH = (
    "/mnt/bs-remed-scale-0d08dcf/bs-remed-20260818-0d08dcf/website-2m/source"
)


with transaction.atomic():
    retained = CoreNode.objects.select_related("connection", "added_by").get(pk=101)
    if retained.connection_id != 60 or retained.type != CoreNode.Type.WEBSITE:
        raise RuntimeError("the retained SFTP fixture identity changed")
    node = CoreNode.objects.filter(name=NAME, connection_id=60).first()
    if node is None:
        node = CoreNode.objects.create(
            connection=retained.connection,
            status=CoreNode.Status.ACTIVE,
            type=CoreNode.Type.WEBSITE,
            name=NAME,
            notify_on_success=True,
            notify_on_fail=True,
            timezone="UTC",
            added_by=retained.added_by,
        )
        website = CoreWebsite.objects.create(
            node=node,
            name=NAME,
            backup_type=1,
            incremental=False,
            parallel=3,
            paths=[{"name": SOURCE_PATH, "path": SOURCE_PATH, "type": "directory"}],
            excludes=[],
            excludes_glob=[],
            excludes_regex=[],
            includes_glob=[],
            includes_regex=[],
            verbose=False,
        )
    else:
        website = node.website
        if website.paths != [
            {"name": SOURCE_PATH, "path": SOURCE_PATH, "type": "directory"}
        ]:
            raise RuntimeError("the existing exact-owned node path changed")

node.connection.validate()
print(
    json.dumps(
        {
            "run_id": RUN_ID,
            "result": "exact-owned website scale node is ready",
            "connection_validation": "passed",
        },
        sort_keys=True,
    )
)
