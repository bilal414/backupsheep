from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("apps", "0046_core_managed_ssh_operation")]

    operations = [
        migrations.AlterModelOptions(
            name="coreaccountgroup",
            options={
                "db_table": "core_account_mtm_group",
                "permissions": [
                    ("notify_on_success", "Can receive success notifications"),
                    ("notify_on_fail", "Can receive fail notifications"),
                    ("notify_via_email", "Can receive email notifications"),
                    ("notify_via_slack", "Can receive slack notifications"),
                    ("notify_via_telegram", "Can receive telegram notifications"),
                    ("backup_create", "Can create on-demand backup of node."),
                    (
                        "backup_restore",
                        "Can restore backups to scoped nodes or new resources.",
                    ),
                    (
                        "backup_download",
                        "Can download any on-demand/scheduled backup of node.",
                    ),
                    (
                        "backup_delete",
                        "Can delete any on-demand/scheduled backup of node.",
                    ),
                    (
                        "schedule_changes",
                        "Can create, modify and delete backup schedules.",
                    ),
                    ("node_changes", "Can create, modify and delete nodes."),
                    (
                        "integration_changes",
                        "Can create, modify and delete integrations.",
                    ),
                    (
                        "storage_changes",
                        "Can create, modify and delete storage accounts.",
                    ),
                ],
                "verbose_name": "Account Group",
                "verbose_name_plural": "Account Groups",
            },
        )
    ]
