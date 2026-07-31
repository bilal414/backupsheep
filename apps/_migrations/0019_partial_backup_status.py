from django.db import migrations, models


BACKUP_STATUS_CHOICES = [
    (1, "Pending"),
    (2, "In-Progress"),
    (3, "Complete"),
    (4, "Failed"),
    (5, "Retrying"),
    (6, "Started"),
    (7, "Max Retries Failed"),
    (8, "Ready For Upload"),
    (9, "Upload In Progress"),
    (10, "Upload Complete"),
    (22, "Upload Validation"),
    (23, "Partial (Some Destinations Failed)"),
    (11, "Upload Failed"),
    (12, "Delete REQUESTED"),
    (13, "Delete In-Progress"),
    (14, "Delete Completed"),
    (15, "Delete Failed"),
    (20, "Delete Failed (Not Found)"),
    (16, "Delete Max Retries Failed"),
    (17, "Download In-Progress"),
    (18, "Download Complete"),
    (19, "Cancelled"),
    (21, "Timeout"),
    (30, "Storage Validation Failed"),
]


class Migration(migrations.Migration):
    dependencies = [("apps", "0018_immutable_storage_and_cost_controls")]

    operations = [
        migrations.AlterField(
            model_name=model_name,
            name="status",
            field=models.IntegerField(choices=BACKUP_STATUS_CHOICES, default=3),
        )
        for model_name in (
            "coredigitaloceanbackup",
            "corehetznerbackup",
            "coreupcloudbackup",
            "coreoraclebackup",
            "coreovhcabackup",
            "coreovheubackup",
            "coreovhusbackup",
            "corevultrbackup",
            "coregooglecloudbackup",
            "corewebsitebackup",
            "corewordpressbackup",
            "corebasecampbackup",
            "coredatabasebackup",
            "coreawsbackup",
            "corelightsailbackup",
            "coreawsrdsbackup",
        )
    ]
