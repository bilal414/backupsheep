from ..account.models import *
from django.db import models

from ..connection.models import CoreConnection
from ..node.models import CoreNode


class CoreLog(TimeStampedModel):
    class Type(models.IntegerChoices):
        GENERIC = 1, "GENERIC"
        NODE = 2, "NODE"
        CONNECTION = 3, "CONNECTION"

    account = models.ForeignKey(
        CoreAccount, related_name="logs", on_delete=models.CASCADE
    )
    type = models.IntegerField(choices=Type.choices, default=Type.GENERIC)
    data = models.JSONField(null=True)

    class Meta:
        db_table = "core_log"

    @property
    def node(self):
        node_id = self.data.get("node_id")
        if node_id:
            if CoreNode.objects.filter(id=node_id).exists():
                return CoreNode.objects.get(id=node_id)
            else:
                return None

    @property
    def node_name(self):
        return self.data.get("node_name")

    @property
    def integration(self):
        connection_id = self.data.get("connection_id")
        if connection_id:
            if CoreConnection.objects.filter(id=connection_id).exists():
                return CoreConnection.objects.get(id=connection_id)
            else:
                return None

    @property
    def integration_name(self):
        return self.data.get("connection_name")

    @property
    def backup(self):
        backup_id = self.data.get("backup_id")
        if backup_id and self.node:
            if hasattr(self.node, self.integration.integration.code):
                node_type_object = getattr(self.node, self.integration.integration.code)
                if node_type_object.backups.filter(id=backup_id).exists():
                    return node_type_object.backups.get(id=backup_id)
                else:
                    return None

    @property
    def backup_name(self):
        return self.data.get("backup_name")

    @property
    def backup_type(self):
        backup_type = self.data.get("backup_type")
        if backup_type == 1:
            return "On-Demand"
        elif backup_type == 2:
            return "Scheduled"