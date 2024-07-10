from django.db import models
from model_utils.models import TimeStampedModel
import uuid


class CoreDownload(TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.TextField()
    path = models.TextField()
    count = models.BigIntegerField(default=0)
    key = models.CharField(max_length=64)

    class Meta:
        db_table = "core_download"

