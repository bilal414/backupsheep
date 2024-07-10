from django.db import models
from model_utils.models import TimeStampedModel
import uuid
from apps.console.account.models import CoreAccount, CoreAccountGroup
from apps.console.member.models import CoreMember


class CoreInvite(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACCEPTED = 1, "Accepted"
        EXPIRED = 2, "Expired"
        CANCELLED = 3, "Cancelled"
        PENDING = 4, "Pending"

    added_by = models.ForeignKey(
        CoreMember,
        related_name="invites_sent",
        on_delete=models.CASCADE,
    )

    account = models.ForeignKey(
        CoreAccount, related_name="invites", editable=False, on_delete=models.CASCADE
    )
    groups = models.ManyToManyField(
        CoreAccountGroup, related_name="invites"
    )
    status = models.IntegerField(choices=Status.choices, default=Status.PENDING, editable=False)
    notify_on_success = models.BooleanField(default=True, null=True)
    notify_on_fail = models.BooleanField(default=True, null=True)
    timezone = models.CharField(max_length=64, default="UTC")
    first_name = models.CharField(max_length=64)
    last_name = models.CharField(max_length=64)
    email = models.EmailField()
    uuid = models.UUIDField(default=uuid.uuid4, editable=False)

    class Meta:
        db_table = "core_invite"

    @property
    def full_name(self):
        """Returns the person's full name."""
        return f"{self.first_name} {self.last_name}"
