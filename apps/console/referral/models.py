from django.db import models
from model_utils.models import TimeStampedModel


class CoreReferral(TimeStampedModel):
    # referral code for account
    referral_code = models.CharField(max_length=64, null=True)
    # If this account is rewarded only if invited by another member.
    ip_address = models.CharField(max_length=64, null=True)
    # created = models.BigIntegerField()

    class Meta:
        db_table = 'core_referral'

