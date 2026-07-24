from datetime import timedelta
import json

from django.conf import settings
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.core.serializers.json import DjangoJSONEncoder
from django.dispatch import receiver
from django.utils import timezone

from ..account.models import *
from django.db import models

from ..connection.models import CoreConnection
from ..member.models import CoreMember
from ..node.models import CoreNode


class CoreLog(TimeStampedModel):
    # Choices-only extension (BACKUP..AUTH appended after CONNECTION): the column is
    # a plain IntegerField, so this changes no SQL. Django's migration autodetector
    # still records the choices list in its state, so the next generated migration
    # will include a state-only AlterField for it.
    class Type(models.IntegerChoices):
        GENERIC = 1, "GENERIC"
        NODE = 2, "NODE"
        CONNECTION = 3, "CONNECTION"
        BACKUP = 4, "BACKUP"
        MEMBER = 5, "MEMBER"
        SCHEDULE = 6, "SCHEDULE"
        STORAGE = 7, "STORAGE"
        RESTORE = 8, "RESTORE"
        AUTH = 9, "AUTH"

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

    @classmethod
    def record(cls, account, log_type, data):
        """Write one activity-log row and return it.

        `data` is a JSON dict; by convention it carries a human-readable 'message'
        plus optional 'error', 'action', 'actor_email' and '*_id'/'*_name' pairs the
        properties above understand. Logging must never break the caller, so any bad
        input (junk data, unusable account, DB error) is swallowed and None returned.
        Input is validated *before* issuing SQL: an exception raised mid-query would
        poison the caller's transaction under atomic blocks.
        """
        try:
            if not isinstance(data, dict):
                data = {"message": str(data)}
            log_type = int(log_type)
            json.dumps(data, cls=DjangoJSONEncoder)
            if not isinstance(account, CoreAccount) or account.pk is None:
                raise ValueError("account must be a saved CoreAccount")
            return cls.objects.create(account=account, type=log_type, data=data)
        except Exception as e:
            print(f"CoreLog.record failed: {e}")
            return None

    @classmethod
    def prune(cls):
        """Delete rows older than LOG_RETENTION_DAYS (default 30). Returns the
        number of deleted rows."""
        retention_days = getattr(settings, "LOG_RETENTION_DAYS", 30)
        cutoff = timezone.now() - timedelta(days=retention_days)
        deleted_count, _ = cls.objects.filter(created__lt=cutoff).delete()
        return deleted_count


def _request_ip(request):
    """Best-effort client IP; the auth signals may fire without a request."""
    if request is None:
        return None
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


@receiver(user_logged_in)
def log_user_logged_in(sender, request, user, **kwargs):
    """Record successful logins as AUTH activity. Must never break auth."""
    try:
        member = getattr(user, "member", None)
        if member is None:
            return
        account = member.get_current_account()
        if account is None:
            return
        CoreLog.record(
            account,
            CoreLog.Type.AUTH,
            {
                "message": f"{user.email} logged in.",
                "action": "login",
                "actor_email": user.email,
                "ip": _request_ip(request),
            },
        )
    except Exception:
        pass


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    """Record failed logins as AUTH activity, but only when the attempted account
    can be resolved -- an unknown email has no account to attach the row to, so it
    is skipped silently. Must never break auth."""
    try:
        username = (credentials or {}).get("username") or (credentials or {}).get("email")
        if not username:
            return
        member = CoreMember.objects.filter(
            Q(user__email__iexact=username) | Q(user__username__iexact=username)
        ).first()
        if member is None:
            return
        account = member.get_current_account()
        if account is None:
            return
        CoreLog.record(
            account,
            CoreLog.Type.AUTH,
            {
                "message": f"Failed login attempt for {username}.",
                "action": "login_failed",
                "actor_email": username,
                "ip": _request_ip(request),
            },
        )
    except Exception:
        pass