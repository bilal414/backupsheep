from datetime import timedelta
from dataclasses import dataclass
import json

from django.conf import settings
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.core.serializers.json import DjangoJSONEncoder
from django.dispatch import receiver
from django.db.models import Q
from django.utils import timezone

from backupsheep.sentry_security import scrub_sensitive_text

from ..account.models import *
from django.db import models

from ..connection.models import CoreConnection
from ..member.models import CoreMember
from ..node.models import CoreNode


def _activity_text(value, limit=1200):
    """Return a bounded, display-safe scalar from a legacy JSON value."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (str, int, float)):
        # Bound work as well as rendered output. A pathological historical JSON
        # scalar should not make one register row consume unbounded CPU/memory.
        raw_value = str(value)[: max(4096, limit * 4)]
        return scrub_sensitive_text(raw_value).strip()[:limit]
    if isinstance(value, dict):
        for key in ("public_message", "message", "code", "category"):
            if value.get(key) is not None:
                return _activity_text(value.get(key), limit=limit)
    return ""


def _activity_id(value):
    """Coerce historical integer-like identifiers without accepting booleans."""
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


@dataclass(frozen=True)
class ActivityPresentation:
    """A query-free, redacted event presenter consumed by the console template."""

    event_ref: str
    category_label: str
    category_slug: str
    outcome_label: str
    outcome_slug: str
    message: str
    error: str
    action: str
    actor_label: str
    actor_kind: str
    source_label: str
    subject_label: str
    subject_meta: str
    node_id: int | None
    connection_id: int | None
    backup_id: int | None
    correlation_id: str
    request_id: str


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

    TYPE_PRESENTATION = {
        Type.GENERIC: ("System", "system"),
        Type.NODE: ("Source", "source"),
        Type.CONNECTION: ("Connection", "connection"),
        Type.BACKUP: ("Backup", "backup"),
        Type.MEMBER: ("Access", "access"),
        Type.SCHEDULE: ("Schedule", "schedule"),
        Type.STORAGE: ("Destination", "destination"),
        Type.RESTORE: ("Restore", "restore"),
        Type.AUTH: ("Authentication", "authentication"),
    }

    OUTCOME_CHOICES = (
        ("succeeded", "Succeeded"),
        ("accepted", "Accepted"),
        ("in_progress", "In progress"),
        ("failed", "Failed"),
        ("denied", "Denied"),
        ("recorded", "Recorded"),
    )
    OUTCOME_LABELS = dict(OUTCOME_CHOICES)
    OUTCOME_ALIASES = {
        "succeeded": frozenset(("success", "succeeded", "complete", "completed", "ok", "verified")),
        "accepted": frozenset(("accepted", "requested", "queued", "scheduled")),
        "in_progress": frozenset(("pending", "in_progress", "in-progress", "running", "retrying", "reconciling")),
        "failed": frozenset(("fail", "failed", "error", "blocked")),
        "denied": frozenset(("denied", "rejected", "unauthorized")),
        "recorded": frozenset(("recorded", "unknown", "informational", "info")),
    }
    ACCEPTED_ACTIONS = frozenset(
        (
            "trigger",
            "restore_create",
            "restore_resume_verification",
            "database_restore_resume_verification",
            "reset_incremental",
        )
    )
    PROGRESS_MESSAGE_FRAGMENTS = (
        "still being reconciled",
        "in progress",
        "waiting for",
        "retrying",
    )
    ACCEPTED_MESSAGE_FRAGMENTS = (
        " requested",
        "request accepted",
        " scheduled",
        "queued",
    )

    account = models.ForeignKey(
        CoreAccount, related_name="logs", on_delete=models.CASCADE
    )
    type = models.IntegerField(choices=Type.choices, default=Type.GENERIC)
    data = models.JSONField(null=True)

    class Meta:
        db_table = "core_log"

    @staticmethod
    def safe_data(log_or_data):
        data = getattr(log_or_data, "data", log_or_data)
        return data if isinstance(data, dict) else {}

    @classmethod
    def _meaningful_error(cls, data):
        raw_value = data.get("error")
        if raw_value is None or raw_value is False:
            return ""
        value = _activity_text(raw_value)
        if value.lower() in {"", "n/a", "none", "null", "false"}:
            return ""
        return value

    @classmethod
    def classify_outcome(cls, log_or_data):
        """Classify legacy rows conservatively without claiming unproven success."""
        data = cls.safe_data(log_or_data)
        explicit = _activity_text(data.get("outcome"), limit=64).lower()
        for outcome, aliases in cls.OUTCOME_ALIASES.items():
            if explicit in aliases:
                return outcome

        if cls._meaningful_error(data):
            return "failed"

        action = _activity_text(data.get("action"), limit=128).lower()
        if action == "login_failed":
            return "denied"

        message = _activity_text(data.get("message")).lower()
        if any(fragment in message for fragment in cls.PROGRESS_MESSAGE_FRAGMENTS):
            return "in_progress"
        if action in cls.ACCEPTED_ACTIONS or any(
            fragment in message for fragment in cls.ACCEPTED_MESSAGE_FRAGMENTS
        ):
            return "accepted"

        # A successful authentication signal is narrowly proven by the login
        # action. Other legacy prose is not recovery or operation evidence.
        if action == "login":
            return "succeeded"
        return "recorded"

    @classmethod
    def _outcome_queries(cls):
        """Return database predicates in the same precedence order as the presenter."""
        explicit = {}
        for name, values in cls.OUTCOME_ALIASES.items():
            predicate = Q()
            for value in values:
                predicate |= Q(data__outcome__iexact=value)
            explicit[name] = predicate
        known_explicit = Q()
        for predicate in explicit.values():
            known_explicit |= predicate

        empty_error = Q(data__error__isnull=True) | Q(data__error=False)
        for empty_value in ("", "n/a", "none", "null", "false"):
            empty_error |= Q(data__error__iexact=empty_value)
        meaningful_error = ~empty_error

        action_denied = Q(data__action__iexact="login_failed")
        action_accepted = Q()
        for action in cls.ACCEPTED_ACTIONS:
            action_accepted |= Q(data__action__iexact=action)

        progress_message = Q()
        for fragment in cls.PROGRESS_MESSAGE_FRAGMENTS:
            progress_message |= Q(data__message__icontains=fragment)
        accepted_message = Q()
        for fragment in cls.ACCEPTED_MESSAGE_FRAGMENTS:
            accepted_message |= Q(data__message__icontains=fragment.strip())
        unmatched = ~known_explicit
        predicates = {}
        predicates["failed"] = explicit["failed"] | (unmatched & meaningful_error)
        remaining = unmatched & ~meaningful_error
        predicates["denied"] = explicit["denied"] | (remaining & action_denied)
        remaining &= ~action_denied
        predicates["in_progress"] = explicit["in_progress"] | (
            remaining & progress_message
        )
        remaining &= ~progress_message
        predicates["accepted"] = explicit["accepted"] | (
            remaining & (action_accepted | accepted_message)
        )
        remaining &= ~(action_accepted | accepted_message)
        predicates["succeeded"] = explicit["succeeded"] | (
            remaining & Q(data__action__iexact="login")
        )
        predicates["recorded"] = explicit["recorded"] | ~(
            predicates["failed"]
            | predicates["denied"]
            | predicates["in_progress"]
            | predicates["accepted"]
            | predicates["succeeded"]
        )
        return predicates

    @classmethod
    def outcome_query(cls, outcome):
        return cls._outcome_queries().get(outcome)

    def build_presentation(self, *, node=None, connection=None):
        """Build a redacted historical row without performing database lookups."""
        data = self.safe_data(self)
        outcome = self.classify_outcome(data)
        category_label, category_slug = self.TYPE_PRESENTATION.get(
            self.type, ("Other", "other")
        )

        node_id = _activity_id(data.get("node_id"))
        connection_id = _activity_id(data.get("connection_id"))
        backup_id = _activity_id(data.get("backup_id"))
        node_name = _activity_text(data.get("node_name"), limit=240)
        connection_name = _activity_text(data.get("connection_name"), limit=240)
        backup_name = _activity_text(data.get("backup_name"), limit=240)
        if not node_name and node is not None:
            node_name = _activity_text(getattr(node, "name", None), limit=240)
        if not connection_name and connection is not None:
            connection_name = _activity_text(
                getattr(connection, "name", None), limit=240
            )

        typed_subjects = {
            self.Type.RESTORE: (
                _activity_text(data.get("restore_name"), limit=240),
                _activity_id(data.get("restore_id")),
                "Restore",
            ),
            self.Type.BACKUP: (backup_name, backup_id, "Backup"),
            self.Type.SCHEDULE: (
                _activity_text(data.get("schedule_name"), limit=240),
                _activity_id(data.get("schedule_id")),
                "Schedule",
            ),
            self.Type.STORAGE: (
                _activity_text(data.get("storage_name"), limit=240),
                _activity_id(data.get("storage_id")),
                "Destination",
            ),
            self.Type.CONNECTION: (connection_name, connection_id, "Connection"),
            self.Type.NODE: (node_name, node_id, "Source"),
        }
        subject_name, subject_id, subject_kind = typed_subjects.get(
            self.type, ("", None, "Workspace")
        )
        if not subject_name and not subject_id and node_id:
            subject_name, subject_id, subject_kind = node_name, node_id, "Source"
        if not subject_name and not subject_id and connection_id:
            subject_name, subject_id, subject_kind = (
                connection_name,
                connection_id,
                "Connection",
            )
        if self.type == self.Type.AUTH:
            subject_name, subject_id, subject_kind = "Sign-in access", None, "Workspace"
        if not subject_name:
            subject_name = f"{subject_kind} {subject_id}" if subject_id else subject_kind

        subject_meta_parts = []
        if subject_id:
            subject_meta_parts.append(f"ID {subject_id}")
        if node_name and subject_kind != "Source":
            subject_meta_parts.append(f"Source: {node_name}")
        if connection_name and subject_kind not in {"Source", "Connection"}:
            subject_meta_parts.append(f"Connection: {connection_name}")

        actor = _activity_text(data.get("actor_email"), limit=320)
        action = _activity_text(data.get("action"), limit=128)
        if actor:
            actor_kind = "User"
            source_label = "Console or API"
        elif self.type == self.Type.AUTH:
            actor_kind = "Authentication service"
            source_label = "BackupSheep authentication"
        elif self.type == self.Type.SCHEDULE:
            actor_kind = "Automation"
            source_label = "BackupSheep scheduler"
        elif self.type in {self.Type.BACKUP, self.Type.RESTORE}:
            actor_kind = "Automation"
            source_label = "BackupSheep worker"
        elif _activity_text(data.get("sender_name"), limit=128):
            actor_kind = "Automation"
            source_label = "Notification service"
        else:
            actor_kind = "System"
            source_label = "BackupSheep"

        return ActivityPresentation(
            event_ref=f"evt_{self.pk}",
            category_label=category_label,
            category_slug=category_slug,
            outcome_label=self.OUTCOME_LABELS[outcome],
            outcome_slug=outcome.replace("_", "-"),
            message=_activity_text(data.get("message")) or "Event recorded.",
            error=self._meaningful_error(data),
            action=action.replace("_", " ").strip().title(),
            actor_label=actor or actor_kind,
            actor_kind=actor_kind,
            source_label=source_label,
            subject_label=subject_name,
            subject_meta=" · ".join(subject_meta_parts),
            node_id=node.pk if node is not None else None,
            connection_id=connection.pk if connection is not None else None,
            backup_id=backup_id,
            correlation_id=_activity_text(data.get("correlation_id"), limit=160),
            request_id=_activity_text(data.get("request_id"), limit=160),
        )

    @classmethod
    def attach_presentations(cls, logs, *, nodes_by_id=None, connections_by_id=None):
        """Attach presenters using caller-supplied, already-scoped bulk lookups."""
        nodes_by_id = nodes_by_id or {}
        connections_by_id = connections_by_id or {}
        for log in logs:
            data = cls.safe_data(log)
            node = nodes_by_id.get(_activity_id(data.get("node_id")))
            connection = connections_by_id.get(
                _activity_id(data.get("connection_id"))
            )
            if connection is None and node is not None:
                connection = getattr(node, "connection", None)
            log.presentation = log.build_presentation(
                node=node,
                connection=connection,
            )
        return logs

    @property
    def node(self):
        node_id = _activity_id(self.safe_data(self).get("node_id"))
        if node_id:
            return CoreNode.objects.filter(
                id=node_id,
                connection__account_id=self.account_id,
            ).first()

    @property
    def node_name(self):
        return self.safe_data(self).get("node_name")

    @property
    def integration(self):
        connection_id = _activity_id(self.safe_data(self).get("connection_id"))
        if connection_id:
            return CoreConnection.objects.filter(
                id=connection_id,
                account_id=self.account_id,
            ).first()

    @property
    def integration_name(self):
        return self.safe_data(self).get("connection_name")

    @property
    def backup(self):
        backup_id = _activity_id(self.safe_data(self).get("backup_id"))
        node = self.node
        integration = self.integration
        if backup_id and node and integration:
            if hasattr(node, integration.integration.code):
                node_type_object = getattr(node, integration.integration.code)
                if node_type_object.backups.filter(id=backup_id).exists():
                    return node_type_object.backups.get(id=backup_id)
                else:
                    return None

    @property
    def backup_name(self):
        return self.safe_data(self).get("backup_name")

    @property
    def backup_type(self):
        backup_type = self.safe_data(self).get("backup_type")
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


def record_user_logged_in(request, user):
    """Record a successful session or native-token login without breaking auth."""
    try:
        member = getattr(user, "member", None)
        if member is None:
            return None
        account = member.get_current_account()
        if account is None:
            return None
        return CoreLog.record(
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
        return None


@receiver(user_logged_in)
def log_user_logged_in(sender, request, user, **kwargs):
    """Record successful Django session logins as AUTH activity."""
    record_user_logged_in(request, user)


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
