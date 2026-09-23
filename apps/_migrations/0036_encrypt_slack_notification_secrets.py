from cryptography.fernet import Fernet, InvalidToken
from django.db import migrations, models
from django.db.migrations.exceptions import IrreversibleError


SECRET_PREFIX = "bs-slack-fernet-v1:"


def _sanitize_metadata(payload):
    if not isinstance(payload, dict):
        return {}
    sanitized = {}
    for name in ("team", "enterprise"):
        value = payload.get(name)
        if not isinstance(value, dict):
            continue
        identity = {
            key: value.get(key)
            for key in ("id", "name")
            if isinstance(value.get(key), str) and value.get(key)
        }
        if identity:
            sanitized[name] = identity
    return sanitized


def _encrypt_legacy_value(value, key, *, row_id, field_name):
    if value in (None, "", b""):
        return None
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError(
                f"Slack row {row_id} has invalid {field_name} bytes"
            ) from error
    if not isinstance(value, str):
        raise RuntimeError(f"Slack row {row_id} has invalid {field_name} data")

    fernet = Fernet(key)
    if value.startswith(SECRET_PREFIX):
        # An interrupted/manual pre-deployment run must not double-encrypt. The
        # existing token still has to authenticate under this account's key.
        try:
            fernet.decrypt(value[len(SECRET_PREFIX) :].encode("ascii"))
        except (InvalidToken, UnicodeEncodeError) as error:
            raise RuntimeError(
                f"Slack row {row_id} has malformed {field_name} ciphertext"
            ) from error
        return value

    return SECRET_PREFIX + fernet.encrypt(value.encode("utf-8")).decode("ascii")


def encrypt_slack_secrets(apps, schema_editor):
    CoreNotificationSlack = apps.get_model("apps", "CoreNotificationSlack")
    fields = ("access_token", "refresh_token", "configuration_url", "url")
    for row in CoreNotificationSlack.objects.select_related("account").iterator():
        key = row.account.encryption_key
        if isinstance(key, memoryview):
            key = key.tobytes()
        if not key:
            # Keeping a plaintext provider bearer is worse than stopping the
            # deployment. The transaction can be retried after repairing the
            # owning account's encryption key.
            raise RuntimeError(
                f"Slack row {row.pk} belongs to an account without an encryption key"
            )
        for field_name in fields:
            setattr(
                row,
                field_name,
                _encrypt_legacy_value(
                    getattr(row, field_name),
                    bytes(key),
                    row_id=row.pk,
                    field_name=field_name,
                ),
            )
        row.data = _sanitize_metadata(row.data)
        row.save(update_fields=(*fields, "data"))


def refuse_plaintext_reverse(apps, schema_editor):
    raise IrreversibleError(
        "Slack credentials cannot be safely migrated back to plaintext storage"
    )


class Migration(migrations.Migration):
    dependencies = [("apps", "0035_coremember_auth_session_version")]

    operations = [
        migrations.AlterField(
            model_name="corenotificationslack",
            name="access_token",
            field=models.TextField(editable=False, null=True),
        ),
        migrations.AlterField(
            model_name="corenotificationslack",
            name="refresh_token",
            field=models.TextField(editable=False, null=True),
        ),
        migrations.AlterField(
            model_name="corenotificationslack",
            name="configuration_url",
            field=models.TextField(editable=False, null=True),
        ),
        migrations.AlterField(
            model_name="corenotificationslack",
            name="url",
            field=models.TextField(editable=False, null=True),
        ),
        migrations.RunPython(encrypt_slack_secrets, refuse_plaintext_reverse),
        migrations.AddConstraint(
            model_name="corenotificationslack",
            constraint=models.CheckConstraint(
                condition=models.Q(access_token__isnull=True)
                | models.Q(access_token__startswith=SECRET_PREFIX),
                name="slack_access_token_ciphertext_v1",
            ),
        ),
        migrations.AddConstraint(
            model_name="corenotificationslack",
            constraint=models.CheckConstraint(
                condition=models.Q(refresh_token__isnull=True)
                | models.Q(refresh_token__startswith=SECRET_PREFIX),
                name="slack_refresh_token_ciphertext_v1",
            ),
        ),
        migrations.AddConstraint(
            model_name="corenotificationslack",
            constraint=models.CheckConstraint(
                condition=models.Q(configuration_url__isnull=True)
                | models.Q(configuration_url__startswith=SECRET_PREFIX),
                name="slack_configuration_ciphertext_v1",
            ),
        ),
        migrations.AddConstraint(
            model_name="corenotificationslack",
            constraint=models.CheckConstraint(
                condition=models.Q(url__isnull=True)
                | models.Q(url__startswith=SECRET_PREFIX),
                name="slack_webhook_ciphertext_v1",
            ),
        ),
    ]
