from cryptography.fernet import Fernet, InvalidToken
from django.db import migrations, models


SECRET_PREFIX = "bs-wordpress-fernet-v1:"
SECRET_FIELDS = ("key", "http_user", "http_pass")


def _account_key(value, *, row_id):
    if isinstance(value, memoryview):
        value = value.tobytes()
    if not value:
        raise RuntimeError(
            f"WordPress row {row_id} belongs to an account without an encryption key"
        )
    try:
        # Validate both the type and Fernet format before touching any row.
        Fernet(bytes(value))
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            f"WordPress row {row_id} belongs to an account with an invalid encryption key"
        ) from error
    return bytes(value)


def _normalize_value(value, *, row_id, field_name):
    if value in (None, "", b""):
        return None
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError(
                f"WordPress row {row_id} has invalid {field_name} bytes"
            ) from error
    if not isinstance(value, str):
        raise RuntimeError(
            f"WordPress row {row_id} has invalid {field_name} data"
        )
    return value


def _encrypt_legacy_value(value, key, *, row_id, field_name):
    value = _normalize_value(value, row_id=row_id, field_name=field_name)
    if value is None:
        return None
    fernet = Fernet(key)
    if value.startswith(SECRET_PREFIX):
        try:
            fernet.decrypt(value[len(SECRET_PREFIX) :].encode("ascii"))
        except (InvalidToken, UnicodeEncodeError) as error:
            raise RuntimeError(
                f"WordPress row {row_id} has malformed {field_name} ciphertext"
            ) from error
        return value
    return SECRET_PREFIX + fernet.encrypt(value.encode("utf-8")).decode("ascii")


def _decrypt_for_rollback(value, key, *, row_id, field_name):
    value = _normalize_value(value, row_id=row_id, field_name=field_name)
    if value is None:
        return None
    if not value.startswith(SECRET_PREFIX):
        raise RuntimeError(
            f"WordPress row {row_id} has unversioned {field_name} data"
        )
    try:
        return Fernet(key).decrypt(
            value[len(SECRET_PREFIX) :].encode("ascii")
        ).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, UnicodeEncodeError) as error:
        raise RuntimeError(
            f"WordPress row {row_id} has malformed {field_name} ciphertext"
        ) from error


def _transform_rows(apps, transform):
    CoreAuthWordPress = apps.get_model("apps", "CoreAuthWordPress")
    for row in CoreAuthWordPress.objects.select_related(
        "connection__account"
    ).iterator():
        key = _account_key(row.connection.account.encryption_key, row_id=row.pk)
        for field_name in SECRET_FIELDS:
            value = getattr(row, field_name)
            if field_name == "key" and value in (None, "", b""):
                raise RuntimeError(f"WordPress row {row.pk} has no integration key")
            setattr(
                row,
                field_name,
                transform(
                    value,
                    key,
                    row_id=row.pk,
                    field_name=field_name,
                ),
            )
        row.save(update_fields=SECRET_FIELDS)


def encrypt_wordpress_credentials(apps, schema_editor):
    _transform_rows(apps, _encrypt_legacy_value)


def decrypt_wordpress_credentials(apps, schema_editor):
    # Explicit rollback restores the exact legacy representation so the prior
    # application revision can operate. Any missing/wrong key aborts the atomic
    # migration rather than leaving a mixture of plaintext and ciphertext.
    _transform_rows(apps, _decrypt_for_rollback)


class Migration(migrations.Migration):
    dependencies = [("apps", "0038_invalidate_email_verification_bearers")]

    operations = [
        migrations.AlterField(
            model_name="coreauthwordpress",
            name="key",
            field=models.TextField(editable=False),
        ),
        migrations.AlterField(
            model_name="coreauthwordpress",
            name="http_user",
            field=models.TextField(blank=True, editable=False, null=True),
        ),
        migrations.AlterField(
            model_name="coreauthwordpress",
            name="http_pass",
            field=models.TextField(blank=True, editable=False, null=True),
        ),
        migrations.RunPython(
            encrypt_wordpress_credentials,
            decrypt_wordpress_credentials,
        ),
        migrations.AddConstraint(
            model_name="coreauthwordpress",
            constraint=models.CheckConstraint(
                condition=models.Q(key__startswith=SECRET_PREFIX),
                name="wordpress_key_ciphertext_v1",
            ),
        ),
        migrations.AddConstraint(
            model_name="coreauthwordpress",
            constraint=models.CheckConstraint(
                condition=models.Q(http_user__isnull=True)
                | models.Q(http_user__startswith=SECRET_PREFIX),
                name="wordpress_http_user_ciphertext_v1",
            ),
        ),
        migrations.AddConstraint(
            model_name="coreauthwordpress",
            constraint=models.CheckConstraint(
                condition=models.Q(http_pass__isnull=True)
                | models.Q(http_pass__startswith=SECRET_PREFIX),
                name="wordpress_http_pass_ciphertext_v1",
            ),
        ),
    ]
