"""Safely rewrap active BSE1 data keys to a local-file keyring's active key."""

from __future__ import annotations

import hashlib
import re
from contextlib import contextmanager

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.console.backup.models import (
    CoreBackupEncryptionEnvelope,
    CoreBackupKeyWrap,
)
from backupsheep.artifact_crypto import WrappedDataKey


_KEY_ID = re.compile(r"^lfk-[0-9a-f]{32}$")
_INSTALLATION_ID = re.compile(r"^[0-9a-f]{64}$")


def _validated_rotation_scope(*, source_key: str, witness: str, lane: str) -> None:
    if _KEY_ID.fullmatch(source_key) is None:
        raise CommandError("The expected source key ID is invalid.")
    installation_id = str(getattr(settings, "BACKUPSHEEP_INSTALLATION_ID", ""))
    if not _INSTALLATION_ID.fullmatch(witness) or witness != installation_id:
        raise CommandError(
            "The installation identity witness does not match this deployment."
        )
    if lane not in {"database", "files"}:
        raise CommandError("The artifact keyring lane is invalid.")
    if (
        getattr(settings, "BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE", "") != "bse1"
        or getattr(settings, "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER", "")
        != "local-file"
    ):
        raise CommandError("Production local-file BSE1 artifact custody is not active.")


@contextmanager
def _configured_provider(*, lane: str):
    # Reuse the same fail-closed construction path used by seal and restore.
    from apps._tasks.artifact_encryption import _configured_provider as provider_factory

    with provider_factory() as provider:
        if (
            getattr(provider, "name", None) != CoreBackupKeyWrap.Provider.LOCAL_FILE
            or getattr(provider, "enterprise_eligible", None) is not True
            or getattr(provider, "lane", None) != lane
        ):
            raise CommandError(
                "The configured artifact key provider does not match this source lane."
            )
        yield provider


def _rotate_one(
    envelope_id: int,
    *,
    provider,
    source_key: str,
    destination_key: str,
    installation_id: str,
    expected_lane: str,
) -> str:
    """Rotate one envelope under a row lock; return rotated/already-rotated."""

    with transaction.atomic():
        envelope = CoreBackupEncryptionEnvelope.objects.select_for_update().get(
            pk=envelope_id
        )
        wraps = list(
            CoreBackupKeyWrap.objects.select_for_update()
            .filter(envelope=envelope)
            .order_by("generation", "pk")
        )
        active = [item for item in wraps if item.status == item.Status.ACTIVE]
        if envelope.status != envelope.Status.ACTIVE or len(active) != 1:
            raise CommandError(
                f"Envelope {envelope.pk} is not in a single-active-wrap state."
            )
        current = active[0]
        context, validated = envelope.validate_restore_state()
        if (
            validated.pk != current.pk
            or context.installation_id != installation_id
            or context.lane != expected_lane
        ):
            raise CommandError(
                f"Envelope {envelope.pk} failed its durable custody witness."
            )
        if current.wrapping_key_id == destination_key:
            return "already-rotated"
        if (
            current.provider != CoreBackupKeyWrap.Provider.LOCAL_FILE
            or current.wrapping_key_id != source_key
        ):
            raise CommandError(
                f"Envelope {envelope.pk} is active under an unexpected wrapping key."
            )

        try:
            rewrapped = provider.rewrap_data_key(
                WrappedDataKey(
                    provider_name=current.provider,
                    wrapping_key_id=current.wrapping_key_id,
                    ciphertext=bytes(current.wrapped_data_key),
                ),
                context,
                destination_key_id=destination_key,
            )
        except Exception as error:
            raise CommandError(
                f"The local-file provider could not rewrap envelope {envelope.pk}; "
                "no database state changed."
            ) from error
        if (
            rewrapped.provider_name != CoreBackupKeyWrap.Provider.LOCAL_FILE
            or rewrapped.wrapping_key_id != destination_key
            or not isinstance(rewrapped.ciphertext, bytes)
            or not rewrapped.ciphertext
            or len(rewrapped.ciphertext) > 8192
        ):
            raise CommandError(
                f"The local-file provider returned an invalid wrap for envelope {envelope.pk}."
            )

        next_generation = max((item.generation for item in wraps), default=0) + 1
        replacement = CoreBackupKeyWrap(
            envelope=envelope,
            generation=next_generation,
            provider=CoreBackupKeyWrap.Provider.LOCAL_FILE,
            wrapping_key_id=destination_key,
            wrapped_data_key=rewrapped.ciphertext,
            wrapped_key_sha256=hashlib.sha256(rewrapped.ciphertext).hexdigest(),
            status=CoreBackupKeyWrap.Status.PENDING,
        )
        replacement.full_clean()
        replacement.save()

        rotated_at = timezone.now()
        current.status = CoreBackupKeyWrap.Status.RETIRED
        current.retired_at = rotated_at
        current.full_clean()
        current.save(update_fields=("status", "retired_at", "modified"))

        replacement.status = CoreBackupKeyWrap.Status.ACTIVE
        replacement.activated_at = rotated_at
        replacement.full_clean()
        replacement.save(update_fields=("status", "activated_at", "modified"))
        _context, observed = envelope.validate_restore_state()
        if observed.pk != replacement.pk:
            raise CommandError(
                f"Envelope {envelope.pk} did not activate its replacement key wrap."
            )
        return "rotated"


class Command(BaseCommand):
    help = (
        "Rewrap active BSE1 data keys from one retained local-file key to the "
        "keyring's active key. The default is a read-only plan; --apply performs "
        "bounded rotations."
    )

    def add_arguments(self, parser):
        parser.add_argument("--expected-source-key-id", required=True)
        parser.add_argument("--installation-id-witness", required=True)
        parser.add_argument("--lane", required=True, choices=("database", "files"))
        parser.add_argument("--limit", type=int, default=100)
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args, **options):
        source_key = str(options["expected_source_key_id"])
        installation_id = str(options["installation_id_witness"])
        lane = str(options["lane"])
        limit = options["limit"]
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise CommandError("--limit must be between 1 and 10000.")
        _validated_rotation_scope(
            source_key=source_key,
            witness=installation_id,
            lane=lane,
        )

        with _configured_provider(lane=lane) as provider:
            destination_key = str(provider.active_key_id)
            if destination_key == source_key:
                raise CommandError(
                    "The expected source key is already the keyring's active key."
                )
            if source_key not in provider.key_ids:
                raise CommandError(
                    "The expected source key is absent from this lane keyring."
                )
            candidates = list(
                CoreBackupEncryptionEnvelope.objects.filter(
                    status=CoreBackupEncryptionEnvelope.Status.ACTIVE,
                    key_wraps__status=CoreBackupKeyWrap.Status.ACTIVE,
                    key_wraps__provider=CoreBackupKeyWrap.Provider.LOCAL_FILE,
                    key_wraps__wrapping_key_id=source_key,
                    context_canonical_json__contains=f'"lane":"{lane}"',
                )
                .order_by("pk")
                .values_list("pk", flat=True)[:limit]
            )
            remaining = CoreBackupEncryptionEnvelope.objects.filter(
                status=CoreBackupEncryptionEnvelope.Status.ACTIVE,
                key_wraps__status=CoreBackupKeyWrap.Status.ACTIVE,
                key_wraps__provider=CoreBackupKeyWrap.Provider.LOCAL_FILE,
                key_wraps__wrapping_key_id=source_key,
                context_canonical_json__contains=f'"lane":"{lane}"',
            ).count()
            if not options["apply"]:
                self.stdout.write(
                    "Artifact key-wrap rotation plan: "
                    f"lane={lane} source={source_key} destination={destination_key} "
                    f"selected={len(candidates)} remaining_source={remaining}; "
                    "no keyring or database mutation performed."
                )
                return

            rotated = 0
            already_rotated = 0
            for envelope_id in candidates:
                result = _rotate_one(
                    envelope_id,
                    provider=provider,
                    source_key=source_key,
                    destination_key=destination_key,
                    installation_id=installation_id,
                    expected_lane=lane,
                )
                if result == "rotated":
                    rotated += 1
                else:
                    already_rotated += 1
        remaining_after = CoreBackupEncryptionEnvelope.objects.filter(
            status=CoreBackupEncryptionEnvelope.Status.ACTIVE,
            key_wraps__status=CoreBackupKeyWrap.Status.ACTIVE,
            key_wraps__provider=CoreBackupKeyWrap.Provider.LOCAL_FILE,
            key_wraps__wrapping_key_id=source_key,
            context_canonical_json__contains=f'"lane":"{lane}"',
        ).count()
        self.stdout.write(
            self.style.SUCCESS(
                "Artifact key-wrap rotation batch committed: "
                f"lane={lane} rotated={rotated} already_rotated={already_rotated} "
                f"remaining_source={remaining_after}."
            )
        )
