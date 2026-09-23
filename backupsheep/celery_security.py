"""Authenticated, lane-scoped Celery task envelopes for stock Docker.

RabbitMQ permissions isolate queue consumption, but a broker credential alone is not
proof that a message came from the web control plane, Beat, or an expected worker
handoff.  Each publishing lane therefore signs a deterministic task envelope with its
own Ed25519 key.  Consumers receive only the installation's public-key registry and
reject unsigned, modified, misrouted, or policy-invalid work before task code runs.

The replay ledger stores hashes and routing metadata only; task arguments and secrets
are never persisted there.  Exact completed deliveries are acknowledged without being
executed again.  A broker redelivery of an unfinished delivery remains allowed because
BackupSheep uses late acknowledgements and durable task-specific execution fences.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from celery import Task, current_app, states
from celery.exceptions import Ignore, Reject
from celery.signals import beat_init, before_task_publish, worker_init, worker_ready
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_ssh_private_key,
    load_ssh_public_key,
)
from django.conf import settings
from django.db import DatabaseError, transaction
from django.utils import timezone
from kombu.utils import json as kombu_json

from backupsheep.celery_task_intent import TaskIntentError, resolve_task_intent
from backupsheep.celery_task_manifest import (
    DEFAULT_TASK_MAX_AGE_SECONDS,
    LANES as MANIFEST_LANES,
    TaskManifestError,
    task_policy,
    validate_configured_routes,
    validate_registered_tasks,
)


SECURITY_GENERATION = "3"
ENVELOPE_VERSION = 2
AUTH_HEADER = "backupsheep_auth"
SECRET_ROOT = Path("/run/secrets")
MAX_KEY_FILE_BYTES = 16 * 1024
INSTALLATION_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
NONCE_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
LANES = ("app", "beat", "cloud", "database", "files", "storage", "logs")
if set(LANES) != set(MANIFEST_LANES):  # pragma: no cover - import-time invariant
    raise TaskManifestError("Celery security lanes drifted from the task manifest")
CONSUMER_QUEUES = {
    "cloud": frozenset(("cloud", "default")),
    "database": frozenset(("database",)),
    "files": frozenset(("files",)),
    "storage": frozenset(("storage",)),
    "logs": frozenset(("logs",)),
}
MAX_CLOCK_SKEW_SECONDS = 300
WORKER_READY_FILE = Path("/run/backupsheep/celery-ready")
EXECUTION_HEADER_FIELDS = (
    "lang",
    "meth",
    "shadow",
    "eta",
    "expires",
    "timelimit",
    "root_id",
    "parent_id",
    "group",
    "group_index",
    "replaced_task_nesting",
    "stamped_headers",
    "stamps",
    "utc",
    "ignore_result",
    "origin",
    "argsrepr",
    "kwargsrepr",
    "compression",
)
DIRECT_HEADER_FIELDS = frozenset(("task", "id", "retries"))


class TaskProvenanceError(RuntimeError):
    """A task cannot cross the authenticated lane boundary."""


def _security_required() -> bool:
    """Return the explicit stock-Docker enforcement switch.

    Hosted/external brokers keep their existing operator-managed contract.  Stock
    Compose pins this switch to true in every Django/Celery service, so deleting a
    generation/key variable fails closed instead of silently disabling verification.
    """

    return str(os.environ.get("BACKUPSHEEP_CELERY_SECURITY_REQUIRED") or "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


@dataclass(frozen=True)
class SecurityConfiguration:
    installation_id: str
    lane: str
    private_key_file: str
    public_keys_file: str


@dataclass(frozen=True)
class TrustedKeyRegistry:
    generation: int
    keys: dict[str, Ed25519PublicKey]


def _required_environment(name: str) -> str:
    value = str(os.environ.get(name) or "").strip()
    if not value:
        raise TaskProvenanceError(f"{name} is required")
    return value


def _security_configuration(*, publishing: bool) -> SecurityConfiguration:
    generation = _required_environment("BACKUPSHEEP_CELERY_SECURITY_GENERATION")
    if generation != SECURITY_GENERATION:
        raise TaskProvenanceError(
            f"BACKUPSHEEP_CELERY_SECURITY_GENERATION must be {SECURITY_GENERATION}"
        )
    installation_id = _required_environment("BACKUPSHEEP_INSTALLATION_ID")
    if not INSTALLATION_ID_PATTERN.fullmatch(installation_id):
        raise TaskProvenanceError("installation identity is malformed")
    lane = _required_environment("BACKUPSHEEP_CELERY_LANE")
    allowed_lanes = LANES if publishing else (*CONSUMER_QUEUES, "preflight")
    if lane not in allowed_lanes:
        raise TaskProvenanceError("Celery lane is not authorized for this operation")
    private_key_file = str(
        os.environ.get("CELERY_SIGNING_PRIVATE_KEY_FILE") or ""
    ).strip()
    if publishing and not private_key_file:
        raise TaskProvenanceError("the publishing lane has no signing key")
    public_keys_file = _required_environment("CELERY_TRUSTED_PUBLIC_KEYS_FILE")
    return SecurityConfiguration(
        installation_id=installation_id,
        lane=lane,
        private_key_file=private_key_file,
        public_keys_file=public_keys_file,
    )


def _read_immutable_file(path_value: str, label: str) -> bytes:
    try:
        root = SECRET_ROOT.resolve(strict=True)
        path = Path(path_value)
        if not path.is_absolute():
            raise TaskProvenanceError(f"{label} path must be absolute")
        unresolved = path.lstat()
        if stat.S_ISLNK(unresolved.st_mode):
            raise TaskProvenanceError(f"{label} must not be a symbolic link")
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root)
    except TaskProvenanceError:
        raise
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as error:
        raise TaskProvenanceError(
            f"{label} must be an existing file directly below {SECRET_ROOT}"
        ) from error
    if len(relative.parts) != 1:
        raise TaskProvenanceError(f"{label} must be directly below {SECRET_ROOT}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise TaskProvenanceError(f"{label} could not be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise TaskProvenanceError(
                f"{label} must be one regular, non-hard-linked file"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise TaskProvenanceError(f"{label} must not be group/world writable")
        if metadata.st_size <= 0 or metadata.st_size > MAX_KEY_FILE_BYTES:
            raise TaskProvenanceError(f"{label} has an invalid size")
        payload = os.read(descriptor, MAX_KEY_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_KEY_FILE_BYTES or b"\x00" in payload:
        raise TaskProvenanceError(f"{label} has invalid content")
    return payload


def _load_private_key(path_value: str) -> Ed25519PrivateKey:
    try:
        key = load_ssh_private_key(
            _read_immutable_file(path_value, "Celery signing private key"),
            password=None,
        )
    except (TypeError, ValueError) as error:
        raise TaskProvenanceError("Celery signing private key is invalid") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise TaskProvenanceError("Celery signing private key must be Ed25519")
    return key


def _load_public_registry(
    path_value: str, installation_id: str
) -> TrustedKeyRegistry:
    payload = _read_immutable_file(path_value, "Celery trusted public-key registry")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TaskProvenanceError(
            "Celery trusted public-key registry is invalid"
        ) from error
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "installation_id", "generation", "keys"}
        or document.get("version") != ENVELOPE_VERSION
        or document.get("installation_id") != installation_id
        or isinstance(document.get("generation"), bool)
        or not isinstance(document.get("generation"), int)
        or not 1 <= document["generation"] <= 2**31 - 1
        or not isinstance(document.get("keys"), dict)
        or set(document["keys"]) != set(LANES)
    ):
        raise TaskProvenanceError(
            "Celery trusted public-key registry does not match this installation"
        )
    keys: dict[str, Ed25519PublicKey] = {}
    for lane, encoded in document["keys"].items():
        if not isinstance(encoded, str) or len(encoded) > 256:
            raise TaskProvenanceError("Celery trusted public key is malformed")
        try:
            key = load_ssh_public_key(encoded.encode("ascii"))
        except (UnicodeEncodeError, TypeError, ValueError) as error:
            raise TaskProvenanceError("Celery trusted public key is invalid") from error
        if not isinstance(key, Ed25519PublicKey):
            raise TaskProvenanceError("Celery trusted public keys must be Ed25519")
        keys[lane] = key
    return TrustedKeyRegistry(generation=document["generation"], keys=keys)


def _load_public_keys(
    path_value: str, installation_id: str
) -> dict[str, Ed25519PublicKey]:
    """Compatibility helper for the Docker preflight identity proof."""

    return _load_public_registry(path_value, installation_id).keys


def _canonical_bytes(value: Any) -> bytes:
    try:
        rendered = kombu_json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as error:
        raise TaskProvenanceError(
            "task envelope cannot be represented by the JSON transport"
        ) from error
    return rendered.encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _body_parts(body: Any) -> tuple[Any, Any, dict[str, Any]]:
    if not isinstance(body, (list, tuple)) or len(body) != 3:
        raise TaskProvenanceError("Celery task protocol 2 body is required")
    args, kwargs, embed = body
    if not isinstance(kwargs, Mapping) or not isinstance(embed, Mapping):
        raise TaskProvenanceError("Celery task body structure is invalid")
    normalized_embed = {
        "callbacks": embed.get("callbacks"),
        "errbacks": embed.get("errbacks"),
        "chain": embed.get("chain"),
        "chord": embed.get("chord"),
    }
    return args, dict(kwargs), normalized_embed


def _body_digest(body: Any) -> str:
    args, kwargs, embed = _body_parts(body)
    return _digest([args, kwargs, embed])


def _execution_headers_digest(source: Any) -> str:
    values = {}
    for name in EXECUTION_HEADER_FIELDS:
        if isinstance(source, Mapping):
            value = source.get(name)
        else:
            value = getattr(source, name, None)
        if name == "timelimit" and isinstance(value, tuple):
            value = list(value)
        values[name] = value
    return _digest(values)


def _custom_headers_digest(source: Any) -> str:
    if isinstance(source, Mapping):
        headers = source
    else:
        headers = getattr(source, "headers", None) or {}
    if not isinstance(headers, Mapping):
        raise TaskProvenanceError("Celery custom headers are malformed")
    excluded = set(EXECUTION_HEADER_FIELDS) | DIRECT_HEADER_FIELDS | {AUTH_HEADER}
    return _digest(
        {key: value for key, value in headers.items() if key not in excluded}
    )


def _request_body_digest(task_args: Any, task_kwargs: Any, request: Any) -> str:
    embed = {
        "callbacks": getattr(request, "callbacks", None),
        "errbacks": getattr(request, "errbacks", None),
        "chain": getattr(request, "chain", None),
        "chord": getattr(request, "chord", None),
    }
    return _digest([task_args, task_kwargs, embed])


def _task_destination(task_name: str) -> tuple[str, str, str]:
    try:
        policy = task_policy(task_name)
    except TaskManifestError as error:
        raise TaskProvenanceError(str(error)) from error
    queue = policy.queue
    return queue, policy.target, f"backupsheep.{queue}"


def _publisher_allowed(publisher: str, target: str, task_name: str) -> bool:
    try:
        policy = task_policy(task_name)
    except TaskManifestError:
        return False
    return target == policy.target and publisher in policy.publishers


def _signature_payload(envelope: Mapping[str, Any]) -> bytes:
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    return _canonical_bytes(unsigned)


def _build_envelope(
    *,
    config: SecurityConfiguration,
    headers: Mapping[str, Any],
    body: Any,
    exchange: str,
    routing_key: str,
    now: int | None = None,
) -> dict[str, Any]:
    task_name = str(headers.get("task") or "")
    task_id = str(headers.get("id") or "")
    if not task_name or not task_id or len(task_name) > 255 or len(task_id) > 255:
        raise TaskProvenanceError("task name and durable task id are required")
    queue, target, expected_exchange = _task_destination(task_name)
    if routing_key != queue or exchange != expected_exchange:
        raise TaskProvenanceError("task publication does not match its reviewed route")
    if not _publisher_allowed(config.lane, target, task_name):
        raise TaskProvenanceError(
            f"Celery lane {config.lane} cannot publish {task_name} to {target}"
        )
    try:
        policy = task_policy(task_name)
    except TaskManifestError as error:
        raise TaskProvenanceError(str(error)) from error
    retries = headers.get("retries", 0)
    if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
        raise TaskProvenanceError("task retry count is invalid")
    issued_at = int(time.time() if now is None else now)
    args, kwargs, _embed = _body_parts(body)
    try:
        intent = resolve_task_intent(
            task_name=task_name,
            task_id=task_id,
            args=args,
            kwargs=kwargs,
            publisher=config.lane,
            intent=policy.intent,
            phase="publish",
        )
    except TaskIntentError as error:
        raise TaskProvenanceError(f"task has no durable intent: {error}") from error
    registry = _load_public_registry(
        config.public_keys_file, config.installation_id
    )
    private_key = _load_private_key(config.private_key_file)
    identity_probe = b"backupsheep-celery-key-generation"
    try:
        registry.keys[config.lane].verify(
            private_key.sign(identity_probe), identity_probe
        )
    except InvalidSignature as error:
        raise TaskProvenanceError(
            "Celery signing key does not match the active registry generation"
        ) from error
    envelope = {
        "version": ENVELOPE_VERSION,
        "installation_id": config.installation_id,
        "key_generation": registry.generation,
        "publisher": config.lane,
        "target": target,
        "task": task_name,
        "id": task_id,
        "queue": queue,
        "exchange": exchange,
        "retries": retries,
        "issued_at": issued_at,
        "expires_at": issued_at + policy.max_age_seconds,
        "nonce": secrets.token_hex(16),
        "body_sha256": _body_digest(body),
        "execution_headers_sha256": _execution_headers_digest(headers),
        "custom_headers_sha256": _custom_headers_digest(headers),
        "intent_sha256": _digest(intent),
    }
    signature = private_key.sign(_signature_payload(envelope))
    envelope["signature"] = base64.b64encode(signature).decode("ascii")
    return envelope


def sign_task_message(
    sender=None,
    body=None,
    exchange=None,
    routing_key=None,
    headers=None,
    **_kwargs,
) -> None:
    """Celery ``before_task_publish`` handler; mutate only the auth header."""

    if not _security_required():
        return
    if headers is None:
        raise TaskProvenanceError("Celery publication headers are missing")
    config = _security_configuration(publishing=True)
    exchange_name = str(getattr(exchange, "name", exchange) or "")
    headers[AUTH_HEADER] = _build_envelope(
        config=config,
        headers=headers,
        body=body,
        exchange=exchange_name,
        routing_key=str(routing_key or ""),
    )


def _validated_envelope(
    *,
    config: SecurityConfiguration,
    task_name: str,
    task_id: str,
    task_args: Any,
    task_kwargs: Any,
    request: Any,
    now: int | None = None,
) -> tuple[dict[str, Any], str, str]:
    custom_headers = getattr(request, "headers", None)
    envelope = custom_headers.get(AUTH_HEADER) if isinstance(custom_headers, dict) else None
    required = {
        "version",
        "installation_id",
        "key_generation",
        "publisher",
        "target",
        "task",
        "id",
        "queue",
        "exchange",
        "retries",
        "issued_at",
        "expires_at",
        "nonce",
        "body_sha256",
        "execution_headers_sha256",
        "custom_headers_sha256",
        "intent_sha256",
        "signature",
    }
    if not isinstance(envelope, dict) or set(envelope) != required:
        raise TaskProvenanceError("task authentication envelope is missing or malformed")
    if envelope["version"] != ENVELOPE_VERSION:
        raise TaskProvenanceError("task authentication version is unsupported")
    if envelope["installation_id"] != config.installation_id:
        raise TaskProvenanceError("task belongs to a different installation")
    publisher = envelope["publisher"]
    if publisher not in LANES:
        raise TaskProvenanceError("task publisher lane is invalid")
    if envelope["target"] != config.lane:
        raise TaskProvenanceError("task was delivered to the wrong consumer lane")
    queue, target, expected_exchange = _task_destination(task_name)
    try:
        policy = task_policy(task_name)
    except TaskManifestError as error:
        raise TaskProvenanceError(str(error)) from error
    delivery = getattr(request, "delivery_info", {}) or {}
    actual_queue = str(delivery.get("routing_key") or "")
    actual_exchange = str(delivery.get("exchange") or "")
    if (
        envelope["task"] != task_name
        or envelope["id"] != task_id
        or envelope["queue"] != queue
        or envelope["exchange"] != expected_exchange
        or envelope["target"] != target
        or actual_queue != queue
        or actual_exchange != expected_exchange
    ):
        raise TaskProvenanceError("task identity or broker route was modified")
    retries = getattr(request, "retries", 0)
    if envelope["retries"] != retries:
        raise TaskProvenanceError("task retry context was modified")
    issued_at = envelope["issued_at"]
    expires_at = envelope["expires_at"]
    current_time = int(time.time() if now is None else now)
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or issued_at > current_time + MAX_CLOCK_SKEW_SECONDS
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at != issued_at + policy.max_age_seconds
        or current_time > expires_at
    ):
        raise TaskProvenanceError("task signed lifetime is invalid or expired")
    if not isinstance(envelope["nonce"], str) or not NONCE_PATTERN.fullmatch(
        envelope["nonce"]
    ):
        raise TaskProvenanceError("task nonce is invalid")
    if not isinstance(envelope["body_sha256"], str) or not DIGEST_PATTERN.fullmatch(
        envelope["body_sha256"]
    ):
        raise TaskProvenanceError("task body digest is invalid")
    if not isinstance(
        envelope["execution_headers_sha256"], str
    ) or not DIGEST_PATTERN.fullmatch(envelope["execution_headers_sha256"]):
        raise TaskProvenanceError("task execution-header digest is invalid")
    if not isinstance(
        envelope["custom_headers_sha256"], str
    ) or not DIGEST_PATTERN.fullmatch(envelope["custom_headers_sha256"]):
        raise TaskProvenanceError("task custom-header digest is invalid")
    if not isinstance(
        envelope["intent_sha256"], str
    ) or not DIGEST_PATTERN.fullmatch(envelope["intent_sha256"]):
        raise TaskProvenanceError("task intent digest is invalid")
    if envelope["body_sha256"] != _request_body_digest(
        task_args, task_kwargs, request
    ):
        raise TaskProvenanceError("task arguments or canvas were modified")
    if envelope["execution_headers_sha256"] != _execution_headers_digest(request):
        raise TaskProvenanceError("task execution headers were modified")
    if envelope["custom_headers_sha256"] != _custom_headers_digest(request):
        raise TaskProvenanceError("task custom headers were modified")
    if not _publisher_allowed(publisher, target, task_name):
        raise TaskProvenanceError("task publisher is not allowed by the lane policy")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (binascii.Error, TypeError, ValueError) as error:
        raise TaskProvenanceError("task signature encoding is invalid") from error
    if len(signature) != 64:
        raise TaskProvenanceError("task signature length is invalid")
    registry = _load_public_registry(config.public_keys_file, config.installation_id)
    if (
        isinstance(envelope["key_generation"], bool)
        or envelope["key_generation"] != registry.generation
    ):
        raise TaskProvenanceError("task signing-key generation is not active")
    try:
        registry.keys[publisher].verify(signature, _signature_payload(envelope))
    except InvalidSignature as error:
        raise TaskProvenanceError("task signature verification failed") from error
    try:
        durable_intent = resolve_task_intent(
            task_name=task_name,
            task_id=task_id,
            args=task_args,
            kwargs=task_kwargs,
            publisher=publisher,
            intent=policy.intent,
            phase="consume",
        )
    except TaskIntentError as error:
        raise TaskProvenanceError(f"task durable intent is invalid: {error}") from error
    if envelope["intent_sha256"] != _digest(durable_intent):
        raise TaskProvenanceError("task durable intent changed after publication")

    envelope_digest = hashlib.sha256(_signature_payload(envelope) + signature).hexdigest()
    execution_key = _digest(
        [
            config.installation_id,
            task_name,
            task_id,
            envelope["retries"],
            envelope["nonce"],
        ]
    )
    return envelope, envelope_digest, execution_key


def _register_delivery(
    *,
    execution_key: str,
    envelope_digest: str,
    envelope: Mapping[str, Any],
    redelivered: bool,
) -> str:
    """Register one execution identity and return its replay disposition."""

    from apps.console.task_security.models import CoreCeleryTaskReplay

    with transaction.atomic():
        record, created = CoreCeleryTaskReplay.objects.get_or_create(
            execution_key=execution_key,
            defaults={
                "envelope_digest": envelope_digest,
                "task_id": envelope["id"],
                "task_name": envelope["task"],
                "publisher_lane": envelope["publisher"],
                "target_lane": envelope["target"],
                "retry_count": envelope["retries"],
            },
        )
        if created:
            return "new"
        record = CoreCeleryTaskReplay.objects.select_for_update().get(
            execution_key=execution_key
        )
        record.delivery_count += 1
        record.save(update_fields=["delivery_count", "last_seen_at"])
    if record.status in {
        CoreCeleryTaskReplay.Status.COMPLETE,
        CoreCeleryTaskReplay.Status.RETRY,
    }:
        return "completed-replay"
    if record.envelope_digest != envelope_digest:
        return "alternate-replay"
    return "redelivery" if redelivered else "active-replay"


def _complete_delivery(execution_key: str, status: str) -> None:
    if not execution_key or status not in {"complete", "retry"}:
        return
    from apps.console.task_security.models import CoreCeleryTaskReplay

    CoreCeleryTaskReplay.objects.filter(execution_key=execution_key).update(
        status=status,
        completed_at=timezone.now(),
        last_seen_at=timezone.now(),
    )


def prune_completed_task_replays(*, now=None) -> int:
    """Delete only expired terminal replays, never unfinished redeliveries."""

    from datetime import timedelta

    from apps.console.task_security.models import CoreCeleryTaskReplay

    current_time = now or timezone.now()
    configured_retention = int(
        getattr(
            settings,
            "CELERY_TASK_REPLAY_RETENTION_SECONDS",
            14 * 24 * 60 * 60,
        )
    )
    minimum_retention = DEFAULT_TASK_MAX_AGE_SECONDS + MAX_CLOCK_SKEW_SECONDS
    if configured_retention < minimum_retention:
        raise TaskProvenanceError(
            "Celery replay retention must exceed every accepted signature lifetime"
        )
    batch_size = int(
        getattr(settings, "CELERY_TASK_REPLAY_CLEANUP_BATCH_SIZE", 1000)
    )
    if not 1 <= batch_size <= 10000:
        raise TaskProvenanceError("Celery replay cleanup batch size is invalid")
    cutoff = current_time - timedelta(seconds=configured_retention)
    with transaction.atomic():
        execution_keys = list(
            CoreCeleryTaskReplay.objects.filter(
                status__in=(
                    CoreCeleryTaskReplay.Status.COMPLETE,
                    CoreCeleryTaskReplay.Status.RETRY,
                ),
                completed_at__isnull=False,
                last_seen_at__lte=cutoff,
            )
            .order_by("last_seen_at", "execution_key")
            .values_list("execution_key", flat=True)[:batch_size]
        )
        if not execution_keys:
            return 0
        deleted, _details = CoreCeleryTaskReplay.objects.filter(
            execution_key__in=execution_keys,
            status__in=(
                CoreCeleryTaskReplay.Status.COMPLETE,
                CoreCeleryTaskReplay.Status.RETRY,
            ),
            completed_at__isnull=False,
            last_seen_at__lte=cutoff,
        ).delete()
    return deleted


class AuthenticatedTask(Task):
    """Celery base task that verifies provenance before application code."""

    abstract = True

    def before_start(self, task_id, args, kwargs):
        if not _security_required():
            return super().before_start(task_id, args, kwargs)
        try:
            config = _security_configuration(publishing=False)
            envelope, envelope_digest, execution_key = _validated_envelope(
                config=config,
                task_name=self.name,
                task_id=str(task_id),
                task_args=args,
                task_kwargs=kwargs,
                request=self.request,
            )
            disposition = _register_delivery(
                execution_key=execution_key,
                envelope_digest=envelope_digest,
                envelope=envelope,
                redelivered=bool(
                    (getattr(self.request, "delivery_info", {}) or {}).get(
                        "redelivered"
                    )
                ),
            )
        except TaskProvenanceError as error:
            raise Reject(f"BackupSheep rejected unauthenticated task: {error}", requeue=False)
        except DatabaseError as error:
            raise Reject(
                "BackupSheep task replay ledger is temporarily unavailable",
                requeue=True,
            ) from error
        if disposition in {
            "completed-replay",
            "alternate-replay",
            "active-replay",
        }:
            raise Ignore()
        self.request.backupsheep_execution_key = execution_key

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        execution_key = getattr(self.request, "backupsheep_execution_key", "")
        try:
            _complete_delivery(execution_key, "retry")
        except DatabaseError:
            pass
        return super().on_retry(exc, task_id, args, kwargs, einfo)

    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        execution_key = getattr(self.request, "backupsheep_execution_key", "")
        if status != states.RETRY:
            try:
                _complete_delivery(execution_key, "complete")
            except DatabaseError:
                pass
        return super().after_return(status, retval, task_id, args, kwargs, einfo)


def mark_worker_ready(sender=None, **_kwargs) -> None:
    """Publish a non-secret readiness witness after the AMQP consumer is live."""

    if not _security_required():
        return
    config = _security_configuration(publishing=False)
    parent = WORKER_READY_FILE.parent
    temporary = parent / f".{WORKER_READY_FILE.name}.{os.getpid()}"
    try:
        metadata = parent.stat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise TaskProvenanceError("worker readiness directory is not private")
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.write(descriptor, f"{config.lane}\n".encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, WORKER_READY_FILE)
    except (OSError, UnicodeEncodeError) as error:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise TaskProvenanceError(
            "could not publish the authenticated worker readiness witness"
        ) from error


def validate_startup_task_manifest(sender=None, **_kwargs) -> None:
    """Fail worker/Beat startup when registrations or routes drift from review."""

    if not _security_required():
        return
    app = getattr(sender, "app", None)
    if app is None and hasattr(sender, "tasks"):
        app = sender
    if app is None:
        app = current_app
    try:
        validate_configured_routes(getattr(settings, "CELERY_TASK_ROUTES", {}))
        validate_registered_tasks(app.tasks, required_base=AuthenticatedTask)
    except TaskManifestError as error:
        raise TaskProvenanceError(
            f"Celery startup refused task-manifest drift: {error}"
        ) from error


def install_task_security() -> None:
    before_task_publish.connect(sign_task_message, weak=False)
    worker_init.connect(validate_startup_task_manifest, weak=False)
    beat_init.connect(validate_startup_task_manifest, weak=False)
    worker_ready.connect(mark_worker_ready, weak=False)
