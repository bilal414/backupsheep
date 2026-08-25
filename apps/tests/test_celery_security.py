import copy
import json
import os
import tempfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from celery import Celery, states
from celery.worker.request import Request as WorkerRequest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.test import TestCase, override_settings
from django.utils import timezone
from kombu.utils import json as kombu_json

from apps.console.task_security.models import CoreCeleryTaskReplay
from backupsheep import celery_security


@override_settings(
    CELERY_TASK_DEFAULT_QUEUE="default",
    CELERY_TASK_ROUTES={
        "backup_database": {"queue": "database"},
        "backup_website": {"queue": "files"},
        "delete_from_disk": {"queue": "storage"},
        "send_log_to_db": {"queue": "logs"},
        "cloud_task": {"queue": "cloud"},
        "cleanup_database_ciphertext_fence": {"queue": "database"},
        "cleanup_files_ciphertext_fence": {"queue": "files"},
        "stage_local_restore_ciphertext": {"queue": "storage"},
        "cleanup_local_restore_ciphertext": {"queue": "storage"},
    },
)
class CeleryTaskEnvelopeTests(TestCase):
    installation_id = "a" * 64

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.secret_root = Path(self.temporary.name)
        self.keys = {}
        self.public_keys = {}
        public_keys = {}
        for lane in celery_security.LANES:
            key = Ed25519PrivateKey.generate()
            self.keys[lane] = key
            private_path = self.secret_root / f"celery_signing_{lane}_private_key"
            private_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.OpenSSH,
                    serialization.NoEncryption(),
                )
            )
            private_path.chmod(0o600)
            public_keys[lane] = key.public_key().public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH,
            ).decode("ascii")
        self.public_keys = public_keys
        self.registry = self.secret_root / "celery_trusted_public_keys"
        self.registry.write_text(
            json.dumps(
                {
                    "version": celery_security.ENVELOPE_VERSION,
                    "installation_id": self.installation_id,
                    "generation": 1,
                    "keys": public_keys,
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        self.registry.chmod(0o600)
        self.root_patch = mock.patch.object(
            celery_security, "SECRET_ROOT", self.secret_root
        )
        self.root_patch.start()
        self.intent_patch = mock.patch.object(
            celery_security,
            "resolve_task_intent",
            return_value={"kind": "test-intent", "id": "stable"},
        )
        self.intent_patch.start()

    def tearDown(self):
        self.intent_patch.stop()
        self.root_patch.stop()
        self.temporary.cleanup()

    def config(self, lane):
        return celery_security.SecurityConfiguration(
            installation_id=self.installation_id,
            lane=lane,
            private_key_file=str(
                self.secret_root / f"celery_signing_{lane}_private_key"
            ),
            public_keys_file=str(self.registry),
        )

    @staticmethod
    def headers(task="backup_database", task_id="durable-id", retries=0):
        return {
            "task": task,
            "id": task_id,
            "retries": retries,
            "eta": "2026-08-26T12:00:00+00:00",
            "expires": "2026-08-27T12:00:00+00:00",
            "timelimit": [7200, 7100],
            "root_id": "root-id",
            "parent_id": "parent-id",
            "group": "group-id",
            "group_index": 2,
            "replaced_task_nesting": 1,
            "stamped_headers": ["tenant"],
            "stamps": {"tenant": "installation"},
            "utc": True,
            "ignore_result": True,
            "lang": "py",
            "meth": None,
            "shadow": "reviewed-shadow",
            "origin": "reviewed-origin",
            "argsrepr": "[123]",
            "kwargsrepr": "{'force': False}",
            "compression": None,
        }

    @staticmethod
    def body():
        return (
            [123],
            {"force": False},
            {
                "callbacks": None,
                "errbacks": None,
                "chain": None,
                "chord": None,
            },
        )

    def request(self, envelope, headers=None, body=None, redelivered=False):
        headers = headers or self.headers()
        body = body or self.body()
        _args, _kwargs, embed = body
        values = {
            name: headers.get(name)
            for name in celery_security.EXECUTION_HEADER_FIELDS
        }
        return SimpleNamespace(
            headers={celery_security.AUTH_HEADER: envelope},
            delivery_info={
                "exchange": envelope["exchange"],
                "routing_key": envelope["queue"],
                "redelivered": redelivered,
            },
            retries=headers["retries"],
            callbacks=embed.get("callbacks"),
            errbacks=embed.get("errbacks"),
            chain=embed.get("chain"),
            chord=embed.get("chord"),
            **values,
        )

    def envelope(self, *, lane="app", headers=None, body=None, now=1000):
        headers = headers or self.headers()
        body = body or self.body()
        queue, _target, exchange = celery_security._task_destination(headers["task"])
        return celery_security._build_envelope(
            config=self.config(lane),
            headers=headers,
            body=body,
            exchange=exchange,
            routing_key=queue,
            now=now,
        )

    def validate(self, envelope, *, headers=None, body=None, now=1000):
        headers = headers or self.headers()
        body = body or self.body()
        return celery_security._validated_envelope(
            config=celery_security.SecurityConfiguration(
                installation_id=self.installation_id,
                lane=envelope["target"],
                private_key_file="",
                public_keys_file=str(self.registry),
            ),
            task_name=headers["task"],
            task_id=headers["id"],
            task_args=body[0],
            task_kwargs=body[1],
            request=self.request(envelope, headers=headers, body=body),
            now=now,
        )

    def test_signed_delayed_task_validates_only_within_reviewed_maximum_age(self):
        envelope = self.envelope(now=1000)
        validated, _digest, _execution_key = self.validate(envelope, now=100000)
        self.assertEqual(validated["publisher"], "app")
        self.assertEqual(validated["target"], "database")
        self.assertEqual(
            validated["expires_at"],
            1000 + celery_security.task_policy("backup_database").max_age_seconds,
        )
        with self.assertRaises(celery_security.TaskProvenanceError):
            self.validate(envelope, now=validated["expires_at"] + 1)

    def test_key_generation_rotation_immediately_retires_old_signatures(self):
        envelope = self.envelope(now=1000)
        self.registry.write_text(
            json.dumps(
                {
                    "version": celery_security.ENVELOPE_VERSION,
                    "installation_id": self.installation_id,
                    "generation": 2,
                    "keys": self.public_keys,
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            celery_security.TaskProvenanceError, "generation"
        ):
            self.validate(envelope, now=1000)

    def test_durable_intent_is_required_and_rechecked_by_consumer(self):
        celery_security.resolve_task_intent.side_effect = (
            celery_security.TaskIntentError("missing durable row")
        )
        with self.assertRaisesRegex(
            celery_security.TaskProvenanceError, "durable intent"
        ):
            self.envelope()

        celery_security.resolve_task_intent.side_effect = None
        celery_security.resolve_task_intent.return_value = {
            "kind": "test-intent",
            "id": "published",
        }
        envelope = self.envelope()
        celery_security.resolve_task_intent.return_value = {
            "kind": "test-intent",
            "id": "changed",
        }
        with self.assertRaisesRegex(
            celery_security.TaskProvenanceError, "intent changed"
        ):
            self.validate(envelope)

    def test_body_signature_and_route_tampering_fail_closed(self):
        envelope = self.envelope()
        tampered_body = ([999], self.body()[1], self.body()[2])
        with self.assertRaises(celery_security.TaskProvenanceError):
            self.validate(envelope, body=tampered_body)

        tampered = copy.deepcopy(envelope)
        tampered["queue"] = "files"
        with self.assertRaises(celery_security.TaskProvenanceError):
            self.validate(tampered)

        tampered = copy.deepcopy(envelope)
        tampered["publisher"] = "beat"
        with self.assertRaises(celery_security.TaskProvenanceError):
            self.validate(tampered)

    def test_every_execution_relevant_header_is_authenticated(self):
        envelope = self.envelope()
        for field in celery_security.EXECUTION_HEADER_FIELDS:
            changed = self.headers()
            changed[field] = "tampered"
            with self.subTest(field=field), self.assertRaises(
                celery_security.TaskProvenanceError
            ):
                self.validate(envelope, headers=changed)

    def test_unreviewed_custom_header_is_authenticated(self):
        headers = {**self.headers(), "audit_label": "reviewed"}
        envelope = self.envelope(headers=headers)
        request = self.request(envelope, headers=headers)
        request.headers["audit_label"] = "tampered"
        with self.assertRaises(celery_security.TaskProvenanceError):
            celery_security._validated_envelope(
                config=celery_security.SecurityConfiguration(
                    installation_id=self.installation_id,
                    lane="database",
                    private_key_file="",
                    public_keys_file=str(self.registry),
                ),
                task_name=headers["task"],
                task_id=headers["id"],
                task_args=self.body()[0],
                task_kwargs=self.body()[1],
                request=request,
                now=1000,
            )

    def test_real_protocol_two_round_trip_preserves_authenticated_values(self):
        app = Celery("celery-security-parity")

        @app.task(name="backup_database")
        def parity_task(*_args, **_kwargs):
            return None

        message = app.amqp.as_task_v2(
            "durable-id",
            "backup_database",
            args=[123],
            kwargs={"force": False},
            eta="2026-08-26T12:00:00+00:00",
            expires="2026-08-27T12:00:00+00:00",
            group_id="group-id",
            group_index=2,
            retries=3,
            time_limit=7200,
            soft_time_limit=7100,
            root_id="root-id",
            parent_id="parent-id",
            shadow="reviewed-shadow",
            origin="reviewed-origin",
            ignore_result=True,
            argsrepr="[123]",
            kwargsrepr="{'force': False}",
            stamped_headers=["tenant"],
            tenant="installation",
            replaced_task_nesting=1,
            callbacks=[{"task": "send_log_to_db", "args": [7]}],
            errbacks=[{"task": "send_log_to_db", "args": [8]}],
            chain=[{"task": "delete_from_disk", "args": ["id"]}],
            chord={"task": "send_log_to_db", "args": [9]},
        )
        wire_headers = kombu_json.loads(kombu_json.dumps(message.headers))
        wire_headers["audit_label"] = "reviewed"
        wire_body = kombu_json.loads(kombu_json.dumps(message.body))
        fake_message = SimpleNamespace(
            headers=wire_headers,
            body=wire_body,
            payload=wire_body,
            content_type="application/json",
            content_encoding="utf-8",
            delivery_info={"exchange": "backupsheep.database", "routing_key": "database"},
            properties={},
        )
        worker_request = WorkerRequest(
            fake_message,
            app=app,
            task=parity_task,
            decoded=True,
        )
        consumer_context = worker_request._context

        self.assertEqual(
            celery_security._execution_headers_digest(wire_headers),
            celery_security._execution_headers_digest(consumer_context),
        )
        self.assertEqual(
            celery_security._custom_headers_digest(wire_headers),
            celery_security._custom_headers_digest(consumer_context),
        )
        self.assertEqual(
            celery_security._body_digest(wire_body),
            celery_security._request_body_digest(
                wire_body[0], wire_body[1], consumer_context
            ),
        )

    def test_compromised_lane_cannot_forge_another_lane_or_cross_policy(self):
        headers = self.headers(task="backup_website")
        with self.assertRaises(celery_security.TaskProvenanceError):
            self.envelope(lane="database", headers=headers)

        storage_headers = self.headers(task="delete_from_disk")
        storage_envelope = self.envelope(lane="database", headers=storage_headers)
        self.validate(storage_envelope, headers=storage_headers)

        recovery_envelope = self.envelope(lane="cloud", headers=headers)
        self.validate(recovery_envelope, headers=headers)

        cleanup_headers = self.headers(task="cleanup_database_ciphertext_fence")
        cleanup_envelope = self.envelope(lane="storage", headers=cleanup_headers)
        self.validate(cleanup_envelope, headers=cleanup_headers)
        with self.assertRaises(celery_security.TaskProvenanceError):
            self.envelope(lane="files", headers=cleanup_headers)

        files_cleanup_headers = self.headers(task="cleanup_files_ciphertext_fence")
        files_cleanup_envelope = self.envelope(
            lane="storage", headers=files_cleanup_headers
        )
        self.validate(files_cleanup_envelope, headers=files_cleanup_headers)

        restore_stage_headers = self.headers(task="stage_local_restore_ciphertext")
        restore_stage_envelope = self.envelope(
            lane="database", headers=restore_stage_headers
        )
        self.validate(restore_stage_envelope, headers=restore_stage_headers)
        with self.assertRaises(celery_security.TaskProvenanceError):
            self.envelope(lane="cloud", headers=restore_stage_headers)

        restore_cleanup_headers = self.headers(
            task="cleanup_local_restore_ciphertext"
        )
        restore_cleanup_envelope = self.envelope(
            lane="files", headers=restore_cleanup_headers
        )
        self.validate(restore_cleanup_envelope, headers=restore_cleanup_headers)

        with self.assertRaises(celery_security.TaskProvenanceError):
            self.envelope(lane="app", headers=cleanup_headers)

        unreviewed = self.headers(task="unreviewed_new_task")
        with self.assertRaisesRegex(
            celery_security.TaskProvenanceError, "reviewed manifest"
        ):
            self.envelope(lane="app", headers=unreviewed)

    def test_key_files_must_be_direct_regular_nonlinked_secrets(self):
        original = self.secret_root / "celery_signing_app_private_key"
        symlink = self.secret_root / "symlink-key"
        symlink.symlink_to(original)
        with self.assertRaises(celery_security.TaskProvenanceError):
            celery_security._load_private_key(str(symlink))

        hardlink = self.secret_root / "hardlink-key"
        os.link(original, hardlink)
        with self.assertRaises(celery_security.TaskProvenanceError):
            celery_security._load_private_key(str(original))

    def test_replay_ledger_allows_only_unfinished_broker_redelivery(self):
        envelope = self.envelope()
        _, envelope_digest, execution_key = self.validate(envelope)
        arguments = {
            "execution_key": execution_key,
            "envelope_digest": envelope_digest,
            "envelope": envelope,
        }
        self.assertEqual(
            celery_security._register_delivery(**arguments, redelivered=False), "new"
        )
        self.assertEqual(
            celery_security._register_delivery(**arguments, redelivered=False),
            "active-replay",
        )
        self.assertEqual(
            celery_security._register_delivery(**arguments, redelivered=True),
            "redelivery",
        )
        altered = {**arguments, "envelope_digest": "f" * 64}
        self.assertEqual(
            celery_security._register_delivery(**altered, redelivered=True),
            "alternate-replay",
        )
        celery_security._complete_delivery(execution_key, "retry")
        self.assertEqual(
            celery_security._register_delivery(**arguments, redelivered=True),
            "completed-replay",
        )
        self.assertEqual(
            CoreCeleryTaskReplay.objects.get(pk=execution_key).status,
            CoreCeleryTaskReplay.Status.RETRY,
        )

    def test_fresh_signed_recovery_of_same_durable_task_is_not_a_broker_replay(self):
        first = self.envelope()
        _first, first_digest, first_key = self.validate(first)
        self.assertEqual(
            celery_security._register_delivery(
                execution_key=first_key,
                envelope_digest=first_digest,
                envelope=first,
                redelivered=False,
            ),
            "new",
        )
        celery_security._complete_delivery(first_key, "complete")

        # A durable recovery sweep may republish the same task id after losing the
        # broker. Its newly signed nonce is a distinct authorized publication, while
        # replaying either exact signed envelope still resolves to its existing row.
        second = self.envelope()
        _second, second_digest, second_key = self.validate(second)
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first_key, second_key)
        self.assertEqual(
            celery_security._register_delivery(
                execution_key=second_key,
                envelope_digest=second_digest,
                envelope=second,
                redelivered=False,
            ),
            "new",
        )
        self.assertEqual(
            celery_security._register_delivery(
                execution_key=first_key,
                envelope_digest=first_digest,
                envelope=first,
                redelivered=True,
            ),
            "completed-replay",
        )

    def test_retry_after_return_does_not_overwrite_retry_state(self):
        task = celery_security.AuthenticatedTask()
        task.bind(Celery("retry-state-test"))
        task.push_request(backupsheep_execution_key="execution-key")
        try:
            complete_patch = mock.patch(
                "backupsheep.celery_security._complete_delivery"
            )
            complete = complete_patch.start()
            task.on_retry(Exception("retry"), "id", (), {}, None)
            task.after_return(states.RETRY, None, "id", (), {}, None)
            complete.assert_called_once_with("execution-key", "retry")
            task.after_return(states.SUCCESS, None, "id", (), {}, None)
            self.assertEqual(complete.call_args_list[-1].args, ("execution-key", "complete"))
        finally:
            complete_patch.stop()
            task.pop_request()

    @override_settings(
        CELERY_TASK_REPLAY_RETENTION_SECONDS=14 * 24 * 60 * 60,
        CELERY_TASK_REPLAY_CLEANUP_BATCH_SIZE=100,
    )
    def test_replay_cleanup_deletes_only_expired_terminal_rows(self):
        now = timezone.now()

        def create(key, status, completed_at):
            row = CoreCeleryTaskReplay.objects.create(
                execution_key=key * 64,
                envelope_digest=key.upper() * 64,
                task_id=f"task-{key}",
                task_name="backup_database",
                publisher_lane="app",
                target_lane="database",
                status=status,
                completed_at=completed_at,
            )
            CoreCeleryTaskReplay.objects.filter(pk=row.pk).update(
                completed_at=completed_at,
                last_seen_at=completed_at,
            )
            return row

        old = now - timedelta(days=15)
        recent = now - timedelta(days=1)
        create("a", CoreCeleryTaskReplay.Status.COMPLETE, old)
        create("b", CoreCeleryTaskReplay.Status.RETRY, old)
        create("c", CoreCeleryTaskReplay.Status.ACTIVE, old)
        create("d", CoreCeleryTaskReplay.Status.COMPLETE, recent)

        self.assertEqual(
            celery_security.prune_completed_task_replays(now=now), 2
        )
        self.assertEqual(
            set(CoreCeleryTaskReplay.objects.values_list("execution_key", flat=True)),
            {"c" * 64, "d" * 64},
        )
