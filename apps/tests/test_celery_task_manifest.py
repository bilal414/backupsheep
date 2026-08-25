import ast
import importlib
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.conf import settings
from django.core.management.base import CommandError
from django.test import SimpleTestCase

from backupsheep import celery_security
from backupsheep.celery_task_manifest import (
    CELERY_FRAMEWORK_TASKS,
    RISKY_TASKS,
    TASK_POLICIES,
    TaskManifestError,
    celery_routes,
    validate_configured_routes,
    validate_registered_tasks,
)
from backupsheep.celery_task_intent import (
    INTENT_RESOLVERS,
    TaskIntentError,
    notification_fanout_task_id,
    resolve_task_intent,
)


def _decorated_production_tasks():
    root = Path(settings.BASE_DIR) / "apps" / "_tasks"
    names = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if (
                    not isinstance(decorator, ast.Call)
                    or not isinstance(decorator.func, ast.Attribute)
                    or decorator.func.attr != "task"
                ):
                    continue
                name = node.name
                for keyword in decorator.keywords:
                    if (
                        keyword.arg == "name"
                        and isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                    ):
                        name = keyword.value.value
                names.append(name)
    return names


class CeleryTaskManifestTests(SimpleTestCase):
    def test_every_production_task_has_one_explicit_manifest_entry(self):
        decorated = _decorated_production_tasks()
        self.assertEqual(len(decorated), len(set(decorated)))
        self.assertEqual(set(decorated), set(TASK_POLICIES))
        self.assertNotIn("backupsheep.celery.debug_task", TASK_POLICIES)
        self.assertLessEqual(
            {policy.intent for policy in TASK_POLICIES.values()},
            set(INTENT_RESOLVERS),
        )

    def test_settings_routes_are_exactly_derived_from_manifest(self):
        validate_configured_routes(settings.CELERY_TASK_ROUTES)
        self.assertEqual(settings.CELERY_TASK_ROUTES, celery_routes())
        self.assertIs(settings.CELERY_TASK_IGNORE_RESULT, True)
        self.assertTrue(
            all("*" not in task_name for task_name in settings.CELERY_TASK_ROUTES)
        )

    def test_runtime_registry_matches_after_all_reviewed_imports(self):
        from backupsheep.celery import app

        for module_name in settings.CELERY_IMPORTS:
            importlib.import_module(module_name)
        app.finalize()
        validate_registered_tasks(
            app.tasks, required_base=celery_security.AuthenticatedTask
        )
        self.assertTrue(CELERY_FRAMEWORK_TASKS <= set(app.tasks))

    def test_registry_and_route_drift_fail_closed(self):
        with self.assertRaises(TaskManifestError):
            validate_registered_tasks(
                {
                    **{name: object() for name in TASK_POLICIES},
                    **{name: object() for name in CELERY_FRAMEWORK_TASKS},
                    "new_task": object(),
                }
            )
        registry = {
            **{name: object() for name in TASK_POLICIES},
            **{name: object() for name in CELERY_FRAMEWORK_TASKS},
        }
        with self.assertRaisesRegex(TaskManifestError, "authenticated base"):
            validate_registered_tasks(registry, required_base=celery_security.AuthenticatedTask)
        routes = celery_routes()
        routes.pop(next(iter(routes)))
        with self.assertRaises(TaskManifestError):
            validate_configured_routes(routes)

    def test_publisher_matrix_has_no_blanket_control_grant(self):
        self.assertNotIn(
            "app", TASK_POLICIES["cleanup_database_ciphertext_fence"].publishers
        )
        self.assertNotIn(
            "beat", TASK_POLICIES["restore_database_backup"].publishers
        )
        self.assertEqual(
            TASK_POLICIES["delete_cloud_node_requested"].publishers,
            frozenset(("app", "cloud")),
        )
        self.assertEqual(
            TASK_POLICIES["delete_local_node_requested"].publishers,
            frozenset(("app", "storage")),
        )
        self.assertEqual(
            TASK_POLICIES["maintain_managed_ssh_database_operations"].publishers,
            frozenset(("beat", "database")),
        )
        self.assertEqual(
            TASK_POLICIES["maintain_managed_ssh_files_operations"].publishers,
            frozenset(("beat", "files")),
        )
        self.assertEqual(
            TASK_POLICIES["prepare_local_backup_destinations"].publishers,
            frozenset(("database", "files", "storage")),
        )
        for task_name in (
            "backup_database",
            "backup_website",
            "backup_wordpress",
            "backup_basecamp",
        ):
            self.assertIn("storage", TASK_POLICIES[task_name].publishers)
        for task_name, policy in TASK_POLICIES.items():
            if task_name.startswith("backup_"):
                self.assertNotIn(
                    "beat",
                    policy.publishers,
                    f"Beat must publish only the durable scheduler task: {task_name}",
                )
        self.assertTrue(
            all(TASK_POLICIES[name].intent not in {"", "message"} for name in RISKY_TASKS)
        )

    def test_backup_intent_binds_every_execution_argument_to_outbox_payload(self):
        from apps.console.backup.models import CoreBackupRequest

        payload = {
            "node_id": 17,
            "schedule_id": None,
            "storage_ids": [3, 9],
            "notes": "reviewed",
            "resume": True,
        }
        request = SimpleNamespace(
            pk=5,
            correlation_id=uuid.uuid4(),
            task_id="stable-backup-task",
            task_name="backup_website",
            node_id=17,
            payload=payload,
        )
        with mock.patch.object(CoreBackupRequest, "objects") as manager:
            manager.filter.return_value.first.return_value = request
            intent = resolve_task_intent(
                task_name="backup_website",
                task_id=request.task_id,
                args=[],
                kwargs=payload,
                publisher="app",
                intent="backup_request",
            )
            self.assertIn("payload_sha256", intent)

            with self.assertRaisesRegex(TaskIntentError, "differs"):
                resolve_task_intent(
                    task_name="backup_website",
                    task_id=request.task_id,
                    args=[],
                    kwargs={**payload, "storage_ids": [3]},
                    publisher="app",
                    intent="backup_request",
                )

    def test_destination_intent_binds_model_lane_phase_and_request_digest(self):
        from apps._tasks.integration.storage import tasks as storage_tasks
        from apps.console.utils.models import UtilBackup

        source_task_id = "a-source-task"
        backup = SimpleNamespace(
            pk=71,
            node_id=19,
            celery_task_id=source_task_id,
            status=UtilBackup.Status.IN_PROGRESS,
            _meta=SimpleNamespace(label_lower="apps.corewebsitebackup"),
            node=SimpleNamespace(
                _destination_request_digest=mock.Mock(return_value="request-digest"),
                local_destination_preparation_task_id=mock.Mock(),
            ),
        )
        model = SimpleNamespace(objects=mock.Mock())
        model.objects.select_related.return_value.filter.return_value.first.return_value = (
            backup
        )
        phase_task_id = uuid.uuid5(
            uuid.NAMESPACE_URL,
            "backupsheep:local-destination:"
            f"{backup._meta.label_lower}:{backup.pk}:{source_task_id}",
        ).hex
        backup.node.local_destination_preparation_task_id.return_value = phase_task_id

        with mock.patch.dict(storage_tasks._BACKUP_MODELS, {"website": model}):
            intent = resolve_task_intent(
                task_name="prepare_local_backup_destinations",
                task_id=phase_task_id,
                args=["website", backup.pk],
                kwargs={},
                publisher="files",
                intent="backup_destination",
            )
            self.assertEqual(intent["request_digest"], "request-digest")
            self.assertEqual(intent["source_task_id"], source_task_id)
            with self.assertRaisesRegex(TaskIntentError, "does not own"):
                resolve_task_intent(
                    task_name="prepare_local_backup_destinations",
                    task_id=phase_task_id,
                    args=["website", backup.pk],
                    kwargs={},
                    publisher="database",
                    intent="backup_destination",
                )
            with self.assertRaisesRegex(TaskIntentError, "not reserved"):
                resolve_task_intent(
                    task_name="prepare_local_backup_destinations",
                    task_id="wrong-phase-id",
                    args=["website", backup.pk],
                    kwargs={},
                    publisher="storage",
                    intent="backup_destination",
                )

    def test_storage_upload_intent_requires_owning_source_lane_and_witness(self):
        from apps._tasks.integration.storage import tasks as storage_tasks

        point = SimpleNamespace(
            pk=83,
            _meta=SimpleNamespace(label_lower="apps.corewebsitebackupstoragepoints"),
        )
        relation = SimpleNamespace(filter=mock.Mock())
        relation.filter.return_value.first.return_value = point
        backup = SimpleNamespace(
            pk=71,
            node_id=19,
            stored_website_backups=relation,
            _meta=SimpleNamespace(label_lower="apps.corewebsitebackup"),
        )
        node = SimpleNamespace(
            pk=19,
            _local_backup_model_key=mock.Mock(return_value="website"),
            authorized_local_destination_point_ids=mock.Mock(return_value=[point.pk]),
        )
        model = SimpleNamespace(objects=mock.Mock())
        model.objects.filter.return_value.first.return_value = backup

        with mock.patch.dict(storage_tasks._BACKUP_MODELS, {"website": model}), mock.patch(
            "apps.console.node.models.CoreNode.objects.filter"
        ) as node_filter:
            node_filter.return_value.first.return_value = node
            intent = resolve_task_intent(
                task_name="storage_upload",
                task_id="upload-id",
                args=[node.pk, backup.pk, point.pk],
                kwargs={},
                publisher="files",
                intent="storage_upload",
            )
            self.assertEqual(intent["model_key"], "website")
            with self.assertRaisesRegex(TaskIntentError, "does not own"):
                resolve_task_intent(
                    task_name="storage_upload",
                    task_id="forged-upload-id",
                    args=[node.pk, backup.pk, point.pk],
                    kwargs={},
                    publisher="database",
                    intent="storage_upload",
                )
            node.authorized_local_destination_point_ids.return_value = []
            with self.assertRaisesRegex(TaskIntentError, "authorization"):
                resolve_task_intent(
                    task_name="storage_upload",
                    task_id="unwitnessed-upload-id",
                    args=[node.pk, backup.pk, point.pk],
                    kwargs={},
                    publisher="files",
                    intent="storage_upload",
                )

    def test_restore_ciphertext_intent_requires_reserved_phase_id_and_lane(self):
        from apps._tasks.artifact_encryption import local_restore_phase_task_id
        from apps._tasks.integration.storage import tasks as storage_tasks

        statuses = SimpleNamespace(PENDING=1, COMPLETE=3, FAILED=4)
        restore = SimpleNamespace(
            pk=73,
            backup_id=27,
            storage_point_id=91,
            celery_task_id="source-restore-task",
            correlation_id=uuid.uuid4(),
            status=statuses.PENDING,
            execution_metadata={},
            Status=statuses,
            _meta=SimpleNamespace(label_lower="apps.corewebsiterestore"),
        )
        model = SimpleNamespace(objects=mock.Mock())
        model.objects.filter.return_value.first.return_value = restore
        stage_id = local_restore_phase_task_id(restore, "stage")

        with mock.patch.dict(storage_tasks._LOCAL_RESTORE_MODELS, {"website": model}):
            intent = resolve_task_intent(
                task_name="stage_local_restore_ciphertext",
                task_id=stage_id,
                args=["website", restore.pk],
                kwargs={},
                publisher="files",
                intent="restore_ciphertext",
            )
            self.assertEqual(intent["phase_task_id"], stage_id)
            self.assertEqual(intent["storage_point_id"], restore.storage_point_id)
            with self.assertRaisesRegex(TaskIntentError, "does not own"):
                resolve_task_intent(
                    task_name="stage_local_restore_ciphertext",
                    task_id=stage_id,
                    args=["website", restore.pk],
                    kwargs={},
                    publisher="database",
                    intent="restore_ciphertext",
                )
            with self.assertRaisesRegex(TaskIntentError, "not reserved"):
                resolve_task_intent(
                    task_name="stage_local_restore_ciphertext",
                    task_id="unreserved-id",
                    args=["website", restore.pk],
                    kwargs={},
                    publisher="storage",
                    intent="restore_ciphertext",
                )

            restore.status = statuses.COMPLETE
            restore.execution_metadata = {
                "local_restore_ciphertext_handoff": {"status": "authenticated"}
            }
            cleanup_id = local_restore_phase_task_id(restore, "cleanup")
            cleanup = resolve_task_intent(
                task_name="cleanup_local_restore_ciphertext",
                task_id=cleanup_id,
                args=["website", restore.pk],
                kwargs={},
                publisher="files",
                intent="restore_ciphertext",
            )
            self.assertEqual(cleanup["phase"], "cleanup")

    def test_restore_handoff_publishers_set_reserved_phase_ids(self):
        restore_common = (
            Path(settings.BASE_DIR) / "apps/_tasks/integration/restore_common.py"
        ).read_text(encoding="utf-8")
        restore_tasks = (
            Path(settings.BASE_DIR) / "apps/_tasks/integration/restore.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'task_id=local_restore_phase_task_id(restore, "stage")',
            restore_common,
        )
        self.assertIn(
            'task_id=local_restore_phase_task_id(restore, "cleanup")',
            restore_tasks,
        )

    def test_source_log_publication_reads_only_id_and_uses_content_bound_task_id(self):
        from apps.console.log.models import CoreLog

        data = {
            "sender_name": "BackupSheep - Notification Bot",
            "message": "opaque database value",
            "notification_fanout_status": "pending",
        }
        task_id = notification_fanout_task_id(41, data)
        manager = mock.Mock()
        manager.only.return_value.filter.return_value.exists.return_value = True
        with mock.patch.object(CoreLog, "objects", manager):
            intent = resolve_task_intent(
                task_name="send_log_to_db",
                task_id=task_id,
                args=[41],
                kwargs={},
                publisher="files",
                intent="log_record",
                phase="publish",
            )
        self.assertEqual(
            intent,
            {"kind": "notification-fanout", "id": 41, "task_id": task_id},
        )
        manager.only.assert_called_once_with("pk")
        with self.assertRaisesRegex(TaskIntentError, "malformed"):
            resolve_task_intent(
                task_name="send_log_to_db",
                task_id="attacker-selected",
                args=[41],
                kwargs={},
                publisher="database",
                intent="log_record",
                phase="publish",
            )

    def test_managed_ssh_maintenance_runs_within_operation_ttl(self):
        expected = {
            "maintain-managed-ssh-database-operations": (
                "maintain_managed_ssh_database_operations",
                "database",
            ),
            "maintain-managed-ssh-files-operations": (
                "maintain_managed_ssh_files_operations",
                "files",
            ),
        }
        for schedule_name, (task_name, queue) in expected.items():
            entry = settings.CELERY_BEAT_SCHEDULE[schedule_name]
            self.assertEqual(entry["task"], task_name)
            self.assertGreater(entry["schedule"], 0)
            self.assertLess(entry["schedule"], 300)
            self.assertEqual(TASK_POLICIES[task_name].queue, queue)
            self.assertEqual(
                TASK_POLICIES[task_name].publishers,
                frozenset(("beat", queue)),
            )

    def test_worker_startup_gate_rejects_unregistered_task(self):
        registry = {
            **{name: object() for name in TASK_POLICIES},
            **{name: object() for name in CELERY_FRAMEWORK_TASKS},
            "attacker.injected": object(),
        }
        with mock.patch.dict(
            "os.environ", {"BACKUPSHEEP_CELERY_SECURITY_REQUIRED": "true"}
        ):
            with self.assertRaisesRegex(
                celery_security.TaskProvenanceError, "startup refused"
            ):
                celery_security.validate_startup_task_manifest(
                    sender=SimpleNamespace(app=SimpleNamespace(tasks=registry))
                )

    def test_stock_preflight_rejects_route_manifest_drift(self):
        from apps.management.commands.docker_preflight import (
            _assert_celery_task_manifest,
        )

        routes = celery_routes()
        routes.pop(next(iter(routes)))
        with self.assertRaisesRegex(CommandError, "task manifest drifted"):
            _assert_celery_task_manifest(
                SimpleNamespace(CELERY_TASK_ROUTES=routes, CELERY_IMPORTS=())
            )
