import uuid
from pathlib import Path
from types import SimpleNamespace

from django.conf import settings
from django.test import SimpleTestCase

from apps._tasks.artifact_encryption import (
    ArtifactPipelineError,
    local_restore_phase_task_id,
)


class RestoreHandoffTaskIdentityTests(SimpleTestCase):
    def test_phase_ids_are_deterministic_restore_bound_and_distinct(self):
        restore = SimpleNamespace(
            pk=41,
            correlation_id=uuid.uuid4(),
            _meta=SimpleNamespace(label_lower="apps.corewebsiterestore"),
        )
        stage = local_restore_phase_task_id(restore, "stage")
        cleanup = local_restore_phase_task_id(restore, "cleanup")

        self.assertEqual(stage, local_restore_phase_task_id(restore, "stage"))
        self.assertNotEqual(stage, cleanup)
        self.assertEqual(len(stage), 32)
        with self.assertRaises(ArtifactPipelineError):
            local_restore_phase_task_id(restore, "unreviewed")

    def test_both_publishers_set_the_reserved_phase_id(self):
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
