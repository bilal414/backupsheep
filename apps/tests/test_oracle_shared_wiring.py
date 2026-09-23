"""Focused regression tests for the shared Oracle Cloud wiring."""

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, override_settings

from apps._tasks.integration.oracle import oracle_retry_token
from apps._tasks.integration.oracle_acceptance import (
    OracleAcceptanceFault,
    maybe_fault_after_accepted_backup,
    maybe_fault_after_accepted_restore,
)
from apps.api.v1.node.views import _validate_oracle_restore_request
from apps.console.backup.models import CoreOracleBackup
from apps.console.node.models import CoreNode, CoreOracle
from apps.console.utils.models import UtilBackup


class OracleSharedWiringTests(SimpleTestCase):
    compartment_id = "ocid1.compartment.oc1..oracle-test"
    availability_domain = "AD-1"
    source_instance_id = "ocid1.instance.oc1..oracle-source"
    source_volume_id = "ocid1.volume.oc1..oracle-volume"
    image_backup_id = "ocid1.image.oc1..oracle-image"
    volume_backup_id = "ocid1.volumebackup.oc1..oracle-volume-backup"

    def _node(self, *, node_type, unique_id, metadata=None):
        connection = SimpleNamespace(
            integration=SimpleNamespace(code="oracle"),
            name="oracle-test-connection",
        )
        oracle = SimpleNamespace(
            unique_id=unique_id,
            metadata=dict(
                {
                    "_bs_compartment_id": self.compartment_id,
                    "_bs_availability_domain": self.availability_domain,
                },
                **(metadata or {}),
            ),
        )
        return SimpleNamespace(
            type=node_type,
            name="oracle-test-node",
            connection=connection,
            oracle=oracle,
        )

    def _backup(self, *, node_type, backup_id, witness):
        state = SimpleNamespace(
            provider_resource_id=backup_id,
            provider_idempotency_key=witness["request_token"],
            provider_metadata={"witness": witness},
        )
        return SimpleNamespace(
            unique_id=backup_id,
            uuid_str=witness["marker"],
            get_execution_state=lambda create=False: state,
        )

    def _oracle_witness(self, *, node_type):
        marker = "backup-marker-001"
        source_id = (
            self.source_instance_id
            if node_type == CoreNode.Type.CLOUD
            else self.source_volume_id
        )
        witness = {
            "provider": "oracle",
            "marker": marker,
            "source_id": source_id,
            "compartment_id": self.compartment_id,
            "request_token": oracle_retry_token(marker),
        }
        if node_type == CoreNode.Type.CLOUD:
            witness["resource_type"] = "compute_image"
            backup_id = self.image_backup_id
        else:
            witness["volume_type"] = "block"
            backup_id = self.volume_backup_id
        return backup_id, witness

    def test_oracle_cloud_route_is_present_in_shared_url_config(self):
        cloud_urls = Path("apps/api/v1/cloud/urls.py").read_text()
        self.assertIn(
            'include("apps.api.v1.cloud.oracle.urls")',
            cloud_urls,
        )
        self.assertTrue(Path("apps/api/v1/cloud/oracle/urls.py").is_file())

    def test_server_setup_and_restore_ui_expose_oracle_scope(self):
        setup = Path(
            "apps/console/_templates/console/setup/_setup_cloud_node.html"
        ).read_text()
        detail = Path(
            "apps/console/_templates/console/node/detail.html"
        ).read_text()
        self.assertNotIn('{% if integration.code != "oracle" %}', setup)
        self.assertIn('integration.code == "oracle"', detail)
        self.assertIn("oracleCompartmentId", detail)
        self.assertIn("oracleAvailabilityDomain", detail)
        self.assertIn("subnet_id", detail)
        self.assertIn("shape", detail)

    def test_core_oracle_delegates_backup_and_restore_to_adapters(self):
        node = self._node(
            node_type=CoreNode.Type.CLOUD,
            unique_id=self.source_instance_id,
        )
        integration = SimpleNamespace(node=node)
        oracle_model = CoreOracle()
        backup = SimpleNamespace(
            uuid_str="backup-marker",
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
        )
        restore_adapter = mock.Mock()
        restore_adapter.restore_snapshot.return_value = "restore-status"
        restore_adapter.check_restore.return_value = "check-status"
        with mock.patch(
            "apps._tasks.integration.oracle.create_or_adopt_oracle_backup",
            return_value="backup-id",
        ) as create, mock.patch(
            "apps._tasks.integration.oracle.OracleRestoreAdapter",
            return_value=restore_adapter,
        ):
            self.assertEqual(CoreOracle.create_snapshot(integration, backup), "backup-id")
            self.assertEqual(
                CoreOracle.restore_snapshot(oracle_model, "backup", "restore"),
                "restore-status",
            )
            self.assertEqual(
                CoreOracle.check_restore(oracle_model, "restore"), "check-status"
            )
        create.assert_called_once_with(node, backup)
        restore_adapter.restore_snapshot.assert_called_once_with("backup", "restore")
        restore_adapter.check_restore.assert_called_once_with("restore")

    def test_core_oracle_backup_delegates_poll_and_delete_to_adapter(self):
        node = self._node(
            node_type=CoreNode.Type.VOLUME,
            unique_id=self.source_volume_id,
            metadata={"_bs_vol_type": "block"},
        )
        account = SimpleNamespace(create_backup_log=mock.Mock())
        node.connection.account = account
        oracle = SimpleNamespace(node=node)

        def bind_execution_fence(owner, token):
            backup._required_backup_lease_owner = owner
            backup._required_backup_lease_token = token
            return backup

        def unbind_execution_fence():
            backup._required_backup_lease_owner = ""
            backup._required_backup_lease_token = ""
            return backup

        backup = SimpleNamespace(
            oracle=oracle,
            pk=101,
            uuid_str="backup-marker",
            unique_id=self.volume_backup_id,
            status=UtilBackup.Status.IN_PROGRESS,
            save=mock.Mock(),
            record_provider_reference=mock.Mock(),
            _enqueue_delete_reconciliation=mock.Mock(),
            bind_execution_fence=mock.Mock(side_effect=bind_execution_fence),
            ensure_execution_fence=mock.Mock(),
            unbind_execution_fence=mock.Mock(side_effect=unbind_execution_fence),
        )
        adapter = mock.Mock()
        adapter.poll_backup.return_value = UtilBackup.Status.COMPLETE
        adapter.delete_backup.return_value = "delete_accepted"
        with mock.patch(
            "apps._tasks.integration.oracle.oracle_backup_adapter",
            return_value=adapter,
        ), mock.patch(
            "apps._tasks.integration.oracle.claim_oracle_delete_reconciliation",
            return_value=(backup, "api-delete-token"),
        ) as claim, mock.patch(
            "apps._tasks.integration.oracle.release_oracle_delete_reconciliation",
            return_value=backup,
        ) as release:
            self.assertEqual(
                CoreOracleBackup.poll_status(backup), UtilBackup.Status.COMPLETE
            )
            self.assertFalse(CoreOracleBackup.soft_delete(backup))

        claim.assert_called_once_with(
            backup,
            mock.ANY,
            mock.ANY,
            allow_initial=True,
        )
        release.assert_called_once_with(
            backup,
            mock.ANY,
            "api-delete-token",
            retry_seconds=mock.ANY,
        )
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_IN_PROGRESS)
        adapter.poll_backup.assert_called_once_with(backup)
        adapter.delete_backup.assert_called_once_with(backup)
        backup._enqueue_delete_reconciliation.assert_called_once_with()
        account.create_backup_log.assert_called_once()

    def test_oracle_restore_validation_accepts_exact_cloud_scope(self):
        node = self._node(
            node_type=CoreNode.Type.CLOUD,
            unique_id=self.source_instance_id,
            metadata={"_bs_shape": "VM.Standard.E4.Flex"},
        )
        backup_id, witness = self._oracle_witness(node_type=CoreNode.Type.CLOUD)
        backup = self._backup(
            node_type=CoreNode.Type.CLOUD,
            backup_id=backup_id,
            witness=witness,
        )
        params = {
            "compartment_id": self.compartment_id,
            "availability_domain": self.availability_domain,
            "shape": "VM.Standard.E4.Flex",
            "subnet_id": "ocid1.subnet.oc1..oracle-subnet",
            "assign_public_ip": False,
        }
        self.assertEqual(
            _validate_oracle_restore_request(node, backup, "oracle-fork-001", params),
            params,
        )

    def test_oracle_restore_validation_rejects_unscoped_or_forged_values(self):
        node = self._node(
            node_type=CoreNode.Type.CLOUD,
            unique_id=self.source_instance_id,
        )
        backup_id, witness = self._oracle_witness(node_type=CoreNode.Type.CLOUD)
        backup = self._backup(
            node_type=CoreNode.Type.CLOUD,
            backup_id=backup_id,
            witness=witness,
        )
        base = {
            "compartment_id": self.compartment_id,
            "availability_domain": self.availability_domain,
            "shape": "VM.Standard.E4.Flex",
            "subnet_id": "ocid1.subnet.oc1..oracle-subnet",
        }
        for field, value in (
            ("compartment_id", "ocid1.compartment.oc1..foreign"),
            ("subnet_id", "not-an-ocid"),
        ):
            with self.subTest(field=field):
                params = dict(base, **{field: value})
                with self.assertRaisesRegex(Exception, "exact source backup"):
                    _validate_oracle_restore_request(
                        node, backup, "oracle-fork-001", params
                    )
        forged = dict(base)
        forged["extra"] = "not-supported"
        with self.assertRaisesRegex(Exception, "exact source backup"):
            _validate_oracle_restore_request(node, backup, "oracle-fork-001", forged)

    def test_oracle_volume_restore_validation_binds_volume_kind_and_scope(self):
        node = self._node(
            node_type=CoreNode.Type.VOLUME,
            unique_id=self.source_volume_id,
            metadata={"_bs_vol_type": "block"},
        )
        backup_id, witness = self._oracle_witness(node_type=CoreNode.Type.VOLUME)
        backup = self._backup(
            node_type=CoreNode.Type.VOLUME,
            backup_id=backup_id,
            witness=witness,
        )
        params = {
            "compartment_id": self.compartment_id,
            "availability_domain": self.availability_domain,
        }
        self.assertEqual(
            _validate_oracle_restore_request(node, backup, "oracle-volume-fork", params),
            params,
        )
        mismatched = dict(witness, volume_type="boot")
        forged_backup = self._backup(
            node_type=CoreNode.Type.VOLUME,
            backup_id=backup_id,
            witness=mismatched,
        )
        with self.assertRaisesRegex(Exception, "exact source backup"):
            _validate_oracle_restore_request(
                node, forged_backup, "oracle-volume-fork", params
            )

    @override_settings(
        ORACLE_BACKUP_ACCEPTANCE_FAULT_ENABLED=True,
        ORACLE_BACKUP_ACCEPTANCE_FAULT_MODE="drop_response",
        ORACLE_BACKUP_ACCEPTANCE_FAULT_MARKER="backup-marker-001",
        ORACLE_BACKUP_ACCEPTANCE_FAULT_ROW_ID="41",
        ORACLE_BACKUP_ACCEPTANCE_FAULT_TASK_ID="task-41",
        ORACLE_BACKUP_ACCEPTANCE_FAULT_RESOURCE_TYPE="volume",
    )
    def test_backup_fault_gate_records_before_deliberate_lost_response(self):
        backup = SimpleNamespace(
            pk=41,
            uuid_str="backup-marker-001",
            celery_task_id="task-41",
            metadata={},
            ensure_execution_fence=mock.Mock(),
            save=mock.Mock(),
        )
        with self.assertRaises(OracleAcceptanceFault):
            maybe_fault_after_accepted_backup(
                backup,
                resource_type="volume",
                request_token="request-token",
                provider_resource_id="ocid1.volumebackup.oc1..accepted",
                request_metadata={"provider": "oracle"},
            )
        self.assertTrue(backup.metadata["_oracle_acceptance_fault"]["consumed"])
        backup.save.assert_called_once()
        backup.ensure_execution_fence.assert_called_once()

    @override_settings(
        ORACLE_RESTORE_ACCEPTANCE_FAULT_ENABLED=True,
        ORACLE_RESTORE_ACCEPTANCE_FAULT_MODE="hold",
        ORACLE_RESTORE_ACCEPTANCE_FAULT_MARKER="restore-marker-001",
        ORACLE_RESTORE_ACCEPTANCE_FAULT_ROW_ID="42",
        ORACLE_RESTORE_ACCEPTANCE_FAULT_TASK_ID="task-42",
        ORACLE_RESTORE_ACCEPTANCE_FAULT_RESOURCE_TYPE="volume",
        ORACLE_RESTORE_ACCEPTANCE_FAULT_HOLD_SECONDS=7,
    )
    def test_restore_fault_gate_holds_only_the_exact_selected_row(self):
        restore = SimpleNamespace(
            pk=42,
            celery_task_id="task-42",
            execution_metadata={},
            assert_live_execution_fence=mock.Mock(),
            save=mock.Mock(),
        )
        sleep = mock.Mock()
        self.assertTrue(
            maybe_fault_after_accepted_restore(
                restore,
                marker="restore-marker-001",
                resource_type="volume",
                request_token="request-token",
                provider_resource_id="ocid1.volume.oc1..accepted",
                request_metadata={"provider": "oracle"},
                sleep_callback=sleep,
            )
        )
        sleep.assert_called_once_with(7)
        restore.assert_live_execution_fence.assert_called_once()
        restore.save.assert_called_once()
        self.assertTrue(restore.execution_metadata["oracle_acceptance_fault"]["consumed"])
