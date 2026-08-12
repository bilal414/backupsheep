"""Focused safety tests for non-Vultr cloud/volume restores.

These tests exercise the provider boundary with deterministic fakes.  They prove
that a lost mutation response is reconciled before another create request, that
ambiguous ownership fails closed, and that provider failures are persisted as
safe categories rather than response text.
"""

from datetime import timedelta
from types import SimpleNamespace
from unittest import mock
from uuid import UUID

import requests as raw_requests
from botocore.exceptions import ClientError
from django.utils import timezone

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreCloudRestore
from apps.console.connection.models import (
    CoreAuthAWS,
    CoreAuthDigitalOcean,
    CoreAWSRegion,
)
from apps.console.node.models import (
    CoreAWS,
    CoreDigitalOcean,
    CoreNode,
    _backup_provider_response_error,
    _restore_http_class,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


def response(status_code, payload=None, headers=None):
    return SimpleNamespace(
        status_code=status_code,
        headers=headers or {},
        json=lambda: payload or {},
        close=lambda: None,
    )


class NonVultrRestoreReliabilityTests(BaseTestCase):
    def _digitalocean(self):
        connection = factories.make_connection(self.account, self.member, code="digitalocean")
        CoreAuthDigitalOcean.objects.create(
            connection=connection,
            api_key=bs_encrypt("test-token", self.account.get_encryption_key()),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name="do-source",
            added_by=self.member,
        )
        integration = CoreDigitalOcean.objects.create(
            node=node,
            name="do-source",
            unique_id="source-droplet",
        )
        backup = integration.backups.create(
            uuid="do-backup",
            unique_id="123456",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        return node, backup

    def _aws(self):
        connection = factories.make_connection(self.account, self.member, code="aws")
        CoreAuthAWS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
            access_key=bs_encrypt("access", self.account.get_encryption_key()),
            secret_key=bs_encrypt("secret", self.account.get_encryption_key()),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name="aws-source",
            added_by=self.member,
        )
        integration = CoreAWS.objects.create(
            node=node,
            name="aws-source",
            unique_id="i-source",
            resource_type=CoreAWS.ResourceType.INSTANCE,
        )
        backup = integration.backups.create(
            uuid="aws-backup",
            unique_id="ami-source",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        return node, backup

    def _aws_volume(self):
        connection = factories.make_connection(self.account, self.member, code="aws")
        CoreAuthAWS.objects.create(
            connection=connection,
            region=CoreAWSRegion.objects.get(code="us-east-1"),
            access_key=bs_encrypt("access", self.account.get_encryption_key()),
            secret_key=bs_encrypt("secret", self.account.get_encryption_key()),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.VOLUME,
            name="aws-volume-source",
            added_by=self.member,
        )
        integration = CoreAWS.objects.create(
            node=node,
            name="aws-volume-source",
            unique_id="vol-source",
            resource_type=CoreAWS.ResourceType.VOLUME,
        )
        backup = integration.backups.create(
            uuid="aws-volume-backup",
            unique_id="snap-source",
            status=UtilBackup.Status.COMPLETE,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        return node, backup

    @staticmethod
    def expire_reconciliation(restore):
        restore.refresh_from_db()
        state = dict(restore.params["_bs_restore_reconciliation"])
        state["mutation_started_at"] = (
            timezone.now() - timedelta(seconds=60)
        ).isoformat()
        state["visibility_deadline_at"] = (
            timezone.now() - timedelta(seconds=1)
        ).isoformat()
        restore.params["_bs_restore_reconciliation"] = state
        restore.save(update_fields=["params", "modified"])

    def test_http_categories_are_explicit_and_never_response_text(self):
        cases = {
            404: "PROVIDER_NOT_FOUND",
            401: "PROVIDER_AUTH_FAILED",
            429: "PROVIDER_RATE_LIMIT",
            503: "PROVIDER_TRANSIENT_OUTAGE",
            422: "PROVIDER_FAILED",
        }
        for status_code, expected_code in cases.items():
            error = _restore_http_class(
                response(status_code, {"message": "credential-secret"}),
                mutation=True,
            )
            self.assertEqual(error.code, expected_code)
            self.assertNotIn("credential-secret", str(error))

        quota_response = response(
            403,
            {
                "error": {
                    "code": "resource_limit_exceeded",
                    "message": "provider-secret",
                }
            },
        )
        restore_error = _restore_http_class(quota_response, mutation=True)
        backup_error = _backup_provider_response_error(
            quota_response, mutation=True
        )
        self.assertEqual(restore_error.code, "QUOTA_EXCEEDED")
        self.assertEqual(backup_error.code, "QUOTA_EXCEEDED")
        self.assertFalse(restore_error.retryable)
        self.assertFalse(backup_error.retryable)
        self.assertNotIn("provider-secret", str(restore_error))
        self.assertNotIn("provider-secret", str(backup_error))

        maintenance_response = response(
            403,
            {"error": {"code": "maintenance", "message": "provider-secret"}},
        )
        restore_error = _restore_http_class(maintenance_response, mutation=True)
        backup_error = _backup_provider_response_error(
            maintenance_response, mutation=True
        )
        self.assertEqual(restore_error.code, "PROVIDER_TRANSIENT_OUTAGE")
        self.assertEqual(backup_error.code, "PROVIDER_TRANSIENT_OUTAGE")
        self.assertTrue(restore_error.retryable)
        self.assertTrue(backup_error.retryable)
        self.assertTrue(restore_error.unknown_outcome)
        self.assertTrue(backup_error.unknown_outcome)

    def test_digitalocean_timeout_is_fenced_then_exact_tag_match_is_adopted(self):
        node, backup = self._digitalocean()
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="do-restored",
            params={"size": "s-1vcpu-1gb"},
        )
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.console.node.models.requests.post",
            side_effect=raw_requests.Timeout("provider-secret"),
        ) as create:
            result = node.digitalocean.restore_snapshot(backup, restore)

        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        restore.refresh_from_db()
        self.assertTrue(restore.params["_bs_create_outcome_unknown"])
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_TIMEOUT")
        self.assertNotIn("provider-secret", restore.error)
        self.assertIn("timeout", create.call_args.kwargs)
        marker = restore.restore_marker
        candidate = response(
            200,
            {
                "droplets": [
                    {
                        "id": 901,
                        "name": "do-restored",
                        "tags": [marker],
                        "image": {"id": 123456},
                        "status": "new",
                    }
                ],
                "meta": {"total": 1},
            },
        )
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.console.node.models.requests.get", return_value=candidate
        ), mock.patch("apps.console.node.models.requests.post") as duplicate_create:
            node.digitalocean.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "901")
        self.assertFalse(restore.params["_bs_create_outcome_unknown"])
        create.assert_called_once()
        duplicate_create.assert_not_called()

    def test_digitalocean_inventory_timeout_is_classified_and_read_only(self):
        node, backup = self._digitalocean()
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="do-inventory-timeout",
            params={"size": "s-1vcpu-1gb", "_bs_create_outcome_unknown": True},
        )
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.console.node.models.requests.get",
            side_effect=raw_requests.Timeout("inventory-secret"),
        ) as inventory, mock.patch("apps.console.node.models.requests.post") as create:
            result = node.digitalocean.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_TIMEOUT")
        self.assertTrue(restore.params["_bs_create_outcome_unknown"])
        self.assertIn("timeout", inventory.call_args.kwargs)
        create.assert_not_called()

    def test_digitalocean_zero_match_waits_then_fails_without_duplicate_create(self):
        node, backup = self._digitalocean()
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="do-zero-match",
            params={"size": "s-1vcpu-1gb", "_bs_create_outcome_unknown": True},
        )
        empty = response(200, {"droplets": [], "meta": {"total": 0}})
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.console.node.models.requests.get", return_value=empty
        ), mock.patch("apps.console.node.models.requests.post") as create:
            first = node.digitalocean.restore_snapshot(backup, restore)
            self.assertEqual(first, CoreCloudRestore.Status.IN_PROGRESS)
            self.expire_reconciliation(restore)
            second = node.digitalocean.restore_snapshot(backup, restore)
            third = node.digitalocean.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(second, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(third, CoreCloudRestore.Status.FAILED)
        self.assertEqual(
            restore.params["_bs_last_error_code"],
            "PROVIDER_RECONCILIATION_REQUIRED",
        )
        create.assert_not_called()

    def test_digitalocean_duplicate_marker_matches_fail_closed(self):
        node, backup = self._digitalocean()
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="do-duplicate",
            params={"size": "s-1vcpu-1gb", "_bs_create_outcome_unknown": True},
            restore_marker="backupsheep-restore-duplicate",
        )
        payload = response(
            200,
            {
                "droplets": [
                    {"id": 1, "tags": [restore.restore_marker], "image": {"id": 123456}},
                    {"id": 2, "tags": [restore.restore_marker], "image": {"id": 123456}},
                ],
                "meta": {"total": 2},
            },
        )
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch("apps.console.node.models.requests.get", return_value=payload), mock.patch(
            "apps.console.node.models.requests.post"
        ) as create:
            with self.assertRaises(ValueError):
                node.digitalocean.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.status, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_DUPLICATE_MATCH")
        create.assert_not_called()

    def test_new_digitalocean_poll_404_is_terminal_and_source_is_not_touched(self):
        node, backup = self._digitalocean()
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="do-404",
            resource_id="901",
            restore_marker="backupsheep-restore-404",
            params={
                "_bs_marker_required": True,
                "_backupsheep_restore": {"source_id": backup.unique_id},
            },
        )
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.console.node.models.requests.get",
            return_value=response(404, {"message": "secret-provider-body"}),
        ):
            result = node.digitalocean.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_NOT_FOUND")
        self.assertNotIn("secret-provider-body", restore.error)

    def test_aws_ec2_timeout_then_tag_and_source_reconciliation_avoids_duplicate_run(self):
        node, backup = self._aws()
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="aws-restored",
            params={"instance_type": "t3.micro"},
        )
        client = mock.MagicMock()
        client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-source",
                            "InstanceType": "t3.micro",
                            "SubnetId": "subnet-0123456789abcdef0",
                            "SecurityGroups": [
                                {"GroupId": "sg-0123456789abcdef0"}
                            ],
                        }
                    ]
                }
            ]
        }
        client.run_instances.side_effect = raw_requests.Timeout("aws-secret")
        with mock.patch.object(CoreAuthAWS, "get_client", return_value=client):
            result = node.aws.restore_snapshot(backup, restore)

        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        restore.refresh_from_db()
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_TIMEOUT")
        marker = restore.restore_marker
        client.reset_mock()
        client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-restored",
                            "ImageId": "ami-source",
                            "State": {"Name": "pending"},
                            "Tags": [
                                {"Key": "BackupSheepRestore", "Value": marker},
                                {"Key": "BackupSheepSource", "Value": "ami-source"},
                            ],
                        }
                    ]
                }
            ]
        }
        with mock.patch.object(CoreAuthAWS, "get_client", return_value=client):
            node.aws.restore_snapshot(backup, restore)

        restore.refresh_from_db()
        self.assertEqual(restore.resource_id, "i-restored")
        client.run_instances.assert_not_called()

    def test_aws_ec2_and_ebs_zero_match_waits_without_mutation(self):
        for make_source, resource_kind in (
            (self._aws, "ec2"),
            (self._aws_volume, "ebs"),
        ):
            with self.subTest(resource_kind=resource_kind):
                node, backup = make_source()
                restore = CoreCloudRestore.objects.create(
                    node=node,
                    backup_id=backup.id,
                    name=f"aws-{resource_kind}-zero-match",
                    params={"_bs_create_outcome_unknown": True},
                )
                client = mock.MagicMock()
                if resource_kind == "ec2":
                    client.describe_instances.return_value = {
                        "Reservations": []
                    }
                else:
                    client.describe_volumes.return_value = {"Volumes": []}
                with mock.patch.object(CoreAuthAWS, "get_client", return_value=client):
                    first = node.aws.restore_snapshot(backup, restore)
                    self.assertEqual(first, CoreCloudRestore.Status.IN_PROGRESS)
                    self.expire_reconciliation(restore)
                    second = node.aws.restore_snapshot(backup, restore)
                    third = node.aws.restore_snapshot(backup, restore)

                restore.refresh_from_db()
                self.assertEqual(second, CoreCloudRestore.Status.IN_PROGRESS)
                self.assertEqual(third, CoreCloudRestore.Status.FAILED)
                self.assertEqual(
                    restore.params["_bs_last_error_code"],
                    "PROVIDER_RECONCILIATION_REQUIRED",
                )
                client.run_instances.assert_not_called()
                client.create_volume.assert_not_called()

    def test_digitalocean_poll_timeout_is_classified_and_has_timeout(self):
        node, backup = self._digitalocean()
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="do-poll-timeout",
            resource_id="901",
            restore_marker="backupsheep-restore-poll-timeout",
            params={
                "_bs_marker_required": True,
                "_backupsheep_restore": {"source_id": backup.unique_id},
            },
        )
        with mock.patch.object(
            CoreAuthDigitalOcean,
            "get_client",
            return_value={"Authorization": "Bearer test-token"},
        ), mock.patch(
            "apps.console.node.models.requests.get",
            side_effect=raw_requests.Timeout("poll-secret"),
        ) as poll:
            result = node.digitalocean.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.IN_PROGRESS)
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_TIMEOUT")
        self.assertIn("timeout", poll.call_args.kwargs)

    def test_aws_ec2_restore_infers_and_persists_source_network_configuration(self):
        node, backup = self._aws()
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="aws-network-restored",
            params={},
        )
        client = mock.MagicMock()
        client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-source",
                            "InstanceType": "t3.micro",
                            "SubnetId": "subnet-0123456789abcdef0",
                            "SecurityGroups": [
                                {"GroupId": "sg-0123456789abcdef0"}
                            ],
                            "KeyName": "restore-key",
                        }
                    ]
                }
            ]
        }
        client.run_instances.return_value = {
            "Instances": [{"InstanceId": "i-network-restored"}]
        }

        with mock.patch.object(CoreAuthAWS, "get_client", return_value=client):
            node.aws.restore_snapshot(backup, restore)

        request = client.run_instances.call_args.kwargs
        self.assertEqual(request["InstanceType"], "t3.micro")
        self.assertEqual(request["SubnetId"], "subnet-0123456789abcdef0")
        self.assertEqual(
            request["SecurityGroupIds"], ["sg-0123456789abcdef0"]
        )
        self.assertEqual(request["KeyName"], "restore-key")
        restore.refresh_from_db()
        self.assertEqual(
            restore.params["_bs_source_configuration"]["security_group_ids"],
            ["sg-0123456789abcdef0"],
        )

    def test_aws_ec2_restore_uses_durable_configuration_after_source_deletion(self):
        node, backup = self._aws()
        backup.record_provider_reference(
            metadata={
                "source_configuration": {
                    "schema": 1,
                    "source_type": "instance",
                    "source_id": "i-source",
                    "instance_type": "t3.micro",
                    "subnet_id": "subnet-0123456789abcdef0",
                    "security_group_ids": ["sg-0123456789abcdef0"],
                    "key_name": "restore-key",
                }
            }
        )
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="aws-source-deleted-restored",
            params={},
        )
        client = mock.MagicMock()
        client.run_instances.return_value = {
            "Instances": [{"InstanceId": "i-source-deleted-restored"}]
        }

        with mock.patch.object(CoreAuthAWS, "get_client", return_value=client):
            node.aws.restore_snapshot(backup, restore)

        client.describe_instances.assert_not_called()
        self.assertEqual(
            client.run_instances.call_args.kwargs["SecurityGroupIds"],
            ["sg-0123456789abcdef0"],
        )

    def test_aws_ec2_source_mismatch_fails_closed_before_polling(self):
        node, backup = self._aws()
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="aws-foreign",
            resource_id="i-foreign",
            restore_marker="backupsheep-restore-foreign",
            params={
                "_bs_marker_required": True,
                "_backupsheep_restore": {"source_id": backup.unique_id},
            },
        )
        client = mock.MagicMock()
        client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-foreign",
                            "ImageId": "ami-someone-else",
                            "State": {"Name": "running"},
                            "Tags": [
                                {"Key": "BackupSheepRestore", "Value": restore.restore_marker}
                            ],
                        }
                    ]
                }
            ]
        }
        with mock.patch.object(CoreAuthAWS, "get_client", return_value=client):
            result = node.aws.check_restore(restore)

        restore.refresh_from_db()
        self.assertEqual(result, CoreCloudRestore.Status.FAILED)
        self.assertEqual(restore.params["_bs_last_error_code"], "PROVIDER_OWNERSHIP_MISMATCH")

    def test_client_error_categories_are_safe(self):
        error = ClientError(
            {
                "Error": {"Code": "AccessDeniedException", "Message": "secret-token"},
                "ResponseMetadata": {"HTTPStatusCode": 403},
            },
            "Describe",
        )
        classified = __import__("apps.console.node.models", fromlist=["_restore_exception"])._restore_exception(error)
        self.assertEqual(classified.code, "PROVIDER_AUTH_FAILED")
        self.assertNotIn("secret-token", str(classified))

    def test_notify_backup_fail_uses_safe_contract_and_durable_correlation(self):
        node, backup = self._digitalocean()
        sensitive_text = (
            "provider-body https://10.20.30.40:8443/private "
            "username=admin path=/home/admin token=SUPERSECRET"
        )
        sensitive_error = type("NodeBackupFailedError", (Exception,), {})(
            sensitive_text
        )
        sensitive_error.attempt_no = 1
        sensitive_error.backup_uuid = backup.uuid_str

        with mock.patch.object(self.account.__class__, "create_log") as create_log, mock.patch(
            "apps._tasks.helper.tasks.send_postmark_email.delay"
        ) as send_email:
            node.notify_backup_fail(sensitive_error, UtilBackup.Type.ON_DEMAND)

        create_log.assert_called_once()
        logged_data = create_log.call_args.kwargs["data"]
        send_email.assert_called_once()
        emailed_data = send_email.call_args.args[2]
        self.assertEqual(logged_data, emailed_data)
        self.assertEqual(logged_data["error_code"], "BACKUP_FAILED")
        self.assertTrue(logged_data["remediation"])
        self.assertEqual(str(UUID(logged_data["correlation_id"])), logged_data["correlation_id"])
        for payload in (logged_data, emailed_data):
            self.assertNotIn("endpoint_ip", payload)
            self.assertNotIn("endpoint_ipv6", payload)
            serialized = repr(payload)
            for secret in (
                "provider-body",
                "10.20.30.40",
                "admin",
                "/home/admin",
                "SUPERSECRET",
            ):
                self.assertNotIn(secret, serialized)

        state = backup.get_execution_state(create=False)
        self.assertIsNotNone(state)
        self.assertEqual(state.last_error_code, "BACKUP_FAILED")
        self.assertEqual(str(state.correlation_id), logged_data["correlation_id"])
