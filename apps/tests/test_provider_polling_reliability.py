from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

import requests as raw_requests
from django.utils import timezone

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import CoreDigitalOceanBackup, _provider_owned
from apps.console.connection.models import CoreAuthDigitalOcean
from apps.console.node.models import CoreNode
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


class ProviderOwnershipContractTests(BaseTestCase):
    def test_expected_source_must_be_present_and_exact(self):
        resource = {"id": "snapshot-1", "name": "backup-1"}

        self.assertFalse(
            _provider_owned(
                resource,
                resource_id="snapshot-1",
                marker="backup-1",
                source_fields=(("source_id", "server-1"),),
            )
        )
        resource["source_id"] = "server-1"
        self.assertTrue(
            _provider_owned(
                resource,
                resource_id="snapshot-1",
                marker="backup-1",
                source_fields=(("source_id", "server-1"),),
            )
        )

    def test_nested_source_without_id_is_not_ownership_proof(self):
        self.assertFalse(
            _provider_owned(
                {
                    "id": "snapshot-1",
                    "name": "backup-1",
                    "source": {"name": "server-1"},
                },
                resource_id="snapshot-1",
                marker="backup-1",
                source_fields=(("source", "server-1"),),
            )
        )


class DigitalOceanProviderReliabilityTests(BaseTestCase):
    def make_backup(self, *, unique_id="snapshot-1", metadata=None):
        node = factories.make_cloud_node(
            self.account,
            self.member,
            code="digitalocean",
            node_type=CoreNode.Type.CLOUD,
        )
        CoreAuthDigitalOcean.objects.create(
            connection=node.connection,
            api_key=bs_encrypt(
                "test-token", self.account.get_encryption_key()
            ),
        )
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean,
            uuid="backup-marker-1",
            unique_id=unique_id,
            status=UtilBackup.Status.IN_PROGRESS,
            attempt_no=1,
            type=UtilBackup.Type.ON_DEMAND,
            metadata=metadata,
        )
        return node, backup

    def poll(self, backup, provider_response=None, side_effect=None):
        with mock.patch(
            "apps.console.connection.models.CoreAuthDigitalOcean.get_verified_client",
            return_value={"Authorization": "Bearer redacted"},
        ), mock.patch(
            "apps.console.backup.models.requests.get",
            return_value=provider_response,
            side_effect=side_effect,
        ):
            return backup.poll_status()

    def execution(self, backup):
        return backup.execution_records.get()

    def owned_snapshot(self, backup, *, state="new", resource_id="droplet-1"):
        return {
            "snapshot": {
                "id": backup.unique_id,
                "name": backup.uuid_str,
                "resource_id": resource_id,
                "resource_type": "droplet",
                "status": state,
            }
        }

    def test_poll_404_is_terminal_not_found_without_persisting_body(self):
        _, backup = self.make_backup()
        result = self.poll(
            backup,
            response(404, {"message": "secret-token-from-provider"}),
        )

        self.assertEqual(result, UtilBackup.Status.FAILED)
        execution = self.execution(backup)
        self.assertEqual(execution.last_error_code, "PROVIDER_NOT_FOUND")
        self.assertEqual(execution.provider_status, "not_found")
        self.assertNotIn("secret-token", execution.last_error_message)
        self.assertNotIn("secret-token", str(execution.provider_metadata))

    def test_poll_auth_failure_is_terminal_and_categorized(self):
        _, backup = self.make_backup()

        self.assertEqual(
            self.poll(backup, response(403, {"message": "credential detail"})),
            UtilBackup.Status.FAILED,
        )
        self.assertEqual(
            self.execution(backup).last_error_code, "PROVIDER_AUTH_FAILED"
        )

    def test_poll_429_respects_retry_after(self):
        _, backup = self.make_backup()
        before = timezone.now()

        result = self.poll(
            backup,
            response(429, headers={"Retry-After": "120"}),
        )

        self.assertEqual(result, UtilBackup.Status.IN_PROGRESS)
        execution = self.execution(backup)
        self.assertEqual(execution.last_error_code, "PROVIDER_RATE_LIMIT")
        self.assertEqual(execution.provider_status, "rate_limited")
        self.assertGreaterEqual(execution.next_retry_at, before + timedelta(seconds=119))
        self.assertLessEqual(execution.next_retry_at, before + timedelta(seconds=122))

    def test_poll_5xx_and_timeout_are_retryable_but_distinct(self):
        _, outage_backup = self.make_backup(unique_id="snapshot-outage")
        _, timeout_backup = self.make_backup(unique_id="snapshot-timeout")

        self.assertEqual(
            self.poll(outage_backup, response(503)),
            UtilBackup.Status.IN_PROGRESS,
        )
        self.assertEqual(
            self.poll(timeout_backup, side_effect=raw_requests.Timeout("secret")),
            UtilBackup.Status.IN_PROGRESS,
        )
        self.assertEqual(
            self.execution(outage_backup).last_error_code,
            "PROVIDER_TRANSIENT_OUTAGE",
        )
        timeout_execution = self.execution(timeout_backup)
        self.assertEqual(timeout_execution.last_error_code, "PROVIDER_TIMEOUT")
        self.assertNotIn("secret", timeout_execution.last_error_message)

    def test_poll_ownership_mismatch_fails_closed(self):
        _, backup = self.make_backup()

        result = self.poll(
            backup,
            response(200, self.owned_snapshot(backup, resource_id="foreign-droplet")),
        )

        self.assertEqual(result, UtilBackup.Status.FAILED)
        self.assertEqual(
            self.execution(backup).last_error_code,
            "PROVIDER_OWNERSHIP_MISMATCH",
        )

    def test_poll_explicit_provider_failure_is_terminal(self):
        _, backup = self.make_backup()

        result = self.poll(
            backup,
            response(200, self.owned_snapshot(backup, state="failed")),
        )

        self.assertEqual(result, UtilBackup.Status.FAILED)
        execution = self.execution(backup)
        self.assertEqual(execution.last_error_code, "PROVIDER_FAILED")
        self.assertEqual(execution.provider_status, "failed")

    def test_poll_successful_in_progress_is_not_recorded_as_an_error(self):
        _, backup = self.make_backup()

        result = self.poll(
            backup,
            response(200, self.owned_snapshot(backup, state="new")),
        )

        self.assertEqual(result, UtilBackup.Status.IN_PROGRESS)
        execution = self.execution(backup)
        self.assertEqual(execution.provider_status, "new")
        self.assertEqual(execution.last_error_code, "")
        backup.refresh_from_db()
        self.assertTrue(backup.metadata["_provider_ownership_verified"])

    def test_delete_refuses_ownership_mismatch_without_delete_request(self):
        _, backup = self.make_backup()
        backup.status = UtilBackup.Status.DELETE_REQUESTED
        backup.save(update_fields=["status", "modified"])
        foreign = response(
            200,
            self.owned_snapshot(backup, resource_id="foreign-droplet"),
        )

        with mock.patch(
            "apps.console.connection.models.CoreAuthDigitalOcean.get_verified_client",
            return_value={"Authorization": "Bearer redacted"},
        ), mock.patch(
            "apps.console.backup.models.requests.get", return_value=foreign
        ), mock.patch("apps.console.backup.models.requests.delete") as delete:
            backup.soft_delete()

        delete.assert_not_called()
        backup.refresh_from_db()
        self.assertEqual(backup.status, UtilBackup.Status.DELETE_FAILED)
        self.assertEqual(
            self.execution(backup).last_error_code,
            "PROVIDER_OWNERSHIP_MISMATCH",
        )

    def test_delete_404_is_idempotent_only_after_ownership_proof(self):
        _, unproven = self.make_backup(unique_id="snapshot-unproven")
        _, proven = self.make_backup(
            unique_id="snapshot-proven",
            metadata={
                "_provider_ownership_verified": True,
                "_provider_source_id": "droplet-1",
            },
        )
        for backup in (unproven, proven):
            backup.status = UtilBackup.Status.DELETE_REQUESTED
            backup.save(update_fields=["status", "modified"])

        with mock.patch(
            "apps.console.connection.models.CoreAuthDigitalOcean.get_verified_client",
            return_value={"Authorization": "Bearer redacted"},
        ), mock.patch(
            "apps.console.backup.models.requests.get", return_value=response(404)
        ), mock.patch("apps.console.backup.models.requests.delete") as delete:
            unproven.soft_delete()
            proven.soft_delete()

        delete.assert_not_called()
        unproven.refresh_from_db()
        proven.refresh_from_db()
        self.assertEqual(
            unproven.status, UtilBackup.Status.DELETE_FAILED_NOT_FOUND
        )
        self.assertEqual(proven.status, UtilBackup.Status.DELETE_COMPLETED)
