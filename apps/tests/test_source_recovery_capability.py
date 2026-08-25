"""Fail-closed coverage for source families without complete recovery parity."""

import uuid
from unittest import mock

from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps._tasks import backup_dispatch
from apps._tasks.integration.basecamp import backup_basecamp
from apps._tasks.integration.wordpress import backup_wordpress
from apps.api.v1.mobile.views import MobileBootstrapView
from apps.api.v1.saas.basecamp.serializers import CoreBasecampReadSerializer
from apps.api.v1.saas.wordpress.serializers import CoreWordPressReadSerializer
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.backup.models import (
    CoreBasecampBackup,
    CoreBasecampBackupStoragePoints,
    CoreBackupRequest,
    CoreWordPressBackup,
    CoreWordPressBackupStoragePoints,
)
from apps.console.connection.models import CoreAuthBasecamp, CoreAWSRegion
from apps.console.node.models import CoreBasecamp, CoreNode, CoreWordPress
from apps.console.setting.models import CoreSiteSettings
from apps.tests import factories
from apps.tests.base import BaseTestCase
from backupsheep.source_recovery_policy import (
    SOURCE_RECOVERY_UNAVAILABLE_MESSAGE,
    SourceRecoveryUnavailable,
    available_backup_endpoints,
    require_source_backup_creation,
    source_backup_creation_available,
)
from utils.middleware import OnboardingMiddleware


ENTERPRISE_POLICY = {
    "BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE": True,
    "BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE": "bse1",
    "BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE": False,
    # A deployment flag must never override the enterprise recovery gate.
    "WORDPRESS_INTEGRATION_ENABLED": True,
    "BASECAMP_INTEGRATION_ENABLED": True,
}

LEGACY_COMPATIBILITY_POLICY = {
    "BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE": False,
    "BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE": "legacy-only",
    "BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE": True,
    "WORDPRESS_INTEGRATION_ENABLED": True,
    "BASECAMP_INTEGRATION_ENABLED": True,
}


class SourceRecoveryPolicyTests(SimpleTestCase):
    @override_settings(**ENTERPRISE_POLICY)
    def test_enterprise_mode_blocks_both_families_even_when_flags_are_true(self):
        for code in ("wordpress", "basecamp"):
            with self.subTest(code=code):
                self.assertFalse(source_backup_creation_available(code))
                with self.assertRaises(SourceRecoveryUnavailable) as raised:
                    require_source_backup_creation(code)
                self.assertEqual(str(raised.exception.detail), SOURCE_RECOVERY_UNAVAILABLE_MESSAGE)
                self.assertEqual(
                    raised.exception.get_codes(), "source_recovery_unavailable"
                )

    @override_settings(**LEGACY_COMPATIBILITY_POLICY)
    def test_explicit_legacy_compatibility_mode_is_available(self):
        self.assertTrue(source_backup_creation_available("wordpress"))
        self.assertTrue(source_backup_creation_available("basecamp"))
        self.assertTrue(source_backup_creation_available("website"))

    def test_every_legacy_compatibility_prerequisite_fails_closed(self):
        cases = (
            {
                **LEGACY_COMPATIBILITY_POLICY,
                "BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE": True,
            },
            {
                **LEGACY_COMPATIBILITY_POLICY,
                "BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE": "bse1",
            },
            {
                **LEGACY_COMPATIBILITY_POLICY,
                "BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE": False,
            },
            {
                **LEGACY_COMPATIBILITY_POLICY,
                "WORDPRESS_INTEGRATION_ENABLED": False,
            },
            {
                **LEGACY_COMPATIBILITY_POLICY,
                # Policy settings must already be parsed booleans. A direct
                # string override cannot accidentally enable the family.
                "WORDPRESS_INTEGRATION_ENABLED": "true",
            },
        )
        for settings_override in cases:
            with self.subTest(settings_override=settings_override):
                with override_settings(**settings_override):
                    self.assertFalse(source_backup_creation_available("wordpress"))

    @override_settings(**ENTERPRISE_POLICY)
    def test_public_capability_list_omits_unrecoverable_families(self):
        self.assertEqual(
            available_backup_endpoints(
                ("database", "wordpress", "basecamp", "website")
            ),
            ["database", "website"],
        )

    @override_settings(**ENTERPRISE_POLICY)
    def test_mobile_bootstrap_does_not_advertise_blocked_endpoints(self):
        account = mock.Mock(id=11, name="Infrastructure")
        membership = mock.Mock(primary=True)
        memberships = mock.Mock()
        memberships.filter.return_value.first.return_value = membership
        member = mock.Mock(
            id=7,
            full_name="Operations User",
            email="ops@example.test",
            timezone="UTC",
            memberships=memberships,
            get_current_account=lambda: account,
        )
        request = mock.Mock(
            user=mock.Mock(member=member),
            build_absolute_uri=lambda path: f"https://backup.example.test{path}",
        )

        with mock.patch(
            "apps.api.v1.mobile.views.member_has_perm", return_value=True
        ):
            response = MobileBootstrapView().get(request)

        endpoints = response.data["capabilities"]["backup_endpoints"]
        self.assertNotIn("wordpress", endpoints)
        self.assertNotIn("basecamp", endpoints)
        self.assertIn("website", endpoints)


@override_settings(**ENTERPRISE_POLICY)
class EnterpriseSourceRecoveryBoundaryTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save(update_fields=("setup_completed", "modified"))
        OnboardingMiddleware._completed = False

        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        self.nodes = {
            "wordpress": self._make_source("wordpress"),
            "basecamp": self._make_source("basecamp"),
        }

    def _make_source(self, code):
        connection = factories.make_connection(self.account, self.member, code=code)
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.SAAS,
            name=f"existing-{code}",
            added_by=self.member,
        )
        if code == "wordpress":
            CoreWordPress.objects.create(node=node, name="Existing WordPress")
        else:
            CoreBasecamp.objects.create(
                node=node,
                name="Existing Basecamp",
                projects=[],
                all_projects=False,
            )
        return node

    def test_connection_creation_and_backup_api_refuse_before_mutation(self):
        with mock.patch.object(backup_dispatch.current_app, "send_task") as send_task:
            for code, node in self.nodes.items():
                with self.subTest(code=code, boundary="connection"):
                    response = self.client.post(
                        f"/api/v1/connections/{code}/", {}, format="json"
                    )
                    self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
                    self.assertEqual(
                        response.json()["detail"], SOURCE_RECOVERY_UNAVAILABLE_MESSAGE
                    )

                with self.subTest(code=code, boundary="backup"):
                    response = self.client.post(
                        f"/api/v1/nodes/{node.id}/take_snapshot/",
                        {"storage_point_ids": [999999]},
                        format="json",
                    )
                    self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
                    self.assertEqual(
                        response.json()["detail"], SOURCE_RECOVERY_UNAVAILABLE_MESSAGE
                    )

        self.assertFalse(CoreBackupRequest.objects.exists())
        send_task.assert_not_called()

    def test_direct_outbox_and_replayed_worker_bypasses_fail_before_backup_rows(self):
        task_by_family = {
            "wordpress": backup_wordpress,
            "basecamp": backup_basecamp,
        }
        with mock.patch.object(backup_dispatch.current_app, "send_task") as send_task:
            for code, node in self.nodes.items():
                with self.subTest(code=code, boundary="outbox"):
                    with self.assertRaises(SourceRecoveryUnavailable):
                        backup_dispatch.create_backup_request(
                            node=node,
                            storage_ids=[],
                            requested_by=self.member,
                            trigger=CoreBackupRequest.Trigger.ON_DEMAND,
                            idempotency_key=f"blocked-{code}",
                        )

                with self.subTest(code=code, boundary="worker"):
                    with self.assertRaises(SourceRecoveryUnavailable):
                        task_by_family[code].run(node_id=node.id)

        self.assertFalse(CoreBackupRequest.objects.exists())
        self.assertFalse(self.nodes["wordpress"].wordpress.backups.exists())
        self.assertFalse(self.nodes["basecamp"].basecamp.backups.exists())
        send_task.assert_not_called()

    def test_disabled_basecamp_does_not_decrypt_or_refresh_oauth_credentials(self):
        auth = CoreAuthBasecamp.objects.create(
            connection=self.nodes["basecamp"].connection,
            access_token=b"encrypted-access-canary",
            refresh_token=b"encrypted-refresh-canary",
            identity_id="existing-identity",
        )
        with mock.patch(
            "apps.console.connection.models.bs_decrypt"
        ) as decrypt, mock.patch(
            "apps.console.connection.models.requests.post"
        ) as post:
            with self.assertRaises(SourceRecoveryUnavailable):
                auth.get_refresh_token()

        decrypt.assert_not_called()
        post.assert_not_called()

    @override_settings(**LEGACY_COMPATIBILITY_POLICY)
    def test_explicit_compatibility_gate_matches_usable_legacy_download_paths(self):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        aws_s3 = storage.storage_aws_s3
        encryption_key = self.account.get_encryption_key()
        aws_s3.access_key = bs_encrypt("legacy-access", encryption_key)
        aws_s3.secret_key = bs_encrypt("legacy-secret", encryption_key)
        aws_s3.region = CoreAWSRegion.objects.get(code="us-east-1")
        aws_s3.save(
            update_fields=("access_key", "secret_key", "region", "modified")
        )
        storage_points = {
            "wordpress": CoreWordPressBackupStoragePoints.objects.create(
                backup=CoreWordPressBackup.objects.create(
                    wordpress=self.nodes["wordpress"].wordpress,
                    uuid=f"legacy-{uuid.uuid4().hex}",
                ),
                storage=storage,
                storage_file_id="legacy/wordpress.zip",
            ),
            "basecamp": CoreBasecampBackupStoragePoints.objects.create(
                backup=CoreBasecampBackup.objects.create(
                    basecamp=self.nodes["basecamp"].basecamp,
                    uuid=f"legacy-{uuid.uuid4().hex}",
                ),
                storage=storage,
                storage_file_id="legacy/basecamp.zip",
            ),
        }
        s3_client = mock.Mock()
        s3_client.head_object.return_value = {}
        s3_client.generate_presigned_url.return_value = (
            "https://download.example.test/legacy"
        )

        with mock.patch(
            "apps.console.backup.models.bounded_boto3_client",
            return_value=s3_client,
        ):
            for code, storage_point in storage_points.items():
                with self.subTest(code=code):
                    download_url = storage_point.generate_download_url()
                    self.assertTrue(source_backup_creation_available(code))
                    self.assertTrue(storage_point.direct_download_permitted())
                    self.assertEqual(
                        download_url, "https://download.example.test/legacy"
                    )

    def test_old_pending_outbox_rows_are_terminalized_without_dispatch_or_deletion(self):
        requests = []
        for code, node in self.nodes.items():
            requests.append(
                CoreBackupRequest.objects.create(
                    request_key=f"old-{code}-{uuid.uuid4().hex}",
                    task_id=uuid.uuid4().hex,
                    task_name=node.backup_task_name(),
                    node=node,
                    payload={"node_id": node.id, "storage_ids": []},
                    next_dispatch_at=timezone.now(),
                )
            )

        with mock.patch.object(backup_dispatch.current_app, "send_task") as send_task:
            for request in requests:
                self.assertFalse(backup_dispatch.publish_backup_request(request.id))

        for request in requests:
            request.refresh_from_db()
            self.assertEqual(request.status, CoreBackupRequest.Status.CANCELLED)
            self.assertEqual(request.last_error_code, "SOURCE_RECOVERY_UNAVAILABLE")
            self.assertEqual(
                request.last_error_message, SOURCE_RECOVERY_UNAVAILABLE_MESSAGE
            )
        send_task.assert_not_called()

        # Existing source rows remain readable for investigation and retention.
        wordpress = self.nodes["wordpress"].wordpress
        basecamp = self.nodes["basecamp"].basecamp
        self.assertEqual(CoreWordPressReadSerializer(wordpress).data["id"], wordpress.id)
        self.assertEqual(CoreBasecampReadSerializer(basecamp).data["id"], basecamp.id)

    def test_console_and_api_choice_lists_hide_blocked_families(self):
        response = self.client.get(reverse("console:setup:integration_select"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        content = response.content.decode()
        self.assertNotIn('id="wordpress"', content)
        self.assertNotIn('id="basecamp"', content)

        response = self.client.get(reverse("console:node:index"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        content = response.content.decode()
        self.assertEqual(content.count("Complete recovery unavailable"), 2)
        for node in self.nodes.values():
            self.assertNotIn(f'data-node-id="{node.id}"', content)

        with mock.patch(
            "apps.console.connection.models.CoreConnectionLocation.refresh_local_ip_addresses"
        ):
            for code in self.nodes:
                with self.subTest(code=code):
                    response = self.client.get(
                        f"/api/v1/connections/{code}/endpoints/"
                    )
                    self.assertEqual(response.status_code, status.HTTP_200_OK)
                    self.assertEqual(response.json(), [])
