from types import SimpleNamespace
from unittest import mock

from django.test import override_settings
from django.test import SimpleTestCase
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.test import APIClient

from apps.api.v1.mobile.views import MobileBootstrapView
from apps.tests.base import BaseTestCase


class MobileBootstrapContractUnitTests(SimpleTestCase):
    """Fast contract coverage that does not require a local PostgreSQL service."""

    @override_settings(APP_NAME="BackupSheep Enterprise")
    @mock.patch("apps.api.v1.mobile.views.member_has_perm", return_value=True)
    def test_response_contract_is_stable_and_secret_free(self, _permission_check):
        account = SimpleNamespace(id=11, name="Infrastructure")
        membership = SimpleNamespace(primary=True)
        memberships = mock.Mock()
        memberships.filter.return_value.first.return_value = membership
        member = SimpleNamespace(
            id=7,
            full_name="Operations User",
            email="ops@example.test",
            timezone="America/Chicago",
            memberships=memberships,
            get_current_account=lambda: account,
        )
        request = SimpleNamespace(
            user=SimpleNamespace(member=member),
            build_absolute_uri=lambda path: f"https://backup.example.test{path}",
        )

        response = MobileBootstrapView().get(request)
        payload = response.data

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(payload["mobile_api_version"], 1)
        self.assertEqual(
            payload["installation"]["canonical_url"],
            "https://backup.example.test",
        )
        self.assertEqual(payload["session"]["account"]["id"], 11)
        self.assertTrue(payload["session"]["is_owner"])
        self.assertEqual(
            set(payload["session"]["permissions"]),
            set(MobileBootstrapView.PERMISSION_CODENAMES),
        )
        self.assertFalse(
            payload["capabilities"]["mutation_contracts"][
                "local_restore_idempotency"
            ]
        )
        self.assertEqual(MobileBootstrapView.permission_classes, (IsAuthenticated,))

        serialized = str(payload).lower()
        for forbidden in (
            "password",
            "secret_key",
            "api_key",
            "encryption_key",
            "private_key",
        ):
            self.assertNotIn(forbidden, serialized)


class MobileBootstrapAPITests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()

    def test_bootstrap_requires_authentication(self):
        response = self.client.get("/api/v1/mobile/bootstrap/")

        self.assertIn(
            response.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )

    @override_settings(APP_NAME="BackupSheep Enterprise")
    def test_owner_bootstrap_is_scoped_and_secret_free(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.get(
            "/api/v1/mobile/bootstrap/", HTTP_HOST="backup.example.test"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        payload = response.json()
        self.assertEqual(payload["api_version"], 1.0)
        self.assertEqual(payload["mobile_api_version"], 1)
        self.assertEqual(
            payload["installation"],
            {
                "display_name": "BackupSheep Enterprise",
                "canonical_url": "http://backup.example.test",
            },
        )
        self.assertEqual(payload["session"]["member"]["id"], self.member.id)
        self.assertEqual(payload["session"]["account"]["id"], self.account.id)
        self.assertTrue(payload["session"]["is_owner"])
        self.assertEqual(payload["session"]["role"], "owner")
        self.assertEqual(
            set(payload["session"]["permissions"]),
            set(MobileBootstrapView.PERMISSION_CODENAMES),
        )
        self.assertTrue(all(payload["session"]["permissions"].values()))
        self.assertTrue(
            payload["capabilities"]["mutation_contracts"][
                "on_demand_backup_idempotency"
            ]
        )
        self.assertFalse(
            payload["capabilities"]["mutation_contracts"][
                "local_restore_idempotency"
            ]
        )

        serialized = str(payload).lower()
        for forbidden in (
            "password",
            "secret_key",
            "api_key",
            "encryption_key",
            "private_key",
        ):
            self.assertNotIn(forbidden, serialized)
