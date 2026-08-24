from rest_framework import status
from rest_framework.test import APIClient

from apps.console.setting.models import CoreSiteSettings
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


BACKUP_CHART_ENDPOINTS = (
    "website",
    "database",
    "digitalocean",
    "aws",
    "aws_rds",
    "basecamp",
    "google_cloud",
    "hetzner",
    "lightsail",
    "oracle",
    "ovh_ca",
    "ovh_eu",
    "ovh_us",
    "upcloud",
    "vultr",
    "wordpress",
)


class LiveAPIContractTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False

        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_authenticated_login_probe_does_not_mint_privileged_token(self):
        response = self.client.get("/api/v1/check/login/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json(),
            {"login": True, "firebase_login_token": None},
        )

    def test_anonymous_login_probe_preserves_legacy_response_shape(self):
        self.client.force_authenticate(user=None)
        response = self.client.get("/api/v1/check/login/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json(),
            {"login": False, "firebase_login_token": None},
        )

    def test_backup_highcharts_routes_return_chart_data(self):
        for endpoint in BACKUP_CHART_ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(
                    f"/api/v1/backups/{endpoint}/highcharts/"
                )

                self.assertEqual(response.status_code, status.HTTP_200_OK)
                payload = response.json()
                self.assertEqual(set(payload), {"categories", "series"})
                self.assertEqual(len(payload["series"]), 1)
                self.assertEqual(
                    len(payload["categories"]),
                    len(payload["series"][0]["data"]),
                )
