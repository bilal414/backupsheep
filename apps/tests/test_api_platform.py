"""Global API abuse controls: throttling, pagination, and the documentation endpoints."""

from django.core.cache import cache
from django.test import Client, override_settings

from apps.api.v1.utils.api_pagination import ApiLimitOffsetPagination
from apps.tests import factories
from apps.tests.base import BaseTestCase


class ThrottlingTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()
        cache.clear()

    @override_settings(API_THROTTLE_USER_RATE="3/minute")
    def test_authenticated_requests_are_limited_per_identity(self):
        self.client.force_login(self.user)
        statuses = [self.client.get("/api/v1/check/login/").status_code for _ in range(4)]
        self.assertEqual(statuses[:3], [200, 200, 200])
        self.assertEqual(statuses[3], 429)
        response = self.client.get("/api/v1/check/login/")
        self.assertEqual(response.status_code, 429)
        self.assertTrue(response.has_header("Retry-After"))

        # Another identity has its own bucket.
        _, _, other_user = factories.make_account()
        other = Client()
        other.force_login(other_user)
        self.assertEqual(other.get("/api/v1/check/login/").status_code, 200)

    @override_settings(API_THROTTLE_WRITE_RATE="2/minute")
    def test_writes_have_a_tighter_limit_than_reads(self):
        self.client.force_login(self.user)
        for _ in range(5):
            self.assertEqual(self.client.get("/api/v1/check/login/").status_code, 200)
        statuses = [
            self.client.post("/api/v1/tokens/", {}, content_type="application/json").status_code
            for _ in range(3)
        ]
        self.assertEqual(statuses, [400, 400, 429])
        # Reads keep working while writes are throttled.
        self.assertEqual(self.client.get("/api/v1/check/login/").status_code, 200)

    @override_settings(API_THROTTLE_ANON_RATE="2/minute")
    def test_anonymous_requests_are_limited_per_peer(self):
        anonymous = Client()
        statuses = [anonymous.get("/api/v1/check/login/").status_code for _ in range(3)]
        self.assertEqual(statuses, [200, 200, 429])

    def test_login_endpoint_keeps_its_dedicated_throttles(self):
        from apps.api.v1.auth.views import APIAuthLogin
        from apps.api.v1.utils.api_throttles import LoginIdentityRateThrottle, LoginRateThrottle

        self.assertEqual(APIAuthLogin.throttle_classes, [LoginRateThrottle, LoginIdentityRateThrottle])

    def test_throttle_rates_are_validated_at_boot(self):
        from django.core.exceptions import ImproperlyConfigured

        from backupsheep import settings as settings_module

        # An unconfigured name falls through to the default, which is validated too.
        self.assertEqual(settings_module._throttle_rate("API_THROTTLE_TEST_RATE", "600/minute"), "600/minute")
        with self.assertRaises(ImproperlyConfigured):
            settings_module._throttle_rate("API_THROTTLE_TEST_RATE", "lots")
        with self.assertRaises(ImproperlyConfigured):
            settings_module._throttle_rate("API_THROTTLE_TEST_RATE", "0/minute")
        with self.assertRaises(ImproperlyConfigured):
            settings_module._throttle_rate("API_THROTTLE_TEST_RATE", "10/fortnight")


class PaginationTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()
        self.client.force_login(self.user)
        for _ in range(3):
            factories.make_storage(self.account, self.member)

    def test_lists_are_unpaginated_unless_limit_is_sent(self):
        response = self.client.get("/api/v1/storage/all/")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)
        self.assertEqual(len(response.json()), 3)

    def test_limit_and_offset_return_the_envelope(self):
        response = self.client.get("/api/v1/storage/all/", {"limit": 2})
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body["count"], 3)
        self.assertEqual(len(body["results"]), 2)
        self.assertIn("limit=2", body["next"])
        self.assertIn("offset=2", body["next"])
        self.assertIsNone(body["previous"])

        response = self.client.get("/api/v1/storage/all/", {"limit": 2, "offset": 2})
        body = response.json()
        self.assertEqual(len(body["results"]), 1)
        self.assertIsNone(body["next"])

    def test_limit_is_capped(self):
        self.assertEqual(ApiLimitOffsetPagination.max_limit, 500)
        response = self.client.get("/api/v1/storage/all/", {"limit": 100000})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("limit=100000", response.json().get("next") or "")

    def test_invalid_limit_never_widens_the_page(self):
        response = self.client.get("/api/v1/storage/all/", {"limit": "abc"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["results"]), 1)


class DocumentationTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()

    def test_schema_and_ui_require_a_member_by_default(self):
        anonymous = Client()
        self.assertIn(anonymous.get("/api/v1/schema/").status_code, (401, 403))
        self.assertIn(anonymous.get("/api/v1/docs/").status_code, (401, 403))
        self.assertIn(anonymous.get("/api/v1/docs/swagger/").status_code, (401, 403))

    @override_settings(API_DOCS_PUBLIC=True)
    def test_operator_can_publish_the_documentation(self):
        response = Client().get("/api/v1/docs/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"redoc", response.content.lower())
        self.assertNotIn(b"googleapis", response.content)
        self.assertNotIn(b"cdn.jsdelivr", response.content)

    def test_schema_describes_credentials_and_scopes(self):
        self.client.force_login(self.user)
        response = self.client.get("/api/v1/schema/", HTTP_ACCEPT="application/vnd.oai.openapi+json")
        self.assertEqual(response.status_code, 200, response.content[:300])
        document = response.json()
        self.assertEqual(document["info"]["title"], "BackupSheep API")
        schemes = document["components"]["securitySchemes"]
        self.assertEqual(schemes["apiToken"]["scheme"], "bearer")
        flows = schemes["oauth2"]["flows"]
        self.assertEqual(flows["authorizationCode"]["authorizationUrl"], "/o/authorize/")
        self.assertIn("backups:restore", flows["authorizationCode"]["scopes"])
        self.assertIn("clientCredentials", flows)

        restore = document["paths"]["/api/v1/backups/website/{id}/restore/"]["post"]
        self.assertEqual(restore["x-backupsheep-scope"], "backups:restore")
        self.assertIn({"oauth2": ["backups:restore"]}, restore["security"])
        self.assertIn({"apiToken": []}, restore["security"])
        self.assertTrue(restore["description"].startswith("**Required scope:** `backups:restore`"))

        login = document["paths"]["/api/v1/auth/login/"]["post"]
        self.assertEqual(login["security"], [])
        tokens = document["paths"]["/api/v1/tokens/"]["post"]
        self.assertEqual(tokens["x-backupsheep-scope"], "interactive-only")
        self.assertNotIn({"apiToken": []}, tokens["security"])

        # Every documented operation carries a classification.
        for path, operations in document["paths"].items():
            for method, operation in operations.items():
                if method in ("get", "post", "put", "patch", "delete"):
                    self.assertIn("x-backupsheep-scope", operation, (method, path))

    def test_schema_is_memoized_per_process(self):
        from apps.api.v1.docs.views import ApiSchemaView

        self.client.force_login(self.user)
        ApiSchemaView._schema_cache.clear()
        self.client.get("/api/v1/schema/", HTTP_ACCEPT="application/vnd.oai.openapi+json")
        self.assertEqual(len(ApiSchemaView._schema_cache), 1)
        self.client.get("/api/v1/schema/", HTTP_ACCEPT="application/vnd.oai.openapi+json")
        self.assertEqual(len(ApiSchemaView._schema_cache), 1)


class DeploymentCheckTests(BaseTestCase):
    def test_deploy_system_checks_report_no_errors(self):
        """docker_preflight runs ``check --deploy`` with fail_level=ERROR inside
        every production container; a settings combination that trips a
        deploy-only error (for example django-oauth-toolkit's E001) would stop
        the stack from starting without any unit test noticing."""
        from django.core import checks

        messages = checks.run_checks(include_deployment_checks=True)
        errors = [str(message) for message in messages if message.level >= checks.ERROR]
        self.assertEqual(errors, [])
        oauth_messages = [
            str(message) for message in messages if str(message.id or "").startswith("oauth2_provider.")
        ]
        self.assertEqual(oauth_messages, [])


class ApiAccessConsolePageTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        factories.complete_onboarding()

    def test_page_requires_login_and_renders_catalog_data(self):
        anonymous = Client().get("/console/settings/api-access/")
        self.assertEqual(anonymous.status_code, 302)

        self.client.force_login(self.user)
        response = self.client.get("/console/settings/api-access/")
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn("Personal API tokens", content)
        self.assertIn("OAuth 2.0 applications", content)
        self.assertIn("settings-api-access-initial", content)
        self.assertIn("backups:restore", content)
        self.assertIn("/o/authorize/", content)
        # The navigation exposes the page from every settings screen.
        self.assertIn('href="/console/settings/api-access/"', content)
        self.assertNotIn("bsk_", content.replace("bsk_…", ""))

