import socket
from pathlib import Path
from unittest import mock

import paramiko
from django.http import Http404
from django.test import SimpleTestCase
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APIClient

from apps.api.v1.connection.view_helpers import (
    connection_error_response,
    safe_connection_action,
)
from apps.console.connection.models import CoreAuthDatabase, CoreAuthWebsite
from apps.console.connection.reliability import (
    DatabaseEventPrivilegeError,
    classified_connection_error,
)
from apps.console.setting.models import CoreSiteSettings
from apps.tests import factories
from apps.tests.base import BaseTestCase
from utils.middleware import OnboardingMiddleware


TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "console"
    / "_templates"
    / "console"
    / "setup"
    / "_setup_and_list_connection.html"
)


class ConnectionViewErrorContractTests(SimpleTestCase):
    def assert_contract(self, response, *, code, retryable):
        self.assertEqual(response.data["connection_error"]["code"], code)
        self.assertIs(response.data["connection_error"]["retryable"], retryable)
        self.assertTrue(response.data["connection_error"]["detail"])
        self.assertTrue(response.data["connection_error"]["remediation"])
        self.assertEqual(response.data["detail"], response.data["connection_error"]["detail"])

    def test_timeout_is_typed_retryable_and_secret_safe(self):
        with mock.patch(
            "apps.console.connection.reliability.logger.warning"
        ) as warning:
            response = connection_error_response(
                socket.timeout("password=never-return-this"),
                stage="validation",
            )
        self.assertEqual(response.status_code, status.HTTP_504_GATEWAY_TIMEOUT)
        self.assert_contract(response, code="TCP_TIMEOUT", retryable=True)
        self.assertNotIn("never-return-this", str(response.data))
        warning.assert_called_once_with(
            "Connection operation failed.",
            extra={
                "connection_failure_code": "TCP_TIMEOUT",
                "connection_failure_stage": "tcp",
            },
        )
        self.assertNotIn("never-return-this", repr(warning.call_args))

    def test_dns_auth_and_host_key_failures_are_distinct(self):
        cases = (
            (socket.gaierror("private.internal"), "DNS_FAILURE", True),
            (paramiko.AuthenticationException("password"), "AUTH_FAILED", False),
            (
                RuntimeError("host is not found in known_hosts; token=private"),
                "HOST_KEY_UNKNOWN",
                False,
            ),
            (
                RuntimeError("SSH host key changed; token=private"),
                "HOST_KEY_CHANGED",
                False,
            ),
        )
        for error, code, retryable in cases:
            with self.subTest(code=code):
                response = connection_error_response(error, stage="validation")
                self.assert_contract(response, code=code, retryable=retryable)
                self.assertNotIn("private", str(response.data))

    def test_decorator_replaces_raw_error_response_body(self):
        @safe_connection_action(stage="object_discovery")
        def unsafe_view():
            return Response(
                {"detail": "access_key=do-not-return"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        response = unsafe_view()
        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assert_contract(
            response,
            code="CONNECTION_VALIDATION_FAILED",
            retryable=False,
        )
        self.assertNotIn("do-not-return", str(response.data))

    def test_decorator_preserves_success_response(self):
        expected = Response({"eligible_objects": []}, status=status.HTTP_200_OK)

        @safe_connection_action(stage="object_discovery")
        def successful_view():
            return expected

        self.assertIs(successful_view(), expected)

    def test_decorator_preserves_object_ownership_404(self):
        @safe_connection_action(stage="object_discovery")
        def hidden_object_view():
            raise Http404("private object identity")

        response = hidden_object_view()
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data, {"detail": "Not found."})
        self.assertNotIn("private object identity", str(response.data))


class LiveConnectionViewContractTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        site_settings = CoreSiteSettings.load()
        site_settings.setup_completed = True
        site_settings.save()
        OnboardingMiddleware._completed = False
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.node = factories.make_website_node(self.account, self.member)

    def test_website_validation_endpoint_never_returns_raw_timeout(self):
        with mock.patch.object(
            CoreAuthWebsite,
            "validate",
            side_effect=socket.timeout("password=api-secret"),
        ):
            response = self.client.post(
                f"/api/v1/connections/website/{self.node.connection_id}/validate/",
                {},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_504_GATEWAY_TIMEOUT)
        self.assertEqual(response.json()["connection_error"]["code"], "TCP_TIMEOUT")
        self.assertNotIn("api-secret", response.content.decode())

    def test_website_object_discovery_endpoint_never_returns_raw_dns_error(self):
        with mock.patch.object(
            CoreAuthWebsite,
            "get_eligible_objects",
            side_effect=socket.gaierror("private.database.internal"),
        ), mock.patch(
            "apps.console.connection.reliability.logger.warning"
        ) as warning:
            response = self.client.post(
                f"/api/v1/connections/website/{self.node.connection_id}/objects/",
                {},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertEqual(response.json()["connection_error"]["code"], "DNS_FAILURE")
        self.assertNotIn("private.database.internal", response.content.decode())
        warning.assert_called_once_with(
            "Connection operation failed.",
            extra={
                "connection_failure_code": "DNS_FAILURE",
                "connection_failure_stage": "dns",
            },
        )
        self.assertNotIn("private.database.internal", repr(warning.call_args))

    def test_database_discovery_endpoints_never_return_exception_text(self):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="database",
        )
        CoreAuthDatabase.objects.create(
            connection=connection,
            host="db.example.com",
            port=5432,
            database_name="appdb",
            type=CoreAuthDatabase.DatabaseType.POSTGRESQL,
            version=CoreAuthDatabase.DatabaseVersion.POSTGRESQL_18,
        )
        cases = (
            ("get_eligible_objects", "objects", "object_discovery"),
            (
                "update_db_type_and_version",
                "update_db_type_and_version",
                "metadata_discovery",
            ),
        )
        for method_name, action_name, expected_stage in cases:
            secret = f"password={action_name}-must-not-leak"
            with self.subTest(action=action_name), mock.patch.object(
                CoreAuthDatabase,
                method_name,
                side_effect=RuntimeError(secret),
            ), mock.patch(
                "apps.console.connection.reliability.logger.warning"
            ) as warning:
                response = self.client.post(
                    f"/api/v1/connections/database/{connection.id}/{action_name}/",
                    {},
                    format="json",
                )

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(
                response.json()["connection_error"]["code"],
                "CONNECTION_VALIDATION_FAILED",
            )
            self.assertEqual(
                response.json()["connection_error"]["stage"],
                expected_stage,
            )
            self.assertNotIn(secret, response.content.decode())
            self.assertNotIn(secret, repr(warning.call_args))
            warning.assert_called_once_with(
                "Connection operation failed.",
                extra={
                    "connection_failure_code": "CONNECTION_VALIDATION_FAILED",
                    "connection_failure_stage": expected_stage,
                },
            )

    def test_database_event_privilege_validation_keeps_specific_safe_contract(self):
        connection = factories.make_connection(
            self.account,
            self.member,
            code="database",
        )
        CoreAuthDatabase.objects.create(
            connection=connection,
            host="db.example.com",
            port=3306,
            database_name="appdb",
            type=CoreAuthDatabase.DatabaseType.MYSQL,
            version=CoreAuthDatabase.DatabaseVersion.MYSQL_8_4,
            include_stored_procedure=True,
        )

        def event_privilege_failure(*_args, **_kwargs):
            try:
                raise RuntimeError("password=api-secret host=db.internal")
            except RuntimeError as raw_error:
                try:
                    raise DatabaseEventPrivilegeError(
                        internal_detail=raw_error.__class__.__name__
                    ) from raw_error
                except DatabaseEventPrivilegeError as event_error:
                    raise classified_connection_error(
                        event_error,
                        stage="database",
                    ) from event_error

        with mock.patch.object(
            CoreAuthDatabase,
            "check_connection",
            side_effect=event_privilege_failure,
        ):
            response = self.client.post(
                f"/api/v1/connections/database/{connection.id}/validate/",
                {},
                format="json",
            )

        payload = response.json()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            payload["connection_error"]["code"],
            "DATABASE_EVENT_PRIVILEGE_REQUIRED",
        )
        self.assertEqual(payload["connection_error"]["stage"], "authorization")
        self.assertFalse(payload["connection_error"]["retryable"])
        self.assertIn("EVENT privilege", payload["connection_error"]["remediation"])
        self.assertNotIn("api-secret", response.content.decode())
        self.assertNotIn("db.internal", response.content.decode())

    def test_provider_specific_validation_keeps_cross_account_resource_hidden(self):
        other_account, other_member, _ = factories.make_account()
        other_node = factories.make_website_node(other_account, other_member)

        response = self.client.post(
            f"/api/v1/connections/website/{other_node.connection_id}/validate/",
            {},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.json(), {"detail": "Not found."})


class ConnectionSetupTemplateResilienceTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.source = TEMPLATE_PATH.read_text()

    def method_source(self, name, next_name):
        return self.source.split(f"async {name}", 1)[1].split(
            f"async {next_name}", 1
        )[0]

    def test_bounded_request_uses_abort_controller_and_always_clears_timer(self):
        request_source = self.method_source("requestJSON", "getOauthUrl")
        self.assertIn("new AbortController()", request_source)
        self.assertIn("controller.abort()", request_source)
        self.assertIn("signal: controller.signal", request_source)
        self.assertIn("finally", request_source)
        self.assertIn("window.clearTimeout(timeout)", request_source)
        self.assertIn("requestTimeoutMs: 60000", self.source)
        self.assertEqual(self.source.count("fetch("), 1)
        self.assertNotIn("response.statusText", self.source)

    def test_validation_and_discovery_only_use_bounded_request_helper(self):
        validate_source = self.method_source(
            "validateConnection", "updateDBTypeAndVersion"
        )
        metadata_source = self.method_source(
            "updateDBTypeAndVersion", "resumeConnection"
        )
        endpoints_source = self.method_source("getEndpoints", "getAWSRegions")
        regions_source = self.method_source("getAWSRegions", "getWordPressKey")
        for source in (
            validate_source,
            metadata_source,
            endpoints_source,
            regions_source,
        ):
            self.assertIn("this.requestJSON", source)
            self.assertNotIn("fetch(", source)
        self.assertIn("finally", validate_source)
        self.assertIn("finally", endpoints_source)
        self.assertIn("finally", regions_source)

    def test_managed_actions_post_then_poll_with_bounded_no_store_requests(self):
        validate_source = self.method_source(
            "validateConnection", "updateDBTypeAndVersion"
        )
        metadata_source = self.method_source(
            "updateDBTypeAndVersion", "resumeConnection"
        )
        polling_source = self.method_source(
            "waitForManagedOperation", "sshHostKeyTarget"
        )
        for source in (validate_source, metadata_source):
            self.assertIn("method: 'POST'", source)
            self.assertIn("body: '{}'", source)
            self.assertIn("await this.waitForManagedOperation", source)
        self.assertIn("managed-ssh-operations", polling_source)
        self.assertIn("this.managedOperationTimeoutMs", polling_source)
        self.assertIn("Date.now() < deadline", polling_source)
        self.assertIn("window.setTimeout(resolve, 750)", polling_source)
        self.assertIn("method: 'GET'", polling_source)
        self.assertIn("cache: 'no-store'", polling_source)
        self.assertIn("this.requestJSON", polling_source)
        self.assertIn('operationStatus === "failed"', polling_source)
        self.assertIn('operationStatus === "expired"', polling_source)

    def test_submit_and_validate_controls_are_disabled_and_restored(self):
        self.assertIn(
            ':disabled="loading || discoveryLoading || connectionMutationOutcomeUnknown"',
            self.source,
        )
        self.assertIn(
            ":disabled=\"validatingConnectionId === '{{ connection.id }}'\"",
            self.source,
        )
        save_source = self.method_source("saveConnection", "pauseConnection")
        self.assertIn("finally", save_source)
        self.assertIn("this.loading = false", save_source)

    def test_save_failure_preserves_live_secret_fields(self):
        save_source = self.method_source("saveConnection", "pauseConnection")
        self.assertNotIn("this.selectedAuth.private_key = null", save_source)
        self.assertNotIn("this.selectedAuth.ssh_password = null", save_source)
        self.assertIn("JSON.parse(JSON.stringify(this.selectedAuth))", save_source)

    def test_structured_error_contract_is_rendered_inline(self):
        for field in ("code", "detail", "remediation", "retryable"):
            self.assertIn(f"connectionFailure?.{field}", self.source)

    def test_full_mysql_object_option_discloses_events_and_privilege(self):
        self.assertIn("Include Database Objects?", self.source)
        self.assertIn(
            "stored procedures, functions, triggers, and scheduled event definitions",
            self.source,
        )
        self.assertIn("EVENT privilege", self.source)
        for code in (
            "REQUEST_TIMEOUT",
            "TCP_TIMEOUT",
            "DNS_FAILURE",
            "AUTH_FAILED",
            "HOST_KEY_UNKNOWN",
            "HOST_KEY_CHANGED",
        ):
            self.assertIn(code, self.source)
        self.assertNotIn("response.statusText", self.method_source("requestJSON", "getOauthUrl"))

    def test_new_mysql_84_selection_defaults_tls_without_overriding_opt_out(self):
        self.assertIn('@click="selectDatabaseVersion(version)"', self.source)
        self.assertIn("version?.code === 'mysql_8_4'", self.source)
        self.assertIn(
            "typeof this.selectedAuth.use_ssl === 'undefined'",
            self.source,
        )
        self.assertIn("this.selectedAuth.use_ssl = true", self.source)
        self.assertIn("New MySQL 8.4 connections start with TLS required", self.source)
        self.assertNotIn("ssl-mode=PREFERRED", self.source)

    def test_managed_key_divider_remains_when_managed_key_is_unavailable(self):
        marker = "<!-- Website and Database-->"
        section = self.source.split(marker, 1)[1].split(
            "Use Your Private Key?", 1
        )[0]
        self.assertLess(
            section.index('border-t border-slate-200'),
            section.index('{% if ssh_managed_key_enabled %}'),
        )

    def test_unknown_ssh_host_key_has_explicit_review_and_approval_flow(self):
        self.assertIn("async previewSSHHostKey()", self.source)
        self.assertIn("async approveSSHHostKey(replace = false)", self.source)
        self.assertIn("/api/v1/utils/ssh-host-keys/preview/", self.source)
        self.assertIn("/api/v1/utils/ssh-host-keys/approve/", self.source)
        self.assertIn("hostKeyReview?.fingerprint", self.source)
        self.assertIn("Approve this host key and retry", self.source)
        self.assertIn("Replace verified host key and retry", self.source)
        self.assertIn("await this.previewSSHHostKey()", self.source)
        self.assertIn("await this.saveConnection()", self.source)
        self.assertNotIn("hostKeyReview?.key_base64", self.source)

    def test_ssh_security_switches_have_distinct_accessible_names(self):
        self.assertIn('aria-label="Use your private key"', self.source)
        self.assertIn(
            'aria-label="Use legacy SHA-1 key verification"',
            self.source,
        )


class NodeSetupManagedOperationTemplateTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        root = Path(__file__).resolve().parents[1] / "console" / "_templates" / "console" / "setup"
        cls.database = (root / "_setup_database_node.html").read_text()
        cls.website = (root / "_setup_website_node.html").read_text()

    def test_object_discovery_posts_and_polls_with_deadlines_and_abort(self):
        for name, source in (("database", self.database), ("website", self.website)):
            with self.subTest(template=name):
                self.assertIn("async waitForManagedObjectDiscovery(accepted)", source)
                self.assertIn("managed-ssh-operations", source)
                self.assertIn("const deadline = Date.now() + 300000", source)
                self.assertIn("Date.now() < deadline", source)
                self.assertIn("new AbortController()", source)
                self.assertIn("controller.abort()", source)
                self.assertIn("window.clearTimeout(timeout)", source)
                self.assertIn("cache: 'no-store'", source)
                object_source = source.split("async getObjects(path)", 1)[1]
                self.assertIn("method: 'POST'", object_source)
                self.assertIn("waitForManagedObjectDiscovery", object_source)
