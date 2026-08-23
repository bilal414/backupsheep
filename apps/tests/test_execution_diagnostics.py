"""Private diagnostics retain raw exceptions only in correlated Sentry events."""

from unittest import mock

from django.test import SimpleTestCase

from apps._tasks.diagnostics import capture_execution_diagnostic


class ExecutionDiagnosticTests(SimpleTestCase):
    @mock.patch("apps._tasks.diagnostics.capture_exception")
    @mock.patch("apps._tasks.diagnostics.push_scope")
    def test_sentry_event_is_correlation_tagged_without_secret_tags(
        self,
        push_scope,
        capture_exception,
    ):
        scope = push_scope.return_value.__enter__.return_value
        error = RuntimeError("password=raw-secret /srv/customer/private")

        capture_execution_diagnostic(
            error,
            correlation_id="8f841859-63e0-4b78-bb0b-d35043ce4418",
            attempt_no=3,
            stage="website_manifest",
            code="WEBSITE_MANIFEST_FAILED",
        )

        capture_exception.assert_called_once_with(error)
        tags = {call.args for call in scope.set_tag.call_args_list}
        self.assertIn(
            ("backupsheep.correlation_id", "8f841859-63e0-4b78-bb0b-d35043ce4418"),
            tags,
        )
        self.assertIn(("backupsheep.attempt", 3), tags)
        self.assertIn(("backupsheep.stage", "website_manifest"), tags)
        self.assertIn(("backupsheep.code", "WEBSITE_MANIFEST_FAILED"), tags)
        self.assertNotIn("raw-secret", str(tags))
        self.assertNotIn("/srv/customer/private", str(tags))
