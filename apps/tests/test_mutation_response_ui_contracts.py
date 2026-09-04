import re
import shutil
import subprocess
import unittest
from pathlib import Path

from django.template.loader import get_template
from django.test import SimpleTestCase


TEMPLATE_ROOT = (
    Path(__file__).resolve().parents[1]
    / "console"
    / "_templates"
    / "console"
)


def _method_body(source, signature, next_signature):
    pattern = (
        re.escape(signature)
        + r"(?P<body>.*?)\n\s*\},\n\s*"
        + re.escape(next_signature)
    )
    match = re.search(pattern, source, flags=re.DOTALL)
    if not match:
        raise AssertionError(f"Unable to extract JavaScript method {signature}")
    return match.group("body")


def _run_node(script):
    if not shutil.which("node"):
        raise unittest.SkipTest("Node.js is required for the JavaScript contract.")
    return subprocess.run(
        ["node"],
        input=script,
        capture_output=True,
        check=False,
        text=True,
    )


class MutationResponseTemplateContractTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.connection = (
            TEMPLATE_ROOT / "setup" / "_setup_and_list_connection.html"
        ).read_text(encoding="utf-8")
        cls.invite = (
            TEMPLATE_ROOT / "setting" / "invite.html"
        ).read_text(encoding="utf-8")
        cls.multifactor = (
            TEMPLATE_ROOT / "setting" / "multifactor.html"
        ).read_text(encoding="utf-8")
        cls.node_detail = (
            TEMPLATE_ROOT / "node" / "detail.html"
        ).read_text(encoding="utf-8")
        cls.catalog = (
            TEMPLATE_ROOT / "setup" / "1_integration_select.html"
        ).read_text(encoding="utf-8")
        cls.connection_page = (
            TEMPLATE_ROOT / "setup" / "2_integration_open.html"
        ).read_text(encoding="utf-8")

    def test_changed_templates_compile(self):
        for template_name in (
            "console/setup/1_integration_select.html",
            "console/setup/2_integration_open.html",
            "console/setup/_setup_and_list_connection.html",
            "console/setting/invite.html",
            "console/setting/multifactor.html",
            "console/node/detail.html",
        ):
            with self.subTest(template=template_name):
                get_template(template_name)

    def test_connection_save_rejects_a_null_2xx_receipt_and_locks_retry(self):
        body = _method_body(
            self.connection,
            "requireConnectionMutationReceipt(payload) {",
            "extractConnectionFailure(payload, responseStatus = null) {",
        )
        script = f"""
            const component = {{
                unknownConnectionMutationError() {{
                    const error = new Error('unknown');
                    error.connectionFailure = {{code: 'REQUEST_OUTCOME_UNKNOWN'}};
                    return error;
                }},
                requireConnectionMutationReceipt(payload) {{{body}
                }}
            }};
            try {{
                component.requireConnectionMutationReceipt(null);
                process.exit(2);
            }} catch (error) {{
                if (error.connectionFailure?.code !== 'REQUEST_OUTCOME_UNKNOWN') process.exit(3);
            }}
            const receipt = {{id: 17}};
            if (component.requireConnectionMutationReceipt(receipt) !== receipt) process.exit(4);
        """
        completed = _run_node(script)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            ":disabled=\"loading || discoveryLoading || connectionMutationOutcomeUnknown\"",
            self.connection,
        )
        self.assertIn(
            "if (this.loading || this.discoveryLoading || this.connectionMutationOutcomeUnknown) return;",
            self.connection,
        )
        self.assertIn("this.connectionMutationOutcomeUnknown = true", self.connection)
        self.assertIn("Reload before retrying", self.connection)

    def test_invite_accept_treats_a_null_2xx_receipt_as_unknown(self):
        accept = self.invite.split("async acceptInvite(id) {", 1)[1].split(
            "openReject(id, workspace, trigger) {", 1
        )[0]
        self.assertIn("if (!json || typeof json !== 'object'", accept)
        self.assertIn("unknown.outcomeUnknown = true", accept)
        self.assertLess(accept.index("if (!json"), accept.index("json.detail"))
        self.assertIn("Reload this page before retrying", self.invite)

    def test_mfa_mutations_reject_null_2xx_and_incomplete_setup_receipts(self):
        body = _method_body(
            self.multifactor,
            "async mutation(path, payload) {",
            "showMutationError(error, definiteHeading) {",
        )
        script = f"""
            global.fetch = async () => ({{
                ok: true,
                status: 200,
                json: async () => null,
            }});
            const component = {{
                initial: {{id: 9}},
                memberErrors: {{}},
                firstError(value) {{ return value || ''; }},
                unknownSecurityChangeError() {{
                    const error = new Error('unknown');
                    error.outcomeUnknown = true;
                    return error;
                }},
                async mutation(path, payload) {{{body}
                }}
            }};
            component.mutation('auth_multi_factor_token_verify', {{}}).then(
                () => process.exit(2),
                (error) => process.exit(error.outcomeUnknown ? 0 : 3),
            );
        """
        completed = _run_node(script)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        setup = self.multifactor.split("async setupTokenAuth() {", 1)[1].split(
            "async verifyTokenAuth() {", 1
        )[0]
        self.assertIn("!json.binding", setup)
        self.assertIn("typeof json.binding.secret !== 'string'", setup)
        self.assertIn("throw this.unknownSecurityChangeError()", setup)
        self.assertIn("Reload this page before retrying", self.multifactor)

    def test_node_validation_rejects_a_null_2xx_receipt_as_unknown(self):
        body = _method_body(
            self.node_detail,
            "assertValidationReceipt(payload, requireDetail = true) {",
            "notifyValidationError(error) {",
        )
        script = f"""
            const component = {{
                validationOutcomeUnknownError() {{
                    const error = new Error('unknown');
                    error.outcomeUnknown = true;
                    return error;
                }},
                assertValidationReceipt(payload, requireDetail = true) {{{body}
                }}
            }};
            try {{
                component.assertValidationReceipt(null);
                process.exit(2);
            }} catch (error) {{
                if (!error.outcomeUnknown) process.exit(3);
            }}
            const receipt = {{detail: 'Provider source reachable.'}};
            if (component.assertValidationReceipt(receipt) !== receipt) process.exit(4);
        """
        completed = _run_node(script)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Validation outcome not confirmed", self.node_detail)
        self.assertIn("Reload this page before retrying", self.node_detail)
        self.assertGreaterEqual(
            self.node_detail.count("this.assertValidationReceipt(json"),
            3,
        )

    def test_setup_progress_uses_a_non_clipping_mobile_layout(self):
        for source in (self.catalog, self.connection_page):
            with self.subTest(template="catalog" if source is self.catalog else "connection"):
                self.assertIn(
                    'class="min-w-0 w-full lg:w-auto" aria-label="Connection setup progress"',
                    source,
                )
                self.assertIn("grid grid-cols-1", source)
                self.assertIn("sm:grid-cols-3", source)
                self.assertIn("min-h-11 min-w-0", source)
