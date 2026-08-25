from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase


class RabbitMQCapacityPolicyTests(SimpleTestCase):
    def setUp(self):
        self.root = Path(settings.BASE_DIR)

    def test_every_stock_queue_has_reject_publish_message_and_byte_bounds(self):
        provision = (self.root / "deploy/rabbitmq/provision.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("queue_max_messages='10000'", provision)
        self.assertIn("queue_max_bytes='67108864'", provision)
        self.assertIn(
            "queue_pattern='^(default|cloud|database|files|storage|logs)$'",
            provision,
        )
        self.assertIn('"overflow":\"reject-publish\"', provision)
        self.assertIn("set_policy -p", provision)
        self.assertIn("effective_policy_definition", provision)

    def test_capacity_policy_is_upgrade_safe_and_probe_uses_confirms(self):
        entrypoint = (self.root / "deploy/rabbitmq/entrypoint.sh").read_text(
            encoding="utf-8"
        )
        provision = (self.root / "deploy/rabbitmq/provision.sh").read_text(
            encoding="utf-8"
        )
        probe = (self.root / "deploy/rabbitmq/flood-probe.py").read_text(
            encoding="utf-8"
        )
        # Existing durable queues retain empty declaration arguments; the policy
        # can be applied in place without deleting queued recovery work.
        self.assertIn('"queues":[{"name":"default"', entrypoint)
        self.assertIn('"arguments":{}', entrypoint)
        self.assertNotIn("delete_queue", provision)
        self.assertIn('transport_options={"confirm_publish": True}', probe)
        self.assertIn("MessageNacked", probe)
        self.assertIn("--password-file", probe)
        self.assertNotIn("password=args.", probe)

    def test_password_hashing_never_places_plaintext_in_process_arguments(self):
        provision = (self.root / "deploy/rabbitmq/provision.sh").read_text(
            encoding="utf-8"
        )
        entrypoint = (self.root / "deploy/rabbitmq/entrypoint.sh").read_text(
            encoding="utf-8"
        )
        for script in (entrypoint, provision):
            self.assertNotIn("rabbitmqctl hash_password", script)
            self.assertIn("openssl dgst -sha256 -binary", script)
            self.assertNotIn('authenticate_user "$user" "$password"', script)
        self.assertIn("printf '%s' \"$password\"", entrypoint)
        self.assertIn("printf '%s' \"$cleartext\"", provision)
        self.assertIn("add_user \"$user\" \"$hash\" --pre-hashed-password", provision)
        self.assertIn("rabbit_auth_backend_internal:lookup_user", provision)
        self.assertIn("rabbit_password_hashing_sha256", provision)
