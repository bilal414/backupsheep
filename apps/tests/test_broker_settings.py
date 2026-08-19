from pathlib import Path

from django.test import SimpleTestCase

from backupsheep.settings import _resolve_celery_broker_url


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RABBITMQ_CONFIG = PROJECT_ROOT / "deploy" / "rabbitmq" / "90-backupsheep.conf"
COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"


class CeleryBrokerSettingsTests(SimpleTestCase):
    def test_rabbitmq_fragments_take_precedence_and_escape_credentials(self):
        broker_url = _resolve_celery_broker_url(
            {
                "CELERY_BROKER_URL": "memory://should-not-be-used",
                "RABBITMQ_HOST": "rabbitmq.internal",
                "RABBITMQ_PORT": "5673",
                "RABBITMQ_USER": "backup user",
                "RABBITMQ_PASSWORD": "p@ss:/?",
                "RABBITMQ_VHOST": "/production jobs",
            }
        )

        self.assertEqual(
            broker_url,
            "amqp://backup%20user:p%40ss%3A%2F%3F@rabbitmq.internal:5673/production%20jobs",
        )

    def test_default_virtual_host_uses_rabbitmq_root_path(self):
        broker_url = _resolve_celery_broker_url(
            {"RABBITMQ_HOST": "rabbitmq.internal"}
        )

        self.assertEqual(
            broker_url, "amqp://guest:guest@rabbitmq.internal:5672//"
        )

    def test_cloudamqp_url_takes_precedence_over_compose_fallback(self):
        broker_url = _resolve_celery_broker_url(
            {
                "CELERY_BROKER_URL": "amqp://guest:guest@rabbitmq:5672//",
                "CLOUDAMQP_URL": "amqps://backup:secret@rabbitmq.example/vhost",
            }
        )

        self.assertEqual(
            broker_url, "amqps://backup:secret@rabbitmq.example/vhost"
        )

    def test_non_amqp_broker_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "RabbitMQ"):
            _resolve_celery_broker_url({"CELERY_BROKER_URL": "memory://"})


class RabbitMQRuntimeContractTests(SimpleTestCase):
    def test_late_ack_timeout_exceeds_longest_external_command_budget(self):
        settings = {}
        for raw_line in RABBITMQ_CONFIG.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            settings[key] = value

        timeout_ms = int(settings["consumer_timeout"])
        self.assertGreater(timeout_ms, 23 * 60 * 60 * 1000)
        self.assertEqual(timeout_ms, 25 * 60 * 60 * 1000)

    def test_compose_mounts_the_broker_timeout_contract_read_only(self):
        compose = COMPOSE_FILE.read_text(encoding="utf-8")

        self.assertIn(
            "./deploy/rabbitmq/90-backupsheep.conf:"
            "/etc/rabbitmq/conf.d/90-backupsheep.conf:ro",
            compose,
        )
