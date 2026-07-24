from django.test import SimpleTestCase

from backupsheep.settings import _resolve_celery_broker_url


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

    def test_non_amqp_broker_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "RabbitMQ"):
            _resolve_celery_broker_url({"CELERY_BROKER_URL": "memory://"})
