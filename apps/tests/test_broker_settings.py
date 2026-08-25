from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from backupsheep.settings import _resolve_celery_broker_url


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RABBITMQ_CONFIG = PROJECT_ROOT / "deploy" / "rabbitmq" / "90-backupsheep.conf"
RABBITMQ_PROVISION = PROJECT_ROOT / "deploy" / "rabbitmq" / "provision.sh"
COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"
ENV_SAMPLE = PROJECT_ROOT / ".env_sample"
SCALING_GUIDE = PROJECT_ROOT / "docs" / "scaling.md"


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

    def test_production_rejects_missing_or_default_guest_credentials(self):
        with self.assertRaisesRegex(ImproperlyConfigured, "required"):
            _resolve_celery_broker_url(
                {
                    "DJANGO_SERVER": "prod",
                    "RABBITMQ_HOST": "rabbitmq",
                }
            )

        with self.assertRaisesRegex(ImproperlyConfigured, "non-default"):
            _resolve_celery_broker_url(
                {
                    "DJANGO_SERVER": "prod",
                    "CELERY_BROKER_URL": "amqp://guest:guest@rabbitmq:5672//",
                }
            )


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

    def test_compose_uses_a_stable_rabbitmq_hostname(self):
        compose = COMPOSE_FILE.read_text(encoding="utf-8")
        rabbitmq_service = compose.split("\n  rabbitmq:\n", 1)[1].split(
            "\n  migrate:\n", 1
        )[0]

        self.assertIn("\n    hostname: rabbitmq\n", rabbitmq_service)

    def test_default_broker_user_is_not_a_management_administrator(self):
        provision = RABBITMQ_PROVISION.read_text(encoding="utf-8")

        self.assertIn("RabbitMQ user tag drift detected", provision)
        self.assertIn("awk '$2 != \"[]\" { exit 1 }'", provision)


class WorkerCapacityContractTests(SimpleTestCase):
    DEFAULTS = {
        "cloud": ("4", "1"),
        "database": ("1", "1"),
        "files": ("1", "1"),
        "storage": ("2", "1"),
        "logs": ("2", "1"),
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.compose = COMPOSE_FILE.read_text(encoding="utf-8")
        cls.env_sample = ENV_SAMPLE.read_text(encoding="utf-8")

    def _service(self, name):
        service = self.compose.split(f"\n  worker-{name}:\n", 1)[1]
        service = service.split("\n  worker-", 1)[0]
        return service.split("\n  beat:\n", 1)[0]

    def test_each_queue_has_an_independent_bounded_default(self):
        for queue, (concurrency, prefetch) in self.DEFAULTS.items():
            with self.subTest(queue=queue):
                service = self._service(queue)
                variable = queue.upper()
                self.assertIn(
                    f"--concurrency=${{CELERY_{variable}_CONCURRENCY:-{concurrency}}}",
                    service,
                )
                self.assertIn(
                    f"--prefetch-multiplier=${{CELERY_{variable}_PREFETCH_MULTIPLIER:-{prefetch}}}",
                    service,
                )

    def test_sample_environment_matches_compose_capacity_defaults(self):
        for queue, (concurrency, prefetch) in self.DEFAULTS.items():
            with self.subTest(queue=queue):
                variable = queue.upper()
                self.assertIn(
                    f"CELERY_{variable}_CONCURRENCY={concurrency}",
                    self.env_sample,
                )
                self.assertIn(
                    f"CELERY_{variable}_PREFETCH_MULTIPLIER={prefetch}",
                    self.env_sample,
                )

    def test_cpu_and_disk_heavy_workers_default_to_one_active_job(self):
        self.assertEqual(self.DEFAULTS["database"][0], "1")
        self.assertEqual(self.DEFAULTS["files"][0], "1")

    def test_operator_guides_match_starter_capacity_contract(self):
        text = SCALING_GUIDE.read_text(encoding="utf-8")
        for queue, (concurrency, _prefetch) in self.DEFAULTS.items():
            with self.subTest(documented_queue=queue):
                self.assertIn(f"{queue} `{concurrency}`", text)
        self.assertIn("2 vCPU", text)
        self.assertIn("4 GB RAM", text)
        self.assertIn("8 GB of SSD-backed swap", text)
