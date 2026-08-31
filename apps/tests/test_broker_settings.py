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
        node_host = (
            "${BACKUPSHEEP_RABBITMQ_NODE_HOST:?"
            "BACKUPSHEEP_RABBITMQ_NODE_HOST is required}"
        )

        self.assertIn(f'\n    hostname: "{node_host}"\n', rabbitmq_service)
        self.assertIn(
            f'RABBITMQ_NODENAME: "rabbit@{node_host}"', rabbitmq_service
        )

    def test_default_broker_user_is_not_a_management_administrator(self):
        provision = RABBITMQ_PROVISION.read_text(encoding="utf-8")

        self.assertIn('$2 != "[]" || seen[$1]++', provision)

    def test_provisioner_classifies_complete_broker_before_first_mutation(self):
        provision = RABBITMQ_PROVISION.read_text(encoding="utf-8")
        classification_markers = (
            'raw_listed_vhosts="$(ctl list_vhosts name --silent)"',
            "preexisting_vhost_metadata=",
            'preexisting_global_parameter_semantics="$(global_parameter_semantics)"',
            "preexisting_internal_cluster_id=",
            'preexisting_product_parameters="$(ctl -p "$vhost" list_parameters --no-table-headers)"',
            'preexisting_user_limits="$(ctl list_user_limits --global --no-table-headers)"',
            'preexisting_global_vhost_limits="$(ctl list_vhost_limits --global --no-table-headers)"',
            'preexisting_product_vhost_limits="$(ctl list_vhost_limits --vhost "$vhost" --no-table-headers)"',
            'listed_users="$(ctl list_users --no-table-headers)"',
            'raw_preexisting_queues="$(ctl -p "$vhost" list_queues name type durable auto_delete exclusive arguments --silent)"',
            'preexisting_exchanges="$(ctl -p "$vhost" list_exchanges name type durable auto_delete internal arguments --silent)"',
            'preexisting_bindings="$(ctl -p "$vhost" list_bindings source_name destination_name destination_kind routing_key arguments --silent)"',
            'preexisting_policies="$(ctl -p "$vhost" list_policies --silent)"',
            'preexisting_operator_policies="$(ctl -p "$vhost" list_operator_policies --silent)"',
            'preexisting_connections="$(ctl list_connections pid user vhost --silent)"',
            'list_topic_permissions --no-table-headers',
            "prepared_password_hashes=''",
        )
        first_mutation = provision.index(
            'delete_if_present "backupsheep_${role}"'
        )
        for marker in classification_markers:
            with self.subTest(marker=marker):
                self.assertLess(provision.index(marker), first_mutation)
        self.assertLess(
            provision.index("default virtual host contains a queue"),
            first_mutation,
        )
        self.assertLess(
            provision.index("prepared_password_hashes=''"),
            first_mutation,
        )
        self.assertLess(
            provision.index('password="$(read_secret "$role")"'),
            first_mutation,
        )
        self.assertNotIn('[ -z "$(ctl', provision)
        for marker in (
            "default_queues=\"$(ctl -p / list_queues",
            "default_parameters=\"$(ctl -p / list_parameters",
            "default_bindings=\"$(ctl -p / list_bindings",
            "default_policies=\"$(ctl -p / list_policies",
            "default_topic_permissions=\"$(ctl -p / list_topic_permissions",
        ):
            with self.subTest(marker=marker):
                self.assertLess(
                    provision.index(marker),
                    first_mutation,
                )
        self.assertNotIn("ctl delete_vhost /", provision)
        self.assertGreater(
            provision.index("final_default_queues="), first_mutation
        )
        self.assertGreater(
            provision.index("final_connections="), first_mutation
        )

    def test_provisioner_attests_topology_object_properties_and_binding_kind(self):
        provision = RABBITMQ_PROVISION.read_text(encoding="utf-8")

        self.assertIn(
            "list_queues name type durable auto_delete exclusive arguments --silent",
            provision,
        )
        self.assertIn(
            "list_exchanges name type durable auto_delete internal arguments --silent",
            provision,
        )
        self.assertIn(
            "list_bindings source_name destination_name destination_kind "
            "routing_key arguments --silent",
            provision,
        )
        self.assertIn('$3 != "queue"', provision)
        self.assertIn('$4 != $2 || $5 != "[]"', provision)
        self.assertIn('$2 != "direct" || $3 != "true"', provision)
        self.assertIn('[{"x-queue-type","classic"}]', provision)
        for built_in in (
            "amq.direct",
            "amq.fanout",
            "amq.headers",
            "amq.match",
            "amq.rabbitmq.log",
            "amq.rabbitmq.trace",
            "amq.topic",
        ):
            with self.subTest(built_in=built_in):
                self.assertIn(f'$1 == "{built_in}"', provision)
        self.assertIn("validate_reviewed_exchanges product", provision)
        self.assertIn("validate_reviewed_exchanges default", provision)
        self.assertIn('exchange_inventory != "default"', provision)
        self.assertIn('exchange_inventory != "product" || !reviewed_exchange($1)', provision)
        self.assertIn('seen_builtin["amq.rabbitmq.log"] != 1', provision)
        self.assertNotIn('$1 ~ /^amq\\./ { next }', provision)

    def test_user_inventory_parser_cannot_collapse_crafted_usernames(self):
        provision = RABBITMQ_PROVISION.read_text(encoding="utf-8")
        first_mutation = provision.index(
            'delete_if_present "backupsheep_${role}"'
        )

        for marker in (
            "parse_user_inventory()",
            "awk -F '\\t'",
            '$1 !~ /^[a-z0-9_]+$/',
            "length(rabbit_auth_backend_internal:list_users())",
            "RabbitMQ user inventory contains record-boundary injection.",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, provision)
                self.assertLess(provision.index(marker), first_mutation)
        self.assertNotIn("awk 'NF {print $1}'", provision)
        self.assertNotIn("awk '{print $1}'", provision)

    def test_provisioner_attests_all_persistent_runtime_metadata(self):
        provision = RABBITMQ_PROVISION.read_text(encoding="utf-8")
        first_mutation = provision.index(
            'delete_if_present "backupsheep_${role}"'
        )

        for marker in (
            "global_parameter_semantics",
            "validate_vhost_metadata",
            "rabbit_runtime_parameters:list_global()",
            "lookup_global(imported_definition_hash_value)",
            "list_parameters --no-table-headers",
            "list_user_limits --global --no-table-headers",
            "name tracing default_queue_type description tags protected_from_deletion cluster_state",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, provision)
                self.assertLess(provision.index(marker), first_mutation)
        self.assertGreaterEqual(provision.count("global_parameter_semantics"), 3)
        self.assertGreaterEqual(provision.count("list_parameters"), 4)
        self.assertGreaterEqual(provision.count("list_user_limits"), 2)
        self.assertGreaterEqual(
            provision.count("lookup_global(imported_definition_hash_value)"),
            1,
        )
        self.assertIn(
            'final_internal_cluster_id" = "$preexisting_internal_cluster_id',
            provision,
        )

    def test_provisioner_rejects_operator_policy_and_exact_policy_drift(self):
        provision = RABBITMQ_PROVISION.read_text(encoding="utf-8")

        self.assertGreaterEqual(provision.count("list_operator_policies"), 4)
        self.assertIn("RabbitMQ operator policies are not allowed", provision)
        self.assertIn("validate_reviewed_queue_policy", provision)
        self.assertIn('gsub(/"max-length":10000/', provision)
        self.assertIn('gsub(/"max-length-bytes":67108864/', provision)
        self.assertIn('gsub(/"overflow":"reject-publish"/', provision)

    def test_legacy_user_deduplication_uses_exact_full_usernames(self):
        provision = RABBITMQ_PROVISION.read_text(encoding="utf-8")

        self.assertNotIn("${legacy_user#backupsheep_}", provision)
        self.assertIn(
            "guest|backupsheep_bootstrap|backupsheep_app|backupsheep_preflight|",
            provision,
        )
        self.assertIn('*) delete_if_present "$legacy_user" ;;', provision)

    def test_provisioner_quiesces_racing_legacy_connections_before_new_users(self):
        provision = RABBITMQ_PROVISION.read_text(encoding="utf-8")

        first_delete = provision.index(
            'delete_if_present "backupsheep_${role}"'
        )
        close_connections = provision.index("ctl close_all_connections --global")
        first_add = provision.index('ctl add_user "$user"')
        self.assertLess(
            provision.index("preexisting_connections="), first_delete
        )
        self.assertLess(first_delete, close_connections)
        self.assertLess(close_connections, first_add)
        self.assertIn("remaining_connections=", provision)
        self.assertIn("final_connections=", provision)

    def test_provisioner_rejects_all_global_and_per_vhost_limits(self):
        provision = RABBITMQ_PROVISION.read_text(encoding="utf-8")

        self.assertGreaterEqual(provision.count("list_vhost_limits"), 6)
        self.assertIn("global virtual-host limits are not allowed", provision)
        self.assertIn("product virtual-host limits are not allowed", provision)
        self.assertIn("default virtual-host limits are not allowed", provision)


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
