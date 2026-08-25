from django.test import SimpleTestCase

from backupsheep.database_lane_policy import (
    ARTIFACT_LEDGER_TABLES,
    BEAT_TABLES,
    CLOUD_NODE_AND_BACKUP_WRITES,
    CORE_NODE_DELETION_COLUMNS,
    CORE_NODE_STATUS_COLUMNS,
    DML,
    EXPECTED_ROUTINE_ATTRIBUTES,
    EXPECTED_ROUTINES,
    EXPECTED_TRIGGERS,
    EXPECTED_MANAGED_SSH_FOREIGN_KEYS,
    LANE_COLUMN_SELECT_POLICY,
    LANE_COLUMN_UPDATE_POLICY,
    LANE_TABLE_POLICY,
    MANAGED_SSH_MUTABLE_COLUMNS,
    MANAGED_SSH_OPERATION_TABLE,
    MANAGED_SSH_PUBLICATION_COLUMNS,
    MANAGED_SSH_RETENTION_ROUTINE,
    MANAGED_SSH_ROUTINES,
    MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE,
    REPLAY_TABLE,
    RESULT_TABLES,
    RLS_COMMAND_POLICY,
    RLS_POLICY,
    ROW_SECURITY_TABLES,
    ROUTINE_EXECUTE_POLICY,
    SSH_HOST_KEY_APPROVAL_REPLACEMENT_COLUMNS,
    SSH_HOST_KEY_APPROVAL_EVENT_TABLE,
    SSH_HOST_KEY_APPROVAL_TABLE,
    STORAGE_CONFIG_TABLES,
    UNUSED_WORKER_TABLES,
)


class DatabaseLanePolicyTests(SimpleTestCase):
    def test_non_beat_workers_cannot_read_or_mutate_scheduler_tables(self):
        for lane in ("cloud", "database", "files", "storage", "logs"):
            for table in BEAT_TABLES:
                with self.subTest(lane=lane, table=table):
                    self.assertNotIn(table, LANE_TABLE_POLICY[lane])

    def test_beat_can_commit_occurrences_without_identity_or_storage_access(self):
        beat = LANE_TABLE_POLICY["beat"]
        self.assertEqual(
            beat["core_backup_request"],
            frozenset({"SELECT", "INSERT", "UPDATE"}),
        )
        self.assertEqual(
            beat["core_schedule_run"], frozenset({"SELECT", "INSERT"})
        )
        self.assertEqual(
            LANE_COLUMN_UPDATE_POLICY["beat"]["core_schedule"],
            frozenset({"modified"}),
        )
        for table in (
            "auth_user",
            "core_member",
            "core_member_mtm_account",
            "core_storage",
        ):
            with self.subTest(table=table):
                self.assertNotIn(table, beat)

    def test_storage_cannot_read_identity_source_or_provider_secrets(self):
        denied = {
            "auth_user",
            "authtoken_token",
            "django_session",
            "core_auth_aws",
            "core_auth_database",
            "core_auth_website",
            "core_auth_wordpress",
            "core_cloud_restore",
            "core_aws_backup",
            "core_notification_slack",
            "core_notification_telegram",
            "core_site_settings",
        }
        storage = LANE_TABLE_POLICY["storage"]
        self.assertTrue(denied.isdisjoint(storage))
        self.assertNotIn("core_notification_delivery", storage)
        self.assertNotIn(
            "core_notification_slack", LANE_COLUMN_SELECT_POLICY["storage"]
        )
        self.assertNotIn(
            "core_notification_telegram", LANE_COLUMN_SELECT_POLICY["storage"]
        )

    def test_cloud_dml_is_an_explicit_provider_inventory(self):
        cloud = LANE_TABLE_POLICY["cloud"]
        for table in (
            "core_database_backup",
            "core_database_restore",
            "core_website_backup",
            "core_website_restore",
            "core_wordpress_backup",
            "core_basecamp_backup",
        ):
            with self.subTest(table=table):
                self.assertNotIn(table, cloud)
        self.assertEqual(cloud["core_lightsail_bucket_replication"], DML)
        self.assertEqual(cloud["core_lightsail_bucket_restore_run"], DML)
        self.assertNotIn("core_database_backup", CLOUD_NODE_AND_BACKUP_WRITES)
        self.assertNotIn("core_website_restore", CLOUD_NODE_AND_BACKUP_WRITES)

    def test_cloud_provider_credentials_are_read_only_except_ownership_witnesses(self):
        cloud = LANE_TABLE_POLICY["cloud"]
        for table in (
            "core_auth_aws",
            "core_auth_digitalocean",
            "core_auth_google_cloud",
            "core_auth_hetzner",
            "core_auth_lightsail",
            "core_auth_oracle",
            "core_auth_upcloud",
            "core_auth_vultr",
        ):
            with self.subTest(table=table):
                self.assertEqual(cloud[table], frozenset({"SELECT"}))
        self.assertEqual(
            LANE_COLUMN_UPDATE_POLICY["cloud"]["core_auth_digitalocean"],
            frozenset({"info_email", "info_name", "info_uuid", "modified"}),
        )
        self.assertEqual(
            LANE_COLUMN_UPDATE_POLICY["cloud"]["core_auth_upcloud"],
            frozenset({"modified", "username"}),
        )
        for table in (
            "core_auth_aws",
            "core_auth_google_cloud",
            "core_auth_hetzner",
            "core_auth_lightsail",
            "core_auth_oracle",
            "core_auth_vultr",
        ):
            with self.subTest(table=table):
                self.assertNotIn(
                    table, LANE_COLUMN_UPDATE_POLICY.get("cloud", {})
                )

    def test_shared_control_rows_are_command_and_lane_isolated(self):
        for table in (
            "core_account",
            "core_backup_request",
            "core_connection",
            "core_log",
            "core_node",
            "core_schedule",
            "core_schedule_storage_points",
        ):
            with self.subTest(table=table):
                self.assertIn(table, ROW_SECURITY_TABLES)

        self.assertEqual(
            LANE_TABLE_POLICY["database"]["core_node"],
            frozenset({"SELECT"}),
        )
        self.assertEqual(
            LANE_TABLE_POLICY["files"]["core_node"], frozenset({"SELECT"})
        )
        self.assertEqual(
            LANE_COLUMN_UPDATE_POLICY["database"]["core_node"],
            CORE_NODE_STATUS_COLUMNS,
        )
        self.assertEqual(
            LANE_COLUMN_UPDATE_POLICY["files"]["core_node"],
            CORE_NODE_STATUS_COLUMNS,
        )
        for lane in ("cloud", "storage"):
            self.assertEqual(
                LANE_TABLE_POLICY[lane]["core_node"],
                frozenset({"SELECT", "DELETE"}),
            )
            self.assertEqual(
                LANE_COLUMN_UPDATE_POLICY[lane]["core_node"],
                CORE_NODE_DELETION_COLUMNS,
            )
        self.assertEqual(
            RLS_COMMAND_POLICY["core_node"]["cloud"]["SELECT"], "true"
        )
        self.assertNotEqual(
            RLS_COMMAND_POLICY["core_node"]["database"]["UPDATE"],
            RLS_COMMAND_POLICY["core_node"]["files"]["UPDATE"],
        )
        self.assertNotIn("core_schedule_run", LANE_TABLE_POLICY["database"])
        self.assertNotIn("core_schedule_run", LANE_TABLE_POLICY["files"])
        self.assertNotIn("core_schedule_run", LANE_TABLE_POLICY["storage"])
        self.assertEqual(
            LANE_TABLE_POLICY["cloud"]["core_schedule_run"],
            frozenset({"SELECT", "INSERT"}),
        )
        self.assertEqual(
            LANE_TABLE_POLICY["database"]["core_backup_request"],
            frozenset({"SELECT", "UPDATE"}),
        )
        self.assertEqual(
            LANE_TABLE_POLICY["files"]["core_backup_request"],
            frozenset({"SELECT", "UPDATE"}),
        )
        self.assertNotIn("core_backup_request", LANE_TABLE_POLICY["storage"])

    def test_runtime_roles_have_no_celery_result_or_unused_legacy_tables(self):
        for lane, policy in LANE_TABLE_POLICY.items():
            for table in RESULT_TABLES | UNUSED_WORKER_TABLES:
                with self.subTest(lane=lane, table=table):
                    if lane == "app" and table in UNUSED_WORKER_TABLES:
                        continue
                    self.assertNotIn(table, policy)

    def test_source_lanes_can_append_logs_but_cannot_read_or_rewrite_payloads(self):
        for lane in ("cloud", "database", "files", "storage"):
            with self.subTest(lane=lane):
                self.assertEqual(
                    LANE_TABLE_POLICY[lane]["core_log"],
                    frozenset({"INSERT"}),
                )
                self.assertEqual(
                    LANE_COLUMN_SELECT_POLICY[lane]["core_log"],
                    frozenset({"id"}),
                )
                self.assertNotIn(
                    "core_log", LANE_COLUMN_UPDATE_POLICY.get(lane, {})
                )
                self.assertNotIn(
                    "core_notification_delivery", LANE_TABLE_POLICY[lane]
                )
                self.assertNotIn(
                    "core_notification_slack", LANE_COLUMN_SELECT_POLICY[lane]
                )
                self.assertNotIn(
                    "core_notification_telegram", LANE_COLUMN_SELECT_POLICY[lane]
                )
        self.assertEqual(LANE_TABLE_POLICY["logs"]["core_log"], DML)
        self.assertEqual(
            LANE_TABLE_POLICY["logs"]["core_member_mtm_account"],
            frozenset({"SELECT"}),
        )

    def test_database_and_files_source_credentials_do_not_cross(self):
        database = LANE_TABLE_POLICY["database"]
        files = LANE_TABLE_POLICY["files"]
        self.assertEqual(database["core_auth_database"], frozenset({"SELECT"}))
        self.assertEqual(
            LANE_COLUMN_UPDATE_POLICY["database"]["core_auth_database"],
            frozenset({"modified", "type", "version"}),
        )
        self.assertNotIn("core_auth_database", files)
        for table in (
            "core_auth_basecamp",
            "core_auth_website",
            "core_auth_wordpress",
        ):
            with self.subTest(table=table):
                self.assertNotIn(table, database)
                self.assertEqual(files[table], frozenset({"SELECT"}))
        for table in (
            "core_basecamp_backup",
            "core_website_backup",
            "core_website_restore",
            "core_wordpress_backup",
        ):
            self.assertNotIn(table, database)
        for table in (
            "core_database",
            "core_database_backup",
            "core_database_restore",
        ):
            self.assertNotIn(table, files)

        self.assertEqual(
            LANE_COLUMN_UPDATE_POLICY["database"]["core_connection"],
            frozenset({"modified", "status"}),
        )
        self.assertEqual(
            LANE_COLUMN_UPDATE_POLICY["files"]["core_connection"],
            frozenset({"modified", "status"}),
        )
        self.assertNotEqual(
            RLS_POLICY["core_connection"]["database"],
            RLS_POLICY["core_connection"]["files"],
        )

    def test_source_lanes_cannot_read_credentials_or_forge_destination_witnesses(self):
        point_tables = {
            "database": {"core_database_backup_mtm_storage_points"},
            "files": {
                "core_basecamp_backup_mtm_storage_points",
                "core_website_backup_mtm_storage_points",
                "core_wordpress_backup_mtm_storage_points",
            },
        }
        for lane, tables in point_tables.items():
            policy = LANE_TABLE_POLICY[lane]
            with self.subTest(lane=lane):
                self.assertTrue(STORAGE_CONFIG_TABLES.isdisjoint(policy))
            for table in tables:
                with self.subTest(lane=lane, table=table):
                    self.assertEqual(policy[table], frozenset({"SELECT"}))
                    self.assertNotIn(
                        table, LANE_COLUMN_UPDATE_POLICY.get(lane, {})
                    )
        for table in point_tables["database"] | point_tables["files"]:
            self.assertEqual(LANE_TABLE_POLICY["storage"][table], DML)
        for table in ("core_basecamp", "core_database", "core_website", "core_wordpress"):
            self.assertEqual(
                LANE_TABLE_POLICY["storage"][table],
                frozenset({"SELECT", "DELETE"}),
            )

    def test_managed_ssh_intent_is_row_and_column_isolated(self):
        self.assertEqual(
            LANE_TABLE_POLICY["app"][MANAGED_SSH_OPERATION_TABLE],
            frozenset({"SELECT", "INSERT"}),
        )
        self.assertEqual(
            LANE_COLUMN_UPDATE_POLICY["app"][MANAGED_SSH_OPERATION_TABLE],
            MANAGED_SSH_PUBLICATION_COLUMNS,
        )
        self.assertEqual(
            LANE_TABLE_POLICY["app"][SSH_HOST_KEY_APPROVAL_TABLE],
            frozenset({"SELECT", "INSERT", "DELETE"}),
        )
        self.assertEqual(
            LANE_TABLE_POLICY["app"][SSH_HOST_KEY_APPROVAL_EVENT_TABLE],
            frozenset({"SELECT"}),
        )
        for lane in ("preflight", "beat", "cloud", "database", "files", "storage", "logs"):
            self.assertNotIn(
                SSH_HOST_KEY_APPROVAL_EVENT_TABLE, LANE_TABLE_POLICY[lane]
            )
        self.assertEqual(
            LANE_COLUMN_UPDATE_POLICY["app"][SSH_HOST_KEY_APPROVAL_TABLE],
            SSH_HOST_KEY_APPROVAL_REPLACEMENT_COLUMNS,
        )
        for lane, predicate in (
            ("database", "source_lane = 'database'"),
            ("files", "source_lane = 'files'"),
        ):
            with self.subTest(lane=lane):
                self.assertEqual(
                    LANE_TABLE_POLICY[lane][MANAGED_SSH_OPERATION_TABLE],
                    frozenset({"SELECT"}),
                )
                self.assertEqual(
                    LANE_COLUMN_UPDATE_POLICY[lane][MANAGED_SSH_OPERATION_TABLE],
                    MANAGED_SSH_MUTABLE_COLUMNS,
                )
                self.assertEqual(
                    RLS_COMMAND_POLICY[MANAGED_SSH_OPERATION_TABLE][lane][
                        "SELECT"
                    ],
                    predicate,
                )
                self.assertEqual(
                    RLS_COMMAND_POLICY[MANAGED_SSH_OPERATION_TABLE][lane][
                        "UPDATE"
                    ],
                    predicate,
                )
                self.assertNotIn(
                    "DELETE",
                    RLS_COMMAND_POLICY[MANAGED_SSH_OPERATION_TABLE][lane],
                )
                self.assertEqual(
                    LANE_TABLE_POLICY[lane][SSH_HOST_KEY_APPROVAL_TABLE],
                    frozenset({"SELECT"}),
                )
                self.assertIn(
                    f"source_lane = '{lane}'",
                    RLS_COMMAND_POLICY[SSH_HOST_KEY_APPROVAL_TABLE][lane][
                        "SELECT"
                    ],
                )
                approval_predicate = RLS_COMMAND_POLICY[
                    SSH_HOST_KEY_APPROVAL_TABLE
                ][lane]["SELECT"]
                if lane == "database":
                    self.assertIn("core_auth_database", approval_predicate)
                    self.assertIn("use_private_key", approval_predicate)
                else:
                    self.assertIn("core_auth_website", approval_predicate)
                    self.assertIn("protocol = 2", approval_predicate)
        for lane in ("preflight", "beat", "cloud", "storage", "logs"):
            self.assertNotIn(MANAGED_SSH_OPERATION_TABLE, LANE_TABLE_POLICY[lane])

    def test_managed_ssh_trigger_inventory_and_attributes_are_exact(self):
        managed_routines = MANAGED_SSH_ROUTINES
        self.assertEqual(
            EXPECTED_MANAGED_SSH_FOREIGN_KEYS,
            {
                (
                    "core_managed_ssh_operation",
                    "account_id",
                    "core_account",
                    "id",
                    "c",
                    True,
                    True,
                ),
                (
                    "core_managed_ssh_operation",
                    "connection_id",
                    "core_connection",
                    "id",
                    "c",
                    True,
                    True,
                ),
            },
        )
        self.assertEqual(
            managed_routines,
            {
                "backupsheep_is_canonical_ssh_host",
                MANAGED_SSH_RETENTION_ROUTINE,
                "backupsheep_managed_ssh_auth_generation",
                "backupsheep_managed_ssh_account_insert_guard",
                MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE,
                "backupsheep_managed_ssh_connection_active_guard",
                "backupsheep_managed_ssh_connection_identity_guard",
                "backupsheep_managed_ssh_delete_guard",
                "backupsheep_managed_ssh_operation_insert_guard",
                "backupsheep_managed_ssh_operation_update_guard",
                "backupsheep_ssh_host_key_approval_audit",
                "backupsheep_ssh_host_key_approval_event_append_only",
                "backupsheep_ssh_host_key_approval_fence",
                "backupsheep_ssh_host_key_approval_guard",
            },
        )
        managed_triggers = {
            trigger
            for trigger in EXPECTED_TRIGGERS
            if trigger[1].startswith("managed_ssh_")
            or trigger[1].startswith("ssh_host_key_")
        }
        self.assertEqual(len(managed_triggers), 16)
        for name in managed_routines - {
            "backupsheep_is_canonical_ssh_host",
            "backupsheep_managed_ssh_connection_identity_guard",
            "backupsheep_managed_ssh_operation_update_guard",
            "backupsheep_ssh_host_key_approval_event_append_only",
        }:
            self.assertTrue(EXPECTED_ROUTINE_ATTRIBUTES[name][2])
            self.assertEqual(
                EXPECTED_ROUTINE_ATTRIBUTES[name][6],
                ("search_path=pg_catalog, public",),
            )
        for name in (
            "backupsheep_managed_ssh_connection_identity_guard",
            "backupsheep_managed_ssh_operation_update_guard",
            "backupsheep_ssh_host_key_approval_event_append_only",
        ):
            with self.subTest(name=name):
                self.assertFalse(EXPECTED_ROUTINE_ATTRIBUTES[name][2])
                self.assertEqual(EXPECTED_ROUTINE_ATTRIBUTES[name][6], ())
        self.assertEqual(
            EXPECTED_ROUTINE_ATTRIBUTES["backupsheep_is_canonical_ssh_host"],
            (
                "plpgsql",
                "f",
                False,
                False,
                "i",
                "u",
                ("search_path=pg_catalog",),
            ),
        )
        self.assertEqual(
            EXPECTED_ROUTINE_ATTRIBUTES[MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE],
            (
                "sql",
                "f",
                True,
                False,
                "s",
                "u",
                ("search_path=pg_catalog, public",),
            ),
        )
        for lane, executable in ROUTINE_EXECUTE_POLICY.items():
            with self.subTest(lane=lane):
                self.assertTrue(
                    (
                        managed_routines
                        - {
                            MANAGED_SSH_RETENTION_ROUTINE,
                            MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE,
                        }
                    ).isdisjoint(executable)
                )
                if lane in {"database", "files"}:
                    self.assertIn(MANAGED_SSH_RETENTION_ROUTINE, executable)
                else:
                    self.assertNotIn(MANAGED_SSH_RETENTION_ROUTINE, executable)
                if lane in {"app", "database", "files"}:
                    self.assertIn(MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE, executable)
                else:
                    self.assertNotIn(MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE, executable)

    def test_replay_and_artifact_rows_have_lane_policies(self):
        for lane in ("cloud", "database", "files", "storage", "logs"):
            self.assertIn(REPLAY_TABLE, LANE_TABLE_POLICY[lane])
            self.assertEqual(
                RLS_POLICY[REPLAY_TABLE][lane], f"target_lane = '{lane}'"
            )
        for lane in ("app", "preflight", "beat"):
            self.assertNotIn(REPLAY_TABLE, LANE_TABLE_POLICY[lane])

        for table in ARTIFACT_LEDGER_TABLES:
            self.assertIn("database", RLS_POLICY[table])
            self.assertIn("files", RLS_POLICY[table])
            self.assertNotEqual(
                RLS_POLICY[table]["database"], RLS_POLICY[table]["files"]
            )
            for lane in ("database", "files"):
                self.assertNotIn("DELETE", LANE_TABLE_POLICY[lane][table])
