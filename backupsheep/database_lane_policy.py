"""Generation-3 PostgreSQL privilege policy for the stock Docker stack.

The stock deployment deliberately keeps this policy static.  A migration that adds
or removes a table must update this inventory and its lane grants in the same release;
otherwise the post-migration sealing step fails closed before any long-lived service
starts.  Prefix- or wildcard-based grants are intentionally forbidden because a new
credential table must never become readable merely because its name resembles an old
one.
"""

from __future__ import annotations

from types import MappingProxyType


LANES = (
    "app",
    "preflight",
    "beat",
    "cloud",
    "database",
    "files",
    "storage",
    "logs",
)

TABLE_PRIVILEGES = frozenset(
    ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
)
DML = frozenset(("SELECT", "INSERT", "UPDATE", "DELETE"))
MUTATE = frozenset(("SELECT", "INSERT", "UPDATE"))
REPLAY_DML = frozenset(("SELECT", "INSERT", "UPDATE"))
MANAGED_SSH_RETENTION_ROUTINE = (
    "backupsheep_delete_managed_ssh_operation_retention"
)
MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE = "backupsheep_managed_ssh_single_account"
MANAGED_SSH_REVOKE_APPROVAL_ROUTINE = (
    "backupsheep_revoke_ssh_host_key_approval"
)
SSH_HOST_KEY_REVOKE_WITNESS_TABLE = "backupsheep_ssh_host_key_revoke_witness"


# Migrations 0043 and 0046 install the reviewed trigger/helper functions below. No
# other public-schema routine or user-created trigger is accepted by generation 3.
# The tuple is ``(identity arguments, result type)`` as rendered by PostgreSQL.
EXPECTED_ROUTINES = MappingProxyType(
    {
        "backupsheep_artifact_encryption_constraint": ("", "trigger"),
        MANAGED_SSH_RETENTION_ROUTINE: (
            "requested_retention_days integer, requested_batch_size integer",
            "integer",
        ),
        MANAGED_SSH_REVOKE_APPROVAL_ROUTINE: (
            "requested_approval_id bigint, requested_account_id bigint",
            "boolean",
        ),
        "backupsheep_assert_encryption_envelope_state": (
            "envelope_pk bigint",
            "void",
        ),
        "backupsheep_envelope_immutable_fields": ("", "trigger"),
        "backupsheep_envelope_state_constraint": ("", "trigger"),
        "backupsheep_execution_encryption_identity_immutable": ("", "trigger"),
        "backupsheep_is_canonical_ssh_host": ("candidate text", "boolean"),
        "backupsheep_key_wrap_immutable_fields": ("", "trigger"),
        "backupsheep_key_wrap_state_constraint": ("", "trigger"),
        "backupsheep_managed_ssh_auth_generation": ("", "trigger"),
        "backupsheep_managed_ssh_account_insert_guard": ("", "trigger"),
        MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE: (
            "expected_account_id bigint",
            "boolean",
        ),
        "backupsheep_managed_ssh_connection_active_guard": ("", "trigger"),
        "backupsheep_managed_ssh_connection_identity_guard": ("", "trigger"),
        "backupsheep_managed_ssh_delete_guard": ("", "trigger"),
        "backupsheep_managed_ssh_operation_insert_guard": ("", "trigger"),
        "backupsheep_managed_ssh_operation_update_guard": ("", "trigger"),
        "backupsheep_ssh_host_key_approval_audit": ("", "trigger"),
        "backupsheep_ssh_host_key_approval_event_append_only": ("", "trigger"),
        "backupsheep_ssh_host_key_approval_fence": ("", "trigger"),
        "backupsheep_ssh_host_key_approval_guard": ("", "trigger"),
    }
)

# ``(language, kind, security-definer, leakproof, volatility, parallel,
# configuration)`` is an exact allow-list, not a family of accepted attributes.
# The SECURITY DEFINER managed-SSH functions require the hardened search path
# embedded by migration 0046. The operation/connection/event guards need no elevated
# catalog reads and deliberately remain caller-rights triggers.
_DEFAULT_ROUTINE_ATTRIBUTES = (
    "plpgsql",
    "f",
    False,
    False,
    "v",
    "u",
    (),
)
_MANAGED_SSH_SECURITY_DEFINER_ATTRIBUTES = (
    "plpgsql",
    "f",
    True,
    False,
    "v",
    "u",
    ("search_path=pg_catalog, public",),
)
_MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE_ATTRIBUTES = (
    "sql",
    "f",
    True,
    False,
    "s",
    "u",
    ("search_path=pg_catalog, public",),
)
_CANONICAL_SSH_HOST_ROUTINE_ATTRIBUTES = (
    "plpgsql",
    "f",
    False,
    False,
    "i",
    "u",
    ("search_path=pg_catalog",),
)
MANAGED_SSH_ROUTINES = frozenset(
    {
        "backupsheep_is_canonical_ssh_host",
        MANAGED_SSH_RETENTION_ROUTINE,
        MANAGED_SSH_REVOKE_APPROVAL_ROUTINE,
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
    }
)
EXPECTED_ROUTINE_ATTRIBUTES = MappingProxyType(
    {
        name: (
            _CANONICAL_SSH_HOST_ROUTINE_ATTRIBUTES
            if name == "backupsheep_is_canonical_ssh_host"
            else _MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE_ATTRIBUTES
            if name == MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE
            else _MANAGED_SSH_SECURITY_DEFINER_ATTRIBUTES
            if name in {
                MANAGED_SSH_RETENTION_ROUTINE,
                MANAGED_SSH_REVOKE_APPROVAL_ROUTINE,
                MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE,
                "backupsheep_managed_ssh_auth_generation",
                "backupsheep_managed_ssh_account_insert_guard",
                "backupsheep_managed_ssh_connection_active_guard",
                "backupsheep_managed_ssh_delete_guard",
                "backupsheep_managed_ssh_operation_insert_guard",
                "backupsheep_ssh_host_key_approval_audit",
                "backupsheep_ssh_host_key_approval_fence",
                "backupsheep_ssh_host_key_approval_guard",
            }
            else _DEFAULT_ROUTINE_ATTRIBUTES
        )
        for name in EXPECTED_ROUTINES
    }
)
EXPECTED_TRIGGERS = frozenset(
    {
        ("core_backup_artifact", "backup_artifact_encryption_consistency"),
        ("core_backup_encryption_envelope", "backup_envelope_immutable_fields"),
        ("core_backup_encryption_envelope", "backup_envelope_state_consistency"),
        ("core_backup_execution", "backup_execution_encryption_identity_immutable"),
        ("core_backup_key_wrap", "backup_key_wrap_immutable_fields"),
        ("core_backup_key_wrap", "backup_key_wrap_state_consistency"),
        ("core_auth_database", "managed_ssh_database_auth_generation"),
        ("core_auth_website", "managed_ssh_website_auth_generation"),
        ("core_account", "managed_ssh_account_insert_guard"),
        ("core_account", "managed_ssh_account_delete_guard"),
        ("core_auth_database", "managed_ssh_database_auth_delete_guard"),
        ("core_auth_website", "managed_ssh_website_auth_delete_guard"),
        ("core_connection", "managed_ssh_connection_active_guard"),
        ("core_connection", "managed_ssh_connection_identity_guard"),
        ("core_connection", "managed_ssh_connection_delete_guard"),
        ("core_managed_ssh_operation", "managed_ssh_operation_insert_guard"),
        ("core_managed_ssh_operation", "managed_ssh_operation_update_guard"),
        ("core_ssh_host_key_approval", "ssh_host_key_approval_fence"),
        ("core_ssh_host_key_approval", "ssh_host_key_approval_guard"),
        ("core_ssh_host_key_approval", "ssh_host_key_approval_delete_guard"),
        ("core_ssh_host_key_approval", "ssh_host_key_approval_audit"),
        (
            "core_ssh_host_key_approval_event",
            "ssh_host_key_approval_event_append_only",
        ),
    }
)

# The operation model deliberately uses Django DO_NOTHING so Collector cannot issue
# a directly-authorized child DELETE. PostgreSQL owns these parent cascades;
# approval events intentionally have no FK and therefore survive account deletion.
EXPECTED_MANAGED_SSH_FOREIGN_KEYS = frozenset(
    {
        (
            "core_ssh_host_key_approval",
            "account_id",
            "core_account",
            "id",
            "c",
            True,
            True,
        ),
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
    }
)

# Deferred envelope/key-wrap triggers invoke this helper as the caller.  Grant only
# that non-disclosing void helper to the lanes allowed to mutate artifact custody;
# trigger entry points remain non-callable by every long-lived identity.
ROUTINE_EXECUTE_POLICY = MappingProxyType(
    {
        lane: frozenset(
            {
                "backupsheep_assert_encryption_envelope_state",
                *(
                    {MANAGED_SSH_RETENTION_ROUTINE}
                    if lane in {"database", "files"}
                    else set()
                ),
                *(
                    {MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE}
                    if lane in {"app", "database", "files"}
                    else set()
                ),
                *(
                    {MANAGED_SSH_REVOKE_APPROVAL_ROUTINE}
                    if lane == "app"
                    else set()
                ),
            }
        )
        for lane in ("app", "database", "files", "storage")
    }
)


# This is the exact public-schema inventory produced by all migrations at this
# source revision.  Views, materialized views, foreign tables, public routines and
# standalone public types are rejected separately by the provisioner.
EXPECTED_TABLES = frozenset(
    {
        "auth_group",
        "auth_group_permissions",
        "auth_permission",
        "auth_user",
        "auth_user_groups",
        "auth_user_user_permissions",
        "authtoken_token",
        "backupsheep_celery_task_replay",
        SSH_HOST_KEY_REVOKE_WITNESS_TABLE,
        "core_account",
        "core_account_mtm_group",
        "core_account_mtm_group_nodes",
        "core_alibab_region",
        "core_auth_aws",
        "core_auth_aws_rds",
        "core_auth_basecamp",
        "core_auth_database",
        "core_auth_digitalocean",
        "core_auth_google_cloud",
        "core_auth_hetzner",
        "core_auth_lightsail",
        "core_auth_oracle",
        "core_auth_ovh_ca",
        "core_auth_ovh_eu",
        "core_auth_ovh_us",
        "core_auth_upcloud",
        "core_auth_vultr",
        "core_auth_website",
        "core_auth_wordpress",
        "core_aws",
        "core_aws_backup",
        "core_aws_backup_status",
        "core_aws_rds",
        "core_aws_rds_backup",
        "core_aws_rds_backup_status",
        "core_aws_region",
        "core_backup_artifact",
        "core_backup_encryption_envelope",
        "core_backup_execution",
        "core_backup_key_wrap",
        "core_backup_request",
        "core_backup_type",
        "core_basecamp",
        "core_basecamp_backup",
        "core_basecamp_backup_mtm_storage_points",
        "core_cache",
        "core_cloud_restore",
        "core_connection",
        "core_connection_location",
        "core_connection_location_mtm_integrations",
        "core_connection_status",
        "core_database",
        "core_database_backup",
        "core_database_backup_mtm_storage_points",
        "core_database_backup_status",
        "core_database_restore",
        "core_digitalocean",
        "core_digitalocean_backup",
        "core_do_backup_status",
        "core_do_spaces_region",
        "core_download",
        "core_exoscale_region",
        "core_filebase_region",
        "core_google_cloud",
        "core_google_cloud_backup",
        "core_hetzner",
        "core_hetzner_backup",
        "core_ibm_region",
        "core_integration",
        "core_invite",
        "core_invite_groups",
        "core_ionos_region",
        "core_lightsail",
        "core_lightsail_backup",
        "core_lightsail_backup_status",
        "core_lightsail_bucket_replication",
        "core_lightsail_bucket_replication_lease",
        "core_lightsail_bucket_replication_multipart",
        "core_lightsail_bucket_replication_object",
        "core_lightsail_bucket_replication_run",
        "core_lightsail_bucket_restore_object",
        "core_lightsail_bucket_restore_run",
        "core_lightsail_region",
        "core_log",
        "core_managed_ssh_operation",
        "core_member",
        "core_member_mtm_account",
        "core_node",
        "core_notification_delivery",
        "core_notification_email",
        "core_notification_log_email",
        "core_notification_slack",
        "core_notification_telegram",
        "core_oracle",
        "core_oracle_backup",
        "core_oracle_region",
        "core_ovh_ca",
        "core_ovh_ca_backup",
        "core_ovh_ca_backup_status",
        "core_ovh_eu",
        "core_ovh_eu_backup",
        "core_ovh_eu_backup_status",
        "core_ovh_us",
        "core_ovh_us_backup",
        "core_rackcorp_region",
        "core_scaleway_region",
        "core_schedule",
        "core_schedule_run",
        "core_schedule_storage_points",
        "core_server_status",
        "core_server_type",
        "core_ssh_host_key_approval",
        "core_ssh_host_key_approval_event",
        "core_site_settings",
        "core_storage",
        "core_storage_alibaba",
        "core_storage_aws_s3",
        "core_storage_azure",
        "core_storage_backblaze_b2",
        "core_storage_cloudflare",
        "core_storage_deletion_lease",
        "core_storage_do_spaces",
        "core_storage_dropbox",
        "core_storage_exoscale",
        "core_storage_filebase",
        "core_storage_google_cloud",
        "core_storage_google_drive",
        "core_storage_ibm",
        "core_storage_idrive",
        "core_storage_ionos",
        "core_storage_leviia",
        "core_storage_linode",
        "core_storage_local",
        "core_storage_onedrive",
        "core_storage_oracle",
        "core_storage_pcloud",
        "core_storage_rackcorp",
        "core_storage_scaleway",
        "core_storage_tencent",
        "core_storage_type",
        "core_storage_upcloud",
        "core_storage_vultr",
        "core_storage_wasabi",
        "core_tencent_region",
        "core_upcloud",
        "core_upcloud_backup",
        "core_usage_backup",
        "core_usage_node",
        "core_usage_storage",
        "core_vultr",
        "core_vultr_backup",
        "core_vultr_backup_status",
        "core_vultr_database",
        "core_vultr_database_backup",
        "core_vultr_database_restore",
        "core_wasabi_region",
        "core_website",
        "core_website_backup",
        "core_website_backup_file",
        "core_website_backup_mtm_storage_points",
        "core_website_backup_status",
        "core_website_restore",
        "core_wordpress",
        "core_wordpress_backup",
        "core_wordpress_backup_mtm_storage_points",
        "django_admin_log",
        "django_celery_beat_clockedschedule",
        "django_celery_beat_crontabschedule",
        "django_celery_beat_intervalschedule",
        "django_celery_beat_periodictask",
        "django_celery_beat_periodictasks",
        "django_celery_beat_solarschedule",
        "django_celery_results_chordcounter",
        "django_celery_results_groupresult",
        "django_celery_results_taskresult",
        "django_content_type",
        "django_migrations",
        "django_session",
        "util_country",
        "util_delete_files",
        "util_mariadb_options",
        "util_mysql_options",
        "util_postgresql_options",
        "util_setting",
        "util_tag",
    }
)


MIGRATION_TABLE = "django_migrations"
REPLAY_TABLE = "backupsheep_celery_task_replay"
MANAGED_SSH_OPERATION_TABLE = "core_managed_ssh_operation"
SSH_HOST_KEY_APPROVAL_TABLE = "core_ssh_host_key_approval"
SSH_HOST_KEY_APPROVAL_EVENT_TABLE = "core_ssh_host_key_approval_event"
INTERNAL_CONTROL_TABLES = frozenset({SSH_HOST_KEY_REVOKE_WITNESS_TABLE})
ARTIFACT_LEDGER_TABLES = frozenset(
    {
        "core_backup_artifact",
        "core_backup_encryption_envelope",
        "core_backup_execution",
        "core_backup_key_wrap",
    }
)
RESULT_TABLES = frozenset(
    {
        "django_celery_results_chordcounter",
        "django_celery_results_groupresult",
        "django_celery_results_taskresult",
    }
)
UNUSED_WORKER_TABLES = frozenset(
    {
        # These legacy accounting/download scratch models have no production
        # call sites. Keep them web/migrator-owned instead of granting every
        # worker latent cross-account mutation rights.
        "core_cache",
        "core_download",
        "core_usage_backup",
        "core_usage_node",
        "core_usage_storage",
        "util_delete_files",
        "util_setting",
    }
)
BEAT_TABLES = frozenset(
    {
        "django_celery_beat_clockedschedule",
        "django_celery_beat_crontabschedule",
        "django_celery_beat_intervalschedule",
        "django_celery_beat_periodictask",
        "django_celery_beat_periodictasks",
        "django_celery_beat_solarschedule",
    }
)
IDENTITY_TABLES = frozenset(
    {
        "auth_group",
        "auth_group_permissions",
        "auth_permission",
        "auth_user",
        "auth_user_groups",
        "auth_user_user_permissions",
        "authtoken_token",
        "core_account_mtm_group",
        "core_account_mtm_group_nodes",
        "core_invite",
        "core_invite_groups",
        "core_member",
        "core_member_mtm_account",
        "django_admin_log",
        "django_session",
    }
)
PROVIDER_AUTH_TABLES = frozenset(
    table for table in EXPECTED_TABLES if table.startswith("core_auth_")
)
LOCAL_SOURCE_AUTH_TABLES = frozenset(
    {
        "core_auth_basecamp",
        "core_auth_database",
        "core_auth_website",
        "core_auth_wordpress",
    }
)
CLOUD_AUTH_TABLES = PROVIDER_AUTH_TABLES - LOCAL_SOURCE_AUTH_TABLES
STORAGE_CONFIG_TABLES = frozenset(
    table
    for table in EXPECTED_TABLES
    if table == "core_storage" or table.startswith("core_storage_")
)
NOTIFICATION_SECRET_TABLES = frozenset(
    {
        "core_notification_email",
        "core_notification_log_email",
        "core_notification_slack",
        "core_notification_telegram",
        "core_site_settings",
    }
)
SENSITIVE_TABLES = (
    IDENTITY_TABLES
    | PROVIDER_AUTH_TABLES
    | STORAGE_CONFIG_TABLES
    | NOTIFICATION_SECRET_TABLES
    | {
        MANAGED_SSH_OPERATION_TABLE,
        SSH_HOST_KEY_APPROVAL_TABLE,
        SSH_HOST_KEY_APPROVAL_EVENT_TABLE,
    }
    | INTERNAL_CONTROL_TABLES
)

# Operational metadata is deliberately readable to worker lanes because generic
# recovery follows foreign keys across node/backup subclasses.  Provider credentials,
# storage credentials, user identity/session material and notification secrets are
# excluded and added back only for the lanes that execute those capabilities.
COMMON_OPERATIONAL_READ = (
    EXPECTED_TABLES
    - SENSITIVE_TABLES
    - BEAT_TABLES
    - RESULT_TABLES
    - UNUSED_WORKER_TABLES
    - ARTIFACT_LEDGER_TABLES
    - {MIGRATION_TABLE, REPLAY_TABLE, "core_notification_delivery"}
) | {"core_account"}

LOCAL_OPERATIONAL_WRITES = frozenset(
    {
        "core_backup_artifact",
        "core_backup_encryption_envelope",
        "core_backup_execution",
        "core_backup_key_wrap",
        "core_log",
    }
)
# Destination through rows are intentionally absent from source-lane writes.  The
# storage worker validates credentials and commits authorization witnesses there;
# database/files workers can only read the accepted point ids before source access.
DATABASE_WRITES = LOCAL_OPERATIONAL_WRITES | frozenset(
    {
        "core_database",
        "core_database_backup",
        "core_database_restore",
    }
)
FILES_WRITES = LOCAL_OPERATIONAL_WRITES | frozenset(
    {
        "core_basecamp",
        "core_basecamp_backup",
        "core_website",
        "core_website_backup",
        "core_website_backup_file",
        "core_website_restore",
        "core_wordpress",
        "core_wordpress_backup",
    }
)

# Cloud DML is an explicit resource inventory.  A suffix rule previously granted the
# cloud worker write access to database/files backup and restore rows merely because
# their names ended in ``_backup``/``_restore``.  That defeats lane separation and
# would silently grant future models, so every provider-owned row is named here.
CLOUD_NODE_AND_BACKUP_WRITES = frozenset(
    {
        "core_aws",
        "core_aws_backup",
        "core_aws_rds",
        "core_aws_rds_backup",
        "core_cloud_restore",
        "core_digitalocean",
        "core_digitalocean_backup",
        "core_google_cloud",
        "core_google_cloud_backup",
        "core_hetzner",
        "core_hetzner_backup",
        "core_lightsail",
        "core_lightsail_backup",
        "core_lightsail_bucket_replication",
        "core_lightsail_bucket_replication_lease",
        "core_lightsail_bucket_replication_multipart",
        "core_lightsail_bucket_replication_object",
        "core_lightsail_bucket_replication_run",
        "core_lightsail_bucket_restore_object",
        "core_lightsail_bucket_restore_run",
        "core_oracle",
        "core_oracle_backup",
        "core_ovh_ca",
        "core_ovh_ca_backup",
        "core_ovh_eu",
        "core_ovh_eu_backup",
        "core_ovh_us",
        "core_ovh_us_backup",
        "core_upcloud",
        "core_upcloud_backup",
        "core_vultr",
        "core_vultr_backup",
        "core_vultr_database",
        "core_vultr_database_backup",
        "core_vultr_database_restore",
    }
)
CLOUD_WRITES = (
    CLOUD_NODE_AND_BACKUP_WRITES
    | frozenset(
        {
            "core_backup_execution",
            "core_log",
        }
    )
)

# Source backup rows can contain remote paths, object inventories, database names,
# and recovery metadata even when their credential table is separate.  They are
# therefore part of the lane boundary, not generic operational metadata.
DATABASE_SOURCE_TABLES = frozenset(
    table
    for table in EXPECTED_TABLES
    if table == "core_database" or table.startswith("core_database_")
)
FILES_SOURCE_TABLES = frozenset(
    table
    for table in EXPECTED_TABLES
    if any(
        table == prefix or table.startswith(prefix + "_")
        for prefix in ("core_basecamp", "core_website", "core_wordpress")
    )
)
CLOUD_OPERATIONAL_TABLES = frozenset(
    table
    for table in EXPECTED_TABLES
    if any(
        table == prefix or table.startswith(prefix + "_")
        for prefix in (
            "core_aws",
            "core_cloud_restore",
            "core_digitalocean",
            "core_google_cloud",
            "core_hetzner",
            "core_lightsail",
            "core_oracle",
            "core_ovh_ca",
            "core_ovh_eu",
            "core_ovh_us",
            "core_upcloud",
            "core_vultr",
        )
    )
)
CLOUD_READS = (
    COMMON_OPERATIONAL_READ - DATABASE_SOURCE_TABLES - FILES_SOURCE_TABLES
) | CLOUD_AUTH_TABLES
DATABASE_READS = (
    COMMON_OPERATIONAL_READ - CLOUD_OPERATIONAL_TABLES - FILES_SOURCE_TABLES
    | ARTIFACT_LEDGER_TABLES
    | {
        "core_auth_database",
        MANAGED_SSH_OPERATION_TABLE,
        SSH_HOST_KEY_APPROVAL_TABLE,
    }
)
FILES_READS = (
    COMMON_OPERATIONAL_READ - CLOUD_OPERATIONAL_TABLES - DATABASE_SOURCE_TABLES
    | ARTIFACT_LEDGER_TABLES
    | {
        "core_auth_basecamp",
        "core_auth_website",
        "core_auth_wordpress",
        MANAGED_SSH_OPERATION_TABLE,
        SSH_HOST_KEY_APPROVAL_TABLE,
    }
)

# The storage worker operates only local/SAAS backup rows and destination configs.
# Cloud snapshot deletion/replication is routed to cloud; source credentials remain in
# database/files.  In particular this set deliberately excludes every identity,
# session/token, source-auth, cloud-provider-auth, Beat and notification-secret table.
LOCAL_BACKUP_TABLES = frozenset(
    {
        "core_basecamp",
        "core_basecamp_backup",
        "core_basecamp_backup_mtm_storage_points",
        "core_database",
        "core_database_backup",
        "core_database_backup_mtm_storage_points",
        "core_database_restore",
        "core_website",
        "core_website_backup",
        "core_website_backup_file",
        "core_website_backup_mtm_storage_points",
        "core_website_restore",
        "core_wordpress",
        "core_wordpress_backup",
        "core_wordpress_backup_mtm_storage_points",
    }
)
LOCAL_BACKUP_WRITES = LOCAL_BACKUP_TABLES - frozenset(
    {
        "core_basecamp",
        "core_database",
        "core_website",
        "core_wordpress",
    }
)
STORAGE_COMMON_TABLES = frozenset(
    {
        "core_account",
        "core_backup_type",
        "core_basecamp_backup",
        "core_connection",
        "django_content_type",
        "core_database_backup_status",
        "core_integration",
        "core_log",
        "core_node",
        "core_schedule",
        "core_schedule_storage_points",
        "core_storage_type",
        "core_website_backup_status",
    }
)
STORAGE_READS = (
    LOCAL_BACKUP_TABLES
    | STORAGE_COMMON_TABLES
    | STORAGE_CONFIG_TABLES
    | ARTIFACT_LEDGER_TABLES
)
STORAGE_WRITES = (
    LOCAL_BACKUP_WRITES
    | STORAGE_CONFIG_TABLES
    | ARTIFACT_LEDGER_TABLES
    | frozenset(
        {
            "core_log",
        }
    )
)

LOG_WRITES = frozenset(
    {
        "core_log",
        "core_notification_delivery",
        "core_notification_log_email",
    }
)

BEAT_READS = BEAT_TABLES | frozenset(
    {
        "core_backup_request",
        "core_connection",
        "core_integration",
        "core_node",
        "core_schedule",
        "core_schedule_run",
        "core_schedule_storage_points",
        "core_vultr_database",
    }
)
BEAT_WRITES = BEAT_TABLES

LOG_READS = frozenset(
    {
        "auth_user",
        "core_account",
        "core_log",
        "core_member",
        "core_member_mtm_account",
        "core_notification_delivery",
        "core_notification_log_email",
        "core_notification_slack",
        "core_notification_telegram",
        "core_site_settings",
    }
)


def _lane_policy(
    reads,
    writes,
    *,
    consumes_tasks=False,
    replay_privileges=REPLAY_DML,
    write_privileges=DML,
):
    policy: dict[str, frozenset[str]] = {
        table: frozenset(("SELECT",)) for table in reads
    }
    for table in writes:
        policy[table] = write_privileges
    if consumes_tasks:
        policy[REPLAY_TABLE] = replay_privileges
    return MappingProxyType(dict(sorted(policy.items())))


def _with_table_privileges(policy, table, privileges):
    updated = dict(policy)
    updated[table] = frozenset(privileges)
    return MappingProxyType(dict(sorted(updated.items())))


def _with_table_privileges_many(policy, additions):
    updated = dict(policy)
    for table, privileges in additions.items():
        updated[table] = frozenset(privileges)
    return MappingProxyType(dict(sorted(updated.items())))


LANE_TABLE_POLICY = MappingProxyType(
    {
        "app": _with_table_privileges_many(
            _lane_policy(
                EXPECTED_TABLES
                - {REPLAY_TABLE}
                - RESULT_TABLES
                - INTERNAL_CONTROL_TABLES,
                EXPECTED_TABLES
                - RESULT_TABLES
                - {
                    MANAGED_SSH_OPERATION_TABLE,
                    SSH_HOST_KEY_APPROVAL_TABLE,
                    SSH_HOST_KEY_APPROVAL_EVENT_TABLE,
                    SSH_HOST_KEY_REVOKE_WITNESS_TABLE,
                    MIGRATION_TABLE,
                    REPLAY_TABLE,
                },
            ),
            {
                MANAGED_SSH_OPERATION_TABLE: {"SELECT", "INSERT"},
                SSH_HOST_KEY_APPROVAL_TABLE: {"SELECT", "INSERT"},
                SSH_HOST_KEY_APPROVAL_EVENT_TABLE: {"SELECT"},
            },
        ),
        "preflight": _lane_policy({MIGRATION_TABLE}, set()),
        "beat": _with_table_privileges_many(
            _lane_policy(BEAT_READS, BEAT_WRITES),
            {
                # The durable scheduler inserts/dispatches its outbox but never
                # deletes accepted requests or their occurrence audit rows.
                "core_backup_request": {"SELECT", "INSERT", "UPDATE"},
                "core_schedule_run": {"SELECT", "INSERT"},
            },
        ),
        "cloud": _with_table_privileges_many(
            _lane_policy(
                CLOUD_READS,
                CLOUD_WRITES,
                consumes_tasks=True,
            ),
            {
                "core_backup_request": {"SELECT", "INSERT", "UPDATE"},
                "core_log": {"INSERT"},
                "core_node": {"SELECT", "DELETE"},
                "core_schedule_run": {"SELECT", "INSERT"},
            },
        ),
        "database": _with_table_privileges_many(
            _lane_policy(
                DATABASE_READS - {"core_schedule_run"},
                DATABASE_WRITES,
                consumes_tasks=True,
                write_privileges=MUTATE,
            ),
            {
                "core_backup_request": {"SELECT", "UPDATE"},
                "core_log": {"INSERT"},
                MANAGED_SSH_OPERATION_TABLE: {"SELECT"},
            },
        ),
        "files": _with_table_privileges_many(
            _lane_policy(
                FILES_READS - {"core_schedule_run"},
                FILES_WRITES,
                consumes_tasks=True,
                write_privileges=MUTATE,
            ),
            {
                "core_backup_request": {"SELECT", "UPDATE"},
                "core_log": {"INSERT"},
                MANAGED_SSH_OPERATION_TABLE: {"SELECT"},
            },
        ),
        "storage": _with_table_privileges_many(
            _lane_policy(
                STORAGE_READS,
                STORAGE_WRITES,
                consumes_tasks=True,
            ),
            {
                "core_log": {"INSERT"},
                "core_node": {"SELECT", "DELETE"},
                # Storage owns local-node deletion after remote/local artifact
                # cleanup. Grant no UPDATE/INSERT capability on source objects,
                # but let Django Collector remove the exact child of a local node.
                "core_basecamp": {"SELECT", "DELETE"},
                "core_database": {"SELECT", "DELETE"},
                "core_website": {"SELECT", "DELETE"},
                "core_wordpress": {"SELECT", "DELETE"},
            },
        ),
        "logs": _lane_policy(
            LOG_READS,
            LOG_WRITES,
            consumes_tasks=True,
            replay_privileges=DML,
        ),
    }
)


# Operational lanes append a durable CoreLog request and publish only its opaque id.
# Django's PostgreSQL INSERT uses RETURNING id, so grant exactly that one readable
# column. The logs lane alone resolves member/channel identities and owns delivery
# rows; source lanes receive no notification-channel column grants.
LANE_COLUMN_SELECT_POLICY = MappingProxyType(
    {
        lane: MappingProxyType(
            {
                # Django's PostgreSQL INSERT uses RETURNING id. Source lanes may
                # observe only that opaque identifier, never another log's payload,
                # account, type, or timestamps.
                "core_log": frozenset({"id"}),
            }
        )
        for lane in ("cloud", "database", "files", "storage")
    }
)


# Managed-SSH workers can claim and record an outcome, but PostgreSQL—not only
# Django's ``editable=False`` metadata—prevents them from rewriting the authorized
# connection, operation, public-key fingerprint, request path, or intent digest.
MANAGED_SSH_MUTABLE_COLUMNS = frozenset(
    {
        "attempts",
        "claimed_at",
        "completed_at",
        "error_payload",
        "execution_witness_digest",
        "lease_expires_at",
        "lease_token",
        "last_publish_attempt_at",
        "modified",
        "publish_attempts",
        "publish_error_code",
        "published_at",
        "result_digest",
        "result_payload",
        "status",
    }
)
MANAGED_SSH_PUBLICATION_COLUMNS = frozenset(
    {
        "last_publish_attempt_at",
        "modified",
        "publish_attempts",
        "publish_error_code",
        "published_at",
    }
)
SSH_HOST_KEY_APPROVAL_REPLACEMENT_COLUMNS = frozenset(
    {
        "approved_by_member_pk_snapshot",
        "approved_by_user_pk_snapshot",
        "bits",
        "fingerprint",
        "modified",
        "negotiated_host_key_algorithm",
        "public_key_base64",
        "wire_key_type",
    }
)
CORE_NODE_STATUS_COLUMNS = frozenset({"modified", "status"})
CORE_NODE_DELETION_COLUMNS = frozenset(
    {*CORE_NODE_STATUS_COLUMNS, "flag_delete_node"}
)
LANE_COLUMN_UPDATE_POLICY = MappingProxyType(
    {
        # PostgreSQL SELECT ... FOR UPDATE requires at least one UPDATE column.
        # Beat locks a schedule while committing its occurrence, but may change
        # only the non-authoritative timestamp—not status, cadence, node, storage,
        # actor, notes, or retention policy.
        "beat": MappingProxyType(
            {"core_schedule": frozenset({"modified"})}
        ),
        "app": MappingProxyType(
            {
                MANAGED_SSH_OPERATION_TABLE: MANAGED_SSH_PUBLICATION_COLUMNS,
                SSH_HOST_KEY_APPROVAL_TABLE: SSH_HOST_KEY_APPROVAL_REPLACEMENT_COLUMNS,
            }
        ),
        "database": MappingProxyType(
            {
                "core_auth_database": frozenset({"modified", "type", "version"}),
                "core_connection": frozenset({"modified", "status"}),
                "core_node": CORE_NODE_STATUS_COLUMNS,
                MANAGED_SSH_OPERATION_TABLE: MANAGED_SSH_MUTABLE_COLUMNS,
            }
        ),
        "files": MappingProxyType(
            {
                "core_connection": frozenset({"modified", "status"}),
                "core_node": CORE_NODE_STATUS_COLUMNS,
                MANAGED_SSH_OPERATION_TABLE: MANAGED_SSH_MUTABLE_COLUMNS,
            }
        ),
        # Cloud credentials are read capabilities. Provider tasks may only
        # persist the two ownership witnesses adopted after a successful
        # provider read-back; they cannot replace credentials, insert/delete
        # auth rows, or rewrite any other provider configuration.
        "cloud": MappingProxyType(
            {
                "core_auth_digitalocean": frozenset(
                    {"info_email", "info_name", "info_uuid", "modified"}
                ),
                "core_auth_upcloud": frozenset({"modified", "username"}),
                "core_node": CORE_NODE_DELETION_COLUMNS,
            }
        ),
        "storage": MappingProxyType(
            {"core_node": CORE_NODE_DELETION_COLUMNS}
        ),
    }
)


# Row policies complement table grants for the two shared ledgers where a table-level
# split is impossible.  The replay ledger is scoped by target lane.  Artifact custody
# rows are scoped through Django's content-type witness, so database and files workers
# cannot read or alter each other's wrapped keys or authenticated context.  The web
# control plane and storage coordinator require the complete artifact catalog; the
# cloud lane receives only its own execution records.
LOCAL_DATABASE_MODELS = frozenset({"coredatabasebackup"})
LOCAL_FILES_MODELS = frozenset(
    {"corebasecampbackup", "corewebsitebackup", "corewordpressbackup"}
)
CLOUD_BACKUP_MODELS = frozenset(
    {
        "coreawsbackup",
        "coreawsrdsbackup",
        "coredigitaloceanbackup",
        "coregooglecloudbackup",
        "corehetznerbackup",
        "corelightsailbackup",
        "coreoraclebackup",
        "coreovhcabackup",
        "coreovheubackup",
        "coreovhusbackup",
        "coreupcloudbackup",
        "corevultrbackup",
        "corevultrdatabasebackup",
    }
)


def _sql_literal(value: str) -> str:
    if not value or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in value):
        raise RuntimeError("database lane policy contains an unsafe SQL literal")
    return "'" + value + "'"


def _content_type_predicate(column: str, model_names: frozenset[str]) -> str:
    models = ", ".join(_sql_literal(value) for value in sorted(model_names))
    return (
        "EXISTS (SELECT 1 FROM public.django_content_type AS bs_content_type "
        f"WHERE bs_content_type.id = {column} "
        "AND bs_content_type.app_label = 'apps' "
        f"AND bs_content_type.model IN ({models}))"
    )


def _artifact_predicate(table: str, model_names: frozenset[str]) -> str:
    if table in {"core_backup_execution", "core_backup_artifact"}:
        return _content_type_predicate("backup_content_type_id", model_names)
    execution_predicate = _content_type_predicate(
        "bs_execution.backup_content_type_id", model_names
    )
    if table == "core_backup_encryption_envelope":
        return (
            "EXISTS (SELECT 1 FROM public.core_backup_execution AS bs_execution "
            "WHERE bs_execution.id = execution_id AND "
            f"{execution_predicate})"
        )
    if table == "core_backup_key_wrap":
        return (
            "EXISTS (SELECT 1 FROM public.core_backup_encryption_envelope AS bs_envelope "
            "JOIN public.core_backup_execution AS bs_execution "
            "ON bs_execution.id = bs_envelope.execution_id "
            "WHERE bs_envelope.id = envelope_id AND "
            f"{execution_predicate})"
        )
    raise RuntimeError("unknown artifact-ledger RLS table")


def _integration_type_clause(lane: str) -> str:
    if lane == "database":
        return "bs_integration.type = 'database'"
    if lane == "files":
        return "bs_integration.type IN ('saas', 'website')"
    if lane == "storage":
        return "bs_integration.type IN ('database', 'saas', 'website')"
    if lane == "cloud":
        return "bs_integration.type = 'cloud'"
    raise RuntimeError("shared-row policy has an invalid integration lane")


def _connection_lane_predicate(lane: str, outer_connection_id: str) -> str:
    return (
        "EXISTS (SELECT 1 FROM public.core_connection AS bs_connection "
        "JOIN public.core_integration AS bs_integration ON "
        "bs_integration.id = bs_connection.integration_id WHERE "
        f"bs_connection.id = {outer_connection_id} AND "
        f"{_integration_type_clause(lane)})"
    )


def _node_lane_predicate(lane: str, outer_node_id: str) -> str:
    return (
        "EXISTS (SELECT 1 FROM public.core_node AS bs_node "
        "JOIN public.core_connection AS bs_connection ON "
        "bs_connection.id = bs_node.connection_id "
        "JOIN public.core_integration AS bs_integration ON "
        "bs_integration.id = bs_connection.integration_id WHERE "
        f"bs_node.id = {outer_node_id} AND "
        f"{_integration_type_clause(lane)})"
    )


def _schedule_lane_predicate(lane: str, outer_schedule_id: str) -> str:
    return (
        "EXISTS (SELECT 1 FROM public.core_schedule AS bs_schedule "
        "JOIN public.core_node AS bs_node ON bs_node.id = bs_schedule.node_id "
        "JOIN public.core_connection AS bs_connection ON "
        "bs_connection.id = bs_node.connection_id "
        "JOIN public.core_integration AS bs_integration ON "
        "bs_integration.id = bs_connection.integration_id WHERE "
        f"bs_schedule.id = {outer_schedule_id} AND "
        f"{_integration_type_clause(lane)})"
    )


def _account_lane_predicate(lane: str, outer_account_id: str) -> str:
    connection_predicate = (
        "EXISTS (SELECT 1 FROM public.core_connection AS bs_connection "
        "JOIN public.core_integration AS bs_integration ON "
        "bs_integration.id = bs_connection.integration_id WHERE "
        f"bs_connection.account_id = {outer_account_id} AND "
        f"{_integration_type_clause(lane)})"
    )
    if lane != "storage":
        return connection_predicate
    return (
        f"({connection_predicate} OR EXISTS (SELECT 1 FROM public.core_storage "
        f"AS bs_storage WHERE bs_storage.account_id = {outer_account_id}))"
    )


RLS_POLICY = {
    REPLAY_TABLE: {
        lane: f"target_lane = {_sql_literal(lane)}" for lane in LANES if lane not in {"app", "preflight", "beat"}
    },
    MANAGED_SSH_OPERATION_TABLE: {
        "app": "true",
    },
    SSH_HOST_KEY_APPROVAL_TABLE: {
        "app": "true",
    },
    "core_account": {
        "app": "true",
        "cloud": "true",
        "database": _account_lane_predicate("database", "core_account.id"),
        "files": _account_lane_predicate("files", "core_account.id"),
        "storage": _account_lane_predicate("storage", "core_account.id"),
        "logs": "true",
    },
    "core_backup_request": {
        "app": "true",
        "beat": "true",
        "cloud": "true",
        "database": _node_lane_predicate("database", "node_id"),
        "files": _node_lane_predicate("files", "node_id"),
    },
    "core_connection": {
        "app": "true",
        "beat": "true",
        "cloud": (
            "EXISTS (SELECT 1 FROM public.core_integration AS bs_integration "
            "WHERE bs_integration.id = integration_id "
            "AND bs_integration.type = 'cloud')"
        ),
        "database": (
            "EXISTS (SELECT 1 FROM public.core_integration AS bs_integration "
            "WHERE bs_integration.id = integration_id "
            "AND bs_integration.type = 'database')"
        ),
        "files": (
            "EXISTS (SELECT 1 FROM public.core_integration AS bs_integration "
            "WHERE bs_integration.id = integration_id "
            "AND bs_integration.type IN ('saas', 'website'))"
        ),
        "storage": (
            "EXISTS (SELECT 1 FROM public.core_integration AS bs_integration "
            "WHERE bs_integration.id = integration_id "
            "AND bs_integration.type IN ('database', 'saas', 'website'))"
        ),
    },
    "core_log": {
        "app": "true",
        "logs": "true",
    },
    "core_node": {
        "app": "true",
        "beat": "true",
    },
    "core_schedule": {
        "app": "true",
        "beat": "true",
        "cloud": "true",
        "database": _node_lane_predicate("database", "node_id"),
        "files": _node_lane_predicate("files", "node_id"),
        "storage": _node_lane_predicate("storage", "node_id"),
    },
    "core_schedule_storage_points": {
        "app": "true",
        "beat": "true",
        "cloud": "true",
        "database": _schedule_lane_predicate("database", "coreschedule_id"),
        "files": _schedule_lane_predicate("files", "coreschedule_id"),
        "storage": _schedule_lane_predicate("storage", "coreschedule_id"),
    },
}
for _artifact_table in ARTIFACT_LEDGER_TABLES:
    _artifact_lanes = {
        "app": "true",
        "storage": "true",
        "database": _artifact_predicate(
            _artifact_table, LOCAL_DATABASE_MODELS
        ),
        "files": _artifact_predicate(_artifact_table, LOCAL_FILES_MODELS),
    }
    if _artifact_table == "core_backup_execution":
        _artifact_lanes["cloud"] = _artifact_predicate(
            _artifact_table, CLOUD_BACKUP_MODELS
        )
    RLS_POLICY[_artifact_table] = _artifact_lanes
RLS_POLICY = MappingProxyType(
    {
        table: MappingProxyType(dict(sorted(policies.items())))
        for table, policies in sorted(RLS_POLICY.items())
    }
)


def _managed_ssh_approval_predicate(lane: str) -> str:
    lane_literal = _sql_literal(lane)
    operation_reference = (
        "EXISTS (SELECT 1 FROM public.core_managed_ssh_operation "
        "AS bs_managed_operation WHERE "
        "bs_managed_operation.host_key_approval_pk_snapshot = "
        "core_ssh_host_key_approval.id AND "
        "bs_managed_operation.account_id = core_ssh_host_key_approval.account_id "
        f"AND bs_managed_operation.source_lane = {lane_literal})"
    )
    if lane == "database":
        direct_connection = (
            "EXISTS (SELECT 1 FROM public.core_auth_database AS bs_database_auth "
            "JOIN public.core_connection AS bs_connection ON "
            "bs_connection.id = bs_database_auth.connection_id "
            "JOIN public.core_integration AS bs_integration ON "
            "bs_integration.id = bs_connection.integration_id WHERE "
            "bs_connection.account_id = core_ssh_host_key_approval.account_id "
            "AND bs_integration.code = 'database' "
            "AND (COALESCE(bs_database_auth.use_public_key, false) OR "
            "COALESCE(bs_database_auth.use_private_key, false)) "
            "AND bs_database_auth.ssh_host = "
            "core_ssh_host_key_approval.normalized_host "
            "AND bs_database_auth.ssh_port = core_ssh_host_key_approval.port)"
        )
    elif lane == "files":
        direct_connection = (
            "EXISTS (SELECT 1 FROM public.core_auth_website AS bs_website_auth "
            "JOIN public.core_connection AS bs_connection ON "
            "bs_connection.id = bs_website_auth.connection_id "
            "JOIN public.core_integration AS bs_integration ON "
            "bs_integration.id = bs_connection.integration_id WHERE "
            "bs_connection.account_id = core_ssh_host_key_approval.account_id "
            "AND bs_integration.code = 'website' "
            "AND bs_website_auth.protocol = 2 "
            "AND bs_website_auth.host = "
            "core_ssh_host_key_approval.normalized_host "
            "AND bs_website_auth.port = core_ssh_host_key_approval.port)"
        )
    else:  # pragma: no cover - caller inventory is import-time fixed
        raise RuntimeError("managed SSH approval policy has an invalid lane")
    return f"({operation_reference} OR {direct_connection})"


# Command-specific policies are required where a single table has different row
# boundaries per verb. In particular a compromised source worker may maintain its
# own active managed-SSH intent, but retention DELETE is restricted to terminal
# rows. SELECT-only approval access is limited to the exact approval snapshots
# referenced by that lane's operations.
RLS_COMMAND_POLICY = MappingProxyType(
    {
        "core_connection": MappingProxyType(
            {
                # The default queue shares the cloud process. Its durable
                # dispatcher must inspect every request's connection state, but
                # cloud has no connection UPDATE/DELETE grant.
                "cloud": MappingProxyType({"SELECT": "true"}),
            }
        ),
        "core_log": MappingProxyType(
            {
                lane: MappingProxyType(
                    {
                        "INSERT": _account_lane_predicate(
                            lane, "core_log.account_id"
                        ),
                        "SELECT": _account_lane_predicate(
                            lane, "core_log.account_id"
                        ),
                    }
                )
                for lane in ("cloud", "database", "files", "storage")
            }
        ),
        "core_node": MappingProxyType(
            {
                "cloud": MappingProxyType(
                    {
                        "SELECT": "true",
                        "UPDATE": _connection_lane_predicate(
                            "cloud", "connection_id"
                        ),
                        "DELETE": _connection_lane_predicate(
                            "cloud", "connection_id"
                        ),
                    }
                ),
                "database": MappingProxyType(
                    {
                        "SELECT": _connection_lane_predicate(
                            "database", "connection_id"
                        ),
                        "UPDATE": _connection_lane_predicate(
                            "database", "connection_id"
                        ),
                    }
                ),
                "files": MappingProxyType(
                    {
                        "SELECT": _connection_lane_predicate(
                            "files", "connection_id"
                        ),
                        "UPDATE": _connection_lane_predicate(
                            "files", "connection_id"
                        ),
                    }
                ),
                "storage": MappingProxyType(
                    {
                        "SELECT": _connection_lane_predicate(
                            "storage", "connection_id"
                        ),
                        "UPDATE": _connection_lane_predicate(
                            "storage", "connection_id"
                        ),
                        "DELETE": _connection_lane_predicate(
                            "storage", "connection_id"
                        ),
                    }
                ),
            }
        ),
        MANAGED_SSH_OPERATION_TABLE: MappingProxyType(
            {
                lane: MappingProxyType(
                    {
                        "SELECT": f"source_lane = {_sql_literal(lane)}",
                        "UPDATE": f"source_lane = {_sql_literal(lane)}",
                    }
                )
                for lane in ("database", "files")
            }
        ),
        SSH_HOST_KEY_APPROVAL_TABLE: MappingProxyType(
            {
                lane: MappingProxyType(
                    {"SELECT": _managed_ssh_approval_predicate(lane)}
                )
                for lane in ("database", "files")
            }
        ),
    }
)


def row_policy_definitions():
    """Return exact ``(table, lane, command, predicate, name)`` policies."""

    definitions = []
    for table, lane_policies in RLS_POLICY.items():
        for lane, predicate in lane_policies.items():
            definitions.append(
                (table, lane, "ALL", predicate, f"backupsheep_v3_{lane}")
            )
    for table, lane_policies in RLS_COMMAND_POLICY.items():
        for lane, commands in lane_policies.items():
            for command, predicate in commands.items():
                definitions.append(
                    (
                        table,
                        lane,
                        command,
                        predicate,
                        f"backupsheep_v3_{lane}_{command.lower()}",
                    )
                )
    return tuple(sorted(definitions))


ROW_SECURITY_TABLES = frozenset(
    set(RLS_POLICY) | set(RLS_COMMAND_POLICY)
)


def policy_for_lane(lane: str):
    """Return the immutable table/privilege map for one reviewed lane."""

    try:
        return LANE_TABLE_POLICY[lane]
    except KeyError as error:
        raise ValueError(f"unknown database lane: {lane}") from error


def lanes_with_table_privilege(table: str, privilege: str) -> frozenset[str]:
    """Return lanes whose exact policy contains one table privilege."""

    normalized = privilege.upper()
    if normalized not in TABLE_PRIVILEGES:
        raise ValueError(f"unknown table privilege: {privilege}")
    return frozenset(
        lane
        for lane, policy in LANE_TABLE_POLICY.items()
        if normalized in policy.get(table, ())
    )


# Import-time assertions turn a typo or accidental wildcard broadening into an image
# build/test failure rather than a production grant surprise.
if set(LANE_TABLE_POLICY) != set(LANES):  # pragma: no cover - invariant
    raise RuntimeError("database lane policy does not cover every lane")
for _lane, _policy in LANE_TABLE_POLICY.items():  # pragma: no branch - invariant
    if not set(_policy).issubset(EXPECTED_TABLES):  # pragma: no cover
        raise RuntimeError(f"database lane {_lane} names an unknown table")
    for _table, _privileges in _policy.items():
        if not _privileges or not _privileges.issubset(TABLE_PRIVILEGES):  # pragma: no cover
            raise RuntimeError(
                f"database lane {_lane} has invalid privileges for {_table}"
            )
if set(EXPECTED_ROUTINE_ATTRIBUTES) != set(EXPECTED_ROUTINES):  # pragma: no cover
    raise RuntimeError("database routine attributes do not cover exact inventory")
for _table, _lanes in RLS_COMMAND_POLICY.items():  # pragma: no branch - invariant
    if _table not in EXPECTED_TABLES:  # pragma: no cover
        raise RuntimeError("database command policy names an unknown table")
    for _lane, _commands in _lanes.items():
        if _lane not in LANES or not set(_commands).issubset(
            {"SELECT", "INSERT", "UPDATE", "DELETE"}
        ):  # pragma: no cover
            raise RuntimeError("database command policy is invalid")
