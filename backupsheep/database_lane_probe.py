"""Adversarial PostgreSQL probe for a sealed generation-3 stock deployment.

Run this only from the one-shot database sealing container, which receives all
database secret files.  Every test transaction is rolled back.  The probe logs no
DSN, password, row value, or driver diagnostic.
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
import uuid
from contextlib import closing

import psycopg2
from psycopg2 import errors, sql

from backupsheep.database_identity import IdentityConfiguration, ProvisioningError
from backupsheep.database_lane_policy import (
    EXPECTED_ROUTINES,
    LANES,
    MANAGED_SSH_REVOKE_APPROVAL_ROUTINE,
    MANAGED_SSH_RETENTION_ROUTINE,
    MANAGED_SSH_ROUTINES,
    MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE,
    RETIRED_TABLES,
    SSH_HOST_KEY_REVOKE_WITNESS_TABLE,
    STORAGE_CONFIG_TABLES,
)


class LaneProbeError(RuntimeError):
    """A runtime principal crossed a reviewed PostgreSQL boundary."""


def _connect(config: IdentityConfiguration, *, user: str, password: str):
    return psycopg2.connect(
        dbname=config.database,
        user=user,
        password=password,
        host="db",
        port=5432,
        connect_timeout=10,
        application_name="backupsheep-database-lane-adversarial-probe",
        options="-c client_min_messages=warning",
        sslmode="disable",
        target_session_attrs="read-write",
    )


def _expect_denied(connection, statement: str, *, label: str) -> None:
    try:
        with connection.cursor() as cursor:
            cursor.execute(statement)
    except errors.InsufficientPrivilege:
        connection.rollback()
        return
    except psycopg2.Error:
        connection.rollback()
        raise LaneProbeError(f"{label} failed for an unexpected database reason") from None
    connection.rollback()
    raise LaneProbeError(f"{label} was unexpectedly allowed")


def _expect_allowed(connection, statement: str, *, label: str) -> None:
    try:
        with connection.cursor() as cursor:
            cursor.execute(statement)
    except psycopg2.Error:
        connection.rollback()
        raise LaneProbeError(f"{label} was unexpectedly denied") from None
    connection.rollback()


def _assert_role_boundary(connection, lane: str, expected_user: str) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT current_user, role.rolsuper, role.rolcreatedb,
                   role.rolcreaterole, role.rolreplication, role.rolbypassrls,
                   pg_catalog.has_database_privilege(
                       current_user, current_database(), 'CREATE'
                   ),
                   pg_catalog.has_database_privilege(
                       current_user, current_database(), 'TEMPORARY'
                   ),
                   pg_catalog.has_schema_privilege(
                       current_user, 'public', 'CREATE'
                   )
              FROM pg_catalog.pg_roles role
             WHERE role.rolname = current_user
            """
        )
        record = cursor.fetchone()
    connection.rollback()
    if record is None or record[0] != expected_user or any(record[1:]):
        raise LaneProbeError(f"{lane} has an elevated role, DDL, or TEMP capability")

    _expect_denied(
        connection,
        f"CREATE TABLE public.backupsheep_probe_{lane} (id integer)",
        label=f"{lane} public DDL",
    )
    _expect_denied(
        connection,
        f"CREATE TEMPORARY TABLE backupsheep_probe_{lane} (id integer)",
        label=f"{lane} TEMP",
    )


def _replay_insert(target_lane: str, suffix: str) -> str:
    execution_key = (target_lane + suffix).encode("utf-8").hex().ljust(64, "0")[:64]
    envelope_digest = (suffix + target_lane).encode("utf-8").hex().ljust(64, "f")[:64]
    return f"""
        INSERT INTO public.backupsheep_celery_task_replay (
            execution_key, envelope_digest, task_id, task_name,
            publisher_lane, target_lane, retry_count, status,
            first_seen_at, last_seen_at, completed_at, delivery_count
        ) VALUES (
            '{execution_key}', '{envelope_digest}', 'probe-task-id',
            'probe-task', 'app', '{target_lane}', 0, 'active',
            pg_catalog.now(), pg_catalog.now(), NULL, 1
        )
    """


def _assert_replay_row_isolation(config: IdentityConfiguration) -> None:
    with closing(
        _connect(
            config,
            user=config.bootstrap_user,
            password=config.bootstrap_password,
        )
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(_replay_insert("database", "bootstrap-a"))
            cursor.execute(_replay_insert("files", "bootstrap-b"))
            for lane, own_lane in (("database", "database"), ("files", "files")):
                cursor.execute(
                    sql.SQL("SET LOCAL ROLE {}").format(
                        sql.Identifier(config.lane_users[lane])
                    )
                )
                cursor.execute(
                    """
                    SELECT target_lane, pg_catalog.count(*)
                      FROM public.backupsheep_celery_task_replay
                     GROUP BY target_lane
                     ORDER BY target_lane
                    """
                )
                if cursor.fetchall() != [(own_lane, 1)]:
                    raise LaneProbeError(f"{lane} can observe another replay lane")
                cursor.execute("RESET ROLE")
        connection.rollback()


def _set_lane_role(cursor, config: IdentityConfiguration, lane: str | None) -> None:
    if lane is None:
        cursor.execute("RESET ROLE")
        return
    cursor.execute(
        sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(config.lane_users[lane]))
    )


def _insert_artifact_fixture(cursor, *, model_name: str, suffix: str):
    """Create a pending execution/envelope/wrap without a concrete backup FK."""

    cursor.execute(
        """
        SELECT id
          FROM public.django_content_type
         WHERE app_label = 'apps' AND model = %s
        """,
        (model_name,),
    )
    content_type = cursor.fetchone()
    if content_type is None:
        raise LaneProbeError(f"artifact probe is missing content type {model_name}")
    cursor.execute(
        """
        INSERT INTO public.core_backup_execution (
            created, modified, correlation_id, backup_object_id,
            celery_task_id, task_name, worker_name, attempt_count,
            delivery_count, claim_count, phase, lease_owner, lease_token,
            lease_expires_at, heartbeat_at, started_at, finished_at,
            reconciliation_state, reconciliation_reason,
            reconciliation_metadata, last_error_code, last_error_message,
            last_error_at, next_retry_at, progress_completed, progress_total,
            progress_unit, provider_operation_id, provider_resource_id,
            provider_idempotency_key, provider_status, provider_metadata,
            artifact_bytes, artifact_checksum_algorithm, artifact_checksum,
            artifact_verified_at, metadata, backup_content_type_id
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s, %s,
            %s, '', '', 0, 0, 0, '', '', NULL, NULL, NULL, NULL, NULL,
            'none', '', '{}'::jsonb, '', '', NULL, NULL, 0, NULL, '', '', '',
            '', '', '{}'::jsonb, 0, '', '', NULL, '{}'::jsonb, %s
        ) RETURNING id
        """,
        (str(uuid.uuid4()), int(suffix, 16), f"lane-artifact-{suffix}", content_type[0]),
    )
    execution_id = int(cursor.fetchone()[0])
    cursor.execute(
        """
        INSERT INTO public.core_backup_encryption_envelope (
            created, modified, uuid, format_version, algorithm, chunk_size,
            context_canonical_json, context_sha256, header_sha256,
            plaintext_byte_count, plaintext_sha256, ciphertext_byte_count,
            status, sealed_at, execution_id
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s, 1,
            'AES-256-GCM-SIV', 4194304, %s, %s, %s, 0, %s, 0,
            'pending', NULL, %s
        ) RETURNING id
        """,
        (
            str(uuid.uuid4()),
            f'{{"probe":"{suffix}"}}',
            "a" * 64,
            "b" * 64,
            "c" * 64,
            execution_id,
        ),
    )
    envelope_id = int(cursor.fetchone()[0])
    wrapped_key = f"lane-artifact-key-{suffix}".encode("ascii")
    cursor.execute(
        """
        INSERT INTO public.core_backup_key_wrap (
            created, modified, uuid, generation, provider, wrapping_key_id,
            wrapped_data_key, wrapped_key_sha256, status, activated_at,
            retired_at, envelope_id
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s, 1,
            'local-development', 'lane-probe-key', %s, %s, 'pending',
            NULL, NULL, %s
        ) RETURNING id
        """,
        (
            str(uuid.uuid4()),
            psycopg2.Binary(wrapped_key),
            hashlib.sha256(wrapped_key).hexdigest(),
            envelope_id,
        ),
    )
    return {
        "execution": execution_id,
        "envelope": envelope_id,
        "key_wrap": int(cursor.fetchone()[0]),
    }


def _assert_artifact_row_isolation(config: IdentityConfiguration) -> None:
    """Prove local source lanes cannot read or erase each other's key custody."""

    with closing(
        _connect(config, user=config.bootstrap_user, password=config.bootstrap_password)
    ) as connection:
        try:
            with connection.cursor() as cursor:
                fixtures = {
                    "database": _insert_artifact_fixture(
                        cursor, model_name="coredatabasebackup", suffix="da"
                    ),
                    "files": _insert_artifact_fixture(
                        cursor, model_name="corewebsitebackup", suffix="fa"
                    ),
                }
                cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
                cursor.execute("SET CONSTRAINTS ALL DEFERRED")

                for lane, foreign_lane in (
                    ("database", "files"),
                    ("files", "database"),
                ):
                    _set_lane_role(cursor, config, lane)
                    for table, key in (
                        ("core_backup_execution", "execution"),
                        ("core_backup_encryption_envelope", "envelope"),
                        ("core_backup_key_wrap", "key_wrap"),
                    ):
                        cursor.execute(
                            sql.SQL("SELECT id FROM public.{} ORDER BY id").format(
                                sql.Identifier(table)
                            )
                        )
                        if cursor.fetchall() != [(fixtures[lane][key],)]:
                            raise LaneProbeError(
                                f"{lane} artifact visibility crossed at {table}"
                            )
                    cursor.execute(
                        """
                        UPDATE public.core_backup_key_wrap
                           SET modified = modified
                         WHERE id = %s RETURNING id
                        """,
                        (fixtures[foreign_lane]["key_wrap"],),
                    )
                    if cursor.fetchone() is not None:
                        raise LaneProbeError(f"{lane} rewrote another lane's key wrap")
                    _expect_cursor_denied(
                        cursor,
                        "DELETE FROM public.core_backup_key_wrap WHERE id = %s",
                        (fixtures[lane]["key_wrap"],),
                        label=f"{lane} direct artifact proof erasure",
                    )
                    _set_lane_role(cursor, config, None)

                _set_lane_role(cursor, config, "storage")
                cursor.execute(
                    "SELECT id FROM public.core_backup_key_wrap ORDER BY id"
                )
                if cursor.fetchall() != [
                    (fixtures["database"]["key_wrap"],),
                    (fixtures["files"]["key_wrap"],),
                ]:
                    raise LaneProbeError("storage cannot reconcile both local key wraps")
                _set_lane_role(cursor, config, "cloud")
                cursor.execute(
                    "SELECT id FROM public.core_backup_execution ORDER BY id"
                )
                if cursor.fetchall():
                    raise LaneProbeError("cloud observed a local artifact execution")
                _set_lane_role(cursor, config, None)
        finally:
            connection.rollback()


def _expect_cursor_denied(
    cursor,
    statement: str,
    parameters=(),
    *,
    label: str,
) -> None:
    """Assert one statement is denied without discarding an outer probe fixture."""

    cursor.execute("SAVEPOINT backupsheep_lane_denial")
    try:
        cursor.execute(statement, parameters)
    except errors.InsufficientPrivilege:
        cursor.execute("ROLLBACK TO SAVEPOINT backupsheep_lane_denial")
        cursor.execute("RELEASE SAVEPOINT backupsheep_lane_denial")
        return
    except psycopg2.Error:
        cursor.execute("ROLLBACK TO SAVEPOINT backupsheep_lane_denial")
        cursor.execute("RELEASE SAVEPOINT backupsheep_lane_denial")
        raise LaneProbeError(f"{label} failed for an unexpected database reason") from None
    cursor.execute("RELEASE SAVEPOINT backupsheep_lane_denial")
    raise LaneProbeError(f"{label} was unexpectedly allowed")


def _expect_cursor_rejected(
    cursor,
    statement: str,
    parameters=(),
    *,
    label: str,
) -> None:
    """Assert a database invariant (not merely an ACL) rejects a statement."""

    cursor.execute("SAVEPOINT backupsheep_lane_rejection")
    try:
        cursor.execute(statement, parameters)
    except (errors.InsufficientPrivilege, errors.CheckViolation):
        cursor.execute("ROLLBACK TO SAVEPOINT backupsheep_lane_rejection")
        cursor.execute("RELEASE SAVEPOINT backupsheep_lane_rejection")
        return
    except psycopg2.Error:
        cursor.execute("ROLLBACK TO SAVEPOINT backupsheep_lane_rejection")
        cursor.execute("RELEASE SAVEPOINT backupsheep_lane_rejection")
        raise LaneProbeError(f"{label} failed for an unexpected database reason") from None
    cursor.execute("RELEASE SAVEPOINT backupsheep_lane_rejection")
    raise LaneProbeError(f"{label} was unexpectedly allowed")


def _insert_probe_actor(cursor, marker: str) -> tuple[int, int, int]:
    """Create one account/member witness as the bootstrap role."""

    cursor.execute(
        """
        INSERT INTO public.core_account (
            created, modified, name, status, notify_on_success, notify_on_fail,
            stats_storage_used_bs, stats_storage_used_byo, stats_nodes_used
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s,
            1, true, true, 0, 0, 0
        ) RETURNING id
        """,
        (f"database-lane-probe-{marker}",),
    )
    account_id = int(cursor.fetchone()[0])
    cursor.execute(
        """
        INSERT INTO public.auth_user (
            password, last_login, is_superuser, username, first_name, last_name,
            email, is_staff, is_active, date_joined
        ) VALUES (
            '', NULL, false, %s, '', '', %s, false, true,
            pg_catalog.clock_timestamp()
        ) RETURNING id
        """,
        (f"lane-probe-{marker}", f"lane-probe-{marker}@example.invalid"),
    )
    user_id = int(cursor.fetchone()[0])
    cursor.execute(
        """
        INSERT INTO public.core_member (
            created, modified, user_id, timezone,
            auth_multi_factor_display_name, auth_session_version
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s,
            'UTC', '', 1
        ) RETURNING id
        """,
        (user_id,),
    )
    member_id = int(cursor.fetchone()[0])
    cursor.execute(
        """
        INSERT INTO public.core_member_mtm_account (
            created, modified, member_id, account_id, status,
            notify_on_success, notify_on_fail, current, "primary"
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s, %s,
            1, true, true, true, true
        )
        """,
        (member_id, account_id),
    )
    return account_id, member_id, user_id


def _integration_id(cursor, code: str) -> int:
    cursor.execute(
        "SELECT id FROM public.core_integration WHERE code = %s",
        (code,),
    )
    row = cursor.fetchone()
    if row is None:
        raise LaneProbeError(f"managed SSH probe requires the {code} integration")
    return int(row[0])


def _insert_probe_connection(
    cursor,
    *,
    account_id: int,
    integration_id: int,
    marker: str,
) -> int:
    cursor.execute(
        """
        INSERT INTO public.core_connection (
            created, modified, account_id, status, notification,
            managed_ssh_generation, integration_id, name
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s,
            1, 1, 0, %s, %s
        ) RETURNING id
        """,
        (account_id, integration_id, f"lane-probe-{marker}"),
    )
    return int(cursor.fetchone()[0])


def _insert_probe_node(
    cursor,
    *,
    connection_id: int,
    node_type: int,
    marker: str,
) -> int:
    cursor.execute(
        """
        INSERT INTO public.core_node (
            created, modified, connection_id, status, type, name,
            flag_next_run_wait, flag_delete_node, notify_on_success,
            notify_on_fail, email_data, timezone, added_by_id
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s,
            1, %s, %s, NULL, false, true, true, NULL, 'UTC', NULL
        ) RETURNING id
        """,
        (connection_id, node_type, f"lane-probe-node-{marker}"),
    )
    return int(cursor.fetchone()[0])


def _insert_database_auth(
    cursor,
    *,
    connection_id: int,
    host: str,
    use_public_key: bool,
    use_private_key: bool,
) -> None:
    cursor.execute(
        """
        INSERT INTO public.core_auth_database (
            created, modified, connection_id, host, port, database_name,
            all_databases, type, version, include_stored_procedure, use_ssl,
            ssh_port, ssh_host, use_public_key, use_private_key,
            encryption_updated, flag_use_sha1_key_verification
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s,
            'database.example.invalid', 5432, 'probe', false, 3,
            'postgres_18', false, true, 22, %s, %s, %s, true, false
        )
        """,
        (connection_id, host, use_public_key, use_private_key),
    )


def _insert_website_auth(
    cursor,
    *,
    connection_id: int,
    host: str,
    use_private_key: bool,
) -> None:
    cursor.execute(
        """
        INSERT INTO public.core_auth_website (
            created, modified, connection_id, host, port, use_private_key,
            username, password, protocol, use_public_key,
            ftps_use_explicit_ssl, verify_ssl, encryption_updated,
            flag_use_sha1_key_verification
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s,
            %s, 22, %s, '\\x75736572'::bytea, '\\x70617373'::bytea, 2,
            false, false, true, true, false
        )
        """,
        (connection_id, host, use_private_key),
    )


def _insert_host_key_approval(
    cursor,
    config: IdentityConfiguration,
    *,
    account_id: int,
    member_id: int,
    user_id: int,
    host: str,
    fingerprint: str,
) -> int:
    _set_lane_role(cursor, config, "app")
    cursor.execute(
        """
        INSERT INTO public.core_ssh_host_key_approval (
            created, modified, account_id, normalized_host, port,
            wire_key_type, public_key_base64, fingerprint,
            negotiated_host_key_algorithm, bits, generation,
            approved_by_member_pk_snapshot, approved_by_user_pk_snapshot
        ) VALUES (
            pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), %s, %s,
            22, 'ssh-ed25519',
            'cHJvYmUtaG9zdC1rZXktZXZpZGVuY2U=', %s,
            'ssh-ed25519', 256, 1, %s, %s
        ) RETURNING id
        """,
        (account_id, host, fingerprint, member_id, user_id),
    )
    approval_id = int(cursor.fetchone()[0])
    _set_lane_role(cursor, config, None)
    return approval_id


def _probe_ssh_fingerprint(marker: str) -> str:
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(marker.encode("utf-8")).digest()
    ).decode("ascii").rstrip("=")


def _insert_managed_operation(
    cursor,
    config: IdentityConfiguration,
    *,
    account_id: int,
    connection_id: int,
    member_id: int,
    user_id: int,
    approval_id: int,
    approval_fingerprint: str,
    operation: str = "validate",
    created_offset_seconds: int = 0,
    modified_offset_seconds: int = 0,
    expires_offset_seconds: int = 600,
    expected_rejection_label: str | None = None,
) -> int | None:
    cursor.execute(
        "SELECT managed_ssh_generation FROM public.core_connection WHERE id = %s",
        (connection_id,),
    )
    generation = int(cursor.fetchone()[0])
    operation_uuid = uuid.uuid4()
    task_uuid = uuid.uuid4()
    idempotency_key = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    _set_lane_role(cursor, config, "app")
    insert_statement = """
        WITH bs_time AS (
            SELECT pg_catalog.clock_timestamp() AS observed_at
        )
        INSERT INTO public.core_managed_ssh_operation (
            created, modified, uuid, connection_id, account_id,
            requested_by_member_pk_snapshot, requested_by_user_pk_snapshot,
            request_actor_kind, request_source, source_lane, operation,
            requested_path, managed_public_key_fingerprint,
            connection_config_digest, connection_generation,
            host_key_approval_pk_snapshot, host_key_approval_generation,
            host_key_fingerprint, host_key_negotiated_algorithm,
            celery_task_id, idempotency_key, intent_digest, expires_at,
            status, lease_token, lease_expires_at, attempts, claimed_at,
            completed_at, result_payload, result_digest, error_payload,
            execution_witness_digest, publish_attempts,
            last_publish_attempt_at, published_at, publish_error_code
        ) SELECT
            bs_time.observed_at + (%s * interval '1 second'),
            bs_time.observed_at + (%s * interval '1 second'), %s, %s,
            %s, %s, %s, 'member', 'api', 'database', %s, '', %s, %s, %s,
            %s, 1, %s, 'ssh-ed25519', %s, %s, %s,
            bs_time.observed_at + (%s * interval '1 second'), 'pending', NULL,
            NULL, 0, NULL, NULL, '{}'::jsonb, '', '{}'::jsonb, '', 0,
            NULL, NULL, ''
          FROM bs_time
        RETURNING id
        """
    insert_parameters = (
        created_offset_seconds,
        modified_offset_seconds,
        str(operation_uuid),
        connection_id,
        account_id,
        member_id,
        user_id,
        operation,
        "a" * 64,
        "b" * 64,
        generation,
        approval_id,
        approval_fingerprint,
        str(task_uuid),
        idempotency_key,
        "d" * 64,
        expires_offset_seconds,
    )
    if expected_rejection_label is not None:
        _expect_cursor_rejected(
            cursor,
            insert_statement,
            insert_parameters,
            label=expected_rejection_label,
        )
        _set_lane_role(cursor, config, None)
        return None

    cursor.execute(insert_statement, insert_parameters)
    operation_id = int(cursor.fetchone()[0])
    cursor.execute(
        """
        UPDATE public.core_managed_ssh_operation
           SET publish_attempts = 1,
               last_publish_attempt_at = pg_catalog.clock_timestamp(),
               published_at = pg_catalog.clock_timestamp(),
               publish_error_code = '',
               modified = pg_catalog.clock_timestamp()
         WHERE id = %s
        """,
        (operation_id,),
    )
    if cursor.rowcount != 1:
        raise LaneProbeError("app could not record managed SSH publication")
    _set_lane_role(cursor, config, None)
    return operation_id


def _managed_probe_fixture(
    cursor,
    config: IdentityConfiguration,
    marker: str,
    *,
    actor: tuple[int, int, int] | None = None,
):
    account_id, member_id, user_id = actor or _insert_probe_actor(cursor, marker)
    connection_id = _insert_probe_connection(
        cursor,
        account_id=account_id,
        integration_id=_integration_id(cursor, "database"),
        marker=marker,
    )
    host = f"{marker}.example.invalid"
    fingerprint = _probe_ssh_fingerprint(marker)
    _insert_database_auth(
        cursor,
        connection_id=connection_id,
        host=host,
        use_public_key=True,
        use_private_key=False,
    )
    approval_id = _insert_host_key_approval(
        cursor,
        config,
        account_id=account_id,
        member_id=member_id,
        user_id=user_id,
        host=host,
        fingerprint=fingerprint,
    )
    operation_id = _insert_managed_operation(
        cursor,
        config,
        account_id=account_id,
        connection_id=connection_id,
        member_id=member_id,
        user_id=user_id,
        approval_id=approval_id,
        approval_fingerprint=fingerprint,
    )
    return {
        "account": account_id,
        "member": member_id,
        "user": user_id,
        "connection": connection_id,
        "approval": approval_id,
        "approval_fingerprint": fingerprint,
        "operation": operation_id,
    }


def _assert_source_log_boundary(config: IdentityConfiguration) -> None:
    """Prove source lanes append opaque log ids but cannot inspect or rewrite logs."""

    with closing(
        _connect(config, user=config.bootstrap_user, password=config.bootstrap_password)
    ) as connection:
        try:
            with connection.cursor() as cursor:
                marker = uuid.uuid4().hex[:20]
                account_id, _member_id, _user_id = _insert_probe_actor(cursor, marker)
                # One account may legitimately use every worker capability. The
                # RLS predicates below prove each source can append for an account
                # it serves without granting arbitrary-account notification spam.
                for suffix, integration_code in (
                    ("cloud", "digitalocean"),
                    ("database", "database"),
                    ("files", "website"),
                ):
                    _insert_probe_connection(
                        cursor,
                        account_id=account_id,
                        integration_id=_integration_id(cursor, integration_code),
                        marker=marker + suffix,
                    )
                unrelated_account_id, _unused_member, _unused_user = (
                    _insert_probe_actor(cursor, marker + "unrelated")
                )
                log_ids = []
                for lane in ("cloud", "database", "files", "storage"):
                    _set_lane_role(cursor, config, lane)
                    cursor.execute(
                        """
                        INSERT INTO public.core_log (
                            created, modified, account_id, type, data
                        ) VALUES (
                            pg_catalog.clock_timestamp(),
                            pg_catalog.clock_timestamp(), %s, 1,
                            '{"notification_fanout_status":"pending"}'::jsonb
                        ) RETURNING id
                        """,
                        (account_id,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise LaneProbeError(f"{lane} could not append a durable log")
                    log_id = int(row[0])
                    log_ids.append(log_id)
                    # This is the exact database lookup performed by the signed
                    # send_log_to_db intent resolver before apply_async. It may
                    # establish existence by opaque id but cannot fetch payload.
                    cursor.execute(
                        "SELECT id FROM public.core_log WHERE id = %s",
                        (log_id,),
                    )
                    if cursor.fetchone() != (log_id,):
                        raise LaneProbeError(
                            f"{lane} could not resolve its opaque log id"
                        )
                    _expect_cursor_denied(
                        cursor,
                        "SELECT data FROM public.core_log WHERE id = %s",
                        (log_id,),
                        label=f"{lane} log payload read",
                    )
                    _expect_cursor_denied(
                        cursor,
                        "UPDATE public.core_log SET data = '{}'::jsonb WHERE id = %s",
                        (log_id,),
                        label=f"{lane} log payload rewrite",
                    )
                    _expect_cursor_denied(
                        cursor,
                        """
                        INSERT INTO public.core_log (
                            created, modified, account_id, type, data
                        ) VALUES (
                            pg_catalog.clock_timestamp(),
                            pg_catalog.clock_timestamp(), %s, 1, '{}'::jsonb
                        )
                        """,
                        (unrelated_account_id,),
                        label=f"{lane} unrelated-account log append",
                    )

                _set_lane_role(cursor, config, "logs")
                cursor.execute(
                    """
                    UPDATE public.core_log
                       SET data = data || '{"notification_fanout_status":"complete"}'::jsonb,
                           modified = pg_catalog.clock_timestamp()
                     WHERE id = ANY(%s)
                     RETURNING id, data->>'notification_fanout_status'
                    """,
                    (log_ids,),
                )
                rows = cursor.fetchall()
                if len(rows) != len(log_ids) or any(row[1] != "complete" for row in rows):
                    raise LaneProbeError("logs could not consume source log requests")
                _set_lane_role(cursor, config, None)
        finally:
            connection.rollback()


def _assert_shared_node_row_isolation(config: IdentityConfiguration) -> None:
    """Prove shared CoreNode status/deletion rights cannot cross worker lanes."""

    with closing(
        _connect(config, user=config.bootstrap_user, password=config.bootstrap_password)
    ) as connection:
        try:
            with connection.cursor() as cursor:
                marker = uuid.uuid4().hex[:20]
                account_id, _member_id, _user_id = _insert_probe_actor(cursor, marker)
                node_ids = {}
                for lane, integration_code, node_type in (
                    ("cloud", "digitalocean", 1),
                    ("database", "database", 4),
                    ("files", "website", 3),
                ):
                    connection_id = _insert_probe_connection(
                        cursor,
                        account_id=account_id,
                        integration_id=_integration_id(cursor, integration_code),
                        marker=marker + lane,
                    )
                    node_ids[lane] = _insert_probe_node(
                        cursor,
                        connection_id=connection_id,
                        node_type=node_type,
                        marker=marker + lane,
                    )

                expected_visibility = {
                    "cloud": sorted(node_ids.values()),
                    "database": [node_ids["database"]],
                    "files": [node_ids["files"]],
                    "storage": sorted(
                        (node_ids["database"], node_ids["files"])
                    ),
                }
                for lane, expected in expected_visibility.items():
                    _set_lane_role(cursor, config, lane)
                    cursor.execute(
                        "SELECT id FROM public.core_node WHERE id = ANY(%s) ORDER BY id",
                        (list(node_ids.values()),),
                    )
                    observed = [int(row[0]) for row in cursor.fetchall()]
                    if observed != expected:
                        raise LaneProbeError(
                            f"{lane} shared-node visibility crossed its lane"
                        )

                for lane in ("database", "files"):
                    _set_lane_role(cursor, config, lane)
                    own_node_id = node_ids[lane]
                    cursor.execute(
                        """
                        UPDATE public.core_node
                           SET status = status,
                               modified = pg_catalog.clock_timestamp()
                         WHERE id = %s RETURNING id
                        """,
                        (own_node_id,),
                    )
                    if cursor.fetchone() != (own_node_id,):
                        raise LaneProbeError(f"{lane} could not update its node status")
                    foreign_lane = "files" if lane == "database" else "database"
                    cursor.execute(
                        """
                        UPDATE public.core_node
                           SET status = status,
                               modified = pg_catalog.clock_timestamp()
                         WHERE id = %s RETURNING id
                        """,
                        (node_ids[foreign_lane],),
                    )
                    if cursor.fetchone() is not None:
                        raise LaneProbeError(f"{lane} updated another source lane's node")
                    _expect_cursor_denied(
                        cursor,
                        "UPDATE public.core_node SET name = name WHERE id = %s",
                        (own_node_id,),
                        label=f"{lane} node identity rewrite",
                    )
                    _expect_cursor_denied(
                        cursor,
                        "DELETE FROM public.core_node WHERE id = %s",
                        (own_node_id,),
                        label=f"{lane} node deletion",
                    )

                for lane, own_lane, foreign_lane in (
                    ("cloud", "cloud", "database"),
                    ("storage", "database", "cloud"),
                ):
                    _set_lane_role(cursor, config, lane)
                    cursor.execute(
                        """
                        UPDATE public.core_node
                           SET status = status, flag_delete_node = flag_delete_node,
                               modified = pg_catalog.clock_timestamp()
                         WHERE id = %s RETURNING id
                        """,
                        (node_ids[own_lane],),
                    )
                    if cursor.fetchone() != (node_ids[own_lane],):
                        raise LaneProbeError(f"{lane} could not maintain its node")
                    cursor.execute(
                        """
                        UPDATE public.core_node
                           SET status = status, modified = pg_catalog.clock_timestamp()
                         WHERE id = %s RETURNING id
                        """,
                        (node_ids[foreign_lane],),
                    )
                    if cursor.fetchone() is not None:
                        raise LaneProbeError(f"{lane} updated a foreign node")
                    cursor.execute(
                        "DELETE FROM public.core_node WHERE id = %s RETURNING id",
                        (node_ids[foreign_lane],),
                    )
                    if cursor.fetchone() is not None:
                        raise LaneProbeError(f"{lane} deleted a foreign node")

                _set_lane_role(cursor, config, None)
        finally:
            connection.rollback()


def _assert_managed_ssh_row_isolation(config: IdentityConfiguration) -> None:
    """Exercise source lifecycles and app Collector-style deletes under RLS."""

    with closing(
        _connect(config, user=config.bootstrap_user, password=config.bootstrap_password)
    ) as connection:
        try:
            with connection.cursor() as cursor:
                marker = uuid.uuid4().hex[:20]
                # The global helper deliberately bypasses lane RLS: an account with
                # no connection in the caller's lane must still make installation-
                # managed SSH fail closed. Prove false with a second account, remove
                # it completely, then prove the one-account installation predicate.
                primary_actor = _insert_probe_actor(cursor, marker + "primary")
                second_actor = _insert_probe_actor(cursor, marker + "second")
                for lane in ("app", "database", "files"):
                    _set_lane_role(cursor, config, lane)
                    cursor.execute(
                        sql.SQL("SELECT public.{}(%s)").format(
                            sql.Identifier(MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE)
                        ),
                        (primary_actor[0],),
                    )
                    if cursor.fetchone() != (False,):
                        raise LaneProbeError(
                            f"{lane} ignored a second account outside its lane"
                        )
                _set_lane_role(cursor, config, None)
                cursor.execute(
                    "DELETE FROM public.core_member_mtm_account WHERE member_id = %s",
                    (second_actor[1],),
                )
                cursor.execute(
                    "DELETE FROM public.core_member WHERE id = %s", (second_actor[1],)
                )
                cursor.execute(
                    "DELETE FROM public.auth_user WHERE id = %s", (second_actor[2],)
                )
                cursor.execute(
                    "DELETE FROM public.core_account WHERE id = %s", (second_actor[0],)
                )
                cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
                cursor.execute("SET CONSTRAINTS ALL DEFERRED")
                for lane in ("app", "database", "files"):
                    _set_lane_role(cursor, config, lane)
                    cursor.execute(
                        sql.SQL("SELECT public.{}(%s)").format(
                            sql.Identifier(MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE)
                        ),
                        (primary_actor[0],),
                    )
                    if cursor.fetchone() != (True,):
                        raise LaneProbeError(
                            f"{lane} rejected the sole installation account"
                        )
                _set_lane_role(cursor, config, None)

                complete = _managed_probe_fixture(
                    cursor, config, marker + "a", actor=primary_actor
                )
                failed = _managed_probe_fixture(
                    cursor, config, marker + "b", actor=primary_actor
                )
                expired = _managed_probe_fixture(
                    cursor, config, marker + "c", actor=primary_actor
                )

                # Expanding the installation while managed SSH is configured must
                # atomically fence every managed auth row. Roll the synthetic second
                # account back so the remainder can exercise the valid lifecycle.
                _set_lane_role(cursor, config, "app")
                cursor.execute("SAVEPOINT backupsheep_account_fence")
                cursor.execute(
                    """
                    INSERT INTO public.core_account (
                        created, modified, name, status, notify_on_success,
                        notify_on_fail, stats_storage_used_bs,
                        stats_storage_used_byo, stats_nodes_used
                    ) VALUES (
                        pg_catalog.clock_timestamp(),
                        pg_catalog.clock_timestamp(), %s, 1, true, true, 0, 0, 0
                    )
                    """,
                    (f"database-lane-probe-blocked-{marker}",),
                )
                cursor.execute(
                    """
                    SELECT pg_catalog.bool_and(NOT use_public_key)
                      FROM public.core_auth_database
                     WHERE connection_id = ANY(%s)
                    """,
                    ([complete["connection"], failed["connection"], expired["connection"]],),
                )
                if cursor.fetchone() != (True,):
                    raise LaneProbeError(
                        "managed SSH multi-account expansion did not fence credentials"
                    )
                cursor.execute("ROLLBACK TO SAVEPOINT backupsheep_account_fence")
                cursor.execute("RELEASE SAVEPOINT backupsheep_account_fence")
                _set_lane_role(cursor, config, None)

                # The app supplies Django auto_now values, so the database trigger
                # must independently reject time forgery that could pin a stale proof
                # as the newest validation forever. Exercise every temporal edge as
                # the sealed web role, not as the bootstrap fixture owner.
                for label, created_offset, modified_offset, expiry_offset in (
                    ("future created timestamp", 120, 120, 720),
                    ("stale created timestamp", -120, -120, 480),
                    ("created/modified timestamp drift", 0, 5, 600),
                    ("oversized managed operation TTL", 0, 0, 1801),
                ):
                    rejected_operation = _insert_managed_operation(
                        cursor,
                        config,
                        account_id=complete["account"],
                        connection_id=complete["connection"],
                        member_id=complete["member"],
                        user_id=complete["user"],
                        approval_id=complete["approval"],
                        approval_fingerprint=complete["approval_fingerprint"],
                        created_offset_seconds=created_offset,
                        modified_offset_seconds=modified_offset,
                        expires_offset_seconds=expiry_offset,
                        expected_rejection_label=label,
                    )
                    if rejected_operation is not None:  # pragma: no cover - helper invariant
                        raise LaneProbeError(f"{label} returned a managed SSH operation")

                _set_lane_role(cursor, config, "database")
                cursor.execute(
                    """
                    UPDATE public.core_managed_ssh_operation
                       SET status = 'running', lease_token = %s,
                           lease_expires_at = pg_catalog.clock_timestamp() + interval '5 minutes',
                           attempts = attempts + 1,
                           claimed_at = pg_catalog.clock_timestamp(),
                           modified = pg_catalog.clock_timestamp()
                     WHERE id = %s RETURNING id
                    """,
                    (str(uuid.uuid4()), complete["operation"]),
                )
                if cursor.fetchone() != (complete["operation"],):
                    raise LaneProbeError("database could not claim its managed SSH intent")
                cursor.execute(
                    """
                    UPDATE public.core_managed_ssh_operation
                       SET status = 'complete', lease_token = NULL,
                           lease_expires_at = NULL,
                           completed_at = pg_catalog.clock_timestamp(),
                           result_payload = '{"valid":true}'::jsonb,
                           result_digest = %s, error_payload = '{}'::jsonb,
                           execution_witness_digest = %s,
                           modified = pg_catalog.clock_timestamp()
                     WHERE id = %s RETURNING id
                    """,
                    ("e" * 64, "f" * 64, complete["operation"]),
                )
                if cursor.fetchone() != (complete["operation"],):
                    raise LaneProbeError("database could not complete its managed SSH intent")
                cursor.execute(
                    """
                    UPDATE public.core_connection
                       SET status = 1, modified = pg_catalog.clock_timestamp()
                     WHERE id = %s RETURNING status
                    """,
                    (complete["connection"],),
                )
                if cursor.fetchone() != (1,):
                    raise LaneProbeError("validated managed SSH connection did not activate")

                for fixture, status in ((failed, "failed"), (expired, "expired")):
                    cursor.execute(
                        """
                        UPDATE public.core_managed_ssh_operation
                           SET status = %s,
                               completed_at = pg_catalog.clock_timestamp(),
                               error_payload = '{"code":"PROBE"}'::jsonb,
                               execution_witness_digest = %s,
                               modified = pg_catalog.clock_timestamp()
                         WHERE id = %s RETURNING status
                        """,
                        (status, ("1" if status == "failed" else "2") * 64, fixture["operation"]),
                    )
                    if cursor.fetchone() != (status,):
                        raise LaneProbeError(
                            f"database could not record managed SSH {status}"
                        )

                cursor.execute(
                    """
                    SELECT managed_ssh_generation
                      FROM public.core_connection
                     WHERE id = %s
                    """,
                    (complete["connection"],),
                )
                generation = int(cursor.fetchone()[0])
                cursor.execute(
                    """
                    UPDATE public.core_auth_database
                       SET type = type, version = 'postgres_17',
                           modified = pg_catalog.clock_timestamp()
                     WHERE connection_id = %s
                     RETURNING version
                    """,
                    (complete["connection"],),
                )
                if cursor.fetchone() != ("postgres_17",):
                    raise LaneProbeError("database update_metadata columns were denied")
                cursor.execute(
                    """
                    SELECT managed_ssh_generation, status
                      FROM public.core_connection
                     WHERE id = %s
                    """,
                    (complete["connection"],),
                )
                if cursor.fetchone() != (generation, 1):
                    raise LaneProbeError("metadata update incorrectly fenced validation")

                # The web control plane can observe and publish a proof but cannot
                # erase it directly. Parent deletion is tested below through the
                # explicit database-owned FK cascade.
                _set_lane_role(cursor, config, "app")
                _expect_cursor_denied(
                    cursor,
                    "DELETE FROM public.core_managed_ssh_operation WHERE id = %s",
                    (complete["operation"],),
                    label="app direct managed SSH proof erasure",
                )
                _expect_cursor_denied(
                    cursor,
                    "DELETE FROM public.core_ssh_host_key_approval WHERE id = %s",
                    (complete["approval"],),
                    label="app direct SSH approval erasure",
                )

                cursor.execute(
                    """
                    SELECT action, generation
                      FROM public.core_ssh_host_key_approval_event
                     WHERE approval_pk_snapshot = %s
                     ORDER BY generation, action
                    """,
                    (complete["approval"],),
                )
                if cursor.fetchall() != [("approve", 1)]:
                    raise LaneProbeError("app could not read managed SSH trust history")
                _expect_cursor_denied(
                    cursor,
                    """
                    INSERT INTO public.core_ssh_host_key_approval_event (
                        created, modified, approval_pk_snapshot,
                        account_pk_snapshot, normalized_host, port, generation,
                        action, old_wire_key_type, new_wire_key_type,
                        old_public_key_base64, new_public_key_base64,
                        old_fingerprint, new_fingerprint,
                        old_negotiated_host_key_algorithm,
                        new_negotiated_host_key_algorithm, old_bits, new_bits,
                        actor_kind, actor_member_pk_snapshot,
                        actor_user_pk_snapshot
                    ) SELECT
                        created, modified, approval_pk_snapshot,
                        account_pk_snapshot, normalized_host, port, generation,
                        action, old_wire_key_type, new_wire_key_type,
                        old_public_key_base64, new_public_key_base64,
                        old_fingerprint, new_fingerprint,
                        old_negotiated_host_key_algorithm,
                        new_negotiated_host_key_algorithm, old_bits, new_bits,
                        actor_kind, actor_member_pk_snapshot,
                        actor_user_pk_snapshot
                      FROM public.core_ssh_host_key_approval_event
                     WHERE approval_pk_snapshot = %s
                    """,
                    (complete["approval"],),
                    label="app trust-history insert",
                )
                _expect_cursor_denied(
                    cursor,
                    "UPDATE public.core_ssh_host_key_approval_event "
                    "SET action = action WHERE false",
                    label="app trust-history rewrite",
                )
                _expect_cursor_denied(
                    cursor,
                    "DELETE FROM public.core_ssh_host_key_approval_event WHERE false",
                    label="app trust-history deletion",
                )

                # A source-auth change advances the generation and fences the
                # connection pending. Direct generation rollback, account transfer,
                # integration transfer, and activation from the old proof all fail.
                rotated_host = f"rotated-{marker}.example.invalid"
                cursor.execute(
                    """
                    UPDATE public.core_auth_database
                       SET ssh_host = %s, modified = pg_catalog.clock_timestamp()
                     WHERE connection_id = %s
                    """,
                    (rotated_host, complete["connection"]),
                )
                cursor.execute(
                    """
                    SELECT managed_ssh_generation, status
                      FROM public.core_connection WHERE id = %s
                    """,
                    (complete["connection"],),
                )
                if cursor.fetchone() != (generation + 1, 2):
                    raise LaneProbeError("managed SSH auth change did not fence validation")
                _expect_cursor_rejected(
                    cursor,
                    "UPDATE public.core_connection SET managed_ssh_generation = %s "
                    "WHERE id = %s",
                    (generation, complete["connection"]),
                    label="app managed SSH generation rollback",
                )
                _expect_cursor_rejected(
                    cursor,
                    "UPDATE public.core_connection SET account_id = %s WHERE id = %s",
                    (complete["account"] + 1_000_000_000, complete["connection"]),
                    label="app managed SSH account transfer",
                )
                _expect_cursor_rejected(
                    cursor,
                    "UPDATE public.core_connection SET integration_id = %s WHERE id = %s",
                    (_integration_id(cursor, "website"), complete["connection"]),
                    label="app managed SSH integration transfer",
                )
                _expect_cursor_rejected(
                    cursor,
                    "UPDATE public.core_connection SET status = 1 WHERE id = %s",
                    (complete["connection"],),
                    label="app reactivation from stale managed SSH proof",
                )

                # Retention is a separately reviewed SECURITY DEFINER operation.
                # The worker's table identity can never erase either a pending or
                # completed proof directly, even inside its own source lane.
                _set_lane_role(cursor, config, None)
                pending = _managed_probe_fixture(
                    cursor, config, marker + "d", actor=primary_actor
                )
                _set_lane_role(cursor, config, "database")
                _expect_cursor_denied(
                    cursor,
                    "DELETE FROM public.core_managed_ssh_operation WHERE id = %s",
                    (pending["operation"],),
                    label="database pending managed SSH proof erasure",
                )
                _expect_cursor_denied(
                    cursor,
                    "DELETE FROM public.core_managed_ssh_operation WHERE id = %s",
                    (complete["operation"],),
                    label="database completed managed SSH proof erasure",
                )

                _set_lane_role(cursor, config, "files")
                cursor.execute(
                    "SELECT id FROM public.core_managed_ssh_operation WHERE id = %s",
                    (failed["operation"],),
                )
                if cursor.fetchone() is not None:
                    raise LaneProbeError("files observed a database managed SSH intent")
                cursor.execute(
                    "SELECT id FROM public.core_ssh_host_key_approval WHERE id = %s",
                    (failed["approval"],),
                )
                if cursor.fetchone() is not None:
                    raise LaneProbeError("files observed a database host-key approval")

                # Snapshot actor fields are deliberately non-FKs. Removing a member
                # must not strand or silently erase its durable operation witness.
                _set_lane_role(cursor, config, "app")
                cursor.execute(
                    "DELETE FROM public.core_member_mtm_account WHERE member_id = %s",
                    (failed["member"],),
                )
                cursor.execute(
                    "DELETE FROM public.core_member WHERE id = %s RETURNING id",
                    (failed["member"],),
                )
                if cursor.fetchone() != (failed["member"],):
                    raise LaneProbeError("app could not delete a managed-operation actor")
                cursor.execute(
                    "SELECT requested_by_member_pk_snapshot FROM public.core_managed_ssh_operation WHERE id = %s",
                    (failed["operation"],),
                )
                if cursor.fetchone() != (failed["member"],):
                    raise LaneProbeError("member deletion erased the audit snapshot")

                # Mirror Collector for ordinary children, deliberately omitting
                # CoreManagedSSHOperation (its model uses DO_NOTHING). PostgreSQL's
                # reviewed ON DELETE CASCADE must remove that child without a direct
                # app DELETE capability.
                for fixture in (complete, failed, expired, pending):
                    cursor.execute(
                        "DELETE FROM public.core_auth_database WHERE connection_id = %s",
                        (fixture["connection"],),
                    )
                    cursor.execute(
                        "DELETE FROM public.core_connection WHERE id = %s RETURNING id",
                        (fixture["connection"],),
                    )
                    if cursor.fetchone() != (fixture["connection"],):
                        raise LaneProbeError("app could not delete a managed SSH connection")
                    cursor.execute(
                        "SELECT id FROM public.core_managed_ssh_operation "
                        "WHERE connection_id = %s",
                        (fixture["connection"],),
                    )
                    if cursor.fetchone() is not None:
                        raise LaneProbeError(
                            "database FK cascade did not remove managed SSH proof"
                        )
                    cursor.execute(
                        "SELECT id FROM public.core_ssh_host_key_approval WHERE id = %s",
                        (fixture["approval"],),
                    )
                    if cursor.fetchone() != (fixture["approval"],):
                        raise LaneProbeError(
                            "connection deletion erased an account-scoped SSH approval"
                        )

                cursor.execute(
                    "DELETE FROM public.core_account WHERE id = %s RETURNING id",
                    (primary_actor[0],),
                )
                if cursor.fetchone() != (primary_actor[0],):
                    raise LaneProbeError("app could not delete a managed SSH account")
                cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
                cursor.execute("SET CONSTRAINTS ALL DEFERRED")
                for fixture in (complete, failed, expired, pending):
                    cursor.execute(
                        """
                        SELECT action FROM public.core_ssh_host_key_approval_event
                         WHERE approval_pk_snapshot = %s
                         ORDER BY generation DESC LIMIT 1
                        """,
                        (fixture["approval"],),
                    )
                    if cursor.fetchone() != ("revoke",):
                        raise LaneProbeError(
                            "account deletion erased SSH approval audit history"
                        )

                _set_lane_role(cursor, config, None)
        finally:
            connection.rollback()


def _assert_direct_ssh_approval_visibility(config: IdentityConfiguration) -> None:
    """Prove ordinary private/password SSH does not depend on managed intents."""

    with closing(
        _connect(config, user=config.bootstrap_user, password=config.bootstrap_password)
    ) as connection:
        try:
            with connection.cursor() as cursor:
                marker = uuid.uuid4().hex[:20]
                account_id, member_id, user_id = _insert_probe_actor(cursor, marker)
                database_connection = _insert_probe_connection(
                    cursor,
                    account_id=account_id,
                    integration_id=_integration_id(cursor, "database"),
                    marker=marker + "db",
                )
                database_host = f"{marker}-database.example.invalid"
                _insert_database_auth(
                    cursor,
                    connection_id=database_connection,
                    host=database_host,
                    use_public_key=False,
                    use_private_key=True,
                )
                database_approval = _insert_host_key_approval(
                    cursor,
                    config,
                    account_id=account_id,
                    member_id=member_id,
                    user_id=user_id,
                    host=database_host,
                    fingerprint=_probe_ssh_fingerprint(marker + "db"),
                )

                website_approvals = []
                website_connections = []
                for suffix, use_private_key in (("password", False), ("private", True)):
                    website_connection = _insert_probe_connection(
                        cursor,
                        account_id=account_id,
                        integration_id=_integration_id(cursor, "website"),
                        marker=marker + suffix,
                    )
                    website_host = f"{marker}-{suffix}.example.invalid"
                    _insert_website_auth(
                        cursor,
                        connection_id=website_connection,
                        host=website_host,
                        use_private_key=use_private_key,
                    )
                    website_approval = _insert_host_key_approval(
                        cursor,
                        config,
                        account_id=account_id,
                        member_id=member_id,
                        user_id=user_id,
                        host=website_host,
                        fingerprint=_probe_ssh_fingerprint(marker + suffix),
                    )
                    website_connections.append(website_connection)
                    website_approvals.append(website_approval)

                all_approvals = [database_approval, *website_approvals]
                _set_lane_role(cursor, config, "database")
                cursor.execute(
                    """
                    SELECT id FROM public.core_ssh_host_key_approval
                     WHERE id = ANY(%s) ORDER BY id
                    """,
                    (all_approvals,),
                )
                if [int(row[0]) for row in cursor.fetchall()] != [database_approval]:
                    raise LaneProbeError(
                        "database private-key approval visibility crossed its lane"
                    )

                _set_lane_role(cursor, config, "files")
                cursor.execute(
                    """
                    SELECT id FROM public.core_ssh_host_key_approval
                     WHERE id = ANY(%s) ORDER BY id
                    """,
                    (all_approvals,),
                )
                if [int(row[0]) for row in cursor.fetchall()] != sorted(
                    website_approvals
                ):
                    raise LaneProbeError(
                        "SFTP password/private-key approval visibility crossed its lane"
                    )

                # The web role has no directly forgeable approval DELETE. This
                # bootstrap-owned transaction uses SET ROLE only for row-policy and
                # cascade coverage; it must never be accepted as an authenticated app
                # login by the SECURITY DEFINER revoke routine. run_probe separately
                # exercises that routine through the real app connection.
                _set_lane_role(cursor, config, "app")
                _expect_cursor_denied(
                    cursor,
                    "DELETE FROM public.core_ssh_host_key_approval WHERE id = %s",
                    (all_approvals[0],),
                    label="app direct SSH approval erasure",
                )
                cursor.execute(
                    "DELETE FROM public.core_auth_database WHERE connection_id = %s",
                    (database_connection,),
                )
                cursor.execute(
                    "DELETE FROM public.core_auth_website WHERE connection_id = ANY(%s)",
                    (website_connections,),
                )
                for connection_id in [database_connection, *website_connections]:
                    cursor.execute(
                        "DELETE FROM public.core_connection WHERE id = %s RETURNING id",
                        (connection_id,),
                    )
                    if cursor.fetchone() != (connection_id,):
                        raise LaneProbeError("app could not delete an SSH connection")
                cursor.execute(
                    "DELETE FROM public.core_member_mtm_account WHERE account_id = %s",
                    (account_id,),
                )
                cursor.execute(
                    "DELETE FROM public.core_account WHERE id = %s RETURNING id",
                    (account_id,),
                )
                if cursor.fetchone() != (account_id,):
                    raise LaneProbeError("app could not delete an SSH account")
                cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
                cursor.execute(
                    """
                    SELECT pg_catalog.count(*)
                      FROM public.core_ssh_host_key_approval_event
                     WHERE approval_pk_snapshot = ANY(%s)
                       AND action = 'revoke'
                       AND actor_kind = 'system'
                       AND actor_member_pk_snapshot IS NULL
                       AND actor_user_pk_snapshot IS NULL
                    """,
                    (all_approvals,),
                )
                if int(cursor.fetchone()[0]) != len(all_approvals):
                    raise LaneProbeError(
                        "SSH approval account cascade forged or lost system identity"
                    )
                _set_lane_role(cursor, config, None)
        finally:
            connection.rollback()


def run_probe(config: IdentityConfiguration) -> None:
    connections = {}
    try:
        for lane in LANES:
            connection = _connect(
                config,
                user=config.lane_users[lane],
                password=config.lane_passwords[lane],
            )
            connections[lane] = connection
            _assert_role_boundary(connection, lane, config.lane_users[lane])

        managed_trigger_routines = sorted(
            MANAGED_SSH_ROUTINES
            - {
                MANAGED_SSH_RETENTION_ROUTINE,
                MANAGED_SSH_REVOKE_APPROVAL_ROUTINE,
                MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE,
            }
        )
        for lane, connection in connections.items():
            for routine_name in managed_trigger_routines:
                identity_arguments, _result = EXPECTED_ROUTINES[routine_name]
                call_arguments = "NULL::text" if identity_arguments else ""
                _expect_denied(
                    connection,
                    f"SELECT public.{routine_name}({call_arguments})",
                    label=f"{lane} direct trigger-function execution {routine_name}",
                )

        for lane, connection in connections.items():
            statement = (
                f"SELECT public.{MANAGED_SSH_RETENTION_ROUTINE}(30, 1)"
            )
            if lane in {"database", "files"}:
                _expect_allowed(
                    connection,
                    statement,
                    label=f"{lane} bounded managed SSH retention",
                )
            else:
                _expect_denied(
                    connection,
                    statement,
                    label=f"{lane} managed SSH retention execution",
                )

        for lane, connection in connections.items():
            statement = (
                f"SELECT public.{MANAGED_SSH_REVOKE_APPROVAL_ROUTINE}("
                "9223372036854775807, 9223372036854775807)"
            )
            if lane == "app":
                _expect_allowed(
                    connection,
                    statement,
                    label="app bounded SSH approval revoke authority",
                )
            else:
                _expect_denied(
                    connection,
                    statement,
                    label=f"{lane} SSH approval revoke execution",
                )

        for lane, connection in connections.items():
            _expect_denied(
                connection,
                f"SELECT * FROM public.{SSH_HOST_KEY_REVOKE_WITNESS_TABLE}",
                label=f"{lane} SSH revoke capability-witness read",
            )
            _expect_denied(
                connection,
                f"INSERT INTO public.{SSH_HOST_KEY_REVOKE_WITNESS_TABLE} "
                "(backend_pid, approval_id, account_id) VALUES (1, 1, 1)",
                label=f"{lane} SSH revoke capability-witness forgery",
            )

        for lane, connection in connections.items():
            statement = f"SELECT public.{MANAGED_SSH_SINGLE_ACCOUNT_ROUTINE}(NULL)"
            if lane in {"app", "database", "files"}:
                _expect_allowed(
                    connection,
                    statement,
                    label=f"{lane} global managed SSH tenant guard",
                )
            else:
                _expect_denied(
                    connection,
                    statement,
                    label=f"{lane} global managed SSH tenant guard execution",
                )

        for lane in ("cloud", "database", "files", "storage", "logs"):
            _expect_denied(
                connections[lane],
                "SELECT id FROM public.django_celery_beat_periodictask LIMIT 1",
                label=f"{lane} Beat read",
            )
            _expect_denied(
                connections[lane],
                "UPDATE public.django_celery_beat_periodictask SET enabled = enabled WHERE false",
                label=f"{lane} Beat mutation",
            )

        for lane, connection in connections.items():
            for table in (
                "django_celery_results_chordcounter",
                "django_celery_results_groupresult",
                "django_celery_results_taskresult",
            ):
                _expect_denied(
                    connection,
                    f"SELECT * FROM public.{table} LIMIT 1",
                    label=f"{lane} legacy Celery result read {table}",
                )
                _expect_denied(
                    connection,
                    f"DELETE FROM public.{table} WHERE false",
                    label=f"{lane} legacy Celery result mutation {table}",
                )

        _expect_allowed(
            connections["beat"],
            "SELECT id FROM public.core_schedule WHERE false FOR UPDATE",
            label="beat durable schedule lock",
        )
        _expect_denied(
            connections["beat"],
            "UPDATE public.core_schedule SET status = status WHERE false",
            label="beat schedule policy mutation",
        )
        _expect_denied(
            connections["beat"],
            "DELETE FROM public.core_backup_request WHERE false",
            label="beat accepted outbox deletion",
        )
        for table in ("auth_user", "core_member", "core_storage"):
            _expect_denied(
                connections["beat"],
                f"SELECT * FROM public.{table} LIMIT 1",
                label=f"beat identity/storage read {table}",
            )

        for lane in ("cloud", "database", "files", "storage"):
            for table in (
                "core_notification_delivery",
                "core_notification_log_email",
                "core_notification_slack",
                "core_notification_telegram",
            ):
                _expect_denied(
                    connections[lane],
                    f"SELECT * FROM public.{table} LIMIT 1",
                    label=f"{lane} notification identity/secret read {table}",
                )
            _expect_denied(
                connections[lane],
                "UPDATE public.core_notification_delivery SET status = status WHERE false",
                label=f"{lane} notification delivery rewrite",
            )

        for table in (
            "auth_user",
            "authtoken_token",
            "django_session",
            "core_auth_aws",
            "core_auth_database",
            "core_auth_website",
            "core_notification_slack",
            "core_site_settings",
            "core_cloud_restore",
        ):
            _expect_denied(
                connections["storage"],
                f"SELECT * FROM public.{table} LIMIT 1",
                label=f"storage read {table}",
            )

        for table in (
            "core_database_backup",
            "core_database_restore",
            "core_website_backup",
            "core_website_restore",
        ):
            _expect_denied(
                connections["cloud"],
                f"SELECT * FROM public.{table} LIMIT 1",
                label=f"cloud cross-lane read {table}",
            )
        _expect_allowed(
            connections["cloud"],
            "UPDATE public.core_auth_digitalocean "
            "SET info_uuid = info_uuid, info_name = info_name, "
            "info_email = info_email, modified = modified WHERE false",
            label="cloud DigitalOcean ownership-witness update",
        )
        _expect_denied(
            connections["cloud"],
            "UPDATE public.core_auth_digitalocean "
            "SET access_token = access_token WHERE false",
            label="cloud DigitalOcean credential rewrite",
        )
        _expect_allowed(
            connections["cloud"],
            "UPDATE public.core_auth_upcloud "
            "SET username = username, modified = modified WHERE false",
            label="cloud UpCloud ownership-witness update",
        )
        _expect_denied(
            connections["cloud"],
            "UPDATE public.core_auth_upcloud SET password = password WHERE false",
            label="cloud UpCloud credential rewrite",
        )
        for table in (
            "core_auth_aws",
            "core_auth_google_cloud",
            "core_auth_hetzner",
            "core_auth_lightsail",
            "core_auth_oracle",
            "core_auth_vultr",
        ):
            _expect_denied(
                connections["cloud"],
                f"UPDATE public.{table} SET modified = modified WHERE false",
                label=f"cloud provider-auth rewrite {table}",
            )
            _expect_denied(
                connections["cloud"],
                f"DELETE FROM public.{table} WHERE false",
                label=f"cloud provider-auth delete {table}",
            )
        _expect_denied(
            connections["database"],
            "SELECT * FROM public.core_website_backup LIMIT 1",
            label="database read files backup",
        )
        _expect_denied(
            connections["files"],
            "SELECT * FROM public.core_database_backup LIMIT 1",
            label="files read database backup",
        )
        for lane in ("database", "files"):
            for table in sorted(STORAGE_CONFIG_TABLES):
                _expect_denied(
                    connections[lane],
                    f"SELECT * FROM public.{table} LIMIT 1",
                    label=f"{lane} destination credential read {table}",
                )
        for lane, tables in (
            ("database", ("core_database_backup_mtm_storage_points",)),
            (
                "files",
                (
                    "core_basecamp_backup_mtm_storage_points",
                    "core_website_backup_mtm_storage_points",
                ),
            ),
        ):
            for table in tables:
                _expect_denied(
                    connections[lane],
                    f"UPDATE public.{table} SET metadata = metadata WHERE false",
                    label=f"{lane} destination authorization rewrite {table}",
                )
                _expect_denied(
                    connections[lane],
                    f"DELETE FROM public.{table} WHERE false",
                    label=f"{lane} destination authorization delete {table}",
                )
        for lane, connection in connections.items():
            for table in sorted(RETIRED_TABLES):
                _expect_denied(
                    connection,
                    f"SELECT * FROM public.{table} LIMIT 1",
                    label=f"{lane} retired table read {table}",
                )
        _expect_denied(
            connections["app"],
            "SELECT * FROM public.backupsheep_celery_task_replay LIMIT 1",
            label="app replay read",
        )

        for lane in ("database", "files"):
            _expect_allowed(
                connections[lane],
                "UPDATE public.core_managed_ssh_operation SET status = status, modified = modified WHERE false",
                label=f"{lane} managed result update",
            )
            _expect_denied(
                connections[lane],
                "UPDATE public.core_managed_ssh_operation SET intent_digest = intent_digest WHERE false",
                label=f"{lane} managed intent rewrite",
            )
            _expect_allowed(
                connections[lane],
                "UPDATE public.core_connection SET status = status, modified = modified WHERE false",
                label=f"{lane} connection status update",
            )
            _expect_denied(
                connections[lane],
                "UPDATE public.core_connection SET managed_ssh_generation = managed_ssh_generation WHERE false",
                label=f"{lane} managed generation rewrite",
            )
            _expect_denied(
                connections[lane],
                "UPDATE public.core_connection SET name = name WHERE false",
                label=f"{lane} connection identity rewrite",
            )

        _expect_allowed(
            connections["database"],
            "UPDATE public.core_auth_database SET type = type, version = version, modified = modified WHERE false",
            label="database metadata update",
        )
        _expect_denied(
            connections["database"],
            "UPDATE public.core_auth_database SET host = host WHERE false",
            label="database credential rewrite",
        )
        _expect_denied(
            connections["files"],
            "SELECT * FROM public.core_auth_database LIMIT 1",
            label="files read database credentials",
        )

        for lane in ("cloud", "database", "files", "storage", "logs"):
            _expect_allowed(
                connections[lane],
                _replay_insert(lane, f"own-{lane}"),
                label=f"{lane} own replay insert",
            )
            foreign_lane = "files" if lane != "files" else "database"
            _expect_denied(
                connections[lane],
                _replay_insert(foreign_lane, f"foreign-{lane}"),
                label=f"{lane} foreign replay insert",
            )

        _assert_replay_row_isolation(config)
        _assert_artifact_row_isolation(config)
        _assert_source_log_boundary(config)
        _assert_shared_node_row_isolation(config)
        _assert_direct_ssh_approval_visibility(config)
        _assert_managed_ssh_row_isolation(config)
    finally:
        for connection in connections.values():
            connection.close()


def main() -> int:
    try:
        config = IdentityConfiguration.from_environment()
        run_probe(config)
    except (ProvisioningError, LaneProbeError, psycopg2.Error):
        print(
            "BackupSheep database lane adversarial probe failed closed.",
            file=sys.stderr,
        )
        return 1
    print(
        "BackupSheep database lane adversarial probe passed: "
        "cross-lane reads/rows, DDL/TEMP, scheduler/result mutation, replay "
        "crossover, artifact/key-wrap isolation, append-only source logs, "
        "provider credential immutability, "
        "destination credentials/witnesses, managed-SSH lifecycle/retention, "
        "SSH approval visibility/revoke authority, timestamp/TTL forgery, trigger EXECUTE, "
        "and parent cascades passed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
