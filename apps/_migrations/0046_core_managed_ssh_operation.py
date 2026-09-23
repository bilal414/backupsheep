import ipaddress
import re
import uuid

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models
import model_utils.fields


def _canonical_ssh_host(value):
    raw = str(value or "").strip()
    if not raw or len(raw) > 255 or any(ord(character) < 32 for character in raw):
        raise ValueError("invalid SSH host")
    candidate = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    if "%" in candidate:
        raise ValueError("invalid SSH host")
    try:
        parsed_ip = ipaddress.ip_address(candidate)
        if isinstance(parsed_ip, ipaddress.IPv6Address) and (
            parsed_ip.ipv4_mapped is not None
            or (
                parsed_ip in ipaddress.IPv6Network("::/96")
                and parsed_ip not in (ipaddress.IPv6Address("::"), ipaddress.IPv6Address("::1"))
            )
        ):
            raise ValueError("unsupported IPv4-embedded IPv6 host")
        normalized_ip = parsed_ip.compressed.lower()
        if all(character in "0123456789." for character in candidate) and (
            candidate != normalized_ip
        ):
            raise ValueError("noncanonical IPv4 host")
        return normalized_ip
    except ValueError:
        if ":" in candidate or all(
            character in "0123456789." for character in candidate
        ):
            raise ValueError("invalid SSH host") from None
        normalized = candidate.rstrip(".").encode("idna").decode("ascii").lower()
        if (
            not normalized
            or len(normalized) > 253
            or any(
                not 1 <= len(label) <= 63
                or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                is None
                for label in normalized.split(".")
            )
        ):
            raise ValueError("invalid SSH host")
        return normalized


def canonicalize_existing_ssh_hosts(apps, schema_editor):
    database_auth = apps.get_model("apps", "CoreAuthDatabase")
    website_auth = apps.get_model("apps", "CoreAuthWebsite")
    for auth in database_auth.objects.filter(
        models.Q(use_public_key=True) | models.Q(use_private_key=True)
    ).only("pk", "ssh_host"):
        try:
            normalized = _canonical_ssh_host(auth.ssh_host)
        except (TypeError, ValueError, UnicodeError) as error:
            raise RuntimeError(
                f"CoreAuthDatabase {auth.pk} has an invalid SSH host"
            ) from error
        if auth.ssh_host != normalized:
            database_auth.objects.filter(pk=auth.pk).update(ssh_host=normalized)
    for auth in website_auth.objects.filter(protocol=2).only("pk", "host"):
        try:
            normalized = _canonical_ssh_host(auth.host)
        except (TypeError, ValueError, UnicodeError) as error:
            raise RuntimeError(
                f"CoreAuthWebsite {auth.pk} has an invalid SSH host"
            ) from error
        if auth.host != normalized:
            website_auth.objects.filter(pk=auth.pk).update(host=normalized)


MANAGED_SSH_FENCE_SQL = r"""
CREATE FUNCTION backupsheep_is_canonical_ssh_host(candidate text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $$
DECLARE
    label text;
    parsed inet;
BEGIN
    IF candidate IS NULL
       OR length(candidate) < 1
       OR length(candidate) > 255
       OR candidate <> lower(candidate)
       OR candidate <> btrim(candidate)
       OR candidate <> rtrim(candidate, '.')
       OR candidate !~ '^[a-z0-9.:-]+$' THEN
        RETURN FALSE;
    END IF;
    IF position(':' in candidate) > 0 OR candidate ~ '^[0-9.]+$' THEN
        BEGIN
            parsed := candidate::inet;
        EXCEPTION WHEN OTHERS THEN
            RETURN FALSE;
        END;
        IF family(parsed) = 6
           AND (
               parsed <<= '::ffff:0:0/96'::inet
               OR (parsed <<= '::/96'::inet AND candidate NOT IN ('::', '::1'))
           ) THEN
            RETURN FALSE;
        END IF;
        RETURN host(parsed) = candidate
           AND ((position(':' in candidate) > 0 AND family(parsed) = 6)
             OR (position(':' in candidate) = 0 AND family(parsed) = 4));
    END IF;
    IF length(candidate) > 253 THEN
        RETURN FALSE;
    END IF;
    FOREACH label IN ARRAY string_to_array(candidate, '.') LOOP
        IF length(label) < 1
           OR length(label) > 63
           OR (
               label !~ '^[a-z0-9][a-z0-9-]*[a-z0-9]$'
               AND label !~ '^[a-z0-9]$'
           ) THEN
            RETURN FALSE;
        END IF;
    END LOOP;
    RETURN TRUE;
END;
$$;

-- This table is an internal, transaction-scoped capability witness shared only
-- by the SECURITY DEFINER revoke routine and delete audit trigger. Runtime roles
-- receive no privileges on it, so an app-session caller cannot turn an account
-- cascade or a direct DELETE into a forged application-attributed event.
CREATE TABLE backupsheep_ssh_host_key_revoke_witness (
    backend_pid integer NOT NULL,
    approval_id bigint NOT NULL,
    account_id bigint NOT NULL,
    PRIMARY KEY (backend_pid, approval_id, account_id)
);
REVOKE ALL ON TABLE backupsheep_ssh_host_key_revoke_witness FROM PUBLIC;

-- Existing managed-key connections predate the generation latch. Fence them
-- pending so no backup can run until a generation-bound worker validation wins.
UPDATE core_connection AS connection
   SET managed_ssh_generation = 1,
       status = 2,
       modified = clock_timestamp()
 WHERE EXISTS (
           SELECT 1
             FROM core_auth_database AS auth
            WHERE auth.connection_id = connection.id
              AND COALESCE(auth.use_public_key, FALSE)
       )
    OR EXISTS (
           SELECT 1
             FROM core_auth_website AS auth
            WHERE auth.connection_id = connection.id
              AND COALESCE(auth.use_public_key, FALSE)
       );

-- The legacy shared known_hosts file has no tenant ownership witness. Every SSH
-- source must be re-approved into the account-scoped ledger before it is active.
UPDATE core_connection AS connection
   SET status = 2,
       modified = clock_timestamp()
 WHERE EXISTS (
           SELECT 1
             FROM core_auth_database AS auth
            WHERE auth.connection_id = connection.id
              AND (
                  COALESCE(auth.use_public_key, FALSE)
                  OR COALESCE(auth.use_private_key, FALSE)
              )
       )
    OR EXISTS (
           SELECT 1
             FROM core_auth_website AS auth
            WHERE auth.connection_id = connection.id
              AND auth.protocol = 2
       );

CREATE FUNCTION backupsheep_managed_ssh_auth_generation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    relevant_change boolean := FALSE;
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(3141592653589793) THEN
        RAISE EXCEPTION 'managed SSH mutation lock ordering violation'
            USING ERRCODE = 'serialization_failure';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.connection_id IS DISTINCT FROM OLD.connection_id THEN
        RAISE EXCEPTION 'managed SSH authentication ownership is immutable'
            USING ERRCODE = 'check_violation';
    END IF;

    IF TG_TABLE_NAME = 'core_auth_database' THEN
        IF COALESCE(NEW.use_public_key, FALSE)
           AND (SELECT count(*) FROM public.core_account) <> 1 THEN
            RAISE EXCEPTION 'managed SSH authentication requires exactly one account'
                USING ERRCODE = 'check_violation';
        END IF;
        IF (COALESCE(NEW.use_public_key, FALSE) OR COALESCE(NEW.use_private_key, FALSE))
           AND NOT backupsheep_is_canonical_ssh_host(NEW.ssh_host) THEN
            RAISE EXCEPTION 'database SSH host must be canonical'
                USING ERRCODE = 'check_violation';
        END IF;
        relevant_change := (
            TG_OP = 'INSERT'
            AND COALESCE(NEW.use_public_key, FALSE)
        ) OR (
            TG_OP = 'UPDATE'
            AND (COALESCE(OLD.use_public_key, FALSE) OR COALESCE(NEW.use_public_key, FALSE))
            AND ROW(
                NEW.host, NEW.port, NEW.database_name, NEW.all_databases,
                NEW.username, NEW.password, NEW.include_stored_procedure,
                NEW.use_ssl, NEW.ssh_host, NEW.ssh_port, NEW.ssh_username,
                NEW.ssh_password, NEW.private_key, NEW.use_public_key,
                NEW.use_private_key, NEW.flag_use_sha1_key_verification
            ) IS DISTINCT FROM ROW(
                OLD.host, OLD.port, OLD.database_name, OLD.all_databases,
                OLD.username, OLD.password, OLD.include_stored_procedure,
                OLD.use_ssl, OLD.ssh_host, OLD.ssh_port, OLD.ssh_username,
                OLD.ssh_password, OLD.private_key, OLD.use_public_key,
                OLD.use_private_key, OLD.flag_use_sha1_key_verification
            )
        );
    ELSIF TG_TABLE_NAME = 'core_auth_website' THEN
        IF COALESCE(NEW.use_public_key, FALSE)
           AND (SELECT count(*) FROM public.core_account) <> 1 THEN
            RAISE EXCEPTION 'managed SSH authentication requires exactly one account'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.protocol = 2
           AND NOT backupsheep_is_canonical_ssh_host(NEW.host) THEN
            RAISE EXCEPTION 'website SSH host must be canonical'
                USING ERRCODE = 'check_violation';
        END IF;
        relevant_change := (
            TG_OP = 'INSERT'
            AND COALESCE(NEW.use_public_key, FALSE)
        ) OR (
            TG_OP = 'UPDATE'
            AND (COALESCE(OLD.use_public_key, FALSE) OR COALESCE(NEW.use_public_key, FALSE))
            AND ROW(
                NEW.host, NEW.port, NEW.protocol, NEW.username, NEW.password,
                NEW.private_key, NEW.use_public_key, NEW.use_private_key,
                NEW.ftps_use_explicit_ssl, NEW.verify_ssl,
                NEW.flag_use_sha1_key_verification
            ) IS DISTINCT FROM ROW(
                OLD.host, OLD.port, OLD.protocol, OLD.username, OLD.password,
                OLD.private_key, OLD.use_public_key, OLD.use_private_key,
                OLD.ftps_use_explicit_ssl, OLD.verify_ssl,
                OLD.flag_use_sha1_key_verification
            )
        );
    ELSE
        RAISE EXCEPTION 'unexpected managed SSH authentication table'
            USING ERRCODE = 'check_violation';
    END IF;

    IF relevant_change THEN
        UPDATE public.core_connection
           SET managed_ssh_generation = managed_ssh_generation + 1,
               status = 2,
               modified = clock_timestamp()
         WHERE id = NEW.connection_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'managed SSH connection is missing'
                USING ERRCODE = 'foreign_key_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION backupsheep_managed_ssh_operation_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    current_account_id bigint;
    current_generation bigint;
    integration_code varchar(64);
    managed_key_enabled boolean;
    actor_user_id bigint;
    approval_account_id bigint;
    approval_generation bigint;
    approval_fingerprint varchar(128);
    approval_algorithm varchar(64);
    approval_host varchar(255);
    approval_port integer;
    connection_ssh_host varchar(255);
    connection_ssh_port integer;
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(3141592653589793) THEN
        RAISE EXCEPTION 'managed SSH mutation lock ordering violation'
            USING ERRCODE = 'serialization_failure';
    END IF;
    IF (SELECT count(*) FROM public.core_account) <> 1 THEN
        RAISE EXCEPTION 'managed SSH operation requires exactly one account'
            USING ERRCODE = 'check_violation';
    END IF;
    SELECT connection.account_id,
           connection.managed_ssh_generation,
           integration.code,
           CASE integration.code
             WHEN 'database' THEN COALESCE(database_auth.use_public_key, FALSE)
             WHEN 'website' THEN COALESCE(website_auth.use_public_key, FALSE)
             ELSE FALSE
           END,
           CASE integration.code
             WHEN 'database' THEN database_auth.ssh_host
             WHEN 'website' THEN website_auth.host
           END,
           CASE integration.code
             WHEN 'database' THEN database_auth.ssh_port
             WHEN 'website' THEN website_auth.port
           END
      INTO current_account_id,
           current_generation,
           integration_code,
           managed_key_enabled,
           connection_ssh_host,
           connection_ssh_port
      FROM public.core_connection AS connection
      JOIN public.core_integration AS integration
        ON integration.id = connection.integration_id
 LEFT JOIN public.core_auth_database AS database_auth
        ON database_auth.connection_id = connection.id
 LEFT JOIN public.core_auth_website AS website_auth
        ON website_auth.connection_id = connection.id
     WHERE connection.id = NEW.connection_id;

    IF NOT FOUND
       OR NEW.account_id IS DISTINCT FROM current_account_id
       OR NEW.connection_generation IS DISTINCT FROM current_generation
       OR NOT managed_key_enabled
       OR (integration_code = 'database' AND NEW.source_lane <> 'database')
       OR (integration_code = 'website' AND NEW.source_lane <> 'files')
       OR integration_code NOT IN ('database', 'website') THEN
        RAISE EXCEPTION 'managed SSH operation binding is invalid'
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT approval.account_id,
           approval.generation,
           approval.fingerprint,
           approval.negotiated_host_key_algorithm,
           approval.normalized_host,
           approval.port
      INTO approval_account_id,
           approval_generation,
           approval_fingerprint,
           approval_algorithm,
           approval_host,
           approval_port
      FROM public.core_ssh_host_key_approval AS approval
     WHERE approval.id = NEW.host_key_approval_pk_snapshot;
    IF NOT FOUND
       OR approval_account_id IS DISTINCT FROM NEW.account_id
       OR approval_generation IS DISTINCT FROM NEW.host_key_approval_generation
       OR approval_fingerprint IS DISTINCT FROM NEW.host_key_fingerprint
       OR approval_algorithm IS DISTINCT FROM NEW.host_key_negotiated_algorithm
       OR approval_host IS DISTINCT FROM connection_ssh_host
       OR approval_port IS DISTINCT FROM connection_ssh_port THEN
        RAISE EXCEPTION 'managed SSH host-key approval binding is invalid'
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT member.user_id
      INTO actor_user_id
      FROM public.core_member AS member
     WHERE member.id = NEW.requested_by_member_pk_snapshot;

    IF NEW.request_actor_kind <> 'member'
       OR NOT FOUND
       OR NEW.requested_by_user_pk_snapshot IS DISTINCT FROM actor_user_id
       OR NEW.requested_by_member_pk_snapshot < 1
       OR NEW.requested_by_user_pk_snapshot < 1
       OR abs(extract(epoch FROM (NEW.created - clock_timestamp()))) > 60
       OR abs(extract(epoch FROM (NEW.modified - NEW.created))) > 1
       OR NEW.expires_at <= NEW.created
       OR NEW.expires_at > NEW.created + interval '1800 seconds'
       OR NOT EXISTS (
           SELECT 1
             FROM public.core_member_mtm_account AS membership
            WHERE membership.member_id = NEW.requested_by_member_pk_snapshot
              AND membership.account_id = NEW.account_id
              AND membership.status = 1
       )
       OR NEW.status <> 'pending'
       OR NEW.attempts <> 0
       OR NEW.lease_token IS NOT NULL
       OR NEW.lease_expires_at IS NOT NULL
       OR NEW.claimed_at IS NOT NULL
       OR NEW.completed_at IS NOT NULL
       OR NEW.result_payload <> '{}'::jsonb
       OR NEW.result_digest <> ''
       OR NEW.error_payload <> '{}'::jsonb
       OR NEW.execution_witness_digest <> ''
       OR NEW.publish_attempts <> 0
       OR NEW.last_publish_attempt_at IS NOT NULL
       OR NEW.published_at IS NOT NULL
       OR NEW.publish_error_code <> '' THEN
        RAISE EXCEPTION 'managed SSH operation must begin as pristine pending intent'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION backupsheep_managed_ssh_operation_update_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        NEW.uuid, NEW.connection_id, NEW.account_id,
        NEW.requested_by_member_pk_snapshot, NEW.requested_by_user_pk_snapshot,
        NEW.request_actor_kind, NEW.request_source,
        NEW.source_lane, NEW.operation, NEW.requested_path,
        NEW.managed_public_key_fingerprint, NEW.connection_config_digest,
        NEW.connection_generation, NEW.host_key_approval_pk_snapshot,
        NEW.host_key_approval_generation, NEW.host_key_fingerprint,
        NEW.host_key_negotiated_algorithm, NEW.celery_task_id, NEW.idempotency_key,
        NEW.intent_digest, NEW.expires_at, NEW.created
    ) IS DISTINCT FROM ROW(
        OLD.uuid, OLD.connection_id, OLD.account_id,
        OLD.requested_by_member_pk_snapshot, OLD.requested_by_user_pk_snapshot,
        OLD.request_actor_kind, OLD.request_source,
        OLD.source_lane, OLD.operation, OLD.requested_path,
        OLD.managed_public_key_fingerprint, OLD.connection_config_digest,
        OLD.connection_generation, OLD.host_key_approval_pk_snapshot,
        OLD.host_key_approval_generation, OLD.host_key_fingerprint,
        OLD.host_key_negotiated_algorithm, OLD.celery_task_id, OLD.idempotency_key,
        OLD.intent_digest, OLD.expires_at, OLD.created
    ) THEN
        RAISE EXCEPTION 'managed SSH operation intent is immutable'
            USING ERRCODE = 'check_violation';
    END IF;

    IF NEW.attempts < OLD.attempts OR NEW.publish_attempts < OLD.publish_attempts THEN
        RAISE EXCEPTION 'managed SSH attempt counters cannot move backwards'
            USING ERRCODE = 'check_violation';
    END IF;
    IF octet_length(NEW.result_payload::text) > 4194304
       OR octet_length(NEW.error_payload::text) > 65536 THEN
        RAISE EXCEPTION 'managed SSH execution evidence is too large'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'pending' AND (
        NEW.attempts <> 0
        OR NEW.lease_token IS NOT NULL
        OR NEW.lease_expires_at IS NOT NULL
        OR NEW.claimed_at IS NOT NULL
        OR NEW.completed_at IS NOT NULL
        OR NEW.result_payload <> '{}'::jsonb
        OR NEW.result_digest <> ''
        OR NEW.error_payload <> '{}'::jsonb
        OR NEW.execution_witness_digest <> ''
    ) THEN
        RAISE EXCEPTION 'managed SSH pending evidence is invalid'
            USING ERRCODE = 'check_violation';
    ELSIF NEW.status = 'running' AND (
        NEW.attempts < 1
        OR NEW.lease_token IS NULL
        OR NEW.lease_expires_at IS NULL
        OR NEW.claimed_at IS NULL
        OR NEW.completed_at IS NOT NULL
        OR NEW.result_payload <> '{}'::jsonb
        OR NEW.result_digest <> ''
        OR NEW.error_payload <> '{}'::jsonb
        OR NEW.execution_witness_digest <> ''
    ) THEN
        RAISE EXCEPTION 'managed SSH running evidence is invalid'
            USING ERRCODE = 'check_violation';
    ELSIF NEW.status = 'complete' AND (
        NEW.lease_token IS NOT NULL
        OR NEW.lease_expires_at IS NOT NULL
        OR NEW.claimed_at IS NULL
        OR NEW.completed_at IS NULL
        OR NEW.result_digest !~ '^[0-9a-f]{64}$'
        OR NEW.error_payload <> '{}'::jsonb
        OR NEW.execution_witness_digest !~ '^[0-9a-f]{64}$'
    ) THEN
        RAISE EXCEPTION 'managed SSH completion evidence is invalid'
            USING ERRCODE = 'check_violation';
    ELSIF NEW.status IN ('failed', 'expired') AND (
        NEW.lease_token IS NOT NULL
        OR NEW.lease_expires_at IS NOT NULL
        OR NEW.completed_at IS NULL
        OR NEW.result_payload <> '{}'::jsonb
        OR NEW.result_digest <> ''
        OR NEW.error_payload = '{}'::jsonb
        OR NEW.execution_witness_digest !~ '^[0-9a-f]{64}$'
    ) THEN
        RAISE EXCEPTION 'managed SSH failure evidence is invalid'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at THEN
        RAISE EXCEPTION 'managed SSH publication witness is immutable once set'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status IN ('complete', 'failed', 'expired') AND ROW(
        NEW.status, NEW.lease_token, NEW.lease_expires_at, NEW.attempts,
        NEW.claimed_at, NEW.completed_at, NEW.result_payload,
        NEW.result_digest, NEW.error_payload, NEW.execution_witness_digest
    ) IS DISTINCT FROM ROW(
        OLD.status, OLD.lease_token, OLD.lease_expires_at, OLD.attempts,
        OLD.claimed_at, OLD.completed_at, OLD.result_payload,
        OLD.result_digest, OLD.error_payload, OLD.execution_witness_digest
    ) THEN
        RAISE EXCEPTION 'terminal managed SSH execution evidence is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'pending' AND NEW.status NOT IN ('pending', 'running', 'failed', 'expired') THEN
        RAISE EXCEPTION 'invalid managed SSH pending transition'
            USING ERRCODE = 'check_violation';
    ELSIF OLD.status = 'running' AND NEW.status NOT IN ('running', 'complete', 'failed', 'expired') THEN
        RAISE EXCEPTION 'invalid managed SSH running transition'
            USING ERRCODE = 'check_violation';
    ELSIF OLD.status IN ('complete', 'failed', 'expired') AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'terminal managed SSH status is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION backupsheep_managed_ssh_connection_active_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    managed_key_enabled boolean := FALSE;
    latest_status varchar(16);
    latest_generation bigint;
BEGIN
    IF NEW.status = 1 AND OLD.status IS DISTINCT FROM 1 THEN
        SELECT CASE integration.code
                 WHEN 'database' THEN COALESCE(database_auth.use_public_key, FALSE)
                 WHEN 'website' THEN COALESCE(website_auth.use_public_key, FALSE)
                 ELSE FALSE
               END
          INTO managed_key_enabled
          FROM core_integration AS integration
     LEFT JOIN core_auth_database AS database_auth
            ON database_auth.connection_id = NEW.id
     LEFT JOIN core_auth_website AS website_auth
            ON website_auth.connection_id = NEW.id
         WHERE integration.id = NEW.integration_id;

        IF managed_key_enabled THEN
            SELECT operation.status, operation.connection_generation
              INTO latest_status, latest_generation
              FROM core_managed_ssh_operation AS operation
             WHERE operation.connection_id = NEW.id
               AND operation.operation = 'validate'
          ORDER BY operation.created DESC, operation.id DESC
             LIMIT 1;
            IF NOT FOUND
               OR latest_status <> 'complete'
               OR latest_generation IS DISTINCT FROM NEW.managed_ssh_generation THEN
                RAISE EXCEPTION 'managed SSH connection requires latest generation validation'
                    USING ERRCODE = 'check_violation';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION backupsheep_managed_ssh_connection_identity_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.account_id IS DISTINCT FROM OLD.account_id
       OR NEW.integration_id IS DISTINCT FROM OLD.integration_id THEN
        RAISE EXCEPTION 'connection account and integration are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.managed_ssh_generation IS DISTINCT FROM OLD.managed_ssh_generation
       AND (
           pg_trigger_depth() < 2
           OR NEW.managed_ssh_generation <> OLD.managed_ssh_generation + 1
           OR NEW.status <> 2
       ) THEN
        RAISE EXCEPTION 'managed SSH generation can change only through a fencing trigger'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION backupsheep_ssh_host_key_approval_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    actor_user_id bigint;
    key_changed boolean := FALSE;
BEGIN
    IF TG_OP = 'UPDATE' AND ROW(
        NEW.account_id, NEW.normalized_host, NEW.port,
        NEW.created
    ) IS DISTINCT FROM ROW(
        OLD.account_id, OLD.normalized_host, OLD.port,
        OLD.created
    ) THEN
        RAISE EXCEPTION 'SSH host-key approval endpoint identity is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NOT backupsheep_is_canonical_ssh_host(NEW.normalized_host)
       OR NEW.port < 1 OR NEW.port > 65535 THEN
        RAISE EXCEPTION 'SSH host-key approval endpoint is invalid'
            USING ERRCODE = 'check_violation';
    END IF;

    -- Treat the approval ledger as a security boundary, not merely an ORM
    -- cache.  A compromised application role must not be able to persist an
    -- algorithm downgrade or an unbounded/malformed key for a worker to parse.
    IF octet_length(NEW.public_key_base64) < 16
       OR octet_length(NEW.public_key_base64) > 16384
       OR NEW.public_key_base64 !~ '^[A-Za-z0-9+/]+={0,2}$'
       OR length(NEW.public_key_base64) % 4 <> 0
       OR octet_length(NEW.fingerprint) <> 50
       OR NEW.fingerprint !~ '^SHA256:[A-Za-z0-9+/]{43}$'
       OR NOT (
           (
               NEW.wire_key_type = 'ssh-ed25519'
               AND NEW.negotiated_host_key_algorithm = 'ssh-ed25519'
               AND NEW.bits = 256
           )
           OR (
               NEW.wire_key_type = 'ecdsa-sha2-nistp256'
               AND NEW.negotiated_host_key_algorithm = 'ecdsa-sha2-nistp256'
               AND NEW.bits = 256
           )
           OR (
               NEW.wire_key_type = 'ecdsa-sha2-nistp384'
               AND NEW.negotiated_host_key_algorithm = 'ecdsa-sha2-nistp384'
               AND NEW.bits = 384
           )
           OR (
               NEW.wire_key_type = 'ecdsa-sha2-nistp521'
               AND NEW.negotiated_host_key_algorithm = 'ecdsa-sha2-nistp521'
               AND NEW.bits = 521
           )
           OR (
               NEW.wire_key_type = 'ssh-rsa'
               AND NEW.negotiated_host_key_algorithm IN (
                   'rsa-sha2-256', 'rsa-sha2-512'
               )
               AND NEW.bits BETWEEN 3072 AND 16384
           )
       ) THEN
        RAISE EXCEPTION 'SSH host-key approval evidence is invalid'
            USING ERRCODE = 'check_violation';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        key_changed := ROW(
            NEW.wire_key_type, NEW.public_key_base64, NEW.fingerprint,
            NEW.negotiated_host_key_algorithm, NEW.bits
        ) IS DISTINCT FROM ROW(
            OLD.wire_key_type, OLD.public_key_base64, OLD.fingerprint,
            OLD.negotiated_host_key_algorithm, OLD.bits
        );
        IF key_changed THEN
            NEW.generation := OLD.generation + 1;
        ELSIF NEW.generation IS DISTINCT FROM OLD.generation
           OR NEW.approved_by_member_pk_snapshot IS DISTINCT FROM OLD.approved_by_member_pk_snapshot
           OR NEW.approved_by_user_pk_snapshot IS DISTINCT FROM OLD.approved_by_user_pk_snapshot THEN
            RAISE EXCEPTION 'SSH host-key approval generation and actor witness are immutable'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NEW.generation <> 1 THEN
        RAISE EXCEPTION 'SSH host-key approval must begin at generation one'
            USING ERRCODE = 'check_violation';
    END IF;

    IF TG_OP = 'INSERT' OR key_changed THEN
        SELECT member.user_id
          INTO actor_user_id
          FROM public.core_member AS member
         WHERE member.id = NEW.approved_by_member_pk_snapshot;
        IF NOT FOUND
           OR NEW.approved_by_user_pk_snapshot IS DISTINCT FROM actor_user_id
           OR NOT EXISTS (
               SELECT 1
                 FROM public.core_member_mtm_account AS membership
                WHERE membership.member_id = NEW.approved_by_member_pk_snapshot
                  AND membership.account_id = NEW.account_id
                  AND membership.status = 1
           ) THEN
            RAISE EXCEPTION 'SSH host-key approval actor is invalid'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION backupsheep_ssh_host_key_approval_fence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    target_account_id bigint;
    target_host varchar(255);
    target_port integer;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.generation = OLD.generation THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        target_account_id := NEW.account_id;
        target_host := NEW.normalized_host;
        target_port := NEW.port;
    ELSE
        target_account_id := OLD.account_id;
        target_host := OLD.normalized_host;
        target_port := OLD.port;
    END IF;

    UPDATE public.core_connection AS connection
       SET managed_ssh_generation = connection.managed_ssh_generation + 1,
           status = 2,
           modified = clock_timestamp()
     WHERE connection.account_id = target_account_id
       AND (
           EXISTS (
               SELECT 1
                 FROM public.core_auth_database AS auth
                WHERE auth.connection_id = connection.id
                  AND (
                      COALESCE(auth.use_public_key, FALSE)
                      OR COALESCE(auth.use_private_key, FALSE)
                  )
                  AND auth.ssh_host = target_host
                  AND auth.ssh_port = target_port
           )
           OR EXISTS (
               SELECT 1
                 FROM public.core_auth_website AS auth
                WHERE auth.connection_id = connection.id
                  AND auth.protocol = 2
                  AND auth.host = target_host
                  AND auth.port = target_port
           )
       );
    RETURN NULL;
END;
$$;

CREATE FUNCTION backupsheep_ssh_host_key_approval_audit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    routine_witness boolean := FALSE;
    revoke_actor_kind text := 'system';
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.core_ssh_host_key_approval_event (
            approval_pk_snapshot, account_pk_snapshot, normalized_host, port,
            generation, action,
            old_wire_key_type, new_wire_key_type,
            old_public_key_base64, new_public_key_base64,
            old_fingerprint, new_fingerprint,
            old_negotiated_host_key_algorithm,
            new_negotiated_host_key_algorithm,
            old_bits, new_bits, actor_kind,
            actor_member_pk_snapshot, actor_user_pk_snapshot,
            created, modified
        ) VALUES (
            NEW.id, NEW.account_id, NEW.normalized_host, NEW.port,
            NEW.generation, 'approve',
            '', NEW.wire_key_type,
            '', NEW.public_key_base64,
            '', NEW.fingerprint,
            '', NEW.negotiated_host_key_algorithm,
            NULL, NEW.bits, 'member',
            NEW.approved_by_member_pk_snapshot,
            NEW.approved_by_user_pk_snapshot,
            clock_timestamp(), clock_timestamp()
        );
    ELSIF TG_OP = 'UPDATE' AND NEW.generation IS DISTINCT FROM OLD.generation THEN
        INSERT INTO public.core_ssh_host_key_approval_event (
            approval_pk_snapshot, account_pk_snapshot, normalized_host, port,
            generation, action,
            old_wire_key_type, new_wire_key_type,
            old_public_key_base64, new_public_key_base64,
            old_fingerprint, new_fingerprint,
            old_negotiated_host_key_algorithm,
            new_negotiated_host_key_algorithm,
            old_bits, new_bits, actor_kind,
            actor_member_pk_snapshot, actor_user_pk_snapshot,
            created, modified
        ) VALUES (
            NEW.id, NEW.account_id, NEW.normalized_host, NEW.port,
            NEW.generation, 'replace',
            OLD.wire_key_type, NEW.wire_key_type,
            OLD.public_key_base64, NEW.public_key_base64,
            OLD.fingerprint, NEW.fingerprint,
            OLD.negotiated_host_key_algorithm,
            NEW.negotiated_host_key_algorithm,
            OLD.bits, NEW.bits, 'member',
            NEW.approved_by_member_pk_snapshot,
            NEW.approved_by_user_pk_snapshot,
            clock_timestamp(), clock_timestamp()
        );
    ELSIF TG_OP = 'DELETE' THEN
        DELETE FROM public.backupsheep_ssh_host_key_revoke_witness AS witness
         WHERE witness.backend_pid = pg_catalog.pg_backend_pid()
           AND witness.approval_id = OLD.id
           AND witness.account_id = OLD.account_id
         RETURNING TRUE INTO routine_witness;

        IF COALESCE(routine_witness, FALSE) THEN
            -- The database authenticates only the generation-3 application
            -- identity. End-user attribution remains application audit context,
            -- not a forgeable database claim.
            revoke_actor_kind := 'application';
        ELSE
            -- An account-owned cascade runs after the parent account row has
            -- been removed by the same statement. A direct approval DELETE
            -- still sees its parent and must never forge a system actor. This
            -- remains reliable even though PostgreSQL's internal FK triggers
            -- do not expose a distinct pg_trigger_depth() to this row trigger.
            IF EXISTS (
                SELECT 1
                  FROM public.core_account AS account
                 WHERE account.id = OLD.account_id
            ) THEN
                RAISE EXCEPTION 'SSH host-key revoke actor is required'
                    USING ERRCODE = 'insufficient_privilege';
            END IF;
        END IF;
        INSERT INTO public.core_ssh_host_key_approval_event (
            approval_pk_snapshot, account_pk_snapshot, normalized_host, port,
            generation, action,
            old_wire_key_type, new_wire_key_type,
            old_public_key_base64, new_public_key_base64,
            old_fingerprint, new_fingerprint,
            old_negotiated_host_key_algorithm,
            new_negotiated_host_key_algorithm,
            old_bits, new_bits, actor_kind,
            actor_member_pk_snapshot, actor_user_pk_snapshot,
            created, modified
        ) VALUES (
            OLD.id, OLD.account_id, OLD.normalized_host, OLD.port,
            OLD.generation + 1, 'revoke',
            OLD.wire_key_type, '',
            OLD.public_key_base64, '',
            OLD.fingerprint, '',
            OLD.negotiated_host_key_algorithm, '',
            OLD.bits, NULL, revoke_actor_kind,
            NULL, NULL,
            clock_timestamp(), clock_timestamp()
        );
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION backupsheep_ssh_host_key_approval_event_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND pg_trigger_depth() >= 2 THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'SSH host-key approval history is append-only'
        USING ERRCODE = 'check_violation';
END;
$$;

CREATE FUNCTION backupsheep_delete_managed_ssh_operation_retention(
    requested_retention_days integer,
    requested_batch_size integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    caller_identity text[];
    owner_identity text[];
    caller_lane text;
    retention_days integer;
    batch_size integer;
    deleted_count integer;
BEGIN
    SELECT pg_catalog.regexp_match(
               pg_catalog.shobj_description(role.oid, 'pg_authid'),
               '^backupsheep:database-identity-v3:([0-9a-f]{64}):(database|files)$'
           )
      INTO caller_identity
      FROM pg_catalog.pg_roles AS role
     WHERE role.rolname = SESSION_USER;

    SELECT pg_catalog.regexp_match(
               pg_catalog.shobj_description(role.oid, 'pg_authid'),
               '^backupsheep:database-identity-v3:([0-9a-f]{64}):migrator$'
           )
      INTO owner_identity
      FROM pg_catalog.pg_roles AS role
     WHERE role.rolname = CURRENT_USER;

    IF caller_identity IS NULL
       OR owner_identity IS NULL
       OR caller_identity[1] IS DISTINCT FROM owner_identity[1] THEN
        RAISE EXCEPTION 'managed SSH retention requires an authenticated lane role'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    caller_lane := caller_identity[2];
    retention_days := GREATEST(
        7, LEAST(COALESCE(requested_retention_days, 30), 365)
    );
    batch_size := GREATEST(
        1, LEAST(COALESCE(requested_batch_size, 100), 500)
    );

    WITH protected AS MATERIALIZED (
        SELECT DISTINCT ON (operation.connection_id) operation.id
          FROM public.core_managed_ssh_operation AS operation
          JOIN public.core_connection AS connection
            ON connection.id = operation.connection_id
         WHERE operation.source_lane = caller_lane
           AND operation.operation = 'validate'
           AND operation.status = 'complete'
           AND operation.connection_generation = connection.managed_ssh_generation
         ORDER BY operation.connection_id, operation.created DESC, operation.id DESC
    ), eligible AS MATERIALIZED (
        SELECT operation.id
          FROM public.core_managed_ssh_operation AS operation
         WHERE operation.source_lane = caller_lane
           AND operation.status IN ('complete', 'failed', 'expired')
           AND operation.completed_at < (
               pg_catalog.clock_timestamp()
               - pg_catalog.make_interval(days => retention_days)
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM protected
                WHERE protected.id = operation.id
           )
         ORDER BY operation.completed_at, operation.id
         LIMIT batch_size
         FOR UPDATE OF operation SKIP LOCKED
    ), deleted AS (
        DELETE FROM public.core_managed_ssh_operation AS operation
              USING eligible
              WHERE operation.id = eligible.id
          RETURNING operation.id
    )
    SELECT count(*)::integer INTO deleted_count FROM deleted;
    RETURN deleted_count;
END;
$$;

CREATE FUNCTION backupsheep_revoke_ssh_host_key_approval(
    requested_approval_id bigint,
    requested_account_id bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    caller_identity text[];
    owner_identity text[];
    approval_exists boolean;
    deleted boolean;
BEGIN
    SELECT pg_catalog.regexp_match(
               pg_catalog.shobj_description(role.oid, 'pg_authid'),
               '^backupsheep:database-identity-v3:([0-9a-f]{64}):app$'
           )
      INTO caller_identity
      FROM pg_catalog.pg_roles AS role
     WHERE role.rolname = SESSION_USER;

    SELECT pg_catalog.regexp_match(
               pg_catalog.shobj_description(role.oid, 'pg_authid'),
               '^backupsheep:database-identity-v3:([0-9a-f]{64}):migrator$'
           )
      INTO owner_identity
      FROM pg_catalog.pg_roles AS role
     WHERE role.rolname = CURRENT_USER;

    -- The routine owner is the migrator and already controls the schema; allow
    -- it for migrations/tests. Every distinct session identity must be the
    -- generation-3 app role from this exact installation.
    IF SESSION_USER <> CURRENT_USER
       AND (
           caller_identity IS NULL
           OR owner_identity IS NULL
           OR caller_identity[1] IS DISTINCT FROM owner_identity[1]
       ) THEN
        RAISE EXCEPTION 'SSH host-key revoke requires the authenticated app role'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF requested_approval_id IS NULL OR requested_approval_id <= 0
       OR requested_account_id IS NULL OR requested_account_id <= 0 THEN
        RAISE EXCEPTION 'SSH host-key revoke identity is invalid'
            USING ERRCODE = 'check_violation';
    END IF;

    -- Take the global managed-SSH lock before any approval row lock. The
    -- delete trigger asserts this ordering without blocking.
    PERFORM pg_catalog.pg_advisory_xact_lock(3141592653589793);

    SELECT TRUE
      INTO approval_exists
      FROM public.core_ssh_host_key_approval AS approval
     WHERE approval.id = requested_approval_id
       AND approval.account_id = requested_account_id
     FOR UPDATE;
    IF NOT COALESCE(approval_exists, FALSE) THEN
        RETURN FALSE;
    END IF;

    INSERT INTO public.backupsheep_ssh_host_key_revoke_witness (
        backend_pid, approval_id, account_id
    ) VALUES (
        pg_catalog.pg_backend_pid(), requested_approval_id, requested_account_id
    );
    DELETE FROM public.core_ssh_host_key_approval AS approval
     WHERE approval.id = requested_approval_id
       AND approval.account_id = requested_account_id;
    deleted := FOUND;
    IF NOT deleted OR EXISTS (
        SELECT 1
          FROM public.backupsheep_ssh_host_key_revoke_witness AS witness
         WHERE witness.backend_pid = pg_catalog.pg_backend_pid()
           AND witness.approval_id = requested_approval_id
           AND witness.account_id = requested_account_id
    ) THEN
        RAISE EXCEPTION 'SSH host-key revoke witness was not consumed'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN TRUE;
END;
$$;

CREATE FUNCTION backupsheep_managed_ssh_account_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(3141592653589793) THEN
        RAISE EXCEPTION 'managed SSH mutation lock ordering violation'
            USING ERRCODE = 'serialization_failure';
    END IF;
    IF EXISTS (SELECT 1 FROM public.core_account) THEN
        -- A lane identity is safe only while the installation has one security
        -- tenant. Atomically fence every configured managed connection before a
        -- second account becomes visible. The authentication triggers increment
        -- each connection generation and project it back to PENDING.
        UPDATE public.core_auth_database
           SET use_public_key = FALSE,
               modified = pg_catalog.clock_timestamp()
         WHERE COALESCE(use_public_key, FALSE);
        UPDATE public.core_auth_website
           SET use_public_key = FALSE,
               modified = pg_catalog.clock_timestamp()
         WHERE COALESCE(use_public_key, FALSE);
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION backupsheep_managed_ssh_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- PostgreSQL has already identified the row by the time a BEFORE DELETE
    -- trigger runs. A non-blocking advisory assertion is therefore required:
    -- abort a row-first caller immediately instead of waiting while a compliant
    -- advisory-first transaction may be waiting for this row.
    IF NOT pg_catalog.pg_try_advisory_xact_lock(3141592653589793) THEN
        RAISE EXCEPTION 'managed SSH delete lock ordering violation'
            USING ERRCODE = 'serialization_failure';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION backupsheep_managed_ssh_single_account(expected_account_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT expected_account_id IS NOT NULL
       AND expected_account_id > 0
       AND EXISTS (
           SELECT 1 FROM public.core_account WHERE id = expected_account_id
       )
       AND NOT EXISTS (
           SELECT 1 FROM public.core_account WHERE id <> expected_account_id
       )
$$;

CREATE TRIGGER managed_ssh_database_auth_generation
BEFORE INSERT OR UPDATE ON core_auth_database
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_auth_generation();

CREATE TRIGGER managed_ssh_account_insert_guard
BEFORE INSERT ON core_account
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_account_insert_guard();

CREATE TRIGGER managed_ssh_account_delete_guard
BEFORE DELETE ON core_account
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_delete_guard();

CREATE TRIGGER managed_ssh_website_auth_generation
BEFORE INSERT OR UPDATE ON core_auth_website
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_auth_generation();

CREATE TRIGGER managed_ssh_database_auth_delete_guard
BEFORE DELETE ON core_auth_database
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_delete_guard();

CREATE TRIGGER managed_ssh_website_auth_delete_guard
BEFORE DELETE ON core_auth_website
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_delete_guard();

CREATE TRIGGER managed_ssh_operation_insert_guard
BEFORE INSERT ON core_managed_ssh_operation
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_operation_insert_guard();

CREATE TRIGGER managed_ssh_operation_update_guard
BEFORE UPDATE ON core_managed_ssh_operation
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_operation_update_guard();

CREATE TRIGGER managed_ssh_connection_active_guard
BEFORE UPDATE OF status ON core_connection
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_connection_active_guard();

CREATE TRIGGER managed_ssh_connection_identity_guard
BEFORE UPDATE OF account_id, integration_id, managed_ssh_generation ON core_connection
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_connection_identity_guard();

CREATE TRIGGER managed_ssh_connection_delete_guard
BEFORE DELETE ON core_connection
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_delete_guard();

CREATE TRIGGER ssh_host_key_approval_guard
BEFORE INSERT OR UPDATE ON core_ssh_host_key_approval
FOR EACH ROW EXECUTE FUNCTION backupsheep_ssh_host_key_approval_guard();

CREATE TRIGGER ssh_host_key_approval_delete_guard
BEFORE DELETE ON core_ssh_host_key_approval
FOR EACH ROW EXECUTE FUNCTION backupsheep_managed_ssh_delete_guard();

CREATE TRIGGER ssh_host_key_approval_fence
AFTER INSERT OR UPDATE OR DELETE ON core_ssh_host_key_approval
FOR EACH ROW EXECUTE FUNCTION backupsheep_ssh_host_key_approval_fence();

CREATE TRIGGER ssh_host_key_approval_audit
AFTER INSERT OR UPDATE OR DELETE ON core_ssh_host_key_approval
FOR EACH ROW EXECUTE FUNCTION backupsheep_ssh_host_key_approval_audit();

CREATE TRIGGER ssh_host_key_approval_event_append_only
BEFORE INSERT OR UPDATE OR DELETE ON core_ssh_host_key_approval_event
FOR EACH ROW EXECUTE FUNCTION backupsheep_ssh_host_key_approval_event_append_only();

REVOKE ALL ON FUNCTION backupsheep_managed_ssh_auth_generation() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_managed_ssh_operation_insert_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_managed_ssh_operation_update_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_managed_ssh_connection_active_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_managed_ssh_connection_identity_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_ssh_host_key_approval_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_ssh_host_key_approval_fence() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_ssh_host_key_approval_audit() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_ssh_host_key_approval_event_append_only() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_delete_managed_ssh_operation_retention(integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_revoke_ssh_host_key_approval(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_managed_ssh_account_insert_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_managed_ssh_delete_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_managed_ssh_single_account(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION backupsheep_is_canonical_ssh_host(text) FROM PUBLIC;
"""


MANAGED_SSH_FENCE_REVERSE_SQL = r"""
DROP TRIGGER IF EXISTS ssh_host_key_approval_event_append_only ON core_ssh_host_key_approval_event;
DROP TRIGGER IF EXISTS ssh_host_key_approval_audit ON core_ssh_host_key_approval;
DROP TRIGGER IF EXISTS ssh_host_key_approval_delete_guard ON core_ssh_host_key_approval;
DROP TRIGGER IF EXISTS managed_ssh_connection_active_guard ON core_connection;
DROP TRIGGER IF EXISTS managed_ssh_connection_identity_guard ON core_connection;
DROP TRIGGER IF EXISTS managed_ssh_connection_delete_guard ON core_connection;
DROP TRIGGER IF EXISTS ssh_host_key_approval_fence ON core_ssh_host_key_approval;
DROP TRIGGER IF EXISTS ssh_host_key_approval_guard ON core_ssh_host_key_approval;
DROP TRIGGER IF EXISTS managed_ssh_operation_update_guard ON core_managed_ssh_operation;
DROP TRIGGER IF EXISTS managed_ssh_operation_insert_guard ON core_managed_ssh_operation;
DROP TRIGGER IF EXISTS managed_ssh_website_auth_generation ON core_auth_website;
DROP TRIGGER IF EXISTS managed_ssh_website_auth_delete_guard ON core_auth_website;
DROP TRIGGER IF EXISTS managed_ssh_database_auth_generation ON core_auth_database;
DROP TRIGGER IF EXISTS managed_ssh_database_auth_delete_guard ON core_auth_database;
DROP TRIGGER IF EXISTS managed_ssh_account_insert_guard ON core_account;
DROP TRIGGER IF EXISTS managed_ssh_account_delete_guard ON core_account;
DROP FUNCTION IF EXISTS backupsheep_managed_ssh_connection_active_guard();
DROP FUNCTION IF EXISTS backupsheep_managed_ssh_connection_identity_guard();
DROP FUNCTION IF EXISTS backupsheep_ssh_host_key_approval_fence();
DROP FUNCTION IF EXISTS backupsheep_ssh_host_key_approval_guard();
DROP FUNCTION IF EXISTS backupsheep_ssh_host_key_approval_audit();
DROP FUNCTION IF EXISTS backupsheep_ssh_host_key_approval_event_append_only();
DROP FUNCTION IF EXISTS backupsheep_managed_ssh_operation_update_guard();
DROP FUNCTION IF EXISTS backupsheep_managed_ssh_operation_insert_guard();
DROP FUNCTION IF EXISTS backupsheep_managed_ssh_auth_generation();
DROP FUNCTION IF EXISTS backupsheep_managed_ssh_account_insert_guard();
DROP FUNCTION IF EXISTS backupsheep_managed_ssh_delete_guard();
DROP FUNCTION IF EXISTS backupsheep_managed_ssh_single_account(bigint);
DROP FUNCTION IF EXISTS backupsheep_delete_managed_ssh_operation_retention(integer, integer);
DROP FUNCTION IF EXISTS backupsheep_revoke_ssh_host_key_approval(bigint, bigint);
DROP FUNCTION IF EXISTS backupsheep_is_canonical_ssh_host(text);
DROP TABLE IF EXISTS backupsheep_ssh_host_key_revoke_witness;
"""


MANAGED_SSH_FK_CASCADE_SQL = r"""
ALTER TABLE core_ssh_host_key_approval
    ADD CONSTRAINT ssh_host_key_approval_account_fk
        FOREIGN KEY (account_id) REFERENCES core_account(id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE core_managed_ssh_operation
    ADD CONSTRAINT managed_ssh_op_account_fk
        FOREIGN KEY (account_id) REFERENCES core_account(id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT managed_ssh_op_connection_fk
        FOREIGN KEY (connection_id) REFERENCES core_connection(id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
"""


MANAGED_SSH_FK_CASCADE_REVERSE_SQL = r"""
ALTER TABLE core_ssh_host_key_approval
    DROP CONSTRAINT ssh_host_key_approval_account_fk;

ALTER TABLE core_managed_ssh_operation
    DROP CONSTRAINT managed_ssh_op_account_fk,
    DROP CONSTRAINT managed_ssh_op_connection_fk;
"""


class Migration(migrations.Migration):
    dependencies = [("apps", "0045_prepare_node_deletion_lanes")]

    operations = [
        migrations.AddField(
            model_name="coreconnection",
            name="managed_ssh_generation",
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.CreateModel(
            name="CoreSSHHostKeyApproval",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="created",
                    ),
                ),
                (
                    "modified",
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="modified",
                    ),
                ),
                ("normalized_host", models.CharField(editable=False, max_length=255)),
                ("port", models.PositiveIntegerField(editable=False)),
                ("wire_key_type", models.CharField(editable=False, max_length=64)),
                ("public_key_base64", models.TextField(editable=False)),
                ("fingerprint", models.CharField(editable=False, max_length=128)),
                (
                    "negotiated_host_key_algorithm",
                    models.CharField(editable=False, max_length=64),
                ),
                ("bits", models.PositiveIntegerField(editable=False)),
                ("generation", models.PositiveBigIntegerField(default=1, editable=False)),
                ("approved_by_member_pk_snapshot", models.PositiveBigIntegerField(editable=False)),
                ("approved_by_user_pk_snapshot", models.PositiveBigIntegerField(editable=False)),
                (
                    "account",
                    models.ForeignKey(
                        editable=False,
                        db_constraint=False,
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        related_name="ssh_host_key_approvals",
                        to="apps.coreaccount",
                    ),
                ),
            ],
            options={
                "db_table": "core_ssh_host_key_approval",
                "indexes": [
                    models.Index(
                        fields=["account", "normalized_host", "port"],
                        name="ssh_host_key_account_endpoint",
                    )
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("account", "normalized_host", "port"),
                        name="unique_account_ssh_host_key_approval",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(port__gte=1, port__lte=65535),
                        name="ssh_host_key_approval_port_valid",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="CoreSSHHostKeyApprovalEvent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="created",
                    ),
                ),
                (
                    "modified",
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="modified",
                    ),
                ),
                ("approval_pk_snapshot", models.PositiveBigIntegerField(editable=False)),
                ("account_pk_snapshot", models.PositiveBigIntegerField(editable=False)),
                ("normalized_host", models.CharField(editable=False, max_length=255)),
                ("port", models.PositiveIntegerField(editable=False)),
                ("generation", models.PositiveBigIntegerField(editable=False)),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("approve", "Approve"),
                            ("replace", "Replace"),
                            ("revoke", "Revoke"),
                        ],
                        editable=False,
                        max_length=16,
                    ),
                ),
                (
                    "old_wire_key_type",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                (
                    "new_wire_key_type",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                ("old_public_key_base64", models.TextField(blank=True, editable=False)),
                ("new_public_key_base64", models.TextField(blank=True, editable=False)),
                (
                    "old_fingerprint",
                    models.CharField(blank=True, editable=False, max_length=128),
                ),
                (
                    "new_fingerprint",
                    models.CharField(blank=True, editable=False, max_length=128),
                ),
                (
                    "old_negotiated_host_key_algorithm",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                (
                    "new_negotiated_host_key_algorithm",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                ("old_bits", models.PositiveIntegerField(editable=False, null=True)),
                ("new_bits", models.PositiveIntegerField(editable=False, null=True)),
                (
                    "actor_kind",
                    models.CharField(
                        choices=[
                            ("member", "Member"),
                            ("application", "Application"),
                            ("system", "System"),
                        ],
                        editable=False,
                        max_length=16,
                    ),
                ),
                (
                    "actor_member_pk_snapshot",
                    models.PositiveBigIntegerField(editable=False, null=True),
                ),
                (
                    "actor_user_pk_snapshot",
                    models.PositiveBigIntegerField(editable=False, null=True),
                ),
            ],
            options={
                "db_table": "core_ssh_host_key_approval_event",
                "indexes": [
                    models.Index(
                        fields=[
                            "account_pk_snapshot",
                            "normalized_host",
                            "port",
                            "generation",
                        ],
                        name="ssh_host_key_event_endpoint",
                    )
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("approval_pk_snapshot", "generation", "action"),
                        name="unique_ssh_host_key_approval_event",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(port__gte=1, port__lte=65535),
                        name="ssh_host_key_event_port_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(action__in=("approve", "replace", "revoke")),
                        name="ssh_host_key_event_action_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            actor_kind="member",
                            actor_member_pk_snapshot__isnull=False,
                            actor_user_pk_snapshot__isnull=False,
                        )
                        | models.Q(
                            actor_kind__in=("application", "system"),
                            actor_member_pk_snapshot__isnull=True,
                            actor_user_pk_snapshot__isnull=True,
                        ),
                        name="ssh_host_key_event_actor_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            action="approve",
                            old_fingerprint="",
                            new_fingerprint__gt="",
                        )
                        | models.Q(
                            action="replace",
                            old_fingerprint__gt="",
                            new_fingerprint__gt="",
                        )
                        | models.Q(
                            action="revoke",
                            old_fingerprint__gt="",
                            new_fingerprint="",
                        ),
                        name="ssh_host_key_event_transition_valid",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="CoreManagedSSHOperation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="created",
                    ),
                ),
                (
                    "modified",
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="modified",
                    ),
                ),
                (
                    "uuid",
                    models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
                ),
                (
                    "source_lane",
                    models.CharField(
                        choices=[("database", "Database"), ("files", "Files")],
                        editable=False,
                        max_length=16,
                    ),
                ),
                (
                    "operation",
                    models.CharField(
                        choices=[
                            ("validate", "Validate connection"),
                            ("discover", "Discover objects"),
                            ("update_metadata", "Update database metadata"),
                        ],
                        editable=False,
                        max_length=32,
                    ),
                ),
                (
                    "requested_path",
                    models.CharField(blank=True, editable=False, max_length=2048),
                ),
                (
                    "managed_public_key_fingerprint",
                    models.CharField(editable=False, max_length=64),
                ),
                (
                    "connection_config_digest",
                    models.CharField(editable=False, max_length=64),
                ),
                (
                    "connection_generation",
                    models.PositiveBigIntegerField(editable=False),
                ),
                (
                    "host_key_approval_pk_snapshot",
                    models.PositiveBigIntegerField(editable=False),
                ),
                (
                    "host_key_approval_generation",
                    models.PositiveBigIntegerField(editable=False),
                ),
                (
                    "host_key_fingerprint",
                    models.CharField(editable=False, max_length=128),
                ),
                (
                    "host_key_negotiated_algorithm",
                    models.CharField(editable=False, max_length=64),
                ),
                ("requested_by_member_pk_snapshot", models.PositiveBigIntegerField(editable=False)),
                ("requested_by_user_pk_snapshot", models.PositiveBigIntegerField(editable=False)),
                (
                    "request_actor_kind",
                    models.CharField(
                        choices=[
                            ("member", "Member"),
                        ],
                        default="member",
                        editable=False,
                        max_length=16,
                    ),
                ),
                (
                    "request_source",
                    models.CharField(default="api", editable=False, max_length=16),
                ),
                (
                    "celery_task_id",
                    models.UUIDField(editable=False, unique=True),
                ),
                (
                    "idempotency_key",
                    models.CharField(editable=False, max_length=64, unique=True),
                ),
                (
                    "intent_digest",
                    models.CharField(editable=False, max_length=64),
                ),
                ("expires_at", models.DateTimeField(editable=False)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("running", "Running"),
                            ("complete", "Complete"),
                            ("failed", "Failed"),
                            ("expired", "Expired"),
                        ],
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("lease_token", models.UUIDField(blank=True, null=True)),
                ("lease_expires_at", models.DateTimeField(blank=True, null=True)),
                ("attempts", models.PositiveIntegerField(default=0)),
                ("claimed_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("result_payload", models.JSONField(blank=True, default=dict)),
                ("result_digest", models.CharField(blank=True, max_length=64)),
                ("error_payload", models.JSONField(blank=True, default=dict)),
                (
                    "execution_witness_digest",
                    models.CharField(blank=True, max_length=64),
                ),
                ("publish_attempts", models.PositiveIntegerField(default=0)),
                ("last_publish_attempt_at", models.DateTimeField(blank=True, null=True)),
                ("published_at", models.DateTimeField(blank=True, null=True)),
                ("publish_error_code", models.CharField(blank=True, max_length=32)),
                (
                    "account",
                    models.ForeignKey(
                        db_constraint=False,
                        editable=False,
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        related_name="managed_ssh_operations",
                        to="apps.coreaccount",
                    ),
                ),
                (
                    "connection",
                    models.ForeignKey(
                        db_constraint=False,
                        editable=False,
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        related_name="managed_ssh_operations",
                        to="apps.coreconnection",
                    ),
                ),
            ],
            options={
                "db_table": "core_managed_ssh_operation",
                "indexes": [
                    models.Index(
                        fields=["connection", "status"],
                        name="managed_ssh_connection_status",
                    ),
                    models.Index(
                        fields=["status", "expires_at"],
                        name="managed_ssh_status_expiry",
                    ),
                ],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(source_lane__in=("database", "files")),
                        name="managed_ssh_source_lane_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(request_source="api"),
                        name="managed_ssh_request_source_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(request_actor_kind="member"),
                        name="managed_ssh_actor_kind_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            operation__in=(
                                "validate",
                                "discover",
                                "update_metadata",
                            )
                        ),
                        name="managed_ssh_operation_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            status__in=(
                                "pending",
                                "running",
                                "complete",
                                "failed",
                                "expired",
                            )
                        ),
                        name="managed_ssh_status_valid",
                    ),
                    models.CheckConstraint(
                        condition=~models.Q(operation="validate")
                        | models.Q(requested_path=""),
                        name="managed_ssh_validate_path_empty",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            managed_public_key_fingerprint__regex="^[0-9a-f]{64}$"
                        )
                        & models.Q(
                            connection_config_digest__regex="^[0-9a-f]{64}$"
                        )
                        & models.Q(idempotency_key__regex="^[0-9a-f]{64}$")
                        & models.Q(intent_digest__regex="^[0-9a-f]{64}$"),
                        name="managed_ssh_intent_digests_valid",
                    ),
                    models.CheckConstraint(
                        condition=~models.Q(
                            status__in=("complete", "failed", "expired")
                        )
                        | models.Q(completed_at__isnull=False),
                        name="managed_ssh_terminal_completed_at",
                    ),
                    models.CheckConstraint(
                        condition=(
                            models.Q(
                                status="pending",
                                attempts=0,
                                lease_token__isnull=True,
                                lease_expires_at__isnull=True,
                                claimed_at__isnull=True,
                                completed_at__isnull=True,
                                result_payload={},
                                result_digest="",
                                error_payload={},
                                execution_witness_digest="",
                            )
                            | models.Q(
                                status="running",
                                attempts__gte=1,
                                lease_token__isnull=False,
                                lease_expires_at__isnull=False,
                                claimed_at__isnull=False,
                                completed_at__isnull=True,
                                result_payload={},
                                result_digest="",
                                error_payload={},
                                execution_witness_digest="",
                            )
                            | models.Q(
                                status="complete",
                                lease_token__isnull=True,
                                lease_expires_at__isnull=True,
                                claimed_at__isnull=False,
                                completed_at__isnull=False,
                                result_digest__regex="^[0-9a-f]{64}$",
                                error_payload={},
                                execution_witness_digest__regex="^[0-9a-f]{64}$",
                            )
                            | (
                                models.Q(
                                    status__in=("failed", "expired"),
                                    lease_token__isnull=True,
                                    lease_expires_at__isnull=True,
                                    completed_at__isnull=False,
                                    result_payload={},
                                    result_digest="",
                                    execution_witness_digest__regex="^[0-9a-f]{64}$",
                                )
                                & ~models.Q(error_payload={})
                            )
                        ),
                        name="managed_ssh_execution_state_valid",
                    ),
                ],
            },
        ),
        migrations.RunPython(
            canonicalize_existing_ssh_hosts,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.RunSQL(
            sql=MANAGED_SSH_FK_CASCADE_SQL,
            reverse_sql=MANAGED_SSH_FK_CASCADE_REVERSE_SQL,
        ),
        migrations.RunSQL(
            sql=MANAGED_SSH_FENCE_SQL,
            reverse_sql=MANAGED_SSH_FENCE_REVERSE_SQL,
        ),
    ]
