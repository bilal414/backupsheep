#!/bin/sh
# Pure validation helpers for the PostgreSQL runtime migration.  This file is
# sourced by migrate-runtime.sh and by the adversarial contract tests.

backupsheep_postgres_source_identity_mode() {
    storage_intent="$1"
    database_identity_generation="$2"

    case "${storage_intent}:${database_identity_generation}" in
        migrated-debian-generation2-v1:3-pending-upgrade)
            printf '%s' generation2-three-role-v1
            ;;
        migrated-debian-generation2-v1:3)
            # Generation 3 can appear here only after db-seal completed but the
            # storage witness was not promoted. Never authorize a fresh copy.
            printf '%s' generation2-reconcile-v1
            ;;
        migrated-debian-generation2-v1:*)
            printf '%s\n' \
                'The generation-2 PostgreSQL path requires database identity generation 3-pending-upgrade.' >&2
            return 1
            ;;
        migrated-debian-v1:3)
            printf '%s' strict-ten-role-v1
            ;;
        migrated-debian-v1:*)
            printf '%s\n' \
                'The strict PostgreSQL source path requires completed generation-3 database identity state.' >&2
            return 1
            ;;
        *)
            printf '%s\n' 'The PostgreSQL source identity contract is unsupported.' >&2
            return 1
            ;;
    esac
}

backupsheep_postgres_source_identity_is_reconcile_only() {
    case "$1" in
        generation2-reconcile-v1) return 0 ;;
        generation2-three-role-v1|strict-ten-role-v1) return 1 ;;
        *)
            printf '%s\n' 'The PostgreSQL source identity mode is invalid.' >&2
            return 2
            ;;
    esac
}

backupsheep_record_role_names() {
    role_records="$1"

    printf '%s\n' "$role_records" | awk -F'|' '
        NF != 13 { exit 1 }
        $1 !~ /^[a-z_][a-z0-9_]*$/ || length($1) > 63 { exit 1 }
        seen[$1]++ { exit 1 }
        { print $1 }
    ' | LC_ALL=C sort
}

backupsheep_validate_generation2_source() {
    installation_id="$1"
    bootstrap_user="$2"
    source_roles="$3"
    role_security_records="$4"
    application_membership_count="$5"
    role_settings="$6"
    database_acl="$7"
    schema_acl="$8"
    default_acl="$9"
    default_acl_records="${10}"
    database_owner="${11}"
    schema_owner="${12}"
    public_object_owners="${13}"

    [ "$application_membership_count" = 0 ] || {
        printf '%s\n' 'The generation-2 source has an application-role membership.' >&2
        return 1
    }
    record_roles="$(backupsheep_record_role_names "$role_security_records")" || return 1
    [ "$record_roles" = "$source_roles" ] || {
        printf '%s\n' 'The generation-2 role inventory and security records disagree.' >&2
        return 1
    }
    printf '%s\n' "$role_security_records" | awk -F'|' \
        -v installation="$installation_id" -v bootstrap="$bootstrap_user" '
        BEGIN {
            bootstrap_marker = "backupsheep:database-identity-v2:" installation ":bootstrap"
            migrator_marker = "backupsheep:database-identity-v2:" installation ":migrator"
            runtime_marker = "backupsheep:database-identity-v2:" installation ":runtime"
        }
        NF != 13 { exit 1 }
        $1 == bootstrap {
            if ($2 != "true" || $3 != "true" || $4 != "true" ||
                $5 != "true" || $6 != "true" || $7 != "true" ||
                $8 != "true" || $9 != "-1" || $10 != "true" ||
                $11 != "true" || $12 != "true" || $13 != bootstrap_marker) exit 1
            bootstrap_count++
            next
        }
        $13 == migrator_marker { kind = "migrator"; migrator_count++; next_record = 1 }
        $13 == runtime_marker { kind = "runtime"; runtime_count++; next_record = 1 }
        next_record != 1 { exit 1 }
        {
            if ($2 != "false" || $3 != "true" || $4 != "false" ||
                $5 != "false" || $6 != "true" || $7 != "false" ||
                $8 != "false" || $9 != "-1" || $10 != "true" ||
                $11 != "false" || $12 != "true") exit 1
            next_record = 0
            kind = ""
        }
        END {
            if (NR != 3 || bootstrap_count != 1 || migrator_count != 1 || runtime_count != 1) exit 1
        }
    ' || {
        printf '%s\n' 'The generation-2 source roles, attributes, authentication, or markers drifted.' >&2
        return 1
    }

    migrator_user="$(printf '%s\n' "$role_security_records" | awk -F'|' \
        -v marker="backupsheep:database-identity-v2:${installation_id}:migrator" '$13 == marker { print $1 }')"
    runtime_user="$(printf '%s\n' "$role_security_records" | awk -F'|' \
        -v marker="backupsheep:database-identity-v2:${installation_id}:runtime" '$13 == marker { print $1 }')"
    expected_settings="$(printf '%s\n%s\n' \
        "${migrator_user}|<all-databases>|search_path=public, pg_catalog" \
        "${runtime_user}|<all-databases>|search_path=public, pg_catalog" | LC_ALL=C sort)"
    expected_default_acl="$(
        printf '%s\n' \
            "${migrator_user}|public|S|${runtime_user}|${migrator_user}|SELECT|false" \
            "${migrator_user}|public|S|${runtime_user}|${migrator_user}|USAGE|false" \
            "${migrator_user}|public|f|${runtime_user}|${migrator_user}|EXECUTE|false" \
            "${migrator_user}|public|r|${runtime_user}|${migrator_user}|DELETE|false" \
            "${migrator_user}|public|r|${runtime_user}|${migrator_user}|INSERT|false" \
            "${migrator_user}|public|r|${runtime_user}|${migrator_user}|SELECT|false" \
            "${migrator_user}|public|r|${runtime_user}|${migrator_user}|UPDATE|false" | LC_ALL=C sort
    )"
    expected_default_acl_records="$(printf '%s\n' \
        "${migrator_user}|public|S" \
        "${migrator_user}|public|f" \
        "${migrator_user}|public|r" | LC_ALL=C sort)"
    [ "$role_settings" = "$expected_settings" \
        ] && [ "$database_acl" = "${runtime_user}|${migrator_user}|CONNECT|false" \
        ] && [ "$schema_acl" = "${runtime_user}|${migrator_user}|USAGE|false" \
        ] && [ "$default_acl" = "$expected_default_acl" \
        ] && [ "$default_acl_records" = "$expected_default_acl_records" \
        ] && [ "$database_owner" = "$migrator_user" \
        ] && [ "$schema_owner" = "$migrator_user" \
        ] && [ "$public_object_owners" = "$migrator_user" ] || {
        printf '%s\n' 'The generation-2 source settings, ACLs, default privileges, or ownership drifted.' >&2
        return 1
    }
}

backupsheep_validate_generation3_source() {
    installation_id="$1"
    bootstrap_user="$2"
    expected_roles_csv="$3"
    source_roles="$4"
    role_security_records="$5"
    application_membership_count="$6"
    role_settings="$7"
    database_acl="$8"
    schema_acl="$9"
    default_acl="${10}"
    default_acl_records="${11}"
    database_owner="${12}"
    schema_owner="${13}"
    public_object_owners="${14}"

    [ "$application_membership_count" = 0 ] || {
        printf '%s\n' 'The generation-3 source has an application-role membership.' >&2
        return 1
    }
    record_roles="$(backupsheep_record_role_names "$role_security_records")" || return 1
    [ "$record_roles" = "$source_roles" ] || {
        printf '%s\n' 'The generation-3 role inventory and security records disagree.' >&2
        return 1
    }
    printf '%s\n' "$role_security_records" | awk -F'|' \
        -v installation="$installation_id" -v bootstrap="$bootstrap_user" \
        -v roster="$expected_roles_csv" '
        BEGIN {
            count = split(roster, role, ",")
            if (count != 10) exit 1
            kind[1] = "bootstrap"; kind[2] = "migrator"; kind[3] = "app"
            kind[4] = "preflight"; kind[5] = "beat"; kind[6] = "cloud"
            kind[7] = "database"; kind[8] = "files"; kind[9] = "storage"; kind[10] = "logs"
            for (i = 1; i <= count; i++) {
                if (role[i] in expected_kind) exit 1
                expected_kind[role[i]] = kind[i]
            }
            retired_marker = "backupsheep:database-identity-v3:" installation ":retired-v2-runtime"
        }
        NF != 13 { exit 1 }
        $1 in expected_kind {
            role_kind = expected_kind[$1]
            marker = "backupsheep:database-identity-v3:" installation ":" role_kind
            if ($13 != marker) exit 1
            if (role_kind == "bootstrap") {
                if ($1 != bootstrap || $2 != "true" || $3 != "true" ||
                    $4 != "true" || $5 != "true" || $6 != "true" ||
                    $7 != "true" || $8 != "true" || $9 != "-1" ||
                    $10 != "true" || $11 != "true" || $12 != "true") exit 1
            } else {
                expected_limit = (role_kind == "migrator" || role_kind == "preflight" || role_kind == "beat") ? 8 : 128
                if ($2 != "false" || $3 != "true" || $4 != "false" ||
                    $5 != "false" || $6 != "true" || $7 != "false" ||
                    $8 != "false" || $9 != expected_limit || $10 != "true" ||
                    $11 != "false" || $12 != "true") exit 1
            }
            seen[$1]++
            next
        }
        $13 == retired_marker {
            if (retired_count++ || $2 != "false" || $3 != "true" ||
                $4 != "false" || $5 != "false" || $6 != "false" ||
                $7 != "false" || $8 != "false" || $9 != "-1" ||
                $10 != "true" || $11 != "true" || $12 != "false") exit 1
            next
        }
        { exit 1 }
        END {
            for (i = 1; i <= count; i++) if (seen[role[i]] != 1) exit 1
            if (NR != 10 + retired_count || retired_count > 1) exit 1
        }
    ' || {
        printf '%s\n' 'The generation-3 source roles, attributes, authentication, or markers drifted.' >&2
        return 1
    }

    expected_settings="$(printf '%s' "$expected_roles_csv" | awk -F',' '
        {
            for (i = 2; i <= NF; i++) {
                print $i "|<all-databases>|idle_in_transaction_session_timeout=5min"
                print $i "|<all-databases>|lock_timeout=30s"
                print $i "|<all-databases>|search_path=public, pg_catalog"
                print $i "|<all-databases>|statement_timeout=1h"
            }
        }
    ' | LC_ALL=C sort)"
    expected_database_acl="$(printf '%s' "$expected_roles_csv" | awk -F',' '
        { for (i = 3; i <= NF; i++) print $i "|" $2 "|CONNECT|false" }
    ' | LC_ALL=C sort)"
    expected_schema_acl="$(printf '%s' "$expected_roles_csv" | awk -F',' '
        { for (i = 3; i <= NF; i++) print $i "|" $2 "|USAGE|false" }
    ' | LC_ALL=C sort)"
    migrator_user="$(printf '%s' "$expected_roles_csv" | cut -d, -f2)"
    expected_default_acl="$(printf '%s\n' \
        "${migrator_user}|<global>|T|${migrator_user}|${migrator_user}|USAGE|false" \
        "${migrator_user}|<global>|f|${migrator_user}|${migrator_user}|EXECUTE|false" \
        | LC_ALL=C sort)"
    expected_default_acl_records="$(printf '%s\n' \
        "${migrator_user}|<global>|T" \
        "${migrator_user}|<global>|f" | LC_ALL=C sort)"
    default_acl_is_known=false
    if [ -z "$default_acl" ] && [ -z "$default_acl_records" ]; then
        # Generation 3 shipped with schema-local REVOKEs, which PostgreSQL
        # records as no delta at all.  Accept that exact legacy state only as a
        # migration source; current provisioning seals the global defaults.
        default_acl_is_known=true
    elif [ "$default_acl" = "$expected_default_acl" ] \
        && [ "$default_acl_records" = "$expected_default_acl_records" ]; then
        default_acl_is_known=true
    fi
    [ "$role_settings" = "$expected_settings" \
        ] && [ "$database_acl" = "$expected_database_acl" \
        ] && [ "$schema_acl" = "$expected_schema_acl" \
        ] && [ "$default_acl_is_known" = true \
        ] && [ "$database_owner" = "$migrator_user" \
        ] && [ "$schema_owner" = "$migrator_user" \
        ] && [ "$public_object_owners" = "$migrator_user" ] || {
        printf '%s\n' 'The generation-3 source settings, ACLs, default privileges, or ownership drifted.' >&2
        return 1
    }
}

backupsheep_validate_target_placeholders() {
    installation_id="$1"
    bootstrap_user="$2"
    expected_roles_csv="$3"
    role_security_records="$4"
    application_membership_count="$5"
    role_settings="$6"

    [ "$application_membership_count" = 0 ] && [ -z "$role_settings" ] || {
        printf '%s\n' 'The target placeholder roles have memberships or session settings.' >&2
        return 1
    }
    record_roles="$(backupsheep_record_role_names "$role_security_records")" || return 1
    expected_roles="$(printf '%s' "$expected_roles_csv" | tr ',' '\n' | LC_ALL=C sort)"
    [ "$record_roles" = "$expected_roles" ] || {
        printf '%s\n' 'The target placeholder role inventory drifted.' >&2
        return 1
    }
    printf '%s\n' "$role_security_records" | awk -F'|' \
        -v installation="$installation_id" -v bootstrap="$bootstrap_user" \
        -v roster="$expected_roles_csv" '
        BEGIN {
            count = split(roster, role, ",")
            if (count != 10 || role[1] != bootstrap) exit 1
            kind[1] = "bootstrap"; kind[2] = "migrator"; kind[3] = "app"
            kind[4] = "preflight"; kind[5] = "beat"; kind[6] = "cloud"
            kind[7] = "database"; kind[8] = "files"; kind[9] = "storage"; kind[10] = "logs"
            for (i = 1; i <= count; i++) {
                if (role[i] in expected_kind) exit 1
                expected_kind[role[i]] = kind[i]
            }
        }
        NF != 13 || !($1 in expected_kind) { exit 1 }
        {
            role_kind = expected_kind[$1]
            marker = "backupsheep:database-identity-v3:" installation ":" role_kind
            if ($13 != marker || $3 != "true" || $9 != "-1" ||
                $10 != "true" || $11 != "true" || $12 != "true") exit 1
            if (role_kind == "bootstrap") {
                if ($2 != "true" || $4 != "true" || $5 != "true" ||
                    $6 != "true" || $7 != "true" || $8 != "true") exit 1
            } else if ($2 != "false" || $4 != "false" || $5 != "false" ||
                       $6 != "true" || $7 != "false" || $8 != "false") exit 1
            seen[$1]++
        }
        END {
            for (i = 1; i <= count; i++) if (seen[role[i]] != 1) exit 1
            if (NR != count) exit 1
        }
    ' || {
        printf '%s\n' 'The fixed target placeholder role contract drifted.' >&2
        return 1
    }
}

backupsheep_validate_completed_postgres_migration_evidence() {
    completed_evidence="$1"
    expected_generation="$2"
    expected_installation="$3"
    expected_intent="$4"
    expected_witness="$5"
    expected_source_image="$6"
    expected_target_image="$7"

    case "$expected_intent" in
        migrated-debian-generation2-v1)
            expected_source_contract='generation2-three-role-v1'
            ;;
        migrated-debian-v1)
            expected_source_contract='strict-ten-role-v1'
            ;;
        *) return 1 ;;
    esac

    [ "$(printf '%s\n' "$completed_evidence" | wc -l | tr -d ' ')" = 15 ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '1p')" = 'status=complete' ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '2p')" = "generation=${expected_generation}" ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '3p')" = "installation=${expected_installation}" ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '4p')" = "intent=${expected_intent}" ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '5p')" = "witness=${expected_witness}" ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '6p')" = '--receipt--' ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '7p')" = 'status=complete' ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '8p')" = 'receipt_version=2' ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '9p')" = 'restore_strategy=fixed-target-v3-roles-unprivileged-custom-v1' ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '10p')" = "source_contract=${expected_source_contract}" ] || return 1
    [ "$(printf '%s\n' "$completed_evidence" | sed -n '11p')" = "source_image=${expected_source_image}" ] || return 1

    completed_target_image="$(printf '%s\n' "$completed_evidence" | sed -n '12s/^target_image=//p')"
    printf '%s\n' "$completed_target_image" | grep -Ex '^sha256:[0-9a-f]{64}$' >/dev/null || return 1
    [ "$completed_target_image" = "$expected_target_image" ] || return 1
    printf '%s\n' "$completed_evidence" | sed -n '13p' | grep -Ex '^roles_sha256=[0-9a-f]{64}$' >/dev/null || return 1
    printf '%s\n' "$completed_evidence" | sed -n '14p' | grep -Ex '^schema_sha256=[0-9a-f]{64}$' >/dev/null || return 1
    printf '%s\n' "$completed_evidence" | sed -n '15p' | grep -Ex '^data_sha256=[0-9a-f]{64}$' >/dev/null || return 1
    printf '%s' "$completed_target_image"
}
