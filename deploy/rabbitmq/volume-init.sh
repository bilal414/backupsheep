#!/bin/sh
# Create/verify the stock broker volume ownership witness without root privileges.
set -eu
umask 077

data_dir=/var/lib/rabbitmq
witness="${data_dir}/.backupsheep-volume-identity"
pending="${witness}.pending"
temporary_prefix="${pending}.tmp."
mode="${1:-verify}"
installation_id="${BACKUPSHEEP_INSTALLATION_ID:-}"
data_generation="${BACKUPSHEEP_RABBITMQ_DATA_GENERATION:-}"
node_host="${BACKUPSHEEP_RABBITMQ_NODE_HOST:-}"
transition_target="${2:-}"
expected_uid=100
expected_gid=101
allow_stale_pid=false
allow_missing_shutdown_marker=false

valid_node_host() {
    [ "$1" = rabbitmq ] || printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{12}$'
}

valid_metadata_mode() {
    [ "$1" = 600 ] || [ "$1" = 644 ]
}

valid_node_host "$node_host" \
    || { printf '%s\n' 'RabbitMQ durable node host is invalid.' >&2; exit 1; }

invalid_installation_id="$(printf '%s' "$installation_id" | tr -d '0-9a-f')"
[ "${#installation_id}" -eq 64 ] && [ -z "$invalid_installation_id" ] \
    || { printf '%s\n' 'RabbitMQ volume installation identity is malformed.' >&2; exit 1; }
case "$mode" in
    init)
        [ "$#" -eq 1 ] && [ "$data_generation" = '4.3' ] \
            || { printf '%s\n' 'RabbitMQ volume data generation is not attested as 4.3.' >&2; exit 1; }
        ;;
    finalize-transition)
        [ "$#" -eq 1 ] && [ "$data_generation" = '4.3' ] \
            || { printf '%s\n' 'RabbitMQ transition finalization requires the attested 4.3 generation.' >&2; exit 1; }
        ;;
    verify)
        { [ "$#" -eq 0 ] || [ "$#" -eq 1 ]; } && [ "$data_generation" = '4.3' ] \
            || { printf '%s\n' 'RabbitMQ volume data generation is not attested as 4.3.' >&2; exit 1; }
        ;;
    resume)
        [ "$#" -eq 1 ] && [ "$data_generation" = '4.3' ] \
            || { printf '%s\n' 'RabbitMQ volume witness resume requires the attested 4.3 generation.' >&2; exit 1; }
        ;;
    transition)
        [ "$#" -eq 2 ] && [ "$data_generation" = 'unattested' ] \
            && { [ "$transition_target" = '3.13' ] || [ "$transition_target" = '4.2' ] || [ "$transition_target" = '4.3' ]; } \
            || { printf '%s\n' 'RabbitMQ volume transition state is invalid.' >&2; exit 1; }
        if [ "$transition_target" = '3.13' ]; then
            expected_uid=999
            expected_gid=999
        fi
        ;;
    recover)
        [ "$#" -eq 2 ] && [ "$data_generation" = 'unattested' ] \
            && { [ "$transition_target" = '3.13' ] || [ "$transition_target" = '4.2' ] || [ "$transition_target" = '4.3' ]; } \
            || { printf '%s\n' 'RabbitMQ same-version recovery state is invalid.' >&2; exit 1; }
        if [ "$transition_target" = '3.13' ]; then
            expected_uid=999
            expected_gid=999
        fi
        allow_stale_pid=true
        allow_missing_shutdown_marker=true
        ;;
    inspect-legacy)
        [ "$#" -eq 1 ] && [ "$data_generation" = 'unattested' ] \
            || { printf '%s\n' 'RabbitMQ legacy inspection requires the exact unattested generation state.' >&2; exit 1; }
        expected_uid=999
        expected_gid=999
        ;;
    inspect-clean)
        [ "$#" -eq 2 ] && [ "$data_generation" = 'unattested' ] \
            && { [ "$transition_target" = '3.13' ] || [ "$transition_target" = '4.2' ] || [ "$transition_target" = '4.3' ]; } \
            || { printf '%s\n' 'RabbitMQ clean source inspection state is invalid.' >&2; exit 1; }
        if [ "$transition_target" = '3.13' ]; then
            expected_uid=999
            expected_gid=999
        fi
        ;;
    *) exit 1 ;;
esac

[ -d "$data_dir" ] && [ ! -L "$data_dir" ] \
    || { printf '%s\n' 'RabbitMQ data mount is unavailable.' >&2; exit 1; }
[ "$(stat -c '%u:%g' "$data_dir")" = "${expected_uid}:${expected_gid}" ] \
    || { printf '%s\n' "RabbitMQ data mount is not owned by uid ${expected_uid} gid ${expected_gid}." >&2; exit 1; }
unexpected_owner="$(find "$data_dir" -xdev \( ! -user "$expected_uid" -o ! -group "$expected_gid" \) -print -quit)"
[ -z "$unexpected_owner" ] \
    || { printf '%s\n' "RabbitMQ data contains an entry outside uid ${expected_uid} gid ${expected_gid}." >&2; exit 1; }
unexpected_link="$(find "$data_dir" -xdev -type l -print -quit)"
[ -z "$unexpected_link" ] \
    || { printf '%s\n' 'RabbitMQ data contains an unreviewed symbolic link.' >&2; exit 1; }
unexpected_type="$(find "$data_dir" -xdev ! -type d ! -type f -print -quit)"
[ -z "$unexpected_type" ] \
    || { printf '%s\n' 'RabbitMQ data contains a special file type.' >&2; exit 1; }
if ! find "$data_dir" -xdev -type f -exec sh -ceu '
    for entry do
        [ "$(stat -c %h "$entry")" = 1 ] || exit 1
    done
' sh {} +; then
    printf '%s\n' 'RabbitMQ data contains a hard-linked regular file.' >&2
    exit 1
fi
unexpected_writable="$(find "$data_dir" -xdev ! -path "$data_dir" -perm /022 -print -quit)"
if [ -n "$unexpected_writable" ]; then
    printf '%s\n' 'RabbitMQ data contains a group/world-writable entry.' >&2
    exit 1
fi

validate_node_identity_layout() {
    node="rabbit@${node_host}"
    mnesia="${data_dir}/mnesia"
    node_dir="${mnesia}/${node}"
    feature_flags="${mnesia}/${node}-feature_flags"
    plugins_expand="${mnesia}/${node}-plugins-expand"
    cookie="${data_dir}/.erlang.cookie"

    node_directory_count=0
    discovered_node=""
    for candidate in "${mnesia}"/rabbit@*; do
        [ -e "$candidate" ] || [ -L "$candidate" ] || continue
        candidate_name="$(basename -- "$candidate")"
        case "$candidate_name" in
            "$node"|"${node}-feature_flags"|"${node}-plugins-expand") ;;
            "${node}.pid")
                [ "$allow_stale_pid" = true ] \
                    || { printf '%s\n' 'RabbitMQ data contains broker PID residue outside recovery mode.' >&2; return 1; }
                ;;
            *) printf '%s\n' 'RabbitMQ data contains a foreign or stale node-associated entry.' >&2; return 1 ;;
        esac
        [ -d "$candidate" ] && [ ! -L "$candidate" ] || continue
        case "$candidate_name" in
            *-plugins-expand) continue ;;
        esac
        node_directory_count=$((node_directory_count + 1))
        discovered_node="$candidate_name"
    done
    [ "$node_directory_count" -eq 1 ] && [ "$discovered_node" = "$node" ] \
        || { printf '%s\n' 'RabbitMQ data must contain exactly one unambiguous configured node database.' >&2; return 1; }

    [ -d "$mnesia" ] && [ ! -L "$mnesia" ] \
        && [ -d "$node_dir" ] && [ ! -L "$node_dir" ] \
        && [ -d "$plugins_expand" ] && [ ! -L "$plugins_expand" ] \
        || { printf '%s\n' 'RabbitMQ data does not contain the configured durable node layout.' >&2; return 1; }
    [ -f "$feature_flags" ] && [ ! -L "$feature_flags" ] && [ -s "$feature_flags" ] \
        && [ "$(stat -c '%u:%g %h' "$feature_flags")" = "${expected_uid}:${expected_gid} 1" ] \
        && valid_metadata_mode "$(stat -c '%a' "$feature_flags")" \
        || { printf '%s\n' 'RabbitMQ durable node feature-flag metadata is invalid.' >&2; return 1; }
    [ -f "$cookie" ] && [ ! -L "$cookie" ] \
        && [ "$(stat -c '%u:%g %a %h %s' "$cookie")" = "${expected_uid}:${expected_gid} 400 1 20" ] \
        || { printf '%s\n' 'RabbitMQ durable node cookie metadata is invalid.' >&2; return 1; }
    pid_file="${mnesia}/${node}.pid"
    if [ -e "$pid_file" ] || [ -L "$pid_file" ]; then
        [ "$allow_stale_pid" = true ] \
            && [ -f "$pid_file" ] && [ ! -L "$pid_file" ] \
            && [ "$(stat -c '%u:%g %h %s' "$pid_file")" = "${expected_uid}:${expected_gid} 1 1" ] \
            && valid_metadata_mode "$(stat -c '%a' "$pid_file")" \
            && printf '1' | cmp -s "$pid_file" - \
            || { printf '%s\n' 'RabbitMQ durable node PID residue is not the exact recoverable PID 1 marker.' >&2; return 1; }
    fi
}

validate_legacy_node_layout() {
    node="rabbit@${node_host}"
    node_dir="${data_dir}/mnesia/${node}"
    [ -f "${node_dir}/node-type.txt" ] && [ ! -L "${node_dir}/node-type.txt" ] \
        && [ "$(stat -c '%u:%g %h' "${node_dir}/node-type.txt")" = "${expected_uid}:${expected_gid} 1" ] \
        && valid_metadata_mode "$(stat -c '%a' "${node_dir}/node-type.txt")" \
        && printf 'disc.\n' | cmp -s "${node_dir}/node-type.txt" - \
        || { printf '%s\n' 'RabbitMQ durable node type marker is invalid.' >&2; return 1; }
    [ -f "${node_dir}/cluster_nodes.config" ] && [ ! -L "${node_dir}/cluster_nodes.config" ] \
        && [ "$(stat -c '%u:%g %h' "${node_dir}/cluster_nodes.config")" = "${expected_uid}:${expected_gid} 1" ] \
        && valid_metadata_mode "$(stat -c '%a' "${node_dir}/cluster_nodes.config")" \
        && printf '{[%s],[%s]}.\n' "$node" "$node" | cmp -s "${node_dir}/cluster_nodes.config" - \
        || { printf '%s\n' 'RabbitMQ durable node cluster marker is not the exact single-node layout.' >&2; return 1; }
    shutdown_marker="${node_dir}/nodes_running_at_shutdown"
    if [ -e "$shutdown_marker" ] || [ -L "$shutdown_marker" ]; then
        [ -f "$shutdown_marker" ] && [ ! -L "$shutdown_marker" ] \
            && [ "$(stat -c '%u:%g %h' "$shutdown_marker")" = "${expected_uid}:${expected_gid} 1" ] \
            && valid_metadata_mode "$(stat -c '%a' "$shutdown_marker")" \
            && printf '[%s].\n' "$node" | cmp -s "$shutdown_marker" - \
            || { printf '%s\n' 'RabbitMQ durable node shutdown marker is invalid.' >&2; return 1; }
    else
        [ "$allow_missing_shutdown_marker" = true ] \
            || { printf '%s\n' 'RabbitMQ durable node shutdown marker is missing.' >&2; return 1; }
    fi
}

validate_khepri_node_layout() {
    node="rabbit@${node_host}"
    node_dir="${data_dir}/mnesia/${node}"
    quorum_dir="${node_dir}/quorum/${node}"
    coordination_dir="${node_dir}/coordination/${node}"

    for legacy_path in \
        "${node_dir}/node-type.txt" \
        "${node_dir}/cluster_nodes.config" \
        "${node_dir}/nodes_running_at_shutdown" \
        "${node_dir}/schema.DAT" \
        "${node_dir}/rabbit_durable_exchange.DCD" \
        "${node_dir}/rabbit_durable_queue.DCD" \
        "${node_dir}/rabbit_durable_route.DCD" \
        "${node_dir}/rabbit_runtime_parameters.DCD" \
        "${node_dir}/rabbit_topic_permission.DCD" \
        "${node_dir}/rabbit_user.DCD" \
        "${node_dir}/rabbit_user_permission.DCD" \
        "${node_dir}/rabbit_vhost.DCD"; do
        [ ! -e "$legacy_path" ] && [ ! -L "$legacy_path" ] \
            || { printf '%s\n' 'RabbitMQ Khepri data contains a partial legacy metadata layout.' >&2; return 1; }
    done

    # Enabling Khepri on the supported 4.2 hop deliberately removes the legacy
    # Mnesia node, cluster, shutdown, schema, and DCD markers.  Bind the next
    # hop to the exact durable Ra stores that replace those markers instead of
    # treating their expected removal as an empty/fresh node.
    for khepri_dir in "$quorum_dir" "$coordination_dir"; do
        [ -d "$khepri_dir" ] && [ ! -L "$khepri_dir" ] \
            || { printf '%s\n' 'RabbitMQ Khepri data does not contain the configured durable Ra node.' >&2; return 1; }
        for khepri_file in meta.dets names.dets; do
            khepri_path="${khepri_dir}/${khepri_file}"
            [ -f "$khepri_path" ] && [ ! -L "$khepri_path" ] && [ -s "$khepri_path" ] \
                && [ "$(stat -c '%u:%g %h' "$khepri_path")" = "${expected_uid}:${expected_gid} 1" ] \
                && valid_metadata_mode "$(stat -c '%a' "$khepri_path")" \
                || { printf '%s\n' "RabbitMQ Khepri ${khepri_file} metadata is invalid." >&2; return 1; }
        done
    done
}

validate_legacy_mnesia_schema() {
    node_dir="${data_dir}/mnesia/rabbit@${node_host}"
    [ -f "${node_dir}/schema.DAT" ] && [ ! -L "${node_dir}/schema.DAT" ] \
        && [ -s "${node_dir}/schema.DAT" ] \
        && [ "$(stat -c '%u:%g %h' "${node_dir}/schema.DAT")" = "${expected_uid}:${expected_gid} 1" ] \
        && valid_metadata_mode "$(stat -c '%a' "${node_dir}/schema.DAT")" \
        || { printf '%s\n' 'RabbitMQ durable node schema metadata is invalid.' >&2; return 1; }
    for table in \
        rabbit_durable_exchange rabbit_durable_queue rabbit_durable_route \
        rabbit_runtime_parameters rabbit_topic_permission rabbit_user \
        rabbit_user_permission rabbit_vhost; do
        table_path="${node_dir}/${table}.DCD"
        [ -f "$table_path" ] && [ ! -L "$table_path" ] && [ -s "$table_path" ] \
            && [ "$(stat -c '%u:%g %h' "$table_path")" = "${expected_uid}:${expected_gid} 1" ] \
            && valid_metadata_mode "$(stat -c '%a' "$table_path")" \
            || { printf '%s\n' "RabbitMQ durable node table ${table} is invalid." >&2; return 1; }
    done
}

if [ "$mode" = inspect-legacy ]; then
    validate_node_identity_layout
    validate_legacy_node_layout
    validate_legacy_mnesia_schema
    printf '%s\n' "$node_host"
    exit 0
fi

if [ "$mode" = inspect-clean ]; then
    validate_node_identity_layout
    if [ "$transition_target" = 3.13 ]; then
        validate_legacy_node_layout
        validate_legacy_mnesia_schema
    elif [ "$transition_target" = 4.2 ]; then
        # This version is used twice: after the ownership-only 3.13 source
        # conversion (legacy layout) and after a clean 4.2/Khepri shutdown.
        # Classify by the authoritative legacy node marker and require one
        # complete, known layout rather than accepting a partial hybrid.
        if [ -e "${data_dir}/mnesia/rabbit@${node_host}/node-type.txt" ] \
            || [ -L "${data_dir}/mnesia/rabbit@${node_host}/node-type.txt" ]; then
            validate_legacy_node_layout
            validate_legacy_mnesia_schema
        else
            validate_khepri_node_layout
        fi
    else
        validate_khepri_node_layout
    fi
    if [ "$transition_target" != 4.3 ]; then
        printf '%s\n' "$node_host"
        exit 0
    fi
fi

if [ "$mode" = transition ]; then
    # Bind every compatibility hop to the exact historical node host. Without
    # this gate RabbitMQ can silently create a fresh Mnesia tree beside the real
    # one when an old container-ID hostname is not retained.
    validate_node_identity_layout
    if [ "$transition_target" = 3.13 ] || [ "$transition_target" = 4.2 ]; then
        validate_legacy_node_layout
    fi
    if [ "$transition_target" = 3.13 ]; then
        validate_legacy_mnesia_schema
    elif [ "$transition_target" = 4.3 ]; then
        validate_khepri_node_layout
    fi
fi

if [ "$mode" = recover ]; then
    # This mode is reachable only through the wrapper's protected transition
    # ledger and an exact same-version recovery model.  An absent PID covers a
    # crash before the broker wrote it; otherwise only the genuine non-root
    # RabbitMQ PID 1 marker observed on the pinned images is admitted.
    validate_node_identity_layout
    if [ "$transition_target" = 3.13 ]; then
        validate_legacy_node_layout
        validate_legacy_mnesia_schema
    elif [ "$transition_target" = 4.2 ]; then
        if [ -e "${data_dir}/mnesia/rabbit@${node_host}/node-type.txt" ] \
            || [ -L "${data_dir}/mnesia/rabbit@${node_host}/node-type.txt" ]; then
            validate_legacy_node_layout
            validate_legacy_mnesia_schema
        else
            validate_khepri_node_layout
        fi
    else
        validate_khepri_node_layout
    fi
fi

# A kill can leave only a private, non-authoritative staging file.  Reconcile
# those exact names before classifying broker data; they are never promoted on a
# later run.  Fixed .pending remains authoritative and follows the stricter
# validation/recovery rules below.
temporary_count=0
temporary_removed=false
for temporary in "${temporary_prefix}"*; do
    [ -e "$temporary" ] || [ -L "$temporary" ] || continue
    temporary_base="$(basename -- "$temporary")"
    printf '%s\n' "$temporary_base" \
        | grep -Eq '^\.backupsheep-volume-identity\.pending\.tmp\.[A-Za-z0-9]{6}$' \
        || { printf '%s\n' 'RabbitMQ volume contains a noncanonical witness staging name.' >&2; exit 1; }
    temporary_count=$((temporary_count + 1))
    [ "$temporary_count" -le 8 ] \
        || { printf '%s\n' 'RabbitMQ volume contains too many witness staging residues.' >&2; exit 1; }
    [ -f "$temporary" ] && [ ! -L "$temporary" ] \
        && [ "$(stat -c '%u:%g %a %h' "$temporary")" = '100:101 600 1' ] \
        || { printf '%s\n' 'RabbitMQ witness staging residue metadata drifted.' >&2; exit 1; }
    temporary_size="$(stat -c '%s' "$temporary")"
    case "$temporary_size" in
        ''|*[!0-9]*) printf '%s\n' 'RabbitMQ witness staging residue size is invalid.' >&2; exit 1 ;;
    esac
    [ "$temporary_size" -le 4096 ] \
        || { printf '%s\n' 'RabbitMQ witness staging residue is too large.' >&2; exit 1; }
    rm -f -- "$temporary" \
        || { printf '%s\n' 'RabbitMQ witness staging residue could not be removed.' >&2; exit 1; }
    temporary_removed=true
done
if [ "$temporary_removed" = true ]; then
    sync
fi

expected="version=2
installation_id=${installation_id}
data_generation=4.3
node_host=${node_host}
uid=100
gid=101"

legacy_expected="version=1
installation_id=${installation_id}
data_generation=4.3
uid=100
gid=101"

has_exact_witness_bytes() {
    # Command substitution strips every trailing newline, so comparing `cat`
    # output to $expected cannot distinguish zero, one, or many final newlines.
    # Feed the canonical bytes directly to cmp and require exactly one newline.
    printf '%s\n' "$expected" | cmp -s "$1" -
}

has_exact_legacy_witness_bytes() {
    printf '%s\n' "$legacy_expected" | cmp -s "$1" -
}

non_witness_entry="$(find "$data_dir" -xdev -mindepth 1 -maxdepth 1 \
    ! -name '.backupsheep-volume-identity' \
    ! -name '.backupsheep-volume-identity.pending' \
    ! -name '.backupsheep-volume-identity.pending.tmp.*' -print -quit)"

stage_pending_witness() {
    temporary="$(mktemp "${temporary_prefix}XXXXXX")" \
        || { printf '%s\n' 'RabbitMQ witness staging file could not be allocated.' >&2; return 1; }
    chmod 0600 "$temporary" \
        || { rm -f -- "$temporary"; printf '%s\n' 'RabbitMQ witness staging file could not be protected.' >&2; return 1; }
    printf '%s\n' "$expected" > "$temporary" \
        || { rm -f -- "$temporary"; printf '%s\n' 'RabbitMQ witness staging bytes could not be written.' >&2; return 1; }
    # Persist complete bytes under a non-authoritative name, then publish the
    # fixed pending record atomically. A crash can leave only an exact pending
    # record or a safely disposable unique staging residue.
    sync \
        || { rm -f -- "$temporary"; printf '%s\n' 'RabbitMQ witness staging bytes could not be flushed.' >&2; return 1; }
    mv "$temporary" "$pending" \
        || { rm -f -- "$temporary"; printf '%s\n' 'RabbitMQ pending witness could not be published.' >&2; return 1; }
    sync \
        || { printf '%s\n' 'RabbitMQ pending witness publication could not be flushed.' >&2; return 1; }
}

validate_final_witness() {
    [ -f "$witness" ] && [ ! -L "$witness" ] \
        || { printf '%s\n' 'RabbitMQ volume identity witness is missing.' >&2; return 1; }
    [ "$(stat -c '%u:%g %a %h' "$witness")" = '100:101 600 1' ] \
        || { printf '%s\n' 'RabbitMQ volume identity witness metadata drifted.' >&2; return 1; }
    if has_exact_witness_bytes "$witness"; then
        return 0
    fi
    if has_exact_legacy_witness_bytes "$witness"; then
        # Version 1 did not serialize the durable node host. Preserve upgrade
        # compatibility only when the nonempty broker tree itself proves the
        # configured single-node Khepri identity before RabbitMQ can start.
        [ -n "$non_witness_entry" ] \
            && validate_node_identity_layout \
            && validate_khepri_node_layout \
            || { printf '%s\n' 'RabbitMQ legacy volume witness is not bound by an exact durable node tree.' >&2; return 1; }
        return 0
    fi
    printf '%s\n' 'RabbitMQ volume identity witness belongs to another installation, generation, or node host.' >&2
    return 1
}

validate_pending_witness() {
    [ -f "$pending" ] && [ ! -L "$pending" ] \
        || { printf '%s\n' 'RabbitMQ pending volume identity witness is missing.' >&2; return 1; }
    [ "$(stat -c '%u:%g %a %h' "$pending")" = '100:101 600 1' ] \
        || { printf '%s\n' 'RabbitMQ pending volume identity witness metadata drifted.' >&2; return 1; }
    has_exact_witness_bytes "$pending" \
        || { printf '%s\n' 'RabbitMQ pending volume identity witness is invalid.' >&2; return 1; }
}

if [ "$mode" = inspect-clean ]; then
    [ "$transition_target" = 4.3 ] \
        || { printf '%s\n' 'RabbitMQ clean source inspection target is inconsistent.' >&2; exit 1; }
    [ "$(stat -c '%u:%g %a' "$data_dir")" = '100:101 700' ] \
        || { printf '%s\n' 'RabbitMQ clean 4.3 source data permissions are invalid.' >&2; exit 1; }
    if [ -e "$witness" ] || [ -L "$witness" ]; then
        [ ! -e "$pending" ] && [ ! -L "$pending" ] \
            || { printf '%s\n' 'RabbitMQ clean 4.3 source has both final and pending witnesses.' >&2; exit 1; }
        validate_final_witness
    elif [ -e "$pending" ] || [ -L "$pending" ]; then
        validate_pending_witness
    fi
    printf '%s\n' "$node_host"
    exit 0
fi

if [ "$mode" = recover ]; then
    [ -n "$non_witness_entry" ] \
        || { printf '%s\n' 'RabbitMQ same-version recovery refuses an empty data volume.' >&2; exit 1; }
    recovery_root="$(stat -c '%u:%g %a' "$data_dir")"
    case "$recovery_root" in
        "${expected_uid}:${expected_gid} 700") ;;
        "999:999 1777")
            # The pinned 3.13 image leaves the named-volume root at the
            # official image's 01777 seed mode, including after SIGKILL.  At
            # this point every descendant owner, type, link, write bit, node
            # marker, schema file, and optional PID-1 residue has already been
            # proven exact, and the wrapper has proven the volume detached.
            [ "$transition_target" = 3.13 ] \
                || { printf '%s\n' 'RabbitMQ same-version recovery refuses an unexpected permissive root.' >&2; exit 1; }
            chmod 0700 "$data_dir"
            sync
            ;;
        *) printf '%s\n' 'RabbitMQ same-version recovery data permissions are invalid.' >&2; exit 1 ;;
    esac
    if [ "$transition_target" = 3.13 ] || [ "$transition_target" = 4.2 ]; then
        [ ! -e "$witness" ] && [ ! -L "$witness" ] \
            && [ ! -e "$pending" ] && [ ! -L "$pending" ] \
            || { printf '%s\n' 'RabbitMQ legacy same-version recovery refuses a 4.3 volume witness.' >&2; exit 1; }
    elif [ -e "$witness" ] || [ -L "$witness" ]; then
        [ ! -e "$pending" ] && [ ! -L "$pending" ] \
            || { printf '%s\n' 'RabbitMQ same-version recovery found both final and pending witnesses.' >&2; exit 1; }
        validate_final_witness
    elif [ -e "$pending" ] || [ -L "$pending" ]; then
        validate_pending_witness
    fi
    printf '%s\n' "RabbitMQ unattested ${transition_target} same-version recovery mount verified."
    exit 0
fi

if [ "$mode" = transition ]; then
    [ -n "$non_witness_entry" ] \
        || { printf '%s\n' 'RabbitMQ transition refuses an empty data volume.' >&2; exit 1; }
    [ ! -e "$pending" ] && [ ! -L "$pending" ] \
        || { printf '%s\n' 'RabbitMQ volume witness has an interrupted pending write.' >&2; exit 1; }
    if [ "$transition_target" = 3.13 ] || [ "$transition_target" = 4.2 ]; then
        [ ! -e "$witness" ] && [ ! -L "$witness" ] \
            || { printf '%s\n' 'RabbitMQ 4.2 transition refuses an already-finalized volume witness.' >&2; exit 1; }
    elif [ -e "$witness" ] || [ -L "$witness" ]; then
        validate_final_witness
    fi
    chmod 0700 "$data_dir"
    printf '%s\n' "RabbitMQ unattested ${transition_target} transition mount verified."
    exit 0
fi

if [ "$mode" = resume ]; then
    # This path exists only for a crash after init durably wrote the complete
    # pending record but before its rename. It never manufactures a witness from
    # absence and therefore cannot replace the required healthy-4.3 attestation.
    if [ ! -e "$witness" ] && [ ! -L "$witness" ]; then
        validate_pending_witness
        mv "$pending" "$witness"
    else
        [ ! -e "$pending" ] && [ ! -L "$pending" ] \
            || { printf '%s\n' 'RabbitMQ volume identity has both final and pending records.' >&2; exit 1; }
    fi
    # Flush either the resumed rename or an uncertain pre-crash final rename.
    sync
fi

if [ "$mode" = init ] || [ "$mode" = finalize-transition ]; then
    if [ "$mode" = finalize-transition ]; then
        [ -n "$non_witness_entry" ] \
            || { printf '%s\n' 'RabbitMQ transition finalization refuses an empty data volume.' >&2; exit 1; }
    elif [ ! -e "$witness" ] && [ ! -L "$witness" ]; then
        [ -z "$non_witness_entry" ] \
            || { printf '%s\n' 'RabbitMQ fresh initialization refuses a nonempty data volume without a witness.' >&2; exit 1; }
    fi
    # The official image seeds a fresh named-volume root as 01777. Tighten it
    # only after proving that this mode is allowed to create/promote a witness.
    chmod 0700 "$data_dir"
    if [ ! -e "$witness" ] && [ ! -L "$witness" ]; then
        if [ -e "$pending" ] || [ -L "$pending" ]; then
            if ! validate_pending_witness; then
                # Older releases wrote directly to the fixed pending name. A
                # kill could therefore leave zero/partial bytes. Fresh init is
                # safe only on an otherwise empty volume; transition finalizing
                # is authorized only after the protected host ledger attested a
                # healthy 4.3 target. In either case, never promote bad bytes.
                rm -f -- "$pending" \
                    || { printf '%s\n' 'RabbitMQ invalid pending witness could not be reconciled.' >&2; exit 1; }
                sync
                stage_pending_witness
            fi
        else
            stage_pending_witness
        fi
        mv "$pending" "$witness"
        # Persist the directory rename before the wrapper can commit .env.
        sync
    fi
    # Re-flush an exact pre-existing final record as well. This closes the crash
    # window where the rename reached cache but its directory sync did not.
    sync
fi

[ ! -e "$pending" ] && [ ! -L "$pending" ] \
    || { printf '%s\n' 'RabbitMQ volume witness has an interrupted pending write.' >&2; exit 1; }
validate_final_witness
[ "$(stat -c '%u:%g %a' "$data_dir")" = '100:101 700' ] \
    || { printf '%s\n' 'RabbitMQ data mount permissions drifted.' >&2; exit 1; }
if [ -n "$non_witness_entry" ]; then
    # Every steady restart proves the configured host against the one existing
    # Khepri node tree. A changed/missing environment value must never make the
    # broker create a fresh database beside retained backup work.
    validate_node_identity_layout
    validate_khepri_node_layout
fi

printf '%s\n' 'RabbitMQ volume ownership generation 4.3 verified.'
