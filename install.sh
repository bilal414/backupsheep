#!/bin/bash
# BackupSheep Docker installer.
#
# This script deliberately does not provision or reconfigure the host. The operator is
# responsible for installing Git, Docker Engine and the Docker Compose plugin, granting
# the invoking identity access to the intended Docker daemon, and configuring host
# security.
#
# Download this file from the same immutable commit passed with --ref. The installer
# verifies that its own bytes match that commit before it builds or starts anything.

# Never permit inherited shell tracing to disclose generated root keys or any
# other installation secret. Debugging must use the installer's bounded logs.
set +x
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
# Security grammars and byte-length checks must not inherit locale-specific
# collation, where ranges such as [a-z] can also match uppercase/accented bytes.
export LC_ALL=C
# Even a help/refusal path must not resolve utilities through a caller-controlled
# privileged PATH. The non-root command lookup behavior remains unchanged.
if (( EUID == 0 )); then
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
fi

readonly REPOSITORY_URL="https://github.com/bilal414/backupsheep.git"
readonly APP_PORT="8000"
readonly POSTGRES_STORAGE_GENERATION="18-alpine-icu-v1"
readonly POSTGRES_STORAGE_LOGICAL_VOLUME="postgres_data_v1"
readonly -a CORE_SERVICES=(db rabbitmq-volume-init rabbitmq rabbitmq-provision staging-provision db-provision migrate db-seal preflight app-egress-guard app)
readonly -a OPERATION_SERVICES=(
    worker-cloud
    worker-database
    worker-files
    worker-storage
    worker-logs
    beat
)
readonly -a OPERATION_WORKER_SERVICES=(
    worker-cloud
    worker-database
    worker-files
    worker-storage
    worker-logs
)
readonly -a OPERATION_GUARD_SERVICES=(
    cloud-egress-guard
    database-egress-guard
    files-egress-guard
    storage-egress-guard
    logs-egress-guard
)
readonly -a SECRET_NAMES=(
    django_secret_key
    db_bootstrap_password
    db_migrator_password
    db_app_password
    db_preflight_password
    db_beat_password
    db_cloud_password
    db_database_password
    db_files_password
    db_storage_password
    db_logs_password
    rabbitmq_bootstrap_password
    rabbitmq_app_password
    rabbitmq_preflight_password
    rabbitmq_beat_password
    rabbitmq_cloud_password
    rabbitmq_database_password
    rabbitmq_files_password
    rabbitmq_storage_password
    rabbitmq_logs_password
    celery_signing_app_private_key
    celery_signing_beat_private_key
    celery_signing_cloud_private_key
    celery_signing_database_private_key
    celery_signing_files_private_key
    celery_signing_storage_private_key
    celery_signing_logs_private_key
    celery_trusted_public_keys
    onboarding_token
    ssh_managed_database_private_key
    ssh_managed_files_private_key
    artifact_local_file_database_keyring
    artifact_local_file_files_keyring
)
readonly -a LEGACY_SECRET_NAMES=(rabbitmq_password db_password ssh_managed_private_key)
readonly -a LEGACY_ARTIFACT_PROVIDER_SECRET_NAMES=(
    artifact_kms_database_aws_credentials
    artifact_kms_files_aws_credentials
)
readonly ARTIFACT_PROVIDER_ROLLBACK_NAME="artifact_provider_transition_rollback"
readonly -a DATABASE_LANES=(app preflight beat cloud database files storage logs)
readonly -a RABBITMQ_ROLES=(bootstrap app preflight beat cloud database files storage logs)
readonly -a CELERY_SIGNING_LANES=(app beat cloud database files storage logs)
readonly -a EGRESS_ROLES=(APP CLOUD DATABASE FILES STORAGE LOGS)
readonly -a CELERY_ROTATION_SECRET_NAMES=(
    .celery_rotation_app_private_key
    .celery_rotation_beat_private_key
    .celery_rotation_cloud_private_key
    .celery_rotation_database_private_key
    .celery_rotation_files_private_key
    .celery_rotation_storage_private_key
    .celery_rotation_logs_private_key
    .celery_rotation_trusted_public_keys
)

default_install_dir() {
    if [[ -n "${XDG_DATA_HOME:-}" && "${XDG_DATA_HOME}" == /* ]]; then
        printf '%s/backupsheep' "${XDG_DATA_HOME%/}"
    elif [[ -n "${HOME:-}" && "${HOME}" == /* ]]; then
        printf '%s/.local/share/backupsheep' "${HOME%/}"
    else
        printf '%s/backupsheep' "$PWD"
    fi
}

INSTALL_REF=""
IMAGE_MODE="local-build"
IMAGE_MODE_WAS_EXPLICIT=false
RELEASE_TAG=""
INSTALL_DIR="$(default_install_dir)"
INSTALL_DIR_WAS_EXPLICIT=false
PUBLIC_HOST="localhost"
PROJECT_NAME="backupsheep"
PROJECT_NAME_WAS_EXPLICIT=false
ALLOW_ROOT_INSTALL=false
ADOPT_LEGACY_PROJECT=""
APPROVED_COMPOSE_FILE=""
SKIP_START=false
ENABLE_OPERATIONS=false
MIGRATE_DATABASE_IDENTITIES=false
MIGRATE_RABBITMQ_IDENTITIES=false
ROTATE_CELERY_SIGNING_KEYS=false
MIGRATE_STAGING_LAYOUT=false
MIGRATE_EGRESS_POLICY=false
MIGRATE_POSTGRES_RUNTIME=false
MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=false
ARTIFACT_LOCAL_FILE_ROTATE_LANE=""
ARTIFACT_LOCAL_FILE_ROTATE_EXPECTED_KEY_ID=""
INSTALL_WAS_PRESENT=false
ENV_WAS_PRESENT=false
FRESH_CONFIG_PENDING=false
ENV_FILE=""
SECRETS_DIR=""
APP_DOMAIN=""
SCRIPT_PATH=""
STAGING_DIR=""
GIT_BIN=""
DOCKER_BIN=""
MUTATION_LOCK_DIR=""
MUTATION_LOCK_OWNER_FILE=""
MUTATION_LOCK_TOKEN=""
MUTATION_LOCK_HELD=false
POSTGRES_MIGRATION_REQUIRED=false
POSTGRES_SOURCE_IMAGE_ID=""
INSTALL_PARENT_IDENTITY=""
INSTALL_ROOT_IDENTITY=""
INSTALL_PARENT_ANCESTOR_IDENTITY=""
INSTALL_ANCESTOR_IDENTITY=""
ACTIVE_PID=""
ACTIVE_OUTPUT_FILE=""

log() {
    printf '\n==> %s\n' "$*"
}

warn() {
    printf '\nWARNING: %s\n' "$*" >&2
}

die() {
    printf '\nERROR: %s\n' "$*" >&2
    exit 1
}

valid_compose_project_name() {
    local value="$1"
    local LC_ALL=C
    [[ "$value" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]
}

usage() {
    cat <<'EOF'
Install BackupSheep into an existing Docker environment without changing the host.

Usage:
  install.sh --ref COMMIT [options]

Required:
  --ref COMMIT       Exact 40-character Git commit to install. Branches, tags and
                     abbreviated commits are intentionally rejected.

Image source:
  (default)          Build the three BackupSheep images locally from --ref.
  --local-build      Explicitly select the default local-build mode.
  --release-tag TAG  Consume only the signed official image digests for this exact
                     v-prefixed SemVer tag. TAG and the signed descriptor must bind
                     to --ref. No host package is installed.

Options:
  --domain HOST       Accepted/public hostname or IPv4 address (default: localhost).
                      The listener remains on 127.0.0.1:8000.
  --install-dir PATH  Installation directory (default: $XDG_DATA_HOME/backupsheep or
                      $HOME/.local/share/backupsheep; root mode: /opt/backupsheep).
  --allow-root-install
                     Explicitly allow effective UID 0 to create and manage a root-owned
                     installation for an existing rootful Docker daemon. Root remains
                     refused without this flag; non-root callers cannot use it.
  --project-name NAME Fixed Compose project name (default: backupsheep).
  --adopt-legacy-project NAME
                     One-time, explicit adoption of the exact four-volume stock
                     legacy project left by `compose down`; creates only the
                     installation-identity sentinel before normal validation.
  --approved-compose-file PATH
                     Accept only the private regular deployment override at
                     INSTALL_DIR/docker-compose.override.yml in canonical order.
  --enable-operations After the core is healthy, explicitly start the provider workers
                      and scheduler in the Compose "operations" profile.
  --migrate-database-identities
                     Explicitly convert a legacy stock database superuser into the
                     database-only bootstrap identity and generate separate migrator
                     plus per-lane runtime credentials. Required once for an existing
                     install.
  --migrate-rabbitmq-identities
                     Explicitly retire the legacy shared broker login, generate
                     per-lane file credentials and Ed25519 task-signing keys, and
                     enable the one-shot permission reconciler. Required once for
                     an existing install.
  --rotate-celery-signing-keys
                     Explicit generation-3 task-auth upgrade/key rotation. Requires
                     a running owned broker with empty queues after database recovery,
                     and every app/worker/Beat container stopped.
  --migrate-staging-layout
                     One-time authorization to adopt an existing install only when
                     the legacy shared work volume is empty and every new lane volume
                     passes the fail-closed ownership witness.
  --migrate-egress-policy
                     One-time authorization to replace the old stock public/blank
                     egress policy with generation 2 deny-by-default exact TCP tuples.
                     Customized legacy policy must first be reviewed and reset to deny.
  --migrate-postgres-runtime
                     One-time stop-the-world logical migration from the exact retained
                     Debian/UID-999 `pgdata` volume into the distinct Alpine/UID-70/ICU
                     storage generation. The old volume remains detached for rollback.
  --migrate-artifact-key-provider-empty
                     One-time fail-closed transition from a blank, local-development,
                     or historical provider only when the current migration proves zero
                     data-key wraps, plaintext artifact ledgers, and historical database/
                     files backup or storage-point rows. Operations remain disabled and
                     the old policy, credentials, and archive data stay in the encrypted
                     rollback set through deployment acceptance.
  --rotate-artifact-keyring LANE
                     Atomically add a new active 256-bit key to the existing database
                     or files keyring while retaining every legacy key for recovery.
                     Requires --expected-artifact-active-key-id as a stale/replay
                     witness. The matching source worker must be stopped.
  --expected-artifact-active-key-id ID
                     Exact current lfk-... active ID required for keyring rotation.
                     A repeated or stale rotation command fails without mutation.
  --skip-start        Create and validate the installation, but do not build or start it.
  -h, --help          Show this help.

Secure acquisition example (replace COMMIT with a reviewed release commit):
  COMMIT='<40-character-release-commit>'
  curl -fSLo install.sh \
    "https://raw.githubusercontent.com/bilal414/backupsheep/${COMMIT}/install.sh"
  chmod 700 install.sh
  ./install.sh --ref "${COMMIT}" --domain backups.example.com

Do not pipe a remote script to a shell. The default mode uses the same unprivileged
identity already authorized for the intended Docker daemon. Rootful-daemon mode requires
a root-owned installer in a protected directory and the explicit --allow-root-install
flag; it never changes Docker groups, daemon settings, or container user identities.
For that mode, first place this reviewed installer in a root-owned protected directory.
The resulting root-owned backupsheep-compose wrapper must also run as UID 0 with
--allow-root-install as its first argument on every invocation. Use a root login
environment (for example sudo -H) so HOME and any Docker credential/TLS directories are
also protected and root-owned.
EOF
}

cleanup_installer_resources() {
    local cleanup_failed=false
    local output_file="${ACTIVE_OUTPUT_FILE:-}"

    ACTIVE_OUTPUT_FILE=""
    if [[ -n "$output_file" && -f "$output_file" && ! -L "$output_file" \
          && "$(basename -- "$output_file")" == .backupsheep-command.* \
          && "$(file_uid "$output_file" 2>/dev/null || true)" == "$EUID" \
          && "$(file_links "$output_file" 2>/dev/null || true)" == "1" ]]; then
        rm -f -- "$output_file" || cleanup_failed=true
    elif [[ -n "$output_file" && ( -e "$output_file" || -L "$output_file" ) ]]; then
        warn "Refusing to remove unattested command-output path: ${output_file}"
        cleanup_failed=true
    fi
    if [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]]; then
        case "$(basename -- "$STAGING_DIR")" in
            .backupsheep-install.*)
                if [[ ! -L "$STAGING_DIR" \
                      && "$(file_uid "$STAGING_DIR" 2>/dev/null || true)" == "$EUID" \
                      && "$(file_mode "$STAGING_DIR" 2>/dev/null || true)" == "700" ]]; then
                    rm -rf -- "$STAGING_DIR" || cleanup_failed=true
                else
                    warn "Refusing to remove unattested staging directory: ${STAGING_DIR}"
                    cleanup_failed=true
                fi
                ;;
            *)
                warn "Refusing to remove unexpected staging path: ${STAGING_DIR}"
                cleanup_failed=true
                ;;
        esac
    fi
    release_mutation_lock || cleanup_failed=true
    [[ "$cleanup_failed" == false ]]
}

cleanup() {
    local original_status=$?
    trap - HUP INT TERM EXIT
    cleanup_installer_resources || {
        [[ "$original_status" -ne 0 ]] || original_status=74
    }
    exit "$original_status"
}

terminate_active_installer_group() {
    local pid="${ACTIVE_PID:-}" grace=0 own_pgid=""
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || { ACTIVE_PID=""; return 0; }
    own_pgid="$(ps -o pgid= -p $$ 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$pid" == "$own_pgid" ]]; then
        warn "Refusing to signal the installer's own process group."
        ACTIVE_PID=""
        return 1
    fi
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    while kill -0 -- "-$pid" 2>/dev/null && (( grace < 5 )); do
        sleep 1
        grace=$((grace + 1))
    done
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    ACTIVE_PID=""
}

handle_installer_signal() {
    local interrupted_status="$1"
    trap - HUP INT TERM EXIT
    terminate_active_installer_group || true
    cleanup_installer_resources >/dev/null 2>&1 || true
    exit "$interrupted_status"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

file_uid() {
    stat -c '%u' -- "$1" 2>/dev/null || stat -f '%u' -- "$1"
}

file_mode() {
    stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1"
}

file_links() {
    stat -c '%h' -- "$1" 2>/dev/null || stat -f '%l' -- "$1"
}

file_size() {
    stat -c '%s' -- "$1" 2>/dev/null || stat -f '%z' -- "$1"
}

file_identity() {
    stat -c '%d:%i:%s:%h:%u:%a' -- "$1" 2>/dev/null \
        || stat -f '%d:%i:%z:%l:%u:%Lp' -- "$1"
}

file_inode_identity() {
    stat -c '%d:%i' -- "$1" 2>/dev/null || stat -f '%d:%i' -- "$1"
}

directory_inode_identity() {
    stat -c '%d:%i' -- "$1" 2>/dev/null || stat -f '%d:%i' -- "$1"
}

validate_installation_ancestor_chain() {
    local current="$1" parent="" owner="" mode=""
    while :; do
        [[ -d "$current" && ! -L "$current" ]] \
            || die "Installation path ancestor must be a real directory: ${current}."
        owner="$(file_uid "$current")"
        mode="$(file_mode "$current")"
        [[ "$owner" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{3,4}$ ]] \
            || die "Could not attest installation path ancestor ${current}."
        if (( EUID == 0 )); then
            (( 10#$owner == 0 )) \
                || die "A root invocation requires every installation path ancestor to be root-owned: ${current}."
        else
            (( 10#$owner == EUID || 10#$owner == 0 )) \
                || die "Installation path ancestor is owned by an unrelated account: ${current}."
        fi
        if (( (8#$mode & 8#022) != 0 )); then
            (( (8#$mode & 8#1000) != 0 && 10#$owner == 0 )) \
                || die "Installation path ancestor is attacker-writable without a root-owned sticky boundary: ${current}."
        fi
        [[ "$current" == / ]] && break
        parent="$(dirname -- "$current")"
        [[ "$parent" != "$current" ]] || die "Could not walk installation path ancestors."
        current="$parent"
    done
}

installation_ancestor_snapshot() {
    local current="$1" parent="" identity="" owner="" mode=""
    while :; do
        [[ -d "$current" && ! -L "$current" ]] || return 1
        identity="$(directory_inode_identity "$current")" || return 1
        owner="$(file_uid "$current")" || return 1
        mode="$(file_mode "$current")" || return 1
        [[ "$identity" =~ ^[0-9]+:[0-9]+$ && "$owner" =~ ^[0-9]+$ \
            && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        printf '%s|%s|%s|%s\n' "$current" "$identity" "$owner" "$mode"
        [[ "$current" == / ]] && break
        parent="$(dirname -- "$current")"
        [[ "$parent" != "$current" ]] || return 1
        current="$parent"
    done
}

assert_install_parent_ancestor_identity() {
    local parent_dir="" current_snapshot=""
    parent_dir="$(dirname -- "$INSTALL_DIR")"
    current_snapshot="$(installation_ancestor_snapshot "$parent_dir")" \
        || die "Could not re-attest the installation parent ancestor chain."
    [[ "$current_snapshot" == "$INSTALL_PARENT_ANCESTOR_IDENTITY" ]] \
        || die "Installation parent ancestor identity or permissions changed during validation."
}

assert_install_ancestor_identity() {
    local current_snapshot=""
    current_snapshot="$(installation_ancestor_snapshot "$INSTALL_DIR")" \
        || die "Could not re-attest the full installation path ancestor chain."
    [[ "$current_snapshot" == "$INSTALL_ANCESTOR_IDENTITY" ]] \
        || die "Installation path ancestor identity or permissions changed during validation."
}

assert_install_parent_identity() {
    local parent_dir="$(dirname -- "$INSTALL_DIR")"
    [[ -d "$parent_dir" && ! -L "$parent_dir" \
        && "$(directory_inode_identity "$parent_dir")" == "$INSTALL_PARENT_IDENTITY" ]] \
        || die "Installation parent identity changed during validation."
    assert_install_parent_ancestor_identity
}

assert_install_root_identity() {
    [[ -d "$INSTALL_DIR" && ! -L "$INSTALL_DIR" \
        && "$(directory_inode_identity "$INSTALL_DIR")" == "$INSTALL_ROOT_IDENTITY" ]] \
        || die "Installation directory identity changed during validation."
    assert_install_ancestor_identity
}

release_mutation_lock() {
    local release_failed=false

    [[ "$MUTATION_LOCK_HELD" == true ]] || return 0
    if [[ ! -d "$MUTATION_LOCK_DIR" || -L "$MUTATION_LOCK_DIR" \
          || "$(file_uid "$MUTATION_LOCK_DIR")" != "$EUID" \
          || "$(file_mode "$MUTATION_LOCK_DIR")" != "700" \
          || ! -f "$MUTATION_LOCK_OWNER_FILE" || -L "$MUTATION_LOCK_OWNER_FILE" \
          || "$(file_uid "$MUTATION_LOCK_OWNER_FILE")" != "$EUID" \
          || "$(file_mode "$MUTATION_LOCK_OWNER_FILE")" != "600" \
          || "$(file_links "$MUTATION_LOCK_OWNER_FILE")" != "1" \
          || "$(<"$MUTATION_LOCK_OWNER_FILE")" != "$MUTATION_LOCK_TOKEN" ]]; then
        release_failed=true
    elif ! rm -f -- "$MUTATION_LOCK_OWNER_FILE" \
        || ! rmdir -- "$MUTATION_LOCK_DIR"; then
        release_failed=true
    fi
    MUTATION_LOCK_HELD=false
    if [[ "$release_failed" == true ]]; then
        warn "The mutation lock could not be released safely; inspect ${MUTATION_LOCK_DIR} before another mutation."
        return 1
    fi
    return 0
}

acquire_installation_mutation_lock() {
    MUTATION_LOCK_DIR="${INSTALL_DIR}.backupsheep-mutation-lock"
    MUTATION_LOCK_OWNER_FILE="${MUTATION_LOCK_DIR}/owner"
    if ! mkdir "$MUTATION_LOCK_DIR" 2>/dev/null; then
        die "Another installer/wrapper mutation is active, or a stale fail-closed lock remains at ${MUTATION_LOCK_DIR}. Verify that no BackupSheep mutation is running before removing that exact lock manually."
    fi
    MUTATION_LOCK_HELD=true
    trap cleanup EXIT
    trap 'handle_installer_signal 129' HUP
    trap 'handle_installer_signal 130' INT
    trap 'handle_installer_signal 143' TERM
    MUTATION_LOCK_TOKEN="version=1;tool=install.sh;pid=$$;uid=${EUID}"
    chmod 0700 "$MUTATION_LOCK_DIR" \
        || die "Could not protect the new mutation lock directory."
    if ! printf '%s\n' "$MUTATION_LOCK_TOKEN" > "$MUTATION_LOCK_OWNER_FILE" \
        || ! chmod 0600 "$MUTATION_LOCK_OWNER_FILE"; then
        die "Could not publish the mutation-lock ownership witness."
    fi
    [[ -d "$MUTATION_LOCK_DIR" && ! -L "$MUTATION_LOCK_DIR" \
        && "$(file_uid "$MUTATION_LOCK_DIR")" == "$EUID" \
        && "$(file_mode "$MUTATION_LOCK_DIR")" == "700" \
        && -f "$MUTATION_LOCK_OWNER_FILE" && ! -L "$MUTATION_LOCK_OWNER_FILE" \
        && "$(file_uid "$MUTATION_LOCK_OWNER_FILE")" == "$EUID" \
        && "$(file_mode "$MUTATION_LOCK_OWNER_FILE")" == "600" \
        && "$(file_links "$MUTATION_LOCK_OWNER_FILE")" == "1" \
        && "$(<"$MUTATION_LOCK_OWNER_FILE")" == "$MUTATION_LOCK_TOKEN" ]] \
        || die "The new mutation-lock ownership witness failed validation."
}

run_installer_command() {
    local timeout_seconds="$1" label="$2"
    local elapsed=0 status=0 child_pgid="" child_state="" own_pgid="" had_monitor=false
    shift 2
    [[ "$timeout_seconds" =~ ^[1-9][0-9]{0,4}$ ]] \
        || die "Invalid timeout for ${label}."
    [[ $# -gt 0 ]] || die "No command was provided for ${label}."
    case "$-" in *m*) had_monitor=true ;; esac
    set -m
    "$@" &
    ACTIVE_PID=$!
    [[ "$had_monitor" == true ]] || set +m
    child_pgid="$(ps -o pgid= -p "$ACTIVE_PID" 2>/dev/null | tr -d '[:space:]' || true)"
    own_pgid="$(ps -o pgid= -p $$ 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$child_pgid" != "$ACTIVE_PID" || "$child_pgid" == "$own_pgid" ]]; then
        child_state="$(ps -o stat= -p "$ACTIVE_PID" 2>/dev/null | tr -d '[:space:]' || true)"
        if ! kill -0 "$ACTIVE_PID" 2>/dev/null || [[ -z "$child_state" || "$child_state" == Z* ]]; then
            if wait "$ACTIVE_PID"; then status=0; else status=$?; fi
            ACTIVE_PID=""
            return "$status"
        fi
        terminate_active_installer_group || true
        die "Could not isolate ${label} in a dedicated process group."
    fi
    while kill -0 -- "-$ACTIVE_PID" 2>/dev/null && (( elapsed < timeout_seconds )); do
        sleep 1
        elapsed=$((elapsed + 1))
    done
    if kill -0 -- "-$ACTIVE_PID" 2>/dev/null; then
        warn "${label} exceeded its ${timeout_seconds}-second wall-clock deadline."
        terminate_active_installer_group || true
        return 124
    fi
    if wait "$ACTIVE_PID"; then status=0; else status=$?; fi
    ACTIVE_PID=""
    return "$status"
}

run_installer_capture() {
    local timeout_seconds="$1" label="$2" target_name="$3" output_file="" status=0
    shift 3
    [[ "$target_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] \
        || die "Invalid capture target for ${label}."
    output_file="$(mktemp "$(dirname -- "$INSTALL_DIR")/.backupsheep-command.XXXXXXXX")" \
        || die "Could not allocate protected output for ${label}."
    chmod 0600 "$output_file" || die "Could not protect output for ${label}."
    ACTIVE_OUTPUT_FILE="$output_file"
    run_installer_command "$timeout_seconds" "$label" "$@" >"$output_file" || status=$?
    if [[ "$status" -eq 0 ]]; then
        [[ -f "$output_file" && ! -L "$output_file" \
            && "$(file_uid "$output_file")" == "$EUID" \
            && "$(file_mode "$output_file")" == "600" \
            && "$(file_links "$output_file")" == "1" \
            && "$(file_size "$output_file")" -le 65536 ]] \
            || die "Captured output for ${label} failed validation."
        printf -v "$target_name" '%s' "$(<"$output_file")"
    fi
    rm -f -- "$output_file" || die "Could not remove captured output for ${label}."
    ACTIVE_OUTPUT_FILE=""
    return "$status"
}

atomic_move_new() {
    local source_path="$1"
    local destination_path="$2"

    [[ -e "$source_path" && ! -e "$destination_path" && ! -L "$destination_path" ]] \
        || return 1
    if mv --no-target-directory -- "$source_path" "$destination_path" 2>/dev/null; then
        return 0
    fi
    # BSD mv does not provide --no-target-directory. The parent directories used by
    # the installer are owner-only, so this guarded fallback retains the no-clobber
    # property against other users on Docker Desktop hosts.
    [[ -e "$source_path" && ! -e "$destination_path" && ! -L "$destination_path" ]] \
        || return 1
    mv -- "$source_path" "$destination_path"
}

atomic_publish_new_file() {
    local source_path="$1"
    local destination_path="$2"

    [[ -f "$source_path" && ! -L "$source_path" \
        && ! -e "$destination_path" && ! -L "$destination_path" ]] \
        || return 1
    # link(2) is an atomic no-clobber publication. The installer creates these
    # temporary files beside their destination, so both names are guaranteed to
    # be on one filesystem. A concurrent creator wins or loses cleanly; it can
    # never be overwritten by this publication.
    ln -- "$source_path" "$destination_path" 2>/dev/null || return 1
    if rm -f -- "$source_path"; then
        return 0
    fi
    rm -f -- "$destination_path" 2>/dev/null || true
    return 1
}

semver_at_least() {
    local actual="${1#v}"
    local required="$2"
    local actual_major=""
    local actual_minor=""
    local actual_patch=""
    local required_major=""
    local required_minor=""
    local required_patch=""
    local actual_suffix=""
    local component=""

    [[ "$actual" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)([-+][0-9A-Za-z.-]+)?$ ]] \
        || return 2
    actual_major="${BASH_REMATCH[1]}"
    actual_minor="${BASH_REMATCH[2]}"
    actual_patch="${BASH_REMATCH[3]}"
    actual_suffix="${BASH_REMATCH[4]:-}"
    [[ "$required" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 2
    required_major="${BASH_REMATCH[1]}"
    required_minor="${BASH_REMATCH[2]}"
    required_patch="${BASH_REMATCH[3]}"

    for component in major minor patch; do
        local actual_value="actual_${component}"
        local required_value="required_${component}"
        if (( 10#${!actual_value} > 10#${!required_value} )); then
            return 0
        fi
        if (( 10#${!actual_value} < 10#${!required_value} )); then
            return 1
        fi
    done
    [[ "$actual_suffix" != -* ]]
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ref)
                [[ $# -ge 2 ]] || die "--ref requires an exact commit"
                INSTALL_REF="$2"
                shift 2
                ;;
            --branch)
                die "Mutable branches and tags are not accepted. Use --ref with the exact 40-character commit."
                ;;
            --local-build)
                [[ "$IMAGE_MODE_WAS_EXPLICIT" != true ]] \
                    || die "the image-source mode may be specified only once"
                IMAGE_MODE="local-build"
                IMAGE_MODE_WAS_EXPLICIT=true
                shift
                ;;
            --release-tag)
                [[ $# -ge 2 ]] || die "--release-tag requires an exact v-prefixed SemVer tag"
                [[ "$IMAGE_MODE_WAS_EXPLICIT" != true ]] \
                    || die "the image-source mode may be specified only once"
                IMAGE_MODE="signed-release"
                IMAGE_MODE_WAS_EXPLICIT=true
                RELEASE_TAG="$2"
                shift 2
                ;;
            --domain)
                [[ $# -ge 2 ]] || die "--domain requires a hostname or IPv4 address"
                PUBLIC_HOST="$2"
                shift 2
                ;;
            --install-dir)
                [[ $# -ge 2 ]] || die "--install-dir requires an absolute path"
                INSTALL_DIR="$2"
                INSTALL_DIR_WAS_EXPLICIT=true
                shift 2
                ;;
            --allow-root-install)
                [[ "$ALLOW_ROOT_INSTALL" != true ]] \
                    || die "--allow-root-install may be specified only once"
                ALLOW_ROOT_INSTALL=true
                shift
                ;;
            --project-name)
                [[ $# -ge 2 ]] || die "--project-name requires a value"
                [[ "$PROJECT_NAME_WAS_EXPLICIT" != true ]] \
                    || die "--project-name may be specified only once"
                PROJECT_NAME="$2"
                PROJECT_NAME_WAS_EXPLICIT=true
                shift 2
                ;;
            --adopt-legacy-project)
                [[ $# -ge 2 ]] || die "--adopt-legacy-project requires a value"
                [[ -z "$ADOPT_LEGACY_PROJECT" ]] \
                    || die "--adopt-legacy-project may be specified only once"
                ADOPT_LEGACY_PROJECT="$2"
                shift 2
                ;;
            --approved-compose-file)
                [[ $# -ge 2 ]] || die "--approved-compose-file requires a path"
                [[ -z "$APPROVED_COMPOSE_FILE" ]] \
                    || die "--approved-compose-file may be specified only once"
                APPROVED_COMPOSE_FILE="$2"
                shift 2
                ;;
            --approved-compose-file=*)
                [[ -z "$APPROVED_COMPOSE_FILE" ]] \
                    || die "--approved-compose-file may be specified only once"
                APPROVED_COMPOSE_FILE="${1#*=}"
                shift
                ;;
            --enable-operations)
                ENABLE_OPERATIONS=true
                shift
                ;;
            --migrate-database-identities)
                MIGRATE_DATABASE_IDENTITIES=true
                shift
                ;;
            --migrate-rabbitmq-identities)
                MIGRATE_RABBITMQ_IDENTITIES=true
                shift
                ;;
            --rotate-celery-signing-keys)
                ROTATE_CELERY_SIGNING_KEYS=true
                shift
                ;;
            --migrate-staging-layout)
                MIGRATE_STAGING_LAYOUT=true
                shift
                ;;
            --migrate-egress-policy)
                MIGRATE_EGRESS_POLICY=true
                shift
                ;;
            --migrate-postgres-runtime)
                MIGRATE_POSTGRES_RUNTIME=true
                shift
                ;;
            --migrate-artifact-key-provider-empty)
                [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" != true ]] \
                    || die "--migrate-artifact-key-provider-empty may be specified only once"
                MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY=true
                shift
                ;;
            --rotate-artifact-keyring)
                [[ $# -ge 2 ]] || die "--rotate-artifact-keyring requires database or files"
                [[ -z "$ARTIFACT_LOCAL_FILE_ROTATE_LANE" ]] \
                    || die "--rotate-artifact-keyring may be specified only once"
                ARTIFACT_LOCAL_FILE_ROTATE_LANE="$2"
                shift 2
                ;;
            --expected-artifact-active-key-id)
                [[ $# -ge 2 ]] || die "--expected-artifact-active-key-id requires an lfk-... key ID"
                [[ -z "$ARTIFACT_LOCAL_FILE_ROTATE_EXPECTED_KEY_ID" ]] \
                    || die "--expected-artifact-active-key-id may be specified only once"
                ARTIFACT_LOCAL_FILE_ROTATE_EXPECTED_KEY_ID="$2"
                shift 2
                ;;
            --skip-start)
                SKIP_START=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1 (run with --help for usage)"
                ;;
        esac
    done

    [[ "$SKIP_START" != true || "$ENABLE_OPERATIONS" != true ]] \
        || die "--skip-start and --enable-operations cannot be used together"
    [[ "$IMAGE_MODE" == "local-build" || "$IMAGE_MODE" == "signed-release" ]] \
        || die "unsupported image-source mode"
    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        [[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] \
            || die "--release-tag must be an exact v-prefixed SemVer tag"
    else
        [[ -z "$RELEASE_TAG" ]] || die "a release tag is valid only in signed-release mode"
    fi
    [[ "$ROTATE_CELERY_SIGNING_KEYS" != true || "$ENABLE_OPERATIONS" != true ]] \
        || die "--rotate-celery-signing-keys and --enable-operations cannot be used together"
    [[ -z "$ARTIFACT_LOCAL_FILE_ROTATE_LANE" || "$ARTIFACT_LOCAL_FILE_ROTATE_LANE" == database \
        || "$ARTIFACT_LOCAL_FILE_ROTATE_LANE" == files ]] \
        || die "--rotate-artifact-keyring requires database or files"
    [[ -z "$ARTIFACT_LOCAL_FILE_ROTATE_LANE" || "$ENABLE_OPERATIONS" != true ]] \
        || die "--rotate-artifact-keyring and --enable-operations cannot be used together"
    [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" != true || "$ENABLE_OPERATIONS" != true ]] \
        || die "--migrate-artifact-key-provider-empty and --enable-operations cannot be used together"
    [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" != true || -z "$ARTIFACT_LOCAL_FILE_ROTATE_LANE" ]] \
        || die "artifact-provider migration and artifact-keyring rotation cannot run together"
    if [[ -n "$ARTIFACT_LOCAL_FILE_ROTATE_LANE" ]]; then
        [[ "$ARTIFACT_LOCAL_FILE_ROTATE_EXPECTED_KEY_ID" =~ ^lfk-[0-9a-f]{32}$ ]] \
            || die "--rotate-artifact-keyring requires --expected-artifact-active-key-id with the exact current lfk-... ID"
    else
        [[ -z "$ARTIFACT_LOCAL_FILE_ROTATE_EXPECTED_KEY_ID" ]] \
            || die "--expected-artifact-active-key-id requires --rotate-artifact-keyring"
    fi
    if [[ -n "$ADOPT_LEGACY_PROJECT" ]]; then
        if [[ "$PROJECT_NAME_WAS_EXPLICIT" == true && "$PROJECT_NAME" != "$ADOPT_LEGACY_PROJECT" ]]; then
            die "--project-name and --adopt-legacy-project must name the same project"
        fi
        PROJECT_NAME="$ADOPT_LEGACY_PROJECT"
    fi
    apply_install_dir_default_for_mode "$EUID"
}

apply_install_dir_default_for_mode() {
    local effective_uid="$1"

    [[ "$effective_uid" =~ ^[0-9]+$ ]] \
        || die "Internal effective UID validation failed."
    if (( 10#$effective_uid == 0 )) && [[ "$ALLOW_ROOT_INSTALL" == true \
        && "$INSTALL_DIR_WAS_EXPLICIT" != true ]]; then
        INSTALL_DIR="/opt/backupsheep"
    fi
}

root_install_mode_allowed() {
    local effective_uid="$1"
    local approved_override="$2"

    [[ "$effective_uid" =~ ^[0-9]+$ ]] || return 1
    if (( 10#$effective_uid == 0 )); then
        [[ "$approved_override" == true ]]
    else
        [[ "$approved_override" == false ]]
    fi
}

validate_invocation_mode() {
    if root_install_mode_allowed "$EUID" "$ALLOW_ROOT_INSTALL"; then
        return
    fi
    if (( EUID == 0 )); then
        die "Effective UID 0 is refused by default. Rerun with --allow-root-install only for an intentionally root-owned installation using an existing rootful Docker daemon."
    fi
    die "--allow-root-install is valid only when the effective invoking UID is 0. Omit it for the default non-root installation mode."
}

validate_privileged_runtime_environment() {
    local path=""
    local mode=""
    local variable=""

    (( EUID == 0 )) || return 0
    for variable in HOME DOCKER_CONFIG DOCKER_CERT_PATH; do
        path="${!variable-}"
        if [[ "$variable" != HOME && -z "$path" ]]; then
            continue
        fi
        [[ "$path" == /* && -d "$path" && ! -L "$path" \
            && "$(file_uid "$path")" == "$EUID" ]] \
            || die "Root installation requires ${variable} to be an absolute root-owned, non-symlink directory. Use a root login environment (for example sudo -H)."
        mode="$(file_mode "$path")"
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] \
            || die "Could not validate privileged ${variable} permissions."
        (( (8#$mode & 8#022) == 0 )) \
            || die "Root installation requires ${variable} not to be writable by group or other users."
    done
}

require_commands() {
    local command_name=""
    local -a required=(
        awk basename chmod cmp cp dirname docker env find git grep install mkdir mktemp mv od
        ln ps realpath rm rmdir sed ssh-keygen stat sync tr
    )

    for command_name in "${required[@]}"; do
        command_exists "$command_name" \
            || die "Required command '${command_name}' is unavailable. Host prerequisites are the operator's responsibility."
    done
    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        command_exists curl \
            || die "Required command 'curl' is unavailable for signed-release asset download. No host package was installed."
    fi

    GIT_BIN="$(command -v git)"
    DOCKER_BIN="$(command -v docker)"
    [[ "$GIT_BIN" == /* && "$DOCKER_BIN" == /* ]] \
        || die "Git and Docker must resolve to absolute executable paths."
}

validate_installer_source() {
    local source_path="${BASH_SOURCE[0]}"
    local source_parent=""
    local source_parent_mode=""
    local source_owner=""
    local source_mode=""
    local source_links=""

    [[ -f "$source_path" && ! -L "$source_path" ]] \
        || die "The installer must be a downloaded regular file, not a pipe, device or symlink."

    SCRIPT_PATH="$(realpath -- "$source_path")" \
        || die "Cannot resolve the installer path."
    source_owner="$(file_uid "$SCRIPT_PATH")"
    source_mode="$(file_mode "$SCRIPT_PATH")"
    source_links="$(file_links "$SCRIPT_PATH")"
    source_parent="$(dirname -- "$SCRIPT_PATH")"
    source_parent_mode="$(file_mode "$source_parent")"

    [[ "$source_owner" == "$EUID" ]] \
        || die "The installer must be owned by the effective invoking UID."
    (( (8#$source_mode & 8#022) == 0 )) \
        || die "The installer must not be writable by group or other users."
    [[ "$source_links" == "1" ]] \
        || die "The installer must not be hard-linked."
    if (( EUID == 0 )); then
        [[ -d "$source_parent" && ! -L "$source_parent" \
            && "$(file_uid "$source_parent")" == "$EUID" ]] \
            || die "A privileged installer parent directory must be root-owned and must not be a symlink."
        (( (8#$source_parent_mode & 8#022) == 0 )) \
            || die "A privileged installer parent directory must not be writable by group or other users."
    fi
}

validate_ref() {
    [[ "$INSTALL_REF" =~ ^[0-9A-Fa-f]{40}$ ]] \
        || die "--ref must be a full 40-character hexadecimal Git commit."
    INSTALL_REF="$(printf '%s' "$INSTALL_REF" | tr '[:upper:]' '[:lower:]')"
}

validate_public_host() {
    [[ "$PUBLIC_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$|^[A-Za-z0-9]$ ]] \
        || die "--domain must be a hostname or IPv4 address only (without scheme, path or port)."
    [[ "$PUBLIC_HOST" != *".."* ]] \
        || die "--domain cannot contain consecutive dots."
    APP_DOMAIN="${PUBLIC_HOST}:${APP_PORT}"
}

validate_project_name() {
    valid_compose_project_name "$PROJECT_NAME" \
        || die "--project-name must start with a lowercase letter or digit and contain only lowercase letters, digits, '_' or '-'."
    [[ -z "$ADOPT_LEGACY_PROJECT" || "$ADOPT_LEGACY_PROJECT" == "$PROJECT_NAME" ]] \
        || die "--adopt-legacy-project must match the validated Compose project name."
}

validate_install_dir() {
    local parent_dir=""
    local parent_owner=""
    local parent_mode=""
    local existing_ancestor=""
    local unresolved_suffix=""
    local path_component=""
    local physical_ancestor=""
    local install_path_regex='^/[A-Za-z0-9._/@+ -]+$'

    [[ "$INSTALL_DIR" == /* && "$INSTALL_DIR" != "/" ]] \
        || die "--install-dir must be an absolute path other than /."
    [[ "$INSTALL_DIR" != *$'\n'* && "$INSTALL_DIR" != *$'\r'* && "$INSTALL_DIR" != *$'\t'* ]] \
        || die "--install-dir cannot contain control characters."
    [[ "$INSTALL_DIR" != *','* && "$INSTALL_DIR" != *'|'* ]] \
        || die "--install-dir cannot contain a comma or pipe because Docker mount, Compose label, and attestation grammars use them as delimiters."
    [[ "$INSTALL_DIR" =~ $install_path_regex ]] \
        || die "--install-dir contains characters outside the reviewed Docker mount and attestation grammar."

    # BSD realpath has neither GNU -m nor a portable way to canonicalize a path
    # that does not exist yet. Resolve the nearest existing ancestor physically,
    # reject a symlink at that trust boundary, and append literal components only.
    # Dot components are rejected so the unresolved suffix cannot escape its witness.
    while [[ "$INSTALL_DIR" != "/" && "$INSTALL_DIR" == */ ]]; do
        INSTALL_DIR="${INSTALL_DIR%/}"
    done
    case "/${INSTALL_DIR#/}/" in
        *"/../"*|*"/./"*) die "--install-dir cannot contain . or .. path components." ;;
    esac
    existing_ancestor="$INSTALL_DIR"
    while [[ ! -e "$existing_ancestor" && ! -L "$existing_ancestor" ]]; do
        path_component="$(basename -- "$existing_ancestor")"
        [[ -n "$path_component" && "$path_component" != "." && "$path_component" != ".." ]] \
            || die "Could not resolve --install-dir safely."
        unresolved_suffix="/${path_component}${unresolved_suffix}"
        existing_ancestor="$(dirname -- "$existing_ancestor")"
    done
    [[ -d "$existing_ancestor" && ! -L "$existing_ancestor" ]] \
        || die "The nearest existing installation ancestor must be a real directory, not a symlink."
    physical_ancestor="$(cd -P -- "$existing_ancestor" && pwd -P)" \
        || die "Could not resolve the installation directory ancestor."
    INSTALL_DIR="${physical_ancestor}${unresolved_suffix}"
    [[ "$INSTALL_DIR" != "/" ]] || die "--install-dir resolves to /."
    parent_dir="$(dirname -- "$INSTALL_DIR")"

    if [[ ! -d "$parent_dir" ]]; then
        install -d -m 0700 -- "$parent_dir" \
            || die "Cannot create installation parent directory ${parent_dir}. Choose a path writable by the effective invoking UID."
    fi
    [[ -d "$parent_dir" && ! -L "$parent_dir" ]] \
        || die "The installation parent must be a real directory, not a symlink."

    parent_owner="$(file_uid "$parent_dir")"
    parent_mode="$(file_mode "$parent_dir")"
    [[ "$parent_owner" == "$EUID" ]] \
        || die "The installation parent must be owned by the effective invoking UID: ${parent_dir}"
    (( (8#$parent_mode & 8#022) == 0 )) \
        || die "The installation parent must not be group- or world-writable: ${parent_dir}"
    validate_installation_ancestor_chain "$parent_dir"
    INSTALL_PARENT_IDENTITY="$(directory_inode_identity "$parent_dir")"
    [[ "$INSTALL_PARENT_IDENTITY" =~ ^[0-9]+:[0-9]+$ ]] \
        || die "Could not capture the installation parent identity."
    INSTALL_PARENT_ANCESTOR_IDENTITY="$(installation_ancestor_snapshot "$parent_dir")" \
        || die "Could not capture the installation parent ancestor chain."

    if [[ -e "$INSTALL_DIR" || -L "$INSTALL_DIR" ]]; then
        [[ -d "$INSTALL_DIR" && ! -L "$INSTALL_DIR" ]] \
            || die "The installation target must be a real directory, not a file or symlink."
        validate_installation_ancestor_chain "$INSTALL_DIR"
        INSTALL_ROOT_IDENTITY="$(directory_inode_identity "$INSTALL_DIR")"
        [[ "$INSTALL_ROOT_IDENTITY" =~ ^[0-9]+:[0-9]+$ ]] \
            || die "Could not capture the installation directory identity."
        INSTALL_ANCESTOR_IDENTITY="$(installation_ancestor_snapshot "$INSTALL_DIR")" \
            || die "Could not capture the full installation path ancestor chain."
        INSTALL_WAS_PRESENT=true
    fi
}

validate_approved_compose_file() {
    local expected_override="${INSTALL_DIR}/docker-compose.override.yml"
    local approved_real=""
    local mode=""

    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        [[ ! -e "$expected_override" && ! -L "$expected_override" \
            && -z "$APPROVED_COMPOSE_FILE" ]] \
            || die "Signed-release mode rejects docker-compose.override.yml; its runtime model must byte-match the signed source commit."
        return
    fi

    if [[ -e "$expected_override" || -L "$expected_override" ]]; then
        [[ -n "$APPROVED_COMPOSE_FILE" ]] \
            || die "docker-compose.override.yml exists; review it and pass --approved-compose-file with its exact path."
    else
        [[ -z "$APPROVED_COMPOSE_FILE" ]] \
            || die "--approved-compose-file is valid only when INSTALL_DIR/docker-compose.override.yml already exists."
        return
    fi

    [[ -f "$APPROVED_COMPOSE_FILE" && ! -L "$APPROVED_COMPOSE_FILE" ]] \
        || die "The approved Compose override must be a regular, non-symlink file."
    expected_override="$(realpath -- "$expected_override")" \
        || die "Could not resolve the expected Compose override."
    approved_real="$(realpath -- "$APPROVED_COMPOSE_FILE")" \
        || die "Could not resolve the approved Compose override."
    [[ "$approved_real" == "$expected_override" ]] \
        || die "--approved-compose-file accepts only ${expected_override}."
    [[ "$(file_uid "$approved_real")" == "$EUID" ]] \
        || die "The approved Compose override must be owned by the effective invoking UID."
    [[ "$(file_links "$approved_real")" == "1" ]] \
        || die "The approved Compose override must not be hard-linked."
    mode="$(file_mode "$approved_real")"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] \
        || die "Could not validate approved Compose override permissions."
    (( (8#$mode & 8#022) == 0 )) \
        || die "The approved Compose override must not be writable by group or other users."
    [[ "$(file_size "$approved_real")" -le 1048576 ]] \
        || die "The approved Compose override is unexpectedly large."
    APPROVED_COMPOSE_FILE="$approved_real"
}

validate_docker_access() {
    local engine_version=""
    local compose_version=""
    local selected_context=""

    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        [[ -z "${DOCKER_CONTEXT-}" ]] \
            || die "Signed-release mode rejects DOCKER_CONTEXT; select an exact daemon with DOCKER_HOST and reviewed TLS inputs."
        run_installer_capture 30 "Docker context selection probe" selected_context \
            "$DOCKER_BIN" context show 2>/dev/null \
            || die "Could not determine the exact Docker context used by the installer."
        [[ "$selected_context" == default || -n "${DOCKER_HOST-}" ]] \
            || die "Signed-release mode requires the default Docker context or an explicit DOCKER_HOST so every verification phase targets one daemon."
    fi

    run_installer_command 30 "Docker daemon availability probe" \
        "$DOCKER_BIN" info >/dev/null 2>&1 \
        || die "The Docker daemon is unavailable to the effective invoking UID. Install/configure Docker on the host, then retry."
    run_installer_capture 30 "Docker Engine version probe" engine_version \
        "$DOCKER_BIN" version --format '{{.Server.Version}}' 2>/dev/null \
        || die "Could not read the Docker Engine server version from the selected daemon."
    if ! semver_at_least "$engine_version" "28.0.0"; then
        die "Docker Engine 28.0.0 or newer is required by the isolated-network model (found: ${engine_version:-unparseable}). Upgrade the operator-managed Docker host, then retry."
    fi

    run_installer_capture 30 "Docker Compose version probe" compose_version \
        "$DOCKER_BIN" compose version --short 2>/dev/null \
        || die "Docker Compose is unavailable. Install the Compose plugin on the host, then retry."
    if ! semver_at_least "$compose_version" "2.33.1"; then
        die "Docker Compose 2.33.1 or newer is required for the reviewed network routing model (found: ${compose_version:-unparseable}). Upgrade the operator-managed Compose plugin, then retry."
    fi

    log "Using operator-provided Docker Engine ${engine_version} and Compose ${compose_version}; no host settings were changed"
}

git_safe() {
    local git_home="$(dirname -- "$INSTALL_DIR")/.backupsheep-git-home"

    env -i \
        HOME="$git_home" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        LANG=C \
        LC_ALL=C \
        GIT_CONFIG_NOSYSTEM=1 \
        GIT_CONFIG_GLOBAL=/dev/null \
        GIT_TERMINAL_PROMPT=0 \
        GIT_ASKPASS=/bin/false \
        SSH_ASKPASS=/bin/false \
        GIT_ALLOW_PROTOCOL=https \
        "$GIT_BIN" \
        -c core.hooksPath=/dev/null \
        -c init.templateDir=/dev/null \
        -c http.sslVerify=true \
        -c core.fsmonitor=false \
        -c core.untrackedCache=false \
        -c diff.external= \
        "$@"
}

require_regular_checkout_file() {
    local relative_path="$1"
    local absolute_path="${INSTALL_DIR}/${relative_path}"

    [[ -f "$absolute_path" && ! -L "$absolute_path" ]] \
        || die "The verified checkout is missing regular file ${relative_path}."
    git_safe -C "$INSTALL_DIR" cat-file -e "${INSTALL_REF}:${relative_path}" \
        || die "Commit ${INSTALL_REF} does not contain ${relative_path}."
}

validate_checkout_permissions() {
    local unsafe_path=""

    unsafe_path="$(find "$INSTALL_DIR" -xdev \( -type f -o -type d \) \
        \( -perm -002 -o -perm -020 \) -print -quit)"
    [[ -z "$unsafe_path" ]] \
        || die "Checkout content must not be group- or world-writable: ${unsafe_path}"

    unsafe_path="$(find "$INSTALL_DIR" -xdev ! -uid "$EUID" -print -quit)"
    [[ -z "$unsafe_path" ]] \
        || die "Checkout content must be owned by the effective invoking UID: ${unsafe_path}"

    unsafe_path="$(find "$INSTALL_DIR" -xdev -type l -print -quit)"
    [[ -z "$unsafe_path" ]] \
        || die "Symlinks are not accepted in an installer-managed checkout: ${unsafe_path}"
}

validate_checkout_cleanliness() {
    local flags=""
    local entry=""
    local status_code=""
    local relative_path=""
    local status_file=""
    local unexpected_entry=""

    git_safe -C "$INSTALL_DIR" diff --no-ext-diff --no-textconv --quiet -- \
        || die "The existing checkout has modified tracked files. Use a clean, exact release checkout."
    git_safe -C "$INSTALL_DIR" diff --cached --no-ext-diff --no-textconv --quiet -- \
        || die "The existing checkout has staged changes. Use a clean, exact release checkout."

    flags="$(git_safe -C "$INSTALL_DIR" ls-files -v | sed -n '/^[^H]/p')"
    [[ -z "$flags" ]] \
        || die "The existing checkout uses hidden assume-unchanged/skip-worktree flags. Clear them before installation."

    status_file="$(mktemp "$(dirname -- "$INSTALL_DIR")/.backupsheep-status.XXXXXXXX")"
    if ! git_safe -C "$INSTALL_DIR" status \
        --porcelain=v1 -z --untracked-files=all --ignored=matching > "$status_file"; then
        rm -f -- "$status_file"
        die "Could not inventory checkout state safely."
    fi
    while IFS= read -r -d '' entry; do
        status_code="${entry:0:2}"
        relative_path="${entry:3}"
        if [[ "$status_code" == "!!" ]] \
            && { [[ "$relative_path" == ".env" ]] \
                || [[ "$relative_path" == ".secrets/" ]] \
                || [[ "$relative_path" == .secrets/* ]] \
                || [[ "$relative_path" == ".release-evidence/" ]] \
                || [[ "$relative_path" == .release-evidence/* ]] \
                || [[ "$relative_path" =~ ^\.release-evidence\.(download|verify)\.[A-Za-z0-9]{8}/ ]] \
                || [[ "$relative_path" == ".env.image-source.new" ]] \
                || [[ "$relative_path" == ".env.fresh.new" ]] \
                || [[ "$relative_path" =~ ^\.env-(update|artifact-policy)\.[A-Za-z0-9]{8}$ ]] \
                || [[ "$relative_path" == ".release-request" ]] \
                || [[ "$relative_path" == ".release-request.new" ]] \
                || { [[ "$relative_path" == "docker-compose.override.yml" ]] \
                    && [[ "$APPROVED_COMPOSE_FILE" == "${INSTALL_DIR}/docker-compose.override.yml" ]]; }; }; then
            continue
        fi
        unexpected_entry="${status_code} ${relative_path}"
        break
    done < "$status_file"
    rm -f -- "$status_file"
    [[ -z "$unexpected_entry" ]] \
        || die "Unexpected checkout content is present (${unexpected_entry}). Remove it before installation."
}

validate_checkout() {
    local head_commit=""
    local repo_top=""
    local repo_git_dir=""
    local remote_urls=""

    [[ -d "$INSTALL_DIR/.git" && ! -L "$INSTALL_DIR/.git" ]] \
        || die "Existing target is not an installer-managed Git checkout: ${INSTALL_DIR}"

    repo_top="$(git_safe -C "$INSTALL_DIR" rev-parse --show-toplevel)"
    repo_git_dir="$(git_safe -C "$INSTALL_DIR" rev-parse --absolute-git-dir)"
    [[ "$repo_top" == "$INSTALL_DIR" && "$repo_git_dir" == "$INSTALL_DIR/.git" ]] \
        || die "The checkout worktree or Git directory points outside ${INSTALL_DIR}."

    remote_urls="$(git_safe -C "$INSTALL_DIR" remote get-url --all origin)"
    [[ "$remote_urls" == "$REPOSITORY_URL" ]] \
        || die "The checkout origin must be exactly ${REPOSITORY_URL}."

    head_commit="$(git_safe -C "$INSTALL_DIR" rev-parse --verify 'HEAD^{commit}')"
    [[ "$head_commit" == "$INSTALL_REF" ]] \
        || die "Existing checkout is ${head_commit}, not requested commit ${INSTALL_REF}. Follow the reviewed upgrade runbook; the installer never upgrades in place."

    git_safe -C "$INSTALL_DIR" fsck --strict --no-dangling >/dev/null \
        || die "Git object verification failed for ${INSTALL_DIR}."
    [[ ! -e "$INSTALL_DIR/.gitmodules" ]] \
        || die "Installer-managed releases must not depend on Git submodules."

    require_regular_checkout_file Dockerfile
    require_regular_checkout_file Dockerfile.postgres
    require_regular_checkout_file docker-compose.yml
    require_regular_checkout_file .dockerignore
    require_regular_checkout_file .env_sample
    require_regular_checkout_file install.sh
    require_regular_checkout_file backupsheep-compose
    require_regular_checkout_file deploy/release/consume-signed-release.sh
    require_regular_checkout_file deploy/release/signed-release.compose.yml
    require_regular_checkout_file deploy/release/sigstore-trusted-root.json
    require_regular_checkout_file deploy/runtime/compose-json.awk
    require_regular_checkout_file deploy/release-policy.json
    require_regular_checkout_file scripts/release_transition.py
    require_regular_checkout_file deploy/postgres/entrypoint.sh
    require_regular_checkout_file deploy/postgres/storage-witness.sh
    require_regular_checkout_file deploy/postgres/source-identity-contract.sh
    require_regular_checkout_file deploy/postgres/migrate-runtime.sh
    [[ -x "$INSTALL_DIR/backupsheep-compose" ]] \
        || die "The reviewed backupsheep-compose wrapper must remain executable."
    [[ -x "$INSTALL_DIR/deploy/release/consume-signed-release.sh" ]] \
        || die "The reviewed signed-release consumer must remain executable."

    if ! grep -Eq '^/?\.secrets/?$' "$INSTALL_DIR/.dockerignore"; then
        [[ "$(awk '/^[[:space:]]*($|#)/ { next } { print; exit }' "$INSTALL_DIR/.dockerignore")" == "**" ]] \
            || die "The reviewed .dockerignore must explicitly exclude .secrets or use a default-deny build context."
        ! grep -Eq '^![[:space:]]*/?\.secrets(/|$)' "$INSTALL_DIR/.dockerignore" \
            || die "The reviewed default-deny .dockerignore must not re-include .secrets."
    fi

    validate_checkout_cleanliness
    validate_checkout_permissions

    cmp -s -- "$SCRIPT_PATH" "$INSTALL_DIR/install.sh" \
        || die "This installer does not byte-match install.sh at commit ${INSTALL_REF}. Download it from that exact commit and retry."
}

clone_exact_commit() {
    local parent_dir=""
    local fetched_commit=""

    parent_dir="$(dirname -- "$INSTALL_DIR")"
    assert_install_parent_identity
    STAGING_DIR="$(mktemp -d "${parent_dir}/.backupsheep-install.XXXXXXXX")" \
        || die "Could not create a protected staging directory under ${parent_dir}."
    chmod 0700 "$STAGING_DIR"

    log "Fetching immutable BackupSheep commit ${INSTALL_REF}"
    git_safe -C "$STAGING_DIR" init --quiet
    git_safe -C "$STAGING_DIR" remote add origin "$REPOSITORY_URL"
    run_installer_command 300 "immutable Git fetch" git_safe \
        -C "$STAGING_DIR" \
        -c protocol.version=2 \
        -c http.lowSpeedLimit=1024 \
        -c http.lowSpeedTime=30 \
        fetch --quiet --depth=1 --no-tags origin "$INSTALL_REF" \
        || die "The immutable Git fetch failed or exceeded its wall-clock deadline."
    fetched_commit="$(git_safe -C "$STAGING_DIR" rev-parse --verify 'FETCH_HEAD^{commit}')"
    [[ "$fetched_commit" == "$INSTALL_REF" ]] \
        || die "The fetched commit (${fetched_commit}) does not match requested commit ${INSTALL_REF}."
    git_safe -C "$STAGING_DIR" checkout --quiet --detach "$INSTALL_REF"

    assert_install_parent_identity
    atomic_move_new "$STAGING_DIR" "$INSTALL_DIR" \
        || die "Could not atomically publish the verified checkout at ${INSTALL_DIR}."
    STAGING_DIR=""
    chmod 0700 "$INSTALL_DIR"
    validate_installation_ancestor_chain "$INSTALL_DIR"
    INSTALL_ROOT_IDENTITY="$(directory_inode_identity "$INSTALL_DIR")"
    [[ "$INSTALL_ROOT_IDENTITY" =~ ^[0-9]+:[0-9]+$ ]] \
        || die "Could not capture the installed checkout identity."
    INSTALL_ANCESTOR_IDENTITY="$(installation_ancestor_snapshot "$INSTALL_DIR")" \
        || die "Could not capture the installed checkout ancestor chain."
    validate_checkout
}

clone_or_validate_repository() {
    if [[ "$INSTALL_WAS_PRESENT" == true ]]; then
        assert_install_parent_identity
        assert_install_root_identity
        log "Validating existing installation at ${INSTALL_DIR}"
        validate_checkout
    else
        clone_exact_commit
    fi
    assert_install_parent_identity
    assert_install_root_identity
}

random_hex() {
    local bytes="$1"
    [[ -r /dev/urandom ]] || die "The system random source is unavailable."
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
}

validate_env_file() {
    local env_owner=""
    local env_mode=""
    local env_links=""
    local env_size=""

    [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] \
        || die "Configuration must be a regular non-symlink file: ${ENV_FILE}"
    env_owner="$(file_uid "$ENV_FILE")"
    env_mode="$(file_mode "$ENV_FILE")"
    env_links="$(file_links "$ENV_FILE")"
    env_size="$(file_size "$ENV_FILE")"
    [[ "$env_owner" == "$EUID" && "$env_mode" == "600" && "$env_links" == "1" ]] \
        || die "${ENV_FILE} must be owned by the effective invoking UID, mode 0600, and not hard-linked."
    [[ "$env_size" -le 1048576 ]] || die "${ENV_FILE} is unexpectedly large."
    if IFS= read -r -d '' _nul_probe < "$ENV_FILE"; then
        die "${ENV_FILE} contains a NUL byte."
    fi
    ! grep -q $'\r' "$ENV_FILE" || die "${ENV_FILE} contains carriage returns."

    awk '
        /^[[:space:]]*($|#)/ { next }
        $0 !~ /^[A-Za-z_][A-Za-z0-9_]*=/ { exit 2 }
        {
            key = $0
            sub(/=.*/, "", key)
            if (seen[key]++) { exit 3 }
        }
    ' "$ENV_FILE" || die "${ENV_FILE} has malformed or duplicate keys."

    ! grep -Eq '^(COMPOSE_[A-Za-z0-9_]*|BUILDX_[A-Za-z0-9_]*|BUILDKIT_[A-Za-z0-9_]*|DOCKER_BUILDKIT|DOCKER_DEFAULT_PLATFORM|DOCKER_HOST|DOCKER_CONTEXT)=' "$ENV_FILE" \
        || die "${ENV_FILE} contains a Docker/Compose control variable. Pass Docker context intentionally in the invoking shell instead."
    ! grep -Eq '^BACKUPSHEEP_SECRETS=' "$ENV_FILE" \
        || die "${ENV_FILE} contains BACKUPSHEEP_SECRETS, which can replace the complete stock configuration. Remove it before installation."
    ! grep -Eq '^(LD_AUDIT|LD_LIBRARY_PATH|LD_PRELOAD|SSLKEYLOGFILE)=' "$ENV_FILE" \
        || die "${ENV_FILE} contains a forbidden loader or TLS-key-logging variable. Remove it before installation."
}

set_env_value() {
    local key="$1"
    local value="$2"
    local temporary_file=""

    [[ "$key" =~ ^[A-Z0-9_]+$ ]] || die "Invalid environment key: ${key}"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *"'"* ]] \
        || die "Installer-managed environment values must be single-line and quote-safe."

    temporary_file="$(mktemp "${INSTALL_DIR}/.env-update.XXXXXXXX")"
    if ! awk -v key="$key" -v replacement="${key}='${value}'" '
        BEGIN { replaced = 0 }
        {
            current = $0
            sub(/=.*/, "", current)
            if (current == key) {
                if (!replaced) print replacement
                replaced = 1
                next
            }
            print
        }
        END { if (!replaced) print replacement }
    ' "$ENV_FILE" > "$temporary_file"; then
        rm -f -- "$temporary_file"
        die "Could not update ${key} in ${ENV_FILE}."
    fi
    chmod 0600 "$temporary_file"
    mv -f -- "$temporary_file" "$ENV_FILE"
}

set_env_values_atomically() {
    local contract="" key="" value="" temporary_file=""
    (( $# >= 2 && $# % 2 == 0 )) \
        || die "Atomic environment updates require key/value pairs."
    while (( $# > 0 )); do
        key="$1"
        value="$2"
        shift 2
        [[ "$key" =~ ^[A-Z0-9_]+$ ]] || die "Invalid environment key: ${key}"
        [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *"'"* \
            && "$value" != *'|'* && "$value" != *$'\034'* ]] \
            || die "Installer-managed environment values must be single-line and quote-safe."
        contract+="${key}|${value}"$'\034'
    done
    temporary_file="$(mktemp "${INSTALL_DIR}/.env-update.XXXXXXXX")"
    if ! awk -v contract="$contract" '
        BEGIN {
            count = split(contract, lines, "\034")
            for (item = 1; item <= count; item++) {
                if (lines[item] == "") continue
                separator = index(lines[item], "|")
                if (separator < 2) exit 90
                key = substr(lines[item], 1, separator - 1)
                value = substr(lines[item], separator + 1)
                if (key in replacement) exit 91
                replacement[key] = key "=\047" value "\047"
                order[++order_count] = key
            }
        }
        {
            key = $0
            sub(/=.*/, "", key)
            if (key in replacement) {
                if (!seen[key]) print replacement[key]
                seen[key] = 1
                next
            }
            print
        }
        END {
            for (item = 1; item <= order_count; item++) {
                key = order[item]
                if (!seen[key]) print replacement[key]
            }
        }
    ' "$ENV_FILE" > "$temporary_file"; then
        rm -f -- "$temporary_file"
        die "Could not prepare the atomic environment update."
    fi
    chmod 0600 "$temporary_file"
    sync || die "Could not durably stage the atomic environment update."
    mv -f -- "$temporary_file" "$ENV_FILE" \
        || die "Could not atomically publish the environment update."
    sync || die "Could not durably publish the atomic environment update."
    validate_env_file
}

set_image_source_contract_atomically() {
    local contract="$1"
    local temporary_file="${INSTALL_DIR}/.env.image-source.new"

    [[ -n "$contract" && "$contract" != *"'"* && "$contract" != *$'\r'* ]] \
        || die "Image-source contract is empty or not quote-safe."
    [[ ! -e "$temporary_file" && ! -L "$temporary_file" ]] \
        || die "An interrupted image-source contract update must be reconciled before retry."
    ( set -o noclobber; : > "$temporary_file" ) \
        || die "Could not allocate the atomic image-source contract update."
    chmod 0600 "$temporary_file"
    if ! awk -v contract="$contract" '
        BEGIN {
            count = split(contract, lines, "\034")
            for (item = 1; item <= count; item++) {
                if (lines[item] == "") continue
                separator = index(lines[item], "|")
                if (separator < 2) exit 90
                key = substr(lines[item], 1, separator - 1)
                value = substr(lines[item], separator + 1)
                if (key in replacement) exit 91
                replacement[key] = key "=\047" value "\047"
                order[++order_count] = key
            }
        }
        {
            key = $0
            sub(/=.*/, "", key)
            if (key in replacement) {
                if (!seen[key]) print replacement[key]
                seen[key] = 1
                next
            }
            print
        }
        END {
            for (item = 1; item <= order_count; item++) {
                key = order[item]
                if (!seen[key]) print replacement[key]
            }
        }
    ' "$ENV_FILE" > "$temporary_file"; then
        rm -f -- "$temporary_file"
        die "Could not prepare the atomic image-source contract update."
    fi
    chmod 0600 "$temporary_file"
    sync || die "Could not durably stage the image-source contract."
    mv -f -- "$temporary_file" "$ENV_FILE" \
        || die "Could not atomically publish the image-source contract."
    sync || die "Could not durably publish the image-source contract."
    validate_env_file
}

create_fresh_env_atomically() {
    local source="${INSTALL_DIR}/.env_sample" candidate="${INSTALL_DIR}/.env.fresh.new"
    local descriptor="${INSTALL_DIR}/.release-evidence/backupsheep-release-descriptor-v2.txt"
    local release_tag="" release_commit="" descriptor_digest=""
    local release_app="" release_postgres="" release_egress="" release_rabbitmq="" release_rabbitmq_upgrade=""
    local app_image="backupsheep:${INSTALL_REF}"
    local postgres_image="backupsheep-postgres:${INSTALL_REF}"
    local egress_image="backupsheep-egress:${INSTALL_REF}"
    local rabbitmq_image="rabbitmq:4.3.5-alpine@sha256:d07d6a0657affe0354ae61b3ca1a3e4d244c247ac5d7e25940c8759658ce7ad7"
    local rabbitmq_upgrade_image="rabbitmq:4.2.9-alpine@sha256:f093e74d14814d28e3d52e7dee5873ab8e8c2e671e9e11019654bd3443183095"
    local contract="" original_env_file="$ENV_FILE" fresh_key="" fresh_value=""
    local installation_id="" staging_witness="" postgres_witness="" artifact_witness=""

    [[ ! -e "$ENV_FILE" && ! -L "$ENV_FILE" && ! -e "$candidate" && ! -L "$candidate" ]] \
        || die "Fresh configuration publication requires absent final and candidate files."
    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        validate_release_evidence_files
        release_tag="$RELEASE_TAG"
        release_commit="$INSTALL_REF"
        descriptor_digest="sha256:$(sha256_file "$descriptor")"
        release_app="$(release_evidence_value "$descriptor" app_image)"
        release_postgres="$(release_evidence_value "$descriptor" postgres_image)"
        release_egress="$(release_evidence_value "$descriptor" egress_image)"
        release_rabbitmq="$(release_evidence_value "$descriptor" rabbitmq_image)"
        release_rabbitmq_upgrade="$(release_evidence_value "$descriptor" rabbitmq_upgrade_image)"
        app_image="$release_app"
        postgres_image="$release_postgres"
        egress_image="$release_egress"
        rabbitmq_image="$release_rabbitmq"
        rabbitmq_upgrade_image="$release_rabbitmq_upgrade"
    fi
    installation_id="$(random_hex 32)"
    staging_witness="$(sha256_text "BackupSheep/staging-layout/v3|${installation_id}|new-empty-v3")"
    postgres_witness="$(sha256_text "BackupSheep/postgres-storage/v1|${installation_id}|${PROJECT_NAME}|${POSTGRES_STORAGE_LOGICAL_VOLUME}|${POSTGRES_STORAGE_GENERATION}|icu=und|new-empty-v1")"
    artifact_witness="$(sha256_text "BackupSheep/artifact-key-provider/v1|${installation_id}|local-file|generation=1")"
    while IFS='|' read -r fresh_key fresh_value; do
        [[ "$fresh_key" =~ ^[A-Z0-9_]+$ && "$fresh_value" != *$'\n'* \
            && "$fresh_value" != *$'\r'* && "$fresh_value" != *"'"* \
            && "$fresh_value" != *'|'* && "$fresh_value" != *$'\034'* ]] \
            || die "Fresh configuration contract contains an unsafe key or value."
        contract+="${fresh_key}|${fresh_value}"$'\034'
    done <<EOF
BACKUPSHEEP_DATABASE_IDENTITY_GENERATION|3-pending-fresh
BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION|2-pending-fresh
BACKUPSHEEP_CELERY_SECURITY_GENERATION|3-pending-fresh
BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION|1
BACKUPSHEEP_INSTALLATION_BOOTSTRAP_STATE|pending-fresh
BACKUPSHEEP_INSTALLATION_ID|${installation_id}
BACKUPSHEEP_COMPOSE_PROJECT_NAME|${PROJECT_NAME}
BACKUPSHEEP_STAGING_LAYOUT_INTENT|new-empty-v3
BACKUPSHEEP_STAGING_LAYOUT_WITNESS|${staging_witness}
BACKUPSHEEP_POSTGRES_STORAGE_GENERATION|${POSTGRES_STORAGE_GENERATION}-pending-fresh
BACKUPSHEEP_POSTGRES_STORAGE_INTENT|new-empty-v1
BACKUPSHEEP_POSTGRES_STORAGE_WITNESS|${postgres_witness}
BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION|1
BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS|${artifact_witness}
BACKUPSHEEP_IMAGE_MODE|${IMAGE_MODE}
BACKUPSHEEP_RELEASE_TAG|${release_tag}
BACKUPSHEEP_RELEASE_SOURCE_COMMIT|${release_commit}
BACKUPSHEEP_RELEASE_DESCRIPTOR_SHA256|${descriptor_digest}
BACKUPSHEEP_RELEASE_APP_IMAGE|${release_app}
BACKUPSHEEP_RELEASE_POSTGRES_IMAGE|${release_postgres}
BACKUPSHEEP_RELEASE_EGRESS_IMAGE|${release_egress}
BACKUPSHEEP_RELEASE_RABBITMQ_IMAGE|${release_rabbitmq}
BACKUPSHEEP_RELEASE_RABBITMQ_UPGRADE_IMAGE|${release_rabbitmq_upgrade}
BACKUPSHEEP_IMAGE|${app_image}
BACKUPSHEEP_POSTGRES_IMAGE|${postgres_image}
BACKUPSHEEP_EGRESS_IMAGE|${egress_image}
BACKUPSHEEP_RABBITMQ_IMAGE|${rabbitmq_image}
BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE|${rabbitmq_upgrade_image}
DJANGO_ALLOWED_HOSTS|${PUBLIC_HOST},localhost,127.0.0.1
APP_DOMAIN|${APP_DOMAIN}
APP_PROTOCOL|http://
DJANGO_HTTPS|false
BACKUPSHEEP_BIND_ADDRESS|127.0.0.1
EOF
    ( set -o noclobber; : > "$candidate" ) \
        || die "Could not allocate the fresh configuration candidate."
    chmod 0600 "$candidate"
    if ! awk -v contract="$contract" '
        BEGIN {
            count = split(contract, lines, "\034")
            for (item = 1; item <= count; item++) {
                if (lines[item] == "") continue
                separator = index(lines[item], "|")
                if (separator < 2) exit 90
                key = substr(lines[item], 1, separator - 1)
                value = substr(lines[item], separator + 1)
                if (key in replacement) exit 91
                replacement[key] = key "=\047" value "\047"
                order[++order_count] = key
            }
        }
        {
            key = $0
            sub(/=.*/, "", key)
            if (key in replacement) {
                if (!seen[key]) print replacement[key]
                seen[key] = 1
                next
            }
            print
        }
        END {
            for (item = 1; item <= order_count; item++) {
                key = order[item]
                if (!seen[key]) print replacement[key]
            }
        }
    ' "$source" > "$candidate"; then
        rm -f -- "$candidate"
        die "Could not render the fresh configuration atomically."
    fi
    chmod 0600 "$candidate"
    ENV_FILE="$candidate"
    validate_env_file
    ENV_FILE="$original_env_file"
    sync || die "Could not durably stage the fresh configuration."
    [[ ! -e "$ENV_FILE" && ! -L "$ENV_FILE" ]] \
        || die "Fresh configuration destination appeared during publication."
    mv -- "$candidate" "$ENV_FILE" || die "Could not atomically publish fresh configuration."
    sync || die "Could not durably publish fresh configuration."
    validate_env_file
    FRESH_CONFIG_PENDING=true
}

reconcile_fresh_env_candidate() {
    local candidate="${INSTALL_DIR}/.env.fresh.new" size=""
    [[ -e "$candidate" || -L "$candidate" ]] || return 0
    [[ -f "$candidate" && ! -L "$candidate" && "$(file_uid "$candidate")" == "$EUID" \
        && "$(file_mode "$candidate")" == "600" && "$(file_links "$candidate")" == "1" ]] \
        || die "Interrupted fresh configuration candidate has an unsafe identity."
    size="$(file_size "$candidate")"
    [[ "$size" =~ ^[0-9]+$ ]] && (( 10#$size <= 1048576 )) \
        || die "Interrupted fresh configuration candidate is too large."
    if [[ -e "${INSTALL_DIR}/.env" || -L "${INSTALL_DIR}/.env" ]]; then
        ENV_FILE="${INSTALL_DIR}/.env"
        validate_env_file
    fi
    rm -f -- "$candidate" || die "Could not reconcile interrupted fresh configuration candidate."
    sync || die "Could not durably reconcile fresh configuration candidate."
}

reconcile_linked_artifact_publication_residue() {
    local entry="$1"
    local base="$2"
    local destination=""
    local expected_mode=""
    local artifact_kind=""
    local entry_identity=""
    local destination_identity=""
    local destination_inode=""

    case "$base" in
        .artifact-keyring-database.*)
            destination="$(artifact_keyring_path database)"
            expected_mode=444
            artifact_kind=database-keyring
            ;;
        .artifact-keyring-files.*)
            destination="$(artifact_keyring_path files)"
            expected_mode=444
            artifact_kind=files-keyring
            ;;
        .artifact-provider-rollback.*)
            destination="$(artifact_provider_rollback_path)"
            expected_mode=400
            artifact_kind=provider-rollback
            ;;
        *)
            die "Internal artifact publication residue classification failed."
            ;;
    esac

    [[ -f "$entry" && ! -L "$entry" && -f "$destination" && ! -L "$destination" \
        && "$(file_uid "$entry")" == "$EUID" \
        && "$(file_uid "$destination")" == "$EUID" \
        && "$(file_mode "$entry")" == "$expected_mode" \
        && "$(file_mode "$destination")" == "$expected_mode" \
        && "$(file_links "$entry")" == 2 \
        && "$(file_links "$destination")" == 2 ]] \
        || die "Interrupted artifact publication residue does not have the exact safe linked identity."
    entry_identity="$(file_identity "$entry")"
    destination_identity="$(file_identity "$destination")"
    [[ "$entry_identity" == "$destination_identity" ]] \
        || die "Interrupted artifact publication residue is not linked to its exact destination."
    destination_inode="$(file_inode_identity "$destination")"
    case "$artifact_kind" in
        database-keyring) validate_artifact_keyring_content "$entry" database ;;
        files-keyring) validate_artifact_keyring_content "$entry" files ;;
    esac

    rm -f -- "$entry" \
        || die "Could not remove the attested interrupted artifact publication name."
    [[ ! -e "$entry" && ! -L "$entry" \
        && -f "$destination" && ! -L "$destination" \
        && "$(file_inode_identity "$destination")" == "$destination_inode" \
        && "$(file_links "$destination")" == 1 ]] \
        || die "Interrupted artifact publication reconciliation changed its destination identity."
    case "$artifact_kind" in
        database-keyring) validate_secret_file "$destination" ;;
        files-keyring) validate_secret_file "$destination" ;;
        provider-rollback) validate_artifact_provider_rollback "$destination" ;;
        *) die "Internal artifact publication validation classification failed." ;;
    esac
}

reconcile_installer_temp_residues() {
    local path="" base="" entry="" count=0 size="" mode="" links=""
    for path in "${INSTALL_DIR}"/.env-update.* "${INSTALL_DIR}"/.env-artifact-policy.*; do
        [[ -e "$path" || -L "$path" ]] || continue
        base="$(basename -- "$path")"
        [[ "$base" =~ ^\.env-(update|artifact-policy)\.[A-Za-z0-9]{8}$ ]] \
            || die "Installer environment residue has a noncanonical name."
        count=$((count + 1)); (( count <= 8 )) || die "Too many installer environment residues exist."
        [[ -f "$path" && ! -L "$path" && "$(file_uid "$path")" == "$EUID" \
            && "$(file_links "$path")" == "1" ]] \
            || die "Installer environment residue has an unsafe identity."
        mode="$(file_mode "$path")"; [[ "$mode" == "600" ]] \
            || die "Installer environment residue is not owner-only."
        size="$(file_size "$path")"; [[ "$size" =~ ^[0-9]+$ ]] && (( 10#$size <= 1048576 )) \
            || die "Installer environment residue is too large."
        rm -f -- "$path" || die "Could not reconcile installer environment residue."
    done
    if [[ -d "${INSTALL_DIR}/.secrets" && ! -L "${INSTALL_DIR}/.secrets" ]]; then
        [[ "$(file_uid "${INSTALL_DIR}/.secrets")" == "$EUID" \
            && "$(file_mode "${INSTALL_DIR}/.secrets")" == "700" ]] \
            || die "Cannot reconcile an unsafe secret residue directory."
        while IFS= read -r -d '' entry; do
            base="$(basename -- "$entry")"
            case "$base" in
                .managed-key-check.*|.celery-key-check.*|.artifact-provider-rollback.*|\
                .artifact-keyring-database.*|.artifact-keyring-files.*|\
                .artifact-keyring-database-rotation.*|.artifact-keyring-files-rotation.*|\
                .django_secret_key.*|.onboarding_token.*|.rabbitmq_*_password.*|\
                .db_*_password.*|.celery_signing_*_private_key.*|\
                .ssh_managed_*_private_key.*|.artifact_local_file_*_keyring.*|\
                .celery-public.*|.celery-rotation-registry.*|.celery-activate-*.*) ;;
                *) continue ;;
            esac
            [[ "$base" =~ \.[A-Za-z0-9]{8}$ ]] \
                || die "Installer secret residue has a noncanonical name."
            count=$((count + 1)); (( count <= 64 )) || die "Too many installer residues exist."
            links="$(file_links "$entry")"
            case "$base" in
                .artifact-keyring-database.*|.artifact-keyring-files.*)
                    if [[ "$links" == 2 ]]; then
                        reconcile_linked_artifact_publication_residue "$entry" "$base"
                        continue
                    fi
                    ;;
                .artifact-provider-rollback.*)
                    if [[ "$links" == 2 ]]; then
                        reconcile_linked_artifact_publication_residue "$entry" "$base"
                        continue
                    fi
                    # preserve_artifact_provider_rollback changes its fully written,
                    # validated candidate to owner-mode 0400 before publication. A
                    # kill before link(2) leaves that exact unpublished state. Only
                    # its canonical name and bounded, owner-controlled single-link
                    # identity receive this recovery path; other 0400 residues fail.
                    if [[ "$links" == 1 && -f "$entry" && ! -L "$entry" \
                        && "$(file_uid "$entry")" == "$EUID" \
                        && "$(file_mode "$entry")" == 400 ]]; then
                        size="$(file_size "$entry")"
                        [[ "$size" =~ ^[0-9]+$ ]] \
                            && (( 10#$size > 0 && 10#$size <= 32768 )) \
                            || die "Unpublished artifact-provider rollback residue has an invalid size."
                        rm -f -- "$entry" \
                            || die "Could not reconcile unpublished artifact-provider rollback residue."
                        continue
                    fi
                    ;;
            esac
            [[ -f "$entry" && ! -L "$entry" && "$(file_uid "$entry")" == "$EUID" \
                && "$links" == "1" ]] \
                || die "Installer secret residue has an unsafe identity."
            mode="$(file_mode "$entry")"; [[ "$mode" == "600" || "$mode" == "444" ]] \
                || die "Installer secret residue has unsafe permissions."
            size="$(file_size "$entry")"; [[ "$size" =~ ^[0-9]+$ ]] && (( 10#$size <= 1048576 )) \
                || die "Installer secret residue is too large."
            rm -f -- "$entry" || die "Could not reconcile installer secret residue."
        done < <(find "${INSTALL_DIR}/.secrets" -mindepth 1 -maxdepth 1 -type f -print0)
    fi
    sync || die "Could not durably reconcile installer residues."
}

validate_release_request_witness() {
    local witness="${INSTALL_DIR}/.release-request" line1="" line2="" extra="" size=""
    [[ -f "$witness" && ! -L "$witness" && "$(file_uid "$witness")" == "$EUID" \
        && "$(file_mode "$witness")" == "600" && "$(file_links "$witness")" == "1" ]] \
        || die "Signed-release request witness has an unsafe identity."
    size="$(file_size "$witness")"
    [[ "$size" =~ ^[0-9]+$ ]] && (( 10#$size > 0 && 10#$size <= 256 )) \
        || die "Signed-release request witness has an invalid size."
    { IFS= read -r line1; IFS= read -r line2; ! IFS= read -r extra; } < "$witness" \
        || die "Signed-release request witness is not the exact two-line contract."
    [[ "$line1" == "release_tag=${RELEASE_TAG}" && "$line2" == "source_commit=${INSTALL_REF}" ]] \
        || die "Signed-release request witness does not match this exact request."
}

prepare_release_request_witness() {
    local witness="${INSTALL_DIR}/.release-request" candidate="${INSTALL_DIR}/.release-request.new"
    [[ "$IMAGE_MODE" == "signed-release" ]] || return 0
    if [[ -e "$witness" || -L "$witness" ]]; then
        validate_release_request_witness
        return
    fi
    [[ ! -e "$candidate" && ! -L "$candidate" ]] || die "Interrupted signed-release request witness must be reconciled."
    ( set -o noclobber; : > "$candidate" ) || die "Could not allocate signed-release request witness."
    chmod 0600 "$candidate"
    printf 'release_tag=%s\nsource_commit=%s\n' "$RELEASE_TAG" "$INSTALL_REF" > "$candidate"
    sync || die "Could not durably stage signed-release request witness."
    mv -- "$candidate" "$witness" || die "Could not publish signed-release request witness."
    sync || die "Could not durably publish signed-release request witness."
    validate_release_request_witness
}

reconcile_release_request_candidate() {
    local candidate="${INSTALL_DIR}/.release-request.new" size=""
    [[ -e "$candidate" || -L "$candidate" ]] || return 0
    [[ -f "$candidate" && ! -L "$candidate" && "$(file_uid "$candidate")" == "$EUID" \
        && "$(file_mode "$candidate")" == "600" && "$(file_links "$candidate")" == "1" ]] \
        || die "Interrupted signed-release request candidate has an unsafe identity."
    size="$(file_size "$candidate")"
    [[ "$size" =~ ^[0-9]+$ ]] && (( 10#$size <= 256 )) \
        || die "Interrupted signed-release request candidate is too large."
    rm -f -- "$candidate" || die "Could not reconcile interrupted signed-release request candidate."
    sync || die "Could not durably reconcile signed-release request candidate."
}

reconcile_image_source_contract_candidate() {
    local candidate="${INSTALL_DIR}/.env.image-source.new" size=""
    [[ -e "$candidate" || -L "$candidate" ]] || return 0
    ENV_FILE="${INSTALL_DIR}/.env"
    [[ -f "$candidate" && ! -L "$candidate" && "$(file_uid "$candidate")" == "$EUID" \
        && "$(file_mode "$candidate")" == "600" && "$(file_links "$candidate")" == "1" ]] \
        || die "Interrupted image-source contract candidate has an unsafe identity."
    size="$(file_size "$candidate")"
    [[ "$size" =~ ^[0-9]+$ ]] && (( 10#$size <= 1048576 )) \
        || die "Interrupted image-source contract candidate is too large."
    validate_env_file
    rm -f -- "$candidate" || die "Could not remove interrupted image-source contract candidate."
    sync || die "Could not durably reconcile the image-source contract candidate."
}

read_env_value() {
    local key="$1"
    local raw=""

    raw="$(awk -v wanted="$key" '
        {
            current = $0
            sub(/=.*/, "", current)
            if (current == wanted) {
                sub(/^[^=]*=/, "")
                print
                exit
            }
        }
    ' "$ENV_FILE")"

    if [[ "$raw" == \'*\' && "$raw" == *\' ]]; then
        raw="${raw#\'}"
        raw="${raw%\'}"
        [[ "$raw" != *"'"* ]] \
            || die "${key} uses unsupported quoting; migrate it manually before rerunning."
    elif [[ "$raw" == \"*\" && "$raw" == *\" ]]; then
        raw="${raw#\"}"
        raw="${raw%\"}"
        [[ "$raw" != *'\\'* && "$raw" != *'$'* && "$raw" != *'`'* && "$raw" != *'"'* ]] \
            || die "${key} uses unsupported interpolation/escaping; migrate it manually before rerunning."
    else
        [[ "$raw" != *[[:space:]\#\'\"\\\`\$]* ]] \
            || die "${key} must use simple unquoted text or a supported quoted value."
    fi
    printf '%s' "$raw"
}

validate_secret_dir() {
    local secret_owner=""
    local secret_mode=""
    local entry=""
    local base=""
    local allowed=false
    local expected=""

    [[ -d "$SECRETS_DIR" && ! -L "$SECRETS_DIR" ]] \
        || die "Secret storage must be a real directory: ${SECRETS_DIR}"
    secret_owner="$(file_uid "$SECRETS_DIR")"
    secret_mode="$(file_mode "$SECRETS_DIR")"
    [[ "$secret_owner" == "$EUID" && "$secret_mode" == "700" ]] \
        || die "${SECRETS_DIR} must be owned by the effective invoking UID and mode 0700."

    for entry in \
        "$SECRETS_DIR"/* \
        "$SECRETS_DIR"/.[!.]* \
        "$SECRETS_DIR"/..?*; do
        [[ -e "$entry" || -L "$entry" ]] || continue
        base="$(basename -- "$entry")"
        allowed=false
        for expected in \
            "${SECRET_NAMES[@]}" \
            "${LEGACY_SECRET_NAMES[@]}" \
            "${LEGACY_ARTIFACT_PROVIDER_SECRET_NAMES[@]}" \
            "${CELERY_ROTATION_SECRET_NAMES[@]}" \
            "$ARTIFACT_PROVIDER_ROLLBACK_NAME"; do
            if [[ "$base" == "$expected" ]]; then
                allowed=true
                break
            fi
        done
        [[ "$allowed" == true ]] \
            || die "Unexpected entry in protected secret directory: ${base}"
    done
}

validate_artifact_keyring_content() {
    local keyring_file="$1"
    local expected_lane="$2"
    local keyring_size=""
    local final_byte=""
    local active_key_id=""
    local key_id=""
    local key_hex=""
    local keyring_line=""
    local seen_ids=","
    local seen_material=","
    local installation_id=""
    local index=0
    local -a lines=()

    [[ "$expected_lane" == database || "$expected_lane" == files ]] \
        || die "Internal artifact keyring lane is invalid."
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    [[ "$installation_id" =~ ^[0-9a-f]{64}$ ]] \
        || die "The artifact keyring requires the stable installation identity."
    keyring_size="$(file_size "$keyring_file")"
    [[ "$keyring_size" -gt 0 && "$keyring_size" -le 2048 ]] \
        || die "The ${expected_lane} artifact keyring size is invalid."
    ! od -An -v -tx1 "$keyring_file" | grep -Eq '(^|[[:space:]])00([[:space:]]|$)' \
        || die "The ${expected_lane} artifact keyring contains a NUL byte."
    ! grep -q $'\r' "$keyring_file" \
        || die "The ${expected_lane} artifact keyring contains carriage returns."
    final_byte="$(tail -c 1 "$keyring_file" | od -An -tu1 | tr -d '[:space:]')"
    [[ "$final_byte" == 10 ]] \
        || die "The ${expected_lane} artifact keyring must end in one newline."
    while IFS= read -r keyring_line; do
        lines+=("$keyring_line")
    done < "$keyring_file"
    [[ "${#lines[@]}" -ge 5 && "${#lines[@]}" -le 12 ]] \
        || die "The ${expected_lane} artifact keyring must contain one to eight keys."
    [[ "${lines[0]}" == BACKUPSHEEP-ARTIFACT-KEYRING-V1 \
        && "${lines[1]}" == "installation=${installation_id}" \
        && "${lines[2]}" == "lane=${expected_lane}" \
        && "${lines[3]}" =~ ^active=(lfk-[0-9a-f]{32})$ ]] \
        || die "The ${expected_lane} artifact keyring header is invalid."
    active_key_id="${BASH_REMATCH[1]}"
    index=4
    while [[ "$index" -lt "${#lines[@]}" ]]; do
        [[ "${lines[$index]}" =~ ^key=(lfk-[0-9a-f]{32}):([0-9a-f]{64})$ ]] \
            || die "The ${expected_lane} artifact keyring contains an invalid key entry."
        key_id="${BASH_REMATCH[1]}"
        key_hex="${BASH_REMATCH[2]}"
        [[ "$seen_ids" != *",${key_id},"* && "$seen_material" != *",${key_hex},"* ]] \
            || die "The ${expected_lane} artifact keyring contains a duplicate key."
        seen_ids="${seen_ids}${key_id},"
        seen_material="${seen_material}${key_hex},"
        if [[ "$index" -eq 4 ]]; then
            [[ "$key_id" == "$active_key_id" ]] \
                || die "The ${expected_lane} active artifact key must be first."
        fi
        index=$((index + 1))
    done
    key_hex="$(printf '%064d' 0)"
    unset key_hex
}

validate_secret_file() {
    local secret_path="$1"
    local secret_owner=""
    local secret_mode=""
    local secret_links=""
    local secret_size=""
    local secret_name=""
    local secret_value=""
    local minimum_length=0

    [[ -f "$secret_path" && ! -L "$secret_path" ]] \
        || die "Secret must be a regular non-symlink file: ${secret_path}"
    secret_owner="$(file_uid "$secret_path")"
    secret_mode="$(file_mode "$secret_path")"
    secret_links="$(file_links "$secret_path")"
    secret_size="$(file_size "$secret_path")"
    [[ "$secret_owner" == "$EUID" && "$secret_mode" == "444" && "$secret_links" == "1" ]] \
        || die "${secret_path} must be owned by the effective invoking UID, mode 0444, and not hard-linked."
    secret_name="$(basename -- "$secret_path")"
    if [[ "$secret_name" == "artifact_local_file_database_keyring" ]]; then
        validate_artifact_keyring_content "$secret_path" database
        return
    fi
    if [[ "$secret_name" == "artifact_local_file_files_keyring" ]]; then
        validate_artifact_keyring_content "$secret_path" files
        return
    fi
    if [[ "$secret_name" == ssh_managed_*_private_key ]]; then
        [[ "$secret_size" -le 65536 ]] \
            || die "${secret_path} exceeds the 64 KiB managed-key limit."
        ! od -An -v -tx1 "$secret_path" | grep -Eq '(^|[[:space:]])00([[:space:]]|$)' \
            || die "${secret_path} contains a NUL byte."
        if [[ "$secret_size" -gt 0 ]]; then
            local validation_copy=""
            local public_key=""
            validation_copy="$(mktemp "${SECRETS_DIR}/.managed-key-check.XXXXXXXX")"
            cp -- "$secret_path" "$validation_copy"
            chmod 0600 "$validation_copy"
            if ! public_key="$(ssh-keygen -y -P '' -f "$validation_copy" 2>/dev/null)"; then
                rm -f -- "$validation_copy"
                die "${secret_path} is not a readable unencrypted OpenSSH private key."
            fi
            rm -f -- "$validation_copy"
            [[ "$public_key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/]+={0,3}$ ]] \
                || die "${secret_path} must contain an Ed25519 private key."
        fi
        return
    fi

    if [[ "$secret_name" == celery_signing_*_private_key \
        || "$secret_name" == .celery_rotation_*_private_key ]]; then
        local validation_copy=""
        local public_key=""
        [[ "$secret_size" -gt 100 && "$secret_size" -le 16384 ]] \
            || die "${secret_path} has an invalid Ed25519 private-key size."
        ! od -An -v -tx1 "$secret_path" | grep -Eq '(^|[[:space:]])00([[:space:]]|$)' \
            || die "${secret_path} contains a NUL byte."
        validation_copy="$(mktemp "${SECRETS_DIR}/.celery-key-check.XXXXXXXX")"
        cp -- "$secret_path" "$validation_copy"
        chmod 0600 "$validation_copy"
        if ! public_key="$(ssh-keygen -y -f "$validation_copy" 2>/dev/null)"; then
            rm -f -- "$validation_copy"
            die "${secret_path} is not a readable OpenSSH private key."
        fi
        rm -f -- "$validation_copy"
        [[ "$public_key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/]+={0,3}$ ]] \
            || die "${secret_path} must contain an Ed25519 private key."
        return
    fi

    [[ "$secret_size" -gt 0 && "$secret_size" -le 4096 ]] \
        || die "${secret_path} must contain one non-empty bounded secret value."
    awk '
        NR > 1 { exit 1 }
        { if (length($0) == 0 || index($0, "\r") != 0) exit 1 }
        END { if (NR != 1) exit 1 }
    ' "$secret_path" \
        || die "${secret_path} must contain exactly one non-empty logical line."
    ! od -An -v -tx1 "$secret_path" | grep -Eq '(^|[[:space:]])00([[:space:]]|$)' \
        || die "${secret_path} contains a NUL byte."

    secret_value="$(<"$secret_path")"
    case "$secret_name" in
        django_secret_key) minimum_length=48 ;;
        db_password|db_bootstrap_password|db_migrator_password|db_*_password) minimum_length=24 ;;
        rabbitmq_password|rabbitmq_*_password|onboarding_token) minimum_length=32 ;;
        celery_trusted_public_keys) minimum_length=100 ;;
        *) die "Unknown installation secret file: ${secret_name}" ;;
    esac
    [[ "${#secret_value}" -ge "$minimum_length" ]] \
        || die "${secret_name} is shorter than its minimum secure length (${minimum_length} characters)."
}

artifact_keyring_path() {
    local lane="$1"
    [[ "$lane" == database || "$lane" == files ]] \
        || die "Internal artifact keyring lane is invalid."
    printf '%s/artifact_local_file_%s_keyring' "$SECRETS_DIR" "$lane"
}

artifact_provider_rollback_path() {
    printf '%s/%s' "$SECRETS_DIR" "$ARTIFACT_PROVIDER_ROLLBACK_NAME"
}

validate_artifact_provider_rollback() {
    local path="${1:-}"
    local size=""
    local installation_id=""

    [[ -n "$path" ]] || path="$(artifact_provider_rollback_path)"
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    [[ "$installation_id" =~ ^[0-9a-f]{64}$ ]] \
        || die "The artifact-provider rollback requires the stable installation identity."
    [[ -f "$path" && ! -L "$path" \
        && "$(file_uid "$path")" == "$EUID" \
        && "$(file_mode "$path")" == 400 \
        && "$(file_links "$path")" == 1 ]] \
        || die "The artifact-provider transition rollback must be an owner-only mode-0400 single-link file."
    size="$(file_size "$path")"
    [[ "$size" -ge 1 && "$size" -le 32768 ]] \
        || die "The artifact-provider transition rollback has an invalid size."
    ! od -An -v -tx1 "$path" | grep -Eq '(^|[[:space:]])00([[:space:]]|$)' \
        || die "The artifact-provider transition rollback contains a NUL byte."
    ! grep -q $'\r' "$path" \
        || die "The artifact-provider transition rollback contains a carriage return."
    awk -v installation_id="$installation_id" '
        NR == 1 {
            if ($0 != "BACKUPSHEEP-ARTIFACT-PROVIDER-ROLLBACK-V1") exit 1
            next
        }
        NR == 2 {
            if ($0 != "installation=" installation_id) exit 1
            next
        }
        length($0) > 8192 { exit 1 }
        $0 !~ /^BACKUPSHEEP_ARTIFACT_[A-Z0-9_]+=/ &&
            $0 !~ /^AWS_ENDPOINT_URL_KMS=/ { exit 1 }
        {
            key = $0
            sub(/=.*/, "", key)
            if (seen[key]++) exit 1
        }
        END { if (NR < 2) exit 1 }
    ' "$path" \
        || die "The artifact-provider transition rollback is malformed."
}

validate_legacy_artifact_provider_secret_state() {
    local legacy_secret=""
    local rollback_path=""
    local found=false

    rollback_path="$(artifact_provider_rollback_path)"
    for legacy_secret in "${LEGACY_ARTIFACT_PROVIDER_SECRET_NAMES[@]}"; do
        legacy_secret="${SECRETS_DIR}/${legacy_secret}"
        if [[ -e "$legacy_secret" || -L "$legacy_secret" ]]; then
            found=true
        fi
    done
    [[ "$found" == false ]] && return
    [[ -e "$rollback_path" || -L "$rollback_path" ]] \
        || die "A retired artifact-provider credential exists without its protected transition rollback; inspect and remove or recover it explicitly."
    validate_artifact_provider_rollback "$rollback_path"
}

preserve_artifact_provider_rollback() {
    local path=""
    local temporary=""
    local installation_id=""
    local existing_digest=""
    local expected_digest=""

    path="$(artifact_provider_rollback_path)"
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    if ! awk '
        /^[[:space:]]*AWS_ENDPOINT_URL_KMS/ &&
            $0 !~ /^AWS_ENDPOINT_URL_KMS=/ { exit 1 }
    ' "$ENV_FILE"; then
        die "The legacy AWS_ENDPOINT_URL_KMS setting is malformed; preserve and review it manually."
    fi
    if [[ -e "$path" || -L "$path" ]]; then
        validate_artifact_provider_rollback
    fi
    temporary="$(mktemp "${SECRETS_DIR}/.artifact-provider-rollback.XXXXXXXX")"
    if ! {
        printf '%s\n' BACKUPSHEEP-ARTIFACT-PROVIDER-ROLLBACK-V1
        printf 'installation=%s\n' "$installation_id"
        awk '
            /^BACKUPSHEEP_ARTIFACT_[A-Z0-9_]+=/ ||
            /^AWS_ENDPOINT_URL_KMS=/
        ' "$ENV_FILE"
    } > "$temporary"; then
        rm -f -- "$temporary"
        die "Could not preserve the existing artifact-provider policy for rollback."
    fi
    chmod 0400 "$temporary"
    # Validate the unpublished bytes under the same strict grammar. Temporarily
    # address the candidate directly rather than exposing any value in logs.
    [[ "$(file_size "$temporary")" -ge 1 && "$(file_size "$temporary")" -le 32768 ]] \
        || { rm -f -- "$temporary"; die "The existing artifact-provider policy is not bounded for rollback."; }
    ! od -An -v -tx1 "$temporary" | grep -Eq '(^|[[:space:]])00([[:space:]]|$)' \
        || { rm -f -- "$temporary"; die "The existing artifact-provider policy cannot be preserved safely."; }
    ! grep -q $'\r' "$temporary" \
        || { rm -f -- "$temporary"; die "The existing artifact-provider policy cannot be preserved safely."; }
    awk -v installation_id="$installation_id" '
        NR == 1 {
            if ($0 != "BACKUPSHEEP-ARTIFACT-PROVIDER-ROLLBACK-V1") exit 1
            next
        }
        NR == 2 {
            if ($0 != "installation=" installation_id) exit 1
            next
        }
        length($0) > 8192 { exit 1 }
        $0 !~ /^BACKUPSHEEP_ARTIFACT_[A-Z0-9_]+=/ &&
            $0 !~ /^AWS_ENDPOINT_URL_KMS=/ { exit 1 }
        { key = $0; sub(/=.*/, "", key); if (seen[key]++) exit 1 }
        END { if (NR < 2) exit 1 }
    ' "$temporary" \
        || { rm -f -- "$temporary"; die "The existing artifact-provider policy cannot be preserved safely."; }
    validate_artifact_provider_rollback "$temporary"
    if [[ -e "$path" ]]; then
        existing_digest="$(sha256_file "$path")"
        expected_digest="$(sha256_file "$temporary")"
        if [[ "$existing_digest" != "$expected_digest" ]] \
            || ! cmp -s -- "$path" "$temporary"; then
            rm -f -- "$temporary"
            die "The existing artifact-provider rollback does not exactly match the current legacy policy."
        fi
        rm -f -- "$temporary"
        return
    fi
    sync || { rm -f -- "$temporary"; die "Could not durably flush the artifact-provider rollback."; }
    if ! atomic_publish_new_file "$temporary" "$path"; then
        rm -f -- "$temporary"
        die "Could not atomically preserve the artifact-provider rollback."
    fi
    sync || die "The artifact-provider rollback was published but its directory update was not durably flushed."
    validate_artifact_provider_rollback
}

write_artifact_keyring() {
    local lane="$1"
    local destination=""
    local temporary=""
    local key_id=""
    local key_hex=""
    local installation_id=""

    destination="$(artifact_keyring_path "$lane")"
    [[ ! -e "$destination" && ! -L "$destination" ]] \
        || die "Refusing to overwrite the existing ${lane} artifact keyring."
    key_id="lfk-$(random_hex 16)"
    key_hex="$(random_hex 32)"
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    temporary="$(mktemp "${SECRETS_DIR}/.artifact-keyring-${lane}.XXXXXXXX")"
    if ! {
        printf '%s\n' BACKUPSHEEP-ARTIFACT-KEYRING-V1
        printf 'installation=%s\n' "$installation_id"
        printf 'lane=%s\n' "$lane"
        printf 'active=%s\n' "$key_id"
        printf 'key=%s:%s\n' "$key_id" "$key_hex"
    } > "$temporary"; then
        rm -f -- "$temporary"
        die "Could not write the ${lane} artifact keyring."
    fi
    chmod 0444 "$temporary"
    validate_artifact_keyring_content "$temporary" "$lane"
    sync || { rm -f -- "$temporary"; die "Could not durably flush the new ${lane} artifact keyring."; }
    if ! atomic_publish_new_file "$temporary" "$destination"; then
        rm -f -- "$temporary"
        die "Could not atomically publish the ${lane} artifact keyring."
    fi
    sync || die "The ${lane} artifact keyring was published but its directory update could not be durably flushed; stop and inspect protected storage before continuing."
    key_hex="$(printf '%064d' 0)"
    unset key_hex
    validate_secret_file "$destination"
}

assert_artifact_keyring_worker_stopped() {
    local lane="$1"
    local running=""

    running="$(
        "$DOCKER_BIN" ps \
            --all \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
            --filter "label=com.docker.compose.service=worker-${lane}" \
            --format '{{.ID}}'
    )" || die "Could not inspect the ${lane} worker before artifact-key rotation."
    [[ -z "$running" ]] \
        || die "Remove every owned worker-${lane} container before rotating its artifact keyring; stopped, paused, and restarting containers retain the old bind-mounted keyring inode."
}

rotate_artifact_keyring() {
    local lane="$1"
    local destination=""
    local temporary=""
    local original_identity=""
    local current_identity=""
    local original_digest=""
    local current_digest=""
    local key_count=0
    local current_active_key_id=""
    local key_id=""
    local key_hex=""
    local installation_id=""

    destination="$(artifact_keyring_path "$lane")"
    validate_secret_file "$destination"
    assert_artifact_keyring_worker_stopped "$lane"
    current_active_key_id="$(awk -F= 'NR == 4 && $1 == "active" { print $2 }' "$destination")"
    [[ "$current_active_key_id" == "$ARTIFACT_LOCAL_FILE_ROTATE_EXPECTED_KEY_ID" ]] \
        || die "The ${lane} artifact keyring active ID does not match the supplied witness; refusing stale or repeated rotation."
    key_count="$(awk -F= '$1 == "key" { count++ } END { print count + 0 }' "$destination")"
    [[ "$key_count" -ge 1 && "$key_count" -lt 8 ]] \
        || die "The ${lane} artifact keyring is full; no legacy key was evicted. Rewrap every active reference and complete a separately reviewed prune before another rotation."
    original_identity="$(file_identity "$destination")"
    original_digest="$(sha256_file "$destination")"
    key_id="lfk-$(random_hex 16)"
    key_hex="$(random_hex 32)"
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    temporary="$(mktemp "${SECRETS_DIR}/.artifact-keyring-${lane}-rotation.XXXXXXXX")"
    if ! {
        printf '%s\n' BACKUPSHEEP-ARTIFACT-KEYRING-V1
        printf 'installation=%s\n' "$installation_id"
        printf 'lane=%s\n' "$lane"
        printf 'active=%s\n' "$key_id"
        printf 'key=%s:%s\n' "$key_id" "$key_hex"
        tail -n +5 -- "$destination"
    } > "$temporary"; then
        rm -f -- "$temporary"
        die "Could not prepare the ${lane} artifact keyring rotation."
    fi
    chmod 0444 "$temporary"
    validate_artifact_keyring_content "$temporary" "$lane"
    sync || { rm -f -- "$temporary"; die "Could not durably flush the rotated ${lane} artifact keyring."; }
    validate_secret_file "$destination"
    current_identity="$(file_identity "$destination")"
    current_digest="$(sha256_file "$destination")"
    [[ "$current_identity" == "$original_identity" && "$current_digest" == "$original_digest" ]] \
        || { rm -f -- "$temporary"; die "The ${lane} artifact keyring changed concurrently; refusing rotation."; }
    mv -f -- "$temporary" "$destination" \
        || { rm -f -- "$temporary"; die "Could not atomically activate the ${lane} artifact keyring rotation."; }
    sync || die "The rotated ${lane} artifact keyring was activated but its directory update could not be durably flushed; keep its prior keys and stop before creating new backups."
    key_hex="$(printf '%064d' 0)"
    unset key_hex
    validate_secret_file "$destination"
    log "Rotated the ${lane} artifact keyring to active key ID ${key_id}; every prior key remains available for recovery"
}

validate_distinct_artifact_keyrings() {
    local database_keyring=""
    local files_keyring=""

    database_keyring="$(artifact_keyring_path database)"
    files_keyring="$(artifact_keyring_path files)"
    if ! awk -F '[=:]' '
        NR == FNR && $1 == "key" { ids[$2] = 1; material[$3] = 1; next }
        $1 == "key" && (ids[$2] || material[$3]) { exit 1 }
    ' "$database_keyring" "$files_keyring"; then
        die "Database and files artifact keyrings share a key identity or root key."
    fi
}

configure_artifact_keyrings() {
    local allow_rotation="${1:-false}"
    local lane=""
    local destination=""
    local database_generation=""
    local artifact_generation=""
    local allow_create=false

    database_generation="$(read_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION)"
    artifact_generation="$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION)"
    for lane in database files; do
        destination="$(artifact_keyring_path "$lane")"
        if [[ -e "$destination" || -L "$destination" ]]; then
            validate_secret_file "$destination"
            continue
        fi
        allow_create=false
        if [[ "$ENV_WAS_PRESENT" != true || "$database_generation" == 3-pending-fresh ]]; then
            allow_create=true
        elif [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" == true \
            && "$artifact_generation" == 1-pending-empty ]]; then
            allow_create=true
        fi
        [[ "$allow_create" == true ]] \
            || die "The existing installation is missing its ${lane} artifact keyring; refusing to generate replacement root keys. Restore the protected keyring backup."
        write_artifact_keyring "$lane"
    done
    validate_distinct_artifact_keyrings
    [[ "$allow_rotation" == true || "$allow_rotation" == false ]] \
        || die "Internal artifact keyring rotation mode is invalid."
    if [[ "$allow_rotation" == true && -n "$ARTIFACT_LOCAL_FILE_ROTATE_LANE" ]]; then
        [[ "$ENV_WAS_PRESENT" == true && "$database_generation" == 3 ]] \
            || die "--rotate-artifact-keyring is valid only for a completed existing installation."
        rotate_artifact_keyring "$ARTIFACT_LOCAL_FILE_ROTATE_LANE"
        validate_distinct_artifact_keyrings
    fi
}

write_empty_optional_secret_file() {
    local secret_name="$1"
    local secret_path="${SECRETS_DIR}/${secret_name}"
    local temporary_file=""

    [[ "$secret_name" == "ssh_managed_database_private_key" \
        || "$secret_name" == "ssh_managed_files_private_key" ]] \
        || die "Unknown optional secret file: ${secret_name}"
    [[ ! -e "$secret_path" && ! -L "$secret_path" ]] \
        || die "Refusing to overwrite existing optional secret ${secret_name}."
    temporary_file="$(mktemp "${SECRETS_DIR}/.${secret_name}.XXXXXXXX")"
    : > "$temporary_file"
    chmod 0444 "$temporary_file"
    if ! atomic_move_new "$temporary_file" "$secret_path"; then
        rm -f -- "$temporary_file"
        die "Could not atomically publish optional secret ${secret_name}."
    fi
    validate_secret_file "$secret_path"
}

write_secret_file() {
    local secret_name="$1"
    local secret_value="$2"
    local secret_path="${SECRETS_DIR}/${secret_name}"
    local temporary_file=""

    [[ "$secret_name" =~ ^[a-z0-9_]+$ ]] || die "Invalid secret filename."
    [[ -n "$secret_value" ]] || die "Secret ${secret_name} must not be empty."
    [[ "$secret_value" != *$'\n'* && "$secret_value" != *$'\r'* ]] \
        || die "Secret ${secret_name} must be a single line."
    [[ ! -e "$secret_path" && ! -L "$secret_path" ]] \
        || die "Refusing to overwrite existing secret ${secret_name}."

    temporary_file="$(mktemp "${SECRETS_DIR}/.${secret_name}.XXXXXXXX")"
    if ! printf '%s\n' "$secret_value" > "$temporary_file"; then
        rm -f -- "$temporary_file"
        die "Could not write secret ${secret_name}."
    fi
    chmod 0444 "$temporary_file"
    if ! atomic_move_new "$temporary_file" "$secret_path"; then
        rm -f -- "$temporary_file"
        die "Could not atomically publish secret ${secret_name}."
    fi
    validate_secret_file "$secret_path"
}

write_celery_signing_key() {
    local lane="$1"
    local key_set="${2:-active}"
    local secret_name="celery_signing_${lane}_private_key"
    local destination="${SECRETS_DIR}/${secret_name}"
    local temporary_key=""
    local candidate=""
    local valid_lane=false

    for candidate in "${CELERY_SIGNING_LANES[@]}"; do
        if [[ "$candidate" == "$lane" ]]; then
            valid_lane=true
            break
        fi
    done
    [[ "$valid_lane" == true ]] || die "Unknown Celery signing lane: ${lane}"
    if [[ "$key_set" == rotation ]]; then
        secret_name=".celery_rotation_${lane}_private_key"
        destination="${SECRETS_DIR}/${secret_name}"
    else
        [[ "$key_set" == active ]] || die "Unknown Celery signing key set."
    fi
    if [[ -e "$destination" || -L "$destination" ]]; then
        validate_secret_file "$destination"
        return
    fi
    temporary_key="$(mktemp "${SECRETS_DIR}/.${secret_name}.XXXXXXXX")"
    rm -f -- "$temporary_key"
    if ! ssh-keygen -q -t ed25519 -N '' -C '' -f "$temporary_key"; then
        rm -f -- "$temporary_key" "${temporary_key}.pub"
        die "Could not generate the ${lane} Celery signing key."
    fi
    rm -f -- "${temporary_key}.pub"
    chmod 0444 "$temporary_key"
    if ! atomic_move_new "$temporary_key" "$destination"; then
        rm -f -- "$temporary_key"
        die "Could not atomically publish the ${lane} Celery signing key."
    fi
    validate_secret_file "$destination"
}

celery_public_key() {
    local lane="$1"
    local key_set="${2:-active}"
    local private_key="${SECRETS_DIR}/celery_signing_${lane}_private_key"
    local validation_copy=""
    local public_key=""

    if [[ "$key_set" == rotation ]]; then
        private_key="${SECRETS_DIR}/.celery_rotation_${lane}_private_key"
    else
        [[ "$key_set" == active ]] || die "Unknown Celery signing key set."
    fi
    validate_secret_file "$private_key"
    validation_copy="$(mktemp "${SECRETS_DIR}/.celery-public.XXXXXXXX")"
    cp -- "$private_key" "$validation_copy"
    chmod 0600 "$validation_copy"
    if ! public_key="$(ssh-keygen -y -f "$validation_copy" 2>/dev/null)"; then
        rm -f -- "$validation_copy"
        die "Could not derive the ${lane} Celery public key."
    fi
    rm -f -- "$validation_copy"
    [[ "$public_key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/]+={0,3}$ ]] \
        || die "The ${lane} Celery public key is malformed."
    printf '%s' "$public_key"
}

configure_celery_public_registry() {
    local signing_generation="${1:-}"
    local key_set="${2:-active}"
    local installation_id=""
    local expected=""
    local lane=""
    local separator=""
    local existing=""
    local registry="${SECRETS_DIR}/celery_trusted_public_keys"
    local temporary_registry=""

    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    [[ "$installation_id" =~ ^[0-9a-f]{64}$ ]] \
        || die "Cannot bind Celery keys to a malformed installation identity."
    [[ "$signing_generation" =~ ^[1-9][0-9]{0,8}$ ]] \
        || die "Celery signing-key generation is invalid."
    if [[ "$key_set" == rotation ]]; then
        registry="${SECRETS_DIR}/.celery_rotation_trusted_public_keys"
    else
        [[ "$key_set" == active ]] || die "Unknown Celery signing registry set."
    fi
    expected='{"version":2,"installation_id":"'
    expected="${expected}${installation_id}\",\"generation\":${signing_generation},\"keys\":{"
    for lane in "${CELERY_SIGNING_LANES[@]}"; do
        expected="${expected}${separator}\"${lane}\":\"$(celery_public_key "$lane" "$key_set")\""
        separator=','
    done
    expected="${expected}}}"
    if [[ -e "$registry" || -L "$registry" ]]; then
        if [[ "$key_set" == active ]]; then
            validate_secret_file "$registry"
        else
            [[ -f "$registry" && ! -L "$registry" \
                && "$(file_uid "$registry")" == "$EUID" \
                && "$(file_mode "$registry")" == "444" \
                && "$(file_links "$registry")" == "1" ]] \
                || die "The pending Celery public-key registry metadata drifted."
        fi
        existing="$(<"$registry")"
        [[ "$existing" == "$expected" ]] \
            || die "The Celery public-key registry does not match this installation's private keys."
        return
    fi
    if [[ "$key_set" == active ]]; then
        write_secret_file celery_trusted_public_keys "$expected"
        return
    fi
    temporary_registry="$(mktemp "${SECRETS_DIR}/.celery-rotation-registry.XXXXXXXX")"
    if ! printf '%s\n' "$expected" > "$temporary_registry"; then
        rm -f -- "$temporary_registry"
        die "Could not write the pending Celery public-key registry."
    fi
    chmod 0444 "$temporary_registry"
    if ! atomic_move_new "$temporary_registry" "$registry"; then
        rm -f -- "$temporary_registry"
        die "Could not publish the pending Celery public-key registry."
    fi
}

validate_legacy_celery_public_registry() {
    local installation_id=""
    local expected=""
    local separator=""
    local lane=""
    local registry="${SECRETS_DIR}/celery_trusted_public_keys"

    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    expected='{"version":1,"installation_id":"'
    expected="${expected}${installation_id}\",\"keys\":{"
    for lane in "${CELERY_SIGNING_LANES[@]}"; do
        expected="${expected}${separator}\"${lane}\":\"$(celery_public_key "$lane")\""
        separator=','
    done
    expected="${expected}}}"
    validate_secret_file "$registry"
    [[ "$(<"$registry")" == "$expected" ]] \
        || die "The legacy Celery registry does not match its installed private keys."
}

celery_rotation_artifacts_present() {
    local name=""
    for name in "${CELERY_ROTATION_SECRET_NAMES[@]}"; do
        if [[ -e "${SECRETS_DIR}/${name}" || -L "${SECRETS_DIR}/${name}" ]]; then
            return 0
        fi
    done
    return 1
}

prepare_celery_signing_rotation() {
    local next_generation="$1"
    local lane=""

    [[ "$next_generation" =~ ^[1-9][0-9]{0,8}$ ]] \
        || die "The next Celery signing-key generation is invalid."
    set_env_value BACKUPSHEEP_CELERY_SECURITY_GENERATION 3-pending-rotation
    set_env_value BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION "$next_generation"
    for lane in "${CELERY_SIGNING_LANES[@]}"; do
        write_celery_signing_key "$lane" rotation
    done
    configure_celery_public_registry "$next_generation" rotation
}

remove_celery_rotation_artifacts() {
    local name=""
    for name in "${CELERY_ROTATION_SECRET_NAMES[@]}"; do
        rm -f -- "${SECRETS_DIR}/${name}"
    done
}

reject_placeholder_secret() {
    local key="$1"
    local value="$2"

    case "$value" in
        change-this-key|change-this-password|guest)
            die "${key} still contains an unsafe sample/default value."
            ;;
    esac
}

migrate_one_secret() {
    local key="$1"
    local secret_name="$2"
    local generate_if_empty="$3"
    local env_value=""
    local file_value=""
    local secret_path="${SECRETS_DIR}/${secret_name}"

    env_value="$(read_env_value "$key")"
    reject_placeholder_secret "$key" "$env_value"

    if [[ -e "$secret_path" || -L "$secret_path" ]]; then
        validate_secret_file "$secret_path"
        file_value="$(<"$secret_path")"
        if [[ -n "$env_value" && "$file_value" != "$env_value" ]]; then
            die "${key} and ${secret_name} disagree. Resolve the secret source explicitly before rerunning."
        fi
        return
    fi

    if [[ -z "$env_value" ]]; then
        if [[ "$generate_if_empty" == true ]]; then
            write_secret_file "$secret_name" "$(random_hex 32)"
            return
        fi
        die "Cannot safely infer existing ${key}. Restore its current value before migrating to file-backed secrets."
    fi
    write_secret_file "$secret_name" "$env_value"
}

validate_database_role_name() {
    local variable_name="$1"
    local value="$2"

    [[ "$value" =~ ^[a-z][a-z0-9_]{0,62}$ ]] \
        || die "${variable_name} must be a lowercase PostgreSQL role identifier."
}

configure_database_identity_generation() {
    local generation=""
    local bootstrap_user=""
    local migrator_user="backupsheep_migrator"
    local legacy_user=""
    local legacy_secret="${SECRETS_DIR}/db_password"
    local bootstrap_secret="${SECRETS_DIR}/db_bootstrap_password"
    local migrator_secret="${SECRETS_DIR}/db_migrator_password"
    local lane=""
    local variable=""
    local role=""
    local left_role=""
    local right_role=""
    local left_value=""
    local right_value=""
    local secret_path=""
    local right_path=""
    local seen_missing=false
    local -a role_variables=(DB_BOOTSTRAP_USER DB_MIGRATOR_USER)
    local -a secret_paths=("$bootstrap_secret" "$migrator_secret")

    for lane in "${DATABASE_LANES[@]}"; do
        case "$lane" in
            app) variable=DB_APP_USER ;;
            preflight) variable=DB_PREFLIGHT_USER ;;
            beat) variable=DB_BEAT_USER ;;
            cloud) variable=DB_CLOUD_USER ;;
            database) variable=DB_DATABASE_USER ;;
            files) variable=DB_FILES_USER ;;
            storage) variable=DB_STORAGE_USER ;;
            logs) variable=DB_LOGS_USER ;;
            *) die "Internal database lane inventory is invalid." ;;
        esac
        role_variables+=("$variable")
        secret_paths+=("${SECRETS_DIR}/db_${lane}_password")
    done

    generation="$(read_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION)"

    case "$generation" in
        3)
            [[ "$MIGRATE_DATABASE_IDENTITIES" != true ]] \
                || die "Database identities are already generation 3; rerun without --migrate-database-identities."
            ;;
        3-pending-fresh)
            [[ "$MIGRATE_DATABASE_IDENTITIES" != true ]] \
                || die "A fresh database identity transition is already pending; rerun without --migrate-database-identities."
            ;;
        3-pending-upgrade)
            [[ "$MIGRATE_DATABASE_IDENTITIES" == true ]] \
                || die "Database identity generation 3 is pending; rerun with --migrate-database-identities after preserving rollback evidence."
            ;;
        2|"")
            [[ "$MIGRATE_DATABASE_IDENTITIES" == true ]] \
                || die "This installation requires the explicit generation-3 database lane migration. Stop provider operations, preserve an encrypted rollback, then rerun once with --migrate-database-identities."
            ;;
        *)
            die "Unsupported BACKUPSHEEP_DATABASE_IDENTITY_GENERATION=${generation}; refusing to guess database ownership."
            ;;
    esac

    if [[ "$generation" == "" ]]; then
        for secret_path in "${secret_paths[@]}"; do
            [[ ! -e "$secret_path" && ! -L "$secret_path" ]] \
                || die "The legacy database secret transition is incomplete or ambiguous; restore the protected rollback copy before retrying."
        done
        migrate_one_secret DB_PASSWORD db_password false
        validate_secret_file "$legacy_secret"
        bootstrap_user="$(read_env_value DB_BOOTSTRAP_USER)"
        [[ -n "$bootstrap_user" ]] || bootstrap_user="$(read_env_value DB_USER)"
        validate_database_role_name DB_BOOTSTRAP_USER "$bootstrap_user"
        set_env_value DB_BOOTSTRAP_USER "$bootstrap_user"
        set_env_value DB_MIGRATOR_USER "$migrator_user"
        set_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION "3-pending-upgrade"
        generation="3-pending-upgrade"
    elif [[ "$generation" == "2" ]]; then
        for secret_path in "$legacy_secret" "$bootstrap_secret" "$migrator_secret"; do
            [[ -e "$secret_path" || -L "$secret_path" ]] \
                || die "Database identity generation 2 is missing $(basename -- "$secret_path")."
            validate_secret_file "$secret_path"
        done
        bootstrap_user="$(read_env_value DB_BOOTSTRAP_USER)"
        validate_database_role_name DB_BOOTSTRAP_USER "$bootstrap_user"
        validate_database_role_name DB_MIGRATOR_USER "$(read_env_value DB_MIGRATOR_USER)"
        legacy_user="$(read_env_value DB_USER)"
        validate_database_role_name DB_USER "$legacy_user"
        for lane in "${DATABASE_LANES[@]}"; do
            secret_path="${SECRETS_DIR}/db_${lane}_password"
            [[ ! -e "$secret_path" && ! -L "$secret_path" ]] \
                || die "The generation-2 database secret transition is incomplete or ambiguous; restore the protected rollback copy before retrying."
        done
        set_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION "3-pending-upgrade"
        generation="3-pending-upgrade"
    fi

    bootstrap_user="$(read_env_value DB_BOOTSTRAP_USER)"
    [[ -n "$bootstrap_user" ]] || bootstrap_user="backupsheep_bootstrap"
    set_env_value DB_BOOTSTRAP_USER "$bootstrap_user"
    set_env_value DB_MIGRATOR_USER "$migrator_user"
    for lane in "${DATABASE_LANES[@]}"; do
        case "$lane" in
            app) variable=DB_APP_USER ;;
            preflight) variable=DB_PREFLIGHT_USER ;;
            beat) variable=DB_BEAT_USER ;;
            cloud) variable=DB_CLOUD_USER ;;
            database) variable=DB_DATABASE_USER ;;
            files) variable=DB_FILES_USER ;;
            storage) variable=DB_STORAGE_USER ;;
            logs) variable=DB_LOGS_USER ;;
        esac
        set_env_value "$variable" "backupsheep_${lane}"
    done
    set_env_value DB_USER "backupsheep_app"

    if [[ "$generation" == "3-pending-upgrade" \
        && ! -e "$bootstrap_secret" && ! -L "$bootstrap_secret" ]]; then
        [[ -f "$legacy_secret" && ! -L "$legacy_secret" ]] \
            || die "The pending database upgrade lost both its bootstrap and legacy credential; restore the protected rollback copy."
        validate_secret_file "$legacy_secret"
        if ! atomic_move_new "$legacy_secret" "$bootstrap_secret"; then
            die "Could not atomically confine the legacy database credential as db_bootstrap_password."
        fi
    fi

    # The exact ordered prefix makes a terminated secret-generation pass resumable.
    # Compose cannot start db-provision until every listed file exists, so filling a
    # missing suffix cannot rotate a credential already used by PostgreSQL.
    for secret_path in "${secret_paths[@]}"; do
        if [[ -e "$secret_path" || -L "$secret_path" ]]; then
            [[ "$seen_missing" != true ]] \
                || die "The pending database secret set is not an ordered prefix; restore it from the protected rollback copy."
            validate_secret_file "$secret_path"
        else
            [[ "$generation" != "3" ]] \
                || die "Database identity generation 3 is missing $(basename -- "$secret_path"); restore the installed secret instead of rotating it implicitly."
            seen_missing=true
            write_secret_file "$(basename -- "$secret_path")" "$(random_hex 32)"
        fi
    done

    for variable in "${role_variables[@]}"; do
        role="$(read_env_value "$variable")"
        validate_database_role_name "$variable" "$role"
    done
    for left_role in "${role_variables[@]}"; do
        left_value="$(read_env_value "$left_role")"
        for right_role in "${role_variables[@]}"; do
            [[ "$left_role" < "$right_role" ]] || continue
            right_value="$(read_env_value "$right_role")"
            [[ "$left_value" != "$right_value" ]] \
                || die "Database roles ${left_role} and ${right_role} collide."
        done
    done

    for secret_path in "${secret_paths[@]}"; do
        left_value="$(<"$secret_path")"
        for right_path in "${secret_paths[@]}"; do
            [[ "$secret_path" < "$right_path" ]] || continue
            right_value="$(<"$right_path")"
            [[ "$left_value" != "$right_value" ]] \
                || die "Database credentials $(basename -- "$secret_path") and $(basename -- "$right_path") are identical."
        done
        if [[ -f "$legacy_secret" && ! -L "$legacy_secret" ]]; then
            right_value="$(<"$legacy_secret")"
            [[ "$left_value" != "$right_value" ]] \
                || die "A generation-3 database credential reuses the legacy runtime password."
        fi
    done
}

complete_database_identity_generation() {
    local generation=""
    local legacy_secret="${SECRETS_DIR}/db_password"

    generation="$(read_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION)"
    case "$generation" in
        3-pending-fresh|3-pending-upgrade)
            ;;
        3)
            # A prior process may have been interrupted after the database seal and
            # generation witness but before deleting the now-retired v2 credential.
            ;;
        *)
            die "Cannot complete unsupported database identity generation ${generation}."
            ;;
    esac

    # db-seal has already retired the legacy role and preflight will independently
    # validate every ACL/RLS witness. Remove the old credential before writing the
    # generation witness last, so an interrupted upgrade remains explicitly pending.
    if [[ -e "$legacy_secret" || -L "$legacy_secret" ]]; then
        [[ -f "$legacy_secret" && ! -L "$legacy_secret" ]] \
            || die "The retired database credential is not a safe regular file."
        validate_secret_file "$legacy_secret"
        rm -f -- "$legacy_secret"
    fi
    set_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION 3
}

validate_rabbitmq_role_name() {
    local variable_name="$1"
    local value="$2"

    [[ "$value" =~ ^[a-z][a-z0-9_]{0,62}$ ]] \
        || die "${variable_name} must be a lowercase RabbitMQ username."
}

validate_distinct_rabbitmq_passwords() {
    local left_role=""
    local right_role=""
    local left_value=""
    local right_value=""

    for left_role in "${RABBITMQ_ROLES[@]}"; do
        left_value="$(<"${SECRETS_DIR}/rabbitmq_${left_role}_password")"
        for right_role in "${RABBITMQ_ROLES[@]}"; do
            [[ "$left_role" < "$right_role" ]] || continue
            right_value="$(<"${SECRETS_DIR}/rabbitmq_${right_role}_password")"
            [[ "$left_value" != "$right_value" ]] \
                || die "RabbitMQ roles ${left_role} and ${right_role} share a credential."
        done
    done
}

configure_rabbitmq_identity_generation() {
    local generation=""
    local security_generation=""
    local signing_generation=""
    local legacy_user=""
    local role=""
    local lane=""
    local secret_path=""
    local next_generation=""
    local legacy_secret="${SECRETS_DIR}/rabbitmq_password"
    local bootstrap_secret="${SECRETS_DIR}/rabbitmq_bootstrap_password"

    generation="$(read_env_value BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION)"
    security_generation="$(read_env_value BACKUPSHEEP_CELERY_SECURITY_GENERATION)"
    signing_generation="$(read_env_value BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION)"
    if [[ "$ENV_WAS_PRESENT" != true ]]; then
        [[ "$MIGRATE_RABBITMQ_IDENTITIES" != true ]] \
            || die "--migrate-rabbitmq-identities is valid only for an existing legacy installation."
        [[ "$ROTATE_CELERY_SIGNING_KEYS" != true ]] \
            || die "--rotate-celery-signing-keys is valid only for an existing generation-2/3 installation."
        set_env_values_atomically \
            RABBITMQ_LEGACY_USER backupsheep \
            BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION 2-pending-fresh \
            BACKUPSHEEP_CELERY_SECURITY_GENERATION 3-pending-fresh \
            BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION 1
        generation=2-pending-fresh
        security_generation=3-pending-fresh
        signing_generation=1
    fi

    case "$generation" in
        2)
            [[ "$MIGRATE_RABBITMQ_IDENTITIES" != true ]] \
                || die "RabbitMQ identities are already generation 2; rerun without --migrate-rabbitmq-identities."
            for role in "${RABBITMQ_ROLES[@]}"; do
                validate_secret_file "${SECRETS_DIR}/rabbitmq_${role}_password"
            done
            for lane in "${CELERY_SIGNING_LANES[@]}"; do
                validate_secret_file "${SECRETS_DIR}/celery_signing_${lane}_private_key"
            done
            [[ ! -e "$legacy_secret" && ! -L "$legacy_secret" ]] \
                || die "RabbitMQ generation 2 still contains the retired shared secret."
            validate_distinct_rabbitmq_passwords
            case "$security_generation" in
                3)
                    [[ "$signing_generation" =~ ^[1-9][0-9]{0,8}$ ]] \
                        || die "The installed Celery signing-key generation is invalid."
                    configure_celery_public_registry "$signing_generation" active
                    if celery_rotation_artifacts_present; then
                        [[ "$ROTATE_CELERY_SIGNING_KEYS" == true ]] \
                            || die "Completed Celery key rotation has protected cleanup artifacts; rerun with --rotate-celery-signing-keys to verify and remove them."
                        configure_celery_public_registry "$signing_generation" rotation
                        for lane in "${CELERY_SIGNING_LANES[@]}"; do
                            cmp -s -- \
                                "${SECRETS_DIR}/celery_signing_${lane}_private_key" \
                                "${SECRETS_DIR}/.celery_rotation_${lane}_private_key" \
                                || die "Pending ${lane} signing material differs from the active completed rotation."
                        done
                        cmp -s -- \
                            "${SECRETS_DIR}/celery_trusted_public_keys" \
                            "${SECRETS_DIR}/.celery_rotation_trusted_public_keys" \
                            || die "Pending Celery registry differs from the active completed rotation."
                        remove_celery_rotation_artifacts
                    elif [[ "$ROTATE_CELERY_SIGNING_KEYS" == true ]]; then
                        next_generation=$((10#$signing_generation + 1))
                        (( next_generation <= 999999999 )) \
                            || die "Celery signing-key generation is exhausted."
                        prepare_celery_signing_rotation "$next_generation"
                    fi
                    return
                    ;;
                2)
                    [[ "$ROTATE_CELERY_SIGNING_KEYS" == true ]] \
                        || die "This install uses the retired generation-2 task envelope. After database recovery and draining every broker queue, stop app/workers/Beat and rerun with --rotate-celery-signing-keys."
                    [[ -z "$signing_generation" || "$signing_generation" == 1 ]] \
                        || die "The generation-2 task envelope has an unexpected signing-key witness."
                    validate_legacy_celery_public_registry
                    prepare_celery_signing_rotation 2
                    return
                    ;;
                3-pending-rotation)
                    [[ "$ROTATE_CELERY_SIGNING_KEYS" == true ]] \
                        || die "Celery key rotation is pending; rerun with --rotate-celery-signing-keys after preserving broker/database recovery evidence."
                    [[ "$signing_generation" =~ ^[2-9][0-9]{0,8}$ ]] \
                        || die "The pending Celery signing-key generation is invalid."
                    for lane in "${CELERY_SIGNING_LANES[@]}"; do
                        validate_secret_file "${SECRETS_DIR}/.celery_rotation_${lane}_private_key"
                    done
                    configure_celery_public_registry "$signing_generation" rotation
                    return
                    ;;
                *)
                    die "RabbitMQ identity generation 2 has unsupported Celery security generation ${security_generation}."
                    ;;
            esac
            ;;
        2-pending-fresh)
            [[ "$MIGRATE_RABBITMQ_IDENTITIES" != true ]] \
                || die "A fresh RabbitMQ identity transition is already pending; rerun without the migration flag."
            [[ "$ROTATE_CELERY_SIGNING_KEYS" != true ]] \
                || die "A fresh install does not rotate a prior Celery signing generation."
            [[ "$security_generation" == 3-pending-fresh && "$signing_generation" == 1 ]] \
                || die "The pending fresh Celery security generation drifted."
            [[ ! -e "$legacy_secret" && ! -L "$legacy_secret" ]] \
                || die "A pending fresh install unexpectedly contains a legacy RabbitMQ secret."
            ;;
        ''|2-pending-legacy)
            [[ "$MIGRATE_RABBITMQ_IDENTITIES" == true ]] \
                || die "This existing installation still shares one RabbitMQ credential. Review the broker identity migration guide, stop provider operations, create an encrypted rollback, then rerun once with --migrate-rabbitmq-identities."
            [[ "$ROTATE_CELERY_SIGNING_KEYS" != true ]] \
                || die "Migrate the legacy broker identity before requesting a later signing-key rotation."
            if [[ "$generation" == "" ]]; then
                legacy_user="$(read_env_value RABBITMQ_USER)"
                [[ -n "$legacy_user" ]] || legacy_user=backupsheep
                validate_rabbitmq_role_name RABBITMQ_USER "$legacy_user"
                [[ "$legacy_user" != guest ]] \
                    || die "The RabbitMQ guest account cannot be migrated as a stock identity."
                set_env_values_atomically \
                    RABBITMQ_LEGACY_USER "$legacy_user" \
                    BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION 2-pending-legacy \
                    BACKUPSHEEP_CELERY_SECURITY_GENERATION 3-pending-legacy \
                    BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION 1
                security_generation=3-pending-legacy
                signing_generation=1
            else
                [[ "$security_generation" == 3-pending-legacy && "$signing_generation" == 1 ]] \
                    || die "The pending legacy Celery security generation drifted."
                legacy_user="$(read_env_value RABBITMQ_LEGACY_USER)"
                validate_rabbitmq_role_name RABBITMQ_LEGACY_USER "$legacy_user"
            fi
            if [[ ! -e "$legacy_secret" && ! -L "$legacy_secret" \
                && ! -e "$bootstrap_secret" && ! -L "$bootstrap_secret" ]]; then
                migrate_one_secret RABBITMQ_PASSWORD rabbitmq_password false
            fi
            if [[ -e "$legacy_secret" || -L "$legacy_secret" ]]; then
                [[ ! -e "$bootstrap_secret" && ! -L "$bootstrap_secret" ]] \
                    || die "Both legacy and bootstrap RabbitMQ secrets exist; restore the protected rollback before retrying."
                validate_secret_file "$legacy_secret"
                atomic_move_new "$legacy_secret" "$bootstrap_secret" \
                    || die "Could not atomically confine the legacy broker credential."
            fi
            ;;
        *)
            die "Unsupported BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION=${generation}; refusing to guess broker permissions."
            ;;
    esac

    for role in "${RABBITMQ_ROLES[@]}"; do
        secret_path="${SECRETS_DIR}/rabbitmq_${role}_password"
        if [[ -e "$secret_path" || -L "$secret_path" ]]; then
            validate_secret_file "$secret_path"
        else
            write_secret_file "rabbitmq_${role}_password" "$(random_hex 32)"
        fi
    done
    for lane in "${CELERY_SIGNING_LANES[@]}"; do
        write_celery_signing_key "$lane" active
    done
    configure_celery_public_registry "$signing_generation" active
    validate_distinct_rabbitmq_passwords

    # These witnesses are last: no partial secret/key set can look deployable.
    set_env_values_atomically \
        RABBITMQ_USER backupsheep_app \
        RABBITMQ_VHOST backupsheep \
        BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION 2 \
        BACKUPSHEEP_CELERY_SECURITY_GENERATION 3
}

finalize_celery_signing_rotation() {
    local security_generation=""
    local signing_generation=""
    local running=""
    local container_id=""
    local service_name=""
    local broker_id=""
    local broker_ids=""
    local queue_state=""
    local queue_count=0
    local queue_name=""
    local ready=""
    local unacknowledged=""
    local lane=""
    local candidate=""
    local destination=""
    local temporary=""

    security_generation="$(read_env_value BACKUPSHEEP_CELERY_SECURITY_GENERATION)"
    [[ "$security_generation" == 3-pending-rotation ]] || return
    [[ "$ROTATE_CELERY_SIGNING_KEYS" == true ]] \
        || die "Celery key rotation is pending; rerun with --rotate-celery-signing-keys."
    signing_generation="$(read_env_value BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION)"
    [[ "$signing_generation" =~ ^[2-9][0-9]{0,8}$ ]] \
        || die "The pending Celery signing-key generation is invalid."

    running="$(
        "$DOCKER_BIN" ps \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
            --filter status=running \
            --format '{{.ID}}\t{{.Label "com.docker.compose.service"}}'
    )" || die "Could not inventory running services before signing-key rotation."
    while IFS=$'\t' read -r container_id service_name; do
        [[ -n "$container_id" ]] || continue
        case "$service_name" in
            app|worker-cloud|worker-database|worker-files|worker-storage|worker-logs|beat)
                die "Stop app, every worker and Beat after durable database recovery before rotating Celery signing keys (still running: ${service_name})."
                ;;
        esac
    done <<< "$running"

    broker_ids="$(compose ps --all --quiet rabbitmq)" \
        || die "Could not resolve the owned RabbitMQ container before signing-key rotation."
    [[ -n "$broker_ids" && "$broker_ids" != *$'\n'* ]] \
        || die "Signing-key rotation requires exactly one owned RabbitMQ container."
    broker_id="$broker_ids"
    [[ "$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$broker_id")" == running ]] \
        || die "Signing-key rotation requires the owned RabbitMQ service to remain running."
    queue_state="$(
        "$DOCKER_BIN" exec --user 100:101 "$broker_id" \
            rabbitmqctl -q -p backupsheep \
            list_queues name messages_ready messages_unacknowledged --silent
    )" || die "Could not prove the owned RabbitMQ queues are drained."
    while IFS=$'\t' read -r queue_name ready unacknowledged; do
        [[ -n "$queue_name" ]] || continue
        case "$queue_name" in default|cloud|database|files|storage|logs) ;; *)
            die "RabbitMQ contains an unreviewed queue during signing-key rotation: ${queue_name}."
            ;;
        esac
        [[ "$ready" == 0 && "$unacknowledged" == 0 ]] \
            || die "RabbitMQ queue ${queue_name} is not empty; complete database recovery/drain before rotating signing keys."
        queue_count=$((queue_count + 1))
    done <<< "$queue_state"
    [[ "$queue_count" -eq 6 ]] \
        || die "Signing-key rotation requires all six reviewed queues to exist and be empty."

    # Keep each candidate until every active path and the registry have been replaced.
    # An interruption is fail closed (generation remains pending) and a rerun copies
    # the same candidates again; the public registry is committed after private keys.
    for lane in "${CELERY_SIGNING_LANES[@]}"; do
        candidate="${SECRETS_DIR}/.celery_rotation_${lane}_private_key"
        destination="${SECRETS_DIR}/celery_signing_${lane}_private_key"
        validate_secret_file "$candidate"
        temporary="$(mktemp "${SECRETS_DIR}/.celery-activate-${lane}.XXXXXXXX")"
        if ! cp -- "$candidate" "$temporary"; then
            rm -f -- "$temporary"
            die "Could not stage the ${lane} Celery signing-key rotation."
        fi
        chmod 0444 "$temporary"
        mv -f -- "$temporary" "$destination"
        validate_secret_file "$destination"
    done
    candidate="${SECRETS_DIR}/.celery_rotation_trusted_public_keys"
    destination="${SECRETS_DIR}/celery_trusted_public_keys"
    temporary="$(mktemp "${SECRETS_DIR}/.celery-activate-registry.XXXXXXXX")"
    if ! cp -- "$candidate" "$temporary"; then
        rm -f -- "$temporary"
        die "Could not stage the Celery public-key registry rotation."
    fi
    chmod 0444 "$temporary"
    mv -f -- "$temporary" "$destination"
    configure_celery_public_registry "$signing_generation" active

    # Publish the protocol witness before deleting candidates. If cleanup is
    # interrupted, the next explicit rotation run proves candidate==active first.
    set_env_value BACKUPSHEEP_CELERY_SECURITY_GENERATION 3
    remove_celery_rotation_artifacts
    validate_secret_dir
}

reject_connection_url_overrides() {
    local key=""
    local value=""

    for key in DATABASE_URL CELERY_BROKER_URL; do
        value="$(read_env_value "$key")"
        [[ -z "$value" ]] \
            || die "${key} is not accepted by the stock installer because it overrides file-backed component credentials and may expose a credential URL. Use the reviewed external-service deployment path instead."
    done
}

rewrite_env_for_secret_files() {
    set_env_value BACKUPSHEEP_SECRETS_DIR ".secrets"
    set_env_value DJANGO_SECRET_KEY ""
    set_env_value DB_PASSWORD ""
    set_env_value RABBITMQ_PASSWORD ""
    set_env_value ONBOARDING_INSTALL_TOKEN ""
    set_env_value SSH_MANAGED_PRIVATE_KEY_PATH ""
    set_env_value SSH_MANAGED_PUBLIC_KEY ""
    set_env_value SSH_MANAGED_LANE_ISOLATION_REQUIRED "true"
}

prepare_managed_ssh_private_keys() {
    local legacy_path=""
    local legacy_public=""
    local legacy_secret="${SECRETS_DIR}/ssh_managed_private_key"
    local legacy_secret_mode=""
    local lane=""
    local secret_name=""
    local secret_path=""
    local secret_size=""
    local public_setting=""
    local configured_public_key=""
    local configured_public_identity=""
    local validation_copy=""
    local derived_public_key=""
    local database_identity=""
    local files_identity=""

    legacy_path="$(read_env_value SSH_MANAGED_PRIVATE_KEY_PATH)"
    legacy_public="$(read_env_value SSH_MANAGED_PUBLIC_KEY)"
    if [[ -n "$legacy_path" || -n "$legacy_public" ]]; then
        die "The legacy shared managed SSH identity cannot be migrated safely. Create distinct Ed25519 keys at .secrets/ssh_managed_database_private_key and .secrets/ssh_managed_files_private_key, set their lane public keys, remove .secrets/ssh_managed_private_key, clear SSH_MANAGED_PRIVATE_KEY_PATH/SSH_MANAGED_PUBLIC_KEY, and rerun."
    fi
    if [[ -e "$legacy_secret" || -L "$legacy_secret" ]]; then
        legacy_secret_mode="$(file_mode "$legacy_secret" 2>/dev/null || true)"
        if [[ -f "$legacy_secret" && ! -L "$legacy_secret" \
            && "$(file_uid "$legacy_secret")" == "$EUID" \
            && "$(file_links "$legacy_secret")" == "1" \
            && "$legacy_secret_mode" =~ ^[0-7]{3,4}$ \
            && $((8#$legacy_secret_mode)) -eq $((8#0444)) \
            && "$(file_size "$legacy_secret")" == "0" ]]; then
            # Releases before lane isolation created this exact zero-byte,
            # read-only placeholder. It contains no key material and is the
            # only legacy artifact the installer can retire automatically.
            rm -- "$legacy_secret" \
                || die "Could not retire the empty legacy managed SSH placeholder."
        else
            die "The legacy shared managed SSH identity cannot be migrated safely. Create distinct Ed25519 keys at .secrets/ssh_managed_database_private_key and .secrets/ssh_managed_files_private_key, set their lane public keys, remove .secrets/ssh_managed_private_key, clear SSH_MANAGED_PRIVATE_KEY_PATH/SSH_MANAGED_PUBLIC_KEY, and rerun."
        fi
    fi

    for lane in database files; do
        secret_name="ssh_managed_${lane}_private_key"
        secret_path="${SECRETS_DIR}/${secret_name}"
        public_setting="SSH_MANAGED_DATABASE_PUBLIC_KEY"
        [[ "$lane" == "database" ]] || public_setting="SSH_MANAGED_FILES_PUBLIC_KEY"
        if [[ -e "$secret_path" || -L "$secret_path" ]]; then
            validate_secret_file "$secret_path"
        else
            write_empty_optional_secret_file "$secret_name"
        fi
        secret_size="$(file_size "$secret_path")"
        configured_public_key="$(read_env_value "$public_setting")"
        if [[ "$secret_size" -eq 0 ]]; then
            [[ -z "$configured_public_key" ]] \
                || die "${public_setting} requires a non-empty ${secret_path} file."
            continue
        fi

        validation_copy="$(mktemp "${SECRETS_DIR}/.managed-key-check.XXXXXXXX")"
        cp -- "$secret_path" "$validation_copy"
        chmod 0600 "$validation_copy"
        if ! derived_public_key="$(ssh-keygen -y -P '' -f "$validation_copy" 2>/dev/null)"; then
            rm -f -- "$validation_copy"
            die "${secret_path} is invalid or passphrase-protected."
        fi
        rm -f -- "$validation_copy"
        [[ "$derived_public_key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/]+={0,3}$ ]] \
            || die "${secret_path} must contain an Ed25519 private key."

        if [[ -n "$configured_public_key" ]]; then
            configured_public_identity="$(
                printf '%s\n' "$configured_public_key" \
                    | awk '
                        NR == 1 && (NF == 2 || NF == 3) {
                            if ($1 != "ssh-ed25519" || $2 !~ /^[A-Za-z0-9+\/=]+$/) exit 1
                            print $1 " " $2
                            next
                        }
                        { exit 1 }
                        END { if (NR != 1) exit 1 }
                    '
            )" || die "${public_setting} must contain one Ed25519 OpenSSH public key."
            [[ "$configured_public_identity" == "$derived_public_key" ]] \
                || die "${public_setting} does not match ${secret_path}."
        fi
        # Always discard comments and persist only the canonical wire identity.
        set_env_value "$public_setting" "$derived_public_key"
        if [[ "$lane" == "database" ]]; then
            database_identity="$derived_public_key"
        else
            files_identity="$derived_public_key"
        fi
    done

    if [[ -n "$database_identity" || -n "$files_identity" ]]; then
        [[ -n "$database_identity" && -n "$files_identity" ]] \
            || die "Database and files managed SSH identities must be enabled or disabled together."
        [[ "$database_identity" != "$files_identity" ]] \
            || die "Database and files managed SSH identities must use different keys."
    fi
    set_env_value SSH_MANAGED_PRIVATE_KEY_PATH ""
    set_env_value SSH_MANAGED_PUBLIC_KEY ""
    set_env_value SSH_MANAGED_LANE_ISOLATION_REQUIRED "true"
}

ensure_installation_id() {
    local installation_id=""

    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    if [[ -z "$installation_id" ]]; then
        installation_id="$(random_hex 32)"
        set_env_value BACKUPSHEEP_INSTALLATION_ID "$installation_id"
    fi
    [[ "$installation_id" =~ ^[0-9a-f]{64}$ ]] \
        || die "BACKUPSHEEP_INSTALLATION_ID must be one stable 64-character lowercase hexadecimal value."
}

sha256_text() {
    local value="$1"
    local digest=""

    if command_exists sha256sum; then
        digest="$(printf '%s' "$value" | sha256sum | awk '{ print $1 }')"
    elif command_exists shasum; then
        digest="$(printf '%s' "$value" | shasum -a 256 | awk '{ print $1 }')"
    elif command_exists openssl; then
        digest="$(printf '%s' "$value" | openssl dgst -sha256 | awk '{ print $NF }')"
    else
        die "A SHA-256 implementation (sha256sum, shasum, or openssl) is required."
    fi
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
        || die "The host SHA-256 implementation returned an invalid digest."
    printf '%s' "$digest"
}

sha256_file() {
    local path="$1"
    local digest=""

    if command_exists sha256sum; then
        digest="$(sha256sum -- "$path" | awk '{ print $1 }')"
    elif command_exists shasum; then
        digest="$(shasum -a 256 -- "$path" | awk '{ print $1 }')"
    elif command_exists openssl; then
        digest="$(openssl dgst -sha256 -- "$path" | awk '{ print $NF }')"
    else
        die "A SHA-256 implementation (sha256sum, shasum, or openssl) is required."
    fi
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
        || die "The host SHA-256 implementation returned an invalid file digest."
    printf '%s' "$digest"
}

release_evidence_value() {
    local path="$1"
    local key="$2"
    local value=""
    local count=""

    count="$(awk -v prefix="${key}=" 'index($0, prefix) == 1 { count++ } END { print count + 0 }' "$path")"
    [[ "$count" == "1" ]] || die "Signed-release evidence key ${key} is absent or duplicated."
    value="$(awk -v prefix="${key}=" 'index($0, prefix) == 1 { print substr($0, length(prefix) + 1) }' "$path")"
    [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] \
        || die "Signed-release evidence key ${key} is malformed."
    printf '%s' "$value"
}

validate_release_evidence_files() {
    local evidence_dir="${INSTALL_DIR}/.release-evidence"
    local name=""
    local path=""
    local entry=""
    local count=0

    [[ -d "$evidence_dir" && ! -L "$evidence_dir" \
        && "$(file_uid "$evidence_dir")" == "$EUID" \
        && "$(file_mode "$evidence_dir")" == "700" ]] \
        || die "Signed-release evidence directory must be owner-only and non-symlink."
    for name in \
        backupsheep-release-descriptor-v2.txt \
        backupsheep-release-descriptor-v2.sigstore.json \
        release-manifest.json \
        sigstore-trusted-root.json \
        signature-verification.json \
        local-images.txt; do
        path="${evidence_dir}/${name}"
        [[ -f "$path" && ! -L "$path" \
            && "$(file_uid "$path")" == "$EUID" \
            && "$(file_mode "$path")" == "600" \
            && "$(file_links "$path")" == "1" ]] \
            || die "Signed-release evidence ${name} must be an owner-only regular file without hard links."
    done
    while IFS= read -r -d '' entry; do
        count=$((count + 1))
        case "$(basename -- "$entry")" in
            backupsheep-release-descriptor-v2.txt|backupsheep-release-descriptor-v2.sigstore.json|release-manifest.json|sigstore-trusted-root.json|signature-verification.json|local-images.txt) ;;
            *) die "Signed-release evidence contains an unexpected entry." ;;
        esac
    done < <(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print0)
    [[ "$count" -eq 6 ]] || die "Signed-release evidence must contain exactly six control files."
}

validate_requested_image_mode_against_existing() {
    local configured_mode=""
    local configured_tag=""
    local configured_commit=""

    ENV_FILE="${INSTALL_DIR}/.env"
    [[ -e "$ENV_FILE" || -L "$ENV_FILE" ]] || return 0
    validate_env_file
    configured_mode="$(read_env_value BACKUPSHEEP_IMAGE_MODE)"
    [[ -n "$configured_mode" ]] || configured_mode="local-build"
    if [[ "$IMAGE_MODE" == "local-build" \
        && ( -e "${INSTALL_DIR}/.release-request" || -L "${INSTALL_DIR}/.release-request" ) ]]; then
        die "A signed-release request witness exists; local-build mode cannot consume or discard it. Retry the exact signed request."
    fi
    if [[ "$IMAGE_MODE" == "signed-release" && "$configured_mode" == "local-build" \
        && ( -e "${INSTALL_DIR}/.release-request" || -L "${INSTALL_DIR}/.release-request" ) ]]; then
        validate_release_request_witness
        [[ -z "$(read_env_value BACKUPSHEEP_RELEASE_TAG)" \
            && -z "$(read_env_value BACKUPSHEEP_RELEASE_SOURCE_COMMIT)" \
            && -z "$(read_env_value BACKUPSHEEP_RELEASE_DESCRIPTOR_SHA256)" \
            && -z "$(read_env_value BACKUPSHEEP_RELEASE_APP_IMAGE)" \
            && -z "$(read_env_value BACKUPSHEEP_RELEASE_POSTGRES_IMAGE)" \
            && -z "$(read_env_value BACKUPSHEEP_RELEASE_EGRESS_IMAGE)" \
            && -z "$(read_env_value BACKUPSHEEP_RELEASE_RABBITMQ_IMAGE)" \
            && -z "$(read_env_value BACKUPSHEEP_RELEASE_RABBITMQ_UPGRADE_IMAGE)" \
            && "$(read_env_value BACKUPSHEEP_IMAGE)" == "backupsheep:local" \
            && "$(read_env_value BACKUPSHEEP_POSTGRES_IMAGE)" == "backupsheep-postgres:local" \
            && "$(read_env_value BACKUPSHEEP_EGRESS_IMAGE)" == "backupsheep-egress:local" \
            && "$(read_env_value BACKUPSHEEP_RABBITMQ_IMAGE)" == rabbitmq:4.3.5-alpine@sha256:d07d6a0657affe0354ae61b3ca1a3e4d244c247ac5d7e25940c8759658ce7ad7 \
            && "$(read_env_value BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE)" == rabbitmq:4.2.9-alpine@sha256:f093e74d14814d28e3d52e7dee5873ab8e8c2e671e9e11019654bd3443183095 ]] \
            || die "Interrupted signed-release request found non-pristine image-source fields."
        return 0
    fi
    [[ "$configured_mode" == "$IMAGE_MODE" ]] \
        || die "Existing installation image mode is ${configured_mode}; mode changes require a separately reviewed fresh project or rollback procedure."
    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        configured_tag="$(read_env_value BACKUPSHEEP_RELEASE_TAG)"
        configured_commit="$(read_env_value BACKUPSHEEP_RELEASE_SOURCE_COMMIT)"
        [[ "$configured_tag" == "$RELEASE_TAG" && "$configured_commit" == "$INSTALL_REF" ]] \
            || die "Existing signed-release tag/source commit does not match this exact request."
    fi
}

prepare_image_source() {
    local consumer="${INSTALL_DIR}/deploy/release/consume-signed-release.sh"
    if [[ "$IMAGE_MODE" == "local-build" ]]; then
        [[ ! -e "${INSTALL_DIR}/.release-request" && ! -L "${INSTALL_DIR}/.release-request" ]] \
            || die "A signed-release request witness exists; retry the exact signed request."
        [[ ! -e "${INSTALL_DIR}/.release-evidence" && ! -L "${INSTALL_DIR}/.release-evidence" ]] \
            || die "Signed-release evidence exists but local-build mode was requested; select the exact release tag or use the reviewed rollback procedure."
        return
    fi
    prepare_release_request_witness
    log "Verifying signed descriptor and official image digests for ${RELEASE_TAG}"
    run_installer_command 7200 "signed-release verification and digest pulls" "$consumer" \
        --tag "$RELEASE_TAG" \
        --commit "$INSTALL_REF" \
        --install-dir "$INSTALL_DIR" \
        --docker "$DOCKER_BIN" \
        || die "Signed-release verification failed or exceeded its wall-clock deadline."
    validate_release_evidence_files
}

configure_image_source() {
    local descriptor="${INSTALL_DIR}/.release-evidence/backupsheep-release-descriptor-v2.txt"
    local expected_mode="$IMAGE_MODE"
    local expected_tag=""
    local expected_commit=""
    local expected_descriptor_digest=""
    local expected_app="backupsheep:${INSTALL_REF}"
    local expected_postgres="backupsheep-postgres:${INSTALL_REF}"
    local expected_egress="backupsheep-egress:${INSTALL_REF}"
    local expected_rabbitmq="rabbitmq:4.3.5-alpine@sha256:d07d6a0657affe0354ae61b3ca1a3e4d244c247ac5d7e25940c8759658ce7ad7"
    local expected_rabbitmq_upgrade="rabbitmq:4.2.9-alpine@sha256:f093e74d14814d28e3d52e7dee5873ab8e8c2e671e9e11019654bd3443183095"
    local key=""
    local expected=""
    local current=""
    local contract=""

    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        validate_release_evidence_files
        expected_tag="$RELEASE_TAG"
        expected_commit="$INSTALL_REF"
        expected_descriptor_digest="sha256:$(sha256_file "$descriptor")"
        expected_app="$(release_evidence_value "$descriptor" app_image)"
        expected_postgres="$(release_evidence_value "$descriptor" postgres_image)"
        expected_egress="$(release_evidence_value "$descriptor" egress_image)"
        expected_rabbitmq="$(release_evidence_value "$descriptor" rabbitmq_image)"
        expected_rabbitmq_upgrade="$(release_evidence_value "$descriptor" rabbitmq_upgrade_image)"
    fi

    while IFS='|' read -r key expected; do
        current="$(read_env_value "$key")"
        if [[ "$ENV_WAS_PRESENT" == true ]]; then
            if [[ "$IMAGE_MODE" == "signed-release" ]]; then
                [[ "$current" == "$expected" ]] \
                    || die "${key} does not match the installation's immutable ${IMAGE_MODE} image-source contract."
            else
                case "$key" in
                    BACKUPSHEEP_IMAGE_MODE)
                        [[ -z "$current" || "$current" == "local-build" ]] \
                            || die "Existing installation is not in local-build mode."
                        ;;
                    BACKUPSHEEP_RELEASE_*)
                        [[ -z "$current" ]] \
                            || die "${key} must be blank in local-build mode."
                        ;;
                    BACKUPSHEEP_IMAGE|BACKUPSHEEP_POSTGRES_IMAGE|BACKUPSHEEP_EGRESS_IMAGE|BACKUPSHEEP_RABBITMQ_IMAGE|BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE)
                        : # Preserve historical behavior: rebind local tags to --ref.
                        ;;
                esac
            fi
        fi
        [[ "$key" =~ ^[A-Z0-9_]+$ && "$expected" != *$'\n'* && "$expected" != *$'\r'* \
            && "$expected" != *"'"* && "$expected" != *'|'* && "$expected" != *$'\034'* ]] \
            || die "Image-source contract contains an unsafe key or value."
        contract+="${key}|${expected}"$'\034'
    done <<EOF
BACKUPSHEEP_IMAGE_MODE|${expected_mode}
BACKUPSHEEP_RELEASE_TAG|${expected_tag}
BACKUPSHEEP_RELEASE_SOURCE_COMMIT|${expected_commit}
BACKUPSHEEP_RELEASE_DESCRIPTOR_SHA256|${expected_descriptor_digest}
BACKUPSHEEP_RELEASE_APP_IMAGE|${expected_app/#backupsheep:${INSTALL_REF}/}
BACKUPSHEEP_RELEASE_POSTGRES_IMAGE|${expected_postgres/#backupsheep-postgres:${INSTALL_REF}/}
BACKUPSHEEP_RELEASE_EGRESS_IMAGE|${expected_egress/#backupsheep-egress:${INSTALL_REF}/}
BACKUPSHEEP_RELEASE_RABBITMQ_IMAGE|${expected_rabbitmq/#rabbitmq:4.3.5-alpine@sha256:d07d6a0657affe0354ae61b3ca1a3e4d244c247ac5d7e25940c8759658ce7ad7/}
BACKUPSHEEP_RELEASE_RABBITMQ_UPGRADE_IMAGE|${expected_rabbitmq_upgrade/#rabbitmq:4.2.9-alpine@sha256:f093e74d14814d28e3d52e7dee5873ab8e8c2e671e9e11019654bd3443183095/}
BACKUPSHEEP_IMAGE|${expected_app}
BACKUPSHEEP_POSTGRES_IMAGE|${expected_postgres}
BACKUPSHEEP_EGRESS_IMAGE|${expected_egress}
BACKUPSHEEP_RABBITMQ_IMAGE|${expected_rabbitmq}
BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE|${expected_rabbitmq_upgrade}
EOF
    set_image_source_contract_atomically "$contract"
    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        validate_release_request_witness
        rm -f -- "${INSTALL_DIR}/.release-request" || die "Could not remove completed signed-release request witness."
        sync || die "Could not durably finalize the signed-release request witness."
    fi
}

attest_local_release_image() {
    local role="$1"
    local reference="$2"
    local expected_id=""
    local actual_id=""
    local repo_digest_output=""
    local source_label=""
    local revision_label=""
    local version_label=""
    local ids="${INSTALL_DIR}/.release-evidence/local-images.txt"

    expected_id="$(release_evidence_value "$ids" "${role}_image_id")"
    [[ "$expected_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "Persisted ${role} image ID is malformed."
    repo_digest_output="$("$DOCKER_BIN" image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$reference")" \
        || die "Verified ${role} image digest is no longer present locally."
    grep -Fxq -- "$reference" <<< "$repo_digest_output" \
        || die "Local ${role} image no longer exposes the verified official RepoDigest."
    actual_id="$("$DOCKER_BIN" image inspect --format '{{.Id}}' "$reference")"
    [[ "$actual_id" == "$expected_id" ]] || die "Local ${role} image ID changed after verification."
    source_label="$("$DOCKER_BIN" image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$reference")"
    revision_label="$("$DOCKER_BIN" image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$reference")"
    version_label="$("$DOCKER_BIN" image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$reference")"
    [[ "$source_label" == "https://github.com/bilal414/backupsheep" \
        && "$revision_label" == "$INSTALL_REF" \
        && "$version_label" == "$RELEASE_TAG" ]] \
        || die "Local ${role} image provenance labels do not match the signed release."
}

validate_local_release_images() {
    local descriptor="${INSTALL_DIR}/.release-evidence/backupsheep-release-descriptor-v2.txt"
    [[ "$IMAGE_MODE" == "signed-release" ]] || return 0
    validate_release_evidence_files
    [[ "sha256:$(sha256_file "$descriptor")" == "$(read_env_value BACKUPSHEEP_RELEASE_DESCRIPTOR_SHA256)" ]] \
        || die "Signed-release descriptor changed after verification."
    attest_local_release_image app "$(read_env_value BACKUPSHEEP_IMAGE)"
    attest_local_release_image postgres "$(read_env_value BACKUPSHEEP_POSTGRES_IMAGE)"
    attest_local_release_image egress "$(read_env_value BACKUPSHEEP_EGRESS_IMAGE)"
    attest_local_release_image rabbitmq "$(read_env_value BACKUPSHEEP_RABBITMQ_IMAGE)"
    attest_local_release_image rabbitmq_upgrade "$(read_env_value BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE)"
}

configure_postgres_storage_generation() {
    local installation_id=""
    local state=""
    local intent=""
    local witness=""
    local expected_witness=""
    local retired_image_id=""
    local all_volume_names=""
    local old_volume="${PROJECT_NAME}_pgdata"
    local active_volume="${PROJECT_NAME}_${POSTGRES_STORAGE_LOGICAL_VOLUME}"
    local old_exists=false
    local active_exists=false
    local legacy_image_ref=""
    local legacy_image_user=""
    local database_generation=""

    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    state="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_GENERATION)"
    intent="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_INTENT)"
    witness="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_WITNESS)"
    retired_image_id="$(read_env_value BACKUPSHEEP_POSTGRES_RETIRED_IMAGE_ID)"
    database_generation="$(read_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION)"
    all_volume_names="$($DOCKER_BIN volume ls --format '{{.Name}}')" \
        || die "Could not inventory Docker volumes before selecting PostgreSQL storage."
    grep -Fxq -- "$old_volume" <<< "$all_volume_names" && old_exists=true
    grep -Fxq -- "$active_volume" <<< "$all_volume_names" && active_exists=true

    case "$state" in
        "")
            [[ "$active_exists" == false ]] \
                || die "The Alpine PostgreSQL target volume already exists without a generation witness; refusing adoption."
            if [[ "$old_exists" == true ]]; then
                [[ "$MIGRATE_POSTGRES_RUNTIME" == true ]] \
                    || die "The legacy Debian PostgreSQL volume exists. Preserve rollback evidence and rerun once with --migrate-postgres-runtime; it will never be mounted by the Alpine image."
                case "$database_generation" in
                    "")
                        die "Automatic PostgreSQL runtime migration is not supported for a legacy single-superuser database. Preserve the detached Debian volume and exact image for rollback, then initialize a fresh generation-3/Alpine database or use a separately reviewed data-only recovery."
                        ;;
                    2)
                        [[ "$MIGRATE_DATABASE_IDENTITIES" == true ]] \
                            || die "The generation-2 database identity transition requires --migrate-database-identities together with --migrate-postgres-runtime."
                        intent="migrated-debian-generation2-v1"
                        ;;
                    3-pending-upgrade)
                        die "Database identity generation 3 is already pending without a PostgreSQL storage witness, so the source generation is ambiguous. Restore the pre-transition configuration or use a separately reviewed migration; the installer will not guess."
                        ;;
                    3)
                        [[ "$MIGRATE_DATABASE_IDENTITIES" == false ]] \
                            || die "Generation-3 database identities cannot reuse --migrate-database-identities."
                        intent="migrated-debian-v1"
                        ;;
                    *)
                        die "The PostgreSQL source identity generation is not supported by the bundled runtime migration."
                        ;;
                esac
                state="${POSTGRES_STORAGE_GENERATION}-pending-upgrade"
                legacy_image_ref="$(read_env_value BACKUPSHEEP_POSTGRES_IMAGE)"
                [[ -n "$legacy_image_ref" ]] \
                    || die "The legacy PostgreSQL image reference is absent; refusing to guess a rollback runtime."
                retired_image_id="$($DOCKER_BIN image inspect --format '{{.Id}}' "$legacy_image_ref")" \
                    || die "The exact retained legacy PostgreSQL image is not present locally."
                legacy_image_user="$($DOCKER_BIN image inspect --format '{{.Config.User}}' "$retired_image_id")" \
                    || die "Could not inspect the retained legacy PostgreSQL image user."
                [[ "$retired_image_id" =~ ^sha256:[0-9a-f]{64}$ && "$legacy_image_user" == "999:999" ]] \
                    || die "The retained legacy PostgreSQL image is not the reviewed UID/GID-999 runtime."
                set_env_value BACKUPSHEEP_POSTGRES_RETIRED_IMAGE_ID "$retired_image_id"
                POSTGRES_MIGRATION_REQUIRED=true
            else
                [[ "$MIGRATE_POSTGRES_RUNTIME" == false ]] \
                    || die "--migrate-postgres-runtime requires the canonical legacy ${old_volume} volume."
                intent="new-empty-v1"
                state="${POSTGRES_STORAGE_GENERATION}-pending-fresh"
            fi
            expected_witness="$(sha256_text "BackupSheep/postgres-storage/v1|${installation_id}|${PROJECT_NAME}|${POSTGRES_STORAGE_LOGICAL_VOLUME}|${POSTGRES_STORAGE_GENERATION}|icu=und|${intent}")"
            set_env_value BACKUPSHEEP_POSTGRES_STORAGE_INTENT "$intent"
            set_env_value BACKUPSHEEP_POSTGRES_STORAGE_WITNESS "$expected_witness"
            set_env_value BACKUPSHEEP_POSTGRES_STORAGE_GENERATION "$state"
            witness="$expected_witness"
            ;;
        "${POSTGRES_STORAGE_GENERATION}-pending-fresh")
            [[ "$intent" == "new-empty-v1" && "$old_exists" == false ]] \
                || die "Pending fresh PostgreSQL storage conflicts with a legacy volume or intent."
            [[ "$MIGRATE_POSTGRES_RUNTIME" == false ]] \
                || die "--migrate-postgres-runtime is invalid for a pending fresh installation."
            ;;
        "${POSTGRES_STORAGE_GENERATION}-pending-upgrade")
            [[ ( "$intent" == "migrated-debian-v1" \
                || "$intent" == "migrated-debian-generation2-v1" ) \
                && "$old_exists" == true ]] \
                || die "Pending PostgreSQL migration lost its exact legacy volume or intent."
            if [[ "$intent" == "migrated-debian-generation2-v1" ]]; then
                case "$database_generation" in
                    2|3-pending-upgrade)
                        [[ "$MIGRATE_DATABASE_IDENTITIES" == true ]] \
                            || die "The witnessed generation-2 PostgreSQL migration requires the explicit database identity migration flag before sealing."
                        ;;
                    3)
                        [[ "$MIGRATE_DATABASE_IDENTITIES" == false \
                            && "$active_exists" == true ]] \
                            || die "A sealed generation-2 PostgreSQL retry requires the existing target volume and no database identity migration flag."
                        ;;
                    *)
                        die "The witnessed generation-2 PostgreSQL migration has an unsupported database identity state."
                        ;;
                esac
            else
                case "$database_generation" in
                    3)
                        [[ "$MIGRATE_DATABASE_IDENTITIES" == false ]] \
                            || die "The strict PostgreSQL migration already has generation-3 database identities."
                        ;;
                    *) die "The strict PostgreSQL migration lost its generation-3 database identity state." ;;
                esac
            fi
            [[ "$MIGRATE_POSTGRES_RUNTIME" == true ]] \
                || die "The PostgreSQL storage migration remains pending; rerun with --migrate-postgres-runtime."
            [[ "$retired_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
                || die "Pending PostgreSQL migration is missing its exact retained source image ID."
            $DOCKER_BIN image inspect "$retired_image_id" >/dev/null \
                || die "The retained legacy PostgreSQL source image is no longer present locally."
            legacy_image_user="$($DOCKER_BIN image inspect --format '{{.Config.User}}' "$retired_image_id")" \
                || die "Could not re-attest the retained legacy PostgreSQL image user."
            [[ "$legacy_image_user" == "999:999" ]] \
                || die "The retained legacy PostgreSQL image is no longer the reviewed UID/GID-999 runtime."
            POSTGRES_MIGRATION_REQUIRED=true
            ;;
        "$POSTGRES_STORAGE_GENERATION")
            [[ "$MIGRATE_POSTGRES_RUNTIME" == false ]] \
                || die "PostgreSQL storage is already generation ${POSTGRES_STORAGE_GENERATION}; rerun without --migrate-postgres-runtime."
            [[ "$active_exists" == true ]] \
                || die "The completed PostgreSQL generation is missing its canonical active volume."
            case "$intent" in
                new-empty-v1)
                    [[ "$old_exists" == false && -z "$retired_image_id" ]] \
                        || die "Fresh PostgreSQL storage unexpectedly has retired Debian evidence."
                    ;;
                migrated-debian-v1|migrated-debian-generation2-v1)
                    [[ "$old_exists" == true && "$retired_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
                        || die "Migrated PostgreSQL storage is missing its detached legacy volume or exact retired image ID."
                    [[ "$database_generation" == "3" ]] \
                        || die "Completed PostgreSQL storage requires completed generation-3 database identities."
                    ;;
                *) die "Completed PostgreSQL storage has an unsupported intent." ;;
            esac
            ;;
        *) die "Unsupported BACKUPSHEEP_POSTGRES_STORAGE_GENERATION=${state}." ;;
    esac

    expected_witness="$(sha256_text "BackupSheep/postgres-storage/v1|${installation_id}|${PROJECT_NAME}|${POSTGRES_STORAGE_LOGICAL_VOLUME}|${POSTGRES_STORAGE_GENERATION}|icu=und|${intent}")"
    [[ "$witness" == "$expected_witness" ]] \
        || die "BACKUPSHEEP_POSTGRES_STORAGE_WITNESS does not match this installation, volume, runtime, ICU locale, and intent."
}

configure_staging_layout_witness() {
    local intent=""
    local witness=""
    local installation_id=""
    local database_generation=""
    local expected=""
    local capacity_key=""
    local capacity_default=""

    intent="$(read_env_value BACKUPSHEEP_STAGING_LAYOUT_INTENT)"
    witness="$(read_env_value BACKUPSHEEP_STAGING_LAYOUT_WITNESS)"
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    database_generation="$(read_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION)"
    if [[ -n "$intent" || -n "$witness" ]]; then
        [[ "$MIGRATE_STAGING_LAYOUT" != true ]] \
            || die "The staging layout already has an installation witness; rerun without --migrate-staging-layout."
        [[ "$intent" == "new-empty-v3" || "$intent" == "migrate-empty-legacy-v3" ]] \
            || die "BACKUPSHEEP_STAGING_LAYOUT_INTENT is invalid."
        expected="$(sha256_text "BackupSheep/staging-layout/v3|${installation_id}|${intent}")"
        [[ "$witness" == "$expected" ]] \
            || die "The staging layout witness does not match this installation and intent."
        :
    else
        if [[ "$ENV_WAS_PRESENT" != true || "$database_generation" == "3-pending-fresh" ]]; then
            [[ "$MIGRATE_STAGING_LAYOUT" != true ]] \
                || die "--migrate-staging-layout is valid only for a real existing installation."
            intent="new-empty-v3"
        else
            [[ "$MIGRATE_STAGING_LAYOUT" == true ]] \
                || die "Existing installations must stop provider operations, drain/quarantine the legacy shared work volume, and rerun once with --migrate-staging-layout."
            intent="migrate-empty-legacy-v3"
        fi
        witness="$(sha256_text "BackupSheep/staging-layout/v3|${installation_id}|${intent}")"
        set_env_value BACKUPSHEEP_STAGING_LAYOUT_INTENT "$intent"
        set_env_value BACKUPSHEEP_STAGING_LAYOUT_WITNESS "$witness"
    fi

    for capacity_key in \
        BACKUPSHEEP_STAGING_MIN_FREE_BYTES:536870912 \
        BACKUPSHEEP_STAGING_MIN_FREE_INODES:1024 \
        BACKUPSHEEP_PRIVATE_MIN_FREE_BYTES:536870912 \
        BACKUPSHEEP_PRIVATE_MIN_FREE_INODES:1024 \
        BACKUPSHEEP_TRANSFER_MIN_FREE_BYTES:536870912 \
        BACKUPSHEEP_TRANSFER_MIN_FREE_INODES:1024 \
        BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_BYTES:536870912 \
        BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_INODES:1024; do
        capacity_default="${capacity_key#*:}"
        capacity_key="${capacity_key%%:*}"
        if [[ -z "$(read_env_value "$capacity_key")" ]]; then
            set_env_value "$capacity_key" "$capacity_default"
        fi
    done
}

configure_artifact_key_policy() {
    local existing_provider=""
    local generation=""
    local witness=""
    local expected_witness=""
    local installation_id=""
    local rollback_path=""
    local rollback_digest=""
    local recorded_rollback_digest=""

    existing_provider="$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER)"
    generation="$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION)"
    witness="$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS)"
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    rollback_path="$(artifact_provider_rollback_path)"
    if [[ "$ENV_WAS_PRESENT" != true ]]; then
        [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" != true ]] \
            || die "--migrate-artifact-key-provider-empty is valid only for an existing installation."
        generation=1
    elif [[ "$existing_provider" == local-file ]]; then
        case "$generation" in
            1)
                if [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" == true ]]; then
                    [[ -e "$rollback_path" && ! -L "$rollback_path" ]] \
                        || die "The artifact key provider is already generation 1; rerun without --migrate-artifact-key-provider-empty."
                    validate_artifact_provider_rollback
                elif [[ -e "$rollback_path" || -L "$rollback_path" ]]; then
                    die "Artifact-provider transition cleanup is pending; rerun once with --migrate-artifact-key-provider-empty."
                fi
                ;;
            1-pending-empty)
                [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" == true ]] \
                    || die "Artifact key-provider migration is pending; rerun with --migrate-artifact-key-provider-empty while operations remain disabled."
                validate_artifact_provider_rollback
                ;;
            '')
                [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" != true ]] \
                    || die "The installed local-file provider does not need the legacy empty-provider migration flag."
                generation=1
                ;;
            *) die "The artifact key-provider generation is unsupported." ;;
        esac
    elif [[ -z "$existing_provider" || "$existing_provider" == local-development \
        || "$existing_provider" == aws-kms ]]; then
        [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" == true ]] \
            || die "This existing installation needs the explicit --migrate-artifact-key-provider-empty transition. It succeeds only if the current migration proves zero data-key wraps, plaintext artifact ledgers, and historical database/files backup or storage-point rows."
        [[ -z "$generation" && -z "$witness" ]] \
            || die "The legacy artifact provider has unexpected generation metadata."
        preserve_artifact_provider_rollback
        generation=1-pending-empty
    else
        die "The existing installation uses an unsupported artifact key provider. Automatic cryptographic conversion would destroy restore access; recover or rewrap those artifacts under an explicitly reviewed migration before upgrading."
    fi

    expected_witness="$(sha256_text "BackupSheep/artifact-key-provider/v1|${installation_id}|local-file|generation=${generation}")"
    if [[ -n "$witness" && "$witness" != "$expected_witness" ]]; then
        die "The artifact key-provider witness does not match this installation and generation."
    fi
    if [[ "$generation" == 1-pending-empty ]]; then
        validate_artifact_provider_rollback
        rollback_digest="$(sha256_file "$rollback_path")"
        recorded_rollback_digest="$(read_env_value BACKUPSHEEP_ARTIFACT_PROVIDER_ROLLBACK_SHA256)"
        [[ -z "$recorded_rollback_digest" || "$recorded_rollback_digest" == "$rollback_digest" ]] \
            || die "The artifact-provider transition rollback changed during a pending migration."
    fi
    write_artifact_key_policy "$generation" "$expected_witness"
    configure_artifact_keyrings true
}

write_artifact_key_policy() {
    local generation="$1"
    local witness="$2"
    local temporary=""
    local chunk_size=""
    local rollback_digest=""

    [[ "$generation" == 1 || "$generation" == 1-pending-empty ]] \
        || die "Internal artifact key-provider generation is invalid."
    [[ "$witness" =~ ^[0-9a-f]{64}$ ]] \
        || die "Internal artifact key-provider witness is invalid."
    chunk_size="$(read_env_value BACKUPSHEEP_ARTIFACT_CHUNK_SIZE)"
    if [[ -n "$chunk_size" ]]; then
        [[ "$chunk_size" =~ ^[0-9]{1,9}$ ]] \
            && (( 10#$chunk_size >= 65536 && 10#$chunk_size <= 67108864 )) \
            || die "BACKUPSHEEP_ARTIFACT_CHUNK_SIZE must be between 65536 and 67108864."
    fi
    if [[ "$generation" == 1-pending-empty ]]; then
        validate_artifact_provider_rollback
        rollback_digest="$(sha256_file "$(artifact_provider_rollback_path)")"
    fi
    temporary="$(mktemp "${INSTALL_DIR}/.env-artifact-policy.XXXXXXXX")"
    if ! awk '
        $0 !~ /^BACKUPSHEEP_ARTIFACT_[A-Z0-9_]*=/ &&
        $0 !~ /^AWS_ENDPOINT_URL_KMS=/
    ' "$ENV_FILE" > "$temporary"; then
        rm -f -- "$temporary"
        die "Could not prepare the artifact key-provider policy."
    fi
    if ! {
        printf "BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE='bse1'\n"
        printf "BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE='true'\n"
        printf "BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE='false'\n"
        printf "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER='local-file'\n"
        printf "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION='%s'\n" "$generation"
        printf "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS='%s'\n" "$witness"
        if [[ -n "$rollback_digest" ]]; then
            printf "BACKUPSHEEP_ARTIFACT_PROVIDER_ROLLBACK_SHA256='%s'\n" "$rollback_digest"
        fi
        printf "BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH=''\n"
        printf "BACKUPSHEEP_ARTIFACT_LOCAL_WRAPPING_KEY=''\n"
        printf "BACKUPSHEEP_ARTIFACT_LOCAL_KEY_ID='local-v1'\n"
        if [[ -n "$chunk_size" ]]; then
            printf "BACKUPSHEEP_ARTIFACT_CHUNK_SIZE='%s'\n" "$chunk_size"
        fi
    } >> "$temporary"; then
        rm -f -- "$temporary"
        die "Could not write the artifact key-provider policy."
    fi
    chmod 0600 "$temporary"
    mv -f -- "$temporary" "$ENV_FILE" \
        || { rm -f -- "$temporary"; die "Could not atomically publish the artifact key-provider policy."; }
}

seal_artifact_key_provider_migration() {
    local generation=""
    local witness=""
    local expected_witness=""
    local installation_id=""
    local rollback_path=""

    generation="$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION)"
    witness="$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS)"
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    rollback_path="$(artifact_provider_rollback_path)"
    expected_witness="$(sha256_text "BackupSheep/artifact-key-provider/v1|${installation_id}|local-file|generation=${generation}")"
    [[ "$witness" == "$expected_witness" ]] \
        || die "The artifact key-provider witness changed before completion."
    case "$generation" in
        1)
            if [[ ! -e "$rollback_path" && ! -L "$rollback_path" ]]; then
                return
            fi
            [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" == true ]] \
                || die "Artifact-provider transition cleanup requires its explicit flag."
            validate_artifact_provider_rollback
            ;;
        1-pending-empty)
            [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" == true ]] \
                || die "Artifact key-provider migration cannot seal without its explicit flag."
            validate_artifact_provider_rollback
            ;;
        *) die "Cannot seal unsupported artifact key-provider generation ${generation}." ;;
    esac

    # The migrate service has exited successfully before this function is called.
    # The current migrate one-shot proves that no prior-provider wrap or legacy
    # plaintext artifact record exists. Publish the final deployment witness so the
    # new processes can boot, but retain the prior policy and credentials until the
    # rendered model, security preflight, and healthy web process all succeed.
    generation=1
    witness="$(sha256_text "BackupSheep/artifact-key-provider/v1|${installation_id}|local-file|generation=${generation}")"
    write_artifact_key_policy "$generation" "$witness"
}

complete_artifact_key_provider_migration() {
    local generation=""
    local witness=""
    local expected_witness=""
    local installation_id=""
    local legacy_secret=""
    local rollback_path=""

    generation="$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION)"
    witness="$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS)"
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    rollback_path="$(artifact_provider_rollback_path)"
    expected_witness="$(sha256_text "BackupSheep/artifact-key-provider/v1|${installation_id}|local-file|generation=1")"
    [[ "$generation" == 1 && "$witness" == "$expected_witness" ]] \
        || die "Artifact key-provider cleanup requires the sealed generation-1 witness."
    if [[ ! -e "$rollback_path" && ! -L "$rollback_path" ]]; then
        return
    fi
    [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" == true ]] \
        || die "Artifact-provider transition cleanup requires its explicit flag."
    validate_artifact_provider_rollback

    # This runs only after the current image passed model validation, authenticated
    # database preflight, and the web/guard pair became healthy. Until that point
    # the exact prior provider policy and credentials remain available for rollback.
    # Validate the complete historical credential set before deleting any member;
    # a malformed second lane must never cause partial retirement of the first.
    for legacy_secret in "${LEGACY_ARTIFACT_PROVIDER_SECRET_NAMES[@]}"; do
        legacy_secret="${SECRETS_DIR}/${legacy_secret}"
        if [[ -e "$legacy_secret" || -L "$legacy_secret" ]]; then
            [[ -f "$legacy_secret" && ! -L "$legacy_secret" \
                && "$(file_uid "$legacy_secret")" == "$EUID" \
                && "$(file_mode "$legacy_secret")" == 444 \
                && "$(file_links "$legacy_secret")" == 1 ]] \
                || die "A retired artifact-provider credential has unsafe metadata; preserve the rollback and stop."
        fi
    done
    for legacy_secret in "${LEGACY_ARTIFACT_PROVIDER_SECRET_NAMES[@]}"; do
        legacy_secret="${SECRETS_DIR}/${legacy_secret}"
        if [[ -e "$legacy_secret" ]]; then
            rm -f -- "$legacy_secret" \
                || die "Could not retire a historical artifact-provider credential after deployment acceptance."
        fi
    done
    validate_artifact_provider_rollback
    rm -f -- "$rollback_path" \
        || die "Could not retire the artifact-provider transition rollback after deployment acceptance."
    sync || die "Artifact-provider transition cleanup was not durably flushed; inspect protected storage before continuing."
}

adopt_legacy_compose_down_project() {
    local installation_id=""
    local container_listing=""
    local network_listing=""
    local volume_listing=""
    local all_volume_names=""
    local resource_id=""
    local resource_name=""
    local resource_project=""
    local logical_name=""
    local resource_installation_id=""
    local expected_name=""
    local sentinel_name="${PROJECT_NAME}_installation_identity"
    local created_name=""
    local inspected_name=""
    local saw_pgdata=false
    local saw_rabbitmq_data=false
    local saw_backup_workdir=false
    local saw_backup_storage=false
    local volume_count=0

    [[ -n "$ADOPT_LEGACY_PROJECT" && "$ADOPT_LEGACY_PROJECT" == "$PROJECT_NAME" ]] \
        || die "Legacy compose-down adoption requires --adopt-legacy-project with the exact project name."

    # This escape hatch is intentionally narrower than ordinary ownership validation.
    # It recognizes only the stock four-volume layout from releases that predate the
    # installation-identity sentinel, and only after `compose down` removed every
    # project container and network. No generic ownership rule is weakened.
    container_listing="$(
        "$DOCKER_BIN" ps --all --quiet \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}"
    )" || die "Could not inventory legacy project containers; refusing adoption."
    [[ -z "$container_listing" ]] \
        || die "Legacy project adoption requires zero project containers. Rerun without the adoption flag so exact-path ownership can be validated."

    network_listing="$(
        "$DOCKER_BIN" network ls --quiet \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}"
    )" || die "Could not inventory legacy project networks; refusing adoption."
    [[ -z "$network_listing" ]] \
        || die "Legacy project adoption requires zero project networks; run the reviewed compose-down procedure first."

    volume_listing="$(
        "$DOCKER_BIN" volume ls --quiet \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}"
    )" || die "Could not inventory legacy project volumes; refusing adoption."
    all_volume_names="$("$DOCKER_BIN" volume ls --format '{{.Name}}')" \
        || die "Could not inventory Docker volume names; refusing legacy adoption."

    while IFS= read -r resource_id; do
        [[ -n "$resource_id" ]] || continue
        volume_count=$((volume_count + 1))
        resource_name="$("$DOCKER_BIN" volume inspect --format '{{.Name}}' "$resource_id")" \
            || die "Could not inspect a legacy project volume name; refusing adoption."
        resource_project="$(docker_resource_label volume "$resource_id" com.docker.compose.project)" \
            || die "Could not inspect a legacy project volume label; refusing adoption."
        logical_name="$(docker_resource_label volume "$resource_id" com.docker.compose.volume)" \
            || die "Could not inspect a legacy project volume label; refusing adoption."
        resource_installation_id="$(docker_resource_label volume "$resource_id" com.backupsheep.installation-id)" \
            || die "Could not inspect a legacy project volume identity; refusing adoption."

        [[ "$resource_project" == "$PROJECT_NAME" ]] \
            || die "A candidate legacy volume has a mismatched Compose project label; refusing adoption."
        [[ -z "$resource_installation_id" ]] \
            || die "A candidate legacy volume already carries a BackupSheep installation identity; use normal ownership validation instead."
        expected_name="${PROJECT_NAME}_${logical_name}"
        [[ "$resource_name" == "$expected_name" ]] \
            || die "Legacy volume ${resource_name} does not have the exact stock Compose name for ${logical_name}; refusing adoption."

        case "$logical_name" in
            pgdata)
                [[ "$saw_pgdata" != true ]] || die "Duplicate legacy pgdata volume; refusing adoption."
                saw_pgdata=true
                ;;
            rabbitmq_data)
                [[ "$saw_rabbitmq_data" != true ]] || die "Duplicate legacy rabbitmq_data volume; refusing adoption."
                saw_rabbitmq_data=true
                ;;
            backup_workdir)
                [[ "$saw_backup_workdir" != true ]] || die "Duplicate legacy backup_workdir volume; refusing adoption."
                saw_backup_workdir=true
                ;;
            backup_storage)
                [[ "$saw_backup_storage" != true ]] || die "Duplicate legacy backup_storage volume; refusing adoption."
                saw_backup_storage=true
                ;;
            *)
                die "Legacy project has unexpected Compose volume ${logical_name}; refusing adoption."
                ;;
        esac
    done <<< "$volume_listing"

    [[ "$volume_count" -eq 4 \
        && "$saw_pgdata" == true \
        && "$saw_rabbitmq_data" == true \
        && "$saw_backup_workdir" == true \
        && "$saw_backup_storage" == true ]] \
        || die "Legacy adoption requires exactly pgdata, rabbitmq_data, backup_workdir and backup_storage volumes."

    for expected_name in \
        "${PROJECT_NAME}_pgdata" \
        "${PROJECT_NAME}_rabbitmq_data" \
        "${PROJECT_NAME}_backup_workdir" \
        "${PROJECT_NAME}_backup_storage"; do
        grep -Fxq -- "$expected_name" <<< "$all_volume_names" \
            || die "Legacy stock volume ${expected_name} is missing from the complete Docker inventory."
    done
    while IFS= read -r resource_name; do
        [[ -n "$resource_name" ]] || continue
        case "$resource_name" in
            "${PROJECT_NAME}_pgdata"|\
            "${PROJECT_NAME}_rabbitmq_data"|\
            "${PROJECT_NAME}_backup_workdir"|\
            "${PROJECT_NAME}_backup_storage")
                ;;
            "$sentinel_name")
                die "The installation-identity volume name already exists; refusing to adopt or relabel it."
                ;;
            "${PROJECT_NAME}_ssh_trust")
                die "The newer ssh_trust volume already exists; this is not the exact four-volume legacy layout."
                ;;
            "${PROJECT_NAME}_"*)
                die "Unexpected project-prefixed Docker volume ${resource_name} exists outside the labeled legacy set; refusing adoption."
                ;;
        esac
    done <<< "$all_volume_names"

    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    [[ "$installation_id" =~ ^[0-9a-f]{64}$ ]] \
        || die "A stable installation identity is required before legacy adoption."

    created_name="$(
        "$DOCKER_BIN" volume create \
            --label "com.docker.compose.project=${PROJECT_NAME}" \
            --label "com.docker.compose.volume=installation_identity" \
            --label "com.backupsheep.installation-id=${installation_id}" \
            "$sentinel_name"
    )" || die "Could not create the legacy-adoption ownership sentinel; no Compose services were mutated."
    [[ "$created_name" == "$sentinel_name" ]] \
        || die "Docker returned an unexpected ownership-sentinel name; refusing to continue."

    inspected_name="$("$DOCKER_BIN" volume inspect --format '{{.Name}}' "$sentinel_name")" \
        || die "Could not re-inspect the new ownership sentinel; refusing to continue."
    resource_project="$(docker_resource_label volume "$sentinel_name" com.docker.compose.project)" \
        || die "Could not verify the new ownership sentinel project label."
    logical_name="$(docker_resource_label volume "$sentinel_name" com.docker.compose.volume)" \
        || die "Could not verify the new ownership sentinel logical label."
    resource_installation_id="$(docker_resource_label volume "$sentinel_name" com.backupsheep.installation-id)" \
        || die "Could not verify the new ownership sentinel identity label."
    [[ "$inspected_name" == "$sentinel_name" \
        && "$resource_project" == "$PROJECT_NAME" \
        && "$logical_name" == "installation_identity" \
        && "$resource_installation_id" == "$installation_id" ]] \
        || die "The new ownership sentinel did not retain every exact required label; refusing to continue."
}

ensure_compose_project_name() {
    local persisted_project=""
    local installation_id=""
    local container_listing=""
    local sentinel_listing=""
    local resource_id=""
    local working_dir=""
    local config_files=""
    local candidate=""
    local candidates=""
    local candidate_count=0
    local expected_config=""

    expected_config="$(expected_compose_config_files)"

    persisted_project="$(read_env_value BACKUPSHEEP_COMPOSE_PROJECT_NAME)"
    if [[ -n "$persisted_project" ]]; then
        valid_compose_project_name "$persisted_project" \
            || die "BACKUPSHEEP_COMPOSE_PROJECT_NAME is malformed."
        [[ "$persisted_project" == "$PROJECT_NAME" ]] \
            || die "Compose project drift refused: this installation is bound to ${persisted_project}, not ${PROJECT_NAME}. Rerun with --project-name ${persisted_project}."
        [[ -z "$ADOPT_LEGACY_PROJECT" ]] \
            || die "This installation already has a persisted Compose project. Rerun without --adopt-legacy-project."
        return
    fi

    if [[ "$ENV_WAS_PRESENT" != true ]]; then
        [[ -z "$ADOPT_LEGACY_PROJECT" ]] \
            || die "--adopt-legacy-project is only valid for an existing legacy installation."
        set_env_value BACKUPSHEEP_COMPOSE_PROJECT_NAME "$PROJECT_NAME"
        return
    fi

    # Legacy installations predate the persisted project-name witness. Infer it only
    # from exact installation-path container labels or the installation-id sentinel.
    # If a prior `compose down` removed both, require explicit operator migration
    # rather than guessing and accidentally creating a second, empty stack.
    container_listing="$("$DOCKER_BIN" ps --all --quiet)" \
        || die "Could not inventory Docker containers while adopting the Compose project name."
    while IFS= read -r resource_id; do
        [[ -n "$resource_id" ]] || continue
        working_dir="$(docker_resource_label container "$resource_id" com.docker.compose.project.working_dir)" \
            || die "Could not inspect a Docker container while adopting the Compose project name."
        config_files="$(docker_resource_label container "$resource_id" com.docker.compose.project.config_files)" \
            || die "Could not inspect a Docker container while adopting the Compose project name."
        [[ "$working_dir" == "$INSTALL_DIR" && "$config_files" == "$expected_config" ]] \
            || continue
        candidate="$(docker_resource_label container "$resource_id" com.docker.compose.project)" \
            || die "Could not inspect an exact-path container project label while adopting the Compose project name."
        [[ -n "$candidate" ]] \
            || die "An exact-path Compose container has no project label; refusing adoption."
        valid_compose_project_name "$candidate" \
            || die "An exact-path Compose container has a malformed project label; refusing adoption."
        if ! grep -Fxq -- "$candidate" <<< "$candidates"; then
            candidates="${candidates}${candidates:+$'\n'}${candidate}"
            candidate_count=$((candidate_count + 1))
        fi
    done <<< "$container_listing"

    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    sentinel_listing="$(
        "$DOCKER_BIN" volume ls --quiet \
            --filter "label=com.backupsheep.installation-id=${installation_id}"
    )" || die "Could not inventory the Compose ownership sentinel while adopting the project name."
    while IFS= read -r resource_id; do
        [[ -n "$resource_id" ]] || continue
        candidate="$(docker_resource_label volume "$resource_id" com.docker.compose.project)" \
            || die "Could not inspect an installation-id sentinel project label while adopting the Compose project name."
        [[ -n "$candidate" ]] \
            || die "An installation-id sentinel has no Compose project label; refusing adoption."
        valid_compose_project_name "$candidate" \
            || die "An installation-id sentinel has a malformed project label; refusing adoption."
        if ! grep -Fxq -- "$candidate" <<< "$candidates"; then
            candidates="${candidates}${candidates:+$'\n'}${candidate}"
            candidate_count=$((candidate_count + 1))
        fi
    done <<< "$sentinel_listing"

    [[ "$candidate_count" -le 1 ]] \
        || die "Multiple Compose projects claim this installation path or identity; refusing adoption."
    if [[ "$candidate_count" -eq 0 ]]; then
        if [[ -z "$ADOPT_LEGACY_PROJECT" ]]; then
            die "Cannot infer the legacy Compose project name safely. If an old stock Compose down left exactly four data volumes, review them and rerun once with --adopt-legacy-project NAME; otherwise restore an exact-path or installation-id witness."
        fi
        adopt_legacy_compose_down_project
        set_env_value BACKUPSHEEP_COMPOSE_PROJECT_NAME "$PROJECT_NAME"
        return
    fi
    [[ "$candidates" == "$PROJECT_NAME" ]] \
        || die "Legacy Compose project ${candidates} was discovered for this installation. Rerun with --project-name ${candidates}."
    [[ -z "$ADOPT_LEGACY_PROJECT" ]] \
        || die "A normal exact-path or installation-id ownership witness exists. Rerun without --adopt-legacy-project."
    set_env_value BACKUPSHEEP_COMPOSE_PROJECT_NAME "$PROJECT_NAME"
}

validate_egress_policy_generation_two() {
    local role=""
    local mode=""
    local legacy_ipv4=""
    local legacy_ipv6=""
    local ipv4_endpoints=""
    local ipv6_endpoints=""
    local dns_names=""

    for role in "${EGRESS_ROLES[@]}"; do
        mode="$(read_env_value "BACKUPSHEEP_${role}_EGRESS_MODE")"
        legacy_ipv4="$(read_env_value "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV4")"
        legacy_ipv6="$(read_env_value "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV6")"
        ipv4_endpoints="$(read_env_value "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS")"
        ipv6_endpoints="$(read_env_value "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV6_TCP_ENDPOINTS")"
        dns_names="$(read_env_value "BACKUPSHEEP_${role}_EGRESS_ALLOW_DNS_NAMES")"

        [[ -z "$legacy_ipv4" && -z "$legacy_ipv6" ]] \
            || die "Address-only ${role} egress allowlists are retired. Use exact CIDR:TCP-port endpoints."
        [[ "${#ipv4_endpoints}" -le 8192 && "$ipv4_endpoints" != *[!0-9./:,[:space:]]* ]] \
            || die "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS is malformed or too long."
        [[ "${#ipv6_endpoints}" -le 8192 && "$ipv6_endpoints" != *[!0-9A-Fa-f:/\[\],[:space:]]* ]] \
            || die "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV6_TCP_ENDPOINTS is malformed or too long."
        [[ "${#dns_names}" -le 4096 && "$dns_names" != *[!A-Za-z0-9_.\-,[:space:]]* ]] \
            || die "BACKUPSHEEP_${role}_EGRESS_ALLOW_DNS_NAMES is malformed or too long."
        case "$mode" in
            deny)
                [[ -z "$ipv4_endpoints" && -z "$ipv6_endpoints" && -z "$dns_names" ]] \
                    || die "Deny-mode ${role} egress cannot carry outward endpoints or DNS names."
                ;;
            allowlist)
                [[ -n "$ipv4_endpoints" || -n "$ipv6_endpoints" ]] \
                    || die "Allowlist-mode ${role} egress requires at least one exact TCP endpoint."
                ;;
            public)
                [[ -z "$dns_names" ]] \
                    || die "Public-mode ${role} egress uses normal DNS and must not carry an ignored exact-name list."
                ;;
            *)
                die "BACKUPSHEEP_${role}_EGRESS_MODE must be deny, allowlist, or public."
                ;;
        esac
    done
}

configure_egress_policy_generation() {
    local generation=""
    local role=""
    local mode=""
    local all_public=true
    local all_blank=true
    local all_deny=true
    local lists_blank=true
    local key=""

    generation="$(read_env_value BACKUPSHEEP_EGRESS_POLICY_GENERATION)"
    case "$generation" in
        2)
            [[ "$MIGRATE_EGRESS_POLICY" != true ]] \
                || die "--migrate-egress-policy is one-time and this installation already uses generation 2."
            validate_egress_policy_generation_two
            return
            ;;
        '') ;;
        *)
            die "Unsupported BACKUPSHEEP_EGRESS_POLICY_GENERATION=${generation}; refusing to guess outbound policy."
            ;;
    esac

    [[ "$ENV_WAS_PRESENT" == true ]] \
        || die "A fresh installation is missing required egress policy generation 2."
    [[ "$MIGRATE_EGRESS_POLICY" == true ]] \
        || die "This existing installation predates fail-closed egress generation 2. Review outbound dependencies, then rerun once with --migrate-egress-policy."

    for role in "${EGRESS_ROLES[@]}"; do
        mode="$(read_env_value "BACKUPSHEEP_${role}_EGRESS_MODE")"
        [[ "$mode" == public ]] || all_public=false
        [[ -z "$mode" ]] || all_blank=false
        [[ "$mode" == deny ]] || all_deny=false
        for key in \
            "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV4" \
            "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV6" \
            "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS" \
            "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV6_TCP_ENDPOINTS" \
            "BACKUPSHEEP_${role}_EGRESS_ALLOW_DNS_NAMES"; do
            [[ -z "$(read_env_value "$key")" ]] || lists_blank=false
        done
    done
    [[ "$lists_blank" == true && \
        ( "$all_public" == true || "$all_blank" == true || "$all_deny" == true ) ]] \
        || die "Customized legacy egress cannot be migrated automatically. Preserve it for review, reset all six roles to deny with every old/new allowlist blank, then rerun --migrate-egress-policy."

    # The explicit one-time flag authorizes the availability-impacting safe reset.
    # Operations stay unable to reach public providers until the operator configures
    # reviewed exact endpoint tuples under generation 2.
    for role in "${EGRESS_ROLES[@]}"; do
        set_env_value "BACKUPSHEEP_${role}_EGRESS_MODE" deny
        set_env_value "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV4" ""
        set_env_value "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV6" ""
        set_env_value "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS" ""
        set_env_value "BACKUPSHEEP_${role}_EGRESS_ALLOW_IPV6_TCP_ENDPOINTS" ""
        set_env_value "BACKUPSHEEP_${role}_EGRESS_ALLOW_DNS_NAMES" ""
    done
    set_env_value BACKUPSHEEP_EGRESS_POLICY_GENERATION 2
    validate_egress_policy_generation_two
}

create_or_migrate_configuration() {
    local bootstrap_state="" secret_path="" secret_name=""
    ENV_FILE="${INSTALL_DIR}/.env"
    SECRETS_DIR="${INSTALL_DIR}/.secrets"

    if [[ -e "$ENV_FILE" || -L "$ENV_FILE" ]]; then
        ENV_WAS_PRESENT=true
        validate_env_file
        bootstrap_state="$(read_env_value BACKUPSHEEP_INSTALLATION_BOOTSTRAP_STATE)"
        case "$bootstrap_state" in
            pending-fresh)
                FRESH_CONFIG_PENDING=true
                [[ "$(read_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION)" == "3-pending-fresh" ]] \
                    || die "Pending fresh configuration lost its database generation witness."
                [[ "$MIGRATE_DATABASE_IDENTITIES" == false \
                    && "$MIGRATE_RABBITMQ_IDENTITIES" == false \
                    && "$MIGRATE_STAGING_LAYOUT" == false \
                    && "$MIGRATE_EGRESS_POLICY" == false \
                    && "$MIGRATE_POSTGRES_RUNTIME" == false \
                    && "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" == false \
                    && "$ROTATE_CELERY_SIGNING_KEYS" == false \
                    && -z "$ARTIFACT_LOCAL_FILE_ROTATE_LANE" ]] \
                    || die "A pending fresh configuration cannot be combined with migration or rotation flags."
                log "Resuming the exact pending fresh configuration"
                ;;
            complete|'')
                FRESH_CONFIG_PENDING=false
                log "Preserving and validating existing configuration"
                ;;
            *) die "Unsupported BACKUPSHEEP_INSTALLATION_BOOTSTRAP_STATE=${bootstrap_state}." ;;
        esac
    else
        [[ -z "$ARTIFACT_LOCAL_FILE_ROTATE_LANE" ]] \
            || die "--rotate-artifact-keyring is valid only after a completed installation exists."
        log "Creating a protected production configuration"
        # Publish every fresh-generation marker, endpoint, and image-source field
        # in one durable rename. A kill can leave either no .env or the complete
        # initial contract, never a legacy-looking prefix of the fresh state.
        create_fresh_env_atomically
    fi

    if [[ -e "$SECRETS_DIR" || -L "$SECRETS_DIR" ]]; then
        validate_secret_dir
    else
        install -d -m 0700 -- "$SECRETS_DIR"
    fi

    ensure_installation_id
    configure_staging_layout_witness
    ensure_compose_project_name
    configure_postgres_storage_generation
    configure_egress_policy_generation
    configure_artifact_key_policy

    if [[ "$FRESH_CONFIG_PENDING" == true ]]; then
        for secret_name in django_secret_key onboarding_token; do
            secret_path="${SECRETS_DIR}/${secret_name}"
            if [[ -e "$secret_path" || -L "$secret_path" ]]; then
                validate_secret_file "$secret_path"
            elif [[ "$secret_name" == django_secret_key ]]; then
                write_secret_file "$secret_name" "$(random_hex 48)"
            else
                write_secret_file "$secret_name" "$(random_hex 32)"
            fi
        done
    elif [[ "$ENV_WAS_PRESENT" == true ]]; then
        reject_connection_url_overrides
        migrate_one_secret DJANGO_SECRET_KEY django_secret_key false
        migrate_one_secret ONBOARDING_INSTALL_TOKEN onboarding_token true
    else
        write_secret_file django_secret_key "$(random_hex 48)"
        write_secret_file onboarding_token "$(random_hex 32)"
    fi
    configure_database_identity_generation
    configure_rabbitmq_identity_generation
    prepare_managed_ssh_private_keys

    validate_secret_dir
    configure_image_source
    rewrite_env_for_secret_files
    validate_env_file
    if [[ "$FRESH_CONFIG_PENDING" == true ]]; then
        # The pending marker is the commit record: first force every prior env
        # rename and secret directory entry to durable storage, then publish the
        # completed state atomically, and finally flush that commit record.
        sync || die "Could not durably stage the completed fresh configuration."
        set_env_value BACKUPSHEEP_INSTALLATION_BOOTSTRAP_STATE complete
        sync || die "Could not durably complete the fresh configuration witness."
        FRESH_CONFIG_PENDING=false
        validate_env_file
    fi
}

validate_runtime_configuration() {
    local value=""
    local key=""
    local secret_name=""
    local bootstrap_user=""
    local migrator_user=""
    local lane=""
    local variable=""
    local role=""
    local left_role=""
    local right_role=""
    local left_value=""
    local right_value=""
    local staging_intent=""
    local staging_witness=""
    local installation_id=""
    local expected_staging_witness=""
    local postgres_storage_state=""
    local postgres_storage_intent=""
    local postgres_storage_witness=""
    local expected_postgres_storage_witness=""
    local artifact_provider_generation=""
    local artifact_provider_witness=""
    local expected_artifact_provider_witness=""
    local artifact_provider_rollback=""
    local artifact_provider_rollback_digest=""
    local managed_database_public=""
    local managed_files_public=""
    local -a database_role_variables=(DB_BOOTSTRAP_USER DB_MIGRATOR_USER)

    for lane in "${DATABASE_LANES[@]}"; do
        case "$lane" in
            app) variable=DB_APP_USER ;;
            preflight) variable=DB_PREFLIGHT_USER ;;
            beat) variable=DB_BEAT_USER ;;
            cloud) variable=DB_CLOUD_USER ;;
            database) variable=DB_DATABASE_USER ;;
            files) variable=DB_FILES_USER ;;
            storage) variable=DB_STORAGE_USER ;;
            logs) variable=DB_LOGS_USER ;;
            *) die "Internal database lane inventory is invalid." ;;
        esac
        database_role_variables+=("$variable")
    done

    value="$(read_env_value BACKUPSHEEP_IMAGE_MODE)"
    [[ "$value" == "$IMAGE_MODE" ]] || die "BACKUPSHEEP_IMAGE_MODE does not match this installer invocation."
    if [[ "$IMAGE_MODE" == "local-build" ]]; then
        value="$(read_env_value BACKUPSHEEP_IMAGE)"
        [[ "$value" == "backupsheep:${INSTALL_REF}" ]] \
            || die "BACKUPSHEEP_IMAGE must bind to this verified source build."
        value="$(read_env_value BACKUPSHEEP_POSTGRES_IMAGE)"
        [[ "$value" == "backupsheep-postgres:${INSTALL_REF}" ]] \
            || die "BACKUPSHEEP_POSTGRES_IMAGE must be backupsheep-postgres:${INSTALL_REF} for this verified source build."
        value="$(read_env_value BACKUPSHEEP_EGRESS_IMAGE)"
        [[ "$value" == "backupsheep-egress:${INSTALL_REF}" ]] \
            || die "BACKUPSHEEP_EGRESS_IMAGE must bind to this verified source build."
        for key in BACKUPSHEEP_RELEASE_TAG BACKUPSHEEP_RELEASE_SOURCE_COMMIT \
            BACKUPSHEEP_RELEASE_DESCRIPTOR_SHA256 BACKUPSHEEP_RELEASE_APP_IMAGE \
            BACKUPSHEEP_RELEASE_POSTGRES_IMAGE BACKUPSHEEP_RELEASE_EGRESS_IMAGE \
            BACKUPSHEEP_RELEASE_RABBITMQ_IMAGE BACKUPSHEEP_RELEASE_RABBITMQ_UPGRADE_IMAGE; do
            [[ -z "$(read_env_value "$key")" ]] || die "${key} must be blank in local-build mode."
        done
    else
        [[ "$(read_env_value BACKUPSHEEP_RELEASE_TAG)" == "$RELEASE_TAG" \
            && "$(read_env_value BACKUPSHEEP_RELEASE_SOURCE_COMMIT)" == "$INSTALL_REF" ]] \
            || die "Signed-release tag/source commit does not match this invocation."
        [[ "$(read_env_value BACKUPSHEEP_IMAGE)" == "$(read_env_value BACKUPSHEEP_RELEASE_APP_IMAGE)" \
            && "$(read_env_value BACKUPSHEEP_POSTGRES_IMAGE)" == "$(read_env_value BACKUPSHEEP_RELEASE_POSTGRES_IMAGE)" \
            && "$(read_env_value BACKUPSHEEP_EGRESS_IMAGE)" == "$(read_env_value BACKUPSHEEP_RELEASE_EGRESS_IMAGE)" \
            && "$(read_env_value BACKUPSHEEP_RABBITMQ_IMAGE)" == "$(read_env_value BACKUPSHEEP_RELEASE_RABBITMQ_IMAGE)" \
            && "$(read_env_value BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE)" == "$(read_env_value BACKUPSHEEP_RELEASE_RABBITMQ_UPGRADE_IMAGE)" ]] \
            || die "Runtime image references do not match the signed descriptor bindings."
        validate_local_release_images
    fi
    value="$(read_env_value BACKUPSHEEP_BIND_ADDRESS)"
    [[ -z "$value" || "$value" == "127.0.0.1" ]] \
        || die "The installer only starts a loopback-bound web service. Set BACKUPSHEEP_BIND_ADDRESS=127.0.0.1."
    value="$(read_env_value DJANGO_SERVER)"
    [[ "$value" == "prod" ]] || die "DJANGO_SERVER must be prod."
    value="$(read_env_value DJANGO_DEBUG)"
    [[ "$value" == "false" ]] || die "DJANGO_DEBUG must be false."
    value="$(read_env_value DJANGO_SETTINGS_MODULE)"
    [[ "$value" == "backupsheep.settings" ]] \
        || die "DJANGO_SETTINGS_MODULE must be backupsheep.settings."
    value="$(read_env_value BACKUPSHEEP_SECRETS_DIR)"
    [[ "$value" == ".secrets" ]] || die "BACKUPSHEEP_SECRETS_DIR must be .secrets."
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    [[ "$installation_id" =~ ^[0-9a-f]{64}$ ]] \
        || die "BACKUPSHEEP_INSTALLATION_ID must be one stable 64-character lowercase hexadecimal value."
    staging_intent="$(read_env_value BACKUPSHEEP_STAGING_LAYOUT_INTENT)"
    staging_witness="$(read_env_value BACKUPSHEEP_STAGING_LAYOUT_WITNESS)"
    [[ "$staging_intent" == "new-empty-v3" || "$staging_intent" == "migrate-empty-legacy-v3" ]] \
        || die "BACKUPSHEEP_STAGING_LAYOUT_INTENT is invalid."
    expected_staging_witness="$(sha256_text "BackupSheep/staging-layout/v3|${installation_id}|${staging_intent}")"
    [[ "$staging_witness" == "$expected_staging_witness" ]] \
        || die "BACKUPSHEEP_STAGING_LAYOUT_WITNESS does not match this installation."
    value="$(read_env_value BACKUPSHEEP_COMPOSE_PROJECT_NAME)"
    [[ "$value" == "$PROJECT_NAME" ]] \
        || die "BACKUPSHEEP_COMPOSE_PROJECT_NAME must match --project-name exactly."
    postgres_storage_state="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_GENERATION)"
    postgres_storage_intent="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_INTENT)"
    postgres_storage_witness="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_WITNESS)"
    case "$postgres_storage_state:$postgres_storage_intent" in
        "${POSTGRES_STORAGE_GENERATION}:new-empty-v1"|\
        "${POSTGRES_STORAGE_GENERATION}:migrated-debian-v1"|\
        "${POSTGRES_STORAGE_GENERATION}:migrated-debian-generation2-v1"|\
        "${POSTGRES_STORAGE_GENERATION}-pending-fresh:new-empty-v1"|\
        "${POSTGRES_STORAGE_GENERATION}-pending-upgrade:migrated-debian-v1"|\
        "${POSTGRES_STORAGE_GENERATION}-pending-upgrade:migrated-debian-generation2-v1") ;;
        *) die "PostgreSQL storage generation and intent are inconsistent." ;;
    esac
    expected_postgres_storage_witness="$(sha256_text "BackupSheep/postgres-storage/v1|${installation_id}|${PROJECT_NAME}|${POSTGRES_STORAGE_LOGICAL_VOLUME}|${POSTGRES_STORAGE_GENERATION}|icu=und|${postgres_storage_intent}")"
    [[ "$postgres_storage_witness" == "$expected_postgres_storage_witness" ]] \
        || die "PostgreSQL storage witness does not match the reviewed runtime and active volume."
    value="$(read_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION)"
    [[ "$value" == "3" || "$value" == "3-pending-fresh" \
        || "$value" == "3-pending-upgrade" ]] \
        || die "BACKUPSHEEP_DATABASE_IDENTITY_GENERATION must be generation 3 or an explicit generation-3 pending state."
    value="$(read_env_value BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION)"
    [[ "$value" == "2" ]] \
        || die "BACKUPSHEEP_RABBITMQ_IDENTITY_GENERATION must be 2."
    value="$(read_env_value BACKUPSHEEP_CELERY_SECURITY_GENERATION)"
    [[ "$value" == "3" ]] \
        || die "BACKUPSHEEP_CELERY_SECURITY_GENERATION must be 3."
    value="$(read_env_value BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION)"
    [[ "$value" =~ ^[1-9][0-9]{0,8}$ ]] \
        || die "BACKUPSHEEP_CELERY_SIGNING_KEY_GENERATION must be a positive bounded integer."
    for variable in "${database_role_variables[@]}"; do
        role="$(read_env_value "$variable")"
        validate_database_role_name "$variable" "$role"
    done
    [[ "$(read_env_value DB_USER)" == "$(read_env_value DB_APP_USER)" ]] \
        || die "DB_USER must remain the compatibility alias of DB_APP_USER."
    for left_role in "${database_role_variables[@]}"; do
        left_value="$(read_env_value "$left_role")"
        for right_role in "${database_role_variables[@]}"; do
            [[ "$left_role" < "$right_role" ]] || continue
            right_value="$(read_env_value "$right_role")"
            [[ "$left_value" != "$right_value" ]] \
                || die "Database roles ${left_role} and ${right_role} collide."
        done
    done
    value="$(read_env_value DB_HOST)"
    [[ "$value" == "db" ]] \
        || die "The stock database identity provisioner requires DB_HOST=db."
    value="$(read_env_value DB_PORT)"
    [[ "$value" == "5432" ]] \
        || die "The stock database identity provisioner requires DB_PORT=5432."
    value="$(read_env_value RABBITMQ_USER)"
    [[ "$value" == "backupsheep_app" ]] \
        || die "The stock application broker identity must be backupsheep_app."
    value="$(read_env_value RABBITMQ_LEGACY_USER)"
    validate_rabbitmq_role_name RABBITMQ_LEGACY_USER "$value"
    value="$(read_env_value RABBITMQ_VHOST)"
    [[ "$value" == "backupsheep" ]] \
        || die "The stock broker vhost must be backupsheep."
    value="$(read_env_value CELERY_BROKER_URL)"
    [[ -z "$value" ]] || die "CELERY_BROKER_URL must be blank for the stock file-backed broker configuration."
    value="$(read_env_value DATABASE_URL)"
    [[ -z "$value" ]] || die "DATABASE_URL must be blank for the stock file-backed database configuration."

    [[ "$(read_env_value BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE)" == "bse1" ]] \
        || die "BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE must be bse1."
    [[ "$(read_env_value BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE)" == "true" ]] \
        || die "BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE must be true."
    [[ "$(read_env_value BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE)" == "false" ]] \
        || die "BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE must be false."
    [[ "$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER)" == "local-file" ]] \
        || die "BACKUPSHEEP_ARTIFACT_KEY_PROVIDER must be local-file."
    artifact_provider_generation="$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_GENERATION)"
    artifact_provider_witness="$(read_env_value BACKUPSHEEP_ARTIFACT_KEY_PROVIDER_WITNESS)"
    if [[ "$artifact_provider_generation" != 1 ]]; then
        [[ "$artifact_provider_generation" == 1-pending-empty \
            && "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" == true ]] \
            || die "The artifact key-provider generation is not deployable."
    fi
    expected_artifact_provider_witness="$(sha256_text "BackupSheep/artifact-key-provider/v1|${installation_id}|local-file|generation=${artifact_provider_generation}")"
    [[ "$artifact_provider_witness" == "$expected_artifact_provider_witness" ]] \
        || die "The artifact key-provider witness does not match this installation and generation."
    artifact_provider_rollback="$(artifact_provider_rollback_path)"
    artifact_provider_rollback_digest="$(read_env_value BACKUPSHEEP_ARTIFACT_PROVIDER_ROLLBACK_SHA256)"
    if [[ "$artifact_provider_generation" == 1-pending-empty ]]; then
        validate_artifact_provider_rollback
        [[ "$artifact_provider_rollback_digest" == "$(sha256_file "$artifact_provider_rollback")" ]] \
            || die "The pending artifact-provider rollback does not match its protected digest."
    else
        [[ -z "$artifact_provider_rollback_digest" ]] \
            || die "A sealed artifact-provider policy must not retain a rollback digest."
        if [[ -e "$artifact_provider_rollback" || -L "$artifact_provider_rollback" ]]; then
            [[ "$MIGRATE_ARTIFACT_KEY_PROVIDER_EMPTY" == true ]] \
                || die "Artifact-provider transition cleanup requires its explicit flag."
            validate_artifact_provider_rollback
        fi
    fi
    validate_legacy_artifact_provider_secret_state
    [[ -z "$(read_env_value BACKUPSHEEP_ARTIFACT_LOCAL_FILE_KEYRING_PATH)" ]] \
        || die "The shared .env must not expose an artifact keyring path."
    [[ -z "$(read_env_value BACKUPSHEEP_ARTIFACT_LOCAL_WRAPPING_KEY)" ]] \
        || die "The shared .env must not contain artifact root key material."
    configure_artifact_keyrings false

    [[ "$(read_env_value SSH_MANAGED_LANE_ISOLATION_REQUIRED)" == "true" ]] \
        || die "SSH_MANAGED_LANE_ISOLATION_REQUIRED must be true."
    managed_database_public="$(read_env_value SSH_MANAGED_DATABASE_PUBLIC_KEY)"
    managed_files_public="$(read_env_value SSH_MANAGED_FILES_PUBLIC_KEY)"
    if [[ -n "$managed_database_public" || -n "$managed_files_public" ]]; then
        [[ "$managed_database_public" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/]+={0,3}$ \
            && "$managed_files_public" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/]+={0,3}$ ]] \
            || die "Both managed SSH lane public keys must be canonical Ed25519 identities."
        [[ "$managed_database_public" != "$managed_files_public" ]] \
            || die "Managed SSH lane public keys must be different."
    fi

    for key in \
        BACKUPSHEEP_STAGING_MIN_FREE_BYTES \
        BACKUPSHEEP_STAGING_MIN_FREE_INODES \
        BACKUPSHEEP_PRIVATE_MIN_FREE_BYTES \
        BACKUPSHEEP_PRIVATE_MIN_FREE_INODES \
        BACKUPSHEEP_TRANSFER_MIN_FREE_BYTES \
        BACKUPSHEEP_TRANSFER_MIN_FREE_INODES \
        BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_BYTES \
        BACKUPSHEEP_RESTORE_TRANSFER_MIN_FREE_INODES; do
        value="$(read_env_value "$key")"
        [[ "$value" =~ ^[0-9]{1,18}$ ]] \
            || die "${key} must be a bounded non-negative integer."
        if [[ "$key" == *_BYTES ]]; then
            (( 10#$value >= 67108864 )) \
                || die "${key} must retain at least the 64 MiB production floor."
        else
            (( 10#$value >= 128 )) \
                || die "${key} must retain at least the 128-inode production floor."
        fi
    done

    for key in \
        DJANGO_SECRET_KEY \
        DB_PASSWORD \
        RABBITMQ_PASSWORD \
        ONBOARDING_INSTALL_TOKEN \
        SSH_MANAGED_PRIVATE_KEY_PATH \
        SSH_MANAGED_PUBLIC_KEY; do
        value="$(read_env_value "$key")"
        [[ -z "$value" ]] || die "${key} must be blank after migration to file-backed secrets."
    done
    for secret_name in "${SECRET_NAMES[@]}"; do
        validate_secret_file "${SECRETS_DIR}/${secret_name}"
    done
}

env_value_or_default() {
    local key="$1" default_value="$2" value=""
    value="$(read_env_value "$key")"
    [[ -n "$value" ]] || value="$default_value"
    printf '%s' "$value"
}

validate_integer_setting() {
    local key="$1" default_value="$2" minimum="$3" maximum="$4" value=""
    value="$(env_value_or_default "$key" "$default_value")"
    [[ "$value" =~ ^(0|[1-9][0-9]{0,8})$ ]] \
        || die "${key} must be a canonical decimal integer."
    (( 10#$value >= minimum && 10#$value <= maximum )) \
        || die "${key} is outside its reviewed resource range."
}

validate_size_setting() {
    local key="$1" default_value="$2" minimum_bytes="$3" maximum_bytes="$4"
    local value="" magnitude="" unit="" multiplier=0 bytes=0
    value="$(env_value_or_default "$key" "$default_value")"
    [[ "$value" =~ ^([1-9][0-9]{0,7})([kKmMgG])$ ]] \
        || die "${key} must be an integer size with a single k, m, or g suffix."
    magnitude="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]}"
    case "$unit" in
        k|K) multiplier=1024 ;;
        m|M) multiplier=1048576 ;;
        g|G) multiplier=1073741824 ;;
        *) die "${key} has an unsupported size suffix." ;;
    esac
    bytes=$((10#$magnitude * multiplier))
    (( bytes >= minimum_bytes && bytes <= maximum_bytes )) \
        || die "${key} is outside its reviewed resource range."
}

validate_cpu_setting() {
    local key="$1" default_value="$2" value=""
    value="$(env_value_or_default "$key" "$default_value")"
    [[ "$value" =~ ^([0-9]|[1-5][0-9]|6[0-4])(\.[0-9]{1,3})?$ \
        && "$value" != 0 && "$value" != 0.0 && "$value" != 0.00 && "$value" != 0.000 \
        && ! "$value" =~ ^64\.[0-9]*[1-9][0-9]*$ ]] \
        || die "${key} must be a canonical CPU value greater than zero and no more than 64."
}

validate_duration_setting() {
    local key="$1" default_value="$2" value="" magnitude="" unit="" seconds=0
    value="$(env_value_or_default "$key" "$default_value")"
    [[ "$value" =~ ^([1-9][0-9]{0,3})([smh])$ ]] \
        || die "${key} must be a canonical nonzero duration in seconds, minutes, or hours."
    magnitude="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]}"
    case "$unit" in
        s) seconds=$((10#$magnitude)) ;;
        m) seconds=$((10#$magnitude * 60)) ;;
        h) seconds=$((10#$magnitude * 3600)) ;;
    esac
    (( seconds >= 1 && seconds <= 3600 )) \
        || die "${key} is outside its reviewed resource range."
}

validate_compose_model_settings() {
    local key="" default_value=""
    validate_integer_setting BACKUPSHEEP_BIND_PORT 8000 1 65535
    validate_integer_setting BACKUPSHEEP_PIDS_LIMIT 512 32 4096
    validate_integer_setting POSTGRES_PIDS_LIMIT 256 32 4096
    validate_integer_setting RABBITMQ_PIDS_LIMIT 512 32 4096
    validate_integer_setting DOCKER_LOG_MAX_FILE 5 1 20

    validate_size_setting DOCKER_LOG_MAX_SIZE 10m 1048576 1073741824
    validate_size_setting BACKUPSHEEP_TMPFS_SIZE 256m 16777216 2147483648
    validate_size_setting POSTGRES_TMPFS_SIZE 128m 16777216 2147483648
    validate_size_setting RABBITMQ_TMPFS_SIZE 128m 16777216 2147483648
    validate_size_setting POSTGRES_SHM_SIZE 256m 16777216 8589934592
    for key in POSTGRES_MEMORY_LIMIT RABBITMQ_MEMORY_LIMIT DB_PROVISION_MEMORY_LIMIT \
        MIGRATE_MEMORY_LIMIT DB_SEAL_MEMORY_LIMIT PREFLIGHT_MEMORY_LIMIT \
        APP_MEMORY_LIMIT WORKER_CLOUD_MEMORY_LIMIT WORKER_DATABASE_MEMORY_LIMIT \
        WORKER_FILES_MEMORY_LIMIT WORKER_STORAGE_MEMORY_LIMIT \
        WORKER_LOGS_MEMORY_LIMIT BEAT_MEMORY_LIMIT; do
        case "$key" in
            POSTGRES_MEMORY_LIMIT|APP_MEMORY_LIMIT|MIGRATE_MEMORY_LIMIT|WORKER_DATABASE_MEMORY_LIMIT|WORKER_FILES_MEMORY_LIMIT|WORKER_STORAGE_MEMORY_LIMIT) default_value=2g ;;
            RABBITMQ_MEMORY_LIMIT|DB_SEAL_MEMORY_LIMIT|PREFLIGHT_MEMORY_LIMIT|WORKER_CLOUD_MEMORY_LIMIT) default_value=1g ;;
            *) default_value=512m ;;
        esac
        validate_size_setting "$key" "$default_value" 67108864 68719476736
    done

    for key in POSTGRES_CPU_LIMIT RABBITMQ_CPU_LIMIT DB_PROVISION_CPU_LIMIT \
        MIGRATE_CPU_LIMIT DB_SEAL_CPU_LIMIT PREFLIGHT_CPU_LIMIT APP_CPU_LIMIT \
        WORKER_CLOUD_CPU_LIMIT WORKER_DATABASE_CPU_LIMIT WORKER_FILES_CPU_LIMIT \
        WORKER_STORAGE_CPU_LIMIT WORKER_LOGS_CPU_LIMIT BEAT_CPU_LIMIT; do
        case "$key" in
            POSTGRES_CPU_LIMIT|MIGRATE_CPU_LIMIT|APP_CPU_LIMIT|WORKER_CLOUD_CPU_LIMIT|WORKER_DATABASE_CPU_LIMIT|WORKER_FILES_CPU_LIMIT|WORKER_STORAGE_CPU_LIMIT) default_value=2.0 ;;
            RABBITMQ_CPU_LIMIT|DB_SEAL_CPU_LIMIT|PREFLIGHT_CPU_LIMIT|WORKER_LOGS_CPU_LIMIT) default_value=1.0 ;;
            *) default_value=0.5 ;;
        esac
        validate_cpu_setting "$key" "$default_value"
    done

    validate_duration_setting BACKUPSHEEP_STOP_GRACE_PERIOD 5m
    validate_duration_setting POSTGRES_STOP_GRACE_PERIOD 1m
    validate_duration_setting RABBITMQ_STOP_GRACE_PERIOD 3m
}

compose() {
    assert_install_parent_identity
    assert_install_root_identity
    validate_env_file
    validate_compose_model_settings
    local -a compose_environment=(
        /usr/bin/env -i
        "LC_ALL=C"
        "HOME=${HOME-}"
        "PATH=${PATH:-/usr/local/bin:/usr/bin:/bin}"
        "COMPOSE_BAKE=false"
        "COMPOSE_EXPERIMENTAL=false"
        "COMPOSE_MENU=false"
        "COMPOSE_REMOVE_ORPHANS=0"
    )
    local transport_variable=""
    local -a compose_model=(-f "$INSTALL_DIR/docker-compose.yml")

    if [[ -n "$APPROVED_COMPOSE_FILE" ]]; then
        compose_model+=(-f "$APPROVED_COMPOSE_FILE")
    fi
    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        compose_model+=(-f "$INSTALL_DIR/deploy/release/signed-release.compose.yml")
    fi

    # Compose gives the invoking shell precedence over --env-file during
    # interpolation. Do not let an ambient BACKUPSHEEP_BIND_ADDRESS,
    # BACKUPSHEEP_IMAGE, BACKUPSHEEP_POSTGRES_IMAGE, secret path, resource
    # limit, or future model value bypass the configuration that was just parsed
    # and validated above. Preserve only Docker transport/credential-helper
    # inputs and proxy/CA settings needed to reach an intentionally selected
    # daemon or registry.
    for transport_variable in \
        DOCKER_API_VERSION \
        DOCKER_CERT_PATH \
        DOCKER_CONFIG \
        DOCKER_CONTEXT \
        DOCKER_CUSTOM_HEADERS \
        DOCKER_HOST \
        DOCKER_TLS \
        DOCKER_TLS_VERIFY \
        SSH_AUTH_SOCK \
        XDG_RUNTIME_DIR \
        SSL_CERT_DIR \
        SSL_CERT_FILE \
        HTTP_PROXY \
        HTTPS_PROXY \
        NO_PROXY \
        http_proxy \
        https_proxy \
        no_proxy; do
        if [[ -n "${!transport_variable-}" ]]; then
            compose_environment+=(
                "${transport_variable}=${!transport_variable}"
            )
        fi
    done

    unset COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_ENV_FILES
    unset COMPOSE_REMOVE_ORPHANS
    unset COMPOSE_PATH_SEPARATOR COMPOSE_DISABLE_ENV_FILE
    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        local -a wrapper_arguments=()
        [[ -x "$INSTALL_DIR/backupsheep-compose" && ! -L "$INSTALL_DIR/backupsheep-compose" ]] \
            || die "The signed-release Compose wrapper is absent or unsafe."
        if [[ "$ALLOW_ROOT_INSTALL" == true ]]; then
            wrapper_arguments+=(--allow-root-install)
        fi
        wrapper_arguments+=(--inherit-installer-lock)
        run_installer_command 3600 "hardened signed-release Compose operation" \
            "${compose_environment[@]}" "$INSTALL_DIR/backupsheep-compose" \
            "${wrapper_arguments[@]}" "$@"
    else
        run_installer_command 3600 "Docker Compose operation" \
            "${compose_environment[@]}" "$DOCKER_BIN" compose \
            --project-name "$PROJECT_NAME" \
            --project-directory "$INSTALL_DIR" \
            --env-file "$ENV_FILE" \
            "${compose_model[@]}" \
            "$@"
    fi
    assert_install_parent_identity
    assert_install_root_identity
}

expected_compose_config_files() {
    printf '%s' "${INSTALL_DIR}/docker-compose.yml"
    if [[ -n "$APPROVED_COMPOSE_FILE" ]]; then
        printf ',%s' "$APPROVED_COMPOSE_FILE"
    fi
    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        printf ',%s' "$INSTALL_DIR/deploy/release/signed-release.compose.yml"
    fi
}

require_compose_service() {
    local wanted="$1"
    local available_services="$2"

    grep -Fxq -- "$wanted" <<< "$available_services" \
        || die "The reviewed Compose model is missing expected service ${wanted}."
}

validate_compose_model() {
    local available_services=""
    local service_name=""

    log "Validating the exact Compose model without printing expanded secrets"
    compose config --quiet
    available_services="$(compose --profile operations config --services)"
    for service_name in \
        "${CORE_SERVICES[@]}" \
        "${OPERATION_SERVICES[@]}" \
        "${OPERATION_GUARD_SERVICES[@]}"; do
        require_compose_service "$service_name" "$available_services"
    done
    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        validate_signed_release_compose_model
    fi
}

validate_signed_release_compose_model() {
    local rendered=""
    local images=""
    local image=""
    local app_image="$(read_env_value BACKUPSHEEP_IMAGE)"
    local postgres_image="$(read_env_value BACKUPSHEEP_POSTGRES_IMAGE)"
    local egress_image="$(read_env_value BACKUPSHEEP_EGRESS_IMAGE)"
    local rabbit_current="$(read_env_value BACKUPSHEEP_RABBITMQ_IMAGE)"
    local rabbit_upgrade="$(read_env_value BACKUPSHEEP_RABBITMQ_UPGRADE_IMAGE)"

    rendered="$(compose --profile operations config)" \
        || die "Could not render the signed-release Compose model."
    ! grep -Eq '^[[:space:]]+build:' <<< "$rendered" \
        || die "Signed-release Compose model contains a build definition."
    ! grep -Eq '(^|,)(exec|suid|dev)(,|$)' <<< "$rendered" \
        || die "Signed-release Compose model contains an unsafe tmpfs mount option."
    awk -v app="$app_image" -v postgres="$postgres_image" -v egress="$egress_image" -v rabbit="$rabbit_current" -v rabbit_upgrade="$rabbit_upgrade" '
        function finish_service() {
            if ((image == app || image == postgres || image == egress || image == rabbit || image == rabbit_upgrade) && pull != "never") exit 7
        }
        /^services:$/ { in_services = 1; next }
        in_services && /^[^ ]/ { finish_service(); in_services = 0 }
        in_services && /^  [A-Za-z0-9_-]+:$/ {
            finish_service(); image = ""; pull = ""; next
        }
        in_services && /^    image: / { image = substr($0, 12); gsub(/^"|"$/, "", image) }
        in_services && /^    pull_policy: / { pull = substr($0, 18); gsub(/^"|"$/, "", pull) }
        END { if (in_services) finish_service() }
    ' <<< "$rendered" \
        || die "Every signed-release digest service must retain pull_policy: never."
    images="$(compose --profile operations config --images)" \
        || die "Could not enumerate signed-release Compose images."
    for image in "$app_image" "$postgres_image" "$egress_image" "$rabbit_current"; do
        grep -Fxq -- "$image" <<< "$images" \
            || die "Signed-release Compose model omitted verified image ${image}."
    done
    while IFS= read -r image; do
        [[ -n "$image" ]] || continue
        case "$image" in
            "$app_image"|"$postgres_image"|"$egress_image"|"$rabbit_current"|"$rabbit_upgrade") ;;
            *) die "Signed-release Compose model references unauthorized image ${image}." ;;
        esac
    done <<< "$images"
}

docker_resource_label() {
    local resource_type="$1"
    local resource_id="$2"
    local label_name="$3"
    local frame_marker="__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__"
    local label_root=""
    local framed_value=""
    local framed_payload=""
    local declared_length=""
    local label_value=""
    local LC_ALL=C

    case "$resource_type" in
        container) label_root='.Config.Labels' ;;
        network|volume) label_root='.Labels' ;;
        *) die "Unknown Docker resource type during ownership validation." ;;
    esac

    case "$resource_type" in
        container)
            framed_value="$(
                "$DOCKER_BIN" inspect --format \
                    "{{with index ${label_root} \"${label_name}\"}}{{len .}}:{{.}}{{else}}0:{{end}}${frame_marker}" \
                    "$resource_id"
            )" || return 1
            ;;
        network|volume)
            framed_value="$(
                "$DOCKER_BIN" "$resource_type" inspect --format \
                    "{{with index ${label_root} \"${label_name}\"}}{{len .}}:{{.}}{{else}}0:{{end}}${frame_marker}" \
                    "$resource_id"
            )" || return 1
            ;;
    esac

    [[ "$framed_value" == *"$frame_marker" ]] || return 1
    framed_payload="${framed_value%"$frame_marker"}"
    [[ "$framed_payload" == *:* ]] || return 1
    declared_length="${framed_payload%%:*}"
    label_value="${framed_payload#*:}"
    [[ "$declared_length" =~ ^(0|[1-9][0-9]{0,6})$ ]] || return 1
    (( 10#$declared_length <= 1048576 )) || return 1
    (( ${#label_value} == 10#$declared_length )) || return 1
    [[ "$label_value" != *[[:cntrl:]]* ]] || return 1
    printf '%s' "$label_value"
}

docker_resource_name() {
    local resource_type="$1"
    local resource_id="$2"

    case "$resource_type" in
        network) "$DOCKER_BIN" network inspect --format '{{.Name}}' "$resource_id" ;;
        volume) "$DOCKER_BIN" volume inspect --format '{{.Name}}' "$resource_id" ;;
        *) die "Unknown Docker resource type during name validation." ;;
    esac
}

is_exact_interrupted_postgres_source() {
    local resource_id="$1"
    local installation_id="$2"
    local storage_witness="$3"
    local retired_image_id="$4"
    local expected_name="/${PROJECT_NAME}-postgres-migration-source"
    local expected_purpose="postgres-runtime-${storage_witness}"
    local runtime_record=""
    local mount_records=""
    local expected_mount_records=""

    [[ "$installation_id" =~ ^[0-9a-f]{64}$ \
        && "$storage_witness" =~ ^[0-9a-f]{64}$ \
        && "$retired_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    [[ "$(docker_resource_label container "$resource_id" com.backupsheep.project)" == "$PROJECT_NAME" \
        && "$(docker_resource_label container "$resource_id" com.backupsheep.installation-id)" == "$installation_id" \
        && "$(docker_resource_label container "$resource_id" com.backupsheep.postgres-migration)" == "$expected_purpose" \
        && -z "$(docker_resource_label container "$resource_id" com.docker.compose.project)" \
        && -z "$(docker_resource_label container "$resource_id" com.docker.compose.service)" ]] \
        || return 1
    runtime_record="$("$DOCKER_BIN" inspect --format \
        '{{.Name}}|{{.Image}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{.Path}}' \
        "$resource_id")" || return 1
    [[ "$runtime_record" == "${expected_name}|${retired_image_id}|999:999|none|true|[\"ALL\"]|[\"no-new-privileges:true\"]|/usr/local/bin/docker-entrypoint.sh" ]] \
        || return 1
    mount_records="$("$DOCKER_BIN" inspect --format \
        '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Destination}}|{{.RW}}{{println}}{{end}}' \
        "$resource_id" | LC_ALL=C sort)" || return 1
    expected_mount_records="$(printf '%s\n%s' \
        "volume|${PROJECT_NAME}_pgdata|/var/lib/postgresql|true" \
        "volume|${PROJECT_NAME}_postgres_migration_source_socket|/var/run/postgresql|true" \
        | LC_ALL=C sort)"
    [[ "$mount_records" == "$expected_mount_records" ]]
}

create_verified_ownership_sentinel() {
    local installation_id="$1"
    local sentinel_name="${PROJECT_NAME}_installation_identity"
    local created_name=""
    local inspected_name=""
    local resource_project=""
    local logical_name=""
    local resource_installation_id=""

    created_name="$(
        "$DOCKER_BIN" volume create \
            --driver local \
            --label "com.docker.compose.project=${PROJECT_NAME}" \
            --label "com.docker.compose.volume=installation_identity" \
            --label "com.backupsheep.installation-id=${installation_id}" \
            "$sentinel_name"
    )" || die "Could not create the verified ownership sentinel; no Compose service was mutated."
    [[ "$created_name" == "$sentinel_name" ]] \
        || die "Docker returned an unexpected ownership-sentinel name; refusing to continue."

    inspected_name="$(docker_resource_name volume "$sentinel_name")" \
        || die "Could not re-inspect the verified ownership sentinel."
    resource_project="$(docker_resource_label volume "$sentinel_name" com.docker.compose.project)" \
        || die "Could not verify the ownership-sentinel project label."
    logical_name="$(docker_resource_label volume "$sentinel_name" com.docker.compose.volume)" \
        || die "Could not verify the ownership-sentinel logical label."
    resource_installation_id="$(docker_resource_label volume "$sentinel_name" com.backupsheep.installation-id)" \
        || die "Could not verify the ownership-sentinel identity label."
    [[ "$inspected_name" == "$sentinel_name" \
        && "$resource_project" == "$PROJECT_NAME" \
        && "$logical_name" == "installation_identity" \
        && "$resource_installation_id" == "$installation_id" ]] \
        || die "The verified ownership sentinel did not retain every exact required label."
}

validate_compose_project_ownership() {
    local installation_id=""
    local expected_config=""
    local resource_id=""
    local resource_installation_id=""
    local working_dir=""
    local config_files=""
    local logical_name=""
    local available_services=""
    local available_networks=""
    local available_volumes=""
    local all_network_names=""
    local all_volume_names=""
    local expected_resource_name=""
    local retired_ssh_trust_name="${PROJECT_NAME}_ssh_trust"
    local retired_ssh_trust_attachments=""
    local retired_pgdata_name="${PROJECT_NAME}_pgdata"
    local retired_pgdata_attachments=""
    local postgres_storage_intent=""
    local postgres_storage_state=""
    local postgres_retired_image_id=""
    local retired_pgdata_attachment_id=""
    local retired_pgdata_attachment_count=0
    local retired_pgdata_attachment_service=""
    local retired_pgdata_attachment_image=""
    local retired_pgdata_attachment_user=""
    local resource_name=""
    local resource_project=""
    local is_retired_ssh_trust=false
    local is_retired_pgdata=false
    local legacy_resource_witness=false
    local identified_resource_without_sentinel=false
    local identity_volume_count=0
    local container_count=0
    local network_count=0
    local volume_count=0
    local container_listing=""
    local network_listing=""
    local volume_listing=""
    local -a container_ids=()
    local -a network_ids=()
    local -a volume_ids=()

    expected_config="$(expected_compose_config_files)"
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    container_listing="$(
        "$DOCKER_BIN" ps --all --quiet \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}"
    )" || die "Could not inventory existing Compose containers; refusing mutation."
    network_listing="$(
        "$DOCKER_BIN" network ls --quiet \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}"
    )" || die "Could not inventory existing Compose networks; refusing mutation."
    volume_listing="$(
        "$DOCKER_BIN" volume ls --quiet \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}"
    )" || die "Could not inventory existing Compose volumes; refusing mutation."
    all_network_names="$("$DOCKER_BIN" network ls --format '{{.Name}}')" \
        || die "Could not inventory Docker network names; refusing mutation."
    all_volume_names="$("$DOCKER_BIN" volume ls --format '{{.Name}}')" \
        || die "Could not inventory Docker volume names; refusing mutation."
    postgres_storage_intent="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_INTENT)"
    postgres_storage_state="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_GENERATION)"
    postgres_retired_image_id="$(read_env_value BACKUPSHEEP_POSTGRES_RETIRED_IMAGE_ID)"

    while IFS= read -r resource_id; do
        if [[ -n "$resource_id" ]]; then
            container_ids+=("$resource_id")
            container_count=$((container_count + 1))
        fi
    done <<< "$container_listing"
    while IFS= read -r resource_id; do
        if [[ -n "$resource_id" ]]; then
            network_ids+=("$resource_id")
            network_count=$((network_count + 1))
        fi
    done <<< "$network_listing"
    while IFS= read -r resource_id; do
        if [[ -n "$resource_id" ]]; then
            volume_ids+=("$resource_id")
            volume_count=$((volume_count + 1))
        fi
    done <<< "$volume_listing"

    available_services="$(compose --profile operations config --services)"
    available_networks="$(compose --profile operations config --networks)"
    available_volumes="$(compose --profile operations config --volumes)"

    # Compose can adopt an exact-name pre-existing volume or network after only a
    # warning. Label-filtered inventory would miss an unlabeled collision, so prove
    # every resolved stock name before Compose receives any mutating command.
    while IFS= read -r logical_name; do
        [[ -n "$logical_name" ]] || continue
        expected_resource_name="${PROJECT_NAME}_${logical_name}"
        grep -Fxq -- "$expected_resource_name" <<< "$all_network_names" || continue
        resource_project="$(docker_resource_label network "$expected_resource_name" com.docker.compose.project)"
        resource_installation_id="$(docker_resource_label network "$expected_resource_name" com.docker.compose.network)"
        [[ "$resource_project" == "$PROJECT_NAME" && "$resource_installation_id" == "$logical_name" ]] \
            || die "Docker network ${expected_resource_name} collides with this Compose model but is not owned by it."
    done <<< "$available_networks"
    while IFS= read -r logical_name; do
        [[ -n "$logical_name" ]] || continue
        expected_resource_name="${PROJECT_NAME}_${logical_name}"
        grep -Fxq -- "$expected_resource_name" <<< "$all_volume_names" || continue
        resource_project="$(docker_resource_label volume "$expected_resource_name" com.docker.compose.project)"
        resource_installation_id="$(docker_resource_label volume "$expected_resource_name" com.docker.compose.volume)"
        [[ "$resource_project" == "$PROJECT_NAME" && "$resource_installation_id" == "$logical_name" ]] \
            || die "Docker volume ${expected_resource_name} collides with this Compose model but is not owned by it."
    done <<< "$available_volumes"
    # The retired develop-era trust volume is intentionally absent from the v3
    # Compose model, so inspect its canonical physical name separately. A foreign
    # or unlabeled same-name volume must never be mistaken for rollback evidence.
    if grep -Fxq -- "$retired_ssh_trust_name" <<< "$all_volume_names"; then
        resource_project="$(docker_resource_label volume "$retired_ssh_trust_name" com.docker.compose.project)" \
            || die "Could not inspect retired Docker volume ${retired_ssh_trust_name}."
        logical_name="$(docker_resource_label volume "$retired_ssh_trust_name" com.docker.compose.volume)" \
            || die "Could not inspect retired Docker volume ${retired_ssh_trust_name}."
        [[ "$resource_project" == "$PROJECT_NAME" && "$logical_name" == "ssh_trust" ]] \
            || die "Docker volume ${retired_ssh_trust_name} collides with the retired BackupSheep trust volume but is not owned by it."
    fi
    if grep -Fxq -- "$retired_pgdata_name" <<< "$all_volume_names"; then
        resource_project="$(docker_resource_label volume "$retired_pgdata_name" com.docker.compose.project)" \
            || die "Could not inspect retired Docker volume ${retired_pgdata_name}."
        logical_name="$(docker_resource_label volume "$retired_pgdata_name" com.docker.compose.volume)" \
            || die "Could not inspect retired Docker volume ${retired_pgdata_name}."
        [[ "$resource_project" == "$PROJECT_NAME" && "$logical_name" == "pgdata" \
            && ( "$postgres_storage_intent" == "migrated-debian-v1" \
                || "$postgres_storage_intent" == "migrated-debian-generation2-v1" ) ]] \
            || die "Docker volume ${retired_pgdata_name} collides with retired PostgreSQL rollback storage but is not its exact owned volume."
    fi

    if (( container_count == 0 && network_count == 0 && volume_count == 0 )); then
        # Establish the durable installation witness before the first staged
        # Compose mutation. Service-scoped `up` does not create unused top-level
        # volumes, so deferring this until app startup could strand an
        # interrupted installation with identified resources but no safe resume
        # proof.
        create_verified_ownership_sentinel "$installation_id"
        return
    fi
    [[ "$INSTALL_WAS_PRESENT" == true ]] \
        || die "Compose project ${PROJECT_NAME} already owns Docker resources. Choose a unique --project-name; refusing cross-install reuse."

    if (( container_count > 0 )); then
        for resource_id in "${container_ids[@]}"; do
            working_dir="$(docker_resource_label container "$resource_id" com.docker.compose.project.working_dir)" \
                || die "Could not inspect a Compose container working directory."
            config_files="$(docker_resource_label container "$resource_id" com.docker.compose.project.config_files)" \
                || die "Could not inspect a Compose container configuration path."
            logical_name="$(docker_resource_label container "$resource_id" com.docker.compose.service)" \
                || die "Could not inspect a Compose container service label."
            [[ "$working_dir" == "$INSTALL_DIR" && "$config_files" == "$expected_config" ]] \
                || die "Compose project ${PROJECT_NAME} has a container owned by a different installation path. Refusing mutation."
            grep -Fxq -- "$logical_name" <<< "$available_services" \
                || die "Compose project ${PROJECT_NAME} has an unexpected service container: ${logical_name}."
            resource_installation_id="$(docker_resource_label container "$resource_id" com.backupsheep.installation-id)" \
                || die "Could not inspect a Compose container installation identity."
            if [[ -z "$resource_installation_id" ]]; then
                legacy_resource_witness=true
            else
                [[ "$resource_installation_id" == "$installation_id" ]] \
                    || die "Compose project ${PROJECT_NAME} has a container with a different BackupSheep installation identity."
                identified_resource_without_sentinel=true
            fi
        done
    fi

    # Docker volume labels are immutable. New deployments create this empty sentinel
    # so ownership remains provable after `compose down`; a legacy deployment may use
    # its exact-path container labels once to adopt the sentinel safely.
    if (( volume_count > 0 )); then
        for resource_id in "${volume_ids[@]}"; do
            logical_name="$(docker_resource_label volume "$resource_id" com.docker.compose.volume)"
            [[ "$logical_name" == "installation_identity" ]] || continue
            resource_name="$(docker_resource_name volume "$resource_id")" \
                || die "Could not inspect the Compose ownership-sentinel name."
            [[ "$resource_name" == "${PROJECT_NAME}_installation_identity" ]] \
                || die "The Compose ownership sentinel has a non-canonical name."
            resource_installation_id="$(docker_resource_label volume "$resource_id" com.backupsheep.installation-id)"
            [[ "$resource_installation_id" == "$installation_id" ]] \
                || die "The Compose ownership sentinel belongs to a different BackupSheep installation."
            identity_volume_count=$((identity_volume_count + 1))
        done
    fi

    if (( network_count > 0 )); then
        for resource_id in "${network_ids[@]}"; do
            logical_name="$(docker_resource_label network "$resource_id" com.docker.compose.network)"
            grep -Fxq -- "$logical_name" <<< "$available_networks" \
                || die "Compose project ${PROJECT_NAME} has an unexpected network: ${logical_name}."
            resource_name="$(docker_resource_name network "$resource_id")" \
                || die "Could not inspect Compose network ${logical_name}."
            [[ "$resource_name" == "${PROJECT_NAME}_${logical_name}" ]] \
                || die "Compose network ${logical_name} has a non-canonical physical name."
            resource_installation_id="$(docker_resource_label network "$resource_id" com.backupsheep.installation-id)"
            if [[ -z "$resource_installation_id" ]]; then
                [[ "$legacy_resource_witness" == true || "$identity_volume_count" -eq 1 ]] \
                    || die "Cannot prove ownership of legacy Compose network ${logical_name}; refusing mutation."
            else
                [[ "$resource_installation_id" == "$installation_id" ]] \
                    || die "Compose network ${logical_name} belongs to a different BackupSheep installation."
                identified_resource_without_sentinel=true
            fi
        done
    fi

    if (( volume_count > 0 )); then
        for resource_id in "${volume_ids[@]}"; do
            logical_name="$(docker_resource_label volume "$resource_id" com.docker.compose.volume)"
            is_retired_ssh_trust=false
            is_retired_pgdata=false
            if ! grep -Fxq -- "$logical_name" <<< "$available_volumes"; then
                # develop-era installs used one project-owned global SSH trust
                # volume. It is rollback evidence only: the current model never
                # mounts it and runtime volume overrides are refused. Preserve it
                # without treating any other retired/unknown volume as owned.
                case "$logical_name" in
                    ssh_trust) is_retired_ssh_trust=true ;;
                    pgdata)
                        [[ "$postgres_storage_intent" == "migrated-debian-v1" \
                            || "$postgres_storage_intent" == "migrated-debian-generation2-v1" ]] \
                            || die "Retired pgdata is valid only for an explicit PostgreSQL runtime migration."
                        is_retired_pgdata=true
                        ;;
                    *) die "Compose project ${PROJECT_NAME} has an unexpected volume: ${logical_name}." ;;
                esac
                (( identity_volume_count == 1 )) \
                    || die "A retired Compose volume requires exactly one matching installation-identity sentinel."
            fi
            resource_name="$(docker_resource_name volume "$resource_id")" \
                || die "Could not inspect Compose volume ${logical_name}."
            [[ "$resource_name" == "${PROJECT_NAME}_${logical_name}" ]] \
                || die "Compose volume ${logical_name} has a non-canonical physical name."
            if [[ "$is_retired_ssh_trust" == true ]]; then
                resource_project="$(docker_resource_label volume "$resource_id" com.docker.compose.project)" \
                    || die "Could not inspect retired Compose volume ssh_trust."
                [[ "$resource_project" == "$PROJECT_NAME" ]] \
                    || die "The retired Compose volume ssh_trust is not owned by project ${PROJECT_NAME}."
                retired_ssh_trust_attachments="$("$DOCKER_BIN" ps --all --quiet \
                    --filter "volume=${resource_name}")" \
                    || die "Could not prove that retired Compose volume ssh_trust is detached."
                [[ -z "$retired_ssh_trust_attachments" ]] \
                    || die "The retired Compose volume ssh_trust still has attached containers; remove every running or stopped legacy container before retrying."
            fi
            if [[ "$is_retired_pgdata" == true ]]; then
                resource_project="$(docker_resource_label volume "$resource_id" com.docker.compose.project)" \
                    || die "Could not inspect retired Compose volume pgdata."
                [[ "$resource_project" == "$PROJECT_NAME" ]] \
                    || die "The retired Compose volume pgdata is not owned by project ${PROJECT_NAME}."
                retired_pgdata_attachments="$("$DOCKER_BIN" ps --all --quiet --filter "volume=${resource_name}")" \
                    || die "Could not inventory attachments to retired Compose volume pgdata."
                if [[ -n "$retired_pgdata_attachments" ]]; then
                    [[ "$postgres_storage_state" == "${POSTGRES_STORAGE_GENERATION}-pending-upgrade" \
                        && "$POSTGRES_MIGRATION_REQUIRED" == true \
                        && "$postgres_retired_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
                        || die "Retired Compose volume pgdata must remain detached except during the reviewed pre-migration shutdown."
                    retired_pgdata_attachment_count=0
                    while IFS= read -r retired_pgdata_attachment_id; do
                        [[ -n "$retired_pgdata_attachment_id" ]] || continue
                        retired_pgdata_attachment_count=$((retired_pgdata_attachment_count + 1))
                        if grep -Fxq -- "$retired_pgdata_attachment_id" <<< "$container_listing"; then
                            retired_pgdata_attachment_service="$(docker_resource_label container "$retired_pgdata_attachment_id" com.docker.compose.service)" \
                                || die "Could not inspect the legacy PostgreSQL attachment service."
                            retired_pgdata_attachment_image="$("$DOCKER_BIN" inspect --format '{{.Image}}' "$retired_pgdata_attachment_id")" \
                                || die "Could not inspect the legacy PostgreSQL attachment image."
                            retired_pgdata_attachment_user="$("$DOCKER_BIN" inspect --format '{{.Config.User}}' "$retired_pgdata_attachment_id")" \
                                || die "Could not inspect the legacy PostgreSQL attachment user."
                            [[ "$retired_pgdata_attachment_service" == db \
                                && "$retired_pgdata_attachment_image" == "$postgres_retired_image_id" \
                                && "$retired_pgdata_attachment_user" == "999:999" ]] \
                                || die "Legacy PostgreSQL storage is not attached to the exact retained UID/GID-999 database container."
                        else
                            is_exact_interrupted_postgres_source \
                                "$retired_pgdata_attachment_id" "$installation_id" \
                                "$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_WITNESS)" \
                                "$postgres_retired_image_id" \
                                || die "Legacy PostgreSQL storage is attached outside Compose and is not the exact witnessed interrupted migration source."
                        fi
                    done <<< "$retired_pgdata_attachments"
                    [[ "$retired_pgdata_attachment_count" -eq 1 ]] \
                        || die "Legacy PostgreSQL storage must have exactly one reviewed database attachment before shutdown."
                fi
            fi
            resource_installation_id="$(docker_resource_label volume "$resource_id" com.backupsheep.installation-id)"
            if [[ -z "$resource_installation_id" ]]; then
                [[ "$legacy_resource_witness" == true || "$identity_volume_count" -eq 1 ]] \
                    || die "Cannot prove ownership of legacy Compose volume ${logical_name}; refusing mutation."
            else
                [[ "$resource_installation_id" == "$installation_id" ]] \
                    || die "Compose volume ${logical_name} belongs to a different BackupSheep installation."
                if [[ "$logical_name" != "installation_identity" ]]; then
                    identified_resource_without_sentinel=true
                fi
            fi
        done
    fi

    (( identity_volume_count <= 1 )) \
        || die "Compose project ${PROJECT_NAME} has more than one installation-identity sentinel."
    if (( identity_volume_count == 0 )); then
        [[ "$legacy_resource_witness" == true ]] \
            || die "Existing Compose resources have no exact-path legacy container or installation-identity sentinel."
        [[ "$identified_resource_without_sentinel" == false ]] \
            || die "Identified Compose resources exist without their installation-identity sentinel; refusing repair by guess."

        # All project resources have now passed exact path, config, service, logical-name,
        # physical-name and blank-identity checks. This is the only automatic legacy
        # adoption path, and the sentinel is the only Docker resource it creates.
        create_verified_ownership_sentinel "$installation_id"
    fi
}

validate_rabbitmq_data_generation() {
    local generation=""
    local resource_id=""
    local service_name=""
    local logical_name=""
    local rabbit_container_id=""
    local rabbit_volume_id=""
    local container_state=""
    local container_health=""
    local server_version=""
    local container_listing=""
    local volume_listing=""

    generation="$(read_env_value BACKUPSHEEP_RABBITMQ_DATA_GENERATION)"
    [[ -z "$generation" || "$generation" == "4.3" ]] \
        || die "Unsupported BACKUPSHEEP_RABBITMQ_DATA_GENERATION=${generation}. Follow docs/guides/rabbitmq-upgrade.md before this installer."

    container_listing="$(
        "$DOCKER_BIN" ps --all --quiet \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}"
    )" || die "Could not inventory existing RabbitMQ containers; refusing migration."
    volume_listing="$(
        "$DOCKER_BIN" volume ls --quiet \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}"
    )" || die "Could not inventory existing RabbitMQ volumes; refusing migration."

    while IFS= read -r resource_id; do
        [[ -n "$resource_id" ]] || continue
        service_name="$(docker_resource_label container "$resource_id" com.docker.compose.service)"
        if [[ "$service_name" == "rabbitmq" ]]; then
            [[ -z "$rabbit_container_id" ]] \
                || die "Multiple RabbitMQ containers claim Compose project ${PROJECT_NAME}; refusing migration."
            rabbit_container_id="$resource_id"
        fi
    done <<< "$container_listing"
    while IFS= read -r resource_id; do
        [[ -n "$resource_id" ]] || continue
        logical_name="$(docker_resource_label volume "$resource_id" com.docker.compose.volume)"
        if [[ "$logical_name" == "rabbitmq_data" ]]; then
            [[ -z "$rabbit_volume_id" ]] \
                || die "Multiple RabbitMQ volumes claim Compose project ${PROJECT_NAME}; refusing migration."
            rabbit_volume_id="$resource_id"
        fi
    done <<< "$volume_listing"

    if [[ -z "$rabbit_container_id" && -z "$rabbit_volume_id" ]]; then
        if [[ -z "$generation" ]]; then
            set_env_value BACKUPSHEEP_RABBITMQ_DATA_GENERATION "4.3"
        fi
        return
    fi
    [[ -n "$rabbit_container_id" ]] \
        || die "An existing RabbitMQ volume has no live version witness. Follow docs/guides/rabbitmq-upgrade.md; the installer will not guess its format."
    container_state="$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$rabbit_container_id")"
    [[ "$container_state" == "running" ]] \
        || die "The existing RabbitMQ container is not running, so its data generation cannot be proven safely. Follow docs/guides/rabbitmq-upgrade.md."
    container_health="$("$DOCKER_BIN" inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$rabbit_container_id")"
    [[ "$container_health" == "healthy" ]] \
        || die "The existing RabbitMQ container is not healthy, so its data generation cannot be accepted safely. Follow docs/guides/rabbitmq-upgrade.md."
    # The official container starts as root only for volume ownership repair. Run
    # diagnostics as the broker identity so this witness cannot create a root-owned
    # Erlang cookie and make the existing node unstartable on its next restart.
    server_version="$("$DOCKER_BIN" exec --user rabbitmq "$rabbit_container_id" rabbitmq-diagnostics -q server_version 2>/dev/null)" \
        || die "Could not query the existing RabbitMQ server version without consuming work."
    [[ "$server_version" == "4.3.5" ]] \
        || die "RabbitMQ ${server_version} is not the exact pinned 4.3.5 target. Complete or reconcile the documented 3.13/4.2.9/4.3.5 Khepri migration before install.sh can continue."
    if [[ -z "$generation" ]]; then
        die "A live RabbitMQ volume has no attested generation witness. Run the wrapper's explicit 4.3 reconciliation command so it can prove the isolated base-model image reference, local image ID, exact 4.3.5 server and Khepri state before atomically recording the witness."
    fi
}

show_failure_guidance() {
    local wrapper_override=""

    if [[ "$ALLOW_ROOT_INSTALL" == true ]]; then
        wrapper_override=" --allow-root-install"
    fi
    warn "Startup was left in place for evidence and recovery; no volumes or containers were deleted."
    warn "Inspect locally as the installation owner: cd $(printf '%q' "$INSTALL_DIR") && ./backupsheep-compose${wrapper_override} logs --tail=100 rabbitmq-volume-init rabbitmq rabbitmq-provision db-provision migrate db-seal preflight app"
}

wait_for_database_seal() {
    local elapsed=0
    local service_name=""
    local container_id=""
    local status=""
    local exit_code=""

    log "Waiting for the generation-3 database grants to seal"
    while [[ "$elapsed" -lt 300 ]]; do
        for service_name in rabbitmq-provision db-provision migrate db-seal; do
            container_id="$(compose ps --all -q "$service_name" 2>/dev/null || true)"
            [[ -n "$container_id" ]] || continue
            status="$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null || true)"
            exit_code="$("$DOCKER_BIN" inspect --format '{{.State.ExitCode}}' "$container_id" 2>/dev/null || true)"
            if [[ "$status" == "exited" && "$exit_code" != "0" ]]; then
                show_failure_guidance
                die "Database transition service ${service_name} failed (exit code: ${exit_code})."
            fi
            if [[ "$service_name" == "db-seal" && "$status" == "exited" \
                && "$exit_code" == "0" ]]; then
                return
            fi
        done
        sleep 3
        elapsed=$((elapsed + 3))
    done

    show_failure_guidance
    die "Generation-3 database grants did not seal within five minutes."
}

wait_for_app() {
    local elapsed=0
    local container_id=""
    local status=""
    local provision_container_id=""
    local provision_status=""
    local provision_exit_code=""
    local rabbit_provision_container_id=""
    local rabbit_provision_status=""
    local rabbit_provision_exit_code=""
    local migrate_container_id=""
    local migrate_status=""
    local migrate_exit_code=""
    local preflight_container_id=""
    local preflight_status=""
    local preflight_exit_code=""

    log "Waiting for the BackupSheep core to become healthy"
    while [[ "$elapsed" -lt 300 ]]; do
        rabbit_provision_container_id="$(compose ps --all -q rabbitmq-provision 2>/dev/null || true)"
        if [[ -n "$rabbit_provision_container_id" ]]; then
            rabbit_provision_status="$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$rabbit_provision_container_id" 2>/dev/null || true)"
            rabbit_provision_exit_code="$("$DOCKER_BIN" inspect --format '{{.State.ExitCode}}' "$rabbit_provision_container_id" 2>/dev/null || true)"
            if [[ "$rabbit_provision_status" == "exited" && "$rabbit_provision_exit_code" != "0" ]]; then
                show_failure_guidance
                die "RabbitMQ identity provisioning failed (exit code: ${rabbit_provision_exit_code})."
            fi
        fi

        provision_container_id="$(compose ps --all -q db-provision 2>/dev/null || true)"
        if [[ -n "$provision_container_id" ]]; then
            provision_status="$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$provision_container_id" 2>/dev/null || true)"
            provision_exit_code="$("$DOCKER_BIN" inspect --format '{{.State.ExitCode}}' "$provision_container_id" 2>/dev/null || true)"
            if [[ "$provision_status" == "exited" && "$provision_exit_code" != "0" ]]; then
                show_failure_guidance
                die "Database identity provisioning failed (exit code: ${provision_exit_code})."
            fi
        fi

        migrate_container_id="$(compose ps --all -q migrate 2>/dev/null || true)"
        if [[ -n "$migrate_container_id" ]]; then
            migrate_status="$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$migrate_container_id" 2>/dev/null || true)"
            migrate_exit_code="$("$DOCKER_BIN" inspect --format '{{.State.ExitCode}}' "$migrate_container_id" 2>/dev/null || true)"
            if [[ "$migrate_status" == "exited" && "$migrate_exit_code" != "0" ]]; then
                show_failure_guidance
                die "Database migrations failed (exit code: ${migrate_exit_code})."
            fi
        fi

        preflight_container_id="$(compose ps --all -q preflight 2>/dev/null || true)"
        if [[ -n "$preflight_container_id" ]]; then
            preflight_status="$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$preflight_container_id" 2>/dev/null || true)"
            preflight_exit_code="$("$DOCKER_BIN" inspect --format '{{.State.ExitCode}}' "$preflight_container_id" 2>/dev/null || true)"
            if [[ "$preflight_status" == "exited" && "$preflight_exit_code" != "0" ]]; then
                show_failure_guidance
                die "Docker security preflight failed (exit code: ${preflight_exit_code})."
            fi
        fi

        container_id="$(compose ps --all -q app 2>/dev/null || true)"
        if [[ -n "$container_id" ]]; then
            status="$("$DOCKER_BIN" inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
            case "$status" in
                healthy)
                    return
                    ;;
                unhealthy|exited|dead)
                    show_failure_guidance
                    die "BackupSheep core did not start successfully (app state: ${status})."
                    ;;
            esac
        fi
        sleep 3
        elapsed=$((elapsed + 3))
    done

    show_failure_guidance
    die "BackupSheep core did not become healthy within five minutes."
}

refuse_egress_oneoffs_before_topology_removal() {
    local container_listing=""
    local container_id=""
    local oneoff_label=""
    local service_name=""

    container_listing="$(
        "$DOCKER_BIN" ps --all --quiet \
            --filter "label=com.docker.compose.project=${PROJECT_NAME}"
    )" || die "Could not inventory Compose one-offs before topology removal."
    while IFS= read -r container_id; do
        [[ -n "$container_id" ]] || continue
        oneoff_label="$(docker_resource_label \
            container "$container_id" com.docker.compose.oneoff)" \
            || die "Could not inspect a Compose one-off lifecycle label."
        case "$oneoff_label" in
            True|true|TRUE|1) ;;
            *) continue ;;
        esac
        service_name="$(docker_resource_label \
            container "$container_id" com.docker.compose.service)" \
            || die "Could not inspect a Compose one-off service label."
        case "$service_name" in
            app|worker-cloud|worker-database|worker-files|worker-storage|worker-logs)
                die "An egress-backed Compose one-off for ${service_name} still exists. Inspect, stop, and remove that exact one-off before rerunning the installer; no topology was removed."
                ;;
        esac
    done <<< "$container_listing"
}

stop_operations() {
    refuse_egress_oneoffs_before_topology_removal
    log "Removing the complete container topology before build or migration"
    # A guard must never stop/restart independently of the workload that shares
    # its network namespace. `down` removes containers and networks together but
    # intentionally preserves every named data/identity volume.
    if ! compose --profile operations down --timeout 300; then
        die "Could not remove the complete container topology; refusing to build or migrate while provider work may still run."
    fi
}

run_postgres_runtime_migration() {
    local installation_id=""
    local source_image_id=""
    local target_image_ref=""
    local database_name=""
    local bootstrap_user=""
    local witness=""
    local storage_intent=""
    local database_identity_generation=""
    local expected_roles_csv=""
    local variable=""

    [[ "$POSTGRES_MIGRATION_REQUIRED" == true ]] || return 0
    installation_id="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    source_image_id="$(read_env_value BACKUPSHEEP_POSTGRES_RETIRED_IMAGE_ID)"
    target_image_ref="$(read_env_value BACKUPSHEEP_POSTGRES_IMAGE)"
    database_name="$(read_env_value DB_NAME)"
    bootstrap_user="$(read_env_value DB_BOOTSTRAP_USER)"
    witness="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_WITNESS)"
    storage_intent="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_INTENT)"
    database_identity_generation="$(read_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION)"
    for variable in DB_BOOTSTRAP_USER DB_MIGRATOR_USER DB_APP_USER DB_PREFLIGHT_USER \
        DB_BEAT_USER DB_CLOUD_USER DB_DATABASE_USER DB_FILES_USER DB_STORAGE_USER DB_LOGS_USER; do
        if [[ -n "$expected_roles_csv" ]]; then expected_roles_csv+=","; fi
        expected_roles_csv+="$(read_env_value "$variable")"
    done

    log "Migrating the exact detached Debian database into isolated Alpine/ICU storage"
    "$INSTALL_DIR/deploy/postgres/migrate-runtime.sh" \
        "$DOCKER_BIN" "$PROJECT_NAME" "$installation_id" "$source_image_id" \
        "$target_image_ref" "${PROJECT_NAME}_pgdata" \
        "${PROJECT_NAME}_${POSTGRES_STORAGE_LOGICAL_VOLUME}" \
        "$SECRETS_DIR/db_bootstrap_password" "$database_name" "$bootstrap_user" \
        "$expected_roles_csv" "$witness" "$storage_intent" \
        "$database_identity_generation" \
        || die "PostgreSQL logical migration failed; the legacy volume remains detached and the target generation remains pending."

    # The target volume receipt was written only after exact image, inventory and
    # content fingerprints passed. Keep the environment generation pending until
    # the target database roles and schema have also passed db-seal.
    POSTGRES_MIGRATION_REQUIRED=false
    validate_compose_project_ownership
}

complete_postgres_storage_generation() {
    local state=""
    local database_generation=""
    local container_id=""
    local listed_container_id=""
    local container_count=0
    local target_image_ref=""
    local target_image_id=""
    local container_image_id=""
    local witness_mode=""

    state="$(read_env_value BACKUPSHEEP_POSTGRES_STORAGE_GENERATION)"
    database_generation="$(read_env_value BACKUPSHEEP_DATABASE_IDENTITY_GENERATION)"
    case "$state" in
        "${POSTGRES_STORAGE_GENERATION}-pending-fresh")
            witness_mode=finalize-fresh
            ;;
        "${POSTGRES_STORAGE_GENERATION}-pending-upgrade")
            [[ "$POSTGRES_MIGRATION_REQUIRED" == false ]] \
                || die "PostgreSQL migration cannot be promoted before its isolated receipt is complete."
            witness_mode=verify-migration
            ;;
        "$POSTGRES_STORAGE_GENERATION") return 0 ;;
        *) die "PostgreSQL storage cannot be completed from unsupported state ${state}." ;;
    esac
    [[ "$database_generation" == "3" ]] \
        || die "PostgreSQL storage cannot be promoted before generation-3 database identities are sealed."
    while IFS= read -r listed_container_id; do
        [[ -n "$listed_container_id" ]] || continue
        container_id="$listed_container_id"
        container_count=$((container_count + 1))
    done < <(compose ps --all --quiet db)
    [[ "$container_count" -eq 1 && -n "$container_id" ]] \
        || die "PostgreSQL witness promotion requires exactly one database container."
    target_image_ref="$(read_env_value BACKUPSHEEP_POSTGRES_IMAGE)"
    target_image_id="$("$DOCKER_BIN" image inspect --format '{{.Id}}' "$target_image_ref")" \
        || die "Could not inspect the PostgreSQL target image."
    container_image_id="$("$DOCKER_BIN" inspect --format '{{.Image}}' "$container_id")" \
        || die "Could not inspect the PostgreSQL container image."
    [[ "$container_image_id" == "$target_image_id" ]] \
        || die "PostgreSQL container does not use the exact locally built target image."
    "$DOCKER_BIN" exec "$container_id" \
        /usr/local/bin/backupsheep-postgres-storage-witness "$witness_mode" \
        || die "PostgreSQL ICU/storage witness failed; generation remains pending."
    set_env_value BACKUPSHEEP_POSTGRES_STORAGE_GENERATION "$POSTGRES_STORAGE_GENERATION"
}

start_core() {
    stop_operations

    if [[ "$IMAGE_MODE" == "local-build" ]]; then
        log "Building the reviewed PostgreSQL, application, and egress-guard images"
        compose build --pull db app app-egress-guard
    else
        log "Re-attesting the pre-pulled signed-release image IDs and immutable digests"
        validate_local_release_images
    fi
    run_postgres_runtime_migration

    log "Preparing and sealing database identities while every long-lived lane remains blocked"
    if ! compose up --detach --no-build \
        db rabbitmq-volume-init rabbitmq rabbitmq-provision staging-provision \
        db-provision migrate db-seal; then
        show_failure_guidance
        die "Database identity transition startup failed."
    fi
    wait_for_database_seal
    seal_artifact_key_provider_migration
    complete_database_identity_generation
    complete_postgres_storage_generation
    validate_runtime_configuration
    validate_compose_model

    log "Running the security preflight against the sealed database"
    if ! compose up --detach --no-build preflight \
        || ! compose wait preflight >/dev/null; then
        show_failure_guidance
        die "Core security preflight failed after the database identity seal."
    fi

    log "Force-recreating the web/guard network-namespace pair"
    if ! compose up --detach --no-build --no-deps --force-recreate \
        app-egress-guard app; then
        show_failure_guidance
        die "Core startup failed after the database identity seal."
    fi
    wait_for_app
}

quiesce_failed_operations_start() {
    if [[ "$IMAGE_MODE" == "signed-release" ]]; then
        # Egress guards share network namespaces with their workers and may not
        # be stopped independently.  The signed wrapper therefore removes the
        # complete container topology while preserving every named volume.
        compose --profile operations down --timeout 300 >/dev/null 2>&1 || true
    else
        compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
    fi
}

start_operations() {
    local service_name=""
    local service_container_ids=""
    local service_container_count=0
    local container_id=""
    local state=""
    local command_line=""
    local worker_role=""
    local container_ready=false
    local elapsed=0
    local all_ready=false
    local found_container=false
    local current_container_count=0
    local index=0
    local restart_count=""
    local -a operation_container_ids=()
    local -a operation_restart_counts=()
    local -a operation_service_names=()

    log "Explicit operations opt-in received; starting provider workers and the scheduler"
    if ! compose --profile operations up --detach --no-build --no-deps \
        --force-recreate "${OPERATION_GUARD_SERVICES[@]}" \
        "${OPERATION_WORKER_SERVICES[@]}"; then
        quiesce_failed_operations_start
        show_failure_guidance
        die "Operations startup failed; complete-topology quiescence was requested."
    fi
    if ! compose --profile operations up --detach --no-build --no-deps beat; then
        quiesce_failed_operations_start
        show_failure_guidance
        die "Beat startup failed after the guarded workers were recreated; complete-topology quiescence was requested."
    fi

    # A container is initially "running" while init.sh is still executing the
    # deployment preflight. Docker's init shim remains PID 1, so inspect its one
    # direct child and, for workers, require the post-AMQP-consumer readiness witness
    # before accepting readiness. Remote-control pidboxes stay disabled so a worker
    # cannot configure or consume another lane's broker resources.
    while [[ "$elapsed" -lt 180 ]]; do
        all_ready=true
        operation_container_ids=()
        operation_restart_counts=()
        operation_service_names=()
        for service_name in "${OPERATION_SERVICES[@]}"; do
            if ! service_container_ids="$(compose --profile operations ps --all -q "$service_name")"; then
                quiesce_failed_operations_start
                die "Could not inventory operations service ${service_name}; complete-topology quiescence was requested."
            fi
            service_container_count=0
            while IFS= read -r container_id; do
                [[ -n "$container_id" ]] || continue
                service_container_count=$((service_container_count + 1))
                container_ready=true
                state="$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null || true)"
                case "$state" in
                    exited|dead)
                        quiesce_failed_operations_start
                        die "Operations service ${service_name} container ${container_id} terminated during startup; complete-topology quiescence was requested."
                        ;;
                    running) ;;
                    *) container_ready=false ;;
                esac

                # While init.sh runs, its argv already contains the eventual Celery
                # arguments. Only the post-exec child cmdline names the Celery script.
                command_line="$("$DOCKER_BIN" exec "$container_id" sh -ec '
                    set -- $(cat /proc/1/task/1/children)
                    [ "$#" -eq 1 ]
                    case "$1" in *[!0-9]*|"") exit 1 ;; esac
                    tr "\\000" " " < "/proc/$1/cmdline"
                ' 2>/dev/null || true)"
                if [[ "$service_name" == "beat" ]]; then
                    [[ "$command_line" == *"/usr/local/bin/celery -A backupsheep beat "* ]] \
                        || container_ready=false
                else
                    [[ "$command_line" == *"/usr/local/bin/celery -A backupsheep worker "* ]] \
                        || container_ready=false
                    worker_role="${service_name#worker-}"
                    if [[ "$container_ready" == true ]] && ! "$DOCKER_BIN" exec "$container_id" \
                        sh -ec 'test "$(cat /run/backupsheep/celery-ready 2>/dev/null)" = "$1"' \
                        worker-health "$worker_role"; then
                        container_ready=false
                    fi
                fi
                if [[ "$container_ready" == true ]]; then
                    if ! restart_count="$("$DOCKER_BIN" inspect --format '{{.RestartCount}}' "$container_id")"; then
                        quiesce_failed_operations_start
                        die "Could not inspect operations service ${service_name} container ${container_id}; complete-topology quiescence was requested."
                    fi
                    operation_container_ids+=("$container_id")
                    operation_service_names+=("$service_name")
                    operation_restart_counts+=("$restart_count")
                else
                    all_ready=false
                fi
            done <<< "$service_container_ids"
            if [[ "$service_container_count" -eq 0 ]]; then
                all_ready=false
            fi
            if [[ "$service_name" == "beat" && "$service_container_count" -gt 1 ]]; then
                quiesce_failed_operations_start
                die "At most one Beat scheduler is allowed; found ${service_container_count}. Complete-topology quiescence was requested."
            fi
        done
        [[ "$all_ready" == true ]] && break
        sleep 3
        elapsed=$((elapsed + 3))
    done
    if [[ "$all_ready" != true ]]; then
        quiesce_failed_operations_start
        die "Operations services did not finish preflight and exec their expected processes within three minutes; complete-topology quiescence was requested."
    fi

    sleep 10

    # Bind the stability result to the exact ready container set. A vanished or
    # replacement replica has not passed the child-command and broker-ping gates.
    current_container_count=0
    for service_name in "${OPERATION_SERVICES[@]}"; do
        if ! service_container_ids="$(compose --profile operations ps --all -q "$service_name")"; then
            quiesce_failed_operations_start
            die "Could not re-inventory operations service ${service_name}; complete-topology quiescence was requested."
        fi
        service_container_count=0
        while IFS= read -r container_id; do
            [[ -n "$container_id" ]] || continue
            service_container_count=$((service_container_count + 1))
            current_container_count=$((current_container_count + 1))
            found_container=false
            index=0
            while [[ "$index" -lt "${#operation_container_ids[@]}" ]]; do
                if [[ "$container_id" == "${operation_container_ids[$index]}" \
                    && "$service_name" == "${operation_service_names[$index]}" ]]; then
                    found_container=true
                    break
                fi
                index=$((index + 1))
            done
            if [[ "$found_container" != true ]]; then
                quiesce_failed_operations_start
                die "Operations service ${service_name} changed container identity during its stability window; complete-topology quiescence was requested."
            fi
        done <<< "$service_container_ids"
        if [[ "$service_container_count" -eq 0 ]]; then
            quiesce_failed_operations_start
            die "Operations service ${service_name} disappeared during its stability window; complete-topology quiescence was requested."
        fi
        if [[ "$service_name" == "beat" && "$service_container_count" -gt 1 ]]; then
            quiesce_failed_operations_start
            die "More than one Beat scheduler appeared during the stability window; complete-topology quiescence was requested."
        fi
    done
    if [[ "$current_container_count" -ne "${#operation_container_ids[@]}" ]]; then
        quiesce_failed_operations_start
        die "The operations container set changed during its stability window; complete-topology quiescence was requested."
    fi

    index=0
    while [[ "$index" -lt "${#operation_container_ids[@]}" ]]; do
        service_name="${operation_service_names[$index]}"
        container_id="${operation_container_ids[$index]}"
        if ! state="$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null)" \
            || ! restart_count="$("$DOCKER_BIN" inspect --format '{{.RestartCount}}' "$container_id" 2>/dev/null)"; then
            quiesce_failed_operations_start
            die "Could not verify operations service ${service_name} container ${container_id}; complete-topology quiescence was requested."
        fi
        if [[ "$state" != "running" || "$restart_count" != "${operation_restart_counts[$index]}" ]]; then
            quiesce_failed_operations_start
            die "Operations service ${service_name} container ${container_id} was not stable after startup; complete-topology quiescence was requested."
        fi
        index=$((index + 1))
    done
}

print_next_steps() {
    printf '\nBackupSheep core is running from verified commit %s.\n\n' "$INSTALL_REF"
    printf 'The web port is bound to server loopback only. From a trusted workstation, run:\n'
    printf '  ssh -L %s:127.0.0.1:%s user@<server>\n' "$APP_PORT" "$APP_PORT"
    printf 'Then open: http://127.0.0.1:%s/onboarding/\n\n' "$APP_PORT"
    printf 'Retrieve the onboarding token explicitly from the trusted server shell:\n'
    printf '  cd %q && cat .secrets/onboarding_token\n' "$INSTALL_DIR"
    printf '\nInstallation directory: %s\n' "$INSTALL_DIR"
    printf 'Compose project: %s\n' "$PROJECT_NAME"
    printf '\nRecovery warning: PostgreSQL and both artifact keyrings are one cryptographic recovery set.\n'
    printf 'Back up these exact protected files together with PostgreSQL:\n'
    printf '  %s\n' "${INSTALL_DIR}/.secrets/artifact_local_file_database_keyring"
    printf '  %s\n' "${INSTALL_DIR}/.secrets/artifact_local_file_files_keyring"
    printf 'Loss, replacement, or regeneration of either keyring is unrecoverable for retained backups in that lane.\n'
    if [[ "$ALLOW_ROOT_INSTALL" == true ]]; then
        printf 'This is a root-owned installation. Every wrapper invocation must run as effective UID 0 and begin with --allow-root-install.\n'
        printf '  %q/backupsheep-compose --allow-root-install ps --all\n' "$INSTALL_DIR"
    fi
    if [[ "$ENABLE_OPERATIONS" == true ]]; then
        printf 'Provider workers and the scheduler were explicitly enabled.\n'
    else
        printf 'Provider workers and the scheduler were not started. Review provider credentials and then rerun with --enable-operations.\n'
    fi
}

main() {
    trap cleanup EXIT
    trap 'handle_installer_signal 129' HUP
    trap 'handle_installer_signal 130' INT
    trap 'handle_installer_signal 143' TERM
    parse_args "$@"
    validate_invocation_mode
    require_commands
    validate_privileged_runtime_environment
    validate_installer_source
    validate_ref
    validate_public_host
    validate_project_name
    validate_install_dir
    acquire_installation_mutation_lock
    validate_approved_compose_file
    validate_docker_access
    clone_or_validate_repository
    reconcile_installer_temp_residues
    reconcile_fresh_env_candidate
    reconcile_release_request_candidate
    reconcile_image_source_contract_candidate
    validate_requested_image_mode_against_existing
    prepare_image_source
    create_or_migrate_configuration
    # A signing-key rotation is prepared fail closed in configuration first. Prove
    # the exact Compose ownership model before inspecting or mutating its broker,
    # then commit the candidate generation while every publisher/consumer is stopped.
    validate_compose_model
    validate_compose_project_ownership
    finalize_celery_signing_rotation
    validate_runtime_configuration
    validate_compose_model
    validate_rabbitmq_data_generation

    if [[ "$SKIP_START" == true ]]; then
        log "Verified checkout and protected configuration are ready; nothing was built or started"
        printf 'Start the core with a reviewed command from %s; do not use a broad profile-less `up`.\n' "$INSTALL_DIR"
        return
    fi

    start_core
    if [[ "$ENABLE_OPERATIONS" == true ]]; then
        start_operations
    fi
    complete_artifact_key_provider_migration
    print_next_steps
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
