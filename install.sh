#!/usr/bin/env bash
# BackupSheep Docker installer.
#
# This script deliberately does not provision or reconfigure the host. The operator is
# responsible for installing Git, Docker Engine and the Docker Compose plugin, granting
# the invoking user access to the intended Docker daemon, and configuring host security.
#
# Download this file from the same immutable commit passed with --ref. The installer
# verifies that its own bytes match that commit before it builds or starts anything.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly REPOSITORY_URL="https://github.com/bilal414/backupsheep.git"
readonly APP_PORT="8000"
readonly -a CORE_SERVICES=(db rabbitmq migrate preflight app)
readonly -a OPERATION_SERVICES=(
    worker-cloud
    worker-database
    worker-files
    worker-storage
    worker-logs
    beat
)
readonly -a SECRET_NAMES=(
    django_secret_key
    db_password
    rabbitmq_password
    onboarding_token
    ssh_managed_private_key
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
INSTALL_DIR="$(default_install_dir)"
PUBLIC_HOST="localhost"
PROJECT_NAME="backupsheep"
PROJECT_NAME_WAS_EXPLICIT=false
ADOPT_LEGACY_PROJECT=""
APPROVED_COMPOSE_FILE=""
SKIP_START=false
ENABLE_OPERATIONS=false
INSTALL_WAS_PRESENT=false
ENV_WAS_PRESENT=false
ENV_FILE=""
SECRETS_DIR=""
APP_DOMAIN=""
SCRIPT_PATH=""
STAGING_DIR=""
GIT_BIN=""
DOCKER_BIN=""

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

usage() {
    cat <<'EOF'
Install BackupSheep into an existing Docker environment without changing the host.

Usage:
  install.sh --ref COMMIT [options]

Required:
  --ref COMMIT       Exact 40-character Git commit to install. Branches, tags and
                     abbreviated commits are intentionally rejected.

Options:
  --domain HOST       Accepted/public hostname or IPv4 address (default: localhost).
                      The listener remains on 127.0.0.1:8000.
  --install-dir PATH  Installation directory (default: $XDG_DATA_HOME/backupsheep or
                      $HOME/.local/share/backupsheep).
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
  --skip-start        Create and validate the installation, but do not build or start it.
  -h, --help          Show this help.

Secure acquisition example (replace COMMIT with a reviewed release commit):
  COMMIT='<40-character-release-commit>'
  curl -fSLo install.sh \
    "https://raw.githubusercontent.com/bilal414/backupsheep/${COMMIT}/install.sh"
  chmod 700 install.sh
  ./install.sh --ref "${COMMIT}" --domain backups.example.com

Do not pipe a remote script to a shell. Run this installer as the same unprivileged
user that is already authorized to use the intended Docker daemon.
EOF
}

cleanup() {
    if [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]]; then
        case "$(basename -- "$STAGING_DIR")" in
            .backupsheep-install.*)
                rm -rf -- "$STAGING_DIR"
                ;;
            *)
                warn "Refusing to remove unexpected staging path: ${STAGING_DIR}"
                ;;
        esac
    fi
}

trap cleanup EXIT

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
            --domain)
                [[ $# -ge 2 ]] || die "--domain requires a hostname or IPv4 address"
                PUBLIC_HOST="$2"
                shift 2
                ;;
            --install-dir)
                [[ $# -ge 2 ]] || die "--install-dir requires an absolute path"
                INSTALL_DIR="$2"
                shift 2
                ;;
            --project-name)
                [[ $# -ge 2 ]] || die "--project-name requires a value"
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
    if [[ -n "$ADOPT_LEGACY_PROJECT" ]]; then
        if [[ "$PROJECT_NAME_WAS_EXPLICIT" == true && "$PROJECT_NAME" != "$ADOPT_LEGACY_PROJECT" ]]; then
            die "--project-name and --adopt-legacy-project must name the same project"
        fi
        PROJECT_NAME="$ADOPT_LEGACY_PROJECT"
    fi
}

refuse_privileged_invocation() {
    (( EUID != 0 )) \
        || die "Do not run install.sh as root or through sudo. Use the same unprivileged user that is already authorized for the intended Docker daemon."
}

require_commands() {
    local command_name=""
    local -a required=(
        awk basename chmod cmp cp dirname docker env find git grep install mktemp mv od
        realpath rm sed stat tr
    )

    for command_name in "${required[@]}"; do
        command_exists "$command_name" \
            || die "Required command '${command_name}' is unavailable. Host prerequisites are the operator's responsibility."
    done

    GIT_BIN="$(command -v git)"
    DOCKER_BIN="$(command -v docker)"
    [[ "$GIT_BIN" == /* && "$DOCKER_BIN" == /* ]] \
        || die "Git and Docker must resolve to absolute executable paths."
}

validate_installer_source() {
    local source_path="${BASH_SOURCE[0]}"
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

    [[ "$source_owner" == "$EUID" ]] \
        || die "The installer must be owned by the invoking user."
    (( (8#$source_mode & 8#022) == 0 )) \
        || die "The installer must not be writable by group or other users."
    [[ "$source_links" == "1" ]] \
        || die "The installer must not be hard-linked."
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
    [[ "$PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] \
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

    [[ "$INSTALL_DIR" == /* && "$INSTALL_DIR" != "/" ]] \
        || die "--install-dir must be an absolute path other than /."
    [[ "$INSTALL_DIR" != *$'\n'* && "$INSTALL_DIR" != *$'\r'* && "$INSTALL_DIR" != *$'\t'* ]] \
        || die "--install-dir cannot contain control characters."

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
            || die "Cannot create installation parent directory ${parent_dir}. Choose a user-writable path."
    fi
    [[ -d "$parent_dir" && ! -L "$parent_dir" ]] \
        || die "The installation parent must be a real directory, not a symlink."

    parent_owner="$(file_uid "$parent_dir")"
    parent_mode="$(file_mode "$parent_dir")"
    [[ "$parent_owner" == "$EUID" ]] \
        || die "The installation parent must be owned by the invoking user: ${parent_dir}"
    (( (8#$parent_mode & 8#022) == 0 )) \
        || die "The installation parent must not be group- or world-writable: ${parent_dir}"

    if [[ -e "$INSTALL_DIR" || -L "$INSTALL_DIR" ]]; then
        [[ -d "$INSTALL_DIR" && ! -L "$INSTALL_DIR" ]] \
            || die "The installation target must be a real directory, not a file or symlink."
        INSTALL_WAS_PRESENT=true
    fi
}

validate_approved_compose_file() {
    local expected_override="${INSTALL_DIR}/docker-compose.override.yml"
    local approved_real=""
    local mode=""

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
        || die "The approved Compose override must be owned by the invoking user."
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

    "$DOCKER_BIN" info >/dev/null 2>&1 \
        || die "The Docker daemon is unavailable to this user. Install/configure Docker on the host, then retry."
    engine_version="$("$DOCKER_BIN" version --format '{{.Server.Version}}' 2>/dev/null)" \
        || die "Could not read the Docker Engine server version from the selected daemon."
    if ! semver_at_least "$engine_version" "28.0.0"; then
        die "Docker Engine 28.0.0 or newer is required by the isolated-network model (found: ${engine_version:-unparseable}). Upgrade the operator-managed Docker host, then retry."
    fi

    compose_version="$("$DOCKER_BIN" compose version --short 2>/dev/null)" \
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
        || die "Checkout content must be owned by the invoking user: ${unsafe_path}"

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
    require_regular_checkout_file docker-compose.yml
    require_regular_checkout_file .dockerignore
    require_regular_checkout_file .env_sample
    require_regular_checkout_file install.sh
    require_regular_checkout_file backupsheep-compose
    [[ -x "$INSTALL_DIR/backupsheep-compose" ]] \
        || die "The reviewed backupsheep-compose wrapper must remain executable."

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
    STAGING_DIR="$(mktemp -d "${parent_dir}/.backupsheep-install.XXXXXXXX")" \
        || die "Could not create a protected staging directory under ${parent_dir}."
    chmod 0700 "$STAGING_DIR"

    log "Fetching immutable BackupSheep commit ${INSTALL_REF}"
    git_safe -C "$STAGING_DIR" init --quiet
    git_safe -C "$STAGING_DIR" remote add origin "$REPOSITORY_URL"
    git_safe -C "$STAGING_DIR" -c protocol.version=2 fetch --quiet --depth=1 --no-tags origin "$INSTALL_REF"
    fetched_commit="$(git_safe -C "$STAGING_DIR" rev-parse --verify 'FETCH_HEAD^{commit}')"
    [[ "$fetched_commit" == "$INSTALL_REF" ]] \
        || die "The fetched commit (${fetched_commit}) does not match requested commit ${INSTALL_REF}."
    git_safe -C "$STAGING_DIR" checkout --quiet --detach "$INSTALL_REF"

    atomic_move_new "$STAGING_DIR" "$INSTALL_DIR" \
        || die "Could not atomically publish the verified checkout at ${INSTALL_DIR}."
    STAGING_DIR=""
    chmod 0700 "$INSTALL_DIR"
    validate_checkout
}

clone_or_validate_repository() {
    if [[ "$INSTALL_WAS_PRESENT" == true ]]; then
        log "Validating existing installation at ${INSTALL_DIR}"
        validate_checkout
    else
        clone_exact_commit
    fi
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
        || die "${ENV_FILE} must be owned by the invoking user, mode 0600, and not hard-linked."
    [[ "$env_size" -le 1048576 ]] || die "${ENV_FILE} is unexpectedly large."
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
        || die "${SECRETS_DIR} must be owned by the invoking user and mode 0700."

    for entry in \
        "$SECRETS_DIR"/* \
        "$SECRETS_DIR"/.[!.]* \
        "$SECRETS_DIR"/..?*; do
        [[ -e "$entry" || -L "$entry" ]] || continue
        base="$(basename -- "$entry")"
        allowed=false
        for expected in "${SECRET_NAMES[@]}"; do
            if [[ "$base" == "$expected" ]]; then
                allowed=true
                break
            fi
        done
        [[ "$allowed" == true ]] \
            || die "Unexpected entry in protected secret directory: ${base}"
    done
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
        || die "${secret_path} must be owned by the invoking user, mode 0444, and not hard-linked."
    secret_name="$(basename -- "$secret_path")"
    if [[ "$secret_name" == "ssh_managed_private_key" ]]; then
        [[ "$secret_size" -le 65536 ]] \
            || die "${secret_path} exceeds the 64 KiB managed-key limit."
        ! od -An -v -tx1 "$secret_path" | grep -Eq '(^|[[:space:]])00([[:space:]]|$)' \
            || die "${secret_path} contains a NUL byte."
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
        db_password) minimum_length=24 ;;
        rabbitmq_password|onboarding_token) minimum_length=32 ;;
        *) die "Unknown installation secret file: ${secret_name}" ;;
    esac
    [[ "${#secret_value}" -ge "$minimum_length" ]] \
        || die "${secret_name} is shorter than its minimum secure length (${minimum_length} characters)."
}

write_empty_optional_secret_file() {
    local secret_name="$1"
    local secret_path="${SECRETS_DIR}/${secret_name}"
    local temporary_file=""

    [[ "$secret_name" == "ssh_managed_private_key" ]] \
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
}

prepare_managed_ssh_private_key() {
    local configured_path=""
    local secret_path="${SECRETS_DIR}/ssh_managed_private_key"
    local secret_size=""

    configured_path="$(read_env_value SSH_MANAGED_PRIVATE_KEY_PATH)"
    if [[ -e "$secret_path" || -L "$secret_path" ]]; then
        validate_secret_file "$secret_path"
        secret_size="$(file_size "$secret_path")"
        if [[ -n "$configured_path" && "$secret_size" -eq 0 ]]; then
            die "The managed-key placeholder is empty while SSH_MANAGED_PRIVATE_KEY_PATH still names a legacy key. Move that key into .secrets/ssh_managed_private_key (mode 0444), clear the legacy path, and rerun."
        fi
    else
        [[ -z "$configured_path" ]] \
            || die "Move the existing managed SSH private key into .secrets/ssh_managed_private_key (mode 0444), clear SSH_MANAGED_PRIVATE_KEY_PATH, and rerun. The installer will not copy host key material implicitly."
        write_empty_optional_secret_file ssh_managed_private_key
    fi
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
        grep -Fxq "$expected_name" <<< "$all_volume_names" \
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
        [[ "$persisted_project" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] \
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
        if ! grep -Fxq "$candidate" <<< "$candidates"; then
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
        if ! grep -Fxq "$candidate" <<< "$candidates"; then
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

create_or_migrate_configuration() {
    ENV_FILE="${INSTALL_DIR}/.env"
    SECRETS_DIR="${INSTALL_DIR}/.secrets"

    if [[ -e "$ENV_FILE" || -L "$ENV_FILE" ]]; then
        ENV_WAS_PRESENT=true
        validate_env_file
        log "Preserving and validating existing configuration"
    else
        log "Creating a protected production configuration"
        cp -- "$INSTALL_DIR/.env_sample" "$ENV_FILE"
        chmod 0600 "$ENV_FILE"
        validate_env_file
        set_env_value BACKUPSHEEP_IMAGE "backupsheep:${INSTALL_REF}"
        set_env_value DJANGO_ALLOWED_HOSTS "${PUBLIC_HOST},localhost,127.0.0.1"
        set_env_value APP_DOMAIN "$APP_DOMAIN"
        set_env_value APP_PROTOCOL "http://"
        set_env_value DJANGO_HTTPS "false"
        set_env_value BACKUPSHEEP_BIND_ADDRESS "127.0.0.1"
    fi

    if [[ -e "$SECRETS_DIR" || -L "$SECRETS_DIR" ]]; then
        validate_secret_dir
    else
        install -d -m 0700 -- "$SECRETS_DIR"
    fi

    ensure_installation_id
    ensure_compose_project_name

    if [[ "$ENV_WAS_PRESENT" == true ]]; then
        reject_connection_url_overrides
        migrate_one_secret DJANGO_SECRET_KEY django_secret_key false
        migrate_one_secret DB_PASSWORD db_password false
        migrate_one_secret RABBITMQ_PASSWORD rabbitmq_password false
        migrate_one_secret ONBOARDING_INSTALL_TOKEN onboarding_token true
    else
        write_secret_file django_secret_key "$(random_hex 48)"
        write_secret_file db_password "$(random_hex 24)"
        write_secret_file rabbitmq_password "$(random_hex 32)"
        write_secret_file onboarding_token "$(random_hex 32)"
    fi
    prepare_managed_ssh_private_key

    validate_secret_dir
    set_env_value BACKUPSHEEP_IMAGE "backupsheep:${INSTALL_REF}"
    rewrite_env_for_secret_files
    validate_env_file
}

validate_runtime_configuration() {
    local value=""
    local key=""
    local secret_name=""

    value="$(read_env_value BACKUPSHEEP_IMAGE)"
    [[ "$value" == "backupsheep:${INSTALL_REF}" ]] \
        || die "BACKUPSHEEP_IMAGE must be backupsheep:${INSTALL_REF} for this verified source build."
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
    value="$(read_env_value BACKUPSHEEP_INSTALLATION_ID)"
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] \
        || die "BACKUPSHEEP_INSTALLATION_ID must be one stable 64-character lowercase hexadecimal value."
    value="$(read_env_value BACKUPSHEEP_COMPOSE_PROJECT_NAME)"
    [[ "$value" == "$PROJECT_NAME" ]] \
        || die "BACKUPSHEEP_COMPOSE_PROJECT_NAME must match --project-name exactly."
    value="$(read_env_value RABBITMQ_USER)"
    [[ "$value" != "guest" ]] || die "The bundled broker must not use the RabbitMQ guest account."
    value="$(read_env_value CELERY_BROKER_URL)"
    [[ -z "$value" ]] || die "CELERY_BROKER_URL must be blank for the stock file-backed broker configuration."
    value="$(read_env_value DATABASE_URL)"
    [[ -z "$value" ]] || die "DATABASE_URL must be blank for the stock file-backed database configuration."

    for key in \
        DJANGO_SECRET_KEY \
        DB_PASSWORD \
        RABBITMQ_PASSWORD \
        ONBOARDING_INSTALL_TOKEN \
        SSH_MANAGED_PRIVATE_KEY_PATH; do
        value="$(read_env_value "$key")"
        [[ -z "$value" ]] || die "${key} must be blank after migration to file-backed secrets."
    done
    for secret_name in "${SECRET_NAMES[@]}"; do
        validate_secret_file "${SECRETS_DIR}/${secret_name}"
    done
}

compose() {
    (
        local -a compose_environment=(
            /usr/bin/env -i
            "HOME=${HOME-}"
            "PATH=${PATH:-/usr/local/bin:/usr/bin:/bin}"
            "COMPOSE_BAKE=false"
            "COMPOSE_EXPERIMENTAL=false"
            "COMPOSE_REMOVE_ORPHANS=0"
        )
        local transport_variable=""
        local -a compose_model=(-f "$INSTALL_DIR/docker-compose.yml")

        if [[ -n "$APPROVED_COMPOSE_FILE" ]]; then
            compose_model+=(-f "$APPROVED_COMPOSE_FILE")
        fi

        # Compose gives the invoking shell precedence over --env-file during
        # interpolation. Do not let an ambient BACKUPSHEEP_BIND_ADDRESS,
        # BACKUPSHEEP_IMAGE, secret path, resource limit, or future model value
        # bypass the configuration that was just parsed and validated above.
        # Preserve only Docker transport/credential-helper inputs and proxy/CA
        # settings needed to reach an intentionally selected daemon or registry.
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
        "${compose_environment[@]}" "$DOCKER_BIN" compose \
            --project-name "$PROJECT_NAME" \
            --project-directory "$INSTALL_DIR" \
            --env-file "$ENV_FILE" \
            "${compose_model[@]}" \
            "$@"
    )
}

expected_compose_config_files() {
    printf '%s' "${INSTALL_DIR}/docker-compose.yml"
    if [[ -n "$APPROVED_COMPOSE_FILE" ]]; then
        printf ',%s' "$APPROVED_COMPOSE_FILE"
    fi
}

require_compose_service() {
    local wanted="$1"
    local available_services="$2"

    grep -Fxq "$wanted" <<< "$available_services" \
        || die "The reviewed Compose model is missing expected service ${wanted}."
}

validate_compose_model() {
    local available_services=""
    local service_name=""

    log "Validating the exact Compose model without printing expanded secrets"
    compose config --quiet
    available_services="$(compose --profile operations config --services)"
    for service_name in "${CORE_SERVICES[@]}" "${OPERATION_SERVICES[@]}"; do
        require_compose_service "$service_name" "$available_services"
    done
}

docker_resource_label() {
    local resource_type="$1"
    local resource_id="$2"
    local label_name="$3"

    case "$resource_type" in
        container)
            "$DOCKER_BIN" inspect --format \
                "{{with index .Config.Labels \"${label_name}\"}}{{.}}{{end}}" \
                "$resource_id"
            ;;
        network)
            "$DOCKER_BIN" network inspect --format \
                "{{with index .Labels \"${label_name}\"}}{{.}}{{end}}" \
                "$resource_id"
            ;;
        volume)
            "$DOCKER_BIN" volume inspect --format \
                "{{with index .Labels \"${label_name}\"}}{{.}}{{end}}" \
                "$resource_id"
            ;;
        *) die "Unknown Docker resource type during ownership validation." ;;
    esac
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

create_verified_legacy_container_sentinel() {
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
    )" || die "Could not create the verified legacy ownership sentinel; no Compose service was mutated."
    [[ "$created_name" == "$sentinel_name" ]] \
        || die "Docker returned an unexpected legacy ownership-sentinel name; refusing to continue."

    inspected_name="$(docker_resource_name volume "$sentinel_name")" \
        || die "Could not re-inspect the verified legacy ownership sentinel."
    resource_project="$(docker_resource_label volume "$sentinel_name" com.docker.compose.project)" \
        || die "Could not verify the legacy ownership-sentinel project label."
    logical_name="$(docker_resource_label volume "$sentinel_name" com.docker.compose.volume)" \
        || die "Could not verify the legacy ownership-sentinel logical label."
    resource_installation_id="$(docker_resource_label volume "$sentinel_name" com.backupsheep.installation-id)" \
        || die "Could not verify the legacy ownership-sentinel identity label."
    [[ "$inspected_name" == "$sentinel_name" \
        && "$resource_project" == "$PROJECT_NAME" \
        && "$logical_name" == "installation_identity" \
        && "$resource_installation_id" == "$installation_id" ]] \
        || die "The verified legacy ownership sentinel did not retain every exact required label."
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
    local resource_name=""
    local resource_project=""
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
        grep -Fxq "$expected_resource_name" <<< "$all_network_names" || continue
        resource_project="$(docker_resource_label network "$expected_resource_name" com.docker.compose.project)"
        resource_installation_id="$(docker_resource_label network "$expected_resource_name" com.docker.compose.network)"
        [[ "$resource_project" == "$PROJECT_NAME" && "$resource_installation_id" == "$logical_name" ]] \
            || die "Docker network ${expected_resource_name} collides with this Compose model but is not owned by it."
    done <<< "$available_networks"
    while IFS= read -r logical_name; do
        [[ -n "$logical_name" ]] || continue
        expected_resource_name="${PROJECT_NAME}_${logical_name}"
        grep -Fxq "$expected_resource_name" <<< "$all_volume_names" || continue
        resource_project="$(docker_resource_label volume "$expected_resource_name" com.docker.compose.project)"
        resource_installation_id="$(docker_resource_label volume "$expected_resource_name" com.docker.compose.volume)"
        [[ "$resource_project" == "$PROJECT_NAME" && "$resource_installation_id" == "$logical_name" ]] \
            || die "Docker volume ${expected_resource_name} collides with this Compose model but is not owned by it."
    done <<< "$available_volumes"

    if (( container_count == 0 && network_count == 0 && volume_count == 0 )); then
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
            grep -Fxq "$logical_name" <<< "$available_services" \
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
            grep -Fxq "$logical_name" <<< "$available_networks" \
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
            grep -Fxq "$logical_name" <<< "$available_volumes" \
                || die "Compose project ${PROJECT_NAME} has an unexpected volume: ${logical_name}."
            resource_name="$(docker_resource_name volume "$resource_id")" \
                || die "Could not inspect Compose volume ${logical_name}."
            [[ "$resource_name" == "${PROJECT_NAME}_${logical_name}" ]] \
                || die "Compose volume ${logical_name} has a non-canonical physical name."
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
        create_verified_legacy_container_sentinel "$installation_id"
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
    warn "Startup was left in place for evidence and recovery; no volumes or containers were deleted."
    warn "Inspect locally with: cd $(printf '%q' "$INSTALL_DIR") && ./backupsheep-compose logs --tail=100 migrate preflight app"
}

wait_for_app() {
    local elapsed=0
    local container_id=""
    local status=""
    local migrate_container_id=""
    local migrate_status=""
    local migrate_exit_code=""
    local preflight_container_id=""
    local preflight_status=""
    local preflight_exit_code=""

    log "Waiting for the BackupSheep core to become healthy"
    while [[ "$elapsed" -lt 300 ]]; do
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

stop_operations() {
    log "Stopping the exact provider-worker and scheduler set before build or migration"
    if ! compose --profile operations stop "${OPERATION_SERVICES[@]}"; then
        die "Could not stop every operations service; refusing to build or migrate while provider work may still run."
    fi
}

start_core() {
    stop_operations

    log "Building the reviewed application image"
    compose build --pull app

    log "Starting core services only (database, broker, migration, security preflight and web)"
    if ! compose up --detach --no-build "${CORE_SERVICES[@]}"; then
        show_failure_guidance
        die "Core startup failed."
    fi
    wait_for_app
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
    if ! compose --profile operations up --detach --no-build "${OPERATION_SERVICES[@]}"; then
        compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
        show_failure_guidance
        die "Operations startup failed."
    fi

    # A container is initially "running" while init.sh is still executing the
    # deployment preflight. Docker's init shim remains PID 1, so inspect its one
    # direct child and, for workers, require an authenticated Celery ping before
    # accepting readiness. Then require a restart-free stability window.
    while [[ "$elapsed" -lt 180 ]]; do
        all_ready=true
        operation_container_ids=()
        operation_restart_counts=()
        operation_service_names=()
        for service_name in "${OPERATION_SERVICES[@]}"; do
            if ! service_container_ids="$(compose --profile operations ps --all -q "$service_name")"; then
                compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
                die "Could not inventory operations service ${service_name}; all operations services were stopped."
            fi
            service_container_count=0
            while IFS= read -r container_id; do
                [[ -n "$container_id" ]] || continue
                service_container_count=$((service_container_count + 1))
                container_ready=true
                state="$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null || true)"
                case "$state" in
                    exited|dead)
                        compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
                        die "Operations service ${service_name} container ${container_id} terminated during startup; all operations services were stopped."
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
                        sh -ec '
                            node_name="$1@$(hostname)"
                            response="$(celery -A backupsheep inspect ping \
                                --timeout=5 --destination "$node_name" 2>/dev/null)"
                            case "$response" in *pong*) ;; *) exit 1 ;; esac
                        ' worker-health "$worker_role"; then
                        container_ready=false
                    fi
                fi
                if [[ "$container_ready" == true ]]; then
                    if ! restart_count="$("$DOCKER_BIN" inspect --format '{{.RestartCount}}' "$container_id")"; then
                        compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
                        die "Could not inspect operations service ${service_name} container ${container_id}; all operations services were stopped."
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
                compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
                die "At most one Beat scheduler is allowed; found ${service_container_count}. All operations services were stopped."
            fi
        done
        [[ "$all_ready" == true ]] && break
        sleep 3
        elapsed=$((elapsed + 3))
    done
    if [[ "$all_ready" != true ]]; then
        compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
        die "Operations services did not finish preflight and exec their expected processes within three minutes; all were stopped."
    fi

    sleep 10

    # Bind the stability result to the exact ready container set. A vanished or
    # replacement replica has not passed the child-command and broker-ping gates.
    current_container_count=0
    for service_name in "${OPERATION_SERVICES[@]}"; do
        if ! service_container_ids="$(compose --profile operations ps --all -q "$service_name")"; then
            compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
            die "Could not re-inventory operations service ${service_name}; all operations services were stopped."
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
                compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
                die "Operations service ${service_name} changed container identity during its stability window; all operations services were stopped."
            fi
        done <<< "$service_container_ids"
        if [[ "$service_container_count" -eq 0 ]]; then
            compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
            die "Operations service ${service_name} disappeared during its stability window; all operations services were stopped."
        fi
        if [[ "$service_name" == "beat" && "$service_container_count" -gt 1 ]]; then
            compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
            die "More than one Beat scheduler appeared during the stability window; all operations services were stopped."
        fi
    done
    if [[ "$current_container_count" -ne "${#operation_container_ids[@]}" ]]; then
        compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
        die "The operations container set changed during its stability window; all operations services were stopped."
    fi

    index=0
    while [[ "$index" -lt "${#operation_container_ids[@]}" ]]; do
        service_name="${operation_service_names[$index]}"
        container_id="${operation_container_ids[$index]}"
        if ! state="$("$DOCKER_BIN" inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null)" \
            || ! restart_count="$("$DOCKER_BIN" inspect --format '{{.RestartCount}}' "$container_id" 2>/dev/null)"; then
            compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
            die "Could not verify operations service ${service_name} container ${container_id}; all operations services were stopped."
        fi
        if [[ "$state" != "running" || "$restart_count" != "${operation_restart_counts[$index]}" ]]; then
            compose --profile operations stop "${OPERATION_SERVICES[@]}" >/dev/null 2>&1 || true
            die "Operations service ${service_name} container ${container_id} was not stable after startup; all operations services were stopped."
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
    if [[ "$ENABLE_OPERATIONS" == true ]]; then
        printf 'Provider workers and the scheduler were explicitly enabled.\n'
    else
        printf 'Provider workers and the scheduler were not started. Review provider credentials and then rerun with --enable-operations.\n'
    fi
}

main() {
    parse_args "$@"
    refuse_privileged_invocation
    require_commands
    validate_installer_source
    validate_ref
    validate_public_host
    validate_project_name
    validate_install_dir
    validate_approved_compose_file
    validate_docker_access
    clone_or_validate_repository
    create_or_migrate_configuration
    validate_runtime_configuration
    validate_compose_model
    validate_compose_project_ownership
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
    print_next_steps
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
