#!/usr/bin/env bash
# BackupSheep server installer.
#
# Run from a trusted terminal with:
#   curl -fsSL https://raw.githubusercontent.com/bilal414/backupsheep/main/install.sh | sudo bash
#
# This installer deliberately supports the two distributions that the BackupSheep
# Docker image and deployment documentation are tested on: Ubuntu and Debian.

set -Eeuo pipefail
IFS=$'\n\t'

readonly REPOSITORY_URL="https://github.com/bilal414/backupsheep.git"
readonly DEFAULT_BRANCH="main"
readonly DEFAULT_INSTALL_DIR="/opt/backupsheep"
readonly APP_PORT="8000"

BRANCH="$DEFAULT_BRANCH"
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
PUBLIC_HOST="${BACKUPSHEEP_DOMAIN:-}"
SKIP_START=false
ENV_FILE=""
APP_DOMAIN=""
ONBOARDING_TOKEN=""

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
Install BackupSheep on a Debian or Ubuntu server.

Usage:
  install.sh [options]

Options:
  --domain HOST       Public hostname or IPv4 address for this server. The app will
                      be configured for http://HOST:8000. If omitted, the installer
                      detects the server's public IPv4 address.
  --branch BRANCH     Git branch or tag to install (default: main).
  --install-dir PATH  Installation directory (default: /opt/backupsheep).
  --skip-start        Provision the host and configuration but do not start Compose.
  -h, --help          Show this help.

Examples:
  curl -fsSL https://raw.githubusercontent.com/bilal414/backupsheep/main/install.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/bilal414/backupsheep/main/install.sh | sudo bash -s -- --domain backups.example.com
EOF
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "Run this installer as root, for example: curl -fsSL <url> | sudo bash"
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)
                [[ $# -ge 2 ]] || die "--domain requires a hostname or IPv4 address"
                PUBLIC_HOST="$2"
                shift 2
                ;;
            --branch)
                [[ $# -ge 2 ]] || die "--branch requires a value"
                BRANCH="$2"
                shift 2
                ;;
            --install-dir)
                [[ $# -ge 2 ]] || die "--install-dir requires an absolute path"
                INSTALL_DIR="$2"
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
}

load_os_release() {
    [[ -r /etc/os-release ]] || die "Cannot identify this operating system (/etc/os-release is missing)."
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
        debian|ubuntu)
            ;;
        *)
            die "Unsupported operating system: ${PRETTY_NAME:-${ID:-unknown}}. This installer currently supports Debian and Ubuntu."
            ;;
    esac
    [[ -n "${VERSION_CODENAME:-}" ]] || die "This ${ID} release does not provide VERSION_CODENAME."
}

install_base_packages() {
    log "Installing system prerequisites"
    apt-get update
    apt-get install -y ca-certificates curl git
}

install_docker() {
    if docker compose version >/dev/null 2>&1; then
        log "Docker Engine and Compose plugin are already available"
        return
    fi

    log "Installing Docker Engine and the Compose plugin"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
        "$(dpkg --print-architecture)" "$ID" "$VERSION_CODENAME" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

start_docker() {
    if ! docker info >/dev/null 2>&1 && command_exists systemctl && [[ -d /run/systemd/system ]]; then
        systemctl enable --now docker
    fi

    docker info >/dev/null 2>&1 || die "Docker is installed but its daemon is not available. Start Docker and run the installer again."
    docker compose version >/dev/null 2>&1 || die "Docker Compose plugin could not be started."
}

validate_install_dir() {
    [[ "$INSTALL_DIR" == /* && "$INSTALL_DIR" != "/" ]] || die "--install-dir must be an absolute path other than /."
}

validate_public_host() {
    [[ -n "$PUBLIC_HOST" ]] || die "No public hostname or IPv4 address was supplied or detected. Re-run with --domain <hostname-or-ip>."

    # A hostname or IPv4 address is enough for the initial HTTP setup. Keeping the
    # allowed character set narrow prevents a value from changing the generated .env.
    [[ "$PUBLIC_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$|^[A-Za-z0-9]$ ]] \
        || die "--domain must be a hostname or IPv4 address only (without http://, paths, or a port)."
    [[ "$PUBLIC_HOST" != *".."* ]] || die "--domain cannot contain consecutive dots."

    APP_DOMAIN="${PUBLIC_HOST}:${APP_PORT}"
}

detect_public_host() {
    [[ -n "$PUBLIC_HOST" ]] && return

    local detected_host=""
    if detected_host="$(curl -4fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"; then
        if [[ "$detected_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            PUBLIC_HOST="$detected_host"
            return
        fi
    fi

    if command_exists hostname; then
        detected_host="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
        if [[ "$detected_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            PUBLIC_HOST="$detected_host"
            warn "Could not determine a public IP; using local address ${PUBLIC_HOST}. Pass --domain to override it."
            return
        fi
    fi
}

random_hex() {
    local bytes="$1"
    [[ -r /dev/urandom ]] || die "The system random source is unavailable."
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
}

set_env_value() {
    local key="$1"
    local value="$2"

    [[ "$key" =~ ^[A-Z0-9_]+$ ]] || die "Invalid environment key: $key"
    # All values passed here are generated hex strings or validated hostnames, so they
    # cannot contain a quote or sed delimiter.
    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*$|${key}='${value}'|" "$ENV_FILE"
    else
        printf "%s='%s'\n" "$key" "$value" >> "$ENV_FILE"
    fi
}

read_env_value() {
    local key="$1"
    sed -n "s/^${key}='\([^']*\)'$/\1/p" "$ENV_FILE" | head -n 1
}

clone_or_reuse_repository() {
    if [[ -e "$INSTALL_DIR" ]]; then
        if [[ -f "$INSTALL_DIR/docker-compose.yml" && -f "$INSTALL_DIR/.env_sample" ]]; then
            log "Using existing BackupSheep installation at ${INSTALL_DIR}"
            return
        fi

        if [[ ! -d "$INSTALL_DIR" || -n "$(ls -A -- "$INSTALL_DIR")" ]]; then
            die "${INSTALL_DIR} already exists and is not a BackupSheep installation. Choose an empty --install-dir."
        fi
    fi

    log "Downloading BackupSheep (${BRANCH})"
    install -d "$(dirname "$INSTALL_DIR")"
    git clone --depth 1 --branch "$BRANCH" "$REPOSITORY_URL" "$INSTALL_DIR"
}

create_or_keep_env_file() {
    ENV_FILE="${INSTALL_DIR}/.env"
    if [[ -f "$ENV_FILE" ]]; then
        log "Keeping existing configuration at ${ENV_FILE}"
        ONBOARDING_TOKEN="$(read_env_value ONBOARDING_INSTALL_TOKEN)"
        return
    fi

    log "Creating a secure production configuration"
    umask 077
    cp "${INSTALL_DIR}/.env_sample" "$ENV_FILE"
    set_env_value DJANGO_SECRET_KEY "$(random_hex 48)"
    set_env_value DB_PASSWORD "$(random_hex 24)"
    set_env_value ONBOARDING_INSTALL_TOKEN "$(random_hex 32)"
    set_env_value DJANGO_ALLOWED_HOSTS "${PUBLIC_HOST},localhost,127.0.0.1"
    set_env_value APP_DOMAIN "$APP_DOMAIN"
    set_env_value APP_PROTOCOL "http://"
    set_env_value DJANGO_HTTPS "false"
    chmod 600 "$ENV_FILE"
    ONBOARDING_TOKEN="$(read_env_value ONBOARDING_INSTALL_TOKEN)"
}

warn_on_low_resources() {
    local available_kb=""
    if [[ -r /proc/meminfo ]]; then
        available_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
        if [[ -n "$available_kb" && "$available_kb" -lt 1572864 ]]; then
            warn "Less than 1.5 GiB of RAM is currently available. The stack may need more memory for large backups."
        fi
    fi
}

start_stack() {
    log "Validating the Docker Compose configuration"
    (
        cd "$INSTALL_DIR"
        docker compose config -q
    )

    log "Building and starting BackupSheep (the first build can take several minutes)"
    (
        cd "$INSTALL_DIR"
        docker compose up --build --detach --remove-orphans
    )
}

show_logs() {
    (
        cd "$INSTALL_DIR"
        docker compose logs --tail 100 app migrate || true
    )
}

wait_for_app() {
    local elapsed=0
    local container_id=""
    local status=""
    local migrate_container_id=""
    local migrate_status=""
    local migrate_exit_code=""

    log "Waiting for BackupSheep to become healthy"
    while [[ "$elapsed" -lt 300 ]]; do
        migrate_container_id="$(cd "$INSTALL_DIR" && docker compose ps --all -q migrate 2>/dev/null || true)"
        if [[ -n "$migrate_container_id" ]]; then
            migrate_status="$(docker inspect --format '{{.State.Status}}' "$migrate_container_id" 2>/dev/null || true)"
            migrate_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$migrate_container_id" 2>/dev/null || true)"
            if [[ "$migrate_status" == "exited" && "$migrate_exit_code" != "0" ]]; then
                show_logs
                die "Database migrations failed (exit code: ${migrate_exit_code})."
            fi
        fi

        container_id="$(cd "$INSTALL_DIR" && docker compose ps --all -q app 2>/dev/null || true)"
        if [[ -n "$container_id" ]]; then
            status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
            case "$status" in
                healthy)
                    return
                    ;;
                unhealthy|exited|dead)
                    show_logs
                    die "BackupSheep did not start successfully (app state: ${status})."
                    ;;
            esac
        fi
        sleep 3
        elapsed=$((elapsed + 3))
    done

    show_logs
    die "BackupSheep did not become healthy within five minutes."
}

print_next_steps() {
    local app_url="http://${APP_DOMAIN}"

    printf '\n'
    printf 'BackupSheep is running.\n\n'
    printf 'Open: %s/onboarding/\n' "$app_url"
    if [[ -n "$ONBOARDING_TOKEN" ]]; then
        printf 'Onboarding token: %s\n' "$ONBOARDING_TOKEN"
    else
        printf 'Onboarding token: docker compose -f %s/docker-compose.yml exec app cat /code/_storage/install_token\n' "$INSTALL_DIR"
    fi
    printf '\nInstallation directory: %s\n' "$INSTALL_DIR"
    printf 'View logs: cd %s && docker compose logs -f\n' "$INSTALL_DIR"
    printf '\nThe installer exposes plain HTTP on port %s. Open that port in your firewall if needed.\n' "$APP_PORT"
    printf 'Before exposing this instance publicly, configure a TLS reverse proxy and follow:\n'
    printf 'https://github.com/bilal414/backupsheep/blob/main/docs/deployment.md\n'
}

main() {
    parse_args "$@"
    require_root
    validate_install_dir
    load_os_release
    install_base_packages
    detect_public_host
    validate_public_host
    install_docker
    start_docker
    warn_on_low_resources
    clone_or_reuse_repository
    create_or_keep_env_file

    if [[ "$SKIP_START" == true ]]; then
        log "Host and configuration are ready; Compose was not started (--skip-start)."
        printf 'Start BackupSheep with: cd %s && docker compose up --build -d\n' "$INSTALL_DIR"
        return
    fi

    start_stack
    wait_for_app
    print_next_steps
}

main "$@"
