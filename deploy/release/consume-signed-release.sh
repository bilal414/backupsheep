#!/bin/bash
# Verify and materialize one BackupSheep signed release without host package installs.
set +x
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export LC_ALL=C
# A privileged direct invocation must never resolve shell utilities through an
# operator-supplied PATH. Docker itself is supplied as an absolute path and is
# independently canonicalized and attested below.
if (( EUID == 0 )); then
    export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
fi

readonly SOURCE_REPOSITORY="bilal414/backupsheep"
readonly RELEASE_WORKFLOW=".github/workflows/release-images.yml"
readonly OIDC_ISSUER="https://token.actions.githubusercontent.com"
readonly COSIGN_IMAGE="ghcr.io/bilal414/backupsheep-release-verifier@sha256:ba8edf9b99437ffc62650133972365eb381b39b46f208d33c82f8949b159cd5e"
readonly COSIGN_REPODIGEST="ghcr.io/bilal414/backupsheep-release-verifier@sha256:ba8edf9b99437ffc62650133972365eb381b39b46f208d33c82f8949b159cd5e"
readonly COSIGN_AMD64_IMAGE_ID="sha256:6feeb7c97d6b7b709f2dc6b33723de442205437694fd3679461d78635745349d"
readonly COSIGN_ARM64_IMAGE_ID="sha256:9a6ceeac0bc63631bd168417839d56e01a2ee157411daef235df13e0c8d04c01"
readonly COSIGN_RUNTIME_CONTRACT_VERSION="1"
readonly DESCRIPTOR_NAME="backupsheep-release-descriptor-v2.txt"
readonly BUNDLE_NAME="backupsheep-release-descriptor-v2.sigstore.json"
readonly CONSUMER_ASSET_NAME="backupsheep-consume-signed-release-v2.sh"
readonly CONSUMER_BUNDLE_NAME="backupsheep-consume-signed-release-v2.sigstore.json"
readonly MANIFEST_NAME="release-manifest.json"
readonly TRUSTED_ROOT_NAME="sigstore-trusted-root.json"
readonly VERIFICATION_RECEIPT_NAME="signature-verification.json"
readonly TRUSTED_ROOT_SHA256="6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"
readonly APP_REPOSITORY="ghcr.io/bilal414/backupsheep"
readonly POSTGRES_REPOSITORY="ghcr.io/bilal414/backupsheep-postgres"
readonly EGRESS_REPOSITORY="ghcr.io/bilal414/backupsheep-egress"
readonly RABBITMQ_REPOSITORY="ghcr.io/bilal414/backupsheep-rabbitmq"
readonly RABBITMQ_UPGRADE_REPOSITORY="ghcr.io/bilal414/backupsheep-rabbitmq-upgrade"
readonly COSIGN_AMD64_MANIFEST="sha256:29c25a1a2bcbe8190166f65e0914fbd4c904968be5a615f59421dc8fd4526f06"
readonly COSIGN_ARM64_MANIFEST="sha256:2d0bfa77e828bff3c198039763f05f44017e6c2cd75572fce8f61431a95b927d"

STAGING_DIR=""
VERIFIER_DIR=""
VERIFIER_NAME=""
ACTIVE_PID=""
ACTIVE_CAPTURE_FILE=""
BOUNDED_CAPTURE_VALUE=""
VERIFIER_CREATE_UNCERTAIN=false
RECOVERY_VERIFIER_DIR=""
DOCKER_BIN=""
CURL_BIN=""
GIT_BIN=""
SYNC_BIN=""
INSTALL_DIR=""
INSTALL_ANCESTOR_IDENTITY=""
RELEASE_TAG=""
SOURCE_COMMIT=""
INSTALLATION_PATH_DIGEST=""
WORKFLOW_IDENTITY=""
RUNTIME_JSON_PARSER=""
DAEMON_OS=""
DAEMON_ARCH=""
DAEMON_IDENTITY_SHA256=""
MUTATION_LOCK_DIR=""
MUTATION_LOCK_OWNER_FILE=""
MUTATION_LOCK_TOKEN=""
MUTATION_LOCK_HELD=false
MUTATION_LOCK_INHERITED=false
VERIFIED_DESCRIPTOR_SHA256=""
VERIFIED_BUNDLE_SHA256=""
VERIFIED_MANIFEST_SHA256=""
APP_IMAGE=""
POSTGRES_IMAGE=""
EGRESS_IMAGE=""
RABBITMQ_IMAGE=""
RABBITMQ_UPGRADE_IMAGE=""
RELEASE_EPOCH=""
MIGRATION_SET_SHA256=""
MIGRATION_LEAF_SET_SHA256=""
VERIFIER_MANIFEST_DIGEST=""
declare -a DOCKER_ENV=()

die() { printf 'Signed release refused: %s\n' "$*" >&2; exit 1; }
file_uid() { stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"; }
file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
file_links() { stat -c '%h' "$1" 2>/dev/null || stat -f '%l' "$1"; }
file_size() { stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1"; }
file_inode() { stat -c '%i' "$1" 2>/dev/null || stat -f '%i' "$1"; }
file_identity() { stat -c '%d:%i:%s:%h:%u:%a' "$1" 2>/dev/null || stat -f '%d:%i:%z:%l:%u:%Lp' "$1"; }
directory_identity() { stat -c '%d:%i:%u:%a' "$1" 2>/dev/null || stat -f '%d:%i:%u:%Lp' "$1"; }

validate_installation_ancestor_chain() {
    local current="$1" parent="" owner="" mode=""
    while :; do
        [[ -d "$current" && ! -L "$current" ]] \
            || die "installation path ancestor is not a real directory: ${current}"
        owner="$(file_uid "$current")"; mode="$(file_mode "$current")"
        [[ "$owner" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{3,4}$ ]] \
            || die "could not attest installation path ancestor: ${current}"
        if (( EUID == 0 )); then
            (( 10#$owner == 0 )) \
                || die "a root release consumer requires every installation ancestor to be root-owned: ${current}"
        else
            (( 10#$owner == EUID || 10#$owner == 0 )) \
                || die "installation path ancestor is owned by an unrelated account: ${current}"
        fi
        if (( (8#$mode & 8#022) != 0 )); then
            (( 10#$owner == 0 && (8#$mode & 8#1000) != 0 )) \
                || die "installation path ancestor is attacker-writable without a root-owned sticky boundary: ${current}"
        fi
        [[ "$current" == / ]] && break
        parent="$(dirname -- "$current")"
        [[ "$parent" != "$current" ]] || die "could not walk installation path ancestors"
        current="$parent"
    done
}

installation_ancestor_snapshot() {
    local current="$1" parent="" identity=""
    while :; do
        [[ -d "$current" && ! -L "$current" ]] || return 1
        identity="$(directory_identity "$current")" || return 1
        [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ ]] || return 1
        printf '%s|%s\n' "$current" "$identity"
        [[ "$current" == / ]] && break
        parent="$(dirname -- "$current")"
        [[ "$parent" != "$current" ]] || return 1
        current="$parent"
    done
}

assert_installation_ancestor_identity() {
    local current=""
    [[ -n "$INSTALL_ANCESTOR_IDENTITY" ]] || return 0
    current="$(installation_ancestor_snapshot "$INSTALL_DIR")" \
        || die "could not re-attest installation path ancestors"
    [[ "$current" == "$INSTALL_ANCESTOR_IDENTITY" ]] \
        || die "installation path ancestor identity or permissions changed"
}

validate_mutation_lock() {
    local expected_token="$1" actual="" size="" expected_size=0
    [[ -d "$MUTATION_LOCK_DIR" && ! -L "$MUTATION_LOCK_DIR"
        && "$(file_uid "$MUTATION_LOCK_DIR")" == "$EUID"
        && "$(file_mode "$MUTATION_LOCK_DIR")" == "700"
        && -f "$MUTATION_LOCK_OWNER_FILE" && ! -L "$MUTATION_LOCK_OWNER_FILE"
        && "$(file_uid "$MUTATION_LOCK_OWNER_FILE")" == "$EUID"
        && "$(file_mode "$MUTATION_LOCK_OWNER_FILE")" == "600"
        && "$(file_links "$MUTATION_LOCK_OWNER_FILE")" == "1" ]] || return 1
    size="$(file_size "$MUTATION_LOCK_OWNER_FILE")"
    expected_size=$((${#expected_token} + 1))
    [[ "$size" =~ ^[1-9][0-9]*$ && "$size" -eq "$expected_size" && "$size" -le 256 ]] || return 1
    actual="$(<"$MUTATION_LOCK_OWNER_FILE")"
    [[ "$actual" == "$expected_token" ]] || return 1
    [[ "$(find "$MUTATION_LOCK_DIR" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')" == "1" ]] || return 1
}

assert_mutation_lock_ownership() {
    [[ "$MUTATION_LOCK_HELD" == true || "$MUTATION_LOCK_INHERITED" == true ]] \
        || die "signed release mutation lock is not held"
    validate_mutation_lock "$MUTATION_LOCK_TOKEN" \
        || die "signed release mutation-lock ownership changed"
    assert_installation_ancestor_identity
}

acquire_or_inherit_mutation_lock() {
    local inherited="version=1;tool=install.sh;pid=${PPID};uid=${EUID}"
    MUTATION_LOCK_DIR="${INSTALL_DIR}.backupsheep-mutation-lock"
    MUTATION_LOCK_OWNER_FILE="${MUTATION_LOCK_DIR}/owner"
    if [[ -e "$MUTATION_LOCK_DIR" || -L "$MUTATION_LOCK_DIR" ]]; then
        MUTATION_LOCK_TOKEN="$inherited"
        validate_mutation_lock "$MUTATION_LOCK_TOKEN" \
            || die "another mutation is active, or a stale fail-closed mutation lock remains"
        MUTATION_LOCK_INHERITED=true
        return 0
    fi
    mkdir -- "$MUTATION_LOCK_DIR" 2>/dev/null \
        || die "another mutation is active, or a stale fail-closed mutation lock remains"
    MUTATION_LOCK_HELD=true
    MUTATION_LOCK_TOKEN="version=1;tool=consume-signed-release.sh;pid=$$;uid=${EUID}"
    chmod 0700 "$MUTATION_LOCK_DIR" \
        || die "could not protect signed release mutation lock"
    if ! printf '%s\n' "$MUTATION_LOCK_TOKEN" > "$MUTATION_LOCK_OWNER_FILE" \
        || ! chmod 0600 "$MUTATION_LOCK_OWNER_FILE"; then
        die "could not publish signed release mutation-lock ownership witness"
    fi
    validate_mutation_lock "$MUTATION_LOCK_TOKEN" \
        || die "signed release mutation-lock ownership witness failed validation"
}

release_mutation_lock() {
    local failed=false
    [[ "$MUTATION_LOCK_HELD" == true ]] || return 0
    if ! validate_mutation_lock "$MUTATION_LOCK_TOKEN"; then
        failed=true
    elif ! rm -f -- "$MUTATION_LOCK_OWNER_FILE" || ! rmdir -- "$MUTATION_LOCK_DIR"; then
        failed=true
    fi
    MUTATION_LOCK_HELD=false
    if [[ "$failed" == true ]]; then
        printf 'Signed release warning: refusing to release an unattested mutation lock at %s\n' "$MUTATION_LOCK_DIR" >&2
        return 1
    fi
}

validate_privileged_directory() {
    local label="$1" path="$2" mode=""
    [[ "$path" == /* && -d "$path" && ! -L "$path" && "$(file_uid "$path")" == "0" ]] \
        || die "privileged ${label} must be an absolute root-owned, non-symlink directory"
    mode="$(file_mode "$path")"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#022) == 0 )) \
        || die "privileged ${label} must not be writable by group or other users"
}

validate_privileged_file() {
    local label="$1" path="$2" mode=""
    [[ "$path" == /* && -f "$path" && ! -L "$path" && "$(file_uid "$path")" == "0" \
        && "$(file_links "$path")" == "1" ]] \
        || die "privileged ${label} must be an absolute root-owned regular file without links"
    mode="$(file_mode "$path")"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#022) == 0 )) \
        || die "privileged ${label} must not be writable by group or other users"
}

validate_privileged_consumer_environment() {
    local path="" name=""
    (( EUID == 0 )) || return 0
    validate_privileged_directory HOME "${HOME-}"
    if [[ -n "${DOCKER_CONFIG-}" ]]; then
        validate_privileged_directory DOCKER_CONFIG "$DOCKER_CONFIG"
    fi
    if [[ -n "${DOCKER_CERT_PATH-}" ]]; then
        validate_privileged_directory DOCKER_CERT_PATH "$DOCKER_CERT_PATH"
        for name in ca.pem cert.pem key.pem; do
            path="${DOCKER_CERT_PATH}/${name}"
            [[ ! -e "$path" && ! -L "$path" ]] || validate_privileged_file "DOCKER_CERT_PATH/${name}" "$path"
        done
    fi
    if [[ -n "${SSL_CERT_DIR-}" ]]; then
        validate_privileged_directory SSL_CERT_DIR "$SSL_CERT_DIR"
    fi
    if [[ -n "${SSL_CERT_FILE-}" ]]; then
        validate_privileged_file SSL_CERT_FILE "$SSL_CERT_FILE"
    fi
}

validate_privileged_executable() {
    local label="$1" path="$2" canonical="" parent=""
    (( EUID == 0 )) || { printf '%s' "$path"; return 0; }
    canonical="$(realpath -- "$path")" || die "could not canonicalize privileged ${label} executable"
    validate_privileged_file "${label} executable" "$canonical"
    parent="$(dirname -- "$canonical")"
    validate_privileged_directory "${label} executable parent" "$parent"
    [[ -x "$canonical" ]] || die "privileged ${label} executable is not executable"
    printf '%s' "$canonical"
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 -r "$1" | awk '{print $1}'
    else
        die "sha256sum, shasum, or openssl is required"
    fi
}

sha256_text() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        printf '%s' "$1" | openssl dgst -sha256 -r | awk '{print $1}'
    else
        die "sha256sum, shasum, or openssl is required"
    fi
}

validate_regular_file() {
    local path="$1" maximum="$2" size=""
    [[ -f "$path" && ! -L "$path" ]] || die "$(basename -- "$path") is not a regular file"
    size="$(file_size "$path")"
    [[ "$size" =~ ^[0-9]+$ ]] || die "could not bound $(basename -- "$path")"
    (( 10#$size > 0 && 10#$size <= maximum )) || die "$(basename -- "$path") has an invalid size"
    [[ "$(file_uid "$path")" == "$EUID" && "$(file_links "$path")" == "1" ]] || die "$(basename -- "$path") has an unsafe owner or link count"
    case "$(file_mode "$path")" in 600|400|444) ;; *) die "$(basename -- "$path") has unsafe permissions" ;; esac
}

validate_trusted_root() {
    local path="$1" size="" mode=""
    [[ -f "$path" && ! -L "$path" ]] || die "checked-in Sigstore trusted root is not a regular file"
    size="$(file_size "$path")"; mode="$(file_mode "$path")"
    [[ "$size" =~ ^[0-9]+$ ]] && (( 10#$size > 0 && 10#$size <= 65536 )) || die "checked-in Sigstore trusted root has an invalid size"
    [[ "$(file_uid "$path")" == "$EUID" && "$(file_links "$path")" == "1" ]] || die "checked-in Sigstore trusted root has an unsafe owner or link count"
    case "$mode" in 644|600|444|400) ;; *) die "checked-in Sigstore trusted root has unsafe permissions" ;; esac
    [[ "$(sha256_file "$path")" == "$TRUSTED_ROOT_SHA256" ]] || die "checked-in Sigstore trusted root digest mismatch"
}

copy_trusted_root() {
    local source="$1" destination="$2" before="" opened=""
    validate_trusted_root "$source"
    before="$(file_inode "$source"):$(file_size "$source"):$(file_uid "$source"):$(file_links "$source")"
    exec 9< "$source" || die "could not open checked-in Sigstore trusted root"
    opened="$(file_inode /dev/fd/9):$(file_size /dev/fd/9):$(file_uid /dev/fd/9):$(file_links /dev/fd/9)"
    [[ "$opened" == "$before" && ! -L "$source" ]] || { exec 9<&-; die "checked-in Sigstore trusted root changed while opening"; }
    install -m 0444 /dev/fd/9 "$destination" || { exec 9<&-; die "could not copy checked-in Sigstore trusted root"; }
    exec 9<&-
    [[ ! -L "$source" && "$(file_inode "$source"):$(file_size "$source"):$(file_uid "$source"):$(file_links "$source")" == "$before" ]] \
        || die "checked-in Sigstore trusted root changed while copying"
    validate_trusted_root "$destination"
}

docker_client() {
    local status=0
    assert_installation_ancestor_identity
    if "${DOCKER_ENV[@]}" "$DOCKER_BIN" "$@"; then status=0; else status=$?; fi
    assert_installation_ancestor_identity
    return "$status"
}

attest_docker_daemon_platform() {
    local platform="" daemon_id=""
    run_bounded_capture 30 "Docker daemon platform attestation" docker_client \
        version --format '{{.Server.Os}}|{{.Server.Arch}}' \
        || die "could not attest Docker daemon platform"
    platform="$BOUNDED_CAPTURE_VALUE"
    case "$platform" in
        linux\|amd64|linux\|arm64) ;;
        *) die "signed releases require a scanned linux/amd64 or linux/arm64 Docker daemon" ;;
    esac
    DAEMON_OS="${platform%%|*}"
    DAEMON_ARCH="${platform#*|}"
    run_bounded_capture 30 "Docker daemon identity attestation" docker_client \
        info --format '{{.ID}}' \
        || die "could not attest Docker daemon identity"
    daemon_id="$BOUNDED_CAPTURE_VALUE"
    [[ -n "$daemon_id" && ${#daemon_id} -le 256 \
        && "$daemon_id" =~ ^[A-Za-z0-9:._-]+$ ]] \
        || die "Docker daemon identity is not canonical"
    DAEMON_IDENTITY_SHA256="sha256:$(sha256_text "BackupSheep/docker-daemon/v1|${daemon_id}|${DAEMON_OS}|${DAEMON_ARCH}")"
}

attest_local_image_platform() {
    local role="$1" reference="$2" state="" image_os="" image_arch="" image_id=""
    [[ "$DAEMON_OS" == linux && ( "$DAEMON_ARCH" == amd64 || "$DAEMON_ARCH" == arm64 ) ]] \
        || die "Docker daemon platform was not attested before ${role} image use"
    state="$(docker_client image inspect --format '{{.Os}}|{{.Architecture}}|{{.Id}}' "$reference")" \
        || die "could not inspect ${role} image platform"
    IFS='|' read -r image_os image_arch image_id <<< "$state"
    [[ "$image_os" == "$DAEMON_OS" && "$image_arch" == "$DAEMON_ARCH"
        && "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || die "${role} image platform or configuration digest does not match the Docker daemon"
}

git_client() {
    /usr/bin/env -i LC_ALL=C LANG=C HOME=/ PATH=/usr/local/bin:/usr/bin:/bin \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
        GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false GIT_ALLOW_PROTOCOL=https \
        "$GIT_BIN" -c core.hooksPath=/dev/null -c init.templateDir=/dev/null \
        -c http.sslVerify=true -c core.fsmonitor=false -c core.untrackedCache=false \
        -c diff.external= "$@"
}

validate_checkout_control_file() {
    local relative="$1" path="$INSTALL_DIR/$1" mode="" before=""
    [[ -f "$path" && ! -L "$path" && "$(file_uid "$path")" == "$EUID" && "$(file_links "$path")" == "1" ]] \
        || die "release control file has an unsafe identity: ${relative}"
    mode="$(file_mode "$path")"; [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die "could not validate release control file permissions"
    (( (8#$mode & 8#022) == 0 )) || die "release control file is group- or world-writable: ${relative}"
    before="$(file_identity "$path")"
    git_client -C "$INSTALL_DIR" show "${SOURCE_COMMIT}:${relative}" | cmp -s - "$path" \
        || die "release control file does not byte-match source commit: ${relative}"
    [[ ! -L "$path" && "$(file_identity "$path")" == "$before" ]] \
        || die "release control file changed during source attestation: ${relative}"
}

validate_source_checkout() {
    local top="" git_dir="" head="" origins="" relative=""
    [[ -d "$INSTALL_DIR/.git" && ! -L "$INSTALL_DIR/.git" ]] || die "release consumer requires an installer-managed Git checkout"
    top="$(git_client -C "$INSTALL_DIR" rev-parse --show-toplevel)" || die "could not resolve release checkout"
    git_dir="$(git_client -C "$INSTALL_DIR" rev-parse --absolute-git-dir)" || die "could not resolve release Git directory"
    [[ "$top" == "$INSTALL_DIR" && "$git_dir" == "$INSTALL_DIR/.git" ]] || die "release checkout escapes the installation directory"
    head="$(git_client -C "$INSTALL_DIR" rev-parse --verify 'HEAD^{commit}')" || die "could not resolve release checkout HEAD"
    [[ "$head" == "$SOURCE_COMMIT" ]] || die "release checkout HEAD does not match requested source commit"
    origins="$(git_client -C "$INSTALL_DIR" remote get-url --all origin)" || die "could not attest release checkout origin"
    [[ "$origins" == "https://github.com/${SOURCE_REPOSITORY}.git" ]] || die "release checkout origin is not official"
    git_client -C "$INSTALL_DIR" fsck --strict --no-dangling >/dev/null || die "release checkout object verification failed"
    git_client -C "$INSTALL_DIR" diff --no-ext-diff --no-textconv --quiet -- || die "release checkout has modified tracked files"
    git_client -C "$INSTALL_DIR" diff --cached --no-ext-diff --no-textconv --quiet -- || die "release checkout has staged changes"
    for relative in deploy/release/consume-signed-release.sh deploy/release/sigstore-trusted-root.json deploy/release-policy.json deploy/release/signed-release.compose.yml deploy/runtime/compose-json.awk scripts/release_transition.py scripts/signed_release_upgrade.py; do
        validate_checkout_control_file "$relative"
    done
}

strict_json_array_records() {
    local value="$1"
    [[ -n "$RUNTIME_JSON_PARSER" ]] || die "reviewed runtime JSON parser path is not initialized"
    printf '%s\n' "$value" | LC_ALL=C awk -v mode=array -f "$RUNTIME_JSON_PARSER"
}

strict_json_object_records() {
    local value="$1"
    printf '%s\n' "$value" | LC_ALL=C awk -v mode=object -f "$RUNTIME_JSON_PARSER"
}

strict_json_object_keys() {
    local value="$1"
    printf '%s\n' "$value" | LC_ALL=C awk -v mode=keys -f "$RUNTIME_JSON_PARSER"
}

strict_json_path() {
    local document="$1" component="" index=0
    local -a parser_arguments=(-v mode=path)
    shift
    (( $# >= 1 && $# <= 8 )) || die "reviewed JSON path has an invalid component count"
    parser_arguments+=(-v "path_count=$#")
    for component in "$@"; do
        index=$((index + 1))
        parser_arguments+=(-v "path${index}=${component}")
    done
    printf '%s\n' "$document" | LC_ALL=C awk "${parser_arguments[@]}" -f "$RUNTIME_JSON_PARSER"
}

strict_json_optional_path() {
    local document="$1" component="" index=0
    local -a parser_arguments=(-v mode=path -v allow_absent=1)
    shift
    (( $# >= 1 && $# <= 8 )) || die "reviewed optional JSON path has an invalid component count"
    parser_arguments+=(-v "path_count=$#")
    for component in "$@"; do
        index=$((index + 1))
        parser_arguments+=(-v "path${index}=${component}")
    done
    printf '%s\n' "$document" | LC_ALL=C awk "${parser_arguments[@]}" -f "$RUNTIME_JSON_PARSER"
}

strict_json_count() {
    local document="$1" component="" index=0
    local -a parser_arguments=(-v mode=count)
    shift
    (( $# <= 8 )) || die "reviewed JSON count path has an invalid component count"
    parser_arguments+=(-v "path_count=$#")
    for component in "$@"; do
        index=$((index + 1))
        parser_arguments+=(-v "path${index}=${component}")
    done
    printf '%s\n' "$document" | LC_ALL=C awk "${parser_arguments[@]}" -f "$RUNTIME_JSON_PARSER"
}

verifier_snapshot_value() {
    strict_json_path "$verifier_snapshot_json" '#0' "$@"
}

verifier_snapshot_optional_value() {
    strict_json_optional_path "$verifier_snapshot_json" '#0' "$@"
}

verifier_snapshot_count() {
    strict_json_count "$verifier_snapshot_json" '#0' "$@"
}

run_bounded() {
    local limit="$1" label="$2" status=0 elapsed=0 grace=0 job_pgid="" shell_pgid="" job_state=""
    shift 2
    # Monitor mode gives this background job a dedicated process group on both
    # GNU/Linux and macOS Bash. Track and terminate the whole group so an env,
    # Docker credential helper, curl child, or test descendant cannot outlive it.
    set -m
    "$@" &
    ACTIVE_PID=$!
    set +m
    job_pgid="$(ps -o pgid= -p "$ACTIVE_PID" 2>/dev/null | tr -d '[:space:]' || true)"
    shell_pgid="$(ps -o pgid= -p "$$" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ ! "$job_pgid" =~ ^[1-9][0-9]*$ || "$job_pgid" != "$ACTIVE_PID" || "$job_pgid" == "$shell_pgid" ]]; then
        job_state="$(ps -o stat= -p "$ACTIVE_PID" 2>/dev/null | tr -d '[:space:]' || true)"
        if ! kill -0 "$ACTIVE_PID" 2>/dev/null || [[ -z "$job_state" || "$job_state" == Z* ]]; then
            if wait "$ACTIVE_PID"; then status=0; else status=$?; fi
            ACTIVE_PID=""
            return "$status"
        fi
        kill -TERM "$ACTIVE_PID" 2>/dev/null || true
        wait "$ACTIVE_PID" 2>/dev/null || true
        ACTIVE_PID=""
        printf 'Signed release refused: could not isolate %s in a dedicated process group\n' "$label" >&2
        return 125
    fi
    while kill -0 -- "-$ACTIVE_PID" 2>/dev/null; do
        if (( elapsed >= limit )); then
            kill -TERM -- "-$ACTIVE_PID" 2>/dev/null || true
            grace=0
            while kill -0 -- "-$ACTIVE_PID" 2>/dev/null && (( grace < 5 )); do sleep 1; grace=$((grace + 1)); done
            kill -KILL -- "-$ACTIVE_PID" 2>/dev/null || true
            wait "$ACTIVE_PID" 2>/dev/null || true
            ACTIVE_PID=""
            printf 'Signed release refused: %s exceeded %s seconds\n' "$label" "$limit" >&2
            return 124
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    if wait "$ACTIVE_PID"; then status=0; else status=$?; fi
    ACTIVE_PID=""
    return "$status"
}

run_bounded_capture() {
    local limit="$1" label="$2" status=0 attempt=0 capture=""
    shift 2
    BOUNDED_CAPTURE_VALUE=""
    while (( attempt < 8 )); do
        attempt=$((attempt + 1))
        capture="${INSTALL_DIR}/.release-command-output.$$.$RANDOM.${attempt}"
        if (umask 077; set -o noclobber; : > "$capture") 2>/dev/null; then
            break
        fi
        capture=""
    done
    [[ -n "$capture" && -f "$capture" && ! -L "$capture" \
        && "$(file_uid "$capture")" == "$EUID" \
        && "$(file_mode "$capture")" == "600" \
        && "$(file_links "$capture")" == "1" ]] \
        || die "could not create protected output capture for ${label}"
    ACTIVE_CAPTURE_FILE="$capture"
    run_bounded "$limit" "$label" "$@" > "$capture" || status=$?
    if [[ "$status" -eq 0 ]]; then
        [[ -f "$capture" && ! -L "$capture" \
            && "$(file_uid "$capture")" == "$EUID" \
            && "$(file_mode "$capture")" == "600" \
            && "$(file_links "$capture")" == "1" \
            && "$(file_size "$capture")" =~ ^[0-9]+$ \
            && "$(file_size "$capture")" -le 1048576 ]] \
            || die "protected output capture changed during ${label}"
        BOUNDED_CAPTURE_VALUE="$(<"$capture")"
    fi
    rm -f -- "$capture" || die "could not remove protected output capture for ${label}"
    ACTIVE_CAPTURE_FILE=""
    return "$status"
}

download_asset() {
    local tag="$1" name="$2" output="$3" maximum="$4"
    local url="https://github.com/${SOURCE_REPOSITORY}/releases/download/${tag}/${name}"
    # --disable is first, and the empty environment prevents ambient curlrc,
    # proxy, netrc, TLS-debug, and CURL_HOME configuration from weakening TLS.
    assert_installation_ancestor_identity
    run_bounded 310 "release asset download" /usr/bin/env -i LC_ALL=C HOME="$STAGING_DIR" PATH=/usr/bin:/bin \
        "$CURL_BIN" --disable --fail --show-error --silent --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --max-redirs 3 --connect-timeout 15 --max-time 300 \
        --max-filesize "$maximum" --output "$output" "$url" \
        || die "could not download immutable release asset ${name}"
    assert_installation_ancestor_identity
    validate_regular_file "$output" "$maximum"
}

descriptor_value() {
    local path="$1" key="$2" value="" count=""
    count="$(awk -v wanted="${key}=" 'index($0, wanted) == 1 { count++ } END { print count + 0 }' "$path")"
    [[ "$count" == "1" ]] || die "descriptor key ${key} is absent or duplicated"
    value="$(awk -v wanted="${key}=" 'index($0, wanted) == 1 { print substr($0, length(wanted) + 1) }' "$path")"
    [[ -n "$value" && "$value" != *$'\n'* ]] || die "descriptor key ${key} is malformed"
    printf '%s' "$value"
}

validate_descriptor() {
    local path="$1" expected_tag="$2" expected_commit="$3" manifest_path="$4"
    local before_descriptor="" before_manifest="" manifest_digest=""
    local app_ref="" postgres_ref="" egress_ref="" rabbitmq_ref="" rabbitmq_upgrade_ref=""
    local -a lines=()
    validate_regular_file "$path" 2048
    validate_regular_file "$manifest_path" 1048576
    before_descriptor="$(file_identity "$path")"; before_manifest="$(file_identity "$manifest_path")"
    od -An -v -t u1 "$path" | awk '
        { for (i = 1; i <= NF; i++) { byte = $i + 0; count++; last = byte; if (byte != 10 && (byte < 32 || byte > 126)) exit 2 }}
        END { if (count < 1 || count > 2048 || last != 10) exit 3 }
    ' || die "descriptor is not canonical bounded ASCII with a final LF"
    while IFS= read -r descriptor_line; do lines[${#lines[@]}]="$descriptor_line"; done < "$path"
    [[ "${#lines[@]}" -eq 16 ]] || die "descriptor must contain exactly sixteen ordered lines"
    [[ "${lines[0]}" == "BACKUPSHEEP-SIGNED-RELEASE-V2" ]] || die "descriptor magic is invalid or downgraded"
    [[ "${lines[1]}" == "release_tag=${expected_tag}" ]] || die "descriptor release tag mismatch"
    [[ "${lines[2]}" == "source_commit=${expected_commit}" ]] || die "descriptor source commit mismatch"
    [[ "${lines[3]}" =~ ^release_manifest_sha256=sha256:[0-9a-f]{64}$ ]] || die "descriptor manifest digest is malformed"
    [[ "${lines[4]}" =~ ^app_image=${APP_REPOSITORY}@sha256:[0-9a-f]{64}$ ]] || die "descriptor application reference is not official"
    [[ "${lines[5]}" =~ ^postgres_image=${POSTGRES_REPOSITORY}@sha256:[0-9a-f]{64}$ ]] || die "descriptor PostgreSQL reference is not official"
    [[ "${lines[6]}" =~ ^egress_image=${EGRESS_REPOSITORY}@sha256:[0-9a-f]{64}$ ]] || die "descriptor egress reference is not official"
    [[ "${lines[7]}" =~ ^rabbitmq_image=${RABBITMQ_REPOSITORY}@sha256:[0-9a-f]{64}$ ]] || die "descriptor RabbitMQ reference is not official"
    [[ "${lines[8]}" =~ ^rabbitmq_upgrade_image=${RABBITMQ_UPGRADE_REPOSITORY}@sha256:[0-9a-f]{64}$ ]] || die "descriptor RabbitMQ upgrade reference is not official"
    # The signed descriptor may assert the independently distributed verifier
    # trust seed, but it can never select or rotate the verifier that authenticates
    # this descriptor. Every value must byte-match the compiled bootstrap policy.
    [[ "${lines[9]}" == "release_verifier_image=${COSIGN_IMAGE}" \
        && "${lines[10]}" == "release_verifier_runtime_contract_version=${COSIGN_RUNTIME_CONTRACT_VERSION}" \
        && "${lines[11]}" == "release_verifier_linux_amd64_manifest=${COSIGN_AMD64_MANIFEST}" \
        && "${lines[12]}" == "release_verifier_linux_amd64_config=${COSIGN_AMD64_IMAGE_ID}" \
        && "${lines[13]}" == "release_verifier_linux_arm64_manifest=${COSIGN_ARM64_MANIFEST}" \
        && "${lines[14]}" == "release_verifier_linux_arm64_config=${COSIGN_ARM64_IMAGE_ID}" \
        && "${lines[15]}" == "trusted_root_sha256=sha256:${TRUSTED_ROOT_SHA256}" ]] \
        || die "descriptor verifier or trusted-root assertion does not match the independent bootstrap policy"
    manifest_digest="${lines[3]#release_manifest_sha256=sha256:}"
    [[ "$(sha256_file "$manifest_path")" == "$manifest_digest" ]] || die "release manifest does not match the signed descriptor"
    app_ref="${lines[4]#app_image=}"; postgres_ref="${lines[5]#postgres_image=}"; egress_ref="${lines[6]#egress_image=}"
    rabbitmq_ref="${lines[7]#rabbitmq_image=}"; rabbitmq_upgrade_ref="${lines[8]#rabbitmq_upgrade_image=}"
    [[ "$(printf '%s\n' "$app_ref" "$postgres_ref" "$egress_ref" "$rabbitmq_ref" "$rabbitmq_upgrade_ref" | LC_ALL=C sort -u | wc -l | tr -d '[:space:]')" == 5 ]] \
        || die "descriptor release image references collide"
    [[ "$(file_identity "$path")" == "$before_descriptor" && "$(file_identity "$manifest_path")" == "$before_manifest" ]] || die "release input changed while it was parsed"
}

json_string_scalar() {
    local value="$1" pattern="$2" label="$3"
    [[ "$value" =~ ^\"([^\"\\]*)\"$ ]] \
        || die "${label} is not a canonical unescaped JSON string"
    value="${BASH_REMATCH[1]}"
    [[ "$value" =~ $pattern ]] || die "${label} is malformed"
    printf '%s' "$value"
}

validate_signed_transition_metadata() {
    local path="$1" document="" keys="" transition="" migration="" value=""
    validate_regular_file "$path" 1048576
    document="$(<"$path")"
    keys="$(strict_json_object_keys "$document" | LC_ALL=C sort)" \
        || die "release manifest top-level keys are not strict JSON"
    [[ "$keys" == $'"consumer"\n"images"\n"release"\n"schema_version"\n"transition"\n"vulnerability_database"' ]] \
        || die "release manifest top-level contract is not exact schema 4"
    [[ "$(strict_json_path "$document" schema_version)" == 4 ]] \
        || die "release manifest schema is not 4"
    transition="$(strict_json_path "$document" transition)" \
        || die "release manifest transition record is absent"
    keys="$(strict_json_object_keys "$transition" | LC_ALL=C sort)" \
        || die "release transition keys are malformed"
    [[ "$keys" == $'"accepted_predecessors"\n"migration_contract"\n"release_epoch"\n"reviewed_policy"\n"schema_version"' ]] \
        || die "release transition contract has unexpected keys"
    [[ "$(strict_json_path "$transition" schema_version)" == 1 ]] \
        || die "release transition schema is unsupported"
    RELEASE_EPOCH="$(strict_json_path "$transition" release_epoch)" \
        || die "release epoch is absent"
    [[ "$RELEASE_EPOCH" =~ ^[1-9][0-9]{0,9}$ ]] \
        && (( 10#$RELEASE_EPOCH <= 2147483647 )) \
        || die "release epoch is not a positive bounded integer"
    migration="$(strict_json_path "$transition" migration_contract)" \
        || die "release migration contract is absent"
    keys="$(strict_json_object_keys "$migration" | LC_ALL=C sort)" \
        || die "release migration-contract keys are malformed"
    [[ "$keys" == $'"all_migrations_atomic"\n"file"\n"leaf_set_sha256"\n"leaves"\n"migration_set_sha256"\n"migrations"\n"schema_version"\n"sha256"' ]] \
        || die "release migration contract has unexpected keys"
    [[ "$(strict_json_path "$migration" schema_version)" == 1 \
        && "$(strict_json_path "$migration" all_migrations_atomic)" == true ]] \
        || die "release migrations are not the supported all-transactional contract"
    value="$(strict_json_path "$migration" migration_set_sha256)" \
        || die "release migration-set digest is absent"
    MIGRATION_SET_SHA256="$(json_string_scalar "$value" '^sha256:[0-9a-f]{64}$' 'release migration-set digest')"
    value="$(strict_json_path "$migration" leaf_set_sha256)" \
        || die "release migration leaf-set digest is absent"
    MIGRATION_LEAF_SET_SHA256="$(json_string_scalar "$value" '^sha256:[0-9a-f]{64}$' 'release migration leaf-set digest')"
    if [[ "$DAEMON_ARCH" == amd64 ]]; then
        VERIFIER_MANIFEST_DIGEST="$COSIGN_AMD64_MANIFEST"
    elif [[ "$DAEMON_ARCH" == arm64 ]]; then
        VERIFIER_MANIFEST_DIGEST="$COSIGN_ARM64_MANIFEST"
    else
        die "release transition metadata requires an attested daemon architecture"
    fi
}

validate_residue_dir() {
    local path="$1" entry="" base="" count=0 mode="" size="" expected_mode="700" maximum_entries=7
    base="$(basename -- "$path")"
    [[ "$base" =~ ^\.release-evidence\.(download|verify)\.[A-Za-z0-9]{8}$ ]] || die "release residue has a noncanonical name"
    if [[ "$base" == .release-evidence.verify.* ]]; then
        expected_mode="755"
        maximum_entries=5
    fi
    # Directory link counts are filesystem-specific (for example APFS counts
    # child entries).  Exact one-level enumeration and per-entry type/link
    # validation below provide the portable no-symlink/cardinality boundary.
    [[ -d "$path" && ! -L "$path" && "$(file_uid "$path")" == "$EUID" && "$(file_mode "$path")" == "$expected_mode" ]] || die "release residue has an unsafe identity: ${base}"
    while IFS= read -r -d '' entry; do
        count=$((count + 1)); (( count <= maximum_entries )) || die "release residue contains too many entries"
        base="$(basename -- "$entry")"
        case "$base" in "$DESCRIPTOR_NAME"|"$BUNDLE_NAME"|"$MANIFEST_NAME"|"$TRUSTED_ROOT_NAME"|"$VERIFICATION_RECEIPT_NAME"|"$VERIFICATION_RECEIPT_NAME.new"|local-images.txt|.verifier-container-id) ;; *) die "release residue contains an unexpected entry: ${base}" ;; esac
        [[ -f "$entry" && ! -L "$entry" && "$(file_uid "$entry")" == "$EUID" && "$(file_links "$entry")" == "1" ]] || die "release residue entry has an unsafe identity: ${base}"
        mode="$(file_mode "$entry")"; [[ "$mode" == "600" || "$mode" == "444" || "$mode" == "400" ]] || die "release residue entry has unsafe permissions: ${base}"
        size="$(file_size "$entry")"; [[ "$size" =~ ^[0-9]+$ ]] && (( 10#$size <= 1048576 )) || die "release residue entry is too large: ${base}"
        if [[ "$base" == .verifier-container-id ]]; then
            [[ "$expected_mode" == 755 && "$mode" == 600 && "$size" -le 65 ]] \
                || die "verifier container-ID capture has an unsafe location, mode, or size"
            od -An -v -t u1 "$entry" | awk '
                { for (i = 1; i <= NF; i++) { count++; byte = $i + 0; if (byte == 10) { if (newline++) exit 2; seen_newline = 1; next } if (seen_newline || !((byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102))) exit 3 } }
                END { if (count > 65) exit 4 }
            ' || die "verifier container-ID capture contains unsafe bytes"
        fi
    done < <(find "$path" -mindepth 1 -maxdepth 1 -print0)
}

remove_residue_dir() {
    local path="$1" mount_status=0 entry=""
    validate_residue_dir "$path"
    containers_mounting_path "$path" || mount_status=$?
    [[ "$mount_status" -eq 0 ]] || { [[ "$mount_status" -eq 10 ]] && die "release residue is still mounted by a Docker container"; die "could not check release residue mount ownership"; }
    while IFS= read -r -d '' entry; do rm -f -- "$entry"; done < <(find "$path" -mindepth 1 -maxdepth 1 -type f -print0)
    rmdir -- "$path" || die "could not remove validated release residue"
}

scan_containers_mounting_path() {
    local wanted="$1" listing="" container_id="" mounts="" count=0 mount_count=0 mount_source=""
    listing="$(docker_client ps --all --quiet)" || return 1
    while IFS= read -r container_id; do
        [[ -n "$container_id" ]] || continue
        count=$((count + 1)); (( count <= 512 )) || return 1
        [[ "$container_id" =~ ^[0-9a-f]{12,64}$ ]] || return 1
        mounts="$(docker_client inspect --format '{{range .Mounts}}{{if eq .Type "bind"}}{{println .Source}}{{end}}{{end}}' "$container_id")" || return 1
        mount_count=0
        while IFS= read -r mount_source; do
            [[ -n "$mount_source" ]] || continue
            mount_count=$((mount_count + 1)); (( mount_count <= 512 )) || return 1
            # Docker normally reports canonical absolute host paths. Treat a
            # malformed source as an inventory failure instead of attempting a
            # lexical comparison that could permit residue deletion.
            [[ "$mount_source" == /* && "$mount_source" != *'//'*
                && "$mount_source" != *'/./'* && "$mount_source" != *'/../'*
                && "$mount_source" != */. && "$mount_source" != */..
                && ( "$mount_source" == / || "$mount_source" != */ ) ]] || return 1
            # Refuse every path-boundary overlap. A container mounting the
            # residue itself, an ancestor (including the installation root),
            # or a file/subdirectory inside it can retain or influence bytes
            # that cleanup is about to remove.
            if [[ "$mount_source" == "$wanted" || "$mount_source" == / \
                || "$mount_source" == "$wanted/"* || "$wanted" == "$mount_source/"* ]]; then
                return 10
            fi
        done <<< "$mounts"
    done <<< "$listing"
    return 0
}

containers_mounting_path() {
    local status=0 limit="${2:-30}"
    [[ "$limit" =~ ^[1-9][0-9]*$ && "$limit" -le 30 ]] || return 125
    run_bounded "$limit" "Docker bind-mount inventory" scan_containers_mounting_path "$1" || status=$?
    return "$status"
}

attest_verifier_container() {
    local verifier_id="$1" expected_state="${2:-}" expected_exit="${3:-}"
    local expected_image_id="" value="" state="" none_network_id="" endpoint_id=""
    local mount_source_raw="" mount_source="" verifier_env="" expected_verifier_env=""
    local verifier_args="" expected_verifier_args="" labels="" expected_labels=""
    local records="" record="" key="" required_masked="" readonly_paths="" masked_paths=""
    local ulimit_shape="" ulimit_count=0 ulimit_index=0 ulimit_name="" ulimit_soft="" ulimit_hard="" ulimit_seen="|"
    local json_path_regex='^"/[A-Za-z0-9._/@+ -]+"$'
    local json_digest_regex='^"[0-9a-f]{64}"$'
    local verifier_snapshot_json=""
    [[ "$verifier_id" =~ ^[0-9a-f]{64}$ ]] || die "orphan verifier inventory returned a malformed container ID"
    verifier_snapshot_json="$(docker_client inspect "$verifier_id")" \
        || die "could not capture one immutable verifier inspection snapshot"
    [[ -n "$verifier_snapshot_json" && ${#verifier_snapshot_json} -le 2097151 ]] \
        || die "verifier inspection snapshot is empty or oversized"
    [[ "$(strict_json_count "$verifier_snapshot_json")" == 'array|1' ]] \
        || die "verifier inspection snapshot must contain exactly one container"
    [[ "$(verifier_snapshot_value Id)" == "\"${verifier_id}\"" \
        && "$(verifier_snapshot_value Name)" == "\"/${VERIFIER_NAME}\"" ]] \
        || die "orphan verifier ID or canonical name changed during inventory"

    expected_image_id="$(verifier_snapshot_value Image)"
    expected_image_id="${expected_image_id#\"}"; expected_image_id="${expected_image_id%\"}"
    [[ "$expected_image_id" =~ ^sha256:[0-9a-f]{64}$ \
        && "$(verifier_snapshot_value Config Image)" == "\"${COSIGN_IMAGE}\"" ]] \
        || die "orphan verifier image reference or ID mismatch"
    attest_cosign_image "$expected_image_id" false
    if docker_client image inspect "$COSIGN_IMAGE" >/dev/null 2>&1; then
        [[ "$(docker_client image inspect --format '{{.Id}}' "$COSIGN_IMAGE")" == "$expected_image_id" ]] \
            || die "orphan verifier image ID conflicts with the currently pinned verifier reference"
    fi
    [[ "$(verifier_snapshot_value Config User)" == '"65532:65532"' \
        && "$(verifier_snapshot_value Config Hostname)" == '"backupsheep-verifier"' \
        && "$(verifier_snapshot_value Config Domainname)" == '""' \
        && "$(verifier_snapshot_value Config WorkingDir)" == '"/"' \
        && "$(verifier_snapshot_value Config StopSignal)" == '"SIGTERM"' \
        && "$(verifier_snapshot_value Config StopTimeout)" == 5 \
        && "$(verifier_snapshot_value Config Tty)" == false \
        && "$(verifier_snapshot_value Config OpenStdin)" == false \
        && "$(verifier_snapshot_value Config StdinOnce)" == false \
        && "$(verifier_snapshot_value Config AttachStdin)" == false \
        && "$(verifier_snapshot_value Config AttachStdout)" == true \
        && "$(verifier_snapshot_value Config AttachStderr)" == true \
        && "$(verifier_snapshot_optional_value Config Shell)" == '__BACKUPSHEEP_ABSENT__' \
        && "$(verifier_snapshot_optional_value Config Healthcheck)" == '__BACKUPSHEEP_ABSENT__' \
        && "$(verifier_snapshot_value Config Volumes)" == null \
        && "$(verifier_snapshot_value Config Entrypoint)" == '["/ko-app/cosign"]' \
        && "$(verifier_snapshot_value Path)" == '"/ko-app/cosign"' ]] \
        || die "orphan verifier exact process configuration mismatch"

    verifier_args="$(strict_json_array_records "$(verifier_snapshot_value Config Cmd)")" \
        || die "orphan verifier arguments are not a strict bounded JSON string array"
    expected_verifier_args="$(printf '"%s"\n' \
        verify-blob --offline --trusted-root "/evidence/${TRUSTED_ROOT_NAME}" \
        --bundle "/evidence/${BUNDLE_NAME}" \
        --certificate-identity "$WORKFLOW_IDENTITY" \
        --certificate-oidc-issuer "$OIDC_ISSUER" \
        --certificate-github-workflow-repository "$SOURCE_REPOSITORY" \
        --certificate-github-workflow-sha "$SOURCE_COMMIT" \
        --certificate-github-workflow-ref "refs/tags/$RELEASE_TAG" \
        --certificate-github-workflow-trigger push "/evidence/${DESCRIPTOR_NAME}")"
    [[ "$verifier_args" == "$expected_verifier_args" \
        && "$(strict_json_array_records "$(verifier_snapshot_value Args)")" == "$expected_verifier_args" ]] \
        || die "orphan verifier argument boundaries or values mismatch"

    verifier_env="$(strict_json_array_records "$(verifier_snapshot_value Config Env)" | LC_ALL=C sort)" \
        || die "orphan verifier environment is not a strict bounded JSON string array"
    expected_verifier_env="$(printf '"%s"\n' \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/tmp XDG_CACHE_HOME=/tmp/cache XDG_CONFIG_HOME= KO_DATA_PATH= GODEBUG= \
        HTTP_PROXY= HTTPS_PROXY= FTP_PROXY= ALL_PROXY= NO_PROXY= \
        http_proxy= https_proxy= ftp_proxy= all_proxy= no_proxy= \
        SSL_CERT_FILE= SSL_CERT_DIR= REQUESTS_CA_BUNDLE= CURL_CA_BUNDLE= GIT_SSL_CAINFO= \
        DOCKER_CONFIG= COSIGN_REPOSITORY= COSIGN_EXPERIMENTAL= COSIGN_DOCKER_MEDIA_TYPES= SIGSTORE_NO_CACHE= \
        | LC_ALL=C sort)"
    [[ "$verifier_env" == "$expected_verifier_env" ]] \
        || die "orphan verifier environment contains an unexpected or missing entry"

    labels="$(strict_json_object_records "$(verifier_snapshot_value Config Labels)" | LC_ALL=C sort)" \
        || die "orphan verifier labels are not one strict string map"
    [[ "$(verifier_snapshot_count Config Labels)" == 'object|12' ]] \
        || die "orphan verifier label set has an unexpected cardinality"
    expected_labels="$(printf '"%s"\n' \
        'org.opencontainers.image.title=BackupSheep release verifier' \
        'org.opencontainers.image.description=Minimal Cosign verifier rebuilt with reviewed security updates' \
        'org.opencontainers.image.source=https://github.com/bilal414/backupsheep' \
        'org.opencontainers.image.licenses=Apache-2.0' \
        'com.backupsheep.release-verifier.upstream-version=v3.1.3' \
        'com.backupsheep.release-verifier.upstream-commit=11926fa5bbbbde47e88fc006b625a17769b743b2' \
        'com.backupsheep.release-verifier.go-version=go1.26.6' \
        'com.backupsheep.release-verifier.module-graph-sha256=894396e4119d1620852793d03419a7130f4c62881ae5e11301b36c2a775aa6f2' \
        'com.backupsheep.release-verifier=true' \
        "com.backupsheep.installation-path-sha256=${INSTALLATION_PATH_DIGEST}" \
        "com.backupsheep.release-tag=${RELEASE_TAG}" \
        "com.backupsheep.source-commit=${SOURCE_COMMIT}" | LC_ALL=C sort)"
    [[ "$labels" == "$expected_labels" ]] || die "orphan verifier exact image and ownership label set mismatch"

    [[ "$(verifier_snapshot_value HostConfig NetworkMode)" == '"none"' \
        && "$(verifier_snapshot_value HostConfig ReadonlyRootfs)" == true \
        && "$(verifier_snapshot_value HostConfig Privileged)" == false \
        && "$(verifier_snapshot_value HostConfig AutoRemove)" == false \
        && "$(verifier_snapshot_value HostConfig RestartPolicy Name)" == '"no"' \
        && "$(verifier_snapshot_value HostConfig RestartPolicy MaximumRetryCount)" == 0 \
        && "$(verifier_snapshot_value HostConfig Runtime)" == '"runc"' \
        && "$(verifier_snapshot_value HostConfig PidMode)" == '""' \
        && "$(verifier_snapshot_value HostConfig IpcMode)" == '"private"' \
        && "$(verifier_snapshot_value HostConfig CgroupnsMode)" == '"private"' \
        && "$(verifier_snapshot_value HostConfig UsernsMode)" == '""' \
        && "$(verifier_snapshot_value HostConfig UTSMode)" == '""' \
        && "$(verifier_snapshot_value HostConfig PublishAllPorts)" == false \
        && "$(verifier_snapshot_value HostConfig PidsLimit)" == 64 \
        && "$(verifier_snapshot_value HostConfig Memory)" == 268435456 \
        && "$(verifier_snapshot_value HostConfig MemorySwap)" == 268435456 \
        && "$(verifier_snapshot_value HostConfig NanoCpus)" == 500000000 \
        && "$(verifier_snapshot_value HostConfig CpuShares)" == 0 \
        && "$(verifier_snapshot_value HostConfig CpusetCpus)" == '""' \
        && "$(verifier_snapshot_value HostConfig CpusetMems)" == '""' \
        && "$(verifier_snapshot_value HostConfig OomKillDisable)" == false \
        && "$(verifier_snapshot_value HostConfig OomScoreAdj)" == 0 \
        && "$(verifier_snapshot_value HostConfig ShmSize)" == 16777216 ]] \
        || die "orphan verifier namespace, lifecycle, CPU, memory, swap, OOM, PID, or shared-memory policy mismatch"
    value="$(verifier_snapshot_optional_value HostConfig MemorySwappiness)"
    [[ "$value" == null || "$value" == '__BACKUPSHEEP_ABSENT__' ]] \
        || die "orphan verifier memory-swappiness request was not omitted as required by the no-swap contract"
    [[ "$(verifier_snapshot_value HostConfig CapDrop)" == '["ALL"]' \
        && "$(verifier_snapshot_value HostConfig SecurityOpt)" == '["no-new-privileges:true"]' ]] \
        || die "orphan verifier capability or security-option policy mismatch"
    for key in CapAdd Devices DeviceRequests DeviceCgroupRules GroupAdd DNS DNSOptions DNSSearch ExtraHosts VolumesFrom Links Binds; do
        records="$(strict_json_array_records "$(verifier_snapshot_value HostConfig "$key")")" \
            || die "orphan verifier ${key} boundary is not a strict array or null"
        [[ -z "$records" ]] || die "orphan verifier ${key} boundary is not empty"
    done
    [[ "$(verifier_snapshot_optional_value HostConfig Sysctls)" == '__BACKUPSHEEP_ABSENT__' ]] \
        || die "orphan verifier sysctl boundary is not absent"
    value="$(verifier_snapshot_optional_value HostConfig Annotations)"
    if [[ "$value" != '__BACKUPSHEEP_ABSENT__' && "$value" != null ]]; then
        [[ -z "$(strict_json_object_keys "$value")" ]] \
            || die "orphan verifier annotations boundary is not empty"
    fi
    for key in KernelMemory KernelMemoryTCP; do
        value="$(verifier_snapshot_optional_value HostConfig "$key")"
        [[ "$value" == 0 || "$value" == null || "$value" == '__BACKUPSHEEP_ABSENT__' ]] \
            || die "orphan verifier ${key} boundary is not zero"
    done
    for key in Cgroup CgroupParent ContainerIDFile VolumeDriver Isolation; do
        value="$(verifier_snapshot_optional_value HostConfig "$key")"
        [[ "$value" == '""' || "$value" == '__BACKUPSHEEP_ABSENT__' ]] \
            || die "orphan verifier ${key} boundary is not empty"
    done
    value="$(verifier_snapshot_optional_value HostConfig ConsoleSize)"
    [[ "$value" == '[0,0]' || "$value" == null || "$value" == '__BACKUPSHEEP_ABSENT__' ]] \
        || die "orphan verifier console-size boundary is not zero"
    for key in PortBindings; do
        records="$(strict_json_object_keys "$(verifier_snapshot_value HostConfig "$key")")" \
            || die "orphan verifier ${key} boundary is not a strict object or null"
        [[ -z "$records" ]] || die "orphan verifier ${key} boundary is not empty"
    done
    [[ "$(verifier_snapshot_value HostConfig Init)" == false ]] \
        || die "orphan verifier init policy mismatch"
    ulimit_shape="$(verifier_snapshot_count HostConfig Ulimits)"
    [[ "$ulimit_shape" =~ ^array\|([0-9]+)$ ]] \
        || die "orphan verifier ulimit set is not a strict JSON array"
    ulimit_count="${BASH_REMATCH[1]}"
    (( ulimit_count >= 2 && ulimit_count <= 16 )) \
        || die "orphan verifier ulimit set has an unexpected cardinality"
    while (( ulimit_index < ulimit_count )); do
        ulimit_name="$(verifier_snapshot_value HostConfig Ulimits "#${ulimit_index}" Name)"
        ulimit_name="${ulimit_name#\"}"; ulimit_name="${ulimit_name%\"}"
        ulimit_soft="$(verifier_snapshot_value HostConfig Ulimits "#${ulimit_index}" Soft)"
        ulimit_hard="$(verifier_snapshot_value HostConfig Ulimits "#${ulimit_index}" Hard)"
        [[ "$ulimit_name" =~ ^(core|cpu|data|fsize|locks|memlock|msgqueue|nofile|nproc|rss|rttime|sigpending|stack)$ \
            && "$ulimit_soft" =~ ^(-1|0|[1-9][0-9]{0,9})$ \
            && "$ulimit_hard" =~ ^(-1|0|[1-9][0-9]{0,9})$ \
            && "$ulimit_seen" != *"|${ulimit_name}|"* ]] \
            || die "orphan verifier contains an unsafe or duplicate daemon-default ulimit"
        case "$ulimit_name" in
            core) [[ "$ulimit_soft" == 0 && "$ulimit_hard" == 0 ]] \
                || die "orphan verifier core ulimit drifted" ;;
            nofile) [[ "$ulimit_soft" == 1024 && "$ulimit_hard" == 1024 ]] \
                || die "orphan verifier nofile ulimit drifted" ;;
        esac
        ulimit_seen+="${ulimit_name}|"
        ulimit_index=$((ulimit_index + 1))
    done
    [[ "$ulimit_seen" == *'|core|'* && "$ulimit_seen" == *'|nofile|'* ]] \
        || die "orphan verifier exact core/nofile ulimit policy is incomplete"
    [[ "$(strict_json_object_keys "$(verifier_snapshot_value HostConfig LogConfig Config)")" == "" \
        && "$(verifier_snapshot_value HostConfig LogConfig Type)" == '"none"' ]] \
        || die "orphan verifier logging policy mismatch"

    records="$(strict_json_object_records "$(verifier_snapshot_value HostConfig Tmpfs)" | LC_ALL=C sort)" \
        || die "orphan verifier tmpfs policy is not a strict string map"
    [[ "$(verifier_snapshot_count HostConfig Tmpfs)" == 'object|1' \
        && "$records" == '"/tmp=rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=700"' ]] \
        || die "orphan verifier tmpfs map contains conflicting, extra, or reordered options"

    [[ "$(verifier_snapshot_count Mounts)" == 'array|1' \
        && "$(verifier_snapshot_count HostConfig Mounts)" == 'array|1' ]] \
        || die "orphan verifier has an unexpected runtime or requested mount count"
    mount_source_raw="$(verifier_snapshot_value Mounts '#0' Source)"
    [[ "$mount_source_raw" =~ $json_path_regex ]] || die "orphan verifier mount source is not canonical"
    mount_source="${mount_source_raw#\"}"; mount_source="${mount_source%\"}"
    [[ "$mount_source" == "${INSTALL_DIR}/.release-evidence.verify."* \
        && "$(verifier_snapshot_value Mounts '#0' Name)" == '""' \
        && "$(verifier_snapshot_value Mounts '#0' Destination)" == '"/evidence"' \
        && "$(verifier_snapshot_value Mounts '#0' RW)" == false \
        && "$(verifier_snapshot_value Mounts '#0' Type)" == '"bind"' \
        && "$(verifier_snapshot_value Mounts '#0' Propagation)" == '"rprivate"' \
        && "$(verifier_snapshot_value Mounts '#0' Mode)" == '""' ]] \
        || die "orphan verifier runtime mount policy mismatch"
    [[ "$(verifier_snapshot_value HostConfig Mounts '#0' Type)" == '"bind"' \
        && "$(verifier_snapshot_value HostConfig Mounts '#0' Source)" == "$mount_source_raw" \
        && "$(verifier_snapshot_value HostConfig Mounts '#0' Target)" == '"/evidence"' \
        && "$(verifier_snapshot_value HostConfig Mounts '#0' ReadOnly)" == true \
        && "$(verifier_snapshot_value HostConfig Mounts '#0' BindOptions Propagation)" == '"rprivate"' \
        && "$(verifier_snapshot_count HostConfig Mounts '#0' BindOptions)" == 'object|1' \
        && "$(verifier_snapshot_optional_value HostConfig Mounts '#0' VolumeOptions)" == '__BACKUPSHEEP_ABSENT__' \
        && "$(verifier_snapshot_optional_value HostConfig Mounts '#0' TmpfsOptions)" == '__BACKUPSHEEP_ABSENT__' \
        && "$(verifier_snapshot_optional_value HostConfig Mounts '#0' ClusterOptions)" == '__BACKUPSHEEP_ABSENT__' \
        && "$(verifier_snapshot_optional_value HostConfig Mounts '#0' ImageOptions)" == '__BACKUPSHEEP_ABSENT__' ]] \
        || die "orphan verifier mount-create policy mismatch"
    validate_residue_dir "$mount_source"

    records="$(strict_json_object_keys "$(verifier_snapshot_value NetworkSettings Networks)")" \
        || die "orphan verifier network attachment map is malformed"
    [[ "$(verifier_snapshot_count NetworkSettings Networks)" == 'object|1' \
        && "$records" == '"none"' ]] \
        || die "orphan verifier does not have exactly the built-in none network"
    none_network_id="$(docker_client network inspect --format '{{.Id}}' none)" \
        || die "could not attest Docker built-in none network identity"
    [[ "$none_network_id" =~ ^[0-9a-f]{64}$ ]] || die "Docker built-in none network ID is malformed"
    value="$(verifier_snapshot_value NetworkSettings Networks none NetworkID)"
    [[ "$value" == '""' || "$value" == "\"${none_network_id}\"" ]] \
        || die "orphan verifier none-network identity mismatch"
    endpoint_id="$(verifier_snapshot_value NetworkSettings Networks none EndpointID)"
    [[ "$endpoint_id" == '""' || "$endpoint_id" =~ $json_digest_regex ]] \
        || die "orphan verifier none-network endpoint ID is malformed"
    [[ "$(verifier_snapshot_value NetworkSettings Networks none Gateway)" == '""' \
        && "$(verifier_snapshot_value NetworkSettings Networks none IPAddress)" == '""' \
        && "$(verifier_snapshot_value NetworkSettings Networks none IPPrefixLen)" == 0 \
        && "$(verifier_snapshot_value NetworkSettings Networks none MacAddress)" == '""' ]] \
        || die "orphan verifier none-network unexpectedly has addressing"
    for key in Aliases Links; do
        [[ -z "$(strict_json_array_records "$(verifier_snapshot_value NetworkSettings Networks none "$key")")" ]] \
            || die "orphan verifier none-network ${key} is not empty"
    done
    [[ -z "$(strict_json_object_keys "$(verifier_snapshot_value NetworkSettings Networks none DriverOpts)")" ]] \
        || die "orphan verifier none-network driver options are not empty"
    state="$(verifier_snapshot_value State Status)"
    case "$state" in '"created"'|'"running"'|'"exited"') ;; *) die "orphan verifier lifecycle state is unreviewed" ;; esac
    [[ -z "$expected_state" || "$state" == "\"${expected_state}\"" ]] \
        || die "verifier lifecycle state does not match the expected verification phase"
    [[ "$(verifier_snapshot_value State Dead)" == false \
        && "$(verifier_snapshot_value State Paused)" == false \
        && "$(verifier_snapshot_value State Restarting)" == false \
        && "$(verifier_snapshot_value State OOMKilled)" == false ]] \
        || die "verifier entered an unsafe runtime state"
    case "$state" in
        '"created"')
            [[ "$(verifier_snapshot_value State Running)" == false \
                && "$(verifier_snapshot_value State Pid)" == 0 \
                && "$(verifier_snapshot_value State ExitCode)" == 0 \
                && "$value" == '""' && "$endpoint_id" == '""' ]] \
                || die "created verifier has unexpected process or network state"
            ;;
        '"running"')
            [[ "$(verifier_snapshot_value State Running)" == true \
                && "$(verifier_snapshot_value State Pid)" =~ ^[1-9][0-9]*$ \
                && "$(verifier_snapshot_value State ExitCode)" == 0 \
                && "$value" == "\"${none_network_id}\"" \
                && "$endpoint_id" =~ $json_digest_regex ]] \
                || die "running verifier is not attached to the exact built-in none endpoint"
            ;;
        '"exited"')
            [[ "$(verifier_snapshot_value State Running)" == false \
                && "$(verifier_snapshot_value State Pid)" == 0 \
                && "$(verifier_snapshot_value State ExitCode)" =~ ^[0-9]+$ \
                && "$value" == "\"${none_network_id}\"" && "$endpoint_id" == '""' ]] \
                || die "exited verifier has unexpected process or network state"
            ;;
    esac
    if [[ -n "$expected_exit" ]]; then
        [[ "$expected_exit" =~ ^[0-9]+$ && "$state" == '"exited"' \
            && "$(verifier_snapshot_value State ExitCode)" == "$expected_exit" ]] \
            || die "verifier exit status does not match Docker's durable state"
    fi

    readonly_paths="$(strict_json_array_records "$(verifier_snapshot_value HostConfig ReadonlyPaths)" | LC_ALL=C sort)" \
        || die "orphan verifier read-only kernel path boundary is malformed"
    [[ "$readonly_paths" == $'"/proc/bus"\n"/proc/fs"\n"/proc/irq"\n"/proc/sys"\n"/proc/sysrq-trigger"' ]] \
        || die "orphan verifier read-only kernel path boundary drifted"
    masked_paths="$(strict_json_array_records "$(verifier_snapshot_value HostConfig MaskedPaths)" | LC_ALL=C sort)" \
        || die "orphan verifier masked kernel path boundary is malformed"
    printf '%s\n' "$masked_paths" | awk '
        BEGIN {
            required["\"/proc/acpi\""]; required["\"/proc/asound\""];
            required["\"/proc/kcore\""]; required["\"/proc/keys\""]; required["\"/proc/latency_stats\""];
            required["\"/proc/sched_debug\""]; required["\"/proc/scsi\""]; required["\"/proc/timer_list\""];
            required["\"/proc/timer_stats\""]; required["\"/sys/devices/virtual/powercap\""];
            required["\"/sys/firmware\""]
        }
        {
            if (seen[$0]++) exit 2
            if ($0 in required) { present[$0] = 1; next }
            if ($0 == "\"/proc/interrupts\"") next
            if ($0 !~ /^"\/sys\/devices\/system\/cpu\/cpu[0-9]+\/thermal_throttle"$/) exit 3
        }
        END { for (path in required) if (!present[path]) exit 4 }
    ' || die "orphan verifier masked kernel path boundary drifted"
}

attest_verifier_container_bounded() {
    local verifier_id="$1" expected_state="${2:-}" expected_exit="${3:-}"
    run_bounded 30 "verifier configuration attestation" attest_verifier_container \
        "$verifier_id" "$expected_state" "$expected_exit" \
        || die "could not attest canonical verifier container"
}

scan_named_verifier() {
    local listing="" container_id="" count=0
    listing="$(docker_client ps --all --quiet --no-trunc --filter "name=^/${VERIFIER_NAME}$")" || return 1
    while IFS= read -r container_id; do
        [[ -n "$container_id" ]] || continue
        count=$((count + 1)); (( count == 1 )) || return 1
        [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || return 1
    done <<< "$listing"
    (( count == 1 )) || return 10
    printf '%s\n' "$container_id"
    return 0
}

named_verifier_state() {
    run_bounded_capture 15 "verifier inventory" scan_named_verifier
}

reconcile_verifier_orphan() {
    local inventory_status=0 status=0 verifier_id="" state="" current_id=""
    named_verifier_state || inventory_status=$?
    verifier_id="$BOUNDED_CAPTURE_VALUE"
    [[ "$inventory_status" -ne 10 ]] || return 0
    [[ "$inventory_status" -eq 0 ]] || die "could not inventory verifier containers"
    [[ "$verifier_id" =~ ^[0-9a-f]{64}$ ]] || die "verifier inventory did not return one exact container ID"
    attest_verifier_container_bounded "$verifier_id"
    run_bounded_capture 15 "verifier state inspection" docker_client inspect \
        --format '{{.State.Status}}' "$verifier_id" \
        || die "could not inspect attested verifier state"
    state="$BOUNDED_CAPTURE_VALUE"
    case "$state" in
        running)
            run_bounded 15 "verifier stop" docker_client stop --time 5 "$verifier_id" >/dev/null || status=$?
            [[ "$status" -eq 0 ]] || die "could not stop attested orphan verifier"
            ;;
        created|exited) ;;
        *) die "attested verifier entered an unreviewed lifecycle state" ;;
    esac
    inventory_status=0
    named_verifier_state || inventory_status=$?
    current_id="$BOUNDED_CAPTURE_VALUE"
    [[ "$inventory_status" -ne 10 ]] || return 0
    [[ "$inventory_status" -eq 0 ]] || die "could not reinventory stopped verifier"
    [[ "$current_id" == "$verifier_id" ]] || die "canonical verifier name was rebound during reconciliation"
    attest_verifier_container_bounded "$verifier_id"
    status=0
    run_bounded 15 "verifier removal" docker_client rm "$verifier_id" >/dev/null || status=$?
    [[ "$status" -eq 0 ]] || die "could not remove attested orphan verifier"
    inventory_status=0
    named_verifier_state || inventory_status=$?
    current_id="$BOUNDED_CAPTURE_VALUE"
    [[ "$inventory_status" -eq 10 && -z "$current_id" ]] \
        || die "canonical verifier still exists after removal"
}

scan_and_reconcile_installation_verifiers() {
    local listing="" container_id="" count=0 actual_name="" stale_tag="" stale_commit="" snapshot=""
    local stale_identity_digest="" inventory_status=0 status=0 state="" current_id=""
    local saved_name="$VERIFIER_NAME" saved_tag="$RELEASE_TAG" saved_commit="$SOURCE_COMMIT"
    local saved_identity="$WORKFLOW_IDENTITY"
    listing="$(docker_client ps --all --quiet --no-trunc \
        --filter 'label=com.backupsheep.release-verifier=true' \
        --filter "label=com.backupsheep.installation-path-sha256=${INSTALLATION_PATH_DIGEST}")" \
        || return 1
    while IFS= read -r container_id; do
        [[ -n "$container_id" ]] || continue
        status=0
        count=$((count + 1)); (( count <= 8 )) || return 1
        [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || return 1
        snapshot="$(docker_client inspect "$container_id")" || return 1
        [[ "$(strict_json_count "$snapshot")" == 'array|1' \
            && "$(strict_json_path "$snapshot" '#0' Id)" == "\"${container_id}\"" ]] || return 1
        actual_name="$(strict_json_path "$snapshot" '#0' Name)" || return 1
        [[ "${actual_name:0:2}" == '"/' && "${actual_name: -1}" == '"' \
            && "$actual_name" != *[[:cntrl:]]* ]] || return 1
        actual_name="${actual_name#\"/}"; actual_name="${actual_name%\"}"
        stale_tag="$(strict_json_path "$snapshot" '#0' Config Labels com.backupsheep.release-tag)" || return 1
        stale_tag="${stale_tag#\"}"; stale_tag="${stale_tag%\"}"
        stale_commit="$(strict_json_path "$snapshot" '#0' Config Labels com.backupsheep.source-commit)" || return 1
        stale_commit="${stale_commit#\"}"; stale_commit="${stale_commit%\"}"
        [[ "$stale_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ \
            && "$stale_commit" =~ ^[0-9a-f]{40}$ ]] || return 1
        stale_identity_digest="$(sha256_text "${stale_tag}|${stale_commit}")" || return 1
        [[ "$actual_name" == "backupsheep-release-verify-${INSTALLATION_PATH_DIGEST:0:12}-${stale_identity_digest:0:12}" ]] \
            || return 1

        VERIFIER_NAME="$actual_name"
        RELEASE_TAG="$stale_tag"
        SOURCE_COMMIT="$stale_commit"
        WORKFLOW_IDENTITY="https://github.com/${SOURCE_REPOSITORY}/${RELEASE_WORKFLOW}@refs/tags/${RELEASE_TAG}"
        attest_verifier_container "$container_id"
        state="$(docker_client inspect --format '{{.State.Status}}' "$container_id")" || return 1
        case "$state" in
            running)
                status=0
                docker_client stop --time 5 "$container_id" >/dev/null || status=$?
                [[ "$status" -eq 0 ]] || return 1
                ;;
            created|exited) ;;
            *) return 1 ;;
        esac
        status=0
        current_id="$(scan_named_verifier)" || status=$?
        [[ "$status" -ne 10 ]] || continue
        [[ "$status" -eq 0 && "$current_id" == "$container_id" ]] || return 1
        attest_verifier_container "$container_id"
        docker_client rm "$container_id" >/dev/null || return 1
        status=0
        current_id="$(scan_named_verifier)" || status=$?
        [[ "$status" -eq 10 && -z "$current_id" ]] || return 1
    done <<< "$listing"
    VERIFIER_NAME="$saved_name"
    RELEASE_TAG="$saved_tag"
    SOURCE_COMMIT="$saved_commit"
    WORKFLOW_IDENTITY="$saved_identity"
    return 0
}

reconcile_installation_verifier_orphans() {
    run_bounded 120 "installation verifier reconciliation" scan_and_reconcile_installation_verifiers \
        || die "could not safely reconcile all interrupted verifier containers for this installation"
}

cleanup_residues() {
    local residue="" count=0
    while IFS= read -r -d '' residue; do
        count=$((count + 1)); (( count <= 8 )) || die "too many interrupted release residues exist"
        if [[ -e "$residue/.verifier-container-id" || -L "$residue/.verifier-container-id" ]]; then
            [[ -z "$RECOVERY_VERIFIER_DIR" ]] \
                || die "multiple unresolved verifier-create residues require operator review"
            validate_residue_dir "$residue"
            validate_descriptor "$residue/$DESCRIPTOR_NAME" "$RELEASE_TAG" "$SOURCE_COMMIT" "$residue/$MANIFEST_NAME"
            validate_trusted_root "$residue/$TRUSTED_ROOT_NAME"
            RECOVERY_VERIFIER_DIR="$residue"
            VERIFIER_DIR="$residue"
            VERIFIER_CREATE_UNCERTAIN=true
            continue
        fi
        remove_residue_dir "$residue"
    done < <(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -type d \( -name '.release-evidence.download.*' -o -name '.release-evidence.verify.*' \) -print0)
}

image_repo_digest_present() { docker_client image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$1" 2>/dev/null | grep -Fxq -- "$2"; }

attest_cosign_image() {
    local reference="${1:-$COSIGN_IMAGE}" require_repo_digest="${2:-true}"
    local image_id="" expected_image_id="" image_user="" image_env="" image_config="" image_labels=""
    [[ "$require_repo_digest" == true || "$require_repo_digest" == false ]] \
        || die "invalid verifier RepoDigest attestation mode"
    if [[ "$require_repo_digest" == true ]]; then
        image_repo_digest_present "$COSIGN_IMAGE" "$COSIGN_REPODIGEST" \
            || die "local Cosign verifier does not resolve to pinned digest"
    fi
    image_id="$(docker_client image inspect --format '{{.Id}}' "$reference")"; [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "Cosign verifier image ID is malformed"
    attest_local_image_platform cosign "$reference"
    case "$DAEMON_ARCH" in
        amd64) expected_image_id="$COSIGN_AMD64_IMAGE_ID" ;;
        arm64) expected_image_id="$COSIGN_ARM64_IMAGE_ID" ;;
        *) die "Cosign verifier platform was not admitted by release policy" ;;
    esac
    [[ "$image_id" == "$expected_image_id" ]] \
        || die "Cosign verifier image ID does not match the reviewed platform config digest"
    image_user="$(docker_client image inspect --format '{{.Config.User}}' "$reference")"
    [[ "$image_user" == "65532:65532" ]] || die "pinned Cosign verifier has unexpected UID"
    image_config="$(docker_client image inspect --format '{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{.Config.WorkingDir}}|{{json .Config.Shell}}|{{.Config.StopSignal}}|{{json .Config.Healthcheck}}|{{len .Config.Volumes}}' "$reference")" \
        || die "could not inspect pinned Cosign verifier image configuration"
    [[ "$image_config" == '["/ko-app/cosign"]|null|/|null||null|0' ]] \
        || die "pinned Cosign verifier image command, directory, shell, signal, healthcheck, or volume contract is unexpected"
    image_env="$(docker_client image inspect --format '{{json .Config.Env}}' "$reference")" \
        || die "could not inspect pinned Cosign verifier environment"
    [[ "$image_env" == '["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOME=/tmp"]' ]] \
        || die "pinned Cosign verifier image environment is not the exact reviewed scratch-image contract"
    image_labels="$(docker_client image inspect --format '{{len .Config.Labels}}|{{index .Config.Labels "org.opencontainers.image.title"}}|{{index .Config.Labels "org.opencontainers.image.description"}}|{{index .Config.Labels "org.opencontainers.image.source"}}|{{index .Config.Labels "org.opencontainers.image.licenses"}}|{{index .Config.Labels "com.backupsheep.release-verifier.upstream-version"}}|{{index .Config.Labels "com.backupsheep.release-verifier.upstream-commit"}}|{{index .Config.Labels "com.backupsheep.release-verifier.go-version"}}|{{index .Config.Labels "com.backupsheep.release-verifier.module-graph-sha256"}}' "$reference")" \
        || die "could not inspect pinned Cosign verifier provenance labels"
    [[ "$image_labels" == '8|BackupSheep release verifier|Minimal Cosign verifier rebuilt with reviewed security updates|https://github.com/bilal414/backupsheep|Apache-2.0|v3.1.3|11926fa5bbbbde47e88fc006b625a17769b743b2|go1.26.6|894396e4119d1620852793d03419a7130f4c62881ae5e11301b36c2a775aa6f2' ]] \
        || die "pinned Cosign verifier provenance labels differ from the reviewed first-party build"
}

cosign() {
    local status=0 verifier_id="" verifier_id_file="${VERIFIER_DIR}/.verifier-container-id"
    reconcile_installation_verifier_orphans
    reconcile_verifier_orphan
    if [[ -e "$verifier_id_file" || -L "$verifier_id_file" ]]; then
        validate_residue_dir "$VERIFIER_DIR"
        [[ -f "$verifier_id_file" && ! -L "$verifier_id_file" \
            && "$(file_uid "$verifier_id_file")" == "$EUID" \
            && "$(file_mode "$verifier_id_file")" == 600 \
            && "$(file_links "$verifier_id_file")" == 1 ]] \
            || die "unresolved verifier-create capture is unsafe"
    else
        : > "$verifier_id_file"
    fi
    chmod 0600 "$verifier_id_file"
    # Publish the uncertain-create witness before contacting the daemon.  It is
    # intentionally retained across signals/timeouts and retried with the same
    # canonical name and bind source; elapsed empty polls are never treated as
    # proof that a disconnected create request cannot register late.
    VERIFIER_CREATE_UNCERTAIN=true
    : > "$verifier_id_file"
    durable_sync
    run_bounded 30 "Cosign verifier creation" docker_client create \
        --name "$VERIFIER_NAME" --hostname backupsheep-verifier --attach stdout --attach stderr \
        --pull=never --network none \
        --runtime runc --stop-signal SIGTERM --stop-timeout 5 --log-driver none --workdir / \
        --label com.backupsheep.release-verifier=true --label "com.backupsheep.installation-path-sha256=${INSTALLATION_PATH_DIGEST}" \
        --label "com.backupsheep.release-tag=${RELEASE_TAG}" --label "com.backupsheep.source-commit=${SOURCE_COMMIT}" \
        --read-only --cap-drop ALL --security-opt no-new-privileges:true --ipc private --cgroupns private \
        --pids-limit 64 --memory 256m --memory-swap 256m --cpus 0.5 \
        --oom-kill-disable=false --oom-score-adj 0 --shm-size 16m --init=false \
        --ulimit core=0:0 --ulimit nofile=1024:1024 --user 65532:65532 \
        --env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        --env HOME=/tmp --env XDG_CACHE_HOME=/tmp/cache --env XDG_CONFIG_HOME= --env KO_DATA_PATH= --env GODEBUG= \
        --env HTTP_PROXY= --env HTTPS_PROXY= --env FTP_PROXY= --env ALL_PROXY= --env NO_PROXY= \
        --env http_proxy= --env https_proxy= --env ftp_proxy= --env all_proxy= --env no_proxy= \
        --env SSL_CERT_FILE= --env SSL_CERT_DIR= --env REQUESTS_CA_BUNDLE= --env CURL_CA_BUNDLE= --env GIT_SSL_CAINFO= \
        --env DOCKER_CONFIG= --env COSIGN_REPOSITORY= --env COSIGN_EXPERIMENTAL= --env COSIGN_DOCKER_MEDIA_TYPES= --env SIGSTORE_NO_CACHE= \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=700 \
        --mount "type=bind,src=${VERIFIER_DIR},dst=/evidence,readonly,bind-propagation=rprivate" \
        "$COSIGN_IMAGE" "$@" > "$verifier_id_file" || status=$?
    if [[ "$status" -ne 0 ]]; then
        VERIFIER_CREATE_UNCERTAIN=true
        die "Cosign verifier creation had an unknown outcome; protected residue was retained for bounded reconciliation"
    fi
    validate_regular_file "$verifier_id_file" 128
    [[ "$(file_mode "$verifier_id_file")" == 600 ]] \
        || die "verifier container-ID capture has unsafe permissions"
    verifier_id="$(<"$verifier_id_file")"
    rm -f -- "$verifier_id_file" || die "could not remove verifier container-ID capture"
    [[ "$status" -eq 0 && "$verifier_id" =~ ^[0-9a-f]{64}$ ]] \
        || die "could not create the exact pinned Cosign verifier container"
    VERIFIER_CREATE_UNCERTAIN=false
    attest_verifier_container_bounded "$verifier_id" created
    status=0
    run_bounded 180 "Cosign verification" docker_client start --attach "$verifier_id" || status=$?
    if [[ "$status" -ne 124 ]]; then
        attest_verifier_container_bounded "$verifier_id" exited "$status"
    fi
    reconcile_verifier_orphan
    return "$status"
}

verify_signatures() {
    local -a identity_args=(--certificate-identity "$WORKFLOW_IDENTITY" --certificate-oidc-issuer "$OIDC_ISSUER" --certificate-github-workflow-repository "$SOURCE_REPOSITORY" --certificate-github-workflow-sha "$SOURCE_COMMIT" --certificate-github-workflow-ref "refs/tags/$RELEASE_TAG" --certificate-github-workflow-trigger push)
    cosign verify-blob --offline --trusted-root "/evidence/${TRUSTED_ROOT_NAME}" --bundle "/evidence/${BUNDLE_NAME}" "${identity_args[@]}" "/evidence/${DESCRIPTOR_NAME}" >/dev/null || die "Cosign rejected signed release descriptor"
}

write_signature_verification_receipt() {
    local destination="${STAGING_DIR}/${VERIFICATION_RECEIPT_NAME}"
    local candidate="${destination}.new"
    local verifier_config=""
    [[ ! -e "$destination" && ! -L "$destination" && ! -e "$candidate" && ! -L "$candidate" ]] \
        || die "signature-verification receipt destination is not fresh"
    ( set -o noclobber; : > "$candidate" ) \
        || die "could not allocate signature-verification receipt"
    chmod 0600 "$candidate"
    if [[ "$DAEMON_ARCH" == amd64 ]]; then
        verifier_config="$COSIGN_AMD64_IMAGE_ID"
    elif [[ "$DAEMON_ARCH" == arm64 ]]; then
        verifier_config="$COSIGN_ARM64_IMAGE_ID"
    else
        die "signature-verification receipt requires an attested daemon platform"
    fi
    # Every interpolated value has already passed a strict lowercase digest,
    # SemVer, commit, platform, or fixed identity grammar.  Keep the bytes in a
    # canonical, sorted-key JSON form so future upgrade journals can hash and
    # retain this exact successful offline-verification witness.
    printf '%s\n' \
        "{\"daemon_identity_sha256\":\"${DAEMON_IDENTITY_SHA256}\",\"descriptor_bundle_sha256\":\"sha256:${VERIFIED_BUNDLE_SHA256}\",\"descriptor_sha256\":\"sha256:${VERIFIED_DESCRIPTOR_SHA256}\",\"manifest_sha256\":\"sha256:${VERIFIED_MANIFEST_SHA256}\",\"migration_leaf_set_sha256\":\"${MIGRATION_LEAF_SET_SHA256}\",\"migration_set_sha256\":\"${MIGRATION_SET_SHA256}\",\"oidc_issuer\":\"${OIDC_ISSUER}\",\"platform\":\"${DAEMON_OS}/${DAEMON_ARCH}\",\"purpose\":\"target\",\"release_epoch\":${RELEASE_EPOCH},\"release_tag\":\"${RELEASE_TAG}\",\"runtime_contract_version\":${COSIGN_RUNTIME_CONTRACT_VERSION},\"schema_version\":2,\"source_commit\":\"${SOURCE_COMMIT}\",\"trigger\":\"push\",\"trusted_root_sha256\":\"sha256:${TRUSTED_ROOT_SHA256}\",\"verifier_config_digest\":\"${verifier_config}\",\"verifier_manifest_digest\":\"${VERIFIER_MANIFEST_DIGEST}\",\"verifier_reference\":\"${COSIGN_IMAGE}\",\"workflow_identity\":\"${WORKFLOW_IDENTITY}\",\"workflow_ref\":\"refs/tags/${RELEASE_TAG}\"}" \
        > "$candidate" || die "could not render signature-verification receipt"
    durable_sync
    mv -- "$candidate" "$destination" \
        || die "could not publish signature-verification receipt"
    durable_sync
}

attest_release_image() {
    local role="$1" reference="$2" repository="${2%@*}" image_id="" source_label="" revision_label="" version_label=""
    image_repo_digest_present "$reference" "$reference" || die "${role} image does not expose exact official RepoDigest"
    attest_local_image_platform "$role" "$reference"
    [[ "$repository" == "$APP_REPOSITORY" || "$repository" == "$POSTGRES_REPOSITORY" \
        || "$repository" == "$EGRESS_REPOSITORY" || "$repository" == "$RABBITMQ_REPOSITORY" \
        || "$repository" == "$RABBITMQ_UPGRADE_REPOSITORY" ]] \
        || die "${role} image repository is not official"
    image_id="$(docker_client image inspect --format '{{.Id}}' "$reference")"; [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "${role} image ID is malformed"
    source_label="$(docker_client image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$reference")"
    revision_label="$(docker_client image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$reference")"
    version_label="$(docker_client image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$reference")"
    [[ "$source_label" == "https://github.com/${SOURCE_REPOSITORY}" && "$revision_label" == "$SOURCE_COMMIT" && "$version_label" == "$RELEASE_TAG" ]] || die "${role} image provenance labels mismatch"
    printf '%s_image_id=%s\n' "$role" "$image_id" >> "${STAGING_DIR}/local-images.txt"
}

validate_local_image_receipt() {
    local path="$1" line="" index=0
    local -a expected=(
        app_image_id postgres_image_id egress_image_id
        rabbitmq_image_id rabbitmq_upgrade_image_id cosign_image_id
    )
    validate_regular_file "$path" 4096
    [[ "$(file_mode "$path")" == "600" ]] || die "local image receipt must be owner-only"
    while IFS= read -r line; do
        (( index < ${#expected[@]} )) || die "local image receipt contains extra entries"
        [[ "$line" =~ ^${expected[$index]}=sha256:[0-9a-f]{64}$ ]] \
            || die "local image receipt is malformed or out of order at ${expected[$index]}"
        index=$((index + 1))
    done < "$path"
    [[ "$index" -eq "${#expected[@]}" ]] || die "local image receipt is incomplete"
}

validate_persisted_evidence() {
    local evidence="$1" entry="" count=0 base=""
    [[ -d "$evidence" && ! -L "$evidence" && "$(file_uid "$evidence")" == "$EUID" && "$(file_mode "$evidence")" == "700" ]] || die "persisted release evidence directory is unsafe"
    while IFS= read -r -d '' entry; do
        count=$((count + 1)); base="$(basename -- "$entry")"
        case "$base" in "$DESCRIPTOR_NAME"|"$BUNDLE_NAME"|"$MANIFEST_NAME"|"$TRUSTED_ROOT_NAME"|"$VERIFICATION_RECEIPT_NAME"|local-images.txt) ;; *) die "persisted release evidence contains unexpected entry" ;; esac
        validate_regular_file "$entry" 1048576
        [[ "$(file_mode "$entry")" == "600" ]] || die "persisted release evidence must be owner-only"
    done < <(find "$evidence" -mindepth 1 -maxdepth 1 -print0)
    [[ "$count" -eq 6 ]] || die "persisted release evidence is incomplete"
    validate_trusted_root "$evidence/$TRUSTED_ROOT_NAME"
    validate_local_image_receipt "$evidence/local-images.txt"
}

attest_verified_release_inputs() {
    local descriptor_source="${VERIFIER_DIR}/${DESCRIPTOR_NAME}"
    local bundle_source="${VERIFIER_DIR}/${BUNDLE_NAME}"
    local manifest_source="${VERIFIER_DIR}/${MANIFEST_NAME}"
    [[ -n "$VERIFIED_DESCRIPTOR_SHA256" && -n "$VERIFIED_BUNDLE_SHA256" \
        && -n "$VERIFIED_MANIFEST_SHA256" ]] \
        || die "verified release input digests were not captured"
    validate_regular_file "$descriptor_source" 2048
    validate_regular_file "$bundle_source" 1048576
    validate_regular_file "$manifest_source" 1048576
    [[ "$(sha256_file "$descriptor_source")" == "$VERIFIED_DESCRIPTOR_SHA256" \
        && "$(sha256_file "$bundle_source")" == "$VERIFIED_BUNDLE_SHA256" \
        && "$(sha256_file "$manifest_source")" == "$VERIFIED_MANIFEST_SHA256" ]] \
        || die "verified release input bytes changed after signature validation"
    cmp -s -- "$descriptor_source" "$STAGING_DIR/$DESCRIPTOR_NAME" \
        && cmp -s -- "$bundle_source" "$STAGING_DIR/$BUNDLE_NAME" \
        && cmp -s -- "$manifest_source" "$STAGING_DIR/$MANIFEST_NAME" \
        || die "download staging bytes diverged from the exact signature-verified inputs"
    validate_descriptor "$STAGING_DIR/$DESCRIPTOR_NAME" \
        "$RELEASE_TAG" "$SOURCE_COMMIT" "$STAGING_DIR/$MANIFEST_NAME"
}

reconcile_evidence_refresh() {
    local evidence="$1" candidate="${1}/local-images.txt.new" current="${1}/local-images.txt" size=""
    [[ -e "$candidate" || -L "$candidate" ]] || return 0
    [[ -d "$evidence" && ! -L "$evidence" && "$(file_uid "$evidence")" == "$EUID" && "$(file_mode "$evidence")" == "700" ]] || die "evidence refresh parent is unsafe"
    [[ -f "$candidate" && ! -L "$candidate" && "$(file_uid "$candidate")" == "$EUID" && "$(file_links "$candidate")" == "1" ]] \
        || die "evidence refresh candidate has an unsafe identity"
    size="$(file_size "$candidate")"; [[ "$size" =~ ^[0-9]+$ ]] && (( 10#$size <= 1048576 )) \
        || die "evidence refresh candidate is too large"
    [[ "$(file_mode "$candidate")" == "600" ]] || die "evidence refresh candidate is not owner-only"
    validate_regular_file "$current" 1048576
    [[ "$(file_mode "$current")" == "600" ]] || die "current image receipt is not owner-only"
    # The old receipt remains authoritative until the atomic rename. Discard an
    # exact interrupted candidate and regenerate it only after all attestations.
    rm -f -- "$candidate" || die "could not remove validated interrupted evidence refresh"
    durable_sync
}

durable_sync() {
    assert_installation_ancestor_identity
    run_bounded 30 "durable release evidence sync" "$SYNC_BIN" \
        || die "could not durably synchronize release evidence"
    assert_installation_ancestor_identity
}

publish_fresh_evidence() {
    local source="$1" destination="$2"
    assert_mutation_lock_ownership
    [[ -d "$source" && ! -L "$source" && ! -e "$destination" && ! -L "$destination" ]] \
        || die "fresh release evidence publication precondition changed"
    if ! mv --no-target-directory -- "$source" "$destination" 2>/dev/null; then
        # BSD mv has no --no-target-directory. The exclusive installation lock
        # prevents another compliant consumer from racing this fallback. A
        # hostile same-owner destination creation can only make mv nest the
        # source; the exact post-publication validation below then fails closed
        # before success is reported.
        [[ -d "$source" && ! -L "$source" && ! -e "$destination" && ! -L "$destination" ]] \
            || die "fresh release evidence destination appeared concurrently"
        mv -- "$source" "$destination" \
            || die "could not publish fresh release evidence"
    fi
    [[ ! -e "$source" && ! -L "$source" ]] \
        || die "fresh release evidence source still exists after publication"
    validate_persisted_evidence "$destination"
    assert_mutation_lock_ownership
}

cleanup_paths() {
    local path="" entry="" mount_status=0
    if [[ -n "$ACTIVE_CAPTURE_FILE" ]]; then
        if [[ "$ACTIVE_CAPTURE_FILE" == "${INSTALL_DIR}/.release-command-output."* \
            && -f "$ACTIVE_CAPTURE_FILE" && ! -L "$ACTIVE_CAPTURE_FILE" \
            && "$(file_uid "$ACTIVE_CAPTURE_FILE")" == "$EUID" \
            && "$(file_mode "$ACTIVE_CAPTURE_FILE")" == "600" \
            && "$(file_links "$ACTIVE_CAPTURE_FILE")" == "1" ]]; then
            rm -f -- "$ACTIVE_CAPTURE_FILE" 2>/dev/null || true
        fi
        ACTIVE_CAPTURE_FILE=""
    fi
    for path in "${STAGING_DIR:-}" "${VERIFIER_DIR:-}"; do
        [[ -n "$path" && -d "$path" && ! -L "$path" ]] || continue
        if [[ "$path" == "$VERIFIER_DIR" && "$VERIFIER_CREATE_UNCERTAIN" == true \
            && -e "$path/.verifier-container-id" ]]; then
            printf 'Signed release warning: retaining uncertain verifier-create residue %s for retry reconciliation\n' "$path" >&2
            continue
        fi
        if [[ -n "$DOCKER_BIN" && "${#DOCKER_ENV[@]}" -gt 0 ]]; then
            mount_status=0
            containers_mounting_path "$path" >/dev/null 2>&1 || mount_status=$?
            if [[ "$mount_status" -ne 0 ]]; then
                printf 'Signed release warning: refusing to delete mounted or unattested residue %s\n' "$path" >&2
                continue
            fi
        fi
        while IFS= read -r -d '' entry; do rm -f -- "$entry" 2>/dev/null || true; done < <(find "$path" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null)
        rmdir -- "$path" 2>/dev/null || true
    done
}

cleanup() {
    local original_status=$? cleanup_failed=false
    trap - EXIT
    if [[ -n "$VERIFIER_NAME" ]]; then
        (reconcile_installation_verifier_orphans && reconcile_verifier_orphan) >/dev/null 2>&1 \
            || cleanup_failed=true
    fi
    cleanup_paths
    release_mutation_lock || cleanup_failed=true
    [[ "$cleanup_failed" == false || "$original_status" -ne 0 ]] || original_status=1
    exit "$original_status"
}

handle_signal() {
    local status="$1"
    trap - HUP INT TERM EXIT
    if [[ -n "$ACTIVE_PID" ]]; then
        kill -TERM -- "-$ACTIVE_PID" 2>/dev/null || true
        sleep 1
        kill -KILL -- "-$ACTIVE_PID" 2>/dev/null || true
        wait "$ACTIVE_PID" 2>/dev/null || true
        ACTIVE_PID=""
    fi
    if [[ -n "$VERIFIER_NAME" ]]; then
        (reconcile_installation_verifier_orphans && reconcile_verifier_orphan) >/dev/null 2>&1 || true
    fi
    cleanup_paths
    release_mutation_lock >/dev/null 2>&1 || true
    exit "$status"
}

main() {
    local script_real="" trusted_root="" docker_variable="" role="" image_ref="" image_tuple="" cosign_id="" release_identity_digest=""
    local install_path_regex='^/[A-Za-z0-9._/@+ -]+$'
    local selected_context=""
    [[ $# -eq 8 ]] || die "expected --tag TAG --commit COMMIT --install-dir DIR --docker PATH"
    [[ "$1" == --tag && "$3" == --commit && "$5" == --install-dir && "$7" == --docker ]] || die "arguments must be in canonical order"
    RELEASE_TAG="$2"; SOURCE_COMMIT="$4"; INSTALL_DIR="$6"; DOCKER_BIN="$8"
    trap cleanup EXIT
    trap 'handle_signal 129' HUP
    trap 'handle_signal 130' INT
    trap 'handle_signal 143' TERM
    validate_privileged_consumer_environment
    [[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] || die "release tag must be exact SemVer prefixed by v"
    [[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "source commit must be lowercase and full length"
    [[ "$INSTALL_DIR" == /* && -d "$INSTALL_DIR" && ! -L "$INSTALL_DIR" && "$(file_uid "$INSTALL_DIR")" == "$EUID" && "$(file_mode "$INSTALL_DIR")" == "700" ]] || die "installation directory is unsafe"
    [[ "$INSTALL_DIR" != *','* && "$INSTALL_DIR" != *'|'* && "$INSTALL_DIR" != *[[:cntrl:]]* ]] || die "installation path contains Docker mount or filter metacharacters"
    [[ "$INSTALL_DIR" =~ $install_path_regex ]] || die "installation path contains characters outside the reviewed Docker mount and attestation grammar"
    [[ "$(cd -- "$INSTALL_DIR" && pwd -P)" == "$INSTALL_DIR" ]] || die "installation path must already be canonical"
    validate_installation_ancestor_chain "$INSTALL_DIR"
    INSTALL_ANCESTOR_IDENTITY="$(installation_ancestor_snapshot "$INSTALL_DIR")" \
        || die "could not capture installation path ancestor identity"
    assert_installation_ancestor_identity
    [[ "$DOCKER_BIN" == /* && -x "$DOCKER_BIN" ]] || die "Docker path is not an absolute executable"
    DOCKER_BIN="$(validate_privileged_executable Docker "$DOCKER_BIN")"
    [[ -z "${DOCKER_CONTEXT-}" ]] \
        || die "signed releases reject DOCKER_CONTEXT; select an exact daemon with DOCKER_HOST and reviewed TLS inputs"
    if [[ -z "${DOCKER_HOST-}" ]]; then
        run_bounded_capture 30 "Docker context selection probe" \
            /usr/bin/env -i LC_ALL=C LANG=C "HOME=${HOME:-/nonexistent}" \
            PATH=/usr/local/bin:/usr/bin:/bin \
            ${DOCKER_CONFIG:+"DOCKER_CONFIG=${DOCKER_CONFIG}"} \
            "$DOCKER_BIN" context show \
            || die "could not determine the Docker context selected for signed release verification"
        selected_context="$BOUNDED_CAPTURE_VALUE"
        [[ "$selected_context" == default ]] \
            || die "signed releases require the default Docker context or an explicit DOCKER_HOST"
    fi
    CURL_BIN="$(command -v curl)" || die "curl is required only for signed-release mode"
    [[ "$CURL_BIN" == /* && -x "$CURL_BIN" ]] || die "curl path is not an absolute executable"
    CURL_BIN="$(validate_privileged_executable curl "$CURL_BIN")"
    GIT_BIN="$(command -v git)" || die "git is required to attest the signed-release checkout"
    [[ "$GIT_BIN" == /* && -x "$GIT_BIN" ]] || die "git path is not an absolute executable"
    GIT_BIN="$(validate_privileged_executable git "$GIT_BIN")"
    SYNC_BIN="$(command -v sync)" || die "sync is required for crash-safe release evidence"
    [[ "$SYNC_BIN" == /* && -x "$SYNC_BIN" ]] || die "sync path is not an absolute executable"
    SYNC_BIN="$(validate_privileged_executable sync "$SYNC_BIN")"
    script_real="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/$(basename -- "${BASH_SOURCE[0]}")"
    [[ "$script_real" == "$INSTALL_DIR/deploy/release/consume-signed-release.sh" && -f "$script_real" && ! -L "$script_real" && "$(file_uid "$script_real")" == "$EUID" && "$(file_links "$script_real")" == "1" ]] || die "consumer must run from protected installer checkout"
    (( (8#$(file_mode "$script_real") & 8#022) == 0 )) || die "consumer must not be group- or world-writable"
    RUNTIME_JSON_PARSER="$INSTALL_DIR/deploy/runtime/compose-json.awk"
    validate_source_checkout
    trusted_root="$INSTALL_DIR/deploy/release/$TRUSTED_ROOT_NAME"
    validate_trusted_root "$trusted_root"

    DOCKER_ENV=(/usr/bin/env -i "LC_ALL=C" "HOME=/nonexistent" "PATH=/usr/local/bin:/usr/bin:/bin")
    for docker_variable in DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY SSL_CERT_DIR SSL_CERT_FILE; do [[ -n "${!docker_variable-}" ]] && DOCKER_ENV+=("${docker_variable}=${!docker_variable}"); done
    acquire_or_inherit_mutation_lock
    assert_mutation_lock_ownership
    attest_docker_daemon_platform
    INSTALLATION_PATH_DIGEST="$(sha256_text "$INSTALL_DIR")"
    release_identity_digest="$(sha256_text "${RELEASE_TAG}|${SOURCE_COMMIT}")"
    VERIFIER_NAME="backupsheep-release-verify-${INSTALLATION_PATH_DIGEST:0:12}-${release_identity_digest:0:12}"
    WORKFLOW_IDENTITY="https://github.com/${SOURCE_REPOSITORY}/${RELEASE_WORKFLOW}@refs/tags/${RELEASE_TAG}"
    EVIDENCE_DIR="${INSTALL_DIR}/.release-evidence"
    assert_mutation_lock_ownership
    assert_installation_ancestor_identity
    if [[ -e "$EVIDENCE_DIR" || -L "$EVIDENCE_DIR" ]]; then
        reconcile_evidence_refresh "$EVIDENCE_DIR"
        validate_persisted_evidence "$EVIDENCE_DIR"
    fi
    reconcile_installation_verifier_orphans
    reconcile_verifier_orphan
    cleanup_residues
    assert_installation_ancestor_identity
    STAGING_DIR="$(mktemp -d "${INSTALL_DIR}/.release-evidence.download.XXXXXXXX")"
    if [[ -z "$VERIFIER_DIR" ]]; then
        VERIFIER_DIR="$(mktemp -d "${INSTALL_DIR}/.release-evidence.verify.XXXXXXXX")"
    fi
    chmod 0700 "$STAGING_DIR"
    # The installation parent remains 0700. The public verifier inputs need a
    # traversable final bind source for the fixed non-root UID on Linux.
    chmod 0755 "$VERIFIER_DIR"
    assert_installation_ancestor_identity

    download_asset "$RELEASE_TAG" "$DESCRIPTOR_NAME" "$STAGING_DIR/$DESCRIPTOR_NAME" 2048
    download_asset "$RELEASE_TAG" "$BUNDLE_NAME" "$STAGING_DIR/$BUNDLE_NAME" 1048576
    download_asset "$RELEASE_TAG" "$MANIFEST_NAME" "$STAGING_DIR/$MANIFEST_NAME" 1048576
    assert_installation_ancestor_identity
    if [[ -n "$RECOVERY_VERIFIER_DIR" ]]; then
        cmp -s -- "$STAGING_DIR/$DESCRIPTOR_NAME" "$VERIFIER_DIR/$DESCRIPTOR_NAME" \
            && cmp -s -- "$STAGING_DIR/$BUNDLE_NAME" "$VERIFIER_DIR/$BUNDLE_NAME" \
            && cmp -s -- "$STAGING_DIR/$MANIFEST_NAME" "$VERIFIER_DIR/$MANIFEST_NAME" \
            && cmp -s -- "$trusted_root" "$VERIFIER_DIR/$TRUSTED_ROOT_NAME" \
            || die "unresolved verifier-create residue differs from immutable release inputs"
        validate_residue_dir "$VERIFIER_DIR"
    else
        install -m 0444 "$STAGING_DIR/$DESCRIPTOR_NAME" "$VERIFIER_DIR/$DESCRIPTOR_NAME"
        install -m 0444 "$STAGING_DIR/$BUNDLE_NAME" "$VERIFIER_DIR/$BUNDLE_NAME"
        install -m 0444 "$STAGING_DIR/$MANIFEST_NAME" "$VERIFIER_DIR/$MANIFEST_NAME"
        copy_trusted_root "$trusted_root" "$VERIFIER_DIR/$TRUSTED_ROOT_NAME"
    fi
    validate_descriptor "$VERIFIER_DIR/$DESCRIPTOR_NAME" "$RELEASE_TAG" "$SOURCE_COMMIT" "$VERIFIER_DIR/$MANIFEST_NAME"
    validate_signed_transition_metadata "$VERIFIER_DIR/$MANIFEST_NAME"
    APP_IMAGE="$(descriptor_value "$VERIFIER_DIR/$DESCRIPTOR_NAME" app_image)"
    POSTGRES_IMAGE="$(descriptor_value "$VERIFIER_DIR/$DESCRIPTOR_NAME" postgres_image)"
    EGRESS_IMAGE="$(descriptor_value "$VERIFIER_DIR/$DESCRIPTOR_NAME" egress_image)"
    RABBITMQ_IMAGE="$(descriptor_value "$VERIFIER_DIR/$DESCRIPTOR_NAME" rabbitmq_image)"
    RABBITMQ_UPGRADE_IMAGE="$(descriptor_value "$VERIFIER_DIR/$DESCRIPTOR_NAME" rabbitmq_upgrade_image)"
    VERIFIED_DESCRIPTOR_SHA256="$(sha256_file "$VERIFIER_DIR/$DESCRIPTOR_NAME")"
    VERIFIED_BUNDLE_SHA256="$(sha256_file "$VERIFIER_DIR/$BUNDLE_NAME")"
    VERIFIED_MANIFEST_SHA256="$(sha256_file "$VERIFIER_DIR/$MANIFEST_NAME")"
    assert_installation_ancestor_identity
    if run_bounded 30 "cached Cosign verifier lookup" docker_client image inspect "$COSIGN_IMAGE" >/dev/null 2>&1; then
        run_bounded 60 "cached Cosign verifier attestation" attest_cosign_image \
            || die "cached Cosign verifier failed exact attestation"
    fi
    run_bounded 600 "Cosign verifier pull" docker_client pull "$COSIGN_IMAGE" >/dev/null || die "could not pull pinned Cosign verifier"
    run_bounded 60 "Cosign verifier attestation" attest_cosign_image \
        || die "Cosign verifier failed exact attestation"
    verify_signatures
    write_signature_verification_receipt
    attest_verified_release_inputs

    for image_tuple in "app|$APP_IMAGE" "postgres|$POSTGRES_IMAGE" "egress|$EGRESS_IMAGE" \
        "rabbitmq|$RABBITMQ_IMAGE" "rabbitmq_upgrade|$RABBITMQ_UPGRADE_IMAGE"; do
        role="${image_tuple%%|*}"; image_ref="${image_tuple#*|}"
        if run_bounded 30 "cached ${role} lookup" docker_client image inspect "$image_ref" >/dev/null 2>&1; then
            : # A cached image is still re-attested after all exact pulls below.
        fi
        run_bounded 600 "${role} digest pull" docker_client pull "$image_ref" >/dev/null || die "could not pull verified ${role} digest"
    done
    : > "$STAGING_DIR/local-images.txt"
    for image_tuple in "app|$APP_IMAGE" "postgres|$POSTGRES_IMAGE" "egress|$EGRESS_IMAGE" \
        "rabbitmq|$RABBITMQ_IMAGE" "rabbitmq_upgrade|$RABBITMQ_UPGRADE_IMAGE"; do
        run_bounded 60 "${image_tuple%%|*} release image attestation" \
            attest_release_image "${image_tuple%%|*}" "${image_tuple#*|}" \
            || die "${image_tuple%%|*} release image failed exact attestation"
    done
    run_bounded_capture 30 "Cosign verifier image receipt" docker_client image inspect \
        --format '{{.Id}}' "$COSIGN_IMAGE" \
        || die "could not capture Cosign verifier image receipt"
    cosign_id="$BOUNDED_CAPTURE_VALUE"
    printf 'cosign_image_id=%s\n' "$cosign_id" >> "$STAGING_DIR/local-images.txt"
    install -m 0600 "$VERIFIER_DIR/$TRUSTED_ROOT_NAME" "$STAGING_DIR/$TRUSTED_ROOT_NAME" \
        || die "could not retain the exact trusted root with signed release evidence"
    chmod 0600 "$STAGING_DIR"/*
    validate_local_image_receipt "$STAGING_DIR/local-images.txt"
    attest_verified_release_inputs
    durable_sync
    assert_installation_ancestor_identity

    if [[ -d "$EVIDENCE_DIR" ]]; then
        for role in "$DESCRIPTOR_NAME" "$BUNDLE_NAME" "$MANIFEST_NAME" "$TRUSTED_ROOT_NAME" "$VERIFICATION_RECEIPT_NAME"; do cmp -s -- "$STAGING_DIR/$role" "$EVIDENCE_DIR/$role" || die "persisted release evidence conflicts with requested release"; done
        # The receipt is an expected-current witness, not a cache hint. A
        # different local image ID (including the bootstrap verifier) requires
        # an explicit journaled release transition instead of silent refresh.
        cmp -s -- "$STAGING_DIR/local-images.txt" "$EVIDENCE_DIR/local-images.txt" \
            || die "persisted local image receipt conflicts with attested images"
    else
        assert_mutation_lock_ownership
        assert_installation_ancestor_identity
        attest_verified_release_inputs
        publish_fresh_evidence "$STAGING_DIR" "$EVIDENCE_DIR"
        STAGING_DIR=""
        durable_sync
        assert_mutation_lock_ownership
        assert_installation_ancestor_identity
    fi
    assert_mutation_lock_ownership
    printf 'Verified signed release %s at source commit %s.\n' "$RELEASE_TAG" "$SOURCE_COMMIT"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
