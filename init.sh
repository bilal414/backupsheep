#!/bin/sh
# Entrypoint shared by the web, migration, Celery worker, and Beat services.
# Static assets are collected at image-build time, so startup is compatible with
# a read-only root filesystem. Schema migrations remain a one-shot Compose service.
set -eu

# Backup archives, database dumps, SSH material, and transient credentials are private.
# Every image command passes through this entrypoint, including Compose workers/migrate.
umask 077

fail() {
  printf '%s\n' "BackupSheep container startup refused: $*" >&2
  exit 1
}

# The stock namespace policy is the only outbound mediation layer. A process-level
# proxy or alternate CA hook could redirect credentials before application controls
# see the destination, so reject hand-written overrides and then remove the hooks.
for ambient_transport_hook in \
  "${HTTP_PROXY:-}" \
  "${HTTPS_PROXY:-}" \
  "${ALL_PROXY:-}" \
  "${NO_PROXY:-}" \
  "${http_proxy:-}" \
  "${https_proxy:-}" \
  "${all_proxy:-}" \
  "${no_proxy:-}" \
  "${REQUESTS_CA_BUNDLE:-}" \
  "${CURL_CA_BUNDLE:-}"; do
  [ -z "$ambient_transport_hook" ] \
    || fail "ambient proxy and CA-bundle hooks are forbidden."
done

# Do not inherit executable-search or interpreter startup hooks. Runtime
# configuration is data; it must not silently become pre-entrypoint code.
unset \
  BASH_ENV \
  ENV \
  CDPATH \
  GLOBIGNORE \
  LD_AUDIT \
  LD_LIBRARY_PATH \
  LD_PRELOAD \
  PYTHONHOME \
  PYTHONINSPECT \
  PYTHONSTARTUP \
  SSLKEYLOGFILE \
  HTTP_PROXY \
  HTTPS_PROXY \
  ALL_PROXY \
  NO_PROXY \
  http_proxy \
  https_proxy \
  all_proxy \
  no_proxy \
  REQUESTS_CA_BUNDLE \
  CURL_CA_BUNDLE \
  ambient_transport_hook
PATH='/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin'
PYTHONPATH='/code'
PYTHONNOUSERSITE='1'
HOME='/run/backupsheep'
XDG_CACHE_HOME='/run/backupsheep/cache'
XDG_CONFIG_HOME='/run/backupsheep/config'
XDG_RUNTIME_DIR='/run/backupsheep'
TMPDIR='/tmp'
export \
  PATH \
  PYTHONPATH \
  PYTHONNOUSERSITE \
  HOME \
  XDG_CACHE_HOME \
  XDG_CONFIG_HOME \
  XDG_RUNTIME_DIR \
  TMPDIR

[ "${DJANGO_SETTINGS_MODULE:-}" = 'backupsheep.settings' ] \
  || fail "DJANGO_SETTINGS_MODULE must select backupsheep.settings."
[ -z "${BACKUPSHEEP_SECRETS:-}" ] \
  || fail "BACKUPSHEEP_SECRETS is not accepted by the stock Docker runtime."

# Compose assigns one immutable identity to each trust lane. Failing closed catches
# a user override or accidental shared UID before credentials or backup data become
# reachable. Each source lane has its own transfer writer/reader groups; storage
# receives only the two reader groups and cannot enumerate either transfer root.
runtime_role="${BACKUPSHEEP_RUNTIME_ROLE:-}"
database_transfer_writer_gid='10989'
database_transfer_reader_gid='10990'
files_transfer_writer_gid='10991'
files_transfer_reader_gid='10992'
restore_writer_gid='10995'
restore_database_reader_gid='10994'
restore_files_reader_gid='10993'
requires_database_transfer_writer='no'
requires_database_transfer_reader='no'
requires_files_transfer_writer='no'
requires_files_transfer_reader='no'
requires_restore_writer='no'
requires_restore_database_reader='no'
requires_restore_files_reader='no'
case "$runtime_role" in
  web) expected_uid='10001'; expected_gid='10001' ;;
  database)
    expected_uid='10002'; expected_gid='10002'
    requires_database_transfer_writer='yes'
    requires_database_transfer_reader='yes'
    requires_restore_database_reader='yes'
    ;;
  files)
    expected_uid='10003'; expected_gid='10003'
    requires_files_transfer_writer='yes'
    requires_files_transfer_reader='yes'
    requires_restore_files_reader='yes'
    ;;
  storage)
    expected_uid='10004'; expected_gid='10004'
    requires_database_transfer_reader='yes'
    requires_files_transfer_reader='yes'
    requires_restore_writer='yes'
    requires_restore_database_reader='yes'
    requires_restore_files_reader='yes'
    ;;
  logs) expected_uid='10005'; expected_gid='10005' ;;
  beat) expected_uid='10006'; expected_gid='10006' ;;
  migration) expected_uid='10007'; expected_gid='10007' ;;
  cloud) expected_uid='10008'; expected_gid='10008' ;;
  *) fail "BACKUPSHEEP_RUNTIME_ROLE is missing or unsupported." ;;
esac
[ "$(id -u)" = "$expected_uid" ] || fail "expected UID $expected_uid."
[ "$(id -g)" = "$expected_gid" ] || fail "expected GID $expected_gid."

has_database_transfer_writer='no'
has_database_transfer_reader='no'
has_files_transfer_writer='no'
has_files_transfer_reader='no'
has_restore_writer='no'
has_restore_database_reader='no'
has_restore_files_reader='no'
for runtime_gid in $(id -G); do
  case "$runtime_gid" in
    "$expected_gid") ;;
    "$database_transfer_writer_gid") has_database_transfer_writer='yes' ;;
    "$database_transfer_reader_gid") has_database_transfer_reader='yes' ;;
    "$files_transfer_writer_gid") has_files_transfer_writer='yes' ;;
    "$files_transfer_reader_gid") has_files_transfer_reader='yes' ;;
    "$restore_writer_gid") has_restore_writer='yes' ;;
    "$restore_database_reader_gid") has_restore_database_reader='yes' ;;
    "$restore_files_reader_gid") has_restore_files_reader='yes' ;;
    *) fail "runtime identity has an unreviewed supplementary group." ;;
  esac
done
[ "$has_database_transfer_writer" = "$requires_database_transfer_writer" ] \
  || fail "the $runtime_role role has an unsafe database-transfer writer group."
[ "$has_database_transfer_reader" = "$requires_database_transfer_reader" ] \
  || fail "the $runtime_role role has an unsafe database-transfer reader group."
[ "$has_files_transfer_writer" = "$requires_files_transfer_writer" ] \
  || fail "the $runtime_role role has an unsafe files-transfer writer group."
[ "$has_files_transfer_reader" = "$requires_files_transfer_reader" ] \
  || fail "the $runtime_role role has an unsafe files-transfer reader group."
[ "$has_restore_writer" = "$requires_restore_writer" ] \
  || fail "the $runtime_role role has an unsafe restore writer-group assignment."
[ "$has_restore_database_reader" = "$requires_restore_database_reader" ] \
  || fail "the $runtime_role role has an unsafe database-restore reader-group assignment."
[ "$has_restore_files_reader" = "$requires_restore_files_reader" ] \
  || fail "the $runtime_role role has an unsafe files-restore reader-group assignment."

# Compose explicitly allowlists deployment-wide OAuth/email configuration and restores
# a family only for its actual consumer. Enforce that contract again inside the image
# so a hand-written override cannot silently give a compromised worker another key.
# Values are never printed on failure.
reject_credential_group() {
  rejected_group="$1"
  shift
  for rejected_value in "$@"; do
    [ -z "$rejected_value" ] \
      || fail "$runtime_role must not receive $rejected_group credentials."
  done
  unset rejected_group rejected_value
}

allow_log_archive_credentials='no'
allow_notification_credentials='no'
allow_cloud_provider_credentials='no'
allow_basecamp_credentials='no'
allow_storage_provider_credentials='no'
case "$runtime_role" in
  web)
    allow_log_archive_credentials='yes'
    allow_notification_credentials='yes'
    allow_cloud_provider_credentials='yes'
    allow_basecamp_credentials='yes'
    allow_storage_provider_credentials='yes'
    ;;
  cloud) allow_cloud_provider_credentials='yes' ;;
  files) allow_basecamp_credentials='yes' ;;
  storage) allow_storage_provider_credentials='yes' ;;
  logs) allow_notification_credentials='yes' ;;
esac

if [ "$allow_log_archive_credentials" != 'yes' ]; then
  reject_credential_group 'log-archive' \
    "${S3_ACCESS_KEY_ID:-}" \
    "${S3_SECRET_ACCESS_KEY:-}" \
    "${S3_STORAGE_BUCKET_NAME:-}" \
    "${S3_ENDPOINT_URL:-}" \
    "${S3_SIGNATURE_VERSION:-}" \
    "${AWS_S3_ACCESS_KEY:-}" \
    "${AWS_S3_SECRET_ACCESS_KEY:-}" \
    "${AWS_S3_LOGS_BUCKET:-}" \
    "${AWS_S3_LOGS_ENDPOINT:-}" \
    "${AWS_S3_LOGS_REGION:-}" \
    "${LOGS_S3_ACCESS_KEY_ID:-}" \
    "${LOGS_S3_SECRET_ACCESS_KEY:-}" \
    "${LOGS_S3_BUCKET:-}" \
    "${LOGS_S3_ENDPOINT:-}"
fi
if [ "$allow_notification_credentials" != 'yes' ]; then
  reject_credential_group 'email/notification' \
    "${POSTMARK_API_KEY:-}" \
    "${POSTMARK_DOMAIN:-}" \
    "${POSTMARK_EMAIL:-}" \
    "${POSTMARK_API_URL:-}" \
    "${SES_REGION_NAME:-}" \
    "${SES_REGION_ENDPOINT:-}" \
    "${SES_ACCESS_KEY_ID:-}" \
    "${SES_SECRET_ACCESS_KEY:-}" \
    "${AWS_SES_REGION_NAME:-}" \
    "${AWS_SES_REGION_ENDPOINT:-}" \
    "${AWS_SES_ACCESS_KEY_ID:-}" \
    "${AWS_SES_SECRET_ACCESS_KEY:-}" \
    "${MAILGUN_DOMAIN:-}" \
    "${MAILGUN_EMAIL:-}" \
    "${MAILGUN_API_KEY:-}" \
    "${MAILGUN_API_URL:-}" \
    "${EMAIL_PROVIDER:-}" \
    "${SLACK_TOKEN_URL:-}" \
    "${SLACK_CLIENT_ID:-}" \
    "${SLACK_CLIENT_SECRET:-}" \
    "${TELEGRAM_BOT_KEY:-}"
fi
if [ "$allow_cloud_provider_credentials" != 'yes' ]; then
  reject_credential_group 'cloud-provider application' \
    "${DIGITALOCEAN_APP_CLIENT_ID:-}" \
    "${DIGITALOCEAN_APP_CLIENT_SECRET:-}" \
    "${OVH_CA_APP_KEY:-}" \
    "${OVH_CA_APP_SECRET:-}" \
    "${OVH_EU_APP_KEY:-}" \
    "${OVH_EU_APP_SECRET:-}" \
    "${OVH_US_APP_KEY:-}" \
    "${OVH_US_APP_SECRET:-}"
fi
if [ "$allow_basecamp_credentials" != 'yes' ]; then
  reject_credential_group 'Basecamp application' \
    "${BASECAMP_CLIENT_ID:-}" \
    "${BASECAMP_CLIENT_SECRET:-}"
fi
if [ "$allow_storage_provider_credentials" != 'yes' ]; then
  reject_credential_group 'storage-provider application' \
    "${DROPBOX_APP_KEY:-}" \
    "${DROPBOX_APP_SECRET:-}" \
    "${PCLOUD_CLIENT_ID:-}" \
    "${PCLOUD_CLIENT_SECRET:-}" \
    "${MS_CLIENT_ID:-}" \
    "${MS_OBJECT_ID:-}" \
    "${MS_TENANT_ID:-}" \
    "${MS_APPLICATION_ID:-}" \
    "${MS_CLIENT_SECRET_VALUE:-}" \
    "${MS_CLIENT_SECRET_ID:-}" \
    "${GOOGLE_CLIENT_ID:-}" \
    "${GOOGLE_CLIENT_SECRET:-}"
fi
unset \
  allow_log_archive_credentials \
  allow_notification_credentials \
  allow_cloud_provider_credentials \
  allow_basecamp_credentials \
  allow_storage_provider_credentials

# The stock enterprise path uses distinct file-backed AWS credentials for the
# database and files source/restore lanes. Ambient environment, web identity,
# container metadata and SDK endpoint overrides would either leak decrypt authority
# to unrelated roles or bypass the reviewed KMS endpoint policy, so reject them.
for ambient_aws_value in \
  "${AWS_ACCESS_KEY_ID:-}" \
  "${AWS_SECRET_ACCESS_KEY:-}" \
  "${AWS_SESSION_TOKEN:-}" \
  "${AWS_SECURITY_TOKEN:-}" \
  "${AWS_PROFILE:-}" \
  "${AWS_DEFAULT_PROFILE:-}" \
  "${AWS_CONFIG_FILE:-}" \
  "${AWS_CA_BUNDLE:-}" \
  "${AWS_METADATA_SERVICE_ENDPOINT:-}" \
  "${AWS_METADATA_SERVICE_ENDPOINT_MODE:-}" \
  "${BOTO_CONFIG:-}" \
  "${AWS_WEB_IDENTITY_TOKEN_FILE:-}" \
  "${AWS_ROLE_ARN:-}" \
  "${AWS_ROLE_SESSION_NAME:-}" \
  "${AWS_CONTAINER_CREDENTIALS_FULL_URI:-}" \
  "${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:-}" \
  "${AWS_CONTAINER_AUTHORIZATION_TOKEN:-}" \
  "${AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE:-}" \
  "${AWS_ENDPOINT_URL:-}" \
  "${AWS_ENDPOINT_URL_KMS:-}"; do
  [ -z "$ambient_aws_value" ] \
    || fail "ambient AWS credentials, roles, metadata, and endpoint overrides are forbidden."
done
[ "${AWS_EC2_METADATA_DISABLED:-}" = true ] \
  || fail "AWS instance-metadata credentials must be disabled."
[ "${AWS_EC2_METADATA_V1_DISABLED:-}" = true ] \
  || fail "AWS instance-metadata v1 must be disabled."
[ "${AWS_IGNORE_CONFIGURED_ENDPOINT_URLS:-}" = true ] \
  || fail "AWS SDK endpoint environment overrides must be disabled."
database_kms_credentials='/run/secrets/artifact_kms_database_aws_credentials'
files_kms_credentials='/run/secrets/artifact_kms_files_aws_credentials'
case "$runtime_role" in
  database)
    artifact_kms_credentials="$database_kms_credentials"
    [ ! -e "$files_kms_credentials" ] \
      || fail "database must not mount the files artifact-KMS credential secret."
    [ "${AWS_SHARED_CREDENTIALS_FILE:-}" = "$artifact_kms_credentials" ] \
      || fail "the database lane requires its reviewed artifact-KMS credential file."
    [ -f "$artifact_kms_credentials" ] && [ ! -L "$artifact_kms_credentials" ] \
      || fail "the artifact-KMS credential secret must be a regular file."
    [ "$(stat -c '%u:%g:%a:%h' "$artifact_kms_credentials")" = '0:0:444:1' ] \
      || fail "the artifact-KMS credential secret metadata is unsafe."
    ;;
  files)
    artifact_kms_credentials="$files_kms_credentials"
    [ ! -e "$database_kms_credentials" ] \
      || fail "files must not mount the database artifact-KMS credential secret."
    [ "${AWS_SHARED_CREDENTIALS_FILE:-}" = "$artifact_kms_credentials" ] \
      || fail "the files lane requires its reviewed artifact-KMS credential file."
    [ -f "$artifact_kms_credentials" ] && [ ! -L "$artifact_kms_credentials" ] \
      || fail "the artifact-KMS credential secret must be a regular file."
    [ "$(stat -c '%u:%g:%a:%h' "$artifact_kms_credentials")" = '0:0:444:1' ] \
      || fail "the artifact-KMS credential secret metadata is unsafe."
    ;;
  *)
    [ -z "${AWS_SHARED_CREDENTIALS_FILE:-}" ] \
      || fail "$runtime_role must not receive artifact-KMS credentials."
    [ ! -e "$database_kms_credentials" ] && [ ! -e "$files_kms_credentials" ] \
      || fail "$runtime_role must not mount an artifact-KMS credential secret."
    ;;
esac

# The image is intentionally unusable under a weakened `docker run`. These checks
# make the Compose isolation contract part of container startup instead of relying
# only on operator discipline. A Docker-daemon administrator can always replace the
# image or entrypoint; this gate protects against missing/partial runtime flags.
status_value() {
  key="$1"
  awk -v wanted="$key:" '$1 == wanted { print $2; exit }' /proc/self/status
}

require_all_zero() {
  name="$1"
  value="$(status_value "$name")"
  case "$value" in
    ''|*[!0]*) fail "$name must contain only zeroes." ;;
  esac
}

for capability_set in CapInh CapPrm CapEff CapBnd CapAmb; do
  require_all_zero "$capability_set"
done
[ "$(status_value NoNewPrivs)" = '1' ] \
  || fail "no-new-privileges must be enabled."
[ "$(status_value Seccomp)" = '2' ] \
  || fail "the Docker seccomp filter must be active."

pid_one_comm=''
IFS= read -r pid_one_comm < /proc/1/comm || true
[ "$pid_one_comm" = 'docker-init' ] \
  || fail "Docker init and a private PID namespace are required."
[ ! -e /var/run/docker.sock ] && [ ! -e /run/docker.sock ] \
  || fail "the Docker control socket must not be mounted."

require_mount() {
  wanted_path="$1"
  wanted_type="$2"
  shift 2
  while IFS=' ' read -r _source mount_path filesystem options _rest; do
    [ "$mount_path" = "$wanted_path" ] || continue
    if [ "$wanted_type" != 'any' ] && [ "$filesystem" != "$wanted_type" ]; then
      fail "$wanted_path must use a $wanted_type filesystem."
    fi
    for required_option in "$@"; do
      case ",$options," in
        *",$required_option,"*) ;;
        *) fail "$wanted_path mount is missing $required_option." ;;
      esac
    done
    return 0
  done < /proc/mounts
  fail "$wanted_path is not a dedicated mount."
}

require_mount / any ro
require_mount /tmp tmpfs rw noexec nosuid nodev
require_mount /run/backupsheep tmpfs rw noexec nosuid nodev

reject_dedicated_mount() {
  rejected_path="$1"
  while IFS=' ' read -r _source mount_path _filesystem _options _rest; do
    [ "$mount_path" != "$rejected_path" ] \
      || fail "$runtime_role must not mount $rejected_path."
  done < /proc/mounts
}

verify_owned_directory() {
  directory="$1"
  owner="$2"
  group="$3"
  mode="$4"
  [ ! -L "$directory" ] && [ -d "$directory" ] \
    || fail "$directory must be a real directory."
  [ "$(stat -c '%u:%g:%a' "$directory")" = "$owner:$group:$mode" ] \
    || fail "$directory has unsafe ownership or permissions."
}

case "$runtime_role" in
  database)
    require_mount /code/_storage any rw
    require_mount /var/lib/backupsheep/transfer/database any rw
    require_mount /var/lib/backupsheep/restore-transfer any ro
    verify_owned_directory /code/_storage "$expected_uid" "$expected_gid" 700
    verify_owned_directory /var/lib/backupsheep/transfer/database 0 "$database_transfer_writer_gid" 3771
    verify_owned_directory /var/lib/backupsheep/restore-transfer 0 "$restore_writer_gid" 3771
    reject_dedicated_mount /var/lib/backupsheep/ssh-trust
    reject_dedicated_mount /var/lib/backupsheep/transfer/files
    reject_dedicated_mount /backups
    ;;
  files)
    require_mount /code/_storage any rw
    require_mount /var/lib/backupsheep/transfer/files any rw
    require_mount /var/lib/backupsheep/restore-transfer any ro
    verify_owned_directory /code/_storage "$expected_uid" "$expected_gid" 700
    verify_owned_directory /var/lib/backupsheep/transfer/files 0 "$files_transfer_writer_gid" 3771
    verify_owned_directory /var/lib/backupsheep/restore-transfer 0 "$restore_writer_gid" 3771
    reject_dedicated_mount /var/lib/backupsheep/ssh-trust
    reject_dedicated_mount /var/lib/backupsheep/transfer/database
    reject_dedicated_mount /backups
    ;;
  storage)
    require_mount /code/_storage any rw
    require_mount /var/lib/backupsheep/transfer/database any ro
    require_mount /var/lib/backupsheep/transfer/files any ro
    require_mount /var/lib/backupsheep/restore-transfer any rw
    require_mount /backups any rw
    verify_owned_directory /code/_storage "$expected_uid" "$expected_gid" 700
    verify_owned_directory /var/lib/backupsheep/transfer/database 0 "$database_transfer_writer_gid" 3771
    verify_owned_directory /var/lib/backupsheep/transfer/files 0 "$files_transfer_writer_gid" 3771
    verify_owned_directory /var/lib/backupsheep/restore-transfer 0 "$restore_writer_gid" 3771
    verify_owned_directory /backups "$expected_uid" "$expected_gid" 700
    reject_dedicated_mount /var/lib/backupsheep/ssh-trust
    ;;
  web)
    reject_dedicated_mount /var/lib/backupsheep/ssh-trust
    reject_dedicated_mount /code/_storage
    reject_dedicated_mount /var/lib/backupsheep/transfer/database
    reject_dedicated_mount /var/lib/backupsheep/transfer/files
    reject_dedicated_mount /var/lib/backupsheep/restore-transfer
    reject_dedicated_mount /backups
    ;;
  *)
    reject_dedicated_mount /code/_storage
    reject_dedicated_mount /var/lib/backupsheep/transfer/database
    reject_dedicated_mount /var/lib/backupsheep/transfer/files
    reject_dedicated_mount /var/lib/backupsheep/restore-transfer
    reject_dedicated_mount /backups
    reject_dedicated_mount /var/lib/backupsheep/ssh-trust
    ;;
esac

# A Compose file can look bounded while the selected daemon silently runs without
# controller support, or an override can remove the limits. Verify the active
# cgroup, not only the YAML. Every application role has finite PID, memory, and CPU
# limits; an unlimited controller is a startup failure.
require_finite_cgroup_value() {
  label="$1"
  value="$2"
  case "$value" in
    ''|max|-1|0|*[!0-9]*) fail "$label cgroup limit is missing or unlimited." ;;
  esac
}

require_cgroup_value_at_most() {
  label="$1"
  value="$2"
  maximum="$3"
  awk -v observed="$value" -v ceiling="$maximum" \
    'BEGIN { exit !(observed <= ceiling) }' \
    || fail "$label cgroup limit exceeds the immutable container ceiling."
}

# These are hard safety ceilings, not sizing recommendations. Operators may tune
# each Compose role below them, but a poisoned .env cannot turn a syntactically
# finite value into a host-sized pseudo-limit. Backup payloads are streamed to
# disk and no single application process requires these generous maxima.
max_pids='4096'
max_memory_bytes='34359738368'
max_cpu_cores='32'

if [ -r /sys/fs/cgroup/cgroup.controllers ]; then
  pids_limit="$(cat /sys/fs/cgroup/pids.max 2>/dev/null || true)"
  memory_limit="$(cat /sys/fs/cgroup/memory.max 2>/dev/null || true)"
  cpu_limit=''
  cpu_period=''
  if [ -r /sys/fs/cgroup/cpu.max ]; then
    IFS=' ' read -r cpu_limit cpu_period < /sys/fs/cgroup/cpu.max || true
  fi
  require_finite_cgroup_value 'PID' "$pids_limit"
  require_finite_cgroup_value 'memory' "$memory_limit"
  require_finite_cgroup_value 'CPU quota' "$cpu_limit"
  require_finite_cgroup_value 'CPU period' "$cpu_period"
  require_cgroup_value_at_most 'PID' "$pids_limit" "$max_pids"
  require_cgroup_value_at_most 'memory' "$memory_limit" "$max_memory_bytes"
  awk -v quota="$cpu_limit" -v period="$cpu_period" -v ceiling="$max_cpu_cores" \
    'BEGIN { exit !(quota / period <= ceiling) }' \
    || fail "CPU cgroup limit exceeds the immutable container ceiling."
else
  pids_limit=''
  memory_limit=''
  cpu_limit=''
  cpu_period=''
  for candidate in \
    /sys/fs/cgroup/pids/pids.max \
    /sys/fs/cgroup/pids.max; do
    [ -r "$candidate" ] || continue
    pids_limit="$(cat "$candidate")"
    break
  done
  for candidate in \
    /sys/fs/cgroup/memory/memory.limit_in_bytes \
    /sys/fs/cgroup/memory.limit_in_bytes; do
    [ -r "$candidate" ] || continue
    memory_limit="$(cat "$candidate")"
    break
  done
  for candidate in \
    /sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us \
    /sys/fs/cgroup/cpu/cpu.cfs_quota_us \
    /sys/fs/cgroup/cpu.cfs_quota_us; do
    [ -r "$candidate" ] || continue
    cpu_limit="$(cat "$candidate")"
    break
  done
  for candidate in \
    /sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us \
    /sys/fs/cgroup/cpu/cpu.cfs_period_us \
    /sys/fs/cgroup/cpu.cfs_period_us; do
    [ -r "$candidate" ] || continue
    cpu_period="$(cat "$candidate")"
    break
  done
  require_finite_cgroup_value 'PID' "$pids_limit"
  require_finite_cgroup_value 'memory' "$memory_limit"
  require_finite_cgroup_value 'CPU quota' "$cpu_limit"
  require_finite_cgroup_value 'CPU period' "$cpu_period"
  require_cgroup_value_at_most 'PID' "$pids_limit" "$max_pids"
  require_cgroup_value_at_most 'memory' "$memory_limit" "$max_memory_bytes"
  awk -v quota="$cpu_limit" -v period="$cpu_period" -v ceiling="$max_cpu_cores" \
    'BEGIN { exit !(quota / period <= ceiling) }' \
    || fail "CPU cgroup limit exceeds the immutable container ceiling."
fi

# Core files can contain database/provider credentials; never leave process dumps.
ulimit -c 0 || fail "could not disable core dumps."

prepare_private_dir() {
  directory="$1"
  [ ! -L "$directory" ] || fail "$directory must not be a symbolic link."
  [ -d "$directory" ] || fail "$directory is missing; mount its tmpfs first."
  [ "$(stat -c '%u:%g:%a' "$directory")" = "$expected_uid:$expected_gid:700" ] \
    || fail "$directory must be owned by $expected_uid:$expected_gid at mode 0700."
  [ -w "$directory" ] || fail "$directory is not writable."
}

prepare_private_dir /run/backupsheep
[ ! -L /tmp ] || fail "/tmp must not be a symbolic link."
[ -d /tmp ] && [ -w /tmp ] || fail "/tmp must be a writable tmpfs."

# A container restart can preserve its tmpfs contents. Never let a readiness witness
# from the previous Celery process satisfy the new process's healthcheck. The
# authenticated worker_ready signal recreates this file atomically only after the new
# AMQP consumer is live; PID 1 exiting still stops the container.
case "$runtime_role" in
  cloud|database|files|storage|logs)
    worker_ready_file=/run/backupsheep/celery-ready
    if [ -e "$worker_ready_file" ] || [ -L "$worker_ready_file" ]; then
      [ ! -d "$worker_ready_file" ] \
        || fail "the stale worker readiness witness is not a file."
      rm -f -- "$worker_ready_file" \
        || fail "could not remove the stale worker readiness witness."
    fi
    # A crash between the exclusive temporary-file create and atomic replace can
    # also leave the PID-named staging file in this private tmpfs. Clear only that
    # fixed prefix so a restarted process cannot be denied readiness indefinitely.
    for worker_ready_temporary in /run/backupsheep/.celery-ready.*; do
      if [ -e "$worker_ready_temporary" ] || [ -L "$worker_ready_temporary" ]; then
        [ ! -d "$worker_ready_temporary" ] \
          || fail "a stale worker readiness staging path is not a file."
        rm -f -- "$worker_ready_temporary" \
          || fail "could not remove a stale worker readiness staging file."
      fi
    done
    unset worker_ready_file worker_ready_temporary
    ;;
esac

mkdir -p \
  "$XDG_CACHE_HOME" \
  "$XDG_CONFIG_HOME" \
  /run/backupsheep/gunicorn \
  /run/backupsheep/ssh
chmod 0700 \
  "$XDG_CACHE_HOME" \
  "$XDG_CONFIG_HOME" \
  /run/backupsheep/gunicorn \
  /run/backupsheep/ssh

# Docker bind-mounts secret sources as root-owned mode 0444. Copy only this source
# lane's Ed25519 identity into its private tmpfs and expose the 0600 copy to SSH.
# Public values are normalized to exactly "ssh-ed25519 base64" so comments can
# never become shell/UI injection material.
canonical_managed_public_identity() {
  raw_public_key="$1"
  setting_name="$2"
  [ -n "$raw_public_key" ] || return 0
  identity="$({
    printf '%s\n' "$raw_public_key" \
      | awk '
          NR == 1 && (NF == 2 || NF == 3) {
            if ($1 != "ssh-ed25519" || $2 !~ /^[A-Za-z0-9+\/=]+$/) exit 1
            print $1 " " $2
            next
          }
          { exit 1 }
          END { if (NR != 1) exit 1 }
        '
  })" || fail "$setting_name must contain one Ed25519 OpenSSH public key."
  key_description="$(printf '%s\n' "$identity" | ssh-keygen -lf - 2>/dev/null)" \
    || fail "$setting_name contains a malformed Ed25519 public key."
  case "$key_description" in
    *'(ED25519)') ;;
    *) fail "$setting_name must contain an Ed25519 public key." ;;
  esac
  printf '%s' "$identity"
}

database_public_identity="$(canonical_managed_public_identity \
  "${SSH_MANAGED_DATABASE_PUBLIC_KEY:-}" SSH_MANAGED_DATABASE_PUBLIC_KEY)"
files_public_identity="$(canonical_managed_public_identity \
  "${SSH_MANAGED_FILES_PUBLIC_KEY:-}" SSH_MANAGED_FILES_PUBLIC_KEY)"
if [ -n "$database_public_identity" ] || [ -n "$files_public_identity" ]; then
  [ -n "$database_public_identity" ] && [ -n "$files_public_identity" ] \
    || fail "both managed SSH lane public keys must be configured together."
  [ "$database_public_identity" != "$files_public_identity" ] \
    || fail "database and files managed SSH identities must be different."
fi
SSH_MANAGED_DATABASE_PUBLIC_KEY="$database_public_identity"
SSH_MANAGED_FILES_PUBLIC_KEY="$files_public_identity"
SSH_MANAGED_PUBLIC_KEY=''
export SSH_MANAGED_DATABASE_PUBLIC_KEY SSH_MANAGED_FILES_PUBLIC_KEY SSH_MANAGED_PUBLIC_KEY

managed_key_source=''
managed_public_identity=''
case "$runtime_role" in
  database)
    managed_key_source='/run/secrets/ssh_managed_database_private_key'
    managed_public_identity="$database_public_identity"
    ;;
  files)
    managed_key_source='/run/secrets/ssh_managed_files_private_key'
    managed_public_identity="$files_public_identity"
    ;;
esac
managed_key_target='/run/backupsheep/ssh/managed_private_key'
SSH_MANAGED_PRIVATE_KEY_PATH=''
if [ -n "$managed_key_source" ] && [ -e "$managed_key_source" ]; then
  [ -f "$managed_key_source" ] && [ ! -L "$managed_key_source" ] \
    || fail "the managed SSH private-key secret must be a regular file."
  managed_key_size="$(wc -c < "$managed_key_source")"
  case "$managed_key_size" in
    ''|*[!0-9]*) fail "could not measure the managed SSH private-key secret." ;;
  esac
  [ "$managed_key_size" -le 65536 ] \
    || fail "the managed SSH private-key secret exceeds 64 KiB."
  if [ "$managed_key_size" -gt 0 ]; then
    [ -n "$managed_public_identity" ] \
      || fail "a managed SSH private key requires its lane public key."
    cp "$managed_key_source" "$managed_key_target" \
      || fail "could not stage the managed SSH private key."
    chmod 0600 "$managed_key_target" \
      || fail "could not protect the managed SSH private key."
    derived_public_identity="$(ssh-keygen -y -P '' -f "$managed_key_target" 2>/dev/null)" \
      || fail "the managed SSH private-key secret is invalid or passphrase-protected."
    case "$derived_public_identity" in
      ssh-ed25519' '*) ;;
      *) fail "the managed SSH private-key secret must be Ed25519." ;;
    esac
    [ "$derived_public_identity" = "$managed_public_identity" ] \
      || fail "the managed SSH private key does not match its lane public key."
    SSH_MANAGED_PRIVATE_KEY_PATH="$managed_key_target"
  fi
fi
case "$runtime_role" in
  database|files)
    [ -z "$managed_public_identity" ] || [ -n "$SSH_MANAGED_PRIVATE_KEY_PATH" ] \
      || fail "the lane public key requires a non-empty managed key secret in this worker."
    ;;
esac
export SSH_MANAGED_PRIVATE_KEY_PATH

# Compose dependency ordering is evaluated when `compose up` runs, but Docker may
# later auto-restart a long-running service after a daemon/host restart. Re-run the
# application-level deployment gate before every web/worker/Beat process so those
# restarts still validate settings, secrets, migrations, database authentication,
# and a non-consuming broker connection. Migration and the gate itself are the two
# deliberate one-shot exceptions.
run_deployment_preflight='yes'
if [ "$#" -ge 3 ] \
  && [ "$1" = 'python' ] \
  && [ "$2" = 'manage.py' ]; then
  case "$3" in
    migrate|docker_preflight) run_deployment_preflight='no' ;;
  esac
fi
# Database identity provision/seal are reviewed one-shots around migrations. They do
# not load Django settings and cannot run the runtime preflight before its restricted
# login and exact grants exist.
if [ "$#" -eq 4 ] \
  && [ "$1" = 'python' ] \
  && [ "$2" = '-m' ] \
  && [ "$3" = 'backupsheep.database_identity' ] \
  ; then
  case "$4" in
    provision|seal) run_deployment_preflight='no' ;;
  esac
fi
if [ "$run_deployment_preflight" = 'yes' ]; then
  python /code/manage.py docker_preflight \
    || fail "the deployment preflight did not pass."
fi

# Hosted platforms use this image for workers, Beat, and one-off migration commands.
# Docker passes their configured command as arguments to ENTRYPOINT, so honor it before
# running the web-server startup path below. Quoted argv is passed directly to exec;
# there is intentionally no eval, interpolation, or `sh -c` wrapper.
if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec gunicorn backupsheep.wsgi:application \
  --chdir /code \
  --workers 4 \
  --timeout 3600 \
  --graceful-timeout 30 \
  --max-requests 1000 \
  --max-requests-jitter 100 \
  --worker-tmp-dir /run/backupsheep/gunicorn \
  --limit-request-line 4094 \
  --limit-request-fields 100 \
  --limit-request-field_size 8190 \
  --bind 0.0.0.0:8000
