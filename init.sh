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

# Do not inherit executable-search or interpreter startup hooks from an env file.
# Runtime configuration is data; it must not silently become pre-entrypoint code.
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
  SSLKEYLOGFILE
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

# Dockerfile supplies this exact identity. Failing closed catches an accidental
# root override before provider credentials or backup data become reachable.
expected_uid='10001'
expected_gid='10001'
[ "$(id -u)" = "$expected_uid" ] || fail "expected UID $expected_uid."
[ "$(id -g)" = "$expected_gid" ] || fail "expected GID $expected_gid."

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
  [ "$(stat -c '%u:%g' "$directory")" = "$expected_uid:$expected_gid" ] \
    || fail "$directory must be owned by $expected_uid:$expected_gid."
  [ -w "$directory" ] || fail "$directory is not writable."
  chmod 0700 "$directory" || fail "could not protect $directory."
}

prepare_private_dir /run/backupsheep
[ ! -L /tmp ] || fail "/tmp must not be a symbolic link."
[ -d /tmp ] && [ -w /tmp ] || fail "/tmp must be a writable tmpfs."

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

# Compose secrets are deliberately host-readable only through an owner-only
# directory, but Docker bind-mounts their files as root-owned mode 0444. OpenSSH
# rejects a private key with that mode. Copy a configured key into this role's
# private tmpfs, validate it without a passphrase prompt, and expose only the 0600
# copy to Django/SSH. The source stays immutable and never enters a named volume.
managed_key_source='/run/secrets/ssh_managed_private_key'
managed_key_target='/run/backupsheep/ssh/managed_private_key'
SSH_MANAGED_PRIVATE_KEY_PATH=''
if [ -e "$managed_key_source" ]; then
  [ -f "$managed_key_source" ] && [ ! -L "$managed_key_source" ] \
    || fail "the managed SSH private-key secret must be a regular file."
  managed_key_size="$(wc -c < "$managed_key_source")"
  case "$managed_key_size" in
    ''|*[!0-9]*) fail "could not measure the managed SSH private-key secret." ;;
  esac
  [ "$managed_key_size" -le 65536 ] \
    || fail "the managed SSH private-key secret exceeds 64 KiB."
  if [ "$managed_key_size" -gt 0 ]; then
    cp "$managed_key_source" "$managed_key_target" \
      || fail "could not stage the managed SSH private key."
    chmod 0600 "$managed_key_target" \
      || fail "could not protect the managed SSH private key."
    ssh-keygen -y -P '' -f "$managed_key_target" >/dev/null 2>&1 \
      || fail "the managed SSH private-key secret is invalid or passphrase-protected."
    SSH_MANAGED_PRIVATE_KEY_PATH="$managed_key_target"
  fi
fi
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
