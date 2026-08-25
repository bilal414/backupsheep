#!/bin/sh
# Install and reconcile a namespace-local outbound policy from a no-secret guard.
set -eu
umask 077

fail() {
  printf '%s\n' "BackupSheep egress guard refused startup: $*" >&2
  exit 1
}

validate_peer_host() {
  peer_name="$1"
  peer_host="$2"
  [ -n "$peer_host" ] && [ "${#peer_host}" -le 253 ] \
    || fail "${peer_name} peer host must be between 1 and 253 characters."
  case "$peer_host" in
    -*|*[!A-Za-z0-9_.:-]*) fail "${peer_name} peer host contains an invalid character." ;;
  esac
}

validate_peer_port() {
  peer_name="$1"
  peer_port="$2"
  case "$peer_port" in
    ''|*[!0-9]*) fail "${peer_name} peer port must be a decimal TCP port." ;;
  esac
  [ "$peer_port" -ge 1 ] 2>/dev/null && [ "$peer_port" -le 65535 ] 2>/dev/null \
    || fail "${peer_name} peer port must be between 1 and 65535."
}

workload_uid_for_role() {
  case "$1" in
    app) printf '%s' 10001 ;;
    database) printf '%s' 10002 ;;
    files) printf '%s' 10003 ;;
    storage) printf '%s' 10004 ;;
    logs) printf '%s' 10005 ;;
    cloud) printf '%s' 10008 ;;
    *) return 1 ;;
  esac
}

policy_lease_seconds() {
  # Three complete polling intervals plus a small scheduling allowance keeps
  # ordinary DNS jitter available while placing a hard kernel deadline on every
  # authorization that the userspace reconciler is responsible for renewing.
  printf '%s' $(($1 * 3 + 5))
}

validate_dns_name() {
  dns_context="$1"
  dns_name="$2"
  [ -n "$dns_name" ] && [ "${#dns_name}" -le 253 ] \
    || fail "${dns_context} DNS name must be between 1 and 253 characters."
  case "$dns_name" in
    .*|*.|*..*|*[!A-Za-z0-9_.-]*) \
      fail "${dns_context} DNS name is not a canonical exact name." ;;
  esac
  dns_validation_ifs="$IFS"
  IFS='.'
  set -f
  for dns_label in $dns_name; do
    [ -n "$dns_label" ] && [ "${#dns_label}" -le 63 ] \
      || fail "${dns_context} DNS name contains an invalid label length."
    case "$dns_label" in
      -*|*-) fail "${dns_context} DNS name contains a hyphen at a label boundary." ;;
    esac
  done
  set +f
  IFS="$dns_validation_ifs"
}

append_dns_name() {
  append_context="$1"
  append_name="$(printf '%s' "$2" | tr 'A-Z' 'a-z')"
  validate_dns_name "$append_context" "$append_name"
  case ",${allowed_dns_names}," in
    *,"${append_name}",*) return 0 ;;
  esac
  allowed_dns_count=$((allowed_dns_count + 1))
  [ "$allowed_dns_count" -le 66 ] \
    || fail "strict DNS policy has more than 66 exact names."
  if [ -n "$allowed_dns_names" ]; then
    allowed_dns_names="${allowed_dns_names},${append_name}"
  else
    allowed_dns_names="$append_name"
  fi
}

append_peer_dns_name() {
  peer_context="$1"
  peer_value="$2"
  # IP literals never require DNS. Every non-literal peer is an exact mandatory
  # name in strict mode so normal database/broker clients keep working.
  case "$peer_value" in
    *:*) return 0 ;;
    *[!0-9.]*) append_dns_name "$peer_context peer" "$peer_value" ;;
    *) return 0 ;;
  esac
}

validate_dns_process() {
  dns_process="$1"
  dns_uid="$2"
  dns_gid="$3"
  dns_executable="$4"
  case "$dns_process" in ''|0|*[!0-9]*) return 1 ;; esac
  [ -r "/proc/${dns_process}/status" ] || return 1
  [ "$(awk '/^State:/ { print $2; exit }' "/proc/${dns_process}/status")" != Z ] \
    || return 1
  [ "$(awk '/^Uid:/ { print $2 ":" $3 ":" $4 ":" $5 }' "/proc/${dns_process}/status")" = \
      "${dns_uid}:${dns_uid}:${dns_uid}:${dns_uid}" ] || return 1
  [ "$(awk '/^Gid:/ { print $2 ":" $3 ":" $4 ":" $5 }' "/proc/${dns_process}/status")" = \
      "${dns_gid}:${dns_gid}:${dns_gid}:${dns_gid}" ] || return 1
  [ "$(awk '$1 == "Groups:" { print NF; exit }' "/proc/${dns_process}/status")" = 1 ] \
    || return 1
  for dns_capability in CapInh CapPrm CapEff CapBnd CapAmb; do
    [ "$(awk -v wanted="${dns_capability}:" '$1 == wanted { print $2; exit }' \
        "/proc/${dns_process}/status")" = '0000000000000000' ] || return 1
  done
  [ "$(awk '$1 == "NoNewPrivs:" { print $2; exit }' "/proc/${dns_process}/status")" = 1 ] \
    || return 1
  tr '\000' '\n' < "/proc/${dns_process}/cmdline" | grep -qx "$dns_executable"
}

resolved_addresses() {
  address_family="$1"
  peer_host="$2"
  case "$address_family" in
    4) database=ahostsv4; address_pattern='^[0-9.]+$' ;;
    6) database=ahostsv6; address_pattern='^[0-9A-Fa-f:]+$' ;;
    *) fail "the requested address family is invalid." ;;
  esac
  # getent emits one row per socket type. Canonicalize it so DNS answer ordering
  # and duplicate STREAM/DGRAM rows cannot cause a spurious policy refresh. Docker's
  # embedded DNS can transiently miss one query while endpoints are being updated;
  # retry required IPv4 discovery immediately before declaring the peer absent.
  attempts=1
  [ "$address_family" = 6 ] || attempts=3
  attempt=1
  while [ "$attempt" -le "$attempts" ]; do
    resolved="$(
      getent "$database" "$peer_host" 2>/dev/null \
        | awk -v pattern="$address_pattern" '$1 ~ pattern { print $1 }' \
        | sort -u
    )"
    if [ -n "$resolved" ]; then
      printf '%s\n' "$resolved"
      return 0
    fi
    attempt=$((attempt + 1))
    [ "$attempt" -gt "$attempts" ] || sleep 0.1
  done
  return 0
}

emit_peer_routes() {
  peer_name="$1"
  peer_host="$2"
  peer_port="$3"
  default_interface="$4"
  resolved_count=0

  for address_family in 4 6; do
    addresses="$(resolved_addresses "$address_family" "$peer_host")"
    old_ifs="$IFS"
    IFS='
'
    for peer_address in $addresses; do
      [ -n "$peer_address" ] || continue
      resolved_count=$((resolved_count + 1))
      [ "$resolved_count" -le 16 ] \
        || fail "${peer_name} peer resolved to more than 16 addresses."
      case "$address_family:$peer_address" in
        4:*[!0-9.]*) fail "${peer_name} peer returned an invalid IPv4 address." ;;
        6:*[!0-9A-Fa-f:]*) fail "${peer_name} peer returned an invalid IPv6 address." ;;
      esac

      route_line="$(ip -o -"$address_family" route get "$peer_address" 2>/dev/null)" \
        || fail "${peer_name} peer address ${peer_address} has no route."
      [ "$(printf '%s\n' "$route_line" | awk 'NF { count++ } END { print count + 0 }')" = 1 ] \
        || fail "${peer_name} peer address ${peer_address} has an ambiguous route."
      peer_interface="$(printf '%s\n' "$route_line" | awk '{ for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }')"
      case "$peer_interface" in
        ''|*[!A-Za-z0-9_.:-]*) fail "${peer_name} peer route interface is invalid." ;;
      esac
      [ "${#peer_interface}" -le 15 ] \
        || fail "${peer_name} peer route interface is too long."
      [ "$peer_interface" != lo ] && [ "$peer_interface" != "$default_interface" ] \
        || fail "${peer_name} peer must use a dedicated non-default internal interface."
      if printf '%s\n' "$route_line" | awk '{ for (i=1; i<=NF; i++) if ($i == "via") exit 0; exit 1 }'; then
        fail "${peer_name} peer must be directly connected, not routed through a gateway."
      fi

      printf '%s|%s|%s|%s|%s\n' \
        "$peer_name" "$address_family" "$peer_address" "$peer_interface" "$peer_port"
    done
    IFS="$old_ifs"
  done

  [ "$resolved_count" -gt 0 ] \
    || fail "${peer_name} peer host ${peer_host} did not resolve to an address."
}

peer_snapshot() {
  snapshot_default_interface="$1"
  snapshot_database_host="$2"
  snapshot_database_port="$3"
  snapshot_broker_host="$4"
  snapshot_broker_port="$5"

  database_snapshot="$(emit_peer_routes \
    database "$snapshot_database_host" "$snapshot_database_port" \
    "$snapshot_default_interface")" || return 1
  broker_snapshot="$(emit_peer_routes \
    broker "$snapshot_broker_host" "$snapshot_broker_port" \
    "$snapshot_default_interface")" || return 1
  printf '%s\n%s\n' "$database_snapshot" "$broker_snapshot" | sort
}

validate_peer_snapshot() {
  snapshot="$1"
  database_interfaces="$(printf '%s\n' "$snapshot" | awk -F '|' '$1 == "database" { print $4 }' | sort -u)"
  broker_interfaces="$(printf '%s\n' "$snapshot" | awk -F '|' '$1 == "broker" { print $4 }' | sort -u)"
  [ "$(printf '%s\n' "$database_interfaces" | awk 'NF { count++ } END { print count + 0 }')" = 1 ] \
    || fail "database peer addresses must share exactly one internal interface."
  [ "$(printf '%s\n' "$broker_interfaces" | awk 'NF { count++ } END { print count + 0 }')" = 1 ] \
    || fail "broker peer addresses must share exactly one internal interface."
  [ "$database_interfaces" != "$broker_interfaces" ] \
    || fail "database and broker peers must use distinct internal interfaces."
}

peer_elements() {
  element_family="$1"
  element_snapshot="$2"
  element_timeout="$3"
  printf '%s\n' "$element_snapshot" | awk -F '|' \
    -v family="$element_family" -v timeout="$element_timeout" '
    $2 == family {
      if (count++) printf ", "
      printf "\"%s\" . %s . %s timeout %ss", $4, $3, $5, timeout
    }
  '
}

apply_peer_snapshot() {
  update_snapshot="$1"
  update_authorized="$2"
  update_mode="$3"
  update_workload_uid="$4"
  update_timeout="$5"
  update_ipv4="$(peer_elements 4 "$update_snapshot" "$update_timeout")"
  update_ipv6="$(peer_elements 6 "$update_snapshot" "$update_timeout")"
  update_commands="$({
    printf '%s\n' 'flush set inet backupsheep_egress internal_ipv4'
    printf '%s\n' 'flush set inet backupsheep_egress internal_ipv6'
    if [ "$update_mode" != public ]; then
      printf '%s\n' 'flush set inet backupsheep_egress strict_workload_lease'
    fi
    if [ -n "$update_ipv4" ]; then
      printf 'add element inet backupsheep_egress internal_ipv4 { %s }\n' "$update_ipv4"
    fi
    if [ -n "$update_ipv6" ]; then
      printf 'add element inet backupsheep_egress internal_ipv6 { %s }\n' "$update_ipv6"
    fi
    if [ "$update_mode" != public ] && [ "$update_authorized" = true ]; then
      printf 'add element inet backupsheep_egress strict_workload_lease { %s timeout %ss }\n' \
        "$update_workload_uid" "$update_timeout"
    fi
  })"
  if ! update_error="$(printf '%s\n' "$update_commands" \
      | nft --check --file - 2>&1 >/dev/null)"; then
    printf '%s\n' "BackupSheep egress guard could not validate an exact peer-set update: ${update_error}" >&2
    return 1
  fi
  # Flush and add operations in one nft batch are one atomic netlink transaction:
  # there is no interval where a broad bridge rule or half-refreshed tuple set exists.
  if ! update_error="$(printf '%s\n' "$update_commands" \
      | nft --file - 2>&1 >/dev/null)"; then
    printf '%s\n' "BackupSheep egress guard could not apply an exact peer-set update: ${update_error}" >&2
    return 1
  fi
  nft list set inet backupsheep_egress internal_ipv4 >/dev/null 2>&1 \
    && nft list set inet backupsheep_egress internal_ipv6 >/dev/null 2>&1 \
    && { [ "$update_mode" = public ] \
      || nft list set inet backupsheep_egress strict_workload_lease >/dev/null 2>&1; }
}

write_reconciler_state() {
  reconciler_status="$1"
  reconciler_snapshot="$2"
  reconciler_lease_seconds="$3"
  reconciler_state=/run/backupsheep-egress/reconciler-state
  [ -f "$reconciler_state" ] && [ ! -L "$reconciler_state" ] \
    && [ "$(stat -c '%u:%g:%a:%h' "$reconciler_state")" = '10020:10020:600:1' ] \
    || return 1
  reconciler_sha256="$(printf '%s' "$reconciler_snapshot" | sha256sum | awk '{print $1}')"
  reconciler_monotonic_seconds="$(cut -d. -f1 /proc/uptime)"
  case "$reconciler_monotonic_seconds" in ''|*[!0-9]*) return 1 ;; esac
  printf 'status=%s\npeers_sha256=%s\nlease_seconds=%s\nrenewed_monotonic_seconds=%s\nenvironment=minimal-shell-only\n' \
    "$reconciler_status" "$reconciler_sha256" "$reconciler_lease_seconds" \
    "$reconciler_monotonic_seconds" > "$reconciler_state"
}

if [ "${1:-}" = monitor ]; then
  shift
  [ "$#" = 11 ] || fail "peer monitor arguments are incomplete."
  [ "$(id -u):$(id -g)" = '10020:10020' ] \
    || fail "peer monitor must run as the unprivileged guard identity."
  [ "$(id -G)" = 10020 ] \
    || fail "peer monitor must not retain supplementary groups."
  for capability in CapInh CapPrm CapEff CapBnd CapAmb; do
    capability_value="$(awk -v wanted="${capability}:" '$1 == wanted { print $2; exit }' /proc/self/status)"
    [ "$capability_value" = '0000000000001000' ] \
      || fail "peer monitor must retain only NET_ADMIN in ${capability}."
  done
  [ "$(awk '$1 == "NoNewPrivs:" { print $2; exit }' /proc/self/status)" = 1 ] \
    || fail "peer monitor must run with no_new_privs."
  expected_snapshot="$1"
  monitor_default_interface="$2"
  monitor_database_host="$3"
  monitor_database_port="$4"
  monitor_broker_host="$5"
  monitor_broker_port="$6"
  monitor_interval="$7"
  monitor_mode="$8"
  monitor_resolver_pid="$9"
  monitor_forwarder_pid="${10}"
  monitor_role="${11}"
  case "$monitor_interval" in
    ''|*[!0-9]*) fail "peer monitor interval must be a decimal number of seconds." ;;
  esac
  [ "$monitor_interval" -ge 1 ] 2>/dev/null && [ "$monitor_interval" -le 300 ] 2>/dev/null \
    || fail "peer monitor interval must be between 1 and 300 seconds."
  case "$monitor_mode" in deny|allowlist|public) ;; *) fail "peer monitor mode is invalid." ;; esac
  monitor_workload_uid="$(workload_uid_for_role "$monitor_role")" \
    || fail "peer monitor role is invalid."
  monitor_lease_seconds="$(policy_lease_seconds "$monitor_interval")"
  monitor_environment_names="$(
    env | awk -F= 'NF { print $1 }' | sort -u
  )"
  [ "$monitor_environment_names" = "PATH
PWD
SHLVL" ] \
    || fail "peer monitor environment is not the expected minimal shell environment."
  if [ "$monitor_mode" = public ]; then
    [ "$monitor_resolver_pid" = 0 ] && [ "$monitor_forwarder_pid" = 0 ] \
      || fail "public mode must not start strict DNS processes."
  else
    validate_dns_process "$monitor_resolver_pid" 10021 10021 \
      /usr/local/bin/backupsheep-dns-proxy \
      || fail "strict DNS parser lost its identity or zero-capability boundary."
    validate_dns_process "$monitor_forwarder_pid" 10022 10022 \
      /usr/local/bin/backupsheep-dns-forwarder \
      || fail "strict DNS forwarder lost its identity or zero-capability boundary."
  fi

  reconciler_status=ready
  write_reconciler_state ready "$expected_snapshot" "$monitor_lease_seconds" \
    || fail "peer monitor could not initialize its health witness."
  # Docker service IPs can change after a peer container is recreated. Reconcile
  # the two exact sets in this existing namespace: restarting the guard container
  # would strand a long-lived network_mode:service worker in its old namespace.
  while :; do
    if [ "$monitor_mode" != public ] \
        && { ! validate_dns_process "$monitor_resolver_pid" 10021 10021 \
              /usr/local/bin/backupsheep-dns-proxy \
          || ! validate_dns_process "$monitor_forwarder_pid" 10022 10022 \
              /usr/local/bin/backupsheep-dns-forwarder; }; then
      # The separately-identified resolver cannot be restarted by this monitor:
      # it intentionally has neither the same UID nor a capability-bearing parent.
      # DNS is already fail-closed. Keep this namespace alive but make health block
      # until the operator recreates the paired guard and workload together.
      # Revoke immediately when possible. Even if both this nft transaction and
      # all later updates fail, the kernel expires the last lease independently.
      apply_peer_snapshot '' false "$monitor_mode" "$monitor_workload_uid" \
        "$monitor_lease_seconds" || true
      expected_snapshot=''
      if [ "$reconciler_status" != blocked ]; then
        write_reconciler_state blocked '' "$monitor_lease_seconds" \
          || fail "peer monitor could not publish a DNS resolver failure."
        reconciler_status=blocked
      fi
      sleep "$monitor_interval"
      continue
    fi

    snapshot_valid=false
    if current_snapshot="$(peer_snapshot \
        "$monitor_default_interface" \
        "$monitor_database_host" "$monitor_database_port" \
        "$monitor_broker_host" "$monitor_broker_port" 2>/dev/null)"; then
      if (validate_peer_snapshot "$current_snapshot"); then
        snapshot_valid=true
      fi
    fi

    if [ "$snapshot_valid" != true ]; then
      # DNS absence/ambiguity can never preserve a stale address. Flush both
      # internal sets/strict lease and remain alive in the worker's namespace.
      # Expiring elements remain fail-closed if this emergency transaction fails.
      if [ -n "$expected_snapshot" ]; then
        if apply_peer_snapshot '' false "$monitor_mode" "$monitor_workload_uid" \
            "$monitor_lease_seconds"; then
          expected_snapshot=''
        fi
      fi
      if [ "$reconciler_status" != blocked ]; then
        write_reconciler_state blocked '' "$monitor_lease_seconds" \
          || fail "peer monitor could not publish its blocked health state."
        reconciler_status=blocked
      fi
      sleep "$monitor_interval"
      continue
    fi

    # Renew on every complete observation, not only on address drift. Internal
    # tuples and the strict workload lease otherwise expire in the kernel.
    if ! apply_peer_snapshot "$current_snapshot" true "$monitor_mode" \
        "$monitor_workload_uid" "$monitor_lease_seconds"; then
        apply_peer_snapshot '' false "$monitor_mode" "$monitor_workload_uid" \
          "$monitor_lease_seconds" || true
        expected_snapshot=''
        write_reconciler_state blocked '' "$monitor_lease_seconds" \
          || fail "peer monitor could not publish an update failure."
        reconciler_status=blocked
        sleep "$monitor_interval"
        continue
    fi
    expected_snapshot="$current_snapshot"
    # A ready witness is a short-lived proof of the same successful cycle that
    # renewed the kernel authorization. Refresh it every time: process liveness
    # alone cannot keep Docker health green after the lease has expired.
    write_reconciler_state ready "$expected_snapshot" "$monitor_lease_seconds" \
      || fail "peer monitor could not publish its renewed health witness."
    reconciler_status=ready
    sleep "$monitor_interval"
  done
fi

[ "$#" = 0 ] || fail "unexpected entrypoint arguments were supplied."
[ "$(id -u)" = 0 ] && [ "$(id -g)" = 0 ] \
  || fail "policy bootstrap must start as container root."
[ -d /run/backupsheep-egress ] && [ ! -L /run/backupsheep-egress ] \
  || fail "/run/backupsheep-egress must be a private tmpfs."
[ "$(stat -c '%u:%g:%a' /run/backupsheep-egress)" = '0:0:700' ] \
  || fail "/run/backupsheep-egress must be root-owned mode 0700."
# Refuse accidental secret injection before processing policy, then discard the
# complete bootstrap environment before entering the long-lived reconciler.
if env | awk -F= '{ print $1 }' \
    | grep -Eq '(PASSWORD|SECRET|TOKEN|CREDENTIAL|PRIVATE|_KEY)'; then
  fail "the no-secret guard received a secret-like environment variable."
fi

role="${BACKUPSHEEP_EGRESS_ROLE:-}"
case "$role" in
  app|cloud|database|files|storage|logs) ;;
  *) fail "BACKUPSHEEP_EGRESS_ROLE is missing or unsupported." ;;
esac

[ "${BACKUPSHEEP_EGRESS_POLICY_GENERATION:-}" = 2 ] \
  || fail "BACKUPSHEEP_EGRESS_POLICY_GENERATION=2 is required; complete the fail-closed egress upgrade."

mode="${BACKUPSHEEP_EGRESS_MODE:-deny}"
case "$mode" in
  deny|allowlist|public) ;;
  *) fail "BACKUPSHEEP_EGRESS_MODE must be deny, allowlist, or public." ;;
esac
workload_uid="$(workload_uid_for_role "$role")" \
  || fail "BACKUPSHEEP_EGRESS_ROLE has no workload identity."
monitor_interval="${BACKUPSHEEP_EGRESS_DNS_REFRESH_SECONDS:-1}"
case "$monitor_interval" in
  ''|*[!0-9]*) fail "BACKUPSHEEP_EGRESS_DNS_REFRESH_SECONDS must be a decimal number." ;;
esac
[ "$monitor_interval" -ge 1 ] 2>/dev/null && [ "$monitor_interval" -le 300 ] 2>/dev/null \
  || fail "BACKUPSHEEP_EGRESS_DNS_REFRESH_SECONDS must be between 1 and 300."
lease_seconds="$(policy_lease_seconds "$monitor_interval")"

default_routes="$(ip -o -4 route show default 2>/dev/null || true)"
[ "$(printf '%s\n' "$default_routes" | awk 'NF { count++ } END { print count + 0 }')" = 1 ] \
  || fail "the namespace must have exactly one IPv4 default route."
egress_interface="$(printf '%s\n' "$default_routes" | awk '{ for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }')"
case "$egress_interface" in
  ''|*[!A-Za-z0-9_.:-]*) fail "the default-route interface is invalid." ;;
esac
[ "${#egress_interface}" -le 15 ] || fail "the default-route interface is too long."

database_host="${BACKUPSHEEP_EGRESS_DATABASE_HOST:-}"
database_port="${BACKUPSHEEP_EGRESS_DATABASE_PORT:-}"
broker_host="${BACKUPSHEEP_EGRESS_BROKER_HOST:-}"
broker_port="${BACKUPSHEEP_EGRESS_BROKER_PORT:-}"
validate_peer_host database "$database_host"
validate_peer_port database "$database_port"
validate_peer_host broker "$broker_host"
validate_peer_port broker "$broker_port"
[ "${database_host}:${database_port}" != "${broker_host}:${broker_port}" ] \
  || fail "database and broker peer endpoints must be distinct."

allowed_dns_names=''
allowed_dns_count=0
explicit_dns_names="${BACKUPSHEEP_EGRESS_ALLOW_DNS_NAMES:-}"
[ "${#explicit_dns_names}" -le 4096 ] \
  || fail "the exact DNS-name allowlist is too long."
if [ "$mode" != allowlist ] && [ -n "$explicit_dns_names" ]; then
  fail "BACKUPSHEEP_EGRESS_ALLOW_DNS_NAMES is valid only in allowlist mode."
fi
if [ "$mode" != public ]; then
  append_peer_dns_name database "$database_host"
  append_peer_dns_name broker "$broker_host"
  explicit_names_ifs="$IFS"
  IFS=', '
  set -f
  for explicit_dns_name in $explicit_dns_names; do
    [ -n "$explicit_dns_name" ] || continue
    append_dns_name explicit "$explicit_dns_name"
  done
  set +f
  IFS="$explicit_names_ifs"
  [ -n "$allowed_dns_names" ] \
    || fail "deny/allowlist mode requires at least one exact internal DNS name."
  [ "${#allowed_dns_names}" -le 4096 ] \
    || fail "the canonical exact DNS-name policy is too long."
fi

internal_peers="$(peer_snapshot \
  "$egress_interface" \
  "$database_host" "$database_port" \
  "$broker_host" "$broker_port")"
validate_peer_snapshot "$internal_peers"

normalize_ipv4_tcp_endpoints() {
  raw="$1"
  [ "${#raw}" -le 8192 ] || fail "the IPv4 TCP endpoint allowlist is too long."
  normalized=''
  count=0
  old_ifs="$IFS"
  IFS=', '
  # Expansion is intentional after strict validation below; globbing stays disabled
  # so an endpoint can never turn into a filesystem-derived token.
  set -f
  for endpoint in $raw; do
    [ -n "$endpoint" ] || continue
    count=$((count + 1))
    [ "$count" -le 128 ] || fail "the IPv4 TCP endpoint allowlist has too many entries."
    case "$endpoint" in
      *[!0-9./:]*) fail "the IPv4 TCP endpoint allowlist contains an invalid character." ;;
      *:*) ;;
      *) fail "every IPv4 TCP endpoint must be CIDR:port." ;;
    esac
    cidr="${endpoint%:*}"
    port="${endpoint##*:}"
    [ -n "$cidr" ] && [ "$cidr" != "$endpoint" ] \
      || fail "every IPv4 TCP endpoint must be CIDR:port."
    case "$cidr" in ''|*[!0-9./]*) fail "an IPv4 TCP endpoint has an invalid CIDR." ;; esac
    validate_peer_port "outward IPv4 TCP endpoint" "$port"
    if [ -n "$normalized" ]; then
      normalized="${normalized}, ${cidr} . ${port}"
    else
      normalized="${cidr} . ${port}"
    fi
  done
  set +f
  IFS="$old_ifs"
  printf '%s' "$normalized"
}

normalize_ipv6_tcp_endpoints() {
  raw="$1"
  [ "${#raw}" -le 8192 ] || fail "the IPv6 TCP endpoint allowlist is too long."
  normalized=''
  count=0
  old_ifs="$IFS"
  IFS=', '
  set -f
  for endpoint in $raw; do
    [ -n "$endpoint" ] || continue
    count=$((count + 1))
    [ "$count" -le 128 ] || fail "the IPv6 TCP endpoint allowlist has too many entries."
    case "$endpoint" in
      *[!0-9A-Fa-f:/\[\]]*) fail "the IPv6 TCP endpoint allowlist contains an invalid character." ;;
      \[*\]:*) ;;
      *) fail "every IPv6 TCP endpoint must be [CIDR]:port." ;;
    esac
    remainder="${endpoint#\[}"
    cidr="${remainder%%\]*}"
    suffix="${remainder#*\]}"
    [ -n "$cidr" ] && [ "$suffix" != "$remainder" ] && [ "${suffix#:}" != "$suffix" ] \
      || fail "every IPv6 TCP endpoint must be [CIDR]:port."
    port="${suffix#:}"
    case "$cidr" in ''|*[!0-9A-Fa-f:/]*) fail "an IPv6 TCP endpoint has an invalid CIDR." ;; esac
    case "$port" in ''|*[!0-9]*) fail "an IPv6 TCP endpoint has an invalid port." ;; esac
    validate_peer_port "outward IPv6 TCP endpoint" "$port"
    if [ -n "$normalized" ]; then
      normalized="${normalized}, ${cidr} . ${port}"
    else
      normalized="${cidr} . ${port}"
    fi
  done
  set +f
  IFS="$old_ifs"
  printf '%s' "$normalized"
}

legacy_allow_ipv4="${BACKUPSHEEP_EGRESS_ALLOW_IPV4:-}"
legacy_allow_ipv6="${BACKUPSHEEP_EGRESS_ALLOW_IPV6:-}"
if [ -n "$legacy_allow_ipv4" ] || [ -n "$legacy_allow_ipv6" ]; then
  fail "address-only egress allowlists are retired; configure exact IPv4/IPv6 TCP endpoints."
fi
allow_ipv4_tcp="$(normalize_ipv4_tcp_endpoints "${BACKUPSHEEP_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS:-}")"
allow_ipv6_tcp="$(normalize_ipv6_tcp_endpoints "${BACKUPSHEEP_EGRESS_ALLOW_IPV6_TCP_ENDPOINTS:-}")"
if [ "$mode" = deny ] && { [ -n "$allow_ipv4_tcp" ] || [ -n "$allow_ipv6_tcp" ]; }; then
  fail "deny mode does not accept an outward TCP endpoint."
fi
if [ "$mode" = allowlist ] && [ -z "$allow_ipv4_tcp" ] && [ -z "$allow_ipv6_tcp" ]; then
  fail "allowlist mode requires at least one exact TCP endpoint."
fi

route_gateways() {
  gateway_family="$1"
  ip -o -"$gateway_family" route show 2>/dev/null \
    | awk '{ for (i=1; i<=NF; i++) if ($i == "via") print $(i+1) }' \
    | sort -u
}

gateway_ipv4="$(route_gateways 4)"
gateway_ipv6="$(route_gateways 6)"
internal_ipv4="$(peer_elements 4 "$internal_peers" "$lease_seconds")"
internal_ipv6="$(peer_elements 6 "$internal_peers" "$lease_seconds")"

rules=/run/backupsheep-egress/rules.nft
marker=/run/backupsheep-egress/ready

{
  # Never flush the namespace ruleset: Docker owns the embedded-DNS plumbing in
  # this namespace. Add only the dedicated table on a fresh guard namespace.
  printf '%s\n' 'table inet backupsheep_egress {'
  if [ "$mode" != public ]; then
    # Run before Docker's own output-DNAT chain. Untrusted workload UIDs cannot
    # reach Docker DNS directly; their standard resolver traffic is redirected to
    # the exact-name parser. Only the monitor and fixed-index forwarder retain DNS.
    printf '%s\n' '  chain dns_redirect {'
    printf '%s\n' '    type nat hook output priority dstnat - 10; policy accept;'
    printf '%s\n' '    meta skuid != 10020 meta skuid != 10021 meta skuid != 10022 ip daddr 127.0.0.11 udp dport 53 redirect to :1053'
    printf '%s\n' '    meta skuid != 10020 meta skuid != 10021 meta skuid != 10022 ip daddr 127.0.0.11 tcp dport 53 redirect to :1053'
    printf '%s\n' '  }'
  fi
  printf '%s\n' '  set never_ipv4 { type ipv4_addr; flags interval; elements = { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } }'
  printf '%s\n' '  set never_ipv6 { type ipv6_addr; flags interval; elements = { ::/128, ::1/128, 64:ff9b::/96, 64:ff9b:1::/48, fd00:ec2::254/128 } }'
  printf '%s\n' '  set special_ipv4 { type ipv4_addr; flags interval; elements = { 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24 } }'
  printf '%s\n' '  set special_ipv6 { type ipv6_addr; flags interval; elements = { 100::/64, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 } }'
  printf '  set internal_ipv4 { type ifname . ipv4_addr . inet_service; flags timeout; timeout %ss;' \
    "$lease_seconds"
  if [ -n "$internal_ipv4" ]; then
    printf ' elements = { %s };' "$internal_ipv4"
  fi
  printf '%s\n' ' }'
  printf '  set internal_ipv6 { type ifname . ipv6_addr . inet_service; flags timeout; timeout %ss;' \
    "$lease_seconds"
  if [ -n "$internal_ipv6" ]; then
    printf ' elements = { %s };' "$internal_ipv6"
  fi
  printf '%s\n' ' }'
  if [ -n "$allow_ipv4_tcp" ]; then
    printf '  set allowed_ipv4_tcp { type ipv4_addr . inet_service; flags interval; elements = { %s } }\n' "$allow_ipv4_tcp"
  fi
  if [ -n "$allow_ipv6_tcp" ]; then
    printf '  set allowed_ipv6_tcp { type ipv6_addr . inet_service; flags interval; elements = { %s } }\n' "$allow_ipv6_tcp"
  fi
  if [ "$mode" != public ]; then
    # A strict workload is authorized only while this kernel timer is alive. The
    # reconciler renews it atomically with both peer sets; no userspace failure can
    # preserve an old lease beyond this fixed deadline.
    printf '  set strict_workload_lease { type uid; flags timeout; timeout %ss; elements = { %s timeout %ss }; }\n' \
      "$lease_seconds" "$workload_uid" "$lease_seconds"
  fi
  printf '%s\n' '  chain output {'
  printf '%s\n' '    type filter hook output priority filter; policy drop;'
  if [ "$mode" != public ]; then
    # A failed/misordered redirect must block, not fall back to unfiltered Docker
    # DNS. Direct DNS to an outward allowlisted address is denied as well.
    printf '%s\n' '    meta skuid != 10020 meta skuid != 10022 ip daddr 127.0.0.11 meta l4proto { tcp, udp } th dport 53 counter reject with icmpx type admin-prohibited'
    printf '%s\n' '    meta skuid 10022 ct original ip daddr 127.0.0.11 ct original proto-dst 53 meta l4proto { tcp, udp } counter accept'
    printf '%s\n' '    meta skuid 10022 counter reject with icmpx type admin-prohibited'
    printf '    oifname "%s" meta l4proto { tcp, udp } th dport 53 reject with icmpx type admin-prohibited\n' "$egress_interface"
    # Keep kernel-generated IPv6 control traffic and local loopback outside the
    # socket-identity lease. Docker's embedded resolver replies from a root-owned
    # loopback socket; workload DNS was already forced through the exact-name proxy
    # above. The hostile-packet parser is confined to 127.0.0.1 and the structured
    # forwarder to Docker DNS. Every other non-local data socket except the monitor
    # must hold the role lease before established-connection handling can accept it.
    printf '%s\n' '    meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept'
    # The hostile-packet parser may emit only replies from its fixed DNS
    # listener. A parser compromise must not become a loopback pivot into the
    # workload's web/API or any other service in this shared network namespace.
    printf '%s\n' '    meta skuid 10021 ip saddr 127.0.0.1 ip daddr 127.0.0.1 udp sport 1053 ct direction reply counter accept'
    printf '%s\n' '    meta skuid 10021 ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 1053 ct direction reply counter accept'
    printf '%s\n' '    meta skuid 10021 counter reject with icmpx type admin-prohibited'
    printf '%s\n' '    oifname "lo" accept'
    printf '%s\n' '    meta skuid != 10020 meta skuid != @strict_workload_lease reject with icmpx type admin-prohibited'
  fi
  if [ "$mode" = public ]; then
    printf '%s\n' '    oifname "lo" accept'
  fi
  # Only replies to connections initiated from outside this namespace bypass
  # current destination tuples (for example, web responses on the published
  # port). Original-direction workload flows must re-match the current peer or
  # outward tuple on every packet, so removing an address revokes open sessions.
  printf '%s\n' '    ct direction reply ct state established,related accept'
  if [ "$mode" = public ]; then
    printf '%s\n' '    meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept'
  fi
  printf '%s\n' '    ip daddr @never_ipv4 reject with icmpx type admin-prohibited'
  printf '%s\n' '    ip6 daddr @never_ipv6 reject with icmpx type admin-prohibited'
  old_ifs="$IFS"
  IFS='
'
  for gateway_address in $gateway_ipv4; do
    [ -n "$gateway_address" ] || continue
    case "$gateway_address" in *[!0-9.]*) fail "the kernel returned an invalid IPv4 gateway." ;; esac
    printf '    ip daddr %s reject with icmpx type admin-prohibited\n' "$gateway_address"
  done
  for gateway_address in $gateway_ipv6; do
    [ -n "$gateway_address" ] || continue
    case "$gateway_address" in *[!0-9A-Fa-f:]*) fail "the kernel returned an invalid IPv6 gateway." ;; esac
    printf '    ip6 daddr %s reject with icmpx type admin-prohibited\n' "$gateway_address"
  done
  IFS="$old_ifs"
  # Internal stateful services are authorized by an exact DNS-resolved address,
  # dedicated interface, protocol, and port tuple. No bridge subnet or gateway is
  # trusted merely because it is attached to this namespace.
  printf '%s\n' '    oifname . ip daddr . tcp dport @internal_ipv4 accept'
  printf '%s\n' '    oifname . ip6 daddr . tcp dport @internal_ipv6 accept'
  if [ -n "$allow_ipv4_tcp" ]; then
    printf '    oifname "%s" ip daddr . tcp dport @allowed_ipv4_tcp accept\n' "$egress_interface"
  fi
  if [ -n "$allow_ipv6_tcp" ]; then
    printf '    oifname "%s" ip6 daddr . tcp dport @allowed_ipv6_tcp accept\n' "$egress_interface"
  fi
  if [ "$mode" = public ]; then
    printf '    oifname "%s" ip daddr @special_ipv4 reject with icmpx type admin-prohibited\n' "$egress_interface"
    printf '    oifname "%s" ip6 daddr @special_ipv6 reject with icmpx type admin-prohibited\n' "$egress_interface"
    printf '    oifname "%s" meta nfproto { ipv4, ipv6 } accept\n' "$egress_interface"
  fi
  printf '%s\n' '  }'
  printf '%s\n' '  chain input {'
  printf '%s\n' '    type filter hook input priority filter; policy drop;'
  printf '%s\n' '    iifname "lo" accept'
  printf '%s\n' '    ct state established,related accept'
  printf '%s\n' '    meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept'
  if [ "$role" = app ]; then
    printf '    iifname "%s" tcp dport 8000 ct state new accept\n' "$egress_interface"
  fi
  printf '%s\n' '  }'
  printf '%s\n' '  chain forward { type filter hook forward priority filter; policy drop; }'
  printf '%s\n' '}'
} > "$rules"
chmod 0600 "$rules"

# A malformed or injected operator value is rejected before the live namespace is
# touched. nft then loads one complete ruleset transactionally.
nft --check --file "$rules" >/dev/null \
  || fail "the generated outbound policy is invalid."
confirmed_peers="$(peer_snapshot \
  "$egress_interface" \
  "$database_host" "$database_port" \
  "$broker_host" "$broker_port")"
validate_peer_snapshot "$confirmed_peers"
[ "$confirmed_peers" = "$internal_peers" ] \
  || fail "an internal peer changed while the outbound policy was being prepared."
nft --file "$rules" >/dev/null \
  || fail "the outbound policy could not be installed."
nft list table inet backupsheep_egress >/dev/null \
  || fail "the outbound policy is not active."

rules_sha256="$(sha256sum "$rules" | awk '{print $1}')"
peers_sha256="$(printf '%s' "$internal_peers" | sha256sum | awk '{print $1}')"
dns_names_sha256="$(printf '%s' "$allowed_dns_names" | sha256sum | awk '{print $1}')"
peer_count="$(printf '%s\n' "$internal_peers" | awk 'NF { count++ } END { print count + 0 }')"
printf 'role=%s\nmode=%s\ninterface=%s\npeer_count=%s\npeers_sha256=%s\ndns_names_sha256=%s\nrules_sha256=%s\n' \
  "$role" "$mode" "$egress_interface" "$peer_count" "$peers_sha256" \
  "$dns_names_sha256" "$rules_sha256" > "$marker"
chmod 0444 "$marker"
reconciler_state=/run/backupsheep-egress/reconciler-state
: > "$reconciler_state"
chmod 0600 "$reconciler_state"
chown 10020:10020 "$reconciler_state"
resolver_state=/run/backupsheep-egress/resolver-state
forwarder_state=/run/backupsheep-egress/forwarder-state
forwarder_directory=/run/backupsheep-egress/dns-forwarder
forwarder_socket=${forwarder_directory}/upstream.sock
resolver_pid=0
forwarder_pid=0
if [ "$mode" != public ]; then
  : > "$resolver_state"
  : > "$forwarder_state"
  mkdir "$forwarder_directory"
  chmod 0711 "$forwarder_directory"
  chown 10022:10022 "$forwarder_directory"
  # Root deliberately has no DAC_OVERRIDE. World-readability inside this private
  # mount namespace lets bootstrap verify each non-secret one-time witness before
  # making it immutable; only its distinct DNS process can write it.
  chmod 0644 "$resolver_state"
  chown 10021:10021 "$resolver_state"
  chmod 0644 "$forwarder_state"
  chown 10022:10022 "$forwarder_state"
fi
# The application has a different mount namespace, so it cannot see this tmpfs.
# Search-only access lets the unprivileged guard identities reach only their
# pre-created state/socket paths without replacing root-owned policy artifacts.
chmod 0711 /run/backupsheep-egress

if [ "$mode" != public ]; then
  # Start the only upstream resolver first. It accepts only an authenticated two-byte
  # {immutable-name-index, A-or-AAAA} request and never parses a workload packet.
  setpriv \
    --reuid=10022 \
    --regid=10022 \
    --clear-groups \
    --inh-caps=-all \
    --ambient-caps=-all \
    --bounding-set=-all \
    --no-new-privs \
    /usr/local/bin/backupsheep-dns-forwarder \
    "$allowed_dns_names" "$forwarder_socket" "$forwarder_state" &
  forwarder_pid=$!
  forwarder_ready=false
  forwarder_attempt=1
  while [ "$forwarder_attempt" -le 50 ]; do
    if validate_dns_process "$forwarder_pid" 10022 10022 \
          /usr/local/bin/backupsheep-dns-forwarder \
        && grep -qx status=ready "$forwarder_state" \
        && grep -qx "pid=${forwarder_pid}" "$forwarder_state" \
        && [ -S "$forwarder_socket" ] \
        && [ "$(stat -c '%u:%g:%a:%h' "$forwarder_socket")" = '10022:10022:622:1' ]; then
      forwarder_ready=true
      break
    fi
    forwarder_attempt=$((forwarder_attempt + 1))
    sleep 0.05
  done
  if [ "$forwarder_ready" != true ]; then
    kill "$forwarder_pid" 2>/dev/null || true
    wait "$forwarder_pid" 2>/dev/null || true
    fail "the fixed-index strict DNS forwarder did not become ready."
  fi

  # Keep the hostile-packet parser outside both NET_ADMIN and upstream-DNS trust
  # boundaries. It has a distinct UID, no capabilities or secret, and only a
  # loopback listener plus the fixed-structure local forwarder socket.
  setpriv \
    --reuid=10021 \
    --regid=10021 \
    --clear-groups \
    --inh-caps=-all \
    --ambient-caps=-all \
    --bounding-set=-all \
    --no-new-privs \
    /usr/local/bin/backupsheep-dns-proxy \
    "$allowed_dns_names" "$resolver_state" "$forwarder_socket" &
  resolver_pid=$!
  resolver_ready=false
  resolver_attempt=1
  while [ "$resolver_attempt" -le 50 ]; do
    if validate_dns_process "$resolver_pid" 10021 10021 \
          /usr/local/bin/backupsheep-dns-proxy \
        && grep -qx status=ready "$resolver_state" \
        && grep -qx "pid=${resolver_pid}" "$resolver_state"; then
      resolver_ready=true
      break
    fi
    resolver_attempt=$((resolver_attempt + 1))
    sleep 0.05
  done
  if [ "$resolver_ready" != true ]; then
    kill "$resolver_pid" 2>/dev/null || true
    kill "$forwarder_pid" 2>/dev/null || true
    wait "$resolver_pid" 2>/dev/null || true
    wait "$forwarder_pid" 2>/dev/null || true
    fail "the zero-capability strict DNS parser did not become ready."
  fi
  # Both processes close their one-time witness before serving. Make the witnesses
  # root-owned and immutable so neither isolated identity can forge readiness later.
  chown 0:0 "$resolver_state"
  chmod 0444 "$resolver_state"
  chown 0:0 "$forwarder_state"
  chmod 0444 "$forwarder_state"
fi

# The monitor is deliberately PID 1 with no secret, listener, supplementary group,
# or filesystem write surface beyond its health witness. NET_ADMIN is the only
# retained capability so it can refresh exact sets in the existing shared namespace.
exec env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin setpriv \
  --reuid=10020 \
  --regid=10020 \
  --clear-groups \
  --inh-caps=+net_admin \
  --ambient-caps=+net_admin \
  --bounding-set=-all,+net_admin \
  --no-new-privs \
  /usr/local/bin/backupsheep-egress-guard monitor \
  "$internal_peers" "$egress_interface" \
  "$database_host" "$database_port" "$broker_host" "$broker_port" \
  "$monitor_interval" "$mode" "$resolver_pid" "$forwarder_pid" "$role"
