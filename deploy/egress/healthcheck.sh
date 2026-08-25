#!/bin/sh
# Prove that the exact-set reconciler is ready and retains only NET_ADMIN.
set -eu

if [ "$(id -u):$(id -g)" = '0:0' ]; then
  exec setpriv \
    --reuid=10020 \
    --regid=10020 \
    --clear-groups \
    --inh-caps=-all \
    --ambient-caps=-all \
    --bounding-set=-all \
    --no-new-privs \
    /usr/local/bin/backupsheep-egress-healthcheck unprivileged
fi

[ "${1:-}" = unprivileged ]
[ "$(id -u):$(id -g):$(id -G)" = '10020:10020:10020' ]
[ "$(stat -c '%u:%g:%a' /run/backupsheep-egress)" = '0:0:711' ]
[ -f /run/backupsheep-egress/ready ] \
  && [ ! -L /run/backupsheep-egress/ready ] \
  && [ "$(stat -c '%u:%g:%a:%h' /run/backupsheep-egress/ready)" = '0:0:444:1' ]
[ -f /run/backupsheep-egress/reconciler-state ] \
  && [ ! -L /run/backupsheep-egress/reconciler-state ] \
  && [ "$(stat -c '%u:%g:%a:%h' /run/backupsheep-egress/reconciler-state)" = '10020:10020:600:1' ]

status_value() {
  awk -v wanted="$1:" '$1 == wanted { print $2; exit }' /proc/1/status
}

[ "$(awk '/^Uid:/ { print $2 ":" $3 ":" $4 ":" $5 }' /proc/1/status)" = '10020:10020:10020:10020' ]
[ "$(awk '/^Gid:/ { print $2 ":" $3 ":" $4 ":" $5 }' /proc/1/status)" = '10020:10020:10020:10020' ]
for capability in CapInh CapPrm CapEff CapBnd CapAmb; do
  [ "$(status_value "$capability")" = '0000000000001000' ]
done
[ "$(status_value NoNewPrivs)" = 1 ]

# PID 1 is a polling reconciler, never a network service or secret-bearing process.
for descriptor in /proc/1/fd/*; do
  descriptor_target="$(readlink "$descriptor" 2>/dev/null || true)"
  case "$descriptor_target" in socket:* ) exit 1 ;; esac
done

grep -Eq '^role=(app|cloud|database|files|storage|logs)$' /run/backupsheep-egress/ready
grep -Eq '^mode=(deny|allowlist|public)$' /run/backupsheep-egress/ready
grep -Eq '^interface=[A-Za-z0-9_.:-]{1,15}$' /run/backupsheep-egress/ready
awk -F= '$1 == "peer_count" && $2 >= 2 && $2 <= 32 { found=1 } END { exit !found }' \
  /run/backupsheep-egress/ready
grep -Eq '^peers_sha256=[0-9a-f]{64}$' /run/backupsheep-egress/ready
grep -Eq '^dns_names_sha256=[0-9a-f]{64}$' /run/backupsheep-egress/ready
grep -Eq '^rules_sha256=[0-9a-f]{64}$' /run/backupsheep-egress/ready
grep -qx 'status=ready' /run/backupsheep-egress/reconciler-state
grep -Eq '^peers_sha256=[0-9a-f]{64}$' /run/backupsheep-egress/reconciler-state
grep -Eq '^lease_seconds=[0-9]{1,3}$' /run/backupsheep-egress/reconciler-state
grep -Eq '^renewed_monotonic_seconds=[0-9]+$' /run/backupsheep-egress/reconciler-state
grep -qx 'environment=minimal-shell-only' /run/backupsheep-egress/reconciler-state
lease_seconds="$(awk -F= '$1 == "lease_seconds" { print $2; exit }' \
  /run/backupsheep-egress/reconciler-state)"
renewed_monotonic_seconds="$(awk -F= '$1 == "renewed_monotonic_seconds" { print $2; exit }' \
  /run/backupsheep-egress/reconciler-state)"
current_monotonic_seconds="$(cut -d. -f1 /proc/uptime)"
case "$lease_seconds" in ''|*[!0-9]*) exit 1 ;; esac
case "$renewed_monotonic_seconds" in ''|*[!0-9]*) exit 1 ;; esac
case "$current_monotonic_seconds" in ''|*[!0-9]*) exit 1 ;; esac
[ "$lease_seconds" -ge 15 ] && [ "$lease_seconds" -le 912 ]
renewal_age=$((current_monotonic_seconds - renewed_monotonic_seconds))
[ "$renewal_age" -ge 0 ] && [ "$renewal_age" -lt "$lease_seconds" ]
tr '\000' '\n' < /proc/1/cmdline | grep -qx monitor

mode="$(awk -F= '$1 == "mode" { print $2; exit }' /run/backupsheep-egress/ready)"
if [ "$mode" != public ]; then
  validate_dns_witness() {
    witness_state="$1"
    witness_uid="$2"
    witness_executable="$3"
    [ -f "$witness_state" ] && [ ! -L "$witness_state" ] \
      && [ "$(stat -c '%u:%g:%a:%h' "$witness_state")" = '0:0:444:1' ]
    grep -qx status=ready "$witness_state"
    witness_pid="$(awk -F= '$1 == "pid" { print $2; exit }' "$witness_state")"
    case "$witness_pid" in ''|0|*[!0-9]*) return 1 ;; esac
    [ -r "/proc/${witness_pid}/status" ]
    [ "$(awk '/^State:/ { print $2; exit }' "/proc/${witness_pid}/status")" != Z ]
    [ "$(awk '/^Uid:/ { print $2 ":" $3 ":" $4 ":" $5 }' "/proc/${witness_pid}/status")" = \
        "${witness_uid}:${witness_uid}:${witness_uid}:${witness_uid}" ]
    [ "$(awk '/^Gid:/ { print $2 ":" $3 ":" $4 ":" $5 }' "/proc/${witness_pid}/status")" = \
        "${witness_uid}:${witness_uid}:${witness_uid}:${witness_uid}" ]
    [ "$(awk '$1 == "Groups:" { print NF; exit }' "/proc/${witness_pid}/status")" = 1 ]
    for capability in CapInh CapPrm CapEff CapBnd CapAmb; do
      [ "$(awk -v wanted="${capability}:" '$1 == wanted { print $2; exit }' \
          "/proc/${witness_pid}/status")" = '0000000000000000' ]
    done
    [ "$(awk '$1 == "NoNewPrivs:" { print $2; exit }' "/proc/${witness_pid}/status")" = 1 ]
    tr '\000' '\n' < "/proc/${witness_pid}/cmdline" | grep -qx "$witness_executable"
  }
  validate_dns_witness /run/backupsheep-egress/resolver-state 10021 \
    /usr/local/bin/backupsheep-dns-proxy
  validate_dns_witness /run/backupsheep-egress/forwarder-state 10022 \
    /usr/local/bin/backupsheep-dns-forwarder
  [ -S /run/backupsheep-egress/dns-forwarder/upstream.sock ]
  [ "$(stat -c '%u:%g:%a:%h' /run/backupsheep-egress/dns-forwarder/upstream.sock)" = \
      '10022:10022:622:1' ]
else
  [ ! -e /run/backupsheep-egress/resolver-state ]
  [ ! -e /run/backupsheep-egress/forwarder-state ]
  [ ! -e /run/backupsheep-egress/dns-forwarder ]
fi
