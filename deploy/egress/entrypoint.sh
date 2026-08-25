#!/bin/sh
# Install a namespace-local outbound policy, then permanently discard NET_ADMIN.
set -eu
umask 077

fail() {
  printf '%s\n' "BackupSheep egress guard refused startup: $*" >&2
  exit 1
}

[ "$(id -u)" = 0 ] && [ "$(id -g)" = 0 ] \
  || fail "policy bootstrap must start as container root."
[ -d /run/backupsheep-egress ] && [ ! -L /run/backupsheep-egress ] \
  || fail "/run/backupsheep-egress must be a private tmpfs."
[ "$(stat -c '%u:%g:%a' /run/backupsheep-egress)" = '0:0:700' ] \
  || fail "/run/backupsheep-egress must be root-owned mode 0700."

role="${BACKUPSHEEP_EGRESS_ROLE:-}"
case "$role" in
  app|cloud|database|files|storage|logs) ;;
  *) fail "BACKUPSHEEP_EGRESS_ROLE is missing or unsupported." ;;
esac

mode="${BACKUPSHEEP_EGRESS_MODE:-public}"
case "$mode" in
  public|allowlist) ;;
  *) fail "BACKUPSHEEP_EGRESS_MODE must be public or allowlist." ;;
esac

default_routes="$(ip -o -4 route show default 2>/dev/null || true)"
[ "$(printf '%s\n' "$default_routes" | awk 'NF { count++ } END { print count + 0 }')" = 1 ] \
  || fail "the namespace must have exactly one IPv4 default route."
egress_interface="$(printf '%s\n' "$default_routes" | awk '{ for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }')"
case "$egress_interface" in
  ''|*[!A-Za-z0-9_.:-]*) fail "the default-route interface is invalid." ;;
esac
[ "${#egress_interface}" -le 15 ] || fail "the default-route interface is too long."

normalize_cidrs() {
  family="$1"
  raw="$2"
  [ "${#raw}" -le 4096 ] || fail "the ${family} allowlist is too long."
  normalized=''
  count=0
  old_ifs="$IFS"
  IFS=', '
  # Expansion is intentional after a strict character check below; globbing stays
  # disabled so a CIDR can never turn into a filesystem-derived token.
  set -f
  for cidr in $raw; do
    [ -n "$cidr" ] || continue
    count=$((count + 1))
    [ "$count" -le 128 ] || fail "the ${family} allowlist has too many entries."
    case "$family:$cidr" in
      ipv4:*[!0-9./]*) fail "the IPv4 allowlist contains an invalid character." ;;
      ipv6:*[!0-9A-Fa-f:./]*) fail "the IPv6 allowlist contains an invalid character." ;;
    esac
    if [ -n "$normalized" ]; then
      normalized="${normalized}, ${cidr}"
    else
      normalized="$cidr"
    fi
  done
  set +f
  IFS="$old_ifs"
  printf '%s' "$normalized"
}

allow_ipv4="$(normalize_cidrs ipv4 "${BACKUPSHEEP_EGRESS_ALLOW_IPV4:-}")"
allow_ipv6="$(normalize_cidrs ipv6 "${BACKUPSHEEP_EGRESS_ALLOW_IPV6:-}")"
if [ "$mode" = allowlist ] && [ -z "$allow_ipv4" ] && [ -z "$allow_ipv6" ]; then
  fail "allowlist mode requires at least one destination CIDR."
fi

rules=/run/backupsheep-egress/rules.nft
marker=/run/backupsheep-egress/ready

{
  printf '%s\n' 'flush ruleset'
  printf '%s\n' 'table inet backupsheep_egress {'
  printf '%s\n' '  set never_ipv4 { type ipv4_addr; flags interval; elements = { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } }'
  printf '%s\n' '  set never_ipv6 { type ipv6_addr; flags interval; elements = { ::/128, ::1/128, fd00:ec2::254/128 } }'
  printf '%s\n' '  set special_ipv4 { type ipv4_addr; flags interval; elements = { 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24 } }'
  printf '%s\n' '  set special_ipv6 { type ipv6_addr; flags interval; elements = { 64:ff9b:1::/48, 100::/64, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 } }'
  if [ -n "$allow_ipv4" ]; then
    printf '  set allowed_ipv4 { type ipv4_addr; flags interval; elements = { %s } }\n' "$allow_ipv4"
  fi
  if [ -n "$allow_ipv6" ]; then
    printf '  set allowed_ipv6 { type ipv6_addr; flags interval; elements = { %s } }\n' "$allow_ipv6"
  fi
  printf '%s\n' '  chain output {'
  printf '%s\n' '    type filter hook output priority filter; policy drop;'
  printf '%s\n' '    oifname "lo" accept'
  printf '%s\n' '    ct state established,related accept'
  printf '%s\n' '    meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept'
  printf '%s\n' '    ip daddr @never_ipv4 reject with icmpx type admin-prohibited'
  printf '%s\n' '    ip6 daddr @never_ipv6 reject with icmpx type admin-prohibited'
  # Database and broker bridges are Compose-internal and have no default route.
  # Their exact connected routes remain usable without exposing those subnets on
  # the outward interface.
  printf '    oifname != "%s" accept\n' "$egress_interface"
  if [ -n "$allow_ipv4" ]; then
    printf '%s\n' '    ip daddr @allowed_ipv4 accept'
  fi
  if [ -n "$allow_ipv6" ]; then
    printf '%s\n' '    ip6 daddr @allowed_ipv6 accept'
  fi
  if [ "$mode" = public ]; then
    printf '%s\n' '    ip daddr @special_ipv4 reject with icmpx type admin-prohibited'
    printf '%s\n' '    ip6 daddr @special_ipv6 reject with icmpx type admin-prohibited'
    printf '%s\n' '    meta nfproto { ipv4, ipv6 } accept'
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
nft --file "$rules" >/dev/null \
  || fail "the outbound policy could not be installed."
nft list table inet backupsheep_egress >/dev/null \
  || fail "the outbound policy is not active."

rules_sha256="$(sha256sum "$rules" | awk '{print $1}')"
printf 'role=%s\nmode=%s\ninterface=%s\nrules_sha256=%s\n' \
  "$role" "$mode" "$egress_interface" "$rules_sha256" > "$marker"
chmod 0400 "$marker"

# The sleep process is deliberately PID 1 and has no secret, shell listener, group,
# privilege, or capability (including in its bounding set). The rules persist in the
# shared network namespace after NET_ADMIN is irreversibly discarded.
exec setpriv \
  --reuid=10020 \
  --regid=10020 \
  --clear-groups \
  --inh-caps=-all \
  --ambient-caps=-all \
  --bounding-set=-all \
  --no-new-privs \
  /bin/sleep 2147483647
