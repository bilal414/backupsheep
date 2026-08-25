#!/bin/sh
# Prove that the active guard has installed a policy and discarded its privilege.
set -eu

[ -f /run/backupsheep-egress/ready ] \
  && [ ! -L /run/backupsheep-egress/ready ] \
  && [ "$(stat -c '%u:%g:%a:%h' /run/backupsheep-egress/ready)" = '0:0:400:1' ]

status_value() {
  awk -v wanted="$1:" '$1 == wanted { print $2; exit }' /proc/1/status
}

[ "$(awk '/^Uid:/ { print $2 ":" $3 ":" $4 ":" $5 }' /proc/1/status)" = '10020:10020:10020:10020' ]
[ "$(awk '/^Gid:/ { print $2 ":" $3 ":" $4 ":" $5 }' /proc/1/status)" = '10020:10020:10020:10020' ]
for capability in CapInh CapPrm CapEff CapBnd CapAmb; do
  value="$(status_value "$capability")"
  case "$value" in ''|*[!0]*) exit 1 ;; esac
done
[ "$(status_value NoNewPrivs)" = 1 ]

grep -Eq '^role=(app|cloud|database|files|storage|logs)$' /run/backupsheep-egress/ready
grep -Eq '^mode=(public|allowlist)$' /run/backupsheep-egress/ready
grep -Eq '^interface=[A-Za-z0-9_.:-]{1,15}$' /run/backupsheep-egress/ready
grep -Eq '^rules_sha256=[0-9a-f]{64}$' /run/backupsheep-egress/ready
