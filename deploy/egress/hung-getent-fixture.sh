#!/bin/sh
# Acceptance-only resolver fixture: bootstrap succeeds, the unprivileged monitor hangs.
set -eu

if [ "$(id -u)" = 10020 ]; then
  exec sleep 30
fi
exec /usr/bin/getent "$@"
