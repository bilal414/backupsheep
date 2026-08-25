#!/bin/sh
# Disposable Linux-kernel acceptance test for the namespace-local egress policy.
set -eu
umask 077

image="${1:-backupsheep-egress:test}"
suffix="$$"
external_net="backupsheep-egress-test-external-${suffix}"
internal_net="backupsheep-egress-test-internal-${suffix}"
external_server="backupsheep-egress-test-external-server-${suffix}"
internal_server="backupsheep-egress-test-internal-server-${suffix}"
guard="backupsheep-egress-test-guard-${suffix}"
alpine='alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412'
python='python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4'

cleanup() {
  docker rm -f "$guard" "$external_server" "$internal_server" >/dev/null 2>&1 || true
  docker network rm "$external_net" "$internal_net" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

fail() {
  printf '%s\n' "egress policy acceptance failed: $*" >&2
  if docker inspect "$guard" >/dev/null 2>&1; then
    docker logs "$guard" >&2 || true
  fi
  exit 1
}

run_guard() {
  role="$1"
  mode="$2"
  allow_ipv4="${3:-}"
  docker run -d --name "$guard" \
    --network "$external_net" --network "$internal_net" \
    --cap-drop ALL \
    --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /run/backupsheep-egress:rw,noexec,nosuid,nodev,size=1m,mode=0700 \
    --pids-limit 32 --memory 64m --cpus 0.25 \
    -e "BACKUPSHEEP_EGRESS_ROLE=${role}" \
    -e "BACKUPSHEEP_EGRESS_MODE=${mode}" \
    -e "BACKUPSHEEP_EGRESS_ALLOW_IPV4=${allow_ipv4}" \
    "$image" >/dev/null
  for _attempt in 1 2 3 4 5; do
    if docker exec "$guard" /usr/local/bin/backupsheep-egress-healthcheck \
        >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "guard did not become healthy."
}

client() {
  docker run --rm --network "container:${guard}" "$alpine" "$@"
}

docker network create "$external_net" >/dev/null
docker network create --internal "$internal_net" >/dev/null
docker run -d --name "$external_server" --network "$external_net" \
  "$python" python -m http.server 8080 >/dev/null
docker run -d --name "$internal_server" --network "$internal_net" \
  "$python" python -m http.server 8080 >/dev/null
external_ip="$(docker inspect "$external_server" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
internal_ip="$(docker inspect "$internal_server" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
case "${external_ip}:${internal_ip}" in *[!0-9.:]*) fail "test network address is invalid." ;; esac

# Public mode keeps the lane's private DB/broker bridge usable but denies another
# private host reached through the outward interface, metadata, and reserved ranges.
run_guard database public
client wget -q -T 3 -O /dev/null "http://${internal_ip}:8080/" \
  || fail "the internal lane was blocked."
if client wget -q -T 2 -O /dev/null "http://${external_ip}:8080/" 2>/dev/null; then
  fail "an unapproved private destination was reachable on the outward interface."
fi
if client wget -q -T 2 -O /dev/null \
    http://169.254.169.254/latest/meta-data/ 2>/dev/null; then
  fail "cloud metadata was reachable."
fi
client nc -z -w 5 1.1.1.1 443 || fail "ordinary public HTTPS egress was blocked."
docker rm -f "$guard" >/dev/null

# A reviewed private target can be added explicitly. Cloud metadata remains a
# non-overridable denial even if a poisoned environment tries to allow it.
run_guard files public "${external_ip}/32,169.254.169.254/32"
client wget -q -T 3 -O /dev/null "http://${external_ip}:8080/" \
  || fail "an explicitly approved private destination was blocked."
if client wget -q -T 2 -O /dev/null \
    http://169.254.169.254/latest/meta-data/ 2>/dev/null; then
  fail "an allowlist entry overrode the metadata denial."
fi
docker rm -f "$guard" >/dev/null

# Strict mode permits only the listed outward CIDRs (plus the isolated internal
# lane); this is suitable for a separately governed egress proxy.
run_guard storage allowlist 1.1.1.1/32
client nc -z -w 5 1.1.1.1 443 || fail "the strict allowlist blocked its approved target."
if client nc -z -w 2 1.0.0.1 443 2>/dev/null; then
  fail "strict mode permitted an unlisted public destination."
fi
docker rm -f "$guard" >/dev/null

# Reject shell/nft injection characters before a live ruleset is touched.
if docker run --name "$guard" --network "$external_net" \
    --cap-drop ALL \
    --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --security-opt no-new-privileges:true --read-only \
    --tmpfs /run/backupsheep-egress:rw,noexec,nosuid,nodev,size=1m,mode=0700 \
    -e BACKUPSHEEP_EGRESS_ROLE=cloud \
    -e BACKUPSHEEP_EGRESS_MODE=public \
    -e 'BACKUPSHEEP_EGRESS_ALLOW_IPV4=1.1.1.1/32;flush ruleset' \
    "$image" >/dev/null 2>&1; then
  fail "an injected CIDR value was accepted."
fi
docker rm "$guard" >/dev/null

printf '%s\n' 'BackupSheep egress policy acceptance passed.'
