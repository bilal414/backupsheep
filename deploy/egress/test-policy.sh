#!/bin/sh
# Disposable Linux-kernel acceptance test for the namespace-local egress policy.
set -eu
umask 077

image="${1:-backupsheep-egress:test}"
suffix="$$"
subnet_octet=$((($$ % 200) + 20))
external_net="backupsheep-egress-test-external-${suffix}"
database_net="backupsheep-egress-test-database-${suffix}"
broker_net="backupsheep-egress-test-broker-${suffix}"
external_allowed="backupsheep-egress-test-external-allowed-${suffix}"
external_unapproved="backupsheep-egress-test-external-unapproved-${suffix}"
database_server="backupsheep-egress-test-database-server-${suffix}"
broker_server="backupsheep-egress-test-broker-server-${suffix}"
internal_unapproved="backupsheep-egress-test-internal-unapproved-${suffix}"
gateway_backend="backupsheep-egress-test-gateway-backend-${suffix}"
address_holder="backupsheep-egress-test-address-holder-${suffix}"
guard="backupsheep-egress-test-guard-${suffix}"
probe="backupsheep-egress-test-probe-${suffix}"
namespace_client="backupsheep-egress-test-namespace-client-${suffix}"
persistent_client="backupsheep-egress-test-persistent-client-${suffix}"
alpine='alpine:3.22.5@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce'
python='python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4'

cleanup() {
  docker rm -f \
    "$guard" "$probe" "$namespace_client" "$persistent_client" \
    "$external_allowed" "$external_unapproved" \
    "$database_server" "$broker_server" "$internal_unapproved" \
    "$gateway_backend" "$address_holder" >/dev/null 2>&1 || true
  docker network rm "$external_net" "$database_net" "$broker_net" \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

fail() {
  printf '%s\n' "egress policy acceptance failed: $*" >&2
  if docker inspect "$guard" >/dev/null 2>&1; then
    docker logs "$guard" >&2 || true
    docker exec "$guard" nft list table inet backupsheep_egress >&2 || true
  fi
  exit 1
}

container_ip() {
  container_name="$1"
  network_name="$2"
  docker inspect "$container_name" \
    --format "{{(index .NetworkSettings.Networks \"${network_name}\").IPAddress}}"
}

start_database_server() {
  docker run -d --name "$database_server" \
    --network "$database_net" --network-alias egress-test-database \
    "$python" /bin/sh -c \
      'python -c '\''import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 5432))
s.listen()
while True:
    connection, _address = s.accept()
    with connection:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            connection.sendall(data)'\'' >/dev/null 2>&1 & python -m http.server 15432 >/dev/null 2>&1 & wait' \
    >/dev/null
}

exercise_established_tuple_revocation() {
  database_ip="$(container_ip "$database_server" "$database_net")"
  # Keep a minimal init as PID 1 so Python can genuinely stop itself; Linux PID 1
  # signal semantics otherwise ignore this fixture's self-SIGSTOP and let it race
  # through the second exchange before tuple revocation.
  docker run -d --init --name "$persistent_client" --network "container:${guard}" \
    --user "${workload_uid}:${workload_uid}" --cap-drop ALL \
    --security-opt no-new-privileges:true --read-only "$python" \
    python -c 'import os, signal, socket, sys
connection = socket.create_connection((sys.argv[1], 5432), timeout=3)
connection.sendall(b"FIRST")
if connection.recv(5) != b"FIRST":
    raise SystemExit(2)
print("FIRST", flush=True)
os.kill(os.getpid(), signal.SIGSTOP)
connection.settimeout(1)
connection.sendall(b"SECOND")
if connection.recv(6) != b"SECOND":
    raise SystemExit(3)
print("SECOND", flush=True)' "$database_ip" >/dev/null

  first_observed=false
  for _attempt in $(seq 1 30); do
    if docker logs "$persistent_client" 2>&1 | grep -Fxq FIRST; then
      first_observed=true
      break
    fi
    sleep 0.1
  done
  [ "$first_observed" = true ] \
    || fail "the persistent-flow revocation fixture did not establish its first exchange."
  docker exec "$persistent_client" /bin/sh -ec '
    set -- $(cat /proc/1/task/1/children)
    [ "$#" -eq 1 ]
    grep -Eq "^State:[[:space:]]+T" "/proc/$1/status"
  ' || fail "the persistent-flow revocation fixture was not stopped before tuple removal."

  # Freeze reconciliation but leave the still-live strict UID lease intact, then
  # revoke only the current database tuple. A generic established-flow accept
  # would let SECOND bypass this empty set.
  docker kill --signal STOP "$guard" >/dev/null
  docker exec "$guard" nft flush set inet backupsheep_egress internal_ipv4
  docker kill --signal CONT "$persistent_client" >/dev/null
  persistent_exit="$(docker wait "$persistent_client")"
  [ "$persistent_exit" != 0 ] \
    || fail "an established workload flow survived removal of its current database tuple."
  if docker logs "$persistent_client" 2>&1 | grep -Fxq SECOND; then
    fail "the revoked established workload flow completed a second exchange."
  fi
  active_lease="$(docker exec "$guard" \
    nft list set inet backupsheep_egress strict_workload_lease 2>/dev/null || true)"
  printf '%s\n' "$active_lease" | grep -Fq 'elements = {' \
    || fail "the persistent-flow test exceeded the independent strict lease."
  docker rm "$persistent_client" >/dev/null
  docker kill --signal CONT "$guard" >/dev/null
  wait_for_guard
  must_connect "$database_ip" 5432 \
    "the database tuple was not restored after the revocation test."
}

run_guard() {
  role="$1"
  mode="$2"
  allow_ipv4_tcp_endpoints="$3"
  allow_dns_names="$4"
  getent_fixture="${5:-}"
  case "$role" in
    app) workload_uid=10001 ;;
    database) workload_uid=10002 ;;
    files) workload_uid=10003 ;;
    storage) workload_uid=10004 ;;
    logs) workload_uid=10005 ;;
    cloud) workload_uid=10008 ;;
    *) fail "the test requested an unsupported workload role." ;;
  esac
  set -- docker run -d --name "$guard" --restart on-failure:20 \
    --network "$external_net" --network "$database_net" --network "$broker_net" \
    --cap-drop ALL \
    --cap-add CHOWN --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /run/backupsheep-egress:rw,noexec,nosuid,nodev,size=1m,mode=0700 \
    --pids-limit 32 --memory 64m --cpus 0.25
  if [ -n "$getent_fixture" ]; then
    [ -f "$getent_fixture" ] && [ ! -L "$getent_fixture" ] \
      && [ -x "$getent_fixture" ] \
      || fail "the hung-DNS getent fixture is not a regular executable."
    set -- "$@" \
      --mount "type=bind,src=${getent_fixture},dst=/usr/local/bin/getent,readonly"
  fi
  set -- "$@" \
    -e "BACKUPSHEEP_EGRESS_ROLE=${role}" \
    -e BACKUPSHEEP_EGRESS_POLICY_GENERATION=2 \
    -e "BACKUPSHEEP_EGRESS_MODE=${mode}" \
    -e "BACKUPSHEEP_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS=${allow_ipv4_tcp_endpoints}" \
    -e "BACKUPSHEEP_EGRESS_ALLOW_DNS_NAMES=${allow_dns_names}" \
    -e BACKUPSHEEP_EGRESS_DATABASE_HOST=egress-test-database \
    -e BACKUPSHEEP_EGRESS_DATABASE_PORT=5432 \
    -e BACKUPSHEEP_EGRESS_BROKER_HOST=egress-test-broker \
    -e BACKUPSHEEP_EGRESS_BROKER_PORT=5672 \
    -e BACKUPSHEEP_EGRESS_DNS_REFRESH_SECONDS=1 \
    "$image"
  "$@" >/dev/null
  wait_for_guard
}

wait_for_guard() {
  for _attempt in $(seq 1 30); do
    if docker exec "$guard" /usr/local/bin/backupsheep-egress-healthcheck \
        >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "guard did not become healthy."
}

client() {
  docker run --rm --network "container:${guard}" \
    --user "${workload_uid}:${workload_uid}" --cap-drop ALL \
    --security-opt no-new-privileges:true "$alpine" "$@"
}

dns_probe() {
  docker run --rm -i --network "container:${guard}" \
    --user "${workload_uid}:${workload_uid}" --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --read-only "$python" python - "$@" < deploy/egress/dns-probe.py
}

must_connect() {
  destination="$1"
  port="$2"
  reason="$3"
  client nc -z -w 5 "$destination" "$port" \
    || fail "$reason"
}

must_block() {
  destination="$1"
  port="$2"
  reason="$3"
  if client nc -z -w 2 "$destination" "$port" 2>/dev/null; then
    fail "$reason"
  fi
}

exercise_policy() {
  current_database_ip="$(container_ip "$database_server" "$database_net")"
  current_broker_ip="$(container_ip "$broker_server" "$broker_net")"
  current_unapproved_ip="$(container_ip "$internal_unapproved" "$database_net")"

  [ "$(docker inspect "$guard" --format '{{len .Mounts}}')" = 0 ] \
    || fail "the no-secret guard unexpectedly received a bind or volume mount."
  [ "$(docker inspect "$guard" --format '{{.HostConfig.ReadonlyRootfs}}')" = true ] \
    || fail "the no-secret guard root filesystem is writable."
  # The runtime healthcheck is deliberately capability-free and must remain valid
  # after PID 1 has become a non-dumpable UID 10020 process.
  for _health_attempt in 1 2 3; do
    docker exec "$guard" /usr/local/bin/backupsheep-egress-healthcheck \
      >/dev/null 2>&1 \
      || fail "a repeated post-privilege-drop healthcheck failed."
    sleep 1
  done

  must_connect "$current_database_ip" 5432 \
    "the exact database address/port tuple was blocked."
  must_connect "$current_broker_ip" 5672 \
    "the exact broker address/port tuple was blocked."
  must_connect "$external_allowed_ip" 8080 \
    "the explicitly approved outward destination was blocked."
  if [ "$mode" = allowlist ]; then
    must_block "$external_allowed_ip" 9090 \
      "an unapproved port on an approved outward address was reachable."
  else
    must_connect "$external_allowed_ip" 9090 \
      "public mode did not retain its explicit private compatibility endpoint."
  fi

  must_block "$current_database_ip" 15432 \
    "an unapproved port on the database peer was reachable."
  must_block "$current_unapproved_ip" 5432 \
    "an unapproved peer on the database bridge was reachable."
  must_block "$external_unapproved_ip" 8080 \
    "an unapproved peer on the outward bridge was reachable."
  must_block "$external_gateway" "$gateway_port" \
    "the Docker/host gateway was reachable."
  must_block 169.254.169.254 80 \
    "cloud metadata was reachable."

  ruleset="$(docker exec "$guard" nft list table inet backupsheep_egress)"
  printf '%s\n' "$ruleset" | grep -Fq " . ${current_database_ip} . 5432" \
    || fail "the database tuple is absent from the active policy."
  printf '%s\n' "$ruleset" | grep -Fq " . ${current_broker_ip} . 5672" \
    || fail "the broker tuple is absent from the active policy."
  printf '%s\n' "$ruleset" \
    | grep -Fq 'oifname . ip daddr . tcp dport @internal_ipv4 accept' \
    || fail "the exact IPv4 tuple-set rule is absent from the active policy."
  if [ "$mode" = allowlist ]; then
    printf '%s\n' "$ruleset" \
      | grep -Fq "${external_allowed_ip} . 8080" \
      || fail "the exact outward address/port tuple is absent from the active policy."
    if printf '%s\n' "$ruleset" | grep -Fq "${external_allowed_ip} . 9090"; then
      fail "the active policy contains an unapproved outward port."
    fi
  fi
  if printf '%s\n' "$ruleset" | grep -Fq 'oifname !='; then
    fail "the policy still broadly trusts non-default interfaces."
  fi
}

# Use small explicit test-only subnets so the harness remains runnable when a full
# BackupSheep topology has consumed Docker's default local address pools.
docker network create \
  --subnet "10.253.${subnet_octet}.0/28" \
  --gateway "10.253.${subnet_octet}.1" \
  "$external_net" >/dev/null
docker network create --internal \
  --subnet "10.253.${subnet_octet}.16/28" \
  --gateway "10.253.${subnet_octet}.17" \
  "$database_net" >/dev/null
docker network create --internal \
  --subnet "10.253.${subnet_octet}.32/28" \
  --gateway "10.253.${subnet_octet}.33" \
  "$broker_net" >/dev/null

start_database_server
docker run -d --name "$broker_server" \
  --network "$broker_net" --network-alias egress-test-broker \
  "$python" python -m http.server 5672 >/dev/null
docker run -d --name "$internal_unapproved" --network "$database_net" \
  "$python" python -m http.server 5432 >/dev/null
docker run -d --name "$external_allowed" \
  --network "$external_net" --network-alias egress-test-approved \
  "$python" /bin/sh -c \
    'python -m http.server 8080 >/dev/null 2>&1 & python -m http.server 9090 >/dev/null 2>&1 & wait' \
  >/dev/null
docker run -d --name "$external_unapproved" --network "$external_net" \
  "$python" python -m http.server 8080 >/dev/null

# Bind a known-live endpoint in the daemon's host network namespace, whose bridge
# address is the default gateway. An unguarded control connection proves the target
# is reachable before each guarded denial is trusted.
gateway_port=$((20000 + ($$ % 20000)))
docker run -d --name "$gateway_backend" --network host \
  "$python" python -m http.server "$gateway_port" >/dev/null
external_gateway="$(docker network inspect "$external_net" \
  --format '{{(index .IPAM.Config 0).Gateway}}')"
case "${gateway_port}:${external_gateway}" in
  *[!0-9.:]*) fail "the gateway acceptance target is invalid." ;;
esac
gateway_control_ready=false
for _attempt in $(seq 1 10); do
  if docker run --rm --network "$external_net" "$alpine" \
      nc -z -w 2 "$external_gateway" "$gateway_port"; then
    gateway_control_ready=true
    break
  fi
  sleep 1
done
[ "$gateway_control_ready" = true ] \
  || fail "the unguarded control could not reach the live gateway endpoint."

external_allowed_ip="$(container_ip "$external_allowed" "$external_net")"
external_unapproved_ip="$(container_ip "$external_unapproved" "$external_net")"
case "${external_allowed_ip}:${external_unapproved_ip}" in
  *[!0-9.:]*) fail "a test network address is invalid." ;;
esac

# Public mode may reach ordinary public addresses plus an explicit private target,
# while internal bridges remain exact peer/port allowlists.
run_guard database public "${external_allowed_ip}/32:8080,${external_allowed_ip}/32:9090" ''
exercise_policy
public_ruleset="$(docker exec "$guard" nft list table inet backupsheep_egress)"
if printf '%s\n' "$public_ruleset" | grep -Fq 'chain dns_redirect'; then
  fail "public mode unexpectedly changed Docker DNS behavior."
fi
if docker exec "$guard" test -e /run/backupsheep-egress/resolver-state; then
  fail "public mode unexpectedly started the strict DNS resolver."
fi
# The exact internal tuples are kernel-expiring even in public outward mode. If
# the reconciler cannot run, a stale/reassigned database address loses access
# without changing public mode's intentionally permissive outward behavior.
docker kill --signal STOP "$guard" >/dev/null
sleep 17
must_connect "$external_allowed_ip" 8080 \
  "public outward mode changed while its reconciler was stopped."
must_block "$(container_ip "$database_server" "$database_net")" 5432 \
  "a public-mode internal tuple survived its kernel expiration deadline."
public_internal_after_expiry="$(docker exec "$guard" \
  nft list set inet backupsheep_egress internal_ipv4 2>/dev/null || true)"
if printf '%s\n' "$public_internal_after_expiry" | grep -Fq 'elements = {'; then
  fail "public-mode internal peer elements did not expire in the kernel."
fi
docker kill --signal CONT "$guard" >/dev/null
wait_for_guard
must_connect "$(container_ip "$database_server" "$database_net")" 5432 \
  "public-mode internal tuples were not renewed after reconciliation resumed."
docker rm -f "$guard" >/dev/null

# Strict mode permits only listed outward address/CIDR and TCP-port tuples. Internal
# DB/broker access stays exact and an outward tuple cannot authorize another port or
# any peer on an internal interface.
run_guard storage allowlist "${external_allowed_ip}/32:8080" 'egress-test-approved'
exercise_policy
exercise_established_tuple_revocation
# Strict DNS accepts only exact reviewed names and only address lookups. Mixed case,
# the local transaction ID, and an EDNS record are deliberately supplied by the raw
# probe; the proxy canonicalizes/strips them before using Docker DNS. Arbitrary and
# suffix-derived qnames are refused locally over both UDP and TCP.
dns_probe udp EgReSs-TeSt-ApPrOvEd 1 0 \
  || fail "an exact approved UDP A lookup was not safely proxied."
dns_probe tcp EGRESS-TEST-APPROVED 28 0 \
  || fail "an exact approved TCP AAAA lookup was not safely proxied."
dns_probe udp secret.egress-test-approved 1 5 \
  || fail "a suffix-derived DNS tunneling name was not refused."
dns_probe tcp exfil-canary.attacker.invalid 1 5 \
  || fail "an arbitrary DNS tunneling name was not refused over TCP."
dns_probe udp egress-test-approved 16 5 \
  || fail "a non-address query type was not refused."
strict_ruleset="$(docker exec "$guard" nft list table inet backupsheep_egress)"
printf '%s\n' "$strict_ruleset" | grep -Fq 'chain dns_redirect' \
  || fail "strict mode did not install its workload DNS redirect."
printf '%s\n' "$strict_ruleset" \
  | grep -Fq 'meta skuid != 10020 meta skuid != 10021 meta skuid != 10022 ip daddr 127.0.0.11 udp dport 53 redirect to :1053' \
  || fail "strict mode lacks the UID-separated UDP Docker-DNS redirect."
strict_interface="$(docker exec "$guard" awk -F= \
  '$1 == "interface" { print $2 }' /run/backupsheep-egress/ready)"
printf '%s\n' "$strict_ruleset" \
  | grep -Fq "oifname \"${strict_interface}\" meta l4proto { tcp, udp } th dport 53 reject" \
  || fail "strict mode did not deny direct DNS on its outward interface."
resolver_pid="$(docker exec "$guard" awk -F= '$1 == "pid" { print $2 }' \
  /run/backupsheep-egress/resolver-state)"
forwarder_pid="$(docker exec "$guard" awk -F= '$1 == "pid" { print $2 }' \
  /run/backupsheep-egress/forwarder-state)"
for dns_identity in "${resolver_pid}:10021:parser" "${forwarder_pid}:10022:forwarder"; do
  dns_pid="${dns_identity%%:*}"
  dns_remainder="${dns_identity#*:}"
  dns_uid="${dns_remainder%%:*}"
  dns_label="${dns_remainder#*:}"
  for capability in CapInh CapPrm CapEff CapBnd CapAmb; do
    [ "$(docker exec "$guard" awk -v wanted="${capability}:" \
        '$1 == wanted { print $2; exit }' "/proc/${dns_pid}/status")" = \
        '0000000000000000' ] \
      || fail "the strict DNS ${dns_label} retained ${capability}."
  done
  docker exec "$guard" grep -q "^Uid:[[:space:]]*${dns_uid}[[:space:]]*${dns_uid}[[:space:]]*${dns_uid}[[:space:]]*${dns_uid}" \
    "/proc/${dns_pid}/status" \
    || fail "the strict DNS ${dns_label} is not isolated under UID ${dns_uid}."
done
printf '%s\n' "$strict_ruleset" | grep -Eq 'meta skuid 10021 counter .* reject' \
  || fail "the hostile-packet parser is not denied every non-DNS-reply flow."
printf '%s\n' "$strict_ruleset" \
  | grep -Eq 'meta skuid 10021 ip saddr 127\.0\.0\.1 ip daddr 127\.0\.0\.1 udp sport 1053 ct direction reply counter packets [1-9][0-9]*' \
  || fail "legitimate redirected UDP DNS did not use the parser's exact reply-only rule."
printf '%s\n' "$strict_ruleset" \
  | grep -Eq 'meta skuid 10021 ip saddr 127\.0\.0\.1 ip daddr 127\.0\.0\.1 tcp sport 1053 ct direction reply counter packets [1-9][0-9]*' \
  || fail "legitimate redirected TCP DNS did not use the parser's exact reply-only rule."
printf '%s\n' "$strict_ruleset" \
  | grep -Eq 'meta skuid 10022 ct original ip daddr 127\.0\.0\.11 ct original proto-dst 53 meta l4proto \{ tcp, udp \} counter packets [1-9][0-9]*' \
  || fail "the structured DNS forwarder did not use its one exact translated upstream rule."
printf '%s\n' "$strict_ruleset" | grep -Eq 'meta skuid 10022 counter .* reject' \
  || fail "the structured DNS forwarder is not denied every other destination."
if docker exec --user 10021:10021 "$guard" getent ahostsv4 example.com \
    >/dev/null 2>&1; then
  fail "the hostile-packet parser UID retained direct upstream DNS access."
fi

# A compromise of the hostile DNS-packet parser must not become a loopback pivot
# into a workload service. Start known-live TCP and UDP echo canaries in the same
# network namespace, prove the leased workload UID can reach both, then prove
# parser-UID payloads never arrive.
docker run -d --name "$persistent_client" --network "container:${guard}" \
  --user "${workload_uid}:${workload_uid}" --cap-drop ALL \
  --security-opt no-new-privileges:true --read-only "$python" \
  python -u -c 'import selectors, socket
selector = selectors.DefaultSelector()
tcp = socket.socket()
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("127.0.0.1", 18081))
tcp.listen()
selector.register(tcp, selectors.EVENT_READ, "TCP")
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("127.0.0.1", 18082))
selector.register(udp, selectors.EVENT_READ, "UDP")
while True:
    for key, _events in selector.select():
        if key.data == "TCP":
            connection, _address = tcp.accept()
            with connection:
                data = connection.recv(256)
                print("TCP:" + data.decode("ascii"), flush=True)
                connection.sendall(data)
        else:
            data, address = udp.recvfrom(256)
            print("UDP:" + data.decode("ascii"), flush=True)
            udp.sendto(data, address)' >/dev/null
loopback_canary_ready=false
for _attempt in $(seq 1 20); do
  if docker run --rm --network "container:${guard}" \
      --user "${workload_uid}:${workload_uid}" --cap-drop ALL \
      --security-opt no-new-privileges:true --read-only "$python" \
      python -c 'import socket
tcp = socket.create_connection(("127.0.0.1", 18081), timeout=1)
tcp.sendall(b"WORKLOAD-TCP")
assert tcp.recv(256) == b"WORKLOAD-TCP"
tcp.close()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(1)
udp.sendto(b"WORKLOAD-UDP", ("127.0.0.1", 18082))
assert udp.recvfrom(256)[0] == b"WORKLOAD-UDP"'; then
    loopback_canary_ready=true
    break
  fi
  sleep 0.1
done
[ "$loopback_canary_ready" = true ] \
  || fail "the workload control could not reach the live loopback canaries."
docker logs "$persistent_client" 2>&1 | grep -Fxq 'TCP:WORKLOAD-TCP' \
  || fail "the TCP loopback canary did not observe its workload control."
docker logs "$persistent_client" 2>&1 | grep -Fxq 'UDP:WORKLOAD-UDP' \
  || fail "the UDP loopback canary did not observe its workload control."
docker exec --user 10021:10021 "$guard" /bin/sh -c \
  'printf %s PARSER-TCP | nc -w 1 127.0.0.1 18081' >/dev/null 2>&1 || true
docker exec --user 10021:10021 "$guard" /bin/sh -c \
  'printf %s PARSER-UDP | nc -u -w 1 127.0.0.1 18082' >/dev/null 2>&1 || true
sleep 1
if docker logs "$persistent_client" 2>&1 | grep -Fq PARSER-TCP; then
  fail "the hostile-packet parser initiated a TCP loopback connection."
fi
if docker logs "$persistent_client" 2>&1 | grep -Fq PARSER-UDP; then
  fail "the hostile-packet parser initiated a UDP loopback flow."
fi
docker rm -f "$persistent_client" >/dev/null

for socket_kind in SOCK_DGRAM SOCK_STREAM; do
  docker run --rm --network "container:${guard}" \
    --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true \
    --read-only "$python" python -c \
    'import socket, sys
s = socket.socket(socket.AF_INET, getattr(socket, sys.argv[1]))
try:
    s.bind(("127.0.0.1", 1053))
except OSError:
    raise SystemExit(0)
raise SystemExit(1)' "$socket_kind" \
    || fail "a workload could replace the ${socket_kind} strict DNS listener."
done
docker run -d --name "$namespace_client" --network "container:${guard}" \
  --user "${workload_uid}:${workload_uid}" --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only "$alpine" sleep 2147483647 >/dev/null
guard_host_pid="$(docker inspect "$guard" --format '{{.State.Pid}}')"
if docker exec "$namespace_client" kill -0 "$guard_host_pid" 2>/dev/null; then
  fail "the namespace-sharing application could signal the guard PID."
fi
if docker exec "$namespace_client" test -e /usr/local/bin/backupsheep-egress-guard; then
  fail "the namespace-sharing application could see the guard mount namespace."
fi
docker exec "$namespace_client" /bin/sh -c \
  "awk '/^Cap(Inh|Prm|Eff|Bnd|Amb):/ { count++; if (\$2 !~ /^0+\$/) exit 1 } END { if (count != 5) exit 1 }' /proc/1/status" \
  || fail "the namespace-sharing application retained a capability."

# Freeze the only lease-renewing userspace process. No emergency nft command can
# run in this state, so this directly proves the kernel deadline closes strict
# egress (including established-flow handling) for a still-running workload.
docker kill --signal STOP "$guard" >/dev/null
sleep 17
strict_lease_after_expiry="$(docker exec "$guard" \
  nft list set inet backupsheep_egress strict_workload_lease 2>/dev/null || true)"
if printf '%s\n' "$strict_lease_after_expiry" | grep -Fq 'elements = {'; then
  fail "the strict workload lease did not expire in the kernel."
fi
strict_internal_after_expiry="$(docker exec "$guard" \
  nft list set inet backupsheep_egress internal_ipv4 2>/dev/null || true)"
if printf '%s\n' "$strict_internal_after_expiry" | grep -Fq 'elements = {'; then
  fail "strict internal peer elements did not expire in the kernel."
fi
if docker exec "$namespace_client" nc -z -w 2 "$external_allowed_ip" 8080 \
    2>/dev/null; then
  fail "strict outward egress survived the kernel lease deadline."
fi
if docker exec "$namespace_client" nc -z -w 2 \
    "$(container_ip "$database_server" "$database_net")" 5432 2>/dev/null; then
  fail "strict internal egress survived the kernel lease deadline."
fi
if docker exec "$guard" /usr/local/bin/backupsheep-egress-healthcheck \
    >/dev/null 2>&1; then
  fail "guard health survived beyond its last successful kernel-lease renewal."
fi
docker kill --signal CONT "$guard" >/dev/null
wait_for_guard
docker exec "$namespace_client" nc -z -w 5 "$external_allowed_ip" 8080 \
  || fail "strict outward egress was not restored by a complete reconciliation."
docker exec "$namespace_client" nc -z -w 5 \
  "$(container_ip "$database_server" "$database_net")" 5432 \
  || fail "strict internal egress was not restored by a complete reconciliation."

# Recreate a DNS-named stateful peer at a different dynamic IP. The unprivileged
# namespace reconciler must atomically refresh in place; the address holder that
# took the old IP remains blocked for the already-running application namespace.
old_database_ip="$(container_ip "$database_server" "$database_net")"
restart_count_before="$(docker inspect "$guard" --format '{{.RestartCount}}')"
docker rm -f "$database_server" >/dev/null
blocked_state_observed=false
for _attempt in $(seq 1 15); do
  active_internal_set="$(docker exec "$guard" \
    nft list set inet backupsheep_egress internal_ipv4 2>/dev/null || true)"
  if docker exec --user 10020:10020 "$guard" grep -qx status=blocked \
      /run/backupsheep-egress/reconciler-state 2>/dev/null \
      && ! printf '%s\n' "$active_internal_set" | grep -Fq 'elements = {'; then
    blocked_state_observed=true
    break
  fi
  sleep 1
done
[ "$blocked_state_observed" = true ] \
  || fail "an absent required peer did not flush both internal sets and block health."
if docker exec "$guard" /usr/local/bin/backupsheep-egress-healthcheck \
    >/dev/null 2>&1; then
  fail "the guard stayed healthy while a required internal peer was absent."
fi
docker run -d --name "$address_holder" --network "$database_net" \
  "$python" python -m http.server 5432 >/dev/null
address_holder_ip="$(container_ip "$address_holder" "$database_net")"
[ "$address_holder_ip" = "$old_database_ip" ] \
  || fail "the unapproved address holder did not receive the stale peer address."
holder_ready=false
for _attempt in $(seq 1 10); do
  if docker run --rm --network "$database_net" "$alpine" \
      nc -z -w 2 "$address_holder_ip" 5432; then
    holder_ready=true
    break
  fi
  sleep 1
done
[ "$holder_ready" = true ] \
  || fail "the unguarded control could not reach the stale-address holder."
if docker exec "$namespace_client" nc -z -w 2 "$address_holder_ip" 5432 \
    2>/dev/null; then
  fail "the absent-peer flush left the stale database address authorized."
fi
start_database_server
new_database_ip="$(container_ip "$database_server" "$database_net")"
[ "$new_database_ip" != "$old_database_ip" ] \
  || fail "the dynamic-IP fixture did not move the database peer."
policy_refreshed=false
for _attempt in $(seq 1 30); do
  active_internal_set="$(docker exec "$guard" \
    nft list set inet backupsheep_egress internal_ipv4 2>/dev/null || true)"
  if printf '%s\n' "$active_internal_set" | grep -Fq " . ${new_database_ip} . 5432" \
      && ! printf '%s\n' "$active_internal_set" | grep -Fq " . ${old_database_ip} . 5432"; then
    policy_refreshed=true
    break
  fi
  sleep 1
done
[ "$policy_refreshed" = true ] \
  || fail "Docker DNS drift did not atomically refresh the in-namespace peer set."
wait_for_guard
restart_count_after="$(docker inspect "$guard" --format '{{.RestartCount}}')"
[ "$restart_count_after" = "$restart_count_before" ] \
  || fail "the reconciler restarted and abandoned the application's network namespace."
must_connect "$new_database_ip" 5432 \
  "the refreshed dynamic database peer tuple was blocked."
docker exec "$namespace_client" nc -z -w 5 "$new_database_ip" 5432 \
  || fail "a long-lived namespace-sharing application lost the refreshed database tuple."
must_block "$address_holder_ip" 5432 \
  "the old/reassigned database address remained authorized."
if docker exec "$namespace_client" nc -z -w 2 "$address_holder_ip" 5432 \
    2>/dev/null; then
  fail "a long-lived namespace-sharing application retained the stale database tuple."
fi
docker rm -f "$namespace_client" >/dev/null
docker rm -f "$guard" >/dev/null

# An omitted mode selects deny: exact internal database/broker tuples and exact
# internal DNS names remain available, while no outward destination is authorized.
run_guard database '' '' ''
docker exec "$guard" cat /run/backupsheep-egress/ready | grep -qx mode=deny \
  || fail "an omitted egress mode did not select deny."
must_connect "$(container_ip "$database_server" "$database_net")" 5432 \
  "deny mode blocked its exact database peer."
must_connect "$(container_ip "$broker_server" "$broker_net")" 5672 \
  "deny mode blocked its exact broker peer."
dns_probe udp egress-test-database 1 0 \
  || fail "deny mode blocked its mandatory internal DNS name."
dns_probe tcp exfil-canary.attacker.invalid 1 5 \
  || fail "deny mode forwarded a non-internal DNS name."
must_block "$external_allowed_ip" 8080 \
  "deny mode permitted an outward destination."
must_block "$external_unapproved_ip" 8080 \
  "deny mode permitted an unapproved outward destination."
deny_guard_ip="$(container_ip "$guard" "$external_net")"
if docker run --rm --network "$external_net" "$alpine" \
    nc -z -w 2 "$deny_guard_ip" 1053 2>/dev/null; then
  fail "deny mode exposed its loopback-only DNS proxy on an external interface."
fi
for _health_attempt in 1 2 3; do
  docker exec "$guard" /usr/local/bin/backupsheep-egress-healthcheck \
    >/dev/null 2>&1 \
    || fail "deny mode failed a repeated post-drop healthcheck."
  sleep 1
done
deny_ruleset="$(docker exec "$guard" \
  nft list table inet backupsheep_egress)"
printf '%s\n' "$deny_ruleset" | grep -Fq 'chain dns_redirect' \
  || fail "deny mode omitted the exact-name loopback DNS redirect."
if printf '%s\n' "$deny_ruleset" \
    | grep -Eq 'set allowed_ipv[46]|@allowed_ipv[46]'; then
  fail "deny mode installed an outward allowlist set or rule."
fi
if printf '%s\n' "$deny_ruleset" | grep -Fq 'meta nfproto { ipv4, ipv6 } accept'; then
  fail "deny mode installed the public outward accept rule."
fi
docker rm -f "$guard" >/dev/null

# Deny cannot be silently widened with an allowlist variable; the operator must
# make the mode transition explicit.
if docker run --name "$probe" \
    --network "$external_net" --network "$database_net" --network "$broker_net" \
    --cap-drop ALL \
    --cap-add CHOWN --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --security-opt no-new-privileges:true --read-only \
    --tmpfs /run/backupsheep-egress:rw,noexec,nosuid,nodev,size=1m,mode=0700 \
    -e BACKUPSHEEP_EGRESS_ROLE=database \
    -e BACKUPSHEEP_EGRESS_POLICY_GENERATION=2 \
    -e BACKUPSHEEP_EGRESS_MODE=deny \
    -e "BACKUPSHEEP_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS=${external_allowed_ip}/32:8080" \
    -e BACKUPSHEEP_EGRESS_DATABASE_HOST=egress-test-database \
    -e BACKUPSHEEP_EGRESS_DATABASE_PORT=5432 \
    -e BACKUPSHEEP_EGRESS_BROKER_HOST=egress-test-broker \
    -e BACKUPSHEEP_EGRESS_BROKER_PORT=5672 \
    "$image" >/dev/null 2>&1; then
  fail "deny mode accepted an outward TCP endpoint."
fi
docker logs "$probe" 2>&1 | grep -Fq \
  'deny mode does not accept an outward TCP endpoint' \
  || fail "deny mode did not fail closed on an outward TCP endpoint."
docker rm "$probe" >/dev/null

# Reject shell/nft injection characters before a live ruleset is touched. Supplying
# valid internal peers ensures this specifically reaches CIDR validation.
if docker run --name "$probe" \
    --network "$external_net" --network "$database_net" --network "$broker_net" \
    --cap-drop ALL \
    --cap-add CHOWN --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --security-opt no-new-privileges:true --read-only \
    --tmpfs /run/backupsheep-egress:rw,noexec,nosuid,nodev,size=1m,mode=0700 \
    -e BACKUPSHEEP_EGRESS_ROLE=cloud \
    -e BACKUPSHEEP_EGRESS_POLICY_GENERATION=2 \
    -e BACKUPSHEEP_EGRESS_MODE=public \
    -e 'BACKUPSHEEP_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS=1.1.1.1/32:443;flush ruleset' \
    -e BACKUPSHEEP_EGRESS_DATABASE_HOST=egress-test-database \
    -e BACKUPSHEEP_EGRESS_DATABASE_PORT=5432 \
    -e BACKUPSHEEP_EGRESS_BROKER_HOST=egress-test-broker \
    -e BACKUPSHEEP_EGRESS_BROKER_PORT=5672 \
    "$image" >/dev/null 2>&1; then
  fail "an injected TCP endpoint value was accepted."
fi
docker logs "$probe" 2>&1 | grep -Fq 'IPv4 TCP endpoint allowlist contains an invalid character' \
  || fail "the injected endpoint did not reach the expected fail-closed validator."
docker rm "$probe" >/dev/null

if docker run --name "$probe" \
    --network "$external_net" --network "$database_net" --network "$broker_net" \
    --cap-drop ALL \
    --cap-add CHOWN --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --security-opt no-new-privileges:true --read-only \
    --tmpfs /run/backupsheep-egress:rw,noexec,nosuid,nodev,size=1m,mode=0700 \
    -e BACKUPSHEEP_EGRESS_ROLE=cloud \
    -e BACKUPSHEEP_EGRESS_POLICY_GENERATION=2 \
    -e BACKUPSHEEP_EGRESS_MODE=allowlist \
    -e "BACKUPSHEEP_EGRESS_ALLOW_IPV4_TCP_ENDPOINTS=${external_allowed_ip}/32:8080" \
    -e 'BACKUPSHEEP_EGRESS_ALLOW_DNS_NAMES=approved.example;flush ruleset' \
    -e BACKUPSHEEP_EGRESS_DATABASE_HOST=egress-test-database \
    -e BACKUPSHEEP_EGRESS_DATABASE_PORT=5432 \
    -e BACKUPSHEEP_EGRESS_BROKER_HOST=egress-test-broker \
    -e BACKUPSHEEP_EGRESS_BROKER_PORT=5672 \
    "$image" >/dev/null 2>&1; then
  fail "an injected exact DNS-name value was accepted."
fi
docker logs "$probe" 2>&1 | grep -Fq 'DNS name is not a canonical exact name' \
  || fail "the injected DNS name did not reach the fail-closed validator."
docker rm "$probe" >/dev/null

# Old address-only variables are a hard error rather than silently widening every
# TCP/UDP port on an approved address.
if docker run --name "$probe" \
    --network "$external_net" --network "$database_net" --network "$broker_net" \
    --cap-drop ALL \
    --cap-add CHOWN --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --security-opt no-new-privileges:true --read-only \
    --tmpfs /run/backupsheep-egress:rw,noexec,nosuid,nodev,size=1m,mode=0700 \
    -e BACKUPSHEEP_EGRESS_ROLE=cloud \
    -e BACKUPSHEEP_EGRESS_POLICY_GENERATION=2 \
    -e BACKUPSHEEP_EGRESS_MODE=allowlist \
    -e "BACKUPSHEEP_EGRESS_ALLOW_IPV4=${external_allowed_ip}/32" \
    -e BACKUPSHEEP_EGRESS_DATABASE_HOST=egress-test-database \
    -e BACKUPSHEEP_EGRESS_DATABASE_PORT=5432 \
    -e BACKUPSHEEP_EGRESS_BROKER_HOST=egress-test-broker \
    -e BACKUPSHEEP_EGRESS_BROKER_PORT=5672 \
    "$image" >/dev/null 2>&1; then
  fail "the retired address-only egress variable was accepted."
fi
docker logs "$probe" 2>&1 | grep -Fq 'address-only egress allowlists are retired' \
  || fail "a retired address-only allowlist did not fail closed."
docker rm "$probe" >/dev/null

# The policy generation is a runtime witness, not an installer-only marker.
if docker run --name "$probe" \
    --network "$external_net" --network "$database_net" --network "$broker_net" \
    --cap-drop ALL \
    --cap-add CHOWN --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --security-opt no-new-privileges:true --read-only \
    --tmpfs /run/backupsheep-egress:rw,noexec,nosuid,nodev,size=1m,mode=0700 \
    -e BACKUPSHEEP_EGRESS_ROLE=cloud \
    -e BACKUPSHEEP_EGRESS_MODE=deny \
    -e BACKUPSHEEP_EGRESS_DATABASE_HOST=egress-test-database \
    -e BACKUPSHEEP_EGRESS_DATABASE_PORT=5432 \
    -e BACKUPSHEEP_EGRESS_BROKER_HOST=egress-test-broker \
    -e BACKUPSHEEP_EGRESS_BROKER_PORT=5672 \
    "$image" >/dev/null 2>&1; then
  fail "the guard accepted a missing egress policy generation."
fi
docker logs "$probe" 2>&1 | grep -Fq 'BACKUPSHEEP_EGRESS_POLICY_GENERATION=2 is required' \
  || fail "a missing egress policy generation did not fail closed."
docker rm "$probe" >/dev/null

# A libc resolver that never returns must not outlive the kernel authorization
# lease or leave health green. The root bootstrap resolves normally; once the
# monitor drops to UID 10020, the mounted fixture hangs every lookup and each
# child is forcibly bounded by the production timeout.
hung_getent_fixture="$(cd "$(dirname "$0")" && pwd -P)/hung-getent-fixture.sh"
run_guard database deny '' '' "$hung_getent_fixture"
initial_lease="$(docker exec --user 10020:10020 "$guard" awk -F= \
  '$1 == "lease_seconds" { print $2; exit }' \
  /run/backupsheep-egress/reconciler-state)"
[ "$initial_lease" = 15 ] \
  || fail "the stock kernel lease does not exceed the complete lookup budget."
sleep 17
if docker exec "$guard" /usr/local/bin/backupsheep-egress-healthcheck \
    >/dev/null 2>&1; then
  fail "hung DNS left the egress guard healthy beyond its kernel lease."
fi
docker exec --user 10020:10020 "$guard" grep -qx status=blocked \
  /run/backupsheep-egress/reconciler-state \
  || fail "hung DNS did not publish a blocked reconciliation witness."
hung_internal_set="$(docker exec "$guard" \
  nft list set inet backupsheep_egress internal_ipv4 2>/dev/null || true)"
if printf '%s\n' "$hung_internal_set" | grep -Fq 'elements = {'; then
  fail "hung DNS preserved an internal peer tuple beyond its kernel lease."
fi
hung_strict_lease="$(docker exec "$guard" \
  nft list set inet backupsheep_egress strict_workload_lease 2>/dev/null || true)"
if printf '%s\n' "$hung_strict_lease" | grep -Fq 'elements = {'; then
  fail "hung DNS preserved the workload authorization beyond its kernel lease."
fi
must_block "$(container_ip "$database_server" "$database_net")" 5432 \
  "hung DNS left the database tuple reachable beyond its kernel lease."
docker exec "$guard" /bin/sh -ec '
  for process_status in /proc/[0-9]*/status; do
    process_state="$(awk "/^State:/ { print \$2; exit }" \
      "$process_status" 2>/dev/null || true)"
    [ "$process_state" != Z ]
  done
' || fail "the forcibly bounded resolver left a zombie process."
docker rm -f "$guard" >/dev/null

printf '%s\n' 'BackupSheep exact-peer egress policy acceptance passed.'
