# Container egress guard

Each Internet-capable application role shares a network namespace with one
no-secret egress guard. The guard is the only process that receives `NET_ADMIN`.
It installs one nftables ruleset transactionally and then becomes UID/GID 10020
with `NET_ADMIN` as its only inheritable, permitted, effective, bounding, and
ambient capability plus `no_new_privs`. It has no application secret, data mount, or
supplementary group. Bootstrap rejects
secret-like environment names, then launches the long-lived monitor with only the
shell's minimal `PATH`, `PWD`, and `SHLVL` environment. The workload uses
`network_mode: service:<guard>` but retains a private PID namespace; it does not share
the guard's mount, IPC, user, or secret context. Treat the two containers as one
lifecycle unit and recreate them together. The wrapper refuses independent guard
lifecycle commands, and guards use `restart: "no"` so Docker cannot silently replace a
namespace owner beneath its running workload. The stock `deny` mode and strict `allowlist` mode add
the two zero-capability DNS identities described below. Explicit-risk `public` mode
adds neither DNS process.

## Internal service policy

The stock Compose model supplies the configured PostgreSQL and RabbitMQ service
hostnames and TCP ports to every guard. At startup the guard resolves those names
through Docker DNS and accepts a peer only when all of these are true:

- the peer is directly connected on a non-default internal interface;
- PostgreSQL and RabbitMQ use different dedicated interfaces; and
- destination address, interface, TCP protocol, and destination port all match.

No bridge subnet is trusted. Other containers on an attached bridge, other ports
on an approved peer, routed peers, and every discovered gateway are denied. The
deny/allowlist/public policy applies only on the namespace's default egress interface,
so an outward tuple cannot accidentally authorize an internal bridge peer.

Docker may assign a new address when a stateful service is recreated. A one-second
DNS/route reconciler atomically flushes and replaces only the two exact nftables
sets in the existing namespace. Every tuple is also a kernel-expiring element. In
`deny` and `allowlist` mode the same transaction renews a timed lease for the role's one fixed
runtime UID, and that lease is checked before any non-local data or established-
connection acceptance. Loopback remains available to Docker's root-owned embedded
resolver, but untrusted DNS was already forced through the exact-name proxy. This
in-place update is required because restarting the guard can strand
an already-running `network_mode: service:...` application in its old namespace.
If either peer is absent or ambiguous, both internal sets and the strict lease are
revoked and health becomes blocked until a complete valid snapshot returns.

The kernel deadline is three polling intervals plus twelve seconds (fifteen seconds
with the stock one-second interval). That exceeds the complete 8.4-second worst-case
sequential peer-lookup budget and remains independent of the reconciler: if DNS
resolution hangs, each lookup child is killed, an nft update fails, and even the emergency
empty-set transaction also fails, old internal tuples expire. In `deny` and
`allowlist` mode all
socket egress from the workload UID expires as well, including an established flow;
the no-secret guard identities retain only the surrounding fixed policy so recovery
can be attempted. Public mode intentionally keeps its ordinary outward behavior,
but its database/broker tuples still expire. Retaining only `NET_ADMIN` in this
isolated guard keeps that capability out of every secret-bearing app/worker process.
Health is a fresh-renewal assertion, not a process-liveness assertion. The healthcheck
requires the most recent successful reconciliation witness to be younger than the
kernel lease and, in strict modes, proves that both DNS identities are still the exact
expected zero-capability processes. The workload's separate healthcheck proves its local
web/worker readiness and opens fresh TCP connections to both PostgreSQL and RabbitMQ
through the guard's current exact peer sets. It therefore becomes unhealthy after guard
loss, lease expiry, or peer revocation even though its private PID namespace still has a
live process. Health does not mutate lifecycle state. If the guard or either DNS process
is unexpectedly lost, recreate the paired guard and workload together; do not
independently restart a guard underneath a running workload.

## Paired lifecycle commands

A broad `up` is accepted only before any guard/workload pair exists, such as a fresh
installation or after a reviewed whole-stack `down`. Once a pair exists, neither a broad
`up` nor a workload-only `up` may change it. Recreate the web pair exactly:

```sh
./backupsheep-compose up --detach --no-build --no-deps --force-recreate \
  app-egress-guard app
```

After reviewing durable work and provider side effects, recreate all operations pairs
and then start singleton Beat separately:

```sh
./backupsheep-compose --profile operations up --detach --no-build --no-deps \
  --force-recreate \
  cloud-egress-guard database-egress-guard files-egress-guard \
  storage-egress-guard logs-egress-guard \
  worker-cloud worker-database worker-files worker-storage worker-logs
./backupsheep-compose --profile operations up --detach --no-build --no-deps beat
```

The wrapper refuses independent `start`, `restart`, `stop`, `kill`, `pause`, or `rm` of
a guard. Stopping a workload/Beat for an operations pause leaves its no-secret guard in
place; changing an image, guard, network, or whole topology requires the paired commands
above or a reviewed whole-stack `down` followed by controlled startup. A Docker daemon
restart does not recover a `restart: "no"` guard or prove that the workload rejoined its
current namespace; use the exact paired recovery command before returning the role to
service. Named data and
identity volumes are not removed by ordinary `down`; never add `--volumes`.

## Outward modes

- `deny` is the stock default. It permits no workload-initiated destination on the
  default interface and refuses outward endpoint or extra DNS-name configuration. Exact
  PostgreSQL/RabbitMQ tuples and their exact internal DNS names remain available.
  The web role can still reply on an already-established connection accepted at its
  published port; it cannot initiate a new outward connection.
- `allowlist` permits only configured role-specific outward TCP endpoint tuples and
  requires at least one tuple. IPv4 entries use `CIDR:port` (for example,
  `203.0.113.10/32:443`); IPv6 entries use `[CIDR]:port` (for example,
  `[2001:db8::10/128]:443`). Select it explicitly for a role that needs a reviewed
  provider, source, storage, or KMS endpoint.
- `public` is an explicit risk opt-in. It permits ordinary public destinations while
  denying metadata, reserved, private, discovered-gateway, and well-known NAT64
  destinations by default. Exact TCP endpoint tuples are evaluated first as explicit
  special-range exceptions, intended only for a narrow reviewed private target. They
  can override the ordinary private/reserved set, but cannot override the fixed `never`
  set (including the two well-known NAT64 prefixes) or a discovered gateway. Public mode
  uses ordinary Docker DNS and requires an empty exact-name list. It is unsuitable as an
  enterprise default.

All three modes keep the exact internal database/broker rules described above.

### Strict DNS policy

An IP/port allowlist alone does not stop a compromised process from encoding secrets in
arbitrary query labels sent to Docker's embedded DNS. In `deny` and `allowlist` mode, nftables
therefore redirects workload TCP/UDP queries for `127.0.0.11:53` to a guard-owned
parser on loopback. The reconciler retains UID 10020 and only `NET_ADMIN`. UID 10021
is the hostile-packet parser: it validates the client packet and can send only a
two-byte `{immutable-name-index, A-or-AAAA}` request over a Unix `SOCK_SEQPACKET`
socket. It cannot contact Docker DNS. UID 10022 is the only upstream forwarder: it
authenticates UID 10021 with `SO_PEERCRED`, validates the fixed request, constructs a
fresh canonical query, and is the only non-monitor identity allowed to reach Docker's
embedded resolver. Both DNS identities have empty capability sets and
`no_new_privileges`; the parser's listener binds only `127.0.0.1`. Direct DNS on the
outward interface is denied even when its address and port appear in an allowed tuple.

The parser permits only canonical IN `A` and `AAAA` questions for the exact configured
PostgreSQL/RabbitMQ names. `allowlist` mode can additionally include reviewed
`BACKUPSHEEP_<ROLE>_EGRESS_ALLOW_DNS_NAMES`; `deny` rejects that widening. The forwarder rebuilds
every allowed upstream query with a lower-case exact name, fresh transaction ID, and
no additional/EDNS records. Unknown names, subdomains of an allowed name, wildcard
patterns, other query types, malformed questions, and suffix matches are refused
without contacting the upstream resolver. The complete canonical policy is capped at
66 unique names, including non-literal PostgreSQL/RabbitMQ names; list every required
CNAME target separately.

DNS permission and network permission are independent. Each resolved provider/KMS
endpoint still needs the minimum reviewed IPv4/IPv6 CIDR-and-TCP-port tuple for that
role. Conversely, an allowed tuple grants arbitrary TCP traffic to every address and
the selected port in that CIDR. This is transport-level defense in depth, not a
resource-aware exfiltration boundary: a compromised role can reach another tenant or
resource served by the same IP and port. Enterprise operations therefore require
dedicated/private endpoints or a controlled proxy that authenticates and authorizes
the intended resource.

The fixed pre-allow policy hard-blocks the well-known NAT64 prefixes `64:ff9b::/96` and
`64:ff9b:1::/48`; no endpoint tuple can override them. A deployment-specific NAT64
prefix cannot be discovered portably by the container and remains a host/network
responsibility. Enterprise operators must disable that translation path for these
networks or block every site-specific NAT64 prefix at the host/network boundary, then
prove that restricted IPv4 destinations cannot be reached through IPv6 translation.

## Generation-2 upgrade

`BACKUPSHEEP_EGRESS_POLICY_GENERATION=2` is mandatory in `.env`, the Compose wrapper,
preflight, and every guard. Address-only `BACKUPSHEEP_<ROLE>_EGRESS_ALLOW_IPV4` and
`...ALLOW_IPV6` values are retired and any non-empty value fails closed. Existing
stock installs with all six roles uniformly public/blank, blank/blank, or deny/blank
must review their dependencies and run the installer once with
`--migrate-egress-policy`. That
explicit migration resets all six roles to `deny`, clears old and new lists, and
writes generation 2. Customized or mixed legacy policies are not guessed: preserve
them for review, manually reset all roles and lists to the documented deny state, and
then run the one-time migration. The flag is rejected after generation 2 is active.

## Acceptance test

Build the guard and run the disposable Linux-kernel harness:

```sh
docker build --file Dockerfile.egress --tag backupsheep-egress:test .
./deploy/egress/test-policy.sh backupsheep-egress:test
```

The harness proves the intended database and broker tuples work while a wrong
port on an otherwise allowed outward address, an unapproved internal peer, an
unapproved outward peer, metadata, and a
known-live host gateway endpoint are blocked in all applicable modes. It also forces a
Docker DNS address change and proves the old address loses authorization for an
already-running namespace-sharing client without restarting the guard. The harness
then freezes the reconciler past the kernel deadline and proves public-mode internal
tuples expire while public outward access remains unchanged, and that strict-mode
internal and outward access both stop for a still-running workload and recover only
after a complete reconciliation. Deny/allowlist
probes prove exact UDP/TCP A/AAAA resolution works while arbitrary/suffix labels and
other query types are refused, client ID/case/EDNS channels are stripped, and direct
external DNS is denied. A separate omitted-mode run proves `deny` is the default,
keeps exact database/broker access and exact internal DNS usable, exposes no DNS
listener on an external interface, rejects an attempted CIDR widening, and denies
every tested outward target. Repeated post-drop healthchecks cover every mode.
Finally, the harness proves that the client has zero capabilities and
cannot signal the reconciler, while both DNS processes have no capabilities and the
UID-10021 parser cannot issue an arbitrary upstream DNS query.
