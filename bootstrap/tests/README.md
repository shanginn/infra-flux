# Controlled HA tests

These tools act only when an operator explicitly invokes them. They are not a
scheduled chaos service. Keep target aliases, CA fingerprints, tokens and JSONL
observations outside Git. Never run two faults concurrently.

Install the reviewed `common.py`, `node-fault.py`, `recovery-gate.py` and
`api-observer.py` together as root-owned files in `/etc/infra-flux/ha-tests`, mode
0700. Do not overwrite an unrelated directory. Use the existing SSH aliases;
preserve the original SSH/WireGuard path. No fault is executed by installation.

Before any fault, finish real PostgreSQL activation and its Mac restore check.
Run `recovery-gate.py --ca-sha256 "$CA"`. It requires three Ready nodes, three
ready APIs, three healthy etcd members, all Garage partitions replicated on
three sites, and exactly one PostgreSQL primary with two asynchronous streaming
replicas within 16 MiB. It also checks the approved primary software watchdog.
For stability, require this gate to pass twice at least 30 seconds apart before
starting another fault. A failure blocks the next test; do not waive it to meet
a schedule.

Start independent API observers on both VPS, through the original SSH route:

```sh
python3 /etc/infra-flux/ha-tests/api-observer.py --ca-sha256 "$CA" --duration 900
```

Each observer creates its own labelled ConfigMap inside the owned
`infra-ha-test` namespace, writes a random nonce and reads it back every two
seconds. Capture stdout to a private JSONL file on the control computer. An SSH
disconnect is an observation gap, not proof that the surviving cluster failed.
Run the separate public observer outside the cluster, with direct TCP/UDP DNS
queries and HTTP per VPS. Do not use a Mac UDP DNS result when local FakeDNS
intercepts it. Keep PostgreSQL transaction and S3 write/read observers running
through the stable Service endpoints, with explicitly isolated test data.

The read-only `observe-public.py` accepts repeated `--address` arguments,
`--hostname`, `--duration` and `--interval`. Run it from the independently
reachable external host, for example with private variables:

```sh
python3 observe-public.py --address "$MSK_PUBLIC" --address "$FIN_PUBLIC" \
  --hostname ingress.apps.shanginn.io --duration 900 --interval 2
```

It records HTTP health per address and authoritative UDP/TCP DNS answer sets.
These direct authoritative queries do not measure end-user resolver caching.

For an approved service interruption on its owning node:

```sh
python3 /etc/infra-flux/ha-tests/node-fault.py arm \
  --ca-sha256 "$CA" --node fin --kind service-stop \
  --unit infra-headscale.service --seconds 120
# Read the returned token; trigger within 30 seconds of arming.
python3 /etc/infra-flux/ha-tests/node-fault.py trigger --token "$TOKEN"
```

`arm` first runs the recovery gate and acquires a resourceVersion-protected
cluster-wide ConfigMap lock. It schedules an independent local systemd timer
before returning an armed token. The timer retries local restoration after
failure, even if the controlling SSH session or Kubernetes API disappears.
Only `infra-headscale.service` and `infra-derper.service` may be stopped, and
only when already running and enabled. It never stops the namespace service.

For a one-node private-network partition, use `--kind vpn-partition` without
`--unit`. Install `nft` first. One uniquely named `inet` table covers IPv4 and
IPv6, with input/output/forward base chains at priority −450 and four
`tailscale0` counter/drop rules. The batch is atomic and refuses an existing
table. These base chains are independent of the chains that Calico and
Tailscale reconcile. An accept in another base chain cannot override their
drop verdict ([nftables verdict semantics](https://netfilter.org/projects/nftables/manpage.html)).
The preflight rejects existing flowtables, which could bypass the forward
hook, and checks that the return route to the SSH client avoids `tailscale0`.
No ruleset is flushed. Rollback checks the table's token comment and recorded
handle, then deletes only that table by handle. A damaged rule does not prevent
removal of the owned table. The old exact-rule rollback remains available for
state armed by an earlier helper; new partitions always use the separate table.
The existing public/old-WireGuard SSH path and Tailscale's outer transport are
not targeted. A software-watchdog reset during a primary partition is an
expected possible result, and must be recorded.

During the entire partition, poll `status --token "$TOKEN"` over the original
SSH path every two seconds and save the JSON privately. Its
`partition_observation` checks effective hooks, priorities, rule order and
verdicts, and reports packet/byte counters for all four rules. Require
`present=true` and `valid=true` throughout the intended interval, unchanged
boot ID and increasing counters under the independent probes. In parallel,
probe the isolated node's VPN API from a surviving node and the surviving VPN
APIs from the isolated node, with bounded timeouts. API writes through each
surviving node's local proxy, PostgreSQL transactions and S3 probes measure the
cluster's useful availability separately. Missing samples are gaps, not proof
of continued isolation. Unexpected connectivity, missing/changed rules or an
early reboot invalidates the claimed duration; restore and record the actual
observed interval. `status` never repairs or reapplies a disappearing rule.

For a single approved reboot, use `--kind reboot --confirm-reboot --seconds 300`.
The helper requires SSH, tailscaled, the local API proxy and kubelet enabled at
boot. **A timer cannot power on a machine or repair a failed boot.** Transient
timers do not survive reboot; normal service startup and volatile firewall
rules provide recovery after successful boot. The global lock persists and
blocks subsequent tests until recovery is verified. Have provider console or
physical recovery available before rebooting; do not claim a hard power-loss
test from an orderly reboot.

At any time an operator can restore the selected fault early:

```sh
python3 /etc/infra-flux/ha-tests/node-fault.py rollback --token "$TOKEN"
python3 /etc/infra-flux/ha-tests/recovery-gate.py --ca-sha256 "$CA"
# Repeat the recovery gate after at least 30 seconds of stable observations.
python3 /etc/infra-flux/ha-tests/node-fault.py finish --token "$TOKEN"
```

`finish` restores again idempotently, runs the gate and then releases the global
lock. If a controller crashes during arming, the lock intentionally remains;
inspect the matching local `active.json` and cluster ConfigMap before recovery.
Never remove the lock merely because the deadline passed. The local state is
`/var/lib/infra-flux-fault-tests/active.json`; use `status --token` for a readback.

Suggested order, with full recovery between every step: baseline for 60 seconds;
active Headscale for 120 seconds; Moscow DERP for 120 seconds; Finland DERP for
120 seconds; each single-node reboot, starting with a PostgreSQL replica and
recording the actual primary before each test; finally a single-node VPN
partition for 120 seconds. Target the current primary only when its reset risk
was explicitly approved. Home public-IP changes require separate router
control and are not implemented here.

Record actual fault start/end, first failed request, last failure, first stable
success, latency, request counts and observation gaps. Preserve every acknowledged
PostgreSQL/S3 probe ID and read it after failover; report missing acknowledged
transactions explicitly. Asynchronous PostgreSQL can lose recent commits.
DNS TTL 30 does not guarantee all resolvers switch within 30 seconds; cached
or stale answers can last longer. A stopped DERP while all peers are direct
does not prove relay failover. Record actual peer paths and authenticated relay
traffic; do not silently combine a UDP-blocking fault with a relay outage.

The test namespace and any interrupted observer ConfigMaps contain only test
state. Remove them only after matching ownership and confirmed completion of
the entire suite. These tools do not delete application data or old-cluster
resources.
