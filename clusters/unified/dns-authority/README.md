# BIND authority during DNS overlap

This component runs one BIND server on each VPS. It serves the twenty static zones from the shared generator in `components/bind9/base/configs/zones` and keeps persistent secondary copies of the two RFC2136 zones. It does not expose a public port. The public CoreDNS listener routes the corresponding DNS queries to the `bind-authority` Service, whose `internalTrafficPolicy: Local` keeps each VPS using its own BIND copy.

The dynamic zones have exactly one existing primary during overlap. This component refuses updates, update forwarding, recursion and outgoing transfers. It polls the primary at most every 10 seconds, independently of NOTIFY delivery. The current primary SOA determines expiry: if it becomes unavailable, previously transferred data is served until that expiry. A surviving copy is not proof that a writer migration is complete.

PowerDNS customer zones and their API writers are outside this component. Do not advertise this backend for those zones or point a default DNS route at it while expecting PowerDNS answers.

## Prerequisites

Run the guarded DNS volume preparation on both VPSs before applying these manifests. Each node needs a separately bounded 256 MiB filesystem mounted at `/var/lib/infra-dns/bind`, with `/var/lib/infra-dns/bind/data` owned by UID/GID 53. Local PV capacity is a scheduling declaration and does not enforce a disk quota. The PVs use `Retain`; recreating a StatefulSet does not erase transferred zones.

Create `dns-authority/bind-transfer-runtime` outside Git with one key, `named.conf.transfers`. Its content defines the BIND `legacy-bind` primaries list. For the current unsigned public transfer path, its form is:

```bind
primaries legacy-bind {
    PRIMARY_IP port 53;
};
```

`PRIMARY_IP` is an operator-supplied address, not a literal to apply. The egress NetworkPolicy must match the actual primary endpoint. Adding TSIG later requires importing the transfer-only key securely on both sides, adding its definition and reference to this include, and verifying authenticated transfers. Do not reuse certificate-update credentials for zone transfer.

The public DNS namespace must permit egress to this namespace's UDP/TCP port 5353. Add the Prometheus discovery namespace and a scrape job selecting the `bind-metrics` port. The included Role grants pod discovery only; port 9119 is limited to the monitoring namespace. BIND's raw statistics interface is loopback-only.

## Activate and validate

Render with `kubectl kustomize clusters/unified/dns-authority`. Validate the exact pinned image with `named-checkconf -z` before activation. The init container repeats this check. Both Pods must become Ready before forwarding public queries: readiness requires an authoritative SOA for all twenty-two zones, including completed dynamic transfers.

Check every zone over UDP and TCP through each public VPS. Compare complete static records and dynamic transferred records with the currently serving authority; check serials, TTLs, negative answers, wildcards and delegations. Queries outside these zones must be refused and unsigned updates/transfers rejected. Keep existing authoritative endpoints operating throughout delegation and glue cache expiry.

StatefulSets intentionally use `OnDelete`: updating both independent one-replica StatefulSets automatically could interrupt both endpoints, and a PodDisruptionBudget does not gate controller rollouts. Validate configuration, activate one VPS, verify authoritative answers and parity, then activate the other. The supervised BIND process detects projected configuration and zone-file changes every five seconds, validates a stable generation with `named-checkconf -z`, then sends SIGHUP to its own child process. Invalid generations leave the previous authority running. Verify serials and answers after publication; the validation check does not replace external parity checks. Changes to the supervisor itself or container settings require the controlled one-VPS-at-a-time replacement above. The shared zone ConfigMap has a stable historical name to avoid restarting the legacy dynamic primary.

Do not delete either local volume or retire the old primary until all dynamic writers have been moved and a complete independent replacement is verified. Transfer and expiry status must be monitored during overlap.

Images are pinned to the [official ISC BIND image](https://hub.docker.com/r/internetsystemsconsortium/bind9) and [Prometheus Community BIND exporter](https://github.com/prometheus-community/bind_exporter). Configuration references: [BIND authoritative and transfer settings](https://bind9.readthedocs.io/en/stable/reference.html) and [Kubernetes internal traffic policy](https://kubernetes.io/docs/concepts/services-networking/service-traffic-policy/).

The exporter enables `server,view` collectors (the view collector includes zone serials): `bind_zone_serial` exposes each local SOA serial, while `bind_config_time_seconds`, `bind_boot_time_seconds` and zone-transfer success/failure counters distinguish reloads, process restarts and transfer errors. A serial is not a replication-age timestamp; compare it with the primary and alert on sustained divergence rather than subtracting serials as if they were seconds.

Run the offline readiness and graceful-reload checks with `python3 clusters/unified/dns-authority/test_runtime.py`. They use isolated fake processes and never connect to a cluster.
