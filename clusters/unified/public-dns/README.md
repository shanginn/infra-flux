# Authoritative DNS for applications

This stack serves only `apps.shanginn.io`. A DaemonSet places one CoreDNS and one publisher sidecar on each VPS (`infra.shanginn.io/site=msk|fin`). TCP and UDP port 53 use `hostPort`; the pods use the normal pod network. There is no recursive forwarder, zone transfer, or dependency on the existing BIND containers.

`settings.json` defines public ingress addresses and TTL 30. NS/glue addresses stay published regardless of ingress health. `ingress.apps.shanginn.io` and wildcard names contain the addresses currently considered healthy. The zone apex has NS/SOA only; it is not an application endpoint.

The publisher elected through a Kubernetes Lease checks each public `http://IP/ping` with `Host: ingress.apps.shanginn.io`, requiring HTTP 200 and body `OK`. Checks run every 10 seconds with a 3-second timeout. Three consecutive failures remove a target; two consecutive successes restore it. Counters persist in the zone ConfigMap across leader changes. If both targets fail, the last nonempty address set remains published and the `infra_dns_all_targets_down` alert condition is set.

Each sidecar reads the ConfigMap directly every two seconds and atomically replaces its local zone file. CoreDNS checks the SOA every second. ConfigMap volume projection delay is therefore not on the normal update path. Every API write includes the current resourceVersion. Lease epochs fence stale publishers after another leader publishes; unsuccessful or expired leadership prevents writes. Only the elected VPS provides the active health-check vantage point: this does not measure accessibility from every country or customer network.

## Install and verify

1. Ensure both new VPS public TCP/UDP 53 ports are free and reachable. The CNI must support `hostPort`. Ensure both public `/ping` requests return `200 OK` through the OS proxy and Traefik before delegation.
2. Include this directory in the unified Flux Kustomization. `kubectl kustomize clusters/unified/public-dns` renders it without applying anything. The runtime ConfigMap and Lease use Flux `IfNotPresent` and `prune: Disabled`; Git supplies their initial seed, while the publisher owns subsequent state. **Do not repeatedly apply the rendered seed with plain `kubectl apply`**, which does not honor Flux apply annotations and can reset live state.
3. Verify two Ready pods, both DNS servers over TCP and UDP, and nonzero `infra_dns_last_probe_timestamp_seconds`. Query SOA and both application A records directly on each public IP, with recursion disabled. Verify an unrelated domain is refused. Monitoring discovers both metrics ports through its read-only namespace Role.
4. In the existing parent zone, delegate `apps.shanginn.io` to `ns-msk.apps.shanginn.io` and `ns-fin.apps.shanginn.io`, with matching public A glue. Increment the parent SOA. This stack does not modify the parent zone.

Examples (run from a machine outside the cluster):

```sh
dig @157.228.139.163 ingress.apps.shanginn.io A +norecurse
dig @89.35.119.225 ingress.apps.shanginn.io A +norecurse +tcp
dig @157.228.139.163 apps.shanginn.io SOA +norecurse
dig @89.35.119.225 example.org A +norecurse
```

## Operation

Changing the two public addresses requires updating `settings.json`, the NetworkPolicy destinations, and parent-zone glue, then confirming both servers publish the new SOA and addresses. Keep target names `msk` and `fin`: adding a public site requires an explicit state/NS migration. Keep the mutable ConfigMap and Lease together when restoring etcd; never reset the Lease epoch while retaining a higher zone epoch. The controller deliberately refuses that inconsistent state.

Existing running DNS processes keep serving their last valid zone when the API is unavailable. Health-based changes then stop. A restarted container retains its pod's zone volume; recreating the whole pod requires Kubernetes and its seed ConfigMap to be available. This is not an independent DNS control plane outside Kubernetes.

With a healthy API, removal normally takes roughly 20–30 seconds of probes, followed by API/file propagation and resolver caching. Losing the leader can add about 37–40 seconds for Lease takeover. TTL 30 is a request to caches, not an upper bound: resolver serve-stale behavior, application caches, and existing connections can extend disruption. `/ping` proves the ingress path, not every application's database or business operation. Real node/ingress/network interruption tests require the operator's approved maintenance window.

Run the controller's offline behavior checks with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 clusters/unified/public-dns/test_controller.py
```

The manifests pin [CoreDNS 1.14.7](https://github.com/coredns/coredns/releases/tag/v1.14.7) and [official Python 3.14.6 slim-trixie](https://hub.docker.com/_/python) by image digest. Implementation references: [CoreDNS file reload](https://coredns.io/plugins/file/), [Kubernetes Leases](https://kubernetes.io/docs/concepts/architecture/leases/), [ConfigMap update propagation](https://kubernetes.io/docs/concepts/configuration/configmap/), and [Flux apply policies](https://fluxcd.io/flux/components/kustomize/kustomizations/#controlling-the-apply-behavior-of-resources).
