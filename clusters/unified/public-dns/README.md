# Public authoritative DNS

This stack exposes the public DNS listener on each VPS (`infra.shanginn.io/site=msk|fin`). A DaemonSet places one CoreDNS and one application-zone publisher on each VPS. TCP and UDP port 53 use `hostPort`; the pods use the normal pod network.

CoreDNS serves `apps.shanginn.io` directly from its local application-zone file. The shared `shanginn.io` and root `.` server block forwards other queries to the `bind-authority` Service in the `dns-authority` namespace. The Service's `internalTrafficPolicy: Local` selects only the persistent BIND copy on the same VPS. The explicit parent-zone entry ensures DS queries for the locally served child are answered by the parent authority. The Service address in `Corefile` must match `dns-authority/service.yaml`; backend DNS uses port 5353 behind the Service's port 53. A failed local backend does not silently fall back to the other VPS through this Service.

The [BIND component](../dns-authority/README.md) serves twenty static zones from the shared Git zone generator and two persistent secondary zones: `vibesites.ru` and `xn--80aacc0bc7ayl4g.xn--p1ai`. The secondaries keep the existing RFC2136 primary as their only writer during overlap. Queries outside these twenty-two zones and the application zone are refused; this listener is not a recursive resolver. Backend zone transfers and updates are refused. PowerDNS customer zones and their API writers are separate and are **not** supplied by this root forwarding route. Do not delegate those domains here until their complete serving and update paths have been migrated and verified.

## Application-zone publication

`settings.json` defines public ingress addresses and TTL 30. NS/glue addresses stay published regardless of ingress health. `ingress.apps.shanginn.io` and wildcard names contain the addresses currently considered healthy. The zone apex has NS/SOA only; it is not an application endpoint.

The publisher elected through a Kubernetes Lease checks each public `http://IP/ping` with `Host: ingress.apps.shanginn.io`, requiring HTTP 200 and body `OK`. Checks run every 10 seconds with a 3-second timeout. Three consecutive failures remove a target; two consecutive successes restore it. Counters persist in the zone ConfigMap across leader changes. If both targets fail, the last nonempty address set remains published and the `infra_dns_all_targets_down` alert condition is set.

Each sidecar reads the ConfigMap directly every two seconds and atomically replaces its local zone file. CoreDNS checks the SOA every second. ConfigMap volume projection delay is therefore not on the normal update path. Every API write includes the current resourceVersion. Lease epochs fence stale publishers after another leader publishes; unsuccessful or expired leadership prevents writes. Only the elected VPS provides the active health-check vantage point: this does not measure accessibility from every country or customer network.

## Install and verify

1. Prepare the two bounded BIND volumes and runtime transfer configuration as described in the [backend runbook](../dns-authority/README.md). Each VPS has its own 256 MiB filesystem; the data path persists across Pod replacement. Both backend Pods must be Ready, including successful transfers of both dynamic zones, before activating root forwarding.
2. Ensure both VPS public TCP/UDP 53 ports are free and reachable and that the CNI supports `hostPort`. Ensure both public `/ping` requests return `200 OK` through the OS proxy and Traefik before application delegation.
3. Render both directories, then reconcile through the intended unified Flux configuration. The mutable application-zone ConfigMap and Lease use Flux `IfNotPresent` and `prune: Disabled`; Git supplies their initial seed, while the publisher owns subsequent state. **Do not repeatedly apply the rendered seed with plain `kubectl apply`**, which does not honor Flux apply annotations and can reset live state.
4. Verify both public DNS Pods and both backend Pods, each listener over TCP and UDP, and nonzero `infra_dns_last_probe_timestamp_seconds`. Readiness alone does not prove end-to-end backend record parity. Run the verifier below and separately check the application-zone SOA, NS and current ingress addresses. Monitoring discovers the public DNS metrics through its read-only namespace Role; backend exporter metrics are separate.
5. Keep `apps.shanginn.io` delegated in its parent to `ns-msk.apps.shanginn.io` and `ns-fin.apps.shanginn.io`, with matching public A glue. Increment the parent SOA when editing that delegation. The publisher changes only its application zone; it does not edit parent zones or registrar settings.

Render and inspect without changing the cluster:

```sh
kubectl kustomize clusters/unified/dns-authority
kubectl kustomize clusters/unified/public-dns
ssh k8s-msk 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n dns-authority get pods -o wide'
ssh k8s-msk 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n public-dns get pods -o wide'
```

Examples (run from a machine outside the cluster):

```sh
dig @157.228.139.163 ingress.apps.shanginn.io A +norecurse
dig @89.35.119.225 ingress.apps.shanginn.io A +norecurse +tcp
dig @157.228.139.163 apps.shanginn.io SOA +norecurse
dig @89.35.119.225 example.org A +norecurse
```

## Record-parity verification

[The read-only verifier](../../../bootstrap/dns/verify-zones.py) compares all twenty static Git zones and live AXFR snapshots of the two dynamic zones. It queries every configured RRset through both transports, including wildcard synthesis, CNAME lookups, negative answers, delegations, recursion refusal and transfer refusal. It fails if the static source or dynamic snapshot changes during the run; rerun after publication settles. It does not change DNS records or test dynamic writes.

The local Python environment needs `dnspython==2.9.0`. SSH query hosts need Python 3 and `dig`. Use an external administration host that can query both public endpoints and read the legacy dynamic AXFR source. A separate backend SSH vantage runs direct Pod queries from the corresponding VPS; no backend port needs public exposure. Keep reports outside this public repository; the verifier creates its output with mode 0600 and refuses to overwrite an existing report.

Run from the repository root. Supply the existing external SSH alias and current primary address in the shell variables before executing this example. The backend Pod addresses are discovered from the intended cluster, and the public addresses come from the checked-in settings:

```sh
python3 -m venv /tmp/infra-dns-verify-venv
/tmp/infra-dns-verify-venv/bin/pip install 'dnspython==2.9.0'
/tmp/infra-dns-verify-venv/bin/python bootstrap/dns/verify-zones.py --self-test

: "${DNS_QUERY_SSH_ALIAS:?Set the external SSH query alias}"
: "${DNS_LEGACY_PRIMARY_IP:?Set the current dynamic primary IP}"
dns_report_dir="$(mktemp -d "${TMPDIR:-/tmp}/infra-dns-verify.XXXXXX")"
(
for dns_site in msk fin; do
  dns_host="k8s-${dns_site}"
  dns_public_ip="$(python3 -c 'import json,sys; print(json.load(open("clusters/unified/public-dns/settings.json"))["targets"][sys.argv[1]])' "$dns_site")"
  dns_backend_ip="$(ssh "$dns_host" "kubectl --kubeconfig=/etc/kubernetes/admin.conf -n dns-authority get pod bind-${dns_site}-0 -o jsonpath='{.status.podIP}'")"
  /tmp/infra-dns-verify-venv/bin/python bootstrap/dns/verify-zones.py \
    --via "$DNS_QUERY_SSH_ALIAS" \
    --server "${dns_site}=${dns_public_ip}" \
    --backend-via "$dns_host" \
    --backend-server "bind-${dns_site}=${dns_backend_ip}:5353" \
    --legacy-primary "legacy=${DNS_LEGACY_PRIMARY_IP}" \
    --cohosted-zone apps.shanginn.io \
    --output "${dns_report_dir}/${dns_site}.json" || exit "$?"
done
)
```

`--cohosted-zone apps.shanginn.io` accounts for the public listener answering that child zone directly: its NS/glue answers use the child's TTL. The matching direct BIND checks still verify the parent delegation and its original TTL. Do not omit the backend checks or broadly ignore TTL differences. Repeat from independent external query networks to check asymmetric reachability. Also verify the application-zone wildcard and ingress addresses independently; the twenty-two-zone comparison does not enumerate application health changes.

## Delegation overlap and retirement

Publish explicit nameserver A/AAAA records and registry glue where required before adding new nameservers to a domain. Account for the old cached answers for these names, including any previous wildcard answer. Every advertised endpoint must already serve complete, current data over UDP and TCP.

Add the new nameservers to both the relevant registrar delegation and the child zone's apex NS set while keeping the old endpoints alive. Change only domains whose authoritative service is being migrated; the presence of a zone file in Git does not establish its current public delegation. Check parent NS/glue, child NS/address records and DNSSEC DS at the actual authoritative servers. Preserve existing DS/key continuity for any signed delegation.

Retain the old endpoints through the longest measured parent delegation, glue, nameserver address and child NS cache lifetime after each relevant change, with a safety margin. Do not infer completion from a single recursive resolver or a fixed propagation estimate. If retaining the final names `ns1`/`ns2`, repoint their authoritative addresses and registry glue while the old IPs still answer; keep the added nameservers active during the second cache window. Nameserver numbering conveys no priority.

Do not retire the existing dynamic primary merely because its two secondary copies pass read checks. Move and verify RFC2136 writers, update authentication and the separate PowerDNS API/writer path before removing those dependencies. Secondary data is served only until its SOA expiry when the primary cannot be reached. Run record-parity checks again after each publication or endpoint change; keep failed checks and measured cache deadlines outside Git.

## Configuration reload and operation

`public-dns-config-8kb7hccgc2` deliberately has a stable name. ConfigMap edits do not change the DaemonSet's Pod template or automatically restart both listeners. When upgrading an existing process that has no reload plugin, validate the exact transition in an isolated Pod, then send one guarded `SIGUSR1` after verifying the mounted configuration and container identity. Once the reload plugin is active, use automatic reload only: another manual signal can leave a watcher attached to the previous instance. CoreDNS observes projected `Corefile` changes through its reload plugin (`5s` interval, `1s` jitter); Kubernetes volume projection adds its own delay. Verify the loaded configuration and public answers after reconciliation. `settings.json` and publisher Python code are read at process startup, so changing those requires controlled Pod replacement, one VPS at a time, with the other endpoint verified before proceeding. The DaemonSet rollout settings permit at most one unavailable Pod when a Pod-template update is used.

The shared BIND zone ConfigMap and backend configuration also keep stable names. Each backend supervisor checks projected changes every five seconds, validates a stable generation with `named-checkconf -z`, and reloads its existing BIND process. Invalid generations leave the previous authority running. Bump SOA serials when publishing zone content and verify the served serials and RRsets. Backend StatefulSets use `OnDelete`; supervisor/image/Pod-setting changes must be activated on one VPS and checked before replacing the other. A PodDisruptionBudget does not serialize independent StatefulSet rollouts.

Changing the two public addresses requires updating `settings.json`, the NetworkPolicy destinations, and parent-zone glue, then confirming both servers publish the new SOA and addresses. Keep target names `msk` and `fin`: adding a public site requires an explicit state/NS migration. Keep the mutable ConfigMap and Lease together when restoring etcd; never reset the Lease epoch while retaining a higher zone epoch. The controller deliberately refuses that inconsistent state.

Existing running application-zone processes keep serving their last valid zone when the API is unavailable. Health-based changes then stop. A restarted container retains its Pod's application-zone volume; recreating the whole Pod requires Kubernetes and its seed ConfigMap to be available. BIND secondary data has a separate persistent local volume, but its primary reachability and SOA expiry still apply. This is not an independent DNS control plane outside Kubernetes.

With a healthy API, removal normally takes roughly 20–30 seconds of probes, followed by API/file propagation and resolver caching. Losing the leader can add about 37–40 seconds for Lease takeover. TTL 30 is a request to caches, not an upper bound: resolver serve-stale behavior, application caches, and existing connections can extend disruption. `/ping` proves the ingress path, not every application's database or business operation. Real node/ingress/network interruption tests require the operator's approved maintenance window.

Run the controller's offline behavior checks with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 clusters/unified/public-dns/test_controller.py
```

The manifests pin [CoreDNS 1.14.7](https://github.com/coredns/coredns/releases/tag/v1.14.7) and [official Python 3.14.6 slim-trixie](https://hub.docker.com/_/python) by image digest. Implementation references: [CoreDNS file reload](https://coredns.io/plugins/file/), [Kubernetes Leases](https://kubernetes.io/docs/concepts/architecture/leases/), [ConfigMap update propagation](https://kubernetes.io/docs/concepts/configuration/configmap/), and [Flux apply policies](https://fluxcd.io/flux/components/kustomize/kustomizations/#controlling-the-apply-behavior-of-resources).
