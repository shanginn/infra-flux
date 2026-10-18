# Temporary private bridge for legacy PowerDNS clients

The parent PowerDNS Kustomization includes two migration Services and two
additive NetworkPolicies. The API has a separate generated ConfigMap and rolls
one replica at a time. The existing reader ConfigMap and reader Pod templates
stay unchanged. Bridge readiness does not switch any production client or writer.

The Services use `ClusterIP` with only verified VPS VPN addresses in
`externalIPs`, without NodePort or public ingress. `externalIPs` is
[deprecated since Kubernetes 1.36](https://kubernetes.io/docs/concepts/services-networking/service/#external-ips);
retire this bridge after the legacy clients move.

| Entry on each VPS | Destination | Receiving source |
| --- | --- | --- |
| UDP/TCP 5354 | Ready local reader, port 5353 | Enrolled client's VPN address |
| TCP 18081 | Any ready API replica, port 8081 | Measured kube-proxy MASQUERADE source |

Reader traffic uses `externalTrafficPolicy: Local` and fails without a ready
local reader. API traffic uses `Cluster`; its two replicas retain their home
preference and may run on any two of the three nodes. Measure both local and
remote endpoint paths for **each** VPS before an API rollout: a replacement API
Pod can move to either VPS. A route lookup is not source-NAT evidence.

## Private substitution contract

Create the reviewed ConfigMap `flux-system/unified-legacy-dns` before enabling
this revision in Flux. Give it label `reconcile.fluxcd.io/watch: Enabled` and
exactly these nine string values. The root Flux Kustomization requires this
additional source; keep `unified-network` and its three-key bootstrap contract
unchanged. Store actual addresses and rendered manifests outside public Git.

Activate in two reviewed Git revisions after the private ConfigMap exists.
First publish **only** the `flux-system/sync.yaml` change adding this required
substitution source; keep the old PowerDNS manifests. Wait for Flux Ready at
that revision and read back both sources in the live `unified` Kustomization.
Only then publish the API configuration and bridge manifests. The old live spec
cannot use new substitutions merely because its next build contains an updated
copy of itself: combining these steps can substitute empty values and partially
apply. Record the accepted first revision before releasing the second.

| Variable | Required value |
| --- | --- |
| `MSK_VPN_ADDRESS`, `FIN_VPN_ADDRESS` | Distinct IPv4 addresses assigned to the intended VPS VPN interfaces |
| `LEGACY_CONTABO_VPN_CIDR`, `LEGACY_RUBASE_VPN_CIDR` | Distinct enrolled client IPv4 addresses, each `/32` |
| `MSK_API_LOCAL_SOURCE_CIDR`, `FIN_API_LOCAL_SOURCE_CIDR` | Source received by an endpoint on the entry VPS, each `/32` |
| `MSK_API_REMOTE_SOURCE_CIDR`, `FIN_API_REMOTE_SOURCE_CIDR` | Source received by endpoints on another node, each `/32` |
| `POWERDNS_API_ACCESS_REVISION` | SHA256 of the four API source values, computed below |

The revision is SHA256 of UTF-8 `json.dumps(source_values, sort_keys=True,
separators=(',', ':'))`, where `source_values` contains exactly the four
`*_API_*_SOURCE_CIDR` keys above. Recompute it with every access change. The
API-only Pod annotation forces a rollout even when Flux substitutes a private
value after Kustomize generated the ConfigMap name. The render guard validates
this digest. No whole Pod/VPN CIDR is accepted for a measured source.

`api-access.conf` preserves the existing loopback and cluster allowlist, adding
only those four `/32`s. Both the API NetworkPolicy and PowerDNS allowlist admit
the measured sources. The original `api.conf` remains in the unchanged reader
ConfigMap. Headscale must permit both reader identities to use UDP/TCP 5354 and
only the writer identity to use TCP 18081. Source NAT prevents the API policy
from identifying the original client; the entry ACL and API key remain required.

## Validate and activate

1. Verify cluster identity, client/node identities, all six entry-to-endpoint
   combinations and restricted Headscale policy. Preserve the old administration,
   DNS and API paths. Remove any temporary diagnostic Service on the same ports.
2. Run the offline render guard against the approved pre-bridge revision and
   private ConfigMap, then render/substitute with strict missing-variable checks:

   ```sh
   python3 -B clusters/unified/powerdns/test_legacy_bridge.py \
     --baseline-ref APPROVED_COMMIT --values /private/path/unified-legacy-dns.yaml
   kubectl kustomize clusters/unified/powerdns
   ```

   The guard needs PyYAML, `kubectl` and `flux`. It checks the original reader and
   ConfigMap render against the baseline, API-only changes, exact source values,
   traffic policies and access revision. It performs no cluster operations.
   For the full root render, supply both reviewed substitution ConfigMaps.
3. Server-side dry run against the verified cluster; then reconcile the reviewed
   revision. Confirm both API replicas Ready and inspect their effective
   allowlists without exporting credentials. Compare reader UID/container IDs,
   restart counts, template and original ConfigMap to the pre-change evidence.
   Public DNS and its backends must continue answering during the API rollout.

## Acceptance before switching clients

From each enrolled legacy host, verify SOA over UDP and TCP through both VPN
entries. From the writer, make a read-only authenticated API request through
both entries and verify local and remote endpoint paths. Reader-only API access
must be denied. Verify denied access to SSH, Kubernetes, etcd and PostgreSQL.

From outside the VPN check both VPS public IPv4 and any public IPv6 addresses:
UDP/TCP 5354 and TCP 18081 must not provide a service. Inspect effective Service
and kernel forwarding rules; `ss` alone cannot prove a Service is closed.
Confirm public UDP/TCP 53 and the old administration channel still work.
Ordinary [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
cannot block all traffic from a Pod's own node and does not replace entry ACLs
or API authentication.

Host success does not prove application Pod egress. Before switching an actual
legacy application, verify its Pod-to-VPN path and effective namespace egress
policy. Do not change customer data as a connectivity test or infer writer
cutover from bridge readiness. Repeat source measurement after a relevant CNI,
service-proxy, addressing or routing change before updating the allowlist.

## Retirement or rollback

Before client cutover, removing `legacy-bridge` from the parent resources is a
bounded rollback of its two Services and two NetworkPolicies. After cutover,
restore a verified client path first. Check that migration ports stop forwarding
and existing Services/public DNS remain healthy.

To finish retirement, return the API config volume to the original generated
ConfigMap, remove its access-revision annotation and the separate API generator,
then remove the required `unified-legacy-dns` substitution source. Reconcile and
verify API readiness before deleting that private ConfigMap. Do not remove its
values while any manifest still references them. Do not restart readers, flush
firewall rules or revoke unrelated VPN identities.
