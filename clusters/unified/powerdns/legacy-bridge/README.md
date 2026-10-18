# Temporary private bridge for legacy PowerDNS clients

This optional directory is **inactive** until explicitly added to the parent
PowerDNS Kustomization. It creates two new Services and two additive
NetworkPolicies. It does not change public DNS, existing Services, workload
placement, replicas, credentials or the Headscale policy.

Both Services use `type: ClusterIP` with only the two verified VPS VPN addresses
in `externalIPs`. There is no NodePort, LoadBalancer or public ingress.
`externalIPs` is [deprecated since Kubernetes 1.36](https://kubernetes.io/docs/concepts/services-networking/service/#external-ips);
this bridge is temporary and must be retired after the legacy clients move.

| Entry on each VPS | Destination | Source seen by the destination |
| --- | --- | --- |
| UDP/TCP 5354 | Ready reader on the same VPS, port 5353 | Legacy client's VPN address for traffic entering over VPN |
| TCP 18081 | Any ready API replica, port 8081 | Source after kube-proxy MASQUERADE; measure for each VPS |

Reader traffic uses `externalTrafficPolicy: Local`; it fails on a VPS without a
ready local reader. API traffic uses `Cluster` because its two replicas are not
guaranteed to run on both VPS. The existing API preference for home is preserved.
MASQUERADE can select a tunnel/interface address instead of the node's VPN IP.
Queries originating on the destination node also follow a different source-NAT
path and do not substitute for tests from an enrolled legacy client.

## Activation

1. Verify the intended cluster identity, node VPN addresses, restricted
   Headscale policy and enrolled client identities. Keep the old administration
   path and old DNS/API endpoints. The policy must permit both reader tags to
   reach UDP/TCP 5354 and only the writer tag to reach TCP 18081 on the two VPS.
2. Populate these six required substitutions from private, reviewed runtime
   evidence. No defaults are provided:

   | Variable | Required value |
   | --- | --- |
   | `MSK_VPN_ADDRESS`, `FIN_VPN_ADDRESS` | Distinct IPv4 addresses actually assigned to the intended VPS VPN interfaces |
   | `LEGACY_CONTABO_VPN_CIDR`, `LEGACY_RUBASE_VPN_CIDR` | Distinct enrolled legacy client IPv4 addresses, each with `/32` |
   | `MSK_API_SOURCE_CIDR`, `FIN_API_SOURCE_CIDR` | Measured API ingress source for each VPS, each with `/32` |

   Verify the source at the receiving API Pod, including local and remote
   endpoint paths. If one VPS produces multiple sources, stop and review an
   explicit additional `/32`; do not widen a variable to the whole VPN or Pod
   network. Headscale authenticates the writer before entry; after source NAT,
   the API NetworkPolicy cannot distinguish the original reader from writer.
   The API key remains required.
3. The current `api.conf` allows loopback and `10.0.0.0/8`. If an observed source
   is outside this allowlist, review a narrow allowlist change before activation.
   This component does not change it. The runtime generates its configuration
   when the API process starts, so updating a ConfigMap alone does not prove a
   new allowlist is active. Do not restart the public DNS workloads.
4. Add the six values to a reviewed private Flux substitution source and add
   `legacy-bridge` to the parent PowerDNS resources only after review. The current
   root Flux Kustomization reads `unified-network`; its bootstrap currently
   expects exactly the original three network keys. Extending that ConfigMap
   also requires reviewing that bootstrap contract, or selecting an additional
   private substitution source. Do not overwrite the existing ConfigMap or
   rerun bootstrap to bypass a mismatch.
5. Render locally, substitute only the six known variables from the reviewed
   private source, require no unresolved placeholders, and validate the result
   against the intended API with server-side dry run before reconciliation:

   ```sh
   kubectl kustomize clusters/unified/powerdns/legacy-bridge
   kubectl --context REVIEWED_CONTEXT apply --server-side --dry-run=server \
     -f /private/path/rendered-legacy-bridge.yaml
   ```

   Keep rendered manifests and runtime evidence outside Git. Dry run validates
   admission; it does not prove packet routing, source NAT or access controls.

## Acceptance before switching any client

From each actual legacy host, verify DNS SOA over UDP and TCP through both VPN
entries; check that each reaches its local reader. From the writer, use a
read-only authenticated API request through both entries and confirm the
observed receiving source. Verify access to local and remote API replicas.
From the reader-only client, API access must be denied. Also verify denied
access to SSH, Kubernetes, etcd and PostgreSQL through the VPN.

Check both VPS public IPv4 addresses and any public IPv6 addresses from outside
the VPN: UDP/TCP 5354 and TCP 18081 must not provide a service. Inspect the
effective Service and kube-proxy rules for private destination addresses only;
`ss` alone is insufficient because Service forwarding uses kernel rules rather
than a listening process. Confirm the previous public UDP/TCP 53 answers and
administration connection still work. Ordinary Kubernetes NetworkPolicy cannot
block all traffic from a Pod's own node; it does not replace the entry ACL or API
authentication. See [NetworkPolicy semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

Host success does not prove Pod egress. Before switching a legacy application,
verify its actual Pod-to-VPN path and source NAT, and review its namespace's
egress policy separately. Do not infer successful writer migration from bridge
readiness or change customer data as a connectivity test.

## Retirement or rollback

After writers and readers have moved and no legacy endpoint depends on this
bridge, remove only `legacy-bridge` from the parent resources. Flux pruning
removes the four objects labelled `app.kubernetes.io/part-of=powerdns-legacy-bridge`.
Verify the private migration ports no longer forward, while the original
Services and public DNS remain healthy. Then remove only the six dedicated
substitutions from the reviewed runtime source.

Before client cutover, the same removal is a bounded rollback. After cutover,
restore a verified client path first: deleting a bridge still in use interrupts
that traffic. Do not delete or restart the existing PowerDNS/public DNS
workloads, flush firewall rules, or revoke unrelated VPN identities.
