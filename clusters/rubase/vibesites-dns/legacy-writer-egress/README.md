# Optional legacy writer egress

This directory is inactive. Its parent does not include it, and the separate
Flux activation template is suspended. It renders only two additive egress
NetworkPolicies in `vibesites-pi`; application-owned policies remain intact.
The app selector matches `vibesites-pi-default`; the worker selector matches
`vibesites-pi-worker`. Neither voice workloads nor other namespaces are selected.

The application repository owns the existing policies in
`vibesites-redknife/k8s/network-policy.yaml` and deploys them through its CI
workflow. These separate policy names let infrastructure own the temporary
VPN permission without competing over the application's objects.

Before activation, create the private ConfigMap `legacy-dns-network` in the
**legacy cluster's** `flux-system` namespace. It must contain exactly
`MSK_VPN_ADDRESS` and `FIN_VPN_ADDRESS`: distinct literal IPv4 addresses observed
on the two intended VPS VPN interfaces, with no prefix, whitespace or defaults.
Keep values and rendered manifests outside Git. The manifest appends `/32`;
never substitute a network range. A similarly named map in another cluster is
not available here. Missing substitutions must fail validation.

Render this directory, substitute only those two reviewed values, require no
remaining placeholders and server-side dry-run against the intended legacy
cluster. The only permission added must be TCP18081 to those two `/32`s. Then
activate the reviewed dedicated Flux template by setting `suspend: false` and
adding it through the intended cluster's existing Flux entrypoint. Do not add
the activation template to this directory's own `resources`.

Activate only after the restricted reader/writer Headscale tags and private API
bridge are verified. This permission alone does not establish routing, source
NAT, API authentication or readiness. Before switching a writer, use its existing
app **and** worker containers to verify the real API path through both VPS
entries, preserving their Pod/container identities. Their installed runtime can
perform the read-only requests; no package installation or workload restart is
needed. A successful host or BIND Pod probe does not prove writer Pod egress.

Keep the existing namespace/TCP8081 route until cutover is verified. Afterwards,
retire these two policies through their own Flux inventory once no writer uses
the bridge. Before removing a bridge already in use, restore a verified writer
path. Do not delete the application's existing NetworkPolicies.
