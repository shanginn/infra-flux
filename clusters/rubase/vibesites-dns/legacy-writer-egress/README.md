# Temporary legacy writer egress

The enabled standalone Flux manifest is
[`clusters/rubase/legacy-powerdns-writer-egress.yaml`](../../legacy-powerdns-writer-egress.yaml).
It reconciles this directory independently of the existing DNS Kustomization.
The example remains suspended. This directory renders only two additive egress
NetworkPolicies in `vibesites-pi`; application-owned policies remain intact.
The app selector is `app.kubernetes.io/name: vibesites-pi`; the worker selector
requires `app.kubernetes.io/name: vibesites-pi-worker` and
`app.kubernetes.io/component: temporal-worker`. Neither voice workloads nor
other namespaces are selected.

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
publish the reviewed standalone manifest and confirm the legacy GitRepository
has that revision. Bootstrap only that one Flux Kustomization after the private
ConfigMap has been read back. Its `dependsOn: vibesites-dns` must resolve to the
existing Ready DNS Kustomization in the same `flux-system` namespace. Do not
bootstrap the entire legacy cluster directory or add this object to its own
`resources`. Do not assume a file at the cluster directory root is automatically
reconciled: inspect the actual live owner and inventory first.

Before the initial private ConfigMap or Flux object creation, pin and recheck
the legacy `kube-system`, `flux-system` and application namespace UIDs, the
GitRepository identity/source, and the DNS dependency UID. Require both new
policy names and the new Flux object to be absent. Create the private ConfigMap
with label `reconcile.fluxcd.io/watch: Enabled`; if one already exists, require
its exact reviewed data and ownership rather than overwriting it. Read back
its UID and both values before creating the single Flux object. Keep this
identity evidence private. These checks target the legacy cluster, not the
new unified cluster.

Wait for the dedicated Kustomization Ready at the published revision. Its
inventory must contain exactly `legacy-powerdns-app-egress` and
`legacy-powerdns-worker-egress`; verify their selectors, two `/32`s and sole
TCP18081 permission. Confirm existing policies and application Pod identities
are unchanged. Later edits to this directory reconcile through that dedicated
object; changes to the standalone Flux object's spec require a reviewed update
to that object unless an explicit parent owner is introduced.

Before activation, verify the exact private bridge Service and API Pod identities,
measured source allowlist, and delivered restricted reader/writer Headscale
rules. These two additional destination permissions may be activated to enable
real application probes while connectivity is still being diagnosed. Activation
does not change the writer endpoint, credentials or DNS data, and it is not
connectivity acceptance. Preserve every failed probe.

Before switching a writer, require successful authenticated host and workload
checks through both VPS entries. Use the existing app **and** worker containers
to test the real path, preserving their Pod/container identities and the
application's request deadline. Their installed runtime can perform read-only
requests; no package installation or workload restart is needed. A successful
host or BIND Pod probe does not prove writer Pod egress. Keep actual writer
cutover gated on connectivity and data/fencing verification independently of
this narrow permission change.

Keep the existing namespace/TCP8081 route until cutover is verified. Afterwards,
retire these two policies through their own Flux inventory once no writer uses
the bridge. Because the initial standalone object may have no parent owner,
removing its file from Git alone does not delete the live object. Suspend it,
verify its exact two-object inventory and remove that dedicated object with
normal Flux pruning; confirm only those two policies disappear. Before removing a bridge already in use, restore a verified writer
path. Do not delete the application's existing NetworkPolicies.
