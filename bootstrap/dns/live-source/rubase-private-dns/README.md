# Private DNS entry to the existing Rubase PowerDNS

This inactive component adds one Service in `vibesites-dns`:
`vibesites-powerdns-private-dns`. It forwards UDP and TCP 5355 on the verified
Rubase VPN address to port 53 of the existing PowerDNS Pod. It adds no API port,
workload, database operation, writer alias change or public listener. No parent
includes it, and no activation is performed by the render test.

This is preparation for investigating a DNS frontend move while retaining the
existing Rubase writer. It does not establish a completed frontend design or
authorize a database cutover. Existing DNS and API Services, their selectors, public
endpoints and application credentials stay unchanged.

## Private values and activation prerequisites

`RUBASE_VPN_ADDRESS` must be one literal IPv4 address independently observed on
the intended Rubase VPN interface. Keep that value and rendered manifests in
private storage. A future owner must require a scoped private substitution map,
fail on missing values and validate that no placeholder remains. Do not reuse
or broaden an existing substitution map, activate this through a whole root
reconcile, or apply the unsubstituted manifest.

Before any activation, pin the host, cluster, namespace, source owner, existing
PowerDNS Service/Deployment/Pod identities and the Pod's numeric DNS ports.
Require the new Service name to be absent and check all Services and effective
forwarding rules for a conflicting private port 5355. A missing socket alone
does not prove a Kubernetes Service port is unused. Both traffic policies are
`Local`: the entry node must have a Ready local PowerDNS endpoint, and this
bridge provides no failover to another source database.

The current inspected namespace policies do not isolate the existing PowerDNS
Pod. This component therefore includes no NetworkPolicy. A new narrow ingress
policy selecting that Pod could block existing DNS or API clients. Recheck the
effective policy before activation; any necessary change needs a separate
review of every existing caller rather than a speculative isolation policy.

The VPN must separately permit only the reviewed unified DNS callers to reach
this exact destination on UDP/TCP 5355. The existing legacy-to-VPS permissions
do not grant this reverse path. Private `externalIPs` alone are not an access
control boundary. Verify actual delivered VPN rules, Pod-to-VPN forwarding and
any source translation; do not infer them from a route lookup. No permission
to 8081, database ports or host administration is needed.

## Validation and acceptance

Run the offline test from the repository root:

```sh
python3 bootstrap/dns/live-source/rubase-private-dns/test_component.py
```

The test uses local `kubectl kustomize` and `flux envsubst`; it makes no cluster
requests. It compares the complete Rubase DNS render before and after inclusion
and requires exactly one additional DNS-only Service with every existing object
unchanged. It also checks that the selector matches the current PowerDNS Pod
template and excludes its schema-init Job.

A future activation needs an exact private substituted render and server-side
dry run, followed by a narrowly owned Service creation and independent readback.
Verify numeric EndpointSlice ports and the unchanged serving Pod identity.
From each actual unified frontend caller, compare SOA and representative live
customer answers against the existing source over both UDP and TCP. Preserve
failed requests and verify source/backend attribution. Test that public
addresses do not expose 5355 while existing public DNS and API paths still work.
This acceptance must precede any frontend route change; it does not change
writer authority or claim a database snapshot boundary.

Before any caller uses the bridge, retirement removes only this Service through
its eventual exact owner. Once in use, first restore and verify the caller's
previous DNS path. Never restart the source Pod, revoke writer grants or remove
an existing Service as part of bridge cleanup.
