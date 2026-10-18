# Optional PowerDNS read routes

These files are **inactive**. No cluster root or component references them.
The three Kustomize Components are alternatives for existing owners; the fourth
directory creates only a separately labelled DNS preview. They do not import
data, fence a database, enable a writer, change registrar settings or switch an
existing Service selector.

| Variant | Existing owner to change later | Result |
| --- | --- | --- |
| `legacy-dnsdist` | Each legacy cluster's `vibesites-dns` Kustomization | Preserve all BIND suffixes and public Service identities; send other DNS queries to both private reader entries on 5354. |
| `rubase-proxy` | Dedicated `legacy-powerdns-api-proxy` Kustomization | Send its DNS ports directly to both private reader entries; preserve HAProxy API configuration. |
| `unified-public` | Unified `public-dns` Kustomization | Keep the local `apps.shanginn.io` authority and all 22 BIND suffixes; send the default route to the node-local PowerDNS reader Service. |
| `contabo-forwarder` | A new, explicitly bootstrapped standalone preview owner | Two DNS-only Pods and a separate preview Service. No API listener, API credential or permission to VPN port 18081. |

Use the existing Flux owner for every existing resource. Check actual inventories
and managed fields first, including any legacy root owner that also claims DNS
objects. Do not create a second Flux owner for a ConfigMap, Deployment or Service.
No variant changes BIND configuration, dynamic journals, legacy PostgreSQL or
its schema-init containers.

## Render and configuration checks

Run the offline tests from the repository root:

```sh
python3 bootstrap/dns/read-route/test_routes.py
```

The tests invoke `kubectl kustomize`, with PyYAML installed, and compare complete
rendered objects. They prove configuration scope, not deployed DNS behavior.
For a private candidate, copy the intended existing Kustomization to a separate
review checkout, then add the applicable `components` entry:

```yaml
# From clusters/{rubase,contabo}/vibesites-dns/kustomization.yaml:
components:
  - ../../../bootstrap/dns/read-route/legacy-dnsdist
```

The component paths from `clusters/rubase/vibesites-dns/legacy-api-proxy` and
`clusters/unified/public-dns` are respectively
`../../../../bootstrap/dns/read-route/rubase-proxy` and
`../../../bootstrap/dns/read-route/unified-public`.
Render the changed owner with `kubectl kustomize PATH` into a private file.
Do not apply a rendered cluster root or publish those references before the
activation gates below. The Contabo preview renders independently with:

```sh
kubectl kustomize bootstrap/dns/read-route/contabo-forwarder
```

Legacy variants require the already enrolled hosts' measured, distinct literal
IPv4 `MSK_VPN_ADDRESS` and `FIN_VPN_ADDRESS` substitutions. The proxy and DNS-only preview policies
allow only those two `/32` destinations for UDP/TCP 5354. They do not widen Headscale
ACLs. Verify actual source translation and receiver policy from each consumer
before enabling a route; a host-level success alone does not prove Pod access.

The dnsdist and Contabo preview Pod templates also require
`LEGACY_DNS_READ_ROUTE_REVISION`: SHA-256 of compact sorted JSON containing the
two addresses **and** the SHA-256 of each applied variant file. Compute it from
reviewed private values, retain it in a private watched ConfigMap, and reject
unresolved substitutions. This makes address or source changes trigger a rollout.
The existing Rubase proxy keeps its existing private-map contract and revision
annotation; its generated ConfigMap changes when this Corefile is merged. Do
not remove the old address variable from its private map in the same step.

First reconcile the owning Flux object's required `substituteFrom` sources,
with the private maps present, and verify that exact live spec. Only then
publish the component reference. For later private-map changes, suspend only
the owning dedicated Flux object, update values and their computed revision,
validate the merged candidate, then resume. Never roll with a revision computed
from a different address set.

Before activation, validate the candidate with the **actual deployed dnsdist
binary** and pinned CoreDNS image in an isolated fixture. Exercise positive SOA,
NXDOMAIN, REFUSED, UDP without TCP fallback, TCP, both upstream failures and a
surviving upstream. Run a server-side dry run against the identity-checked target.
These source files alone do not assert that those image/runtime checks passed.

## Health and failure behavior

Dnsdist checks the private synthetic SOA and sets `mustResolve=true` so NXDOMAIN,
SERVFAIL and REFUSED are not accepted as health success. It chooses a healthy
backend using its existing default policy and returns SERVFAIL when none is
available. Existing BIND routing remains separate. The public synthetic
`health.test` and `vibesites-dns-health.test` suffixes return REFUSED.
The unified root chain repeats the scoped refusal for apex DS queries, because
CoreDNS routes those queries through the parent rather than the child block.

CoreDNS checks network reachability, retries SERVFAIL/REFUSED on the other
upstream, and fails quickly when all upstreams are known down. A DNS response
such as REFUSED can satisfy CoreDNS's transport health check; it does **not**
prove correct zone content or PostgreSQL freshness. Independently check SOA/data
parity and replication lag. These variants add no answer cache. The shared explicit parent/root chain preserves DS routing. Its first forwarder
excludes all 22 BIND suffixes using `except`; only those names reach the BIND
forwarder. It has no response-based `next`, so a customer NXDOMAIN does not
fall through to an unrelated authority.

Neither process `/ready` nor dnsdist's existing TCP readiness checks test the
complete backend path. The dnsdist rolling strategy preserves the old replica
while a new Pod becomes Ready, but `minReadySeconds` is not an authority check.
Rehearse a separately labelled candidate, require both backend health and real
queries before switching, and measure the real rolling transition. Do not infer
zero interruption from Kubernetes readiness alone.

Primary references: [dnsdist server configuration](https://www.dnsdist.org/reference/config.html),
[dnsdist server selection](https://www.dnsdist.org/guides/serverselection.html),
[CoreDNS forward](https://coredns.io/plugins/forward/),
[CoreDNS template](https://coredns.io/plugins/template/),
[CoreDNS server-block routing](https://coredns.io/manual/toc/#server-blocks).

## Activation order

1. Complete the reviewed database fence, a fresh fenced backup and isolated
   restoration, explicit-ID import, six sequence readbacks and complete table
   parity. Both ordinary database writers remain fenced throughout the DNS read
   transition. An earlier observational backup is not a final fenced snapshot.
2. Verify every existing reader and writer consumer, including dormant/configured
   Contabo API clients and both legacy internal DNS aliases. A single idle SQL
   session sample cannot prove that no future writes are possible. Determine the
   Contabo database disposition and preserve its data before closing its API.
3. Validate the separately labelled Contabo preview and the Rubase proxy's new
   DNS route directly, while existing Service selectors still point at the old
   Pod. The Rubase proxy **must stop forwarding DNS to the old Service before
   either old DNS alias can select that proxy**. Otherwise a forwarding loop is
   created. Preserve the API proxy's original authenticated health configuration.
4. Activate unified default routing and both legacy public dnsdist routes through
   their existing owners, one endpoint at a time. Verify all retained old public
   addresses, both new entries and every internal alias. Keep the actual old
   Service UIDs, ClusterIPs, DNS ports and external/NodePort mappings unchanged.
5. Only after the Contabo API-client question and database fence are resolved,
   prepare a separate reviewed patch in its existing Service owner: select
   `app.kubernetes.io/name: legacy-pdns-read-forwarder` on both DNS aliases,
   retain DNS 53 UDP/TCP and their named target ports, and explicitly **remove
   the TCP 8081 Service port**. The preview has no `http-api` container port or
   listener. Closing 8081 is intentional; never silently redirect Contabo API
   writes or give that VPN client a writer tag. This selector/port patch is not
   included here. If a real Contabo writer is still required, resolve its
   ownership/routing separately before this step.
6. Prove fresh backend attribution for every changed path while writers remain
   fenced. Equal old/new answers are insufficient because both databases can
   contain the same frozen data. Use scoped request counters or observed fresh
   flows, stable identities/serial boundaries, and retain every failed sample.
7. Follow the separately reviewed writer cutover only after complete read-path
   convergence. Verify writer Service identity and API/DNS behavior, enable only
   the new writer, then perform a bounded owned canary. Preserve the old writer
   fence. These variants never grant or restore SQL privileges.

Before any new write, a failed read-route transition can return to the exact
reviewed old routes while both writers stay fenced. After a new write, do not
restore a stale database's writer or read route without a new consistency plan.
Retain old resources and evidence until rollback and retirement conditions are
verified. Delete a preview only through its owner after no Service uses it.
