# Temporary PowerDNS API proxy

This optional directory creates a separate preview Service, two proxy Pods,
a generated ConfigMap and a NetworkPolicy. It is not included by the parent DNS
Kustomization. The Flux example is suspended. Rendering or enabling the preview
does not change existing writer URLs, DNS Services or database writers.

HAProxy checks both private API entries with the existing
`powerdns-api/api-key` Secret. Client headers pass through unchanged: the proxy
does not add its health-check credential to client requests. HTTP access logs,
header capture and admin sockets are disabled. A credential rotation requires
a controlled proxy rollout after the old and new API identities are verified.

Only a failed connection establishment may retry, once, against another
available entry. Responses, response timeouts and connections lost after a
request was sent must not trigger replay. An ambiguous write still requires
reconciliation with authoritative data; this proxy does not make writes exactly
once. Its per-phase timeouts do not replace the application's absolute deadline.

CoreDNS forwards the preview's UDP/TCP DNS ports to the existing old PowerDNS
Service. This preserves the DNS ports of the writer alias during a later selector
switch. Never point that forwarding destination at the alias being switched or
at the preview itself. The process readiness probe keeps DNS available when both
API entries are down; `/ready` on port 8404 separately reports API availability.
HAProxy and DNS metrics are on ports 8404 and 9153, restricted to the monitoring
namespace. A monitoring collector must actually scrape them before claiming
monitoring coverage. Both proxy replicas share the legacy host's failure domain.

## Private substitutions

Use the existing `flux-system/legacy-dns-network` ConfigMap without changing its
two-key contract: `MSK_VPN_ADDRESS` and `FIN_VPN_ADDRESS`. The proxy also requires
a separate `flux-system/legacy-dns-proxy` ConfigMap containing exactly:

- `LEGACY_POWERDNS_DNS_SERVICE_ADDRESS`: the observed ClusterIP of the old DNS
  Service that continues selecting the old PowerDNS Pod.
- `LEGACY_DNS_PROXY_CONFIG_REVISION`: SHA-256 of compact, sorted-key JSON containing
  the three address values above. Use `config_revision()` in the validation
  helper. This annotation rolls the Pods when private substitutions change;
  the generated ConfigMap name alone cannot track post-build substitutions.

All addresses must be distinct literal IPv4 addresses, without prefixes or
whitespace. Record actual identities and values privately. Missing or malformed
values must fail validation, never become defaults. Both private maps should
carry `reconcile.fluxcd.io/watch: Enabled`.

The revision is computed by the operator, not automatically by Flux. For later
address changes, suspend only this dedicated Flux object, update the two private
maps, validate their merged values and recomputed revision, then resume it.
Verify the new Pod template and effective configuration. Updating the revision
first while reconciliation is active can roll Pods with old addresses and leave
no later rollout when the address map changes.

Run `python3 test_config.py` with PyYAML and kubectl available. An optional
`--values /private/path.json` validates the four merged substitutions. Render,
substitute the reviewed values, reject remaining placeholders and perform a
server-side dry run against the identity-checked legacy cluster. Keep the
rendered result outside public Git.

## Activation and switch

Before creating the preview, verify the cluster and namespace UIDs, existing
Services and their named ports/selectors, old DNS Pod, application and worker
Pods, API key identity and the two private bridge entries. Confirm the new
resource names are unowned/absent, the current network policies permit the
intended flows, and resources are available. Bootstrap only this dedicated Flux
object after the private ConfigMaps are read back; do not apply an entire legacy
cluster directory. Its inventory must contain only this directory's resources.

Validate the pinned HAProxy image with dummy credentials and isolated backends
before activation. Exercise both paths, connection-only failover, and an already
received mutation followed by a lost response or timeout. Such mutation tests
must use disposable backends, never customer data.

Through the preview, verify authenticated and rejected API requests from both
application replicas and the worker within their real request deadline. Verify
DNS answers, authoritative flags, NXDOMAIN and REFUSED behavior over UDP/TCP
from a source already permitted to reach the preview's DNS container ports;
the application policies permit API access but do not grant this DNS access.
Do not broaden application egress just to run a DNS probe. Separately,
test each entry and failure recovery without changing the working Services.
Check metrics and all original Pod/Service identities afterwards.

Switch the existing writer alias only after the old database writer is fenced,
a final consistent encrypted backup is restored and checked, imported data and
sequences agree, and every old public read path serves the new data. A guarded
selector change must preserve the alias's UID, ClusterIP and all named ports.
Verify the Kubernetes-managed EndpointSlices after the change. Never change the
old DNS Service selector to the proxy while CoreDNS still forwards to it.

After any possible new write, restoring an old selector is not a database
rollback: reverse fencing and reconciliation are required before enabling the
old writer. Retire the preview through its dedicated Flux inventory only when
no clients or retained aliases depend on it. A standalone Flux object has no
implicit parent owner; deleting its file alone does not remove live resources.
