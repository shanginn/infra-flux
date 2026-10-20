# Private application search

These two independent SearXNG services retain the application-local Service names
and their existing image digests. They run on FIN so search-engine requests use
the Finnish connection. Application workers and databases can run on HOME.
Each service requests 100m CPU and 256Mi memory, with limits of one CPU and
768Mi memory. There is no persistent volume, public ingress or external Service.

Provision each runtime Secret privately before creating its Deployment:

| Namespace | Secret | Required keys |
| --- | --- | --- |
| `mrcatcha` | `mrcatcha-app-searxng-runtime` | `settings.yml`, `SEARXNG_BASE_URL`, `FORCE_OWNERSHIP` |
| `wtfhappendbot` | `wtf-happend-bot-searxng-runtime` | `settings.yml`, `SEARXNG_BASE_URL`, `FORCE_OWNERSHIP`, `SEARXNG_SECRET` |

Copy the source settings and environment values exactly. Preserve the two
applications' different configurations and secrets; copy only the listed keys,
not their complete application Secrets. The WTF settings ConfigMap becomes a
Secret in the destination. Keep all values outside this public repository.
Settings are mounted through `subPath`, and environment values are read at
startup; a later configuration change requires a rollout of that service.

Render either subdirectory independently with `kubectl kustomize`. The two
scoped Flux owners are declared in `../searxng-flux.yaml` and included by the
applications parent. Provision both runtime Secrets before publishing an
activation. Verify the pinned image pulls, the Pod
becomes Ready, and both the Service and Pod return HTTP successfully. Test a
bounded real JSON search from an appropriately labelled Pod in the same
application namespace, including usable results from the configured engines.
HTTP readiness alone does not prove that external searches work.

Ingress permits only Pods in the same namespace with the matching application
instance label, on port 8080. Egress permits cluster DNS and public IPv4
HTTP/HTTPS; private address ranges are excluded from search-engine traffic.
Verify an unrelated namespace cannot reach the service. The manifests start no
bots or workers and change no existing clients. Client handover and source
retirement are separate steps; the current users on the old cluster continue to
use their existing Service until deliberately moved.
