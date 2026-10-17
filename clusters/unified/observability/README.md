# Grafana and log exploration

Grafana is at `https://grafana.apps.shanginn.io`. Two replicas run on different VPS nodes, with sessions and application state in the dedicated `grafana` PostgreSQL database. Dashboards and data sources are provisioned from this directory. Pod-local scratch data is disposable. The old `grafana.shanginn.io` service is unrelated.

## Prepare and activate

1. Prepare the dedicated PostgreSQL role/database and runtime Secret with `bootstrap/ansible/observability.yml`. Retain the namespace ownership annotation. The Secret `observability/grafana-runtime` must contain `GF_SECURITY_ADMIN_USER`, `GF_SECURITY_ADMIN_PASSWORD`, `GF_SECURITY_SECRET_KEY`, `GF_DATABASE_USER`, `GF_DATABASE_PASSWORD`, and `ca.crt`. Never commit these values. All replicas must share the same encryption key. PostgreSQL uses `verify-full` against `unified-postgres.database.svc:5432`, with the CA mounted at `/etc/postgresql/ca.crt`.
2. Install the `letsencrypt-production` ClusterIssuer and ensure HTTP-01 is reachable through Traefik. The Ingress requests `grafana-tls`; it serves the UI only on the HTTPS entrypoint. Grafana's NetworkPolicy selects only Grafana Pods, so it does not isolate cert-manager's temporary HTTP-01 solver Pods.
3. Add this directory to Flux after the runtime prerequisites exist. Add `logging/` as a separate Flux Kustomization only after its host filesystem prerequisite succeeds. The Grafana Kustomization intentionally does not create the log volume or activate the logging workload.
4. Verify both Grafana replicas, their `/api/health`, the issued certificate, login, a live dashboard query from each Prometheus replica, and a log query. Configuration validation alone does not establish runtime readiness or successful collection.

The admin Secret initializes Grafana; changing its password later in a Secret does not automatically reset an existing database account. Rotate an existing password through Grafana's supported account administration, then synchronize the protected bootstrap value. Preserve `GF_SECURITY_SECRET_KEY` with the encrypted runtime backup: it encrypts database-held credentials. The PostgreSQL backup contains Grafana's application state; the node runtime bundle includes `/etc/infra-flux/observability-runtime.json`.

## Dashboards and data sources

The ten provisioned dashboards cover nodes, Kubernetes workloads, control plane, PostgreSQL, Garage, ingress/DNS, VPN, backups, logs, and application error tracking. The error-tracking dashboard links to GlitchTip and shows its capacity guard, queue, worker activity, process metrics and scrape health. Shared database and queue gauges use max across replicas; task counters are summed. SDK/DSN integration and a verified canary are required to establish application exception delivery. Panels distinguish missing data from healthy zero values. Rates require a sufficient scrape window; narrow windows and newly started targets can be empty. Workload dashboards cover observed infrastructure and resource behavior; they do not prove business transactions or automatically instrument application exceptions.

Select **Prometheus replica 0** or **Prometheus replica 1** using the dashboard data-source selector. They are separate time series databases; ordinal numbers are not site names. Explicit selection keeps a query on one history and avoids double-counting two collectors. If a replica is unavailable, select the other. This setup does not merge history or provide automatic data-source failover.

Log exploration always uses **Loki home**. The log service is home-only and unavailable while that node is offline. Metrics dashboards and the Grafana UI remain on the VPS nodes, subject to the shared PostgreSQL/API quorum and available resources. The logging README describes retention and collection loss limits.

Grafana requests 50m CPU and 128 MiB RAM per VPS, with limits of 1 CPU and 512 MiB. Both replicas can coexist only on the two VPS nodes, so updates use `maxSurge: 0` and `maxUnavailable: 1`. Each replica opens at most three PostgreSQL connections. There is no persistent Grafana volume. Disable public signup and anonymous access; create normal Viewer accounts for routine access. The server has no general Internet egress or plugin download path. Its unauthenticated process-metrics endpoint is disabled because the UI Ingress would also expose that path.

## Versions and maintenance

Images are pinned by version and manifest digest in `grafana.yaml` and `logging/workloads.yaml`. Upgrade in Git, validate configuration with the corresponding official release, inspect upstream migration/release notes, and verify runtime queries after rollout. ConfigMap contents opt out of Flux string substitution so Grafana variables and Alloy capture-group references retain their intended syntax.

References: [Grafana high availability](https://grafana.com/docs/grafana/latest/setup-grafana/set-up-for-high-availability/), [provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/), [configuration](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/), [Grafana 13.2.4](https://github.com/grafana/grafana/releases/tag/v13.2.4).
