# Bounded home log storage

Loki runs once on home with filesystem storage. Alloy reads container stdout/stderr on every node and sends it to the private Loki Service. No public Ingress, NodePort, host port or external log destination is configured. NetworkPolicy allows only Alloy ingestion, Grafana queries and Prometheus metrics.

## Filesystem prerequisite

Run `bootstrap/ansible/logging.yml` with the private inventory, `logging_prepare_enabled=true`, and the verified live `logging_cluster_uid`. It only prepares storage; it does not apply Kubernetes workloads. It requires the existing owned Debian 13 home cluster marker, matching Kubernetes CA and live cluster UID, and at least 114 GiB root free before allocation.

The helper exclusively creates `/var/lib/infra-logging/loki.ext4`, physically preallocates **4 GiB** with `fallocate` and verifies that allocation before formatting **that new file only** as ext4 (`nodiscard`). Kernel initialization and later zero/discard operations can make parts of a loop backing file sparse even after this initial reservation. The fixed file length and inner filesystem capacity remain the hard size bound. Existing partitions and filesystems are not formatted. Its owned systemd mount persists at `/var/lib/infra-logging/loki`; Loki uses the `data` subdirectory. Mount and verification units are ordered before kubelet. No change to kubelet's existing service or the host's partition layout is made. The guard orders startup but is not a kubelet dependency: its failure must not stop the whole node. If the log mount fails, the underlying root path has no `data` directory for this local PV. Kubernetes' local-volume plugin checks the existing source path and fails on a missing directory; it does not create this source as a hostPath `DirectoryOrCreate` volume would. The helper creates `data` only after verifying the mounted loop filesystem.

The ownership record binds the image inode/device, filesystem UUID, machine identity, cluster UID and CA. The parent `/var/lib/infra-logging` is root-owned mode **0711**: traversal permits node-exporter to obtain filesystem capacity, but other users cannot list it. The mount root and Loki data directory stay **0700**, and the image stays **0600**. Data and image contents are not made readable. Normal load/verify rejects a parent with any other mode. A rerun validates the exact mount, loop backing file/inode, fixed length, filesystem UUID/capacity, data ownership and active/enabled units without reformatting. Every verification also requires root free space of at least **110 GiB plus any currently unallocated bytes of the 4 GiB image**. The JSON readback reports allocated bytes, unallocated bytes, and required/actual root headroom. Allocation is not assumed to remain equal to apparent file length. Foreign paths, symlinks, insufficient reserve, changed helper contents and incomplete preparation fail closed. **Do not delete an intent marker or retry formatting after a partial failure.** Inspect the specific owned file, loop device, mount and units first, then use a separately reviewed recovery action. Removing a PVC does not remove this Retain volume or its backing file.

At least **110 GiB** must remain free on the root filesystem for the separate PostgreSQL restore workflow. The fixed-size log image limits root consumption to 4 GiB plus its small filesystem bookkeeping; sparse portions may allocate later within that budget. The verified headroom accounts for them. This does not reserve space for unrelated applications; free-space checks and alerts must remain active. After activation, verify `node_filesystem_avail_bytes` exists for the exact mount and `node_filesystem_device_error` is zero. The low-capacity alert requires this metric; a missing metric is not evidence of free space. Monitoring alerts on low available capacity. The 4 GiB PV declaration describes capacity; the fixed-size loop filesystem supplies the actual hard bound.

## Existing owned directory permission maintenance

For an existing verified volume created with parent mode 0700, use the explicit `enable-metrics-traversal` action after reviewing and installing the exact new helper source. The normal Ansible preparation refuses to overwrite a different installed helper; replace it only through an independently checked source-hash comparison. Read both the parent and mounted filesystem root device/inode, the existing ownership record and the installed helper hash immediately before the maintenance command:

```sh
python3 /etc/infra-flux/logging-volume.py enable-metrics-traversal \
  --expected-cluster-uid "$CLUSTER_UID" \
  --expected-helper-sha256 "$REVIEWED_INSTALLED_SHA256" \
  --expected-root-device "$LOG_ROOT_DEVICE" \
  --expected-root-inode "$LOG_ROOT_INODE" \
  --expected-mount-device "$LOG_MOUNT_DEVICE" \
  --expected-mount-inode "$LOG_MOUNT_INODE"
```

This action validates the live cluster, machine/CA, image inode, mounted filesystem UUID, units and free-space reserve, then changes only those exact owned directories: parent 0700→0711, and mounted filesystem root 0755→0700 (mkfs initially uses 0755). The Loki data directory remains 10001:10001 mode 0700. It takes the preparation lock and accepts already-correct 0711/0700 modes without another change. It never formats, mounts, restarts or changes a service. A foreign owner, replaced directory, unexpected mode or mismatched helper hash fails closed. Verify node-exporter’s exact mount metrics after the change; do not infer success from the permission command alone.

## Retention and overload behavior

- Retention is **48 hours**, with 24-hour TSDB index periods, a 10-minute compactor interval and a 2-hour deletion delay. Retention is asynchronous; it is not a promise that data disappears at exactly 48 hours.
- Ingestion is capped at **20 KiB/s** (`0.01953125` MiB/s) for the single tenant, about **3.30 GiB / 3.54 decimal GB** over 48 hours before compression, with a 1 MiB burst. Each stream is limited to 8 KiB/s with a 256 KiB burst, larger than a collector’s 128 KiB batch. The 4 GiB volume also contains WAL, indexes, deletion state and working files. Compression often reduces chunk bytes, but WAL, indexes and delayed retention also consume space. Measure actual growth and headroom before widening these limits; raw 48-hour input is not a bound on total disk use. The filesystem hard cap remains the final limit.
- Maximum line length is 8 KiB, active streams 500, label names 8, and label values 256 bytes. Queries cover at most 48 hours, return at most 1000 entries and have bounded concurrency/timeouts. The log dashboard requests 200 lines.
- Full storage or exhausted ingestion/cardinality limits reject logs. Loki does not automatically evict files just because free space is low. Stop excess emitters or deliberately revise the storage/retention plan after diagnosis; do not delete arbitrary WAL or chunk files.
- Each Alloy has a 128 KiB batch, 5-second send timeout, three bounded retries and no client disk WAL. Its positions and temporary data use two 8 MiB memory volumes. RAM is capped at 192 MiB per node; it cannot accumulate an unbounded queue on a VPS disk. HTTP 429 is not retried.
- Home loss, exhausted limits, collector restarts and prolonged network outages can lose logs. `tail_from_end` and ephemeral positions intentionally avoid replaying all old host logs after startup. These are operational logs, not a lossless audit archive or a backup system.

Loki requests 100m CPU/512 MiB RAM, with limits of 2 CPU/2 GiB, on home only. Alloy requests 25m CPU/64 MiB RAM per node, with limits of 250m CPU/192 MiB. No persistent log storage is allocated on the VPS nodes. The 4 GiB Loki filesystem is disposable observability data and is not added to business-data backups.

## Collection and sensitive information

Alloy mounts only `/var/log/pods` read-only. It does not request Kubernetes API credentials, read Secrets, inspect environment variables, or collect the host journal. Namespace, Pod and container labels come from CRI paths; retained labels are only namespace, Pod, container, node and stream. Pod UIDs and file paths do not become Loki labels.

Test/audit/backup/restore namespaces and matching temporary Pod names are excluded; the logging namespace is also excluded to prevent feedback loops. Key-material lines are dropped, and common authorization, cookie, password/token, JWT, URL-credential and query-string patterns are redacted before transmission. This is **best-effort filtering**, not a guarantee that arbitrary application secrets are recognized. Applications must avoid printing credentials and personal payloads. Add a namespace or Pod exclusion before enabling collection of especially sensitive workloads.

Validate the release configurations with `alloy validate config.alloy` and `loki -config.file=loki.yaml -verify-config=true`, then verify private targets, rejected/dropped-log metrics and one deliberately harmless application log in Grafana after activation. A ready collector does not prove every application emits useful logs.

References: [Loki retention](https://grafana.com/docs/loki/latest/operations/storage/retention/), [Alloy file source](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.file/), [processing/redaction](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.process/), [write buffering and retries](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.write/), [Loki 3.7.8](https://github.com/grafana/loki/releases/tag/v3.7.8), [Alloy 1.20.1](https://github.com/grafana/alloy/releases/tag/v1.20.1).

The missing-source behavior is implemented in Kubernetes [local volume getGlobalLocalPath](https://github.com/kubernetes/kubernetes/blob/v1.36.5/pkg/volume/local/local.go), before Pod mount setup. Never manually create the underlying `data` directory while the filesystem is unmounted.
