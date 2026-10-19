# VPS kubelet memory reservation

`kubelet-memory-maintenance.yml` changes the existing MSK or FIN reservation
from 4Gi to 2Gi. CPU reservation stays at one core, eviction thresholds stay
unchanged, and HOME stays at 8Gi. This increases schedulable memory by 2Gi per
VPS; it does not free physical RAM or change Pod requests/limits.

Use one VPS per invocation, MSK first and FIN only after MSK is verified. Do not
replay `cluster.yml`: the original bootstrap fingerprint remains immutable.
The template default affects future bootstrap rendering, while this separate
maintenance updates only the memory scalar in the active kubelet config and
its already-referenced per-node kubeadm patch.

## Inspect and review

```sh
ansible-playbook -i /private/inventory.yml kubelet-memory-maintenance.yml \
  --limit msk -e kubelet_memory_action=inspect
```

Inspection is read-only. It requires the existing verified endpoint and serving
TLS maintenance records, root-owned config files, the actual init.yaml reference
to the kubeadm patch, an unused memory-maintenance record, the available shared
maintenance lock, and three healthy control planes/etcd members. It rejects
kubelet command-line overrides. Save the returned `review` object privately as
`kubelet_memory_review` in an extra-vars file and review its exact node UID,
machine/boot IDs, CA, config/patch/immutable-file hashes, effective configz and
allocatable values. Run from the reviewed helper revision. No packages are
installed; the existing Python YAML dependency is required.

The serving-TLS helper includes an exact descendant check for the completed
memory operation. Preserve that source update for future serving-certificate
renewals. Its original record and the kubeadm bootstrap record are not rewritten.

## Apply once and read back

```sh
ansible-playbook -i /private/inventory.yml kubelet-memory-maintenance.yml \
  --limit msk -e kubelet_memory_action=apply -e @/private/msk-memory-review.yml
ansible-playbook -i /private/inventory.yml kubelet-memory-maintenance.yml \
  --limit msk -e kubelet_memory_action=readback
```

Apply compares the whole reviewed preimage, takes the existing cluster CAS lock,
and saves root-only backups and a durable receipt under
`/etc/infra-flux/kubelet-memory-maintenance`. It preserves config permissions,
changes only `systemReserved.memory` in the two files and dispatches one kubelet
restart. It does not restart containerd or any Pod and does not edit static Pod
manifests, API endpoints, CPU/eviction settings, credentials or the bootstrap
fingerprint. The recovery check requires exact configz equality except 4Gi→2Gi,
exactly 2Gi more Node allocatable memory, a renewed same-UID lease, unchanged
running container IDs/PIDs, unchanged static manifests and healthy APIs/etcd.

Any existing record prevents another apply, including a completed record.
A partial write, timeout or lost restart acknowledgement remains unresolved;
readback never restarts, reapplies files, adopts an unknown outcome or releases
its retained lock. Preserve the receipt and backups for explicit recovery review.
Do not delete a record to retry. A normal successful operation releases its own
lock only after saving verified evidence. Proceed to FIN with its own fresh
inspection and review, then independently read it back.
