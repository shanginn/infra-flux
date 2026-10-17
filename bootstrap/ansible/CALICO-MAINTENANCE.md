# Calico API endpoint maintenance

Calico's host CNI plugin and token refresher use the node-local API proxy at
`https://api.unified.internal:7443`. The proxy reaches all control planes
without depending on the Kubernetes Service IP or kube-proxy rules. The API
certificate must include this DNS name, and each host and host-network Calico
Pod must resolve it to loopback through the host's static hosts mapping.

Flux owns `kube-system/kubernetes-services-endpoint`. Calico 3.33 already reads
this optional ConfigMap in `upgrade-ipam`, `install-cni` and `calico-node`.
Creating it changes no running environment and performs no rollout. A later
Pod/container startup can adopt it, including during a reboot; publish this
configuration outside an active fault test. Neither the immutable kubeadm
bootstrap fingerprint nor its templates are edited.

After the ConfigMap has reconciled and the cluster is healthy, inspect using
the pinned Ansible environment and the full existing inventory:

```sh
ansible-playbook -i inventory.yml calico-endpoint-maintenance.yml
```

Save each returned `review` object in a private file outside Git:

```yaml
calico_endpoint_apply: true
calico_endpoint_review:
  fin: <complete reviewed object>
  home: <complete reviewed object>
  msk: <complete reviewed object>
```

Run the same playbook with that private file, without limiting the inventory:

```sh
ansible-playbook -i inventory.yml calico-endpoint-maintenance.yml -e @/private/path/calico-review.yml
```

The helper verifies the owned bootstrap marker and unchanged bytes, cluster
CA, node UID/VPN identity, bootstrap field manager, exact DaemonSet UID/spec,
Calico version and per-node Pod UID. It shares the resourceVersion-protected
`infra-ha-test/active-fault` lock with the fault harness and etcd maintenance.
An active fault prevents Pod replacement. API readiness and all three etcd
members must be healthy, with all three Calico Pods Ready, before proceeding.
Only the reviewed Pod is deleted, using an API-enforced UID precondition;
there is no broad rollout, force deletion or DaemonSet template change.

Sensitive CNI/marker preimages and resumable state stay root-only under
`/etc/infra-flux/calico-endpoint-maintenance/`. The helper compares parsed
kubeconfigs: only the server setting and normal service-account token renewal
may differ. It waits for `calico-node`'s startup token refresher to write the
new endpoint and a new token, then performs an authenticated Calico API read
through that endpoint with CA verification. This exercises the real refresher
write path; it does not wait hours for a later scheduled renewal. The same
refresher implementation uses the retained environment for later writes.
Tokens and kubeconfig contents are never printed.

A restricted, digest-pinned Python Pod is then created on that node in the
owned test namespace. It obtains a normal CNI address, resolves the Kubernetes
service through cluster DNS, and completes a CA-verified TLS request to the
API ClusterIP. An HTTP authentication denial is acceptable for this tokenless
connectivity probe. It has a three-minute active deadline and small resource
limits. Cleanup checks its ownership and exact UID; a reused name cannot
delete another Pod. The helper requires cleanup and thirty seconds of stable
three-member/API/Calico health before releasing the lock and moving on.

A failed check stops the sequence and retains the lock. Inspect the private
record, preimage hashes, replacement Pod UID and disposable Pod before retrying
the same reviewed invocation. A crash after the intended deletion can resume
without deleting a second Calico Pod. Incomplete state or an unexpected new
Pod requires manual review; it is not silently adopted. If the disposable
probe failed and was cleaned up, preserve the record/evidence and investigate
before a separately reviewed retry. Never remove a lock solely because a
timeout expired. There is no automatic restoration of an old kubeconfig,
which would conflict with Calico's ongoing token updates.

This removes the CNI-to-Service-IP startup dependency. It does not guarantee
a fixed boot time or resolve unrelated etcd, API backoff, routing, DNS or
image-download failures. All-node outages and the local proxy's own recovery
remain separate concerns. Recheck the endpoint and maintained optional
ConfigMap support when upgrading Calico.

Sources: [Calico manifest](https://raw.githubusercontent.com/projectcalico/calico/v3.33.0/manifests/calico.yaml),
[installer](https://raw.githubusercontent.com/projectcalico/calico/v3.33.0/cni-plugin/pkg/install/install.go),
[token refresher](https://raw.githubusercontent.com/projectcalico/calico/v3.33.0/node/pkg/cni/token_watch.go),
[host-network hosts handling](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.5/pkg/kubelet/kubelet_pods.go).
