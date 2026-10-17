# etcd startup-probe maintenance

This procedure changes only `failureThreshold`, `periodSeconds` and
`timeoutSeconds` in the existing etcd static Pod's `startupProbe`. Defaults are
30, 10 and 5: approximately five minutes before a continuously failing startup
check requests a restart, plus initial delay, termination grace and restart
backoff. API startup/backoff and node readiness can add further delay. This is
not a five-minute availability guarantee.

The endpoint remains the loopback `/readyz`; readiness and `/livez` liveness
are unchanged. A startup probe stops after its first success, so this change
does not detect a later stalled Raft stream in an already started process.
Do not substitute readiness for liveness: loss of quorum is not proof that
restarting every process will help.

Use the pinned local Ansible environment and the existing SSH aliases. First
run the default read-only inspection against the full three-node inventory:

```sh
ansible-playbook -i inventory.yml etcd-probe-maintenance.yml
```

The owned HA-test namespace/fault lock must already exist from the controlled
HA-test setup. An active fault or another maintenance operation blocks the
change. Inspection checks the shared CA, node identities, all three Ready
nodes, direct APIs and etcd members, and prints the before/candidate SHA256 and
exact three-field change. A previously unmodified manifest must have the
reviewed kubeadm probe values 60/10/15 and etcd image 3.6.8. Unexpected content
or an unowned existing maintenance directory is rejected.

After reviewing that result, create a private variables file outside Git:

```yaml
etcd_probe_apply: true
etcd_probe_expected_manifest_sha256:
  home: <reviewed home manifest SHA256>
  msk: <reviewed Moscow manifest SHA256>
  fin: <reviewed Finland manifest SHA256>
```

Apply that exact reviewed change without limiting the inventory:

```sh
ansible-playbook -i inventory.yml etcd-probe-maintenance.yml -e @/private/path/probe-review.yml
```

The playbook runs one node at a time. The helper takes the same cluster-wide
resourceVersion-protected lock as the fault harness, preserves the original
manifest and bootstrap-marker bytes under the private root-owned
`/etc/infra-flux/etcd-probe-maintenance/`, and replaces the manifest atomically.
It decodes both manifests using `kubectl create --dry-run=client`, verifies that
only the three allowed values differ, and checks the exact preimage again
immediately before writing. Backups are outside kubelet's watched directory.
The immutable bootstrap fingerprint, certificates, data directory, membership
and other component manifests are not changed.

Before releasing the lock or advancing to the next node, all three etcd
members and APIs must recover, membership IDs must match, and kubelet's mirror
Pod must show the new settings with a successfully started container. These
checks must remain successful for at least 30 seconds. Failure stops the
playbook and retains the lock; it does not automatically restore an older
manifest or release another operation's lock.

For interruption recovery, inspect the private `record.json` and saved
`manifest.before.yaml`/`bootstrap.before.json` against their recorded hashes.
The same guarded helper can resume when the manifest matches either its saved
preimage or exact candidate and all three members are healthy. The full
playbook deliberately refuses inspection on other nodes while one node holds
the lock; `--limit` is also rejected. Resume only the recorded node with the
same reviewed helper revision and approved SSH transport. Stream
`files/etcd-probe-maintenance.py` to `/usr/bin/python3 -` on that node with the
original reviewed arguments:

```text
apply --node <recorded-node> --ca-sha256 <original-reviewed-CA-SHA256> --expected-sha256 <original-reviewed-manifest-SHA256> --threshold 30 --period 10 --timeout 5
```

Use the originally reviewed threshold/period/timeout if they differ from these
defaults. This preserves all CA, preimage, token/UID, membership and health
checks; it is not an unlock or force-recovery mode. After successful completion
releases this operation's lock, rerun the full playbook with the original
private variables to continue the sequence.

A partial initial backup directory without a complete record requires manual
inspection; preserve the directory and inspect its ownership, saved files and
cluster lock before a separately reviewed recovery. It is never silently
adopted. Do not remove a lock merely because a timeout expired. If a rollback
is needed, review and restore the exact saved manifest atomically, then verify
all three members before releasing only this recorded maintenance token. Keep
the preimage and recovery material private.

The immutable bootstrap playbook is not rerun or bypassed. A later kubeadm
upgrade may regenerate the native probes: include this maintenance policy in
that upgrade review and inspect the resulting manifest. This version refuses
an unexpected image, probe, bootstrap fingerprint or changed existing policy;
those require a separately reviewed maintenance revision.

A lower threshold can repeatedly interrupt legitimate recovery after a long
absence, especially when a larger database needs a full snapshot across a slow
WAN. Keep a margin above measured cold replay/snapshot recovery time and revisit
the policy as the backend grows. `EtcdRepeatedRestarts` reports at least two
etcd container restarts in 20 minutes, sustained for one minute. It covers slow
startup loops that the broader `PodCrashLooping` threshold might miss, without
asserting that startup was the cause. Verify that the monitoring revision has
reconciled before applying this procedure. Notification delivery still depends
on the configured monitoring channel and its availability.

References: [Kubernetes probe guidance](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/),
[etcd snapshot catch-up](https://etcd.io/docs/v3.6/op-guide/maintenance/).
