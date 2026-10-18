# Optional per-site public DNS configuration

This inactive component prepares the existing public DNS DaemonSet for separately
reviewed changes on each VPS. Add it only through its existing Flux owner after
reviewing the rendered change. No parent currently references it.

The first render adds `msk.Corefile` and `fin.Corefile`, both byte-identical to the
current shared Corefile. CoreDNS receives its node name through the downward API
and Kubernetes expands `$(NODE_NAME)` in its argument; a shell is not required.
Node names must match those keys. The original Corefile and all publisher files
remain present for existing processes during preparation.

`OnDelete` prevents a template update from automatically replacing both listeners.
After source publication and the exact server dry run, replace one **UID-pinned**
Pod at a time. Before replacing the first, verify both existing processes, mounted
configuration, publisher state, all authoritative zones and other externally
reachable nameservers. Preserve the serving Pod at the other site. Measure the
selected hostPort endpoint's gap, wait for its exact new process and DNS parity,
and only then replace the second. If a dispatch outcome is uncertain, read back
that Pod UID and the controller state; never repeat a deletion by name.

A replacement temporarily interrupts that individual hostPort endpoint. This
component does not claim an uninterrupted response from that address. Keep the
legacy authorities available throughout this bootstrap. It changes no DNS route,
Service selector, database or application writer.

After both Pods use their own file, change only one site's Corefile per reviewed
source revision. Verify the other site's file, imported dependencies, process and
publisher state stayed unchanged. The reload plugin observes the selected file;
check the actual reload result and DNS answers before changing the other site.
A later template/image update also requires explicit, sequential Pod replacement
while this DaemonSet remains `OnDelete`.

Do not combine this component with the old `read-route/unified-public` component:
that component changes only the original shared Corefile, which the new processes
no longer use. Introduce the reviewed reader egress policy separately, then copy
that reviewed routing configuration to exactly one site file at a time. Preserve
both local application DNS publishing and all BIND suffixes. No such route change
is included here.

Run `python3 bootstrap/dns/public-dns-per-site/test_component.py` with PyYAML and
kubectl installed. These checks compare a real render against the existing base;
they do not replace exact-image and deployed DNS acceptance.

References: [argument environment expansion](https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/),
[DaemonSet update strategies](https://kubernetes.io/docs/tasks/manage-daemon/update-daemon-set/).
