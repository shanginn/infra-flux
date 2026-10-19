# Per-site public PowerDNS read routes

These components are inactive until explicitly added to the unified public DNS base. Keep the existing `public-dns-per-site` bootstrap component enabled. Prepare `../public-reader-egress` first: it only permits DNS to the private reader Pods and does not select a new route.

Each of `msk` and `fin` changes only that node's selected Corefile in the existing stable ConfigMap. The DaemonSet, Pods, other site file, shared fallback file, application publisher and BIND suffix list stay unchanged. Do not combine these components with the older `unified-public` shared-file component.

Activate one site at a time using an exact reviewed source revision. Pause every actual Flux claimant before publishing; use a UID/resource-version guarded update equal to the server dry run, then verify the mounted file, unchanged processes and publisher, real DNS responses and backend attribution. A successful ConfigMap update or CoreDNS reload metric alone does not prove that the new route loaded. Resume the exact owners only after the site passes, then independently read back convergence before advancing.

The default PowerDNS route requires the completed fenced import, fresh data and sequence parity, effective fences on both legacy databases, and private reader readiness. The original 22 BIND suffixes still use BIND; private health zones return REFUSED publicly. Keep the old aliases and writer configuration separate until their own guarded transition. An uncertain update is readback-only and must never be replayed under a new operation path.
