# Shared Rubase mail hub

## Scope

This is one multi-domain mail hub for all services hosted by the owner. It is
not a Vibesites-specific installation. `vibesites.ru` is only the first catalog
entry.

The active pre-cutover topology is:

```text
Git/Flux
  ├─ components/mail-server/base
  ├─ mail/domains/*.yaml
  └─ SOPS-age Secrets
           │
           ▼
Primary Kubernetes
  ├─ Traefik 80/443 (existing sites stay unchanged)
  ├─ Stalwart CE 0.16.13, one StatefulSet, RocksDB PVC
  ├─ GitOps reconciler using official stalwart-cli apply
  ├─ VictoriaMetrics probes/rules
  └─ Vandelay snapshots → encrypted restic repository
                                  │ HTTPS, bucket-scoped credentials
                                  ▼
                         Off-site S3 storage
```

Contabo is not a secondary mail store and not active-active. A secondary MX
spool-and-forward is explicitly outside this phase.

## Names and endpoints

- SMTP identity, PTR and EHLO: `mx1.shanginn.io`
- user portal and client discovery after cutover: `mail.shanginn.io`
- restricted administration: `mail-admin.shanginn.io`

`mail.shanginn.io` is not moved during the pre-cutover phase because
`shanginn.io` currently has an existing MX that resolves this name through the
Contabo wildcard. Moving it without a mail migration would be destructive.
During this phase Stalwart publishes `mail-admin.shanginn.io` as its canonical
HTTPS URL. The gated cutover component switches the canonical URL to
`mail.shanginn.io`; the more-specific `/admin` Traefik route remains protected
by the same allowlist, while `mail-admin.shanginn.io` stays as the restricted
administrative entry point.

## Source of truth

- reusable workload: `components/mail-server/base/`
- gated public ports/user endpoint: `components/mail-server/cutover/`
- temporary recovery bootstrap: `components/mail-server/bootstrap/`
- Rubase overlay: `clusters/rubase/mail-server/`
- Flux entry: `clusters/rubase/mail-server.yaml`
- logical domains/accounts/aliases/groups/quotas/policies:
  `mail/domains/*.yaml`
- encrypted credentials and DKIM keys: `mail/secrets/*.enc.yaml`
- authoritative DNS zones: `components/bind9/base/configs/zones/`
- Contabo MinIO endpoint/user/bucket:
  `clusters/contabo/minio/mail-backup-*.yaml`
- public runbooks: `docs/mail/`

Stalwart is configured with the official schema-driven CLI. The renderer emits
NDJSON containing only `upsert` and singleton `update` operations during normal
reconciliation. DNS management is always `Manual`, so Stalwart cannot change a
zone outside Git.

## Lifecycle and drift

Removing a YAML entry never removes the live object. The reconciler has no
`*Destroy` permissions, and its generated plan contains no destroy operation.
An omitted object remains live and is treated as drift until an operator either
restores it to Git or follows the two-phase prune procedure in
`mail/README.md`.

UI edits to Git-managed objects are temporary drift. The next ten-minute
reconcile overwrites mutable managed fields. The UI is for inspection,
diagnostics and explicitly documented emergency actions, not a second source
of truth.

## Security boundary

- anonymous relay is denied; relaying requires an authenticated session;
- domain `allowRelaying` and catch-all are false unless explicitly declared;
- plaintext IMAP/POP3 listeners are absent;
- the public component contains only 25, 465, 587 and 993;
- admin ingress and the permanent admin credential are IP-restricted;
- recovery credentials exist only during bootstrap and are removed afterward;
- GitOps credentials are limited to get/create/update/query and explicitly
  lack destroy permissions;
- passwords and DKIM/private backup material are SOPS-encrypted;
- the off-site S3 endpoint is TLS-only and rate-limited; its private
  versioned bucket has a dedicated non-admin policy and no anonymous access;
- Stalwart runs as UID/GID 2000, with a read-only root filesystem, seccomp and
  only `NET_BIND_SERVICE`;
- logs stay at `info`; raw SMTP/body events exist only at `trace` and are not
  enabled.

The local PVC is monitored but is not a DR copy. Encrypted off-site restic
snapshots provide disaster recovery.

## Staged rollout

1. Apply SOPS trust, the internal mail workload and off-site backup.
2. Verify the permanent admin, no-destroy reconciler, TLS, backup and restore.
3. Ensure all temporary recovery resources are absent.
4. Obtain provider PTR and verify FCrDNS, DNSBL and outbound TCP/25.
5. Move `mail.shanginn.io`, add it to the certificate, switch the canonical
   public URL, enable the gated
   cutover component, perform external TLS/open-relay/delivery tests.
6. Only then uncomment the reviewed pilot MX/SPF/DKIM/DMARC block.

MTA-STS and TLS-RPT are deliberately absent until the HTTPS policy endpoint and
report handling have been implemented and tested end-to-end.
