# Declarative mail catalog

`mail/domains/*.yaml` is the source of truth for public mail domains,
mailboxes, aliases, groups, sender identities, quotas and lifecycle state.
Kustomize packages these files into `mail-domain-catalog`; the scheduled
reconciler validates them and emits an idempotent Stalwart `apply` plan.

The normal plan contains only `upsert` and singleton `update` operations. If
an object disappears from Git it is deliberately left in Stalwart and reported
as drift: omission never deletes a mailbox or mail.

Deletion is a separate two-phase break-glass procedure:

1. set `lifecycle.state: disabled` and reconcile;
2. wait at least seven days, set `disabledSince`, set
   `prune.approved: true` and a unique `prune.token`;
3. query and review the exact Domain id, render a scoped prune plan with
   `ALLOW_MAIL_DELETION=true`, `CONFIRM_PRUNE=<token>` and
   `PRUNE_DOMAIN_ID=<id>`, dry-run it, take/verify a final backup, then apply it
   manually with a break-glass administrator.

No scheduled workload has a Stalwart `*Destroy` permission.

Secrets referenced by `credentialRef` are keys in the SOPS-encrypted
`mail-system-credentials` Secret. DKIM keys and backup credentials are
separate encrypted Secrets. Never put personal data, message content or
plaintext credentials in this catalog.
