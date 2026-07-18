# Mail hub operations

## Client settings after cutover

| Purpose | Host | Port | Security | Authentication |
| --- | --- | ---: | --- | --- |
| IMAP | `mail.shanginn.io` | 993 | implicit TLS | full email address |
| SMTP submission | `mail.shanginn.io` | 587 | STARTTLS required | full email address |
| SMTP submission | `mail.shanginn.io` | 465 | implicit TLS | full email address |
| Account portal | `https://mail.shanginn.io` | 443 | TLS | mailbox credentials |
| Administration | `https://mail-admin.shanginn.io/admin` | 443 | TLS + allowlist | permanent admin password |

POP3 110/995 and plaintext IMAP 143 are not published.
After cutover OAuth/JMAP discovery is canonical on `mail.shanginn.io`.
The `/admin` path on that hostname and the `mail-admin.shanginn.io` entry point
both use the admin IP allowlist.

Administrative credentials and allowed source networks are SOPS-encrypted.
Recovery credentials must remain absent during normal operation.

## Add a domain

1. Copy `mail/domains/vibesites.ru.yaml` to
   `mail/domains/example.org.yaml`.
2. Declare at least one real mailbox and make `postmaster@example.org` and
   `abuse@example.org` either mailboxes, group addresses or aliases.
3. Generate a unique RSA-2048 DKIM key. Add its private PEM as
   `<domain>.pem` in the SOPS-encrypted `mail-dkim-keys` Secret; the reusable
   workload already mounts the whole keyring at `/run/dkim`. Publish only the
   derived public key.
4. Add each `credentialRef` as a key in the encrypted
   `mail-system-credentials` Secret.
5. Add the catalog filename to the generated list in
   `mail/kustomization.yaml`, render, and dry-run the Stalwart plan.
6. Prepare the authoritative MX, SPF, DKIM and DMARC records in the shared
   BIND zone and bump SOA. Keep MX held until the domain-specific gate passes.
7. Merge/push and confirm the reconciler Job completed.

Cross-domain delivery to one inbox is declared by putting an alias whose
`domain` is another catalog domain on the target account. Stalwart also treats
those aliases as allowed sender identities, so the From address aligns with
the corresponding domain's DKIM signature and DMARC policy.

Catch-all stays disabled unless `catchAll.enabled: true` and the target is an
already declared address.

## Rotate a mailbox password

Decrypt only to a protected temporary file, replace the referenced key, then
re-encrypt in place:

```sh
SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/keys.txt" \
  sops mail/secrets/system-credentials.enc.yaml
```

Commit only the encrypted file. The next reconcile replaces the Stalwart
credential. Keep the old secret only for an explicitly bounded overlap window.

Native Stalwart `AppPassword` values are server-generated and cannot be
supplied back through the v0.16 declarative schema. To avoid a hidden UI source
of truth, this deployment initially uses dedicated Git-managed service
accounts/credentials for applications. Do not create unmanaged app passwords
in the UI. Revisit this when Stalwart exposes an importable app-password
secret.

## Rotate DKIM

1. Generate a new encrypted private key and a new selector.
2. Add the new selector/key mount and a second DKIM declaration.
3. Publish its public TXT record and confirm it from both authoritative
   servers.
4. Reconcile, send a signed test and verify alignment.
5. Mark the old selector retiring; keep its TXT record for at least seven
   days.
6. Remove the old signer, then remove its public record in a later SOA bump.

Never reuse a DKIM key across domains.

## SOPS recovery

Flux receives the age private key only as `flux-system/sops-age`. The local
key is in `$HOME/.config/sops/age/keys.txt`; it must be escrowed in the owner's
password manager/off-site recovery material before the production cutover.
The private key must never enter Git.

To restore Flux trust to a cluster:

```sh
kubectl --context rubase -n flux-system create secret generic sops-age \
  --from-file=age.agekey="$HOME/.config/sops/age/keys.txt"
```

Use `--dry-run=client -o yaml | kubectl apply -f -` when the Secret already
exists. Repeat with the `contabo` context.

## Backup

Every day at 02:17 Asia/Yekaterinburg:

1. the catalog builds the list of opted-in real mailboxes;
2. official Vandelay v1.0.6 captures one convergent JMAP SQLite archive per
   account;
3. restic encrypts those archives before sending them to the dedicated
   `mail-hub` bucket on Contabo MinIO;
4. retention keeps 14 daily, 8 weekly and 12 monthly snapshots;
5. `restic check --read-data-subset=5%` and freshness metrics are recorded.

The S3 endpoint is TLS-only and serves a private bucket with a dedicated
non-admin credential. Backup traffic reaches Stalwart through an internal TLS
listener and does not traverse the public administrator Ingress.

Trigger and inspect:

```sh
kubectl --context rubase -n mail-system create job \
  --from=cronjob/mail-backup mail-backup-manual-YYYYMMDD
kubectl --context rubase -n mail-system logs -f job/mail-backup-manual-YYYYMMDD
```

Logs must show Vandelay completion, one restic snapshot, retention and a
successful repository check. They must not show passwords or message bodies.
The finished Job and its plaintext ephemeral Vandelay archives are
automatically removed after one hour; off-site restic snapshots remain
encrypted and follow the separate retention policy.

## Isolated restore rehearsal

Never restore into production first.

1. Create an isolated namespace or local container network with no public
   Service/MX.
2. Bootstrap an empty Stalwart with a temporary test domain/account.
3. Restore the chosen restic snapshot to an empty directory.
4. Run Vandelay export against the isolated target:

```sh
export VANDELAY_PASSWORD='<isolated-target-password>'
vandelay export \
  --url http://isolated-stalwart:8080 \
  --auth-basic isolated-admin \
  --account-name hello@vibesites.ru \
  /restore/account-hello-vibesites-ru.sqlite
```

5. Verify folder/message counts, attachments and a known test message; run a
   second export and confirm it is convergent.
6. Delete the isolated environment and record evidence in the private
   operational log, not in public Git.

Never use Vandelay `--prune` during a normal restore rehearsal.

## External validation gate

Run from a host that is not Rubase and is not on the admin allowlist:

```sh
dig +short mx1.shanginn.io A
dig +short -x 185.221.212.224
openssl s_client -connect mx1.shanginn.io:993 -servername mx1.shanginn.io
openssl s_client -starttls smtp -connect mx1.shanginn.io:25 -servername mx1.shanginn.io
```

Open-relay negative test:

```sh
swaks --server mx1.shanginn.io \
  --from external@example.net \
  --to unrelated@example.org \
  --quit-after RCPT
```

The unauthenticated foreign RCPT must be rejected. Also test an authenticated
submission, an inbound pilot address, SPF/DKIM/DMARC alignment, a Gmail/Yandex
delivery in both directions, queue drain and both authoritative BIND servers.
