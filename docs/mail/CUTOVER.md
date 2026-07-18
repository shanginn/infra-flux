# Mail cutover gate

All boxes are required before adding
`../../../components/mail-server/cutover` to the Rubase overlay and
uncommenting a domain's MX records.

- [ ] `mx1.shanginn.io A` resolves correctly on both authoritative servers.
- [ ] provider PTR is exactly `mx1.shanginn.io`.
- [ ] forward-confirmed reverse DNS passes.
- [ ] the delivery IP is checked against major DNSBLs.
- [ ] outbound TCP/25 is reachable and a controlled delivery succeeds.
- [ ] `mail-hub-tls` is valid for `mx1`, `mail-admin`, and (at cutover) `mail`.
- [ ] encrypted admin allowlist is current; password login is tested.
- [ ] recovery env, recovery Secret and bootstrap Job are absent.
- [ ] scheduled reconciler succeeds twice and contains zero destroy operations.
- [ ] off-site backup succeeds and is younger than 36 hours.
- [ ] isolated restore evidence is stored outside public Git.
- [ ] local PVC and node storage have sufficient free capacity.
- [ ] control-plane and block-I/O health are stable under a full reconcile.
- [ ] SMTP, 465/587, IMAPS and HTTPS probes are green.
- [ ] alert rules are evaluated; a notification receiver is configured or an
      explicit temporary blackhole waiver is recorded.
- [ ] unauthenticated foreign RCPT/open-relay tests reject.
- [ ] authenticated submission accepts only declared sender identities.
- [ ] pilot SPF and DKIM records validate; DMARC starts at `p=none`.
- [ ] inbound/outbound tests with Gmail and Yandex pass and queue drains.
- [ ] the existing `shanginn.io` MX dependency on `mail.shanginn.io` has a
      reviewed migration plan before changing that A record.

Rollback before MX: remove/disable the `mail-server` Flux Kustomization; no
mail traffic depends on it.

Rollback after MX: restore the prior MX/A records with a higher SOA serial,
leave the old DKIM public key published, keep Stalwart/PVC intact, and do not
prune any account.
