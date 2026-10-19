# DNS secondaries while the existing API remains active

These optional components prepare DNS readers in the unified cluster while the
existing PowerDNS API continues writing to its current database. They do not
move the database, switch application aliases or suspend writes. Nothing in
this directory is included by a live parent Kustomization.

The DNS-only source Service is in `rubase-private-dns`. The receiving component
is `clusters/unified/dns-authority/legacy-powerdns-secondary`. Both require the
same private `RUBASE_VPN_ADDRESS` substitution. Keep that inventory and transfer
credentials outside public Git.

`../legacy-axfr-policy.py` renders the narrowly additive Headscale policy. Its
JSON input contains the current `policy`, the two VPS `readers` and the legacy
`primary` overlay address. It preserves existing rules and adds only UDP/TCP
5355 from those readers to the source. Bind these addresses to the current
registered nodes before use; the renderer itself has no network access.
Check the proposed policy with the installed Headscale version and retain the
current file before publishing and reloading it. Read back both the file and
the running policy, then test allowed and denied connections. This renderer
does not apply anything and must not be used to rerun an earlier maintenance
operation whose outcome is unknown.

Before advertising the new readers:

1. Create the separate DNS-only Service under a scoped Flux owner and confirm
   its numeric EndpointSlice ports and unchanged source Pod identity.
2. Authorize a dedicated transfer-only TSIG key on the selected source zones.
   Preserve existing keys and metadata. PowerDNS 4.9 uses the zone API's
   `master_tsig_key_ids` field for `TSIG-ALLOW-AXFR`; generic metadata writes to
   that protected kind are rejected. Do not replace records or change zone type.
3. Securely extend the existing BIND transfer Secret, preserving its earlier
   primary definitions. Validate the exact pinned BIND image's configuration,
   then activate only the receiving component and verify completed transfers
   on both VPSs. The existing public DNS routing needs no change.
4. Compare actual authoritative data over UDP and TCP, observe later source
   serial changes reaching both secondaries, and verify unsigned transfers and
   updates remain refused. A successful transfer is not a database cutover.

NATIVE source zones can serve AXFR without being changed to PRIMARY. Polling
introduces a refresh delay, and copies expire according to the source SOA.
The optional component has a finite zone inventory: additions and deletions
need explicit reconciliation before this can replace every application DNS
path. Do not claim that AXFR automatically handles zone creation or deletion.
Retain old endpoints through their measured delegation and address cache
windows and retain the source database until its separate migration is complete.

References: [PowerDNS zone API](https://doc.powerdns.com/authoritative/http-api/zone.html),
[TSIG transfers](https://doc.powerdns.com/authoritative/tsig.html),
[NATIVE zones](https://doc.powerdns.com/zonecontrol/1.6.4/user/editing.html#native-zones).
