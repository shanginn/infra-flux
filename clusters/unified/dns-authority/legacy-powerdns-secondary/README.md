# Optional PowerDNS secondaries

This component is inactive: no parent references it. It adds persistent BIND
secondary copies of these three zones from the existing Rubase PowerDNS writer:

- `xn--80aaa0aef8ckd2c.xn--p1ai`
- `xn--80agrjfkbaugg.xn--p1ai`
- `xn--90aoavb.xn--p1ai`

The generated replacement changes only `bind-authority-config/named.conf.zones`:
the original 22 declarations remain identical, followed by three secondary
declarations. Keep that prefix synchronized with the base; the render tests
reject drift. No writable primary, Git seed, workload, Service, storage or
readiness change is included. Each new copy is stored in its existing BIND
volume under a distinct `/var/lib/bind/pdns-*` file.

The additional egress policy permits only BIND Pods to reach
`${RUBASE_VPN_ADDRESS}/32` on UDP/TCP 5355. The owning Flux substitution source
must provide this single private IPv4 address. The existing transfer permission
for the original two secondary zones is retained. This policy does not create
a VPN grant or an upstream listener.

## Private transfer contract

The existing `dns-authority/bind-transfer-runtime` Secret must retain the
`named.conf.transfers` key and its current `legacy-bind` definition. Append a
separate TSIG key and a `legacy-powerdns` primaries list. The following is a
non-runnable shape; replace both private values outside Git:

```bind
key "legacy-powerdns-transfer" {
    algorithm hmac-sha256;
    secret "<private base64 key>";
};
primaries legacy-powerdns {
    <RUBASE_VPN_ADDRESS> port 5355 key "legacy-powerdns-transfer";
};
```

The address must match the egress substitution. The key name, algorithm and
material must match the key authorized for these exact zones on PowerDNS.
Preserve the existing Secret permissions and mount. Do not add the key or a
rendered Secret to this component. BIND supports per-primary transfer ports
and TSIG keys in its [primaries configuration](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-primaries).

## Activation and acceptance

1. Establish the separately reviewed private DNS-only 5355 bridge and reverse
   VPN permission for the two BIND hosts. Authorize signed transfers on the
   existing PowerDNS zones and prepare the private Secret. Keep application
   writers and the existing zone kind unchanged.
2. Validate the complete mounted configuration with `named-checkconf -z`
   using the deployed BIND image. Check the old `legacy-bind` contract as well
   as the new key/list. Reject missing substitutions or mismatched private
   addresses before publication.
3. Add `legacy-powerdns-secondary` to the dns-authority parent's
   `components` only after review. Both BIND Pods share this ConfigMap and
   Secret; their existing supervisor validates changes and reloads named.
   This is a shared reload, not a one-site-at-a-time rollout.
4. Check successful signed AXFR on both sites, then compare all three zones'
   complete served RRsets and serials with the live source. Bracket that
   comparison with source SOAs and repeat if a source serial changes. Check
   authoritative UDP/TCP answers, persistent files and transfer/expiry
   monitoring. Preserve acceptance of all original 22 zones and the apps zone.

The existing readiness probe deliberately still checks only the original 22
zones. Ready alone does not prove these new transfers succeeded. The current
public listeners forward to BIND, so the new zones become publicly answerable
through those listeners after transfer; this component does not change NS
delegations, old listeners, application API aliases or writers.

## Limits

This stages read replicas, not a database migration or a second writer.
PowerDNS NATIVE zones can serve AXFR but do not provide primary-mode NOTIFY;
BIND uses the existing ten-second refresh/retry bounds. That interval is a
polling setting, not a guaranteed delivery deadline: source serial changes,
network availability and transfer completion still matter.

The inventory is finite. New source zones need an explicit stanza and review.
Deleting a source zone does not immediately delete a transferred copy; synchronize
the inventory and remove the secondary declaration explicitly. During a source
outage, an already transferred copy can serve until its SOA expiry, rather than
indefinitely. API metadata, credentials and database contents are not replicated.
See the PowerDNS [operation modes](https://doc.powerdns.com/authoritative/modes-of-operation.html)
and [NATIVE zone transfer behavior](https://doc.powerdns.com/zonecontrol/1.6.4/user/editing.html#native-zones).

Run the local render checks with
`python3 clusters/unified/dns-authority/legacy-powerdns-secondary/test_component.py`
in an environment with PyYAML and kubectl. They render the actual base plus
component and check scope; they do not establish live transfer or parser acceptance.
