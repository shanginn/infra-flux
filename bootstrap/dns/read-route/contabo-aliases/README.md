# Retained Contabo DNS aliases

This inactive component changes only `powerdns-authoritative` and
`vibesites-powerdns`: select the existing DNS-only read forwarders and remove the
TCP 8081 API Service port. It preserves each Service's identity, ClusterIP, DNS
53 UDP/TCP and named DNS target ports. Both exact original selectors and port
lists are tested before applying the patch. No parent includes this component.

Activate through the existing Service owners only after both source databases
are fenced, their final snapshots are preserved and restored, all data differences
have an explicit disposition, and the imported database plus two replicas match.
The forwarders must already use the direct private reader route; routing them
back through these aliases would create a loop. Verify both aliases over UDP and
TCP and bracket the closed API-port test with successful DNS queries from the
same caller. Keep old resources and database fences in place.

The ordinary SQL application fence blocks DML and sequence writes, including
existing prepared sessions, while retaining SELECT for old DNS readers. It does
not close the PowerDNS process's listener, prevent a privileged administrator or
owner from changing DDL/grants, or fence unrelated roles. Removing the Service
port closes this API entry point; it is not a claim that every possible network
path to the old Pod is closed. Do not restore old writer grants after the new
writer starts accepting changes.
