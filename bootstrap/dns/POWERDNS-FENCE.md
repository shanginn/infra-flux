# PowerDNS application write fence

`powerdns-fence.py` removes ordinary PowerDNS API write privileges while keeping
SQL reads and connections available. It does not stop DNS, change passwords,
restart Pods, terminate clients, disable accounts or automatically enable a
writer. Source and target are separate, explicitly identified operations.

This is an application permission boundary. A database owner or administrator
can restore privileges, and the source application role owns its old schema.
Keep initialization containers, schema bootstrap, manual grants and other
administrative changes stopped throughout cutover. An API process using ordinary
DML cannot bypass the revoked privileges; this is not a hostile-owner boundary.

Use an existing private administrative environment with Python 3.10+ and psycopg
3 (or psycopg2 for this fence alone). The connection rules, five-field database
identity and private-file rules are described in [snapshot instructions](POWERDNS-SNAPSHOT.md).
An explicit superuser connection to the identified primary is required. The
source role must be `powerdns`; the target role must be `powerdns_api`.

Before a write pause, finish and test final snapshot recovery, data import,
replica verification, old/new DNS read routing, writer alias switching and a
separate guarded writer-enable operation. Having this tool available does not
make that complete cutover ready. Reads can continue during a write pause; DNS
change requests can fail until the new writer is enabled.

## Inspect and pin the preimage

A private inspection plan contains `identity` and `writer_role`. Run `inspect`
with `--plan`, `--connection-file` and a new `--output` path. It checks the actual
primary, roles, relation owners, schema and effective table/column/sequence
privileges. Unexpected objects, memberships, defaults, prepared transactions,
custom functions/triggers/rules or another ordinary write path stop inspection.
Other login roles' membership chains are checked conservatively, including
NOINHERIT paths and reachable relation owners. It does not assume that a
NetworkPolicy or a closed new connection has stopped an existing SQL session.

The reviewed mutation plan contains:

- `format: 1`, `kind: powerdns-sql-dml-fence-plan`;
- a fresh canonical UUID in `operation_id`;
- the exact `identity`, `writer_role`, and `before_sha256`, computed from the
  canonical JSON inspection result, not the whitespace-formatted file.

Inputs, output, state and receipts belong outside Git. The state directory must
be owned mode `0700`. Use the same state directory for this database across
operations; the persistent journal is keyed by PostgreSQL system identifier,
database OID and database name, rather than operation UUID.

```sh
python3 bootstrap/dns/powerdns-fence.py inspect \
  --plan /private/path/inspect-plan.json \
  --connection-file /private/path/connection.json \
  --output /private/path/inspection.json

python3 bootstrap/dns/powerdns-fence.py fence-once \
  --plan /private/path/fence-plan.json \
  --connection-file /private/path/connection.json \
  --state-dir /private/path/fence-state \
  --output /private/path/fence-receipt.json
```

## Mutation and uncertain outcomes

The one-shot operation holds the same advisory lock as the importer and final
SQL-fenced snapshot. It acquires SHARE ROW EXCLUSIVE locks on all seven tables
with a two-second lock timeout, allowing ordinary reads while draining table
writes. It rechecks the pinned preimage, records durable intent, revokes table
DML and sequence USAGE/UPDATE, then verifies effective privileges before commit.
SELECT, CONNECT and sequence SELECT must remain effective. It verifies the
committed result again and writes a receipt valid for at most fifteen minutes.
Individual statements have a fifteen-second timeout and the CLI has a
180-second deadline. Lock contention fails rather than terminating another client.

A failure before acknowledged commit rolls back its transaction. A lost commit
reply is **unknown**, even if a later ROLLBACK succeeds. The durable intent remains;
no automatic grant, second dispatch, writer enable or receipt adoption occurs.
Inspect actual state through the original administration channel. Do not delete
the journal, invent a completed receipt or change operation ID to retry.

`verify` requires the original verified receipt via `--original-receipt`. It
checks that the exact fenced state still exists and emits a new time-bounded
receipt to a new output path; it does not change privileges. It cannot convert an
uncertain operation into a verified one. Keep the exact receipt embedded in the
final snapshot: renewing it afterward does not rewrite the snapshot's boundary.

Both source and target must remain fenced through final encrypted recovery,
import, six sequence writes/readback, replica comparison and DNS read convergence.
The [importer](POWERDNS-IMPORT.md) never enables writers. After a possible new
write, recovery must not blindly restore old writer privileges; a reverse data
migration needs its own reviewed boundary.

Offline tests: `python3 bootstrap/dns/test_powerdns_fence.py`. These test failure
handling and contracts; SQL permission and concurrent transaction behavior also
require an isolated PostgreSQL integration rehearsal before live use.
