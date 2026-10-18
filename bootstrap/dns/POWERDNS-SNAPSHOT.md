# PowerDNS snapshots before writer migration

`powerdns-snapshot.py` exports a PostgreSQL-backed PowerDNS authority without
changing its data, stopping applications, fencing the API, or importing anything.
A normal export is an **observation**, even if its sequence counters stay still.
The command prints only counts, a digest and capture status.

The snapshot contains every column of the seven official tables: `domains`,
`records`, `supermasters`, `comments`, `domainmetadata`, `cryptokeys`, `tsigkeys`.
It preserves IDs, `NULL` versus empty strings, disabled/auth flags, order names,
comments, metadata and key material. Treat the whole file as a secret: it can
contain private DNSSEC keys and TSIG credentials. Keep connection files,
identities, fence evidence and snapshots outside Git, in an owned mode `0700`
directory; inputs and output must be private regular files. Output uses mode
`0600`, refuses an existing path and refuses any Git worktree. Hashes detect
integrity changes; they are not signatures or a substitute for private storage.

## Preconditions and identity

Use an existing administrative environment with Python 3.10+ and psycopg 3.
Do not expose PostgreSQL to obtain a snapshot. A Unix socket is supported;
TCP requires `sslmode=verify-full` and the appropriate CA. The export account
needs read access to all seven tables, the six sequences, system catalogs and
`pg_control_system()`. The tool does not create roles or grants. Its connection
starts with `default_transaction_read_only=on` and every export explicitly uses
`REPEATABLE READ READ ONLY`, then rolls back. It refuses a reused connection
that already has a transaction.

Prepare a private connection JSON using libpq fields, for example a connection
from an already authorized PostgreSQL container:

```json
{"host":"/run/postgresql","dbname":"powerdns","user":"postgres"}
```

For TCP, use a verified DNS hostname, `sslmode`, `sslrootcert`, and a private
`passfile` or a password inside this private JSON. Passwords never belong in
command arguments, shell history, configuration in this repository, or tool
output. SSH transport and running inside a container are separate operational
steps; the exporter does not open tunnels or copy files between machines.

Independently verify the intended PostgreSQL primary and obtain its system
identifier, database OID and login role through the existing administration path:

```sql
SELECT c.system_identifier::text, d.oid::bigint, current_database(), current_user,
       pg_is_in_recovery()
FROM pg_control_system() c
JOIN pg_database d ON d.datname = current_database();
```

The expected identity file has exactly these fields. Replace the placeholders
with verified values; `database_oid` must be an integer:

```json
{
  "label": "source-authority",
  "system_identifier": "<verified PostgreSQL system identifier>",
  "database_oid": 0,
  "database": "powerdns",
  "user": "postgres"
}
```

The label is an operator identifier; the system identifier and database OID bind
the capture to the actual database. The exporter checks them before reading data,
requires a primary, and records the server version and MVCC snapshot identity.
It rejects additional/missing tables, unknown column layouts, row security,
nonstandard ID sequences, non-NATIVE zones and data incompatible with the new
schema. PostgreSQL 15 or newer is required.

## Observation export and local validation

Run from the repository on a host that can already reach the selected database;
choose a new output filename for every capture:

```sh
python3 bootstrap/dns/powerdns-snapshot.py export \
  --connection-file /private/path/powerdns/connection.json \
  --identity-file /private/path/powerdns/source-identity.json \
  --output /private/path/powerdns/observation-001.json

python3 bootstrap/dns/powerdns-snapshot.py validate \
  --snapshot /private/path/powerdns/observation-001.json \
  --identity-file /private/path/powerdns/source-identity.json
```

The hard limits are 10,000 total rows and 1 MiB of canonical table data. Smaller
limits can be selected with `--max-rows` and `--max-bytes`; larger limits are
rejected. Counts and serialized size are checked before fetching table contents.
Exceeding either limit fails the capture; no records are truncated. Each statement
has a 15-second timeout, lock acquisition has a 2-second timeout, and idle
transactions expire after 60 seconds. The seven tables receive ordinary
AccessShare locks while read, so a concurrent schema change may wait until the
capture ends. Application row updates remain possible.

Table data is consistent within the transaction. PostgreSQL sequences are not
MVCC snapshots: their changes are immediately visible and are not rolled back.
The exporter therefore reads each sequence's `last_value` and `is_called` before
and after the table reads. It never calls `nextval` or `setval`. An observation
can report sequence movement and must not become a cutover snapshot merely
because a later pair of readings matches. Updates and deletes can leave counters
unchanged. See [PostgreSQL isolation](https://www.postgresql.org/docs/current/transaction-iso.html)
and [sequence semantics](https://www.postgresql.org/docs/current/functions-sequence.html).

## Final capture requires independently verified fencing

`--final` is reserved for a separately performed and reviewed writer cutover.
The exporter supports two distinct evidence formats. With a
`powerdns-sql-dml-fence` receipt from [powerdns-fence.py](powerdns-fence.py), it
checks actual effective privileges, identity, schema and ACLs before and after
capture, while holding the shared cutover advisory lock. It records
`fence_verification: sql-effective-privileges`. Ordinary application writes must
be denied while reads remain available; TCP 8081 need not be closed. See the
[SQL fence operating instructions](POWERDNS-FENCE.md) for its owner/admin limits.

The older `powerdns-writer-fence` format below remains an **external attestation**.
The exporter cannot independently verify that network fence and records
`fence_verification: external-attestation`. Do not use its blocked-port assertion
to describe a SQL privilege fence. The data-only importer accepts SQL receipts.

Before making that attestation, verify that the old API on TCP 8081 is unreachable
from its actual writer workloads, public TCP/UDP 53 still answers, all in-flight
database writers have drained, and other write paths are disabled. Account for
existing connections, additive network policies, direct SQL, RFC2136, jobs and
initialization containers. The old PowerDNS initializer must not restart while
capturing: its health-zone initialization can write independently of API access.
Keep the fence in force through verification and activation of the new writer.

The private fence JSON must contain exactly:

- `format: 1`, `kind: "powerdns-writer-fence"`, and `source` identical to the
  expected identity file.
- `fence_id`: a fresh canonical UUID; `checked_at` and `valid_until`: UTC timestamps
  spanning the whole capture, with no more than fifteen minutes between them.
- `checks`: exactly `old_api_8081_blocked`, `old_dns_udp53_available`,
  `old_dns_tcp53_available`, `old_db_writers_drained`,
  `other_write_paths_disabled`, `no_legacy_pod_restart`, all boolean `true` only
  after those checks actually succeed.
- `evidence_sha256`: exactly `api_probe`, `dns_probe`, `db_sessions`,
  `other_writers`, `workload_identity`, each the lowercase SHA256 of the privately
  retained corresponding evidence. Bind workload identity evidence to the actual
  Pod UID and relevant fencing configuration, so a restart cannot go unnoticed.

A JSON assertion is not a check. Keep its referenced evidence private and review
it separately. The exporter validates the document's structure, source, interval
and digests; it does not read the external evidence or validate its conclusions.

```sh
python3 bootstrap/dns/powerdns-snapshot.py export \
  --connection-file /private/path/powerdns/connection.json \
  --identity-file /private/path/powerdns/source-identity.json \
  --final --fence-evidence /private/path/powerdns/verified-fence.json \
  --output /private/path/powerdns/final-001.json

python3 bootstrap/dns/powerdns-snapshot.py validate \
  --snapshot /private/path/powerdns/final-001.json \
  --identity-file /private/path/powerdns/source-identity.json \
  --require-final
```

Local validation verifies capture-time evidence. It does not renew an expired
fence or prove that writers remain stopped when the snapshot is later imported.
The importer must recheck the active fence and destination identity.

## Importer contract

Use `validate_snapshot(snapshot, expected_source, require_final=True)` from this
module before accepting input. SHA256 covers the complete payload. Separate
per-table hashes cover every column; per-zone hashes cover the domain row and
its records, comments, metadata and DNSSEC keys. Global TSIG keys and supermaster
entries remain covered by their table hashes. Canonical JSON uses sorted keys,
UTF-8 without ASCII escaping, compact separators, and rows sorted by ID or the
supermaster composite key. No DNS content is normalized or discarded.

All imported IDs must be positive and fit the official destination types.
Foreign keys must resolve. Every sequence must be at or beyond its source IDs;
when `is_called=false`, its next value must be strictly above existing IDs. All
six positions and their `is_called` flags must be preserved. Never derive new
positions with `MAX` across the destination: its dedicated health zone reserves
`domains.id=2000000000` and `records.id=2000000000..2000000002` without advancing
sequences. The exporter always rejects those row IDs or domain/record sequence next values
that reach that reserved range. An observation preserves a source `health.test`
zone and its records unchanged and records any conflicting probe names in
`destination_collisions`. Such a snapshot cannot receive final status. Resolve
the probe-name conflict in a separate reviewed change before final capture:
either move the destination probe to a unique name and update its seed/readiness
checks, or define an exact verified merge. No automatic omission, renaming or
merging of source rows is allowed.

A destination comparison must match **all source rows plus exactly the verified
owned health seed**. It must not exclude all `.test` zones or legacy health rows.
The [data-only importer](POWERDNS-IMPORT.md) implements row and sequence import
with independent destination checks. Fencing and writer activation are separate
operations; this snapshot module performs none of them.
In particular, `setval` changes are not rolled back after an import error, so a
retry must never blindly rewind a sequence after any new writer has been enabled.

Offline tests:

```sh
python3 bootstrap/dns/test_powerdns_snapshot.py
```
