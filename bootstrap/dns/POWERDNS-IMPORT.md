# Data-only PowerDNS import

`powerdns-import.py` imports one verified final snapshot into the already owned
target schema. It never creates schema or roles, changes grants, enables writers,
or writes to the source database. Use Python 3.10+ and psycopg 3 in an existing
administrative environment. SSH/container transport, encrypted snapshot recovery,
replica checks and traffic switching remain separate operations.

Prepare the source and target SQL DML fences with `powerdns-fence.py` first.
The final snapshot must embed the exact source fence receipt. The importer checks
both receipts and independently rechecks the target's actual effective privileges,
owners, ACLs and schema throughout the import. The shared session advisory lock
`infra-flux/powerdns-cutover` serializes cooperating fence/import operations.
Administrators and database owners can bypass this application fence; do not run
bootstrap, manual grants or another cutover concurrently.
Both fence attestations must have at least three minutes remaining when import
validation runs, covering the bounded importer deadline.

Keep every input and the persistent state directory outside Git. The state
directory must be owned mode `0700`; files must be owned regular mode `0600`.
Snapshot contents can include private DNSSEC and TSIG material. Connection files
follow `powerdns-snapshot.py` rules: one Unix socket or verified TLS endpoint,
credentials only inside private files. Never put credentials in arguments.

The private plan has exactly these keys:

| Field | Value |
|---|---|
| `format`, `kind` | `1`, `powerdns-data-import` |
| `operation_id` | Fresh canonical UUID |
| `source`, `target` | Verified five-field identities from `powerdns-snapshot.py` |
| `writer_role` | `powerdns_api` |
| `snapshot_sha256` | Final snapshot envelope's `sha256` |
| `source_fence_sha256`, `target_fence_sha256` | Canonical JSON digests of the exact SQL fence receipts |
| `target_schema_sha256` | Target fence receipt's `after.schema_sha256` |
| `target_seed_sha256` | Canonical digest of `powerdns-import.py`'s `health_seed()` |

All receipt and plan digests use `powerdns-snapshot.py`'s canonical JSON function,
not hashes of whitespace-formatted files. Validate without connecting:

```sh
python3 bootstrap/dns/powerdns-import.py plan-check \
  --plan /private/path/import-plan.json \
  --snapshot /private/path/final.json \
  --source-fence /private/path/source-fence.json \
  --target-fence /private/path/target-fence.json
```

For the reviewed import, use the same inputs with `import-once`, adding
`--connection-file /private/path/target-connection.json` and
`--state-dir /private/path/import-state`. Reuse that same state directory for the
target database across operations; a new operation UUID does not bypass its
existing receipt. Import requires an unused target: exactly the four seed rows
and all six sequences at `(1,false)`.

The row transaction locks the seven tables with a two-second lock timeout,
inserts explicit IDs and columns, and compares every row plus the exact seed
before commit. Source schema, owners, ACLs and roles are never restored into
production. The target's `health.test` domain ID `2000000000` and record IDs
`2000000000..2000000002` remain unchanged. The source's distinct legacy health
zone is retained along with all other source rows.

After row commit, the tool restores all six source `last_value`/`is_called` pairs
and verifies them individually and together. It never uses `MAX(id)` over the
reserved seed IDs. A durable intent precedes the row commit and every `setval`.
`setval` is not rolled back by transaction failure, so a partial result must be
inspected rather than replayed. See [PostgreSQL sequence semantics](https://www.postgresql.org/docs/18/functions-sequence.html).

The CLI has a 180-second deadline and 15-second statement limits. A failed or
interrupted operation retains its receipt and leaves the target API fenced.
Existing receipts prevent another `import-once`, including after success.
Use `readback` with the same inputs, connection and state directory, plus a new
`--output /private/path/readback.json`. Readback compares current rows and all
six sequences; it does not resume, repair, adopt success, change the original
receipt, or enable writers. Expired capture receipts may be inspected through
readback, but live target fencing is still mandatory.

Successful import means the primary matched the final snapshot and remained
fenced. Before separately enabling its writer, verify both asynchronous replicas,
all retained old/new DNS read paths and the API proxy. Never automatically
unfence the old database after the new writer may have accepted a mutation.

Offline tests: `python3 bootstrap/dns/test_powerdns_import.py`.
