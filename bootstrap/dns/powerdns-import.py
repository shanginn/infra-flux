#!/usr/bin/env python3
"""One-shot data-only import into an already fenced, owned PowerDNS database.

No DDL, grants, writer activation, automatic resume, or source database writes.
All inputs and receipts are private; stdout never contains DNS records or keys.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import timedelta
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import sys
import uuid


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


snapshot_lib = module('powerdns-snapshot')
require = snapshot_lib.require
digest = snapshot_lib.sha256
LOCK_NAME = 'infra-flux/powerdns-cutover'
PLAN_KEYS = {'format', 'kind', 'operation_id', 'source', 'target', 'writer_role',
             'snapshot_sha256', 'source_fence_sha256', 'target_fence_sha256',
             'target_schema_sha256', 'target_seed_sha256'}


def health_seed():
    tables = {table: [] for table in snapshot_lib.TABLES}
    domain = dict.fromkeys(snapshot_lib.COLUMNS['domains'])
    domain.update(id=snapshot_lib.RESERVED_DOMAIN, name='health.test', type='NATIVE')
    tables['domains'] = [domain]
    for ident, name, kind, content in (
        (2_000_000_000, 'health.test', 'SOA', 'ns.health.test hostmaster.health.test 1 300 60 86400 60'),
        (2_000_000_001, 'health.test', 'NS', 'ns.health.test'),
        (2_000_000_002, 'ns.health.test', 'A', '127.0.0.1'),
    ):
        row = dict.fromkeys(snapshot_lib.COLUMNS['records'])
        row.update(id=ident, domain_id=domain['id'], name=name, type=kind, content=content,
                   ttl=60, disabled=False, auth=True)
        tables['records'].append(row)
    return tables


def validate_inputs(plan, snapshot, source_fence, target_fence, fence_lib, *, current=True):
    require(isinstance(plan, dict) and set(plan) == PLAN_KEYS, 'Import plan fields differ')
    require(plan['format'] == 1 and plan['kind'] == 'powerdns-data-import', 'Import plan kind differs')
    require(str(uuid.UUID(plan['operation_id'])) == plan['operation_id'], 'Canonical operation UUID required')
    for key in ('source', 'target'):
        snapshot_lib.validate_identity(plan[key])
    require((plan['source']['system_identifier'], plan['source']['database_oid']) !=
            (plan['target']['system_identifier'], plan['target']['database_oid']), 'Source and target are identical')
    require(plan['writer_role'] == 'powerdns_api', 'Only the dedicated target API role is supported')
    for key in PLAN_KEYS:
        if key.endswith('_sha256'):
            require(isinstance(plan[key], str) and len(plan[key]) == 64 and
                    all(c in '0123456789abcdef' for c in plan[key]), 'Invalid plan digest')
    payload = snapshot_lib.validate_snapshot(snapshot, plan['source'], require_final=True)
    require(snapshot['sha256'] == plan['snapshot_sha256'], 'Final snapshot differs from plan')
    require(digest(source_fence) == plan['source_fence_sha256'] and
            digest(target_fence) == plan['target_fence_sha256'], 'Fence receipts differ from plan')
    for receipt, identity in ((source_fence, plan['source']), (target_fence, plan['target'])):
        fence_lib.validate_receipt(receipt, identity, require_phase='verified-fenced')
        if current:
            now = snapshot_lib.timestamp(snapshot_lib.utc_now())
            require(snapshot_lib.timestamp(receipt['checked_at']) <= now and
                    now + timedelta(seconds=180) <= snapshot_lib.timestamp(receipt['valid_until']),
                    'Fence attestation must cover the complete importer deadline')
    require(source_fence['writer_role'] == 'powerdns' and target_fence['writer_role'] == plan['writer_role'],
            'Fence writer role differs')
    require(payload['capture']['fence'] == source_fence, 'Snapshot is not bound to this source fence')
    require(target_fence['after']['schema_sha256'] == plan['target_schema_sha256'], 'Target schema preimage differs')
    require(plan['target_seed_sha256'] == digest(health_seed()), 'Exact owned health seed required')
    return payload


def expected_tables(payload):
    seed = health_seed()
    return {t: sorted(payload['tables'][t] + seed[t], key=lambda row: snapshot_lib.rows_key(t, row))
            for t in snapshot_lib.TABLES}


@contextmanager
def database_lock(connection):
    require(connection.autocommit and connection.info.transaction_status == 0, 'Fresh idle autocommit connection required')
    with connection.cursor() as cursor:
        cursor.execute('SELECT pg_try_advisory_lock(hashtextextended(%s,0))', (LOCK_NAME,))
        require(cursor.fetchone()[0] is True, 'Another cutover operation holds the database lock')
    try:
        yield
    finally:
        # Closing the connection also releases this session lock after an error.
        with connection.cursor() as cursor:
            cursor.execute('SELECT pg_advisory_unlock(hashtextextended(%s,0))', (LOCK_NAME,))


def guard(connection, plan, target_fence, fence_lib):
    actual = fence_lib.assert_fenced(connection, plan['target'], plan['writer_role'])
    require(digest(actual) == target_fence['after_sha256'], 'Target fence or catalog changed')
    require(actual['schema_sha256'] == plan['target_schema_sha256'], 'Target schema changed')
    with connection.cursor() as cursor:
        cursor.execute("SELECT c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,pg_get_userbyid(c.relowner) "
                       "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                       "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f') ORDER BY 1")
        relations = cursor.fetchall()
        require({r[0] for r in relations} == set(snapshot_lib.TABLES) and
                all(r[1:] == ('r', False, False, 'powerdns_owner') for r in relations), 'Target relations or ownership differ')
        cursor.execute("SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid "
                       "WHERE c.relnamespace='public'::regnamespace AND NOT t.tgisinternal")
        require(cursor.fetchone()[0] == 0, 'Custom target triggers are unsupported')
        cursor.execute("SELECT count(*) FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class "
                       "WHERE c.relnamespace='public'::regnamespace")
        require(cursor.fetchone()[0] == 0, 'Target rewrite rules are unsupported')
        for table, names in snapshot_lib.COLUMNS.items():
            cursor.execute('SELECT attname FROM pg_attribute WHERE attrelid=%s::regclass '
                           'AND attnum>0 AND NOT attisdropped ORDER BY attnum', ('public.' + table,))
            require(tuple(r[0] for r in cursor.fetchall()) == names, 'Target columns differ')
    return actual


def read_tables(connection):
    result = {}
    total_rows = total_bytes = 0
    with connection.cursor() as cursor:
        for table in snapshot_lib.TABLES:
            cursor.execute('SELECT count(*),coalesce(sum(octet_length(to_jsonb(t)::text)),0) FROM public.' + table + ' t')
            count, size = cursor.fetchone()
            total_rows += count
            total_bytes += int(size)
            require(total_rows <= snapshot_lib.MAX_ROWS + 4 and total_bytes <= snapshot_lib.MAX_BYTES + 4096,
                    'Target data exceeds comparison bounds')
            cursor.execute('SELECT to_jsonb(t)::text FROM public.' + table + ' t ORDER BY ' +
                           ('ip,nameserver' if table == 'supermasters' else 'id') + ' LIMIT %s',
                           (snapshot_lib.MAX_ROWS + 5,))
            rows = [json.loads(row[0]) for row in cursor.fetchall()]
            require(len(rows) == count, 'Target row count changed')
            result[table] = sorted(rows, key=lambda row: snapshot_lib.rows_key(table, row))
    return result


def read_sequences(connection):
    result = {}
    with connection.cursor() as cursor:
        for name in snapshot_lib.SEQUENCES:
            cursor.execute('SELECT last_value,is_called FROM public.' + name)
            last, called = cursor.fetchone()
            result[name] = {'last_value': last, 'is_called': called}
    return result


def insert_rows(connection, tables):
    with connection.cursor() as cursor:
        for table, columns in snapshot_lib.COLUMNS.items():
            if tables[table]:
                # Identifiers are exclusively constants from the reviewed schema.
                sql = 'INSERT INTO public.' + table + ' (' + ','.join(columns) + ') VALUES (' + ','.join(['%s'] * len(columns)) + ')'
                cursor.executemany(sql, [tuple(row[name] for name in columns) for row in tables[table]])


def import_once(connection, plan, payload, target_fence, fence_lib, journal):
    """Caller holds the per-target file lock; no existing journal may be reused."""
    wanted = expected_tables(payload)
    desired_sequences = payload['sequences_after']
    with database_lock(connection):
        guard(connection, plan, target_fence, fence_lib)
        require(read_tables(connection) == health_seed(), 'Target is not exactly the owned empty seed')
        before_sequences = read_sequences(connection)
        require(all(v == {'last_value': 1, 'is_called': False} for v in before_sequences.values()),
                'Target sequences are not unused; investigate without import')
        journal.start({'format': 1, 'kind': 'powerdns-data-import-receipt', 'operation_id': plan['operation_id'],
                       'plan_sha256': digest(plan), 'snapshot_sha256': plan['snapshot_sha256'],
                       'target': plan['target'], 'target_fence_sha256': plan['target_fence_sha256'],
                       'sequences_before': before_sequences, 'desired_sequences': desired_sequences,
                       'phase': 'prepared', 'verified': False, 'writer_enabled': False})
        try:
            journal.update(phase='row-transaction-dispatch-intent')
            try:
                with connection.cursor() as cursor:
                    cursor.execute('BEGIN')
                    cursor.execute("SET LOCAL statement_timeout='15s'")
                    cursor.execute("SET LOCAL lock_timeout='2s'")
                    cursor.execute("SET LOCAL idle_in_transaction_session_timeout='60s'")
                    cursor.execute('LOCK TABLE ' + ','.join('public.' + t for t in snapshot_lib.TABLES) + ' IN SHARE ROW EXCLUSIVE MODE')
                guard(connection, plan, target_fence, fence_lib)
                require(read_tables(connection) == health_seed() and read_sequences(connection) == before_sequences,
                        'Target preimage changed before row insertion')
                insert_rows(connection, payload['tables'])
                require(read_tables(connection) == wanted, 'Inserted rows or health seed differ')
                guard(connection, plan, target_fence, fence_lib)
                journal.update(phase='row-commit-dispatch-intent')
                with connection.cursor() as cursor:
                    cursor.execute('COMMIT')
            except BaseException:
                # An unknown COMMIT is still unknown, even if ROLLBACK succeeds.
                try:
                    with connection.cursor() as cursor:
                        cursor.execute('ROLLBACK')
                except Exception:
                    pass
                raise
            journal.update(phase='rows-committed')
            require(read_tables(connection) == wanted, 'Committed rows differ')
            for name, value in desired_sequences.items():
                guard(connection, plan, target_fence, fence_lib)
                journal.update(phase='sequence-dispatch-intent', sequence=name)
                with connection.cursor() as cursor:
                    cursor.execute('SELECT setval(%s::regclass,%s,%s)',
                                   ('public.' + name, value['last_value'], value['is_called']))
                    require(cursor.fetchone()[0] == value['last_value'], 'Sequence result differs')
                require(read_sequences(connection)[name] == value, 'Sequence readback differs')
                journal.update(phase='sequence-verified', sequence=name)
            guard(connection, plan, target_fence, fence_lib)
            require(read_tables(connection) == wanted and read_sequences(connection) == desired_sequences,
                    'Final target data or sequences differ')
            journal.update(phase='verified-imported-writer-fenced', verified=True,
                           table_sha256={t: digest(rows) for t, rows in wanted.items()},
                           row_counts={t: len(rows) for t, rows in wanted.items()},
                           sequences_after=desired_sequences, writer_enabled=False)
        except BaseException as error:
            journal.update(error_type=type(error).__name__, outcome='failed-or-unknown-no-resume', verified=False)
            raise
    return journal.value


def readback(connection, plan, payload, target_fence, fence_lib):
    """Read only. Never sets a sequence, resumes an operation, or changes a receipt."""
    with database_lock(connection):
        guard(connection, plan, target_fence, fence_lib)
        tables, sequences = read_tables(connection), read_sequences(connection)
        guard(connection, plan, target_fence, fence_lib)
        return {'format': 1, 'kind': 'powerdns-import-readback', 'target': plan['target'],
                'plan_sha256': digest(plan), 'snapshot_sha256': plan['snapshot_sha256'],
                'rows_exact': tables == expected_tables(payload), 'sequences_exact': sequences == payload['sequences_after'],
                'row_counts': {t: len(rows) for t, rows in tables.items()},
                'table_sha256': {t: digest(rows) for t, rows in tables.items()}, 'sequences': sequences,
                'target_api_fenced': True, 'writer_enabled': False, 'resumed': False}


class Journal:
    def __init__(self, path):
        self.path, self.value = path, None

    def start(self, value):
        require(self.value is None, 'Operation already started')
        snapshot_lib.write_private_json(self.path, value)
        self.value = value

    def update(self, **fields):
        require(snapshot_lib.read_private_json(self.path) == self.value, 'Import receipt changed')
        value = dict(self.value)
        value.setdefault('history', [])
        value['history'] = value['history'] + [{'at': snapshot_lib.utc_now(), 'phase': value['phase']}]
        value.update(fields, updated_at=snapshot_lib.utc_now())
        temporary = self.path.with_name('.' + self.path.name + '-' + uuid.uuid4().hex)
        snapshot_lib.write_private_json(temporary, value)
        os.replace(temporary, self.path)
        fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self.value = value


@contextmanager
def state_lock(directory, target):
    directory = Path(directory)
    st = directory.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077,
            'State directory must be owned private and not a symlink')
    require(not any((p / '.git').exists() for p in (directory.resolve(), *directory.resolve().parents)),
            'Import state must remain outside Git')
    key = digest({k: target[k] for k in ('system_identifier', 'database_oid', 'database')})
    lock = directory / ('powerdns-import-' + key + '.lock')
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as handle:
        st = os.fstat(handle.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1 and not st.st_mode & 0o077,
                'Unsafe import lock')
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield directory / ('powerdns-import-' + key + '.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan-check', 'import-once', 'readback'))
    for name in ('plan', 'snapshot', 'source-fence', 'target-fence'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--connection-file', type=Path)
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    def expired(*_):
        raise TimeoutError('Bounded importer deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    fence_lib = module('powerdns-fence')
    plan, snapshot, source_fence, target_fence = [snapshot_lib.read_private_json(getattr(args, n))
                                               for n in ('plan', 'snapshot', 'source_fence', 'target_fence')]
    payload = validate_inputs(plan, snapshot, source_fence, target_fence, fence_lib, current=args.command != 'readback')
    if args.command == 'plan-check':
        print(json.dumps({'valid': True, 'plan_sha256': digest(plan), 'snapshot_sha256': snapshot['sha256'], 'runtime_mutated': False}))
        return
    require(args.connection_file and args.state_dir, 'Private connection and persistent state directory required')
    if args.command == 'readback':
        require(args.output is not None and not args.output.exists(), 'New private readback output required')
    config = snapshot_lib.read_private_json(args.connection_file, 16384)
    snapshot_lib.validate_connection(config, plan['target'])
    import psycopg
    with state_lock(args.state_dir, plan['target']) as path:
        require(args.command != 'import-once' or not path.exists(), 'Prior import receipt exists; readback only, never replay')
        if args.command == 'readback':
            previous = snapshot_lib.read_private_json(path)
            require(previous['plan_sha256'] == digest(plan), 'Readback plan differs from original operation')
        readonly = 'on' if args.command == 'readback' else 'off'
        with psycopg.connect(**config, autocommit=True, connect_timeout=10,
                            application_name='infra-flux-pdns-data-import',
                            options='-c statement_timeout=15000 -c lock_timeout=2000 -c default_transaction_read_only=' + readonly) as connection:
            if args.command == 'import-once':
                result = import_once(connection, plan, payload, target_fence, fence_lib, Journal(path))
                print(json.dumps({'receipt': str(path), 'phase': result['phase'], 'verified': result['verified'], 'writer_enabled': False}))
            else:
                result = readback(connection, plan, payload, target_fence, fence_lib)
                snapshot_lib.write_private_json(args.output, result)
                print(json.dumps({'readback': str(args.output), 'rows_exact': result['rows_exact'],
                                  'sequences_exact': result['sequences_exact'], 'resumed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error_type': type(error).__name__,
                          'message': str(error) if isinstance(error, snapshot_lib.InvalidSnapshot) else
                          'Import failed or outcome unknown; preserve receipt and use readback, never replay'}))
        sys.exit(1)
