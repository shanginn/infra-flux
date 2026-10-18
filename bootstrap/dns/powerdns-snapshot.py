#!/usr/bin/env python3
"""Bounded, read-only PowerDNS PostgreSQL exports. Never import or fence writers.

Snapshots can contain DNSSEC/TSIG secrets. Only private files receive contents;
stdout contains counts and hashes. Requires psycopg 3 only for the export command.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

FORMAT = 1
MAX_ROWS = 10_000
MAX_BYTES = 1_048_576
MAX_FILE_BYTES = 2 * MAX_BYTES
RESERVED_DOMAIN = 2_000_000_000
RESERVED_RECORDS = {2_000_000_000, 2_000_000_001, 2_000_000_002}
COLUMNS = {
    'domains': ('id', 'name', 'master', 'last_check', 'type', 'notified_serial', 'account', 'options', 'catalog'),
    'records': ('id', 'domain_id', 'name', 'type', 'content', 'ttl', 'prio', 'disabled', 'ordername', 'auth'),
    'supermasters': ('ip', 'nameserver', 'account'),
    'comments': ('id', 'domain_id', 'name', 'type', 'modified_at', 'account', 'comment'),
    'domainmetadata': ('id', 'domain_id', 'kind', 'content'),
    'cryptokeys': ('id', 'domain_id', 'flags', 'active', 'published', 'content'),
    'tsigkeys': ('id', 'name', 'algorithm', 'secret'),
}
TABLES = tuple(COLUMNS)
SEQUENCES = {t + '_id_seq': t for t in TABLES if t != 'supermasters'}
INTEGER_COLUMNS = {'id', 'domain_id', 'last_check', 'notified_serial', 'ttl', 'prio', 'modified_at', 'flags'}
BOOLEAN_COLUMNS = {'disabled', 'auth', 'active', 'published'}
NONNULL = {
    'domains': {'id', 'name', 'type'}, 'records': {'id'},
    'supermasters': {'ip', 'nameserver', 'account'},
    'comments': {'id', 'domain_id', 'name', 'type', 'modified_at', 'comment'},
    'domainmetadata': {'id'}, 'cryptokeys': {'id', 'flags'}, 'tsigkeys': {'id'},
}
TEXT_LIMITS = {
    'domains': {'name': 255, 'master': 128, 'account': 40},
    'records': {'name': 255, 'type': 10, 'content': 65535, 'ordername': 255},
    'supermasters': {'nameserver': 255, 'account': 40},
    'comments': {'name': 255, 'type': 10, 'account': 40, 'comment': 65535},
    'domainmetadata': {'kind': 32}, 'cryptokeys': {},
    'tsigkeys': {'name': 255, 'algorithm': 50, 'secret': 255},
}
IDENTITY_KEYS = {'label', 'system_identifier', 'database_oid', 'database', 'user'}
FENCE_CHECKS = {'old_api_8081_blocked', 'old_dns_udp53_available', 'old_dns_tcp53_available',
                'old_db_writers_drained', 'other_write_paths_disabled', 'no_legacy_pod_restart'}
FENCE_PROOFS = {'api_probe', 'dns_probe', 'db_sessions', 'other_writers', 'workload_identity'}


class InvalidSnapshot(ValueError):
    """Messages are fixed strings: never include data, credentials or DB errors."""


def require(condition, message):
    if not condition:
        raise InvalidSnapshot(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def timestamp(value):
    require(isinstance(value, str), 'Timestamp is missing')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise InvalidSnapshot('Invalid timestamp') from None
    require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0, 'UTC timestamp required')
    return parsed


def validate_identity(identity):
    require(isinstance(identity, dict) and set(identity) == IDENTITY_KEYS, 'Source identity fields differ')
    require(isinstance(identity['label'], str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', identity['label']), 'Invalid source label')
    require(isinstance(identity['system_identifier'], str) and re.fullmatch(r'[1-9][0-9]{0,19}', identity['system_identifier']), 'Invalid PostgreSQL system identifier')
    require(type(identity['database_oid']) is int and 0 < identity['database_oid'] < 2**32, 'Invalid database OID')
    require(identity['database'] == 'powerdns', 'Unexpected database name')
    require(isinstance(identity['user'], str) and re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]{0,62}', identity['user']), 'Invalid database role')


def rows_key(table, row):
    return (row['ip'], row['nameserver']) if table == 'supermasters' else row['id']


def validate_limits(max_rows, max_bytes):
    require(type(max_rows) is int and 0 < max_rows <= MAX_ROWS, 'Invalid row cap')
    require(type(max_bytes) is int and 0 < max_bytes <= MAX_BYTES, 'Invalid byte cap')


def validate_tables(tables, max_rows=MAX_ROWS, max_bytes=MAX_BYTES):
    require(isinstance(tables, dict) and set(tables) == set(TABLES), 'Exactly seven PowerDNS tables required')
    validate_limits(max_rows, max_bytes)
    count = 0
    normalized = {}
    for table in TABLES:
        rows = tables[table]
        require(isinstance(rows, list), 'Table must contain a row array')
        count += len(rows)
        require(count <= max_rows, 'Snapshot row cap exceeded')
        keys = set()
        for row in rows:
            require(isinstance(row, dict) and set(row) == set(COLUMNS[table]), 'PowerDNS row columns differ')
            for name, value in row.items():
                if value is None:
                    require(name not in NONNULL[table], 'Unexpected NULL in required column')
                elif name in INTEGER_COLUMNS:
                    bits = 64 if (table, name) in (('records', 'id'), ('domains', 'notified_serial')) else 32
                    require(type(value) is int and -(2**(bits-1)) <= value < 2**(bits-1), 'Integer column has incompatible value')
                elif name in BOOLEAN_COLUMNS:
                    require(type(value) is bool, 'Boolean column has incompatible value')
                else:
                    require(isinstance(value, str) and '\x00' not in value, 'Text column has incompatible value')
                    require(name not in TEXT_LIMITS[table] or len(value) <= TEXT_LIMITS[table][name], 'Text exceeds target column length')
            if table == 'supermasters':
                try:
                    ipaddress.ip_interface(row['ip'])
                except ValueError:
                    raise InvalidSnapshot('Invalid supermaster network address') from None
            if table != 'supermasters':
                require(0 < row['id'] < (2**63 if table == 'records' else 2**31), 'Source row ID is outside positive range')
            if table == 'domains':
                require(row['type'] == 'NATIVE', 'Only NATIVE domains may be imported')
                require(row['id'] != RESERVED_DOMAIN, 'Reserved health domain ID collision')
            if table == 'records':
                require(row['id'] not in RESERVED_RECORDS, 'Reserved health record collision')
            if table in ('domains', 'records', 'comments', 'tsigkeys') and row['name'] is not None:
                require(row['name'] == row['name'].lower(), 'New schema rejects uppercase names')
            key = rows_key(table, row)
            require(key not in keys, 'Duplicate source primary key')
            keys.add(key)
        normalized[table] = sorted(rows, key=lambda row: rows_key(table, row))
    require(len(canonical(normalized)) <= max_bytes, 'Snapshot byte cap exceeded')
    domains = {r['id'] for r in normalized['domains']}
    names = [r['name'] for r in normalized['domains']]
    require(len(names) == len(set(names)), 'Duplicate domain name')
    for table in ('records', 'comments', 'domainmetadata', 'cryptokeys'):
        require(all(r['domain_id'] is None or r['domain_id'] in domains for r in normalized[table]), 'Orphaned domain reference')
    tsig = [(r['name'], r['algorithm']) for r in normalized['tsigkeys'] if r['name'] is not None and r['algorithm'] is not None]
    require(len(tsig) == len(set(tsig)), 'Duplicate TSIG identity')
    return normalized


def destination_collisions(tables):
    collisions = []
    if any(row['name'] == 'health.test' for row in tables['domains']):
        collisions.append('reserved_health_zone_name')
    if any(row['name'] in ('health.test', 'ns.health.test') for row in tables['records']):
        collisions.append('reserved_health_record_name')
    return collisions


def zone_hashes(tables):
    return {str(domain['id']): sha256({'domain': domain, **{
        table: [row for row in tables[table] if row['domain_id'] == domain['id']]
        for table in ('records', 'comments', 'domainmetadata', 'cryptokeys')}})
        for domain in tables['domains']}


def validate_sequences(sequences, tables):
    require(isinstance(sequences, dict) and set(sequences) == set(SEQUENCES), 'Exactly six ID sequences required')
    for name, table in SEQUENCES.items():
        value = sequences[name]
        require(isinstance(value, dict) and set(value) == {'last_value', 'is_called'}, 'Sequence fields differ')
        last, called = value['last_value'], value['is_called']
        limit = 2**63 - 1 if table == 'records' else 2**31 - 1
        require(type(last) is int and 1 <= last <= limit and type(called) is bool, 'Invalid sequence position')
        max_id = max((r['id'] for r in tables[table]), default=0)
        require(last >= max_id and (called or last > max_id), 'Sequence is behind imported IDs')
        next_id = last + int(called)
        require(next_id <= limit, 'Sequence exhausted')
        if table in ('domains', 'records'):
            # Leave the reserved high range untouched, with room for ordinary IDs.
            require(next_id < RESERVED_DOMAIN, 'Sequence reaches reserved health IDs')


def validate_fence(evidence, source, started, finished):
    require(isinstance(evidence, dict) and set(evidence) == {
        'format', 'kind', 'source', 'fence_id', 'checked_at', 'valid_until', 'checks', 'evidence_sha256'}, 'Fence evidence fields differ')
    require(evidence['format'] == 1 and evidence['kind'] == 'powerdns-writer-fence', 'Fence evidence format differs')
    require(evidence['source'] == source, 'Fence source identity differs')
    try:
        require(str(uuid.UUID(evidence['fence_id'])) == evidence['fence_id'], 'Invalid fence identifier')
    except (ValueError, TypeError, AttributeError):
        raise InvalidSnapshot('Invalid fence identifier') from None
    begin, end = timestamp(evidence['checked_at']), timestamp(evidence['valid_until'])
    require(begin <= timestamp(started) <= timestamp(finished) <= end, 'Fence interval does not cover capture')
    require(0 < (end - begin).total_seconds() <= 900, 'Fence evidence must expire within fifteen minutes')
    require(isinstance(evidence['checks'], dict) and set(evidence['checks']) == FENCE_CHECKS and
            all(value is True for value in evidence['checks'].values()), 'Fence checks are incomplete')
    proofs = evidence['evidence_sha256']
    require(isinstance(proofs, dict) and set(proofs) == FENCE_PROOFS and all(
        isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) for value in proofs.values()), 'Fence proof digests are incomplete')


def make_snapshot(source, tables, before, after, started, finished, transaction, *,
                  final=False, fence=None, max_rows=MAX_ROWS, max_bytes=MAX_BYTES):
    validate_identity(source)
    require(type(final) is bool, 'Final flag must be boolean')
    require(timestamp(started) <= timestamp(finished), 'Capture interval is reversed')
    require(isinstance(transaction, dict) and set(transaction) == {'snapshot', 'server_version_num', 'read_only', 'isolation'}, 'Transaction proof fields differ')
    require(transaction['read_only'] is True and transaction['isolation'] == 'repeatable read', 'Read-only repeatable-read transaction required')
    require(isinstance(transaction['snapshot'], str) and re.fullmatch(r'[0-9]+:[0-9]+:[0-9,]*', transaction['snapshot']), 'Invalid MVCC snapshot')
    require(type(transaction['server_version_num']) is int and transaction['server_version_num'] >= 150000, 'PostgreSQL 15 or newer required')
    tables = validate_tables(tables, max_rows, max_bytes)
    validate_sequences(before, tables)
    validate_sequences(after, tables)
    stable = before == after
    collisions = destination_collisions(tables)
    if final:
        require(not collisions, 'Destination health names collide; resolve separately before final capture')
        require(stable, 'Sequences changed during final capture')
        validate_fence(fence, source, started, finished)
    else:
        require(fence is None, 'Fence evidence requires explicit final capture')
    payload = {'format': FORMAT, 'source': source, 'capture': {
        'started_at': started, 'finished_at': finished, 'transaction': transaction,
        'final_for_cutover': final, 'fence_verification': 'external-attestation' if final else 'not-verified',
        'fence': fence, 'sequences_stable': stable},
        'limits': {'max_rows': max_rows, 'max_bytes': max_bytes}, 'tables': tables,
        'destination_collisions': collisions,
        'table_sha256': {t: sha256(tables[t]) for t in TABLES}, 'zone_sha256': zone_hashes(tables),
        'sequences_before': before, 'sequences_after': after}
    # Detach every row and identity from mutable caller-owned dictionaries.
    payload = json.loads(canonical(payload))
    return {'payload': payload, 'sha256': sha256(payload)}


def validate_snapshot(snapshot, expected_source, *, require_final=False):
    validate_identity(expected_source)
    require(isinstance(snapshot, dict) and set(snapshot) == {'payload', 'sha256'}, 'Snapshot envelope differs')
    payload = snapshot['payload']
    require(isinstance(payload, dict) and set(payload) == {'format', 'source', 'capture', 'limits', 'tables', 'destination_collisions', 'table_sha256', 'zone_sha256', 'sequences_before', 'sequences_after'}, 'Snapshot payload fields differ')
    require(snapshot['sha256'] == sha256(payload), 'Snapshot integrity mismatch')
    require(payload['format'] == FORMAT and payload['source'] == expected_source, 'Snapshot source identity differs')
    capture, limits = payload['capture'], payload['limits']
    require(isinstance(capture, dict) and set(capture) == {'started_at', 'finished_at', 'transaction', 'final_for_cutover', 'fence_verification', 'fence', 'sequences_stable'}, 'Capture fields differ')
    require(isinstance(limits, dict) and set(limits) == {'max_rows', 'max_bytes'}, 'Snapshot limits differ')
    rebuilt = make_snapshot(expected_source, payload['tables'], payload['sequences_before'], payload['sequences_after'],
        capture['started_at'], capture['finished_at'], capture['transaction'], final=capture['final_for_cutover'],
        fence=capture['fence'], **limits)
    require(rebuilt == snapshot, 'Snapshot canonical content or per-table hash differs')
    require(not require_final or capture['final_for_cutover'] is True, 'Observation is not a final cutover snapshot')
    return payload


def read_private_json(path, cap=MAX_FILE_BYTES):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                info.st_nlink == 1 and not info.st_mode & 0o077, 'Input must be an owned private regular file')
        require(info.st_size <= cap, 'Private input exceeds byte cap')
        raw = handle.read(cap + 1)
    require(len(raw) <= cap, 'Private input exceeds byte cap')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON object key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(InvalidSnapshot('Invalid JSON number')))


def write_private_json(path, value):
    path = Path(path)
    parent = path.parent.resolve(strict=True)
    info = parent.stat()
    require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'Output directory must be owned and private')
    require(not any((ancestor / '.git').exists() for ancestor in (parent, *parent.parents)), 'Snapshots must remain outside Git worktrees')
    raw = canonical(value) + b'\n'
    require(len(raw) <= MAX_FILE_BYTES, 'Snapshot file exceeds byte cap')
    descriptor = os.open(parent / path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        # A partial private file is deliberately retained and never overwritten.
        raise


def export_snapshot(connection, expected_source, *, final=False, fence=None, max_rows=MAX_ROWS, max_bytes=MAX_BYTES):
    """Use a fresh psycopg connection in autocommit mode; no SQL writes occur."""
    validate_identity(expected_source)
    validate_limits(max_rows, max_bytes)
    require(connection.autocommit and connection.info.transaction_status == 0, 'Fresh idle autocommit connection required')
    started = utc_now()
    with connection.cursor() as cursor:
        cursor.execute('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        try:
            cursor.execute("SET LOCAL statement_timeout='15s'")
            cursor.execute("SET LOCAL lock_timeout='2s'")
            cursor.execute("SET LOCAL idle_in_transaction_session_timeout='60s'")
            cursor.execute("SET LOCAL search_path=pg_catalog")
            cursor.execute("SELECT system_identifier::text FROM pg_control_system()")
            system_identifier = cursor.fetchone()[0]
            cursor.execute("SELECT d.oid::bigint,current_database(),current_user,pg_is_in_recovery(),current_setting('transaction_read_only'),current_setting('transaction_isolation'),pg_current_snapshot()::text,current_setting('server_version_num')::int FROM pg_database d WHERE d.datname=current_database()")
            oid, database, user, recovery, readonly, isolation, mvcc, version = cursor.fetchone()
            source = {'label': expected_source['label'], 'system_identifier': system_identifier,
                      'database_oid': oid, 'database': database, 'user': user}
            require(source == expected_source and recovery is False, 'Connected source identity or primary status differs')
            transaction = {'snapshot': mvcc, 'server_version_num': version, 'read_only': readonly == 'on', 'isolation': isolation}
            # AccessShare locks prevent table replacement until rollback; never lock rows.
            for table in TABLES:
                cursor.execute('SELECT 1 FROM public.' + table + ' LIMIT 0')
            cursor.execute("SELECT c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f') ORDER BY 1")
            relations = cursor.fetchall()
            require({row[0] for row in relations} == set(TABLES) and all(row[1:] == ('r', False, False) for row in relations), 'Source table set or row visibility differs')
            for table, expected_columns in COLUMNS.items():
                cursor.execute("SELECT a.attname,t.typname FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid WHERE a.attrelid=%s::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum", ('public.' + table,))
                columns = cursor.fetchall()
                require(tuple(row[0] for row in columns) == expected_columns, 'Source schema columns differ')
                for name, kind in columns:
                    allowed = {'int4', 'int8'} if name in INTEGER_COLUMNS else {'bool'} if name in BOOLEAN_COLUMNS else {'varchar', 'text', 'inet'}
                    require(kind in allowed, 'Source column type differs')
            cursor.execute("SELECT sequencename,data_type,start_value,min_value,max_value,increment_by,cycle,cache_size FROM pg_sequences WHERE schemaname='public' ORDER BY 1")
            sequence_definitions = cursor.fetchall()
            require({row[0] for row in sequence_definitions} == set(SEQUENCES), 'Source sequence set differs')
            for name, kind, start, minimum, maximum, increment, cycle, cache in sequence_definitions:
                is_record = SEQUENCES[name] == 'records'
                require((kind, start, minimum, maximum, increment, cycle, cache) ==
                    ('bigint' if is_record else 'integer', 1, 1, 2**63-1 if is_record else 2**31-1, 1, False, 1), 'Nonstandard sequence definition')
                cursor.execute('SELECT pg_get_serial_sequence(%s,%s)', ('public.' + SEQUENCES[name], 'id'))
                require(cursor.fetchone()[0] == 'public.' + name, 'ID sequence ownership differs')
            def sequences():
                result = {}
                for name in SEQUENCES:
                    cursor.execute('SELECT last_value,is_called FROM public.' + name)
                    last, called = cursor.fetchone()
                    result[name] = {'last_value': last, 'is_called': called}
                return result
            before = sequences()
            total_rows, total_bytes = 0, 0
            tables = {}
            for table in TABLES:
                cursor.execute('SELECT count(*) FROM public.' + table)
                count = cursor.fetchone()[0]
                total_rows += count
                require(total_rows <= max_rows, 'Source row cap exceeded')
                cursor.execute('SELECT coalesce(sum(octet_length(to_jsonb(t)::text)),0) FROM public.' + table + ' t')
                total_bytes += int(cursor.fetchone()[0])
                require(total_bytes <= max_bytes, 'Source byte cap exceeded')
                cursor.execute('SELECT to_jsonb(t)::text FROM public.' + table + ' t ORDER BY ' +
                               ('ip,nameserver' if table == 'supermasters' else 'id') + ' LIMIT %s', (max_rows + 1,))
                rows = []
                while True:
                    result = cursor.fetchone()
                    if result is None:
                        break
                    require(len(result[0].encode()) <= max_bytes, 'Source row byte cap exceeded')
                    rows.append(json.loads(result[0]))
                    require(len(rows) <= count, 'Source row count differs inside snapshot')
                require(len(rows) == count, 'Source row count differs inside snapshot')
                tables[table] = rows
            after = sequences()
            cursor.execute('SELECT pg_is_in_recovery()')
            require(cursor.fetchone()[0] is False, 'Source ceased being primary')
            finished = utc_now()
            snapshot = make_snapshot(source, tables, before, after, started, finished, transaction,
                final=final, fence=fence, max_rows=max_rows, max_bytes=max_bytes)
        finally:
            cursor.execute('ROLLBACK')
    return snapshot


def summary(snapshot):
    payload = snapshot['payload']
    return {'ok': True, 'sha256': snapshot['sha256'], 'rows': {t: len(payload['tables'][t]) for t in TABLES},
            'sequences_stable': payload['capture']['sequences_stable'],
            'final_for_cutover': payload['capture']['final_for_cutover'],
            'fence_verification': payload['capture']['fence_verification'],
            'destination_collisions': payload['destination_collisions']}


def validate_connection(connection, identity):
    require(isinstance(connection, dict) and set(connection) <= {'host', 'hostaddr', 'port', 'dbname', 'user', 'password', 'passfile', 'sslmode', 'sslrootcert'} and
            connection.get('dbname') == 'powerdns' and connection.get('user') == identity['user'], 'Connection fields differ')
    host = connection.get('host')
    require(isinstance(host, str) and host and ',' not in host and not any(c.isspace() for c in host), 'One explicit PostgreSQL host required')
    if host.startswith('/'):
        require(not connection.get('hostaddr'), 'Socket connection must not redirect to a TCP address')
    else:
        require(connection.get('sslmode') == 'verify-full', 'TCP connections require verified PostgreSQL TLS')
        if 'hostaddr' in connection:
            try:
                ipaddress.ip_address(connection['hostaddr'])
            except ValueError:
                raise InvalidSnapshot('One PostgreSQL host address required') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    export = commands.add_parser('export')
    export.add_argument('--connection-file', type=Path, required=True)
    export.add_argument('--identity-file', type=Path, required=True)
    export.add_argument('--output', type=Path, required=True)
    export.add_argument('--max-rows', type=int, default=MAX_ROWS)
    export.add_argument('--max-bytes', type=int, default=MAX_BYTES)
    export.add_argument('--final', action='store_true')
    export.add_argument('--fence-evidence', type=Path)
    validate = commands.add_parser('validate')
    validate.add_argument('--snapshot', type=Path, required=True)
    validate.add_argument('--identity-file', type=Path, required=True)
    validate.add_argument('--require-final', action='store_true')
    args = parser.parse_args()
    identity = read_private_json(args.identity_file, 8192)
    validate_identity(identity)
    if args.command == 'validate':
        snapshot = read_private_json(args.snapshot)
        validate_snapshot(snapshot, identity, require_final=args.require_final)
    else:
        require(bool(args.fence_evidence) == args.final, 'Final capture requires explicit fence evidence')
        connection = read_private_json(args.connection_file, 16384)
        validate_connection(connection, identity)
        fence = read_private_json(args.fence_evidence, 16384) if args.fence_evidence else None
        import psycopg
        with psycopg.connect(**connection, autocommit=True, connect_timeout=10,
                application_name='infra-flux-pdns-readonly-snapshot', options='-c default_transaction_read_only=on') as conn:
            snapshot = export_snapshot(conn, identity, final=args.final, fence=fence,
                                       max_rows=args.max_rows, max_bytes=args.max_bytes)
        write_private_json(args.output, snapshot)
    print(json.dumps(summary(snapshot), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # psycopg and JSON exceptions may contain SQL values, passwords or key material.
        print(json.dumps({'ok': False, 'error_type': type(error).__name__,
                          'message': str(error) if isinstance(error, InvalidSnapshot) else 'Read-only snapshot failed; inspect privately without printing contents'}))
        sys.exit(1)
