"""Offline migration-integrity tests; no database, SSH or production writes."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('snapshot', Path(__file__).with_name('powerdns-snapshot.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
SOURCE = {'label': 'source-test', 'system_identifier': '1234567890', 'database_oid': 12345,
          'database': 'powerdns', 'user': 'postgres'}
START, END = '2026-10-18T00:00:00+00:00', '2026-10-18T00:00:02+00:00'
TX = {'snapshot': '10:12:11', 'server_version_num': 180004, 'read_only': True, 'isolation': 'repeatable read'}


def fixture():
    tables = {t: [] for t in p.TABLES}
    tables['domains'] = [{'id': 7, 'name': 'example.invalid', 'master': None, 'last_check': None,
        'type': 'NATIVE', 'notified_serial': None, 'account': '', 'options': None, 'catalog': None}]
    tables['records'] = [dict(zip(p.COLUMNS['records'], (101, 7, 'a.example.invalid', 'A', '192.0.2.1', 300, None, True, '', False)))]
    tables['comments'] = [dict(zip(p.COLUMNS['comments'], (3, 7, 'a.example.invalid', 'A', 1, '', 'fixture comment')))]
    tables['domainmetadata'] = [{'id': 2, 'domain_id': 7, 'kind': 'SOA-EDIT-API', 'content': 'DEFAULT'}]
    tables['cryptokeys'] = [{'id': 4, 'domain_id': 7, 'flags': 257, 'active': False, 'published': True, 'content': 'fixture-private-key'}]
    tables['tsigkeys'] = [{'id': 5, 'name': 'fixture-key', 'algorithm': 'hmac-sha256', 'secret': 'fixture-secret'}]
    sequences = {name: {'last_value': max((r['id'] for r in tables[t]), default=1), 'is_called': bool(tables[t])}
                 for name, t in p.SEQUENCES.items()}
    return tables, sequences


def fence():
    return {'format': 1, 'kind': 'powerdns-writer-fence', 'source': copy.deepcopy(SOURCE),
        'fence_id': '00000000-0000-4000-8000-000000000001', 'checked_at': START,
        'valid_until': '2026-10-18T00:10:00+00:00',
        'checks': dict.fromkeys(p.FENCE_CHECKS, True), 'evidence_sha256': dict.fromkeys(p.FENCE_PROOFS, 'a' * 64)}


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tables, self.sequences = fixture()

    def build(self, **kwargs):
        return p.make_snapshot(SOURCE, self.tables, self.sequences, self.sequences, START, END, TX, **kwargs)

    def test_roundtrip_preserves_null_empty_flags_private_fields_and_metadata(self):
        snapshot = self.build()
        payload = p.validate_snapshot(snapshot, SOURCE)
        self.assertEqual(payload['tables'], self.tables)
        self.assertIsNone(payload['tables']['domains'][0]['master'])
        self.assertEqual(payload['tables']['domains'][0]['account'], '')
        self.assertTrue(payload['tables']['records'][0]['disabled'])
        self.assertFalse(payload['tables']['records'][0]['auth'])
        self.assertEqual(payload['tables']['records'][0]['ordername'], '')
        output = json.dumps(p.summary(snapshot))
        for private in ('fixture-private-key', 'fixture-secret', 'example.invalid'):
            self.assertNotIn(private, output)
        self.assertFalse(payload['capture']['final_for_cutover'])

    def test_row_and_dictionary_order_do_not_change_hash(self):
        self.tables['records'].append({**self.tables['records'][0], 'id': 100})
        one = self.build()
        self.tables['records'].reverse()
        self.tables['domains'][0] = dict(reversed(list(self.tables['domains'][0].items())))
        self.assertEqual(one, self.build())

    def test_integrity_and_per_table_hash_mismatches_rejected(self):
        for recalculate_outer in (False, True):
            snapshot = self.build()
            snapshot['payload']['tables']['tsigkeys'][0]['secret'] = 'changed'
            if recalculate_outer:
                snapshot['sha256'] = p.sha256(snapshot['payload'])
            with self.subTest(recalculate_outer=recalculate_outer), self.assertRaises(p.InvalidSnapshot):
                p.validate_snapshot(snapshot, SOURCE)

    def test_zone_hash_covers_metadata_and_disabled_records(self):
        before = self.build()['payload']['zone_sha256']
        self.tables['domainmetadata'][0]['content'] = 'INCREASE'
        self.assertNotEqual(before, self.build()['payload']['zone_sha256'])
        before = self.build()['payload']['zone_sha256']
        self.tables['records'][0]['disabled'] = False
        self.assertNotEqual(before, self.build()['payload']['zone_sha256'])

    def test_all_seven_tables_and_exact_columns_required(self):
        for mutation in ('missing_table', 'extra_table', 'missing_column', 'extra_column'):
            tables, _ = fixture()
            if mutation == 'missing_table': del tables['cryptokeys']
            if mutation == 'extra_table': tables['unknown'] = []
            if mutation == 'missing_column': del tables['records'][0]['disabled']
            if mutation == 'extra_column': tables['records'][0]['unknown'] = None
            with self.subTest(mutation=mutation), self.assertRaises(p.InvalidSnapshot):
                p.validate_tables(tables)

    def test_caps_fail_without_truncation_and_cannot_be_raised(self):
        for options in ({'max_rows': 1}, {'max_bytes': 10}, {'max_rows': p.MAX_ROWS + 1}, {'max_bytes': p.MAX_BYTES + 1}):
            with self.subTest(options=options), self.assertRaises(p.InvalidSnapshot):
                self.build(**options)
        self.assertEqual(len(self.tables['records']), 1)

    def test_reserved_ids_rejected(self):
        for table, field, value in [('domains', 'id', p.RESERVED_DOMAIN),
                                   *[('records', 'id', n) for n in p.RESERVED_RECORDS]]:
            tables, _ = fixture()
            tables[table][0][field] = value
            with self.subTest(table=table, field=field, value=value), self.assertRaises(p.InvalidSnapshot):
                p.validate_tables(tables)

    def test_health_name_collisions_are_preserved_in_observation_but_never_final(self):
        self.tables['domains'][0]['name'] = 'health.test'
        self.tables['records'][0]['name'] = 'ns.health.test'
        snapshot = self.build()
        self.assertEqual(snapshot['payload']['tables'], self.tables)
        self.assertEqual(snapshot['payload']['destination_collisions'], ['reserved_health_zone_name', 'reserved_health_record_name'])
        p.validate_snapshot(snapshot, SOURCE)
        with self.assertRaises(p.InvalidSnapshot): self.build(final=True, fence=fence())

    def test_socket_cannot_bypass_tcp_tls_with_hostaddr_or_multihost(self):
        base = {'dbname': 'powerdns', 'user': 'postgres'}
        for values in ({'host': '/run/postgresql', 'hostaddr': '192.0.2.1'},
                       {'host': '/run/postgresql,db.example.invalid'}, {'host': 'db.example.invalid'}):
            with self.subTest(values=values), self.assertRaises(p.InvalidSnapshot):
                p.validate_connection({**base, **values}, SOURCE)
        p.validate_connection({**base, 'host': '/run/postgresql'}, SOURCE)
        p.validate_connection({**base, 'host': 'db.example.invalid', 'sslmode': 'verify-full'}, SOURCE)

    def test_duplicate_ids_orphans_non_native_and_uppercase_rejected(self):
        for mutation in ('duplicate', 'orphan', 'non_native', 'uppercase', 'bool_id', 'negative_id'):
            tables, _ = fixture()
            if mutation == 'duplicate': tables['records'].append(copy.deepcopy(tables['records'][0]))
            if mutation == 'orphan': tables['records'][0]['domain_id'] = 999
            if mutation == 'non_native': tables['domains'][0]['type'] = 'MASTER'
            if mutation == 'uppercase': tables['records'][0]['name'] = 'A.example.invalid'
            if mutation == 'bool_id': tables['records'][0]['id'] = True
            if mutation == 'negative_id': tables['domains'][0]['id'] = -1
            with self.subTest(mutation=mutation), self.assertRaises(p.InvalidSnapshot):
                p.validate_tables(tables)

    def test_six_sequences_required_and_unused_sequence_remains_uncalled(self):
        self.tables['comments'] = []
        self.sequences['comments_id_seq'] = {'last_value': 1, 'is_called': False}
        self.assertEqual(self.build()['payload']['sequences_after']['comments_id_seq'], {'last_value': 1, 'is_called': False})
        del self.sequences['comments_id_seq']
        with self.assertRaises(p.InvalidSnapshot): self.build()

    def test_sequence_lag_uncalled_collision_reserved_range_and_exhaustion_rejected(self):
        for position in ({'last_value': 100, 'is_called': True}, {'last_value': 101, 'is_called': False},
                         {'last_value': p.RESERVED_DOMAIN-1, 'is_called': True},
                         {'last_value': 2**63-1, 'is_called': True}):
            seq = copy.deepcopy(self.sequences)
            seq['records_id_seq'] = position
            with self.subTest(position=position), self.assertRaises(p.InvalidSnapshot):
                p.validate_sequences(seq, self.tables)

    def test_sequence_movement_observed_but_never_final(self):
        after = copy.deepcopy(self.sequences)
        after['records_id_seq']['last_value'] += 1
        observed = p.make_snapshot(SOURCE, self.tables, self.sequences, after, START, END, TX)
        self.assertFalse(observed['payload']['capture']['sequences_stable'])
        p.validate_snapshot(observed, SOURCE)
        with self.assertRaises(p.InvalidSnapshot):
            p.make_snapshot(SOURCE, self.tables, self.sequences, after, START, END, TX, final=True, fence=fence())

    def test_stable_sequences_alone_never_certify_final(self):
        with self.assertRaises(p.InvalidSnapshot): self.build(final=True)
        with self.assertRaises(p.InvalidSnapshot): p.validate_snapshot(self.build(), SOURCE, require_final=True)

    def test_final_requires_explicit_external_fence_attestation(self):
        snapshot = self.build(final=True, fence=fence())
        p.validate_snapshot(snapshot, SOURCE, require_final=True)
        self.assertEqual(snapshot['payload']['capture']['fence_verification'], 'external-attestation')

    def test_wrong_stale_short_false_or_unproven_fence_rejected(self):
        for mutation in ('identity', 'stale', 'starts_late', 'long', 'false', 'missing_proof'):
            evidence = fence()
            if mutation == 'identity': evidence['source']['database_oid'] += 1
            if mutation == 'stale': evidence['valid_until'] = START
            if mutation == 'starts_late': evidence['checked_at'] = END
            if mutation == 'long': evidence['valid_until'] = '2026-10-18T01:00:00+00:00'
            if mutation == 'false': evidence['checks']['old_db_writers_drained'] = False
            if mutation == 'missing_proof': del evidence['evidence_sha256']['api_probe']
            with self.subTest(mutation=mutation), self.assertRaises(p.InvalidSnapshot):
                self.build(final=True, fence=evidence)

    def test_expected_source_identity_cannot_be_swapped(self):
        for key, value in [('label', 'other'), ('system_identifier', '2'), ('database_oid', 999), ('user', 'other')]:
            with self.subTest(key=key), self.assertRaises(p.InvalidSnapshot):
                p.validate_snapshot(self.build(), {**SOURCE, key: value})

    def test_wrong_transaction_is_rejected(self):
        for key, value in [('read_only', False), ('isolation', 'read committed')]:
            with self.subTest(key=key), self.assertRaises(p.InvalidSnapshot):
                p.make_snapshot(SOURCE, self.tables, self.sequences, self.sequences, START, END, {**TX, key: value})

    def test_private_file_roundtrip_and_never_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'snapshot.json'
            p.write_private_json(path, self.build())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(p.read_private_json(path), self.build())
            with self.assertRaises(FileExistsError): p.write_private_json(path, self.build())
            path.chmod(0o644)
            with self.assertRaises(p.InvalidSnapshot): p.read_private_json(path)

    def test_symlink_duplicate_json_oversize_and_git_output_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'input.json'
            path.write_text('{"a":1,"a":2}')
            path.chmod(0o600)
            with self.assertRaises(p.InvalidSnapshot): p.read_private_json(path)
            with self.assertRaises(p.InvalidSnapshot): p.read_private_json(path, 1)
            (root / 'link.json').symlink_to(path)
            with self.assertRaises(OSError): p.read_private_json(root / 'link.json')
            (root / '.git').mkdir()
            with self.assertRaises(p.InvalidSnapshot): p.write_private_json(root / 'output.json', self.build())


class FakeCursor:
    def __init__(self, tables, sequences, *, too_many=False, too_large=False):
        self.tables, self.sequences, self.too_many, self.too_large = tables, sequences, too_many, too_large
        self.calls, self.result = [], []

    def __enter__(self): return self
    def __exit__(self, *args): pass
    def fetchone(self): return self.result.pop(0) if self.result else None
    def fetchall(self):
        result, self.result = self.result, []
        return result

    def execute(self, statement, args=()):
        self.calls.append((statement, args))
        self.result = []
        if statement.startswith(('BEGIN ', 'SET LOCAL ', 'ROLLBACK', 'LOCK TABLE ')): return
        if statement == 'SELECT system_identifier::text FROM pg_control_system()': self.result = [(SOURCE['system_identifier'],)]
        elif statement.startswith('SELECT d.oid'): self.result = [(SOURCE['database_oid'], 'powerdns', 'postgres', False, 'on', 'repeatable read', '10:12:11', 180004)]
        elif statement.startswith('SELECT c.relname'): self.result = [(t, 'r', False, False) for t in p.TABLES]
        elif statement.startswith('SELECT a.attname'):
            table = args[0].split('.')[1]
            self.result = [(name, 'int4' if name in p.INTEGER_COLUMNS else 'bool' if name in p.BOOLEAN_COLUMNS else 'text') for name in p.COLUMNS[table]]
        elif statement.startswith('SELECT sequencename'):
            self.result = [(name, 'bigint' if table == 'records' else 'integer', 1, 1,
                            2**63-1 if table == 'records' else 2**31-1, 1, False, 1) for name, table in p.SEQUENCES.items()]
        elif statement.startswith('SELECT pg_get_serial_sequence'): self.result = [(args[0] + '_id_seq',)]
        elif statement.startswith('SELECT last_value'):
            name = statement.split('public.')[1]
            self.result = [(self.sequences[name]['last_value'], self.sequences[name]['is_called'])]
        elif statement.startswith('SELECT count(*)'):
            table = statement.split('public.')[1]
            self.result = [(p.MAX_ROWS+1 if self.too_many else len(self.tables[table]),)]
        elif statement.startswith('SELECT coalesce(sum'):
            table = statement.split('public.')[1].split()[0]
            self.result = [(p.MAX_BYTES+1 if self.too_large else sum(len(p.canonical(r)) for r in self.tables[table]),)]
        elif statement.startswith('SELECT to_jsonb'):
            table = statement.split('public.')[1].split()[0]
            self.result = [(json.dumps(r),) for r in self.tables[table]]
        elif statement == 'SELECT pg_is_in_recovery()': self.result = [(False,)]
        else: raise AssertionError('Unexpected SQL')


class ExportTransactionTests(unittest.TestCase):
    def connection(self, **kwargs):
        tables, sequences = fixture()
        cursor = FakeCursor(tables, sequences, **kwargs)
        class Connection:
            autocommit = True
            info = SimpleNamespace(transaction_status=0)
            def cursor(self): return cursor
        return Connection(), cursor

    def test_export_is_read_only_repeatable_read_with_rollback_and_six_pairs(self):
        conn, cursor = self.connection()
        result = p.export_snapshot(conn, SOURCE)
        p.validate_snapshot(result, SOURCE)
        statements = [s for s, _ in cursor.calls]
        self.assertEqual(statements[0], 'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        self.assertEqual(statements[-1], 'ROLLBACK')
        self.assertEqual(sum(s.startswith('SELECT last_value') for s in statements), 12)
        self.assertTrue(all(s.startswith(('SELECT ', 'SET LOCAL ', 'BEGIN ', 'ROLLBACK', 'LOCK TABLE ')) for s in statements))

    def test_all_relation_locks_precede_snapshot_acquisition(self):
        conn, cursor = self.connection()
        p.export_snapshot(conn, SOURCE)
        statements = [s for s, _ in cursor.calls]
        locks = [i for i,s in enumerate(statements) if s.startswith('LOCK TABLE ')]
        self.assertEqual(len(locks),1)
        self.assertLess(locks[0],next(i for i,s in enumerate(statements) if s.startswith('SELECT ')))
        self.assertEqual(statements[locks[0]],'LOCK TABLE '+','.join('public.'+t for t in p.TABLES)+' IN ACCESS SHARE MODE')

    def test_cap_failure_rolls_back_without_fetching_table_rows(self):
        conn, cursor = self.connection(too_many=True)
        with self.assertRaises(p.InvalidSnapshot): p.export_snapshot(conn, SOURCE)
        statements = [s for s, _ in cursor.calls]
        self.assertEqual(statements[-1], 'ROLLBACK')
        self.assertFalse(any(s.startswith('SELECT to_jsonb') for s in statements))

    def test_byte_cap_failure_rolls_back_without_fetching_table_rows(self):
        conn, cursor = self.connection(too_large=True)
        with self.assertRaises(p.InvalidSnapshot): p.export_snapshot(conn, SOURCE)
        statements = [s for s, _ in cursor.calls]
        self.assertEqual(statements[-1], 'ROLLBACK')
        self.assertFalse(any(s.startswith('SELECT to_jsonb') for s in statements))

    def test_existing_transaction_is_not_rolled_back(self):
        conn, cursor = self.connection()
        conn.info.transaction_status = 2
        with self.assertRaises(p.InvalidSnapshot): p.export_snapshot(conn, SOURCE)
        self.assertEqual(cursor.calls, [])

    def test_invalid_caps_rejected_before_any_database_query(self):
        conn, cursor = self.connection()
        with self.assertRaises(p.InvalidSnapshot): p.export_snapshot(conn, SOURCE, max_rows=p.MAX_ROWS+1)
        self.assertEqual(cursor.calls, [])


if __name__ == '__main__':
    unittest.main()
