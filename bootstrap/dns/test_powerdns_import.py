"""Offline failure-behavior tests; never connect to a database."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('importer', Path(__file__).with_name('powerdns-import.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fixture_spec = importlib.util.spec_from_file_location('fixtures', Path(__file__).with_name('test_powerdns_snapshot.py'))
f = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(f)


class Database:
    """Models transactional rows, nontransactional sequences and uncertain replies."""
    autocommit = True
    info = SimpleNamespace(transaction_status=0)

    def __init__(self, failure=None):
        self.tables = m.health_seed()
        self.sequences = {name: {'last_value': 1, 'is_called': False} for name in m.snapshot_lib.SEQUENCES}
        self.failure, self.events, self.saved = failure, [], None
        self.fenced, self.journal = True, None
        self.insert_count = self.sequence_count = 0

    def cursor(self):
        return Cursor(self)


class Cursor:
    def __init__(self, database):
        self.db, self.result = database, []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def fetchone(self):
        return self.result.pop(0)

    def fetchall(self):
        result, self.result = self.result, []
        return result

    def execute(self, sql, args=()):
        d = self.db
        d.events.append((sql, args))
        if 'pg_try_advisory_lock' in sql:
            self.result = [(d.failure != 'locked',)]
        elif 'pg_advisory_unlock' in sql:
            self.result = [(True,)]
        elif sql == 'BEGIN':
            d.saved = copy.deepcopy(d.tables)
        elif sql == 'COMMIT':
            d.saved = None
            if d.failure == 'commit-reply-lost':
                raise OSError('simulated connection loss after commit')
            if d.failure == 'fence-lost-after-commit':
                d.fenced = False
        elif sql == 'ROLLBACK':
            if d.saved is not None:
                d.tables, d.saved = d.saved, None
        elif sql.startswith(('SET LOCAL', 'LOCK TABLE')):
            pass
        elif sql.startswith('SELECT count(*),coalesce'):
            table = sql.split('FROM public.')[1].split()[0]
            rows = d.tables[table]
            self.result = [(len(rows), sum(len(json.dumps(row)) for row in rows))]
        elif sql.startswith('SELECT to_jsonb'):
            table = sql.split('FROM public.')[1].split()[0]
            self.result = [(json.dumps(row),) for row in d.tables[table]]
        elif sql.startswith('SELECT last_value'):
            state = d.sequences[sql.split('public.')[1]]
            self.result = [(state['last_value'], state['is_called'])]
        elif sql.startswith('SELECT setval'):
            self.check_intent('sequence-dispatch-intent')
            name, last, called = args
            d.sequences[name.removeprefix('public.')] = {'last_value': last, 'is_called': called}
            d.sequence_count += 1
            if d.failure == 'second-sequence-reply-lost' and d.sequence_count == 2:
                raise OSError('simulated sequence reply loss')
            self.result = [(last,)]
        elif sql.startswith('SELECT c.relname,c.relkind'):
            self.result = [(name, 'r', False, False, 'powerdns_owner') for name in m.snapshot_lib.TABLES]
        elif sql.startswith('SELECT count(*) FROM pg_trigger'):
            self.result = [(1 if d.failure == 'custom-trigger' else 0,)]
        elif sql.startswith('SELECT count(*) FROM pg_rewrite'):
            self.result = [(0,)]
        elif sql.startswith('SELECT attname FROM pg_attribute'):
            self.result = [(name,) for name in m.snapshot_lib.COLUMNS[args[0].removeprefix('public.')]]
        else:
            raise AssertionError('Unexpected SQL in offline simulator: ' + sql)

    def check_intent(self, phase):
        record = m.snapshot_lib.read_private_json(self.db.journal.path)
        if record['phase'] != phase:
            raise AssertionError('SQL mutation before durable intent')

    def executemany(self, sql, values):
        self.check_intent('row-transaction-dispatch-intent')
        table = sql.split('public.')[1].split()[0]
        columns = sql.split('(')[1].split(')')[0].split(',')
        if tuple(columns) != m.snapshot_lib.COLUMNS[table]:
            raise AssertionError('Implicit or wrong column mapping')
        self.db.tables[table].extend(dict(zip(columns, row)) for row in values)
        self.db.insert_count += 1
        if self.db.failure == 'second-table-fails' and self.db.insert_count == 2:
            raise ValueError('fixture secret must never appear in receipts')


class ImportTests(unittest.TestCase):
    def fixture(self, failure=None):
        tables, sequences = f.fixture()
        payload = {'tables': tables, 'sequences_after': sequences}
        target = {**f.SOURCE, 'label': 'target-test', 'system_identifier': '9876543210'}
        plan = {'operation_id': '00000000-0000-4000-8000-000000000002', 'target': target,
                'snapshot_sha256': 'b' * 64, 'target_fence_sha256': 'c' * 64,
                'target_sequences_before': copy.deepcopy(Database().sequences)}
        return Database(failure), plan, payload

    def run_case(self, directory, failure=None):
        db, plan, payload = self.fixture(failure)
        journal = m.Journal(Path(directory) / 'receipt.json')
        db.journal = journal

        def guard(connection, *_):
            m.require(connection.fenced, 'Target API no longer fenced')
            connection.events.append(('GUARD', ()))
        return db, plan, payload, journal, patch.object(m, 'guard', side_effect=guard)

    def test_exact_data_and_six_sequences_keep_seed_and_writer_fenced(self):
        with tempfile.TemporaryDirectory() as directory:
            db, plan, payload, journal, guard = self.run_case(directory)
            with guard:
                result = m.import_once(db, plan, payload, {}, None, journal)
            self.assertTrue(result['verified'])
            self.assertFalse(result['writer_enabled'])
            self.assertTrue(db.fenced)
            self.assertEqual(m.read_tables(db), m.expected_tables(payload))
            self.assertEqual(db.sequences, payload['sequences_after'])
            self.assertEqual(db.sequence_count, 6)
            # No MAX(id), DDL, privileges, sequence increments or private record data in receipt.
            statements = '\n'.join(sql for sql, _ in db.events)
            for forbidden in ('MAX(', 'GRANT ', 'CREATE ', 'TRUNCATE ', 'nextval('):
                self.assertNotIn(forbidden, statements)
            receipt = journal.path.read_text()
            for private in ('fixture-private-key', 'fixture-secret', 'example.invalid'):
                self.assertNotIn(private, receipt)

    def test_row_failure_rolls_back_every_row_and_does_not_touch_sequences(self):
        with tempfile.TemporaryDirectory() as directory:
            db, plan, payload, journal, guard = self.run_case(directory, 'second-table-fails')
            with guard, self.assertRaises(ValueError):
                m.import_once(db, plan, payload, {}, None, journal)
            self.assertEqual(db.tables, m.health_seed())
            self.assertEqual(db.sequence_count, 0)
            self.assertFalse(journal.value['verified'])
            self.assertEqual(journal.value['phase'], 'row-transaction-dispatch-intent')
            self.assertNotIn('fixture secret', journal.path.read_text())

    def test_unknown_commit_is_preserved_without_sequence_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            db, plan, payload, journal, guard = self.run_case(directory, 'commit-reply-lost')
            with guard, self.assertRaises(OSError):
                m.import_once(db, plan, payload, {}, None, journal)
            self.assertEqual(m.read_tables(db), m.expected_tables(payload))
            self.assertEqual(db.sequence_count, 0)
            self.assertEqual(journal.value['phase'], 'row-commit-dispatch-intent')
            self.assertFalse(journal.value['verified'])

    def test_partial_setval_does_not_claim_rollback_or_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            db, plan, payload, journal, guard = self.run_case(directory, 'second-sequence-reply-lost')
            with guard, self.assertRaises(OSError):
                m.import_once(db, plan, payload, {}, None, journal)
            self.assertEqual(db.sequence_count, 2)
            self.assertEqual(m.read_tables(db), m.expected_tables(payload))
            self.assertEqual(journal.value['phase'], 'sequence-dispatch-intent')
            self.assertEqual(journal.value['outcome'], 'failed-or-unknown-no-resume')
            before = copy.deepcopy(db.sequences)
            with patch.object(m, 'guard'):
                result = m.readback(db, plan, payload, {}, None)
            self.assertTrue(result['rows_exact'])
            self.assertFalse(result['sequences_exact'])
            self.assertFalse(result['resumed'])
            self.assertEqual(db.sequences, before)
            self.assertEqual(db.sequence_count, 2)

    def test_fence_loss_stops_before_first_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            db, plan, payload, journal, guard = self.run_case(directory, 'fence-lost-after-commit')
            with guard, self.assertRaises(m.snapshot_lib.InvalidSnapshot):
                m.import_once(db, plan, payload, {}, None, journal)
            self.assertEqual(db.sequence_count, 0)
            self.assertFalse(journal.value['verified'])

    def test_changed_seed_or_unreviewed_sequence_refused_before_intent(self):
        for mode in ('seed', 'sequence'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                db, plan, payload, journal, guard = self.run_case(directory)
                if mode == 'seed':
                    db.tables['records'][0]['content'] = 'changed'
                else:
                    db.sequences['domains_id_seq']['is_called'] = True
                with guard, self.assertRaises(m.snapshot_lib.InvalidSnapshot):
                    m.import_once(db, plan, payload, {}, None, journal)
                self.assertFalse(journal.path.exists())
                self.assertEqual(db.insert_count, 0)

    def test_reviewed_consumed_seed_sequences_keep_exact_source_values(self):
        with tempfile.TemporaryDirectory() as directory:
            db, plan, payload, journal, guard = self.run_case(directory)
            for name in ('domains_id_seq', 'records_id_seq', 'domainmetadata_id_seq'):
                db.sequences[name] = {'last_value': 1, 'is_called': True}
                # A source equal or ahead of that preimage is allowed.
                payload['sequences_after'][name] = {'last_value': 10, 'is_called': True}
            plan['target_sequences_before'] = copy.deepcopy(db.sequences)
            with guard:
                result = m.import_once(db, plan, payload, {}, None, journal)
            self.assertTrue(result['verified'])
            self.assertEqual(result['sequences_before'], plan['target_sequences_before'])
            self.assertEqual(db.sequences, payload['sequences_after'])

    def test_reviewed_preimage_cannot_move_next_value_backwards(self):
        for prior, desired in (({'last_value': 10, 'is_called': True}, {'last_value': 10, 'is_called': False}),
                               ({'last_value': 11, 'is_called': False}, {'last_value': 9, 'is_called': True})):
            with self.subTest(prior=prior), tempfile.TemporaryDirectory() as directory:
                db, plan, payload, journal, guard = self.run_case(directory)
                name = 'comments_id_seq'
                db.sequences[name] = prior
                plan['target_sequences_before'] = copy.deepcopy(db.sequences)
                payload['sequences_after'][name] = desired
                with guard, self.assertRaises(m.snapshot_lib.InvalidSnapshot):
                    m.import_once(db, plan, payload, {}, None, journal)
                self.assertFalse(journal.path.exists())
                self.assertEqual(db.insert_count, 0)
                self.assertEqual(db.sequence_count, 0)

    def test_sequence_preimage_requires_all_six_typed_bounded_pairs(self):
        before = Database().sequences
        for changed in ({}, {**before, 'records_id_seq': {'last_value': True, 'is_called': False}},
                        {**before, 'records_id_seq': {'last_value': 2_000_000_000, 'is_called': True}}):
            with self.subTest(changed=changed), self.assertRaises(m.snapshot_lib.InvalidSnapshot):
                m.validate_sequence_preimage(changed, before)

    def test_journal_cannot_be_reused_and_unknown_receipt_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            original = {'phase': 'sequence-dispatch-intent', 'verified': False}
            m.snapshot_lib.write_private_json(path, original)
            with self.assertRaises(FileExistsError):
                m.Journal(path).start({'phase': 'prepared'})
            self.assertEqual(m.snapshot_lib.read_private_json(path), original)

    def test_target_lock_identity_ignores_operation_id_label_and_login(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.fixture()[1]['target']
            with m.state_lock(directory, target) as one:
                pass
            with m.state_lock(directory, {**target, 'label': 'renamed', 'user': 'other-admin'}) as two:
                pass
            self.assertEqual(one, two)

    def test_advisory_lock_refusal_does_not_create_journal_or_write_data(self):
        with tempfile.TemporaryDirectory() as directory:
            db, plan, payload, journal, guard = self.run_case(directory, 'locked')
            with guard, self.assertRaises(m.snapshot_lib.InvalidSnapshot):
                m.import_once(db, plan, payload, {}, None, journal)
            self.assertFalse(journal.path.exists())
            self.assertEqual(db.insert_count, 0)

    def test_observation_is_never_an_importable_final_snapshot(self):
        tables, sequences = f.fixture()
        snapshot = f.p.make_snapshot(f.SOURCE, tables, sequences, sequences, f.START, f.END, f.TX)
        target = self.fixture()[1]['target']
        plan = dict.fromkeys(m.PLAN_KEYS, 'a' * 64)
        plan.update(format=1, kind='powerdns-data-import', operation_id='00000000-0000-4000-8000-000000000002',
                    source=f.SOURCE, target=target, writer_role='powerdns_api', snapshot_sha256=snapshot['sha256'])
        with self.assertRaises(m.snapshot_lib.InvalidSnapshot):
            m.validate_inputs(plan, snapshot, {}, {}, None)

    def sql_contract(self):
        fence = m.module('powerdns-fence')
        target = self.fixture()[1]['target']

        def receipt(identity, writer):
            effective = {'connect': True,
                'tables': {t: {'SELECT': True, **dict.fromkeys(fence.DML, False)} for t in m.snapshot_lib.TABLES},
                'columns': {t: {'INSERT': False, 'UPDATE': False} for t in m.snapshot_lib.TABLES},
                'sequences': {s: {'SELECT': True, 'USAGE': False, 'UPDATE': False} for s in m.snapshot_lib.SEQUENCES}}
            after = {'identity': identity, 'writer_role': writer, 'schema_sha256': 'd' * 64,
                     'role': {'name': writer, 'superuser': False, 'inherit': False, 'createrole': False,
                              'createdb': writer == 'powerdns', 'login': True, 'replication': False, 'bypassrls': False},
                     'catalog_acl': {'database': [], 'schema': [], 'relations': []}, 'effective': effective}
            before = copy.deepcopy(after)
            for table in m.snapshot_lib.TABLES:
                before['effective']['tables'][table]['INSERT'] = True
            return fence.make_receipt('00000000-0000-4000-8000-000000000003', before, after)
        source_fence, target_fence = receipt(f.SOURCE, 'powerdns'), receipt(target, 'powerdns_api')
        tables, sequences = f.fixture()
        at = m.snapshot_lib.utc_now()
        snapshot = m.snapshot_lib.make_snapshot(f.SOURCE, tables, sequences, sequences, at, at, f.TX,
                                                final=True, fence=source_fence)
        plan = {'format': 1, 'kind': 'powerdns-data-import',
            'operation_id': '00000000-0000-4000-8000-000000000002', 'source': f.SOURCE, 'target': target,
            'writer_role': 'powerdns_api', 'snapshot_sha256': snapshot['sha256'],
            'source_fence_sha256': m.digest(source_fence), 'target_fence_sha256': m.digest(target_fence),
            'target_schema_sha256': target_fence['after']['schema_sha256'], 'target_seed_sha256': m.digest(m.health_seed()),
            'target_sequences_before': copy.deepcopy(Database().sequences)}
        return plan, snapshot, source_fence, target_fence, fence

    def test_actual_final_snapshot_and_sql_fence_contract_agree(self):
        args = self.sql_contract()
        payload = m.validate_inputs(*args)
        self.assertTrue(payload['capture']['final_for_cutover'])
        self.assertEqual(payload['capture']['fence'], args[2])

    def test_expired_target_fence_refused_for_import_but_readback_possible(self):
        plan, snapshot, source_fence, target_fence, fence = self.sql_contract()
        now = datetime.now(timezone.utc)
        target_fence['checked_at'] = (now - timedelta(minutes=20)).isoformat()
        target_fence['valid_until'] = (now - timedelta(minutes=5)).isoformat()
        plan['target_fence_sha256'] = m.digest(target_fence)
        with self.assertRaises(m.snapshot_lib.InvalidSnapshot):
            m.validate_inputs(plan, snapshot, source_fence, target_fence, fence)
        m.validate_inputs(plan, snapshot, source_fence, target_fence, fence, current=False)

    def test_fresh_receipt_cannot_replace_snapshot_embedded_source_fence(self):
        plan, snapshot, source_fence, target_fence, fence = self.sql_contract()
        other = fence.make_receipt('00000000-0000-4000-8000-000000000004', source_fence['before'], source_fence['after'])
        plan['source_fence_sha256'] = m.digest(other)
        with self.assertRaises(m.snapshot_lib.InvalidSnapshot):
            m.validate_inputs(plan, snapshot, other, target_fence, fence)

    def test_nearly_expired_fence_cannot_outlive_import_deadline(self):
        plan, snapshot, source_fence, target_fence, fence = self.sql_contract()
        now = datetime.now(timezone.utc)
        target_fence['checked_at'] = (now - timedelta(minutes=12)).isoformat()
        target_fence['valid_until'] = (now + timedelta(minutes=2)).isoformat()
        plan['target_fence_sha256'] = m.digest(target_fence)
        with self.assertRaises(m.snapshot_lib.InvalidSnapshot):
            m.validate_inputs(plan, snapshot, source_fence, target_fence, fence)

    def test_live_guard_rejects_acl_drift_and_custom_trigger(self):
        plan, _, _, target_fence, _ = self.sql_contract()
        observation = copy.deepcopy(target_fence['after'])
        fake = SimpleNamespace(assert_fenced=lambda *args: observation)
        m.guard(Database(), plan, target_fence, fake)
        observation['catalog_acl'] = {'unexpected': True}
        with self.assertRaises(m.snapshot_lib.InvalidSnapshot):
            m.guard(Database(), plan, target_fence, fake)
        observation['catalog_acl'] = target_fence['after']['catalog_acl']
        with self.assertRaises(m.snapshot_lib.InvalidSnapshot):
            m.guard(Database('custom-trigger'), plan, target_fence, fake)


if __name__ == '__main__':
    unittest.main()
